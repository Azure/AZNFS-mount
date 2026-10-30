#!/bin/bash
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
#
# Regression tests for the locking between the NFSv4 watchdog (aznfswatchdogv4)
# and the NFSv4 mount helper around the immutable flag on the NFSv4 mountmap
# files, MOUNTMAPv4 (TLS mounts) and MOUNTMAPv4NOTLS (non-TLS mounts).
#
# A mount helper clears the immutable flag on a mountmap, updates it and sets
# the flag again, all while holding the mountmap lock. The watchdog used to set
# the flag at startup without taking that lock, so a watchdog (re)starting while
# mounts were in flight, f.e. at boot, could set it in the middle of a mount
# helper's update. The update then failed with EPERM and failed the mount, or,
# when it landed between the truncating open and the write, left the mountmap
# empty.
#
# The real aznfswatchdogv4 script is run against a sandboxed copy of the
# install, with real chattr and flock. Nothing outside the sandbox is modified,
# the watchdog is always stopped as soon as it enters its main loop, before it
# processes any mountmap entry.
#
# Needs root, for chattr +i, and a filesystem under root's home directory that
# supports the immutable flag.
#
# Usage: sudo ./testing/test_mountmap_lock.sh
#
# AZNFS_LOCK_STRESS_SECS   Seconds to run the parallel stress against the
#                          watchdog, default 20. 0 skips the stress test.
#
SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STRESS_SECS=${AZNFS_LOCK_STRESS_SECS:-20}
STRESS_WRITERS_PER_MAP=8

if [ "$(id -u)" != "0" ]; then
    echo "Must be run as root, the immutable flag can only be set by root."
    exit 1
fi

for cmd in chattr lsattr flock pgrep; do
    if ! command -v $cmd >/dev/null 2>&1; then
        echo "'$cmd' is not installed, cannot run the mountmap lock tests."
        exit 1
    fi
done

if [ ! -s "$SOURCE_DIR/lib/common.sh" ]; then
    echo "'$SOURCE_DIR/lib/common.sh' is missing or empty."
    exit 1
fi

SANDBOX_HOME=$(getent passwd root 2>/dev/null | cut -d: -f6)
SANDBOX_HOME=${SANDBOX_HOME:-/root}
SANDBOX=$(mktemp -d "${SANDBOX_HOME}/.aznfs-mountmap-lock-test.XXXXXX") || exit 1
if [ -z "$SANDBOX" -o ! -d "$SANDBOX" ]; then
    echo "Not able to create a sandbox directory, aborting."
    exit 1
fi
chmod 0755 "$SANDBOX" || exit 1
umask 022

PASS=0
FAIL=0
FAILED_TESTS=()
WD_PID=
HOLDER_PID=
WRITER_PIDS=

pass()
{
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

fail()
{
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
    FAILED_TESTS+=("$1")
}

stop_watchdog()
{
    local kids

    [ -z "$WD_PID" ] && return 0
    kids=$(pgrep -P $WD_PID)
    kill $WD_PID $kids 2>/dev/null
    wait $WD_PID 2>/dev/null
    WD_PID=
}

cleanup()
{
    stop_watchdog
    [ -n "$HOLDER_PID" ] && kill $HOLDER_PID 2>/dev/null
    [ -n "$WRITER_PIDS" ] && kill $WRITER_PIDS 2>/dev/null
    wait 2>/dev/null
    chattr -R -f -i "$SANDBOX" 2>/dev/null
    rm -rf "$SANDBOX"
}
trap cleanup EXIT

probe="$SANDBOX/probe"
touch "$probe"
if ! chattr +i "$probe" 2>/dev/null; then
    echo "The filesystem holding '$SANDBOX' does not support the immutable flag."
    exit 1
fi
chattr -i "$probe"
rm -f "$probe"

#
# Lines every mountmap starts with. They must all still be there at the end of
# every test, a mountmap truncated by a failed update loses them.
#
baseline()
{
    local i

    case "$1" in
        v4notls)
            for i in 1 2 3; do
                echo "base$i.file.core.windows.net 10.161.255.$i 192.0.2.$i"
            done
            ;;
        v4)
            for i in 1 2 3; do
                echo "base$i.file.core.windows.net;192.0.2.$i;/nonexistent/stunnel_base$i.conf;/nonexistent/stunnel_base$i.log;/nonexistent/stunnel_base$i.pid;1;waiting;9999999999"
            done
            ;;
    esac
}

#
# Fresh sandboxed install: common.sh and aznfswatchdogv4 from this tree, with
# every path that would reach the real install redirected into the sandbox.
#
setup_sandbox()
{
    local var

    ROOT="$SANDBOX/root"
    OPT="$ROOT/opt/microsoft/aznfs"
    DATA="$OPT/data"
    LOGDIR="$ROOT/log"

    [ -d "$ROOT" ] && chattr -R -f -i "$ROOT"
    rm -rf "$ROOT"
    mkdir -p "$DATA" "$LOGDIR" "$ROOT/etc"

    #
    # OPTDIR is all there is to redirect on most versions, the log and the
    # mountmaps live under it. Versions with a configurable log directory and
    # a logrotate config also have their defaults redirected; those lines are
    # optional, but must never be left pointing at the real system.
    #
    sed -e "s#^OPTDIR=\"/opt/microsoft/\${APPNAME}\"#OPTDIR=\"$OPT\"#" \
        -e "s#^LOGROTATE_CONFIG=\"/etc/logrotate.d/\${APPNAME}\"#LOGROTATE_CONFIG=\"$ROOT/etc/logrotate.d/\${APPNAME}\"#" \
        -e "s#^AZNFS_LOGDIR_DEFAULT=\"/var/log/aznfs\"#AZNFS_LOGDIR_DEFAULT=\"$LOGDIR\"#" \
        "$SOURCE_DIR/lib/common.sh" > "$OPT/common.sh"

    #
    # A rewrite that did not apply would have the watchdog work on the real
    # install, so that is fatal rather than a test failure.
    #
    if ! grep -q "^OPTDIR=\"$OPT\"" "$OPT/common.sh"; then
        echo "Not able to sandbox common.sh, aborting."
        exit 1
    fi

    for var in LOGROTATE_CONFIG AZNFS_LOGDIR_DEFAULT; do
        if grep -q "^${var}=" "$OPT/common.sh" &&
           ! grep -q "^${var}=\"$ROOT/" "$OPT/common.sh"; then
            echo "Not able to sandbox $var in common.sh, aborting."
            exit 1
        fi
    done

    sed -e "s#^\. /opt/microsoft/aznfs/common.sh#. $OPT/common.sh#" \
        "$SOURCE_DIR/src/aznfswatchdogv4" > "$OPT/aznfswatchdogv4"
    if ! grep -q "^\. $OPT/common.sh" "$OPT/aznfswatchdogv4" ||
       grep -q "^\. /opt/microsoft/aznfs/common.sh" "$OPT/aznfswatchdogv4"; then
        echo "Not able to sandbox aznfswatchdogv4, aborting."
        exit 1
    fi

    printf 'AUTO_UPDATE_AZNFS=false\nAZNFS_LOGDIR=%s\n' "$LOGDIR" > "$DATA/config"

    MOUNTMAPv4="$DATA/mountmapv4"
    MOUNTMAPv4NOTLS="$DATA/mountmapv4notls"

    baseline v4 > "$MOUNTMAPv4"
    baseline v4notls > "$MOUNTMAPv4NOTLS"
    chattr +i "$MOUNTMAPv4" "$MOUNTMAPv4NOTLS"
}

# wait_for <seconds> <command...>: poll the command every 0.1s.
wait_for()
{
    local i limit=$(( $1 * 10 ))
    shift

    for ((i = 0; i < limit; i++)); do
        "$@" && return 0
        sleep 0.1
    done
    return 1
}

is_immutable()
{
    [[ "$(lsattr -d "$1" 2>/dev/null | awk '{print $1}')" == *i* ]]
}

start_watchdog()
{
    AZNFS_LOGDIR="$LOGDIR" bash "$OPT/$1" >/dev/null 2>>"$ROOT/$1.stderr" &
    WD_PID=$!
}

watchdog_alive()
{
    kill -0 $WD_PID 2>/dev/null
}

#
# The main loop is the first place the watchdog runs "sleep 5"
# (MONITOR_INTERVAL_SECS), startup only runs "sleep 2" in log_version_info().
#
watchdog_in_main_loop()
{
    pgrep -P $WD_PID -xf "sleep 5" >/dev/null 2>&1
}

# Is the watchdog waiting in flock(1) for the lock on the given file?
watchdog_blocked_on()
{
    local p

    for p in $(pgrep -P $WD_PID -x flock); do
        ls -l /proc/$p/fd 2>/dev/null | grep -q " $1\$" && return 0
    done
    return 1
}

# Stays true while the watchdog is neither blocked on $1 nor done with startup.
watchdog_starting()
{
    watchdog_alive && ! is_immutable "$1" && ! watchdog_blocked_on "$1" && ! watchdog_in_main_loop
}

dump_watchdog_logs()
{
    local log

    # The log is in the log directory on versions that have one, else in data.
    for log in "$LOGDIR/aznfs.log" "$DATA/aznfs.log"; do
        [ -s "$log" ] || continue
        echo "    --- $log (tail)"
        tail -5 "$log" | sed -e 's/\x1b\[[0-9;]*m//g' -e 's/^/    /'
    done
    cat "$ROOT"/*.stderr 2>/dev/null | tail -5 | sed 's/^/    /'
}

#
# Stand-in for a mount helper in the middle of a mountmap update: holds the
# mountmap lock with the immutable flag cleared until told to finish, then
# rewrites the mountmap the way the mount helpers do (truncating redirection)
# and sets the flag again.
#
start_holder()
{
    local mm=$1 fd out rc

    rm -f "$ROOT/held" "$ROOT/release" "$ROOT/holder.err"
    (
        exec {fd}<"$mm"
        flock -e $fd
        chattr -f -i "$mm"
        touch "$ROOT/held"
        while [ ! -e "$ROOT/release" ]; do
            sleep 0.05
        done
        out=$(cat "$mm"; echo "holder-entry")
        { echo "$out" > "$mm"; } 2>>"$ROOT/holder.err"
        rc=$?
        chattr -f +i "$mm"
        flock -u $fd
        exit $rc
    ) &
    HOLDER_PID=$!
}

#
# The watchdog must wait for a mount helper holding the mountmap lock instead
# of setting the immutable flag under it, and must carry on once the lock is
# released.
#
# test_watchdog_waits_for_lock <watchdog> <mountmap variable> <baseline kind>
#
test_watchdog_waits_for_lock()
{
    local wd=$1 mmvar=$2 kind=$3 mm result holder_rc name

    name="$wd waits for the $mmvar lock before setting the immutable flag"
    echo "=== $name"

    setup_sandbox
    mm=${!mmvar}

    start_holder "$mm"
    if ! wait_for 10 test -e "$ROOT/held"; then
        fail "$name (lock holder did not start)"
        kill $HOLDER_PID 2>/dev/null; wait $HOLDER_PID 2>/dev/null; HOLDER_PID=
        return
    fi

    start_watchdog $wd
    wait_for 30 eval '! watchdog_starting "$mm"'

    if ! watchdog_alive; then
        result="exited"
    elif is_immutable "$mm"; then
        result="set the immutable flag while the lock was held"
    elif watchdog_blocked_on "$mm"; then
        result="blocked"
    elif watchdog_in_main_loop; then
        result="reached its main loop without setting the immutable flag"
    else
        result="did not get to the immutable flag within 30s"
    fi

    if [ "$result" == "blocked" ]; then
        # Give an unlocked chattr every chance to show up.
        sleep 0.5
        is_immutable "$mm" && result="set the immutable flag while the lock was held"
    fi

    if [ "$result" == "blocked" ]; then
        pass "$name"
    else
        fail "$name (watchdog $result)"
        dump_watchdog_logs
    fi

    touch "$ROOT/release"
    wait $HOLDER_PID
    holder_rc=$?
    HOLDER_PID=

    if [ $holder_rc -eq 0 ]; then
        pass "$wd: concurrent $mmvar update by the mount helper succeeds"
    else
        fail "$wd: concurrent $mmvar update by the mount helper failed: $(tr '\n' ' ' < "$ROOT/holder.err")"
    fi

    if wait_for 15 eval 'watchdog_in_main_loop && is_immutable "$mm"'; then
        pass "$wd: sets the immutable flag on $mmvar once the lock is released and starts monitoring"
    else
        fail "$wd: did not set the immutable flag on $mmvar and reach its main loop after the lock was released"
        dump_watchdog_logs
    fi
    stop_watchdog

    if [ "$(baseline $kind; echo holder-entry)" == "$(cat "$mm")" ]; then
        pass "$wd: $mmvar contents intact"
    else
        fail "$wd: $mmvar contents not intact: [$(tr '\n' '|' < "$mm")]"
    fi
}

#
# Mount helper stand-in for the stress tests: adds its own entry and removes it
# again in a loop, with the same lock, chattr and redirection pattern as the
# mount helpers, until $ROOT/stop appears. Any failed update is recorded in
# $ROOT/stress.fail.
#
stress_writer()
{
    local mm=$1 id=$2 fd out err="$ROOT/writer.$2.err"

    while [ ! -e "$ROOT/stop" ]; do
        exec {fd}<"$mm"
        flock -e $fd
        chattr -f -i "$mm"
        { echo "writer-$id" >> "$mm"; } 2>"$err" ||
            echo "$(basename "$mm") add writer-$id: $(cat "$err")" >> "$ROOT/stress.fail"
        chattr -f +i "$mm"
        flock -u $fd
        exec {fd}<&-

        sleep 0.0$((RANDOM % 5))

        exec {fd}<"$mm"
        flock -e $fd
        chattr -f -i "$mm"
        out=$(sed "/^writer-$id\$/d" "$mm")
        { echo "$out" > "$mm"; } 2>"$err" ||
            echo "$(basename "$mm") remove writer-$id: $(cat "$err")" >> "$ROOT/stress.fail"
        chattr -f +i "$mm"
        flock -u $fd
        exec {fd}<&-

        sleep 0.0$((RANDOM % 5))
    done
}

#
# Mount helpers keep updating the mountmaps while the watchdog is started over
# and over again.
#
# test_stress <watchdog> <mountmap variable:baseline kind>...
#
test_stress()
{
    local wd=$1 starts=0 end spec mmvar kind mm i id=0 ok name
    shift

    name="$wd restarted repeatedly during parallel mountmap updates"
    echo "=== $name (${STRESS_SECS}s)"

    setup_sandbox
    rm -f "$ROOT/stop" "$ROOT/stress.fail"
    WRITER_PIDS=

    for spec in "$@"; do
        mmvar=${spec%%:*}
        for ((i = 0; i < STRESS_WRITERS_PER_MAP; i++)); do
            id=$((id + 1))
            stress_writer "${!mmvar}" $id &
            WRITER_PIDS="$WRITER_PIDS $!"
        done
    done

    ok=true
    end=$(( $(date +%s) + STRESS_SECS ))
    while [ $(date +%s) -lt $end ]; do
        start_watchdog $wd
        starts=$((starts + 1))
        if ! wait_for 30 watchdog_in_main_loop; then
            fail "$name (watchdog start $starts did not reach its main loop)"
            dump_watchdog_logs
            ok=false
            stop_watchdog
            break
        fi
        stop_watchdog
    done

    touch "$ROOT/stop"
    wait $WRITER_PIDS
    WRITER_PIDS=

    if [ -s "$ROOT/stress.fail" ]; then
        fail "$name: $(wc -l < "$ROOT/stress.fail") mountmap update(s) failed in $starts watchdog starts"
        head -5 "$ROOT/stress.fail" | sed 's/^/    /'
        ok=false
    fi

    for spec in "$@"; do
        mmvar=${spec%%:*}
        kind=${spec##*:}
        mm=${!mmvar}
        if [ "$(baseline $kind)" != "$(grep -v '^$' "$mm")" ]; then
            fail "$name: $mmvar contents not intact: [$(tr '\n' '|' < "$mm")]"
            ok=false
        elif ! is_immutable "$mm"; then
            fail "$name: $mmvar left without the immutable flag"
            ok=false
        fi
    done

    $ok && pass "$name ($starts watchdog starts, no failed updates)"
}

test_watchdog_waits_for_lock aznfswatchdogv4 MOUNTMAPv4 v4
test_watchdog_waits_for_lock aznfswatchdogv4 MOUNTMAPv4NOTLS v4notls

if [ "$STRESS_SECS" -gt 0 ] 2>/dev/null; then
    test_stress aznfswatchdogv4 MOUNTMAPv4:v4 MOUNTMAPv4NOTLS:v4notls
else
    echo "=== Stress test skipped (AZNFS_LOCK_STRESS_SECS=$STRESS_SECS)"
fi

echo
echo "Passed: $PASS, Failed: $FAIL"
if [ $FAIL -ne 0 ]; then
    printf '  %s\n' "${FAILED_TESTS[@]}"
    exit 1
fi
exit 0
