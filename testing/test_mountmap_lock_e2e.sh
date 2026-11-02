#!/bin/bash
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
#
# End-to-end test for the NFSv4 watchdog mountmap locking, with REAL Azure Files
# NFSv4 mounts made through the installed AZNFS package.
#
# Workers mount and unmount the share in parallel, each on its own mount point,
# while aznfswatchdogv4 is restarted, or stopped and started again, every few
# seconds. If the watchdog sets the immutable flag on a mountmap without holding
# the mountmap lock, a mount helper's update of that mountmap fails with EPERM
# and the mount helper reports it ("Operation not permitted", "MOUNTMAPv4 may be
# in inconsistent state", "failed to update ...mountmapv4").
#
# The race window is short, so this test does not hit an unfixed watchdog on
# every run. testing/test_mountmap_lock.sh is the deterministic regression test,
# this one checks the locking holds up with real mounts.
#
# Must run as root on a machine with AZNFS installed, it tests whatever version
# is installed. It only creates mount points under a new directory in /mnt and
# restarts aznfswatchdogv4, it does not change the installed package. The
# watchdog is left running when the test ends.
#
# Usage: sudo NFSV4_STORAGE_ACCOUNTS="<account> [...]" ./testing/test_mountmap_lock_e2e.sh
#
# NFSV4_STORAGE_ACCOUNTS     Space-separated Azure Files storage accounts with an
#                            NFS file share named githubtest. The first one is
#                            used.
# AZNFS_LOCK_E2E_SHARE       Share to mount instead, <host>:/<account>/<share>.
# AZNFS_LOCK_E2E_OPTIONS     Mount options, default
#                            vers=4,minorversion=1,sec=sys,nconnect=4.
# AZNFS_LOCK_E2E_SECS        Seconds to run, default 120.
# AZNFS_LOCK_E2E_WORKERS     Parallel mount workers, default 10.
#
DURATION=${AZNFS_LOCK_E2E_SECS:-120}
WORKERS=${AZNFS_LOCK_E2E_WORKERS:-10}
OPTIONS=${AZNFS_LOCK_E2E_OPTIONS:-vers=4,minorversion=1,sec=sys,nconnect=4}
MOUNTMAPv4=/opt/microsoft/aznfs/data/mountmapv4
WATCHDOG=aznfswatchdogv4

# Mount helper output when an update of a mountmap was refused.
MOUNTMAP_ERRORS='Operation not permitted|inconsistent state|failed to update .*mountmap|failed to add to .*mountmap|Failed to touch'

# Mount helper refusing to mount while the watchdog is stopped, expected here.
WATCHDOG_DOWN='service not running'

# A single mount is not expected to take longer than this.
MOUNT_TIMEOUT=120

if [ "$(id -u)" != "0" ]; then
    echo "Must be run as root."
    exit 1
fi

for cmd in mount umount mountpoint systemctl timeout lsattr; do
    if ! command -v $cmd >/dev/null 2>&1; then
        echo "'$cmd' is not installed, cannot run the test."
        exit 1
    fi
done

if [ ! -x /sbin/mount.aznfs ] || ! systemctl cat $WATCHDOG.service >/dev/null 2>&1; then
    echo "AZNFS is not installed, cannot run the test."
    exit 1
fi

for var in DURATION WORKERS; do
    if ! [[ "${!var}" =~ ^[1-9][0-9]*$ ]]; then
        echo "Invalid $var '${!var}', must be a positive number."
        exit 1
    fi
done

if [ -n "$AZNFS_LOCK_E2E_SHARE" ]; then
    SHARE=$AZNFS_LOCK_E2E_SHARE
else
    read -r account _ <<< "$NFSV4_STORAGE_ACCOUNTS"
    if [ -z "$account" ]; then
        echo "Set NFSV4_STORAGE_ACCOUNTS (or AZNFS_LOCK_E2E_SHARE) to the share to mount."
        exit 1
    fi
    SHARE="${account}.file.core.windows.net:/${account}/githubtest"
fi

#
# A new directory for every run, so the test never mounts over, or unmounts,
# anything that was there before.
#
MPROOT=$(mktemp -d /mnt/aznfs-lock-e2e.XXXXXX) || exit 1
chmod 0755 "$MPROOT"
ANCHOR="$MPROOT/anchor"
RESULTS="$MPROOT/results"
STOP="$MPROOT/stop"
mkdir -p "$ANCHOR" "$RESULTS"

PASS=0
FAIL=0
FAILED_TESTS=()
WORKER_PIDS=

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

# Random number of tenths of a second in [$1, $2], as a sleep argument.
random_secs()
{
    local t=$(( $1 + RANDOM % ($2 - $1 + 1) ))
    echo "$((t / 10)).$((t % 10))"
}

start_watchdog()
{
    # Repeated starts must not run into the unit's start rate limit.
    systemctl reset-failed $WATCHDOG 2>/dev/null
    systemctl start $WATCHDOG
}

cleanup()
{
    local mp

    touch "$STOP"
    [ -n "$WORKER_PIDS" ] && wait $WORKER_PIDS 2>/dev/null

    for mp in "$MPROOT"/worker*; do
        [ -d "$mp" ] || continue
        mountpoint -q "$mp" && umount "$mp"
    done

    #
    # Stopped while the last mount of the endpoint goes away. The watchdog
    # otherwise may tear down the endpoint's TLS tunnel while the kernel is
    # still sending its final requests through it, which makes umount wait
    # for an RPC timeout.
    #
    if mountpoint -q "$ANCHOR"; then
        systemctl stop $WATCHDOG
        umount "$ANCHOR"
    fi
    start_watchdog

    for mp in "$MPROOT"/worker* "$ANCHOR"; do
        mountpoint -q "$mp" 2>/dev/null || rmdir "$mp" 2>/dev/null
    done
    rm -rf "$RESULTS" "$STOP"
    rmdir "$MPROOT" 2>/dev/null
}
trap cleanup EXIT

#
# Mounts and unmounts the share on its own mount point until $STOP appears or
# the time is up, recording "<rc> <mount helper output>" for every mount.
#
worker()
{
    local id=$1 end=$2 mp="$MPROOT/worker$1" out rc
    mkdir -p "$mp"

    while [ ! -e "$STOP" ] && [ "$(date +%s)" -lt "$end" ]; do
        out=$(timeout -s KILL $MOUNT_TIMEOUT mount -t aznfs "$SHARE" "$mp" -o "$OPTIONS" 2>&1)
        rc=$?
        echo "$rc $(echo "$out" | sed 's/\x1b\[[0-9;]*m//g' | tr '\n' ' ')" >> "$RESULTS/worker$id"
        mountpoint -q "$mp" && umount "$mp"
        sleep "0.$((RANDOM % 5))"
    done
}

echo "=== Parallel NFSv4 mounts of $SHARE while $WATCHDOG is restarted (${DURATION}s, $WORKERS workers)"

start_watchdog

#
# Kept mounted for the whole run, so the endpoint's TLS tunnel stays up and the
# workers' mounts exercise the same mountmap updates the mounts at boot do.
#
if ! out=$(timeout -s KILL $MOUNT_TIMEOUT mount -t aznfs "$SHARE" "$ANCHOR" -o "$OPTIONS" 2>&1); then
    echo "$out"
    echo "Not able to mount $SHARE, cannot run the test."
    exit 1
fi

end=$(( $(date +%s) + DURATION ))
for ((i = 1; i <= WORKERS; i++)); do
    worker $i $end &
    WORKER_PIDS="$WORKER_PIDS $!"
done

restarts=0
stop_starts=0
start_failures=0
while [ "$(date +%s)" -lt "$end" ]; do
    sleep "$(random_secs 25 50)"
    if [ $((RANDOM % 4)) -eq 0 ]; then
        systemctl stop $WATCHDOG
        sleep "$(random_secs 5 25)"
        start_watchdog || start_failures=$((start_failures + 1))
        stop_starts=$((stop_starts + 1))
    else
        systemctl restart $WATCHDOG || start_failures=$((start_failures + 1))
        restarts=$((restarts + 1))
    fi
done

wait $WORKER_PIDS
WORKER_PIDS=

cat "$RESULTS"/worker* > "$RESULTS/all" 2>/dev/null
total=$(grep -c . "$RESULTS/all")
mountmap_errors=$(grep -cE "$MOUNTMAP_ERRORS" "$RESULTS/all")
hung=$(grep -c '^137 ' "$RESULTS/all")
refused=$(grep -v '^0 ' "$RESULTS/all" | grep -vE "$MOUNTMAP_ERRORS" | grep -c "$WATCHDOG_DOWN")
other=$(grep -v '^0 ' "$RESULTS/all" | grep -vE "$MOUNTMAP_ERRORS|$WATCHDOG_DOWN" | grep -vc '^137 ')
ok=$(grep '^0 ' "$RESULTS/all" | grep -vcE "$MOUNTMAP_ERRORS")

echo "  $total mounts: $ok succeeded, $refused refused while $WATCHDOG was stopped (expected)," \
     "$mountmap_errors with mountmap update errors, $hung hung, $other failed otherwise;" \
     "$restarts watchdog restarts, $stop_starts stop/starts"

if [ $mountmap_errors -eq 0 ]; then
    pass "no mountmap update failed during $((restarts + stop_starts)) watchdog restarts"
else
    fail "$mountmap_errors mount(s) hit a mountmap update failure"
    grep -E "$MOUNTMAP_ERRORS" "$RESULTS/all" | head -5 | cut -c1-300 | sed 's/^/    /'
fi

if [ $hung -eq 0 ] && [ $other -eq 0 ]; then
    pass "no mount hung or failed for any other reason"
else
    fail "$hung mount(s) hung, $other failed for another reason"
    grep -v '^0 ' "$RESULTS/all" | grep -vE "$MOUNTMAP_ERRORS|$WATCHDOG_DOWN" | head -5 | cut -c1-300 | sed 's/^/    /'
fi

#
# Guards against a run that tells nothing, f.e. the watchdog never coming back
# up so that every mount was refused.
#
if [ $ok -ge $WORKERS ] && [ $((restarts + stop_starts)) -ge 5 ] && [ $start_failures -eq 0 ]; then
    pass "$ok mounts succeeded across the watchdog restarts"
else
    fail "run not representative: $ok mounts succeeded, $((restarts + stop_starts)) restarts, $start_failures failed watchdog start(s)"
fi

if mountpoint -q "$ANCHOR" && grep -q . "$MOUNTMAPv4" &&
   [[ "$(lsattr -d "$MOUNTMAPv4" 2>/dev/null | awk '{print $1}')" == *i* ]]; then
    pass "mount kept up during the run is still mounted, $MOUNTMAPv4 is not empty and is immutable"
else
    fail "mount kept up during the run, or $MOUNTMAPv4, not in the expected state"
fi

echo
echo "Passed: $PASS, Failed: $FAIL"
if [ $FAIL -ne 0 ]; then
    printf '  %s\n' "${FAILED_TESTS[@]}"
    exit 1
fi
exit 0
