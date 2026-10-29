#!/bin/bash

#
# Unit test for stunnel logging and pid file location of NFSv4 TLS mounts.
#
# Runs add_stunnel_configuration() from src/nfsv4mountscript.sh with stubbed
# helpers, then starts stunnel with the generated config and checks:
# - without AZNFS_LOGDIR there is no 'output =' and stunnel logs to syslog,
# - with AZNFS_LOGDIR stunnel logs to <AZNFS_LOGDIR>/stunnel_<ip>.log,
# - the pid file is under STUNNELPIDDIR, which is under /run.
#
# Needs stunnel and read access to syslog (root, or the adm / systemd-journal
# group). Exits 0 on success, 1 on failure, 77 if it cannot run here.
#

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
MOUNTSCRIPT="$REPO_DIR/src/nfsv4mountscript.sh"
COMMON="$REPO_DIR/lib/common.sh"

TEST_DIR=$(mktemp -d)
FAILED=0
STUNNEL_PIDS=()

cleanup_test()
{
    local p
    for p in "${STUNNEL_PIDS[@]}"; do
        kill "$p" 2>/dev/null
    done
    rm -rf "$TEST_DIR"
}
trap cleanup_test EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }
skip() { echo "SKIP: $*"; exit 77; }

STUNNEL=$(command -v stunnel || command -v stunnel4) || skip "stunnel is not installed"

for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem; do
    [ -f "$f" ] && STUNNEL_CAFILE=$f && break
done
[ -n "$STUNNEL_CAFILE" ] || skip "no system CA bundle found"

if command -v journalctl &> /dev/null && journalctl -q --no-pager -n 1 &> /dev/null; then
    SYSLOG_READER=journal
elif [ -r /var/log/syslog ]; then
    SYSLOG_READER=/var/log/syslog
elif [ -r /var/log/messages ]; then
    SYSLOG_READER=/var/log/messages
else
    skip "cannot read syslog, run as root"
fi

# Settings of the code under test.
eval "$(grep -m1 '^DEBUG_LEVEL=' "$MOUNTSCRIPT")"
eval "$(grep -m1 '^stunnel_timeout_idle=' "$MOUNTSCRIPT")"
APPNAME=aznfs
eval "$(grep -m1 '^STUNNELPIDDIR=' "$COMMON")"

if [[ "$STUNNELPIDDIR" == /run/* ]]; then
    pass "STUNNELPIDDIR is $STUNNELPIDDIR"
else
    fail "STUNNELPIDDIR is '$STUNNELPIDDIR', expected under /run"
fi

# Stubs for what add_stunnel_configuration() uses from common.sh and the mount script.
chattr() { :; }
vecho() { :; }
eecho() { echo "eecho: $*" >&2; }
get_cert_path_based_and_command() { return 0; }
get_check_host_value() { echo "teststorage.file.core.windows.net"; }
canonicalize_distro_id() { echo "$1"; }

source <(sed -n '/^add_stunnel_configuration()/,/^}$/p' "$MOUNTSCRIPT")
declare -F add_stunnel_configuration > /dev/null || { fail "add_stunnel_configuration() not found in $MOUNTSCRIPT"; exit 1; }

USER_CAFILE=$STUNNEL_CAFILE
LOCALHOST=127.0.0.1
nfs_host=teststorage.file.core.windows.net
isRedHat=0
# Nothing listens on port 1, connections are accepted and then fail to connect.
CONNECT_PORT=1
AZNFS_FIPS_CURVES=P-256:P-384:P-521

free_port()
{
    local p i
    for i in $(seq 50); do
        p=$((40000 + RANDOM % 20000))
        if ! (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; then
            echo $p
            return 0
        fi
    done
    return 1
}

#
# Generate a stunnel config the way nfsv4mountscript.sh does.
# $1: name of this run, $2: AZNFS_LOGDIR (empty for syslog).
#
generate_config()
{
    AZNFS_LOGDIR=$2
    STUNNEL_LOG_FILE_DIR="${AZNFS_LOGDIR:-$TEST_DIR/$1/default-logs}"
    STUNNELPIDDIR="$TEST_DIR/$1/run"
    stunnel_conf_file="$TEST_DIR/$1/stunnel.conf"
    available_port=$(free_port) || return 1

    mkdir -p "$STUNNELPIDDIR" "$STUNNEL_LOG_FILE_DIR"
    : > "$stunnel_conf_file"
    add_stunnel_configuration 127.0.0.1
}

#
# Start stunnel with the generated config, make one connection, and print the
# pid of the stunnel daemon.
#
run_stunnel()
{
    local conf=$1
    local pid_file=$(sed -n 's/^pid = //p' "$conf")
    local port=$(sed -n 's/^accept = .*://p' "$conf")
    local out i

    out=$("$STUNNEL" "$conf" 2>&1)
    [ -n "$out" ] && echo "stunnel: $out" >&2

    for i in $(seq 50); do
        [ -s "$pid_file" ] && break
        sleep 0.1
    done
    [ -s "$pid_file" ] || return 1

    (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null
    cat "$pid_file"
}

# Print syslog lines of process $1 since $2.
syslog_lines()
{
    if [ "$SYSLOG_READER" == "journal" ]; then
        journalctl -q --no-pager --since "$2" _PID="$1"
    else
        grep "stunnel\[$1\]" "$SYSLOG_READER"
    fi
}

#
# Syslog mode.
#
if ! generate_config syslog ""; then
    fail "syslog mode: add_stunnel_configuration() failed"
else
    conf="$TEST_DIR/syslog/stunnel.conf"

    if grep -q '^output' "$conf"; then
        fail "syslog mode: config has '$(grep '^output' "$conf")'"
    else
        pass "syslog mode: config has no 'output ='"
    fi

    if grep -qx "pid = $TEST_DIR/syslog/run/stunnel_127.0.0.1.pid" "$conf"; then
        pass "syslog mode: pid file is under STUNNELPIDDIR"
    else
        fail "syslog mode: unexpected '$(grep '^pid' "$conf")'"
    fi

    if grep -qx "debug = $DEBUG_LEVEL" "$conf"; then
        pass "syslog mode: config has 'debug = $DEBUG_LEVEL'"
    else
        fail "syslog mode: config has '$(grep '^debug' "$conf")'"
    fi

    since=$(date '+%Y-%m-%d %H:%M:%S')
    if ! daemon_pid=$(run_stunnel "$conf"); then
        fail "syslog mode: stunnel did not start"
    else
        STUNNEL_PIDS+=("$daemon_pid")
        found=
        for i in $(seq 50); do
            syslog_lines "$daemon_pid" "$since" | grep -q 'accepted connection' && found=1 && break
            sleep 0.2
        done

        if [ -n "$found" ]; then
            pass "syslog mode: stunnel logged the connection to syslog"
        else
            fail "syslog mode: no 'accepted connection' from stunnel[$daemon_pid] in syslog"
        fi

        if [ -z "$(ls -A "$TEST_DIR/syslog/default-logs")" ]; then
            pass "syslog mode: no stunnel log file created"
        else
            fail "syslog mode: log file created: $(ls -A "$TEST_DIR/syslog/default-logs")"
        fi
    fi
fi

#
# File mode, the control: same config but with AZNFS_LOGDIR set.
#
if ! generate_config file "$TEST_DIR/file/logdir"; then
    fail "file mode: add_stunnel_configuration() failed"
else
    conf="$TEST_DIR/file/stunnel.conf"
    log_file="$TEST_DIR/file/logdir/stunnel_127.0.0.1.log"

    if grep -qx "output = $log_file" "$conf"; then
        pass "file mode: config has 'output = <AZNFS_LOGDIR>/stunnel_<ip>.log'"
    else
        fail "file mode: unexpected '$(grep '^output' "$conf")'"
    fi

    if ! daemon_pid=$(run_stunnel "$conf"); then
        fail "file mode: stunnel did not start"
    else
        STUNNEL_PIDS+=("$daemon_pid")
        found=
        for i in $(seq 50); do
            grep -q 'accepted connection' "$log_file" 2>/dev/null && found=1 && break
            sleep 0.2
        done

        if [ -n "$found" ]; then
            pass "file mode: stunnel logged the connection to $log_file"
        else
            fail "file mode: no 'accepted connection' in $log_file"
        fi
    fi
fi

[ $FAILED -eq 0 ] && echo "All tests passed." || echo "Some tests failed."
exit $FAILED
