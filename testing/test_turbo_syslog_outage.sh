#!/bin/bash

#
# Unit test: Turbo client output piped to syslog survives a syslog outage.
#
# Runs turbo_syslog() from src/nfsv3mountscript.sh against a private syslog
# socket, removes the socket mid-stream (f.e. journald restart) and brings it
# back, then checks that:
# - writing into the pipe never fails (the reader stays alive),
# - lines sent after the socket is back reach syslog again.
#
# Needs python3 for the test syslog socket. Exits 0 on success, 1 on failure,
# 77 if it cannot run here.
#

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
MOUNTSCRIPT="$REPO_DIR/src/nfsv3mountscript.sh"

TEST_DIR=$(mktemp -d)
SOCK="$TEST_DIR/syslog.sock"
RECEIVED="$TEST_DIR/received"
FAILED=0
SERVER_PID=

cleanup_test()
{
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    [ -n "$LOGGER_FD" ] && exec {LOGGER_FD}>&-
    rm -rf "$TEST_DIR"
}
trap cleanup_test EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }
skip() { echo "SKIP: $*"; exit 77; }

command -v logger &> /dev/null || skip "logger is not installed"
command -v python3 &> /dev/null || skip "python3 is not installed"

# Without --socket-errors logger(1) logs via glibc syslog() to /dev/log only, a private socket can't be used.
logger --help 2>&1 | grep -q -- '--socket-errors' || skip "logger has no --socket-errors (util-linux < 2.26)"

source <(sed -n '/^turbo_syslog()/,/^}$/p' "$MOUNTSCRIPT")
declare -F turbo_syslog > /dev/null || { fail "turbo_syslog() not found in $MOUNTSCRIPT"; exit 1; }
TURBO_SYSLOG_TAG=aznfsclient_test

start_syslog()
{
    python3 - "$SOCK" "$RECEIVED" <<'EOF' &
import os, socket, sys
path, out = sys.argv[1], sys.argv[2]
try:
    os.unlink(path)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(path)
with open(out, "a") as f:
    while True:
        f.write(s.recv(65536).decode(errors="replace") + "\n")
        f.flush()
EOF
    SERVER_PID=$!
    for i in $(seq 50); do
        [ -S "$SOCK" ] && return 0
        sleep 0.1
    done
    return 1
}

stop_syslog()
{
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    SERVER_PID=
    rm -f "$SOCK"
}

wait_received()
{
    for i in $(seq 50); do
        grep -q "$1" "$RECEIVED" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# Like aznfsclient, a write into a pipe whose reader died fails with EPIPE.
send()
{
    printf '%s\n' "$@" >&$LOGGER_FD
}

trap '' PIPE
start_syslog || { fail "test syslog socket did not come up"; exit 1; }
exec {LOGGER_FD}> >(turbo_syslog -u "$SOCK" 2>/dev/null)

send before-1 before-2 && wait_received before-2
check_before=$?
[ $check_before -eq 0 ] && pass "lines reach syslog" || fail "lines did not reach syslog before the outage"

stop_syslog
writes_ok=1
send during-1 during-2 || writes_ok=
sleep 0.5
for i in 1 2 3; do
    send "after-outage-$i" || { writes_ok=; break; }
    sleep 0.2
done

if [ -n "$writes_ok" ]; then
    pass "writes kept succeeding while syslog was down"
else
    fail "writes failed while syslog was down (reader gone, EPIPE)"
fi

start_syslog || { fail "test syslog socket did not come back"; exit 1; }
recovered=
for i in $(seq 10); do
    send "recovered-$i" || break
    wait_received "recovered-" && recovered=1 && break
done

if [ -n "$recovered" ]; then
    pass "lines reach syslog again after it came back"
else
    fail "no line reached syslog after it came back"
fi

if grep -q "aznfsclient_test" "$RECEIVED" 2>/dev/null; then
    pass "lines are tagged with TURBO_SYSLOG_TAG"
else
    fail "lines not tagged with TURBO_SYSLOG_TAG"
fi

[ $FAILED -eq 0 ] && echo "All tests passed." || echo "Some tests failed."
exit $FAILED
