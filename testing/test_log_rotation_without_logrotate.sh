#!/bin/bash

#
# Unit test for rotate_logs_without_logrotate() in lib/common.sh, the rotation
# the watchdogs do where logrotate is not installed (f.e. the AKS CSI driver
# image). Runs the real function with a small size limit and a PATH without
# logrotate. Exits 0 on success, 1 on failure.
#

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
COMMON="$REPO_DIR/lib/common.sh"

TEST_DIR=$(mktemp -d)
FAILED=0

cleanup_test()
{
    [ -n "$WRITER_FD" ] && exec {WRITER_FD}>&-
    rm -rf "$TEST_DIR"
}
trap cleanup_test EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }
check() { local desc=$1; shift; if "$@"; then pass "$desc"; else fail "$desc"; fi; }

source <(sed -n '/^rotate_logs_without_logrotate()/,/^}$/p' "$COMMON")
declare -F rotate_logs_without_logrotate > /dev/null || { fail "rotate_logs_without_logrotate() not found in $COMMON"; exit 1; }

# Only the tools the function needs, so logrotate (and optionally gzip) are not found.
make_path()
{
    local dir=$TEST_DIR/bin-$1 t
    mkdir -p "$dir"
    for t in stat rm mv cp flock "${@:2}"; do
        ln -sf "$(command -v "$t")" "$dir/$t"
    done
    echo "$dir"
}
PATH_GZIP=$(make_path gzip gzip)
PATH_NOGZIP=$(make_path nogzip)

APPNAME=aznfs
OPTDIRDATA=$TEST_DIR/opt
AZNFS_LOGDIR=$TEST_DIR/logs
LOG_ROTATE_SIZE=1000
LOG_ROTATE_KEEP=7
LOG_ROTATE_CHECK_SECS=300
mkdir -p "$OPTDIRDATA" "$AZNFS_LOGDIR"
LOG=$AZNFS_LOGDIR/aznfs.log

grow() { head -c "$2" /dev/zero | tr '\0' "$3" > "$1"; }
rotate() { NEXT_LOG_ROTATE_CHECK=0; PATH=$1 rotate_logs_without_logrotate; }

# Small files are left alone.
grow "$LOG" 500 a
rotate "$PATH_GZIP"
check "file below the size limit not rotated" test ! -e "$LOG.1" -a "$(stat -c %s "$LOG")" -eq 500

# Past the limit: copied to .1, emptied in place (same inode, writers keep their fd).
grow "$LOG" 1500 b
inode=$(stat -c %i "$LOG")
rotate "$PATH_GZIP"
check "rotated to aznfs.log.1" test "$(stat -c %s "$LOG.1" 2>/dev/null)" -eq 1500
check "aznfs.log truncated in place" test "$(stat -c %s "$LOG")" -eq 0 -a "$(stat -c %i "$LOG")" -eq "$inode"

# An O_APPEND writer (like stunnel and aznfsclient) continues at the start, no sparse gap.
exec {WRITER_FD}>>"$AZNFS_LOGDIR/stunnel_10.0.0.1.log"
grow "$AZNFS_LOGDIR/stunnel_10.0.0.1.log" 1200 s
rotate "$PATH_GZIP"
printf 'after rotation\n' >&$WRITER_FD
check "stunnel log rotated" test -s "$AZNFS_LOGDIR/stunnel_10.0.0.1.log.1"
check "O_APPEND writer continues at the start of the truncated file" \
    test "$(cat "$AZNFS_LOGDIR/stunnel_10.0.0.1.log")" == "after rotation"

# Keeps LOG_ROTATE_KEEP files, newest uncompressed, older ones gzipped, oldest dropped.
for i in 1 2 3 4 5 6 7 8 9; do
    grow "$LOG" 1100 "$i"
    rotate "$PATH_GZIP"
done
check "aznfs.log.1 is the newest rotation, uncompressed" test "$(head -c1 "$LOG.1")" == 9
check "aznfs.log.2 .. .7 are gzipped" test -s "$LOG.2.gz" -a -s "$LOG.7.gz" -a ! -e "$LOG.2"
check "aznfs.log.7.gz is the oldest kept rotation" test "$(gzip -dc "$LOG.7.gz" | head -c1)" == 3
check "no more than 7 rotations kept" test ! -e "$LOG.8" -a ! -e "$LOG.8.gz"

# Without gzip the rotated files are kept uncompressed.
rm -f "$LOG".*
for i in 1 2; do
    grow "$LOG" 1100 "$i"
    rotate "$PATH_NOGZIP"
done
check "without gzip older rotations stay uncompressed" test -s "$LOG.2" -a ! -e "$LOG.2.gz"

# A symlink in the log dir is never followed.
rm -f "$LOG".*
grow "$TEST_DIR/target" 2000 t
rm -f "$LOG"
ln -s "$TEST_DIR/target" "$LOG"
rotate "$PATH_GZIP"
check "symlinked log file not rotated or truncated" test ! -e "$LOG.1" -a "$(stat -c %s "$TEST_DIR/target")" -eq 2000
rm -f "$LOG"

# Checked at most every LOG_ROTATE_CHECK_SECS.
grow "$LOG" 1500 c
NEXT_LOG_ROTATE_CHECK=$((SECONDS + 300))
PATH=$PATH_GZIP rotate_logs_without_logrotate
check "not checked again before LOG_ROTATE_CHECK_SECS" test "$(stat -c %s "$LOG")" -eq 1500

# Left to logrotate where it is installed.
ln -sf /bin/true "$PATH_GZIP/logrotate"
rotate "$PATH_GZIP"
check "skipped when logrotate is installed" test "$(stat -c %s "$LOG")" -eq 1500
rm -f "$PATH_GZIP/logrotate"

# Nothing to do while logging to syslog.
AZNFS_LOGDIR= rotate "$PATH_GZIP"
check "skipped while logging to syslog" test "$(stat -c %s "$LOG")" -eq 1500

[ $FAILED -eq 0 ] && echo "All tests passed." || echo "Some tests failed."
exit $FAILED
