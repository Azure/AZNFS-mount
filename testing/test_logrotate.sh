#!/bin/bash

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

#
# Unit tests for the configurable log directory (AZNFS_LOGDIR) and the logrotate
# config generation done by lib/common.sh and the package maintainer scripts.
#
# These tests run fully sandboxed: they neither need root nor a real mount, and
# they never touch the real /opt/microsoft/aznfs or /etc/logrotate.d.
#
# Usage: ./testing/test_logrotate.sh
#

SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
E2E="$SOURCE_DIR/testing/test_logrotate_e2e.sh"

#
# Required rather than skipped around. Several sections are guarded by a
# "command -v logrotate" and their cases would simply not run without it,
# which the test count floor at the end reports as missing tests. The E2E
# already refuses to run without it, and the package depends on it.
#
if ! command -v logrotate >/dev/null 2>&1; then
    echo "logrotate is not installed, cannot run the rotation tests."
    echo "Install it and re-run: apt install logrotate / dnf install logrotate"
    exit 1
fi

#
# Not under /tmp. The rule being tested refuses a log directory with a world
# writable ancestor, and /tmp is exactly that, so a sandbox there would fail
# every path resolution test for a reason that has nothing to do with the case
# under test. HOME is owned by whoever runs this and is not world writable.
#
# Checked before anything is derived from it. An empty SANDBOX would make ROOT
# "/root", and setup_sandbox would then be removing and recreating a real home
# directory instead of staying inside the sandbox.
#
# Under "sudo -E" HOME can still be the unprivileged caller's home, which they
# could replace between setup and the root operations below. Root resolves its
# own home from passwd instead, and refuses a parent it does not own.
#
if [ "$(id -u)" == "0" ]; then
    SANDBOX_HOME=$(getent passwd root 2>/dev/null | cut -d: -f6)
    SANDBOX_HOME=${SANDBOX_HOME:-/root}

    if [ "$(stat -c %u "$SANDBOX_HOME" 2>/dev/null)" != "0" ]; then
        echo "Refusing to sandbox under '$SANDBOX_HOME', it is not root owned."
        exit 1
    fi
else
    SANDBOX_HOME=${HOME:-/root}
fi

SANDBOX=$(mktemp -d "${SANDBOX_HOME}/.aznfs-logrotate-test.XXXXXX") || exit 1

if [ -z "$SANDBOX" -o ! -d "$SANDBOX" ]; then
    echo "Not able to create a sandbox directory, aborting."
    exit 1
fi

chmod 0755 "$SANDBOX" || exit 1

trap 'rm -rf "$SANDBOX"' EXIT

#
# Matches root's environment, which is what the scripts actually run under.
# Without it the sandbox directories come out group writable and are correctly
# rejected by the log directory safety check.
#
umask 022

PASS=0
FAIL=0
SKIP=0
FAILED_TESTS=()

RED="\e[2;31m"
GREEN="\e[2;32m"
NORMAL="\e[0m"

cleanup()
{
    chmod -R u+w "$SANDBOX" 2>/dev/null
    rm -rf "$SANDBOX"
}
trap cleanup EXIT

#
# Assertion helpers.
#
ok()
{
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NORMAL}: $1"
}

#
# A handful of cases rely on permission bits keeping the caller out, which does
# not hold for root. Report them rather than dropping them silently, so a root
# run is not mistaken for full coverage.
#
skipped()
{
    SKIP=$((SKIP + 1))
    echo "  SKIP: $1 (${2:-running as root})"
}

nok()
{
    FAIL=$((FAIL + 1))
    FAILED_TESTS+=("$1")
    echo -e "  ${RED}FAIL${NORMAL}: $1"
    [ -n "$2" ] && echo "        expected: $2"
    [ -n "$3" ] && echo "        actual:   $3"
}

assert_eq()
{
    local desc="$1" expected="$2" actual="$3"

    if [ "$expected" == "$actual" ]; then
        ok "$desc"
    else
        nok "$desc" "$expected" "$actual"
    fi
}

assert_contains()
{
    local desc="$1" needle="$2" file="$3"

    if [ -f "$file" ] && grep -qF -- "$needle" "$file"; then
        ok "$desc"
    else
        nok "$desc" "file containing '$needle'" "$(cat "$file" 2>/dev/null | head -3)"
    fi
}

#
# Build a sandboxed copy of common.sh with OPTDIR and the logrotate config path
# redirected into the sandbox, so we can exercise it as an unprivileged user.
#
ROOT="$SANDBOX/root"
COMMON="$SANDBOX/common_test.sh"
CONFIG="$ROOT/opt/microsoft/aznfs/data/config"
LRCONF="$ROOT/etc/logrotate.d/aznfs"

setup_sandbox()
{
    rm -rf "$ROOT"
    mkdir -p "$ROOT/opt/microsoft/aznfs/data" "$ROOT/etc/logrotate.d"
    cp "$SOURCE_DIR/src/aznfs.logrotate" "$ROOT/opt/microsoft/aznfs/"

    #
    # create_mountmap_file() runs 'chattr +i' on a freshly created mountmap,
    # which needs root and would abort common.sh. Pre-create the files so that
    # code path is skipped and we can test the logging logic unprivileged.
    #
    touch "$ROOT/opt/microsoft/aznfs/data/mountmap" \
          "$ROOT/opt/microsoft/aznfs/data/mountmapv4"

    sed -e "s#^OPTDIR=\"/opt/microsoft/\${APPNAME}\"#OPTDIR=\"$ROOT/opt/microsoft/\${APPNAME}\"#" \
        -e "s#^LOGROTATE_CONFIG=\"/etc/logrotate.d/\${APPNAME}\"#LOGROTATE_CONFIG=\"$ROOT/etc/logrotate.d/\${APPNAME}\"#" \
        "$SOURCE_DIR/lib/common.sh" > "$COMMON"
}

#
# Source the sandboxed common.sh and echo the resolved value of the given
# variable. Extra env assignments can be passed as "VAR=value" arguments.
#
# Note: common.sh closes all inherited fds > 2 on the way out, which also closes
#       the fd bash uses to restore a redirected stdout. So the value is written
#       to a file (opened after sourcing) rather than echoed to stdout.
#
resolve()
{
    local var="$1"; shift
    local out="$SANDBOX/resolve.out"

    rm -f "$out"
    env AZNFS_VERSION=3 "$@" bash -c \
        ". '$COMMON'; printf '%s' \"\${$var}\" > '$out'" >/dev/null 2>&1
    cat "$out" 2>/dev/null
}

#
# logrotate refuses "su root root" when not run as root, and when it *is* run
# as root it refuses a config that is group or other writable. The default
# umask here is 0002, so the mode has to be normalized as well for the suite to
# behave the same for both kinds of user.
#
make_conf()
{
    local dest="$1"

    grep -v "su root root" "$LRCONF" > "$dest"
    chmod 0644 "$dest"
}

write_config()
{
    printf '%s\n' "$@" > "$CONFIG"
}

echo "=============================================="
echo " AZNFS log directory / logrotate unit tests"
echo "=============================================="

# ---------------------------------------------------------------------------
echo
echo "[1] Log directory resolution"
# ---------------------------------------------------------------------------

setup_sandbox
assert_eq "no config file -> default log dir" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$(resolve LOGFILE)"

setup_sandbox
write_config "AUTO_UPDATE_AZNFS=false"
assert_eq "config without AZNFS_LOGDIR -> default" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$(resolve LOGFILE)"

setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/varlog"
assert_eq "config sets log dir" \
    "$SANDBOX/varlog/aznfs.log" "$(resolve LOGFILE)"

setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/varlog"
assert_eq "env var overrides config" \
    "$SANDBOX/envlog/aznfs.log" "$(resolve LOGFILE AZNFS_LOGDIR=$SANDBOX/envlog)"

setup_sandbox
write_config "#AZNFS_LOGDIR=$SANDBOX/commented"
assert_eq "commented-out setting is ignored" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$(resolve LOGFILE)"

setup_sandbox
write_config "   AZNFS_LOGDIR   =   $SANDBOX/spaced   "
assert_eq "whitespace around key/value tolerated" \
    "$SANDBOX/spaced/aznfs.log" "$(resolve LOGFILE)"

setup_sandbox
write_config "AZNFS_LOGDIR=\"$SANDBOX/quoted\""
assert_eq "double-quoted value tolerated" \
    "$SANDBOX/quoted/aznfs.log" "$(resolve LOGFILE)"

setup_sandbox
write_config "AZNFS_LOGDIR='$SANDBOX/squoted'"
assert_eq "single-quoted value tolerated" \
    "$SANDBOX/squoted/aznfs.log" "$(resolve LOGFILE)"

setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/first" "AZNFS_LOGDIR=$SANDBOX/second"
assert_eq "duplicate keys -> last one wins" \
    "$SANDBOX/second/aznfs.log" "$(resolve LOGFILE)"

setup_sandbox
write_config "AZNFS_LOGDIR="
assert_eq "empty value -> falls back to default" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$(resolve LOGFILE)"

setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/trailing/"
assert_eq "trailing slash does not produce a double slash" \
    "$SANDBOX/trailing/aznfs.log" "$(resolve LOGFILE)"

setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/multi///"
assert_eq "multiple trailing slashes stripped" \
    "$SANDBOX/multi/aznfs.log" "$(resolve LOGFILE)"

setup_sandbox
assert_eq "trailing slash stripped from env var too" \
    "$SANDBOX/envtrail/aznfs.log" "$(resolve LOGFILE AZNFS_LOGDIR=$SANDBOX/envtrail/)"

#
# A path written with and without a trailing slash must be treated as the same
# directory, otherwise the logrotate config would be needlessly regenerated and
# the admin's local rotation policy silently discarded.
#
setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/samedir"
resolve LOGFILE >/dev/null
echo "# admin tweak" >> "$LRCONF"
write_config "AZNFS_LOGDIR=$SANDBOX/samedir/"
resolve LOGFILE >/dev/null
assert_eq "trailing-slash variant does not discard local policy edits" \
    "# admin tweak" "$(tail -n1 "$LRCONF")"

setup_sandbox
write_config "AZNFS_LOGDIR=/proc/cannot/create/here"
assert_eq "uncreatable dir -> falls back to default" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$(resolve LOGFILE)"

#
# An invalid value in the config file must not stop a valid per-invocation
# override from being used, the env variable documents as taking precedence.
#
setup_sandbox
write_config "AZNFS_LOGDIR=/bad path/from/config"
assert_eq "invalid config + valid env override -> env override wins" \
    "$SANDBOX/goodenv/aznfs.log" "$(resolve LOGFILE "AZNFS_LOGDIR=$SANDBOX/goodenv")"

setup_sandbox
write_config "AZNFS_LOGDIR=/bad path/from/config"
resolve LOGFILE >/dev/null
assert_contains "invalid config still falls back in the rotation config" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$LRCONF"

setup_sandbox
write_config "AZNFS_LOGDIR=/bad path/from/config"
resolve LOGFILE "AZNFS_LOGDIR=$SANDBOX/goodenv" >/dev/null
if grep -qF -- "$SANDBOX/goodenv/aznfs.log" "$LRCONF" 2>/dev/null; then
    nok "env override still not written into the rotation config" \
        "config on the default dir" "config follows the env override"
else
    ok "env override still not written into the rotation config"
fi

# ---------------------------------------------------------------------------
echo
echo "[1b] Rejected log directory values (must fall back, never fail a mount)"
# ---------------------------------------------------------------------------

#
# The log directory is substituted into LOGROTATE_CONFIG with sed and used in
# logrotate glob patterns, so characters like '&', '|', '*' and whitespace
# would produce a corrupt config or match unrelated files. A relative path
# would put logs somewhere that depends on the caller's cwd. All of these must
# be rejected in favour of the default directory.
#
# Every unsafe character is rejected by the same check, so only the ones with a
# distinct failure mode are covered here rather than one case per character.
#
DEFAULT_LOG="$ROOT/opt/microsoft/aznfs/data/aznfs.log"

reject_case()
{
    local desc="$1" value="$2"

    setup_sandbox
    write_config "AZNFS_LOGDIR=$value"
    assert_eq "$desc" "$DEFAULT_LOG" "$(resolve LOGFILE)"
}

# '&' is the "whole match" reference in a sed replacement.
reject_case "ampersand in path rejected"        "$SANDBOX/a&b"
# '|' is the delimiter used in the sed expressions.
reject_case "pipe in path rejected"             "$SANDBOX/a|b"
# '*' would turn the log path into a glob matching unrelated files.
reject_case "glob '*' in path rejected"         "$SANDBOX/a*b"
# A shell metacharacter, standing in for the rest of the unsafe set.
reject_case "shell metacharacter rejected"      "$SANDBOX/a\$b"
# Would otherwise be silently truncated at the space.
reject_case "embedded space rejected (not truncated)" "$SANDBOX/my logs"
reject_case "relative path rejected"            "relative/dir"
reject_case "root directory rejected"           "/"

setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/ok-dir_1.2@x+y"
assert_eq "path with safe punctuation accepted" \
    "$SANDBOX/ok-dir_1.2@x+y/aznfs.log" "$(resolve LOGFILE)"

#
# An existing but non-writable directory must fall back too. Previously this
# got past the mkdir check and then failed the mount outright.
#
# Permission bits alone do not keep root out, so skip this case when running
# as root rather than asserting something that cannot hold.
if [ "$(id -u)" -ne 0 ]; then
    setup_sandbox
    mkdir -p "$SANDBOX/nowrite"
    chmod a-w "$SANDBOX/nowrite"
    write_config "AZNFS_LOGDIR=$SANDBOX/nowrite"
    assert_eq "existing non-writable dir -> falls back" "$DEFAULT_LOG" "$(resolve LOGFILE)"

    rc=$(env AZNFS_VERSION=3 bash -c ". '$COMMON'" >/dev/null 2>&1; echo $?)
    assert_eq "existing non-writable dir -> mount not failed" "0" "$rc"
else
    skipped "existing non-writable dir -> falls back"
    skipped "existing non-writable dir -> mount not failed"
fi
chmod u+w "$SANDBOX/nowrite"

setup_sandbox
: > "$SANDBOX/isafile"
write_config "AZNFS_LOGDIR=$SANDBOX/isafile"
assert_eq "path that is a file -> falls back" "$DEFAULT_LOG" "$(resolve LOGFILE)"

#
# A rejected value must not leak into the generated logrotate config either.
#
setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/a&b"
resolve LOGFILE >/dev/null
if grep -q "PLACEHOLDER" "$LRCONF" 2>/dev/null; then
    nok "rejected value does not corrupt the config" "no placeholder left" "placeholder present"
else
    ok "rejected value does not corrupt the config"
fi
assert_contains "rejected value: config uses the default dir" "$DEFAULT_LOG" "$LRCONF"

# ---------------------------------------------------------------------------
echo
echo "[1c] Config file parsing edge cases"
# ---------------------------------------------------------------------------

setup_sandbox
printf 'AZNFS_LOGDIR=%s\r\n' "$SANDBOX/crlf" > "$CONFIG"
assert_eq "CRLF line endings tolerated" "$SANDBOX/crlf/aznfs.log" "$(resolve LOGFILE)"

setup_sandbox
printf 'AZNFS_LOGDIR=%s' "$SANDBOX/nonl" > "$CONFIG"          # no trailing newline
assert_eq "missing trailing newline tolerated" "$SANDBOX/nonl/aznfs.log" "$(resolve LOGFILE)"

setup_sandbox
write_config "MY_AZNFS_LOGDIR=$SANDBOX/wrong"
assert_eq "key as substring does not match" "$DEFAULT_LOG" "$(resolve LOGFILE)"

setup_sandbox
write_config "AZNFS_LOGDIR_EXTRA=$SANDBOX/wrong"
assert_eq "key with suffix does not match" "$DEFAULT_LOG" "$(resolve LOGFILE)"

setup_sandbox
printf '\tAZNFS_LOGDIR\t=\t%s\n' "$SANDBOX/tabbed" > "$CONFIG"
assert_eq "tab separated key/value tolerated" "$SANDBOX/tabbed/aznfs.log" "$(resolve LOGFILE)"

setup_sandbox
write_config "AUTO_UPDATE_AZNFS=true" "AZNFS_LOGDIR=$SANDBOX/among" "SOMETHING_ELSE=1"
assert_eq "setting found among other settings" "$SANDBOX/among/aznfs.log" "$(resolve LOGFILE)"

setup_sandbox
rm -f "$CONFIG"
mkdir -p "$CONFIG"                                            # config path is a directory
assert_eq "config path being a directory does not break logging" \
    "$DEFAULT_LOG" "$(resolve LOGFILE)"
rmdir "$CONFIG"

setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/created/nested/deep"
resolve LOGFILE >/dev/null
if [ -d "$SANDBOX/created/nested/deep" ]; then
    ok "missing log dir is created (including parents)"
else
    nok "missing log dir is created (including parents)" "directory exists" "missing"
fi

# ---------------------------------------------------------------------------
echo
echo "[2] Turbo log dir (AZNFSC_LOGDIR) inheritance"
# ---------------------------------------------------------------------------

resolve_turbo()
{
    local out="$SANDBOX/turbo.out"

    local snippet="$SANDBOX/turbo_snippet.sh"

    #
    # Run the real block out of nfsv3mountscript.sh rather than a copy of it,
    # so that this keeps testing the shipped logic.
    #
    {
        echo "AZNFS_VERSION=3"
        echo ". '$COMMON'"
        sed -n '/^# Directory where the turbo log file/,/^AZNFSC_LOGDIR="\$(normalize_dir "\${AZNFSC_LOGDIR:-/p' \
            "$SOURCE_DIR/src/nfsv3mountscript.sh"
        echo "printf '%s' \"\$AZNFSC_LOGDIR\" > '$out'"
    } > "$snippet"

    rm -f "$out"
    env "$@" bash "$snippet" >/dev/null 2>&1
    cat "$out" 2>/dev/null
}

setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/varlog"
assert_eq "turbo log dir inherits AZNFS_LOGDIR" \
    "$SANDBOX/varlog" "$(resolve_turbo)"

setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/varlog"
assert_eq "AZNFSC_LOGDIR env still overrides (back-compat)" \
    "$SANDBOX/turbo" "$(resolve_turbo AZNFSC_LOGDIR=$SANDBOX/turbo)"

#
# A syntactically valid but unusable turbo directory must fall back as well,
# otherwise it is only caught by the touch in create_aznfsclient_mount_args,
# which fails the mount instead.
#
setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/varlog"
assert_eq "uncreatable AZNFSC_LOGDIR falls back to AZNFS_LOGDIR" \
    "$SANDBOX/varlog" "$(resolve_turbo "AZNFSC_LOGDIR=/proc/nope/nope")"

if [ "$(id -u)" -ne 0 ]; then
    setup_sandbox
    mkdir -p "$SANDBOX/turbo-ro"
    chmod 0555 "$SANDBOX/turbo-ro"
    write_config "AZNFS_LOGDIR=$SANDBOX/varlog"
    assert_eq "unwritable AZNFSC_LOGDIR falls back to AZNFS_LOGDIR" \
        "$SANDBOX/varlog" "$(resolve_turbo "AZNFSC_LOGDIR=$SANDBOX/turbo-ro")"
    chmod 0755 "$SANDBOX/turbo-ro"
else
    skipped "unwritable AZNFSC_LOGDIR falls back to AZNFS_LOGDIR"
fi

#
# AZNFSC_LOGDIR reaches unquoted expansions in create_aznfsclient_mount_args,
# where whitespace word splits and glob characters expand, so it has to go
# through the same validation AZNFS_LOGDIR does instead of being trusted.
#
for bad in "$SANDBOX/tur bo" "$SANDBOX/tur*bo" "relative/turbo" "/"; do
    setup_sandbox
    write_config "AZNFS_LOGDIR=$SANDBOX/varlog"
    assert_eq "unsafe AZNFSC_LOGDIR '$bad' falls back to AZNFS_LOGDIR" \
        "$SANDBOX/varlog" "$(resolve_turbo "AZNFSC_LOGDIR=$bad")"
done

setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/varlog"
assert_eq "trailing slash on AZNFSC_LOGDIR is normalized" \
    "$SANDBOX/turbo" "$(resolve_turbo "AZNFSC_LOGDIR=$SANDBOX/turbo/")"

#
# A valid per-invocation override must not hide an unusable configured
# directory. Rotation follows the configured directory, so if it is never
# probed the policy ends up rotating a path nothing can write to, while the
# default that later invocations fall back to is left uncovered.
#
setup_sandbox
write_config "AZNFS_LOGDIR=/proc/nope/nope"
assert_eq "valid override still logs to the override" \
    "$SANDBOX/override/aznfs.log" "$(resolve LOGFILE AZNFS_LOGDIR=$SANDBOX/override)"
assert_contains "unusable configured dir is not rotated behind a valid override" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$LRCONF"
if grep -q "/proc/nope/nope" "$LRCONF"; then
    nok "unusable configured dir absent from policy" "absent" "still rotated"
else
    ok "unusable configured dir absent from policy"
fi

if [ "$(id -u)" -ne 0 ]; then
    setup_sandbox
    mkdir -p "$SANDBOX/cfg-ro"
    chmod 0555 "$SANDBOX/cfg-ro"
    write_config "AZNFS_LOGDIR=$SANDBOX/cfg-ro"
    resolve LOGFILE AZNFS_LOGDIR=$SANDBOX/override >/dev/null
    if grep -q "$SANDBOX/cfg-ro/aznfs.log" "$LRCONF"; then
        nok "unwritable configured dir absent from policy" "absent" "still rotated"
    else
        ok "unwritable configured dir absent from policy"
    fi
    chmod 0755 "$SANDBOX/cfg-ro"
else
    skipped "unwritable configured dir absent from policy"
fi

#
# Probing a directory must not leave the probe file behind. The turbo path
# probes with the default name rather than a real log file, so that is where a
# missing cleanup would show up as a stray dotfile.
#
setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/varlog"
resolve_turbo "AZNFSC_LOGDIR=$SANDBOX/turbo-probed" >/dev/null
leftover=$(ls -A "$SANDBOX/turbo-probed" 2>/dev/null | wc -l)
assert_eq "probe file is not left behind" "0" "$leftover"

#
# The probe must never use a real log file name. Probing with one races with
# another mount or watchdog starting at the same time: it can create and open
# the log between the existence check and the cleanup, and the probe would then
# unlink a log that is being actively written.
#
setup_sandbox
mkdir -p "$SANDBOX/live" "$SANDBOX/varlog"
echo "live history" > "$SANDBOX/live/aznfs.log"
echo "turbo history" > "$SANDBOX/live/turbo_mnt.log"
write_config "AZNFS_LOGDIR=$SANDBOX/live"
resolve LOGFILE AZNFS_LOGDIR=$SANDBOX/override >/dev/null
assert_eq "probing the configured dir keeps its live log" \
    "live history" "$(cat "$SANDBOX/live/aznfs.log" 2>/dev/null)"

setup_sandbox
mkdir -p "$SANDBOX/turbo-live"
echo "turbo history" > "$SANDBOX/turbo-live/aznfs.log"
write_config "AZNFS_LOGDIR=$SANDBOX/varlog"
resolve_turbo "AZNFSC_LOGDIR=$SANDBOX/turbo-live" >/dev/null
assert_eq "probing the turbo dir keeps an existing log" \
    "turbo history" "$(cat "$SANDBOX/turbo-live/aznfs.log" 2>/dev/null)"

#
# common.sh is sourced as root from the setuid mount path. If the configured
# directory is writable by others, a fixed probe name lets an unprivileged user
# pre-create a symlink there and have root write through it. mktemp creates
# with O_EXCL under an unpredictable name, so it refuses an existing symlink.
#
if grep -q 'probe=$(mktemp "${dir}/.aznfs-logdir-probe' "$COMMON"; then
    ok "probe is created with mktemp, not a predictable name"
else
    nok "probe is created with mktemp, not a predictable name" \
        "mktemp under an unpredictable name" "a guessable name"
fi

if grep -qE '^\s*touch "\$probe"' "$COMMON"; then
    nok "probe does not touch a guessable path" "no touch on a fixed probe" "still touched"
else
    ok "probe does not touch a guessable path"
fi

#
# The logs are written as root and the turbo client holds its log open with
# ">>", which cannot be made to refuse a symlink, so the directory itself has
# to be one that only its owner can put files into.
#
setup_sandbox
mkdir -p "$SANDBOX/grpw"
chmod 0775 "$SANDBOX/grpw"
write_config "AZNFS_LOGDIR=$SANDBOX/grpw"
assert_eq "group writable log dir -> falls back" "$DEFAULT_LOG" "$(resolve LOGFILE)"

setup_sandbox
mkdir -p "$SANDBOX/othw"
chmod 0757 "$SANDBOX/othw"
write_config "AZNFS_LOGDIR=$SANDBOX/othw"
assert_eq "world writable log dir -> falls back" "$DEFAULT_LOG" "$(resolve LOGFILE)"

setup_sandbox
mkdir -p "$SANDBOX/sticky"
chmod 1777 "$SANDBOX/sticky"
write_config "AZNFS_LOGDIR=$SANDBOX/sticky"
assert_eq "sticky world writable log dir -> falls back (/tmp style)" \
    "$DEFAULT_LOG" "$(resolve LOGFILE)"

setup_sandbox
mkdir -p "$SANDBOX/safe"
chmod 0755 "$SANDBOX/safe"
write_config "AZNFS_LOGDIR=$SANDBOX/safe"
assert_eq "own, non group writable log dir is accepted" \
    "$SANDBOX/safe/aznfs.log" "$(resolve LOGFILE)"

#
# The whole chain matters, not just the final directory. A safe log directory
# under a parent others can write to can be renamed away and replaced.
#
setup_sandbox
mkdir -p "$SANDBOX/openparent/logs"
chmod 0777 "$SANDBOX/openparent"
chmod 0755 "$SANDBOX/openparent/logs"
write_config "AZNFS_LOGDIR=$SANDBOX/openparent/logs"
assert_eq "safe dir under a writable parent -> falls back" \
    "$DEFAULT_LOG" "$(resolve LOGFILE)"

#
# Sticky is not accepted either. It protects entries that already exist, so it
# cannot help with a component that does not exist yet: whoever can write to
# the directory creates it first, and mkdir -p would then follow or trust it.
# Refusing world writable ancestors outright is what removes that race.
#
#
# A system group owned parent is how distros ship the obvious destination:
# /var/log is root:syslog 0775 on Debian and Ubuntu. Refusing it would make
# AZNFS_LOGDIR=/var/log/aznfs, the value the README recommends, silently fall
# back to the default. Every other sandbox path here is 0755 all the way up,
# so nothing else in this suite would notice.
#
setup_sandbox
mkdir -p "$SANDBOX/sysgrp/logs"
chmod 0775 "$SANDBOX/sysgrp"
chmod 0755 "$SANDBOX/sysgrp/logs"

# Any group we are in with gid < 1000 has the same shape as /var/log's syslog.
sysgrp=$(id -Gn | tr ' ' '\n' | grep -x -m1 -E 'root|syslog')

# Running as root we can chgrp to it directly, which is the only way to cover
# the accept path on a box whose login user is in neither group.
if [ -z "$sysgrp" ] && [ "$(id -u)" == "0" ]; then
    getent group syslog >/dev/null 2>&1 && sysgrp=syslog || sysgrp=root
fi

if [ -n "$sysgrp" ] && chgrp "$sysgrp" "$SANDBOX/sysgrp" 2>/dev/null; then
    write_config "AZNFS_LOGDIR=$SANDBOX/sysgrp/logs"
    assert_eq "group writable parent owned by a system group is accepted" \
        "$SANDBOX/sysgrp/logs/aznfs.log" "$(resolve LOGFILE)"
else
    SKIP=$((SKIP + 1))
    echo "  SKIP: group writable parent owned by a system group (no system group available)"
fi

#
# The same parent owned by a group real users can be in is not acceptable: a
# member could create the log directory, or a symlink in its place, first.
#
setup_sandbox
mkdir -p "$SANDBOX/usergrp/logs"
chmod 0775 "$SANDBOX/usergrp"
chmod 0755 "$SANDBOX/usergrp/logs"

#
# Set explicitly rather than inherited: under sudo the caller's primary group
# is root, which the rule allows, so an inherited group would have this assert
# a premise that is not true instead of a real fallback.
#
usergrp=$(id -Gn | tr ' ' '\n' | grep -vx -E 'root|syslog' | head -1)
[ -z "$usergrp" ] && usergrp=$(getent group | cut -d: -f1 | grep -vx -E 'root|syslog' | head -1)

if [ -n "$usergrp" ] && chgrp "$usergrp" "$SANDBOX/usergrp" 2>/dev/null; then
    write_config "AZNFS_LOGDIR=$SANDBOX/usergrp/logs"
    assert_eq "group writable parent owned by a user group -> falls back" \
        "$DEFAULT_LOG" "$(resolve LOGFILE)"
else
    skipped "group writable parent owned by a user group -> falls back" \
        "no non-allowlisted group available"
fi

#
# A low numbered gid is not by itself a reason to trust a group: GID ranges are
# configurable and ordinary groups such as "users" sit at 100 on many distros.
# Only the named groups distros use for log directories are accepted, so a
# sub-1000 group that is not one of them has to be refused.
#
notallowed=$(id -Gn | tr ' ' '\n' | grep -vx -E 'root|syslog' | while read -r g; do
    gid=$(getent group "$g" | cut -d: -f3)
    [ -n "$gid" ] && [ "$gid" -lt 1000 ] && { echo "$g"; break; }
done)

if [ -n "$notallowed" ]; then
    setup_sandbox
    mkdir -p "$SANDBOX/lowgid/logs"
    chmod 0755 "$SANDBOX/lowgid/logs"
    chgrp "$notallowed" "$SANDBOX/lowgid" && chmod 0775 "$SANDBOX/lowgid"
    write_config "AZNFS_LOGDIR=$SANDBOX/lowgid/logs"
    assert_eq "sub-1000 group that is not allowlisted ('$notallowed') -> falls back" \
        "$DEFAULT_LOG" "$(resolve LOGFILE)"
else
    SKIP=$((SKIP + 1))
    echo "  SKIP: sub-1000 non-allowlisted group (none available)"
fi

#
# Group writable is never acceptable for the log directory itself, whoever
# owns it, since the log is created inside it.
#
setup_sandbox
mkdir -p "$SANDBOX/grpdir"
chmod 0775 "$SANDBOX/grpdir"
[ -n "$sysgrp" ] && chgrp "$sysgrp" "$SANDBOX/grpdir" 2>/dev/null
write_config "AZNFS_LOGDIR=$SANDBOX/grpdir"
assert_eq "group writable log directory itself -> falls back" \
    "$DEFAULT_LOG" "$(resolve LOGFILE)"

setup_sandbox
mkdir -p "$SANDBOX/stickyparent/logs"
chmod 1777 "$SANDBOX/stickyparent"
chmod 0755 "$SANDBOX/stickyparent/logs"
write_config "AZNFS_LOGDIR=$SANDBOX/stickyparent/logs"
assert_eq "safe dir under a sticky writable parent -> falls back" \
    "$DEFAULT_LOG" "$(resolve LOGFILE)"

#
# The same, but with the parent owned by a system group, so the gid rule above
# cannot be what rejects it. Without this the world writable rule is not
# isolated by any test: every other world writable fixture here also has a user
# owned group, and would be refused for that reason instead.
#
setup_sandbox
mkdir -p "$SANDBOX/wwsys/logs"
chmod 0755 "$SANDBOX/wwsys/logs"
if [ -n "$sysgrp" ] && chgrp "$sysgrp" "$SANDBOX/wwsys" 2>/dev/null && chmod 1777 "$SANDBOX/wwsys"; then
    write_config "AZNFS_LOGDIR=$SANDBOX/wwsys/logs"
    assert_eq "world writable parent -> falls back even for a system group" \
        "$DEFAULT_LOG" "$(resolve LOGFILE)"
else
    SKIP=$((SKIP + 1))
    echo "  SKIP: world writable parent owned by a system group (no system group available)"
fi

#
# The race the sticky carve out used to leave open: the log directory does not
# exist yet, so a local user can create it, or a symlink in its place, in the
# window before we do. Refusing the world writable ancestor closes it without
# having to win the race.
#
setup_sandbox
mkdir -p "$SANDBOX/racy"
chmod 1777 "$SANDBOX/racy"
write_config "AZNFS_LOGDIR=$SANDBOX/racy/notyet"
assert_eq "missing dir under a sticky writable parent -> falls back" \
    "$DEFAULT_LOG" "$(resolve LOGFILE)"

if [ -e "$SANDBOX/racy/notyet" ]; then
    nok "nothing is created under a world writable parent" \
        "no directory created" "the directory was created anyway"
else
    ok "nothing is created under a world writable parent"
fi

#
# The /tmp/aznfs -> /etc escape, the one case sticky does not cover: the link
# is theirs and was created before ours. Its target is root owned and passes
# every check, so following it would have root create and append to a log
# inside the target directory.
#
setup_sandbox
mkdir -p "$SANDBOX/sticky" "$SANDBOX/linktarget"
chmod 1777 "$SANDBOX/sticky"
chmod 0755 "$SANDBOX/linktarget"
ln -sfn "$SANDBOX/linktarget" "$SANDBOX/sticky/aznfs"
write_config "AZNFS_LOGDIR=$SANDBOX/sticky/aznfs"
assert_eq "symlink planted in a sticky parent -> falls back" \
    "$DEFAULT_LOG" "$(resolve LOGFILE)"

if [ -e "$SANDBOX/linktarget/aznfs.log" ]; then
    nok "nothing is created inside the symlink target" "no aznfs.log" "aznfs.log was created"
else
    ok "nothing is created inside the symlink target"
fi

#
# The same link, but with the log directory below it so that it does not exist
# yet. mkdir -p follows the link, so creating first and checking afterwards
# would have root create directories inside the target even though the path is
# then correctly rejected.
#
setup_sandbox
mkdir -p "$SANDBOX/sticky2" "$SANDBOX/linktarget2"
chmod 1777 "$SANDBOX/sticky2"
chmod 0755 "$SANDBOX/linktarget2"
ln -sfn "$SANDBOX/linktarget2" "$SANDBOX/sticky2/link"
write_config "AZNFS_LOGDIR=$SANDBOX/sticky2/link/new"
assert_eq "log dir below a planted symlink -> falls back" \
    "$DEFAULT_LOG" "$(resolve LOGFILE)"

if [ -e "$SANDBOX/linktarget2/new" ]; then
    nok "nothing is created through a planted symlink" \
        "target untouched" "root created a directory inside the target"
else
    ok "nothing is created through a planted symlink"
fi

#
# The safety check has to run before the write probe: probing an unvalidated
# directory is itself a root write into a path somebody else may control. The
# probe removes itself, so this leaves nothing to observe afterwards and is
# pinned by inspection instead.
#
usable_body=$(sed -n '/^usable_logdir()/,/^}/p' "$COMMON")
safe_at=$(printf '%s\n' "$usable_body" | grep -n 'safe_logdir "$dir"' | head -1 | cut -d: -f1)
mkdir_at=$(printf '%s\n' "$usable_body" | grep -n 'mkdir "$dir"' | head -1 | cut -d: -f1)
probe_at=$(printf '%s\n' "$usable_body" | grep -n 'aznfs-logdir-probe' | head -1 | cut -d: -f1)

if [ -n "$safe_at" ] && [ -n "$probe_at" ] && [ "$safe_at" -lt "$probe_at" ]; then
    ok "log dir is validated before anything is created in it"
else
    nok "log dir is validated before anything is created in it" \
        "safe_logdir before the probe" "probe runs first"
fi

if [ -n "$safe_at" ] && [ -n "$mkdir_at" ] && [ "$safe_at" -lt "$mkdir_at" ]; then
    ok "log dir is validated before it is created"
else
    nok "log dir is validated before it is created" \
        "safe_logdir before mkdir -p" "mkdir runs first"
fi

#
# And again afterwards, since the components we create did not exist to be
# checked the first time.
#
if [ "$(printf '%s\n' "$usable_body" | grep -c 'safe_logdir "$dir"')" -ge 2 ]; then
    ok "log dir is revalidated after it is created"
else
    nok "log dir is revalidated after it is created" "two safe_logdir calls" "only one"
fi

#
# A symlink is never accepted as the log directory or as any component of it,
# whatever it points at. Following one would mean trusting a path somebody else
# may have created.
#
setup_sandbox
mkdir -p "$SANDBOX/target-unsafe"
chmod 0777 "$SANDBOX/target-unsafe"
ln -sfn "$SANDBOX/target-unsafe" "$SANDBOX/link-unsafe"
write_config "AZNFS_LOGDIR=$SANDBOX/link-unsafe"
assert_eq "symlink to an unsafe dir -> falls back" "$DEFAULT_LOG" "$(resolve LOGFILE)"

setup_sandbox
mkdir -p "$SANDBOX/target-safe"
chmod 0755 "$SANDBOX/target-safe"
ln -sfn "$SANDBOX/target-safe" "$SANDBOX/link-safe"
write_config "AZNFS_LOGDIR=$SANDBOX/link-safe"
assert_eq "symlink to a safe dir -> falls back too" "$DEFAULT_LOG" "$(resolve LOGFILE)"

#
# A trailing slash must not smuggle a symlink past the check: "test -L link/"
# is false, because the slash forces the kernel to resolve the link, so the
# same directory written two ways has to reach the same decision. safe_logdir
# is called directly here: every caller normalizes first, so going through one
# would strip the slash before the guard ever saw it and the test could not
# fail.
#
setup_sandbox
mkdir -p "$SANDBOX/slashtarget"
chmod 0755 "$SANDBOX/slashtarget"
ln -sfn "$SANDBOX/slashtarget" "$SANDBOX/slashlink"

slash_check()
{
    timeout 10 bash -c "eval \"\$(sed -n '/^safe_logdir()/,/^}/p' '$SOURCE_DIR/lib/common.sh')\"; safe_logdir '$1'" >/dev/null 2>&1
}

slash_check "$SANDBOX/slashtarget" && slash_rc=accept || slash_rc=reject
assert_eq "safe_logdir accepts the plain target dir" "accept" "$slash_rc"

slash_check "$SANDBOX/slashlink" && slash_rc=accept || slash_rc=reject
assert_eq "safe_logdir rejects a symlinked dir" "reject" "$slash_rc"

slash_check "$SANDBOX/slashlink/" && slash_rc=accept || slash_rc=reject
assert_eq "safe_logdir rejects it with a trailing slash too" "reject" "$slash_rc"

#
# The fallback log file is not exempt from the symlink rule. Nothing upstream
# has checked it, it runs as root, and the append would follow the link.
#
# The link goes at the fallback itself: a link in the *chosen* directory is
# already caught by usable_logdir, so planting it there would exercise that
# check instead of this one and the test could not fail.
setup_sandbox
write_config "AZNFS_LOGDIR=relative/not-absolute"
mkdir -p "$(dirname "$DEFAULT_LOG")"
ln -sfn "$SANDBOX/elsewhere" "$DEFAULT_LOG"

fb_out=$(env AZNFS_VERSION=3 bash -c ". '$COMMON'; echo REACHED" 2>&1)
if printf '%s' "$fb_out" | grep -q "REACHED"; then
    nok "symlinked log in the chosen dir is fatal" "refused" "kept going"
else
    ok "symlinked log in the chosen dir is fatal"
fi

if printf '%s' "$fb_out" | grep -q "symlink, refusing to log through it"; then
    ok "symlinked log is refused by name"
else
    nok "symlinked log is refused by name" "a symlink diagnostic" "$fb_out"
fi

if [ -e "$SANDBOX/elsewhere" ]; then
    nok "symlinked log target is never created" "no file" "a file was created"
else
    ok "symlinked log target is never created"
fi

#
# The same refusal, but pointed at a file that already exists. The case above
# cannot catch a write through the link: _log opens $LOGFILE for reading with
# 999<, which fails on a dangling link, so the append never happens. With a
# real target the redirect succeeds and a diagnostic sent through eecho would
# append root owned lines to it, which is precisely what the guard exists to
# prevent.
#
setup_sandbox
write_config "AZNFS_LOGDIR=relative/not-absolute"
mkdir -p "$(dirname "$DEFAULT_LOG")"
printf 'untouched\n' > "$SANDBOX/linkvictim"
ln -sfn "$SANDBOX/linkvictim" "$DEFAULT_LOG"

env AZNFS_VERSION=3 bash -c ". '$COMMON'; echo REACHED" >"$SANDBOX/linkvictim.out" 2>&1

assert_eq "refusing a symlinked log leaves its target untouched" \
    "untouched" "$(cat "$SANDBOX/linkvictim")"

if grep -q "No such file or directory" "$SANDBOX/linkvictim.out"; then
    nok "refusal reports cleanly, without a raw shell error" "a clean diagnostic" \
        "$(cat "$SANDBOX/linkvictim.out")"
else
    ok "refusal reports cleanly, without a raw shell error"
fi

#
# Warning about a rejected configured directory must not run before the log
# file exists: _log opens $LOGFILE with 999<, so the warning would be preceded
# by a raw shell error on the caller's terminal. Reached when the environment
# override is usable but the configured directory is not.
#
setup_sandbox
mkdir -p "$SANDBOX/envgood" "$SANDBOX/cfgbad"
chmod 0755 "$SANDBOX/envgood"
chmod 0777 "$SANDBOX/cfgbad"
write_config "AZNFS_LOGDIR=$SANDBOX/cfgbad"

warn_out=$(env AZNFS_VERSION=3 AZNFS_LOGDIR="$SANDBOX/envgood" \
    bash -c ". '$COMMON'; true" 2>&1)

if printf '%s' "$warn_out" | grep -q "No such file or directory"; then
    nok "warning about a bad configured dir does not leak a shell error" \
        "a clean warning" "$warn_out"
else
    ok "warning about a bad configured dir does not leak a shell error"
fi

if printf '%s' "$warn_out" | grep -q "Not able to use configured log directory"; then
    ok "the bad configured dir is still reported"
else
    nok "the bad configured dir is still reported" "a warning naming it" "$warn_out"
fi

#
# The README has to name the groups the code actually allows. "a system group"
# described a rule that does not exist: root:daemon is a system group and is
# rejected. Derived from the case arm so the two cannot drift.
#
allowed_groups=$(sed -n 's/^ *\([a-z|]*\)) ;;$/\1/p' "$COMMON" | head -1)

if [ -z "$allowed_groups" ]; then
    nok "README names the groups the code allows" "a group allowlist in common.sh" "none found"
else
    missing=""
    for g in $(printf '%s' "$allowed_groups" | tr '|' ' '); do
        grep -q "\`$g\`" "$SOURCE_DIR/README.md" || missing="${missing} $g"
    done

    if [ -n "$missing" ]; then
        nok "README names the groups the code allows" "$allowed_groups" "missing:${missing}"
    else
        ok "README names the groups the code allows"
    fi
fi

if grep -q "when the group is a system group" "$SOURCE_DIR/README.md"; then
    nok "README does not overstate the group rule" \
        "the two group names" "the broader claim 'a system group'"
else
    ok "README does not overstate the group rule"
fi

#
# The e2e unmounts its mount point before every mount, as root, so a mistyped
# target would take down a live system path. usage_check() has to refuse those
# before do_mount() ever sees them.
#
e2e_mp_check()
{
    {
        echo "OPTDIR=/nonexistent-optdir"
        echo "NFS_SHARE=host:/export"
        echo "MOUNT_POINT='$1'"
        sed -n '/^usage_check()/,/^}/p' "$E2E"
        echo 'id() { echo 0; }'
        echo 'usage_check'
    } > "$SANDBOX/e2e_mp.sh"

    bash "$SANDBOX/e2e_mp.sh" 2>&1 | head -1
}

setup_sandbox
mp_bad=""
for mp in / // /home /var /usr /etc /boot /tmp /mnt relative/path; do
    case "$(e2e_mp_check "$mp")" in
        *"Refusing"*|*"absolute path"*) ;;
        *) mp_bad="${mp_bad} ${mp}" ;;
    esac
done

if [ -n "$mp_bad" ]; then
    nok "e2e refuses dangerous mount points" "all refused" "accepted:${mp_bad}"
else
    ok "e2e refuses dangerous mount points"
fi

#
# ... without refusing a legitimate target, or the guard would just break the
# test rather than protect it.
#
case "$(e2e_mp_check "$SANDBOX/e2e-target")" in
    *"Refusing"*|*"absolute path"*)
        nok "e2e still accepts a normal mount point" "accepted" "refused" ;;
    *)
        ok "e2e still accepts a normal mount point" ;;
esac

#
# A Turbo mount is served by aznfsclient over FUSE, so findmnt reports
# fuse.aznfsclient, not nfs. The first version of the guard above allowed only
# nfs/nfs4/aznfs and refused the live Turbo mount point, which is the one the
# Turbo assertions need. Found by running against a real v3 Turbo share, since
# nothing sandboxed here knows what a real mount reports.
#
for fstype in nfs nfs4 aznfs fuse.aznfsclient; do
    if sed -n '/^usage_check()/,/^}/p' "$E2E" | grep -q "|${fstype})\||${fstype}|\|${fstype}|"; then
        ok "e2e mount point guard accepts $fstype"
    else
        nok "e2e mount point guard accepts $fstype" "$fstype in the allowlist" "missing"
    fi
done

#
# "/." and "/var/log/.." name directories the literal "/" case cannot see, so
# they would reach safe_logdir as ordinary paths and put the log, and the
# rotation policy, at the filesystem root.
#
for d in "/." "/.." "//." "/var/log/.." "/a/./b" "/opt/../tmp"; do
    setup_sandbox
    write_config "AZNFS_LOGDIR=$d"
    got=$(resolve LOGFILE)
    if [ "$got" == "$DEFAULT_LOG" ]; then
        ok "dotted path '$d' falls back to the default"
    else
        nok "dotted path '$d' falls back to the default" "$DEFAULT_LOG" "$got"
    fi
done

#
# ... while a directory whose name merely contains a dot is still usable.
#
setup_sandbox
mkdir -p "$SANDBOX/my.app/logs"
chmod 0755 "$SANDBOX/my.app" "$SANDBOX/my.app/logs"
write_config "AZNFS_LOGDIR=$SANDBOX/my.app/logs"
assert_eq "a dot inside a directory name is still accepted" \
    "$SANDBOX/my.app/logs/aznfs.log" "$(resolve LOGFILE)"

#
# All four copies have to refuse them, not just the runtime one.
#
for f in "$SOURCE_DIR/lib/common.sh" \
         "$SOURCE_DIR/packaging/aznfs/DEBIAN/postinst" \
         "$SOURCE_DIR/packaging/aznfs/RPM/aznfs.spec" \
         "$SOURCE_DIR/scripts/aznfs_install.sh"; do
    if grep -q '\*/\.\./\*|\*/\./\*)' "$f"; then
        ok "$(basename $f): refuses . and .. components"
    else
        nok "$(basename $f): refuses . and .. components" \
            "a */../*|*/./* case" "missing, so /. reaches the log directory rule"
    fi
done

#
# A run that aborts before deploying must not leave its backup behind. This is
# how 35 root owned backup directories accumulated on the test machine.
#
if sed -n '/if \[ ! -f "$BACKUP\/.deploying" \]; then/,/fi/p' "$E2E" |
   grep -qF 'rm -rf "$BACKUP"'; then
    ok "e2e removes its backup when no deployment began"
else
    nok "e2e removes its backup when no deployment began" \
        "rm -rf \$BACKUP inside the not-deploying branch" "backup is kept forever"
fi

#
# The turbo lookup has to use the directory in force after set_logdir "",
# not the one captured at backup time, or it silently skips on any machine
# with a custom log directory configured.
#
if grep -q 'turbo_log=$(ls -1 "$CONFIGURED_LOGDIR"' "$E2E"; then
    nok "e2e looks for the turbo log in the active directory" \
        "\$OPTDIRDATA" "\$CONFIGURED_LOGDIR, which is stale after set_logdir \"\""
else
    ok "e2e looks for the turbo log in the active directory"
fi

#
# The mount point guard has the same exposure the log directory rule had:
# "/var/log/.." passes the denylist and then resolves to /var when umount and
# mkdir act on it.
#
for mp in "/var/log/.." "/mnt/x/./y" "/opt/../tmp"; do
    case "$(e2e_mp_check "$mp")" in
        *"'.' or '..'"*|*"Refusing"*)
            ok "e2e refuses a mount point containing '$mp'" ;;
        *)
            nok "e2e refuses a mount point containing '$mp'" "refused" "accepted" ;;
    esac
done

#
# restore_logs must not delete a live log that appeared while the test ran: a
# concurrent mount or the watchdog can create one, and it is not this test's
# to remove. Only numbered rotation artefacts are attributable.
#
if sed -n '/^restore_logs()/,/^}/p' "$E2E" | grep -q '\*\.log\.\[0-9\]\*'; then
    ok "e2e only deletes numbered rotations on cleanup"
else
    nok "e2e only deletes numbered rotations on cleanup" \
        "a *.log.[0-9]* case" "every unbacked-up match is removed, including live logs"
fi

#
# The mount point component walk must not word split. "${mp//\// }" unquoted
# turns "/safe dir/target" into unrelated tokens and walks neither, so a
# symlinked component goes unexamined on exactly the paths that need checking.
#
if grep -q 'for mp_part in \${mp//' "$E2E"; then
    nok "e2e walks mount point components without word splitting" \
        "IFS=/ with globbing off" "unquoted \${mp//\\// } expansion"
elif grep -q 'IFS=/' "$E2E" && grep -q 'set -f' "$E2E"; then
    ok "e2e walks mount point components without word splitting"
else
    nok "e2e walks mount point components without word splitting" "IFS=/ with globbing off" "neither found"
fi

#
# A rotation restored from the backup is indistinguishable from one the phase
# produced, so both rotation assertions have to start from a clean slate or
# they pass when logrotate did nothing.
#
for fn in "aznfs.log.\[0-9\]\*" "turbo_log}\".\[0-9\]\*"; do
    if grep -q "rm -f .*$fn" "$E2E"; then
        ok "e2e clears prior rotations before asserting ($fn)"
    else
        nok "e2e clears prior rotations before asserting ($fn)" \
            "an rm of stale rotations" "a stale .1 would satisfy the assertion"
    fi
done

#
# ... and an unchanged inode is only evidence of copytruncate if something
# rotated. With nothing rotated it is trivially unchanged.
#
if grep -q 'nothing rotated, so the inode proves nothing' "$E2E"; then
    ok "e2e inode assertion is conditional on a rotation"
else
    nok "e2e inode assertion is conditional on a rotation" \
        "a guard for the no-rotation case" "it would pass when logrotate selected nothing"
fi

#
# mkdir honours the caller's umask. Under 0002 an install time creation lands
# on 0775, which the rule then refuses, so the directory the admin configured
# would be created and immediately rejected. common.sh already chmods; the
# packaging copies had drifted.
#
for f in "$SOURCE_DIR/lib/common.sh" \
         "$SOURCE_DIR/packaging/aznfs/DEBIAN/postinst" \
         "$SOURCE_DIR/packaging/aznfs/RPM/aznfs.spec" \
         "$SOURCE_DIR/scripts/aznfs_install.sh"; do
    #
    # Without -p on the final component: -p succeeds on an entry that already
    # exists, so a symlink planted after the validation above would be followed.
    # Plain mkdir fails with EEXIST instead.
    #
    if grep -qE 'mkdir "\$(logdir|dir|AZNFS_LOGDIR)" 2>/dev/null && chmod 0755' "$f"; then
        ok "$(basename $f): chmods a log directory it creates"
    else
        nok "$(basename $f): chmods a log directory it creates" \
            "mkdir followed by chmod 0755" "umask 0002 would leave it 0775 and self-reject"
    fi

    #
    # Parents with -p, final component without. The fallback to the package's
    # own default still uses -p, and should: it is not in a parent anyone else
    # can write to, and its parents may legitimately be missing.
    #
    if grep -qE 'mkdir -p "\$\(dirname "\$(logdir|dir|AZNFS_LOGDIR)"\)"' "$f"; then
        ok "$(basename $f): creates the final component without -p"
    else
        nok "$(basename $f): creates the final component without -p" \
            "mkdir -p on the parent, plain mkdir on the target" "mkdir -p follows a symlink planted at the target"
    fi

    #
    # The fallback to the default directory creates it too, and was missed when
    # the chmod above was added, so under umask 0002 a fresh install could land
    # on a 0775 default that the runtime check then refuses.
    #
    if ! grep -qE 'mkdir -p "\$(logdir|AZNFS_LOGDIR)"( 2>/dev/null)?$' "$f"; then
        ok "$(basename $f): chmods the fallback directory too"
    else
        nok "$(basename $f): chmods the fallback directory too" \
            "every mkdir paired with a chmod" "$(grep -nE 'mkdir -p "\$(logdir|AZNFS_LOGDIR)"( 2>/dev/null)?$' "$f" | head -1)"
    fi

    #
    # The staged policy file must come from mktemp. A plain redirection takes
    # the caller's umask, and the mount helper is setuid and does not reset it,
    # so under umask 000 root creates a 0666 file on a predictable path that
    # the caller can write logrotate directives into before it is installed.
    #
    if grep -q 'logrotate\.tmp\.\$\$' "$f"; then
        nok "$(basename $f): stages the policy with mktemp" \
            "mktemp" "a predictable .tmp.\$\$ name created by redirection"
    elif grep -q 'mktemp "\$(dirname' "$f" || ! grep -q 'logrotate\.tmp' "$f"; then
        ok "$(basename $f): stages the policy with mktemp"
    else
        nok "$(basename $f): stages the policy with mktemp" "mktemp" "something else"
    fi

    #
    # ... and only one it creates. Re-permissioning a directory the admin made
    # is not this code's business.
    #
    if grep -q '\[ ! -d "\$\(logdir\|dir\|AZNFS_LOGDIR\)" \]' "$f"; then
        ok "$(basename $f): leaves an existing log directory's mode alone"
    else
        nok "$(basename $f): leaves an existing log directory's mode alone" \
            "a [ ! -d ] guard before the chmod" "it would chmod an admin's directory"
    fi
done

#
# The end state of the above: whatever umask the caller had, the installed
# policy is 0644 and the log directory 0755. The mount helper is setuid and
# does not reset umask, so a caller controls it.
#
setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/umask000"
( umask 000; resolve LOGFILE >/dev/null )

if [ -f "$LRCONF" ]; then
    assert_eq "policy mode is 0644 under umask 000" "644" "$(stat -c %a "$LRCONF")"
else
    nok "policy mode is 0644 under umask 000" "a generated policy" "none generated"
fi

if [ -d "$SANDBOX/umask000" ]; then
    assert_eq "log directory mode is 0755 under umask 000" "755" "$(stat -c %a "$SANDBOX/umask000")"
else
    nok "log directory mode is 0755 under umask 000" "a created directory" "none created"
fi

#
# Nothing may be left behind next to the policy: a stray temp file there is
# itself read as a rotation config on the next logrotate run.
#
stray=$(find "$(dirname "$(dirname "$LRCONF")")" -maxdepth 1 -name '.aznfs-logrotate.tmp.*' 2>/dev/null | wc -l)
assert_eq "no staged temp file left behind" "0" "$stray"

#
# The suite depends on logrotate throughout. Skipping around it silently drops
# whole sections, which the floor then reports as missing tests.
#
lr_pre=$(sed -n '/^if ! command -v logrotate/,/^fi$/p' "$0")

if [ -z "$lr_pre" ]; then
    nok "the suite refuses to run without logrotate" \
        "a precondition that exits" "no precondition found at all"
elif printf '%s' "$(PATH= bash -c "$lr_pre"' ; echo REACHED' 2>&1)" | grep -q REACHED; then
    nok "the suite refuses to run without logrotate" \
        "it exits" "execution continued past the precondition"
else
    ok "the suite refuses to run without logrotate"
fi

#
# The e2e's own resolver must validate the default directory too, not just a
# configured one. It runs as root and backs up, rotates and restores through
# whatever it returns, so accepting an unsafe default would mean doing all of
# that through a path somebody else can write to.
#
e2e_logdir_check()
{
    {
        echo "SOURCE_DIR='$SOURCE_DIR'"
        echo "OPTDIRDATA='$1'"
        echo "CONFIG_FILE='$SANDBOX/e2e-cfg'"
        sed -n '/^safe_logdir()$/,/^}$/p' "$COMMON"
        sed -n '/^logdir_is_usable()/,/^}/p;/^installed_logdir()/,/^}/p' "$E2E"
        echo 'if out=$(installed_logdir); then echo "OK:$out"; else echo "ABORT"; fi'
    } > "$SANDBOX/e2e_logdir.sh"

    bash "$SANDBOX/e2e_logdir.sh" 2>/dev/null | tail -1
}

setup_sandbox
: > "$SANDBOX/e2e-cfg"
mkdir -p "$SANDBOX/e2e-safe"
chmod 0755 "$SANDBOX/e2e-safe"
mkdir -p "$SANDBOX/e2e-open"
chmod 0777 "$SANDBOX/e2e-open"

assert_eq "e2e accepts a safe default log directory" \
    "OK:$SANDBOX/e2e-safe" "$(e2e_logdir_check "$SANDBOX/e2e-safe")"

assert_eq "e2e refuses a world writable default" \
    "ABORT" "$(e2e_logdir_check "$SANDBOX/e2e-open")"

ln -sfn "$SANDBOX/e2e-elsewhere" "$SANDBOX/e2e-safe/aznfs.log"
assert_eq "e2e refuses a symlinked log in the default" \
    "ABORT" "$(e2e_logdir_check "$SANDBOX/e2e-safe")"

#
# The turbo log check is fatal, so the README must not promise that a mount
# never fails over a logging setting. The two have to agree: either the code
# stops being fatal or the doc names the exception.
#
turbo_fatal=$(grep -c "Not able to use turbo log '" "$SOURCE_DIR/src/nfsv3mountscript.sh")

if [ "$turbo_fatal" -gt 0 ]; then
    if grep -q "A mount never fails because of a" "$SOURCE_DIR/README.md"; then
        nok "README does not promise mounts never fail over logging" \
            "the turbo exception documented" "an unconditional promise"
    elif grep -q "the mount fails rather than starting" "$SOURCE_DIR/README.md"; then
        ok "README does not promise mounts never fail over logging"
    else
        nok "README does not promise mounts never fail over logging" \
            "the turbo exception documented" "no mention of it"
    fi
else
    skipped "README does not promise mounts never fail over logging"
fi

#
# The log file itself gets the same no-symlink rule as the directory. -w
# follows the link and reports on the target, so a symlink aimed at something
# writable would otherwise be accepted and appended to as root.
#
setup_sandbox
mkdir -p "$SANDBOX/symlog" "$SANDBOX/elsewhere"
chmod 0755 "$SANDBOX/symlog" "$SANDBOX/elsewhere"
: > "$SANDBOX/elsewhere/victim.log"
ln -sfn "$SANDBOX/elsewhere/victim.log" "$SANDBOX/symlog/aznfs.log"
write_config "AZNFS_LOGDIR=$SANDBOX/symlog"
assert_eq "symlinked aznfs.log -> falls back" "$DEFAULT_LOG" "$(resolve LOGFILE)"

if [ -s "$SANDBOX/elsewhere/victim.log" ]; then
    nok "nothing is written through a symlinked log" "victim untouched" "root wrote through the link"
else
    ok "nothing is written through a symlinked log"
fi

#
# The turbo log is fatal rather than a fallback: AZNFSC_LOGDIR defaults to
# AZNFS_LOGDIR, so for most mounts "fall back to AZNFS_LOGDIR" recomputes the
# same path and hands the unusable one straight back to the client.
#
turbo_blk=$(sed -n '/turbo_log="\$AZNFSC_LOGDIR/,/^    fi/p' "$SOURCE_DIR/src/nfsv3mountscript.sh")

if printf '%s\n' "$turbo_blk" | grep -q 'AZNFSC_LOGDIR="\$AZNFS_LOGDIR"'; then
    nok "turbo log problem is fatal, not a no-op fallback" \
        "mount fails" "reassigns AZNFSC_LOGDIR to the same directory"
else
    ok "turbo log problem is fatal, not a no-op fallback"
fi

if printf '%s\n' "$turbo_blk" | grep -q '\[ -L "\$turbo_log" \]'; then
    ok "turbo log is checked for a symlink"
else
    nok "turbo log is checked for a symlink" "-L on turbo_log" "missing"
fi

#
# A dangling link is invisible to -e, which follows it, so the check has to
# test -L on its own or root's touch creates the link's target.
#
setup_sandbox
mkdir -p "$SANDBOX/dangle"
chmod 0755 "$SANDBOX/dangle"
ln -sfn "$SANDBOX/never/created.log" "$SANDBOX/dangle/aznfs.log"
write_config "AZNFS_LOGDIR=$SANDBOX/dangle"
assert_eq "dangling symlinked log -> falls back" "$DEFAULT_LOG" "$(resolve LOGFILE)"

if [ -e "$SANDBOX/never/created.log" ]; then
    nok "a dangling link's target is not created" "target absent" "root created it"
else
    ok "a dangling link's target is not created"
fi

#
# A directory sitting at the log path is writable, so -w alone accepts it while
# the append that follows cannot work.
#
setup_sandbox
mkdir -p "$SANDBOX/dirlog/aznfs.log"
chmod 0755 "$SANDBOX/dirlog" "$SANDBOX/dirlog/aznfs.log"
write_config "AZNFS_LOGDIR=$SANDBOX/dirlog"
assert_eq "directory at the log path -> falls back" "$DEFAULT_LOG" "$(resolve LOGFILE)"

#
# A repeated leading slash must not spin the walk: dirname "//" is "//" on some
# systems, so the loop needs a fixpoint guard rather than only testing for "/".
#
walk_rc=0
timeout 10 bash -c "eval \"\$(sed -n '/^safe_logdir()/,/^}/p' '$SOURCE_DIR/lib/common.sh')\"; safe_logdir '//var/log/aznfs'" >/dev/null 2>&1 || walk_rc=$?
if [ "$walk_rc" == "124" ]; then
    nok "path walk terminates on a repeated leading slash" "terminates" "hangs"
else
    ok "path walk terminates on a repeated leading slash"
fi

if grep -q '\[ "$parent" == "$path" \] && break' "$COMMON"; then
    ok "common.sh walk terminates on a dirname fixpoint"
else
    nok "common.sh walk terminates on a dirname fixpoint" "a fixpoint guard" "only a test for /"
fi

#
# A symlinked component anywhere in the chain, not just the final one.
#
setup_sandbox
mkdir -p "$SANDBOX/safelink" "$SANDBOX/openhost/target"
chmod 0755 "$SANDBOX/safelink" "$SANDBOX/openhost/target"
chmod 0777 "$SANDBOX/openhost"
ln -sfn "$SANDBOX/openhost/target" "$SANDBOX/safelink/logs"
write_config "AZNFS_LOGDIR=$SANDBOX/safelink/logs"
assert_eq "symlink into a writable parent -> falls back" \
    "$DEFAULT_LOG" "$(resolve LOGFILE)"

setup_sandbox
mkdir -p "$SANDBOX/turbo-unsafe"
chmod 0777 "$SANDBOX/turbo-unsafe"
mkdir -p "$SANDBOX/varlog"
write_config "AZNFS_LOGDIR=$SANDBOX/varlog"
assert_eq "world writable AZNFSC_LOGDIR -> falls back" \
    "$SANDBOX/varlog" "$(resolve_turbo "AZNFSC_LOGDIR=$SANDBOX/turbo-unsafe")"

#
# Written with a trailing slash, a symlinked turbo log directory must reach the
# same verdict: "test -L link/" is false, so the value has to be normalized
# before it is validated, not after.
#
setup_sandbox
mkdir -p "$SANDBOX/turbo-target"
chmod 0755 "$SANDBOX/turbo-target"
ln -sfn "$SANDBOX/turbo-target" "$SANDBOX/turbo-link"
mkdir -p "$SANDBOX/varlog"
write_config "AZNFS_LOGDIR=$SANDBOX/varlog"
assert_eq "symlinked AZNFSC_LOGDIR -> falls back" \
    "$SANDBOX/varlog" "$(resolve_turbo "AZNFSC_LOGDIR=$SANDBOX/turbo-link")"
assert_eq "symlinked AZNFSC_LOGDIR with a trailing slash -> falls back" \
    "$SANDBOX/varlog" "$(resolve_turbo "AZNFSC_LOGDIR=$SANDBOX/turbo-link/")"

#
# The same rule has to hold at install time and in the installer, otherwise the
# policy would rotate a directory the runtime refuses to use.
#
#
# The installer has its own copy of the rule, so exercise it rather than only
# grepping for it.
#
run_installer_logdir_snippet()
{
    local snippet="$SANDBOX/installer.sh"

    {
        echo "APPNAME=aznfs"
        echo "OPTDIRDATA='$ROOT/opt/microsoft/aznfs/data'"
        echo "AZNFS_LOGDIR='$1'"
        sed -n '/^aznfs_safe_logdir()/,/^}/p;/^# Only accept an absolute path/,/^touch "\$LOGFILE" 2>\/dev\/null$/p' \
            "$SOURCE_DIR/scripts/aznfs_install.sh"
        echo 'printf "%s" "$LOGFILE"'
    } > "$snippet"

    bash "$snippet" 2>/dev/null
}

setup_sandbox
mkdir -p "$SANDBOX/inst-unsafe"
chmod 0777 "$SANDBOX/inst-unsafe"
assert_eq "installer: world writable log dir falls back" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$(run_installer_logdir_snippet "$SANDBOX/inst-unsafe")"

#
# 0775 and 0757 pin the group and the other check separately, a 0777 directory
# trips both at once and would let either of them be dropped unnoticed.
#
setup_sandbox
mkdir -p "$SANDBOX/inst-grpw"
chmod 0775 "$SANDBOX/inst-grpw"
assert_eq "installer: group writable log dir falls back" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$(run_installer_logdir_snippet "$SANDBOX/inst-grpw")"

setup_sandbox
mkdir -p "$SANDBOX/inst-othw"
chmod 0757 "$SANDBOX/inst-othw"
assert_eq "installer: other writable log dir falls back" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$(run_installer_logdir_snippet "$SANDBOX/inst-othw")"

setup_sandbox
mkdir -p "$SANDBOX/inst-safe"
chmod 0755 "$SANDBOX/inst-safe"
assert_eq "installer: safe log dir is used" \
    "$SANDBOX/inst-safe/aznfs.log" "$(run_installer_logdir_snippet "$SANDBOX/inst-safe")"

#
# The installer's fallback is not exempt either. It runs as root and touch
# follows a link, so a link planted at the default path would have the install
# create a root owned file wherever it points. The link goes at the fallback,
# not in the requested directory, because a link there is already caught by
# the mode rules and the test could not fail.
#
setup_sandbox
mkdir -p "$ROOT/opt/microsoft/aznfs/data"
ln -sfn "$SANDBOX/inst-elsewhere" "$ROOT/opt/microsoft/aznfs/data/aznfs.log"
mkdir -p "$SANDBOX/inst-bad"
chmod 0777 "$SANDBOX/inst-bad"
assert_eq "installer: symlinked fallback log is not written through" \
    "/dev/null" "$(run_installer_logdir_snippet "$SANDBOX/inst-bad")"

if [ -e "$SANDBOX/inst-elsewhere" ]; then
    nok "installer: symlink target is never created" "no file" "a file was created"
else
    ok "installer: symlink target is never created"
fi

for f in "$SOURCE_DIR/packaging/aznfs/DEBIAN/postinst" \
         "$SOURCE_DIR/packaging/aznfs/RPM/aznfs.spec" \
         "$SOURCE_DIR/scripts/aznfs_install.sh"; do
    if grep -q 'mktemp "\${\(AZNFS_\)\?[Ll][Oo][Gg][Dd][Ii][Rr]}/\.aznfs-logdir-probe' "$f" ||
       grep -q 'aznfs-logdir-probe.XXXXXXXX' "$f"; then
        ok "$(basename $f): probes with mktemp, not a known name"
    else
        nok "$(basename $f): probes with mktemp, not a known name" "mktemp probe" "touch on a known name"
    fi

    #
    # The owner half needs a directory belonging to somebody else, which an
    # unprivileged suite cannot create, so it is pinned by inspection. The
    # group and other bits are exercised behaviourally above.
    #
    if grep -q '\[ "$owner" == "0" -o "$owner" == "$me" \] || return 1' "$f"; then
        ok "$(basename $f): rejects a component owned by somebody else"
    else
        nok "$(basename $f): rejects a component owned by somebody else" \
            "owner compared against root and us" "missing"
    fi

    #
    # The whole chain, not just the final directory: a safe log directory under
    # a parent others can write to can be renamed away and replaced.
    #
    if grep -q 'path=$(dirname "$path")' "$f"; then
        ok "$(basename $f): checks every parent component"
    else
        nok "$(basename $f): checks every parent component" \
            "walks up to /" "only the final directory"
    fi

    #
    # The walk must judge a symlink as itself. Following it would accept a link
    # planted at the configured path, since its target is root owned.
    #
    if grep -q "stat -L" "$f"; then
        nok "$(basename $f): does not follow symlinks while walking" \
            "stat without -L" "stat -L"
    else
        ok "$(basename $f): does not follow symlinks while walking"
    fi

    #
    # Canonicalizing first would reintroduce exactly that, the resolved path no
    # longer contains the planted link.
    #
    if grep -q 'readlink -f' "$f"; then
        nok "$(basename $f): does not canonicalize before walking" \
            "walks the path as configured" "readlink -f"
    else
        ok "$(basename $f): does not canonicalize before walking"
    fi

    #
    # Symlinks are also caught by the world writable check, since a link is
    # 0777, so this cannot be exercised behaviourally. It is pinned here
    # because that overlap is the point: without the explicit check, relaxing
    # the mode rules would silently stop rejecting links.
    #
    if grep -q '\[ -L "$path" \] && return 1' "$f"; then
        ok "$(basename $f): rejects symlinks explicitly"
    else
        nok "$(basename $f): rejects symlinks explicitly" \
            "an explicit -L check" "only the implicit 0777 mode check"
    fi

    #
    # The log file too, not just the directory chain: -w follows a link and
    # reports on its target.
    #
    if grep -q '\[ -L "${logdir}/aznfs.log" \]' "$f" ||
       grep -q '\[ -L "${AZNFS_LOGDIR}/${APPNAME}.log" \]' "$f"; then
        ok "$(basename $f): refuses a symlinked log file"
    else
        nok "$(basename $f): refuses a symlinked log file" \
            "-L on the log path" "only -w, which follows the link"
    fi

    #
    # GNU dirname collapses "//" to "/", so the walk terminates here with or
    # without this guard and no behavioural test can tell them apart. Pinned by
    # inspection because the platforms where dirname "//" is "//" are exactly
    # the ones this suite never runs on.
    #
    if grep -q '\[ "$parent" == "$path" \] && break' "$f"; then
        ok "$(basename $f): walk terminates on a dirname fixpoint"
    else
        nok "$(basename $f): walk terminates on a dirname fixpoint" \
            "a fixpoint guard" "only a test for /"
    fi

    #
    # Group writable ancestors owned by a system group have to stay allowed,
    # or /var/log, which is root:syslog 0775, becomes unusable.
    #
    if grep -q 'root|syslog) ;;' "$f"; then
        ok "$(basename $f): names the trusted groups explicitly"
    else
        nok "$(basename $f): names the trusted groups explicitly" \
            "an explicit group allowlist" "a gid threshold, or no allowance"
    fi

    #
    # No sticky carve out. It cannot protect a component that does not exist
    # yet, which is where the mkdir race lived.
    #
    if grep -q 'special' "$f"; then
        nok "$(basename $f): allows no sticky exception" \
            "world writable ancestors refused outright" "a sticky carve out"
    else
        ok "$(basename $f): allows no sticky exception"
    fi

    #
    # Same ordering rule as common.sh, and these run as root too: nothing may
    # be created in the directory before it has been validated.
    #
    f_safe_at=$(grep -n 'aznfs_safe_logdir "' "$f" | head -1 | cut -d: -f1)
    f_mkdir_at=$(grep -n 'mkdir -p "$logdir"\|mkdir -p "$AZNFS_LOGDIR"' "$f" | head -1 | cut -d: -f1)
    f_probe_at=$(grep -n 'aznfs-logdir-probe' "$f" | head -1 | cut -d: -f1)

    if [ -n "$f_safe_at" ] && [ -n "$f_probe_at" ] && [ "$f_safe_at" -lt "$f_probe_at" ] &&
       [ -n "$f_mkdir_at" ] && [ "$f_safe_at" -lt "$f_mkdir_at" ]; then
        ok "$(basename $f): validates before creating anything in the log dir"
    else
        nok "$(basename $f): validates before creating anything in the log dir" \
            "safety check before mkdir and the probe" "creation runs first"
    fi

    if [ "$(grep -c 'aznfs_safe_logdir "' "$f")" -ge 2 ]; then
        ok "$(basename $f): revalidates after creating the log dir"
    else
        nok "$(basename $f): revalidates after creating the log dir" \
            "two aznfs_safe_logdir calls" "only one"
    fi

    if [ "$(grep -c '8#\${' "$f")" -ge 2 ]; then
        ok "$(basename $f): rejects a group or other writable log directory"
    else
        nok "$(basename $f): rejects a group or other writable log directory" \
            "group and other bits checked" "fewer than two checks"
    fi

    #
    # An existing log we cannot append to has to be caught here too, or the
    # policy rotates a path common.sh has already fallen back from.
    #
    if grep -q '\[ ! -w "' "$f"; then
        ok "$(basename $f): rejects an unwritable existing log"
    else
        nok "$(basename $f): rejects an unwritable existing log" \
            "existing log writability checked" "missing"
    fi
done

#
# Behavioural reproduction of the attack. The probing shell reports its own pid
# and then waits, which lets us plant the symlink a pid-derived name would use
# at exactly the right moment, the way an attacker spraying that directory
# would. With a predictable name the victim file gets created; with mktemp the
# name is never guessable and the victim stays absent.
#
setup_sandbox
mkdir -p "$SANDBOX/hostile"
sed -n '/^is_valid_logdir()/,/^}/p;/^usable_logdir()/,/^}/p' "$COMMON" > "$SANDBOX/probefns.sh"

cat > "$SANDBOX/race.sh" <<EOF
echo \$\$ > "$SANDBOX/race.pid"
while [ ! -f "$SANDBOX/race.go" ]; do sleep 0.02; done
. "$SANDBOX/probefns.sh"
usable_logdir "$SANDBOX/hostile"
EOF

bash "$SANDBOX/race.sh" >/dev/null 2>&1 &
race_pid=$!

for _ in $(seq 1 100); do
    [ -s "$SANDBOX/race.pid" ] && break
    sleep 0.02
done

ln -sfn "$SANDBOX/victim" "$SANDBOX/hostile/.aznfs-logdir-probe.$(cat "$SANDBOX/race.pid")"
touch "$SANDBOX/race.go"
wait $race_pid 2>/dev/null

if [ -e "$SANDBOX/victim" ]; then
    nok "a planted probe symlink is not written through" \
        "victim untouched" "root wrote through the planted symlink"
else
    ok "a planted probe symlink is not written through"
fi

#
# An existing log file we cannot append to still makes the directory unusable.
#
if [ "$(id -u)" -ne 0 ]; then
    setup_sandbox
    mkdir -p "$SANDBOX/rolog"
    : > "$SANDBOX/rolog/aznfs.log"
    chmod 0444 "$SANDBOX/rolog/aznfs.log"
    write_config "AZNFS_LOGDIR=$SANDBOX/rolog"
    assert_eq "unwritable existing log file -> falls back" \
        "$DEFAULT_LOG" "$(resolve LOGFILE)"
    chmod 0644 "$SANDBOX/rolog/aznfs.log"
else
    skipped "unwritable existing log file -> falls back"
fi

# ---------------------------------------------------------------------------
echo
echo "[3] logrotate config generation"
# ---------------------------------------------------------------------------

setup_sandbox
resolve LOGFILE >/dev/null
assert_contains "config generated on first run" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$LRCONF"

assert_contains "config covers turbo logs too" \
    "$ROOT/opt/microsoft/aznfs/data/turbo*.log" "$LRCONF"

if ! grep -q "AZNFS_LOGDIR_PLACEHOLDER" "$LRCONF"; then
    ok "placeholder fully substituted"
else
    nok "placeholder fully substituted" "no placeholder" "placeholder still present"
fi

#
# Any placeholder left behind produces a config logrotate cannot parse, so the
# check has to cover every one in the template rather than just the log
# directory.
#
leftover=$(grep -o 'AZNFS_[A-Z]*_PLACEHOLDER' "$LRCONF" | sort -u | tr '\n' ' ')
if [ -z "$leftover" ]; then
    ok "no placeholder of any kind survives substitution"
else
    nok "no placeholder of any kind survives substitution" "none" "$leftover"
fi

# ---------------------------------------------------------------------------
echo
echo "[3a] Rotation policy limits are configurable"
# ---------------------------------------------------------------------------

setup_sandbox
resolve LOGFILE >/dev/null
assert_contains "default size is 100M" "size 100M" "$LRCONF"
assert_contains "default retention is 7" "rotate 7" "$LRCONF"

setup_sandbox
write_config "AZNFS_LOGSIZE=250M" "AZNFS_LOGCOUNT=3"
resolve LOGFILE >/dev/null
assert_contains "configured size is used" "size 250M" "$LRCONF"
assert_contains "configured retention is used" "rotate 3" "$LRCONF"

if grep -qE '^[[:space:]]*size 100M' "$LRCONF"; then
    nok "configured size replaces the default" "only the configured size" "default still present"
else
    ok "configured size replaces the default"
fi

#
# Every suffix logrotate accepts, plus a bare byte count.
#
for sz in 500k 1048576; do
    setup_sandbox
    write_config "AZNFS_LOGSIZE=$sz"
    resolve LOGFILE >/dev/null
    assert_contains "size '$sz' accepted" "size $sz" "$LRCONF"
done

#
# Keeping nothing is a legitimate choice on a small disk, so 0 is allowed.
#
setup_sandbox
write_config "AZNFS_LOGCOUNT=0"
resolve LOGFILE >/dev/null
assert_contains "retention of 0 accepted" "rotate 0" "$LRCONF"

#
# Anything unusable falls back to the default instead of emitting a policy
# logrotate would reject, and never fails the mount.
#
for bad in 0 100X "10 M" 100MB; do
    setup_sandbox
    write_config "AZNFS_LOGSIZE=$bad"
    resolve LOGFILE >/dev/null
    assert_contains "bad size '$bad' falls back to the default" "size 100M" "$LRCONF"
done

for bad in -1 3.5; do
    setup_sandbox
    write_config "AZNFS_LOGCOUNT=$bad"
    resolve LOGFILE >/dev/null
    assert_contains "bad count '$bad' falls back to the default" "rotate 7" "$LRCONF"
done

setup_sandbox
write_config "AZNFS_LOGSIZE=nonsense"
warn_out="$SANDBOX/warn.out"
rm -f "$warn_out"
env AZNFS_VERSION=3 bash -c ". '$COMMON' > '$warn_out' 2>&1" >/dev/null 2>&1

if sed 's/\x1b\[[0-9;]*m//g' "$warn_out" 2>/dev/null | grep -q "AZNFS_LOGSIZE"; then
    ok "a bad size is reported to the user"
else
    nok "a bad size is reported to the user" "warning mentioning AZNFS_LOGSIZE" \
        "$(tail -2 "$warn_out" 2>/dev/null)"
fi

#
# The policy has to be regenerated when the limits change, not only when the
# log directory does, otherwise a changed limit would never take effect.
#
setup_sandbox
write_config "AZNFS_LOGSIZE=100M"
resolve LOGFILE >/dev/null
write_config "AZNFS_LOGSIZE=400M"
resolve LOGFILE >/dev/null
assert_contains "changing the size regenerates the policy" "size 400M" "$LRCONF"

setup_sandbox
write_config "AZNFS_LOGCOUNT=7"
resolve LOGFILE >/dev/null
write_config "AZNFS_LOGCOUNT=2"
resolve LOGFILE >/dev/null
assert_contains "changing the retention regenerates the policy" "rotate 2" "$LRCONF"

#
# ... but an unchanged configuration must still leave a hand edited policy
# alone, which is the whole point of the markers.
#
setup_sandbox
write_config "AZNFS_LOGSIZE=100M"
resolve LOGFILE >/dev/null
echo "# edited by the admin" >> "$LRCONF"
resolve LOGFILE >/dev/null
assert_contains "unchanged config leaves a hand edited policy alone" \
    "# edited by the admin" "$LRCONF"

#
# Every place that describes when the policy is regenerated has to name all
# three inputs. Naming only the log directory understates when a hand edited
# policy is discarded, and that claim went stale once the limits became
# configurable.
#
for f in "$SOURCE_DIR/lib/common.sh" \
         "$SOURCE_DIR/src/aznfs.logrotate" \
         "$SOURCE_DIR/packaging/aznfs/DEBIAN/postinst" \
         "$SOURCE_DIR/packaging/aznfs/RPM/aznfs.spec"; do
    claim=$(grep -n "regenerated only" "$f" | head -1 | cut -d: -f1)

    if [ -z "$claim" ]; then
        nok "$(basename $f): says when the policy is regenerated" "a claim" "none"
        continue
    fi

    blurb=$(sed -n "$((claim > 2 ? claim - 2 : 1)),$((claim + 3))p" "$f")
    missing=
    for k in AZNFS_LOGDIR AZNFS_LOGSIZE AZNFS_LOGCOUNT; do
        printf '%s\n' "$blurb" | grep -q "$k" || missing="$missing $k"
    done

    if [ -z "$missing" ]; then
        ok "$(basename $f): regeneration claim names all three settings"
    else
        nok "$(basename $f): regeneration claim names all three settings" \
            "all three named" "missing:$missing"
    fi
done

#
# The README makes the same claim to users.
#
if grep -q "AZNFS_LOGDIR\`, \`AZNFS_LOGSIZE\` or" "$SOURCE_DIR/README.md"; then
    ok "README regeneration claim names all three settings"
else
    nok "README regeneration claim names all three settings" \
        "all three named" "understates when local edits are lost"
fi

#
# Tarball deployments ship the template but have no maintainer script, so
# nothing renders the policy at install time the way the deb and rpm paths do.
# The guarantee there is that whatever first writes a log also creates the
# policy: common.sh does both in the same run, so a log can never be growing
# without a policy covering it.
#
setup_sandbox
rm -f "$LRCONF"
resolve LOGFILE >/dev/null

if [ -f "$LRCONF" ] && [ -f "$ROOT/opt/microsoft/aznfs/data/aznfs.log" ]; then
    ok "tarball case: first use creates the log and the policy together"
else
    nok "tarball case: first use creates the log and the policy together" "both present" \
        "log=$([ -f "$ROOT/opt/microsoft/aznfs/data/aznfs.log" ] && echo yes || echo no) policy=$([ -f "$LRCONF" ] && echo yes || echo no)"
fi

#
# The deb and rpm copies of the two logrotate functions have to stay byte
# identical. They drifted once already: the deb copy had "|| true" on five
# assignments and the rpm copy did not, which is set -e protection that only
# one of them had.
#
# The rpm copy escapes % as %% and carries a comment saying why, so the two are
# compared after undoing both. Anything else that differs is drift.
for fn in install_logrotate_config aznfs_safe_logdir; do
    if diff <(sed -n "/^${fn}()/,/^}/p" "$SOURCE_DIR/packaging/aznfs/DEBIAN/postinst") \
            <(sed -n "/^${fn}()/,/^}/p" "$SOURCE_DIR/packaging/aznfs/RPM/aznfs.spec" |
              grep -v '^        # %% not %: rpm expands macros' |
              grep -v '^        # named u, G or a would otherwise rewrite' |
              grep -v '^        # collapses %% back to % in the installed' |
              sed 's/%%/%/g') >/dev/null 2>&1; then
        ok "deb and rpm copies of $fn() are identical"
    else
        nok "deb and rpm copies of $fn() are identical" "no drift" "the copies differ"
    fi
done

#
# aznfs_install.sh carries a third copy of aznfs_safe_logdir(). It has no
# install_logrotate_config(), so it is not in the loop above, and it was outside
# the drift guard entirely until a umask fix had to be applied to all three by
# hand. That is the drift this catches.
#
if diff <(sed -n '/^aznfs_safe_logdir()/,/^}/p' "$SOURCE_DIR/packaging/aznfs/DEBIAN/postinst") \
        <(sed -n '/^aznfs_safe_logdir()/,/^}/p' "$SOURCE_DIR/scripts/aznfs_install.sh") >/dev/null 2>&1; then
    ok "aznfs_install.sh copy of aznfs_safe_logdir() is identical"
else
    nok "aznfs_install.sh copy of aznfs_safe_logdir() is identical" "no drift" "the copies differ"
fi

#
# The fourth copy is safe_logdir() in common.sh, the one that decides at mount
# time. Install time and runtime disagreeing is how the installer creates a
# directory the mount then refuses. The two carry different comments, so only
# the code is compared, with the differing function name normalised away.
#
logdir_fn_body()
{
    sed -n "/^$2()/,/^}/p" "$1" |
        grep -vE '^[[:space:]]*#' |
        grep -vE '^[[:space:]]*$' |
        sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e "1s/^$2()/fn()/"
}

if diff <(logdir_fn_body "$SOURCE_DIR/lib/common.sh" safe_logdir) \
        <(logdir_fn_body "$SOURCE_DIR/packaging/aznfs/DEBIAN/postinst" aznfs_safe_logdir) >/dev/null 2>&1; then
    ok "common.sh and packaging log directory checks agree"
else
    nok "common.sh and packaging log directory checks agree" "no drift" "the copies differ"
fi

#
# The install time generators produce the same policy, so they have to
# substitute every placeholder too. A missed one ships a broken config.
#
for f in "$SOURCE_DIR/packaging/aznfs/DEBIAN/postinst" \
         "$SOURCE_DIR/packaging/aznfs/RPM/aznfs.spec"; do
    missing=
    for ph in AZNFS_LOGDIR AZNFS_LOGFILES AZNFS_LOGPOLICY AZNFS_LOGSIZE AZNFS_LOGCOUNT; do
        grep -q "s|${ph}_PLACEHOLDER|" "$f" || missing="$missing ${ph}_PLACEHOLDER"
    done

    if [ -z "$missing" ]; then
        ok "$(basename $f): substitutes every placeholder in the template"
    else
        nok "$(basename $f): substitutes every placeholder in the template" \
            "all placeholders" "missing:$missing"
    fi

    if grep -q 'AZNFS_LOGSIZE\[\[:space:\]\]\*=' "$f"; then
        ok "$(basename $f): reads the limits from the config file"
    else
        nok "$(basename $f): reads the limits from the config file" \
            "AZNFS_LOGSIZE parsed" "not read at install time"
    fi
done

#
# Every placeholder the template defines must be substituted by every
# generator, so the template cannot grow one that only common.sh knows about.
#
for ph in $(grep -o 'AZNFS_[A-Z]*_PLACEHOLDER' "$SOURCE_DIR/src/aznfs.logrotate" | sort -u); do
    if grep -q "s|${ph}|" "$COMMON"; then
        ok "common.sh substitutes $ph"
    else
        nok "common.sh substitutes $ph" "substituted" "left in the generated config"
    fi
done

setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/varlog"
resolve LOGFILE >/dev/null
assert_contains "config follows configured log dir" "$SANDBOX/varlog/aznfs.log" "$LRCONF"

# Idempotency: a local policy edit must survive a re-run.
echo "# local tweak" >> "$LRCONF"
resolve LOGFILE >/dev/null
assert_eq "local edits preserved when dir unchanged" \
    "# local tweak" "$(tail -n1 "$LRCONF")"

# Changing the directory must regenerate (dropping the local edit is expected).
write_config "AZNFS_LOGDIR=$SANDBOX/newlog"
resolve LOGFILE >/dev/null
assert_contains "config regenerated when dir changes" "$SANDBOX/newlog/aznfs.log" "$LRCONF"

# Transient env override must NOT rewrite the system-wide config.
setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/varlog"
resolve LOGFILE >/dev/null
resolve LOGFILE AZNFS_LOGDIR=$SANDBOX/envlog >/dev/null
assert_contains "env override does not rewrite system config" "$SANDBOX/varlog/aznfs.log" "$LRCONF"

#
# An unusable per-invocation override must not cost the configured directory
# its rotation: only the effective log file falls back, the rotation config
# must still cover the directory from the config file.
#
setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/keepme"
resolve LOGFILE >/dev/null

#
# ... and the fallback lands on the configured directory rather than the
# default, since that is the directory the rotation policy covers.
#
assert_eq "bad env override falls back to the configured dir" \
    "$SANDBOX/keepme/aznfs.log" "$(resolve LOGFILE "AZNFS_LOGDIR=$SANDBOX/bad path")"
assert_contains "bad env override keeps the configured dir rotated" \
    "$SANDBOX/keepme/aznfs.log" "$LRCONF"

if grep -qF -- "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$LRCONF"; then
    nok "bad env override does not switch rotation to the default dir" \
        "config still on the configured dir" "config regenerated for the default dir"
else
    ok "bad env override does not switch rotation to the default dir"
fi

#
# ... but when the configured directory itself is unusable, the rotation config
# has to fall back with it.
#
setup_sandbox
write_config "AZNFS_LOGDIR=/proc/cannot/create/here"
resolve LOGFILE >/dev/null
assert_contains "unusable configured dir falls back in the config too" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$LRCONF"

#
# An unwritable log in the configured directory makes it unusable too, and this
# has to be noticed while a valid override is hiding it. The override decides
# where this invocation logs, the configured directory decides what is rotated,
# so probing the latter without the log file would leave the policy on a
# directory every later mount falls back away from, and the log actually being
# written uncovered.
#
# 0444 does not keep root out, so there is no unwritable log to react to.
if [ "$(id -u)" == "0" ]; then
    skipped "unwritable log in the configured dir falls back in the config"
    skipped "rotation does not cover a configured dir with an unwritable log"
else
    setup_sandbox
    mkdir -p "$SANDBOX/cfgro" "$SANDBOX/envok"
    chmod 0755 "$SANDBOX/cfgro" "$SANDBOX/envok"
    : > "$SANDBOX/cfgro/aznfs.log"
    chmod 0444 "$SANDBOX/cfgro/aznfs.log"
    write_config "AZNFS_LOGDIR=$SANDBOX/cfgro"
    resolve LOGFILE "AZNFS_LOGDIR=$SANDBOX/envok" >/dev/null
    assert_contains "unwritable log in the configured dir falls back in the config" \
        "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$LRCONF"

    if grep -qF -- "$SANDBOX/cfgro/aznfs.log" "$LRCONF"; then
        nok "rotation does not cover a configured dir with an unwritable log" \
            "config on the default dir" "config still on the unwritable dir"
    else
        ok "rotation does not cover a configured dir with an unwritable log"
    fi
fi

#
# The rendered config is staged outside /etc/logrotate.d. A temp file left
# there by an interrupted mount is read by logrotate as a config of its own,
# which fails the whole run with a duplicate log entry for every path in it.
#
if grep -q 'tmpfile="${LOGROTATE_CONFIG}.tmp' "$COMMON"; then
    nok "rendered config is staged outside the logrotate config dir" \
        "staged in the parent directory" "staged in /etc/logrotate.d"
else
    ok "rendered config is staged outside the logrotate config dir"
fi

lrconf_dir=$(dirname "$LRCONF")
if compgen -G "$lrconf_dir/*.tmp.*" >/dev/null; then
    nok "no staging file is left in the logrotate config dir" "no temp file" "a temp file remains"
else
    ok "no staging file is left in the logrotate config dir"
fi

# ---------------------------------------------------------------------------
echo
echo "[3b] Log directory changed midway"
# ---------------------------------------------------------------------------

#
# Only the configured directory is rotated. Long running processes keep writing
# to the directory they picked up at startup, which is why the watchdogs must be
# restarted after a change (documented in the README).
#
setup_sandbox
DEFAULTDIR="$ROOT/opt/microsoft/aznfs/data"

resolve LOGFILE >/dev/null
assert_contains "before change: default dir covered" "$DEFAULTDIR/aznfs.log" "$LRCONF"

write_config "AZNFS_LOGDIR=$SANDBOX/moved"
resolve LOGFILE >/dev/null
assert_contains "after change: new dir covered" "$SANDBOX/moved/aznfs.log" "$LRCONF"
assert_contains "after change: new turbo logs covered" "$SANDBOX/moved/turbo*.log" "$LRCONF"

if grep -qF -- "$DEFAULTDIR/aznfs.log" "$LRCONF"; then
    nok "after change: old dir no longer covered" "only the configured dir" "old dir still listed"
else
    ok "after change: old dir no longer covered"
fi

# Old logs must be left in place, never moved or deleted.
setup_sandbox
resolve LOGFILE >/dev/null
echo "historic entry" >> "$DEFAULTDIR/aznfs.log"
write_config "AZNFS_LOGDIR=$SANDBOX/moved2"
resolve LOGFILE >/dev/null
if [ -f "$DEFAULTDIR/aznfs.log" ] && grep -q "historic entry" "$DEFAULTDIR/aznfs.log"; then
    ok "old log file left in place with its content intact"
else
    nok "old log file left in place with its content intact" "file preserved" "missing or emptied"
fi

# Switching back to the default must regenerate, with no duplicate entries.
write_config "AUTO_UPDATE_AZNFS=false"
resolve LOGFILE >/dev/null
dupcount=$(grep -c -- "$DEFAULTDIR/aznfs.log" "$LRCONF")
assert_eq "switching back to default: single log entry" "1" "$dupcount"

if command -v logrotate >/dev/null 2>&1; then
    make_conf "$SANDBOX/back.conf"
    if logrotate -d -s "$SANDBOX/back.state" "$SANDBOX/back.conf" 2>&1 | grep -qiE "error:"; then
        nok "config after switching back is valid" "no errors" \
            "$(logrotate -d -s "$SANDBOX/back.state" "$SANDBOX/back.conf" 2>&1 | grep -i error: | head -1)"
    else
        ok "config after switching back is valid"
    fi
fi

# ---------------------------------------------------------------------------
echo
echo "[3c] Chained log directory changes (default -> B -> C -> default)"
# ---------------------------------------------------------------------------

#
# Each change must leave the config pointing at exactly the configured
# directory, and must stay valid for logrotate.
#
setup_sandbox
DEFAULTDIR="$ROOT/opt/microsoft/aznfs/data"

resolve LOGFILE >/dev/null                          # default

write_config "AZNFS_LOGDIR=$SANDBOX/dirB"           # default -> B
resolve LOGFILE >/dev/null
assert_contains "B covered after default -> B" "$SANDBOX/dirB/aznfs.log" "$LRCONF"

write_config "AZNFS_LOGDIR=$SANDBOX/dirC"           # B -> C
resolve LOGFILE >/dev/null
assert_contains "C covered after B -> C" "$SANDBOX/dirC/aznfs.log" "$LRCONF"
if grep -qF -- "$SANDBOX/dirB/aznfs.log" "$LRCONF"; then
    nok "B dropped after B -> C" "only C" "B still listed"
else
    ok "B dropped after B -> C"
fi

write_config "AUTO_UPDATE_AZNFS=false"              # C -> default
resolve LOGFILE >/dev/null
assert_contains "default covered after C -> default" "$DEFAULTDIR/aznfs.log" "$LRCONF"

dupdef=$(grep -c -- "$DEFAULTDIR/aznfs.log" "$LRCONF")
assert_eq "no duplicate default entry after chain" "1" "$dupdef"

#
# When the directory changes the user must be told where the previous logs are,
# since nothing removes them and a log that stops growing is never rotated out.
# The notice must fire only on an actual change, not on every mount.
#
setup_sandbox
notice_out()
{
    local out="$SANDBOX/notice.out"
    rm -f "$out"
    env AZNFS_VERSION=3 "$@" bash -c ". '$COMMON' > '$out' 2>&1" >/dev/null 2>&1
    sed 's/\x1b\[[0-9;]*m//g' "$out" 2>/dev/null
}

notice_out >/dev/null                                   # first run, default
write_config "AZNFS_LOGDIR=$SANDBOX/notified"
first=$(notice_out)                                     # the change
second=$(notice_out)                                    # same dir again

if echo "$first" | grep -q "remain in '$ROOT/opt/microsoft/aznfs/data'"; then
    ok "user is told where the previous logs remain"
else
    nok "user is told where the previous logs remain" "notice naming the old dir" "$(echo "$first" | tail -2)"
fi

#
# The notice has to be actionable on its own: a user who only ever sees this
# line must know how to finish the change without going to the README.
#
if echo "$first" | grep -q "systemctl restart aznfswatchdog aznfswatchdogv4"; then
    ok "notice includes the watchdog restart command"
else
    nok "notice includes the watchdog restart command" \
        "systemctl restart aznfswatchdog aznfswatchdogv4" "$(echo "$first" | tail -3)"
fi

if echo "$second" | grep -q "are not removed automatically"; then
    nok "notice is not repeated when the dir is unchanged" "no notice" "notice repeated"
else
    ok "notice is not repeated when the dir is unchanged"
fi


if command -v logrotate >/dev/null 2>&1; then
    setup_sandbox
    write_config "AZNFS_LOGDIR=$SANDBOX/chainB"
    resolve LOGFILE >/dev/null
    write_config "AZNFS_LOGDIR=$SANDBOX/chainC"
    resolve LOGFILE >/dev/null

    make_conf "$SANDBOX/chain.conf"
    chain_out=$(logrotate -d -s "$SANDBOX/chain.state" "$SANDBOX/chain.conf" 2>&1)
    if echo "$chain_out" | grep -qiE "error:"; then
        nok "config after chained changes is valid" "no errors" "$(echo "$chain_out" | grep -i error: | head -1)"
    else
        ok "config after chained changes is valid"
    fi
fi

# Missing template -> graceful no-op, and mounts must still work.
setup_sandbox
rm -f "$ROOT/opt/microsoft/aznfs/aznfs.logrotate"
assert_eq "missing template -> logging still works" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$(resolve LOGFILE)"
if [ ! -f "$LRCONF" ]; then
    ok "missing template -> no config written"
else
    nok "missing template -> no config written" "no file" "file exists"
fi

# Missing /etc/logrotate.d (logrotate not installed) -> graceful no-op.
setup_sandbox
rm -rf "$ROOT/etc/logrotate.d"
assert_eq "no logrotate.d -> logging still works" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$(resolve LOGFILE)"

# Read-only /etc/logrotate.d -> must not fail the mount, no temp file left behind.
setup_sandbox
chmod a-w "$ROOT/etc/logrotate.d"
assert_eq "read-only logrotate.d -> logging still works" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$(resolve LOGFILE)"
leftover=$(find "$ROOT/etc/logrotate.d" -name 'aznfs.tmp.*' 2>/dev/null | wc -l)
assert_eq "read-only logrotate.d -> no temp file leaked" "0" "$leftover"
chmod u+w "$ROOT/etc/logrotate.d"

# ---------------------------------------------------------------------------
echo
echo "[4] Generated config validated by logrotate itself"
# ---------------------------------------------------------------------------

if command -v logrotate >/dev/null 2>&1; then
    setup_sandbox
    write_config "AZNFS_LOGDIR=$SANDBOX/rot"
    resolve LOGFILE >/dev/null

    # logrotate refuses to run as non-root with "su root root"; strip for the test.
    make_conf "$SANDBOX/nosu.conf"

    if logrotate -d -s "$SANDBOX/state" "$SANDBOX/nosu.conf" >"$SANDBOX/lr.out" 2>&1; then
        ok "logrotate parses generated config"
    else
        nok "logrotate parses generated config" "exit 0" "$(tail -3 "$SANDBOX/lr.out")"
    fi

    #
    # The limits are substituted into the policy, so a value the config file
    # accepts but logrotate does not would only show up here.
    #
    for combo in "500k 0" "2G 30" "1048576 1"; do
        set -- $combo
        setup_sandbox
        write_config "AZNFS_LOGDIR=$SANDBOX/rot" "AZNFS_LOGSIZE=$1" "AZNFS_LOGCOUNT=$2"
        resolve LOGFILE >/dev/null
        make_conf "$SANDBOX/nosu.conf"

        if logrotate -d -s "$SANDBOX/state" "$SANDBOX/nosu.conf" >"$SANDBOX/lr.out" 2>&1; then
            ok "logrotate accepts size=$1 rotate=$2"
        else
            nok "logrotate accepts size=$1 rotate=$2" "exit 0" "$(tail -3 "$SANDBOX/lr.out")"
        fi
    done

    #
    # And that logrotate reads them as the limits we meant, not just as valid
    # syntax. 1k is 1024 bytes, and rotate 0 keeps nothing.
    #
    setup_sandbox
    write_config "AZNFS_LOGDIR=$SANDBOX/rot" "AZNFS_LOGSIZE=1k" "AZNFS_LOGCOUNT=0"
    resolve LOGFILE >/dev/null
    make_conf "$SANDBOX/nosu.conf"
    logrotate -d -s "$SANDBOX/state" "$SANDBOX/nosu.conf" >"$SANDBOX/lr.out" 2>&1

    if grep -q "1024 bytes" "$SANDBOX/lr.out"; then
        ok "logrotate resolves the configured size to the right byte count"
    else
        nok "logrotate resolves the configured size to the right byte count" \
            "1024 bytes" "$(grep -i 'rotating pattern' "$SANDBOX/lr.out" | head -1)"
    fi

    if grep -qi "no old logs will be kept" "$SANDBOX/lr.out"; then
        ok "a retention of 0 really keeps nothing"
    else
        nok "a retention of 0 really keeps nothing" \
            "no old logs will be kept" "$(grep -i 'rotating pattern' "$SANDBOX/lr.out" | head -1)"
    fi

    #
    # Back to the shipped defaults: everything below inspects the policy this
    # package generates out of the box, not the custom limits above.
    #
    setup_sandbox
    write_config "AZNFS_LOGDIR=$SANDBOX/rot"
    resolve LOGFILE >/dev/null
    make_conf "$SANDBOX/nosu.conf"
    logrotate -d -s "$SANDBOX/state" "$SANDBOX/nosu.conf" >"$SANDBOX/lr.out" 2>&1

    if ! grep -qiE "error:|unknown option|unexpected" "$SANDBOX/lr.out"; then
        ok "logrotate reports no config errors"
    else
        nok "logrotate reports no config errors" "no errors" "$(grep -iE 'error:|unknown option' "$SANDBOX/lr.out" | head -2)"
    fi

    #
    # Rotation policy: size based only.
    #
    # "size" makes logrotate ignore time directives, so a stray daily/weekly/
    # monthly here would be dead config at best. More importantly, a time based
    # policy would rotate tiny logs on every run and cap the retained history
    # at 'rotate' days, which is exactly what we don't want for support logs.
    #
    if ! grep -qE "^[[:space:]]*(daily|weekly|monthly|yearly)[[:space:]]*$" "$LRCONF"; then
        ok "policy has no time based rotation directive"
    else
        nok "policy has no time based rotation directive" "size based only" \
            "$(grep -E '^[[:space:]]*(daily|weekly|monthly|yearly)' "$LRCONF")"
    fi

    if grep -qE "^[[:space:]]*size[[:space:]]+[0-9]+[kKmMgG]?[[:space:]]*$" "$LRCONF"; then
        ok "policy rotates on size"
    else
        nok "policy rotates on size" "a 'size N' directive" "$(grep -E 'size' "$LRCONF" | head -2)"
    fi

    #
    # The retention test below overrides 'rotate' to keep the run short, so
    # assert the shipped value separately: it must be present and bounded,
    # otherwise rotated logs would accumulate forever.
    #
    shipped_rotate=$(sed -n 's|^[[:space:]]*rotate[[:space:]]*\([0-9]*\)[[:space:]]*$|\1|p' "$LRCONF" | head -1)
    if [ -n "$shipped_rotate" ] && [ "$shipped_rotate" -ge 1 ] && [ "$shipped_rotate" -le 20 ]; then
        ok "shipped policy keeps a bounded number of rotations (rotate $shipped_rotate)"
    else
        nok "shipped policy keeps a bounded number of rotations" "1..20" "rotate '${shipped_rotate:-missing}'"
    fi

    #
    # The README describes the retention, so the policy it describes has to be
    # the one that ships. delaycompress means the newest rotation stays
    # uncompressed, which the docs must not contradict.
    #
    if grep -qE '^[[:space:]]*delaycompress[[:space:]]*$' "$LRCONF"; then
        if grep -q "the newest rotation is left" "$SOURCE_DIR/README.md"; then
            ok "README describes delaycompress accurately"
        else
            nok "README describes delaycompress accurately" \
                "docs mention the newest rotation staying uncompressed" "docs claim all are compressed"
        fi
    fi

    #
    # Only the configured directory is rotated, so a running Turbo client
    # keeps writing to its old log with nothing rotating it until that mount is
    # remounted. That is an accepted limitation, but it has to be documented.
    #
    if grep -q "keeps writing to its existing" "$SOURCE_DIR/README.md" &&
       grep -q "Unmount and mount it again" "$SOURCE_DIR/README.md"; then
        ok "README documents that a running Turbo mount needs remounting"
    else
        nok "README documents that a running Turbo mount needs remounting" \
            "docs explain the Turbo log stays in the old directory" "not documented"
    fi

    #
    # A small, long-untouched log must NOT be rotated: this is the regression
    # guard for re-introducing time based rotation.
    #
    setup_sandbox
    write_config "AZNFS_LOGDIR=$SANDBOX/quiet"
    resolve LOGFILE >/dev/null
    make_conf "$SANDBOX/quiet.conf"

    printf 'a handful of watchdog events\n%.0s' {1..50} > "$SANDBOX/quiet/aznfs.log"
    touch -d '30 days ago' "$SANDBOX/quiet/aznfs.log"
    cat > "$SANDBOX/quiet.state" <<EOF
logrotate state -- version 2
"$SANDBOX/quiet/aznfs.log" 2000-01-01-0:0:0
EOF

    lrq=$(logrotate -d -s "$SANDBOX/quiet.state" "$SANDBOX/quiet.conf" 2>&1)
    if echo "$lrq" | grep -q "does not need rotating"; then
        ok "small 30-day-old log is not churned (no time based rotation)"
    else
        nok "small 30-day-old log is not churned (no time based rotation)" \
            "not rotated" "$(echo "$lrq" | grep -E 'needs rotating' | head -1)"
    fi

    # ... and an oversized log must still rotate.
    head -c 1100000 /dev/zero | tr '\0' 'x' > "$SANDBOX/quiet/turbo_mnt_busy.log"
    sed -i 's/^[[:space:]]*size .*/\tsize 1M/' "$SANDBOX/quiet.conf"
    lrb=$(logrotate -d -s "$SANDBOX/quiet.state" "$SANDBOX/quiet.conf" 2>&1)
    if echo "$lrb" | grep -qE "(rotating|copying) .*turbo_mnt_busy\.log"; then
        ok "oversized turbo log is rotated on size"
    else
        nok "oversized turbo log is rotated on size" "rotated" "$(echo "$lrb" | tail -3)"
    fi

    # The small log must still be left alone in that same run.
    if echo "$lrb" | grep -A6 "considering log $SANDBOX/quiet/aznfs.log" | grep -q "does not need rotating"; then
        ok "small log still untouched while a sibling rotates"
    else
        nok "small log still untouched while a sibling rotates" "not rotated" \
            "$(echo "$lrb" | grep -A6 "considering log $SANDBOX/quiet/aznfs.log" | tail -3)"
    fi

    # copytruncate must preserve writes from a process holding the log open.
    : > "$SANDBOX/rot/aznfs.log"
    (
        exec 3>> "$SANDBOX/rot/aznfs.log"
        echo "before-rotate" >&3
        sleep 2
        echo "after-rotate" >&3
    ) &
    writer=$!
    sleep 1
    logrotate -f -s "$SANDBOX/state" "$SANDBOX/nosu.conf" >/dev/null 2>&1
    wait $writer

    if grep -q "after-rotate" "$SANDBOX/rot/aznfs.log" 2>/dev/null; then
        ok "copytruncate: writer keeps writing to live log after rotation"
    else
        nok "copytruncate: writer keeps writing to live log after rotation" \
            "'after-rotate' in live log" "$(cat "$SANDBOX/rot/aznfs.log" 2>/dev/null)"
    fi

    rotated=$(cat "$SANDBOX/rot/aznfs.log.1" 2>/dev/null; zcat "$SANDBOX/rot/aznfs.log.1.gz" 2>/dev/null)
    if echo "$rotated" | grep -q "before-rotate"; then
        ok "copytruncate: pre-rotation content preserved in rotated file"
    else
        nok "copytruncate: pre-rotation content preserved in rotated file" \
            "'before-rotate' in rotated file" "$rotated"
    fi

    if ! grep -q "before-rotate" "$SANDBOX/rot/aznfs.log" 2>/dev/null; then
        ok "copytruncate: live log truncated"
    else
        nok "copytruncate: live log truncated" "old content gone" "old content still present"
    fi

    # -----------------------------------------------------------------------
    echo
    echo "[4b] Retention: old rotations are actually deleted"
    # -----------------------------------------------------------------------

    #
    # Drive real rotations by growing the log past the threshold, rather than
    # forcing them, so the size trigger is exercised. The threshold is lowered
    # to 1M in a copy of the generated config: the code path is identical to
    # 100M and this keeps the test fast.
    #
    # Each generation is filled with a distinct digit so we can tell which
    # rotation holds which content, and prove the oldest is really removed and
    # not just renamed.
    #
    setup_sandbox
    write_config "AZNFS_LOGDIR=$SANDBOX/ret"
    resolve LOGFILE >/dev/null

    make_conf "$SANDBOX/ret.conf"
    sed -i -e 's|^[[:space:]]*size .*|\tsize 1M|' -e 's|^[[:space:]]*rotate .*|\trotate 3|' \
        "$SANDBOX/ret.conf"

    for gen in 1 2 3 4 5 6; do
        head -c 1200000 /dev/zero | tr '\0' "$gen" > "$SANDBOX/ret/aznfs.log"
        logrotate -s "$SANDBOX/ret.state" "$SANDBOX/ret.conf" 2>/dev/null
    done

    nrot=$(ls "$SANDBOX/ret"/aznfs.log.* 2>/dev/null | wc -l)
    assert_eq "retention capped at 'rotate' files after 6 rotations" "3" "$nrot"

    #
    # The three newest generations must be kept, in order.
    #
    gen_of()
    {
        local f="$1"
        { zcat "$f" 2>/dev/null || cat "$f"; } | head -c 1
    }

    assert_eq "newest rotation holds the latest generation" \
        "6" "$(gen_of "$SANDBOX/ret/aznfs.log.1")"
    assert_eq "second rotation holds the previous generation" \
        "5" "$(gen_of "$SANDBOX/ret/aznfs.log.2.gz")"
    assert_eq "oldest kept rotation holds generation 4" \
        "4" "$(gen_of "$SANDBOX/ret/aznfs.log.3.gz")"

    #
    # ... and the aged out generations must be gone from disk entirely.
    #
    stale=0
    for f in "$SANDBOX/ret"/aznfs.log*; do
        case "$(gen_of "$f")" in
            1|2|3) stale=1 ;;
        esac
    done
    assert_eq "aged out generations deleted, not just renamed" "0" "$stale"

    # delaycompress: newest rotation stays plain, older ones are gzipped.
    if file "$SANDBOX/ret/aznfs.log.1" | grep -q "gzip"; then
        nok "delaycompress keeps the newest rotation uncompressed" "plain text" "gzipped"
    else
        ok "delaycompress keeps the newest rotation uncompressed"
    fi

    if file "$SANDBOX/ret/aznfs.log.2.gz" | grep -q "gzip"; then
        ok "older rotations are compressed"
    else
        nok "older rotations are compressed" "gzip" "not compressed"
    fi

    #
    # The whole point: disk usage stays bounded no matter how long this runs.
    #
    total=$(du -sb "$SANDBOX/ret" | cut -f1)
    if [ "$total" -lt $((1200000 * 4)) ]; then
        ok "total log dir size stays bounded ($total bytes after 6 rotations)"
    else
        nok "total log dir size stays bounded" "< 4.8MB" "$total bytes"
    fi
else
    echo "  SKIP: logrotate binary not installed"
fi

# ---------------------------------------------------------------------------
echo
echo "[5] Package maintainer script (postinst) behaviour"
# ---------------------------------------------------------------------------

#
# Extract install_logrotate_config() from the deb postinst and run it against the
# sandbox. postinst runs under 'set -e', so any non-zero exit aborts the install;
# these tests guard against that.
#
run_postinst_snippet()
{
    local snippet="$SANDBOX/snippet.sh"

    #
    # Include CONFIG_FILE too, it's declared before LOGROTATE_TEMPLATE. Leaving
    # it out silently makes install_logrotate_config() see no configured log
    # directory at all, so every case would "pass" by falling back to default.
    #
    sed -n '/^CONFIG_FILE=/,/^AUTO_UPDATE_AZNFS=/p;/^aznfs_safe_logdir()/,/^}/p;/^install_logrotate_config()/,/^}/p' \
        "$SOURCE_DIR/packaging/aznfs/DEBIAN/postinst" > "$snippet"
    sed -i "s#/opt/microsoft/aznfs#$ROOT/opt/microsoft/aznfs#g; s#/etc/logrotate.d#$ROOT/etc/logrotate.d#g" "$snippet"
    echo 'install_logrotate_config' >> "$snippet"

    bash -e "$snippet" >"$SANDBOX/postinst.out" 2>&1
}

#
# The same for the RPM scriptlet. It generates the policy independently of both
# common.sh and the deb postinst, and until now was only ever checked by
# inspection, so a shell error in it would have shipped: nothing here builds an
# rpm. Extracting and running it is not a substitute for an install, but it
# does exercise the code.
#
# rpm's own macro expansion is the one part this cannot cover. That needs
# rpmbuild, which is not available here.
#
#
# rpm collapses %% to % when it writes the scriptlet into the package. Every
# test that runs spec text has to go through here, so that none of them can
# end up exercising a form that is never installed: run verbatim, stat prints
# a literal "%u" and the scriptlet rejects every directory.
#
rpm_scriptlet()
{
    sed -n "$1" "$SOURCE_DIR/packaging/aznfs/RPM/aznfs.spec" | sed 's/%%/%/g'
}

run_rpm_post_snippet()
{
    local snippet="$SANDBOX/rpmsnippet.sh"

    rpm_scriptlet '/^CONFIG_FILE=/,/^AUTO_UPDATE_AZNFS=/p;/^aznfs_safe_logdir()/,/^}/p;/^install_logrotate_config()/,/^}/p' > "$snippet"

    sed -i "s#/opt/microsoft/aznfs#$ROOT/opt/microsoft/aznfs#g; s#/etc/logrotate.d#$ROOT/etc/logrotate.d#g" "$snippet"
    echo 'install_logrotate_config' >> "$snippet"

    bash -e "$snippet" >"$SANDBOX/rpmpost.out" 2>&1
}

setup_sandbox
if ! grep -q '^install_logrotate_config()' "$SOURCE_DIR/packaging/aznfs/RPM/aznfs.spec"; then
    nok "rpm %post: scriptlet can be extracted" "install_logrotate_config() at column 0" "not extractable"
else
    ok "rpm %post: scriptlet can be extracted"

    #
    # A positive control. Without it the %post assertions below all still pass
    # when aznfs_safe_logdir rejects everything, because "reject everything"
    # lands on the same default directory they expect. That is exactly what a
    # mis-escaped stat format does, so the broken form has to be visible here.
    #
    rpm_fn="$SANDBOX/rpmfn.sh"
    rpm_scriptlet '/^aznfs_safe_logdir()/,/^}/p' > "$rpm_fn"

    mkdir -p "$SANDBOX/rpmgood"
    chmod 0755 "$SANDBOX/rpmgood"
    mkdir -p "$SANDBOX/rpmbad"
    chmod 0777 "$SANDBOX/rpmbad"

    if bash -c ". '$rpm_fn'; aznfs_safe_logdir '$SANDBOX/rpmgood'" >/dev/null 2>&1; then
        ok "rpm %post: scriptlet accepts a safe log directory"
    else
        nok "rpm %post: scriptlet accepts a safe log directory" "accepted" \
            "rejected, so the scriptlet rejects everything"
    fi

    if bash -c ". '$rpm_fn'; aznfs_safe_logdir '$SANDBOX/rpmbad'" >/dev/null 2>&1; then
        nok "rpm %post: scriptlet rejects a world writable one" "rejected" "accepted"
    else
        ok "rpm %post: scriptlet rejects a world writable one"
    fi

    #
    # The escaping itself has to be pinned. Both forms behave the same when
    # bash runs them directly, so no behavioural test here can tell them
    # apart; the difference only shows under rpm's macro expansion, where a
    # defined macro named u, G or a rewrites the bare form. Verified with
    # rpmbuild: %%u survives as %u, bare %u becomes the macro's value.
    #
    spec_fmt=$(sed -n '/^aznfs_safe_logdir()/,/^}/p' \
        "$SOURCE_DIR/packaging/aznfs/RPM/aznfs.spec" | grep -E "stat -c|printf '%")

    if printf '%s\n' "$spec_fmt" | grep -qE "stat -c '%[a-zA-Z]"; then
        nok "rpm spec escapes % in its format strings" \
            "%%u %%G %%a" "a bare % that rpm can expand"
    elif printf '%s\n' "$spec_fmt" | grep -q "stat -c '%%u %%G %%a'"; then
        ok "rpm spec escapes % in its format strings"
    else
        nok "rpm spec escapes % in its format strings" "%%u %%G %%a" "$spec_fmt"
    fi

    if printf '%s\n' "$spec_fmt" | grep -q "printf '%%04d'"; then
        ok "rpm spec escapes % in its printf width"
    else
        nok "rpm spec escapes % in its printf width" "%%04d" "$spec_fmt"
    fi

    #
    # The deb copy must NOT be escaped: nothing expands macros there, so %%
    # would reach bash literally and stat would print "%u".
    #
    if grep -q "stat -c '%u %G %a'" "$SOURCE_DIR/packaging/aznfs/DEBIAN/postinst"; then
        ok "deb postinst keeps the bare % format"
    else
        nok "deb postinst keeps the bare % format" "%u %G %a" "escaped, which breaks it"
    fi

    run_rpm_post_snippet
    assert_eq "rpm %post: fresh install exits 0" "0" "$?"
    assert_contains "rpm %post: generates config" \
        "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$LRCONF"

    leftover=$(grep -o 'AZNFS_[A-Z]*_PLACEHOLDER' "$LRCONF" 2>/dev/null | sort -u | tr '\n' ' ')
    if [ -z "$leftover" ]; then
        ok "rpm %post: substitutes every placeholder"
    else
        nok "rpm %post: substitutes every placeholder" "none left" "$leftover"
    fi

    assert_contains "rpm %post: default size" "size 100M" "$LRCONF"
    assert_contains "rpm %post: default retention" "rotate 7" "$LRCONF"

    setup_sandbox
    write_config "AZNFS_LOGSIZE=750k" "AZNFS_LOGCOUNT=2"
    run_rpm_post_snippet
    assert_eq "rpm %post: configured limits exit 0" "0" "$?"
    assert_contains "rpm %post: honours configured size" "size 750k" "$LRCONF"
    assert_contains "rpm %post: honours configured retention" "rotate 2" "$LRCONF"

    setup_sandbox
    write_config "AZNFS_LOGSIZE=bogus" "AZNFS_LOGCOUNT=-4"
    run_rpm_post_snippet
    assert_eq "rpm %post: bad limits must not abort the install" "0" "$?"
    assert_contains "rpm %post: bad size falls back" "size 100M" "$LRCONF"
    assert_contains "rpm %post: bad retention falls back" "rotate 7" "$LRCONF"

    #
    # The policy it writes has to be one logrotate will actually accept.
    #
    if command -v logrotate >/dev/null 2>&1; then
        setup_sandbox
        write_config "AZNFS_LOGSIZE=2G" "AZNFS_LOGCOUNT=5"
        run_rpm_post_snippet
        make_conf "$SANDBOX/rpm-nosu.conf"

        if logrotate -d -s "$SANDBOX/rpmstate" "$SANDBOX/rpm-nosu.conf" \
                >"$SANDBOX/rpmlr.out" 2>&1; then
            ok "rpm %post: generated policy is valid logrotate config"
        else
            nok "rpm %post: generated policy is valid logrotate config" "exit 0" \
                "$(tail -3 "$SANDBOX/rpmlr.out")"
        fi
    fi
fi

setup_sandbox
run_postinst_snippet
assert_eq "postinst: fresh install exits 0" "0" "$?"
assert_contains "postinst: generates config" "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$LRCONF"

setup_sandbox
write_config "AUTO_UPDATE_AZNFS=false"
run_postinst_snippet
assert_eq "postinst: config lacking AZNFS_LOGDIR must not abort (set -e + egrep)" "0" "$?"

setup_sandbox
write_config "AZNFS_LOGDIR=/proc/nope/nope"
run_postinst_snippet
assert_eq "postinst: uncreatable log dir must not abort install" "0" "$?"
assert_contains "postinst: falls back to default log dir" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$LRCONF"

#
# mkdir -p returns success for an existing directory even when nothing can be
# written into it, e.g. a read only filesystem. common.sh probes with a touch
# and falls back, so the install time policy has to agree. If it does not, the
# policy rotates the unusable directory while the log that is actually written,
# the one under the fallback, goes uncovered.
#
# Only root can be kept out by permission bits alone, so skip when running as
# root. The rest of the suite needs no privileges either.
#
if [ "$(id -u)" -ne 0 ]; then
    setup_sandbox
    mkdir -p "$SANDBOX/ro-logdir"
    chmod 0555 "$SANDBOX/ro-logdir"
    write_config "AZNFS_LOGDIR=$SANDBOX/ro-logdir"

    run_postinst_snippet
    assert_eq "postinst: unwritable existing log dir must not abort install" "0" "$?"
    assert_contains "postinst: unwritable existing log dir falls back" \
        "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$LRCONF"

    if grep -q "$SANDBOX/ro-logdir/aznfs.log" "$LRCONF"; then
        nok "postinst: unwritable log dir is not rotated" "absent from policy" "still rotated"
    else
        ok "postinst: unwritable log dir is not rotated"
    fi

    #
    # The same value must land on the same directory at runtime, otherwise the
    # two drift apart again and the rotation covers the wrong path.
    #
    assert_eq "runtime agrees: unwritable existing log dir falls back too" \
        "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$(resolve LOGFILE)"

    chmod 0755 "$SANDBOX/ro-logdir"
else
    skipped "postinst: unwritable existing log dir must not abort install"
    skipped "postinst: unwritable existing log dir falls back"
    skipped "postinst: unwritable log dir is not rotated"
    skipped "runtime agrees: unwritable existing log dir falls back too"
fi

#
# An existing log we cannot append to makes common.sh fall back at the first
# mount, so the policy must not be left pointing at that directory.
#
if [ "$(id -u)" -ne 0 ]; then
    setup_sandbox
    mkdir -p "$SANDBOX/pkg-rolog"
    : > "$SANDBOX/pkg-rolog/aznfs.log"
    chmod 0444 "$SANDBOX/pkg-rolog/aznfs.log"
    write_config "AZNFS_LOGDIR=$SANDBOX/pkg-rolog"
    run_postinst_snippet
    assert_eq "postinst: unwritable existing log must not abort install" "0" "$?"
    assert_contains "postinst: unwritable existing log falls back" \
        "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$LRCONF"
    assert_eq "install and runtime agree on an unwritable existing log" \
        "$DEFAULT_LOG" "$(resolve LOGFILE)"
    chmod 0644 "$SANDBOX/pkg-rolog/aznfs.log"
else
    skipped "postinst: unwritable existing log must not abort install"
    skipped "postinst: unwritable existing log falls back"
    skipped "install and runtime agree on an unwritable existing log"
fi

#
# A directory others can write to must be refused at install time as well,
# otherwise the policy would rotate a directory the runtime refuses to use.
#
setup_sandbox
mkdir -p "$SANDBOX/pkg-unsafe"
chmod 0777 "$SANDBOX/pkg-unsafe"
write_config "AZNFS_LOGDIR=$SANDBOX/pkg-unsafe"
run_postinst_snippet
assert_eq "postinst: unsafe log dir must not abort install" "0" "$?"
assert_contains "postinst: unsafe log dir falls back" \
    "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$LRCONF"

#
# The maintainer script has its own copy of the path handling, so the unsafe
# values must be rejected there too, without aborting the install (set -e).
# One character case and one whitespace case are enough, they share the check.
#
postinst_reject()
{
    local desc="$1" value="$2" rc

    setup_sandbox
    write_config "AZNFS_LOGDIR=$value"
    run_postinst_snippet
    rc=$?

    if [ "$rc" != "0" ]; then
        nok "$desc" "exit 0" "exit $rc"
        return
    fi

    if grep -q "PLACEHOLDER" "$LRCONF" 2>/dev/null; then
        nok "$desc" "no placeholder left" "config corrupted"
        return
    fi

    assert_contains "$desc" "$ROOT/opt/microsoft/aznfs/data/aznfs.log" "$LRCONF"
}

postinst_reject "postinst: unsafe character rejected, config not corrupted" "$SANDBOX/a&b"
postinst_reject "postinst: embedded space rejected"                        "$SANDBOX/my logs"
postinst_reject "postinst: relative path rejected"                         "relative/dir"

setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/pkg-ok_1.2"
run_postinst_snippet
assert_eq "postinst: valid path exits 0" "0" "$?"
assert_contains "postinst: valid path used" "$SANDBOX/pkg-ok_1.2/aznfs.log" "$LRCONF"

#
# The config has to be written atomically. Rendering straight into
# $LOGROTATE_CONFIG truncates it before sed runs, so a failure part way through
# would leave an empty policy and silently disable rotation.
#
for f in "packaging/aznfs/DEBIAN/postinst" "packaging/aznfs/RPM/aznfs.spec"; do
    if grep -q 'LOGROTATE_TEMPLATE" > "\$tmpfile"' "$SOURCE_DIR/$f"; then
        ok "$(basename $f): renders the config to a temp file"
    else
        nok "$(basename $f): renders the config to a temp file" \
            "sed ... > \$tmpfile" "writes straight to the destination"
    fi

    if grep -q 'mv -f "\$tmpfile" "\$LOGROTATE_CONFIG"' "$SOURCE_DIR/$f"; then
        ok "$(basename $f): replaces the config only after sed succeeds"
    else
        nok "$(basename $f): replaces the config only after sed succeeds" \
            "mv -f \$tmpfile" "missing"
    fi
done

#
# A failed render must leave the previous policy untouched rather than
# truncating it.
#
setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/atomic"
run_postinst_snippet
echo "# admin tweak" >> "$LRCONF"
before_sum=$(md5sum "$LRCONF" | cut -d' ' -f1)

#
# Force the render to fail, then retarget the directory so a regeneration is
# attempted. Replacing the template with a directory makes sed fail for any
# uid; removing read permission would not, since root reads it regardless and
# the case would silently stop exercising the error path.
#
TEMPLATE_PATH="$ROOT/opt/microsoft/aznfs/aznfs.logrotate"
mv "$TEMPLATE_PATH" "$SANDBOX/template.saved"
mkdir -p "$TEMPLATE_PATH"
write_config "AZNFS_LOGDIR=$SANDBOX/atomic2"
run_postinst_snippet
rc=$?
rmdir "$TEMPLATE_PATH"
mv "$SANDBOX/template.saved" "$TEMPLATE_PATH"

assert_eq "postinst: failed render does not abort the install" "0" "$rc"
assert_eq "postinst: failed render leaves the previous policy intact" \
    "$before_sum" "$(md5sum "$LRCONF" | cut -d' ' -f1)"

leftover=$(find "$(dirname "$LRCONF")" -name 'aznfs.tmp.*' 2>/dev/null | wc -l)
assert_eq "postinst: failed render leaves no temp file behind" "0" "$leftover"

if command -v logrotate >/dev/null 2>&1; then
    make_conf "$SANDBOX/pkg.conf"
    if logrotate -d -s "$SANDBOX/pkg.state" "$SANDBOX/pkg.conf" 2>&1 | grep -qiE "^error:"; then
        nok "postinst: generated config is valid" "no errors" "logrotate reported an error"
    else
        ok "postinst: generated config is valid"
    fi
fi

setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/upg"
run_postinst_snippet
echo "# admin tweak" >> "$LRCONF"
run_postinst_snippet
assert_eq "postinst: upgrade preserves admin's policy edits" \
    "# admin tweak" "$(tail -n1 "$LRCONF")"

setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/upg"
run_postinst_snippet
echo "# admin tweak" >> "$LRCONF"
write_config "AZNFS_LOGDIR=$SANDBOX/upg/"
run_postinst_snippet
assert_eq "postinst: trailing-slash variant preserves policy edits" \
    "# admin tweak" "$(tail -n1 "$LRCONF")"

# ---------------------------------------------------------------------------
echo
echo "[6] Every packaging path ships the logrotate template"
# ---------------------------------------------------------------------------

#
# The repo has more than one packaging script: package.sh and the one the Azure
# build pipeline actually runs, generate_package.sh. The RPM %files list
# requires the template, and postinst chmods it, so a packaging path that
# doesn't stage it produces a broken package. Check every script that builds
# packages, not just the one that happens to be edited.
#
for pkgscript in package.sh generate_package.sh; do
    [ -f "$SOURCE_DIR/$pkgscript" ] || continue

    # RPM staging.
    if grep -q "aznfs.logrotate.*rpm_pkg_dir" "$SOURCE_DIR/$pkgscript"; then
        ok "$pkgscript stages the template for rpm"
    else
        nok "$pkgscript stages the template for rpm" "a cp into the rpm staging dir" "missing"
    fi

    # DEB staging.
    if grep -q "aznfs.logrotate.*deb/" "$SOURCE_DIR/$pkgscript"; then
        ok "$pkgscript stages the template for deb"
    else
        nok "$pkgscript stages the template for deb" "a cp into the deb staging dir" "missing"
    fi

    # Tarball staging, only where that path exists.
    if grep -q "generate_tarball_package" "$SOURCE_DIR/$pkgscript"; then
        if grep -q "aznfs.logrotate.*tar_pkg_dir" "$SOURCE_DIR/$pkgscript"; then
            ok "$pkgscript stages the template for tarball"
        else
            nok "$pkgscript stages the template for tarball" "a cp into the tarball staging dir" "missing"
        fi
    fi
done

#
# The spec lists the template in %files, so rpmbuild fails outright if any RPM
# staging path forgets it.
#
if grep -q "^/opt/microsoft/aznfs/aznfs.logrotate" "$SOURCE_DIR/packaging/aznfs/RPM/aznfs.spec"; then
    ok "spec %files lists the template"
else
    nok "spec %files lists the template" "the template listed" "missing"
fi

# ---------------------------------------------------------------------------
echo
echo "[7] Log directory overrides are dropped by the setuid mount helper"
# ---------------------------------------------------------------------------

#
# mount.aznfs is installed setuid root and execs the mount script, which keeps
# the caller's environment. Honouring a caller supplied log directory there
# would let an unprivileged user make root create and write files at a path of
# their choosing. The helper must therefore drop these variables, the same way
# it already drops BASH_ENV and LD_PRELOAD.
#
MOUNTC="$SOURCE_DIR/src/mount.aznfs.c"

for v in AZNFS_LOGDIR AZNFSC_LOGDIR; do
    if grep -q "unsetenv(\"$v\")" "$MOUNTC"; then
        ok "mount.aznfs drops $v from the caller's environment"
    else
        nok "mount.aznfs drops $v from the caller's environment" \
            "unsetenv(\"$v\")" "missing, setuid path would honour it"
    fi
done

#
# The unsetenv calls have to happen before the exec, otherwise they are
# pointless.
#
if [ -f "$MOUNTC" ]; then
    unset_line=$(grep -n 'unsetenv("AZNFS_LOGDIR")' "$MOUNTC" | head -1 | cut -d: -f1)
    exec_line=$(grep -n 'execv(' "$MOUNTC" | head -1 | cut -d: -f1)

    if [ -n "$unset_line" ] && [ -n "$exec_line" ] && [ "$unset_line" -lt "$exec_line" ]; then
        ok "the overrides are dropped before exec'ing the mount script"
    else
        nok "the overrides are dropped before exec'ing the mount script" \
            "unsetenv before execv" "unsetenv=$unset_line execv=$exec_line"
    fi
fi

# It still has to compile.
if command -v gcc >/dev/null 2>&1; then
    if gcc -fsyntax-only "$MOUNTC" 2>/dev/null; then
        ok "mount.aznfs.c still compiles"
    else
        nok "mount.aznfs.c still compiles" "clean compile" "compile errors"
    fi
else
    skipped "mount.aznfs.c still compiles" "no gcc"
fi

#
# The checks above only assert the source contains the calls. This one runs the
# real thing: the shipped source is compiled with nothing changed but the exec
# target, then executed with all four variables set, and the exec'd process
# reports what survived. setreuid(0, 0) means it only reaches execv as root, so
# without root there is nothing to observe and the case is skipped rather than
# quietly passing.
#
if command -v gcc >/dev/null 2>&1 && [ -f "$MOUNTC" ]; then
    mdir="$SANDBOX/mountc"
    mkdir -p "$mdir"

    sed "s|#define MOUNTSCRIPT \"/opt/microsoft/aznfs/mountscript.sh\"|#define MOUNTSCRIPT \"$mdir/probe.sh\"|" \
        "$MOUNTC" > "$mdir/mount_aznfs.c"

    #
    # Only the exec target may differ, otherwise this would be testing a
    # rewritten program rather than the one that ships.
    #
    mdiff=$(diff "$MOUNTC" "$mdir/mount_aznfs.c" | grep -c '^[<>]')
    if [ "$mdiff" == "2" ]; then
        ok "mount.aznfs test binary differs only in the exec target"
    else
        nok "mount.aznfs test binary differs only in the exec target" \
            "2 changed lines" "$mdiff"
    fi

    cat > "$mdir/probe.sh" <<PROBE
#!/bin/bash
{
  echo "AZNFS_LOGDIR=\${AZNFS_LOGDIR-<unset>}"
  echo "AZNFSC_LOGDIR=\${AZNFSC_LOGDIR-<unset>}"
  echo "BASH_ENV=\${BASH_ENV-<unset>}"
  echo "LD_PRELOAD=\${LD_PRELOAD-<unset>}"
  echo "umask=\$(umask)"
  echo "argv=\$*"
} > "$mdir/env.out"
chmod 0666 "$mdir/env.out" 2>/dev/null
PROBE
    chmod +x "$mdir/probe.sh"

    if gcc -o "$mdir/mount_aznfs" "$mdir/mount_aznfs.c" 2>/dev/null &&
       [ "$(id -u)" == "0" ]; then
        rm -f "$mdir/env.out"

        # umask 000 is the caller's, so a helper that inherits it is visible.
        ( umask 000
          env AZNFS_LOGDIR=/tmp/evil-logdir AZNFSC_LOGDIR=/tmp/evil-turbo \
              BASH_ENV=/tmp/evil-bashenv LD_PRELOAD=/tmp/evil-preload \
              "$mdir/mount_aznfs" --probe-arg >/dev/null 2>&1 )

        for v in AZNFS_LOGDIR AZNFSC_LOGDIR BASH_ENV LD_PRELOAD; do
            if grep -q "^${v}=<unset>$" "$mdir/env.out" 2>/dev/null; then
                ok "mount.aznfs really drops $v before exec"
            else
                nok "mount.aznfs really drops $v before exec" "${v}=<unset>" \
                    "$(grep "^${v}=" "$mdir/env.out" 2>/dev/null || echo 'no output, it never execd')"
            fi
        done

        #
        # ... while still passing the caller's arguments through, or the helper
        # would be secure and useless.
        #
        if grep -q "^argv=--probe-arg$" "$mdir/env.out" 2>/dev/null; then
            ok "mount.aznfs still forwards the caller's arguments"
        else
            nok "mount.aznfs still forwards the caller's arguments" "argv=--probe-arg" \
                "$(grep '^argv=' "$mdir/env.out" 2>/dev/null)"
        fi

        #
        # Inheriting the caller's umask would make every file the script creates
        # as root world writable, the staged policy among them.
        #
        if grep -q "^umask=0022$" "$mdir/env.out" 2>/dev/null; then
            ok "mount.aznfs resets the caller's umask"
        else
            nok "mount.aznfs resets the caller's umask" "umask=0022" \
                "$(grep '^umask=' "$mdir/env.out" 2>/dev/null || echo 'no output, it never execd')"
        fi
    else
        for v in AZNFS_LOGDIR AZNFSC_LOGDIR BASH_ENV LD_PRELOAD; do
            skipped "mount.aznfs really drops $v before exec" "needs root: setreuid(0,0) fails otherwise"
        done
        skipped "mount.aznfs still forwards the caller's arguments" "needs root"
        skipped "mount.aznfs resets the caller's umask" "needs root"
    fi
else
    skipped "mount.aznfs test binary differs only in the exec target" "no gcc"
    for v in AZNFS_LOGDIR AZNFSC_LOGDIR BASH_ENV LD_PRELOAD; do
        skipped "mount.aznfs really drops $v before exec" "no gcc"
    done
    skipped "mount.aznfs still forwards the caller's arguments" "no gcc"
fi

# ---------------------------------------------------------------------------
echo
echo "[8] E2E safety guards"
# ---------------------------------------------------------------------------

#
# The E2E runs as root against a live installation, so the only checks kept
# here are the ones that stop it damaging the machine it runs on. Everything
# else about how it manages its own scratch state is the E2E's business and
# shows up when it is run.
#

# It deploys the repo over the installed scripts, so a partial deployment has to
# still be restorable: the marker restore_state() keys off must be set before
# the first copy, not after the last.
e2e_deploy_body=$(sed -n '/^deploy_build()/,/^}/p' "$E2E")
first_copy_at=$(printf '%s\n' "$e2e_deploy_body" | grep -n 'deploy_file "\$SOURCE_DIR' | head -1 | cut -d: -f1)
deploying_at=$(printf '%s\n' "$e2e_deploy_body" | grep -n 'touch "\$BACKUP/\.deploying"' | head -1 | cut -d: -f1)

if [ -n "$first_copy_at" ] && [ -n "$deploying_at" ] && [ "$deploying_at" -lt "$first_copy_at" ]; then
    ok "E2E marks deployment started before the first copy"
else
    nok "E2E marks deployment started before the first copy" \
        "marker before any file is replaced" "marked too late to recover"
fi

if grep -q 'if \[ ! -f "\$BACKUP/\.deploying" \]' "$E2E"; then
    ok "E2E restores whenever deployment has begun"
else
    nok "E2E restores whenever deployment has begun" \
        "restore guarded on .deploying" "guarded on completion"
fi

# It must never destroy production logs it has not backed up.
if grep -qE 'rm -f .*(aznfs|turbo)\*\.log\*' "$E2E"; then
    nok "E2E never bulk deletes rotated logs" "targeted removal only" "a bulk delete of live logs"
else
    ok "E2E never bulk deletes rotated logs"
fi

if grep -q 'restore_logs' "$E2E" && grep -q 'RESTORE_INCOMPLETE' "$E2E"; then
    ok "E2E reports an incomplete restoration instead of claiming success"
else
    nok "E2E reports an incomplete restoration instead of claiming success" \
        "restoration failures surfaced" "silently swallowed"
fi

# It is run repeatedly on a dev box, so a clean run must not leak its backup.
if grep -q 'kept for inspection' "$E2E"; then
    nok "E2E removes its backup after a clean restore" "backup removed on success" "kept every run"
else
    ok "E2E removes its backup after a clean restore"
fi

# It runs as root, so its scratch must not sit under a caller controlled $HOME:
# under "sudo -E" that is the invoking user's directory.
if grep -q 'getent passwd 0' "$E2E" && ! grep -q 'mktemp -d "${HOME' "$E2E"; then
    ok "E2E takes its scratch from root's passwd home, not \$HOME"
else
    nok "E2E takes its scratch from root's passwd home, not \$HOME" \
        "root home resolved from passwd" "caller controlled \$HOME"
fi

# It resolves the configured log directory the same way the runtime does, so it
# cannot back up or rotate a directory the installation would never use.
if grep -q 'safe_logdir "$d"' "$E2E" &&
   grep -q "sed -n '/\^safe_logdir()\$/,/\^}\$/p'" "$E2E"; then
    ok "E2E applies the shipped safety rules to the configured directory"
else
    nok "E2E applies the shipped safety rules to the configured directory" \
        "safe_logdir extracted from common.sh" "its own copy, or no check"
fi

# Argument errors must exit before anything is allocated or deployed.
before=$(ls -d /tmp/aznfs-e2e-backup.* /tmp/aznfs-e2e-scratch.* 2>/dev/null | wc -l)
"$E2E" >/dev/null 2>&1              # no arguments, usage error
"$E2E" bogus:/share >/dev/null 2>&1 # missing mount point
after=$(ls -d /tmp/aznfs-e2e-backup.* /tmp/aznfs-e2e-scratch.* 2>/dev/null | wc -l)
assert_eq "early exits leak no temp directories" "$before" "$after"

# ---------------------------------------------------------------------------
echo
echo "[9] Internal state cannot be injected from the environment"
# ---------------------------------------------------------------------------

#
# common.sh is sourced into a shell whose environment comes from the caller and
# mount.aznfs is setuid root, so any internal variable that is only assigned on
# a failure path must be initialized first. Otherwise an inherited value is
# taken for a real failure and an unprivileged caller can force the fallback
# and the regeneration of the rotation config.
#
setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/adminchoice"

assert_eq "clean run uses the configured directory" \
    "$SANDBOX/adminchoice/aznfs.log" "$(resolve LOGFILE)"

assert_eq "inherited bad_logdir cannot force the fallback" \
    "$SANDBOX/adminchoice/aznfs.log" "$(resolve LOGFILE "bad_logdir=$SANDBOX/adminchoice")"

setup_sandbox
write_config "AZNFS_LOGDIR=$SANDBOX/adminchoice"
resolve LOGFILE "bad_logdir=$SANDBOX/adminchoice" >/dev/null
assert_contains "inherited bad_logdir cannot rewrite the rotation config" \
    "$SANDBOX/adminchoice/aznfs.log" "$LRCONF"

if grep -qE '^bad_logdir=$' "$SOURCE_DIR/lib/common.sh"; then
    ok "bad_logdir is initialized before use"
else
    nok "bad_logdir is initialized before use" "bad_logdir= before the config is parsed" "missing"
fi

#
# A logging setup failure must never stop a mount, even if a caller has errexit
# enabled around the sourcing.
#
if grep -q 'ensure_logrotate_config || true' "$SOURCE_DIR/lib/common.sh"; then
    ok "logrotate setup failure cannot abort the mount"
else
    nok "logrotate setup failure cannot abort the mount" "ensure_logrotate_config || true" "unguarded call"
fi

rc=$(env AZNFS_VERSION=3 bash -c "set -e; . '$COMMON'" >/dev/null 2>&1; echo $?)
assert_eq "sourcing under 'set -e' still succeeds" "0" "$rc"

# ---------------------------------------------------------------------------
echo
#
# A test that calls a helper which does not exist prints "command not found"
# and carries on, so the case is silently never run. That is how assert_rc got
# in: two security assertions looked fine and counted nothing. Check every
# assertion helper this file invokes is actually defined.
#
undefined_helpers=""
for helper in $(grep -oE '^[[:space:]]*(assert|ok|nok)[A-Za-z_]*' "$0" | tr -d '[:blank:]' | sort -u); do
    if ! grep -q "^${helper}()" "$0"; then
        undefined_helpers="${undefined_helpers} ${helper}"
    fi
done

if [ -n "$undefined_helpers" ]; then
    nok "every assertion helper used is defined" "all defined" "missing:${undefined_helpers}"
else
    ok "every assertion helper used is defined"
fi

echo "=============================================="
echo -e " Passed: ${GREEN}${PASS}${NORMAL}   Failed: ${RED}${FAIL}${NORMAL}   Skipped: ${SKIP}"
echo "=============================================="

if [ $FAIL -ne 0 ]; then
    echo "Failed tests:"
    for t in "${FAILED_TESTS[@]}"; do
        echo "  - $t"
    done
    exit 1
fi

#
# A test that stops running does not fail, it just stops being counted. That
# has happened here: a dropped newline merged an assertion into the line above
# it, which silently removed the case instead of breaking anything. Raise this
# floor deliberately when adding tests, and only lower it when removing them on
# purpose.
#
EXPECTED_MIN_TESTS=388

if [ $((PASS + SKIP)) -lt $EXPECTED_MIN_TESTS ]; then
    echo "Only $((PASS + SKIP)) tests ran, expected at least ${EXPECTED_MIN_TESTS}."
    echo "Tests have gone missing rather than failed, check for a merged or deleted case."
    exit 1
fi

exit 0
