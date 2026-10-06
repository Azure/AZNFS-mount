#!/bin/bash

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

#
# End-to-end test for the configurable AZNFS log directory and log rotation,
# against a REAL Azure NFS mount on a machine with AZNFS installed.
#
# This must run as root. It:
#   1. Backs up the live /opt/microsoft/aznfs scripts, config and logrotate config.
#   2. Deploys the scripts from this repo over the installed ones.
#   3. Mounts the share, changes the log directory, remounts, rotates for real.
#   4. Restores everything it touched, including the original files.
#
# It does not touch any pre-existing mount other than the mount point given to it.
#
# The mount point must already exist as a root owned directory, every component
# included. This script never creates it: it unmounts and mounts that path as
# root, so a component it created, or one another user could replace, would be
# a way to redirect those operations elsewhere.
#
# Usage:
#   sudo ./testing/test_logrotate_e2e.sh <nfs_host>:<export> <mount_point> [mount_opts]
#
# Example:
#   sudo mkdir -p /mount/ipstorageaccrm/nfstestshare
#   sudo ./testing/test_logrotate_e2e.sh \
#       ipstorageaccrm.file.core.windows.net:/ipstorageaccrm/nfstestshare \
#       /mount/ipstorageaccrm/nfstestshare \
#       vers=4,minorversion=1,sec=sys,nconnect=4
#

SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

NFS_SHARE="$1"
MOUNT_POINT="$2"
MOUNT_OPTS="${3:-vers=4,minorversion=1,sec=sys,nconnect=4}"

OPTDIR="/opt/microsoft/aznfs"
OPTDIRDATA="${OPTDIR}/data"
CONFIG_FILE="${OPTDIRDATA}/config"
LRCONF="/etc/logrotate.d/aznfs"
#
# Set by alloc_tmpdirs() to a path inside the private SCRATCH directory.
# A fixed path such as /var/log/aznfs-e2e is predictable, and this script
# runs as root, so a local user could replace it with a symlink between any
# check and the moment common.sh creates and writes through it.
#
ALTLOGDIR=

#
# Set by restore_logs() when it could not put a log back.
#
RESTORE_INCOMPLETE=no

#
# Both are allocated by alloc_tmpdirs() only once the arguments have been
# validated, so that a usage error exits without leaving
# temporary directories behind.
#
# SCRATCH holds every scratch file rather than a predictable /tmp path. This
# script runs as root, so a local user could otherwise pre-create those paths
# as symlinks and have the privileged run overwrite arbitrary files.
#
BACKUP=
SCRATCH=

PASS=0
FAIL=0
SKIP=0
FAILED_TESTS=()

RED="\e[2;31m"
GREEN="\e[2;32m"
YELLOW="\e[2;33m"
NORMAL="\e[0m"

ok()   { PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NORMAL}: $1"; }
nok()  { FAIL=$((FAIL+1)); FAILED_TESTS+=("$1"); echo -e "  ${RED}FAIL${NORMAL}: $1"; [ -n "${2:-}" ] && echo "        want: $2"; [ -n "${3:-}" ] && echo "        got:  $3"; }

# Reported separately so a share that cannot exercise a case is never mistaken
# for one that passed it.
skip() { SKIP=$((SKIP+1)); echo -e "  ${YELLOW}SKIP${NORMAL}: $1"; [ -n "$2" ] && echo "        $2"; }
info() { echo -e "${YELLOW}==> $*${NORMAL}"; }

assert_file()
{
    if [ -f "$2" ]; then ok "$1"; else nok "$1" "missing: $2"; fi
}

assert_contains()
{
    if [ -f "$3" ] && grep -qF -- "$2" "$3"; then
        ok "$1"
    else
        nok "$1" "'$2' not found in $3"
    fi
}

usage_check()
{
    if [ "$(id -u)" != "0" ]; then
        echo "This script must be run as root (it deploys files under $OPTDIR)."
        exit 1
    fi

    if [ -z "$NFS_SHARE" -o -z "$MOUNT_POINT" ]; then
        echo "Usage: sudo $0 <nfs_host>:<export> <mount_point> [mount_opts]"
        exit 1
    fi

    #
    # do_mount() unmounts $MOUNT_POINT before every mount, and this runs as
    # root, so a mistyped mount point would take down a live system path.
    # Validate it here rather than in do_mount, which has to stay free to
    # remount the target this script owns.
    #
    case "$MOUNT_POINT" in
        /*) ;;
        *)
            echo "Mount point must be an absolute path, got '$MOUNT_POINT'."
            exit 1
            ;;
    esac

    mp="$MOUNT_POINT"
    while [ "$mp" != "/" ] && [ "${mp%/}" != "$mp" ]; do
        mp="${mp%/}"
    done

    #
    # Stripping trailing slashes is not enough: "/var/log/.." passes the list
    # below and then resolves to /var when umount acts on it.
    #
    case "$mp/" in
        */../*|*/./*)
            echo "Mount point must not contain '.' or '..' components, got '$MOUNT_POINT'."
            exit 1
            ;;
    esac

    case "$mp" in
        /|/bin|/boot|/dev|/etc|/home|/lib|/lib32|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
            echo "Refusing '$mp' as a mount point: this script unmounts it before each mount."
            exit 1
            ;;
    esac

    #
    # Every component of the mount point must already exist as a real,
    # root owned directory that no other user can swap out. Rejecting only the
    # symlinks that exist right now is not enough: do_mount() runs umount and
    # mount on this path as root, so a component created or replaced after the
    # check would redirect those operations somewhere else.
    #
    # Requiring the whole path to pre-exist removes the "created later" half,
    # which is also why do_mount() no longer runs mkdir -p. Requiring every
    # directory on it to be root owned and not writable by anyone else removes
    # the "replaced later" half, since renaming an entry needs write permission
    # on its parent. A sticky parent such as /tmp is still fine: there only the
    # owner of an entry can rename it, and every entry here is root owned.
    #
    # Split on / only, with globbing off: unquoted ${mp//\// } would word split
    # "/safe dir/target" into unrelated tokens and walk neither of them, and a
    # component containing * would expand against the CWD.
    #
    mp_oldifs=$IFS
    IFS=/
    set -f
    mp_parts=($mp)
    IFS=$mp_oldifs
    set +f

    mp_walk=
    mp_paths=("/")
    for mp_part in "${mp_parts[@]}"; do
        [ -z "$mp_part" ] && continue
        mp_walk="${mp_walk}/${mp_part}"
        mp_paths+=("$mp_walk")
    done

    mp_bad=
    for mp_walk in "${mp_paths[@]}"; do
        if [ -L "$mp_walk" ]; then
            mp_bad="Mount point component '$mp_walk' is a symlink, refusing '$MOUNT_POINT'."
        elif [ ! -d "$mp_walk" ]; then
            mp_bad="Mount point component '$mp_walk' does not exist or is not a directory.
This test never creates the mount point; create it as root first, then re-run."
        elif [ "$(stat -c %u "$mp_walk" 2>/dev/null)" != "0" ]; then
            mp_bad="Mount point component '$mp_walk' is not owned by root, refusing '$MOUNT_POINT'."
        else
            # %a is 3 or 4 digits, normalized so the bit positions are fixed.
            mp_mode=$(stat -c %a "$mp_walk" 2>/dev/null)
            mp_mode=$(printf '%04d' "$((10#${mp_mode:-0}))")

            case "$mp_mode" in
                [1357]???) ;;
                ??[2367]?|???[2367])
                    mp_bad="Mount point component '$mp_walk' is group or world writable (mode $mp_mode) and not sticky, refusing '$MOUNT_POINT'."
                    ;;
            esac
        fi

        [ -n "$mp_bad" ] && break
    done

    if [ -n "$mp_bad" ]; then
        echo "$mp_bad"
        exit 1
    fi

    #
    # Anything already mounted here that is not an NFS mount was not put here
    # by this script, so it is not ours to unmount. A Turbo mount is a FUSE
    # mount served by aznfsclient, so findmnt reports fuse.aznfsclient rather
    # than nfs.
    #
    if mountpoint -q "$mp" 2>/dev/null; then
        mp_fstype=$(findmnt -n -o FSTYPE "$mp" 2>/dev/null | tail -1)

        case "$mp_fstype" in
            nfs|nfs4|aznfs|fuse.aznfsclient) ;;
            *)
                echo "'$mp' is already mounted (${mp_fstype:-unknown}) and is not an NFS mount."
                echo "Refusing to unmount it. Pick a mount point this test can own."
                exit 1
                ;;
        esac
    fi

    MOUNT_POINT="$mp"

    if [ ! -d "$OPTDIR" ]; then
        echo "AZNFS does not appear to be installed ($OPTDIR missing)."
        exit 1
    fi

    if command -v logrotate >/dev/null 2>&1; then :; else
        echo "logrotate is not installed, cannot run rotation tests."
        exit 1
    fi

}

#
# safe_logdir() decides, together with the writability check below, where the
# installed AZNFS actually logs. Pulled straight out of lib/common.sh rather
# than copied, so the rule this test applies cannot drift from the shipped one.
#
eval "$(sed -n '/^safe_logdir()$/,/^}$/p' "$SOURCE_DIR/lib/common.sh")"

if ! declare -f safe_logdir >/dev/null 2>&1; then
    echo "Not able to extract safe_logdir() from lib/common.sh, aborting."
    exit 1
fi

#
# The log directory the installed config points at, the default when it is not
# set or not usable. Mirrors how common.sh resolves it.
#
logdir_is_usable()
{
    local d="$1"

    safe_logdir "$d" || return 1

    # -w follows a link, so the link itself has to be rejected first.
    [ -L "$d/aznfs.log" ] && return 1
    [ -e "$d/aznfs.log" ] && [ ! -w "$d/aznfs.log" ] && return 1

    return 0
}

#
# The packaged default, read out of common.sh rather than repeated here. This
# test used to assume the default was the data directory; when the shipped
# default moved to /var/log/aznfs the assumption silently made backup_state()
# skip the directory the installation actually logs to, so the run could rotate
# and truncate live logs and then restore nothing.
#
AZNFS_LOGDIR_DEFAULT=$(sed -n 's|^AZNFS_LOGDIR_DEFAULT="\(.*\)"$|\1|p' "$SOURCE_DIR/lib/common.sh" | head -1)

if [ -z "$AZNFS_LOGDIR_DEFAULT" ]; then
    echo "Not able to read AZNFS_LOGDIR_DEFAULT from lib/common.sh, aborting."
    exit 1
fi

#
# Mirrors fallback_logdir() in common.sh: the packaged default is preferred,
# and the data directory is the last resort when it cannot be used.
#
default_logdir()
{
    if logdir_is_usable "$AZNFS_LOGDIR_DEFAULT"; then
        echo "$AZNFS_LOGDIR_DEFAULT"
    else
        echo "$OPTDIRDATA"
    fi
}

DEFAULT_LOGDIR=$(default_logdir)

installed_logdir()
{
    local d=

    if [ -f "$CONFIG_FILE" ]; then
        d=$(sed -n 's|^[[:space:]]*AZNFS_LOGDIR[[:space:]]*=[[:space:]]*||p' "$CONFIG_FILE" 2>/dev/null |
                tail -n1 | sed -e 's|[[:space:]]*$||' -e 's|^"\(.*\)"$|\1|' -e "s|^'\(.*\)'$|\1|")
    fi

    while [ -n "$d" ] && [ "$d" != "/" ] && [ "${d%/}" != "$d" ]; do
        d=${d%/}
    done

    case "$d" in
        ""|/|/*[!A-Za-z0-9._/@+-]*) d="$DEFAULT_LOGDIR" ;;
        /*) ;;
        *) d="$DEFAULT_LOGDIR" ;;
    esac

    #
    # The same fallback common.sh makes. A directory that is not root owned, or
    # that holds a log we cannot append to, is not where the installed AZNFS
    # logs, so this test must not back it up, rotate it or restore over it
    # either. It runs as root, so doing so would mean touching files outside
    # the installation it claims to restore.
    #
    # Checked even when the path does not exist yet. safe_logdir() walks up to
    # the deepest existing component, and restore_state() copies the backed up
    # logs into this path later, so a missing directory under an ancestor
    # somebody else can write to is exactly where they would place something to
    # catch that copy.
    #
    # The default is not exempt: common.sh validates it too, and if the
    # installation's own log directory is unsafe there is nowhere left to fall
    # back to. Signalled by return code, because this runs inside a command
    # substitution where exit would only leave the subshell.
    #
    if ! logdir_is_usable "$d"; then
        if [ "$d" == "$DEFAULT_LOGDIR" ]; then
            echo "Default log directory '$d' is not usable, refusing to run." >&2
            return 1
        fi

        echo "Configured log directory '$d' is not usable, AZNFS falls back to '$DEFAULT_LOGDIR'." >&2
        d="$DEFAULT_LOGDIR"

        if ! logdir_is_usable "$d"; then
            echo "Default log directory '$d' is not usable either, refusing to run." >&2
            return 1
        fi
    fi

    echo "$d"
}

#
# Allocate the temporary directories. Called after usage_check() so that early
# exits do not leak them.
#
#
# Checked rather than assumed. This runs as root, and an empty BACKUP or
# SCRATCH would send the backup, the deployment and the cleanup at paths
# rooted in "/" instead of aborting.
#
alloc_tmpdirs()
{
    BACKUP=$(mktemp -d /tmp/aznfs-e2e-backup.XXXXXX) || BACKUP=
    if [ -z "$BACKUP" -o ! -d "$BACKUP" ]; then
        echo "Not able to create the backup directory, aborting."
        exit 1
    fi

    #
    # Not under /tmp, and not under $HOME either. SCRATCH holds ALTLOGDIR, the
    # alternate log directory this test configures AZNFS to use, and
    # safe_logdir() refuses a world writable ancestor, so /tmp would be
    # rejected by the very rule being tested. $HOME is no good either: this
    # runs as root, but under "sudo -E" $HOME is still the calling user's, and
    # they could then swap the scratch directory for a symlink while root is
    # writing through it. Root's home comes from passwd, not the environment.
    #
    local roothome
    roothome=$(getent passwd 0 | cut -d: -f6)
    roothome="${roothome:-/root}"

    if [ ! -d "$roothome" ] || [ "$(stat -c '%u' "$roothome" 2>/dev/null)" != "0" ]; then
        echo "Root's home '$roothome' is missing or not root owned, aborting."
        rmdir "$BACKUP" 2>/dev/null
        exit 1
    fi

    SCRATCH=$(mktemp -d "${roothome}/.aznfs-e2e-scratch.XXXXXX") || SCRATCH=
    if [ -z "$SCRATCH" -o ! -d "$SCRATCH" ]; then
        echo "Not able to create the scratch directory, aborting."
        rmdir "$BACKUP" 2>/dev/null
        exit 1
    fi

    if ! chmod 0755 "$SCRATCH"; then
        echo "Not able to set the scratch directory mode, aborting."
        rm -rf "$SCRATCH"
        rmdir "$BACKUP" 2>/dev/null
        exit 1
    fi

    # Private, created atomically by mktemp -d above, so nothing to race on.
    ALTLOGDIR="$SCRATCH/altlog"
}

#
# Save everything we are about to modify so the machine can be put back exactly
# as it was, including the case where the test aborts midway.
#
#
# Copy one file into the backup. cleanup() restores from these, and a missing
# backup means the original is restored wrong or removed outright, so a failed
# copy has to stop the run before anything is deployed.
#
backup_file()
{
    local src="$1"
    local dest="$2"

    [ -f "$src" ] || return 0

    if ! cp -a "$src" "$dest"; then
        echo "FATAL: not able to back up '$src' to '$dest'."
        echo "Refusing to continue, the run could not put the original back."
        exit 1
    fi
}

#
# Copy a glob of live logs into the backup. The tests rotate and truncate the
# originals, so a silently incomplete backup would be restored over real logs
# afterwards. A glob matching nothing is normal and fine; anything else, a full
# filesystem, an unreadable log, an I/O error, has to stop the run before it
# touches anything.
#
backup_logs()
{
    local pattern="$1"
    local dest="$2"
    local f

    for f in $pattern; do
        [ -e "$f" ] || continue

        if ! cp -a "$f" "$dest/"; then
            echo "FATAL: not able to back up '$f' to '$dest'."
            echo "Refusing to continue, the run would rotate logs it cannot restore."
            exit 1
        fi
    done
}

backup_state()
{
    info "Backing up live state to $BACKUP"

    mkdir -p "$BACKUP/optdir"
    for f in common.sh nfsv3mountscript.sh nfsv4mountscript.sh mountscript.sh aznfs_install.sh aznfs.logrotate; do
        backup_file "$OPTDIR/$f" "$BACKUP/optdir/"
    done

    backup_file "$CONFIG_FILE" "$BACKUP/config"
    backup_file "$LRCONF" "$BACKUP/logrotate.aznfs"

    #
    # The tests rotate and truncate the live logs, so back them up too and put
    # them back afterwards. Without this a test run would destroy whatever
    # history the machine had accumulated.
    #
    # The installed config may point AZNFS_LOGDIR somewhere other than the
    # default, and the watchdog is restarted while that is still in effect, so
    # the configured directory has to be covered as well.
    #
    mkdir -p "$BACKUP/logs/default"
    backup_logs "$DEFAULT_LOGDIR/aznfs.log*" "$BACKUP/logs/default"
    backup_logs "$DEFAULT_LOGDIR/turbo*.log*" "$BACKUP/logs/default"

    if ! CONFIGURED_LOGDIR=$(installed_logdir); then
        echo "Refusing to back up or rotate through an unusable log directory."
        exit 1
    fi

    echo "$CONFIGURED_LOGDIR" > "$BACKUP/configured_logdir"

    # common.sh creates a missing configured directory while being sourced, so
    # remember whether it was there to begin with.
    [ -d "$CONFIGURED_LOGDIR" ] && echo yes > "$BACKUP/configured_logdir_existed"

    if [ "$CONFIGURED_LOGDIR" != "$DEFAULT_LOGDIR" ]; then
        info "Also backing up the configured log directory $CONFIGURED_LOGDIR"
        mkdir -p "$BACKUP/logs/configured"
        backup_logs "$CONFIGURED_LOGDIR/aznfs.log*" "$BACKUP/logs/configured"
        backup_logs "$CONFIGURED_LOGDIR/turbo*.log*" "$BACKUP/logs/configured"
    fi
}

#
# Put one backed up file back where it came from. A failure here leaves the
# repo's scripts deployed over the installed ones, so it has to be reported
# rather than swallowed, and cleanup must not claim success afterwards.
#
restore_file()
{
    local src="$1"
    local dest="$2"

    if ! cp -a "$src" "$dest"; then
        echo "WARNING: not able to restore '$dest' from '$src'."
        RESTORE_INCOMPLETE=yes
        return 1
    fi
}

#
# Put the backed up logs back, then drop only the rotations this run created.
#
# The order matters: removing the live logs first and copying afterwards leaves
# production logs gone if a copy then fails on a full filesystem or an I/O
# error. Copying first means a failure leaves the originals in place, and it is
# reported rather than swallowed.
#
restore_logs()
{
    local src="$1"
    local dest="$2"
    local f base failed=0

    [ -d "$dest" ] || return 0

    for f in "$src"/*; do
        [ -e "$f" ] || continue

        if ! cp -a "$f" "$dest/"; then
            echo "WARNING: not able to restore '$(basename "$f")' into '$dest'."
            failed=1
        fi
    done

    if [ $failed -ne 0 ]; then
        echo "WARNING: logs in '$dest' were NOT fully restored."
        echo "The originals are still under $BACKUP, put them back by hand."
        RESTORE_INCOMPLETE=yes
        return 1
    fi

    #
    # Anything not in the backup is a rotation this run produced, with one
    # exception that matters: a mount or the watchdog running alongside this
    # test can create a live log here while it runs, and that file is not ours
    # to delete. Only numbered rotation artefacts are removed, so a live
    # aznfs.log or turbo*.log that appeared during the run survives.
    #
    for f in "$dest"/aznfs.log* "$dest"/turbo*.log*; do
        [ -e "$f" ] || continue

        base=$(basename "$f")
        [ -e "$src/$base" ] && continue

        case "$base" in
            *.log.[0-9]*)
                rm -f "$f"
                ;;
            *)
                echo "WARNING: leaving '$base' in '$dest', it appeared during the run"
                echo "         but is not a rotation this test can attribute to itself."
                ;;
        esac
    done
}

restore_state()
{
    #
    # Only restore if we actually started deploying, otherwise we could delete
    # live files we never backed up.
    #
    # Nothing was deployed, so nothing needs restoring and the backup is of no
    # use to anyone. Removing it here stops a run that aborts during
    # backup_state from leaving a root owned directory behind every time.
    #
    if [ ! -f "$BACKUP/.deploying" ]; then
        rm -rf "$BACKUP"
        return
    fi

    info "Restoring original state"

    for f in "$BACKUP/optdir"/*; do
        [ -f "$f" ] || continue
        restore_file "$f" "$OPTDIR/$(basename "$f")"
    done

    # aznfs.logrotate is new in this change, remove it if it wasn't there before.
    if [ ! -f "$BACKUP/optdir/aznfs.logrotate" ]; then
        rm -f "$OPTDIR/aznfs.logrotate"
    fi

    if [ -f "$BACKUP/config" ]; then
        restore_file "$BACKUP/config" "$CONFIG_FILE"
    else
        rm -f "$CONFIG_FILE"
    fi

    if [ -f "$BACKUP/logrotate.aznfs" ]; then
        restore_file "$BACKUP/logrotate.aznfs" "$LRCONF"
    else
        rm -f "$LRCONF"
    fi

    #
    # Safe to remove: it lives inside the private SCRATCH directory that
    # alloc_tmpdirs() created, so it can only be one we made.
    #
    rm -rf "$ALTLOGDIR"

    #
    # Put the logs back exactly as we found them, dropping the rotated files
    # this run created.
    #
    restore_logs "$BACKUP/logs/default" "$DEFAULT_LOGDIR"

    # And the configured directory, when it is a different one.
    cfg=$(cat "$BACKUP/configured_logdir" 2>/dev/null)
    if [ -n "$cfg" -a "$cfg" != "$DEFAULT_LOGDIR" -a -d "$cfg" ]; then
        restore_logs "$BACKUP/logs/configured" "$cfg"

        #
        # If the directory only came into existence because the test sourced
        # common.sh, take it away again so a custom configured installation is
        # left exactly as it was found.
        #
        if [ ! -f "$BACKUP/configured_logdir_existed" ]; then
            rmdir "$cfg" 2>/dev/null
        fi
    fi

    # Put the watchdogs back on the original scripts.
    systemctl restart aznfswatchdog aznfswatchdogv4 2>/dev/null

    if [ "$RESTORE_INCOMPLETE" == "yes" ]; then
        echo "Restoration was INCOMPLETE, see the warnings above. $BACKUP is kept."
    else
        #
        # Removed on success. Keeping it "for inspection" leaks a directory per
        # run, and there is nothing to inspect once everything went back.
        #
        echo "Original files and logs restored from $BACKUP."
        [ -n "$BACKUP" ] && rm -rf "$BACKUP"
    fi
}

cleanup()
{
    mountpoint -q "$MOUNT_POINT" 2>/dev/null && umount "$MOUNT_POINT" 2>/dev/null
    restore_state
    rm -rf "$SCRATCH"
}

deploy_build()
{
    info "Deploying repo scripts over the installed ones"

    #
    # A half deployed installation would be tested and then restored as if it
    # were whole, so any failure here has to stop the run.
    #
    deploy_file()
    {
        if ! cp -f "$1" "$2"; then
            echo "Not able to deploy '$2', aborting before the installation is changed further."
            echo "The backup is in '$BACKUP', restore_state() will put the originals back."
            exit 1
        fi
    }

    #
    # Marked before the first copy, not after the last. This is what lets
    # restore_state() put the originals back, and a deployment that fails half
    # way through is precisely when that has to happen: by then the
    # installation is already a mix of repo and installed files.
    #
    touch "$BACKUP/.deploying"

    deploy_file "$SOURCE_DIR/lib/common.sh"            "$OPTDIR/common.sh"
    deploy_file "$SOURCE_DIR/src/nfsv3mountscript.sh"  "$OPTDIR/nfsv3mountscript.sh"
    deploy_file "$SOURCE_DIR/src/nfsv4mountscript.sh"  "$OPTDIR/nfsv4mountscript.sh"
    deploy_file "$SOURCE_DIR/src/mountscript.sh"       "$OPTDIR/mountscript.sh"
    deploy_file "$SOURCE_DIR/scripts/aznfs_install.sh" "$OPTDIR/aznfs_install.sh"
    deploy_file "$SOURCE_DIR/src/aznfs.logrotate"      "$OPTDIR/aznfs.logrotate"

    if ! chmod 0644 "$OPTDIR/common.sh" "$OPTDIR/aznfs.logrotate" ||
       ! chmod 0755 "$OPTDIR"/*.sh; then
        echo "Not able to set permissions on the deployed files, aborting."
        echo "The backup is in '$BACKUP', restore_state() will put the originals back."
        exit 1
    fi

    # Watchdogs must pick up the new common.sh.
    systemctl restart aznfswatchdog aznfswatchdogv4
    sleep 3
}

set_logdir()
{
    sed -i '/AZNFS_LOGDIR/d' "$CONFIG_FILE" 2>/dev/null
    [ -n "$1" ] && echo "AZNFS_LOGDIR=$1" >> "$CONFIG_FILE"
}

do_mount()
{
    #
    # No mkdir -p here: usage_check() has already established that every
    # component exists and is root owned, and creating one now would reopen
    # the window it closes.
    #
    mountpoint -q "$MOUNT_POINT" && umount "$MOUNT_POINT"
    mount -t aznfs "$NFS_SHARE" "$MOUNT_POINT" -o "$MOUNT_OPTS"
}

usage_check

echo "=================================================="
echo " AZNFS log directory / rotation  --  E2E (root)"
echo "=================================================="
echo " share : $NFS_SHARE"
echo " mount : $MOUNT_POINT"
echo " opts  : $MOUNT_OPTS"
echo "=================================================="

alloc_tmpdirs

#
# Installed before backup_state, not after: backup_state exits when a backup
# copy fails, and that must still take the private SCRATCH directory with it.
#
trap cleanup EXIT

backup_state
deploy_build

# ---------------------------------------------------------------------------
info "[1] Default log directory"
# ---------------------------------------------------------------------------

set_logdir ""
rm -f "$LRCONF"

if do_mount; then
    ok "mount succeeded with default log dir"
else
    nok "mount succeeded with default log dir" "mount command failed"
fi

assert_file  "aznfs.log exists in default dir" "$DEFAULT_LOGDIR/aznfs.log"
assert_file  "logrotate config generated"      "$LRCONF"
assert_contains "logrotate covers default aznfs.log" "$DEFAULT_LOGDIR/aznfs.log" "$LRCONF"
assert_contains "marker records default dir"         "# AZNFS_LOGDIR: $DEFAULT_LOGDIR" "$LRCONF"

if logrotate -d -s "$SCRATCH/lr1.state" "$LRCONF" 2>&1 | grep -qiE "^error:"; then
    nok "logrotate accepts generated config" "$(logrotate -d -s "$SCRATCH/lr1.state" "$LRCONF" 2>&1 | grep -i '^error:' | head -1)"
else
    ok "logrotate accepts generated config"
fi

mount_log_lines=$(wc -l < "$DEFAULT_LOGDIR/aznfs.log")
echo "    (aznfs.log currently $mount_log_lines lines)"

# ---------------------------------------------------------------------------
info "[2] Real rotation with a live mount (copytruncate)"
# ---------------------------------------------------------------------------

# Force rotation while the mount is live, then confirm logging still works.
#
# Any rotation restored from the backup is cleared first: it is indistinguishable
# from one this phase produced, so leaving it would let the assertion below pass
# on a rotation that happened before the test started.
#
rm -f "$DEFAULT_LOGDIR"/aznfs.log.[0-9]*
before_inode=$(stat -c %i "$DEFAULT_LOGDIR/aznfs.log")
logrotate -f -s "$SCRATCH/lr1.state" "$LRCONF" >"$SCRATCH/lr1.out" 2>&1
lr1_rc=$?
after_inode=$(stat -c %i "$DEFAULT_LOGDIR/aznfs.log")

assert_eq_inode()
{
    if [ "$before_inode" == "$after_inode" ]; then
        ok "copytruncate kept the same inode (open fds stay valid)"
    else
        nok "copytruncate kept the same inode (open fds stay valid)" \
            "inode changed $before_inode -> $after_inode"
    fi
}
assert_eq_inode

if [ "$lr1_rc" -eq 0 ] && ls "$DEFAULT_LOGDIR"/aznfs.log.1* >/dev/null 2>&1; then
    ok "rotated copy created"
else
    nok "rotated copy created" "a fresh aznfs.log.1*" \
        "logrotate rc=$lr1_rc, $(tail -2 "$SCRATCH/lr1.out" 2>/dev/null)"
fi

# Trigger fresh logging (remount) and confirm it lands in the live file.
umount "$MOUNT_POINT" 2>/dev/null
do_mount
sleep 2

if [ -s "$DEFAULT_LOGDIR/aznfs.log" ]; then
    ok "logging continues into the live log after rotation"
else
    nok "logging continues into the live log after rotation" "aznfs.log is empty"
fi

# ---------------------------------------------------------------------------
info "[3] Change log directory MIDWAY (watchdog running, mount live)"
# ---------------------------------------------------------------------------

old_log_size=$(stat -c %s "$DEFAULT_LOGDIR/aznfs.log")
old_log_sum=$(md5sum "$DEFAULT_LOGDIR/aznfs.log" | cut -d' ' -f1)

set_logdir "$ALTLOGDIR"

# A new mount picks up the new directory.
umount "$MOUNT_POINT" 2>/dev/null
do_mount
sleep 2

assert_file "new log dir created"                 "$ALTLOGDIR/aznfs.log"
assert_file "OLD log file still present"          "$DEFAULT_LOGDIR/aznfs.log"
assert_contains "logrotate covers NEW dir"        "$ALTLOGDIR/aznfs.log"   "$LRCONF"
assert_contains "marker updated to new dir"       "# AZNFS_LOGDIR: $ALTLOGDIR" "$LRCONF"

if grep -qF -- "$DEFAULT_LOGDIR/aznfs.log" "$LRCONF"; then
    nok "only the configured dir is rotated" "old dir not listed" "old dir still listed"
else
    ok "only the configured dir is rotated"
fi

if logrotate -d -s "$SCRATCH/lr2.state" "$LRCONF" 2>&1 | grep -qiE "^error:"; then
    nok "config after the change is valid" "no errors" \
        "$(logrotate -d -s "$SCRATCH/lr2.state" "$LRCONF" 2>&1 | grep -i '^error:' | head -1)"
else
    ok "config after the change is valid"
fi

#
# The watchdog was started before the change, so it must still be writing to the
# old directory. This is expected behaviour and the reason the old directory
# stays covered by logrotate.
#
wd_pid=$(systemctl show -p MainPID --value aznfswatchdog 2>/dev/null)
if [ -n "$wd_pid" ] && [ "$wd_pid" != "0" ]; then
    wd_log=$(ls -l /proc/$wd_pid/fd 2>/dev/null | grep -o '/[^ ]*aznfs\.log' | head -1)
    echo "    watchdog(pid $wd_pid) log target: ${wd_log:-<not holding aznfs.log open>}"
fi

new_sum=$(md5sum "$DEFAULT_LOGDIR/aznfs.log" | cut -d' ' -f1)
if [ "$old_log_sum" == "$new_sum" ]; then
    echo "    old log unchanged since the switch"
else
    echo "    old log still being appended to (expected until watchdog restart)"
fi

# Old content must never be moved or truncated by the switch itself.
new_size=$(stat -c %s "$DEFAULT_LOGDIR/aznfs.log")
if [ "$new_size" -ge "$old_log_size" ]; then
    ok "old log content preserved (not moved or truncated)"
else
    nok "old log content preserved (not moved or truncated)" \
        "size shrank $old_log_size -> $new_size"
fi

# ---------------------------------------------------------------------------
info "[4] Rotation works in the NEW directory"
# ---------------------------------------------------------------------------

logrotate -f -s "$SCRATCH/lr2.state" "$LRCONF" 2>/dev/null

if ls "$ALTLOGDIR"/aznfs.log.1* >/dev/null 2>&1; then
    ok "new dir log rotated"
else
    nok "new dir log rotated" "no rotated file in $ALTLOGDIR"
fi

# ---------------------------------------------------------------------------
info "[5] Watchdog restart moves it to the new directory"
# ---------------------------------------------------------------------------

systemctl restart aznfswatchdog aznfswatchdogv4
sleep 6

wd_pid=$(systemctl show -p MainPID --value aznfswatchdog 2>/dev/null)
wd_log=$(ls -l /proc/$wd_pid/fd 2>/dev/null | grep -o '/[^ ]*aznfs\.log' | head -1)
echo "    watchdog(pid $wd_pid) now targets: ${wd_log:-<none open right now>}"

before=$(stat -c %s "$ALTLOGDIR/aznfs.log" 2>/dev/null || echo 0)
umount "$MOUNT_POINT" 2>/dev/null
do_mount
sleep 2
after=$(stat -c %s "$ALTLOGDIR/aznfs.log" 2>/dev/null || echo 0)

if [ "$after" -gt "$before" ]; then
    ok "post-restart logging goes to the new directory"
else
    nok "post-restart logging goes to the new directory" "new log did not grow ($before -> $after)"
fi

# ---------------------------------------------------------------------------
info "[6] Switch back to the default directory"
# ---------------------------------------------------------------------------

set_logdir ""
umount "$MOUNT_POINT" 2>/dev/null
do_mount
sleep 2

assert_contains "marker back to default" "# AZNFS_LOGDIR: $DEFAULT_LOGDIR" "$LRCONF"

dupes=$(grep -c -- "$DEFAULT_LOGDIR/aznfs.log" "$LRCONF")
if [ "$dupes" == "1" ]; then
    ok "no duplicate entry after switching back"
else
    nok "no duplicate entry after switching back" "default path appears $dupes times"
fi

if logrotate -d -s "$SCRATCH/lr3.state" "$LRCONF" 2>&1 | grep -qiE "^error:"; then
    nok "config valid after switching back" "logrotate reported an error"
else
    ok "config valid after switching back"
fi

# ---------------------------------------------------------------------------
info "[7] Bad log directory must not break mounting"
# ---------------------------------------------------------------------------

set_logdir "/proc/definitely/not/creatable"
umount "$MOUNT_POINT" 2>/dev/null

if do_mount; then
    ok "mount still succeeds with an unusable AZNFS_LOGDIR"
else
    nok "mount still succeeds with an unusable AZNFS_LOGDIR" "mount failed"
fi

assert_file "fell back to default log file" "$DEFAULT_LOGDIR/aznfs.log"

umount "$MOUNT_POINT" 2>/dev/null

# ---------------------------------------------------------------------------
info "[8] Size policy is honoured by a normal (non-forced) logrotate run"
# ---------------------------------------------------------------------------

#
# Phases 2 and 4 use 'logrotate -f', which bypasses the size threshold. Here we
# check the policy itself: a small log must NOT be rotated by a normal run, no
# matter how old it is. This is the regression guard for re-introducing time
# based rotation.
#
set_logdir ""
umount "$MOUNT_POINT" 2>/dev/null
do_mount
sleep 2

# Make the live log small and old.
: > "$DEFAULT_LOGDIR/aznfs.log"
echo "a small amount of history" >> "$DEFAULT_LOGDIR/aznfs.log"
touch -d '60 days ago' "$DEFAULT_LOGDIR/aznfs.log"

# Pretend it was last rotated long ago, so any time based policy would fire.
cat > "$SCRATCH/size.state" <<EOF
logrotate state -- version 2
"$DEFAULT_LOGDIR/aznfs.log" 2000-01-01-0:0:0
EOF

size_out=$(logrotate -d -s "$SCRATCH/size.state" "$LRCONF" 2>&1)

if echo "$size_out" | grep -A6 "considering log $DEFAULT_LOGDIR/aznfs.log" | grep -q "does not need rotating"; then
    ok "small 60-day-old log NOT rotated (size policy, no time rotation)"
else
    nok "small 60-day-old log NOT rotated (size policy, no time rotation)" \
        "$(echo "$size_out" | grep -A6 "considering log $DEFAULT_LOGDIR/aznfs.log" | tail -2)"
fi

if echo "$size_out" | grep -qiE "^error:"; then
    nok "no logrotate errors on the live config" "$(echo "$size_out" | grep -i '^error:' | head -1)"
else
    ok "no logrotate errors on the live config"
fi

#
# Everything above this point rotates with "logrotate -f", which ignores the
# size threshold completely: under -f even a 1-byte log rotates. The two checks
# just above use "logrotate -d", a dry run that changes nothing on disk. So
# until here nothing has shown that crossing "size" is what actually causes a
# rotation, which is the only thing that ever triggers one in production.
#
lr_size=$(grep -m1 -E '^[[:space:]]*size[[:space:]]+' "$LRCONF" | awk '{print $2}')
case "$lr_size" in
    *[kK]) lr_bytes=$(( ${lr_size%[kK]} * 1024 )) ;;
    *[mM]) lr_bytes=$(( ${lr_size%[mM]} * 1024 * 1024 )) ;;
    *[gG]) lr_bytes=$(( ${lr_size%[gG]} * 1024 * 1024 * 1024 )) ;;
    *[0-9]) lr_bytes=$lr_size ;;
    *)     lr_bytes="" ;;
esac

if [ -z "$lr_bytes" ]; then
    skip "oversized log IS rotated by a non-forced run" "could not parse size '$lr_size' from the live policy"
    skip "copytruncate kept the inode on a size-triggered rotation" "no parsed size"
else
    rm -f "$DEFAULT_LOGDIR"/aznfs.log.[0-9]*
    : > "$DEFAULT_LOGDIR/aznfs.log"
    dd if=/dev/zero bs=1M count=$(( lr_bytes / 1048576 + 1 )) status=none >> "$DEFAULT_LOGDIR/aznfs.log"
    ino_before=$(stat -c %i "$DEFAULT_LOGDIR/aznfs.log")

    cat > "$SCRATCH/real.state" <<EOF
logrotate state -- version 2
"$DEFAULT_LOGDIR/aznfs.log" 2000-01-01-0:0:0
EOF
    logrotate -s "$SCRATCH/real.state" "$LRCONF" >"$SCRATCH/real.out" 2>&1

    if [ -f "$DEFAULT_LOGDIR/aznfs.log.1" ]; then
        ok "oversized log IS rotated by a non-forced run"
    else
        nok "oversized log IS rotated by a non-forced run" \
            "aznfs.log.1 after exceeding $lr_size" "$(tail -2 "$SCRATCH/real.out")"
    fi

    ino_after=$(stat -c %i "$DEFAULT_LOGDIR/aznfs.log" 2>/dev/null)
    if [ -n "$ino_after" ] && [ "$ino_before" = "$ino_after" ]; then
        ok "copytruncate kept the inode on a size-triggered rotation"
    else
        nok "copytruncate kept the inode on a size-triggered rotation" \
            "inode $ino_before" "inode ${ino_after:-file missing}"
    fi

    rm -f "$DEFAULT_LOGDIR"/aznfs.log.[0-9]*
    : > "$DEFAULT_LOGDIR/aznfs.log"
fi

assert_contains "config covers turbo logs glob" "$DEFAULT_LOGDIR/turbo*.log" "$LRCONF"

# ---------------------------------------------------------------------------
info "[8b] Turbo client logs are really rotated"
# ---------------------------------------------------------------------------

#
# Turbo logs only exist for a v3 Turbo mount, so on any other share there is
# nothing to assert and these are skipped rather than failed. Everything above
# only proves the glob is in the policy; this is the part that needs a real
# aznfsclient log, which is why it cannot be covered synthetically.
#
# set_logdir "" above put the installation back on the default directory, so
# that is where the turbo log is now. CONFIGURED_LOGDIR is what was configured
# at backup time and would miss it on a machine that uses a custom one.
turbo_log=$(ls -1 "$DEFAULT_LOGDIR"/turbo*.log 2>/dev/null | head -1)

if [ -z "$turbo_log" ]; then
    skip "turbo log produced by the mount" "no turbo*.log present, not a v3 Turbo mount"
    skip "turbo log matched by the live policy" "no turbo log to match"
    skip "turbo log rotated by size" "no turbo log to rotate"
    skip "turbo log truncated in place (copytruncate)" "no turbo log to rotate"
else
    ok "turbo log produced by the mount"

    #
    # logrotate has to actually select it, not merely contain a glob that looks
    # like it would. A mount point with characters the glob does not cover, or
    # a log written somewhere else, would show up here and nowhere else.
    #
    if logrotate -d -s "$SCRATCH/turbo.state" "$LRCONF" 2>&1 | grep -qF "considering log $turbo_log"; then
        ok "turbo log matched by the live policy"
    else
        nok "turbo log matched by the live policy" "logrotate considers $turbo_log" "not selected"
    fi

    #
    # aznfsclient holds this log open for the life of the mount, which is the
    # whole reason the policy uses copytruncate. Rotating it for real while the
    # mount is up is the only way to see that the client keeps logging to the
    # same inode afterwards.
    #
    turbo_inode_before=$(stat -c '%i' "$turbo_log")
    head -c 2000000 /dev/urandom | base64 >> "$turbo_log"

    # A rotation left over from an earlier run would satisfy the check below
    # without logrotate having done anything now.
    rm -f "${turbo_log}".[0-9]*

    cp "$LRCONF" "$SCRATCH/turbo.conf"
    sed -i 's/^\([[:space:]]*\)size .*/\1size 1k/' "$SCRATCH/turbo.conf"

    # No -f: it rotates regardless of size, so the 1k threshold above would
    # never be what selects the log and this would pass with size removed.
    logrotate -s "$SCRATCH/turbo.state" "$SCRATCH/turbo.conf" >"$SCRATCH/turbo.out" 2>&1

    #
    # Non-empty, not just present: an empty .1 would mean logrotate created the
    # file without copying the log into it.
    #
    turbo_rotation=$(find "$(dirname "$turbo_log")" -maxdepth 1 -name "$(basename "$turbo_log").1*" -size +0c 2>/dev/null | head -1)

    if [ -n "$turbo_rotation" ]; then
        ok "turbo log rotated by size"
    else
        nok "turbo log rotated by size" "a non-empty ${turbo_log}.1" "$(tail -2 "$SCRATCH/turbo.out")"
    fi

    turbo_inode_after=$(stat -c '%i' "$turbo_log" 2>/dev/null)

    #
    # Only meaningful once something actually rotated: if logrotate selected
    # nothing the inode is trivially unchanged and this would pass for the
    # wrong reason.
    #
    if [ -z "$turbo_rotation" ]; then
        nok "turbo log truncated in place (copytruncate)" \
            "a rotation to inspect" "nothing rotated, so the inode proves nothing"
    elif [ -n "$turbo_inode_after" ] && [ "$turbo_inode_before" == "$turbo_inode_after" ]; then
        ok "turbo log truncated in place (copytruncate)"
    else
        nok "turbo log truncated in place (copytruncate)" \
            "same inode $turbo_inode_before" "now $turbo_inode_after, aznfsclient would keep writing to the rotated file"
    fi
fi

# ---------------------------------------------------------------------------
info "[9] A process started before the change keeps using the OLD directory"
# ---------------------------------------------------------------------------

#
# The watchdog resolves LOGFILE once when it sources common.sh, so after a log
# directory change it keeps writing to the directory it started with. The
# watchdog is event driven and may be idle during this test, so we reproduce
# the same behaviour explicitly with the production common.sh.
#
set_logdir ""
: > "$DEFAULT_LOGDIR/aznfs.log"

cat > "$SCRATCH/longrun.sh" <<'LONGRUN'
AZNFS_VERSION=e2e
. /opt/microsoft/aznfs/common.sh
echo "$LOGFILE" > __TARGET__
# Wait for the log directory to be switched under us, then log.
sleep 6
vecho "long running process still logging after the switch"
echo "$LOGFILE" >> __TARGET__
LONGRUN
sed -i "s|__TARGET__|$SCRATCH/longrun.target|g" "$SCRATCH/longrun.sh"

rm -f "$SCRATCH/longrun.target"
bash "$SCRATCH/longrun.sh" >/dev/null 2>&1 &
longrun_pid=$!
sleep 2

# Switch the log directory while it is running.
set_logdir "$ALTLOGDIR"
umount "$MOUNT_POINT" 2>/dev/null
do_mount
sleep 2

wait $longrun_pid 2>/dev/null
sleep 1

started_with=$(head -1 "$SCRATCH/longrun.target" 2>/dev/null)
ended_with=$(tail -1 "$SCRATCH/longrun.target" 2>/dev/null)

echo "    process resolved LOGFILE at start : $started_with"
echo "    ... and still used at the end     : $ended_with"

if [ "$started_with" == "$DEFAULT_LOGDIR/aznfs.log" ] && [ "$ended_with" == "$DEFAULT_LOGDIR/aznfs.log" ]; then
    ok "long running process keeps writing to the OLD directory (as expected)"
else
    nok "long running process keeps writing to the OLD directory (as expected)" \
        "start=$started_with end=$ended_with"
fi

if grep -q "long running process still logging" "$DEFAULT_LOGDIR/aznfs.log" 2>/dev/null; then
    ok "its log line really landed in the OLD directory"
else
    nok "its log line really landed in the OLD directory" "line not found in $DEFAULT_LOGDIR/aznfs.log"
fi

#
# This is why the watchdog services must be restarted after changing the log
# directory: only the configured directory is rotated from here on.
#
if grep -qF -- "$DEFAULT_LOGDIR/aznfs.log" "$LRCONF"; then
    nok "old dir is no longer rotated (restart required, per README)" \
        "old dir not in config" "old dir still listed"
else
    ok "old dir is no longer rotated (restart required, per README)"
fi

rm -f "$SCRATCH/longrun.sh" "$SCRATCH/longrun.target"
umount "$MOUNT_POINT" 2>/dev/null

# ---------------------------------------------------------------------------
echo
echo "=================================================="
echo -e " Passed: ${GREEN}${PASS}${NORMAL}   Failed: ${RED}${FAIL}${NORMAL}   Skipped: ${YELLOW}${SKIP}${NORMAL}"
echo "=================================================="

if [ $FAIL -ne 0 ]; then
    echo "Failed tests:"
    for t in "${FAILED_TESTS[@]}"; do echo "  - $t"; done
    exit 1
fi

exit 0
