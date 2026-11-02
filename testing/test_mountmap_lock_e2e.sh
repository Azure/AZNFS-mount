#!/bin/bash
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
#
# End-to-end test for the NFSv4 watchdog mountmap locking, with REAL Azure Files
# NFSv4 mounts made through an installed AZNFS package.
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
# Must run as root. Like testscript.sh, when RELEASE_NUMBER is set it installs
# that AZNFS release first and removes it again at the end, it refuses to run
# then if AZNFS is already installed. Otherwise it tests the AZNFS version
# already installed, and leaves it installed. Either way it only creates mount
# points under a new directory in /mnt and restarts aznfswatchdogv4, and leaves
# no mount behind.
#
# Usage: sudo NFSV4_STORAGE_ACCOUNTS="<account> [...]" ./testing/test_mountmap_lock_e2e.sh
#
# RELEASE_NUMBER             AZNFS release to install for the test and remove
#                            afterwards.
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
MOUNTMAPv3=/opt/microsoft/aznfs/data/mountmap
MOUNTMAPv4=/opt/microsoft/aznfs/data/mountmapv4
MOUNTMAPv4NOTLS=/opt/microsoft/aznfs/data/mountmapv4notls
WATCHDOG=aznfswatchdogv4

# The mountmap the test's mounts are recorded in, as nfsv4mountscript.sh picks it.
if [[ "$OPTIONS" == *notls* ]]; then
    MOUNTMAP=$MOUNTMAPv4NOTLS
else
    MOUNTMAP=$MOUNTMAPv4
fi

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

INSTALLED_BY_TEST=

#
# Same as testscript.sh. Refuses to install over an AZNFS that is already
# there, the test removes what it installed at the end and must not remove an
# installation it did not make.
#
install_release()
{
    local release_url="https://github.com/Azure/AZNFS-mount/releases/download/${RELEASE_NUMBER}/aznfs_install.sh"

    if [ -e /sbin/mount.aznfs ]; then
        echo "AZNFS is already installed. Remove it, or unset RELEASE_NUMBER to test the installed version."
        exit 1
    fi

    if ! command -v wget >/dev/null 2>&1; then
        echo "'wget' is not installed, cannot install AZNFS ${RELEASE_NUMBER}."
        exit 1
    fi

    echo "Installing AZNFS ${RELEASE_NUMBER} from $release_url"
    export AZNFS_NONINTERACTIVE_INSTALL=1

    # pipefail, else a failed download runs an empty script and succeeds.
    if ! (set -o pipefail; wget -O - -q "$release_url" | bash); then
        echo "[ERROR] Not able to install AZNFS ${RELEASE_NUMBER}."
        exit 1
    fi
    INSTALLED_BY_TEST=1
}

has_entries()
{
    [ -f "$1" ] && grep -q '^[^[:space:]]' "$1"
}

#
# Like testscript.sh. Package removal refuses to proceed while a mountmap has
# entries, and stops the watchdog that removes them along with the DNAT rules
# of non-TLS mounts, so first give the watchdog the time to remove the ones for
# the share this test unmounted.
#
remove_release()
{
    local distro_id i rc

    for ((i = 0; i < 60; i++)); do
        has_entries "$MOUNTMAPv4" || has_entries "$MOUNTMAPv4NOTLS" || has_entries "$MOUNTMAPv3" || break
        sleep 2
    done

    if [ -f /etc/centos-release ]; then
        distro_id="centos"
    else
        distro_id=$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | tr -d '"' | tr '[:upper:]' '[:lower:]')
    fi

    case "$distro_id" in
        ubuntu|debian)
            apt-get purge -y aznfs ;;
        centos|rocky|rhel|almalinux|ol|azurelinux|mariner)
            yum remove -y aznfs ;;
        sles|suse|opensuse*)
            zypper remove -y aznfs_sles ;;
        *)
            echo "[ERROR] Unknown Linux distribution '$distro_id', not able to remove AZNFS."
            return 1 ;;
    esac
    rc=$?

    if [ $rc -ne 0 ]; then
        echo "[ERROR] Not able to remove AZNFS ${RELEASE_NUMBER}, exit code $rc."
        return 1
    fi
    echo "Removed AZNFS ${RELEASE_NUMBER}."
}

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

#
# Unmounts $1 until nothing is mounted on it any more, retrying for a while as
# a share can still be busy right after it was mounted. Fails, with the last
# umount error in UMOUNT_ERROR, if something is still mounted there.
#
unmount()
{
    local mp=$1 i

    UMOUNT_ERROR=
    for ((i = 0; i < 10; i++)); do
        mountpoint -q "$mp" || return 0
        UMOUNT_ERROR=$(umount "$mp" 2>&1) || sleep 1
    done
    ! mountpoint -q "$mp"
}

CLEANUP_FAILED=

cleanup()
{
    local mp

    touch "$STOP"
    [ -n "$WORKER_PIDS" ] && wait $WORKER_PIDS 2>/dev/null

    for mp in "$MPROOT"/worker*; do
        [ -d "$mp" ] || continue
        if ! unmount "$mp"; then
            echo "[ERROR] Not able to unmount $mp: $UMOUNT_ERROR"
            CLEANUP_FAILED=1
        fi
    done

    #
    # Stopped while the last mount of the endpoint goes away. The watchdog
    # otherwise may tear down the endpoint's TLS tunnel while the kernel is
    # still sending its final requests through it, which makes umount wait
    # for an RPC timeout.
    #
    if mountpoint -q "$ANCHOR"; then
        systemctl stop $WATCHDOG
        if ! unmount "$ANCHOR"; then
            echo "[ERROR] Not able to unmount $ANCHOR: $UMOUNT_ERROR"
            CLEANUP_FAILED=1
        fi
    fi
    systemctl cat $WATCHDOG.service >/dev/null 2>&1 && start_watchdog

    for mp in "$MPROOT"/worker* "$ANCHOR"; do
        mountpoint -q "$mp" 2>/dev/null || rmdir "$mp" 2>/dev/null
    done
    rm -rf "$RESULTS" "$STOP"
    rmdir "$MPROOT" 2>/dev/null

    if [ -n "$INSTALLED_BY_TEST" ] && ! remove_release; then
        CLEANUP_FAILED=1
    fi

    # A test that left the machine in a bad state must not pass.
    [ -n "$CLEANUP_FAILED" ] && exit 1
}
trap cleanup EXIT

[ -n "$RELEASE_NUMBER" ] && install_release

if [ ! -x /sbin/mount.aznfs ] || ! systemctl cat $WATCHDOG.service >/dev/null 2>&1; then
    echo "AZNFS is not installed, cannot run the test."
    exit 1
fi

#
# Mounts and unmounts the share on its own mount point until $STOP appears or
# the time is up, recording "<rc> <mount helper output>" for every mount. A
# mount point that cannot be unmounted is recorded in umount<id> and ends the
# worker, mounting on it again would stack mounts.
#
worker()
{
    local id=$1 end=$2 mp="$MPROOT/worker$1" out rc
    mkdir -p "$mp"

    while [ ! -e "$STOP" ] && [ "$(date +%s)" -lt "$end" ]; do
        out=$(timeout -s KILL $MOUNT_TIMEOUT mount -t aznfs "$SHARE" "$mp" -o "$OPTIONS" 2>&1)
        rc=$?
        echo "$rc $(echo "$out" | sed 's/\x1b\[[0-9;]*m//g' | tr '\n' ' ')" >> "$RESULTS/worker$id"
        if ! unmount "$mp"; then
            echo "$mp: $UMOUNT_ERROR" | tr '\n' ' ' >> "$RESULTS/umount$id"
            echo >> "$RESULTS/umount$id"
            break
        fi
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
cat "$RESULTS"/umount* > "$RESULTS/umount" 2>/dev/null
total=$(grep -c . "$RESULTS/all")
umount_failures=$(grep -c . "$RESULTS/umount")
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

if [ $umount_failures -eq 0 ]; then
    pass "every mount was unmounted again"
else
    fail "$umount_failures worker(s) stopped early, not able to unmount their mount point"
    head -5 "$RESULTS/umount" | cut -c1-300 | sed 's/^/    /'
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

if mountpoint -q "$ANCHOR" && grep -q . "$MOUNTMAP" &&
   [[ "$(lsattr -d "$MOUNTMAP" 2>/dev/null | awk '{print $1}')" == *i* ]]; then
    pass "mount kept up during the run is still mounted, $MOUNTMAP is not empty and is immutable"
else
    fail "mount kept up during the run, or $MOUNTMAP, not in the expected state"
fi

echo
echo "Passed: $PASS, Failed: $FAIL"
if [ $FAIL -ne 0 ]; then
    printf '  %s\n' "${FAILED_TESTS[@]}"
    exit 1
fi
exit 0
