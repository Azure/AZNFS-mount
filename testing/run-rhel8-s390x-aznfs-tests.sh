#!/bin/bash

set -euo pipefail

XFSTESTS_COMMIT="22348afe338c0f6d540c0d7ef0db749eaa51b218"
XFSTESTS_REPOSITORY="https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git"
DEFAULT_RPM_SHA256="c9be4eeb1e8c7c4e83e15521a2dfe94ab455d3138a0395707a0f7a85fccff057"

RPM_PATH=""
ACCOUNT=""
TEST_SHARE=""
SCRATCH_SHARE=""
EXPECTED_RPM_SHA256="$DEFAULT_RPM_SHA256"
RESULTS_ROOT="/var/tmp"
XFSTESTS_DIR="/usr/local/src/xfstests-dev"
IO_SIZE_MIB=64
CONFIRM_DESTRUCTIVE=false
BASIC_ONLY=false

usage()
{
    cat <<'EOF'
Usage:
  run-rhel8-s390x-aznfs-tests.sh \
    --rpm PATH \
    --account STORAGE_ACCOUNT \
    --test-share TEST_SHARE \
    --scratch-share SCRATCH_SHARE \
    --confirm-destructive

Required arguments:
  --rpm PATH                Path to the AZNFS s390x RPM.
  --account NAME            Azure Files storage account name.
  --test-share NAME         Dedicated, empty NFS test share.
  --scratch-share NAME      Dedicated, empty NFS scratch share. Required
                            unless --basic is used.
  --confirm-destructive     Confirm that xfstests may destroy share contents.
                            Required unless --basic is used.

Optional arguments:
  --basic                   Run package, service, mount, and basic I/O tests
                            only. Skip the xfstests build and execution.
  --rpm-sha256 SHA256       Expected RPM digest.
  --results-root DIR        Parent directory for the result archive.
  --xfstests-dir DIR        xfstests source directory.
  --io-size-mib N           Basic I/O test size in MiB.
  -h, --help                Show this help.

Both shares must use NFS with NoRootSquash and must contain no valuable data.
Run this script as a regular user with passwordless sudo, or as root.
EOF
}

log()
{
    printf '\n[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

die()
{
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

run_root()
{
    if [[ "$(id -u)" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rpm)
            RPM_PATH="${2:-}"
            shift 2
            ;;
        --account)
            ACCOUNT="${2:-}"
            shift 2
            ;;
        --test-share)
            TEST_SHARE="${2:-}"
            shift 2
            ;;
        --scratch-share)
            SCRATCH_SHARE="${2:-}"
            shift 2
            ;;
        --rpm-sha256)
            EXPECTED_RPM_SHA256="${2:-}"
            shift 2
            ;;
        --results-root)
            RESULTS_ROOT="${2:-}"
            shift 2
            ;;
        --xfstests-dir)
            XFSTESTS_DIR="${2:-}"
            shift 2
            ;;
        --io-size-mib)
            IO_SIZE_MIB="${2:-}"
            shift 2
            ;;
        --confirm-destructive)
            CONFIRM_DESTRUCTIVE=true
            shift
            ;;
        --basic)
            BASIC_ONLY=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "Unknown argument: $1"
            ;;
    esac
done

[[ -n "$RPM_PATH" ]] || die "--rpm is required"
[[ -n "$ACCOUNT" ]] || die "--account is required"
[[ -n "$TEST_SHARE" ]] || die "--test-share is required"
if [[ "$BASIC_ONLY" == false ]]; then
    [[ -n "$SCRATCH_SHARE" ]] || die "--scratch-share is required without --basic"
    [[ "$CONFIRM_DESTRUCTIVE" == true ]] ||
        die "--confirm-destructive is required without --basic"
    [[ "$TEST_SHARE" != "$SCRATCH_SHARE" ]] ||
        die "The test and scratch shares must be different"
fi
[[ "$IO_SIZE_MIB" =~ ^[1-9][0-9]*$ ]] ||
    die "--io-size-mib must be a positive integer"

[[ -f "$RPM_PATH" ]] || die "RPM not found: $RPM_PATH"
RPM_PATH="$(readlink -f "$RPM_PATH")"
RESULTS_ROOT="$(readlink -m "$RESULTS_ROOT")"
XFSTESTS_DIR="$(readlink -m "$XFSTESTS_DIR")"

ENDPOINT="${ACCOUNT}.file.core.windows.net"
TEST_EXPORT="/${ACCOUNT}/${TEST_SHARE}"
SCRATCH_EXPORT="/${ACCOUNT}/${SCRATCH_SHARE}"
TEST_DEV="${ENDPOINT}:${TEST_EXPORT}"
SCRATCH_DEV="${ENDPOINT}:${SCRATCH_EXPORT}"
TEST_DIR="/mnt/aznfs-test"
SCRATCH_MNT="/mnt/aznfs-scratch"
WRAPPER_DIR="/opt/xfstests-aznfs/bin"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS_DIR="${RESULTS_ROOT}/aznfs-rhel810-s390x-${RUN_ID}"
ARCHIVE="${RESULTS_DIR}.tar.gz"

unmount_all()
{
    local mount_dir

    for mount_dir in "$SCRATCH_MNT" "$TEST_DIR"; do
        while mountpoint -q "$mount_dir"; do
            run_root umount "$mount_dir" || break
        done
    done
}

cleanup()
{
    unmount_all || true
}

trap cleanup EXIT

mkdir -p "$RESULTS_DIR"
exec > >(tee -a "${RESULTS_DIR}/runner.log") 2>&1

log "Validating host and RPM"
[[ "$(uname -m)" == "s390x" ]] || die "This test requires an s390x host"
source /etc/os-release
[[ "${VERSION_ID%%.*}" == "8" ]] ||
    die "This test requires an EL8 operating system"
[[ "$(getconf GNU_LIBC_VERSION)" == "glibc 2.28" ]] ||
    die "Expected glibc 2.28"

printf '%s  %s\n' "$EXPECTED_RPM_SHA256" "$RPM_PATH" |
    sha256sum --check -
[[ "$(rpm -qp --queryformat '%{ARCH}' "$RPM_PATH")" == "s390x" ]] ||
    die "RPM architecture is not s390x"
[[ "$(rpm -qpl "$RPM_PATH" | grep -c '^/usr/lib/.build-id' || true)" -eq 0 ]] ||
    die "RPM contains conflicting /usr/lib/.build-id entries"
rpm -Kv "$RPM_PATH"

getent ahostsv4 "$ENDPOINT"
command -v nc >/dev/null 2>&1 || run_root dnf install -y nmap-ncat
nc -vz "$ENDPOINT" 2049

if [[ "${ID:-}" == "rhel" ]] && command -v subscription-manager >/dev/null; then
    log "Enabling RHEL 8 s390x repositories"
    run_root subscription-manager repos \
        --enable="rhel-8-for-s390x-baseos-rpms" \
        --enable="rhel-8-for-s390x-appstream-rpms" \
        --enable="codeready-builder-for-rhel-8-s390x-rpms"
fi

log "Installing and verifying AZNFS"
run_root dnf install -y --nogpgcheck "$RPM_PATH"
rpm -q aznfs
rpm -V aznfs >"${RESULTS_DIR}/rpm-verify.txt" || true
file /sbin/mount.aznfs /sbin/aznfsclient
if ldd /sbin/aznfsclient | tee "${RESULTS_DIR}/aznfsclient-ldd.txt" |
    grep -q 'not found'; then
    die "aznfsclient has unresolved libraries"
fi
systemctl is-enabled aznfswatchdog.service
systemctl is-enabled aznfswatchdogv4.service
systemctl is-active aznfswatchdog.service
systemctl is-active aznfswatchdogv4.service
run_root mkdir -p "$TEST_DIR" "$SCRATCH_MNT"

basic_io()
{
    local mode="$1"
    local options="vers=4.1"
    local test_id

    [[ "$mode" == "tls" ]] || options+=",notls,clean"
    unmount_all

    log "Running ${mode} mount and basic I/O validation"
    run_root mount -t aznfs -o "$options" "$TEST_DEV" "$TEST_DIR"
    findmnt -T "$TEST_DIR" -o TARGET,SOURCE,FSTYPE,OPTIONS

    if [[ "$mode" == "tls" ]]; then
        pgrep -a stunnel
        run_root ss -ltnp | grep stunnel
    fi

    test_id="${mode}-${RUN_ID}"
    run_root mkdir -p "${TEST_DIR}/${test_id}"
    run_root dd if=/dev/urandom \
        of="${TEST_DIR}/${test_id}/data.bin" \
        bs=1M count="$IO_SIZE_MIB" conv=fsync status=none
    run_root sh -c \
        "cd '$TEST_DIR/$test_id' && sha256sum data.bin >data.sha256"
    run_root sh -c \
        "cd '$TEST_DIR/$test_id' && sha256sum --check data.sha256"
    run_root mv \
        "${TEST_DIR}/${test_id}/data.bin" \
        "${TEST_DIR}/${test_id}/data-renamed.bin"
    run_root ln \
        "${TEST_DIR}/${test_id}/data-renamed.bin" \
        "${TEST_DIR}/${test_id}/data-hardlink.bin"
    run_root ln -s \
        data-renamed.bin \
        "${TEST_DIR}/${test_id}/data-symlink.bin"
    sync
    unmount_all
}

basic_io tls
basic_io notls

if [[ "$BASIC_ONLY" == false ]]; then
log "Installing xfstests build dependencies"
if ! rpm -q epel-release >/dev/null 2>&1; then
    run_root dnf install -y \
        https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
fi
run_root dnf makecache
run_root dnf groupinstall -y "Development Tools"
run_root dnf install -y \
    acl attr automake bc dbench dump e2fsprogs fio gawk gcc \
    gdbm-devel git indent kernel-devel libacl-devel libaio-devel \
    libcap-devel libtool libuuid-devel lvm2 make nfs-utils psmisc \
    python3 quota sed sqlite xfsdump xfsprogs xfsprogs-devel

log "Building pinned xfstests revision"
if [[ ! -d "${XFSTESTS_DIR}/.git" ]]; then
    run_root mkdir -p "$(dirname "$XFSTESTS_DIR")"
    run_root git clone "$XFSTESTS_REPOSITORY" "$XFSTESTS_DIR"
fi
if ! run_root git -C "$XFSTESTS_DIR" cat-file -e \
    "${XFSTESTS_COMMIT}^{commit}"; then
    run_root git -C "$XFSTESTS_DIR" fetch origin "$XFSTESTS_COMMIT"
fi
run_root git -C "$XFSTESTS_DIR" checkout --detach "$XFSTESTS_COMMIT"
run_root make -C "$XFSTESTS_DIR" -j"$(nproc)"
run_root make -C "$XFSTESTS_DIR" install
run_root git -C "$XFSTESTS_DIR" rev-parse HEAD |
    tee "${RESULTS_DIR}/xfstests-commit.txt"

run_root useradd -m fsgqa 2>/dev/null || true
run_root useradd fsgqa2 2>/dev/null || true
run_root useradd 123456-fsgqa 2>/dev/null || true

log "Installing xfstests AZNFS mount wrapper"
run_root mkdir -p "$WRAPPER_DIR"
run_root tee "${WRAPPER_DIR}/mount" >/dev/null <<EOF
#!/bin/bash
set -e
args=("\$@")
for ((i = 0; i + 1 < \${#args[@]}; i++)); do
    if [[ "\${args[\$i]}" == "-t" ]] &&
       [[ "\${args[\$((i + 1))]}" == "nfs" ||
          "\${args[\$((i + 1))]}" == "nfs4" ]]; then
        args[\$((i + 1))]="aznfs"
        for ((j = 0; j < \${#args[@]}; j++)); do
            if [[ "\${args[\$j]}" == *:"/${ACCOUNT}/"* ]]; then
                args[\$j]="${ENDPOINT}:\${args[\$j]#*:}"
            fi
        done
        break
    fi
done
exec /usr/bin/mount "\${args[@]}"
EOF
run_root chmod 0755 "${WRAPPER_DIR}/mount"

discover_source()
{
    local options="$1"
    local device="$2"
    local mount_dir="$3"
    local source

    unmount_all
    run_root mount -t aznfs -o "$options" "$device" "$mount_dir" >&2
    source="$(findmnt -n -o SOURCE -T "$mount_dir")"
    unmount_all
    printf '%s\n' "$source"
}

write_local_config()
{
    local options="$1"
    local test_source="$2"
    local scratch_source="$3"

    run_root tee "${XFSTESTS_DIR}/local.config" >/dev/null <<EOF
export TEST_DEV="${test_source}"
export TEST_DIR="${TEST_DIR}"
export SCRATCH_DEV="${scratch_source}"
export SCRATCH_MNT="${SCRATCH_MNT}"
export NFS_MOUNT_OPTIONS="-o ${options}"
EOF
}

run_xfstests_mode()
{
    local mode="$1"
    local options="vers=4.1"
    local test_source
    local scratch_source
    local smoke_rc
    local quick_rc

    [[ "$mode" == "tls" ]] || options+=",notls,clean"

    log "Discovering ${mode} AZNFS mount sources"
    test_source="$(discover_source "$options" "$TEST_DEV" "$TEST_DIR")"
    scratch_source="$(discover_source "$options" "$SCRATCH_DEV" "$SCRATCH_MNT")"
    write_local_config "$options" "$test_source" "$scratch_source"

    unmount_all
    log "Running ${mode} xfstests smoke set"
    pushd "$XFSTESTS_DIR" >/dev/null
    set +e
    run_root env \
        PATH="${WRAPPER_DIR}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin" \
        ./check --fs nfs \
        generic/001 generic/002 generic/005 2>&1 |
        tee "${RESULTS_DIR}/xfstests-${mode}-smoke.log"
    smoke_rc=${PIPESTATUS[0]}
    set -e
    popd >/dev/null
    printf '%s\n' "$smoke_rc" >"${RESULTS_DIR}/xfstests-${mode}-smoke.rc"

    run_root rm -rf "${XFSTESTS_DIR}/results"
    unmount_all
    log "Running ${mode} xfstests quick group"
    pushd "$XFSTESTS_DIR" >/dev/null
    set +e
    run_root env \
        PATH="${WRAPPER_DIR}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin" \
        ./check --fs nfs -g quick 2>&1 |
        tee "${RESULTS_DIR}/xfstests-${mode}-quick.log"
    quick_rc=${PIPESTATUS[0]}
    set -e
    popd >/dev/null
    printf '%s\n' "$quick_rc" >"${RESULTS_DIR}/xfstests-${mode}-quick.rc"

    if [[ -d "${XFSTESTS_DIR}/results" ]]; then
        run_root cp -a \
            "${XFSTESTS_DIR}/results" \
            "${RESULTS_DIR}/xfstests-results-${mode}"
        run_root chown -R "$(id -u):$(id -g)" \
            "${RESULTS_DIR}/xfstests-results-${mode}"
    fi
}

run_xfstests_mode tls
run_xfstests_mode notls
else
    log "Basic mode selected; skipping the xfstests build and execution"
fi

log "Collecting environment and logs"
{
    uname -a
    cat /etc/redhat-release
    getconf GNU_LIBC_VERSION
    rpm --version
    rpm -q aznfs
    sha256sum "$RPM_PATH"
} >"${RESULTS_DIR}/environment.txt"
rpm -qa | sort >"${RESULTS_DIR}/packages.txt"
run_root journalctl \
    -u aznfswatchdog.service \
    -u aznfswatchdogv4.service \
    --since "24 hours ago" \
    --no-pager >"${RESULTS_DIR}/aznfs-watchdog-journal.log"
run_root cp /opt/microsoft/aznfs/data/aznfs.log \
    "${RESULTS_DIR}/aznfs.log" 2>/dev/null || true
run_root chown -R "$(id -u):$(id -g)" "$RESULTS_DIR"
tar -C "$RESULTS_ROOT" -czf "$ARCHIVE" "$(basename "$RESULTS_DIR")"

log "Testing complete"
printf 'Results directory: %s\n' "$RESULTS_DIR"
printf 'Result archive: %s\n' "$ARCHIVE"
printf 'Review all *.rc files and *.out.bad files before declaring success.\n'
