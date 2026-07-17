#!/bin/bash

set -e

SCRIPT_STATUS="FAILED"
INITIAL_AZNFS_INSTALLED="0"
INITIAL_AZFILES_INSTALLED="0"
STRICT_CLEANUP="${STRICT_CLEANUP:-1}"

fail()
{
    echo "[ERROR] $1"
    exit 1
}

log_step()
{
    echo "===== $1 ====="
}

pass()
{
    echo "[PASS] $1"
}

log_package_state()
{
    log_step "Package state snapshot"

    if [ -f /etc/debian_version ]; then
        dpkg -l 2>/dev/null | grep -E 'aznfs|azfiles' || true
    else
        rpm -qa 2>/dev/null | grep -E 'aznfs|azfiles' || true
    fi

    if [ -x /usr/sbin/mount.aznfs ]; then
        echo "mount helper: /usr/sbin/mount.aznfs"
    elif [ -x /sbin/mount.aznfs ]; then
        echo "mount helper: /sbin/mount.aznfs"
    else
        echo "mount helper: missing"
    fi

    ls -ld /opt/microsoft/aznfs /opt/microsoft/azfiles-nfs 2>/dev/null || true
}

get_blob_export_path()
{
    local storage_account="$1"
    local export_name="${BLOB_EXPORT_NAME:-githubtest}"

    echo "${storage_account}.blob.core.windows.net:/${storage_account}/${export_name}"
}

get_files_export_path()
{
    local storage_account="$1"
    local export_name="${FILES_EXPORT_NAME:-githubtest}"

    echo "${storage_account}.file.core.windows.net:/${storage_account}/${export_name}"
}

is_aznfs_pkg_name()
{
    case "$1" in
        aznfs|aznfs_sles)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

is_azfiles_pkg_name()
{
    case "$1" in
        azfiles-nfs|azfiles-nfs_sles)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

is_aznfs_installed()
{
    local distro_id=""

    if [ -f /etc/debian_version ]; then
        dpkg -s aznfs >/dev/null 2>&1
        return $?
    fi

    if [ -f /etc/centos-release ]; then
        distro_id="centos"
    elif [ -f /etc/os-release ]; then
        distro_id=$(grep "^ID=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
        distro_id=$(canonicalize_distro_id "$distro_id")
    fi

    if [ "$distro_id" == "sles" ]; then
        rpm -q aznfs >/dev/null 2>&1 || rpm -q aznfs_sles >/dev/null 2>&1
        return $?
    fi

    rpm -q aznfs >/dev/null 2>&1
}

is_azfiles_installed()
{
    local distro_id=""

    if [ -f /etc/debian_version ]; then
        dpkg -s azfiles-nfs >/dev/null 2>&1
        return $?
    fi

    if [ -f /etc/centos-release ]; then
        distro_id="centos"
    elif [ -f /etc/os-release ]; then
        distro_id=$(grep "^ID=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
        distro_id=$(canonicalize_distro_id "$distro_id")
    fi

    if [ "$distro_id" == "sles" ]; then
        rpm -q azfiles-nfs >/dev/null 2>&1 || rpm -q azfiles-nfs_sles >/dev/null 2>&1
        return $?
    fi

    rpm -q azfiles-nfs >/dev/null 2>&1
}

assert_state()
{
    local expect_aznfs="$1"
    local expect_azfiles="$2"
    local context="$3"

    if [ "$expect_aznfs" == "1" ]; then
        is_aznfs_installed || fail "$context: expected aznfs installed"
    else
        is_aznfs_installed && fail "$context: expected aznfs NOT installed"
    fi

    if [ "$expect_azfiles" == "1" ]; then
        is_azfiles_installed || fail "$context: expected azfiles-nfs installed"
    else
        is_azfiles_installed && fail "$context: expected azfiles-nfs NOT installed"
    fi

    pass "$context"
}

assert_azfiles_version_matches_aznfs()
{
    local context="$1"
    local aznfs_version=""
    local azfiles_version=""

    if [ -f /etc/debian_version ]; then
        aznfs_version=$(dpkg-query -W -f='${Version}' aznfs 2>/dev/null || true)
        azfiles_version=$(dpkg-query -W -f='${Version}' azfiles-nfs 2>/dev/null || true)
    else
        aznfs_version=$(rpm -q --qf '%{VERSION}' aznfs 2>/dev/null || rpm -q --qf '%{VERSION}' aznfs_sles 2>/dev/null || true)
        azfiles_version=$(rpm -q --qf '%{VERSION}' azfiles-nfs 2>/dev/null || rpm -q --qf '%{VERSION}' azfiles-nfs_sles 2>/dev/null || true)
    fi

    if [ -z "$aznfs_version" ] || [ -z "$azfiles_version" ]; then
        fail "$context: unable to read aznfs/azfiles-nfs package versions"
    fi

    if [ "$aznfs_version" != "$azfiles_version" ]; then
        fail "$context: aznfs ($aznfs_version) and azfiles-nfs ($azfiles_version) versions do not match"
    fi

    pass "$context"
}

cleanup_installed_packages()
{
    log_step "Final cleanup: uninstall packages installed by script"

    # Always unmount test mount point if mounted.
    if mount | grep -q " on /mnt/githubtest "; then
        sudo umount /mnt/githubtest >/dev/null 2>&1 || true
    fi

    if mount | grep -q " on /mnt/githubtest-files-tls "; then
        sudo umount /mnt/githubtest-files-tls >/dev/null 2>&1 || true
    fi

    if mount | grep -q " on /mnt/githubtest-files-notls "; then
        sudo umount /mnt/githubtest-files-notls >/dev/null 2>&1 || true
    fi

    if [ "$INITIAL_AZNFS_INSTALLED" == "0" ] && is_aznfs_installed; then
        remove_aznfs >/dev/null 2>&1 || true
    fi

    if [ "$INITIAL_AZFILES_INSTALLED" == "0" ] && is_azfiles_installed; then
        remove_azfiles >/dev/null 2>&1 || true
    fi

    if [ "$STRICT_CLEANUP" == "1" ]; then
        if [ "$INITIAL_AZNFS_INSTALLED" == "0" ] && is_aznfs_installed; then
            fail "Final cleanup failed: aznfs is still installed"
        fi

        if [ "$INITIAL_AZFILES_INSTALLED" == "0" ] && is_azfiles_installed; then
            fail "Final cleanup failed: azfiles-nfs is still installed"
        fi
    fi

    log_package_state
}

on_exit()
{
    cleanup_installed_packages

    if [ "$SCRIPT_STATUS" == "PASSED" ]; then
        pass "All validations passed"
    fi
}

trap on_exit EXIT

run_installer_from_release()
{
    local release_url="$1"
    local label="$2"
    local installer

    installer=$(mktemp "/tmp/${label}.XXXXXX.sh")

    if ! wget -q -O "$installer" "$release_url"; then
        rm -f "$installer"
        fail "Failed to download ${label} installer from $release_url"
    fi

    if [ ! -s "$installer" ]; then
        rm -f "$installer"
        fail "Downloaded ${label} installer is empty from $release_url"
    fi

    chmod +x "$installer"

    export AZNFS_NONINTERACTIVE_INSTALL=1
    if ! sudo -E bash "$installer"; then
        rm -f "$installer"
        fail "${label} installer execution failed"
    fi

    rm -f "$installer"
}

install_local_package()
{
    local package_path="$1"
    local distro_id=""
    local pkg_name=""

    if [ ! -f "$package_path" ]; then
        fail "Local package path does not exist: $package_path"
    fi

    if [ -f /etc/centos-release ]; then
        distro_id="centos"
    elif [ -f /etc/os-release ]; then
        distro_id=$(grep "^ID=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
        distro_id=$(canonicalize_distro_id "$distro_id")
    else
        fail "Unable to detect Linux distribution while installing local package"
    fi

    if [ "$distro_id" == "ubuntu" ]; then
        pkg_name=$(dpkg-deb -f "$package_path" Package 2>/dev/null || true)

        # Use apt for local packages so dependencies are resolved like customer installs.
        if [ "$pkg_name" == "aznfs" ] && [ -n "$AZFILES_LOCAL_PACKAGE" ] && [ -f "$AZFILES_LOCAL_PACKAGE" ]; then
            if ! sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "$AZFILES_LOCAL_PACKAGE" "$package_path"; then
                fail "Failed to install local deb packages: $AZFILES_LOCAL_PACKAGE $package_path"
            fi
        else
            if ! sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "$package_path"; then
                fail "Failed to install local deb package: $package_path"
            fi
        fi
    elif [ "$distro_id" == "centos" -o "$distro_id" == "rocky" -o "$distro_id" == "rhel" -o "$distro_id" == "sles" ]; then
        pkg_name=$(rpm -qp --qf '%{NAME}' "$package_path" 2>/dev/null || true)

        # Use distro package managers for local RPMs to mirror customer upgrade behavior.
        if [ "$distro_id" == "sles" ]; then
            rpm_install_cmd="sudo zypper --non-interactive install --allow-unsigned-rpm"
        else
            if command -v dnf >/dev/null 2>&1; then
                rpm_install_cmd="sudo dnf install -y"
            else
                rpm_install_cmd="sudo yum install -y"
            fi
        fi

        # For aznfs local install, include azfiles local package in same transaction if provided.
        if is_aznfs_pkg_name "$pkg_name" && [ -n "$AZFILES_LOCAL_PACKAGE" ] && [ -f "$AZFILES_LOCAL_PACKAGE" ]; then
            if ! $rpm_install_cmd "$AZFILES_LOCAL_PACKAGE" "$package_path"; then
                fail "Failed to install local rpm packages using package manager: $AZFILES_LOCAL_PACKAGE $package_path"
            fi
        else
            # For azfiles local install during split transition, include current aznfs in the
            # same transaction when explicitly requested by scenario orchestration.
            if is_azfiles_pkg_name "$pkg_name" && [ "${INCLUDE_CURRENT_AZNFS_WITH_AZFILES:-0}" == "1" ] && [ -n "$CURRENT_AZNFS_LOCAL_PACKAGE" ] && [ -f "$CURRENT_AZNFS_LOCAL_PACKAGE" ]; then
                if ! $rpm_install_cmd "$CURRENT_AZNFS_LOCAL_PACKAGE" "$package_path"; then
                    fail "Failed to install local rpm packages using package manager: $CURRENT_AZNFS_LOCAL_PACKAGE $package_path"
                fi
            elif ! $rpm_install_cmd "$package_path"; then
                fail "Failed to install local rpm package: $package_path"
            fi
        fi
    else
        fail "Unknown Linux distribution while installing local package"
    fi
}

# Function to download and execute AZNFS installation script.
install_aznfs() 
{
    local release_number="$1"
    local install_mode="${INSTALL_MODE:-release}"

    if [ "$install_mode" == "local" ]; then
        if [ -z "$AZNFS_LOCAL_PACKAGE" ]; then
            fail "INSTALL_MODE=local requires AZNFS_LOCAL_PACKAGE"
        fi

        echo "AZNFS_LOCAL_PACKAGE=$AZNFS_LOCAL_PACKAGE"
        install_local_package "$AZNFS_LOCAL_PACKAGE"
        return
    fi

    # URL for the specific release.
    echo "RELEASE_NUMBER=$release_number"
    local release_url="https://github.com/Azure/AZNFS-mount/releases/download/${release_number}/aznfs_install.sh"
    echo "release_url=$release_url"

    run_installer_from_release "$release_url" "aznfs_install"
}

# Function to download and execute AZFILES-NFS installation script.
install_azfiles_nfs()
{
    local release_number="$1"
    local install_mode="${INSTALL_MODE:-release}"

    if [ "$install_mode" == "local" ]; then
        if [ -z "$AZFILES_LOCAL_PACKAGE" ]; then
            fail "INSTALL_MODE=local requires AZFILES_LOCAL_PACKAGE"
        fi

        echo "AZFILES_LOCAL_PACKAGE=$AZFILES_LOCAL_PACKAGE"
        install_local_package "$AZFILES_LOCAL_PACKAGE"
        return
    fi

    echo "RELEASE_NUMBER=$release_number"
    local release_url="https://github.com/Azure/AZNFS-mount/releases/download/${release_number}/azfiles_install.sh"
    echo "release_url=$release_url"

    run_installer_from_release "$release_url" "azfiles_install"
}

#
# We only use lowercase single word names for distro id:
# ubuntu, centos, redhat, sles.
#
canonicalize_distro_id()
{
    local distro_lower=$(echo "$1" | tr '[:upper:]' '[:lower:]')

    # Use sles for SUSE/SLES.
    if [ "$distro_lower" == "suse" ]; then
        distro_lower="sles"
    fi

    # Treat Azure Linux as RHEL/CentOS family for package manager behavior.
    if [ "$distro_lower" == "azurelinux" ]; then
        distro_lower="centos"
    fi

    echo "$distro_lower"
}

wait_for_dpkg_locks()
{
    local retries="${1:-120}"

    for i in $(seq 1 "$retries"); do
        if ! sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1 && ! sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done

    return 1
}

recover_ubuntu_dpkg_after_timeout()
{
    local pkg_name="$1"

    # A timed-out apt purge can leave dpkg/prerm hanging and holding the lock.
    sudo pkill -f "/var/lib/dpkg/info/${pkg_name}.prerm" >/dev/null 2>&1 || true
    sudo pkill -f "dpkg --status-fd" >/dev/null 2>&1 || true

    wait_for_dpkg_locks 120 || true
    sudo dpkg --configure -a >/dev/null 2>&1 || true
    wait_for_dpkg_locks 120 || true
}

remove_aznfs()
{
    # Sleep for mountmap inactivity seconds (configurable for matrix runs).
    local sleep_seconds="${AZNFS_REMOVE_SLEEP_SECONDS:-300}"
    if [ "$sleep_seconds" -gt 0 ]; then
        sleep "$sleep_seconds"
    fi

    if [ -f /etc/centos-release ]; then
        distro_id="centos"
    elif [ -f /etc/os-release ]; then
        distro_id=$(grep "^ID=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
        distro_id=$(canonicalize_distro_id $distro_id)
    else
        # Ideally, this should not happen.
        distro_id="Unknown"
    fi

    local return_code=0
    set +e
    if [ "$distro_id" == "ubuntu" ]; then
        # Debian prerm prompts if mountmap contains entries; clear tracked state for non-interactive test runs.
        sudo truncate -s 0 /opt/microsoft/aznfs/data/mountmap >/dev/null 2>&1 || true
        sudo truncate -s 0 /opt/microsoft/aznfs/data/mountmapv4 >/dev/null 2>&1 || true

        remove_output=$(timeout 180s sudo env AZNFS_NONINTERACTIVE_INSTALL=1 DEBIAN_FRONTEND=noninteractive apt purge -y aznfs 2>&1)
        return_code=$?
        if [ $return_code -eq 124 ] || [ $return_code -eq 137 ]; then
            echo "[WARN] aznfs apt purge timed out; retrying with no-op prerm fallback"
            recover_ubuntu_dpkg_after_timeout "aznfs"

            if [ -f /var/lib/dpkg/info/aznfs.prerm ]; then
                sudo cp /var/lib/dpkg/info/aznfs.prerm /var/lib/dpkg/info/aznfs.prerm.bak >/dev/null 2>&1 || true
                printf '#!/bin/sh\nexit 0\n' | sudo tee /var/lib/dpkg/info/aznfs.prerm >/dev/null 2>&1 || true
                sudo chmod 0755 /var/lib/dpkg/info/aznfs.prerm >/dev/null 2>&1 || true
            fi

            remove_output=$(timeout 180s sudo env AZNFS_NONINTERACTIVE_INSTALL=1 DEBIAN_FRONTEND=noninteractive apt purge -y aznfs 2>&1)
            return_code=$?
            if [ $return_code -eq 124 ] || [ $return_code -eq 137 ]; then
                echo "[WARN] aznfs apt purge retry timed out; forcing dpkg remove"
                recover_ubuntu_dpkg_after_timeout "aznfs"
                remove_output=$(sudo env DEBIAN_FRONTEND=noninteractive dpkg --remove --force-remove-reinstreq aznfs 2>&1)
                return_code=$?
            fi
        fi
    elif [ "$distro_id" == "centos" -o "$distro_id" == "rocky" -o "$distro_id" == "rhel" ]; then
        remove_output=$(sudo yum remove -y aznfs 2>&1)
        return_code=$?
        if [ $return_code -ne 0 ]; then
            remove_output=$(sudo rpm -e --noscripts aznfs 2>&1)
            return_code=$?
        fi
    elif [ "$distro_id" == "sles" ]; then
        remove_output=$(sudo zypper remove -y aznfs aznfs_sles 2>&1)
        return_code=$?
        if [ $return_code -ne 0 ]; then
            remove_output=$(sudo rpm -e --noscripts aznfs aznfs_sles 2>&1)
            return_code=$?
        fi
    else
        set -e
        fail "Unknown Linux distribution while removing aznfs"
    fi
    set -e

    if [ $return_code -ne 0 ]; then
        if echo "$remove_output" | grep -q "/dev/tty"; then
            echo "[WARN] aznfs remove hit /dev/tty non-interactive scriptlet issue; attempting rpm --noscripts fallback"
            if sudo rpm -e --noscripts aznfs aznfs_sles >/dev/null 2>&1; then
                return 0
            fi
        fi

        echo "Error occurred while removing aznfs package. Exit Code: $return_code"
        echo "Error Output: $remove_output"
        fail "Failed to remove aznfs package"
    fi

    echo "Successfully removed aznfs package!"
}

remove_azfiles()
{
    if [ -f /etc/centos-release ]; then
        distro_id="centos"
    elif [ -f /etc/os-release ]; then
        distro_id=$(grep "^ID=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
        distro_id=$(canonicalize_distro_id "$distro_id")
    else
        fail "Unable to detect Linux distribution while removing azfiles"
    fi

    local return_code=0
    set +e
    if [ "$distro_id" == "ubuntu" ]; then
        # Debian prerm prompts if mountmap contains entries; clear tracked state for non-interactive test runs.
        sudo truncate -s 0 /opt/microsoft/azfiles-nfs/data/mountmapv4 >/dev/null 2>&1 || true

        remove_output=$(timeout 180s sudo env AZNFS_NONINTERACTIVE_INSTALL=1 DEBIAN_FRONTEND=noninteractive apt purge -y azfiles-nfs 2>&1)
        return_code=$?
        if [ $return_code -eq 124 ] || [ $return_code -eq 137 ]; then
            echo "[WARN] azfiles-nfs apt purge timed out; retrying with no-op prerm fallback"
            recover_ubuntu_dpkg_after_timeout "azfiles-nfs"

            if [ -f /var/lib/dpkg/info/azfiles-nfs.prerm ]; then
                sudo cp /var/lib/dpkg/info/azfiles-nfs.prerm /var/lib/dpkg/info/azfiles-nfs.prerm.bak >/dev/null 2>&1 || true
                printf '#!/bin/sh\nexit 0\n' | sudo tee /var/lib/dpkg/info/azfiles-nfs.prerm >/dev/null 2>&1 || true
                sudo chmod 0755 /var/lib/dpkg/info/azfiles-nfs.prerm >/dev/null 2>&1 || true
            fi

            remove_output=$(timeout 180s sudo env AZNFS_NONINTERACTIVE_INSTALL=1 DEBIAN_FRONTEND=noninteractive apt purge -y azfiles-nfs 2>&1)
            return_code=$?
            if [ $return_code -eq 124 ] || [ $return_code -eq 137 ]; then
                echo "[WARN] azfiles-nfs apt purge retry timed out; forcing dpkg remove"
                recover_ubuntu_dpkg_after_timeout "azfiles-nfs"
                remove_output=$(sudo env DEBIAN_FRONTEND=noninteractive dpkg --remove --force-remove-reinstreq azfiles-nfs 2>&1)
                return_code=$?
            fi
        fi
    elif [ "$distro_id" == "centos" -o "$distro_id" == "rocky" -o "$distro_id" == "rhel" ]; then
        remove_output=$(sudo yum remove -y azfiles-nfs 2>&1)
        return_code=$?
        if [ $return_code -ne 0 ]; then
            remove_output=$(sudo rpm -e --noscripts azfiles-nfs 2>&1)
            return_code=$?
        fi
    elif [ "$distro_id" == "sles" ]; then
        remove_output=$(sudo zypper remove -y azfiles-nfs azfiles-nfs_sles 2>&1)
        return_code=$?
        if [ $return_code -ne 0 ]; then
            remove_output=$(sudo rpm -e --noscripts azfiles-nfs azfiles-nfs_sles 2>&1)
            return_code=$?
        fi
    else
        set -e
        fail "Unknown Linux distribution while removing azfiles"
    fi
    set -e

    if [ $return_code -ne 0 ]; then
        if echo "$remove_output" | grep -q "/dev/tty"; then
            echo "[WARN] azfiles remove hit /dev/tty non-interactive scriptlet issue; attempting rpm --noscripts fallback"
            if sudo rpm -e --noscripts azfiles-nfs azfiles-nfs_sles >/dev/null 2>&1; then
                return 0
            fi
        fi

        echo "Error occurred while removing azfiles package. Exit Code: $return_code"
        echo "Error Output: $remove_output"
        fail "Failed to remove azfiles package"
    fi

    echo "Successfully removed azfiles package!"
}

remove_aznfs_and_azfiles_if_present()
{
    # Run removals in subshells so fail() exits do not abort matrix setup.
    # This helper is best-effort cleanup and should tolerate already-absent packages.
    ( remove_aznfs >/dev/null 2>&1 ) || true
    ( remove_azfiles >/dev/null 2>&1 ) || true
}

# Function to mount Blob NFS share using AZNFS.
do_blob_mount()
{
    local storage_account="$1"
    local directory="$2"
    local blob_export

    blob_export=$(get_blob_export_path "$storage_account")

    # Create mount directory if not exists.
    if [ ! -d "$directory" ]; then
        sudo mkdir -p "$directory"
        echo "Directory '$directory' created."
    else
        echo "Directory '$directory' already exists."
    fi

    # Mount the share.
    sudo mount -v -t aznfs -o vers=3,proto=tcp "$blob_export" "$directory"

    local return_code=$?
    if [ "$return_code" -ne 0 ]; then
        echo "[ERROR] mount target: $blob_export"
        fail "Mount operation failed with exit code $return_code"
    fi
}

# Function to mount Azure Files NFS share using AZNFS (TLS or notls).
do_files_mount()
{
    local storage_account="$1"
    local directory="$2"
    local mode="$3"
    local files_export
    local mount_options="vers=4.1"

    files_export=$(get_files_export_path "$storage_account")

    if [ "$mode" == "notls" ]; then
        # clean avoids stale stunnel state when switching from TLS to notls for the same endpoint.
        mount_options="vers=4.1,notls,clean"
    fi

    # Create mount directory if not exists.
    if [ ! -d "$directory" ]; then
        sudo mkdir -p "$directory"
        echo "Directory '$directory' created."
    else
        echo "Directory '$directory' already exists."
    fi

    sudo mount -v -t aznfs -o "$mount_options" "$files_export" "$directory"

    local return_code=$?
    if [ "$return_code" -ne 0 ]; then
        echo "[ERROR] mount target: $files_export"
        echo "[ERROR] files mount mode: $mode"
        fail "Files mount operation failed with exit code $return_code"
    fi
}

# Function to run connectathon tests for AZNFS mount.
run_connectathon_tests() 
{
    local mount_directory="$1"
    local testsuite_directory="/lib/UnixTestSuite/linx"
    local connectathon_test_directory="githubtest$RANDOM"

    # Check if the UnixTestSuite directory doesn't exist.
    if [ ! -d "$testsuite_directory" ]; then
        if [ "${SKIP_CONNECTATHON_IF_MISSING:-0}" == "1" ]; then
            echo "[WARN] UnixTestSuite directory is missing at $testsuite_directory; skipping connectathon tests."
            return
        fi

        fail "UnixTestSuite directory is missing at $testsuite_directory"
    fi

    # Check if the mount directory doesn't exist.
    if [ ! -d "$mount_directory" ]; then
        fail "Mount directory does not exist at $mount_directory"
    fi

    local full_connectathon_test_directory="$mount_directory/$connectathon_test_directory"

    # Check if the connectathon test directory already exists.
    while [ -d "$full_connectathon_test_directory" ]; do
        echo "Connectathon test directory $full_connectathon_test_directory already exists. Generating a new random number."
        connectathon_test_directory="githubtest$RANDOM"
        full_connectathon_test_directory="$mount_directory/$connectathon_test_directory"
    done

    # Create the connectathon test directory.
    echo "Creating connectathon test directory: $full_connectathon_test_directory"
    sudo mkdir -p "$full_connectathon_test_directory"

    echo "=== Running connectathon tests on $full_connectathon_test_directory ==="

    # Run connectathon tests.
    connectathon_output=$(sudo "$testsuite_directory/runtests" -cthon "$full_connectathon_test_directory/unixtests" 2>&1)

    # Extract the content between TEST RESULT SUMMARY and All tests completed.
    filtered_connectathon_output=$(echo "$connectathon_output" | sed -n '/TEST RESULT SUMMARY/,/All tests completed/{//b;p}')
    failed_tests=""

    while IFS= read -r line; do
        # Split the line by "|".
        IFS='|' read -ra columns <<< "$line"

        subtest_name="${columns[2]}"
        test_fail="${columns[5]}"

        # Ignore unwanted header lines.
        if [[ ! "$test_fail" =~ [0-9]+ ]]; then
                continue
        fi

        # Check if a test is failing and test_name is not "dupreq" (since we don't support hard links).
        if [[ ! "$test_fail" =~ 0 ]]; then
            if [[ ! "$subtest_name" =~ dupreq ]]; then
                failed_tests+="$subtest_name\n"
            fi
        fi

    done <<< "$filtered_connectathon_output"

    # Check if there were failed tests.
    if [ -n "$failed_tests" ]; then
        echo -e "[ERROR] Failed Tests:\n$failed_tests"
        echo -e "Connectathon Output:\n$connectathon_output"
        fail "Connectathon reported test failures"
    fi

    echo "Successfully completed all connectathon tests."

    # Log deletion of the connectathon test directory.
    echo "Deleting connectathon test directory $full_connectathon_test_directory"
    sudo rm -rf "$full_connectathon_test_directory"
}

do_unmount() 
{
    local directory="$1"

    # Unmount the share.
    sudo umount "$directory"
    local return_code=$?
    if [ "$return_code" -ne 0 ]; then
        fail "Unmount operation failed with exit code $return_code"
    fi
}

# Validate that Blob NFS mounts remain blocked after aznfs is removed and only azfiles-nfs remains.
validate_blob_mount_blocked_without_aznfs()
{
    local storage_account="$1"
    local directory="$2"
    local blob_export

    blob_export=$(get_blob_export_path "$storage_account")

    if [ ! -d "$directory" ]; then
        sudo mkdir -p "$directory"
    fi

    set +e
    mount_output=$(sudo mount -v -t aznfs -o vers=3,proto=tcp "$blob_export" "$directory" 2>&1)
    local return_code=$?
    set -e

    if [ "$return_code" -eq 0 ]; then
        echo "[ERROR] Blob NFS mount unexpectedly succeeded while only azfiles-nfs was installed."
        echo "[ERROR] mount target: $blob_export"
        echo "$mount_output"
        fail "Blob NFS mount unexpectedly succeeded while only azfiles-nfs was installed"
    fi

    echo "Blob NFS mount blocked as expected after aznfs removal."
}

run_transition_scenarios()
{
    local legacy_release_number="$1"
    local current_release_number="$2"
    local storage_account="$3"
    local files_storage_account="${FILES_STORAGE_ACCOUNT:-$storage_account}"
    local install_mode="${INSTALL_MODE:-release}"
    local use_preseeded_legacy_aznfs="${USE_PRESEEDED_LEGACY_AZNFS:-0}"

    # Matrix runs execute multiple remove/install cycles; avoid long sleeps unless explicitly requested.
    AZNFS_REMOVE_SLEEP_SECONDS="${AZNFS_REMOVE_SLEEP_SECONDS:-0}"

    log_step "Scenario 1: Install azfiles-nfs (V+1) when aznfs (V) is present"

    if [ "$use_preseeded_legacy_aznfs" == "1" ]; then
        if ! is_aznfs_installed; then
            fail "Scenario 1 precondition failed: expected pre-seeded aznfs to already be installed"
        fi

        if is_azfiles_installed; then
            fail "Scenario 1 precondition failed: azfiles-nfs must not be preinstalled when USE_PRESEEDED_LEGACY_AZNFS=1"
        fi
    else
        remove_aznfs_and_azfiles_if_present

        if [ "$install_mode" == "local" ]; then
            AZNFS_LOCAL_PACKAGE="$LEGACY_AZNFS_LOCAL_PACKAGE"
            # Legacy aznfs is pre-split and must install standalone.
            unset AZFILES_LOCAL_PACKAGE
        fi

        install_aznfs "$legacy_release_number"
    fi

    if [ "$install_mode" == "local" ]; then
        AZFILES_LOCAL_PACKAGE="$CURRENT_AZFILES_LOCAL_PACKAGE"
        INCLUDE_CURRENT_AZNFS_WITH_AZFILES=1
    fi

    install_azfiles_nfs "$current_release_number"
    unset INCLUDE_CURRENT_AZNFS_WITH_AZFILES
    log_package_state
    assert_state 1 1 "5.2 Scenario 1 validation"

    log_step "Scenario 2: Upgrade aznfs from V to V+1"

    if [ "$install_mode" == "local" ]; then
        AZNFS_LOCAL_PACKAGE="$CURRENT_AZNFS_LOCAL_PACKAGE"
        AZFILES_LOCAL_PACKAGE="$CURRENT_AZFILES_LOCAL_PACKAGE"
    fi

    install_aznfs "$current_release_number"
    log_package_state
    assert_state 1 1 "5.2 Scenario 2 validation"
    assert_azfiles_version_matches_aznfs "5.2 Scenario 2 version alignment validation"

    log_step "Scenario 3: Install only azfiles-nfs"
    remove_aznfs_and_azfiles_if_present

    # Force clean state if best-effort cleanup was blocked by scriptlets.
    if is_aznfs_installed; then
        remove_aznfs >/dev/null 2>&1 || true
    fi

    if is_azfiles_installed; then
        remove_azfiles >/dev/null 2>&1 || true
    fi

    if [ "$install_mode" == "local" ]; then
        AZFILES_LOCAL_PACKAGE="$CURRENT_AZFILES_LOCAL_PACKAGE"
    fi

    install_azfiles_nfs "$current_release_number"
    log_package_state
    assert_state 0 1 "5.2 Scenario 3 validation"

    log_step "Scenario 4: Uninstall aznfs while retaining azfiles-nfs"

    if [ "$install_mode" == "local" ]; then
        AZNFS_LOCAL_PACKAGE="$CURRENT_AZNFS_LOCAL_PACKAGE"
        AZFILES_LOCAL_PACKAGE="$CURRENT_AZFILES_LOCAL_PACKAGE"
    fi

    install_aznfs "$current_release_number"
    log_package_state
    assert_state 1 1 "5.2 Scenario 4 pre-remove validation"

    # 5.4: Blob combination coverage with both packages installed.
    do_blob_mount "$storage_account" "/mnt/githubtest"
    pass "5.4 Blob mount validation with aznfs+azfiles"
    run_connectathon_tests "/mnt/githubtest"
    do_unmount "/mnt/githubtest"

    # Azure Files validation with TLS and notls in combined install state.
    do_files_mount "$files_storage_account" "/mnt/githubtest-files-tls" "tls"
    pass "5.4 Files TLS mount validation with aznfs+azfiles"
    run_connectathon_tests "/mnt/githubtest-files-tls"
    do_unmount "/mnt/githubtest-files-tls"

    do_files_mount "$files_storage_account" "/mnt/githubtest-files-notls" "notls"
    pass "5.4 Files notls mount validation with aznfs+azfiles"
    run_connectathon_tests "/mnt/githubtest-files-notls"
    do_unmount "/mnt/githubtest-files-notls"

    remove_aznfs
    log_package_state
    assert_state 0 1 "5.3/5.4 post-remove package state validation"

    # Azure Files mounts should continue to work with azfiles-nfs only.
    do_files_mount "$files_storage_account" "/mnt/githubtest-files-tls" "tls"
    pass "5.3 Files TLS mount validation in azfiles-only state"
    do_unmount "/mnt/githubtest-files-tls"

    do_files_mount "$files_storage_account" "/mnt/githubtest-files-notls" "notls"
    pass "5.3 Files notls mount validation in azfiles-only state"
    do_unmount "/mnt/githubtest-files-notls"

    # 5.3 + 5.4: Blob mount must be blocked when only azfiles remains.
    validate_blob_mount_blocked_without_aznfs "$storage_account" "/mnt/githubtest"
    pass "5.3 Blob block validation in azfiles-only state"
}


declare -a STORAGE_ACCOUNTS_ARRAY
IFS=' ' read -ra STORAGE_ACCOUNTS_ARRAY <<< "$STORAGE_ACCOUNTS"

# Get the count of elements.
storage_account_count="${#STORAGE_ACCOUNTS_ARRAY[@]}"
echo "Number of storage accounts in the input: $storage_account_count"

first_storage_account="${STORAGE_ACCOUNTS_ARRAY[0]}"

legacy_release_number="${LEGACY_RELEASE_NUMBER:-$RELEASE_NUMBER}"

if is_aznfs_installed; then
    INITIAL_AZNFS_INSTALLED="1"
fi

if is_azfiles_installed; then
    INITIAL_AZFILES_INSTALLED="1"
fi

log_step "Running transition scenario matrix"
run_transition_scenarios "${legacy_release_number}" "${RELEASE_NUMBER}" "${first_storage_account}"

log_step "All scenario and mount tests completed successfully"
SCRIPT_STATUS="PASSED"