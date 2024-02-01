#!/bin/bash

# Function to download and execute AZNFS installation script.
install_aznfs() 
{
    local release_number="$1"

    # URL for the specific release.
    echo "RELEASE_NUMBER=$release_number"
    local release_url="https://github.com/Azure/AZNFS-mount/releases/download/${release_number}/aznfs_install.sh"
    echo "release_url=$release_url"

    # Download and execute the installation script.
    export AZNFS_NONINTERACTIVE_INSTALL=1
    sudo wget -O - -q "$release_url" | bash

    local return_code=$?
    if [ "$return_code" -ne 0 ]; then
        echo "[ERROR] Installation script failed with exit code $return_code"
        exit 1
    fi
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

    echo "$distro_lower"
}

remove_aznfs()
{
    # sleep for mountmap inactivity seconds.
    sleep 300

    if [ -f /etc/centos-release ]; then
        distro_id="centos"
    elif [ -f /etc/os-release ]; then
        distro_id=$(grep "^ID=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
        distro_id=$(canonicalize_distro_id $distro_id)
    else
        # Ideally, this should not happen.
        distro_id="Unknown"
    fi

    if [ "$distro_id" == "ubuntu" ]; then
        remove_output=$(apt purge -y aznfs 2>&1)
    elif [ "$distro_id" == "centos" -o "$distro_id" == "rocky" -o "$distro_id" == "rhel" ]; then
        remove_output=$(yum remove -y aznfs 2>&1)
    elif [ "$distro_id" == "sles" ]; then
        remove_output=$(zypper remove -y aznfs_sles 2>&1)
    else
        # Ideally, this should not happen.
        echo "Unknown Linux Distribution!"
    fi

    return_code=$?
    if [ $return_code -ne 0 ]; then
        echo "Error occurred while removing the package. Exit Code: $return_code"
        echo "Error Output: $remove_output"
        exit 1
    fi

    echo "Successfully removed aznfs package!"
}

# Function to mount NFS share using AZNFS.
do_mount() 
{
    local storage_account="$1"
    local directory="$2"

    # Create mount directory if not exists.
    if [ ! -d "$directory" ]; then
        sudo mkdir -p "$directory"
        echo "Directory '$directory' created."
    else
        echo "Directory '$directory' already exists."
    fi

    # Mount the share.
    sudo mount -v -t aznfs -o vers=3,proto=tcp "${storage_account}.blob.core.windows.net:/${storage_account}/githubtest" "$directory"

    local return_code=$?
    if [ "$return_code" -ne 0 ]; then
        echo "[ERROR] Mount operation failed with exit code $return_code"
        exit 1
    fi
}

# Function to run connectathon tests for AZNFS mount.
run_connectathon_tests() 
{
    local mount_directory="$1"
    local testsuite_directory="/lib/UnixTestSuite/linx"
    local random_number=$RANDOM
    local connectathon_test_directory="githubtest$random_number"

    # Check if the UnixTestSuite directory doesn't exist.
    if [ ! -d "$testsuite_directory" ]; then
        echo "[ERROR] UnixTestSuite directory is missing at: $testsuite_directory"
        exit 1
    fi

    # Check if the mount directory doesn't exist.
    if [ ! -d "$mount_directory" ]; then
        echo "[ERROR] Mount directory does not exist at: $mount_directory"
        exit 1
    fi

    local full_connectathon_test_directory="$mount_directory/$connectathon_test_directory"

    # Check if the connectathon test directory already exists.
    while [ -d "$full_connectathon_test_directory" ]; do
        echo "Connectathon test directory $full_connectathon_test_directory already exists. Generating a new random number."
        random_number=$RANDOM
        connectathon_test_directory="githubtest$random_number"
        full_connectathon_test_directory="$mount_directory/$connectathon_test_directory"
    done

    # Create the connectathon test directory.
    echo "Creating connectathon test directory: $full_connectathon_test_directory"
    sudo mkdir -p "$full_connectathon_test_directory"

    echo "=== Running connectathon tests on: $full_connectathon_test_directory ==="

    # Run connectathon tests.
    # TODO:
    # 1. Fail the job if any mandatory connectathon test fails, and don't delete the directory as well.
    sudo "$testsuite_directory/runtests" -cthon "$full_connectathon_test_directory/unixtests"

    # Log deletion of the connectathon test directory.
    echo "Deleting connectathon test directory: $full_connectathon_test_directory"
    sudo rm -rf "$full_connectathon_test_directory"
}

do_unmount() 
{
    local directory="$1"

    # Unmount the share.
    sudo umount "$directory"
    local return_code=$?
    if [ "$return_code" -ne 0 ]; then
        echo "[ERROR] Unmount operation failed with exit code $return_code"
        exit 1
    fi
}


declare -a STORAGE_ACCOUNTS_ARRAY
IFS=' ' read -ra STORAGE_ACCOUNTS_ARRAY <<< "$STORAGE_ACCOUNTS"

# Get the count of elements.
storage_account_count="${#STORAGE_ACCOUNTS_ARRAY[@]}"
echo "Number of storage accounts in the input: $storage_account_count"

first_storage_account="${STORAGE_ACCOUNTS_ARRAY[0]}"

install_aznfs "${RELEASE_NUMBER}"
do_mount "${first_storage_account}" "/mnt/githubtest" 
run_connectathon_tests "/mnt/githubtest"
do_unmount "/mnt/githubtest"
remove_aznfs