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

# Function to mount NFS share using AZNFS.
do_mount() 
{
    local storage_account="$1"
    local directory="$2"

    # Create mount directory if not exists.
    if [ ! -d "$directory" ]; then
        sudo mkdir "$directory"
        echo "Directory '$directory' created."
    else
        echo "Directory '$directory' already exists."
    fi

    # Mount the share.
    sudo mount -t aznfs -o vers=3,proto=tcp "${storage_account}.blob.core.windows.net:/${storage_account}/container1" "$directory"
    
    local return_code=$?
    if [ "$return_code" -ne 0 ]; then
        echo "[ERROR] Mount operation failed with exit code $return_code"
        exit 1
    fi
}

# Function to run connectathon tests for AZNFS mount
run_connectathon_tests() 
{
    local mount_directory="$1"
    local testsuite_directory="/lib/UnixTestSuite/linx"

    echo "=== RUNNING CONNECTATHON TESTS FOR AZNFS MOUNT ==="

    # Check if the UnixTestSuite directory doesn't exist
    if [ ! -d "$testsuite_directory" ]; then
    echo "[ERROR] UnixTestSuite directory is missing at: $testsuite_directory"
    exit 1
    fi

    # Check if the mount directory doesn't exist
    if [ ! -d "$mount_directory" ]; then
    echo "[ERROR] Mount directory does not exist at: $mount_directory"
    exit 1
    fi

    # Run connectathon tests.
    sudo "$testsuite_directory/runtests" -cthon "$mount_directory/unixtests"
}

do_unmount() 
{
    local directory="$1"

    # Unmount the share.
    sudo umount -f "$directory"
    local return_code=$?
    if [ "$return_code" -ne 0 ]; then
        echo "[ERROR] Unmount operation failed with exit code $return_code" >&2
        exit 1
    fi
}


declare -a STORAGE_ACCOUNTS_ARRAY
IFS=' ' read -ra STORAGE_ACCOUNTS_ARRAY <<< "$STORAGE_ACCOUNTS"

# Get the count of elements.
storage_account_count="${#STORAGE_ACCOUNTS_ARRAY[@]}"
echo "Number of storage accounts in the input: $storage_account_count"

# Access the first storage account.
first_storage_account="${STORAGE_ACCOUNTS_ARRAY[0]}"

install_aznfs "${RELEASE_NUMBER}"
do_mount "${first_storage_account}" "/mnt/palashvij" 
run_connectathon_tests "/mnt/palashvij"
do_unmount "/mnt/palashvij"