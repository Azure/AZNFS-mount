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

# Function to run connectathon tests for AZNFS mount.
run_connectathon_tests() 
{
    local mount_directory="$1"
    local testsuite_directory="/lib/UnixTestSuite/linx"
    local random_number=$((10000 + RANDOM % 90000))
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
    if [ -d "$full_connectathon_test_directory" ]; then
        echo "[ERROR] Connectathon test directory already exists at: $full_connectathon_test_directory"
        echo "Please rerun the workflow with a new random number."
        exit 1
    fi

    # Create the connectathon test directory.
    echo "Creating connectathon test directory: $full_connectathon_test_directory"
    sudo mkdir -p "$full_connectathon_test_directory"

    echo "=== Running connectathon tests on mountpoint: $full_connectathon_test_directory ==="

    # Run connectathon tests.
    sudo "$testsuite_directory/runtests" -cthon "$full_connectathon_test_directory/unixtests"

    # Log deletion of the connectathon test directory.
    echo "Deleting connectathon test directory: $full_connectathon_test_directory"
    sudo rm -r "$full_connectathon_test_directory"
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
remove_aznfs