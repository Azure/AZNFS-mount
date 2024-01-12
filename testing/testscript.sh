#!/bin/bash

# Function to download and execute AZNFS installation script.
install_aznfs() {
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
        log "Error: Installation script failed with exit code $return_code"
        exit 1
    fi
}

# Function to check scripts for errors using shellcheck
check_scripts_with_shellcheck() {
  local files_to_check=(
    "/usr/sbin/aznfswatchdog"
    "/opt/microsoft/aznfs/common.sh"
    "/opt/microsoft/aznfs/mountscript.sh"
  )

  for file in "${files_to_check[@]}"; do
    echo "***Checking $file for errors...***"
    output=$(shellcheck --severity=error "$file")

    if [ -n "$output" ]; then
      echo "$output"
    else
      echo "No errors found in $file."
    fi
  done
}

# Function to mount NFS share using AZNFS.
do_mount() {
    local storage_account="$1"
    local directory="$2"

    # Create mount directory if not exists.
    if [ ! -d "$directory" ]; then
        echo "Creating directory '$directory'..."
        sudo mkdir "$directory"
        echo "Directory '$directory' created."
    else
        echo "Directory '$directory' already exists."
    fi

    # Mount the share.
    sudo mount -t aznfs -o vers=3,proto=tcp "${storage_account}.blob.core.windows.net:/${storage_account}/container1" "$directory"
    
    local return_code=$?
    if [ "$return_code" -ne 0 ]; then
        log "Error: Mount operation failed with exit code $return_code"
        exit 1
    fi

    nfsstat_output=$(nfsstat -m)
    echo "Output of nfsstat -m:"
    echo "$nfsstat_output"
}

# Function to run connectathon tests for AZNFS mount
run_connectathon_tests() {
  local mount_directory="$1"

  echo "RUNNING UNIX TEST SUITE FOR AZNFS MOUNTED SHARE AT $mount_directory"
  sudo /lib/UnixTestSuite/linx/runtests -cthon "$mount_directory/unixtests"
}

# Function to perform basic tests
perform_basic_tests() {
    local base_dir=$1

    for ((n=0; n<2; n++))
    do
        DIRNAME="$base_dir/testdir$RANDOM"
        echo "[$(date -u)] Creating directory $DIRNAME"
        mkdir "$DIRNAME"
        for ((m=0; m<2; m++))
        do
            FILENAME="testfile$RANDOM"
            SYMLINK="testsymlink$RANDOM"

            echo "[$(date -u)] Create file $FILENAME"
            touch "$DIRNAME/$FILENAME"
            echo "[$(date -u)] Create Symlink $SYMLINK"
            ln -s "$DIRNAME/$FILENAME" "$DIRNAME/$SYMLINK"
            echo "[$(date -u)] Writing to $DIRNAME/$FILENAME"
            echo "[$(date -u)] This is a test file for test" > "$DIRNAME/$FILENAME"
            dd if=/dev/zero of="$DIRNAME/$FILENAME" bs=1M count=10000
        done

        # Clean up files in the directory after each iteration
        rm -rf "$DIRNAME"
    done
}

perform_mount_stress_test() {
    local storage_account="$1"
    local lower_limit="$2"
    local upper_limit="$3"

    for ((i=lower_limit; i<=upper_limit; i++)); do
        local mount_directory="/mnt/palashvijmh$i"
        
        mkdir -p "$mount_directory"
        mount -t aznfs -o vers=3,proto=tcp "$storage_account.blob.core.windows.net:/$storage_account/container1" "$mount_directory"
        echo "$i"
        
        local file_path="$mount_directory/file$i"
        touch "$file_path"
        
        dd if=/dev/zero of="$file_path" bs=1M count=100
        if [ $? -ne 0 ]; then
            echo "****dd failed for mount $i"
        fi
        
        date
    done

    # Removing all the files in mounted shares
    for ((i=lower_limit; i<=upper_limit; i++)); do
        rm -f "/mnt/palashvijmh$i/file$i"
    done
}

perform_unmount_stress_test() {
    local lower_limit="$1"
    local upper_limit="$2"

    for ((i=lower_limit; i<=upper_limit; i++)); do
        local mount_directory="/mnt/palashvijmh$i"
        
        umount -f "$mount_directory"
        rm -r "$mount_directory"
        
        echo "$i"
        date -u
    done
}


install_aznfs "${RELEASE_NUMBER}"
check_scripts_with_shellcheck
do_mount "${STORAGE_ACCOUNT}" "/mnt/palashvij" 
run_connectathon_tests "/mnt/palashvij"
perform_basic_tests "/mnt/palashvij"
umount -f "/mnt/palashvij"
perform_mount_stress_test "${STORAGE_ACCOUNT}" "1" "100"
perform_unmount_stress_test "1" "100"