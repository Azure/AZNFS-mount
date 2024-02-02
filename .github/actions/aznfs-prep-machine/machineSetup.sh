#!/bin/bash

MOUNTMAP="/opt/microsoft/aznfs/data/mountmap"

install_dependencies() 
{
    local runner="$1"

    if [ "$runner" == "self-hosted-ubuntu18" -o "$runner" == "self-hosted-ubuntu20" -o "$runner" == "self-hosted-ubuntu22" ]; then
        sudo apt-get update
        sudo apt install -y wget build-essential
    elif [ "$runner" == "self-hosted-centos7" -o "$runner" == "self-hosted-centos8" -o "$runner" == "self-hosted-redhat7" -o "$runner" == "self-hosted-redhat8" -o "$runner" == "self-hosted-redhat9" -o "$runner" == "self-hosted-rocky8" -o "$runner" == "self-hosted-rocky9" ]; then
        sudo yum install -y wget && sudo yum groupinstall -y "Development Tools"
    elif [ "$runner" == "self-hosted-suse15" ]; then
        sudo zypper install -y wget && sudo zypper install -y time
    fi
        
    install_error=$?
    if [ $install_error -ne 0 ]; then
        echo "[ERROR] Installing dependencies for $runner machine failed!"
        exit 1
    fi
}

untar_unix_test_suite()
{
    echo "Checking if /lib/UnixTestSuite already exists..."
    if [ -d "/lib/UnixTestSuite" ]; then
        echo "Directory '/lib/UnixTestSuite' already exists. Skipping untar."
    else
        echo "Untarring UnixTestSuite.tar to /lib..."
        tar -xf "$GITHUB_WORKSPACE/UnixTestSuite.tar" -C /lib

        if [ $? -ne 0 ]; then
            echo "[ERROR] Unable to untar UnixTestSuite.tar."
            exit 1
        fi

        echo "UnixTestSuite.tar untarred successfully to /lib/UnixTestSuite."
    fi

}

umount_all()
{
    echo "unmounting all nfs shares (if any)"

    nfsstat_output=$(nfsstat -m)
    if [ -n "$nfsstat_output" ]; then
        echo "nfsstat output: $nfsstat_output"
        sudo umount -af -t nfs
        
        # Check the exit status
        if [ $? -eq 0 ]; then
            echo "Unmount successful."
        else
            echo "Unmount failed. Check for errors."
        fi
    fi
}

remove_aznfs()
{
    local runner="$1"

    timeout=300  # Maximum wait-time (MOUNTMAP_INACTIVITY_SECONDS).
    start_time=$(date +%s)

    while [ -z "$(cat "$MOUNTMAP")" ]; do
        current_time=$(date +%s)
        elapsed_time=$((current_time - start_time))

        if [ "$elapsed_time" -ge "$timeout" ]; then
            echo "[ERROR] Timed out waiting for MOUNTMAP to become empty."
            exit 1
        fi

        echo "Waiting for MOUNTMAP to become empty..."
        sleep 30
    done

    if [ "$runner" == "self-hosted-ubuntu18" -o "$runner" == "self-hosted-ubuntu20" -o "$runner" == "self-hosted-ubuntu22" ]; then
        sudo apt purge -y aznfs
    elif [ "$runner" == "self-hosted-centos7" -o "$runner" == "self-hosted-centos8" -o "$runner" == "self-hosted-redhat7" -o "$runner" == "self-hosted-redhat8" -o "$runner" == "self-hosted-redhat9" -o "$runner" == "self-hosted-rocky8" -o "$runner" == "self-hosted-rocky9" ]; then
        sudo yum remove -y aznfs
    elif [ "$runner" == "self-hosted-suse15" ]; then
        sudo zypper remove -y aznfs_sles
    fi
        
    remove_error=$?
    if [ $remove_error -ne 0 ]; then
        echo "[ERROR] Installing removing aznfs for $runner machine failed!"
        exit 1
    fi
}

check_if_aznfs_installed_already()
{
    local runner="$1"

    if [ "$runner" == "self-hosted-ubuntu18" -o "$runner" == "self-hosted-ubuntu20" -o "$runner" == "self-hosted-ubuntu22" ]; then
        current_version=$(apt-cache show aznfs 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2)
    elif [ "$runner" == "self-hosted-centos7" -o "$runner" == "self-hosted-centos8" -o "$runner" == "self-hosted-redhat7" -o "$runner" == "self-hosted-redhat8" -o "$runner" == "self-hosted-redhat9" -o "$runner" == "self-hosted-rocky8" -o "$runner" == "self-hosted-rocky9" ]; then
        current_version=$(yum info aznfs 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2)
    elif [ "$runner" == "self-hosted-suse15" ]; then
        current_version=$(zypper info aznfs_sles 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2 | cut -d '-' -f1)
    fi

    if [ -n "$current_version" ]; then
        remove_aznfs "$runner"
        echo "Successfully removed aznfs $current_version from $runner"
    fi   
}

runs_on="$1"  # The value passed from the workflow.

install_dependencies "$runs_on"
untar_unix_test_suite
umount_all
check_if_aznfs_installed_already "$runs_on"