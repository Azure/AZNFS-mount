#!/bin/bash

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

runs_on="$1"  # The value passed from the workflow.

install_dependencies "$runs_on"
untar_unix_test_suite
