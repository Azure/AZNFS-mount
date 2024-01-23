#!/bin/bash

install_dependencies() 
{
    local distro="$1"

    if [ "$distro" == "ubuntu" ]; then
        sudo apt-get update
        sudo apt-get install -y build-essential
    elif [ "$distro" == "centos" -o "$distro" == "rocky" -o "$distro" == "rhel" ]; then
        sudo yum groupinstall -y "Development Tools"
    fi
        
    install_error=$?
    if [ $install_error -ne 0 ]; then
        echo "[ERROR] Installing dependencies for runner machine failed!"
        exit 1
    fi
}

untar_unix_test_suite()
{
   local directory="/lib"

    if [ ! -d "$directory" ]; then
        sudo mkdir -p "$directory" || { echo "[ERROR] Unable to create directory $directory. Exiting."; exit 1; }
        echo "Directory '$directory' created."
    else
        echo "Directory '$directory' already exists."
    fi


    echo "Untarring UnixTestSuite.tar to /lib..."
    tar -xf "$GITHUB_WORKSPACE/UnixTestSuite.tar" -C /lib

    if [ $? -ne 0 ]; then
        echo "[ERROR] Unable to untar UnixTestSuite.tar."
        exit 1
    fi

    echo "UnixTestSuite.tar untarred successfully to /lib."
}

runs_on="$1"  # The value passed from the workflow.

install_dependencies "$runs_on"
untar_unix_test_suite
