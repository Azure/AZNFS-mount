#!/bin/bash

install_dependencies() {
    local distro="$1"

    if [ "$distro" == "ubuntu" ]; then
        sudo apt-get update
        sudo apt-get install -y build-essential
    elif [ "$distro" == "centos" -o "$distro" == "rocky" -o "$distro" == "rhel" ]; then
        sudo yum groupinstall -y "Development Tools"
    fi
}

untar_unix_test_suite() {
    mkdir -p /lib
    tar -xf "$GITHUB_WORKSPACE/UnixTestSuite.tar" -C /lib
}

runs_on="$1"  # The value passed from the workflow.

install_dependencies "$runs_on"
untar_unix_test_suite
