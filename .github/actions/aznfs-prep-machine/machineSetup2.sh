#!/bin/bash

runs_on="$1"  # The value passed from the workflow.

if [ "$runs_on" == "ubuntu" ]; then
    sudo apt-get update
    sudo apt-get install -y build-essential
elif [ "$runs_on" == "centos" -o "$runs_on" == "rocky" -o "$runs_on" == "rhel" ]; then
    sudo yum groupinstall -y "Development Tools"
fi
