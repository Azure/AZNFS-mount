#!/bin/bash
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

RELEASE_NUMBER=x.y.z
apt_update_done=false
yum="yum"
apt=0
zypper=0
distro_id=
install_cmd=

RED="\e[2;31m"
GREEN="\e[2;32m"
YELLOW="\e[2;33m"
NORMAL="\e[0m"

#
# Core logging function.
#
_log()
{
    echoarg=""

    # We only support -n argument to echo.
    if [ "$1" == "-n" ]; then
        echoarg="-n"
        shift
    fi

    color=$1
    msg=$2

    echo $echoarg -e "${color}${msg}${NORMAL}"
}

#
# Plain echo.
#
pecho()
{
    echoarg=""
    color=$NORMAL
    if [ "$1" == "-n" ]; then
        echoarg="-n"
        shift
    fi
    _log $echoarg $color "${*}"
}

#
# Success echo.
#
secho()
{
    echoarg=""
    color=$GREEN
    if [ "$1" == "-n" ]; then
        echoarg="-n"
        shift
    fi
    _log $echoarg $color "${*}"
}

#
# Warning echo.
#
wecho()
{
    echoarg=""
    color=$YELLOW
    if [ "$1" == "-n" ]; then
        echoarg="-n"
        shift
    fi
    _log $echoarg $color "${*}"
}

#
# Error echo.
#
eecho()
{
    echoarg=""
    color=$RED
    if [ "$1" == "-n" ]; then
        echoarg="-n"
        shift
    fi
    _log $echoarg $color "${*}"
}

use_dnf_or_yum() 
{
    yum="yum"
    if command -v dnf &> /dev/null; then
        yum="dnf"
        pecho "Using 'dnf' instead of 'yum'"
    fi
}

#
# This returns distro id in a canonical form, that rest of the code understands.
# We only use lowercase single word names for distro names:
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

#
# Install the package appropriately as per the current distro.
# If distro_id is already detected it uses that else it tries to guess
# the distro.
#
ensure_pkg()
{
    local pkg="$1"
    local distro="$distro_id"

    if [ "$distro" == "ubuntu" ]; then
        if ! $apt_update_done; then
            sudo apt -y update
            if [ $? -ne 0 ]; then
                echo
                eecho "\"apt update\" failed"
                eecho "Please make sure \"apt update\" runs successfully and then try again!"
                exit 1
                echo
            fi
            # Need to run apt update only once.
            apt_update_done=true
        fi
        apt=1
        sudo apt install -y $pkg
    elif [ "$distro" == "centos" -o "$distro" == "rocky" -o "$distro" == "rhel" ]; then
        # lsb_release package is called redhat-lsb-core in redhat/centos.
        if [ "$pkg" == "lsb-release" ]; then
            pkg="redhat-lsb-core"
        fi
        use_dnf_or_yum
        sudo $yum install -y $pkg
    elif [ "$distro" == "sles" ]; then
        zypper=1
        sudo zypper install -y $pkg
    fi
}

if [ $RELEASE_NUMBER == "x.y.z" ]; then
    eecho "This script is directly downloaded from the github source code."
    eecho "Please download the aznfs_install.sh from 'https://github.com/Azure/BlobNFS-mount/releases/latest'"
    eecho "If the problem persists, contact Microsoft support."
    exit 1
fi

#
# Detect OS and Version.
#
__m=$(uname -m 2>/dev/null) || __m=unknown
__s=$(uname -s 2>/dev/null) || __s=unknown

#
# Try to detect the distro in a resilient manner and set distro_id
# global variables.
#
case "${__m}:${__s}" in
    "x86_64:Linux")
        if [ -f /etc/centos-release ]; then
            pecho "Retrieving distro info from /etc/centos-release..."
            distro_id="centos"
        elif [ -f /etc/os-release ]; then
            pecho "Retrieving distro info from /etc/os-release..."
            distro_id=$(grep "^ID=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
            distro_id=$(canonicalize_distro_id $distro_id)
        else
            eecho "[FATAL] Unknown linux distro.'/etc/os-release' is not present."
            pecho "Download .deb/.rpm package based on your distro from 'https://github.com/Azure/BlobNFS-mount/releases/latest'"
            pecho "If the problem persists, contact Microsoft support."
        fi
        ;;
    *)
        eecho "[FATAL] Unsupported platform: ${__m}:${__s}."
        exit 1
        ;;
esac

ensure_pkg "wget"

if [ $apt -eq 1 ]; then
    install_cmd="apt"
    wget https://github.com/Azure/BlobNFS-mount/releases/download/${RELEASE_NUMBER}/aznfs_${RELEASE_NUMBER}_amd64.deb -P /tmp
    sudo apt install /tmp/aznfs_${RELEASE_NUMBER}_amd64.deb
    install_error=$?
    rm /tmp/aznfs_${RELEASE_NUMBER}_amd64.deb
elif [ $zypper -eq 1 ]; then
    install_cmd="zypper"
    # Does not support SUSE for now.
else
    install_cmd="yum"
    # Does not support CentOS for now.
fi

if [ $install_error -ne 0 ]; then
    eecho "[FATAL] Error installing aznfs (Error: $install_error). See '$install_cmd' command logs for more information."
fi

secho "Latest version of AZNFS is installed."
