#!/bin/bash
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

RELEASE_NUMBER=x.y.z
REPO_OWNER="Azure"
REPO_NAME="AZNFS-mount"
AZNFS_RELEASE="aznfs-${RELEASE_NUMBER}-1"
AZNFS_RELEASE_SUSE="aznfs_sles-${RELEASE_NUMBER}-1"
SERVICE_NAME="cmdline"
AUTO_UPDATE_AZNFS=false
user_wants_update=false
apt_update_done=false
yum="yum"
apt=0
zypper=0
distro_id=
install_cmd=

# Define the path to the configuration file
CONFIG_FILE="/opt/microsoft/aznfs/config.txt"

RED="\e[2;31m"
GREEN="\e[2;32m"
YELLOW="\e[2;33m"
NORMAL="\e[0m"

#
# Core logging function.
#
_log()
{
    color=$1
    msg=$2

    echo -e "${color}${msg}${NORMAL}"
}

#
# Plain echo.
#
pecho()
{
    color=$NORMAL
    _log $color "${*}"
}

#
# Success echo.
#
secho()
{
    color=$GREEN
    _log $color "${*}"
}

#
# Warning echo.
#
wecho()
{
    color=$YELLOW
    _log $color "${*}"
}

#
# Error echo.
#
eecho()
{
    color=$RED
    _log $color "${*}"
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

# Function to canonicalize boolean values
canonicalize_boolean() 
{
    local value=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    
    if [ "$value" == "true" ] || [ "$value" == "false" ]; then
        echo "$value"
    else
        # If set anything other than boolean values, set false.
        echo "false"
    fi
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
            apt -y update
            if [ $? -ne 0 ]; then
                echo
                eecho "\"apt update\" failed"
                eecho "Please make sure \"apt update\" runs successfully and then try again!"
                echo
                exit 1
            fi
            # Need to run apt update only once.
            apt_update_done=true
        fi
        apt=1
        apt install -y $pkg
    elif [ "$distro" == "centos" -o "$distro" == "rocky" -o "$distro" == "rhel" ]; then
        # lsb_release package is called redhat-lsb-core in redhat/centos.
        if [ "$pkg" == "lsb-release" ]; then
            pkg="redhat-lsb-core"
        fi
        use_dnf_or_yum
        $yum install -y $pkg
    elif [ "$distro" == "sles" ]; then
        zypper=1
        zypper install -y $pkg
    fi
}

verify_super_user()
{
    if [ $(id -u) -ne 0 ]; then
        eecho "Run this script as root!"
        exit 1
    fi
}

check_config_file()
{
    if [ -f "$CONFIG_FILE" ]; then
        # Read the value of AUTO_UPDATE_AZNFS from the configuration file
        AUTO_UPDATE_AZNFS=$(grep "^AUTO_UPDATE_AZNFS=" "$CONFIG_FILE" | cut -d '=' -f2)
        
        # Canonicalize and validate the value
        AUTO_UPDATE_AZNFS=$(canonicalize_boolean "$AUTO_UPDATE_AZNFS")
    else
        # If the configuration file doesn't exist, set a default value
        AUTO_UPDATE_AZNFS="false"
    fi

    pecho "AUTO_UPDATE_AZNFS is set to: $AUTO_UPDATE_AZNFS"
    
    # Check if the user has set the environment variable to true
    if [ "$AUTO_UPDATE_AZNFS" = "true"  ]; then
        user_wants_update=true
    fi
}

#NOTE: 1) Set apt_update_done = true by default if not want to run in upgrade, else in case of watchdog - run, but don't fail badly and exit.
#      2) Mandatory for upgrading if super user? idts. It's script and It's run by root user. Does it inherit these props?

# Check if an argument is provided and equals "watchdog"
if [ $# -gt 0 ] && [ "$1" == "watchdog" ]; then
    SERVICE_NAME="$1"
    pecho "Service Name: $SERVICE_NAME"
else
    exit 1
fi

if [ "$RELEASE_NUMBER" == "x.y.z" ] && [ "$SERVICE_NAME" != "watchdog" ]; then
    eecho "This script is directly downloaded from the github source code."
    eecho "Please download the aznfs_install.sh from 'https://github.com/Azure/AZNFS-mount/releases/latest/download/aznfs_install.sh'"
    eecho "If the problem persists, contact Microsoft support."
    exit 1
fi

#
# Only super user can install aznfs.
#
verify_super_user

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
            eecho "[FATAL] Unknown linux distro, /etc/os-release not found!"
            pecho "Download .deb/.rpm package based on your distro from 'https://github.com/Azure/AZNFS-mount/releases/latest'"
            pecho "If the problem persists, contact Microsoft support."
        fi
        ;;
    *)
        eecho "[FATAL] Unsupported platform: ${__m}:${__s}."
        exit 1
        ;;
esac

ensure_pkg "wget"

if [ "$SERVICE_NAME" == "watchdog" ]; then
    check_config_file

    # Define the GitHub API URL to get the latest release
    API_URL="https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest"
    RELEASE_NUMBER=$(curl -s "$API_URL" | grep "tag_name" | cut -d '"' -f 4)
    pecho "Latest release version: $RELEASE_NUMBER"
fi

# Check if apt is available
if [ $apt -eq 1 ]; then
    install_cmd="apt"
    package_info=$(apt-cache show aznfs 2>/dev/null)
    is_uninstalled=$(echo "$package_info" | grep "^Status" | grep "\<deinstall\>")
    current_version=$(apt-cache show aznfs 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2)
    if [ -n "$current_version" -a -z "$is_uninstalled" ]; then
        # Check if the service name is "watchdog"
        if [ "$SERVICE_NAME" == "watchdog" ]; then
            # Compare the current version with the latest release
            result=$(compare_versions "$current_version" "$RELEASE_NUMBER")
            
            # Check if an update is available
            if [ "$result" -eq "1" ]; then
                # Check if the user wants to perform the update
                if [ "$user_wants_update" = "true" ]; then
                    AZNFS_RELEASE="aznfs-${RELEASE_NUMBER}-1"
                    # Create a flag file to indicate that an update is in progress
                    touch /tmp/update_in_progress_from_watchdog.flag
                else
                    vecho "Version $RELEASE_NUMBER of AZNFS is available. Set AUTO_UPDATE_AZNFS=true to update"
                fi
            else
                vecho "AZNFS version $current_version is up-to-date or newer."
            fi
            
        elif [ "$SERVICE_NAME" == "cmdline" ]; then
            # Check if the current version matches the desired release number
            if [ "$current_version" == "$RELEASE_NUMBER" ]; then
                secho "AZNFS version $current_version is already installed."
                exit 0
            fi
            
            # Ask the user if they want to install the desired release
            read -n 1 -p "AZNFS version $current_version is already installed. Do you want to install version $RELEASE_NUMBER? [Y/n] " result < /dev/tty
            echo
            if [ -n "$result" -a "$result" != "y" -a "$result" != "Y" ]; then
                eecho "Installation aborted!"
                exit 1
            fi
        fi
        
        # For watchdog, the flag file will always be present; otherwise, the service will be cmdline
        if [ -f /tmp/update_in_progress_from_watchdog.flag ] || [ "$SERVICE_NAME" == "cmdline" ]; then
            wget "https://github.com/Azure/AZNFS-mount/releases/download/${RELEASE_NUMBER}/${AZNFS_RELEASE}_amd64.deb" -P /tmp
            apt install -y "/tmp/${AZNFS_RELEASE}_amd64.deb"
            install_error=$?
            rm -f "/tmp/${AZNFS_RELEASE}_amd64.deb"

            if [ "$SERVICE_NAME" == "watchdog" ]; then
                systemctl daemon-reload
                systemctl restart aznfswatchdog
            fi
        fi
    fi

elif [ $zypper -eq 1 ]; then
    install_cmd="zypper"
    current_version=$(zypper info aznfs_sles 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2 | cut -d '-' -f1)
    if [ -n "$current_version" ]; then
        # Check if the service name is "watchdog"
        if [ "$SERVICE_NAME" == "watchdog" ]; then
            # Compare the current version with the latest release
            result=$(compare_versions "$current_version" "$RELEASE_NUMBER")
            
            # Check if an update is available
            if [ "$result" -eq "1" ]; then
                # Check if the user wants to perform the update
                if [ "$user_wants_update" = "true" ]; then
                    AZNFS_RELEASE_SUSE="aznfs_sles-${RELEASE_NUMBER}-1"
                    # Create a flag file to indicate that an update is in progress
                    touch /tmp/update_in_progress_from_watchdog.flag
                else
                    vecho "Version $RELEASE_NUMBER of AZNFS is available. Set AUTO_UPDATE_AZNFS=true to update"
                fi
            else
                vecho "AZNFS version $current_version is up-to-date or newer."
            fi
            
        elif [ "$SERVICE_NAME" == "cmdline" ]; then
            # Check if the current version matches the desired release number
            if [ "$current_version" == "$RELEASE_NUMBER" ]; then
                secho "AZNFS version $current_version is already installed."
                exit 0
            fi
        read -n 1 -p "AZNFS version $current_version is already installed. Do you want to install version $RELEASE_NUMBER? [Y/n] " result < /dev/tty
        echo
        if [ -n "$result" -a "$result" != "y" -a "$result" != "Y" ]; then
            eecho "Installation aborted!"
            exit 1
        fi

        # For watchdog, the flag file will always be present; otherwise, the service will be cmdline
        if [ -f /tmp/update_in_progress_from_watchdog.flag ] || [ "$SERVICE_NAME" == "cmdline" ]; then
            wget https://github.com/Azure/AZNFS-mount/releases/download/${RELEASE_NUMBER}/${AZNFS_RELEASE_SUSE}.x86_64.rpm -P /tmp
            zypper install --allow-unsigned-rpm -y /tmp/${AZNFS_RELEASE_SUSE}.x86_64.rpm
            install_error=$?
            rm -f /tmp/${AZNFS_RELEASE_SUSE}.x86_64.rpm

            if [ "$SERVICE_NAME" == "watchdog" ]; then
                systemctl daemon-reload
                systemctl restart aznfswatchdog
            fi
        fi
    fi


else
    install_cmd="yum"
    current_version=$(yum info aznfs 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2)
    if [ -n "$current_version" ]; then
        # Check if the service name is "watchdog"
        if [ "$SERVICE_NAME" == "watchdog" ]; then
            # Compare the current version with the latest release
            result=$(compare_versions "$current_version" "$RELEASE_NUMBER")
            
            # Check if an update is available
            if [ "$result" -eq "1" ]; then
                # Check if the user wants to perform the update
                if [ "$user_wants_update" = "true" ]; then
                    AZNFS_RELEASE="aznfs-${RELEASE_NUMBER}-1"
                    # Create a flag file to indicate that an update is in progress
                    touch /tmp/update_in_progress_from_watchdog.flag
                else
                    vecho "Version $RELEASE_NUMBER of AZNFS is available. Set AUTO_UPDATE_AZNFS=true to update"
                fi
            else
                vecho "AZNFS version $current_version is up-to-date or newer."
            fi
            
        elif [ "$SERVICE_NAME" == "cmdline" ]; then
            # Check if the current version matches the desired release number
            if [ "$current_version" == "$RELEASE_NUMBER" ]; then
                secho "AZNFS version $current_version is already installed."
                exit 0
            fi
            read -n 1 -p "AZNFS version $current_version is already installed. Do you want to install version $RELEASE_NUMBER? [Y/n] " result < /dev/tty
            echo
            if [ -n "$result" -a "$result" != "y" -a "$result" != "Y" ]; then
                eecho "Installation aborted!"
                exit 1
            fi
        fi
        # For watchdog, the flag file will always be present; otherwise, the service will be cmdline
        if [ -f /tmp/update_in_progress_from_watchdog.flag ] || [ "$SERVICE_NAME" == "cmdline" ]; then
            wget https://github.com/Azure/AZNFS-mount/releases/download/${RELEASE_NUMBER}/${AZNFS_RELEASE}.x86_64.rpm -P /tmp
            yum install -y /tmp/${AZNFS_RELEASE}.x86_64.rpm
            install_error=$?
            rm -f /tmp/${AZNFS_RELEASE}.x86_64.rpm

            if [ "$SERVICE_NAME" == "watchdog" ]; then
                systemctl daemon-reload
                systemctl restart aznfswatchdog
            fi
        fi
    fi
fi

if [ $install_error -ne 0 ]; then
    eecho "[FATAL] Error installing aznfs (Error: $install_error). See '$install_cmd' command logs for more information."
    exit 1
fi

secho "Version $RELEASE_NUMBER of aznfs mount helper is successfully installed."