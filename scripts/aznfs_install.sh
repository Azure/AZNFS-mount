#!/bin/bash
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

APPNAME="aznfs"
OPTDIR="/opt/microsoft/${APPNAME}"
OPTDIRDATA="${OPTDIR}/data"
LOGFILE="${OPTDIRDATA}/${APPNAME}.log"
CONFIG_FILE="${OPTDIRDATA}/config"

RELEASE_NUMBER=x.y.z
REPO_OWNER="Azure"
REPO_NAME="AZNFS-mount"
AZNFS_RELEASE="aznfs-${RELEASE_NUMBER}-1"
AZNFS_RELEASE_SUSE="aznfs_sles-${RELEASE_NUMBER}-1"
RUN_MODE="manual-update"
AUTO_UPDATE_AZNFS=false
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

HOSTNAME=$(hostname)

#
# Core logging function.
#
_log()
{
    color=$1
    msg=$2

    if [ "$RUN_MODE" == "auto-update" ]; then
        log_message="$(date -u +"%a %b %d %G %T.%3N") $HOSTNAME $$: ${color}${msg}${NORMAL}"
        (
            flock -e 999
            echo -e "$log_message" >> "$LOGFILE"
        ) 999<"$LOGFILE"
    fi

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

#
# Verbose echo, no-op unless AZNFS_VERBOSE env variable is set.
#
vecho()
{
    color=$NORMAL

    # Unless AZNFS_VERBOSE flag is set, do not echo to console.
    if [ -z "$AZNFS_VERBOSE" -o "$AZNFS_VERBOSE" == "0" ]; then
        (
            flock -e 999
            echo -e "$(date -u +"%a %b %d %G %T.%3N") $HOSTNAME $$: ${color}${*}${NORMAL}" >> $LOGFILE
        ) 999<$LOGFILE

        return
    fi

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

is_new_version_available()
{
    local current_version_integer=$(echo $1 | tr -d ".")
    local latest_version_integer=$(echo $2 | tr -d ".")

    [ $latest_version_integer -gt $current_version_integer ]
}

# Function to perform AZNFS updates
perform_aznfs_updates() 
{
    # For watchdog, the flag file will always be present; otherwise, the service will be "manual-update"
    if [ -f /tmp/.update_in_progress_from_watchdog.flag ] || [ "$RUN_MODE" == "manual-update" ]; then
        if [ "$install_cmd" == "apt" ]; then
            AZNFS_RELEASE="aznfs-${RELEASE_NUMBER}-1"
            package_name=${AZNFS_RELEASE}_amd64.deb
        elif [ "$install_cmd" == "zypper" ]; then
            AZNFS_RELEASE_SUSE="aznfs_sles-${RELEASE_NUMBER}-1"
            package_name=${AZNFS_RELEASE_SUSE}.x86_64.rpm
        else
            AZNFS_RELEASE="aznfs-${RELEASE_NUMBER}-1"
            package_name=${AZNFS_RELEASE}.x86_64.rpm
        fi
                
        # Use wget to download the package, and check for success
        wget "https://github.com/Azure/AZNFS-mount/releases/download/${RELEASE_NUMBER}/${package_name}" -P /tmp
        wget_status=$?

        if [ $wget_status -ne 0 ]; then
            eecho "Failed to download the package using wget. Exiting."
            exit 1
        fi

        # Check if the downloaded file exists before proceeding with installation
        if [ -f "/tmp/${package_name}" ]; then
            if [ "$install_cmd" == "zypper" ]; then
                $install_cmd install --allow-unsigned-rpm -y "/tmp/${package_name}"
            else
                $install_cmd install -y "/tmp/${package_name}"
            fi
            install_error=$?
            rm -f "/tmp/${package_name}"

            if [ "$RUN_MODE" == "auto-update" ] && [ "$install_error" -eq 0 ]; then
                pecho "AZNFS updates installed. Restarting aznfswatchdog to apply changes!"
                systemctl daemon-reload
                systemctl restart aznfswatchdog
                exit 0 # Nothing in the script will run after this point.
            fi
        else
            eecho "Downloaded package file not found. Installation aborted."
            exit 1
        fi
    fi
}

check_aznfs_updates()
{
    local current_version="$1"

    # Check if the service name is "auto-update"
    if [ "$RUN_MODE" == "auto-update" ]; then
        # Compare the current version with the latest release
        if is_new_version_available "$current_version" "$RELEASE_NUMBER"; then
            # Check if an update is available
            if [ "$AUTO_UPDATE_AZNFS" == "true" ]; then   
                # Get the PID of aznfswatchdog
                aznfswatchdog_pid=$(pgrep aznfswatchdog)
                if [ -n "$aznfswatchdog_pid" ]; then
                    # Create a flag file with the PID to indicate that an update is in progress
                    echo "$aznfswatchdog_pid" > /tmp/.update_in_progress_from_watchdog.flag
                else
                    eecho "AZNFS auto-update can only be invoked by aznfswatchdog!"
                    exit 1
                fi
            else
                wecho "Version $RELEASE_NUMBER of AZNFS is available. Update to AZNFS $RELEASE_NUMBER for the latest features and improvements."
                wecho "Set AUTO_UPDATE_AZNFS=true in $CONFIG_FILE to auto-update" 
            fi
        else
            pecho "AZNFS version $current_version is up-to-date or newer"
        fi
        
    elif [ "$RUN_MODE" == "manual-update" ]; then
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

parse_user_config()
{
    if [ -f "$CONFIG_FILE" ]; then
        # Read the value of AUTO_UPDATE_AZNFS from the configuration file
        AUTO_UPDATE_AZNFS=$(grep "^AUTO_UPDATE_AZNFS=" "$CONFIG_FILE" | cut -d '=' -f2)
        
        # Convert to lowercase for easy comparison later.
        AUTO_UPDATE_AZNFS=${AUTO_UPDATE_AZNFS,,}
    else
        # If the configuration file doesn't exist, set a default value
        AUTO_UPDATE_AZNFS="false"
    fi

    pecho "AUTO_UPDATE_AZNFS is set to: $AUTO_UPDATE_AZNFS"
}

######################
# Action starts here #
######################

# Check if an argument is provided and equals "auto-update"
if [ $# -gt 0 ] && [ "$1" == "auto-update" ]; then
    RUN_MODE="$1"
    pecho "Service Name: $RUN_MODE"
fi

if [ "$RELEASE_NUMBER" == "x.y.z" ] && [ "$RUN_MODE" != "auto-update" ]; then
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

if [ "$RUN_MODE" == "auto-update" ]; then
    parse_user_config

    # Define the GitHub API URL to get the latest release
    API_URL="https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest"
    RELEASE_INFO=$(curl -s "$API_URL")
    if [ $? -ne 0 ]; then
        eecho "Failed to retrieve latest release information. Exiting."
        exit 1
    fi

    # Parse the release number from the JSON response
    RELEASE_NUMBER=$(echo "$RELEASE_INFO" | grep "tag_name" | cut -d '"' -f 4)
    if [ -z "$RELEASE_NUMBER" ]; then
        eecho "Failed to retrieve latest release number from Latest release information. Exiting."
        exit 1
    fi
fi

# Check if apt is available
if [ $apt -eq 1 ]; then
    install_cmd="apt"
    package_info=$(apt-cache show aznfs 2>/dev/null)
    is_uninstalled=$(echo "$package_info" | grep "^Status" | grep "\<deinstall\>")
    current_version=$(apt-cache show aznfs 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2)
    # Check if RUN_MODE is auto-update and current_version is empty
    if [ "$RUN_MODE" == "auto-update" ] && [ -z "$current_version" ]; then
        pecho "Unable to retrieve the current version of AZNFS. Exiting."
        exit 1
    fi
    if [ -n "$current_version" -a -z "$is_uninstalled" ]; then
        check_aznfs_updates "$current_version"
    fi
    perform_aznfs_updates

elif [ $zypper -eq 1 ]; then
    install_cmd="zypper"
    current_version=$(zypper info aznfs_sles 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2 | cut -d '-' -f1)
    # Check if RUN_MODE is auto-update and current_version is empty
    if [ "$RUN_MODE" == "auto-update" ] && [ -z "$current_version" ]; then
        pecho "Unable to retrieve the current version of AZNFS. Exiting."
        exit 1
    fi
    if [ -n "$current_version" ]; then
        check_aznfs_updates "$current_version"
    fi
    perform_aznfs_updates

else
    install_cmd="yum"
    current_version=$(yum info aznfs 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2)
    # Check if RUN_MODE is auto-update and current_version is empty
    if [ "$RUN_MODE" == "auto-update" ] && [ -z "$current_version" ]; then
        pecho "Unable to retrieve the current version of AZNFS. Exiting."
        exit 1
    fi
    if [ -n "$current_version" ]; then
        check_aznfs_updates "$current_version"
    fi
    perform_aznfs_updates
fi

if [ -n "$install_error" ] && [ "$install_error" -ne 0 ]; then  
    eecho "[FATAL] Error installing aznfs (Error: $install_error). See '$install_cmd' command logs for more information."
    exit 1
fi

if [ "$RUN_MODE" == "manual-update" ]; then
    secho "Version $RELEASE_NUMBER of aznfs mount helper is successfully installed."
fi