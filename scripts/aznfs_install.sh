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
FLAG_FILE="/tmp/.update_in_progress_from_watchdog.flag"

RELEASE_NUMBER=x.y.z
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

# Function to perform AZNFS update.
perform_aznfs_update() 
{
    if [ "$install_cmd" == "apt" ]; then
        AZNFS_RELEASE="aznfs-${RELEASE_NUMBER}-1"
        package_name=${AZNFS_RELEASE}_amd64.deb
    elif [ "$install_cmd" == "zypper" ]; then
        AZNFS_RELEASE_SUSE="aznfs_sles-${RELEASE_NUMBER}-1"
        package_name=${AZNFS_RELEASE_SUSE}.x86_64.rpm
    else
        if [ "$distro_id" == "mariner" ]; then
            AZNFS_RELEASE="aznfs_mariner-${RELEASE_NUMBER}-1"
            package_name=${AZNFS_RELEASE}.x86_64.rpm
        else
            AZNFS_RELEASE="aznfs-${RELEASE_NUMBER}-1"
            package_name=${AZNFS_RELEASE}.x86_64.rpm
        fi
    fi

    # Use wget to download the package, and check for success.
    wget_output=$(wget --timeout=120 "https://github.com/Azure/AZNFS-mount/releases/download/${RELEASE_NUMBER}/${package_name}" -P /tmp 2>&1)
    if [ $? -ne 0 ]; then
        eecho "Failed to download the package using wget, exiting!"
        eecho "$wget_output"
        exit 1
    fi

    # It's not possible that wget is successful, and package is not present before installation.
    if [ ! -f "/tmp/${package_name}" ]; then
        eecho "[BUG] Downloaded package file '/tmp/${package_name}' not found, installation aborted!"
        exit 1
    fi

    #
    # Here we capture the output seperately in case of auto-update, since we want it to be silent update
    # and show in logs only in case of error while installation. 
    # For users manual-update, we needn't capture the output seperately and let it out on terminal to avoid
    # issues with dialog box showing up.
    #
    if [ "$RUN_MODE" == "auto-update" ]; then
        if [ "$install_cmd" == "zypper" ]; then
            install_output=$(AZNFS_NONINTERACTIVE_INSTALL=1 $install_cmd install --allow-unsigned-rpm -y "/tmp/${package_name}" 2>&1)
        else
            install_output=$(DEBIAN_FRONTEND=noninteractive AZNFS_NONINTERACTIVE_INSTALL=1 $install_cmd install -y "/tmp/${package_name}" 2>&1)
        fi
        install_error=$?
        rm -f "/tmp/${package_name}"

        if [ $install_error -ne 0 ]; then
            eecho "[FATAL] Error installing AZNFS version $RELEASE_NUMBER (Error: $install_error)"
            eecho "$install_output"
            exit 1
        fi
        secho "Successfully updated AZNFS version $current_version to $RELEASE_NUMBER."
        pecho "Restarting aznfs watchdog service to apply changes..."
        systemctl daemon-reload
        systemctl restart aznfswatchdog
        systemctl restart aznfswatchdogv4

    elif [ "$RUN_MODE" == "manual-update" ]; then
        # Choosing the appropriate installation options based on distro.
        install_options="-y"
        [ "$install_cmd" == "zypper" ] && install_options="$install_options --allow-unsigned-rpm"

        if [ "$AZNFS_NONINTERACTIVE_INSTALL" == "1" ] || [ "$install_cmd" == "apt" -a "$DEBIAN_FRONTEND" == "noninteractive" ]; then
            # Install the package without input from /dev/tty in case of noninteractive install.
            $install_cmd install $install_options "/tmp/${package_name}"
        else
            $install_cmd install $install_options "/tmp/${package_name}" < /dev/tty
        fi
        install_error=$?
        rm -f "/tmp/${package_name}"

        if [ $install_error -ne 0 ]; then
            eecho "[FATAL] Error installing AZNFS version $RELEASE_NUMBER (Error: $install_error). See '$install_cmd' command logs above for more information"
            exit 1
        fi
        secho "Version $RELEASE_NUMBER of aznfs mount helper is successfully installed"
    fi

    exit 0 # Nothing in the script will run after this point.
}

check_aznfs_update()
{
    local current_version="$1"

    # Check if the service name is "auto-update".
    if [ "$RUN_MODE" == "auto-update" ]; then
        # Compare the current version with the latest release.
        if is_new_version_available "$current_version" "$RELEASE_NUMBER"; then
            # Get the PID of aznfswatchdog.
            pid_aznfswatchdog=$(pgrep -x aznfswatchdog)
            if [ -n "$pid_aznfswatchdog" ]; then
                # Create a flag file with the PID to indicate that an update is in progress.
                echo "$pid_aznfswatchdog" > "$FLAG_FILE"
                if [ $? -ne 0 ]; then
                    eecho "Failed to create the flag file to indicate update in progress, exiting!"
                    exit 1
                fi
            else
                eecho "AZNFS auto-update can only be invoked by aznfswatchdog!"
                exit 1
            fi
        else
            pecho "Not auto-updating to $RELEASE_NUMBER. AZNFS version $current_version is up-to-date or newer!"
            exit 0
        fi
        
    elif [ "$RUN_MODE" == "manual-update" ]; then
        # Check if the current version matches the desired release number.
        if [ "$current_version" == "$RELEASE_NUMBER" ]; then
            secho "AZNFS version $current_version is already installed"
            exit 0
        fi

        # Check for noninteractive installation.
        if [ "$AZNFS_NONINTERACTIVE_INSTALL" == "1" ] || [ "$install_cmd" == "apt" -a "$DEBIAN_FRONTEND" == "noninteractive" ]; then
            return
        fi
        
        # Ask the user if they want to install the desired release.
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

    if [ "$distro" == "ubuntu" -o "$distro" == "debian" ]; then
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
        install_error=$?
    elif [ "$distro" == "centos" -o "$distro" == "rocky" -o "$distro" == "rhel" -o "$distro" == "mariner" ]; then
        # lsb_release package is called redhat-lsb-core in redhat/centos.
        if [ "$pkg" == "lsb-release" ]; then
            pkg="redhat-lsb-core"
        fi
        use_dnf_or_yum
        $yum install -y $pkg
        install_error=$?
    elif [ "$distro" == "sles" ]; then
        zypper=1
        zypper install -y $pkg
        install_error=$?
    elif [ -n "$AZNFS_FORCE_PACKAGE_MANAGER" ]; then
        case "$AZNFS_FORCE_PACKAGE_MANAGER" in
            apt)
                apt=1
                wecho "[WARNING] Forcing package manager '$AZNFS_FORCE_PACKAGE_MANAGER' on unsupported distro <$distro>"
                wecho "[WARNING] Proceeding with the AZNFS installation, please contact Microsoft support in case of any issues."
                apt install -y $pkg
                install_error=$?
                ;;
            yum|dnf)
                yum=$AZNFS_FORCE_PACKAGE_MANAGER
                wecho "[WARNING] Forcing package manager '$AZNFS_FORCE_PACKAGE_MANAGER' on unsupported distro <$distro>"
                wecho "[WARNING] Proceeding with the AZNFS installation, please contact Microsoft support in case of any issues."
                $yum install -y $pkg
                install_error=$?
                ;;
            zypper)
                zypper=1
                wecho "[WARNING] Forcing package manager '$AZNFS_FORCE_PACKAGE_MANAGER' on unsupported distro <$distro>"
                wecho "[WARNING] Proceeding with the AZNFS installation, please contact Microsoft support in case of any issues."
                zypper install -y $pkg
                install_error=$?
                ;;
            *)
                eecho "[FATAL] Unsupported value for AZNFS_FORCE_PACKAGE_MANAGER <$AZNFS_FORCE_PACKAGE_MANAGER>. Use 'apt', 'yum', 'dnf', or 'zypper'"
                exit 1
                ;;
        esac
    else
        eecho "[FATAL] Unsupported linux distro <$distro>"
        pecho "Check 'https://github.com/Azure/AZNFS-mount/blob/main/README.md#supported-distros' to see the list of supported distros"
        pecho "Download .deb/.rpm package based on your distro from 'https://github.com/Azure/AZNFS-mount/releases/latest' or try running install after setting env variable 'AZNFS_FORCE_PACKAGE_MANAGER' to one of 'apt', 'yum', 'dnf', or 'zypper'"
        exit 1
    fi

    if [ $install_error -ne 0 ]; then
        eecho "[FATAL] Error installing $pkg (Error: $install_error)"
        exit 1
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
    if [ ! -f "$CONFIG_FILE" ]; then
        eecho "$CONFIG_FILE not found. Please make sure it is present."
        exit 1
    fi

    # Read the value of AUTO_UPDATE_AZNFS from the configuration file.
    AUTO_UPDATE_AZNFS=$(egrep -o '^AUTO_UPDATE_AZNFS[[:space:]]*=[[:space:]]*[^[:space:]]*' "$CONFIG_FILE" | tr -d '[:blank:]' | cut -d '=' -f2)
    if [ -z "$AUTO_UPDATE_AZNFS" ]; then
        eecho "AUTO_UPDATE_AZNFS is missing in $CONFIG_FILE."
        exit 1
    fi

    # Convert to lowercase for easy comparison later.
    AUTO_UPDATE_AZNFS=${AUTO_UPDATE_AZNFS,,}
    if [ "$AUTO_UPDATE_AZNFS" != "true" ] && [ "$AUTO_UPDATE_AZNFS" != "false" ]; then
        eecho "Invalid value for AUTO_UPDATE_AZNFS: '$AUTO_UPDATE_AZNFS'."
        exit 1
    fi

    # Bailout and do nothing if user didn't set the auto-update.
    if [ "$AUTO_UPDATE_AZNFS" == "false" ]; then
        exit 0
    fi
    pecho "AUTO_UPDATE_AZNFS is set to: $AUTO_UPDATE_AZNFS"
}

######################
# Action starts here #
######################

# Check if an argument is provided and equals "auto-update".
if [ $# -gt 0 ] && [ "$1" == "auto-update" ]; then
    RUN_MODE="auto-update"
    parse_user_config
    pecho "Running auto-update..."
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
            pecho "Download .deb/.rpm package based on your distro from 'https://github.com/Azure/AZNFS-mount/releases/latest' or try running install after setting env variable 'AZNFS_FORCE_PACKAGE_MANAGER' to one of 'apt', 'yum', 'dnf', or 'zypper'"
            pecho "If the problem persists, contact Microsoft support."
            exit 1
        fi
        ;;
    *)
        eecho "[FATAL] Unsupported platform: ${__m}:${__s}."
        exit 1
        ;;
esac

ensure_pkg "wget"

if [ "$RUN_MODE" == "auto-update" ]; then
    # Define the GitHub API URL to get the latest release.
    API_URL="https://api.github.com/repos/Azure/AZNFS-mount/releases/latest"
    RELEASE_INFO=$(curl -sS --max-time 60 "$API_URL" 2>&1)
    if [ $? -ne 0 ]; then
        eecho "Failed to retrieve latest release information, exiting!"
        eecho "**************************************************************"
        eecho "JSON Response:"
        eecho "$RELEASE_INFO"
        eecho "**************************************************************"
        exit 1
    fi

    # Parse the release number from the JSON response.
    RELEASE_NUMBER=$(echo "$RELEASE_INFO" | grep '"tag_name":' | cut -d '"' -f 4)
    if [ -z "$RELEASE_NUMBER" ]; then
        eecho "Failed to retrieve latest release number, exiting!"
        eecho "**************************************************************"
        eecho "JSON Response:"
        eecho "$RELEASE_INFO"
        eecho "**************************************************************"
        exit 1
    fi
fi

if [ $apt -eq 1 ]; then
    install_cmd="apt"
    package_info=$(apt-cache show aznfs 2>/dev/null)
    is_uninstalled=$(echo "$package_info" | grep "^Status" | grep "\<deinstall\>")
    current_version=$(apt-cache show aznfs 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2)
    # Without current version, auto-update cannot proceed.
    if [ "$RUN_MODE" == "auto-update" ] && [ -z "$current_version" ]; then
        eecho "Unable to retrieve the current version of AZNFS, exiting!"
        exit 1
    fi

    if [ -n "$current_version" -a -z "$is_uninstalled" ]; then
        is_installed=true
    else
        is_installed=false
    fi

    if $is_installed; then
        # Check if we need to update otherwise we exit for manual-update as well as auto-update.
        check_aznfs_update "$current_version"
    fi
    perform_aznfs_update

elif [ $zypper -eq 1 ]; then
    install_cmd="zypper"
    current_version=$(zypper info aznfs_sles 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2 | cut -d '-' -f1)
    # Without current version, auto-update cannot proceed.
    if [ "$RUN_MODE" == "auto-update" ] && [ -z "$current_version" ]; then
        eecho "Unable to retrieve the current version of AZNFS, exiting!"
        exit 1
    fi
    if [ -n "$current_version" ]; then
        # Check if we need to update otherwise we exit for manual-update as well as auto-update.
        check_aznfs_update "$current_version"
    fi
    perform_aznfs_update

else
    install_cmd=$yum
    current_version=$($install_cmd info aznfs 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2)
    # Without current version, auto-update cannot proceed.
    if [ "$RUN_MODE" == "auto-update" ] && [ -z "$current_version" ]; then
        eecho "Unable to retrieve the current version of AZNFS, exiting!"
        exit 1
    fi
    if [ -n "$current_version" ]; then
        # Check if we need to update otherwise we exit for manual-update as well as auto-update.
        check_aznfs_update "$current_version"
    fi
    perform_aznfs_update
fi
