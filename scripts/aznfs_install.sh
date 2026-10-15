#!/bin/bash
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

APPNAME="aznfs"
OPTDIR="/opt/microsoft/${APPNAME}"
OPTDIRDATA="${OPTDIR}/data"
CONFIG_FILE="${OPTDIRDATA}/config"
FLAG_FILE="/tmp/.update_in_progress_from_watchdog.flag"

#
# Same log destination and AZNFS_LOGDIR checks as init_logging() in common.sh,
# keep the two in sync.
#
LOGFILE=
AZNFS_LOGDIR=$(sed -n 's/^AZNFS_LOGDIR[[:space:]]*=[[:space:]]*//p' "$CONFIG_FILE" 2>/dev/null | tail -n1 | sed -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e 's#/*$##')
NO_ROTATE_RE='^/(etc|usr|boot|efi|dev|tmp|var/tmp)/'
if [ -n "$AZNFS_LOGDIR" ] &&
   [[ "$AZNFS_LOGDIR" =~ ^/[A-Za-z0-9._@+/-]+$ ]] &&
   ! [[ "$AZNFS_LOGDIR/" =~ $NO_ROTATE_RE || "$(readlink -m "$AZNFS_LOGDIR")/" =~ $NO_ROTATE_RE ]] &&
   (umask 022; mkdir -p "$AZNFS_LOGDIR") 2>/dev/null &&
   [ -z "$(find -L "$AZNFS_LOGDIR" -maxdepth 0 -perm /022 2>/dev/null)" ] &&
   { [ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" != "1" ] || [[ "$(stat -L -c %C "$AZNFS_LOGDIR" 2>/dev/null)" == *:var_log_t:* ]]; } &&
   [ ! -L "$AZNFS_LOGDIR/${APPNAME}.log" ] &&
   (umask 022; touch "$AZNFS_LOGDIR/${APPNAME}.log") 2>/dev/null; then
    LOGFILE="$AZNFS_LOGDIR/${APPNAME}.log"
elif ! command -v logger &> /dev/null || [ ! -S /dev/log ]; then
    # /var/log/aznfs is set up by common.sh when usable, else the last resort is OPTDIRDATA.
    if [ -f "/var/log/${APPNAME}/${APPNAME}.log" ] && [ ! -L "/var/log/${APPNAME}/${APPNAME}.log" ]; then
        LOGFILE="/var/log/${APPNAME}/${APPNAME}.log"
    else
        LOGFILE="${OPTDIRDATA}/${APPNAME}.log"
        (umask 022; touch "$LOGFILE")
    fi
fi

AUTO_UPDATE_AZNFS=false
apt_update_done=false
package_updated=0
yum="yum"
apt=0
zypper=0
distro_id=

RED="\e[2;31m"
GREEN="\e[2;32m"
YELLOW="\e[2;33m"
NORMAL="\e[0m"

HOSTNAME=$(hostname)

#
# Write a log line to LOGFILE, or to syslog with the given priority if LOGFILE
# is not set.
#
_log_write()
{
    local priority=$1
    local color=$2
    local msg=$3
    local level

    if [ -n "$LOGFILE" ]; then
        case "$priority" in
            err)     level=ERROR ;;
            warning) level=WARN ;;
            *)       level=INFO ;;
        esac
        (
            flock -e 999
            echo -e "$(date -u +"%a %b %d %G %T.%3N") $HOSTNAME $$: [${level}] ${color}${msg}${NORMAL}" >> "$LOGFILE"
        ) 999<"$LOGFILE"
    else
        echo -e "$$: ${msg}" | logger -t "$APPNAME" -p "user.${priority}"
    fi
}

#
# Core logging function.
#
_log()
{
    color=$1
    msg=$2
    priority=${3:-info}

    _log_write "$priority" "$color" "$msg"

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
    _log $color "${*}" warning
}

#
# Error echo.
#
eecho()
{
    color=$RED
    _log $color "${*}" err
}

#
# Verbose echo, no-op unless AZNFS_VERBOSE env variable is set.
#
vecho()
{
    color=$NORMAL

    # Unless AZNFS_VERBOSE flag is set, do not echo to console.
    if [ -z "$AZNFS_VERBOSE" -o "$AZNFS_VERBOSE" == "0" ]; then
        _log_write info "$color" "${*}"
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

#
# This returns distro id in a canonical form, that rest of the code understands.
# We only use lowercase single word names for distro names:
# debian, ubuntu, centos, redhat, sles.
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
    local distro="$distro_id"

    if [ "$distro" == "ubuntu" -o "$distro" == "debian" ]; then
        apt -y update
        if [ $? -ne 0 ]; then
            echo
            eecho "\"apt -y update\" failed"
            eecho "Please make sure \"apt -y update\" runs successfully and then try again!"
            echo
            exit 1
        fi
        apt=1
    elif [ "$distro" == "centos" -o "$distro" == "rocky" -o "$distro" == "rhel" -o "$distro" == "azurelinux" -o "$distro" == "ol" ]; then
        use_dnf_or_yum
        check_update_opt=" --refresh"
        $yum -y check-update $check_update_opt >/dev/null 2>&1

        # centos7 doesn't support --refresh option.
        if [ $? -eq 1 ]; then
            check_update_opt=""
            $yum -y check-update
        fi

        # 0 means no update available, 100 means updates found.
        if [ $? -eq 1 ]; then
            echo
            eecho "\"${yum} -y check-update$check_update_opt\" failed"
            eecho "Please make sure \"${yum} -y check-update$check_update_opt\" runs successfully and then try again!"
            echo
            exit 1
        fi
    elif [ "$distro" == "sles" ]; then
        zypper=1
        zypper refresh
        if [ $? -ne 0 ]; then
            echo
            eecho "\"zypper refresh\" failed"
            eecho "Please make sure \"zypper refresh\" runs successfully and then try again!"
            echo
            exit 1
        fi
    else
        eecho "[FATAL] Unsupported linux distro <$distro>"
        eecho "Cannot install aznfs package updates."
        pecho "Check 'https://github.com/Azure/AZNFS-mount/blob/main/README.md#supported-distros' to see the list of supported distros"
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
        eecho "AUTO_UPDATE_AZNFS is missing in '$CONFIG_FILE'."
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
    pecho "AUTO_UPDATE_AZNFS is set to: '$AUTO_UPDATE_AZNFS'"
}

create_flag_file()
{
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
}

######################
# Action starts here #
######################

parse_user_config
pecho "Running auto-update..."

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
    "x86_64:Linux" | "aarch64:Linux")
        if [ -f /etc/centos-release ]; then
            pecho "Retrieving distro info from /etc/centos-release..."
            distro_id="centos"
        elif [ -f /etc/os-release ]; then
            pecho "Retrieving distro info from /etc/os-release..."
            distro_id=$(grep "^ID=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
            distro_id=$(canonicalize_distro_id $distro_id)
        else
            eecho "[FATAL] Unknown linux distro, /etc/os-release not found!"
            eecho "Cannot install aznfs package updates."
            pecho "Please contact Microsoft support."
            exit 1
        fi
        ;;
    *)
        eecho "[FATAL] Unsupported platform: ${__m}:${__s}."
        eecho "[FATAL] AZNFS package update aborted."
        exit 1
        ;;
esac

ensure_pkg

if [ $apt -eq 1 ]; then
    current_version=$(dpkg-query -W -f='${Version}\n' aznfs 2>/dev/null)
    available_upgrade_version=$(apt list --upgradable 2>/dev/null | grep '\<aznfs\>' | awk '{print $2}')

    if [ -n "$available_upgrade_version" ]; then
        create_flag_file
        secho "Updating AZNFS from '$current_version' to '$available_upgrade_version'..."
        apt install --only-upgrade -y aznfs
        if [ $? -ne 0 ]; then
            eecho "[ERROR] Failed to update aznfs package to '$available_upgrade_version'."
            exit 1
        else
            package_updated=1
        fi
    fi

#
# Check package updates from microsoft respository
#
elif [ $zypper -eq 1 ]; then
    current_version=$(zypper list-updates | grep "\<aznfs\>" | awk '{print $7}')
    available_upgrade_version=$(zypper list-updates | grep "\<aznfs\>" | awk '{print $9}')

    if [ -n "$available_upgrade_version" ]; then
        create_flag_file
        secho "Updating AZNFS from '$current_version' to '$available_upgrade_version'..."
        zypper update -y aznfs
        if [ $? -ne 0 ]; then
            eecho "[ERROR] Failed to update aznfs package to '$available_upgrade_version'."
            exit 1
        else
            package_updated=1
        fi
    fi

else
    current_pkg_name=$(rpm -q aznfs)
    current_version=$(echo "$current_pkg_name" | sed -E 's/^aznfs-(.+)\.[^.]+$/\1/')
    available_upgrade_version=$($yum list available aznfs.${__m} |& grep "\<aznfs\>" | awk '{print $2}')

    if [ -n "$available_upgrade_version" ]; then
        create_flag_file
        secho "Updating AZNFS from '$current_version' to '$available_upgrade_version'..."
        $yum upgrade -y aznfs
        if [ $? -ne 0 ]; then
            eecho "[ERROR] Failed to update aznfs package to '$available_upgrade_version'."
            exit 1
        else
            package_updated=1
        fi
    fi
fi

if [ $package_updated -eq 1 ]; then
    secho "Successfully updated AZNFS version '$current_version' to '$available_upgrade_version'."
    pecho "Restarting aznfs watchdog service to apply changes..."
    systemctl daemon-reload
    systemctl restart aznfswatchdog
    systemctl restart aznfswatchdogv4
else
    pecho "aznfs is already up-to-date."
fi
