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
# Directory where aznfs.log is created.
# Users can change it either by setting AZNFS_LOGDIR in CONFIG_FILE or by
# exporting the AZNFS_LOGDIR env variable, the env variable takes precedence.
#
if [ -z "$AZNFS_LOGDIR" -a -f "$CONFIG_FILE" ]; then
    AZNFS_LOGDIR=$(sed -n 's|^[[:space:]]*AZNFS_LOGDIR[[:space:]]*=[[:space:]]*||p' "$CONFIG_FILE" 2>/dev/null |
                    tail -n1 | sed -e 's|[[:space:]]*$||' -e 's|^"\(.*\)"$|\1|' -e "s|^'\(.*\)'\$|\1|")
fi

AZNFS_LOGDIR="${AZNFS_LOGDIR:-$OPTDIRDATA}"

# Strip trailing slashes to keep the log path canonical.
while [ "$AZNFS_LOGDIR" != "/" ] && [ "${AZNFS_LOGDIR%/}" != "$AZNFS_LOGDIR" ]; do
    AZNFS_LOGDIR="${AZNFS_LOGDIR%/}"
done

#
# Same rule as safe_logdir() in common.sh, which decides where the logs really
# go: every component has to be one that only root can put files into, and none
# of them may be a symlink. stat is deliberately not given -L, so a link is
# judged as itself and rejected, rather than as the root owned directory a
# local user pointed it at.
#
aznfs_safe_logdir()
{
    local dir="$1"
    local path parent me owner gname mode gbit obit

    me=$(id -u)

    #
    # Trailing slashes are removed first: "test -L link/" is false, because the
    # slash forces the link to be resolved, so a caller passing "dir/" would
    # walk straight past the symlink check below.
    #
    while [ "$dir" != "/" ] && [ "${dir%/}" != "$dir" ]; do
        dir="${dir%/}"
    done

    path="$dir"

    #
    # Start at the deepest component that already exists, so this can be asked
    # about a directory we have not created yet. -L as well as -e, so a
    # dangling symlink counts as existing and is rejected rather than walked
    # straight past.
    #
    while [ "$path" != "/" ] && [ ! -e "$path" ] && [ ! -L "$path" ]; do
        path=$(dirname "$path")
    done

    while : ; do
        # Explicit, so relaxing the mode checks cannot stop rejecting links.
        [ -L "$path" ] && return 1

        read -r owner gname mode < <(stat -c '%u %G %a' "$path" 2>/dev/null)
        [ -n "$owner" ] || return 1
        [ "$owner" == "0" -o "$owner" == "$me" ] || return 1

        mode=$(printf '%04d' "$mode" 2>/dev/null) || return 1
        gbit=$(( 8#${mode: -2:1} ))
        obit=$(( 8#${mode: -1:1} ))

        #
        # World writable is never acceptable, sticky or not. Group writable is
        # allowed for a parent owned by one of the groups distros use for log
        # directories, /var/log is root:syslog 0775, but never for the log
        # directory itself. Named rather than compared against a gid
        # threshold: an ordinary group such as "users" sits at 100 on many
        # distros.
        #
        [ $(( obit & 2 )) -eq 0 ] || return 1

        if [ $(( gbit & 2 )) -ne 0 ]; then
            if [ "$path" == "$dir" ]; then
                return 1
            fi

            case "$gname" in
                root|syslog) ;;
                *) return 1 ;;
            esac
        fi

        [ "$path" == "/" ] && break

        # Any fixpoint ends the walk. dirname "//" is "//" on some systems, and
        # without this the loop would spin forever on a repeated leading slash.
        parent=$(dirname "$path")
        [ "$parent" == "$path" ] && break
        path="$parent"
    done

    return 0
}

#
# Only accept an absolute path built from characters that are safe to use
# unquoted, fall back to the default directory otherwise.
#
case "$AZNFS_LOGDIR" in
    /) AZNFS_LOGDIR="$OPTDIRDATA" ;;
    /*[!A-Za-z0-9._/@+-]*) AZNFS_LOGDIR="$OPTDIRDATA" ;;
    /*) ;;
    *) AZNFS_LOGDIR="$OPTDIRDATA" ;;
esac

# "/." and "/var/log/.." are other spellings of a directory the case above
# would otherwise treat as distinct.
case "${AZNFS_LOGDIR}/" in
    */../*|*/./*) AZNFS_LOGDIR="$OPTDIRDATA" ;;
esac

#
# Never fail the installer over a logging preference: anything unusable falls
# back to the default directory.
#
# The installer runs as root, so the directory has to be one that only root can
# put files into, otherwise another user could plant a symlink at aznfs.log and
# have us write through it. Same rule as safe_logdir() in common.sh. The probe
# goes through mktemp for the same reason, rather than touching a known name.
#
logdir_usable=true

#
# Checked before anything is created, and again afterwards. mkdir -p follows a
# symlinked component, so validating only after the fact would still let a link
# planted in a world writable directory have root create directories inside its
# target.
#
if ! aznfs_safe_logdir "$AZNFS_LOGDIR"; then
    logdir_usable=false
fi

# Only what we create: mkdir honours the caller's umask, so under 0002 this
# would be 0775 and the revalidation below would refuse what we just made. An
# existing directory keeps the mode its owner chose.
if [ "$logdir_usable" == "true" ] && [ ! -d "$AZNFS_LOGDIR" ] &&
   ! { mkdir -p "$(dirname "$AZNFS_LOGDIR")" 2>/dev/null
        mkdir "$AZNFS_LOGDIR" 2>/dev/null && chmod 0755 "$AZNFS_LOGDIR" 2>/dev/null; }; then
    logdir_usable=false
fi

if [ "$logdir_usable" == "true" ] && ! aznfs_safe_logdir "$AZNFS_LOGDIR"; then
    logdir_usable=false
fi

if [ "$logdir_usable" == "true" ]; then
    probe=$(mktemp "${AZNFS_LOGDIR}/.aznfs-logdir-probe.XXXXXXXX" 2>/dev/null) || logdir_usable=false
    [ -n "$probe" ] && rm -f "$probe"
fi

#
# An existing log we cannot append to makes the directory unusable just the
# same, the same check common.sh makes at mount time.
#
if [ "$logdir_usable" == "true" ] &&
   { [ -L "${AZNFS_LOGDIR}/${APPNAME}.log" ] ||
         { [ -e "${AZNFS_LOGDIR}/${APPNAME}.log" ] && { [ ! -f "${AZNFS_LOGDIR}/${APPNAME}.log" ] || [ ! -w "${AZNFS_LOGDIR}/${APPNAME}.log" ]; }; }; }; then
    logdir_usable=false
fi

if [ "$logdir_usable" != "true" ]; then
    AZNFS_LOGDIR="$OPTDIRDATA"
    mkdir -p "$AZNFS_LOGDIR" && chmod 0755 "$AZNFS_LOGDIR"
fi

LOGFILE="${AZNFS_LOGDIR}/${APPNAME}.log"

# The fallback path is checked too: this runs as root, and touch follows a
# link. The diagnostic goes to stderr because wecho is not defined this early.
if [ -L "$LOGFILE" ]; then
    echo "'${LOGFILE}' is a symlink, refusing to log through it!" >&2
    LOGFILE=/dev/null
fi

touch "$LOGFILE" 2>/dev/null

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
# Core logging function.
#
_log()
{
    color=$1
    msg=$2

    log_message="$(date -u +"%a %b %d %G %T.%3N") $HOSTNAME $$: ${color}${msg}${NORMAL}"
    (
        flock -e 999
        echo -e "$log_message" >> "$LOGFILE"
    ) 999<"$LOGFILE"

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
