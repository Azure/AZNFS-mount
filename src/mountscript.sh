#!/bin/bash

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

#
# Load common aznfs helpers.
#
. /opt/microsoft/aznfs/common.sh

#
# True if user has asked for verbose logs using '-v' or '--verbose' with mount command.
#
VERBOSE_MOUNT=false

#
# True if user has asked to use port 2047 using 'port=2047' mount option.
# This signifies server side nconnect which has some special needs.
#
USING_PORT_2047=false

#
# Check if the given string is a valid blob/file FQDN (<accountname>.<blob/file>.core.windows.net).
#
is_valid_fqdn()
{
    # If AzureEndpointOverride environment variable is set, use it to verify FQDN
    if [[ -n "$AzureEndpointOverride" ]]; then
        ModifiedEndPoint = $(echo $AzureEndpointOverride |  sed 's/\./\\./g')
        [[ $1 =~ ^([a-z0-9]{3,24}|fs-[a-z0-9]{1,21})(\.z[0-9]+)?(\.privatelink)?\.(file|blob)(\.preprod)?\.core+$ModifiedEndPoint$ ]]
    else
        [[ $1 =~ ^([a-z0-9]{3,24}|fs-[a-z0-9]{1,21})(\.z[0-9]+)?(\.privatelink)?\.(file|blob)(\.preprod)?\.core\.(windows\.net|usgovcloudapi\.net|chinacloudapi\.cn)$ ]]
    fi
}

#
# Check if any nconnect mount exists for port 2048.
#
has_2048_nconnect_mounts()
{
    local findmnt=$(findmnt --raw --noheading -o MAJ:MIN,FSTYPE,SOURCE,TARGET,OPTIONS -t nfs | egrep "\<port=2048\>" | egrep "\<nconnect=")

    [ -n "$findmnt" ]
}

#
# Check if any nconnect mount exists for port 2047.
#
has_2047_nconnect_mounts()
{
    local findmnt=$(findmnt --raw --noheading -o MAJ:MIN,FSTYPE,SOURCE,TARGET,OPTIONS -t nfs | egrep "\<port=2047\>" | egrep "\<nconnect=")

    [ -n "$findmnt" ]
}

#
# If server side nconnect is not used, check if azure nconnect is supported. If not bail out failing the mount,
# else if NFS client supports Azure nconnect but it's not enabled, enable it.
#
# If server side nconnect is used, disable azure nconnect.
#
check_nconnect()
{
    matchstr="\<nconnect\>=([0-9]+)"
    if [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
        value="${BASH_REMATCH[1]}"
        if [ $value -gt 1 ]; then
            # Load sunrpc module if not already loaded.
            if [ ! -d /sys/module/sunrpc/ ]; then
                modprobe sunrpc
            fi

            #
            # W/o server side nconnect, we need the azure nconnect support,
            # turn it on. OTOH, if Server side nconnect is being used turn off
            # azure nconnect support if enabled.
            #
            if [ $USING_PORT_2047 == false ]; then
                if [ ! -e /sys/module/sunrpc/parameters/enable_azure_nconnect ]; then
                    eecho "nconnect option needs NFS client with Azure nconnect support!"
                    return 1
                fi

                if has_2047_nconnect_mounts; then
                    eecho "One or more mounts to port 2047 are using nconnect."
                    eecho "Cannot mix port 2048 and 2047 nconnect mounts, unmount those and try mounting again!"
                    return 1
                fi

                # Supported, enable if not enabled.
                enabled=$(cat /sys/module/sunrpc/parameters/enable_azure_nconnect)
                if ! [[ "$enabled" =~ [yY] ]]; then
                    vvecho "Azure nconnect not enabled, enabling!"
                    echo Y > /sys/module/sunrpc/parameters/enable_azure_nconnect
                fi
            else
                if has_2048_nconnect_mounts; then
                    eecho "One or more mounts to port 2048 are using nconnect."
                    eecho "Cannot mix port 2048 and 2047 nconnect mounts, unmount those and try mounting again!"
                    return 1
                fi

                if [ -e /sys/module/sunrpc/parameters/enable_azure_nconnect ]; then
                    enabled=$(cat /sys/module/sunrpc/parameters/enable_azure_nconnect)
                    if [[ "$enabled" =~ [yY] ]]; then
                        vvecho "Azure nconnect enabled, disabling!"
                        echo N > /sys/module/sunrpc/parameters/enable_azure_nconnect
                    fi
                fi

                #
                # Higher nconnect values don't work well for server side
                # nconnect, limit to optimal value 4.
                #
                if [ $value -gt 4 ]; then
                    pecho "Suboptimal nconnect value $value, forcing nconnect=4!"
                    MOUNT_OPTIONS=$(echo "$MOUNT_OPTIONS" | sed "s/\<nconnect\>=$value/nconnect=4/g")
                fi
            fi
        fi
    fi
}

#
# Help fix/limit the dirty bytes config of user's machine.
# This is needed on machines with huge amount of RAM which causes the default
# dirty settings to accumulate lot of dirty pages. When lot of dirty pages are
# then flushed to the NFS server, it may cause slowness due to some writes
# timing out. To avoid this we set the dirty config to optimal values.
#
fix_dirty_bytes_config()
{
    # Constants for desired settings.
    local desired_dirty_bytes=$((8 * 1024 * 1024 * 1024))  # 8 GB in bytes
    local desired_dirty_background_bytes=$((4 * 1024 * 1024 * 1024))  # 4 GB in bytes

    # Get current settings.
    local current_dirty_bytes=$(cat /proc/sys/vm/dirty_bytes 2>/dev/null)
    local current_dirty_background_bytes=$(cat /proc/sys/vm/dirty_background_bytes 2>/dev/null)

    # Should not happen but added for robustness.
    if [ -z "$current_dirty_bytes" -o -z "$current_dirty_background_bytes" ]; then
        wecho "current_dirty_bytes=$current_dirty_bytes"
        wecho "current_dirty_background_bytes=$current_dirty_background_bytes"
        return
    fi

    # If current dirty bytes are 0, calculate them from the ratio configs.
    if [ $current_dirty_background_bytes -eq 0 ]; then
        # Get total memory in bytes.
        local total_mem_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        local total_mem_bytes=$((total_mem_KB * 1024))

        local current_dirty_ratio=$(cat /proc/sys/vm/dirty_ratio 2>/dev/null)
        local current_dirty_background_ratio=$(cat /proc/sys/vm/dirty_background_ratio 2>/dev/null)

        # Should not happen but added for robustness.
        if [ -z "$current_dirty_ratio" -o \
             -z "$current_dirty_background_ratio" -o \
             "$current_dirty_ratio" == "0" -o \
             "$current_dirty_background_ratio" == "0" ]; then
            wecho "current_dirty_ratio=$current_dirty_ratio"
            wecho "current_dirty_background_ratio=$current_dirty_background_ratio"
            return
        fi

        current_dirty_bytes=$((total_mem_bytes * current_dirty_ratio / 100))
        current_dirty_background_bytes=$((total_mem_bytes * current_dirty_background_ratio / 100))
    fi

    # If current dirty byte settings are higher than desired, set to desired.
    if [ $desired_dirty_background_bytes -lt $current_dirty_background_bytes ]; then
        vvecho "Setting /proc/sys/vm/dirty_bytes to $desired_dirty_bytes bytes"
        echo $desired_dirty_bytes > /proc/sys/vm/dirty_bytes

        vvecho "Setting /proc/sys/vm/dirty_background_bytes to $desired_dirty_background_bytes bytes"
        echo $desired_dirty_background_bytes > /proc/sys/vm/dirty_background_bytes
    fi
}

#
# Help fix the mount options passed in by user.
#
fix_mount_options()
{
    matchstr="\<sec\>=([^,]+)"
    if ! [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
        MOUNT_OPTIONS="$MOUNT_OPTIONS,sec=sys"
    else
        value="${BASH_REMATCH[1]}"
        if [ "$value" != "sys" ]; then
            pecho "Unsupported mount option sec=$value, fixing to sec=sys!"
            MOUNT_OPTIONS=$(echo "$MOUNT_OPTIONS" | sed "s/\<sec\>=$value/sec=sys/g")
        fi
    fi

    matchstr="\<nolock\>"
    if ! [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
        vvecho "Adding nolock mount option!"
        MOUNT_OPTIONS="$MOUNT_OPTIONS,nolock"
    fi

    matchstr="\<proto\>=([^,]+)"
    if ! [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
        vvecho "Adding proto=tcp mount option!"
        MOUNT_OPTIONS="$MOUNT_OPTIONS,proto=tcp"
    else
        value="${BASH_REMATCH[1]}"
        if [ "$value" != "tcp" ]; then
            pecho "Unsupported mount option proto=$value, fixing to proto=tcp!"
            MOUNT_OPTIONS=$(echo "$MOUNT_OPTIONS" | sed "s/\<proto\>=$value/proto=tcp/g")
        fi
    fi

    matchstr="\<vers\>=([0-9]+)"
    if ! [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
        vvecho "Adding vers=3 mount option!"
        MOUNT_OPTIONS="$MOUNT_OPTIONS,vers=3"
    else
        value="${BASH_REMATCH[1]}"
        if [ "$value" != "3" ]; then
            pecho "Unsupported mount option vers=$value, fixing to vers=3!"
            MOUNT_OPTIONS=$(echo "$MOUNT_OPTIONS" | sed "s/\<vers\>=$value/vers=3/g")
        fi
    fi

    matchstr="\<rsize\>=([0-9]+)"
    if [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
        value="${BASH_REMATCH[1]}"
        if [ $value -ne 1048576 ]; then
            pecho "Suboptimal rsize=$value mount option, setting rsize=1048576!"
            MOUNT_OPTIONS=$(echo "$MOUNT_OPTIONS" | sed "s/\<rsize\>=$value/rsize=1048576/g")
        fi
    fi

    matchstr="\<wsize\>=([0-9]+)"
    if [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
        value="${BASH_REMATCH[1]}"
        if [ $value -ne 1048576 ]; then
            pecho "Suboptimal wsize=$value mount option, setting wsize=1048576!"
            MOUNT_OPTIONS=$(echo "$MOUNT_OPTIONS" | sed "s/\<wsize\>=$value/wsize=1048576/g")
        fi
    fi

    matchstr="\<retrans\>=([0-9]+)"
    if ! [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
        vvecho "Adding retrans=6 mount option!"
        MOUNT_OPTIONS="$MOUNT_OPTIONS,retrans=6"
    else
        value="${BASH_REMATCH[1]}"
        if [ $value -lt 6 ]; then
            pecho "Suboptimal retrans=$value mount option, setting retrans=6!"
            MOUNT_OPTIONS=$(echo "$MOUNT_OPTIONS" | sed "s/\<retrans\>=$value/retrans=6/g")
        fi
    fi

    if [ "$AZNFS_USE_NORESVPORT" == "1" ]; then
        matchstr="\<resvport\>|\<noresvport\>"
        if ! [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
            MOUNT_OPTIONS="$MOUNT_OPTIONS,noresvport"
        fi
    fi

    matchstr="\<port\>=([0-9]+)"
    if [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
        value="${BASH_REMATCH[1]}"
        if [ "$value" == "2047" ]; then
            USING_PORT_2047=true
        fi
    fi

    MOUNT_OPTIONS=$(echo "$MOUNT_OPTIONS" | sed "s/^,//g")
}

#
# Check if mounting this new share will exceed the "max accounts mountable per tenant" limit.
#
check_account_count()
{
    #
    # nfs_ip MUST be set before calling this function.
    #
    local num=$(grep -c " ${nfs_ip}$" $MOUNTMAP)
    if [ $num -ge $MAX_ACCOUNTS_MOUNTABLE_FROM_SINGLE_TENANT ]; then
        #
        # If this is not a new account it will reuse the existing entry and not
        # cause a new entry to be added to MOUNTMAP, in that case allow the mount.
        #
        if ! grep -q "^${nfs_host} " $MOUNTMAP; then
            return 1
        fi
    fi

    return 0
}

#
# Get blob endpoint from account.blob.core.windows.net:/account/container.
#
get_host_from_share()
{
    local hostshare="$1"
    local azprefix="$2"
    IFS=: read host share <<< "$hostshare"

    if [ -z "$host" -o -z "$share" ]; then
        eecho "Bad share name: ${hostshare}."
        eecho "Share to be mounted must be of the form 'account.$azprefix.core.windows.net:/account/container'."
        return 1
    fi

    echo "$host"
}

#
# Get /account/container from account.blob.core.windows.net:/account/container.
#
get_dir_from_share()
{
    local hostshare="$1"
    local azprefix="$2"
    local is_bad_share_name="false"
    IFS=: read _ share <<< "$hostshare"
    IFS=/ read _ account container extra <<< "$share"

    # Added two separate if blocks below instead of one complicated if condition.
    if [ \( $azprefix == "file" \) -a \( -z "$account" -o -z "$container" \) ]; then
        is_bad_share_name="true"
    elif [ \( $azprefix == "blob" \) -a \( -z "$account" -o -z "$container" -o -n "$extra" \) ]; then
        is_bad_share_name="true"
    fi

    if [ $is_bad_share_name == "true" ]; then
        eecho "Bad share name: ${hostshare}."
        eecho "Share to be mounted must be of the form 'account.$azprefix.core.windows.net:/account/container'."
        return 1
    fi

    echo "$share"
}

get_version_from_mount_options()
{
    local mount_options="$MOUNT_OPTIONS"
    local ver_string="vers="
    local minor_ver_string="minorversion"
    local nfs_ver=""
    local nfs_minorvers=""

    #
    # v3 team adds vers=3 option if version is missing in mount command.
    # Hence, to avoid any breaking changes for v3,
    # defaulting vers=3 if the version is not given.
    #
    if [ -z "$mount_options" ] || [[ ! "$mount_options" == *"$ver_string"* ]]; then
        pecho "Adding default vers=3 mount option!"
        mount_options="$mount_options,vers=3"
        echo "3"
        return
    fi

    IFS=','
    read -a options_arr <<< "$mount_options"

    for option in "${options_arr[@]}";
    do
        if [[ "$option" == *"$ver_string"* ]]; then
            nfs_ver=$(echo $option | cut -d= -f2)
        fi

        if [[ "$option" == *"$minor_ver_string"* ]]; then
            nfs_minorvers=$(echo $option | cut -d= -f2)
        fi
    done

    if [ -z "$nfs_minorvers" ]; then
        echo "$nfs_ver"
    else
        echo "$nfs_ver.$nfs_minorvers"
    fi
}

#
# Parse mount options from the mount command executed by the user.
#
parse_arguments()
{
    # Skip share and mountdir.
    shift
    shift
    local next_arg_is_mount_options=false

    OPTIONS=
    MOUNT_OPTIONS=

    for arg in $*; do
        if [ "$arg" == "-o" ]; then
            next_arg_is_mount_options=true
            continue
        fi

        if $next_arg_is_mount_options; then
            MOUNT_OPTIONS=$arg
            next_arg_is_mount_options=false
        else
            OPTIONS="$OPTIONS $arg"

            if [[ "$arg" == "-v" || "$arg" == "--verbose" ]]; then
                VERBOSE_MOUNT=true
            fi
        fi
    done
}

#
# Ensure aznfswatchdog service is running, if not bail out with an appropriate
# error.
#
ensure_aznfswatchdog()
{
    pidof -x aznfswatchdog > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        if systemd_is_init; then
            eecho "aznfswatchdog service not running!"
            pecho "Start the aznfswatchdog service using 'systemctl start aznfswatchdog' and try again."
        else
            eecho "aznfswatchdog service not running, please make sure it's running and try again!"
        fi

        pecho "If the problem persists, contact Microsoft support."
        return 1
    fi
}

# [account.blob.core.windows.net:/account/container /mnt/aznfs -o rw,tcp,nolock,nconnect=16]
vecho "Got arguments: [$*]"

# Check if aznfswatchdog service is running.
if ! ensure_aznfswatchdog; then
    exit 1
fi

mount_point="$2"

OPTIONS=
MOUNT_OPTIONS=
AZ_PREFIX=

parse_arguments $*

nfs_vers=$(get_version_from_mount_options "$MOUNT_OPTIONS")
if [ $? -ne 0 ]; then
    echo "$nfs_vers"
    exit 1
fi

if [ $nfs_vers == "4.1" ]; then
    AZ_PREFIX="file"
else
    AZ_PREFIX="blob"
fi

nfs_host=$(get_host_from_share "$1" "$AZ_PREFIX")
if [ $? -ne 0 ]; then
    echo "$nfs_host"
    exit 1
fi

# TODO: Comment out below code for devfabric. 'is_valid_fqdn' will fail on devfabric.
if ! is_valid_fqdn "$nfs_host" "$AZ_PREFIX"; then
    eecho "Not a valid Azure $AZ_PREFIX NFS endpoint: ${nfs_host}!"
    eecho "Must be of the form 'account.$AZ_PREFIX.core.windows.net'!"
    eecho "For air-gapped environments, must set the environment variable AzureEndpointOverride to the appropriate endpoint!"
    exit 1
fi

nfs_dir=$(get_dir_from_share "$1" "$AZ_PREFIX")
if [ $? -ne 0 ]; then
    echo "$nfs_dir"
    exit 1
fi

if [ -z "$nfs_dir" ]; then
    eecho "Bad share name: ${1}!"
    eecho "Share to be mounted must be of the form 'account.$AZ_PREFIX.core.windows.net:/account/container'!"
    exit 1
fi

if [ "$nfs_vers" == "4.1" ]; then
    $OPTDIR/nfsv4mountscript.sh
else
    $OPTDIR/nfsv3mountscript.sh
fi
