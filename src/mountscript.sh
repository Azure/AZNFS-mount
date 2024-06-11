#!/bin/bash

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

#
# Load common aznfs helpers.
#
AZNFS_VERSION="unknown"
. /opt/microsoft/aznfs/common.sh

#
# True if user has asked for verbose logs using '-v' or '--verbose' with mount command.
#
VERBOSE_MOUNT=false

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
    # Check if version is missing in mount command.
    #
    if [ -z "$mount_options" ] || [[ ! "$mount_options" == *"$ver_string"* ]]; then
        eecho "Missing version in mount options. Example: 'vers=3'."
        exit 1
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

# [account.blob.core.windows.net:/account/container /mnt/aznfs -o rw,tcp,nolock,nconnect=16]
vecho "Got arguments: [$*]"

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
elif [ $nfs_vers == "3" ]; then
    AZ_PREFIX="blob"
else
    eecho "NFS version is not supported by mount helper: $nfs_vers!"
    exit 1
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
    eecho "For isolated environments, must set the environment variable AzureEndpointOverride to the appropriate endpoint!"
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
    $OPTDIR/nfsv4mountscript.sh "$MOUNT_OPTIONS" "$OPTIONS" "$nfs_host" "$nfs_dir" "$mount_point"
else
    $OPTDIR/nfsv3mountscript.sh "$MOUNT_OPTIONS" "$OPTIONS" "$nfs_host" "$nfs_dir" "$mount_point"
fi
