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
# Default order in which we try the network prefixes for a free local IP to use.
# This can be overriden using AZNFS_IP_PREFIXES environment variable.
#
DEFAULT_AZNFS_IP_PREFIXES="10.161 192.168 172.16"
IP_PREFIXES="${AZNFS_IP_PREFIXES:-${DEFAULT_AZNFS_IP_PREFIXES}}"

# Aznfs port, defaults to 2048.
AZNFS_PORT="${AZNFS_PORT:-2048}"

# Default to checking azure nconnect support.
AZNFS_CHECK_AZURE_NCONNECT="${AZNFS_CHECK_AZURE_NCONNECT:-1}"

# Default to fixing mount options passed in to help the user.
AZNFS_FIX_MOUNT_OPTIONS="${AZNFS_FIX_MOUNT_OPTIONS:-1}"

#
# Use noresvport mount option to allow using non-reserve ports by client.
# This allows much higher number of local ports to be used by NFS client and
# hence may alleviate some issues due to running out of very small resv port range.
# Blob NFS doesn't require clients to use reserve ports so we can use non-reserve
# port with Blob NFS but Linux NFS client doesn't reuse source port while reconnecting
# if noresvport option is used. This does not work will with the DRC cache.
#
AZNFS_USE_NORESVPORT="${AZNFS_USE_NORESVPORT:-0}"

#
# Maximum number of accounts that can be mounted from the same tenant/cluster.
# Any number of containers on these many accounts can be mounted.
# With ~350 reserved ports and 16 connections per mount (with nconnect=16) leaving
# some room, 20 is a reasonable limit.
#
MAX_ACCOUNTS_MOUNTABLE_FROM_SINGLE_TENANT=20

#
# Local IP that is free to use.
#
LOCAL_IP=""

#
# Proccess ID of the current process.
#
PID=""

#
# Choose the local IP based on last used IP in MOUNTMAP if this flag is enabled.
#
OPTIMIZE_GET_FREE_LOCAL_IP=true

#
# Check if the given string is a valid blob FQDN (<accountname>.blob.core.windows.net).
#
is_valid_blob_fqdn()
{
    [[ $1 =~ ^([a-z0-9]{3,24})(.z[0-9]+)?(.privatelink)?.blob(.preprod)?.core.(windows.net|usgovcloudapi.net|chinacloudapi.cn)$ ]]
}

#
# Check if nconnect mount option can be used. If not bail out failing the mount,
# else if NFS client supports Azure nconnect but it's not enabled, enable it.
#
check_nconnect()
{
    matchstr="\<nconnect\>=([0-9]+)"
    if [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
        value="${BASH_REMATCH[1]}"
        if [ $value -gt 1 ]; then
            modprobe sunrpc
            if [ ! -e /sys/module/sunrpc/parameters/enable_azure_nconnect ]; then
                eecho "nconnect option needs NFS client with Azure nconnect support!"
                return 1
            fi

            # Supported, enable if not enabled.
            enabled=$(cat /sys/module/sunrpc/parameters/enable_azure_nconnect)
            if ! [[ "$enabled" =~ [yY] ]]; then
                pecho "Azure nconnect not enabled, enabling!"
                echo Y > /sys/module/sunrpc/parameters/enable_azure_nconnect
            fi
        fi
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
        pecho "Adding nolock mount option!"
        MOUNT_OPTIONS="$MOUNT_OPTIONS,nolock"
    fi

    matchstr="\<proto\>=([^,]+)"
    if ! [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
        pecho "Adding proto=tcp mount option!"
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
        pecho "Adding vers=3 mount option!"
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

    if [ "$AZNFS_USE_NORESVPORT" == "1" ]; then
        matchstr="\<resvport\>|\<noresvport\>"
        if ! [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
            MOUNT_OPTIONS="$MOUNT_OPTIONS,noresvport"
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
    IFS=: read host share <<< "$hostshare"

    if [ -z "$host" -o -z "$share" ]; then
        eecho "Bad share name: ${hostshare}."
        eecho "Share to be mounted must be of the form 'account.blob.core.windows.net:/account/container'."
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
    IFS=: read _ share <<< "$hostshare"
    IFS=/ read _ account container extra <<< "$share"

    if [ -z "$account" -o -z "$container" -o -n "$extra" ]; then
        eecho "Bad share name: ${hostshare}."
        eecho "Share to be mounted must be of the form 'account.blob.core.windows.net:/account/container'."
        return 1
    fi

    echo "$share"
}

#
# Is the given address one of the host addresses?
#
is_host_ip()
{
    #
    # Do not make this local as status gathering does not work well when
    # collecting command o/p to local variables.
    #
    route=$(ip -4 route get fibmatch $1 2>/dev/null)
    if [ $? -ne 0 ]; then
        return 1
    fi

    if ! echo "$route" | grep -q "scope host"; then
        return 1
    fi

    return 0
}

#
# Is the given address one of the addresses directly reachable from the host?
#
is_link_ip()
{
    #
    # Do not make this local as status gathering does not work well when
    # collecting command o/p to local variables.
    #
    route=$(ip -4 route get fibmatch $1 2>/dev/null)
    if [ $? -ne 0 ]; then
        return 1
    fi

    if ! echo "$route" | grep -q "scope link"; then
        return 1
    fi

    return 0
}

#
# Check if a given IPv4 address is responding to ICMP pings.
# Uses a 3 secs timeout to bail out in time if address is not responding.
#
is_pinging()
{
    #
    # Unless env var AZNFS_PING_LOCAL_IP_BEFORE_USE is set, pretend IP address
    # is available.
    #
    if [ "$AZNFS_PING_LOCAL_IP_BEFORE_USE" != "1" ]; then
        return 1
    fi

    local ip=$1

    # 3 secs timeout should be good.
    ping -4 -W3 -c1 $ip > /dev/null 2>&1
}

#
# Returns number of octets in an IPv4 prefix.
# If IP prefix is not valid or is not a private IP address prefix, it returns 0.
#
# f.e. For 10 it will return 1, for 10.10 it will return 2, for 10.10.10 it will
# return 3 and for 10.10.10.10, it will return 4.
#
octets_in_ipv4_prefix()
{
    local ip=$1
    local octet="[0-9]{1,3}"
    local octetdot="${octet}\."

    if ! is_valid_ipv4_prefix $ip; then
        echo 0
        return
    fi

    #
    # Check if the IP prefix belongs to the private IP range (10.0.0.0/8,
    # 172.16.0.0/12, or 192.168.0.0/16), i.e., will the user provided prefix
    # result in a private IP address.
    #
    [[ $ip =~ ^10(\.${octet})*$ ]] ||
    [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])(\.${octet})*$ ]] ||
    [[ $ip =~ ^192\.168(\.${octet})*$ ]]

    if [ $? -ne 0 ]; then
        echo 0
        return
    fi

    # 4 octets.
    [[ $ip =~ ^(${octetdot}){3}${octet}$ ]] && echo 4 && return;

    # 3 octets
    [[ $ip =~ ^(${octetdot}){2}${octet}$ ]] && echo 3 && return;

    # 2 octets.
    [[ $ip =~ ^(${octetdot}){1}${octet}$ ]] && echo 2 && return;

    # 1 octet.
    [[ $ip =~ ^${octet}$ ]] && echo 1 && return;

    echo 0
}

search_free_local_ip_with_prefix()
{
    initial_ip_prefix=$1
    num_octets=$(octets_in_ipv4_prefix $ip_prefix)

    if [ $num_octets -ne 2 -a $num_octets -ne 3 ]; then
        eecho "Invalid IPv4 prefix: ${ip_prefix}"
        eecho "Valid prefix must have either 2 or 3 octets and must be a valid private IPv4 address prefix."
        eecho "Examples of valid private IPv4 prefixes are 10.10, 10.10.10, 192.168, 192.168.10 etc."
        return 1
    fi

    local local_ip=""
    local optimize_get_free_local_ip=false
    local used_local_ips_with_same_prefix=$(cat $MOUNTMAP | awk '{print $2}' | grep "^${initial_ip_prefix}\." | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n)
    local iptable_entries=$(iptables-save -t nat)

    _3rdoctet=100
    ip_prefix=$initial_ip_prefix

    #
    # Optimize the process to get free local IP by starting the loop to choose
    # 3rd and 4th octet from the number which was used last and still exist in
    # MOUNTMAP instead of starting it from 100.
    #
    if [ $OPTIMIZE_GET_FREE_LOCAL_IP == true -a -n "$used_local_ips_with_same_prefix" ]; then

        last_used_ip=$(echo "$used_local_ips_with_same_prefix" | tail -n1)

        IFS="." read _ _ last_used_3rd_octet last_used_4th_octet <<< "$last_used_ip"

        if [ $num_octets -eq 2 ]; then
            if [ "$last_used_3rd_octet" == "254" -a "$last_used_4th_octet" == "254" ]; then
                return 1
            fi

            _3rdoctet=$last_used_3rd_octet
            optimize_get_free_local_ip=true
        else
            if [ "$last_used_4th_octet" == "254" ]; then
                return 1
            fi

            optimize_get_free_local_ip=true
        fi
    fi

    while true; do
        if [ $num_octets -eq 2 ]; then
            for ((; _3rdoctet<255; _3rdoctet++)); do
                ip_prefix="${ip_prefix}.$_3rdoctet"

                if is_link_ip $ip_prefix; then
                    vecho "Skipping link network ${ip_prefix}!"
                    continue
                fi

                break
            done

            if [ $_3rdoctet -eq 255 ]; then
                #
                # If the IP prefix had 2 octets and we exhausted all possible
                # values of the 3rd and 4th octet, then we have failed the
                # search for free local IP within the given prefix.
                #
                return 1
            fi
        fi

        if $optimize_get_free_local_ip; then
            _4thoctet=$(expr ${last_used_4th_octet} + 1)
            optimize_get_free_local_ip=false
        else
            _4thoctet=100
        fi

        for ((; _4thoctet<255; _4thoctet++)); do
            local_ip="${ip_prefix}.$_4thoctet"

            is_ip_used_by_aznfs=$(echo "$used_local_ips_with_same_prefix" | grep "^${local_ip}$")
            if [ -n "$is_ip_used_by_aznfs" ]; then
                vecho "$local_ip is in use by aznfs!"
                continue
            fi

            if is_host_ip $local_ip; then
                vecho "Skipping host address ${local_ip}!"
                continue
            fi

            if is_link_ip $local_ip; then
                vecho "Skipping link network ${local_ip}!"
                continue
            fi

            if [ "$nfs_ip" == "$local_ip" ]; then
                vecho "Skipping private endpoint IP ${nfs_ip}!"
                continue
            fi

            is_present_in_iptables=$(echo "$iptable_entries" | grep -c "\<${local_ip}\>")
            if [ $is_present_in_iptables -ne 0 ]; then
                vecho "$local_ip is already present in iptables!"
                continue
            fi

            #
            # Try pinging the address to be sure it is not in use in the
            # client network.
            #
            # Note: If the address exists but not responding to ICMP ping then
            #       we will incorrectly treat it as non-exixtent.
            #
            if is_pinging $local_ip; then
                vecho "Skipping $local_ip as it appears to be in use on the network!"
                continue
            fi

            vecho "Using local IP ($local_ip) for aznfs."
            break
        done

        if [ $_4thoctet -eq 255 ]; then
            if [ $num_octets -eq 2 ]; then
                let _3rdoctet++
                ip_prefix=$initial_ip_prefix
                continue
            else
                #
                # If the IP prefix had 3 octets and we exhausted all possible
                # values of the 4th octet, then we have failed the search for
                # free local IP within the given prefix.
                #
                return 1
            fi
        fi

        #
        # Happy path!
        #
        # Add this entry to MOUNTMAP while we have the MOUNTMAP lock.
        # This is to avoid assigning same local ip to parallel mount requests
        # for different endpoints.
        # ensure_mountmap_exist will also create a matching iptable DNAT rule.
        #
        LOCAL_IP=$local_ip
        ensure_mountmap_exist_nolock "$nfs_host $LOCAL_IP $nfs_ip"

        return 0
    done

    # We will never reach here.
}

#
# Get a local IP that is free to use. Set global variable LOCAL_IP if found.
#
get_free_local_ip()
{
    for ip_prefix in $IP_PREFIXES; do
        vecho "Trying IP prefix ${ip_prefix}."
        if search_free_local_ip_with_prefix "$ip_prefix"; then
            return 0
        fi
    done

    #
    # If the above loop is not able to find a free local IP using optimized way,
    # do a linear search to get the free local IP.
    #
    vecho "Falling back to linear search for free ip!"
    OPTIMIZE_GET_FREE_LOCAL_IP=false
    for ip_prefix in $IP_PREFIXES; do
        vecho "Trying IP prefix ${ip_prefix}."
        if search_free_local_ip_with_prefix "$ip_prefix"; then
            return 0
        fi
    done

    # If we come here we did not get a free address to use.
    return 1
}

#
# For the given AZNFS endpoint FQDN return a local IP that should proxy it.
# If there is at least one mount to the same FQDN it MUST return the local IP
# used for that, else assign a new free local IP.
#
get_local_ip_for_fqdn()
{
        local fqdn=$1
        local mountmap_entry=$(grep -m1 "^${fqdn} " $MOUNTMAP)
        # One local ip per fqdn, so return existing one if already present.
        IFS=" " read _ local_ip _ <<< "$mountmap_entry"

        if [ -n "$local_ip" ]; then
            LOCAL_IP=$local_ip

            #
            # Ask aznfswatchdog to stay away while we are using this proxy IP.
            # This is similar to holding a timed lease, we can safely use this
            # proxy IP w/o worrying about aznfswatchdog deleting it for 5 minutes.
            #
            touch_mountmap

            #
            # This is not really needed since iptable entry must also be present,
            # but it's always better to ensure MOUNTMAP and iptable entries are
            # in sync.
            #
            ensure_iptable_entry $local_ip $nfs_ip
            return 0
        fi

        #
        # First mount of an account on this client.
        #
        get_free_local_ip
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

# MOUNTMAP file must have been created by aznfswatchdog service.
if [ ! -f "$MOUNTMAP" ]; then
    eecho "[FATAL] ${MOUNTMAP} not found!"
    
    if systemd_is_init; then
        pecho "Try restarting the aznfswatchdog service using 'systemctl start aznfswatchdog' and then retry the mount command."
    else
        eecho "aznfswatchdog service not running, please make sure it's running and try again!"
    fi
    
    pecho "If the problem persists, contact Microsoft support."
    exit 1
fi

nfs_host=$(get_host_from_share "$1")
if [ $? -ne 0 ]; then
    echo "$nfs_host"
    exit 1
fi

if ! is_valid_blob_fqdn "$nfs_host"; then
    eecho "Not a valid Azure Blob NFS endpoint: ${nfs_host}!"
    eecho "Must be of the form 'account.blob.core.windows.net'!"
    exit 1
fi

# Resolve the IP address for the NFS host
nfs_ip=$(resolve_ipv4 "$nfs_host" "true")
if [ $? -ne 0 ]; then
    echo "$nfs_ip"
    eecho "Cannot resolve IP address for ${nfs_host}!"
    eecho "Mount failed!"
    exit 1
fi

nfs_dir=$(get_dir_from_share "$1")
if [ $? -ne 0 ]; then
    echo "$nfs_dir"
    exit 1
fi

if [ -z "$nfs_dir" ]; then
    eecho "Bad share name: ${1}!"
    eecho "Share to be mounted must be of the form 'account.blob.core.windows.net:/account/container'!"
    exit 1
fi

mount_point="$2"

OPTIONS=
MOUNT_OPTIONS=

parse_arguments $*

#
# Check azure nconnect flag.
#
if [ "$AZNFS_CHECK_AZURE_NCONNECT" == "1" ]; then
    if ! check_nconnect; then
        eecho "Mount failed!"
        exit 1
    fi
fi

#
# Fix MOUNT_OPTIONS if needed.
#
if [ "$AZNFS_FIX_MOUNT_OPTIONS" == "1" ]; then
    fix_mount_options
fi

#
# Get proxy IP to use for this nfs_ip.
# It'll ensure an appropriate entry is added to MOUNTMAP if not already added,
# and an appropriate iptable DNAT rule is added.
#
exec {fd}<$MOUNTMAP
flock -e $fd
#
# With the lock held first check if adding a new mountmap entry for this account will
# cause "accounts mounted on one client" to exceed the limit.
#
if check_account_count; then
    get_local_ip_for_fqdn $nfs_host
    ret=$?
    account_limit_exceeded=0
else
    account_limit_exceeded=1
fi
flock -u $fd
exec {fd}<&-

if [ "$account_limit_exceeded" == "1" ]; then
    eecho "Mounts to target IP $nfs_ip ($nfs_host) already at max limit ($MAX_ACCOUNTS_MOUNTABLE_FROM_SINGLE_TENANT)!"
    eecho "Mount failed!"
    exit 1
fi

if [ $ret -ne 0 ]; then
    if [ -z "$AZNFS_IP_PREFIXES" ]; then
        eecho "Could not find a free local IP to use for aznfs using DEFAULT_AZNFS_IP_PREFIXES=${DEFAULT_AZNFS_IP_PREFIXES}!"
        eecho "Set AZNFS_IP_PREFIXES env variable correctly to provide free addresses for use by aznfs!"
    else
        eecho "Could not find a free local IP to use for aznfs using AZNFS_IP_PREFIXES=${AZNFS_IP_PREFIXES}!"
        eecho "Ensure AZNFS_IP_PREFIXES env variable is set properly!"
    fi
    exit 1
fi

vecho "nfs_host=[$nfs_host], nfs_ip=[$nfs_ip], nfs_dir=[$nfs_dir], mount_point=[$mount_point], options=[$OPTIONS], mount_options=[$MOUNT_OPTIONS], local_ip=[$LOCAL_IP]."

#
# AZNFS uses fixed port 2048 for mount and nfs.
# Avoid portmap calls by default.
#
if [ -z "$AZNFS_PMAP_PROBE" -o "$AZNFS_PMAP_PROBE" == "0" ]; then
    matchstr="\<port\>="
    if ! [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
        MOUNT_OPTIONS="$MOUNT_OPTIONS,port=$AZNFS_PORT"
    fi
    matchstr="\<mountport\>="
    if ! [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
        MOUNT_OPTIONS="$MOUNT_OPTIONS,mountport=$AZNFS_PORT"
    fi
    MOUNT_OPTIONS=$(echo "$MOUNT_OPTIONS" | sed "s/^,//g")
fi

# Do the actual mount.
mount_output=$(mount -t nfs $OPTIONS -o "$MOUNT_OPTIONS" "${LOCAL_IP}:${nfs_dir}" "$mount_point" 2>&1)
mount_status=$?

if [ -n "$mount_output" ]; then
    pecho "$mount_output"
fi

if [ $mount_status -ne 0 ]; then
    eecho "Mount failed!"
    #
    # Don't bother clearing up the mountmap and/or iptable rule, aznfswatchdog
    # will do it if it's unused (this mount was the one to create it).
    #
    exit 1
fi

vecho "Mount completed: ${nfs_host}:${nfs_dir} on $mount_point using proxy IP $LOCAL_IP and endpoint IP $nfs_ip"
