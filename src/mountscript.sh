#!/bin/bash 

#
# Load common aznfs helpers.
# 
. /opt/microsoft/aznfs/common.sh

# 
# Default order in which we try the network prefixes for a free local IP to use.
# This can be overriden using AZNFS_IP_PREFIXES environment variable. 
# 
DEFAULT_AZNFS_IP_PREFIXES="10.100 192.168 172.16"

IP_PREFIXES="${AZNFS_IP_PREFIXES:-${DEFAULT_AZNFS_IP_PREFIXES}}"

#
# Local IP that is free to use.
#
LOCAL_IP=""

#
# Proccess ID of the current process.
#
PID=""

#
# Check if the given string is a valid blob FQDN (<accountname>.blob.core.windows.net).
#
is_valid_blob_fqdn() 
{ 
    # XXX Are there other valid blob endpoint fqdns? 
    [[ $1 =~ ^([a-z0-9]{3,24}).blob(.preprod)?.core.windows.net$ ]] 
}

# 
# Get blob endpoint from account.blob.core.windows.net:/account/container. 
# 
get_host_from_share() 
{
    local hostshare="$1"
    local host=$(echo $hostshare | cut -d: -f1)
    local share=$(echo $hostshare | cut -d: -f2)

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
    local share=$(echo $hostshare | cut -d: -f2)
    local account=$(echo $share | cut -d/ -f2)
    local container=$(echo $share | cut -d/ -f3)
    local extra=$(echo $share | cut -d/ -f4)

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
    local ip=$1

    # 3 secs timeout should be good.
    ping -4 -W3 -c1 $ip > /dev/null
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
        eecho "Invalid IPv4 prefix: ${ip_prefix}."
        eecho "Valid prefix must have either 2 or 3 octets and must be a valid private IPv4 address prefix."
        eecho "Examples of valid private IPv4 prefixes are 10.10, 10.10.10, 192.168, 192.168.10 etc."
        return 1
    fi
    
    local local_ip=""

    _3rdoctet=100
    ip_prefix=$initial_ip_prefix
    while true; do
        if [ $num_octets -eq 2 ]; then
            # Start from 100 onwards to make aznfs local addresses more identifiable. 

            for ((; _3rdoctet<255; _3rdoctet++)); do 
                ip_prefix="${ip_prefix}.$_3rdoctet" 

                if is_host_ip $ip_prefix; then
                    vecho "Skipping host address ${ip_prefix}!"
                    continue 
                fi 

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

        for ((_4thoctet=100; _4thoctet<255; _4thoctet++)); do 
            local_ip="${ip_prefix}.$_4thoctet" 

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

            if egrep " \<$local_ip\> " "$MOUNTMAP" >/dev/null; then
                # Avoid excessive logs. 
                # vecho "$local_ip is in use by aznfs!"
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
        # Add this entry to MOUNTMAP with PID suffix. This is to avoid assigning
        # same local ip to parallel mount requests. This entry will be deleted
        # from MOUNTMAP and original entry will be added just after mount.
        #
        PID=$$
        local mountmap_entry="$nfs_host:$nfs_dir $local_ip $nfs_ip $PID"
        chattr -f -i $MOUNTMAP
        echo "$mountmap_entry" >> $MOUNTMAP
        if [ $? -ne 0 ]; then
            chattr -f +i $MOUNTMAP
            eecho "[$mountmap_entry] failed to reserve!"
            return 1
        fi
        chattr -f +i $MOUNTMAP

        # Happy path!
        LOCAL_IP=$local_ip
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

    # If we come here we did not get a free address to use.
    return 1
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
# TODO: Make sure this works on all supported distros.  
#
ensure_aznfswatchdog()
{
    if ! systemctl is-active --quiet aznfswatchdog; then
        eecho "aznfswatchdog service not running!"
        pecho "Start the aznfswatchdog service using 'systemctl start aznfswatchdog' and try again."
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
    pecho "Try restarting the aznfswatchdog service using 'systemctl start aznfswatchdog' and then retry the mount command."
    pecho "If the problem persists, contact Microsoft support."
    exit 1
fi

nfs_host=$(get_host_from_share "$1")
if [ $? -ne 0 ]; then
    exit 1
fi

if ! is_valid_blob_fqdn "$nfs_host"; then
    eecho "Not a valid Azure Blob NFS endpoint: ${nfs_host}!"
    eecho "Must be of the form 'account.blob.core.windows.net'!"
    exit 1
fi

nfs_ip=$(resolve_ipv4 "$nfs_host")
if [ $? -ne 0 ]; then
    eecho "Cannot resolve IP address for ${nfs_host}!"
    exit 1
fi

nfs_dir=$(get_dir_from_share "$1")
if [ $? -ne 0 ]; then
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
 
exec {fd}<$MOUNTMAP
flock -e $fd
get_free_local_ip
ret=$?
flock -u $fd
exec {fd}<&-

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

# Add DNAT rule for forwarding LOCAL_IP traffic to the actual blob endpoint IP address.
if ! add_iptable_entry "$LOCAL_IP" "$nfs_ip"; then
    # Do not log anything here since we have already logged in add_iptable_entry.

    # Remove the entry with PID for this mount added in get_free_local_ip() above. 
    ensure_mountmap_not_exist "$nfs_host:$nfs_dir $LOCAL_IP $nfs_ip $PID"

    # Fail the mount for the user since adding iptable entry failed.
    eecho "Mount Failed!"
    exit 1
fi

# Do the actual mount.
mount_output=$(mount -t nfs $OPTIONS -o "$MOUNT_OPTIONS" "${LOCAL_IP}:${nfs_dir}" "$mount_point" 2>&1)
mount_status=$?

if [ -n "$mount_output" ]; then 
    pecho "$mount_output"
fi

if [ $mount_status -ne 0 ]; then
    eecho "Mount failed!"

    # Clear the DNAT rule and the conntrack entry to stop current active connections too.
    delete_iptable_entry "$LOCAL_IP" "$nfs_ip"

    #
    # Ignore the status of delete_iptable_entry and fallthrough to delete the
    # mountmap entry. The iptable entry will be leaked but not deleting
    # mountmap entry might cause this situation to occur again and again and
    # flood the logs.
    #

    # Remove the entry with PID for this mount added in get_free_local_ip() above. 
    ensure_mountmap_not_exist "$nfs_host:$nfs_dir $LOCAL_IP $nfs_ip $PID"

    exit 1
fi

#
# Add new entry in MOUNTMAP before removing the placeholder entry to prevent
# any other thread from using this local IP.
#
if ! ensure_mountmap_exist "$nfs_host:$nfs_dir $LOCAL_IP $nfs_ip"; then
    # Remove the entry with PID for this mount added in get_free_local_ip() above. 
    ensure_mountmap_not_exist "$nfs_host:$nfs_dir $LOCAL_IP $nfs_ip $PID"

    eecho "Mount failed!"

    # Unmount the share mounted above as we are failing the mount.
    unmount_and_delete_iptable_entry "$LOCAL_IP" "$nfs_dir" "$nfs_ip"

    exit 1
fi

#
# Remove the entry with PID for this mount after adding the original entry.
# We do not fail if this fails as aznfswatchdog will be able to correctly
# remove this entry with PID.
#
ensure_mountmap_not_exist "$nfs_host:$nfs_dir $LOCAL_IP $nfs_ip $PID"

exit 0