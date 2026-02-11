#!/bin/bash

#
# NfSv3 logic for mount helper
#

#
# Load common aznfs helpers.
#
AZNFS_VERSION=3
. /opt/microsoft/aznfs/common.sh

MOUNT_OPTIONS=$1
OPTIONS=$2
nfs_host=$3
nfs_dir=$4
mount_point=$5

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

# Default to fixing dirty bytes config to help the user.
AZNFS_FIX_DIRTY_BYTES_CONFIG="${AZNFS_FIX_DIRTY_BYTES_CONFIG:-1}"

# Read ahead size in KB defaults to 16384.
AZNFS_READ_AHEAD_KB="${AZNFS_READ_AHEAD_KB:-16384}"

#
# Use noresvport mount option to allow using non-reserve ports by client.
# This allows much higher number of local ports to be used by NFS client and
# hence may alleviate some issues due to running out of very small resv port range.
# Blob NFS doesn't require clients to use reserve ports so we can use non-reserve
# port with Blob NFS but Linux NFS client doesn't reuse source port while reconnecting
# if noresvport option is used. This does not work will with the DRC cache.
#
AZNFS_USE_NORESVPORT="${AZNFS_USE_NORESVPORT:-0}"

# Set the fingerprint GUID as an environment variable with a default value.
AZNFS_FINGERPRINT="${AZNFS_FINGERPRINT:-80a18d5c-9553-4c64-88dd-d7553c6b3beb}"

#
# Default to maximum number of mount retries in case of server-side returns failure.
# Retries make the mount process more robust. Currently, we don't distinguish between 
# access denied failure due to intermittent issues or genuine mount failures. We retry anyways.
#
AZNFS_MAX_MOUNT_RETRIES="${AZNFS_MAX_MOUNT_RETRIES:-3}"

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
# Choose the local IP based on last used IP in MOUNTMAPv3 if this flag is enabled.
#
OPTIMIZE_GET_FREE_LOCAL_IP=true

#
# True if user has asked to use port 2047 using 'port=2047' mount option.
# This signifies server side nconnect which has some special needs.
#
USING_PORT_2047=false

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

# Function to extract minor number from combined device ID.
get_minor()
{
    local dev_id=$1
    echo $(( (dev_id & 0xff) | ((dev_id >> 12) & ~0xff) ))
}

# Function to extract major number from combined device ID.
get_major()
{
    local dev_id=$1
    echo $(( ((dev_id >> 8) & 0xfff) | ((dev_id >> 32) & ~0xfff) ))
}

#
# To Improve read ahead size to increase large file read throughput.
#
fix_read_ahead_config() 
{
    # Get the block device identifier of the mount point.
    block_device_id=$(stat -c "%d" "$mount_point" 2>/dev/null)
    if [ $? -ne 0 ]; then
        wecho "Failed to get device ID for mount point $mount_point. Cannot set read ahead."
        return
    fi

    # Path to the read_ahead_kb file.
    major=$(get_major $block_device_id)
    minor=$(get_minor $block_device_id)
    read_ahead_path="/sys/class/bdi/$major:$minor/read_ahead_kb"
    if [ ! -e "$read_ahead_path" ]; then
        wecho "The path $read_ahead_path does not exist. Cannot set read ahead."
        return
    fi

    current_read_ahead_value_kb=$(cat "$read_ahead_path")
    if [ $? -ne 0 ]; then
        wecho "Failed to read current read ahead value. Cannot set read ahead."
        return
    fi

    # Compare and update the read ahead value if the desired value is greater.
    if [ "$current_read_ahead_value_kb" -lt "$AZNFS_READ_AHEAD_KB" ]; then
        echo "$AZNFS_READ_AHEAD_KB" > "$read_ahead_path"
        if [ $? -ne 0 ]; then
            wecho "Failed to set read ahead size for $mount_point."
            return
        fi
        vvecho "Read ahead size for $mount_point set to $AZNFS_READ_AHEAD_KB KB!"
    else
        vvecho "Current read ahead size ($current_read_ahead_value_kb KB) for $mount_point is already greater than or equal to the desired value ($AZNFS_READ_AHEAD_KB KB), no update needed!"
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
    local num=$(grep -c " ${nfs_ip}$" $MOUNTMAPv3)
    if [ $num -ge $MAX_ACCOUNTS_MOUNTABLE_FROM_SINGLE_TENANT ]; then
        #
        # If this is not a new account it will reuse the existing entry and not
        # cause a new entry to be added to MOUNTMAPv3, in that case allow the mount.
        #
        if ! grep -q "^${nfs_host} " $MOUNTMAPv3; then
            return 1
        fi
    fi

    return 0
}

#
# To maintain consistency in case of regional account and in general to avoid creating
# multiple DNAT entries corrosponding to one LOCAL_IP, first check for resolved IP in mountmap.
# This will help keep mountmap and DNAT entries in sync with each other.
# If the current resolved IP is different from the one stored in mountmap then it means that the IP has changed
# since the mountmap entry was created (could be due to migration or more likely due to RAs roundrobin DNS). 
# In any case this will be properly handled by aznfswatchdog next time it checks for IP change for this fqdn.
#
resolve_ipv4_with_preference_to_mountmapv3()
{
    local fqdn=$1

    exec {fd}<$MOUNTMAPv3
    flock -e $fd

    local mountmap_entry=$(grep -m1 "^${fqdn} " $MOUNTMAPv3)
    
    flock -u $fd
    exec {fd}<&-

    IFS=" " read _ local_ip old_nfs_ip <<< "$mountmap_entry"
    if [ -n "$old_nfs_ip" ]; then
        echo "$old_nfs_ip"
        return 2 
    fi

    #
    # Resolve FQDN to IPv4 using DNS if not found in the mountmap.
    #
    resolve_ipv4 "$fqdn" "true"
}

#
# For the given AZNFS endpoint FQDN return a local IP that should proxy it.
# If there is at least one mount to the same FQDN it MUST return the local IP
# used for that, else assign a new free local IP.
#
get_local_ip_for_fqdn()
{
        local fqdn=$1
        local mountmap_entry=$(grep -m1 "^${fqdn} " $MOUNTMAPv3)
        # One local ip per fqdn, so return existing one if already present.
        IFS=" " read _ local_ip _ <<< "$mountmap_entry"

        if [ -n "$local_ip" ]; then
            LOCAL_IP=$local_ip

            #
            # Ask aznfswatchdog to stay away while we are using this proxy IP.
            # This is similar to holding a timed lease, we can safely use this
            # proxy IP w/o worrying about aznfswatchdog deleting it for 5 minutes.
            #
            touch_mountmap $MOUNTMAPv3

            #
            # This is not really needed since iptable entry must also be present,
            # but it's always better to ensure MOUNTMAPv3 and iptable entries are
            # in sync.
            #
            ensure_iptable_entry $local_ip $nfs_ip
            return 0
        fi

        #
        # First mount of an account on this client.
        #
        get_free_local_ip $MOUNTMAPv3
}

#
# Perform a pseudo mount to generate a gatepass for the actual mount call.
# This request is expected to fail with "server access denied" if server-side changes are enabled,
# or with "no such file or directory" if not. Failure of this call is expected behavior, 
# and we proceed normally when it occurs.
#
gatepass_mount()
{
    mount_output=$(mount -t nfs $OPTIONS -o "$MOUNT_OPTIONS" "${LOCAL_IP}:${nfs_dir}/$AZNFS_FINGERPRINT" "$mount_point" 2>&1)
    mount_status=$?

    if [ -n "$mount_output" ]; then
        vecho "[Gatepass mount] $mount_output"
    fi

    #
    # Ensure that gatepass mount operation failed (expected behavior).
    # Exit with an error code if it succeeded, which is unexpected.
    #
    if [ $mount_status -eq 0 ]; then
        vecho "[Gatepass mount] Unexpected success!"
        eecho "Mount failed!"
        exit 1
    fi
}

actual_mount()
{
    mount_output=$(mount -t nfs $OPTIONS -o "$MOUNT_OPTIONS" "${LOCAL_IP}:${nfs_dir}" "$mount_point" 2>&1)
    mount_status=$?

    if [ -n "$mount_output" ]; then
        pecho "$mount_output"
    fi

    return $mount_status
}

# Check if aznfswatchdog service is running.
if ! ensure_aznfswatchdog "aznfswatchdog"; then
    exit 1
fi

# MOUNTMAPv3 file must have been created by aznfswatchdog service.
if [ ! -f "$MOUNTMAPv3" ]; then
    eecho "[FATAL] ${MOUNTMAPv3} not found!"
    
    if systemd_is_init; then
        pecho "Try restarting the aznfswatchdog service using 'systemctl start aznfswatchdog' and then retry the mount command."
    else
        eecho "aznfswatchdog service not running, please make sure it's running and try again!"
    fi
    
    pecho "If the problem persists, contact Microsoft support."
    exit 1
fi

# Resolve the IP address for the NFS host
nfs_ip=$(resolve_ipv4_with_preference_to_mountmapv3 "$nfs_host")
status=$?
if [ $status -ne 0 ]; then
    if [ $status -eq 2 ]; then
        vecho "Resolved IP address for FQDN from mountmap [$nfs_host -> $nfs_ip]"
    else
        echo "$nfs_ip"
        eecho "Cannot resolve IP address for ${nfs_host}!"
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
# Check azure nconnect flag.
#
if [ "$AZNFS_CHECK_AZURE_NCONNECT" == "1" ]; then
    if ! check_nconnect; then
        eecho "Mount failed!"
        exit 1
    fi
fi

#
# Fix dirty bytes config if needed.
#
if [ "$AZNFS_FIX_DIRTY_BYTES_CONFIG" == "1" ]; then
    fix_dirty_bytes_config
fi


#
# Get proxy IP to use for this nfs_ip.
# It'll ensure an appropriate entry is added to MOUNTMAPv3 if not already added,
# and an appropriate iptable DNAT rule is added.
#
exec {fd}<$MOUNTMAPv3
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

mount_retry_attempt=0

while [ $mount_retry_attempt -le $AZNFS_MAX_MOUNT_RETRIES ]; do
    gatepass_mount
    
    actual_mount
    mount_status=$?

    if [ $mount_status -eq 0 ]; then
        vvecho "Mount completed: ${nfs_host}:${nfs_dir} on $mount_point using proxy IP $LOCAL_IP and endpoint IP $nfs_ip"
        
        #
        # Fix read ahead config if needed.
        #
        fix_read_ahead_config

        exit 0  # Nothing in this script will run after this point.
    else
        if echo "$mount_output" | grep -Eq "reason given by server: No such file or directory|mount point $mount_point does not exist"; then
            break
        fi

        mount_retry_attempt=$((mount_retry_attempt + 1))
        if [ $mount_retry_attempt -le $AZNFS_MAX_MOUNT_RETRIES ]; then
            vvecho "Mount failed! Retrying mount (attempt $mount_retry_attempt of $AZNFS_MAX_MOUNT_RETRIES)"
        fi
    fi
done

#
# Don't bother clearing up the mountmap and/or iptable rule, aznfswatchdog
# will do it if it's unused (this mount was the one to create it).
#
eecho "Mount failed!"
exit 1