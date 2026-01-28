#!/bin/bash

#
# NfSv3 logic for mount helper
#

#
# Load common aznfs helpers.
#
AZNFS_VERSION=3
. /opt/microsoft/aznfs/common.sh


STUNNEL_BASE_DIR="/etc/stunnel/microsoft/aznfs"
STUNNEL_V3_DIR="${STUNNEL_BASE_DIR}/nfsv3_blob"
STUNNEL_V3_LOG_DIR="${STUNNEL_V3_DIR}/logs"
mkdir -p "${STUNNEL_V3_LOG_DIR}"

# TLS/stunnel related variables for NFSv3
isDebian=0
isRedHat=0
isSUSE=0

# Certificates related variables.
CERT_PATH=
CERT_UPDATE_COMMAND=
STUNNEL_CAFILE=

# TLS version from mount options (1.2 or 1.3)
ssl_version=

# TLS timeout settings
stunnel_timeout_idle=61

# Debug level for stunnel
DEBUG_LEVEL="info"


MOUNT_OPTIONS=$1
OPTIONS=$2
nfs_host=$3
nfs_dir=$4
mount_point=$5

vecho "[DEBUG] nfsv3mountscript.sh started"
vecho "[DEBUG] Arguments: MOUNT_OPTIONS=$MOUNT_OPTIONS"
vecho "[DEBUG] Arguments: nfs_host=$nfs_host, nfs_dir=$nfs_dir, mount_point=$mount_point"
vecho "[DEBUG] Environment: USING_AZNFSCLIENT=$USING_AZNFSCLIENT, AZNFS_STLS_V3=$AZNFS_STLS_V3"

#
# Default order in which we try the network prefixes for a free local IP to use.
# This can be overriden using AZNFS_IP_PREFIXES environment variable.
#
DEFAULT_AZNFS_IP_PREFIXES="10.161 192.168 172.16"
IP_PREFIXES="${AZNFS_IP_PREFIXES:-${DEFAULT_AZNFS_IP_PREFIXES}}"

#
# Directory where the turbo log file will be created.
# User can override it with AZNFSC_LOGDIR env variable.
#
AZNFSC_LOGDIR="${AZNFSC_LOGDIR:-/opt/microsoft/aznfs/data}"

# Aznfs port, defaults to 2048.
AZNFS_PORT="${AZNFS_PORT:-2048}"

# Default to checking azure nconnect support.
AZNFS_CHECK_AZURE_NCONNECT="${AZNFS_CHECK_AZURE_NCONNECT:-1}"

# 
# Default maximum value of nconnect.
# Users can modify the AZNFS_MAX_NCONNECT variable to a lower value.
# This allows mounting more than 20 accounts (with the same endpoint IP) 
# from a single VM by restricting the nconnect value to a lower limit.
#
AZNFS_MAX_NCONNECT="${AZNFS_MAX_NCONNECT:-16}"

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
# Holds the config file path for aznfsclient mount. We should have a default config
# file in OPT_DIR. The user can override this by passing the "configfile=/path/to/file"
# option.
#
CONFIG_FILE_PATH=$OPTDIRDATA/turbo-config.yaml

#
# Sample config file for aznfsclient. User NEEDS to copy this and create a new config
# file.
#
SAMPLE_CONFIG_PATH=$OPTDIRDATA/sample-turbo-config.yaml

#
# Holds the path to the aznfsclient binary. This will be used to mount if the user has
# passed "turbo" option.
#
AZNFSCLIENT_BINARY_PATH="/sbin/aznfsclient"

#
# Holds the parsed args for aznfsclient. If the user has passed options in the mount
# command, this will have the overridden values and pass these to aznfsclient.
# This only holds the args string, the value validation has already happened by the time
# this gets populated.
#
AZNFSCLIENT_MOUNT_ARGS=

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
            if [ "$USING_AZNFSCLIENT" == true ]; then
                #
                # Max supported value for nconnect is 256.
                # Client patch is also not required.
                #
                if [ $value -gt 256 ]; then
                    pecho "Suboptimal nconnect value $value, forcing nconnect=256!"
                    MOUNT_OPTIONS=$(echo "$MOUNT_OPTIONS" | sed "s/\<nconnect\>=$value/nconnect=256/g")
                fi
            else
                # Load sunrpc module if not already loaded.
                if [ ! -d /sys/module/sunrpc/ ]; then
                    modprobe sunrpc
                fi

                # Check if AZNFS_MAX_NCONNECT is defined, numeric, and within the allowed range.
                if [[ "$AZNFS_MAX_NCONNECT" =~ ^[0-9]+$ ]]; then

                    if [[ "$AZNFS_MAX_NCONNECT" -lt 1 || "$AZNFS_MAX_NCONNECT" -gt 16 ]]; then
                        eecho "[ERROR] Incorrect value $AZNFS_MAX_NCONNECT for the environment variable AZNFS_MAX_NCONNECT. It must be between 1 and 16"
                        exit 1
                    fi
                else
                    wecho "AZNFS_MAX_NCONNECT=$AZNFS_MAX_NCONNECT is not defined or invalid. Defaulting to 16."
                    AZNFS_MAX_NCONNECT=16
                fi

                # Calculate the maximum accounts mountable from a single tenant.
                MAX_ACCOUNTS_MOUNTABLE_FROM_SINGLE_TENANT=$((320 / AZNFS_MAX_NCONNECT))

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

                    # Check if the current nconnect value in use is suboptimal.
                    if [[ "$value" -gt "$AZNFS_MAX_NCONNECT" ]]; then
                        pecho "Suboptimal nconnect value $value, limiting nconnect to the advised value by AZNFS_MAX_NCONNECT: $AZNFS_MAX_NCONNECT."
                        MOUNT_OPTIONS=$(echo "$MOUNT_OPTIONS" | sed "s/\<nconnect\>=$value/nconnect=$AZNFS_MAX_NCONNECT/g")
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
                    OPTIMAL_SERVER_SIDE_NCONNECT=4
                    if [ -n "$AZNFS_MAX_NCONNECT" ] && [ "$AZNFS_MAX_NCONNECT" -lt "$OPTIMAL_SERVER_SIDE_NCONNECT" ]; then
                        OPTIMAL_SERVER_SIDE_NCONNECT=$AZNFS_MAX_NCONNECT
                    fi

                    if [ "$value" -gt "$OPTIMAL_SERVER_SIDE_NCONNECT" ]; then
                        pecho "Suboptimal nconnect value $value, forcing nconnect=$OPTIMAL_SERVER_SIDE_NCONNECT!"
                        MOUNT_OPTIONS=$(echo "$MOUNT_OPTIONS" | sed "s/\<nconnect\>=$value/nconnect=$OPTIMAL_SERVER_SIDE_NCONNECT/g")
                    fi
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
        #
        # TODO: Change this when we start supporting rsize as a valid option.
        #
        if [ "$USING_AZNFSCLIENT" == true ]; then
            wecho "Cannot use rsize with turbo. The value provided in config file will be used."
        else
            value="${BASH_REMATCH[1]}"
            if [ $value -ne 1048576 ]; then
                pecho "Suboptimal rsize=$value mount option, setting rsize=1048576!"
                MOUNT_OPTIONS=$(echo "$MOUNT_OPTIONS" | sed "s/\<rsize\>=$value/rsize=1048576/g")
            fi
        fi
    fi

    matchstr="\<wsize\>=([0-9]+)"
    if [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
        #
        # TODO: Change this when we start supporting wsize as a valid option.
        #
        if [ "$USING_AZNFSCLIENT" == true ]; then
            wecho "Cannot use wsize with turbo. The value provided in config file will be used."
        else
            value="${BASH_REMATCH[1]}"
            if [ $value -ne 1048576 ]; then
                pecho "Suboptimal wsize=$value mount option, setting wsize=1048576!"
                MOUNT_OPTIONS=$(echo "$MOUNT_OPTIONS" | sed "s/\<wsize\>=$value/wsize=1048576/g")
            fi
        fi
    fi

    matchstr="\<retrans\>=([0-9]+)"
    if ! [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
        if [ "$USING_AZNFSCLIENT" != true ]; then
            vvecho "Adding retrans=6 mount option!"
            MOUNT_OPTIONS="$MOUNT_OPTIONS,retrans=6"
        fi
    else
        if [ "$USING_AZNFSCLIENT" == true ]; then
            wecho "Cannot use retrans with turbo. The value provided in config file will be used."
        else
            value="${BASH_REMATCH[1]}"
            if [ $value -lt 6 ]; then
                pecho "Suboptimal retrans=$value mount option, setting retrans=6!"
                MOUNT_OPTIONS=$(echo "$MOUNT_OPTIONS" | sed "s/\<retrans\>=$value/retrans=6/g")
            fi
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
    
    #
    # configfile is a turbo only option. If the user is using turbo but has not provided 
    # a config file, the default file created in OPT_DIR should be used. The user first
    # needs to refer the sample-turbo-config.yaml file in OPTDIR and create their own copy
    # at: $OPTDIRDATA/turbo-config.yaml
    #
    config_file_path=
    matchstr="(^|,)configfile=([^,]+)"
    if [[ "$MOUNT_OPTIONS" =~ $matchstr ]]; then
            if [ "$USING_AZNFSCLIENT" != true ]; then
                eecho "configfile option can only be used with the turbo mount option!"
                exit 1
            else
                config_file_path="${BASH_REMATCH[2]}"
            fi
    fi

    if [ "$USING_AZNFSCLIENT" == true ]; then
        if [ -z "$config_file_path" ] || [ ! -f "$config_file_path" ]; then
            #
            # If user has explicitly specified a config file, bail out if we
            # cannot use it.
            #
            if [ -n "$config_file_path" ]; then
                eecho "Config file not found or not a regular file: $config_file_path"
                exit 1
            fi
            if [ ! -f "$CONFIG_FILE_PATH" ]; then
                echo
                wecho "***************************************************************************"
                wecho "No config file provided and default config file $CONFIG_FILE_PATH"
                wecho "not found. Using sample config from $SAMPLE_CONFIG_PATH."
                wecho "This will work with default settings but you might want to provide your own config using"
                wecho "configfile=/path/to/your/config.yaml mount option, or create a global config at"
                wecho "$CONFIG_FILE_PATH!"
                wecho "Refer to the sample config file $SAMPLE_CONFIG_PATH."
                wecho "***************************************************************************"
                echo
                CONFIG_FILE_PATH=$SAMPLE_CONFIG_PATH
            else
                vvecho "Using default config file: $CONFIG_FILE_PATH"
            fi
        else
            vvecho "Using config file: $config_file_path"
            CONFIG_FILE_PATH=$config_file_path
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
    
    vecho "[DEBUG] resolve_ipv4_with_preference_to_mountmapv3: fqdn=$fqdn"
    vecho "[DEBUG] resolve_ipv4_with_preference_to_mountmapv3: Checking MOUNTMAPv3=$MOUNTMAPv3"

    exec {fd}<$MOUNTMAPv3
    flock -e $fd

    local mountmap_entry=$(grep -m1 "^${fqdn} " $MOUNTMAPv3)
    
    flock -u $fd
    exec {fd}<&-

    IFS=" " read _ local_ip old_nfs_ip <<< "$mountmap_entry"
    if [ -n "$old_nfs_ip" ]; then
        vecho "[DEBUG] resolve_ipv4_with_preference_to_mountmapv3: Found in mountmap: $old_nfs_ip"
        echo "$old_nfs_ip"
        return 2 
    fi

    vecho "[DEBUG] resolve_ipv4_with_preference_to_mountmapv3: Not in mountmap, resolving via DNS"
    #
    # Resolve FQDN to IPv4 using DNS if not found in the mountmap.
    #
    resolve_ipv4 "$fqdn" "true"
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
    local used_local_ips_with_same_prefix=$(cat $MOUNTMAPv3 | awk '{print $2}' | grep "^${initial_ip_prefix}\." | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n)
    local iptable_entries=$(iptables-save -t nat)

    _3rdoctet=100
    ip_prefix=$initial_ip_prefix

    #
    # Optimize the process to get free local IP by starting the loop to choose
    # 3rd and 4th octet from the number which was used last and still exist in
    # MOUNTMAPv3 instead of starting it from 100.
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
                ip_prefix="${initial_ip_prefix}.$_3rdoctet"

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
        # Add this entry to MOUNTMAPv3 while we have the MOUNTMAPv3 lock.
        # This is to avoid assigning same local ip to parallel mount requests
        # for different endpoints.
        # ensure_mountmapv3_exist will also create a matching iptable DNAT rule.
        #
        LOCAL_IP=$local_ip
        ensure_mountmapv3_exist_nolock "$nfs_host $LOCAL_IP $nfs_ip"

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
            touch_mountmapv3

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
        get_free_local_ip
}

#
# Perform a pseudo mount to generate a gatepass for the actual mount call.
# This request is expected to fail with "server access denied" if server-side changes are enabled,
# or with "no such file or directory" if not. Failure of this call is expected behavior, 
# and we proceed normally when it occurs.
#
gatepass_mount()
{
    #
    # We use the Linux NFS client for doing the gatepass mount, even if user
    # may have asked for turbo mount. This is ok as NFS client is a requirement
    # for the AZNFS package.
    # Also, ignore MOUNT_OPTIONS as this is not a real mount and options like
    # "turbo" may cause the mount command to bail out w/o attempting the mount.
    # We do not use LOCAL_IP for mounting as for the turbo case we wouldn't have
    # a valid LOCAL_IP.
    #
    mount_output=$(mount -t nfs $OPTIONS -o vers=3,sec=sys,nolock,proto=tcp "${nfs_host}:${nfs_dir}/$AZNFS_FINGERPRINT" "$mount_point" 2>&1)
    mount_status=$?

    if [ -n "$mount_output" ]; then
        vvecho "[Gatepass mount] $mount_output"
    fi

    #
    # Ensure that gatepass mount operation failed (expected behavior).
    # Exit with an error code if it succeeded, which is unexpected.
    #
    if [ $mount_status -eq 0 ]; then
        eecho "[Gatepass mount] Unexpected success!"
        eecho "Mount failed!"
        exit 1
    fi
}

actual_mount()
{
    vecho "[DEBUG] ===== actual_mount ====="
    vecho "[DEBUG] actual_mount: LOCAL_IP=$LOCAL_IP, nfs_dir=$nfs_dir, mount_point=$mount_point"
    vecho "[DEBUG] actual_mount: MOUNT_OPTIONS=$MOUNT_OPTIONS"
    vecho "[DEBUG] actual_mount: OPTIONS=$OPTIONS"
    mount_output=$(mount -t nfs $OPTIONS -o "$MOUNT_OPTIONS" "${LOCAL_IP}:${nfs_dir}" "$mount_point" 2>&1)
    mount_status=$?
    vecho "[DEBUG] actual_mount: mount exit status=$mount_status"

    if [ -n "$mount_output" ]; then
        pecho "$mount_output"
    fi

    return $mount_status
}

#
# Parses the MOUNT_OPTIONS string into aznfsclient arguments.
#
create_aznfsclient_mount_args()
{
    vecho "[DEBUG] ===== create_aznfsclient_mount_args ====="
    vecho "[DEBUG] create_aznfsclient_mount_args: CONFIG_FILE_PATH=$CONFIG_FILE_PATH"
    vecho "[DEBUG] create_aznfsclient_mount_args: nfs_host=$nfs_host, nfs_dir=$nfs_dir"
    args="--config-file=$CONFIG_FILE_PATH"

    # Add account, container and cloud_suffix
    if [ -n "$nfs_dir" ] && [ -n "$nfs_host" ]; then
        account=$(echo "$nfs_host" | cut -d'.' -f1)
        args="$args --account=$account"
        vecho "[DEBUG] create_aznfsclient_mount_args: account=$account"
        container=$(echo "$nfs_dir" | awk -F'/' '{print $3}')
        args="$args --container=$container"
        vecho "[DEBUG] create_aznfsclient_mount_args: container=$container"
        cloud_suffix="${nfs_host#*.}"
        args="$args --cloud-suffix=$cloud_suffix"
        vecho "[DEBUG] create_aznfsclient_mount_args: cloud_suffix=$cloud_suffix"
    fi

    # Add nconnect value
    nconnect=$(echo "$MOUNT_OPTIONS" | grep -o 'nconnect=[^,]*' | cut -d'=' -f2)
    if [ -n "$nconnect" ]; then
        args="$args --nconnect=$nconnect"
        vecho "[DEBUG] create_aznfsclient_mount_args: nconnect=$nconnect"
    fi

    # Add port value
    port=$(echo "$MOUNT_OPTIONS" | grep -o 'port=[^,]*' | cut -d'=' -f2)
    if [ -n "$port" ]; then
        args="$args --port=$port"
        vecho "[DEBUG] create_aznfsclient_mount_args: port=$port"
    fi

    # Note: For EIT (Encryption In Transit), the turbo client will read
    # eit.stls from the config file. The mount script sets up stunnel
    # infrastructure before calling aznfsclient when AZNFS_STLS_V3=1.

    # Finally add the mount point.
    AZNFSCLIENT_MOUNT_ARGS="$args $mount_point"
    vecho "[DEBUG] create_aznfsclient_mount_args: Final args: $AZNFSCLIENT_MOUNT_ARGS"

    turbo_log=$AZNFSC_LOGDIR/turbo$(echo $mount_point | tr -s "/" "_").log
    if [ ! -f $turbo_log ]; then
        touch $turbo_log
        if [ $? -ne 0 ]; then
            eecho "[FATAL] Not able to create '${turbo_log}'!"
            eecho "Mount failed!"
            exit 1
        fi
    fi

    #
    # Turbo mount uses different log file for each mount.
    # All logs from here on will come in that log file.
    #
    LOGFILE=$turbo_log
}

#
# Parses the MOUNT_OPTIONS into aznfsclient args string and calls the 
# turbo client. The client ensures it always prioritizes the option values
# provided as part of the mount command instead of the config file.
#
# TODO: Add debug support.
#
aznfsclient_mount()
{   
    vecho "[DEBUG] ===== aznfsclient_mount ====="
    vecho "[DEBUG] aznfsclient_mount: AZNFSCLIENT_BINARY_PATH=$AZNFSCLIENT_BINARY_PATH"
    create_aznfsclient_mount_args

    # Create named pipe to hold mount status from aznfsclient.
    if [ -d /run ]; then
        export MOUNT_STATUS_PIPE="/run/mount_status_pipe.$$"
    else
        export MOUNT_STATUS_PIPE="/tmp/mount_status_pipe.$$"
    fi
    vecho "[DEBUG] aznfsclient_mount: MOUNT_STATUS_PIPE=$MOUNT_STATUS_PIPE"

    rm -f $MOUNT_STATUS_PIPE
    mkfifo $MOUNT_STATUS_PIPE

    if [ ! -p "$MOUNT_STATUS_PIPE" ]; then
        eecho "Unable to create status pipe!"
        return 1
    fi

    #
    # Get the gatepass before the actual mount.
    #
    vecho "[DEBUG] aznfsclient_mount: Calling gatepass_mount"
    gatepass_mount
    vecho "[DEBUG] aznfsclient_mount: Gatepass acquired"
    vecho "fuse command: $AZNFSCLIENT_BINARY_PATH $AZNFSCLIENT_MOUNT_ARGS -f"
    vvecho "Using log file $LOGFILE"

    #
    # We append to the logfile w/o any support for re-opening log file for
    # log rotation. Use copytruncate option in logrotate config.
    # Redirect stderr too for capturing assert/asan failures.
    #
    vecho "[DEBUG] aznfsclient_mount: Starting aznfsclient process"
    $AZNFSCLIENT_BINARY_PATH $AZNFSCLIENT_MOUNT_ARGS -f >> $LOGFILE 2>&1 &

    vvecho "Waiting for mount to complete (timeout: 30 seconds)..."

    #
    # Read from named pipe with timeout.
    # aznfsclient will send an integer status followed by an optional error string.
    #
    vecho "[DEBUG] aznfsclient_mount: Reading mount status from pipe"
    read -t 30 mount_status mount_str <> $MOUNT_STATUS_PIPE

    read_status=$?
    vecho "[DEBUG] aznfsclient_mount: read_status=$read_status, mount_status=$mount_status"

    # Delete the pipe because this is the only reader.
    rm -f $MOUNT_STATUS_PIPE

    #
    # Check the exit status to determine if it timed out.
    # If it's not timed out the client should have sent either "0"
    # indicating success or one of the following -ve values indicating failure:
    # -2 -> auth enabled in config but "az login" not found.
    # -1 -> some other error in mounting.
    # 
    if [ $read_status -gt 128 ]; then
        eecho "Mount timed out, check $LOGFILE for details!"
        return $read_status
    elif [ "$mount_status" == "-2" ]; then
        eecho "Auth enabled in config but 'az login' not detected"
        eecho "Please perform 'az login' and then try to mount again!"
        eecho "Check $LOGFILE for details!"
        return 1
    elif [ "$mount_status" != "0" ]; then
        if [ -n "$mount_str" ]; then
            eecho "$mount_str"
        else
            eecho "Mount failed with status $mount_status, check $LOGFILE for details!"
        fi
        return 1
    else
        vvecho "Mounted successfully."
    fi
}


# Helper function to get check_host value from hostname
get_check_host_value() {
    local hostname="$1"
    # Extract storage account name from hostname
    local account_name=$(echo "$hostname" | cut -d'.' -f1)
    echo "$account_name"
}

# Get certificate path and update command based on distribution
get_cert_path_based_and_command()
{
    vecho "[DEBUG] get_cert_path_based_and_command: isDebian=$isDebian, isRedHat=$isRedHat, isSUSE=$isSUSE"
    if [ $isDebian -eq 1 ]; then
        CERT_PATH="/usr/local/share/ca-certificates"
        CERT_UPDATE_COMMAND="update-ca-certificates"
        vecho "[DEBUG] Debian path: CERT_PATH=$CERT_PATH"
    elif [ $isRedHat -eq 1 ]; then
        CERT_PATH="/etc/pki/ca-trust/source/anchors"
        CERT_UPDATE_COMMAND="update-ca-trust extract"
        vecho "[DEBUG] RedHat path: CERT_PATH=$CERT_PATH"
        mkdir -p /etc/ssl/certs
        if [ $? -ne 0 ]; then
            eecho "[FATAL] Not able to create /etc/ssl/certs path for certificate!"
            return 1
        fi
    elif [ $isSUSE -eq 1 ]; then
        CERT_PATH="/etc/pki/trust/anchors"
        CERT_UPDATE_COMMAND="update-ca-certificates"
    fi

    STUNNEL_CAFILE="/etc/ssl/certs/DigiCert_Global_Root_G2.pem"
}

# Extract CA certificate for RedHat-based systems
extract_CA()
{
    vecho "[DEBUG] extract_CA: Extracting DigiCert Global Root G2 from /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
    vecho "[DEBUG] extract_CA: Target file: $STUNNEL_CAFILE"
    awk '/DigiCert Global Root G2/ {found=1} found && /BEGIN CERTIFICATE/,/END CERTIFICATE/ {print > "'$STUNNEL_CAFILE'"} found && /END CERTIFICATE/ {exit}' /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
    if [ $? -ne 0 ]; then
        eecho "[FATAL] Failed to extract DigiCert Global Root G2 certificate from /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem!"
        return 1
    fi
    vecho "[DEBUG] extract_CA: Certificate extracted successfully"
}

# Compare CA certificate thumbprint
compare_CA_thumbprint()
{
    vecho "[DEBUG] compare_CA_thumbprint: Comparing certificate thumbprints"
    local thumbprint=$(openssl x509 -in $STUNNEL_CAFILE -noout -fingerprint 2>/dev/null | cut -d'=' -f2)
    vecho "[DEBUG] compare_CA_thumbprint: Installed thumbprint: $thumbprint"
    local expected_thumbprint=$(awk '/DigiCert Global Root G2/ {found=1} found && /BEGIN CERTIFICATE/,/END CERTIFICATE/ {print} found && /END CERTIFICATE/ {exit}' /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem | openssl x509 -noout -fingerprint -sha1 2>/dev/null | cut -d'=' -f2)
    vecho "[DEBUG] compare_CA_thumbprint: Expected thumbprint: $expected_thumbprint"

    vecho "Comparing the thumbprint of the installed DigiCert Global Root G2 certificate. Expected: ${expected_thumbprint}, Installed: ${thumbprint}."

    if [ "$thumbprint" != "$expected_thumbprint" ]; then
        vecho "[DEBUG] compare_CA_thumbprint: Thumbprints DO NOT match"
        return 1
    fi
    vecho "[DEBUG] compare_CA_thumbprint: Thumbprints match"
}

# Install CA certificate
install_CA_cert()
{
    vecho "[DEBUG] ===== install_CA_cert ====="
    vecho "[DEBUG] install_CA_cert: isRedHat=$isRedHat, isDebian=$isDebian, isSUSE=$isSUSE"
    vecho "[DEBUG] install_CA_cert: CERT_PATH=$CERT_PATH, STUNNEL_CAFILE=$STUNNEL_CAFILE"
    # For Debian-based and SUSE-based distributions, if the cert exits, it's in /etc/ssl/certs/DigiCert_Global_Root_G2.pem. For RedHat-based distributions, it's' in /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem.
    if [ $isRedHat -eq 1 ]; then
        vecho "[DEBUG] install_CA_cert: RedHat system, checking CA bundle"
        # If certificate already exists in the system, extract it and return.
        grep -q "DigiCert Global Root G2" /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
        if [ $? -eq 0 ]; then
            vecho "[DEBUG] install_CA_cert: Certificate found in CA bundle"
            vecho "DigiCert Global Root G2 certificate already exists. Extranting it to ${STUNNEL_CAFILE}."
            if ! extract_CA; then
                return 1
            fi
            return 0
        fi
    else
        vecho "[DEBUG] install_CA_cert: Debian/SUSE system, checking /etc/ssl/certs"
        if [ -f /etc/ssl/certs/DigiCert_Global_Root_G2.pem ]; then
            vecho "[DEBUG] install_CA_cert: Certificate already exists in /etc/ssl/certs"
            vecho "DigiCert Global Root G2 certificate already exists in /etc/ssl/certs. No need to install it again."
            return 0
        fi
    fi

    vecho "[DEBUG] install_CA_cert: Downloading certificate from DigiCert"
    vecho "[DEBUG] install_CA_cert: URL: https://cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem"
    vecho "[DEBUG] install_CA_cert: Destination: ${CERT_PATH}/DigiCert_Global_Root_G2.crt"
    wget_error=$(wget https://cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem --no-check-certificate -O ${CERT_PATH}/DigiCert_Global_Root_G2.crt 2>&1)
    if [ $? -ne 0 ]; then
        eecho "[FATAL] Not able to download DigiCert_Global_Root_G2 certificate from https://cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem! Error: ${wget_error}"
        return 1
    fi
    vecho "[DEBUG] install_CA_cert: Certificate downloaded successfully"

    vecho "[DEBUG] install_CA_cert: Running certificate update command: $CERT_UPDATE_COMMAND"
    $CERT_UPDATE_COMMAND
    vecho "[DEBUG] install_CA_cert: Certificate update command completed"

    # In RedHat-based distributions, we need to extract the certificate to /etc/ssl/certs for stunnel to pick it up.
    if [ $isRedHat -eq 1 ]; then
        if ! extract_CA; then
            return 1
        fi
    fi

    vecho "Successfully installed DigiCert_Global_Root_G2 certificate to ${CERT_PATH}/DigiCert_Global_Root_G2.crt."
}

# Helper function to read YAML config values
get_cfg_for_mount() {
    local key="$1"
    local config_file="${CONFIG_FILE_PATH}"
    
    vecho "[DEBUG] get_cfg_for_mount: key='$key', config_file='$config_file'"
    
    if [ ! -f "$config_file" ]; then
        vecho "[DEBUG] get_cfg_for_mount: Config file does not exist"
        echo ""
        return
    fi
    
    # Try using yq if available
    if command -v yq >/dev/null 2>&1; then
        yq eval ".${key}" "$config_file" 2>/dev/null | grep -v "^null$"
        return
    fi
    
    # Fallback to python if available
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import yaml; import sys; 
try:
    with open('$config_file') as f: 
        data = yaml.safe_load(f)
        keys = '$key'.split('.')
        val = data
        for k in keys:
            val = val.get(k, None) if isinstance(val, dict) else None
            if val is None: break
        if val is not None: print(val)
except: pass" 2>/dev/null
        return
    fi
    
    # Simple grep-based fallback for simple keys
    grep "^${key}:" "$config_file" 2>/dev/null | head -1 | awk '{print $2}'
}

make_stunnel_conf_v3() {
  local account_ip="$1"   # resolved BlobNFS endpoint IP
  local hostname="$2"     # hostname for certificate verification
  local tlsver="${stls_tls_version:-TLSv1.3}"
  local cipher="${stls_cipher_suite:-DEFAULT@SECLEVEL=2}"
  # Use high ports to avoid conflicts with system services (rpcbind on 111, nfsd on 2048)
  local rpc_local="${stls_rpc_local:-50111}"
  local nfs_local="${stls_nfs_local:-52048}"
  local conf="${STUNNEL_V3_DIR}/${account_ip}.conf"
  
  vecho "[DEBUG] ===== make_stunnel_conf_v3 ====="
  vecho "[DEBUG] account_ip=$account_ip, hostname=$hostname"
  vecho "[DEBUG] TLS version=$tlsver, cipher=$cipher"
  vecho "[DEBUG] Ports: rpc_local=$rpc_local, nfs_local=$nfs_local"
  vecho "[DEBUG] Config file: $conf"

  # Get certificate paths and validate
  vecho "[DEBUG] Getting certificate paths..."
  if ! get_cert_path_based_and_command; then
      eecho "[FATAL] Failed to get certificate paths"
      return 1
  fi
  vecho "[DEBUG] Certificate paths: STUNNEL_CAFILE=$STUNNEL_CAFILE, CERT_PATH=$CERT_PATH"

  if [ ! -f $STUNNEL_CAFILE ]; then
      vecho "[DEBUG] CA root cert missing: $STUNNEL_CAFILE"
      vecho "CA root cert is missing for stunnel configuration. Install or extract DigiCert_Global_Root_G2 certificate."
      install_CA_cert
      if [ $? -ne 0 ]; then
          eecho "[FATAL] Not able to install DigiCert_Global_Root_G2 certificate!"
          return 1
      fi
      vecho "[DEBUG] Certificate installation completed"
  else
      vecho "[DEBUG] CA cert exists: $STUNNEL_CAFILE"
      vecho "DigiCert_Global_Root_G2 certificate already exists in $STUNNEL_CAFILE."
      # Since the certificate is extracted from the system's CA bundle, we need to compare the thumbprint of the installed certificate with the expected value.
      if [ $isRedHat -eq 1 ]; then
          if ! compare_CA_thumbprint; then
              vecho "Thumbprint of the installed DigiCert Global Root G2 certificate does not match the expected value! Extracting the certificate again."
              rm -f $STUNNEL_CAFILE
              install_CA_cert
              if [ $? -ne 0 ]; then
                  eecho "[FATAL] Not able to install DigiCert_Global_Root_G2 certificate!"
                  return 1
              fi
          fi
      fi
  fi

  # Get checkHost value from hostname
  local stunnel_check_host=$(get_check_host_value "$hostname")
  vecho "[DEBUG] stunnel checkHost value: $stunnel_check_host"

  # For Mariner linux, we need to add ciphers = DEFAULT
  local distro_id=
  if [ -f /etc/os-release ]; then
      distro_id=$(grep "^ID=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
      distro_id=$(canonicalize_distro_id $distro_id)
  fi

  vecho "[DEBUG] Writing stunnel configuration to $conf..."
  cat > "${conf}" <<EOF
# Auto-generated by AZNFS nfsv3 script
CAFile = $STUNNEL_CAFILE
verifyChain = yes
checkHost = $stunnel_check_host
debug = $DEBUG_LEVEL
output = ${STUNNEL_V3_LOG_DIR}/${account_ip}.log
pid = ${STUNNEL_V3_LOG_DIR}/${account_ip}.pid
TIMEOUTidle = $stunnel_timeout_idle

# rpcbind (111)
[nfs3-rpcbind]
client = yes
accept = 127.0.0.1:${rpc_local}
connect = ${account_ip}:111
sslVersion = ${tlsver}
EOF

  if [ "$distro_id" == "azurelinux" ]; then
      echo "ciphers = DEFAULT" >> "${conf}"
  else
      echo "ciphers = ${cipher}" >> "${conf}"
  fi

  cat >> "${conf}" <<EOF
TIMEOUTclose = 0

# nfsd (2048)
[nfs3-nfsd]
client = yes
accept = 127.0.0.1:${nfs_local}
connect = ${account_ip}:2048
sslVersion = ${tlsver}
EOF

  if [ "$distro_id" == "azurelinux" ]; then
      echo "ciphers = DEFAULT" >> "${conf}"
  else
      echo "ciphers = ${cipher}" >> "${conf}"
  fi

  echo "TIMEOUTclose = 0" >> "${conf}"

  vecho "[DEBUG] Stunnel configuration written successfully: $conf"
  echo "${conf}"
}

ensure_stunnel_v3() {
  local account_ip="$1"
  local hostname="$2"
  
  vecho "[DEBUG] ===== ensure_stunnel_v3 ====="
  vecho "[DEBUG] account_ip=$account_ip, hostname=$hostname"
  
  local conf="$(make_stunnel_conf_v3 "${account_ip}" "${hostname}")"
  
  if [ -z "$conf" ] || [ ! -f "$conf" ]; then
      eecho "[FATAL] Failed to create stunnel configuration file! conf='$conf'"
      return 1
  fi
  
  vecho "[DEBUG] Stunnel config file created: $conf"
  
  local pid_file="${STUNNEL_V3_LOG_DIR}/${account_ip}.pid"
  
  vecho "[DEBUG] Checking for existing stunnel process: $pid_file"
  # Check if stunnel is already running for this config
  if [ -f "$pid_file" ]; then
      local pid=$(cat "$pid_file")
      vecho "[DEBUG] Found PID file with PID: $pid"
      if kill -0 "$pid" 2>/dev/null; then
          vecho "[DEBUG] Stunnel already running for $account_ip with PID $pid"
          vecho "Stunnel already running for $account_ip with PID $pid"
          return 0
      else
          vecho "[DEBUG] Stale PID file found, cleaning up"
          vecho "Stale PID file found, cleaning up"
          rm -f "$pid_file"
      fi
  else
      vecho "[DEBUG] No existing stunnel process found"
  fi
  
  # Start stunnel
  vecho "[DEBUG] ===== STARTING STUNNEL PROCESS ====="
  vecho "[DEBUG] Command: stunnel ${conf}"
  vecho "Starting stunnel for $account_ip using config $conf"
  stunnel_status=$(stunnel "${conf}" 2>&1)
  stunnel_exit=$?
  if [ $stunnel_exit -ne 0 ]; then
      eecho "[FATAL] Failed to start stunnel (exit code: $stunnel_exit)"
      eecho "[FATAL] Stunnel output: $stunnel_status"
      return 1
  fi
  vecho "[DEBUG] Stunnel started successfully"
  vecho "[DEBUG] Stunnel output: $stunnel_status"
  
  # Setup iptables DNAT rules to redirect traffic to stunnel
  vecho "[DEBUG] Setting up iptables DNAT rules"
  wire_dnat_to_local_stunnel_v3 "${account_ip}"
}

wire_dnat_to_local_stunnel_v3() {
  local account_ip="$1"
  # Must match the ports used in make_stunnel_conf_v3
  local rpc_local="${stls_rpc_local:-50111}"
  local nfs_local="${stls_nfs_local:-52048}"
  # Start stunnel
  vecho "[DEBUG] ===== STARTING STUNNEL PROCESS ====="
  vecho "[DEBUG] Command: stunnel ${conf}"
  vecho "Starting stunnel for $account_ip using config $conf"
  stunnel_status=$(stunnel "${conf}" 2>&1)
  stunnel_exit=$?
  if [ $stunnel_exit -ne 0 ]; then
      eecho "[FATAL] Failed to start stunnel (exit code: $stunnel_exit)"
      eecho "[FATAL] Stunnel output: $stunnel_status"
      return 1
  fi
  vecho "[DEBUG] Stunnel started successfully"
  vecho "[DEBUG] Stunnel output: $stunnel_status"
  
  # Verify stunnel started successfully
  sleep 1
  if [ -f "$pid_file" ]; then
      local pid=$(cat "$pid_file")
      if kill -0 "$pid" 2>/dev/null; then
          vecho "Stunnel started successfully with PID $pid"
          return 0
      fi
  fi
  
  eecho "[FATAL] Stunnel failed to start properly"
  return 1
}

wire_dnat_to_local_stunnel_v3() {
  local proxy_ip="$1"     # the AZNFS proxy IP picked for BlobNFS
  local rpc_local="${stls_rpc_local:-111}"
  local nfs_local="${stls_nfs_local:-2048}"

  # Redirect BlobNFS ports to local stunnel listeners
  iptables -t nat -A OUTPUT -p tcp -d "${proxy_ip}" --dport 111  -j DNAT --to-destination 127.0.0.1:${rpc_local}
  iptables -t nat -A OUTPUT -p tcp -d "${proxy_ip}" --dport 2048 -j DNAT --to-destination 127.0.0.1:${nfs_local}
}


# Check if aznfswatchdog service is running.
if ! ensure_aznfswatchdog "aznfswatchdog"; then
    exit 1
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

# Check if we're on a Debian-based, RedHat-based, or SUSE-based distribution
# This must be done before turbo mount as well, in case TLS is enabled
vecho "[DEBUG] Detecting distribution type..."
if command -v apt-get &> /dev/null; then
    isDebian=1
    vecho "[DEBUG] Distribution: Debian-based (isDebian=1)"
elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
    isRedHat=1
    vecho "[DEBUG] Distribution: RedHat-based (isRedHat=1)"
elif command -v zypper &> /dev/null; then
    isSUSE=1
    vecho "[DEBUG] Distribution: SUSE-based (isSUSE=1)"
else
    vecho "[DEBUG] Distribution: Unknown"
    if [ "${AZNFS_STLS_V3}" = "1" ]; then
        eecho "[FATAL] Unsupported distribution for TLS mount!"
        exit 1
    fi
fi

#
# If this is a nfs turbo mount, we need to setup stunnel (if EIT enabled) before calling the binary.
#
vecho "[DEBUG] Checking turbo mount: USING_AZNFSCLIENT='$USING_AZNFSCLIENT', AZNFS_STLS_V3='$AZNFS_STLS_V3'"
if [ "$USING_AZNFSCLIENT" == true ]; then
    vecho "[DEBUG] ===== ENTERING TURBO MOUNT PATH ====="
    # Resolve the IP address for the NFS host
    vecho "[DEBUG] Resolving IP for $nfs_host..."
    nfs_ip=$(resolve_ipv4_with_preference_to_mountmapv3 "$nfs_host")
    status=$?
    if [ $status -ne 0 ]; then
        if [ $status -eq 2 ]; then
            vecho "[DEBUG] Resolved IP address for FQDN from mountmap [$nfs_host -> $nfs_ip]"
        else
            echo "$nfs_ip"
            eecho "Cannot resolve IP address for ${nfs_host}!"
            eecho "Mount failed!"
            exit 1
        fi
    else
        vecho "[DEBUG] Resolved IP: $nfs_host -> $nfs_ip"
    fi

    # Check for EIT configuration from mount options or config file
    vecho "[DEBUG] ===== CHECKING EIT CONFIGURATION ====="
    vecho "[DEBUG] AZNFS_STLS_V3='${AZNFS_STLS_V3}'"
    if [ "${AZNFS_STLS_V3}" = "1" ]; then
        vecho "[DEBUG] ===== EIT ENABLED - SETTING UP STUNNEL ====="
        vecho "NFSv3 turbo mount with EIT (stunnel-based encryption) enabled"
        
        # Check for TLS version in mount options
        vecho "[DEBUG] Checking for TLS version in mount options..."
        if [[ "$MOUNT_OPTIONS" == *"tls="* ]]; then
            ssl_version=$(echo "$MOUNT_OPTIONS" | grep -oE 'tls=[^,]+' | awk -F= '{print $2}')
            vecho "[DEBUG] Found tls option: $ssl_version"
            
            # Check if SSL version is either 1.2 or 1.3
            if [[ "$ssl_version" == "1.2" || "$ssl_version" == "1.3" ]]; then
                vecho "[DEBUG] Valid TLS version: $ssl_version"
                stls_tls_version="TLSv${ssl_version}"
            else
                eecho "No valid TLS version. Please provide a valid TLS version (1.2 or 1.3)."
                exit 1
            fi
            
            # Remove the tls option from MOUNT_OPTIONS
            if [[ "$MOUNT_OPTIONS" == *"tls=${ssl_version},"* ]]; then
                MOUNT_OPTIONS=${MOUNT_OPTIONS//tls=$ssl_version,/}
            else
                MOUNT_OPTIONS=${MOUNT_OPTIONS//,tls=$ssl_version/}
            fi
        fi
        
        # Derive TLS config from config file if not set via mount options
        vecho "[DEBUG] Reading TLS config from config file..."
        if [ -z "$stls_tls_version" ]; then
            stls_tls_version="$(get_cfg_for_mount 'stls_tls_version')"
            vecho "[DEBUG] Config file stls_tls_version: '$stls_tls_version'"
        fi
        stls_cipher_suite="$(get_cfg_for_mount 'stls_cipher_suite')"
        vecho "[DEBUG] Config file stls_cipher_suite: '$stls_cipher_suite'"
        stls_rpc_local="$(get_cfg_for_mount 'stls_local_ports.rpcbind')"
        vecho "[DEBUG] Config file stls_rpc_local: '$stls_rpc_local'"
        stls_nfs_local="$(get_cfg_for_mount 'stls_local_ports.nfsd')"
        vecho "[DEBUG] Config file stls_nfs_local: '$stls_nfs_local'"
        
        # Set default TLS version if not specified
        if [ -z "$stls_tls_version" ]; then
            stls_tls_version="TLSv1.3"
            vecho "[DEBUG] Using default TLS version: $stls_tls_version"
        fi
        
        vecho "[DEBUG] Final TLS config: version=$stls_tls_version, cipher=$stls_cipher_suite, rpc_port=$stls_rpc_local, nfs_port=$stls_nfs_local"
        vecho "Setting up stunnel infrastructure for turbo mount with TLS version: $stls_tls_version"
        
        # Setup stunnel for turbo mount
        vecho "[DEBUG] ===== CALLING ensure_stunnel_v3 ====="
        vecho "[DEBUG] Arguments: nfs_ip=$nfs_ip, nfs_host=$nfs_host"
        ensure_stunnel_v3 "${nfs_ip}" "${nfs_host}"
        stunnel_result=$?
        if [ $stunnel_result -ne 0 ]; then
            eecho "[FATAL] Failed to setup stunnel for EIT mount (exit code: $stunnel_result)"
            exit 1
        fi
        
        vecho "[DEBUG] ===== STUNNEL SETUP COMPLETE ====="
        vecho "Stunnel infrastructure ready for turbo mount"
        
        # Note: For turbo mounts, the aznfsclient will connect to the actual
        # NFS server IP directly, but the mount script has set up stunnel
        # which will handle encryption. The aznfsclient reads eit_stls: true
        # from config and uses the stunnel setup.
    fi
    
    vecho "[DEBUG] ===== CALLING aznfsclient_mount ====="
    aznfsclient_mount
    if [ $? -ne 0 ]; then
        eecho "Aznfsclient mount failed!"
        exit 1
    fi

    vecho "[DEBUG] ===== TURBO MOUNT COMPLETE ====="
    exit 0 # Nothing in this script will run after this point.
else
    vecho "[DEBUG] Not a turbo mount, continuing with regular NFSv3 mount"
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


# Setup TLS encryption for regular (non-turbo) NFSv3 mounts if enabled
if [ "${AZNFS_STLS_V3}" = "1" ]; then
  vecho "NFSv3 with TLS encryption enabled"
  
  # Check for TLS version in mount options
  if [[ "$MOUNT_OPTIONS" == *"tls="* ]]; then
      ssl_version=$(echo "$MOUNT_OPTIONS" | grep -oE 'tls=[^,]+' | awk -F= '{print $2}')
      
      # Check if SSL version is either 1.2 or 1.3
      if [[ "$ssl_version" == "1.2" || "$ssl_version" == "1.3" ]]; then
          vecho "TLS version option: $ssl_version"
          stls_tls_version="TLSv${ssl_version}"
      else
          eecho "No valid TLS version. Please provide a valid TLS version (1.2 or 1.3)."
          exit 1
      fi
      
      # Remove the tls option from MOUNT_OPTIONS
      if [[ "$MOUNT_OPTIONS" == *"tls=${ssl_version},"* ]]; then
          MOUNT_OPTIONS=${MOUNT_OPTIONS//tls=$ssl_version,/}
      else
          MOUNT_OPTIONS=${MOUNT_OPTIONS//,tls=$ssl_version/}
      fi
  fi
  
  # Derive per-mount overrides from TurboNFS config if present
  if [ -z "$stls_tls_version" ]; then
      stls_tls_version="$(get_cfg_for_mount 'stls_tls_version')"
  fi
  stls_cipher_suite="$(get_cfg_for_mount 'stls_cipher_suite')"
  stls_rpc_local="$(get_cfg_for_mount 'stls_local_ports.rpcbind')"
  stls_nfs_local="$(get_cfg_for_mount 'stls_local_ports.nfsd')"
  
  # Set default TLS version if not specified
  if [ -z "$stls_tls_version" ]; then
      stls_tls_version="TLSv1.3"
  fi
  
  vecho "Using TLS version: $stls_tls_version"
  
  # Check for mixed TLS and non-TLS mounts to same endpoint
  exec {fd_tls}<$MOUNTMAPv3
  flock -e $fd_tls
  
  # Check if there's an existing non-TLS mount to this endpoint
  if grep -q "^${nfs_ip};" $MOUNTMAPv3; then
      # Check if it's a TLS mount or not
      local existing_entry=$(grep "^${nfs_ip};" $MOUNTMAPv3 | head -1)
      if ! echo "$existing_entry" | grep -q "stls=1"; then
          eecho "Mount failed!"
          eecho "Mount to the same endpoint ${nfs_ip} exists without TLS. Cannot mount with TLS to the same endpoint."
          eecho "Try unmounting the share on ${nfs_host} and run the mount command again."
          flock -u $fd_tls
          exec {fd_tls}<&-
          exit 1
      fi
  fi
  
  flock -u $fd_tls
  exec {fd_tls}<&-

  ensure_stunnel_v3 "${nfs_ip}" "${nfs_host}"
  if [ $? -ne 0 ]; then
      eecho "Failed to setup stunnel for TLS mount"
      exit 1
  fi
  
  wire_dnat_to_local_stunnel_v3 "${LOCAL_IP}"
  
  # Mark this mount as TLS in mountmap for conflict detection
  # This will be added to mountmap along with other mount info
  export AZNFS_MOUNT_IS_TLS=1
else
  # current behavior (DNAT from proxy IP to endpoint IP)
  iptables -t nat -A OUTPUT -p tcp -d "${LOCAL_IP}" -j DNAT --to-destination "${nfs_ip}"
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
