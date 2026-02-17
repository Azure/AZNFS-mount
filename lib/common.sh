#! /bin/bash

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

APPNAME="aznfs"
OPTDIR="/opt/microsoft/${APPNAME}"
OPTDIRDATA="${OPTDIR}/data"
LOGFILE="${OPTDIRDATA}/${APPNAME}.log"
RANDBYTES="${OPTDIRDATA}/randbytes"
INSTALLSCRIPT="${OPTDIR}/aznfs_install.sh"

#
# This stores the map of local IP and share name and external blob endpoint IP.
#
MOUNTMAPv3="${OPTDIRDATA}/mountmap"

#
# This stores the map of hostname and stunnel conf, log, pid files paths.
#
MOUNTMAPv4="${OPTDIRDATA}/mountmapv4"

#
# This stores the map of local IP and share name an external file endpoint IP.
#
MOUNTMAPv4NONTLS="${OPTDIRDATA}/mountmapv4nontls"

RED="\e[2;31m"
GREEN="\e[2;32m"
YELLOW="\e[2;33m"
NORMAL="\e[0m"

HOSTNAME=$(hostname)

LOCALHOST="127.0.0.1"

# Determine the command to use for getting socket statistics: netstat or ss
NETSTATCOMMAND=""

if [ -z "$AZNFS_VERSION" ]; then
    echo '*** AZNFS_VERSION must be defined before including common.sh ***'
    exit 1
elif [ "$AZNFS_VERSION" == "unknown" ]; then
    prefix=""
else
    prefix="[v${AZNFS_VERSION}] "
fi

# Are we running inside the AKS?
AKS_USER="false"

RELEASE_NUMBER_FOR_AKS=x.y.z

#
# How often does the watchdog look for unmounts and/or IP address changes for
# Blob and nfs file endpoints.
#
MONITOR_INTERVAL_SECS=30

#
# ------------------ Common definitions from nfsv3mountscript.sh --------------------
# 

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
# Choose the local IP based on last used IP in MOUNTMAPv3 if this flag is enabled.
#
OPTIMIZE_GET_FREE_LOCAL_IP=true

#
# True if user has asked to use port 2047 using 'port=2047' mount option.
# This signifies server side nconnect which has some special needs.
#
USING_PORT_2047=false

_log()
{
    color=$1
    msg=$2

    echo -e "${color}${msg}${NORMAL}"
    (
        flock -e 999
        echo -e "${prefix}$(date -u +"%a %b %d %G %T.%3N") $HOSTNAME $$: ${color}${msg}${NORMAL}" >> $LOGFILE
    ) 999<$LOGFILE
}

#
# Plain echo with file logging.
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
# Verbose echo, only logs into LOGFILE unless AZNFS_VERBOSE env variable is set.
#
vecho()
{
    color=$NORMAL

    # Unless AZNFS_VERBOSE flag is set, do not echo to console.
    if [ -z "$AZNFS_VERBOSE" -o "$AZNFS_VERBOSE" == "0" ]; then
        (
            flock -e 999
            echo -e "${prefix}$(date -u +"%a %b %d %G %T.%3N") $HOSTNAME $$: ${color}${*}${NORMAL}" >> $LOGFILE
        ) 999<$LOGFILE

        return
    fi

    _log $color "${*}"
}

#
# Verbose echo, only logs into LOGFILE unless '-v' or '--verbose' option is provided.
#
vvecho()
{
    color=$NORMAL

    # Unless VERBOSE_MOUNT flag is set to true, do not echo to console.
    if [ "$VERBOSE_MOUNT" == false ]; then
        (
            flock -e 999
            echo -e "${prefix}$(date -u +"%a %b %d %G %T.%3N") $HOSTNAME $$: ${color}${*}${NORMAL}" >> $LOGFILE
        ) 999<$LOGFILE

        return
    fi

    _log $color "${*}"
}

#
# Check if system is booted with systemd as init.
#
systemd_is_init()
{
    init="$(ps -q 1 -o comm=)"
    [ "$init" == "systemd" ]
}

#
# Ensure aznfswatchdog service is running, if not bail out with an appropriate
# error.
#
ensure_aznfswatchdog()
{
    local process_name="$1"
    pidof -x "$process_name" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        if systemd_is_init; then
            eecho "$process_name service not running!"
            pecho "Start the $process_name service using 'systemctl start $process_name' and try again."
        else
            eecho "$process_name service not running, please make sure it's running and try again!"
        fi

        pecho "If the problem persists, contact Microsoft support."
        return 1
    fi
}

#
# Check if the given string is a valid IPv4 address.
#
is_valid_ipv4_address()
{
    [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] &&
    [ ${BASH_REMATCH[1]} -le 255 ] &&
    [ ${BASH_REMATCH[2]} -le 255 ] &&
    [ ${BASH_REMATCH[3]} -le 255 ] &&
    [ ${BASH_REMATCH[4]} -le 255 ]
}

#
# Check if the given string is a valid IPv4 prefix.
# 10, 10.10, 10.10.10, 10.10.10.10 are valid prefixes, while
# 1000, 10.256, 10. are not valid prefixes.
#
is_valid_ipv4_prefix()
{
    ip -4 route get $1 > /dev/null 2>&1
}

#
# Check if a given TCP port is reachable. Uses a 3 secs timeout to bail out if address/port is not reachable.
#
is_ip_port_reachable()
{
    local ip=$1;
    local port=$2;

    # 3 secs timeout should be good.
    nc -w 3 -z $ip $port > /dev/null 2>&1
}

#
# Verify if FQDN is resolved into IPv4 address by /etc/hosts entry.
#
is_present_in_etc_hosts() 
{
    local ip="$1"
    local hostname="$2"

    # Search for the entry in /etc/hosts
    grep -qE "^[[:space:]]*${ip}[[:space:]]+[^#]*\<${hostname}\>" /etc/hosts
}

#
# Blob fqdn to IPv4 adddress.
# Caller must make sure that it is called only for hostname and not IP address.
#
# Note: Since caller captures its o/p this should not log anything other than
#       the IP address, in case of success return.
#
resolve_ipv4()
{
    local hname="$1"
    local fail_if_present_in_etc_hosts="$2"
    local RETRIES=3

    # Some retries for resilience.
    for((i=0;i<=$RETRIES;i++)) {
        # Resolve hostname to IPv4 address.
        host_op=$(host -4 -t A "$hname" 2>&1)
        if [ $? -ne 0 ]; then
            #
            # Special case of failure to indicate that the fqdn does not exist.
            # We convey it to our caller using the special o/p "NXDOMAIN".
            #
            if [[ "$host_op" =~ .*NXDOMAIN.* ]]; then
                echo "NXDOMAIN"
                return 1
            fi

            vecho "Failed to resolve ${hname}: $host_op!"
            # Exhausted retries?
            if [ $i -eq $RETRIES ]; then
                return 1
            fi
            # Mostly some transient issue, retry after some sleep.
            sleep 1
            continue
        fi

        #
        # For ZRS accounts, we will get 3 IP addresses whose order keeps changing.
        # We sort the output of host so that we always look at the same address,
        # also we shuffle it so that different clients balance out across different
        # zones.
        #
        ipv4_addr_all=$(echo "$host_op" | grep " has address " | awk '{print $4}' |\
                        sort | shuf --random-source=$RANDBYTES)

        cnt_ip=$(echo "$ipv4_addr_all" | wc -l)

        if [ $cnt_ip -eq 0 ]; then
            vecho "host returned 0 address for ${hname}, expected one or more! [$host_op]"
            # Exhausted retries?
            if [ $i -eq $RETRIES ]; then
                return 1
            fi
            # Mostly some transient issue, retry after some sleep.
            sleep 1
            continue
        fi

        break
    }

    # Use first address from the above curated list.
    ipv4_addr=$(echo "$ipv4_addr_all" | head -n1)

    # For ZRS we need to use the first reachable IP.
    if [ $cnt_ip -ne 1 ]; then
        for((i=1;i<=$cnt_ip;i++)) {
            ipv4_addr=$(echo "$ipv4_addr_all" | tail -n +$i | head -n1)
            if is_ip_port_reachable $ipv4_addr 2048; then
                break
            fi
        }
    fi

    if ! is_valid_ipv4_address "$ipv4_addr"; then
        eecho "[FATAL] host returned bad IPv4 address $ipv4_addr for hostname ${hname}!"
        return 1
    fi

    #
    # Check if the IP-FQDN pair is present in /etc/hosts
    # 
    if is_present_in_etc_hosts "$ipv4_addr" "$hname"; then
        if [ "$fail_if_present_in_etc_hosts" == "true" ]; then
            eecho "[FATAL] $hname resolved to $ipv4_addr from /etc/hosts!"
            eecho "AZNFS depends on dynamically detecting DNS changes for proper handling of endpoint address changes"
            eecho "Please remove the entry for $hname from /etc/hosts"
            return 1
        else
            wecho "[FATAL] $hname resolved to $ipv4_addr from /etc/hosts!" 1>/dev/null
            wecho "AZNFS depends on dynamically detecting DNS changes for proper handling of endpoint address changes" 1>/dev/null
            wecho "Please remove the entry for $hname from /etc/hosts" 1>/dev/null
        fi
    fi

    echo $ipv4_addr
    return 0
}

#
# Function to check if an IP is private.
#
is_private_ip()
{
    local ip=$1

    if ! is_valid_ipv4_address $ip; then
        return 1
    fi

    #
    # Check if the IP belongs to the private IP range (10.0.0.0/8,
    # 172.16.0.0/12, or 192.168.0.0/16).f
    #
    [[ $ip =~ ^10\..* ]] ||
    [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\..* ]] ||
    [[ $ip =~ ^192\.168\..* ]]
}

#
# Mount helper must call this function to grab a timed lease on all mountmap
# entries. It should do this if it decides to use any of the entries. Once
# this is called aznfswatchdog is guaranteed to not delete any mountmap entries
# till the next 5 minutes.
#
# Must be called with mountmap lock held.
#
# Parameters:
#   $1 - mountmap_file: The mountmap file to touch
#
touch_mountmap()
{
    local mountmap_file=$1

    chattr -f -i $mountmap_file
    touch $mountmap_file
    if [ $? -ne 0 ]; then
        chattr -f +i $mountmap_file
        eecho "Failed to touch ${mountmap_file}!"
        return 1
    fi
    chattr -f +i $mountmap_file
}

# Create mount map file MOUNTMAPv3 or MOUNTMAPv4
create_mountmap_file()
{
    local mountmap_filename=MOUNTMAPv$AZNFS_VERSION
    if [ ! -f ${!mountmap_filename} ]; then
        touch ${!mountmap_filename}
        if [ $? -ne 0 ]; then
            eecho "[FATAL] Not able to create '${!mountmap_filename}'!"
            return 1
        fi
        chattr -f +i ${!mountmap_filename}
    fi
}

# Create mountmap file MOUNTMAPv4NONTLS
create_mountmap_file_nontlsv4()
{
    local mountmap_filename_nontls=MOUNTMAPv4NONTLS
    if [ ! -f ${!mountmap_filename_nontls} ]; then
        touch ${!mountmap_filename_nontls}
        if [ $? -ne 0 ]; then
            eecho "[FATAL] Not able to create '${!mountmap_filename_nontls}'!"
            return 1
        fi
        chattr -f +i ${!mountmap_filename_nontls}
    fi

    local fslocation_filename=VIRTUALFSLOCATION

    if [ ! -f ${!fslocation_filename} ]; then
        touch ${!fslocation_filename}
        if [ $? -ne 0 ]; then
            eecho "[FATAL] Not able to create '${!fslocation_filename}'!"
            return 1
        fi
        chattr -f +i ${!fslocation_filename}
    fi
}

#
# Calculate control file name based on storage account hostname.
# Returns: AZNFSCtrl.txt<hash> where hash is derived from the account name.
#
get_aznfs_ctrl_filename()
{
    local hostname="$1"
    local account_name=${hostname%%.*}
    local key="abc"
    local keylen=${#key}
    local acc=0

    for (( i=0; i<${#account_name}; ++i )); do
        # Extract single character (byte) from each string
        local ch="${account_name:i:1}"
        local kch="${key:i%keylen:1}"

        # Get decimal byte values
        local b=$(printf '%d' "'$ch")
        local kb=$(printf '%d' "'$kch")

        local xored=$(( (b ^ kb) & 0xFF ))
        local shift_amt=$(( (i % 4) * 8 )) 
        acc=$(( acc ^ (xored << shift_amt ) ))
    done

    acc=$(( acc & 0xFFFFFFFF ))
    echo "AZNFSCtrl.txt${acc}"
}

#
# MOUNTMAPv3 is accessed by both mount.aznfs and aznfswatchdog service. Update it
# only after taking exclusive lock.
#
# Add entry to mountmap in case of a new mount or IP change for blob/file FQDN.
#
# This also ensures that the corresponding DNAT rule is created so that mountmap
# entry and DNAT rule are always in sync.
# For Nfsv4 Non TLS, also add CRC32 based on the account name
#
# Parameters:
#   $1 - entry: The entry to add (format: "host ip nfsip")
#   $2 - mountmap_file: The mountmap file to update
#
ensure_mountmap_exist_nolock()
{
    local entry=$1
    local mountmap_file=$2

    IFS=" " read l_host l_ip l_nfsip <<< "$entry"
    if ! ensure_iptable_entry $l_ip $l_nfsip; then
        eecho "[$entry] failed to add to ${mountmap_file}!"
        return 1
    fi
    line="$entry" 
    if [ "$AZNFS_VERSION" = "4" ]; then
        #calculate crc32 and then append to the line
        local ctrl_filename=$(get_aznfs_ctrl_filename "$l_host")
        vecho "Control file for $l_host: $ctrl_filename"
        line+=" $ctrl_filename"
    fi

    egrep -q "^${line}$" $mountmap_file
    if [ $? -ne 0 ]; then
        chattr -f -i $mountmap_file
        echo "$line" >> $mountmap_file 
        if [ $? -ne 0 ]; then
            chattr -f +i $mountmap_file
            eecho "[$entry] failed to add to ${mountmap_file}!"
            # Could not add mountmap entry, delete the DNAT rule added above.
            ensure_iptable_entry_not_exist $l_ip $l_nfsip
            return 1
        fi
        chattr -f +i $mountmap_file
    else
        pecho "[$entry] already exists in ${mountmap_file}."
    fi
}

#
# Add entry to mountmap with exclusive lock.
#
# Parameters:
#   $1 - entry: The entry to add (format: "host ip nfsip")
#   $2 - mountmap_file: The mountmap file to update
#
ensure_mountmap_exist()
{
    local entry=$1
    local mountmap_file=$2

    (
        flock -e 999
        ensure_mountmap_exist_nolock "$entry" "$mountmap_file"
        return $?
    ) 999<$mountmap_file
}

#
# Delete entry from mountmap and also the corresponding iptable rule.
#
# Parameters:
#   $1 - line: The entry to delete
#   $2 - mountmap_file: The mountmap file to update
#   $3 - ifmatch (optional): Only delete if mountmap mtime matches this value
#
ensure_mountmap_not_exist()
{
    local line=$1
    local mountmap_file=$2
    local ifmatch="$3"

    (
        flock -e 999

        #
        # If user wants to delete the entry only if mountmap has not changed since
        # he looked up, honour that.
        #
        if [ -n "$ifmatch" ]; then
            local mtime=$(stat -c%Y $mountmap_file)
            if [ "$mtime" != "$ifmatch" ]; then
                eecho "[$line] Refusing to remove from ${mountmap_file} as $mtime != $ifmatch!"
                return 1
            fi
        fi

        # Delete iptable rule corresponding to the outgoing mountmap entry.
        IFS=" " read l_host l_ip l_nfsip l_aznfsctrlfile <<< "$line"
        if [ -n "$l_host" -a -n "$l_ip" -a -n "$l_nfsip" ]; then
            if ! ensure_iptable_entry_not_exist $l_ip $l_nfsip; then
                eecho "[$line] Refusing to remove from ${mountmap_file} as iptable entry could not be deleted!"
                return 1
            fi
        fi

        chattr -f -i $mountmap_file
        #
        # We do this thing instead of inplace update by sed as that has a
        # very bad side-effect of creating a new mountmap file. This breaks
        # any locking that we dependent on the old file.
        #
        out=$(sed "\%^${line}$%d" $mountmap_file)
        ret=$?
        if [ $ret -eq 0 ]; then
            #
            # If this echo fails then mountmap could be truncated. In that case we need
            # to reconcile it from the mount info and iptable info. That needs to be done
            # out-of-band.
            #
            echo "$out" > $mountmap_file
            ret=$?
            out=
            if [ $ret -ne 0 ]; then
                eecho "*** [FATAL] $mountmap_file may be in inconsistent state, contact Microsoft support ***"
            fi
        fi

        if [ $ret -ne 0 ]; then
            chattr -f +i $mountmap_file
            eecho "[$line] failed to remove from ${mountmap_file}!"
            # Reinstate DNAT rule deleted above.
            ensure_iptable_entry $l_ip $l_nfsip
            return 1
        fi
        chattr -f +i $mountmap_file

        # Return the mtime after our mods.
        echo $(stat -c%Y $mountmap_file)
    ) 999<$mountmap_file
}

#
# Replace a mountmap entry with a new one.
# This will also update the iptable DNAT rules accordingly, deleting DNAT rule
# corresponding to old entry and adding the DNAT rule corresponding to the new
# entry.
#
# Parameters:
#   $1 - old: The old entry to replace
#   $2 - new: The new entry to replace with
#   $3 - mountmap_file: The mountmap file to update
#
update_mountmap_entry()
{
    local old=$1
    local new=$2
    local mountmap_file=$3

    vecho "Updating mountmap entry [$old -> $new] in $mountmap_file"

    (
        flock -e 999

        IFS=" " read l_host l_ip l_nfsip_old l_aznfsctrlfile <<< "$old"
        if [ -n "$l_host" -a -n "$l_ip" -a -n "$l_nfsip_old" ]; then
            if ! ensure_iptable_entry_not_exist $l_ip $l_nfsip_old; then
                eecho "[$old] Refusing to remove from ${mountmap_file} as old iptable entry could not be deleted!"
                return 1
            fi
        fi

        IFS=" " read l_host l_ip l_nfsip_new l_aznfsctrlfile <<< "$new"
        if [ -n "$l_host" -a -n "$l_ip" -a -n "$l_nfsip_new" ]; then
            if ! ensure_iptable_entry $l_ip $l_nfsip_new; then
                eecho "[$new] Refusing to remove from ${mountmap_file} as new iptable entry could not be added!"
                # Roll back.
                ensure_iptable_entry $l_ip $l_nfsip_old
                return 1
            fi
        fi

        chattr -f -i $mountmap_file
        #
        # We do this thing instead of inplace update by sed as that has a
        # very bad side-effect of creating a new mountmap file. This breaks
        # any locking that we dependent on the old file.
        #
        out=$(sed "s%^${old}$%${new}%g" $mountmap_file)
        ret=$?
        if [ $ret -eq 0 ]; then
            #
            # If this echo fails then mountmap could be truncated. In that case we need
            # to reconcile it from the mount info and iptable info. That needs to be done
            # out-of-band.
            #
            echo "$out" > $mountmap_file
            ret=$?
            out=
            if [ $ret -ne 0 ]; then
                eecho "*** [FATAL] $mountmap_file may be in inconsistent state, contact Microsoft support ***"
            fi
        fi

        if [ $ret -ne 0 ]; then
            chattr -f +i $mountmap_file
            eecho "[$old -> $new] failed to update ${mountmap_file}!"
            # Roll back.
            ensure_iptable_entry_not_exist $l_ip $l_nfsip_new
            ensure_iptable_entry $l_ip $l_nfsip_old
            return 1
        fi
        chattr -f +i $mountmap_file
    ) 999<$mountmap_file
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

#
# Search for a free local IP with the given prefix.
# Takes the IP prefix and the mountmap file to use.
#
search_free_local_ip_with_prefix() 
{
    local initial_ip_prefix=$1
    local mountmap_file=$2
    local num_octets=$(octets_in_ipv4_prefix $ip_prefix)

    if [ $num_octets -ne 2 -a $num_octets -ne 3 ]; then
        eecho "Invalid IPv4 prefix: ${ip_prefix}"
        eecho "Valid prefix must have either 2 or 3 octets and must be a valid private IPv4 address prefix."
        eecho "Examples of valid private IPv4 prefixes are 10.10, 10.10.10, 192.168, 192.168.10 etc."
        return 1
    fi

    local local_ip=""
    local optimize_get_free_local_ip=false
    local used_local_ips_with_same_prefix=$(cat $mountmap_file | awk '{print $2}' | grep "^${initial_ip_prefix}\." | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n)
    local iptable_entries=$(iptables-save -t nat)

    _3rdoctet=100
    ip_prefix=$initial_ip_prefix

    #
    # Optimize the process to get free local IP by starting the loop to choose
    # 3rd and 4th octet from the number which was used last and still exist in
    # mountmap instead of starting it from 100.
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
        # Add this entry to mountmap while we have the mountmap lock.
        # This is to avoid assigning same local ip to parallel mount requests
        # for different endpoints.
        # ensure_mountmap_exist_nolock will also create a matching iptable DNAT rule.
        #
        LOCAL_IP=$local_ip
        ensure_mountmap_exist_nolock "$nfs_host $LOCAL_IP $nfs_ip" "$mountmap_file"

        return 0
    done

    # We will never reach here.
}

#
# Get a local IP that is free to use. Set global variable LOCAL_IP if found.
# Takes the mountmap file to use for tracking used IPs.
#
get_free_local_ip()
{
    local mountmap_file=$1

    for ip_prefix in $IP_PREFIXES; do
        vecho "Trying IP prefix ${ip_prefix}."
        if search_free_local_ip_with_prefix "$ip_prefix" "$mountmap_file"; then
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
        if search_free_local_ip_with_prefix "$ip_prefix" "$mountmap_file"; then
            return 0
        fi
    done

    # If we come here we did not get a free address to use.
    return 1
}

#
# To maintain consistency in case of regional account and in general to avoid creating
# multiple DNAT entries corresponding to one LOCAL_IP, first check for resolved IP in mountmap.
# This will help keep mountmap and DNAT entries in sync with each other.
# If the current resolved IP is different from the one stored in mountmap then it means that the IP has changed
# since the mountmap entry was created (could be due to migration or more likely due to RAs roundrobin DNS). 
# In any case this will be properly handled by aznfswatchdog next time it checks for IP change for this fqdn.
#
# Parameters:
#   $1 - fqdn: The FQDN to resolve
#   $2 - mountmap_file: The mountmap file to check for existing IP
#
resolve_ipv4_with_preference_to_mountmap()
{
    local fqdn=$1
    local mountmap_file=$2

    exec {fd}<$mountmap_file
    flock -e $fd

    local mountmap_entry=$(grep -m1 "^${fqdn} " $mountmap_file)
    
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
# Parameters:
#   $1 - fqdn: The FQDN to get a local IP for
#   $2 - mountmap_file: The mountmap file to use
#
get_local_ip_for_fqdn()
{
    local fqdn=$1
    local mountmap_file=$2
    local mountmap_entry=$(grep -m1 "^${fqdn} " $mountmap_file)
    # One local ip per fqdn, so return existing one if already present.
    IFS=" " read _ local_ip _ <<< "$mountmap_entry"

    if [ -n "$local_ip" ]; then
        LOCAL_IP=$local_ip

        #
        # Ask aznfswatchdog to stay away while we are using this proxy IP.
        # This is similar to holding a timed lease, we can safely use this
        # proxy IP w/o worrying about aznfswatchdog deleting it for 5 minutes.
        #
        touch_mountmap $mountmap_file

        #
        # This is not really needed since iptable entry must also be present,
        # but it's always better to ensure mountmap and iptable entries are
        # in sync.
        #
        ensure_iptable_entry $local_ip $nfs_ip
        return 0
    fi

    #
    # First mount of an account on this client.
    #
    get_free_local_ip $mountmap_file
}

#
# Ensure given DNAT rule exists, if not it creates it else silently exits.
#
ensure_iptable_entry()
{
    iptables -w 60 -t nat -C OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        iptables -w 60 -t nat -I OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2"
        if [ $? -ne 0 ]; then
            eecho "Failed to add DNAT rule [$1 -> $2]!"
            return 1
        fi
        
        #
        # While the DNAT entry was not there, if there was some NFS traffic (targeted to proxy IP),
        # it would have created a conntrack entry with destination and reply source IP as the proxy IP.
        # This conntrack entry will prevent the creation of the correct conntrack entry with destination as
        # proxy IP and reply source as NFS server IP. This will cause traffic to be stalled, hence we need to
        # delete the entry if such an entry exists.
        #
        output=$(conntrack -D -p tcp -d "$1" -r "$1" 2>&1)
        if [ $? -eq 0 ]; then
            wecho "Deleted undesired conntrack entry [$1 -> $1]!"
        fi
    fi
}

#
# We only use lowercase single word names for distro id:
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

log_version_info()
{
    if [ -f /etc/centos-release ]; then
        linux_distro=$(cat /etc/centos-release 2>&1)
        distro_id="centos"
    elif [ -f /etc/os-release ]; then
        linux_distro=$(grep "^PRETTY_NAME=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
        distro_id=$(grep "^ID=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
        distro_id=$(canonicalize_distro_id $distro_id)
    else
        # Ideally, this should not happen.
        linux_distro="Unknown"
    fi

    bash_version=$(bash --version | head -n 1)

    vecho "Linux distribution: $linux_distro"
    vecho "Bash version: $bash_version"

    if [ "$AKS_USER" == "true" ]; then
        vecho "AZNFS version: $RELEASE_NUMBER_FOR_AKS"
        return
    fi

    #
    # aznfswatchdog gets started during postinst, wait for installation to complete for the version to appear correctly.
    #
    sleep 2

    if [ "$distro_id" == "ubuntu" ]; then
        current_version=$(dpkg-query -W -f='${Version}\n' aznfs 2>/dev/null)
    elif [ "$distro_id" == "centos" -o "$distro_id" == "rocky" -o "$distro_id" == "rhel" -o "$distro_id" == "ol" -o "$distro_id" == "azurelinux" ]; then
        current_pkg_name=$(rpm -q aznfs)
        current_version=$(echo "$current_pkg_name" | sed -E 's/^aznfs-(.+)\.[^.]+$/\1/')
    elif [ "$distro_id" == "sles" ]; then
        current_version=$(zypper search --details -i aznfs | grep "\<aznfs\>" | awk '{print $7}')
    else
        # Ideally, this should not happen.
        current_version="Unknown"
    fi

    vecho "AZNFS version: $current_version"
}

#
# Ensure given DNAT rule is deleted, silently exits if the rule doesn't exist.
# Also removes the corresponding entry from conntrack.
#
ensure_iptable_entry_not_exist()
{
    iptables -w 60 -t nat -C OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        iptables -w 60 -t nat -D OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2"
        if [ $? -ne 0 ]; then
            eecho "Failed to delete DNAT rule [$1 -> $2]!"
            return 1
        fi

        # Ignore status of conntrack because entry may not exist (timed out).
        output=$(conntrack -D conntrack -p tcp -d "$1" -r "$2" 2>&1)
        if [ $? -ne 0 ]; then
            vecho "$output"
        fi
    fi
}

#
# Verify if the mountmapv3 entry is present but corresponding DNAT rule does not
# exist. Add it to avoid IOps failure.
#
verify_iptable_entry()
{
    iptables -w 60 -t nat -C OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        wecho "DNAT rule [$1 -> $2] does not exist, adding it."
        iptables -w 60 -t nat -I OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2"
        if [ $? -ne 0 ]; then
            eecho "Failed to add DNAT rule [$1 -> $2]!"
            return 1
        fi

        #
        # While the DNAT entry was not there, if there was some NFS traffic (targeted to proxy IP),
        # it would have created a conntrack entry with destination and reply source IP as the proxy IP.
        # This conntrack entry will prevent the creation of the correct conntrack entry with destination as
        # proxy IP and reply source as NFS server IP. This will cause traffic to be stalled, hence we need to
        # delete the entry if such an entry exists.
        #
        output=$(conntrack -D -p tcp -d "$1" -r "$1" 2>&1)
        if [ $? -eq 0 ]; then
            wecho "Deleted undesired conntrack entry [$1 -> $1]!"
        fi
    fi
}

# Find CheckHost value for stunnel configuration based on storage account hostname.
get_check_host_value()
{
    local hostname=$1
    local check_host_value="*.file.core.windows.net"

    declare -A certs
    certs=(
        ["preprod.core.windows.net$"]="*.file.preprod.core.windows.net"
        ["chinacloudapi.cn$"]="*.file.core.chinacloudapi.cn"
        ["usgovcloudapi.net$"]="*.file.core.usgovcloudapi.net"
    )

    # If AZURE_ENDPOINT_OVERRIDE environment variable is set, use it.
    if [[ -n "$AZURE_ENDPOINT_OVERRIDE" ]]; then
        # Remove any leading dot.
        modified_endpoint=${AZURE_ENDPOINT_OVERRIDE#.}
        check_host_value="*.file.core.$modified_endpoint"
    else
        for cert in "${!certs[@]}"; do
            if [[ "$hostname" =~ $cert ]]; then
                    check_host_value="${certs[$cert]}"
                    break
            fi
        done
    fi

    echo "$check_host_value"
}

# On some distros mount program doesn't pass correct PATH variable.
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if command -v netstat &> /dev/null; then
    NETSTATCOMMAND="netstat"
elif command -v ss &> /dev/null; then
    NETSTATCOMMAND="ss"
fi

if [ ! -d $OPTDIRDATA ]; then
    eecho "[FATAL] '${OPTDIRDATA}' is not present, cannot continue!"
    exit 1
fi

if [ ! -f $LOGFILE ]; then
    touch $LOGFILE
    if [ $? -ne 0 ]; then
        eecho "[FATAL] Not able to create '${LOGFILE}'!"
        exit 1
    fi
fi

# Create mount map file
if ! create_mountmap_file; then
    exit 1
fi

# Create mount map file nontls v4

if ! create_mountmap_file_nontlsv4; then
    exit 1
fi

ulimitfd=$(ulimit -n 2>/dev/null)
if [ -n "$ulimitfd" -a $ulimitfd -lt 131072 ]; then
    ulimit -n 131072
fi

#
# In case there are inherited fds, close other than 0,1,2.
#
pushd /proc/$$/fd  > /dev/null
for fd in *; do
    [ $fd -gt 2 ] && exec {fd}<&-
done
popd  > /dev/null
