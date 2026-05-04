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
# This stores the map of hostname, local proxy IP and storage endpoint IP for NFSv4 non-TLS mounts.
# Format: hostname localip storageip (same as MOUNTMAPv3)
#
MOUNTMAPv4NOTLS="${OPTDIRDATA}/mountmapv4notls"

#
# Read ahead size in KB defaults to 16384 (16 MB).
#
AZNFS_READ_AHEAD_KB="${AZNFS_READ_AHEAD_KB:-16384}"

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
MONITOR_INTERVAL_SECS=5

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
    local probe_port="${3:-2048}"
    local exclude_ip="$4"
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
            # Skip the excluded IP (used during failover to avoid the known-dead IP).
            if [ -n "$exclude_ip" ] && [ "$ipv4_addr" == "$exclude_ip" ]; then
                continue
            fi
            if is_ip_port_reachable $ipv4_addr $probe_port; then
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
# Mount helper must call this function to grab a timed lease on all MOUNTMAPv3
# entries. It should do this if it decides to use any of the entries. Once
# this is called aznfswatchdog is guaranteed to not delete any MOUNTMAPv3 till
# the next 5 minutes.
#
# Must be called with MOUNTMAPv3 lock held.
#
touch_mountmapv3()
{
    chattr -f -i $MOUNTMAPv3
    touch $MOUNTMAPv3
    if [ $? -ne 0 ]; then
        chattr -f +i $MOUNTMAPv3
        eecho "Failed to touch ${MOUNTMAPv3}!"
        return 1
    fi
    chattr -f +i $MOUNTMAPv3
}

# Create mount map file
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

    # For NFSv4, also create the non-TLS mountmap file.
    if [ "$AZNFS_VERSION" == "4" ]; then
        if [ ! -f $MOUNTMAPv4NOTLS ]; then
            touch $MOUNTMAPv4NOTLS
            if [ $? -ne 0 ]; then
                eecho "[FATAL] Not able to create '${MOUNTMAPv4NOTLS}'!"
                return 1
            fi
            chattr -f +i $MOUNTMAPv4NOTLS
        fi
    fi
}

#
# Generic mountmap functions that work with any space-delimited mountmap file.
# Format: "hostname localip storageip"
# Used by both MOUNTMAPv3 (NFSv3) and MOUNTMAPv4NOTLS (NFSv4 non-TLS).
#

#
# Add entry to a mountmap file and create the corresponding DNAT rule.
# Usage: ensure_mountmap_exist_nolock <mountmap_file> <entry>
#
ensure_mountmap_exist_nolock()
{
    local mountmap_file=$1
    local entry=$2

    IFS=" " read l_host l_ip l_nfsip <<< "$entry"
    if ! ensure_iptable_entry $l_ip $l_nfsip; then
        eecho "[$entry] failed to add to ${mountmap_file}!"
        return 1
    fi

    egrep -q "^${entry}$" $mountmap_file
    if [ $? -ne 0 ]; then
        chattr -f -i $mountmap_file
        echo "$entry" >> $mountmap_file
        if [ $? -ne 0 ]; then
            chattr -f +i $mountmap_file
            eecho "[$entry] failed to add to ${mountmap_file}!"
            ensure_iptable_entry_not_exist $l_ip $l_nfsip
            return 1
        fi
        chattr -f +i $mountmap_file
    else
        pecho "[$entry] already exists in ${mountmap_file}."
    fi
}

#
# Add entry to a mountmap file with file locking.
# Usage: ensure_mountmap_exist <mountmap_file> <entry>
#
ensure_mountmap_exist()
{
    local mountmap_file=$1
    local entry=$2

    (
        flock -e 999
        ensure_mountmap_exist_nolock "$mountmap_file" "$entry"
        return $?
    ) 999<$mountmap_file
}

#
# Delete entry from a mountmap file and the corresponding iptable rule.
# Usage: ensure_mountmap_not_exist <mountmap_file> <entry> [<ifmatch_mtime>]
#
ensure_mountmap_not_exist()
{
    local mountmap_file=$1
    local entry=$2
    local ifmatch=$3

    (
        flock -e 999

        if [ -n "$ifmatch" ]; then
            local mtime=$(stat -c%Y $mountmap_file)
            if [ "$mtime" != "$ifmatch" ]; then
                eecho "[$entry] Refusing to remove from ${mountmap_file} as $mtime != $ifmatch!"
                return 1
            fi
        fi

        IFS=" " read l_host l_ip l_nfsip <<< "$entry"
        if [ -n "$l_host" -a -n "$l_ip" -a -n "$l_nfsip" ]; then
            if ! ensure_iptable_entry_not_exist $l_ip $l_nfsip; then
                eecho "[$entry] Refusing to remove from ${mountmap_file} as iptable entry could not be deleted!"
                return 1
            fi
        fi

        chattr -f -i $mountmap_file
        out=$(sed "\%^${entry}$%d" $mountmap_file)
        ret=$?
        if [ $ret -eq 0 ]; then
            echo "$out" > $mountmap_file
            ret=$?
            out=
            if [ $ret -ne 0 ]; then
                eecho "*** [FATAL] ${mountmap_file} may be in inconsistent state, contact Microsoft support ***"
            fi
        fi

        if [ $ret -ne 0 ]; then
            chattr -f +i $mountmap_file
            eecho "[$entry] failed to remove from ${mountmap_file}!"
            ensure_iptable_entry $l_ip $l_nfsip
            return 1
        fi
        chattr -f +i $mountmap_file

        echo $(stat -c%Y $mountmap_file)
    ) 999<$mountmap_file
}

#
# Replace an entry in a mountmap file with a new one.
# Updates the iptable DNAT rules accordingly.
# Usage: update_mountmap_entry <mountmap_file> <old_entry> <new_entry>
#
update_mountmap_entry()
{
    local mountmap_file=$1
    local old=$2
    local new=$3

    vecho "Updating mountmap entry [$old -> $new] in ${mountmap_file}"

    (
        flock -e 999

        IFS=" " read l_host l_ip l_nfsip_old <<< "$old"
        if [ -n "$l_host" -a -n "$l_ip" -a -n "$l_nfsip_old" ]; then
            if ! ensure_iptable_entry_not_exist $l_ip $l_nfsip_old; then
                eecho "[$old] Refusing to update ${mountmap_file} as old iptable entry could not be deleted!"
                return 1
            fi
        fi

        IFS=" " read l_host l_ip l_nfsip_new <<< "$new"
        if [ -n "$l_host" -a -n "$l_ip" -a -n "$l_nfsip_new" ]; then
            if ! ensure_iptable_entry $l_ip $l_nfsip_new; then
                eecho "[$new] Refusing to update ${mountmap_file} as new iptable entry could not be added!"
                ensure_iptable_entry $l_ip $l_nfsip_old
                return 1
            fi
        fi

        chattr -f -i $mountmap_file
        out=$(sed "s%^${old}$%${new}%g" $mountmap_file)
        ret=$?
        if [ $ret -eq 0 ]; then
            echo "$out" > $mountmap_file
            ret=$?
            out=
            if [ $ret -ne 0 ]; then
                eecho "*** [FATAL] ${mountmap_file} may be in inconsistent state, contact Microsoft support ***"
            fi
        fi

        if [ $ret -ne 0 ]; then
            chattr -f +i $mountmap_file
            eecho "[$old -> $new] failed to update ${mountmap_file}!"
            ensure_iptable_entry_not_exist $l_ip $l_nfsip_new
            ensure_iptable_entry $l_ip $l_nfsip_old
            return 1
        fi
        chattr -f +i $mountmap_file
    ) 999<$mountmap_file
}

#
# MOUNTMAPv3 is accessed by both mount.aznfs and aznfswatchdog service. Update it
# only after taking exclusive lock.
#
# Add entry to MOUNTMAPv3 in case of a new mount or IP change for blob FQDN.
#
# This also ensures that the corresponding DNAT rule is created so that MOUNTMAPv3
# entry and DNAT rule are always in sync.
#
ensure_mountmapv3_exist_nolock()
{
    ensure_mountmap_exist_nolock "$MOUNTMAPv3" "$1"
}

ensure_mountmapv3_exist()
{
    ensure_mountmap_exist "$MOUNTMAPv3" "$1"
}

#
# Delete entry from MOUNTMAPv3 and also the corresponding iptable rule.
#
ensure_mountmapv3_not_exist()
{
    ensure_mountmap_not_exist "$MOUNTMAPv3" "$1" "$2"
}

#
# Replace a mountmap entry with a new one.
# This will also update the iptable DNAT rules accordingly, deleting DNAT rule
# corresponding to old entry and adding the DNAT rule corresponding to the new
# entry.
#
update_mountmapv3_entry()
{
    update_mountmap_entry "$MOUNTMAPv3" "$1" "$2"
}

#
# Is the given address one of the host addresses?
#
is_host_ip()
{
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
    if [ "$AZNFS_PING_LOCAL_IP_BEFORE_USE" != "1" ]; then
        return 1
    fi

    local ip=$1
    ping -4 -W3 -c1 $ip > /dev/null 2>&1
}

#
# Returns number of octets in an IPv4 prefix.
# If IP prefix is not valid or is not a private IP address prefix, it returns 0.
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

    [[ $ip =~ ^10(\.${octet})*$ ]] ||
    [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])(\.${octet})*$ ]] ||
    [[ $ip =~ ^192\.168(\.${octet})*$ ]]

    if [ $? -ne 0 ]; then
        echo 0
        return
    fi

    [[ $ip =~ ^(${octetdot}){3}${octet}$ ]] && echo 4 && return;
    [[ $ip =~ ^(${octetdot}){2}${octet}$ ]] && echo 3 && return;
    [[ $ip =~ ^(${octetdot}){1}${octet}$ ]] && echo 2 && return;
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
    local used_local_ips_with_same_prefix=$(cat $MOUNTMAPv3 $MOUNTMAPv4NOTLS 2>/dev/null | awk '{print $2}' | grep "^${initial_ip_prefix}\." | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n)
    local iptable_entries=$(iptables-save -t nat)

    _3rdoctet=100
    ip_prefix=$initial_ip_prefix

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
                return 1
            fi
        fi

        LOCAL_IP=$local_ip
        ${MOUNTMAP_WRITE_FN:-ensure_mountmapv3_exist_nolock} "$nfs_host $LOCAL_IP $nfs_ip"

        return 0
    done
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

    vecho "Falling back to linear search for free ip!"
    OPTIMIZE_GET_FREE_LOCAL_IP=false
    for ip_prefix in $IP_PREFIXES; do
        vecho "Trying IP prefix ${ip_prefix}."
        if search_free_local_ip_with_prefix "$ip_prefix"; then
            return 0
        fi
    done

    return 1
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

#
# Function to extract minor number from combined device ID.
#
get_minor()
{
    local dev_id=$1
    echo $(( (dev_id & 0xff) | ((dev_id >> 12) & ~0xff) ))
}

#
# Function to extract major number from combined device ID.
#
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
