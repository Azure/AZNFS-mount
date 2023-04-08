#! /bin/bash

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

APPNAME="aznfs"
OPTDIR="/opt/microsoft/${APPNAME}"
LOGFILE="${OPTDIR}/${APPNAME}.log"

#
# This stores the map of local IP and share name and external blob endpoint IP.
#
MOUNTMAP="${OPTDIR}/mountmap"

RED="\e[2;31m"
GREEN="\e[2;32m"
YELLOW="\e[2;33m"
NORMAL="\e[0m"

HOSTNAME=$(hostname)

_log()
{
    color=$1
    msg=$2

    echo -e "${color}${msg}${NORMAL}"
    (
        flock -e 999
        echo -e "$(date -u +"%a %b %d %G %T.%3N") $HOSTNAME $$: ${color}${msg}${NORMAL}" >> $LOGFILE
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
    ip -4 route get fibmatch $1 > /dev/null 2>&1
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
# Blob fqdn to IPv4 adddress.
# Caller must make sure that it is called only for hostname and not IP address.
#
resolve_ipv4()
{
    vecho "Inside resolve_ipv4"
    local hname="$1"

    # Some retries for resilience.
    for((i=0;i<3;i++)) {
        # Resolve hostname to IPv4 address.
        host_op=$(host -4 -t A "$hname")
        if [ $? -ne 0 ]; then
            eecho "Failed to resolve ${hname}!"
            # Exhausted retries?
            if [ $i -eq 3 ]; then
                return 1
            fi
            # Mostly some transient issue, retry after some sleep.
            sleep 5
            continue
        fi

        vecho "After host"
        #
        # For ZRS accounts, we will get 3 IP addresses whose order keeps changing.
        # We sort the output of host so that we always look at the same address,
        # also we shuffle it so that different clients balance out across different
        # zones.
        #
        ipv4_addr_all=$(echo "$host_op" | grep " has address " | awk '{print $4}' |\
                        sort | shuf --random-source=/etc/machine-id)

        cnt_ip=$(echo "$ipv4_addr_all" | wc -l)
        vecho "After cnt_ip"

        if [ $cnt_ip -eq 0 ]; then
            eecho "host returned 0 address for ${hname}, expected one or more! [$host_op]"
            # Exhausted retries?
            if [ $i -eq 3 ]; then
                return 1
            fi
            # Mostly some transient issue, retry after some sleep.
            sleep 5
            continue
        fi

        break
    }

    # Use first address from the above curated list.
    ipv4_addr=$(echo "$ipv4_addr_all" | head -n1)
    vecho "After ipv4_addr"

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

    vecho "After is_valid_ipv4_address"
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
# Mount helper must call this function to grab a timed lease on all MOUNTMAP
# entries. It should do this if it decides to use any of the entries. Once
# this is called aznfswatchdog is guaranteed to not delete any MOUNTMAP till
# the next 5 minutes.
#
# Must be called with MOUNTMAP lock held.
#
touch_mountmap()
{
    chattr -f -i $MOUNTMAP
    touch $MOUNTMAP
    if [ $? -ne 0 ]; then
        chattr -f +i $MOUNTMAP
        eecho "Failed to touch ${MOUNTMAP}!"
        return 1
    fi
    chattr -f +i $MOUNTMAP
}

#
# MOUNTMAP is accessed by both mount.aznfs and aznfswatchdog service. Update it
# only after taking exclusive lock.
#
# Add entry to $MOUNTMAP in case of a new mount or IP change for blob FQDN.
#
# This also ensures that the corresponding DNAT rule is created so that MOUNTMAP
# entry and DNAT rule are always in sync.
#
ensure_mountmap_exist_nolock()
{
    IFS=" " read l_host l_ip l_nfsip l_pid <<< "$1"
    if ! ensure_iptable_entry $l_ip $l_nfsip; then
        eecho "[$1] failed to add to ${MOUNTMAP}!"
        return 1
    fi

    egrep -q "^${1}$" $MOUNTMAP
    if [ $? -ne 0 ]; then
        chattr -f -i $MOUNTMAP
        echo "$1" >> $MOUNTMAP
        if [ $? -ne 0 ]; then
            chattr -f +i $MOUNTMAP
            eecho "[$1] failed to add to ${MOUNTMAP}!"
            # Could not add MOUNTMAP entry, delete the DNAT rule added above.
            delete_iptable_entry $l_ip $l_nfsip
            return 1
        fi
        chattr -f +i $MOUNTMAP
    else
        pecho "[$1] already exists in ${MOUNTMAP}."
    fi
}

ensure_mountmap_exist()
{
    (
        flock -e 999
        ensure_mountmap_exist_nolock "$1"
        return $?
    ) 999<$MOUNTMAP
}

#
# Delete entry from $MOUNTMAP and also the corresponding iptable rule.
#
ensure_mountmap_not_exist()
{
    #
    # If user wants to delete the entry only if MOUNTMAP has not changed since
    # he looked up, honour that.
    #
    local ifmatch="$2"
    if [ -n "$ifmatch" ]; then
        local mtime=$(stat -c%Y $MOUNTMAP)
        if [ "$mtime" != "$ifmatch" ]; then
            eecho "[$1] Refusing to remove from ${MOUNTMAP} as $mtime != $ifmatch!"
            return 1
        fi
    fi

    # Delete iptable rule corresponding to the outgoing MOUNTMAP entry.
    IFS=" " read l_host l_ip l_nfsip <<< "$1"
    if [ -n "$l_host" -a -n "$l_ip" -a -n "$l_nfsip" ]; then
        if ! ensure_iptable_entry_not_exist $l_ip $l_nfsip; then
            eecho "[$1] Refusing to remove from ${MOUNTMAP} as iptable entry could not be deleted!"
            return 1
        fi
    fi

    (
        flock -e 999
        chattr -f -i $MOUNTMAP
        sed -i "\%^${1}$%d" $MOUNTMAP
        if [ $? -ne 0 ]; then
            chattr -f +i $MOUNTMAP
            eecho "[$1] failed to remove from ${MOUNTMAP}!"
            # Reinstate DNAT rule deleted above.
            ensure_iptable_entry $l_ip $l_nfsip
            return 1
        fi
        chattr -f +i $MOUNTMAP
    ) 999<$MOUNTMAP
}

#
# Replace a mountmap entry with a new one.
# This will also update the iptable DNAT rules accordingly, deleting DNAT rule
# corresponding to old entry and adding the DNAT rule corresponding to the new
# entry.
#
update_mountmap_entry()
{
    local old=$1
    local new=$2

    IFS=" " read l_host l_ip l_nfsip_old <<< "$old"
    if [ -n "$l_host" -a -n "$l_ip" -a -n "$l_nfsip_old" ]; then
        if ! ensure_iptable_entry_not_exist $l_ip $l_nfsip_old; then
            eecho "[$old] Refusing to remove from ${MOUNTMAP} as old iptable entry could not be deleted!"
            return 1
        fi
    fi

    IFS=" " read l_host l_ip l_nfsip_new <<< "$new"
    if [ -n "$l_host" -a -n "$l_ip" -a -n "$l_nfsip_new" ]; then
        if ! ensure_iptable_entry $l_ip $l_nfsip_new; then
            eecho "[$new] Refusing to remove from ${MOUNTMAP} as new iptable entry could not be added!"
            # Roll back.
            ensure_iptable_entry $l_ip $l_nfsip_old
            return 1
        fi
    fi

    chattr -f -i $MOUNTMAP
    sed -i "s%^${old}$%${new}%g" $MOUNTMAP
    if [ $? -ne 0 ]; then
        chattr -f +i $MOUNTMAP
        eecho "[$old -> $new] failed to update ${MOUNTMAP}!"
        # Roll back.
        ensure_iptable_entry_not_exist $l_ip $l_nfsip_new
        ensure_iptable_entry $l_ip $l_nfsip_old
        return 1
    fi
    chattr -f +i $MOUNTMAP
}

#
# Check if the desired DNAT rule already exist. If not, add new DNAT rule.
#
add_iptable_entry()
{
    iptables -w 60 -t nat -C OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2" 2> /dev/null
    if [ $? -ne 0 ]; then
        iptables -w 60 -t nat -I OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2"
        if [ $? -ne 0 ]; then
            eecho "Failed to add DNAT rule [$1 -> $2]!"
            return 1
        fi
    else
        wecho "DNAT rule [$1 -> $2] already exists."
    fi
}

#
# Delete entry from iptables if the share is unmounted or the IP for blob FQDN
# is resolving into new IP. Also remove the entry from conntrack.
#
delete_iptable_entry()
{
    iptables -w 60 -t nat -C OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2" 2> /dev/null
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
    else
        wecho "DNAT rule [$1 -> $2] does not exist."
    fi
}

#
# Ensure given DNAT rule exists, if not it creates it else silently exits.
#
ensure_iptable_entry()
{
    iptables -w 60 -t nat -C OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2" 2> /dev/null
    if [ $? -ne 0 ]; then
        iptables -w 60 -t nat -I OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2"
        if [ $? -ne 0 ]; then
            eecho "Failed to add DNAT rule [$1 -> $2]!"
            return 1
        fi
    fi
}

#
# Ensure given DNAT rule is deleted, silently exits if the rule doesn't exist.
# Also removes the corresponding entry from conntrack.
#
ensure_iptable_entry_not_exist()
{
    iptables -w 60 -t nat -C OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2" 2> /dev/null
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
# Verify if the mountmap entry is present but corresponding DNAT rule does not
# exist. Add it to avoid IOps failure.
#
verify_iptable_entry()
{
    iptables -w 60 -t nat -C OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2" 2> /dev/null
    if [ $? -ne 0 ]; then
        wecho "DNAT rule [$1 -> $2] does not exist, adding it."
        iptables -w 60 -t nat -I OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2"
        if [ $? -ne 0 ]; then
            eecho "Failed to add DNAT rule [$1 -> $2]!"
            return 1
        fi
    fi
}

mkdir -p $OPTDIR
if [ $? -ne 0 ]; then
    eecho "[FATAL] Not able to create '${OPTDIR}'!"
    exit 1
fi

if [ ! -f $LOGFILE ]; then
    touch $LOGFILE
    if [ $? -ne 0 ]; then
        eecho "[FATAL] Not able to create '${LOGFILE}'!"
        exit 1
    fi
fi

if [ ! -f $MOUNTMAP ]; then
    touch $MOUNTMAP
    if [ $? -ne 0 ]; then
        eecho "[FATAL] Not able to create '${MOUNTMAP}'!"
        exit 1
    fi
    chattr -f +i $MOUNTMAP
fi
