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
MOUNTMAP="${OPTDIRDATA}/mountmap"

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
# Check if system is booted with systemd as init.
#
systemd_is_init()
{
    init="$(ps -q 1 -o comm=)"
    [ "$init" == "systemd" ]
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
    grep -qE "^[[:space:]]*$ip[[:space:]]+[^#]*\<$hostname\>" /etc/hosts
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
    IFS=" " read l_host l_ip l_nfsip <<< "$1"
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
            ensure_iptable_entry_not_exist $l_ip $l_nfsip
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
    (
        flock -e 999

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

        chattr -f -i $MOUNTMAP
        #
        # We do this thing instead of inplace update by sed as that has a
        # very bad side-effect of creating a new MOUNTMAP file. This breaks
        # any locking that we dependent on the old file.
        #
        out=$(sed "\%^${1}$%d" $MOUNTMAP)
        ret=$?
        if [ $ret -eq 0 ]; then
            #
            # If this echo fails then MOUNTMAP could be truncated. In that case we need
            # to reconcile it from the mount info and iptable info. That needs to be done
            # out-of-band.
            #
            echo "$out" > $MOUNTMAP
            ret=$?
            out=
            if [ $ret -ne 0 ]; then
                eecho "*** [FATAL] MOUNTMAP may be in inconsistent state, contact Microsoft support ***"
            fi
        fi

        if [ $ret -ne 0 ]; then
            chattr -f +i $MOUNTMAP
            eecho "[$1] failed to remove from ${MOUNTMAP}!"
            # Reinstate DNAT rule deleted above.
            ensure_iptable_entry $l_ip $l_nfsip
            return 1
        fi
        chattr -f +i $MOUNTMAP

        # Return the mtime after our mods.
        echo $(stat -c%Y $MOUNTMAP)
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

    vecho "Updating mountmap entry [$old -> $new]"

    (
        flock -e 999

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
        #
        # We do this thing instead of inplace update by sed as that has a
        # very bad side-effect of creating a new MOUNTMAP file. This breaks
        # any locking that we dependent on the old file.
        #
        out=$(sed "s%^${old}$%${new}%g" $MOUNTMAP)
        ret=$?
        if [ $ret -eq 0 ]; then
            #
            # If this echo fails then MOUNTMAP could be truncated. In that case we need
            # to reconcile it from the mount info and iptable info. That needs to be done
            # out-of-band.
            #
            echo "$out" > $MOUNTMAP
            ret=$?
            out=
            if [ $ret -ne 0 ]; then
                eecho "*** [FATAL] MOUNTMAP may be in inconsistent state, contact Microsoft support ***"
            fi
        fi

        if [ $ret -ne 0 ]; then
            chattr -f +i $MOUNTMAP
            eecho "[$old -> $new] failed to update ${MOUNTMAP}!"
            # Roll back.
            ensure_iptable_entry_not_exist $l_ip $l_nfsip_new
            ensure_iptable_entry $l_ip $l_nfsip_old
            return 1
        fi
        chattr -f +i $MOUNTMAP
    ) 999<$MOUNTMAP
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
        if [ $? -ne 0 ]; then
            vecho "$output"
        fi
    fi
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
# Verify if the mountmap entry is present but corresponding DNAT rule does not
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
    fi
}

# On some distros mount program doesn't pass correct PATH variable.
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin


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

if [ ! -f $MOUNTMAP ]; then
    touch $MOUNTMAP
    if [ $? -ne 0 ]; then
        eecho "[FATAL] Not able to create '${MOUNTMAP}'!"
        exit 1
    fi
    chattr -f +i $MOUNTMAP
fi

ulimitfd=$(ulimit -n 2>/dev/null)
if [ -n "$ulimitfd" -a $ulimitfd -lt 131072 ]; then
    ulimit -n 131072
fi

#
# In case there are inherited fds, close other than 0,1,2.
#
for fd in $(ls /proc/$$/fd/); do
    [ $fd -gt 2 ] && exec {fd}<&-
done