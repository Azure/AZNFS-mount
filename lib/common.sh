#! /bin/bash

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

_log()
{
    echoarg=""

    # We only support -n argument to echo.
    if [ "$1" == "-n" ]; then
        echoarg="-n"
        shift
    fi

    color=$1
    msg=$2

    echo $echoarg -e "${color}${msg}${NORMAL}"
    (
        flock -e 999
        echo $echoarg -e "$(date -u) $(hostname) $$: ${color}${msg}${NORMAL}" >> $LOGFILE
    ) 999<$LOGFILE
}

#
# Plain echo with file logging.
#
pecho()
{
    echoarg=""
    color=$NORMAL
    if [ "$1" == "-n" ]; then
        echoarg="-n"
        shift
    fi
    _log $echoarg $color "${*}"
}

#
# Success echo.
#
secho()
{
    echoarg=""
    color=$GREEN
    if [ "$1" == "-n" ]; then
        echoarg="-n"
        shift
    fi
    _log $echoarg $color "${*}"
}

#
# Warning echo.
#
wecho()
{
    echoarg=""
    color=$YELLOW
    if [ "$1" == "-n" ]; then
        echoarg="-n"
        shift
    fi
    _log $echoarg $color "${*}"
}

#
# Error echo.
#
eecho()
{
    echoarg=""
    color=$RED
    if [ "$1" == "-n" ]; then
        echoarg="-n"
        shift
    fi
    _log $echoarg $color "${*}"
}

#
# Verbose echo, no-op unless AZNFS_VERBOSE env variable is set.
#
vecho()
{
    echoarg=""
    color=$NORMAL
    if [ "$1" == "-n" ]; then
        echoarg="-n"
        shift
    fi

    # Unless AZNFS_VERBOSE flag is set, do not echo to console.
    if [ -z "$AZNFS_VERBOSE" -o "$AZNFS_VERBOSE" == "0" ]; then
        (
            flock -e 999
            echo $echoarg -e "$(date -u) $(hostname) $$: ${color}${*}${NORMAL}" >> $LOGFILE
        ) 999<$LOGFILE

        return
    fi

    _log $echoarg $color "${*}"
}

# 
# Check if the given string is a valid IPv4 address. 
# 
is_valid_ipv4_address() 
{ 
    #
    # ip route allows 10.10 as a valid address and treats it as 10.10.0.0, so 
    # we need the first coarse filter too.
    #
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && 
    ip -4 route save match $1 > /dev/null 2>&1 
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
# Blob fqdn to IPv4 adddress.
# Caller must make sure that it is called only for hostname and not IP address.
# 
resolve_ipv4()
{ 
    local hname="$1"

    # Resolve hostname to IPv4 address.
    host_op=$(host -4 -t A "$hname" | sort) 
    if [ $? -ne 0 ]; then
        eecho "Bad Blob FQDN: $hname" 
        return 1 
    fi 

    # 
    # For ZRS accounts, we will get 3 IP addresses whose order keeps changing.
    # We sort the output of host so that we always look at the same address.
    # 
    local cnt_ip=$(echo "$host_op" | grep " has address " | awk '{print $4}' | head -n1 | wc -l) 

    if [ $cnt_ip -ne 1 ]; then 
        eecho "host returned $cnt_ip address(es) for ${hname}, expected 1!" 
        return 1 
    fi

    local ipv4_addr=$(echo "$host_op" | grep " has address " | head -n1 | awk '{print $4}') 
    
    if ! is_valid_ipv4_address "$ipv4_addr"; then 
        eecho "[FATAL] host returned bad IPv4 address $ipv4_addr for hostname ${hname}!" 
        return 1 
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
# MOUNTMAP is accessed by both mount.aznfs and aznfswatchdog service. Update it 
# only after taking exclusive lock.
#
# Add entry to $MOUNTMAP in case of a new mount or IP change for blob FQDN.
#
ensure_mountmap_exist()
{
    (
        flock -e 999
        egrep -q "^${1}$" $MOUNTMAP
        if [ $? -ne 0 ]; then
            chattr -f -i $MOUNTMAP
            echo "$1" >> $MOUNTMAP
            if [ $? -ne 0 ]; then
                chattr -f +i $MOUNTMAP
                eecho "[$1] failed to add to ${MOUNTMAP}!"
                return 1
            fi
            chattr -f +i $MOUNTMAP
        else
            pecho "[$1] already exists in ${MOUNTMAP}."
        fi 
    ) 999<$MOUNTMAP
}

#
# Delete entry from $MOUNTMAP in case of unmount or IP change for blob FQDN.
#
ensure_mountmap_not_exist()
{
    (
        flock -e 999
        chattr -f -i $MOUNTMAP
        sed -i "\%^${1}$%d" $MOUNTMAP
        if [ $? -ne 0 ]; then
            chattr -f +i $MOUNTMAP
            eecho "[$1] failed to remove from ${MOUNTMAP}!"
            return 1
        fi
        chattr -f +i $MOUNTMAP
    ) 999<$MOUNTMAP
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

#
# Must be called only when $l_ip:$l_dir is mounted.
#
unmount_and_delete_iptable_entry()
{
    local l_ip=$1
    local l_dir=$2
    local l_nfsip=$3

    pecho "Unmounting [${l_ip}:${l_dir}]."
    if umount -lf "${l_ip}:${l_dir}"; then
        # Clear the DNAT rule.
        if ! delete_iptable_entry "$l_ip" "$l_nfsip"; then
            eecho "iptables failed to delete DNAT rule [$l_ip -> $l_nfsip]!"
        fi
    else
        eecho "Failed to unmount [${l_ip}:${l_dir}]!"
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