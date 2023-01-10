#! /bin/bash

APPNAME="aznfs"
RUNDIR="/run/${APPNAME}"
OPTDIR="/opt/microsoft/${APPNAME}"
LOGFILE="${OPTDIR}/${APPNAME}.log" 

# 
# This stores the map of local IP and share name and external blob endpoint IP. 
# 
MOUNTMAP="${RUNDIR}/mountmap"

RED="\e[2;31m"
RED_BOLD="\e[1;31m"
GREEN="\e[2;32m"
GREEN_BOLD="\e[1;32m"
YELLOW="\e[2;33m"
YELLOW_BOLD="\e[1;33m"
NORMAL="\e[0m"
NORMAL_BOLD="\e[0;1m"

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

    echo $echoarg -e "${color}${msg}${NORMAL}" |& tee -a $LOGFILE
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
    if [ -z "$AZNFS_VERBOSE" ]; then
        return
    fi

    echoarg=""
    color=$NORMAL
    if [ "$1" == "-n" ]; then
        echoarg="-n"
        shift
    fi
    _log $echoarg $color "${*}"
}

# 
# Check if the given string is a valid IPv4 address. 
# 
function is_valid_ipv4_address() 
{ 
    #
    # ip route allows 10.10 as a valid address and treats it as 10.10.0.0, so 
    # we need the first coarse filter too.
    #
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && 
    ip -4 route save match $1 > /dev/null 2>&1 
}

# 
# Blob fqdn to IPv4 adddress.
# Caller must make sure that it is called only for hostname and not IP address.
# 
function resolve_ipv4() 
{ 
    local hname="$1"

    # Resolve hostname to IPv4 address.
    host_op=$(host -4 -t A "$hname") 
    if [ $? -ne 0 ]; then
        eecho "Bad Blob FQDN: $hname" 
        return 1 
    fi 

    # 
    # TODO: For ZRS accounts, we will get 3 IP addresses, that needs to be 
    #       handled.
    # 
    local cnt_ip=$(echo "$host_op" | grep " has address " | awk '{print $4}' | wc -l) 

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
function update_mountmap() 
{ 
    flock $MOUNTMAP -c "eval $*"
}

mkdir -p $RUNDIR