#!/bin/bash

#
# NfSv4 logic for mount helper
#

#
# Load common aznfs helpers.
#
AZNFS_VERSION=4
. /opt/microsoft/aznfs/common.sh

MOUNT_OPTIONS=$1
OPTIONS=$2
nfs_host=$3
nfs_dir=$4
mount_point=$5

STUNNELDIR="/etc/stunnel/microsoft/${APPNAME}/nfsv4_fileShare"
STUNNELLOGDIR="$STUNNELDIR/logs"
NFSV4_PORT_RANGE_START=20049
NFSV4_PORT_RANGE_END=21049
DEBUG_LEVEL="info"

# Certificates related variables.
CERT_PATH=
CERT_UPDATE_COMMAND=
STUNNEL_CAFILE=

# TODO: Might have to use portmap entry in future to determine the CONNECT_PORT for nfsv3.
CONNECT_PORT=2049

# Default timeout for mount command to complete in seconds.
# If the mount command does not complete within this time, the mount is considered failed.
# https://linux.die.net/man/5/nfs
MOUNT_TIMEOUT_IN_SECONDS=180

# Cleanup function to release the lock on mountmap file.
cleanup() {
    flock -u $fd2
    exec {fd2}<&-
}

#
# Local IP that is free to use.
#
LOCAL_IP=""

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


#daniewo also move this to common.sh
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
# also move this to common
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
# To maintain consistency in case of regional account and in general to avoid creating
# multiple DNAT entries corrosponding to one LOCAL_IP, first check for resolved IP in mountmap.
# This will help keep mountmap and DNAT entries in sync with each other.
# If the current resolved IP is different from the one stored in mountmap then it means that the IP has changed
# since the mountmap entry was created (could be due to migration or more likely due to RAs roundrobin DNS). 
# In any case this will be properly handled by aznfswatchdog next time it checks for IP change for this fqdn.
#
# this method will only be used for non tls in v4.
resolve_ipv4_with_preference_to_mountmapv4()
{
    local fqdn=$1

    exec {fd}<$MOUNTMAPv4NONTLS
    flock -e $fd

    local mountmap_entry=$(grep -m1 "^${fqdn} " $MOUNTMAPv4NONTLS)
    
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


get_next_available_port()
{
    for ((port=NFSV4_PORT_RANGE_START; port<=NFSV4_PORT_RANGE_END; port++))
    do
        is_port_available=`$NETSTATCOMMAND -tuapn | grep "$LOCALHOST:$port "`
        if [ -z "$is_port_available" ]; then
            break
        fi
    done

    if [ $port -le $NFSV4_PORT_RANGE_END ]; then
        echo "$port"
    else
        echo ""
    fi
}

find_next_available_port_and_start_stunnel()
{
    while true
    do
        # get the next available port
        available_port=$(get_next_available_port)
        if [ $? -ne 0 ]; then
            eecho "Failed to get the next available port for nfsv4.1 mount."
            return 1
        fi
        vecho "Next Available Port: '$available_port'"

        if [ -z "$available_port" ]; then
            eecho "Running out of ports. For Nfsv4.1, stunnel uses port range from $NFSV4_PORT_RANGE_START to $NFSV4_PORT_RANGE_END. All ports from this range are used by other processes."
            return 1
        fi

        used_port=$(cat $stunnel_conf_file | grep accept | cut -d: -f2)
        vecho "used port: '$used_port'"

        chattr -f -i $stunnel_conf_file

        sed -i "s/$used_port/$available_port/" $stunnel_conf_file
        if [ $? -ne 0 ]; then
            eecho "Failed to replace the port in $stunnel_conf_file."
            chattr -f +i $stunnel_conf_file
            return 1
        fi
        chattr -f +i $stunnel_conf_file

        new_used_port=$(cat $stunnel_conf_file | grep accept | cut -d: -f2)

        # start the stunnel process
        vecho "Starting the stunnel on new port $new_used_port."
        stunnel_status=$(stunnel $stunnel_conf_file 2>&1)
        if [ -n "$stunnel_status" ]; then
            is_binding_error=$(echo $stunnel_status | grep "$LOCALHOST:$new_used_port: Address already in use")
            if [ -z "$is_binding_error" ]; then
                eecho "[FATAL] Not able to start stunnel process after finding available port for '${stunnel_conf_file}'!"
                return 1
            fi
        else
	        vecho "Found new port '$new_used_port' and restarted stunnel."
	        break
        fi
    done
}

get_cert_path_based_and_command()
{
    # Check if we're on a Debian-based distribution
    if command -v apt-get &> /dev/null; then
        CERT_PATH="/usr/local/share/ca-certificates"
        CERT_UPDATE_COMMAND="update-ca-certificates"
        STUNNEL_CAFILE="/etc/ssl/certs/DigiCert_Global_Root_G2.pem"
    # Check if we're on a Red Hat-based distribution
    elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
        CERT_PATH="/etc/pki/ca-trust/source/anchors"
        CERT_UPDATE_COMMAND="update-ca-trust extract"
        STUNNEL_CAFILE="${CERT_PATH}/DigiCert_Global_Root_G2.crt"
    # Check if we're on a SUSE-based distribution
    elif command -v zypper &> /dev/null; then
        CERT_PATH="/etc/pki/trust/anchors"
        CERT_UPDATE_COMMAND="update-ca-certificates"
        STUNNEL_CAFILE="${CERT_PATH}/DigiCert_Global_Root_G2.crt"
    else
        eecho "[FATAL] Unsupported distribution!"
        return 1
    fi
}

install_CA_cert()
{
    wget https://cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem --no-check-certificate -O ${CERT_PATH}/DigiCert_Global_Root_G2.crt
    if [ $? -ne 0 ]; then
        eecho "[FATAL] Not able to download DigiCert_Global_Root_G2 certificate from https://cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem !"
        return 1
    fi

    $CERT_UPDATE_COMMAND
}

#
# Add stunnel configuration in stunnel_<storageaccount_ip>.conf file.
#
add_stunnel_configuration()
{
    local storageaccount_ip=$1
    chattr -f -i $stunnel_conf_file

    if ! get_cert_path_based_and_command; then
        return 1
    fi

    if [ ! -f $STUNNEL_CAFILE ]; then
        vecho "CA root cert is missing for stunnel configuration. Installing DigiCert_Global_Root_G2 certificate."
        install_CA_cert
        if [ $? -ne 0 ]; then
            chattr -f +i $stunnel_conf_file
            eecho "[FATAL] Not able to install DigiCert_Global_Root_G2 certificate!"
            return 1
        fi
    fi

    echo "CAFile = $STUNNEL_CAFILE" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to add CAFile path to $stunnel_conf_file!"
        return 1
    fi

    echo "verifyChain = yes" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to add verifyChain option to $stunnel_conf_file!"
        return 1
    fi

    stunnel_check_host=$(get_check_host_value "$nfs_host")
    echo "checkHost = $stunnel_check_host" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to add checkHost option to $stunnel_conf_file!"
        return 1
    fi

    # TODO: Change to TLSv1.3 once we have TLSv1.3 version enabled.
    echo "sslVersion = TLSv1.2" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to add sslVersion option to $stunnel_conf_file!"
        return 1
    fi

    echo "debug = $DEBUG_LEVEL" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to add debug option to $stunnel_conf_file!"
        return 1
    fi

    stunnel_log_file="$STUNNELLOGDIR/stunnel_$storageaccount_ip.log"
    echo "output = $stunnel_log_file" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to add log file path to $stunnel_conf_file!"
        return 1
    fi

    stunnel_pid_file="$STUNNELLOGDIR/stunnel_$storageaccount_ip.pid"
    echo "pid = $stunnel_pid_file" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to add pid file path to $stunnel_conf_file!"
        return 1
    fi

    echo >> $stunnel_conf_file

    echo "[$storageaccount_ip]" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to add $storageaccount_ip service/entry name to $stunnel_conf_file!"
        return 1
    fi

    echo "client = yes" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to 'client = yes' to $stunnel_conf_file!"
        return 1
    fi
    
    #daniewo,  update the stunnel_conf_file 
    echo "accept = $LOCALHOST:$available_port" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to add 'accept' info to $stunnel_conf_file!"
        return 1
    fi

    echo "connect = $storageaccount_ip:$CONNECT_PORT" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to add 'connect' info to $stunnel_conf_file!"
        return 1
    fi

    # For Mariner linux, we need to add the following line to the stunnel configuration file,
    # otherwise stunnel complains about the missing ciphers for TLSv1.3 - need to do add it even if using
    # TLSv1.2, since ciphers for both TLS versions are checked as part of the initialization process.

    distro_id=
    if [ -f /etc/os-release ]; then
        distro_id=$(grep "^ID=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
        distro_id=$(canonicalize_distro_id $distro_id)
    fi

    if [ "$distro_id" == "mariner" ]; then
        # List available TLSv1.3 ciphersuites using OpenSSL
        available_ciphers=$(openssl ciphers -s -tls1_3 | awk '{print $1}')
        echo "ciphersuites = $available_ciphers" >> $stunnel_conf_file
        if [ $? -ne 0 ]; then
            chattr -f +i $stunnel_conf_file
            eecho "Failed to add 'ciphersuites' info to $stunnel_conf_file!"
            return 1
        fi
    fi

    chattr -f +i $stunnel_conf_file
}


check_if_notls_mount_exists()
{
    # Check if the mount to the same endpoint exists that is using clear text (without TLS).
    local nfs_mounts=$(findmnt | grep nfs4 | grep -v $LOCALHOST 2>&1 | awk '{print $2}')

    #
    # For no matching mounts also, findmnt exits with a failure return, so check
    # for both exit status and non-empty error o/p.
    #
    if [ $? -ne 0 -a -n "$nfs_mounts" ]; then
        eecho "${nfs_mounts}."
        eecho "[FATAL] findmnt failed unexpectedly!"
        # This usually indicates some non-transient issue, bail out.
        exit 1
    fi

    for mount in $nfs_mounts; do
        local mount_hostname=$(echo "$mount" | cut -d: -f1)
        local mount_ip_address=$(getent hosts "$mount_hostname" | awk '{print $1}')

        if [ "$mount_ip_address" == "$storageaccount_ip" ]; then
            eecho "Mount failed!"
            eecho "Mount to the same endpoint ${storageaccount_ip} exists that is using clear text (no TLS). Cannot mount with TLS to the same endpoint as they use the same connection."
            eecho "Try unmounting the share on ${mount_hostname} and run the mount command again."
            exit 1
        fi
    done
}


# For the given AZNFS endpoint FQDN return a local IP that should proxy it.
# If there is at least one mount to the same FQDN it MUST return the local IP
# used for that, else assign a new free local IP.
# really consider moving this to common.sh
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
            # rename this
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
# Mount nfsv4 files share with TLS encryption.
#
tls_nfsv4_files_share_mount()
{
    local storageaccount
    local container
    local extra

    # Set trap to cleanup the lock on mountmap file on exit.
    trap 'cleanup' EXIT

    # Lock the mountmap file as both mounthelper and watchdog processes can update the file.
    exec {fd2}<$MOUNTMAPv4
    flock -e $fd2

    vecho "nfs_dir=[$nfs_dir], nfs_host_ip=[$storageaccount_ip], mount_point=[$mount_point], options=[$OPTIONS], mount_options=[$MOUNT_OPTIONS]."

    IFS=/ read _ storageaccount container extra <<< "$nfs_dir"

    EntryExistinMountMap="true"

    #daniewo do some ip checking
    stunnel_conf_file="$STUNNELDIR/stunnel_$storageaccount_ip.conf"


    if [ ! -f $stunnel_conf_file ]; then
        EntryExistinMountMap="false"
    else
        # If config file exists, update the mountmap status to waiting.
        local existing_mountmap_entry=$(grep -m1 "$stunnel_conf_file" $MOUNTMAPv4)
        if [ -n "$existing_mountmap_entry" ]; then
            chattr -f -i $MOUNTMAPv4
            # Update the status to waiting - even if the mount on this share has failed but we haven't cleaned up the files yet, we should still update the status
            # to waiting and reuse the mountmap entry and stunnel files. Also add mount timeout to the mountmap entry. Used when aznfsWatchdog is cleaning up the mountmap file.
            # Since we are locking the mountmap file, we can't safely update the file using sed, we should overwrite
            # the file instead.
            vecho "Stunnel config file already exist. Updating mountmap status to waiting on $MOUNTMAPv4 for entry $existing_mountmap_entry."
            current_timestamp=$(date +%s)
            mount_timeout=$(($current_timestamp + $MOUNT_TIMEOUT_IN_SECONDS))

            out=$(sed "\#$stunnel_conf_file;#s#\(.*;\)[^;]*;\([0-9]*\)#\1waiting;${mount_timeout}#" $MOUNTMAPv4)
            ret=$?
            if [ $ret -eq 0 ]; then
                #
                # If this echo fails then MOUNTMAPv4 could be truncated.
                #
                echo "$out" > $MOUNTMAPv4
                ret=$?
                out=
                if [ $ret -ne 0 ]; then
                    eecho "*** [FATAL] MOUNTMAPv4 may be in inconsistent state, contact Microsoft support ***"
                fi
            fi

            if [ $ret -ne 0 ]; then
                chattr -f +i $MOUNTMAPv4
                eecho "[FATAL] failed to update ${MOUNTMAPv4}! Won't proceed with mount."
                exit 1
            fi

            chattr -f +i $MOUNTMAPv4
        else
            # There are two cases where the mountmap entry does not exist but the stunnel_conf_file does:
            # 1. Mount script first creates stunnel config file and then adds mountmap entry - so if
            # the mount process is killed after creating stunnel config file but before adding mountmap entry,
            # we should remove the stunnel config file and create a new one.
            # 2. If we kill the watchdog process right after unmount (can happen on reboot), watchdog might have cleaned up the mountmap entry
            # but not the stunnel_conf_file. In this case, we should also remove the stunnel_conf_file and create a new one.
            vecho "Failed to find the mountmap entry for $stunnel_conf_file in $MOUNTMAPv4."
            accept_port=$(cat $stunnel_conf_file | grep accept | cut -d ':' -f 2)
            stunnel_pid_file="$STUNNELLOGDIR/stunnel_$storageaccount_ip.pid"
            stunnel_log_file="$STUNNELLOGDIR/stunnel_$storageaccount_ip.log"

            if [ -f "$stunnel_pid_file" ]; then
                pid=$(cat $stunnel_pid_file)
                vecho "killing stunnel process with pid: $pid on port: $accept_port"
                kill -9 $pid
                if [ $? -ne 0 ]; then
                    vecho "Unable to kill stunnel process $pid!"
                fi
                rm $stunnel_pid_file
            else
                vecho "stunnel pid file does not exist for $storageaccount_ip."
                # If there is a stunnel process running on the port, kill it since the mountmap entry doesn't exist.
                pid=$($NETSTATCOMMAND -tuapn | grep "$LOCALHOST:$accept_port" | awk '{print $7}' | cut -d/ -f1)
                vecho "killing stunnel process with pid:: $pid on port: $accept_port"
                kill -9 $pid
                if [ $? -ne 0 ]; then
                    vecho "Unable to kill stunnel process with pid $pid!"
                fi
            fi

            if [ -f "$stunnel_log_file" ]; then
                rm $stunnel_log_file
            fi

            chattr -i -f $stunnel_conf_file
            rm $stunnel_conf_file
            EntryExistinMountMap="false"
        fi
    fi

    if [ "$EntryExistinMountMap" == "false" ]; then

        # Shouldn't mount with both TLS and noTLS to the same endpoint as they use the same connection.
        check_if_notls_mount_exists

        # Note the available port for stunnel process.
        available_port=$(get_next_available_port)
        if [ $? -ne 0 ]; then
            eecho "Failed to get the available port for nfsv4.1 mount."
            exit 1
        fi

        vecho "Available Port: $available_port"

        if [ -z "$available_port" ]; then
            eecho "Running out of ports. Nfsv4.1 has port range $NFSV4_PORT_RANGE_START to $NFSV4_PORT_RANGE_END. All ports from this range are used by other processes."
            exit 1
        fi

        touch $stunnel_conf_file
        if [ $? -ne 0 ]; then
            eecho "[FATAL] Not able to create '${stunnel_conf_file}'!"
            exit 1
        fi

        chattr -f +i $stunnel_conf_file

        stunnel_log_file=
        stunnel_pid_file=

        add_stunnel_configuration $storageaccount_ip
        add_stunnel_configuration_status=$?

        if [ $add_stunnel_configuration_status -ne 0 ]; then
            eecho "Failed to add stunnel configuration to $stunnel_conf_file!"
            chattr -i -f $stunnel_conf_file
            rm $stunnel_conf_file
            exit 1
        fi

        vecho "Added stunnel configuration to $stunnel_conf_file."

        # start the stunnel process
        current_port=$(cat $stunnel_conf_file | grep accept | cut -d: -f2)
        vecho "Starting the stunnel on port $current_port"

        stunnel_status=$(stunnel $stunnel_conf_file 2>&1)
        if [ -n "$stunnel_status" ]; then
            is_binding_error=$(echo $stunnel_status | grep "$LOCALHOST:$current_port: Address already in use")
            if [ -z "$is_binding_error" ]; then
                eecho "[FATAL] Not able to start stunnel process for '${stunnel_conf_file}'"
                eecho "${stunnel_status}"
                chattr -i -f $stunnel_conf_file
                rm $stunnel_conf_file
                exit 1
            else
                vecho "Stunnel: Address ($LOCALHOST:$current_port) already in use. Find next available port and start stunnel."
                find_next_available_port_and_start_stunnel "$stunnel_conf_file"
                is_stunnel_running=$?
                if [ $is_stunnel_running -ne 0 ]; then
                    eecho "Failed to get the next available port and start stunnel."
                    chattr -i -f $stunnel_conf_file
                    rm $stunnel_conf_file
                    exit 1
                fi
            fi
        fi

        checksumHash=`cksum $stunnel_conf_file | awk '{print $1}'`
        if [ $? -ne 0 ]; then
            eecho "Failed to get the checksum hash of file: '${stunnel_conf_file}'!"
            chattr -i -f $stunnel_conf_file
            rm $stunnel_conf_file
            exit 1
        fi

        # Add mount timeout to the mountmap entry. Used when aznfsWatchdog is cleaning up the mountmap file.
        current_timestamp=$(date +%s)
        mount_timeout=$(($current_timestamp + $MOUNT_TIMEOUT_IN_SECONDS))

        # We keep track of the state in the mountmap file to prevent watchdog from removing the entry before the mount is complete.
        # Waiting: mountmap entry is added but mount command is not executed yet. Watchdog can ignore this entry.
        # Mounted: mount command is executed successfully. If the mount is unmounted, watchdog can remove this entry.
        # Failed: mount command failed. Watchdog can remove this entry.

        local mountmap_entry="$storageaccount_ip;$stunnel_conf_file;$stunnel_log_file;$stunnel_pid_file;$checksumHash;waiting;$mount_timeout"
        chattr -f -i $MOUNTMAPv4
        echo "$mountmap_entry" >> $MOUNTMAPv4
        if [ $? -ne 0 ]; then
            chattr -f +i $MOUNTMAPv4
            eecho "[$mountmap_entry] failed to add!"
            chattr -i -f $stunnel_conf_file
            rm $stunnel_conf_file
            exit 1
        fi
        chattr -f +i $MOUNTMAPv4
    else
        # EntryExistinMountMap is true. That means stunnel_conf_file already exist for the storageaccount IP.
        vecho "Stunnel config file already exist for $storageaccount with IP $storageaccount_ip: $stunnel_conf_file"

        # It's possible that the stunnel process is not running for the storageaccount.
        is_stunnel_running=

        # Check if stunnel_pid_file exist for storageaccount and stunnel process is running.
        stunnel_pid_file="$STUNNELLOGDIR/stunnel_$storageaccount_ip.pid"
        if [ -f "$stunnel_pid_file" ]; then
            is_stunnel_running=$($NETSTATCOMMAND -anp | grep stunnel | grep `cat $stunnel_pid_file`)
        fi

        if [ -z "$is_stunnel_running" ]; then
            current_port=$(cat $stunnel_conf_file | grep accept | cut -d: -f2)
            vecho "stunnel is not running! Restarting the stunnel on port $current_port"

            stunnel_status=$(stunnel $stunnel_conf_file 2>&1)
            if [ -n "$stunnel_status" ]; then
                is_binding_error=$(echo $stunnel_status | grep "$LOCALHOST:$current_port: Address already in use")
                if [ -z "$is_binding_error" ]; then
                    eecho "[FATAL] Not able to start stunnel process for '${stunnel_conf_file}'!"
                    eecho "${stunnel_status}"
                    exit 1
                else
                    checksumHash=`cksum $stunnel_conf_file | awk '{print $1}'`
                    vecho "Stunnel: Address ($LOCALHOST:$current_port) already in use. Find next available port and start stunnel."
                    find_next_available_port_and_start_stunnel "$stunnel_conf_file"
                    is_stunnel_running=$?
                    if [ $is_stunnel_running -ne 0 ]; then
                        eecho "Failed to get the next available port and start stunnel."
                        exit 1
                    fi
                    # If we have updated the port in stunnel config file, we also need to update the checksum hash in mountmap file.
                    new_checksumHash=`cksum $stunnel_conf_file | awk '{print $1}'`
                    chattr -f -i $MOUNTMAPv4

                    # Since we are locking the mountmap file, we can't safely update it using sed, we should overwrite
                    # the file instead.
                    vecho "Updating the checksum hash on $MOUNTMAPv4 from $checksumHash to $new_checksumHash."
                    out=$(sed "s/$checksumHash/$new_checksumHash/" $MOUNTMAPv4)
                    ret=$?
                    if [ $ret -eq 0 ]; then
                        #
                        # If this echo fails then MOUNTMAPv4 could be truncated.
                        #
                        echo "$out" > $MOUNTMAPv4
                        ret=$?
                        out=
                        if [ $ret -ne 0 ]; then
                            eecho "*** [FATAL] MOUNTMAPv4 may be in inconsistent state, contact Microsoft support ***"
                        fi
                    fi

                    if [ $ret -ne 0 ]; then
                        chattr -f +i $MOUNTMAPv4
                        eecho "[FATAL] failed to update ${MOUNTMAPv4}! Won't proceed with mount."
                        exit 1
                    fi

                    chattr -f +i $MOUNTMAPv4
                fi
            fi
        else
            vecho "Stunnel process is already running for $storageaccount_ip."
        fi
    fi

    flock -u $fd2
    exec {fd2}<&-

    stunnel_port=$(cat $stunnel_conf_file | grep accept | cut -d: -f2)

    vecho "Stunnel process is running for $storageaccount_ip on accept port $stunnel_port."

    vecho "Running the mount command: ${LOCALHOST}:${nfs_dir} on $mount_point with port:${stunnel_port}"
    mount_output=$(mount -t nfs -o "$MOUNT_OPTIONS,port=$stunnel_port" "${LOCALHOST}:${nfs_dir}" "$mount_point" 2>&1)
    mount_status=$?

    if [ -n "$mount_output" ]; then
        pecho "$mount_output"
    fi

    # Lock the mountmap file and update the status of the mount entry.
    exec {fd2}<$MOUNTMAPv4
    flock -e $fd2

    chattr -f -i $MOUNTMAPv4
    if [ $mount_status -ne 0 ]; then
        # If the status is not waiting then we should not mark it as failed - it means there are other mounts on the same share.
        vecho "Updating mountmap status to failed."
        out=$(sed "\#$stunnel_conf_file;#s#;waiting#;failed#" $MOUNTMAPv4)
        ret=$?
        if [ $ret -eq 0 ]; then
            #
            # If this echo fails then MOUNTMAPv4 could be truncated.
            #
            echo "$out" > $MOUNTMAPv4
            ret=$?
            out=
            if [ $ret -ne 0 ]; then
                eecho "*** [FATAL] MOUNTMAPv4 may be in inconsistent state, contact Microsoft support ***"
            fi
        fi

        chattr -f +i $MOUNTMAPv4
        eecho "Mount failed!"
        exit 1
    else
        vecho "Updating mountmap status to mounted."
        out=$(sed "\#$stunnel_conf_file;#s#;waiting#;mounted#" $MOUNTMAPv4)
        ret=$?
        if [ $ret -eq 0 ]; then
            #
            # If this echo fails then MOUNTMAPv4 could be truncated.
            #
            echo "$out" > $MOUNTMAPv4
            ret=$?
            out=
            if [ $ret -ne 0 ]; then
                eecho "*** [FATAL] MOUNTMAPv4 may be in inconsistent state, contact Microsoft support ***"
            fi
        fi

        chattr -f +i $MOUNTMAPv4
        vecho "Mount completed: ${LOCALHOST}:${nfs_dir} on $mount_point with port:${stunnel_port}"
    fi
}

# Check if aznfswatchdogv4 service is running.
if ! ensure_aznfswatchdog "aznfswatchdogv4"; then
    exit 1
fi

# Mount helper creates a stunnel process per storage account IP address.
storageaccount_ip=$(getent hosts "$nfs_host" | awk 'NR==1 {print $1}')

if [ -z "$storageaccount_ip" ]; then
    eecho "Failed to resolve the IP address for $nfs_host!"
    exit 1
fi

vecho "nfs_host=[$nfs_host], nfs_host_ip=[$storageaccount_ip], nfs_dir=[$nfs_dir], mount_point=[$mount_point], options=[$OPTIONS], mount_options=[$MOUNT_OPTIONS]."

# MOUNTMAPv4 file must have been created by aznfswatchdog service. It's created in common.sh.
if [ ! -f "$MOUNTMAPv4" ]; then
    eecho "[FATAL] ${MOUNTMAPv4} not found!"

    if systemd_is_init; then
        pecho "Try restarting the aznfswatchdogv4 service using 'systemctl start aznfswatchdogv4' and then retry the mount command."
    else
        eecho "aznfswatchdogv4 service not running, please make sure it's running and try again!"
    fi

    pecho "If the problem persists, contact Microsoft support."
    exit 1
fi

if ! chattr -f +i $MOUNTMAPv4; then
    wecho "chattr does not work for ${MOUNTMAPv4}!"
fi

if [[ "$MOUNT_OPTIONS" == *"notls"* ]]; then
    vecho "notls option is enabled. Mount nfs share without TLS."

    # Need to acquire lock on mountmap file to prevent having mixed TLS and non-TLS mounts on the same endpoint.
    exec {fd2}<$MOUNTMAPv4
    flock -e $fd2

    if [[ "$MOUNT_OPTIONS" == *"clean"* ]]; then

        vecho "clean option is enabled. Update the status of mountmap entry for $storageaccount_ip."
        stunnel_conf_file="$STUNNELDIR/stunnel_$storageaccount_ip.conf"

        if [ -f "$stunnel_conf_file" ]; then
            accept_port=$(cat $stunnel_conf_file | grep accept | cut -d ':' -f 2)
            findmnt=$(findmnt | grep 'nfs4\|$LOCALHOST' 2>&1)

            if echo "$findmnt" | grep "$accept_port" >/dev/null; then
                eecho "There is a share mounted on $storageaccount_ip using TLS. Cannot unmount the share without TLS."
                flock -u $fd2
                exec {fd2}<&-
                exit 1
            fi

            stunnel_pid_file=`cat $MOUNTMAPv4 | grep "stunnel_$storageaccount_ip.pid" | cut -d ";" -f4 | awk 'NR==1 {print $1}'`
            pid=$(cat $stunnel_pid_file)
            vecho "killing stunnel process with pid: $pid on port: $accept_port"
            kill -9 $pid
            if [ $? -ne 0 ]; then
                vecho "Unable to kill stunnel process $pid!"
            fi
            chattr -i -f $stunnel_conf_file
            rm $stunnel_conf_file
        fi
        
        chattr -f -i $MOUNTMAPv4
        #
        # We overwrite the file instead of inplace update by sed as that has a
        # very bad side-effect of creating a new MOUNTMAPv4 file. This breaks
        # any locking that we dependent on the old file.
        #
        out=$(sed "\#$storageaccount_ip#d" $MOUNTMAPv4)
        ret=$?
        if [ $ret -eq 0 ]; then
            #
            # If this echo fails then MOUNTMAPv4 could be truncated.
            #
            echo "$out" > $MOUNTMAPv4
            ret=$?
            out=
            if [ $ret -ne 0 ]; then
                eecho "*** [FATAL] MOUNTMAPv4 may be in inconsistent state, contact Microsoft support ***"
            fi
        fi

        chattr -f +i $MOUNTMAPv4

        if [[ "$MOUNT_OPTIONS" == *"clean,"* ]]; then
            MOUNT_OPTIONS=${MOUNT_OPTIONS//clean,/}
        else
            MOUNT_OPTIONS=${MOUNT_OPTIONS//,clean/}
        fi
    fi

    # If a mount to the same endpoint exists that is using TLS, then we cannot mount without TLS
    # to the same endpoint as they use the same connection.

    # Check if the mount to the same endpoint exists that is using TLS.
    mountmap_entry=$(grep -m1 "${storageaccount_ip};" $MOUNTMAPv4)
    if [ -n "$mountmap_entry" ]; then
        # storage_account=$(echo $mountmap_entry | cut -d';' -f1)
        eecho "Mount failed!"
        eecho "Mount to the same endpoint ${storageaccount_ip} exists that is using TLS. Cannot mount without TLS to the same endpoint as they use the same connection."
        eecho "If there are no mount using TLS on $storageaccount_ip, try mounting again with "clean" option. Otherwise, try unmounting the shares on $storageaccount_ip and run the mount command again."
        flock -u $fd2
        exec {fd2}<&-
        exit 1
    fi

     # Check if the mount to the same endpoint exists that is using non-TLS.
     mountmapnontls_entry=$(grep -m1 "${nfs_host}" $MOUNTMAPv4NONTLS)
     if [ -n "$mountmapnontls_entry" ]; then
        # storage_account=$(echo $mountmap_entry | cut -d';' -f1)
        eecho "Mount failed!"
        eecho "Mount to the same endpoint ${nfs_host} exists that is using non-TLS. Cannot mount without non-TLS to the same endpoint as they use the same connection."
        eecho "If there are no mount using non-TLS on $nfs_host, try mounting again with "clean" option. Otherwise, try unmounting the shares on $nfs_host and run the mount command again."
        flock -u $fd2
        exec {fd2}<&-
        exit 1
    fi

    if [[ "$MOUNT_OPTIONS" == *"notls,"* ]]; then
        MOUNT_OPTIONS=${MOUNT_OPTIONS//notls,/}
    else
        MOUNT_OPTIONS=${MOUNT_OPTIONS//,notls/}
    fi

    #after checking if the endpoint is mounted with TLS in mountmapv4, check for nontls mountmap file

    # Resolve the IP address for the NFS host
    nfs_ip=$(resolve_ipv4_with_preference_to_mountmapv4 "$nfs_host")
    vecho "Resolved IP address for FQDN from mountmap [$nfs_host -> $nfs_ip]"
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


    # daniewo check if nfs_host here needs to be changed to a local_ip (proxy)
    # nfs_ip=$(resolve_ipv4_with_preference_to_mountmapv3 "$nfs_host")
    #nfs_host is the fqdn, we need to mount using l_ip and not nfs_host
    #if we're doing non TLS mount, find a local IP to mount with, also find out what the nfs_ip will be.
    #that could be read from a file after mount
    #potential nconnect checks here too

    #get proxy ip to use for this nfs_ip
    # exec {fd}<$MOUNTMAPv4NONTLS
    # flock -e $fd #daniewo - do we need to grab a different fd?

    # #
    # # With the lock held first check if adding a new mountmap entry for this account will
    # # cause "accounts mounted on one client" to exceed the limit.
    # #
    # if check_account_count; then
    #     get_local_ip_for_fqdn $nfs_host
    #     ret=$?
    #     account_limit_exceeded=0
    # else
    #     account_limit_exceeded=1
    # fi
    # flock -u $fd
    # exec {fd}<&-

    # if [ "$account_limit_exceeded" == "1" ]; then
    # eecho "Mounts to target IP $nfs_ip ($nfs_host) already at max limit ($MAX_ACCOUNTS_MOUNTABLE_FROM_SINGLE_TENANT)!"
    # eecho "Mount failed!"
    # exit 1
    # fi

    # get local ip for fqdn, this here maps to target get_local_ip is from the IPTable
    get_local_ip_for_fqdn $nfs_host   #DANIEWO THIS IS THE CALLER THAT ADDS EVERYTHING INCLUDING INTO MOUNTMAPV4NONTLS.
    ret=$? 

    vecho "nfs_host=[$nfs_host], nfs_ip=[$nfs_ip], nfs_dir=[$nfs_dir], mount_point=[$mount_point], options=[$OPTIONS], mount_options=[$MOUNT_OPTIONS], local_ip=[$LOCAL_IP]."

    # Do the actual non tls mount.
    mount_output=$(mount -t nfs -o "$MOUNT_OPTIONS" "${LOCAL_IP}:${nfs_dir}" "$mount_point" 2>&1)
    mount_status=$?

    flock -u $fd2
    exec {fd2}<&-

    if [ -n "$mount_output" ]; then
        pecho "$mount_output"
        vecho "Mount: ${nfs_host}:${nfs_dir} on $mount_point"
    fi

    if [ $mount_status -ne 0 ]; then
        eecho "Mount failed!"
        exit 1
    else
        vecho "Mount completed: ${nfs_host}:${nfs_dir} on $mount_point"

        #TODO: grep nfs_host and nfs_dir and mount_point because it's possible the l_ip may used from a previous connection
        # and mismatch. So you would have to update localip in the mountmapv4nontls file


        #daniewo add to mountmapv4nontls for the fqdn, local_ip, nfs_ip, AZNFS.txt12345
        # Acquire lock on the non-TLS mountmap file
        exec {fd3}<"$MOUNTMAPv4NONTLS"
        flock -e $fd3

        # Ensure file is writable (remove immutable)
        chattr -f -i "$MOUNTMAPv4NONTLS"

        # Format: "<FQDN> <LOCAL_IP> <NFS_IP> <AZNFS.txt12345>"
        new_entry="$nfs_host $LOCAL_IP $nfs_ip"
        eecho "nfsIP = $nfs_ip aznfsFileName"
        eecho "New entry to add to MOUNTMAPv4NONTLS: $new_entry"
        # Reinstate immutability if used
        chattr -f +i "$MOUNTMAPv4NONTLS"

        # Release lock
        flock -u $fd3
        exec {fd3}<&-
    fi
else
    vecho "Mount nfs share with TLS."

    if [ -z "$NETSTATCOMMAND" ]; then
        eecho "No socket statistics command (netstat or ss) found! Cannot proceed with TLS mount."
        exit 1
    fi

    tls_nfsv4_files_share_mount
fi