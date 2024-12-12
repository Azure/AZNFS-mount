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
NFSV4_PORT_RANGE_START=20049
NFSV4_PORT_RANGE_END=21049
DEBUG_LEVEL="info"

# Certificates related variables.
CERT_PATH=
CERT_UPDATE_COMMAND=
STUNNEL_CAFILE=

# TODO: Might have to use portmap entry in future to determine the CONNECT_PORT for nfsv3.
CONNECT_PORT=2049

get_next_available_port()
{
    for ((port=NFSV4_PORT_RANGE_START; port<=NFSV4_PORT_RANGE_END; port++))
    do
        is_port_available=`netstat -tuapn | grep "$LOCALHOST:$port "`
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
        stunnel_status=$(stunnel $stunnel_conf_file 2>&1)
        if [ -n "$stunnel_status" ]; then
            is_binding_error=$(echo $stunnel_status | grep "$LOCALHOST:$new_used_port: Address already in use")
            if [ -z "$is_binding_error" ]; then
                eecho "[FATAL] Not able to start stunnel process for '${stunnel_conf_file}'!"
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
# Add stunnel configuration in stunnel_<storageaccount>.conf file.
#
add_stunnel_configuration()
{
    local storageaccount=$1
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

    # TODO: checkHost value could be different for prod tenants.
    # So need to change this value in future.
    echo "checkHost = xtest-superadmin.int.rdst-internal.net" >> $stunnel_conf_file
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

    stunnel_log_file="$STUNNELDIR/logs/stunnel_$storageaccount.log"
    echo "output = $stunnel_log_file" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to add log file path to $stunnel_conf_file!"
        return 1
    fi

    stunnel_pid_file="$STUNNELDIR/logs/stunnel_$storageaccount.pid"
    echo "pid = $stunnel_pid_file" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to add pid file path to $stunnel_conf_file!"
        return 1
    fi

    echo >> $stunnel_conf_file

    echo "[$nfs_host]" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to add $nfs_host service/entry name to $stunnel_conf_file!"
        return 1
    fi

    echo "client = yes" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to 'client = yes' to $stunnel_conf_file!"
        return 1
    fi

    echo "accept = $LOCALHOST:$available_port" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to add 'accept' info to $stunnel_conf_file!"
        return 1
    fi

    echo "connect = $nfs_host:$CONNECT_PORT" >> $stunnel_conf_file
    if [ $? -ne 0 ]; then
        chattr -f +i $stunnel_conf_file
        eecho "Failed to add 'connect' info to $stunnel_conf_file!"
        return 1
    fi

    chattr -f +i $stunnel_conf_file
}

#
# For the given AZNFS endpoint FQDN return a local IP that should proxy it.
# If there is at least one mount to the same FQDN it MUST return the local IP
# used for that, else assign a new free local IP.
#
get_local_ip_for_fqdn()
{
        local fqdn=$1
        local mountmap_entry=$(grep -m1 "^${fqdn} " $MOUNTMAPv4NONTLS) #change this to mountmapv4nontls
        # One local ip per fqdn, so return existing one if already present.
        IFS=" " read _ local_ip _ <<< "$mountmap_entry"

        if [ -n "$local_ip" ]; then
            LOCAL_IP=$local_ip

            #
            # Ask aznfswatchdog to stay away while we are using this proxy IP.
            # This is similar to holding a timed lease, we can safely use this
            # proxy IP w/o worrying about aznfswatchdog deleting it for 5 minutes.
            #
            touch_mountmapv4_nontls 

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

    vecho "nfs_dir=[$nfs_dir], mount_point=[$mount_point], options=[$OPTIONS], mount_options=[$MOUNT_OPTIONS]."

    IFS=/ read _ storageaccount container extra <<< "$nfs_dir"

    # Note the available port
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

    EntryExistinMountMap="true"

    stunnel_conf_file="$STUNNELDIR/stunnel_$storageaccount.conf"

    if [ ! -f $stunnel_conf_file ]; then
        EntryExistinMountMap="false"
    fi

    if [ "$EntryExistinMountMap" == "false" ]; then
        touch $stunnel_conf_file
        if [ $? -ne 0 ]; then
            eecho "[FATAL] Not able to create '${stunnel_conf_file}'!"
            exit 1
        fi

        chattr -f +i $stunnel_conf_file

        stunnel_log_file=
        stunnel_pid_file=

        add_stunnel_configuration $storageaccount
        add_stunnel_configuration_status=$?

        if [ $add_stunnel_configuration_status -ne 0 ]; then
            eecho "Failed to add stunnel configuration to $stunnel_conf_file!"
            chattr -i -f $stunnel_conf_file
            rm $stunnel_conf_file
            exit 1
        fi

        # start the stunnel process
        stunnel_status=$(stunnel $stunnel_conf_file 2>&1)
        if [ -n "$stunnel_status" ]; then
            is_binding_error=$(echo $stunnel_status | grep "$LOCALHOST:$available_port: Address already in use")
            if [ -z "$is_binding_error" ]; then
                eecho "[FATAL] Not able to start stunnel process for '${stunnel_conf_file}'!"
                chattr -i -f $stunnel_conf_file
                rm $stunnel_conf_file
                exit 1
            else
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

        local mountmap_entry="$nfs_host;$stunnel_conf_file;$stunnel_log_file;$stunnel_pid_file;$checksumHash"
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
        # EntryExistinMountMap is true. That means stunnel_conf_file already exist for the storageaccount.

        # Check if stunnel_pid_file exist for storageaccount
        stunnel_pid_file=`cat $MOUNTMAPv4 | grep "stunnel_$storageaccount.pid" | cut -d ";" -f4`
        if [ ! -f $stunnel_pid_file ]; then
            eecho "[FATAL] '${stunnel_pid_file}' does not exist!"
            exit 1
        fi

        is_stunnel_running=$(netstat -anp | grep stunnel | grep `cat $stunnel_pid_file`)
        if [ -z "$is_stunnel_running" ]; then
            vecho "stunnel is not running! Restarting the stunnel"

            stunnel_status=$(stunnel $stunnel_conf_file 2>&1)
            if [ -n "$stunnel_status" ]; then
                is_binding_error=$(echo $stunnel_status | grep "$LOCALHOST:$available_port: Address already in use")
                if [ -z "$is_binding_error" ]; then
                    eecho "[FATAL] Not able to start stunnel process for '${stunnel_conf_file}'!"
                    exit 1
                else
                    find_next_available_port_and_start_stunnel "$stunnel_conf_file"
                    is_stunnel_running=$?
                    if [ $is_stunnel_running -ne 0 ]; then
                        eecho "Failed to get the next available port and start stunnel."
                        exit 1
                    fi
                fi
            fi
        fi

        available_port=$(cat $stunnel_conf_file | grep accept | cut -d: -f2)
        vecho "Local Port to use: $available_port"
    fi
    
    #daniewo mount 
    mount_output=$(mount -t nfs -o "$MOUNT_OPTIONS,port=$available_port" "${LOCALHOST}:${nfs_dir}" "$mount_point" 2>&1)
    mount_status=$?

    if [ -n "$mount_output" ]; then
        pecho "$mount_output"
        vecho "Mount completed: ${LOCALHOST}:${nfs_dir} on $mount_point with port:${available_port}"
    fi

    if [ $mount_status -ne 0 ]; then
        eecho "Mount failed!"
        exit 1
    fi
}

#daniewo ----calls start here------

# Check if aznfswatchdogv4 service is running.
if ! ensure_aznfswatchdog "aznfswatchdogv4"; then
    exit 1
fi

vecho "nfs_host=[$nfs_host], nfs_dir=[$nfs_dir], mount_point=[$mount_point], options=[$OPTIONS], mount_options=[$MOUNT_OPTIONS]."

# MOUNTMAPv4 file must have been created by aznfswatchdog service.
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

    # If a mount to the same endpoint exists that is using TLS, then we cannot mount without TLS
    # to the same endpoint as they use the same connection.

    # Check if the mount to the same endpoint exists that is using TLS.
    mountmap_entry=$(grep -m1 "^${nfs_host};" $MOUNTMAPv4)
    if [ -n "$mountmap_entry" ]; then
        eecho "Mount to the same endpoint ${nfs_host} exists that is using TLS."
        eecho "Cannot mount without TLS to the same endpoint as they use the same connection."
        exit 1
    fi

    if [[ "$MOUNT_OPTIONS" == *"notls,"* ]]; then
        MOUNT_OPTIONS=${MOUNT_OPTIONS//notls,/}
    else
        MOUNT_OPTIONS=${MOUNT_OPTIONS//,notls/}
    fi

    # Do the actual mount. daniewo nontls mount
    # get_local_ip_for_fqdn add this,  this will create a local IP that should proxy it. 
    # here is also some logic that returns the local_ip for the mount
    mount_output=$(mount -t nfs -o "$MOUNT_OPTIONS" "${nfs_host}:${nfs_dir}" "$mount_point" 2>&1)
    mount_status=$?
    #call to add file to mountmap
    # Add to new file and use the ensure methods so that we don't have any extra lines
    # Add FQDN proxy IP and Destination IP, does it use proxyip here? nfs_host is the IP?

    if [ -n "$mount_output" ]; then
        pecho "$mount_output"
        vecho "Mount completed: ${nfs_host}:${nfs_dir} on $mount_point"
    fi

    if [ $mount_status -ne 0 ]; then
        eecho "Mount failed!"
        exit 1
    fi
else
    vecho "Mount nfs share with TLS."

    # Check if the mount to the same endpoint exists that is using clear text (without TLS).
    findmnt=$(findmnt | grep nfs4 | grep -v $LOCALHOST 2>&1)

    #
    # For no matching mounts also, findmnt exits with a failure return, so check
    # for both exit status and non-empty error o/p.
    #
    if [ $? -ne 0 -a -n "$findmnt" ]; then
        eecho "${findmnt}."
        eecho "[FATAL] findmnt failed unexpectedly!"
        # This usually indicates some non-transient issue, bail out.
        exit 1
    fi

    if findmnt | grep "nfs4" | grep -v $LOCALHOST | grep -q "$nfs_host"; then
        eecho "Mount to the same endpoint ${nfs_host} exists that is using clear text (without TLS)."
        eecho "Cannot mount with TLS to the same endpoint as they use the same connection."
        exit 1
    fi

    tls_nfsv4_files_share_mount
fi