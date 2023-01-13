#!/bin/bash
#
# Copyright (c) Microsoft Corporation.
#
# This script will
#   1.  Configure host machine to download from packages.microsoft.com
#   2.  Install Azcmagent package
#   3.  Configure for proxy operation (if specified on the command line)
#
# Note that this script is for Linux only

proxy=
outfile=
configfile=
altdownloadfile=
format_success=
format_failure=
apt=0
zypper=0
rpm_distro=
deb_distro=
localinstall=0
debian=0
yum="yum"

function log_failure() {
  logBody="{\"subscriptionId\":\"${subscriptionId}\",\"resourceGroup\":\"${resourceGroup}\",\"tenantId\":\"${tenantId}\",\"location\":\"${location}\",\"correlationId\":\"${correlationId}\",\"authType\":\"${authType}\",\"operation\":\"onboarding\",\"messageType\":\"$1\",\"message\":\"$2\"}"

  his_endpoint=https://gbl.his.arc.azure.com
  if [ "${cloud}" = "AzureUSGovernment" ]; then
    his_endpoint=https://gbl.his.arc.azure.us
  elif [ "${cloud}" = "AzureChinaCloud" ]; then
    his_endpoint=https://gbl.his.arc.azure.cn
  fi

  if command -v wget &> /dev/null; then
    if [ -n "${proxy}" ]; then
        wget -qO- -e use_proxy=yes -e http_proxy=${proxy} --method=PUT --body-data="$logBody" ${his_endpoint}/log &> /dev/null || true
    else
        wget -qO- --method=PUT --body-data="$logBody" ${his_endpoint}/log &> /dev/null || true
    fi
  elif command -v curl &> /dev/null; then
    if [ -n "${proxy}" ]; then
        curl -s -X PUT --proxy ${proxy} -d "$logBody" ${his_endpoint}/log &> /dev/null || true
    else
        curl -s -X PUT -d "$logBody" ${his_endpoint}/log &> /dev/null || true
    fi
  fi
}

# Error codes used by azcmagent are in range of [0, 125].
# Installation scripts will use [127, 255]. Check install_azcmagent.ps1 for the codes used for Windows script.
function exit_failure {
    if [ -n "${outfile}" ]; then
    json_string=$(printf "$format_failure" "failed" "$1" "$2")
    echo "$json_string" > "$outfile"
    fi
    log_failure $1 "$2"
    echo "$2"
    exit 1
}

function exit_success {
    if [ -n "${outfile}" ]; then
    json_string=$(printf "$format_success" "success" "$1")
    echo "$json_string" > "$outfile"
    fi
    echo "$1"
    exit 0
}

function verify_downloadfile {
    if [ -z "${altdownloadfile##*.deb}" ]; then
        if [ $apt -eq 0 ]; then
        exit_failure 127 "$0: error: altdownload file should not have .deb suffix"
    fi
    elif [ -z "${altdownloadfile##*.rpm}" ]; then
        if [ $apt -eq 1 ]; then
        exit_failure 128 "$0: error: altdownload file should not have .rpm suffix"
    fi
    else
    if [ $apt -eq 0 ]; then
        altdownloadfile+=".rpm"
    else
        altdownloadfile+=".deb"
    fi
    fi
}
         
# For Ubuntu, system updates could sometimes occupy apt. We loop and wait until it's no longer busy
function verify_apt_not_busy {
    for i in {1..30}
    do
        sudo lsof /var/lib/dpkg/lock-frontend
        if [ $? -ne 0 ]; then
            return
        fi
        echo "Another apt/dpkg process is updating system. Retrying up to 5 minutes...$(expr $i \* 30) seconds"
        sleep 10
    done
    exit_failure 145 "$0: file /var/lib/dpkg/lock-frontend is still busy after 5 minutes. Please make sure no other apt/dpkg updates is still running, and retry again."
}
           
function use_dnf_or_yum {
    yum="yum"
    if command -v dnf &> /dev/null; then
        yum="dnf"
        localinstall=0
        echo "Using 'dnf' instead of 'yum'"
    fi
}

check_physical_memory {
    size=$(grep MemTotal /proc/meminfo | tr -s ' ' | cut -d ' ' -f2)
    unit=$(grep MemTotal /proc/meminfo | tr -s ' ' | cut -d ' ' -f3)
    if [ $unit == "kB" ]; then
        echo "Total physical memory: ${size} ${unit}"
    fi
}

# Parse the command-line

while [[ $# -gt 0 ]]
do
key="$1"

case "$key" in
    -p|--proxy)
    proxy="$2"
    shift
    shift
    ;;
    -o|--output)
    outfile="$2"
    format_failure='{\n\t"status": "%s",\n\t"error": {\n\t\t"code": "AZCM%04d",\n\t\t"message": "%s"\n\t}\n}'
    format_success='{\n\t"status": "%s",\n\t"message": "%s"\n}'
    shift
    shift
    ;;
    -a|--altdownload)
    altdownloadfile="$2"
    shift
    shift
    ;;
    -h|--help)
    echo "Usage: $0 [--proxy <proxy>] [--output <output file>] [--altdownload <alternate download file>]"
    echo "For example: $0 --proxy \"localhost:8080\" --output out.json --altdownload http://aka.ms/alternateAzcmagent.deb"
    exit 0
    ;;
    *)
    exit_failure 129 "$0: unrecognized argument: '${key}'. Type '$0 --help' for help."
    ;;
esac
done

# Check physical memory available
check_physical_memory

# Make sure we have systemctl in $PATH

if ! [ -x "$(command -v systemctl)" ]; then
    exit_failure 130 "$0: Azure Connected Machine Agent requires systemd, and that the command 'systemctl' be found in your PATH"
fi

# Detect OS and Version

__m=$(uname -m 2>/dev/null) || __m=unknown
__s=$(uname -s 2>/dev/null)  || __s=unknown

distro=
distro_version=
case "${__m}:${__s}" in
    x86_64:Linux)
    if [ -f /etc/centos-release ]; then
       echo "Retrieving distro info from /etc/centos-release..."
           distro=$(awk -F" " '{ print $1 }' /etc/centos-release)
           distro_version=$(awk -F" " '{ print $4 }' /etc/centos-release)
    elif [ -f /etc/os-release ]; then
       echo "Retrieving distro info from /etc/os-release..."
           distro=$(grep ^NAME /etc/os-release | awk -F"=" '{ print $2 }' | tr -d '"')
           distro_version=$(grep VERSION_ID /etc/os-release | awk -F"=" '{ print $2 }' | tr -d '"')
    elif which lsb_release 2>/dev/null; then
       echo "Retrieving distro info from lsb_release command..."
           distro=$(lsb_release -i | awk -F":" '{ print $2 }')
           distro_version=$(lsb_release -r | awk -F":" '{ print $2 }')
    else
           exit_failure 131 "$0: unknown linux distro. For supported OSs, see https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#supported-operating-systems"
        fi
        ;;
    *)
        exit_failure 132 "$0: unsupported platform: ${__m}:${__s}. For supported OSs, see https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#supported-operating-systems"
        ;;
esac

distro_major_version=$(echo "${distro_version}" | cut -f1 -d".")
distro_minor_version=$(echo "${distro_version}" | cut -f2 -d".")

# Configuring commands from https://docs.microsoft.com/en-us/windows-server/administration/linux-package-repository-for-microsoft-software

case "${distro}" in
    *edHat* | *ed\ Hat*)
        if [ "${distro_major_version}" -eq 7 ]; then
            echo "Configuring for Redhat 7..."
            rpm_distro=rhel/7
        elif [ "${distro_major_version}" -eq 8 ]; then
            echo "Configuring for Redhat 8..."
            rpm_distro=rhel/8
        elif [ "${distro_major_version}" -eq 9 ]; then
            echo "Configuring for Redhat 9..."
            rpm_distro=rhel/9.0
        else
            exit_failure 133 "$0: unsupported Linux distribution: ${distro}:${distro_major_version}.${distro_minor_version}. For supported OSs, see https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#supported-operating-systems"
        fi
        use_dnf_or_yum
        sudo -E ${yum} -y install curl
        ;;

    *entOS*)
        # Doc says to use RHEL for CentOS: https://docs.microsoft.com/en-us/windows-server/administration/linux-package-repository-for-microsoft-software
        if [ "${distro_major_version}" -eq 7 ]; then
            echo "Configuring for CentOS 7..."
            rpm_distro=rhel/7
            # Yum install on CentOS 7 is not idempotent, and will throw an error if "Nothing to do"
            # The workaround is to use "yum localinstall"
            localinstall=1
        elif [ "${distro_major_version}" -eq 8 ]; then
            echo "Configuring for CentOS 8..."
            rpm_distro=rhel/8
        else
            exit_failure 133 "$0: unsupported Linux distribution: ${distro}:${distro_major_version}.${distro_minor_version}. For supported OSs, see https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#supported-operating-systems"
        fi
        use_dnf_or_yum
        sudo -E ${yum} -y install curl
        ;;

    *racle*)
        if [ "${distro_major_version}" -eq 7 ]; then
            echo "Configuring for Oracle 7..."
            rpm_distro=rhel/7
        elif [ "${distro_major_version}" -eq 8 ]; then
            echo "Configuring for Oracle 8..."
            rpm_distro=rhel/8
        else
            exit_failure 133 "$0: unsupported Linux distribution: ${distro}:${distro_major_version}.${distro_minor_version}. For supported OSs, see https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#supported-operating-systems"
        fi
        use_dnf_or_yum
        sudo -E ${yum} -y install curl
        ;;

    *SLES*)
        zypper=1
        if [ "${distro_major_version}" -eq 12 ]; then
            echo "Configuring for SLES 12..."
            rpm_distro=sles/12
        elif [ "${distro_major_version}" -eq 15 ]; then
            echo "Configuring for SLES 15..."
        # As of 3/2020, there is a bug in the sles 15 config file in
        # download.microsoft.com.  So use the SLES 12 version for now.
            rpm_distro=sles/12
        else
            exit_failure 133 "$0: unsupported Linux distribution: ${distro}:${distro_major_version}.${distro_minor_version}. For supported OSs, see https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#supported-operating-systems"
        fi
        sudo -E zypper install -y curl
        ;;

    *mazon\ Linux*)
        if [ "${distro_major_version}" -eq 2 ]; then
            echo "Configuring for Amazon Linux 2 ..."
        else
            exit_failure 133 "$0: unsupported Linux distribution: ${distro}:${distro_major_version}.${distro_minor_version}. For supported OSs, see https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#supported-operating-systems"
        fi

    # Amazon Linux does not exist in packages.microsoft.com currently, so use Redhat 7 instead
    rpm_distro=rhel/7
        use_dnf_or_yum
        sudo -E ${yum} -y install curl
        ;;

    *ebian*)
    apt=1
        debian=1
        if [ "${distro_major_version}" -eq 10 ]; then
            echo "Configuring for Debian 10..."
        deb_distro=10
        elif [ "${distro_major_version}" -eq 9 ]; then
            echo "Configuring for Debian 9..."
        deb_distro=9
        elif [ "${distro_major_version}" -eq 11 ]; then
            echo "Configuring for Debian 11..."
        deb_distro=11
        else
            exit_failure 133 "$0: unsupported Linux distribution: ${distro}:${distro_major_version}.${distro_minor_version}. For supported OSs, see https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#supported-operating-systems"
        fi
        sudo -E apt update
        sudo -E apt install -y curl
        sudo -E apt install -y software-properties-common
        ;;        

    *buntu*)
    apt=1
        if [ "${distro_major_version}" -eq 16 ] && [ "${distro_minor_version}" -eq 04 ]; then
            echo "Configuring for Ubuntu 16.04..."
        deb_distro=16.04
        elif [ "${distro_major_version}" -eq 18 ] && [ "${distro_minor_version}" -eq 04 ]; then
            echo "Configuring for Ubuntu 18.04..."
        deb_distro=18.04
        elif [ "${distro_major_version}" -eq 20 ] && [ "${distro_minor_version}" -eq 04 ]; then
            echo "Configuring for Ubuntu 20.04..."
        deb_distro=20.04
        elif [ "${distro_major_version}" -eq 22 ] && [ "${distro_minor_version}" -eq 04 ]; then
            echo "Configuring for Ubuntu 22.04..."
        deb_distro=22.04
        else
            exit_failure 133 "$0: unsupported Linux distribution: ${distro}:${distro_major_version}.${distro_minor_version}. For supported OSs, see https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#supported-operating-systems"
        fi
        verify_apt_not_busy
        sudo -E apt update
        sudo -E apt install -y curl
        ;;        

    *ariner*)
        if [ "${distro_major_version}" -eq 1 ]; then
            echo "Configuring for Common Base Linux Mariner 1..."
        elif [ "${distro_major_version}" -eq 2 ]; then
            echo "Configuring for Common Base Linux Mariner 2..."
        else
            exit_failure 133 "$0: unsupported Linux distribution: ${distro}:${distro_major_version}.${distro_minor_version}. For supported OSs, see https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#supported-operating-systems"
        fi
        use_dnf_or_yum
        sudo -E ${yum} -y install curl
        ;;

    *ocky*)
        if [ "${distro_major_version}" -eq 8 ]; then
            echo "Configuring for Rocky Linux 8..."
            rpm_distro=rhel/8
        else
            exit_failure 133 "$0: unsupported Linux distribution: ${distro}:${distro_major_version}.${distro_minor_version}. For supported OSs, see https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#supported-operating-systems"
        fi
        use_dnf_or_yum
        sudo -E ${yum} -y install curl
        ;;

    *)
        exit_failure 133 "$0: unsupported Linux distribution: ${distro}:${distro_major_version}.${distro_minor_version}. For supported OSs, see https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites#supported-operating-systems"
        ;;
esac

# check whether we are in Azure
imds_response=$(curl "http://169.254.169.254/metadata/instance/compute?api-version=2019-06-01" -f -s -H "Metadata: true" --connect-timeout 1)
if [ $? -eq 0 ]; then
    # due to -f param, will return failed code on 404. So if we get here we are in Azure
    arc_test=$(systemctl show-environment | grep -c 'MSFT_ARC_TEST=true')
    if [ $? -eq 0 ]; then
        # test environment set for daemons, proceed with warning
        echo "WARNING: Running on an Azure Virtual Machine with MSFT_ARC_TEST set.
Azure Connected Machine Agent is designed for use outside Azure.
This virtual machine should only be used for testing purposes.
See https://aka.ms/azcmagent-testwarning for more details.
"
    else        
        exit_failure 141 "$0: cannot install Azure Connected Machine agent on an Azure Virtual Machine.
Azure Connected Machine Agent is designed for use outside Azure.
To connect an Azure VM for TESTING PURPOSES ONLY, see https://aka.ms/azcmagent-testwarning for more details."
    fi
fi

# Install the azcmagent

if [ -n "${altdownloadfile}" ]; then
    verify_downloadfile
    echo "Downloading from alternate location: ${altdownloadfile}..."

    if [ $apt -eq 1 ]; then
        if [ -n "${proxy}" ]; then
        curl --proxy ${proxy} "${altdownloadfile}" -o /tmp/azcmagent.deb            
        else
        curl "${altdownloadfile}" -o /tmp/azcmagent.deb
        fi
    else
        if [ -n "${proxy}" ]; then
        curl --proxy ${proxy} "${altdownloadfile}" -o /tmp/azcmagent.rpm
        else
        curl "${altdownloadfile}" -o /tmp/azcmagent.rpm
        fi
    fi
    if [ $? -ne 0 ]; then
        exit_failure 142 "$0: invalid --altdownload link: ${altdownloadfile}"
    fi
fi

install_cmd=
if [ $apt -eq 1 ]; then
    install_cmd="apt"
    if [ -n "${altdownloadfile}" ]; then
        sudo -E apt install -y /tmp/azcmagent.deb
    elif [ $debian -eq 1 ]; then
        if [ -n "${proxy}" ]; then
            curl --proxy ${proxy} https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
        else
            curl -sSL https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
        fi
        curlret=$?
        if [ $curlret -ne 0 ]; then
            exit_failure 146 "$0: curl download error: $curlret"
        fi
        sudo -E apt-add-repository https://packages.microsoft.com/debian/${deb_distro}/prod
        sudo -E apt-get update
    sudo -E apt install -y azcmagent
    else
        if [ -n "${proxy}" ]; then
            curl --proxy ${proxy} https://packages.microsoft.com/config/ubuntu/${deb_distro}/packages-microsoft-prod.deb -o /tmp/packages-microsoft-prod.deb
        else
            curl https://packages.microsoft.com/config/ubuntu/${deb_distro}/packages-microsoft-prod.deb -o /tmp/packages-microsoft-prod.deb
        fi
    curlret=$?
        if [ $curlret -ne 0 ]; then
            exit_failure 146 "$0: curl download error: $curlret"
        fi
        sudo -E dpkg -i /tmp/packages-microsoft-prod.deb
        sudo -E apt-get update
    sudo -E apt install -y azcmagent
    fi
elif [ $zypper -eq 1 ]; then
    install_cmd="zypper"
    if [ -n "${altdownloadfile}" ]; then
    sudo -E zypper install -y /tmp/azcmagent.rpm
    else
        if [ -n "${proxy}" ]; then
        curl --proxy ${proxy} https://packages.microsoft.com/keys/microsoft.asc > /tmp/microsoft.asc
        else
        curl https://packages.microsoft.com/keys/microsoft.asc > /tmp/microsoft.asc
        fi
    curlret=$?
        if [ $curlret -ne 0 ]; then
            exit_failure 146 "$0: curl download error: $curlret"
        fi
    sudo rpm --import /tmp/microsoft.asc
    sudo -E rpm -Uvh --force https://packages.microsoft.com/config/${rpm_distro}/packages-microsoft-prod.rpm
    sudo -E zypper install -y azcmagent
    fi
else
    install_cmd="yum"
    if [ -n "${altdownloadfile}" ]; then
        if [ $localinstall -eq 0 ]; then
            sudo -E ${yum} -y install /tmp/azcmagent.rpm
        else
            sudo -E ${yum} -y localinstall /tmp/azcmagent.rpm
        fi
    else
        if [ -n "${rpm_distro}" ]; then
            sudo -E rpm -Uvh https://packages.microsoft.com/config/${rpm_distro}/packages-microsoft-prod.rpm
        fi
    sudo -E ${yum} -y install azcmagent
    fi
fi

install_exit_code=$?
if [ $install_exit_code -ne 0 ]; then
    exit_failure 143 "$0: error installing azcmagent (exit code: $install_exit_code). See '$install_cmd' command logs for more information."
fi

# Set proxy, if any

if [ -n "${proxy}" ]; then
    echo "Configuring proxy..."
    sudo azcmagent config set proxy.url ${proxy}
fi

exit_success "Latest version of azcmagent is installed."
