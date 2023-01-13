#!/bin/bash
#
# Copyright (c) Microsoft Corporation.
#

proxy=
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
verify_apt_not_busy {
    for i in {1..30}
    do
        sudo lsof /var/lib/dpkg/lock-frontend
        if [ $? -ne 0 ]; then
            return
        fi
        echo "Another apt/dpkg process is updating system. Retrying up to 5 minutes...$(expr $i \* 30) seconds"
        sleep 10
    done
    echo "file /var/lib/dpkg/lock-frontend is still busy after 5 minutes. Please make sure no other apt/dpkg updates is still running, and retry again."
    exit 1
}
           
use_dnf_or_yum {
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

# Check physical memory available
check_physical_memory

# Detect OS and Version
__m=$(uname -m 2>/dev/null) || __m=unknown
__s=$(uname -s 2>/dev/null)  || __s=unknown

distro=
distro_version=
case "${__m}:${__s}" in
    "x86_64:Linux")
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
               echo "Unknown linux distro."
               exit 1
        fi
        ;;
    *)
        echo "Unsupported platform: ${__m}:${__s}."
        exit 1
        ;;
esac

distro_major_version=$(echo "${distro_version}" | cut -f1 -d".")
distro_minor_version=$(echo "${distro_version}" | cut -f2 -d".")

case "${distro}" in
    *edHat* | *ed\ Hat*)
        use_dnf_or_yum
        sudo -E ${yum} -y install curl
        ;;

    *entOS*)
        use_dnf_or_yum
        sudo -E ${yum} -y install curl
        ;;

    *racle*)
        use_dnf_or_yum
        sudo -E ${yum} -y install curl
        ;;

    *SLES*)
        zypper=1
        sudo -E zypper install -y curl
        ;;

    *mazon\ Linux*)
        use_dnf_or_yum
        sudo -E ${yum} -y install curl
        ;;

    *ebian*)
        apt=1
        debian=1
        sudo -E apt update
        sudo -E apt install -y curl
        sudo -E apt install -y software-properties-common
        ;;        

    *buntu*)
        apt=1
        verify_apt_not_busy
        sudo -E apt update
        sudo -E apt install -y curl
        ;;        

    *ariner*)
        use_dnf_or_yum
        sudo -E ${yum} -y install curl
        ;;

    *ocky*)
        use_dnf_or_yum
        sudo -E ${yum} -y install curl
        ;;

    *)
        echo "Unsupported Linux distribution: ${distro}:${distro_major_version}.${distro_minor_version}."
        exit 1
        ;;
esac

#
# Install the aznfs mount helper.
#
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
