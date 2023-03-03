#!/bin/bash
#
# Copyright (c) Microsoft Corporation.
#

RELEASE_NUMBER=x.y.z
apt=0
zypper=0
debian=0
yum="yum"

# For Ubuntu, system updates could sometimes occupy apt. We loop and wait until it's no longer busy
verify_apt_not_busy() 
{
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
           
use_dnf_or_yum() 
{
    yum="yum"
    if command -v dnf &> /dev/null; then
        yum="dnf"
        localinstall=0
        echo "Using 'dnf' instead of 'yum'"
    fi
}

# Detect OS and Version
__m=$(uname -m 2>/dev/null) || __m=unknown
__s=$(uname -s 2>/dev/null) || __s=unknown

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

case "${distro}" in
    *entOS*)
        use_dnf_or_yum
        sudo -E ${yum} -y install wget
        ;;

    *SUSE*)
        zypper=1
        sudo -E zypper install -y wget
        ;;

    *ebian*)
        apt=1
        debian=1
        sudo -E apt update
        sudo -E apt install -y wget
        sudo -E apt install -y software-properties-common
        ;;

    *buntu*)
        apt=1
        verify_apt_not_busy
        sudo -E apt update
        sudo -E apt install -y wget
        ;;

    *ocky*)
        use_dnf_or_yum
        sudo -E ${yum} -y install wget
        ;;

    *)
        echo "[FATAL] Unsupported Linux distribution: ${distro}:${distro_version}."
        exit 1
        ;;
esac

install_cmd=
if [ $apt -eq 1 ]; then
    install_cmd="apt"
    wget https://github.com/Azure/BlobNFS-mount/releases/download/${RELEASE_NUMBER}/aznfs_${RELEASE_NUMBER}_amd64.deb -P /tmp
    sudo apt install /tmp/aznfs_${RELEASE_NUMBER}_amd64.deb
    rm /tmp/aznfs_${RELEASE_NUMBER}_amd64.deb
elif [ $zypper -eq 1 ]; then
    install_cmd="zypper"
    # Does not support SUSE for now.
else
    install_cmd="yum"
    # Does not support CentOS for now.
fi

install_exit_code=$?
if [ $? -ne 0 ]; then
    echo "[FATAL] Error installing aznfs (exit code: $install_exit_code). See '$install_cmd' command logs for more information."
fi

echo "Latest version of aznfs is installed."
