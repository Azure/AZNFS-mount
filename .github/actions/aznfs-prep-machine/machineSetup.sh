#!/bin/bash

#
# This returns distro id in a canonical form, that rest of the code understands.
# We only use lowercase single word names for distro names:
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

#
# Detect OS and Version.
#
__m=$(uname -m 2>/dev/null) || __m=unknown
__s=$(uname -s 2>/dev/null) || __s=unknown

#
# Try to detect the distro in a resilient manner and set distro_id
# global variables.
#
case "${__m}:${__s}" in
    "x86_64:Linux")
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
        ;;
    *)
        echo "[FATAL] Unsupported platform: ${__m}:${__s}."
        exit 1
        ;;
esac

bash_version=$(bash --version | head -n 1)

echo "Linux distribution: $linux_distro"
echo "Bash version: $bash_version"

if [ "$distro_id" == "ubuntu" ]; then
    sudo apt-get update
    sudo apt-get install -y build-essential
elif [ "$distro_id" == "centos" -o "$distro_id" == "rocky" -o "$distro_id" == "rhel" ]; then
    sudo yum groupinstall -y "Development Tools"
fi