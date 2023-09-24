#!/bin/bash

yum="yum"
apt=1
zypper=0
install_cmd=
distro_id=
REPO_OWNER="Azure"
REPO_NAME="AZNFS-mount"
user_wants_update=false

export DEBIAN_FRONTEND=noninteractive

# Load common aznfs helpers.
. /opt/microsoft/aznfs/common.sh


use_dnf_or_yum() 
{
    yum="yum"
    if command -v dnf &> /dev/null; then
        yum="dnf"
        pecho "Using 'dnf' instead of 'yum'"
    fi
}

#
# Install the package appropriately as per the current distro.
# If distro_id is already detected it uses that else it tries to guess
# the distro.
#
ensure_pkg()
{
    local pkg="$1"
    local distro="$distro_id"

    if [ "$distro" == "ubuntu" ]; then
        apt=1
        apt install -y $pkg
    elif [ "$distro" == "centos" -o "$distro" == "rocky" -o "$distro" == "rhel" ]; then
        # lsb_release package is called redhat-lsb-core in redhat/centos.
        if [ "$pkg" == "lsb-release" ]; then
            pkg="redhat-lsb-core"
        fi
        use_dnf_or_yum
        $yum install -y $pkg
    elif [ "$distro" == "sles" ]; then
        zypper=1
        zypper install -y $pkg
    fi
}

# Custom version comparison function
compare_versions()
{
    local current_version=$1
    local latest_version=$2

    # Split version strings into arrays
    IFS='.' read -ra v1_parts <<< "$current_version"
    IFS='.' read -ra v2_parts <<< "$latest_version"

    # Compare each component of the version
    for ((i = 0; i < ${#v1_parts[@]}; i++)); do
        if [ "${v1_parts[i]}" -lt "${v2_parts[i]}" ]; then
            echo "1" # current_version < latest_version
            return
        elif [ "${v1_parts[i]}" -gt "${v2_parts[i]}" ]; then
            echo "-1" # current version > latest_version
            return
        fi
    done

    # If all components are equal, the versions are equal
    echo "0"
}

check_and_perform_update_if_set() 
{
    REPO_OWNER="Azure"
    REPO_NAME="AZNFS-mount"

    # Define the GitHub API URL to get the latest release
    API_URL="https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest"

    # Use curl to make the API request and extract the latest release version
    LATEST_RELEASE=$(curl -s "$API_URL" | grep "tag_name" | cut -d '"' -f 4)

    # Print the latest release version
    vecho "Latest release version: $LATEST_RELEASE"

    if [ $apt -eq 1 ]; then
        install_cmd="apt"
        package_info=$(apt-cache show aznfs 2>/dev/null)
        is_uninstalled=$(echo "$package_info" | grep "^Status" | grep "\<deinstall\>")
        CURRENT_VERSION=$(apt-cache show aznfs 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2)
        if [ -n "$CURRENT_VERSION" -a -z "$is_uninstalled" ]; then
            result=$(compare_versions "$CURRENT_VERSION" "$LATEST_RELEASE")
            if [ "$result" -eq "1" ]; then
                AZNFS_RELEASE="aznfs-${LATEST_RELEASE}-1"

                # Check if user_wants_update is true before performing the update
                if [ "$user_wants_update" = "true" ]; then
                    vecho "user_wants_update=true, so updating the version"
                    # Download the latest release and install it
                    wget "https://github.com/Azure/AZNFS-mount/releases/download/${LATEST_RELEASE}/${AZNFS_RELEASE}_amd64.deb" -P /tmp
                    vecho "DOWNLOAD SUCCESSFUL"
                    apt install -y "/tmp/${AZNFS_RELEASE}_amd64.deb"
                    install_error=$?

                    # Clean up downloaded package file
                    rm -f "/tmp/${AZNFS_RELEASE}_amd64.deb"
                else
                    vecho "Version $LATEST_RELEASE of AZNFS is available. Set AUTO_UPDATE_AZNFS=true to update"
                fi
            else
                vecho "AZNFS version $CURRENT_VERSION is up-to-date or newer."
            fi
        fi

    elif [ $zypper -eq 1 ]; then
        install_cmd="zypper"
        CURRENT_VERSION=$(zypper info aznfs_sles 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2 | cut -d '-' -f1)
        if [ -n "$CURRENT_VERSION" ]; then
            result=$(compare_versions "$CURRENT_VERSION" "$LATEST_RELEASE")
            if [ "$result" -eq "1" ]; then
                AZNFS_RELEASE_SUSE="aznfs_sles-${LATEST_RELEASE}-1"

                # Check if user_wants_update is true before performing the update
                if [ "$user_wants_update" = true ]; then
                    # Download the latest release and install it
                    wget https://github.com/Azure/AZNFS-mount/releases/download/${LATEST_RELEASE}/${AZNFS_RELEASE_SUSE}.x86_64.rpm -P /tmp
                    zypper install --allow-unsigned-rpm -y /tmp/${AZNFS_RELEASE_SUSE}.x86_64.rpm
                    install_error=$?

                    # Clean up downloaded package file
                    rm -f /tmp/${AZNFS_RELEASE_SUSE}.x86_64.rpm
                else
                    vecho "Version $LATEST_RELEASE of AZNFS is available. Set AUTO_UPDATE_AZNFS=true to update"
                fi
            else
                vecho "AZNFS version $CURRENT_VERSION is up-to-date or newer."
            fi
        fi

    else
        install_cmd="yum"
        CURRENT_VERSION=$(yum info aznfs 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2)
        if [ -n "$CURRENT_VERSION" ]; then
            result=$(compare_versions "$CURRENT_VERSION" "$LATEST_RELEASE")
            if [ "$result" -eq "1" ]; then
                AZNFS_RELEASE="aznfs-${LATEST_RELEASE}-1"

                # Check if user_wants_update is true before performing the update
                if [ "$user_wants_update" = "true" ]; then
                    # Download the latest release and install it
                    wget https://github.com/Azure/AZNFS-mount/releases/download/${LATEST_RELEASE}/${AZNFS_RELEASE}.x86_64.rpm -P /tmp
                    yum install -y /tmp/${AZNFS_RELEASE}.x86_64.rpm
                    install_error=$?

                    # Clean up downloaded package file
                    rm -f /tmp/${AZNFS_RELEASE}.x86_64.rpm
                else
                    vecho "Version $LATEST_RELEASE of AZNFS is available. Set AUTO_UPDATE_AZNFS=true to update"
                fi
            else
                vecho "AZNFS version $CURRENT_VERSION is up-to-date or newer."
            fi
        fi
    fi
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
            pecho "Retrieving distro info from /etc/centos-release..."
            distro_id="centos"
        elif [ -f /etc/os-release ]; then
            pecho "Retrieving distro info from /etc/os-release..."
            distro_id=$(grep "^ID=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
            distro_id=$(canonicalize_distro_id $distro_id)
        else
            eecho "[FATAL] Unknown linux distro, /etc/os-release not found!"
            pecho "Download .deb/.rpm package based on your distro from 'https://github.com/Azure/AZNFS-mount/releases/latest'"
            pecho "If the problem persists, contact Microsoft support."
        fi
        ;;
    *)
        eecho "[FATAL] Unsupported platform: ${__m}:${__s}."
        exit 1
        ;;
esac

ensure_pkg "wget"

vecho "AUTO_UPDATE_AZNFS is set to: $AUTO_UPDATE_AZNFS"
# Check if the user has set the environment variable to true
if [ "$AUTO_UPDATE_AZNFS" = "true"  ]; then
    vecho "updating user_wants_update=true"
    user_wants_update=true
fi

check_and_perform_update_if_set