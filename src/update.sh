#!/bin/bash

yum="yum"
apt=1
zypper=0
install_cmd=
REPO_OWNER="Azure"
REPO_NAME="AZNFS-mount"
user_wants_update=false

# Load common aznfs helpers.
. /opt/microsoft/aznfs/common.sh


# Custom version comparison function
compare_versions() 
{
    local version1=$1
    local version2=$2

    # code for comparing the versions: 3 cases. v1>v2, v1=v2, v1<v2, testrelease edge case ?
    # echo "1" for if latest release > current release

    # echo "0" # Versions are equal
    echo "1"
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
                if [ $user_wants_update ]; then
                    # Download the latest release and install it
                    wget "https://github.com/Azure/AZNFS-mount/releases/download/${LATEST_RELEASE}/${AZNFS_RELEASE}_amd64.deb" -P /tmp
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
                if [ $user_wants_update ]; then
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
                if [ $user_wants_update ]; then
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


# Check if the user has set the environment variable to true
if [ $AUTO_UPDATE_AZNFS ]; then
    user_wants_update=true
fi

check_and_perform_update_if_set