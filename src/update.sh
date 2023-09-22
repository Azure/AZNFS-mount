#!/bin/bash

# Load common aznfs helpers.
. /opt/microsoft/aznfs/common.sh


perform_update() 
{
    # GitHub repository information
    REPO_OWNER="Azure"
    REPO_NAME="AZNFS-mount"

    install_cmd=

    # Get the latest release version from the GitHub API
    LATEST_RELEASE=$(curl -s "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest" | grep "tag_name" | cut -d '"' -f 4)

    # Check if the latest release is different from the currently installed version
    CURRENT_VERSION=$(apt-cache show aznfs 2>/dev/null | grep "^Version" | tr -d " " | cut -d ':' -f2)

    if [ "$LATEST_RELEASE" != "$CURRENT_VERSION" ]; then
        echo "Updating to the latest release: $LATEST_RELEASE"

        AZNFS_RELEASE="aznfs-${LATEST_RELEASE}-1"
        
        wget "https://github.com/Azure/AZNFS-mount/releases/download/${LATEST_RELEASE}/${AZNFS_RELEASE}_amd64.deb" -P /tmp
        
        apt install -y "/tmp/${AZNFS_RELEASE}_amd64.deb"
        install_error=$?

        # Clean up downloaded package file
        rm -f "/tmp/${AZNFS_RELEASE}_amd64.deb"

        if [ $install_error -ne 0 ]; then
            echo "[FATAL] Error updating aznfs (Error: $install_error). See '$install_cmd' command logs for more information."
        fi
    else
        echo "Already updated aznfs"
    fi
}

perform_update