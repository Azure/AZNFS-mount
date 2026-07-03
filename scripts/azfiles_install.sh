#!/bin/bash
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

export APPNAME="azfiles-nfs"
export PKG_NAME="azfiles-nfs"
export AUTO_UPDATE_KEY="AUTO_UPDATE_AZFILES_NFS"
export WATCHDOG_PROC="aznfswatchdogv4"
export WATCHDOG_SERVICE="aznfswatchdogv4"
export WATCHDOG_SERVICE_V4="aznfswatchdogv4"

exec /opt/microsoft/azfiles-nfs/aznfs_install.sh "$@"
