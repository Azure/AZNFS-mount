Name: AZNFS_PACKAGE_NAME
Version: x.y.z
Release: 1
Summary: Mount helper program for correctly handling endpoint IP address changes for Azure Blob NFS mounts and providing a secure communication channel for Azure File NFS mounts
License: MIT
URL: https://github.com/Azure/AZNFS-mount/blob/main/README.md
Requires: bash, PROCPS_PACKAGE_NAME, conntrack-tools, iptables, bind-utils, iproute, util-linux, nfs-utils, NETCAT_PACKAGE_NAME, newt, net-tools, binutils, kernel-headers, openssl, openssl-devel, gcc, make
Recommends: build-essential

%description
Mount helper program for correctly handling endpoint IP address changes for Azure Blob NFS mounts and providing a secure communication channel for Azure File NFS mounts

%prep
mkdir -p ${STG_DIR}/RPM_DIR/root/rpmbuild/SOURCES/
tar -xzvf ${STG_DIR}/AZNFS_PACKAGE_NAME-${RELEASE_NUMBER}-1.x86_64.tar.gz -C ${STG_DIR}/RPM_DIR/

%files
/usr/sbin/aznfswatchdog
/usr/sbin/aznfswatchdogv4
/sbin/mount.aznfs
/opt/microsoft/aznfs/common.sh
/opt/microsoft/aznfs/mountscript.sh
/opt/microsoft/aznfs/nfsv3mountscript.sh
/opt/microsoft/aznfs/nfsv4mountscript.sh
/opt/microsoft/aznfs/aznfs_install.sh
/lib/systemd/system/aznfswatchdog.service
/lib/systemd/system/aznfswatchdogv4.service

%pre
init="$(ps -q 1 -o comm=)"
if [ "$init" != "systemd" ]; then
	echo "Cannot install this package on a non-systemd system!"
	exit 1
fi

INSTALLED_STUNNEL_VERSION="0"
REQUIRED_STUNNEL_VERSION="5.73"

if command -v stunnel >/dev/null 2>&1; then
    INSTALLED_STUNNEL_VERSION=$(stunnel -version 2>&1 | grep -Eo 'stunnel [0-9]+\.[0-9]+' | awk '{print $2}')
fi

cleanup_stunnel_files()
{
	cd -
	rm -rf /tmp/stunnel-${REQUIRED_STUNNEL_VERSION}
	rm -f /tmp/stunnel-${REQUIRED_STUNNEL_VERSION}.tar.gz
}

# Install stunnel if not present or if the installed version is older than the required version.
if (( $(echo $REQUIRED_STUNNEL_VERSION $INSTALLED_STUNNEL_VERSION | awk '{if ($1 > $2) print 1;}') )) ; then
	
	# Install stunnel from source.
	wget https://www.stunnel.org/archive/5.x/stunnel-${REQUIRED_STUNNEL_VERSION}.tar.gz -P /tmp
	if [ $? -ne 0 ]; then
		echo "Failed to download stunnel source code. Please install stunnel and try again."
		exit 1
	fi

	tar -xvf /tmp/stunnel-${REQUIRED_STUNNEL_VERSION}.tar.gz -C /tmp
	if [ $? -ne 0 ]; then
		echo "Failed to extract stunnel tarball. Please install stunnel and try again."
		cleanup_stunnel_files
		exit 1
	fi

	cd /tmp/stunnel-${REQUIRED_STUNNEL_VERSION}
	./configure
	if [ $? -ne 0 ]; then
		echo "Failed to configure the build. Please install stunnel and try again."
		cleanup_stunnel_files
		exit 1
	fi

	make
	if [ $? -ne 0 ]; then
		echo "Failed to build stunnel. Please install stunnel and try again."
		cleanup_stunnel_files
		exit 1
	fi

	make install
	if [ $? -ne 0 ]; then
		echo "Failed to install stunnel. Please install stunnel and try again."
		cleanup_stunnel_files
		exit 1
	fi

	cleanup_stunnel_files

	# Remove the old link and create a symlink to stunnel binary.
    [ -f /bin/stunnel ] && mv /bin/stunnel /bin/stunnel.old
    ln -sf /usr/local/bin/stunnel /bin/stunnel

    if command -v stunnel >/dev/null 2>&1; then
        echo "Successfully installed stunnel version ${REQUIRED_STUNNEL_VERSION}"
        rm -f /bin/stunnel.old
    else
        echo "Failed to install stunnel version ${REQUIRED_STUNNEL_VERSION}. Please install stunnel and try again."
        mv /bin/stunnel.old /bin/stunnel > /dev/null 2>&1
        exit 1
    fi
else
	echo "stunnel version $INSTALLED_STUNNEL_VERSION is already installed."
fi

flag_file="/tmp/.update_in_progress_from_watchdog.flag"

if [ -f "$flag_file" ]; then
	# Get the PID of aznfswatchdog.
	aznfswatchdog_pid=$(pgrep -x aznfswatchdog)
	
	# Read the PID from the flag file.
	aznfswatchdog_pid_inside_flag=$(cat "$flag_file")
	
	if [ "$aznfswatchdog_pid" != "$aznfswatchdog_pid_inside_flag" ]; then
		# The flag file is stale, remove it.
		rm -f "$flag_file"
		echo "Removed stale flag file"
	fi
fi

# In case of manual upgrade, stop the watchdog before proceeding.
if [ $1 == 2 ] && [ ! -f "$flag_file" ]; then
        systemctl stop aznfswatchdog
        systemctl disable aznfswatchdog

        systemctl stop aznfswatchdogv4
        systemctl disable aznfswatchdogv4

        echo "Stopped aznfs watchdog service"
fi


%post

FLAG_FILE="/tmp/.update_in_progress_from_watchdog.flag"
CONFIG_FILE="/opt/microsoft/aznfs/data/config"
AUTO_UPDATE_AZNFS="false"

parse_user_config()
{
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "[BUG] $CONFIG_FILE not found, proceeding with default values..."
        return
    fi

    # Read the value of AUTO_UPDATE_AZNFS from the configuration file and convert to lowercase for easy comparison later.
    AUTO_UPDATE_AZNFS=$(egrep -o '^AUTO_UPDATE_AZNFS[[:space:]]*=[[:space:]]*[^[:space:]]*' "$CONFIG_FILE" | tr -d '[:blank:]' | cut -d '=' -f2)
    AUTO_UPDATE_AZNFS=${AUTO_UPDATE_AZNFS,,}
}

user_consent_for_auto_update()
{
    parse_user_config

    if [ "$AUTO_UPDATE_AZNFS" == "true" ]; then
        return
    fi

    sed -i '/AUTO_UPDATE_AZNFS/d' "$CONFIG_FILE"

    if [ "$AZNFS_NONINTERACTIVE_INSTALL" == "1" ]; then
        echo "AUTO_UPDATE_AZNFS=true" >> "$CONFIG_FILE"
        return
    fi

    title="Enable auto update for AZNFS mount helper"
    auto_update_prompt=$(cat << EOF
    Stay up-to-date with the latest features, improvements, and security patches!

    AUTO-UPDATE WILL JUST UPDATE THE MOUNT HELPER BINARY AND WILL NOT CAUSE ANY DISRUPTION TO MOUNTED SHARES.

    We recommend enabling automatic updates for the best/seamless AZNFS experience.

    You can turn off auto-update at any time from /opt/microsoft/aznfs/data/config.
EOF
)

    if whiptail --title "$title" --yesno "$auto_update_prompt" 0 0 > /dev/tty; then
        echo "AUTO_UPDATE_AZNFS=true" >> "$CONFIG_FILE"
    else
        echo "AUTO_UPDATE_AZNFS=false" >> "$CONFIG_FILE"
    fi
}

# Set appropriate permissions.
chmod 0755 /opt/microsoft/aznfs/
chmod 0755 /usr/sbin/aznfswatchdog
chmod 0755 /usr/sbin/aznfswatchdogv4
chmod 0755 /opt/microsoft/aznfs/mountscript.sh
chmod 0755 /opt/microsoft/aznfs/nfsv3mountscript.sh
chmod 0755 /opt/microsoft/aznfs/nfsv4mountscript.sh
chmod 0755 /opt/microsoft/aznfs/aznfs_install.sh
chmod 0644 /opt/microsoft/aznfs/common.sh

# Set suid bit for mount.aznfs to allow mount for non-super user.
chmod 4755 /sbin/mount.aznfs

# Create data directory for holding mountmap and log file. 
mkdir -p /opt/microsoft/aznfs/data
chmod 0755 /opt/microsoft/aznfs/data

# Create log directory under /etc/stunnel to store stunnel logs
mkdir -p /etc/stunnel/microsoft/aznfs/nfsv4_fileShare/logs
chmod 0644 /etc/stunnel/microsoft/aznfs/nfsv4_fileShare/logs

# In case of upgrade.
if [ $1 == 2 ]; then
	# Move the mountmap, aznfs.log and randbytes files to new path in case these files exists and package is being upgraded.
	if [ -f /opt/microsoft/aznfs/mountmap ]; then
	        chattr -f -i /opt/microsoft/aznfs/mountmap
	        mv -vf /opt/microsoft/aznfs/mountmap /opt/microsoft/aznfs/data/
	        chattr -f +i /opt/microsoft/aznfs/data/mountmap
	fi

	if [ -f /opt/microsoft/aznfs/aznfs.log ]; then
	        mv -vf /opt/microsoft/aznfs/aznfs.log /opt/microsoft/aznfs/data/
	fi

	if [ -f /opt/microsoft/aznfs/randbytes ]; then
	        chattr -f -i /opt/microsoft/aznfs/randbytes
	        mv -vf /opt/microsoft/aznfs/randbytes /opt/microsoft/aznfs/data/
	        chattr -f +i /opt/microsoft/aznfs/data/randbytes
	fi
fi

# Check if the config file exists; if not, create it.
if [ ! -f "$CONFIG_FILE" ]; then
        # Create the config file and set default AUTO_UPDATE_AZNFS=false inside it.
        echo "AUTO_UPDATE_AZNFS=false" > "$CONFIG_FILE"

        # Set the permissions for the config file.
        chmod 0644 "$CONFIG_FILE"
fi

#
# If it's an auto update triggered by aznfswatchdog, don't restart watchdog.
# Additionally, ask user about auto update configuration.
#
if [ ! -f "$FLAG_FILE" ]; then
        user_consent_for_auto_update

		# Wanted by watchdog service
		systemctl enable nfs-client.target

        # Start watchdog service for NFSv3
        systemctl daemon-reload
        systemctl enable aznfswatchdog
        systemctl start aznfswatchdog

        # Start watchdog service for NFSv4
        systemctl enable aznfswatchdogv4
        systemctl start aznfswatchdogv4
else
        # Clean up the update in progress flag file.
        rm -f "$FLAG_FILE"
fi


if [ "DISTRO" != "suse" -a ! -f /etc/centos-release ]; then
	echo 	
	echo "*******************************************************************"
	echo "Do not uninstall AZNFS while you have active aznfs mounts!"
	echo "Doing so may lead to broken AZNFS package with unmet dependencies."
	echo "If you want to uninstall AZNFS make sure you unmount all aznfs mounts."
	echo "********************************************************************"
	echo
fi

%preun
# In case of purge/remove.
RED="\e[2;31m"
NORMAL="\e[0m"
if [ $1 == 0 ]; then
	# Verify if any existing mounts are there, warn the user about this.
	existing_mounts_v3=$(cat /opt/microsoft/aznfs/data/mountmap 2>/dev/null | egrep '^\S+' | wc -l)
	existing_mounts_v4=$(cat /opt/microsoft/aznfs/data/mountmapv4 2>/dev/null | egrep '^\S+' | wc -l)
	if [ $existing_mounts_v3 -ne 0 -o $existing_mounts_v4 -ne 0 ]; then
		echo
		echo -e "${RED}There are existing Azure Blob/Files NFS mounts using aznfs mount helper, they will not be tracked!" > /dev/tty
		echo -n -e "Are you sure you want to continue? [y/N]${NORMAL} " > /dev/tty
		read -n 1 result < /dev/tty
		echo
		if [ "$result" != "y" -a "$result" != "Y" ]; then
			echo "Removal aborted!"
			if [ "DISTRO" != "suse" -a ! -f /etc/centos-release ]; then
				echo
				echo "*******************************************************************"
				echo "Unfortunately some of the anzfs dependencies may have been uninstalled."
				echo "aznfs mounts may be affected and new aznfs shares cannot be mounted."
				echo "To fix this, run the below command to install dependencies:"
				echo "INSTALL_CMD install conntrack-tools iptables bind-utils iproute util-linux nfs-utils NETCAT_PACKAGE_NAME stunnel net-tools"
				echo "*******************************************************************"
				echo
			fi
			exit 1
		fi
	fi

	# Stop aznfswatchdog in case of removing the package.
	systemctl stop aznfswatchdog
	systemctl disable aznfswatchdog

	systemctl stop aznfswatchdogv4
	systemctl disable aznfswatchdogv4

	echo "Stopped aznfswatchdog service"
fi

%postun
# In case of purge/remove.
if [ $1 == 0 ]; then
	chattr -i -f /opt/microsoft/aznfs/data/mountmap
	chattr -i -f /opt/microsoft/aznfs/data/randbytes
	chattr -i -f /opt/microsoft/aznfs/data/mountmapv4
	rm -rf /opt/microsoft/aznfs
	chattr -i -f /etc/stunnel/microsoft/aznfs/nfsv4_fileShare/stunnel*
	rm -rf /etc/stunnel/microsoft
fi