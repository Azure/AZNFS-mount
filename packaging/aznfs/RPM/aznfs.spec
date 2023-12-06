Name: AZNFS_PACKAGE_NAME
Version: x.y.z
Release: 1
Summary: Mount helper program for correctly handling endpoint IP address changes for Azure Blob NFS mounts
License: MIT
URL: https://github.com/Azure/AZNFS-mount/blob/main/README.md
Requires: bash, PROCPS_PACKAGE_NAME, conntrack-tools, iptables, bind-utils, iproute, util-linux, nfs-utils, NETCAT_PACKAGE_NAME, dialog

%description
Mount helper program for correctly handling endpoint IP address changes for Azure Blob NFS mounts

%prep
mkdir -p ${STG_DIR}/RPM_DIR/root/rpmbuild/SOURCES/
tar -xzvf ${STG_DIR}/AZNFS_PACKAGE_NAME-${RELEASE_NUMBER}-1.x86_64.tar.gz -C ${STG_DIR}/RPM_DIR/

%files
/usr/sbin/aznfswatchdog
/sbin/mount.aznfs
/opt/microsoft/aznfs/common.sh
/opt/microsoft/aznfs/mountscript.sh
/opt/microsoft/aznfs/aznfs_install.sh
/lib/systemd/system/aznfswatchdog.service

%pre
init="$(ps -q 1 -o comm=)"
if [ "$init" != "systemd" ]; then
	echo "Cannot install this package on a non-systemd system!"
	exit 1
fi

flag_file="/tmp/.update_in_progress_from_watchdog.flag"

if [ -f "$flag_file" ]; then
	# Get the PID of aznfswatchdog.
	aznfswatchdog_pid=$(pgrep aznfswatchdog)
	
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
        echo "Stopped aznfswatchdog service"
fi

%post
export NCURSES_NO_UTF8_ACS=1

FLAG_FILE="/tmp/.update_in_progress_from_watchdog.flag"
CONFIG_FILE="/opt/microsoft/aznfs/data/config"
AUTO_UPDATE_AZNFS="false"

parse_user_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "$CONFIG_FILE not found. Please make sure it is present."
    fi

	# Read the value of AUTO_UPDATE_AZNFS from the configuration file and convert to lowercase for easy comparison later.
    AUTO_UPDATE_AZNFS=$(egrep -o '^AUTO_UPDATE_AZNFS[[:space:]]*=[[:space:]]*[^[:space:]]*' "$CONFIG_FILE" | tr -d '[:blank:]' | cut -d '=' -f2)
    AUTO_UPDATE_AZNFS=${AUTO_UPDATE_AZNFS,,}
}

user_consent_for_auto_update() {
    parse_user_config

    if [ "$AUTO_UPDATE_AZNFS" == "true" ]; then
        return 0
    fi

    if ! command -v dialog > /dev/null; then
        echo "Error: 'dialog' is not installed. Please install it using your package manager and try again."
        exit 1
    fi

    # To Keep dialog box size based on screen dimensions use terminal window dimensions.
    rows=$(tput lines)
    cols=$(tput cols)
    height=$((rows * 30 / 100))
    width=$((cols * 60 / 100))

    title="Auto-Update Configuration"
    auto_update_prompt="Do you wish to enable automatic updates for AZNFS to ensure you stay up-to-date with the \
                        latest features, improvements, and security patches? We recommend enabling automatic updates \
                        to ensure you have the best AZNFS experience. If you choose to enable automatic updates, \
                        the AZNFS will periodically check for updates and apply them automatically."

    sed -i '/AUTO_UPDATE_AZNFS/d' "$CONFIG_FILE"

    dialog --default-button yes --title "$title" --yesno "$auto_update_prompt" $height $width > /dev/tty 2>&1
    dialog_exit_code=$?
    echo "Dialog exited with code: $dialog_exit_code"
    
    if [ $dialog_exit_code -eq 0 ]; then
        echo "AUTO_UPDATE_AZNFS=true" > "$CONFIG_FILE"
    else
        echo "AUTO_UPDATE_AZNFS=false" > "$CONFIG_FILE"
    fi
}

# Set appropriate permissions.
chmod 0755 /opt/microsoft/aznfs/
chmod 0755 /usr/sbin/aznfswatchdog
chmod 0755 /opt/microsoft/aznfs/mountscript.sh
chmod 0755 /opt/microsoft/aznfs/aznfs_install.sh
chmod 0644 /opt/microsoft/aznfs/common.sh

# Set suid bit for mount.aznfs to allow mount for non-super user.
chmod 4755 /sbin/mount.aznfs

# Create data directory for holding mountmap and log file. 
mkdir -p /opt/microsoft/aznfs/data
chmod 0755 /opt/microsoft/aznfs/data

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

# If it's an auto update triggered by aznfswatchdog, don't restart watchdog.
if [ ! -f "$FLAG_FILE" ]; then
        user_consent_for_auto_update
        systemctl daemon-reload
        systemctl enable aznfswatchdog
        systemctl start aznfswatchdog
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
	existing_mounts=$(cat /opt/microsoft/aznfs/data/mountmap 2>/dev/null | egrep '^\S+' | wc -l)
	if [ $existing_mounts -ne 0 ]; then 
		echo
		echo -e "${RED}There are existing Azure Blob NFS mounts using aznfs mount helper, they will not be tracked!" > /dev/tty
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
				echo "INSTALL_CMD install conntrack-tools iptables bind-utils iproute util-linux nfs-utils NETCAT_PACKAGE_NAME"
				echo "*******************************************************************"
				echo
			fi
			exit 1
		fi
	fi

	# Stop aznfswatchdog in case of removing the package.
	systemctl stop aznfswatchdog
	systemctl disable aznfswatchdog
	echo "Stopped aznfswatchdog service"
fi

%postun
# In case of purge/remove.
if [ $1 == 0 ]; then
	chattr -i -f /opt/microsoft/aznfs/data/mountmap
	chattr -i -f /opt/microsoft/aznfs/data/randbytes
	rm -rf /opt/microsoft/aznfs
fi