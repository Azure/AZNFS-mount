Name: AZNFS_PACKAGE_NAME
Version: x.y.z
Release: 1
Summary: Mount helper program for correctly handling endpoint IP address changes for Azure Blob NFS mounts
License: MIT
URL: https://github.com/Azure/AZNFS-mount/blob/main/README.md
Requires: conntrack-tools, iptables, bind-utils, iproute, util-linux, nfs-utils, NETCAT_PACKAGE_NAME, stunnel

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
/lib/systemd/system/aznfswatchdog.service
/usr/sbin/azfilenfs-watchdog
/lib/systemd/system/azfilenfs-watchdog.service

%pre
init="$(ps -q 1 -o comm=)"
if [ "$init" != "systemd" ]; then
	echo "Cannot install this package on a non-systemd system!"
	exit 1
fi

# In case of upgrade.
if [ $1 == 2 ]; then
	systemctl stop aznfswatchdog
	systemctl disable aznfswatchdog
	echo "Stopped aznfswatchdog service."
fi

%post
# Set appropriate permissions.
chmod 0755 /opt/microsoft/aznfs/
chmod 0755 /usr/sbin/aznfswatchdog
chmod 0755 /opt/microsoft/aznfs/mountscript.sh
chmod 0644 /opt/microsoft/aznfs/common.sh
chmod 0755 /usr/sbin/azfilenfs-watchdog

# Set suid bit for mount.aznfs to allow mount for non-super user.
chmod 4755 /sbin/mount.aznfs

# Create log directory under /etc/stunnel to store stunnel logs
mkdir -p /etc/stunnel/microsoft/aznfs/nfsv4_fileShare/logs

if [ ! -s /opt/microsoft/aznfs/randbytes ]; then
	dd if=/dev/urandom of=/opt/microsoft/aznfs/randbytes bs=256 count=1
fi
if [ ! -s /opt/microsoft/aznfs/randbytes ]; then
	uuidgen > /opt/microsoft/aznfs/randbytes
fi
if [ ! -s /opt/microsoft/aznfs/randbytes ]; then
	date | md5sum | awk '{print $1}' > /opt/microsoft/aznfs/randbytes
fi
if [ ! -s /opt/microsoft/aznfs/randbytes ]; then
	date > /opt/microsoft/aznfs/randbytes
fi
chattr +i /opt/microsoft/aznfs/randbytes

# Start aznfswatchdog service.
systemctl daemon-reload
systemctl enable aznfswatchdog
systemctl start aznfswatchdog

# Start azfilenfs-watchdog service.
systemctl enable azfilenfs-watchdog
systemctl start azfilenfs-watchdog

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
	existing_mounts=$(cat /opt/microsoft/aznfs/mountmap 2>/dev/null | egrep '^\S+' | wc -l)
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

	existing_mounts_for_nfsv4FilesShares=$(cat /opt/microsoft/aznfs/aznfs_files_mountmap 2>/dev/null | egrep '^\S+' | wc -l)
	if [ $existing_mounts_for_nfsv4FilesShares -ne 0 ]; then
		echo
		echo -e "${RED}There are existing Azure Files NFS mounts using aznfs mount helper, they will not be tracked!" > /dev/tty
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
				echo "INSTALL_CMD install conntrack-tools iptables bind-utils iproute util-linux nfs-utils NETCAT_PACKAGE_NAME stunnel"
				echo "*******************************************************************"
				echo
			fi
			exit 1
		fi
	fi
	# Stop aznfswatchdog in case of removing the package.
	systemctl stop aznfswatchdog
	systemctl disable aznfswatchdog
	echo "Stopped aznfswatchdog service."

        # Stop azfilenfs-watchdog in case of removing the package.
        systemctl stop azfilenfs-watchdog
        systemctl disable azfilenfs-watchdog
        echo "Stopped azfilenfs-watchdog service."
fi

%postun
# In case of purge/remove.
if [ $1 == 0 ]; then
   chattr -i -f /opt/microsoft/aznfs/mountmap
   chattr -i -f /opt/microsoft/aznfs/randbytes
   chattr -i -f /opt/microsoft/aznfs/aznfs_files_mountmap
   rm -rf /opt/microsoft/aznfs
   chattr -i -f /etc/stunnel/microsoft/aznfs/nfsv4_fileShare/stunnel*
   rm -rf /etc/stunnel/microsoft/aznfs/nfsv4_fileShare
fi
