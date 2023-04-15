Name: aznfs
Version: x.y.z
Release: 1
Summary: Mount helper program for correctly handling endpoint IP address changes for Azure Blob NFS mounts
License: MIT
URL: https://github.com/Azure/AZNFS-mount/blob/main/README.md
Requires: conntrack-tools, iptables, bind-utils, iproute, util-linux, nfs-utils, netcat

%description
Mount helper program for correctly handling endpoint IP address changes for Azure Blob NFS mounts

%prep
mkdir -p ${STG_DIR}/rpm/root/rpmbuild/SOURCES/
tar -xzvf ${STG_DIR}/aznfs-${RELEASE_NUMBER}-1.x86_64.tar.gz -C ${STG_DIR}/rpm/

%files
/usr/sbin/aznfswatchdog
/sbin/mount.aznfs
/opt/microsoft/aznfs/common.sh
/opt/microsoft/aznfs/mountscript.sh
/lib/systemd/system/aznfswatchdog.service

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

# Set suid bit for mount.aznfs to allow mount for non-super user.
chmod 4755 /sbin/mount.aznfs

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

%preun
# In case of purge/remove.
if [ $1 == 0 ]; then
	# Verify if any existing mounts are there, warn the user about this.
	existing_mounts=$(cat /opt/microsoft/aznfs/mountmap 2>/dev/null | egrep '^\S+' | wc -l)
	if [ $existing_mounts -ne 0 ]; then
		echo "There are existing Azure Blob NFS mounts using aznfs mount helper, they will not be tracked!" > /dev/tty
		
		# RPM install/uninstall in not interactive therefore use this workaround to take user input.
		echo "Are you sure you want to continue? [y/N] " > /dev/tty
		if exec < /dev/tty; then
			read -n 1 result
		fi
		
		echo
		if [ "$result" != "y" -a "$result" != "Y" ]; then
			echo "Removal aborted!"
			exit 1
		fi
	fi

	# Stop aznfswatchdog in case of removing the package.
	systemctl stop aznfswatchdog
	systemctl disable aznfswatchdog
	echo "Stopped aznfswatchdog service."
fi

%postun
# In case of purge/remove.
if [ $1 == 0 ]; then
   chattr -i -f /opt/microsoft/aznfs/mountmap
   chattr -i -f /opt/microsoft/aznfs/randbytes
	rm -rf /opt/microsoft/aznfs
fi