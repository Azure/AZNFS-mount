Name: aznfs
Version: x.y.z
Summary: Mount helper program for correctly handling endpoint IP address changes for Azure Blob NFS mounts
License: MIT
URL: https://github.com/Azure/BlobNFS-mount/blob/main/README.md
Source0: https://github.com/Azure/BlobNFS-mount/archive/refs/tags/%{Version}.tar.gz
Requires: conntrack, iptables, bind9-host, iproute2, util-linux, nfs-common
BuildArch: amd64

%files
%{_sbindir}/aznfswatchdog
/sbin/mount.aznfs
/opt/microsoft/%{Name}/common.sh
/opt/microsoft/%{Name}/mountscript.sh
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

# Start aznfswatchdog service.
systemctl daemon-reload
systemctl enable aznfswatchdog
systemctl start aznfswatchdog

%preun
# In case of perge/remove.
if [ $1 == 0 ];then
	# Verify if any existing mounts are there, warn the user about this.
	existing_mounts=$(cat /opt/microsoft/aznfs/mountmap 2>/dev/null | wc -l)
	if [ $existing_mounts -ne 0 ]; then
		echo "There are existing Azure Blob NFS mounts using aznfs mount helper, they will not be tracked!"
		read -n 1 -p "Are you sure you want to continue? [y/n] " result
		echo
		if [ "$result" != "y" -a "$result" != "Y" ]; then
			exit 1
		fi
	fi
fi

%postun
# In case of perge/remove.
if [ $1 == 0 ];then
   chattr -if /opt/microsoft/aznfs/mountmap
	rm -rf /opt/microsoft/aznfs
fi