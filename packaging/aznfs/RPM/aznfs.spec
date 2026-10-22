Name: AZNFS_PACKAGE_NAME
Version: x.y.z
Release: 1
Summary: Mount helper program for Azure Blob NFS mounts, providing a secure communication channel for Azure File NFS mounts, and supporting the Turbo NFS client
License: MIT
URL: https://github.com/Azure/AZNFS-mount/blob/main/README.md
%if 0%{?custom_stunnel}
Requires: bash, PROCPS_PACKAGE_NAME, conntrack-tools, iptables, bind-utils, iproute, util-linux, nfs-utils, NETCAT_PACKAGE_NAME, newt, net-tools, binutils, kernel-headers, openssl, openssl-devel, gcc, make, wget
Recommends: build-essential

%elif 0%{?azurelinux_build}
Requires: bash, PROCPS_PACKAGE_NAME, conntrack-tools, iptables, bind-utils, iproute, util-linux, nfs-utils, NETCAT_PACKAGE_NAME, newt, stunnel, net-tools, jemalloc, libasan, fuse3

%else
Requires: bash, PROCPS_PACKAGE_NAME, conntrack-tools, iptables, bind-utils, iproute, util-linux, nfs-utils, NETCAT_PACKAGE_NAME, newt, stunnel, net-tools
%endif

#
# We bundle some libs under /opt/microsoft/aznfs/libs/ which are to be used by /sbin/aznfsclient.
# This allows us to not have dependency on the libs provided by the distro thus making us agnostic of the distro and the
# same binary correctly works on all distros regardless of the glibc version (and/or other libs) used by the distro.
# We do this as some of the libs that we use do not have a static version.
# With the __provides_exclude_from directive we tell the RPM package manager to leave these libs alone for our use
# and not confuse other packages with those. Since we are self sufficient and we don't need any libs from the system,
# we use the __requires_exclude_from directive to tell the package manager.
#
%if !0%{?azurelinux_build}
%global __provides_exclude_from ^/opt/microsoft/aznfs/libs/.*\.so.*$
%global __requires_exclude_from ^(/opt/microsoft/aznfs/libs/.*\.so.*|/sbin/aznfsclient)$
%endif

%description
Mount helper program for Azure Blob NFS mounts, providing a secure communication channel for Azure File NFS mounts, and supporting the Turbo NFS client

%prep
mkdir -p ${STG_DIR}/RPM_DIR/root/rpmbuild/SOURCES/
tar -xzvf ${STG_DIR}/AZNFS_PACKAGE_NAME-${RELEASE_NUMBER}-1.BUILD_ARCH.tar.gz -C ${STG_DIR}/RPM_DIR/

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
%if !0%{?azurelinux_build}
OPT_LIBS
%endif
/opt/microsoft/aznfs/sample-turbo-config.yaml
/sbin/aznfsclient

%pre
init="$(ps -q 1 -o comm=)"
if [ "$init" != "systemd" ]; then
	echo "Cannot install this package on a non-systemd system!"
	exit 1
fi

cleanup_stunnel_files()
{
	local stunnel_dir=$1
	cd -
	rm -rf /tmp/${stunnel_dir}
	rm -f /tmp/stunnel-latest.tar.gz
}

# Function to check if stunnel meets minimum version requirement
check_stunnel_version() {
    local required_version="5.40"

    if command -v stunnel >/dev/null 2>&1; then
        # Get installed stunnel version
        installed_version=$(stunnel -version 2>&1 | grep -Eo 'stunnel [0-9]+\.[0-9]+' | awk '{print $2}')

        if [ -n "$installed_version" ]; then
            echo "Found stunnel version: $installed_version"

            # Compare versions using sort -V (version sort)
            # If required_version appears first when sorted, installed version is >= required
            if [ "$(printf '%s\n' "$required_version" "$installed_version" | sort -V | head -n1)" = "$required_version" ]; then
                echo "stunnel version $installed_version meets minimum requirement ($required_version)"
                return 0  # Success - version is adequate
            else
                echo "stunnel version $installed_version is below minimum requirement ($required_version)"
                return 1  # Failure - version is too old
            fi
        else
            echo "Could not determine stunnel version"
            return 1  # Failure - version unknown
        fi
    else
        echo "stunnel is not installed"
        return 1  # Failure - not installed
    fi
}

# Default stunnel package version on RedHat 7 and Centos 7 is not compatible with aznfs.
if [[ "$(grep '^VERSION_ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"' | cut -d'.' -f1)" -eq 7 ]]; then
	if check_stunnel_version; then
        echo "Using existing stunnel installation"
	else
		# Install stunnel from source.
		echo "Installing stunnel from source"
		wget https://www.stunnel.org/downloads/stunnel-latest.tar.gz -P /tmp
		if [ $? -ne 0 ]; then
			echo "Failed to download stunnel source code. Please install stunnel and try again."
			exit 1
		fi

		tar -xvf /tmp/stunnel-latest.tar.gz -C /tmp
		if [ $? -ne 0 ]; then
			echo "Failed to extract stunnel tarball. Please install stunnel and try again."
			rm -f /tmp/stunnel-latest.tar.gz
			exit 1
		fi

		stunnel_dir=$(tar -tf /tmp/stunnel-latest.tar.gz | head -n 1 | cut -f1 -d'/')

		cd /tmp/$stunnel_dir
		./configure
		if [ $? -ne 0 ]; then
			echo "Failed to configure the build. Please install stunnel and try again."
			cleanup_stunnel_files $stunnel_dir
			exit 1
		fi

		make
		if [ $? -ne 0 ]; then
			echo "Failed to build stunnel. Please install stunnel and try again."
			cleanup_stunnel_files $stunnel_dir
			exit 1
		fi

		make install
		if [ $? -ne 0 ]; then
			echo "Failed to install stunnel. Please install stunnel and try again."
			cleanup_stunnel_files $stunnel_dir
			exit 1
		fi

		cleanup_stunnel_files $stunnel_dir

		# Remove the old link and create a symlink to stunnel binary.
		[ -f /bin/stunnel ] && mv /bin/stunnel /bin/stunnel.old
		ln -sf /usr/local/bin/stunnel /bin/stunnel

		if command -v stunnel >/dev/null 2>&1; then
			echo "Successfully installed stunnel version ${stunnel_dir}"
			rm -f /bin/stunnel.old
		else
			echo "Failed to install stunnel version ${stunnel_dir}. Please install stunnel and try again."
			mv /bin/stunnel.old /bin/stunnel > /dev/null 2>&1
			exit 1
		fi
	fi
fi

#
# Do not stop or disable the watchdogs on upgrade. If the transaction is interrupted
# before the post-install scriptlet, the old watchdogs keep running instead of being left disabled.
# The post-install scriptlet restarts them to pick up the new version.
#


%post

FLAG_FILE="/tmp/.update_in_progress_from_watchdog.flag"
CONFIG_FILE="/opt/microsoft/aznfs/data/config"
# restore_watchdogs progress: 0 not run yet, 1 running, 2 done (see on_signal).
restore_state=0
pending_exit=0

#
# Package scriptlets must never prompt, they may run unattended (dnf-automatic, Satellite,
# Ansible). Never change an existing non-empty AUTO_UPDATE_AZNFS value; add it when missing or
# empty (an empty AUTO_UPDATE_AZNFS= counts as not set and is replaced).
#
init_auto_update_config()
{
    if [ ! -f "$CONFIG_FILE" ]; then
        touch "$CONFIG_FILE"
        chmod 0644 "$CONFIG_FILE"
    fi

    # An empty assignment left next to the line added below would make aznfs_install.sh reject the config.
    if grep -q '^AUTO_UPDATE_AZNFS[[:space:]]*=[[:space:]]*$' "$CONFIG_FILE"; then
        sed -i '/^AUTO_UPDATE_AZNFS[[:space:]]*=[[:space:]]*$/d' "$CONFIG_FILE" || echo "[WARNING] Failed to remove empty AUTO_UPDATE_AZNFS from $CONFIG_FILE"
    fi

    # Same parsing as aznfs_install.sh, so both agree on what is configured.
    local value
    value=$(grep -Eo '^AUTO_UPDATE_AZNFS[[:space:]]*=[[:space:]]*[^[:space:]]+' "$CONFIG_FILE" | tr -d '[:blank:]' | cut -d '=' -f2)
    value=${value,,}

    if ! grep -q '^AUTO_UPDATE_AZNFS[[:space:]]*=' "$CONFIG_FILE"; then
        # Legacy behaviour: non-interactive install opts in to auto-update.
        value="false"
        if [ "$AZNFS_NONINTERACTIVE_INSTALL" == "1" ]; then
            value="true"
        fi

        # Make sure we append on a new line.
        if [ -s "$CONFIG_FILE" ] && [ -n "$(tail -c1 "$CONFIG_FILE")" ]; then
            echo >> "$CONFIG_FILE"
        fi
        echo "AUTO_UPDATE_AZNFS=$value" >> "$CONFIG_FILE"
    elif [ "$value" != "true" ] && [ "$value" != "false" ]; then
        echo "[WARNING] Invalid AUTO_UPDATE_AZNFS value '$value' in $CONFIG_FILE, auto-update will not run."
    fi

    if [ "$value" == "false" ]; then
        echo "AZNFS auto-update is disabled. To stay up-to-date with the latest features, improvements and security patches,"
        echo "set AUTO_UPDATE_AZNFS=true in $CONFIG_FILE."
    fi
}

#
# Check that the watchdogs ended up enabled and running, retry once, then report an error with the fix.
# Restart=always does not recover a unit that hit its start rate limit or failed a start condition, so a
# unit that is not active is reset and started once. An active unit is never stopped or restarted here:
# on auto-update aznfswatchdog itself is running this scriptlet.
# Never fails the scriptlet: a persistent cause (e.g. a masked unit) is not fixed by re-running it,
# and a failed postinst would leave the package half-configured and break later package manager runs.
#
verify_watchdogs()
{
    local svc enabled active

    for svc in aznfswatchdog aznfswatchdogv4; do
        enabled=$(systemctl is-enabled $svc 2>/dev/null)
        active=$(systemctl is-active $svc 2>/dev/null)
        [ "$enabled" == "enabled" ] && [ "$active" == "active" ] && continue

        echo "[WARNING] $svc is ${enabled:-unknown} and ${active:-unknown}, retrying..."
        [ "$enabled" == "enabled" ] || systemctl enable $svc
        if [ "$active" != "active" ]; then
            # Clears the failed state and the start rate limit.
            systemctl reset-failed $svc > /dev/null 2>&1
            systemctl start $svc
        fi

        enabled=$(systemctl is-enabled $svc 2>/dev/null)
        active=$(systemctl is-active $svc 2>/dev/null)
        [ "$enabled" == "enabled" ] && [ "$active" == "active" ] && continue

        echo "[ERROR] $svc is ${enabled:-unknown} and ${active:-unknown}, it must be enabled and running for AZNFS mounts to be monitored."
        echo "[ERROR] Check 'systemctl status $svc' and 'journalctl -u $svc', unmask it if masked, then run: systemctl reset-failed $svc; systemctl enable $svc && systemctl start $svc"
    done
    return 0
}

#
# Best effort: enable and (re)start the watchdogs, then verify they are enabled and running. Called at the
# end of this scriptlet, from the EXIT trap and from on_signal, so HUP/INT/TERM part way through still runs
# it; the guard makes it run once. HUP/INT/TERM arriving while it runs are deferred until it is done (see
# on_signal). It cannot run if this scriptlet is SIGKILLed; the pre-install scriptlet does not stop the
# watchdogs on upgrade, so they keep running the old version in that case.
#
restore_watchdogs()
{
    [ $restore_state -ne 0 ] && return
    restore_state=1

    #
    # A valid flag file means aznfswatchdog itself is running this update (aznfs_install.sh).
    # Restarting aznfswatchdog would kill the package manager, so leave that to aznfs_install.sh.
    #
    local auto_update=0
    if [ -f "$FLAG_FILE" ]; then
        if pgrep -x aznfswatchdog | grep -qxF -f "$FLAG_FILE"; then
            auto_update=1
        else
            echo "Removing stale flag file $FLAG_FILE"
        fi
        rm -f "$FLAG_FILE"
    fi

    # Wanted by watchdog service.
    systemctl enable nfs-client.target || echo "[WARNING] Failed to enable nfs-client.target"

    systemctl daemon-reload || echo "[WARNING] systemctl daemon-reload failed"

    # Enable one at a time, one masked unit must not prevent enabling the other.
    local svc
    for svc in aznfswatchdog aznfswatchdogv4; do
        systemctl enable $svc || echo "[WARNING] Failed to enable $svc"
    done
    systemctl restart aznfswatchdogv4 || echo "[WARNING] Failed to restart aznfswatchdogv4"
    if [ $auto_update -eq 0 ]; then
        systemctl restart aznfswatchdog || echo "[WARNING] Failed to restart aznfswatchdog"
    fi

    verify_watchdogs

    restore_state=2
    if [ $pending_exit -ne 0 ]; then
        exit $pending_exit
    fi
}

#
# HUP/INT/TERM: while restore_watchdogs runs the signal is deferred until it is done, so it is never cut short.
# Otherwise run the restore now (it returns at once if already done) and exit with the signal's code.
#
on_signal()
{
    pending_exit=$1
    [ $restore_state -eq 1 ] && return
    restore_watchdogs
    exit $1
}

trap restore_watchdogs EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

# Set appropriate permissions.
chmod 0755 /opt/microsoft/aznfs/
chmod 0755 /usr/sbin/aznfswatchdog
chmod 0755 /usr/sbin/aznfswatchdogv4
chmod 0755 /opt/microsoft/aznfs/mountscript.sh
chmod 0755 /opt/microsoft/aznfs/nfsv3mountscript.sh
chmod 0755 /opt/microsoft/aznfs/nfsv4mountscript.sh
chmod 0755 /opt/microsoft/aznfs/aznfs_install.sh
chmod 0644 /opt/microsoft/aznfs/common.sh

# mount.aznfs must be run by root.
chmod 0755 /sbin/mount.aznfs

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

# Move the turbo sample config file to optdirdata if it exists.
if [ -f /opt/microsoft/aznfs/sample-turbo-config.yaml ]; then
	# chattr if sample config already present (needed for upgrade)
        if [ -f /opt/microsoft/aznfs/data/sample-turbo-config.yaml ]; then
                chattr -f -i /opt/microsoft/aznfs/data/sample-turbo-config.yaml
        fi
        mv -vf /opt/microsoft/aznfs/sample-turbo-config.yaml /opt/microsoft/aznfs/data/
        chattr -f +i /opt/microsoft/aznfs/data/sample-turbo-config.yaml
fi

# Add AUTO_UPDATE_AZNFS to the config file if missing, preserving any existing value.
init_auto_update_config

restore_watchdogs


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

	# KillMode=process keeps the stunnels respawned by aznfswatchdogv4 running when it is stopped, and the
	# post-uninstall scriptlet deletes their files. Kill the whole cgroup first (systemctl kill signals all
	# processes of the unit by default), as stopping it did before KillMode=process.
	systemctl kill aznfswatchdogv4 > /dev/null 2>&1
	systemctl stop aznfswatchdogv4
	systemctl disable aznfswatchdogv4

	echo "Stopped aznfswatchdog service"

	# %files: These files are deleted during uninstallation after %preun and before %postun
	if [ -f /opt/microsoft/aznfs/data/sample-turbo-config.yaml ]; then
		chattr -f -i /opt/microsoft/aznfs/data/sample-turbo-config.yaml
		mv -vf /opt/microsoft/aznfs/data/sample-turbo-config.yaml /opt/microsoft/aznfs/
	fi
fi

%postun
# In case of purge/remove.
if [ $1 == 0 ]; then
	chattr -i -f /opt/microsoft/aznfs/data/mountmap
	chattr -i -f /opt/microsoft/aznfs/data/randbytes
	chattr -i -f /opt/microsoft/aznfs/data/mountmapv4
	chattr -i -f /opt/microsoft/aznfs/data/mountmapv4notls
	rm -rf /opt/microsoft/aznfs
	chattr -i -f /etc/stunnel/microsoft/aznfs/nfsv4_fileShare/stunnel*
	rm -rf /etc/stunnel/microsoft
fi