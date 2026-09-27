Name: AZNFS_PACKAGE_NAME
Version: x.y.z
Release: 1
Summary: Mount helper program for Azure Blob NFS mounts, providing a secure communication channel for Azure File NFS mounts, and supporting the Turbo NFS client
License: MIT
URL: https://github.com/Azure/AZNFS-mount/blob/main/README.md
%if 0%{?custom_stunnel}
Requires: bash, PROCPS_PACKAGE_NAME, conntrack-tools, iptables, bind-utils, iproute, util-linux, nfs-utils, NETCAT_PACKAGE_NAME, newt, net-tools, binutils, kernel-headers, openssl, openssl-devel, gcc, make, wget, logrotate
Recommends: build-essential

%elif 0%{?azurelinux_build}
Requires: bash, PROCPS_PACKAGE_NAME, conntrack-tools, iptables, bind-utils, iproute, util-linux, nfs-utils, NETCAT_PACKAGE_NAME, newt, stunnel, net-tools, jemalloc, libasan, fuse3, logrotate

%else
Requires: bash, PROCPS_PACKAGE_NAME, conntrack-tools, iptables, bind-utils, iproute, util-linux, nfs-utils, NETCAT_PACKAGE_NAME, newt, stunnel, net-tools, logrotate
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
/opt/microsoft/aznfs/aznfs.logrotate
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


%post -p /bin/bash

FLAG_FILE="/tmp/.update_in_progress_from_watchdog.flag"
CONFIG_FILE="/opt/microsoft/aznfs/data/config"
LOGROTATE_TEMPLATE="/opt/microsoft/aznfs/aznfs.logrotate"
LOGROTATE_CONFIG="/etc/logrotate.d/aznfs"
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

#
# Generate the logrotate config for aznfs logs from the packaged template.
# It's generated (and not shipped as a static file) since the log directory is
# configurable using AZNFS_LOGDIR in CONFIG_FILE, with the limits from
# AZNFS_LOGSIZE and AZNFS_LOGCOUNT. It's regenerated only if one of those three
# changed, so that any local change to the rotation policy below is retained
# across package upgrades otherwise.
#
#
# Same rule as safe_logdir() in common.sh, which decides where the logs really
# go: every component has to be one that only root can put files into, and none
# of them may be a symlink. stat is deliberately not given -L, so a link is
# judged as itself and rejected, rather than as the root owned directory a
# local user pointed it at.
#
aznfs_safe_logdir()
{
    local dir="$1"
    local path parent me owner gname mode gbit obit

    me=$(id -u)

    #
    # Trailing slashes are removed first: "test -L link/" is false, because the
    # slash forces the link to be resolved, so a caller passing "dir/" would
    # walk straight past the symlink check below.
    #
    while [ "$dir" != "/" ] && [ "${dir%/}" != "$dir" ]; do
        dir="${dir%/}"
    done

    path="$dir"

    #
    # Start at the deepest component that already exists, so this can be asked
    # about a directory we have not created yet. -L as well as -e, so a
    # dangling symlink counts as existing and is rejected rather than walked
    # straight past.
    #
    while [ "$path" != "/" ] && [ ! -e "$path" ] && [ ! -L "$path" ]; do
        path=$(dirname "$path")
    done

    while : ; do
        # Explicit, so relaxing the mode checks cannot stop rejecting links.
        [ -L "$path" ] && return 1

        # %% not %: rpm expands macros in scriptlet bodies, so a defined macro
        # named u, G or a would otherwise rewrite this format string. rpm
        # collapses %% back to % in the installed script.
        read -r owner gname mode < <(stat -c '%%u %%G %%a' "$path" 2>/dev/null)
        [ -n "$owner" ] || return 1
        [ "$owner" == "0" -o "$owner" == "$me" ] || return 1

        mode=$(printf '%%04d' "$mode" 2>/dev/null) || return 1
        gbit=$(( 8#${mode: -2:1} ))
        obit=$(( 8#${mode: -1:1} ))

        #
        # World writable is never acceptable, sticky or not. Group writable is
        # allowed for a parent owned by one of the groups distros use for log
        # directories, /var/log is root:syslog 0775, but never for the log
        # directory itself. Named rather than compared against a gid
        # threshold: an ordinary group such as "users" sits at 100 on many
        # distros.
        #
        [ $(( obit & 2 )) -eq 0 ] || return 1

        if [ $(( gbit & 2 )) -ne 0 ]; then
            if [ "$path" == "$dir" ]; then
                return 1
            fi

            case "$gname" in
                root|syslog) ;;
                *) return 1 ;;
            esac
        fi

        [ "$path" == "/" ] && break

        # Any fixpoint ends the walk. dirname "//" is "//" on some systems, and
        # without this the loop would spin forever on a repeated leading slash.
        parent=$(dirname "$path")
        [ "$parent" == "$path" ] && break
        path="$parent"
    done

    return 0
}

install_logrotate_config()
{
    local logdir= logfiles= prev_logdir= prev_policy= tmpfile= logsize= logcount=

    if [ ! -f "$LOGROTATE_TEMPLATE" ]; then
        return
    fi

    if [ -f "$CONFIG_FILE" ]; then
        logdir=$(sed -n 's|^[[:space:]]*AZNFS_LOGDIR[[:space:]]*=[[:space:]]*||p' "$CONFIG_FILE" 2>/dev/null | tail -n1 | sed -e 's|[[:space:]]*$||' -e 's|^"\(.*\)"$|\1|' -e "s|^'\(.*\)'\$|\1|") || true
    fi

    logdir=${logdir:-/opt/microsoft/aznfs/data}

    # Strip trailing slashes to keep the generated config path canonical.
    while [ "$logdir" != "/" ] && [ "${logdir%/}" != "$logdir" ]; do
        logdir=${logdir%/}
    done

    #
    # The log directory must be an absolute path built only from characters that
    # are safe as a sed replacement below ('&' and '|' are not) and inside the
    # logrotate glob patterns ('*' and '?' are not). Fall back to the default
    # for anything else rather than writing a broken config.
    #
    case "$logdir" in
        /) logdir= ;;
        /*[!A-Za-z0-9._/@+-]*) logdir= ;;
        /*) ;;
        *) logdir= ;;
    esac

    # "/." and "/var/log/.." are other spellings of a directory the case above
    # would otherwise treat as distinct.
    case "${logdir}/" in
        */../*|*/./*) logdir= ;;
    esac

    if [ -z "$logdir" ]; then
        echo "AZNFS_LOGDIR in $CONFIG_FILE is not a usable path, using /opt/microsoft/aznfs/data instead!"
        logdir=/opt/microsoft/aznfs/data
    fi

    #
    # mkdir -p succeeds for a directory that already exists even when it cannot
    # be written to, e.g. on a read only filesystem. common.sh probes the same
    # way at runtime and falls back when the probe fails, so probe here too.
    # Otherwise the policy would rotate an unusable directory and leave the log
    # that is actually being written, the one under the fallback, uncovered.
    #
    # The probe goes through mktemp rather than touching a known name: this
    # runs as root, and a configured directory that others can write to would
    # otherwise let them redirect it through a planted symlink.
    #
    logdir_usable=true

    #
    # Checked before anything is created, and again afterwards. mkdir -p follows
    # a symlinked component, so validating only after the fact would still let a
    # link planted in a world writable directory have root create directories
    # inside its target.
    #
    if ! aznfs_safe_logdir "$logdir"; then
        echo "Log directory $logdir is not root owned, is writable by others, or is a symlink!"
        logdir_usable=false
    fi

    # Only what we create: mkdir honours the caller's umask, so under 0002
    # this would be 0775 and the revalidation below would refuse what we just
    # made. An existing directory keeps the mode its owner chose.
    if [ "$logdir_usable" == "true" ] && [ ! -d "$logdir" ] &&
       ! { mkdir -p "$(dirname "$logdir")" 2>/dev/null
        mkdir "$logdir" 2>/dev/null && chmod 0755 "$logdir" 2>/dev/null; }; then
        logdir_usable=false
    fi

    if [ "$logdir_usable" == "true" ] && ! aznfs_safe_logdir "$logdir"; then
        echo "Log directory $logdir is not root owned, is writable by others, or is a symlink!"
        logdir_usable=false
    fi

    if [ "$logdir_usable" == "true" ]; then
        probe=$(mktemp "${logdir}/.aznfs-logdir-probe.XXXXXXXX" 2>/dev/null) || logdir_usable=false
        [ -n "$probe" ] && rm -f "$probe"
    fi

    #
    # Mirrors usable_logdir(..., "$LOGFILE") in common.sh. An existing log we
    # cannot append to makes common.sh fall back at the first mount, and the
    # policy would then be rotating a path AZNFS is not writing to.
    #
    if [ "$logdir_usable" == "true" ] &&
       { [ -L "${logdir}/aznfs.log" ] ||
         { [ -e "${logdir}/aznfs.log" ] && { [ ! -f "${logdir}/aznfs.log" ] || [ ! -w "${logdir}/aznfs.log" ]; }; }; }; then
        echo "Log file ${logdir}/aznfs.log is not writable!"
        logdir_usable=false
    fi

    if [ "$logdir_usable" != "true" ]; then
        echo "Not able to use log directory $logdir, using /opt/microsoft/aznfs/data instead!"
        logdir=/opt/microsoft/aznfs/data
        mkdir -p "$logdir" 2>/dev/null && chmod 0755 "$logdir" 2>/dev/null
    fi

    #
    # Rotation policy, same keys and defaults common.sh uses at mount time.
    # Anything unusable falls back rather than producing an invalid policy.
    #
    logsize=$(sed -n 's|^[[:space:]]*AZNFS_LOGSIZE[[:space:]]*=[[:space:]]*||p' "$CONFIG_FILE" 2>/dev/null | tail -n1 | sed -e 's|[[:space:]]*$||' -e 's|^"\(.*\)"$|\1|' -e "s|^'\(.*\)'\$|\1|") || true
    logcount=$(sed -n 's|^[[:space:]]*AZNFS_LOGCOUNT[[:space:]]*=[[:space:]]*||p' "$CONFIG_FILE" 2>/dev/null | tail -n1 | sed -e 's|[[:space:]]*$||' -e 's|^"\(.*\)"$|\1|' -e "s|^'\(.*\)'\$|\1|") || true

    if [ -n "$logsize" ] && ! [[ "$logsize" =~ ^[1-9][0-9]*[kKmMgG]?$ ]]; then
        echo "Invalid AZNFS_LOGSIZE $logsize, rotating at 100M instead!"
        logsize=
    fi

    if [ -n "$logcount" ] && ! [[ "$logcount" =~ ^[0-9]+$ ]]; then
        echo "Invalid AZNFS_LOGCOUNT $logcount, keeping 7 rotations instead!"
        logcount=
    fi

    logsize="${logsize:-100M}"
    logcount="${logcount:-7}"

    #
    # The markers record what the policy was generated for, so a change to any
    # of them regenerates it and a hand edited policy otherwise survives.
    #
    if [ -f "$LOGROTATE_CONFIG" ]; then
        prev_logdir=$(sed -n 's|^# AZNFS_LOGDIR: ||p' "$LOGROTATE_CONFIG" 2>/dev/null | head -1) || true
        prev_policy=$(sed -n 's|^# AZNFS_LOGPOLICY: ||p' "$LOGROTATE_CONFIG" 2>/dev/null | head -1) || true

        if [ "$prev_logdir" == "$logdir" -a \
             "$prev_policy" == "size=${logsize} rotate=${logcount}" ]; then
            return
        fi
    fi

    #
    # Rotate logs from the configured directory only. The watchdog services
    # must be restarted after changing AZNFS_LOGDIR (see README), after which
    # nothing writes to the previous directory any more.
    #
    logfiles="${logdir}/aznfs.log ${logdir}/turbo*.log"

    mkdir -p "$(dirname $LOGROTATE_CONFIG)"

    #
    # Render to a temporary file and only then replace the destination. Writing
    # straight to $LOGROTATE_CONFIG would truncate it before sed runs, so a
    # failure part way through would leave an empty or partial policy, which
    # disables rotation and loses any local edits.
    #
    # Staged outside the logrotate config directory: a temp file left behind
    # there would itself be read as a config and fail the run with duplicate
    # log entries. Same filesystem, so the rename stays atomic.
    # mktemp, not a redirection onto a predictable name: "> $tmpfile" takes the
    # caller's umask, so under umask 000 it is a 0666 file in /etc that can be
    # written before the chmod below. mktemp always creates 0600.
    tmpfile=$(mktemp "$(dirname "$(dirname "$LOGROTATE_CONFIG")")/.aznfs-logrotate.tmp.XXXXXX" 2>/dev/null)

    if [ -z "$tmpfile" ]; then
        echo "Not able to generate $LOGROTATE_CONFIG, aznfs logs will not be rotated!"
        return
    fi

    if ! sed -e "s|AZNFS_LOGDIR_PLACEHOLDER|${logdir}|g" \
             -e "s|AZNFS_LOGFILES_PLACEHOLDER|${logfiles}|g" \
             -e "s|AZNFS_LOGPOLICY_PLACEHOLDER|size=${logsize} rotate=${logcount}|g" \
             -e "s|AZNFS_LOGSIZE_PLACEHOLDER|${logsize}|g" \
             -e "s|AZNFS_LOGCOUNT_PLACEHOLDER|${logcount}|g" \
             "$LOGROTATE_TEMPLATE" > "$tmpfile"; then
        rm -f "$tmpfile"
        echo "Not able to generate $LOGROTATE_CONFIG, aznfs logs will not be rotated!"
        return
    fi

    chmod 0644 "$tmpfile"

    if ! mv -f "$tmpfile" "$LOGROTATE_CONFIG"; then
        rm -f "$tmpfile"
        echo "Not able to update $LOGROTATE_CONFIG, aznfs logs will not be rotated!"
        return
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
# Tolerate the template being absent, install_logrotate_config() below does too.
[ -f /opt/microsoft/aznfs/aznfs.logrotate ] && chmod 0644 /opt/microsoft/aznfs/aznfs.logrotate

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

# Move the turbo sample config file to optdirdata if it exists.
if [ -f /opt/microsoft/aznfs/sample-turbo-config.yaml ]; then
	# chattr if sample config already present (needed for upgrade)
        if [ -f /opt/microsoft/aznfs/data/sample-turbo-config.yaml ]; then
                chattr -f -i /opt/microsoft/aznfs/data/sample-turbo-config.yaml
        fi
        mv -vf /opt/microsoft/aznfs/sample-turbo-config.yaml /opt/microsoft/aznfs/data/
        chattr -f +i /opt/microsoft/aznfs/data/sample-turbo-config.yaml
fi

# Check if the config file exists; if not, create it.
if [ ! -f "$CONFIG_FILE" ]; then
        # Create the config file and set default AUTO_UPDATE_AZNFS=false inside it.
        echo "AUTO_UPDATE_AZNFS=false" > "$CONFIG_FILE"

        #
        # Directory for aznfs.log and the per-mount turbo logs, uncomment and
        # change it to log to a different directory.
        #
        echo "#AZNFS_LOGDIR=/opt/microsoft/aznfs/data" >> "$CONFIG_FILE"
        echo "#AZNFS_LOGSIZE=100M" >> "$CONFIG_FILE"
        echo "#AZNFS_LOGCOUNT=7" >> "$CONFIG_FILE"

        # Set the permissions for the config file.
        chmod 0644 "$CONFIG_FILE"
fi

# Set up log rotation for aznfs logs, as per the configured log directory.
install_logrotate_config

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
	rm -f /etc/logrotate.d/aznfs
	chattr -i -f /etc/stunnel/microsoft/aznfs/nfsv4_fileShare/stunnel*
	rm -rf /etc/stunnel/microsoft
fi