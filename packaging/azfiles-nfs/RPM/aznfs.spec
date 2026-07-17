Name: AZFILES_NFS_PACKAGE_NAME
Version: x.y.z
Release: 1
Summary: Mount helper program for Azure Files NFS mounts
License: MIT
URL: https://github.com/Azure/AZNFS-mount/blob/main/README.md
%if 0%{?custom_stunnel}
Requires: bash, PROCPS_PACKAGE_NAME, conntrack-tools, iptables, bind-utils, iproute, util-linux, nfs-utils, NETCAT_PACKAGE_NAME, newt, net-tools, binutils, kernel-headers, openssl, openssl-devel, gcc, make, wget
Recommends: build-essential
%else
Requires: bash, PROCPS_PACKAGE_NAME, conntrack-tools, iptables, bind-utils, iproute, util-linux, nfs-utils, NETCAT_PACKAGE_NAME, newt, stunnel, net-tools
%endif

# One-time migration bridge from the monolithic pre-split aznfs package.
%global legacy_aznfs_last_monolithic 3.0.19-1
Obsoletes: AZNFS_PACKAGE_NAME <= %{legacy_aznfs_last_monolithic}

# Allow co-install only when aznfs and azfiles-nfs versions match exactly.
Conflicts: AZNFS_PACKAGE_NAME < %{version}-%{release}
Conflicts: AZNFS_PACKAGE_NAME > %{version}-%{release}

%description
Mount helper program for Azure Files NFS mounts.

%prep
mkdir -p ${STG_DIR}/RPM_DIR/root/rpmbuild/SOURCES/
tar -xzvf ${STG_DIR}/AZFILES_NFS_PACKAGE_NAME-${RELEASE_NUMBER}-1.BUILD_ARCH.tar.gz -C ${STG_DIR}/RPM_DIR/

%files
/usr/sbin/aznfswatchdogv4
/sbin/mount.aznfs
/opt/microsoft/azfiles-nfs/mountscript.sh
/opt/microsoft/azfiles-nfs/common.sh
/opt/microsoft/azfiles-nfs/nfsv4mountscript.sh
/opt/microsoft/azfiles-nfs/aznfs_install.sh
/opt/microsoft/azfiles-nfs/azfiles_install.sh
/lib/systemd/system/aznfswatchdogv4.service

%pre
init="$(ps -q 1 -o comm=)"
if [ "$init" != "systemd" ]; then
    echo "Cannot install this package on a non-systemd system!"
    exit 1
fi

for legacy_pkg in aznfs aznfs_stunnel_custom; do
    if rpm -q "$legacy_pkg" >/dev/null 2>&1; then
        if rpm -ql "$legacy_pkg" 2>/dev/null | grep -Eqx '/usr/sbin/aznfswatchdogv4|/opt/microsoft/aznfs/common.sh|/lib/systemd/system/aznfswatchdogv4.service'; then
            echo "Legacy $legacy_pkg detected with moved files. Proceeding with transition to AZFILES_NFS_PACKAGE_NAME ownership."
        fi
    fi
done

cleanup_stunnel_files()
{
    local stunnel_dir=$1
    cd -
    rm -rf /tmp/${stunnel_dir}
    rm -f /tmp/stunnel-latest.tar.gz
}

check_stunnel_version() {
    local required_version="5.40"

    if command -v stunnel >/dev/null 2>&1; then
        installed_version=$(stunnel -version 2>&1 | grep -Eo 'stunnel [0-9]+\.[0-9]+' | awk '{print $2}')

        if [ -n "$installed_version" ]; then
            echo "Found stunnel version: $installed_version"

            if [ "$(printf '%s\n' "$required_version" "$installed_version" | sort -V | head -n1)" = "$required_version" ]; then
                echo "stunnel version $installed_version meets minimum requirement ($required_version)"
                return 0
            else
                echo "stunnel version $installed_version is below minimum requirement ($required_version)"
                return 1
            fi
        else
            echo "Could not determine stunnel version"
            return 1
        fi
    else
        echo "stunnel is not installed"
        return 1
    fi
}

if [[ "$(grep '^VERSION_ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"' | cut -d'.' -f1)" -eq 7 ]]; then
    if check_stunnel_version; then
        echo "Using existing stunnel installation"
    else
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
        ./configure || { echo "Failed to configure the build. Please install stunnel and try again."; cleanup_stunnel_files $stunnel_dir; exit 1; }
        make || { echo "Failed to build stunnel. Please install stunnel and try again."; cleanup_stunnel_files $stunnel_dir; exit 1; }
        make install || { echo "Failed to install stunnel. Please install stunnel and try again."; cleanup_stunnel_files $stunnel_dir; exit 1; }

        cleanup_stunnel_files $stunnel_dir

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
    pid_aznfswatchdogv4=$(pgrep -x aznfswatchdogv4)
    pid_aznfswatchdogv4_in_flagfile=$(cat "$flag_file")

    if [ "$pid_aznfswatchdogv4" != "$pid_aznfswatchdogv4_in_flagfile" ]; then
        rm -f "$flag_file"
        echo "Removed stale flag file"
    fi
fi

if [ $1 == 2 ] && [ ! -f "$flag_file" ]; then
    systemctl stop aznfswatchdogv4
    systemctl disable aznfswatchdogv4
    echo "Stopped aznfswatchdogv4 service"
fi

%post
FLAG_FILE="/tmp/.update_in_progress_from_watchdog.flag"
CONFIG_FILE="/opt/microsoft/azfiles-nfs/data/config"
AUTO_UPDATE_AZFILES_NFS="false"

is_aznfs_installed()
{
    rpm -q aznfs >/dev/null 2>&1 || rpm -q aznfs_sles >/dev/null 2>&1
}

parse_user_config()
{
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "[BUG] $CONFIG_FILE not found, proceeding with default values..."
        return
    fi

    AUTO_UPDATE_AZFILES_NFS=$(egrep -o '^AUTO_UPDATE_AZFILES_NFS[[:space:]]*=[[:space:]]*[^[:space:]]*' "$CONFIG_FILE" | tr -d '[:blank:]' | cut -d '=' -f2)
    AUTO_UPDATE_AZFILES_NFS=${AUTO_UPDATE_AZFILES_NFS,,}
}

user_consent_for_auto_update()
{
    if is_aznfs_installed; then
        # When aznfs is installed, azfiles-nfs is updated through aznfs dependency.
        sed -i '/AUTO_UPDATE_AZFILES_NFS/d' "$CONFIG_FILE"
        echo "AUTO_UPDATE_AZFILES_NFS=false" >> "$CONFIG_FILE"
        return
    fi

    parse_user_config

    if [ "$AUTO_UPDATE_AZFILES_NFS" == "true" ]; then
        return
    fi

    sed -i '/AUTO_UPDATE_AZFILES_NFS/d' "$CONFIG_FILE"

    if [ "$AZNFS_NONINTERACTIVE_INSTALL" == "1" ]; then
        echo "AUTO_UPDATE_AZFILES_NFS=true" >> "$CONFIG_FILE"
        return
    fi

    title="Enable auto update for AZFILES_NFS mount helper"
    auto_update_prompt=$(cat << EOF
    Stay up-to-date with the latest features, improvements, and security patches!

    AUTO-UPDATE WILL JUST UPDATE THE MOUNT HELPER BINARY AND WILL NOT CAUSE ANY DISRUPTION TO MOUNTED SHARES.

    We recommend enabling automatic updates for the best/seamless AZFILES_NFS experience.

    You can turn off auto-update at any time from /opt/microsoft/azfiles-nfs/data/config.
EOF
)

    if whiptail --title "$title" --yesno "$auto_update_prompt" 0 0 > /dev/tty; then
        echo "AUTO_UPDATE_AZFILES_NFS=true" >> "$CONFIG_FILE"
    else
        echo "AUTO_UPDATE_AZFILES_NFS=false" >> "$CONFIG_FILE"
    fi
}

chmod 0755 /opt/microsoft/azfiles-nfs/
chmod 0755 /usr/sbin/aznfswatchdogv4
chmod 0755 /opt/microsoft/azfiles-nfs/nfsv4mountscript.sh
chmod 0755 /opt/microsoft/azfiles-nfs/aznfs_install.sh
chmod 0755 /opt/microsoft/azfiles-nfs/azfiles_install.sh
chmod 0644 /opt/microsoft/azfiles-nfs/common.sh
chmod 0644 /lib/systemd/system/aznfswatchdogv4.service

mkdir -p /opt/microsoft/azfiles-nfs/data
chmod 0755 /opt/microsoft/azfiles-nfs/data

mkdir -p /etc/stunnel/microsoft/azfiles-nfs/nfsv4_fileShare/logs
chmod 0644 /etc/stunnel/microsoft/azfiles-nfs/nfsv4_fileShare/logs

if [ -f /opt/microsoft/azfiles-nfs/azfiles-nfs.log ]; then
    mv -vf /opt/microsoft/azfiles-nfs/azfiles-nfs.log /opt/microsoft/azfiles-nfs/data/
fi

if [ -f /opt/microsoft/azfiles-nfs/randbytes ]; then
    chattr -f -i /opt/microsoft/azfiles-nfs/randbytes
    mv -vf /opt/microsoft/azfiles-nfs/randbytes /opt/microsoft/azfiles-nfs/data/
    chattr -f +i /opt/microsoft/azfiles-nfs/data/randbytes
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "AUTO_UPDATE_AZFILES_NFS=false" > "$CONFIG_FILE"
    chmod 0644 "$CONFIG_FILE"
fi

if [ ! -f "$FLAG_FILE" ]; then
    user_consent_for_auto_update

    systemctl enable nfs-client.target

    systemctl daemon-reload
    systemctl enable aznfswatchdogv4
    systemctl start aznfswatchdogv4
else
    rm -f "$FLAG_FILE"
fi

%preun
RED="\e[2;31m"
NORMAL="\e[0m"
if [ $1 == 0 ]; then
    existing_mounts_v4=$(cat /opt/microsoft/azfiles-nfs/data/mountmapv4 2>/dev/null | egrep '^\S+' | wc -l)
    if [ $existing_mounts_v4 -ne 0 ]; then
        echo
        if [ -t 0 ] && [ -e /dev/tty ]; then
            echo -e "${RED}There are existing Azure Files NFS mounts using azfiles-nfs mount helper, they will not be tracked!" > /dev/tty
            echo -n -e "Are you sure you want to continue? [y/N]${NORMAL} " > /dev/tty
            read -n 1 result < /dev/tty
        else
            echo "Cannot remove AZFILES_NFS_PACKAGE_NAME with active mounts in non-interactive mode." >&2
            echo "Please unmount shares first, then retry uninstall." >&2
            exit 1
        fi
        echo
        if [ "$result" != "y" -a "$result" != "Y" ]; then
            echo "Removal aborted!"
            exit 1
        fi
    fi

    systemctl stop aznfswatchdogv4
    systemctl disable aznfswatchdogv4

    echo "Stopped aznfswatchdogv4 service"
fi

%postun
if [ $1 == 0 ]; then
    chattr -i -f /opt/microsoft/azfiles-nfs/data/randbytes
    chattr -i -f /opt/microsoft/azfiles-nfs/data/mountmapv4
    chattr -i -f /opt/microsoft/azfiles-nfs/data/mountmapv4notls
    rm -rf /opt/microsoft/azfiles-nfs
    chattr -i -f /etc/stunnel/microsoft/azfiles-nfs/nfsv4_fileShare/stunnel*
    rm -rf /etc/stunnel/microsoft
fi
