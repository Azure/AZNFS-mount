#! /bin/bash

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

APPNAME="aznfs"
OPTDIR="/opt/microsoft/${APPNAME}"
OPTDIRDATA="${OPTDIR}/data"
RANDBYTES="${OPTDIRDATA}/randbytes"
INSTALLSCRIPT="${OPTDIR}/aznfs_install.sh"

#
# Config file holding user settings, f.e. AUTO_UPDATE_AZNFS and AZNFS_LOGDIR.
#
AZNFS_CONFIG_FILE="${OPTDIRDATA}/config"

#
# Template used for generating the logrotate config for the aznfs logs and the
# generated logrotate config which is picked by the logrotate service.
#
LOGROTATE_TEMPLATE="${OPTDIR}/${APPNAME}.logrotate"
LOGROTATE_CONFIG="/etc/logrotate.d/${APPNAME}"

#
# Returns the value of the given setting from AZNFS_CONFIG_FILE, empty string
# if the config file and/or the setting is not present.
#
# The whole rest of the line is taken as the value, with surrounding whitespace
# (including a trailing CR from a config edited on Windows) and a matching pair
# of surrounding quotes removed. Embedded whitespace is deliberately kept, so
# that a value like "/var/log/my logs" is seen in full and can be rejected by
# the caller rather than being silently truncated to "/var/log/my".
#
get_user_config()
{
    local key="$1" val

    if [ ! -f "$AZNFS_CONFIG_FILE" ]; then
        return 0
    fi

    val=$(sed -n "s|^[[:space:]]*${key}[[:space:]]*=[[:space:]]*||p" "$AZNFS_CONFIG_FILE" 2>/dev/null |
            tail -n1 | sed -e 's|[[:space:]]*$||')

    case "$val" in
        \"*\") val=${val#\"}; val=${val%\"} ;;
        \'*\') val=${val#\'}; val=${val%\'} ;;
    esac

    echo "$val"
}

#
# Strip trailing slashes from a directory path so that "/var/log/aznfs/" and
# "/var/log/aznfs" are treated as the same directory. Besides avoiding ugly
# double slashes in log paths, this keeps the LOGROTATE_CONFIG idempotency
# check stable, which compares the configured directory as a string.
#
normalize_dir()
{
    local dir="$1"

    # Keep a lone "/" intact.
    while [ "$dir" != "/" ] && [ "${dir%/}" != "$dir" ]; do
        dir="${dir%/}"
    done

    echo "$dir"
}

#
# Can the given path be used as the AZNFS log directory?
#
# It must be an absolute path built only from characters that are safe to use
# unquoted, as a sed replacement when generating LOGROTATE_CONFIG (f.e. '&' and
# '|' are not) and inside the logrotate glob patterns (f.e. '*' and '?' are
# not). Anything else is rejected so we don't end up with a corrupt logrotate
# config, a pattern matching unrelated files, or logs in an unpredictable
# location.
#
is_valid_logdir()
{
    local dir="$1"

    # Must be absolute, and "/" itself is not a sensible log directory.
    case "$dir" in
        /) return 1 ;;
        /*) ;;
        *) return 1 ;;
    esac

    #
    # "/." and "/var/log/.." are other spellings of directories the checks
    # above and below would otherwise treat as distinct, so a "." or ".."
    # component is refused rather than resolved.
    #
    case "$dir/" in
        */../*|*/./*) return 1 ;;
    esac

    case "$dir" in
        *[!A-Za-z0-9._/@+-]*) return 1 ;;
    esac

    return 0
}

#
# Is this a directory that only root can put files into?
#
# The logs are created and appended to as root, and the turbo client keeps its
# log open with ">>", which cannot be made to refuse a symlink. So the only
# durable protection is that nobody else can place a symlink there in the first
# place.
#
# Every component is checked, not just the final directory: a root owned 0755
# log directory sitting under a parent others can write to can simply be
# renamed out of the way and replaced, and the checks we did on it then say
# nothing about what we end up writing to.
#
# Nothing in the chain may be a symlink, and stat is deliberately not given -L
# so that a link is judged as itself rather than as its target. A symlink is
# mode 0777 and belongs to whoever created it, so the checks below reject one.
# Judging it by its target instead would accept a link somebody else planted at
# the path, which is the whole attack: with AZNFS_LOGDIR=/tmp/aznfs a local
# user can pre-create /tmp/aznfs -> /etc, the target passes every check, and
# root then creates and appends to /etc/aznfs.log. For the same reason the path
# is not canonicalized first, that would resolve the planted link away before
# it could be seen.
#
safe_logdir()
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
    # about a directory we have not created yet. Anything below that point does
    # not exist to be unsafe, and gets checked on the second call once it does.
    # -L as well as -e, so a dangling symlink counts as existing and is
    # rejected rather than walked straight past.
    #
    while [ "$path" != "/" ] && [ ! -e "$path" ] && [ ! -L "$path" ]; do
        path=$(dirname "$path")
    done

    while : ; do
        #
        # Rejected explicitly rather than relying on a symlink's 0777 mode
        # failing the checks below, so that relaxing those cannot silently
        # stop rejecting links.
        #
        [ -L "$path" ] && return 1

        read -r owner gname mode < <(stat -c '%u %G %a' "$path" 2>/dev/null)
        [ -n "$owner" ] || return 1

        #
        # Owned by somebody else means they can rename or replace what is
        # inside it, whatever its mode says.
        #
        [ "$owner" == "0" -o "$owner" == "$me" ] || return 1

        #
        # Normalized to four digits so the setuid/sticky digit cannot shift the
        # digits being inspected.
        #
        mode=$(printf '%04d' "$mode" 2>/dev/null) || return 1
        gbit=$(( 8#${mode: -2:1} ))
        obit=$(( 8#${mode: -1:1} ))

        #
        # World writable is never acceptable, sticky or not: sticky protects
        # entries that already exist, so it does nothing for a directory we
        # have not created yet, where anybody can create it, or a symlink in
        # its place, before we do.
        #
        [ $(( obit & 2 )) -eq 0 ] || return 1

        if [ $(( gbit & 2 )) -ne 0 ]; then
            #
            # Group writable is how distros ship the obvious destination:
            # /var/log is root:syslog 0775. Allowed for a parent owned by one
            # of the groups used for that, never for the log directory itself.
            #
            # Named rather than compared against a gid threshold: GID ranges
            # are configurable, and an ordinary group such as "users" sits at
            # 100 on many distros, so "gid < 1000" would trust a group real
            # users are in. "adm" is excluded for the same reason, on Ubuntu it
            # contains the login user.
            #
            # A member of an allowed group can still rename the directory
            # between this check and the writes that follow. Closing that needs
            # the log to be created through a held directory descriptor with
            # no-follow semantics, which a shell cannot do; the set is kept to
            # daemon accounts so nothing a human logs in as is trusted.
            #
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

#
# Can we actually log into this directory? On top of the syntax check above it
# has to exist or be creatable, and a file has to be writable inside it.
#
# The probe file is removed again when it wasn't already there, so probing does
# not leave anything behind; callers create the log files they actually need.
#
usable_logdir()
{
    local dir="$1"

    #
    # Optional. Only inspected, never created or removed here.
    #
    local logfile="$2"

    local probe

    is_valid_logdir "$dir" || return 1

    #
    # Checked before anything is created, and again afterwards. mkdir -p
    # follows a symlinked component, so validating only after the fact would
    # still let a link planted in a world writable directory have root create
    # directories inside its target. The second call covers the components we
    # created ourselves, which did not exist to be checked by the first.
    #
    safe_logdir "$dir" || return 1

    if [ ! -d "$dir" ]; then
        # Parents with -p, the final component without: -p succeeds on an
        # entry that already exists, so a symlink planted between the check
        # above and here would be followed. Plain mkdir fails with EEXIST.
        mkdir -p "$(dirname "$dir")" 2>/dev/null
        mkdir "$dir" 2>/dev/null && chmod 0755 "$dir" 2>/dev/null

        #
        # An existing path that is not a directory fails here, not at the
        # mkdir above.
        #
        [ -d "$dir" ] || return 1

        safe_logdir "$dir" || return 1
    fi

    #
    # mktemp, not a fixed name plus touch. common.sh is sourced as root from
    # the setuid mount path, and if the configured directory is writable by
    # others an unprivileged user could pre-create a symlink at a name we are
    # about to touch and have us write through it. mktemp creates with O_EXCL
    # under an unpredictable name, so it neither follows an existing symlink
    # nor collides with a concurrent mount or watchdog.
    #
    probe=$(mktemp "${dir}/.aznfs-logdir-probe.XXXXXXXX" 2>/dev/null) || return 1
    rm -f "$probe" 2>/dev/null

    #
    # A log file we cannot append to makes the directory unusable just the
    # same. The real log is created once, further below.
    #
    #
    # -L before -w, because -w follows the link and reports on the target: a
    # symlink pointing at something writable would otherwise pass here and the
    # append below would go through it as root. The directory chain already
    # refuses symlinks, so the log file is held to the same rule.
    #
    if [ -n "$logfile" ] && [ -L "$logfile" ]; then
        return 1
    fi

    if [ -n "$logfile" ] && [ -e "$logfile" ] &&
       { [ ! -f "$logfile" ] || [ ! -w "$logfile" ]; }; then
        return 1
    fi

    return 0
}

#
# How large a log has to get before it is rotated, and how many rotations are
# kept. Both feed straight into the generated logrotate policy.
#
# The size is logrotate's own syntax, a number with an optional k/M/G suffix.
# Zero is refused because "size 0" rotates on every run. A count of zero is
# allowed and means keep nothing, which is a sensible choice on a small disk.
#
is_valid_logsize()
{
    [[ "$1" =~ ^[1-9][0-9]*[kKmMgG]?$ ]]
}

is_valid_logcount()
{
    [[ "$1" =~ ^[0-9]+$ ]]
}

#
# Directory where aznfs.log and the per-mount turbo logs are created.
# Users can change it either by setting AZNFS_LOGDIR in AZNFS_CONFIG_FILE or by
# exporting the AZNFS_LOGDIR env variable, the env variable takes precedence.
#
# Note: The env variable is a per-invocation override, hence only the directory
#       configured in AZNFS_CONFIG_FILE is covered by LOGROTATE_CONFIG.
#
#
# Internal state for the log directory resolution below.
#
# This must be initialized: common.sh is sourced into a shell whose environment
# comes from the caller, and mount.aznfs is setuid root, so an inherited value
# would otherwise be taken for a real validation failure and let an
# unprivileged caller force the fallback and the regeneration of the rotation
# config.
#
bad_logdir=
logdir_is_configured_one=
bad_logsize=
bad_logcount=

#
# Defaults for the rotation policy, used when the config file says nothing or
# says something unusable.
#
AZNFS_LOGSIZE_DEFAULT="100M"
AZNFS_LOGCOUNT_DEFAULT="7"

AZNFS_CONFIGURED_LOGDIR="$(normalize_dir "$(get_user_config AZNFS_LOGDIR)")"

if [ -n "$AZNFS_CONFIGURED_LOGDIR" ] && ! is_valid_logdir "$AZNFS_CONFIGURED_LOGDIR"; then
    bad_logdir="$AZNFS_CONFIGURED_LOGDIR"
    AZNFS_CONFIGURED_LOGDIR=
fi

AZNFS_CONFIGURED_LOGDIR="${AZNFS_CONFIGURED_LOGDIR:-$OPTDIRDATA}"
AZNFS_LOGDIR="$(normalize_dir "${AZNFS_LOGDIR:-$AZNFS_CONFIGURED_LOGDIR}")"
LOGFILE="${AZNFS_LOGDIR}/${APPNAME}.log"

#
# Rotation policy. Unlike the log directory these are not overridable from the
# environment: they only ever describe what the generated policy should say, so
# a per-invocation value would have no meaning.
#
AZNFS_LOGSIZE="$(get_user_config AZNFS_LOGSIZE)"
AZNFS_LOGCOUNT="$(get_user_config AZNFS_LOGCOUNT)"

if [ -n "$AZNFS_LOGSIZE" ] && ! is_valid_logsize "$AZNFS_LOGSIZE"; then
    bad_logsize="$AZNFS_LOGSIZE"
    AZNFS_LOGSIZE=
fi

if [ -n "$AZNFS_LOGCOUNT" ] && ! is_valid_logcount "$AZNFS_LOGCOUNT"; then
    bad_logcount="$AZNFS_LOGCOUNT"
    AZNFS_LOGCOUNT=
fi

AZNFS_LOGSIZE="${AZNFS_LOGSIZE:-$AZNFS_LOGSIZE_DEFAULT}"
AZNFS_LOGCOUNT="${AZNFS_LOGCOUNT:-$AZNFS_LOGCOUNT_DEFAULT}"

#
# This stores the map of local IP and share name and external blob endpoint IP.
#
MOUNTMAPv3="${OPTDIRDATA}/mountmap"

#
# This stores the map of hostname and stunnel conf, log, pid files paths.
#
MOUNTMAPv4="${OPTDIRDATA}/mountmapv4"

RED="\e[2;31m"
GREEN="\e[2;32m"
YELLOW="\e[2;33m"
NORMAL="\e[0m"

HOSTNAME=$(hostname)

LOCALHOST="127.0.0.1"

# Determine the command to use for getting socket statistics: netstat or ss
NETSTATCOMMAND=""

if [ -z "$AZNFS_VERSION" ]; then
    echo '*** AZNFS_VERSION must be defined before including common.sh ***'
    exit 1
elif [ "$AZNFS_VERSION" == "unknown" ]; then
    prefix=""
else
    prefix="[v${AZNFS_VERSION}] "
fi

# Are we running inside the AKS?
AKS_USER="false"

RELEASE_NUMBER_FOR_AKS=x.y.z

#
# How often does the watchdog look for unmounts and/or IP address changes for
# Blob and nfs file endpoints.
#
MONITOR_INTERVAL_SECS=5

_log()
{
    color=$1
    msg=$2

    echo -e "${color}${msg}${NORMAL}"
    (
        flock -e 999
        echo -e "${prefix}$(date -u +"%a %b %d %G %T.%3N") $HOSTNAME $$: ${color}${msg}${NORMAL}" >> $LOGFILE
    ) 999<$LOGFILE
}

#
# Plain echo with file logging.
#
pecho()
{
    color=$NORMAL
    _log $color "${*}"
}

#
# Success echo.
#
secho()
{
    color=$GREEN
    _log $color "${*}"
}

#
# Warning echo.
#
wecho()
{
    color=$YELLOW
    _log $color "${*}"
}

#
# Error echo.
#
eecho()
{
    color=$RED
    _log $color "${*}"
}

#
# Verbose echo, only logs into LOGFILE unless AZNFS_VERBOSE env variable is set.
#
vecho()
{
    color=$NORMAL

    # Unless AZNFS_VERBOSE flag is set, do not echo to console.
    if [ -z "$AZNFS_VERBOSE" -o "$AZNFS_VERBOSE" == "0" ]; then
        (
            flock -e 999
            echo -e "${prefix}$(date -u +"%a %b %d %G %T.%3N") $HOSTNAME $$: ${color}${*}${NORMAL}" >> $LOGFILE
        ) 999<$LOGFILE

        return
    fi

    _log $color "${*}"
}

#
# Verbose echo, only logs into LOGFILE unless '-v' or '--verbose' option is provided.
#
vvecho()
{
    color=$NORMAL

    # Unless VERBOSE_MOUNT flag is set to true, do not echo to console.
    if [ "$VERBOSE_MOUNT" == false ]; then
        (
            flock -e 999
            echo -e "${prefix}$(date -u +"%a %b %d %G %T.%3N") $HOSTNAME $$: ${color}${*}${NORMAL}" >> $LOGFILE
        ) 999<$LOGFILE

        return
    fi

    _log $color "${*}"
}

#
# Check if system is booted with systemd as init.
#
systemd_is_init()
{
    init="$(ps -q 1 -o comm=)"
    [ "$init" == "systemd" ]
}

#
# Ensure aznfswatchdog service is running, if not bail out with an appropriate
# error.
#
ensure_aznfswatchdog()
{
    local process_name="$1"
    pgrep -x "$process_name" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        if systemd_is_init; then
            eecho "$process_name service not running!"
            pecho "Start the $process_name service using 'systemctl start $process_name' and try again."
        else
            eecho "$process_name service not running, please make sure it's running and try again!"
        fi

        pecho "If the problem persists, contact Microsoft support."
        return 1
    fi
}

#
# Check if the given string is a valid IPv4 address.
#
is_valid_ipv4_address()
{
    [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] &&
    [ ${BASH_REMATCH[1]} -le 255 ] &&
    [ ${BASH_REMATCH[2]} -le 255 ] &&
    [ ${BASH_REMATCH[3]} -le 255 ] &&
    [ ${BASH_REMATCH[4]} -le 255 ]
}

#
# Check if the given string is a valid IPv4 prefix.
# 10, 10.10, 10.10.10, 10.10.10.10 are valid prefixes, while
# 1000, 10.256, 10. are not valid prefixes.
#
is_valid_ipv4_prefix()
{
    ip -4 route get $1 > /dev/null 2>&1
}

#
# Check if a given TCP port is reachable. Uses a 3 secs timeout to bail out if address/port is not reachable.
#
is_ip_port_reachable()
{
    local ip=$1;
    local port=$2;

    # 3 secs timeout should be good.
    nc -w 3 -z $ip $port > /dev/null 2>&1
}

#
# Verify if FQDN is resolved into IPv4 address by /etc/hosts entry.
#
is_present_in_etc_hosts() 
{
    local ip="$1"
    local hostname="$2"

    # Search for the entry in /etc/hosts
    grep -qE "^[[:space:]]*${ip}[[:space:]]+[^#]*\<${hostname}\>" /etc/hosts
}

#
# Blob fqdn to IPv4 adddress.
# Caller must make sure that it is called only for hostname and not IP address.
#
# Note: Since caller captures its o/p this should not log anything other than
#       the IP address, in case of success return.
#
resolve_ipv4()
{
    local hname="$1"
    local fail_if_present_in_etc_hosts="$2"
    local RETRIES=3

    # Some retries for resilience.
    for((i=0;i<=$RETRIES;i++)) {
        # Resolve hostname to IPv4 address.
        host_op=$(host -4 -t A "$hname" 2>&1)
        if [ $? -ne 0 ]; then
            #
            # Special case of failure to indicate that the fqdn does not exist.
            # We convey it to our caller using the special o/p "NXDOMAIN".
            #
            if [[ "$host_op" =~ .*NXDOMAIN.* ]]; then
                echo "NXDOMAIN"
                return 1
            fi

            vecho "Failed to resolve ${hname}: $host_op!"
            # Exhausted retries?
            if [ $i -eq $RETRIES ]; then
                return 1
            fi
            # Mostly some transient issue, retry after some sleep.
            sleep 1
            continue
        fi

        #
        # For ZRS accounts, we will get 3 IP addresses whose order keeps changing.
        # We sort the output of host so that we always look at the same address,
        # also we shuffle it so that different clients balance out across different
        # zones.
        #
        ipv4_addr_all=$(echo "$host_op" | grep " has address " | awk '{print $4}' |\
                        sort | shuf --random-source=$RANDBYTES)

        cnt_ip=$(echo "$ipv4_addr_all" | wc -l)

        if [ $cnt_ip -eq 0 ]; then
            vecho "host returned 0 address for ${hname}, expected one or more! [$host_op]"
            # Exhausted retries?
            if [ $i -eq $RETRIES ]; then
                return 1
            fi
            # Mostly some transient issue, retry after some sleep.
            sleep 1
            continue
        fi

        break
    }

    # Use first address from the above curated list.
    ipv4_addr=$(echo "$ipv4_addr_all" | head -n1)

    # For ZRS we need to use the first reachable IP.
    if [ $cnt_ip -ne 1 ]; then
        for((i=1;i<=$cnt_ip;i++)) {
            ipv4_addr=$(echo "$ipv4_addr_all" | tail -n +$i | head -n1)
            if is_ip_port_reachable $ipv4_addr 2048; then
                break
            fi
        }
    fi

    if ! is_valid_ipv4_address "$ipv4_addr"; then
        eecho "[FATAL] host returned bad IPv4 address $ipv4_addr for hostname ${hname}!"
        return 1
    fi

    #
    # Check if the IP-FQDN pair is present in /etc/hosts
    # 
    if is_present_in_etc_hosts "$ipv4_addr" "$hname"; then
        if [ "$fail_if_present_in_etc_hosts" == "true" ]; then
            eecho "[FATAL] $hname resolved to $ipv4_addr from /etc/hosts!"
            eecho "AZNFS depends on dynamically detecting DNS changes for proper handling of endpoint address changes"
            eecho "Please remove the entry for $hname from /etc/hosts"
            return 1
        else
            wecho "[FATAL] $hname resolved to $ipv4_addr from /etc/hosts!" 1>/dev/null
            wecho "AZNFS depends on dynamically detecting DNS changes for proper handling of endpoint address changes" 1>/dev/null
            wecho "Please remove the entry for $hname from /etc/hosts" 1>/dev/null
        fi
    fi

    echo $ipv4_addr
    return 0
}

#
# Function to check if an IP is private.
#
is_private_ip()
{
    local ip=$1

    if ! is_valid_ipv4_address $ip; then
        return 1
    fi

    #
    # Check if the IP belongs to the private IP range (10.0.0.0/8,
    # 172.16.0.0/12, or 192.168.0.0/16).f
    #
    [[ $ip =~ ^10\..* ]] ||
    [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\..* ]] ||
    [[ $ip =~ ^192\.168\..* ]]
}

#
# Mount helper must call this function to grab a timed lease on all MOUNTMAPv3
# entries. It should do this if it decides to use any of the entries. Once
# this is called aznfswatchdog is guaranteed to not delete any MOUNTMAPv3 till
# the next 5 minutes.
#
# Must be called with MOUNTMAPv3 lock held.
#
touch_mountmapv3()
{
    chattr -f -i $MOUNTMAPv3
    touch $MOUNTMAPv3
    if [ $? -ne 0 ]; then
        chattr -f +i $MOUNTMAPv3
        eecho "Failed to touch ${MOUNTMAPv3}!"
        return 1
    fi
    chattr -f +i $MOUNTMAPv3
}

# Create mount map file
create_mountmap_file()
{
    local mountmap_filename=MOUNTMAPv$AZNFS_VERSION
    if [ ! -f ${!mountmap_filename} ]; then
        touch ${!mountmap_filename}
        if [ $? -ne 0 ]; then
            eecho "[FATAL] Not able to create '${!mountmap_filename}'!"
            return 1
        fi
        chattr -f +i ${!mountmap_filename}
    fi
}

#
# MOUNTMAPv3 is accessed by both mount.aznfs and aznfswatchdog service. Update it
# only after taking exclusive lock.
#
# Add entry to MOUNTMAPv3 in case of a new mount or IP change for blob FQDN.
#
# This also ensures that the corresponding DNAT rule is created so that MOUNTMAPv3
# entry and DNAT rule are always in sync.
#
ensure_mountmapv3_exist_nolock()
{
    IFS=" " read l_host l_ip l_nfsip <<< "$1"
    if ! ensure_iptable_entry $l_ip $l_nfsip; then
        eecho "[$1] failed to add to ${MOUNTMAPv3}!"
        return 1
    fi

    egrep -q "^${1}$" $MOUNTMAPv3
    if [ $? -ne 0 ]; then
        chattr -f -i $MOUNTMAPv3
        echo "$1" >> $MOUNTMAPv3
        if [ $? -ne 0 ]; then
            chattr -f +i $MOUNTMAPv3
            eecho "[$1] failed to add to ${MOUNTMAPv3}!"
            # Could not add MOUNTMAPv3 entry, delete the DNAT rule added above.
            ensure_iptable_entry_not_exist $l_ip $l_nfsip
            return 1
        fi
        chattr -f +i $MOUNTMAPv3
    else
        pecho "[$1] already exists in ${MOUNTMAPv3}."
    fi
}

ensure_mountmapv3_exist()
{
    (
        flock -e 999
        ensure_mountmapv3_exist_nolock "$1"
        return $?
    ) 999<$MOUNTMAPv3
}

#
# Delete entry from MOUNTMAPv3 and also the corresponding iptable rule.
#
ensure_mountmapv3_not_exist()
{
    (
        flock -e 999

        #
        # If user wants to delete the entry only if MOUNTMAPv3 has not changed since
        # he looked up, honour that.
        #
        local ifmatch="$2"
        if [ -n "$ifmatch" ]; then
            local mtime=$(stat -c%Y $MOUNTMAPv3)
            if [ "$mtime" != "$ifmatch" ]; then
                eecho "[$1] Refusing to remove from ${MOUNTMAPv3} as $mtime != $ifmatch!"
                return 1
            fi
        fi

        # Delete iptable rule corresponding to the outgoing MOUNTMAPv3 entry.
        IFS=" " read l_host l_ip l_nfsip <<< "$1"
        if [ -n "$l_host" -a -n "$l_ip" -a -n "$l_nfsip" ]; then
            if ! ensure_iptable_entry_not_exist $l_ip $l_nfsip; then
                eecho "[$1] Refusing to remove from ${MOUNTMAPv3} as iptable entry could not be deleted!"
                return 1
            fi
        fi

        chattr -f -i $MOUNTMAPv3
        #
        # We do this thing instead of inplace update by sed as that has a
        # very bad side-effect of creating a new MOUNTMAPv3 file. This breaks
        # any locking that we dependent on the old file.
        #
        out=$(sed "\%^${1}$%d" $MOUNTMAPv3)
        ret=$?
        if [ $ret -eq 0 ]; then
            #
            # If this echo fails then MOUNTMAPv3 could be truncated. In that case we need
            # to reconcile it from the mount info and iptable info. That needs to be done
            # out-of-band.
            #
            echo "$out" > $MOUNTMAPv3
            ret=$?
            out=
            if [ $ret -ne 0 ]; then
                eecho "*** [FATAL] MOUNTMAPv3 may be in inconsistent state, contact Microsoft support ***"
            fi
        fi

        if [ $ret -ne 0 ]; then
            chattr -f +i $MOUNTMAPv3
            eecho "[$1] failed to remove from ${MOUNTMAPv3}!"
            # Reinstate DNAT rule deleted above.
            ensure_iptable_entry $l_ip $l_nfsip
            return 1
        fi
        chattr -f +i $MOUNTMAPv3

        # Return the mtime after our mods.
        echo $(stat -c%Y $MOUNTMAPv3)
    ) 999<$MOUNTMAPv3
}

#
# Replace a mountmap entry with a new one.
# This will also update the iptable DNAT rules accordingly, deleting DNAT rule
# corresponding to old entry and adding the DNAT rule corresponding to the new
# entry.
#
update_mountmapv3_entry()
{
    local old=$1
    local new=$2

    vecho "Updating mountmapv3 entry [$old -> $new]"

    (
        flock -e 999

        IFS=" " read l_host l_ip l_nfsip_old <<< "$old"
        if [ -n "$l_host" -a -n "$l_ip" -a -n "$l_nfsip_old" ]; then
            if ! ensure_iptable_entry_not_exist $l_ip $l_nfsip_old; then
                eecho "[$old] Refusing to remove from ${MOUNTMAPv3} as old iptable entry could not be deleted!"
                return 1
            fi
        fi

        IFS=" " read l_host l_ip l_nfsip_new <<< "$new"
        if [ -n "$l_host" -a -n "$l_ip" -a -n "$l_nfsip_new" ]; then
            if ! ensure_iptable_entry $l_ip $l_nfsip_new; then
                eecho "[$new] Refusing to remove from ${MOUNTMAPv3} as new iptable entry could not be added!"
                # Roll back.
                ensure_iptable_entry $l_ip $l_nfsip_old
                return 1
            fi
        fi

        chattr -f -i $MOUNTMAPv3
        #
        # We do this thing instead of inplace update by sed as that has a
        # very bad side-effect of creating a new MOUNTMAPv3 file. This breaks
        # any locking that we dependent on the old file.
        #
        out=$(sed "s%^${old}$%${new}%g" $MOUNTMAPv3)
        ret=$?
        if [ $ret -eq 0 ]; then
            #
            # If this echo fails then MOUNTMAPv3 could be truncated. In that case we need
            # to reconcile it from the mount info and iptable info. That needs to be done
            # out-of-band.
            #
            echo "$out" > $MOUNTMAPv3
            ret=$?
            out=
            if [ $ret -ne 0 ]; then
                eecho "*** [FATAL] MOUNTMAPv3 may be in inconsistent state, contact Microsoft support ***"
            fi
        fi

        if [ $ret -ne 0 ]; then
            chattr -f +i $MOUNTMAPv3
            eecho "[$old -> $new] failed to update ${MOUNTMAPv3}!"
            # Roll back.
            ensure_iptable_entry_not_exist $l_ip $l_nfsip_new
            ensure_iptable_entry $l_ip $l_nfsip_old
            return 1
        fi
        chattr -f +i $MOUNTMAPv3
    ) 999<$MOUNTMAPv3
}

#
# Ensure given DNAT rule exists, if not it creates it else silently exits.
#
ensure_iptable_entry()
{
    iptables -w 60 -t nat -C OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        iptables -w 60 -t nat -I OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2"
        if [ $? -ne 0 ]; then
            eecho "Failed to add DNAT rule [$1 -> $2]!"
            return 1
        fi
        
        #
        # While the DNAT entry was not there, if there was some NFS traffic (targeted to proxy IP),
        # it would have created a conntrack entry with destination and reply source IP as the proxy IP.
        # This conntrack entry will prevent the creation of the correct conntrack entry with destination as
        # proxy IP and reply source as NFS server IP. This will cause traffic to be stalled, hence we need to
        # delete the entry if such an entry exists.
        #
        output=$(conntrack -D -p tcp -d "$1" -r "$1" 2>&1)
        if [ $? -eq 0 ]; then
            wecho "Deleted undesired conntrack entry [$1 -> $1]!"
        fi
    fi
}

#
# We only use lowercase single word names for distro id:
# ubuntu, centos, redhat, sles.
#
canonicalize_distro_id()
{
    local distro_lower=$(echo "$1" | tr '[:upper:]' '[:lower:]')

    # Use sles for SUSE/SLES.
    if [ "$distro_lower" == "suse" ]; then
        distro_lower="sles"
    fi

    echo "$distro_lower"
}

log_version_info()
{
    if [ -f /etc/centos-release ]; then
        linux_distro=$(cat /etc/centos-release 2>&1)
        distro_id="centos"
    elif [ -f /etc/os-release ]; then
        linux_distro=$(grep "^PRETTY_NAME=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
        distro_id=$(grep "^ID=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
        distro_id=$(canonicalize_distro_id $distro_id)
    else
        # Ideally, this should not happen.
        linux_distro="Unknown"
    fi

    bash_version=$(bash --version | head -n 1)

    vecho "Linux distribution: $linux_distro"
    vecho "Bash version: $bash_version"

    if [ "$AKS_USER" == "true" ]; then
        vecho "AZNFS version: $RELEASE_NUMBER_FOR_AKS"
        return
    fi

    #
    # aznfswatchdog gets started during postinst, wait for installation to complete for the version to appear correctly.
    #
    sleep 2

    if [ "$distro_id" == "ubuntu" ]; then
        current_version=$(dpkg-query -W -f='${Version}\n' aznfs 2>/dev/null)
    elif [ "$distro_id" == "centos" -o "$distro_id" == "rocky" -o "$distro_id" == "rhel" -o "$distro_id" == "ol" -o "$distro_id" == "azurelinux" ]; then
        current_pkg_name=$(rpm -q aznfs)
        current_version=$(echo "$current_pkg_name" | sed -E 's/^aznfs-(.+)\.[^.]+$/\1/')
    elif [ "$distro_id" == "sles" ]; then
        current_version=$(zypper search --details -i aznfs | grep "\<aznfs\>" | awk '{print $7}')
    else
        # Ideally, this should not happen.
        current_version="Unknown"
    fi

    vecho "AZNFS version: $current_version"
}

#
# Ensure given DNAT rule is deleted, silently exits if the rule doesn't exist.
# Also removes the corresponding entry from conntrack.
#
ensure_iptable_entry_not_exist()
{
    iptables -w 60 -t nat -C OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        iptables -w 60 -t nat -D OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2"
        if [ $? -ne 0 ]; then
            eecho "Failed to delete DNAT rule [$1 -> $2]!"
            return 1
        fi

        # Ignore status of conntrack because entry may not exist (timed out).
        output=$(conntrack -D conntrack -p tcp -d "$1" -r "$2" 2>&1)
        if [ $? -ne 0 ]; then
            vecho "$output"
        fi
    fi
}

#
# Verify if the mountmapv3 entry is present but corresponding DNAT rule does not
# exist. Add it to avoid IOps failure.
#
verify_iptable_entry()
{
    iptables -w 60 -t nat -C OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        wecho "DNAT rule [$1 -> $2] does not exist, adding it."
        iptables -w 60 -t nat -I OUTPUT -p tcp -d "$1" -j DNAT --to-destination "$2"
        if [ $? -ne 0 ]; then
            eecho "Failed to add DNAT rule [$1 -> $2]!"
            return 1
        fi

        #
        # While the DNAT entry was not there, if there was some NFS traffic (targeted to proxy IP),
        # it would have created a conntrack entry with destination and reply source IP as the proxy IP.
        # This conntrack entry will prevent the creation of the correct conntrack entry with destination as
        # proxy IP and reply source as NFS server IP. This will cause traffic to be stalled, hence we need to
        # delete the entry if such an entry exists.
        #
        output=$(conntrack -D -p tcp -d "$1" -r "$1" 2>&1)
        if [ $? -eq 0 ]; then
            wecho "Deleted undesired conntrack entry [$1 -> $1]!"
        fi
    fi
}

# Find CheckHost value for stunnel configuration based on storage account hostname.
get_check_host_value()
{
    local hostname=$1
    local check_host_value="*.file.core.windows.net"

    declare -A certs
    certs=(
        ["preprod.core.windows.net$"]="*.file.preprod.core.windows.net"
        ["chinacloudapi.cn$"]="*.file.core.chinacloudapi.cn"
        ["usgovcloudapi.net$"]="*.file.core.usgovcloudapi.net"
    )

    # If AZURE_ENDPOINT_OVERRIDE environment variable is set, use it.
    if [[ -n "$AZURE_ENDPOINT_OVERRIDE" ]]; then
        # Remove any leading dot.
        modified_endpoint=${AZURE_ENDPOINT_OVERRIDE#.}
        check_host_value="*.file.core.$modified_endpoint"
    else
        for cert in "${!certs[@]}"; do
            if [[ "$hostname" =~ $cert ]]; then
                    check_host_value="${certs[$cert]}"
                    break
            fi
        done
    fi

    echo "$check_host_value"
}

#
# Make sure the logrotate config rotates the logs from the configured log
# directory, with the configured limits. The config is generated from the
# packaged template and is regenerated only if AZNFS_LOGDIR, AZNFS_LOGSIZE or
# AZNFS_LOGCOUNT has changed, so that any local change done to the rotation
# policy is not lost otherwise.
#
# Only the configured directory is covered. Long running processes like the
# watchdog services resolve LOGFILE once at startup, so they have to be
# restarted after a log directory change, see the README. Logs left in the
# previous directory are not rotated any more and are not removed either.
#
ensure_logrotate_config()
{
    local tmpfile logfiles prev_logdir prev_policy

    # Nothing to do if logrotate is not available on this system.
    if [ ! -d "$(dirname $LOGROTATE_CONFIG)" -o ! -f "$LOGROTATE_TEMPLATE" ]; then
        return 0
    fi

    #
    # The marker lines recorded in the generated config tell us what it was
    # generated for, so we can tell whether any of it changed. They record the
    # configured values, not what the file currently says, so a policy edited
    # by hand is left alone until the configuration itself changes.
    #
    if [ -f "$LOGROTATE_CONFIG" ]; then
        prev_logdir=$(sed -n 's|^# AZNFS_LOGDIR: ||p' "$LOGROTATE_CONFIG" 2>/dev/null | head -1)
        prev_policy=$(sed -n 's|^# AZNFS_LOGPOLICY: ||p' "$LOGROTATE_CONFIG" 2>/dev/null | head -1)

        if [ "$prev_logdir" == "$AZNFS_CONFIGURED_LOGDIR" -a \
             "$prev_policy" == "size=${AZNFS_LOGSIZE} rotate=${AZNFS_LOGCOUNT}" ]; then
            return 0
        fi
    fi

    #
    # Rotate logs from the configured directory only.
    #
    # Processes started before a log directory change keep writing to the
    # directory they picked up at startup, so the watchdog services must be
    # restarted after changing AZNFS_LOGDIR (see README). A running Turbo
    # client cannot be moved that way, it holds its log open for the life of
    # the mount, so that mount has to be remounted. This is a documented
    # limitation rather than something handled here, see the README.
    #
    logfiles="${AZNFS_CONFIGURED_LOGDIR}/${APPNAME}.log ${AZNFS_CONFIGURED_LOGDIR}/turbo*.log"

    #
    # Staged outside the logrotate config directory. A temp file left behind
    # there by an interrupted mount is itself read as a rotation config, and
    # logrotate then fails the whole run with a duplicate log entry for every
    # path in it. The parent is the same filesystem, so the rename below is
    # still atomic.
    #
    # mktemp rather than a redirection onto a predictable name: this runs from
    # the setuid helper, which keeps the caller's umask, so "> $tmpfile" under
    # umask 000 creates a 0666 file in /etc that the caller can write logrotate
    # directives into before the chmod below. mktemp always creates 0600.
    #
    tmpfile=$(mktemp "$(dirname "$(dirname "$LOGROTATE_CONFIG")")/.${APPNAME}-logrotate.tmp.XXXXXX" 2>/dev/null)

    if [ -z "$tmpfile" ]; then
        vecho "Not able to generate '${LOGROTATE_CONFIG}', ${APPNAME} logs will not be rotated!"
        return 1
    fi

    if ! sed -e "s|AZNFS_LOGDIR_PLACEHOLDER|${AZNFS_CONFIGURED_LOGDIR}|g" \
             -e "s|AZNFS_LOGFILES_PLACEHOLDER|${logfiles}|g" \
             -e "s|AZNFS_LOGPOLICY_PLACEHOLDER|size=${AZNFS_LOGSIZE} rotate=${AZNFS_LOGCOUNT}|g" \
             -e "s|AZNFS_LOGSIZE_PLACEHOLDER|${AZNFS_LOGSIZE}|g" \
             -e "s|AZNFS_LOGCOUNT_PLACEHOLDER|${AZNFS_LOGCOUNT}|g" \
             "$LOGROTATE_TEMPLATE" > "$tmpfile" 2>/dev/null; then
        rm -f "$tmpfile"
        vecho "Not able to generate '${LOGROTATE_CONFIG}', ${APPNAME} logs will not be rotated!"
        return 1
    fi

    chmod 0644 "$tmpfile"

    if ! mv -f "$tmpfile" "$LOGROTATE_CONFIG"; then
        rm -f "$tmpfile"
        vecho "Not able to update '${LOGROTATE_CONFIG}', ${APPNAME} logs will not be rotated!"
        return 1
    fi

    vecho "Generated '${LOGROTATE_CONFIG}' for rotating logs in '${AZNFS_CONFIGURED_LOGDIR}'."

    #
    # Tell the user how to complete the change and where the logs from before
    # it are. Long running processes keep logging to the directory they picked
    # up at startup until restarted, and since rotation is size based a log
    # that stops growing is never rotated out, so those files stay until they
    # are removed by hand.
    #
    if [ -n "$prev_logdir" -a "$prev_logdir" != "$AZNFS_CONFIGURED_LOGDIR" ]; then
        wecho "AZNFS log directory changed to '${AZNFS_CONFIGURED_LOGDIR}'."
        wecho "Restart the watchdog services so that they log there too:"
        wecho "    sudo systemctl restart aznfswatchdog aznfswatchdogv4"
        wecho "Logs from before the change remain in '${prev_logdir}' and are not removed automatically."
    fi

    return 0
}

# On some distros mount program doesn't pass correct PATH variable.
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if command -v netstat &> /dev/null; then
    NETSTATCOMMAND="netstat"
elif command -v ss &> /dev/null; then
    NETSTATCOMMAND="ss"
fi

if [ ! -d $OPTDIRDATA ]; then
    eecho "[FATAL] '${OPTDIRDATA}' is not present, cannot continue!"
    exit 1
fi

#
# Make sure we can actually log into the configured directory. If we can't,
# fall back to the default log directory instead of failing the mount over a
# logging preference.
#
# The effective directory and the configured one are probed separately. A
# per-invocation override decides where this invocation logs, but rotation
# always follows the configured directory, so an unusable configured directory
# has to be caught even when a valid override is hiding it. Otherwise the
# policy would rotate a directory nothing can write to, while the default that
# later invocations fall back to is left uncovered.
#
logdir_is_configured_one="no"
[ "$AZNFS_LOGDIR" == "$AZNFS_CONFIGURED_LOGDIR" ] && logdir_is_configured_one="yes"

if ! usable_logdir "$AZNFS_LOGDIR" "$LOGFILE"; then
    # Not clobbered: an invalid value from the config file was recorded above,
    # and that is the one worth naming, not the fallback that also failed.
    [ -z "$bad_logdir" ] && bad_logdir="$AZNFS_LOGDIR"

    #
    # The configured directory is preferred over the default, because that is
    # the one ensure_logrotate_config() covers. Dropping straight to the
    # default would leave the log we actually write to unrotated, which is the
    # problem this change exists to fix.
    #
    if [ "$logdir_is_configured_one" == "no" ] &&
       usable_logdir "$AZNFS_CONFIGURED_LOGDIR" "${AZNFS_CONFIGURED_LOGDIR}/${APPNAME}.log"; then
        AZNFS_LOGDIR="$AZNFS_CONFIGURED_LOGDIR"
    else
        AZNFS_LOGDIR="$OPTDIRDATA"
    fi

    LOGFILE="${AZNFS_LOGDIR}/${APPNAME}.log"
fi

#
# The fallback is not exempt from the rule. Nothing else has checked it, and
# appending through a link here would defeat every check above. The directory
# is root owned, so a link at this path is either an attack or a broken
# install; refusing is safer than writing wherever it points.
#
# Not eecho: that appends to $LOGFILE, which is the link being refused, so the
# refusal would perform the very write it exists to prevent.
#
if [ -L "$LOGFILE" ]; then
    echo "[FATAL] '${LOGFILE}' is a symlink, refusing to log through it!" >&2
    echo "Set AZNFS_LOGDIR in ${AZNFS_CONFIG_FILE} to relocate logs instead." >&2
    exit 1
fi

#
# Created before the warnings below, not after: _log opens $LOGFILE, so warning
# about a rejected directory first leaks a raw shell error to the terminal.
#
if [ ! -f $LOGFILE ]; then
    touch $LOGFILE
    if [ $? -ne 0 ]; then
        echo "[FATAL] Not able to create '${LOGFILE}'!" >&2
        exit 1
    fi
fi

if [ "$logdir_is_configured_one" == "yes" ]; then
    #
    # Same value, so it has already been probed and is warned about below.
    #
    if [ -n "$bad_logdir" ]; then
        AZNFS_CONFIGURED_LOGDIR="$OPTDIRDATA"
    fi
elif ! usable_logdir "$AZNFS_CONFIGURED_LOGDIR" "${AZNFS_CONFIGURED_LOGDIR}/${APPNAME}.log"; then
    wecho "Not able to use configured log directory '${AZNFS_CONFIGURED_LOGDIR}', rotating '${OPTDIRDATA}' instead!"
    AZNFS_CONFIGURED_LOGDIR="$OPTDIRDATA"
fi

if [ -n "$bad_logdir" ]; then
    wecho "Not able to use log directory '${bad_logdir}', using '${AZNFS_LOGDIR}' instead!"
    unset bad_logdir
fi

if [ -n "$bad_logsize" ]; then
    wecho "Invalid AZNFS_LOGSIZE '${bad_logsize}', rotating at '${AZNFS_LOGSIZE}' instead!"
    unset bad_logsize
fi

if [ -n "$bad_logcount" ]; then
    wecho "Invalid AZNFS_LOGCOUNT '${bad_logcount}', keeping '${AZNFS_LOGCOUNT}' rotations instead!"
    unset bad_logcount
fi

# Keep the logrotate config in sync with the configured log directory.
# Never let a logging setup failure stop a mount, guarded in case a caller
# enables errexit around this.
ensure_logrotate_config || true

# Create mount map file
if ! create_mountmap_file; then
    exit 1
fi

ulimitfd=$(ulimit -n 2>/dev/null)
if [ -n "$ulimitfd" -a $ulimitfd -lt 131072 ]; then
    ulimit -n 131072
fi

#
# In case there are inherited fds, close other than 0,1,2.
#
pushd /proc/$$/fd  > /dev/null
for fd in *; do
    [ $fd -gt 2 ] && exec {fd}<&-
done
popd  > /dev/null
