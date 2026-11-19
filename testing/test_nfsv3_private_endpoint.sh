#!/bin/bash

# Exercise the watchdog with stubbed DNS, socket and mount commands; no root or network needed.
REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
WATCHDOG="$REPO_DIR/src/aznfswatchdog"
COMMON="$REPO_DIR/lib/common.sh"
TEST_DIR=$(mktemp -d) || exit 1
trap 'rm -rf "$TEST_DIR"' EXIT
FAILED=0

check()
{
    if "$@"; then
        echo "PASS: $*"
    else
        echo "FAIL: $*"
        FAILED=1
    fi
}

for function in dns_host forget_private_endpoint_state forget_private_endpoint public_dns_lookup_allowed note_public_dns_failure note_public_dns_success get_endpoint_type lookup_endpoint_type resolve_public_ipv4 reconnect_private_endpoint should_skip_regional_account check_for_regional_account run_daily_once process_nfsv3_mounts; do
    source <(sed -n "/^${function}()/,/^}$/p" "$WATCHDOG")
    declare -F "$function" >/dev/null || exit 1
done
for function in is_valid_ipv4_address is_private_ip; do
    source <(sed -n "/^${function}()/,/^}$/p" "$COMMON")
    declare -F "$function" >/dev/null || exit 1
done

declare -A regional_accounts ip_change_count last_ip_change_time private_endpoint_public_ips
declare -A private_endpoint_reset_failures public_dns_failures public_dns_retry_epoch
declare -A endpoint_type_cache endpoint_type_cache_expiry
# Classification is not cached unless a test enables it.
ENDPOINT_TYPE_CACHE_SECS=0
public_dns_resolver_retry_epoch=0
DNS_LOOKUP_TIMEOUT_SECS=3
DNS_LOOKUP_RETRIES=1
DNS_LOOKUP_DEADLINE_SECS=8
PUBLIC_DNS_MAX_BACKOFF_SECS=600
PRIVATE_ENDPOINT_MAX_RESET_ATTEMPTS=3
AZNFS_PUBLIC_DNS_SERVER=1.1.1.1
AZNFS_PRIVATE_ENDPOINT_HOSTS=
AZNFS_SKIP_IP_CHANGE_DETECTION_FOR_REGIONAL_ACCOUNTS=1
AZNFS_SKIP_UNMOUNT_CLEANUP=0
IP_CHANGE_DETECTION_FREQUENCY=60
DAILY_CHECK_AFTER_SECONDS=86400
AKS_USER=true
MOUNTMAP_INACTIVITY_SECS=300
next_daily_run_epoch=100000
next_ip_change_detection_epoch=0
TEST_EPOCH=1000
MOUNTMAPv3="$TEST_DIR/mountmap"
ERROR_LOG="$TEST_DIR/errors"
HOST_LOG="$TEST_DIR/host"
LOCAL_HOST_LOG="$TEST_DIR/local-host"
SOCKET_LOG="$TEST_DIR/sockets"
UPDATE_LOG="$TEST_DIR/updates"
PING_LOG="$TEST_DIR/pings"
HOST_STATUS=0
LOCAL_HOST_STATUS=0
LOCAL_HOST_OUTPUT=
SOCKET_STATUS=0
SOCKET_ERROR=
LOCAL_DNS_STATUS=0
UPDATE_STATUS=0
LOCAL_DNS_IP=100.64.0.4
HOST_OUTPUT='account.blob.core.windows.net has address 20.60.0.1'
HOST=account.blob.core.windows.net
PROXY=10.161.100.100
KEY="$HOST $PROXY $LOCAL_DNS_IP"
MOUNT_OUTPUT="0:1 nfs $PROXY:/account/container /mnt/test rw,vers=3,port=2048"

eecho() { echo "$*" >> "$ERROR_LOG"; }
timeout() { shift; "$@"; }
reset_dns_backoff()
{
    public_dns_failures=()
    public_dns_retry_epoch=()
    public_dns_resolver_retry_epoch=0
}
line_count() { wc -l < "$1" | tr -d ' '; }
wecho() { echo "$*" >> "$ERROR_LOG"; }
pecho() { :; }
vecho() { :; }
date() { echo "$TEST_EPOCH"; }
stat() { echo 100; }
flock() { :; }
findmnt() { echo "$MOUNT_OUTPUT"; }
reconcile_conntrack() { :; }
verify_iptable_entry() { :; }
resolve_ipv4() { echo "$LOCAL_DNS_IP"; return "$LOCAL_DNS_STATUS"; }
ping_new_endpoint() { echo "$1" >> "$PING_LOG"; }
ensure_mountmapv3_not_exist() { : > "$MOUNTMAPv3"; echo 101; }
update_mountmapv3_entry()
{
    echo "$*" >> "$UPDATE_LOG"
    [ "$UPDATE_STATUS" -eq 0 ] || return "$UPDATE_STATUS"
    echo "$2" > "$MOUNTMAPv3"
}
host()
{
    if [ "${!#}" == "$AZNFS_PUBLIC_DNS_SERVER" ]; then
        printf '%s|' "$@" >> "$HOST_LOG"
        echo >> "$HOST_LOG"
        echo "$HOST_OUTPUT"
        return "$HOST_STATUS"
    fi
    printf '%s|' "$@" >> "$LOCAL_HOST_LOG"
    echo >> "$LOCAL_HOST_LOG"
    if [ -n "$LOCAL_HOST_OUTPUT" ]; then
        echo "$LOCAL_HOST_OUTPUT"
    else
        echo "$HOST is an alias for account.privatelink.blob.core.windows.net."
        echo "account.privatelink.blob.core.windows.net has address $LOCAL_DNS_IP"
    fi
    return "$LOCAL_HOST_STATUS"
}
ss()
{
    printf '%s|' "$@" >> "$SOCKET_LOG"
    echo >> "$SOCKET_LOG"
    [ -z "$SOCKET_ERROR" ] || echo "$SOCKET_ERROR" >&2
    return "$SOCKET_STATUS"
}

cycle()
{
    TEST_EPOCH=$((TEST_EPOCH + 61))
    process_nfsv3_mounts
    wait
}

# A privatelink CNAME can occur in both paths; the A-record owner distinguishes them.
check test "$(get_endpoint_type "$HOST")" = private
check grep -Fxq -- "-W|3|-R|1|-4|-t|A|$HOST|" "$LOCAL_HOST_LOG"
PUBLIC_CHAIN=$'account.blob.core.windows.net is an alias for account.privatelink.blob.core.windows.net.\naccount.privatelink.blob.core.windows.net is an alias for blob.byaprdstr18a.store.core.windows.net.'
LOCAL_HOST_OUTPUT="$PUBLIC_CHAIN"$'\nblob.byaprdstr18a.store.core.windows.net has address 135.130.66.1'
check test "$(get_endpoint_type "$HOST")" = public
LOCAL_HOST_OUTPUT='account.privatelink.blob.core.windows.net has address 10.0.0.13'
check test "$(get_endpoint_type account.privatelink.blob.core.windows.net)" = private
LOCAL_HOST_OUTPUT=$'custom.example.com is an alias for ACCOUNT.PRIVATELINK.BLOB.CORE.WINDOWS.NET.\nACCOUNT.PRIVATELINK.BLOB.CORE.WINDOWS.NET. has address 100.64.0.4'
check test "$(get_endpoint_type custom.example.com)" = private

# Address ranges alone do not identify a private endpoint. Custom DNS can opt in per host.
LOCAL_HOST_OUTPUT="$HOST has address 10.0.0.13"
check test "$(get_endpoint_type "$HOST")" = public
AZNFS_PRIVATE_ENDPOINT_HOSTS="other.blob.core.windows.net ACCOUNT.BLOB.CORE.WINDOWS.NET."
: > "$LOCAL_HOST_LOG"
check test "$(get_endpoint_type "$HOST")" = private
check test ! -s "$LOCAL_HOST_LOG"
check test "$(get_endpoint_type another.blob.core.windows.net)" = public
AZNFS_PRIVATE_ENDPOINT_HOSTS=
LOCAL_HOST_OUTPUT=

echo "$KEY" > "$MOUNTMAPv3"
cycle
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.1
check test ! -s "$SOCKET_LOG"
check test ! -s "$UPDATE_LOG"
check grep -Fxq -- '-W|3|-R|1|-4|-t|A|account.blob.core.windows.net|1.1.1.1|' "$HOST_LOG"

HOST_OUTPUT=$'account.blob.core.windows.net has address 20.60.0.2\naccount.blob.core.windows.net has address 20.60.0.1'
cycle
check test "${private_endpoint_public_ips[$KEY]}" = $'20.60.0.1\n20.60.0.2'
check grep -Fxq -- "-Ktn|dst|$PROXY|" "$SOCKET_LOG"
check grep -Fxq /mnt/test "$PING_LOG"
check test "$(cat "$MOUNTMAPv3")" = "$KEY"
check test ! -s "$UPDATE_LOG"

: > "$SOCKET_LOG"
: > "$PING_LOG"
HOST_OUTPUT=$'account.blob.core.windows.net has address 20.60.0.1\naccount.blob.core.windows.net has address 20.60.0.2\naccount.blob.core.windows.net has address 20.60.0.1'
cycle
check test ! -s "$SOCKET_LOG"
check test ! -s "$PING_LOG"

# A classification failure must leave the baseline and connections alone until retry.
LOCAL_HOST_STATUS=1
LOCAL_HOST_OUTPUT='DNS query timed out'
HOST_OUTPUT='account.blob.core.windows.net has address 20.60.0.3'
cycle
check test ! -s "$SOCKET_LOG"
check test "${private_endpoint_public_ips[$KEY]}" = $'20.60.0.1\n20.60.0.2'
check grep -q 'Cannot determine endpoint type' "$ERROR_LOG"
LOCAL_HOST_STATUS=0
LOCAL_HOST_OUTPUT='no A records'
cycle
check test ! -s "$SOCKET_LOG"
check test "${private_endpoint_public_ips[$KEY]}" = $'20.60.0.1\n20.60.0.2'
LOCAL_HOST_OUTPUT=

# Regional private accounts use the same skip policy and opt-out as public accounts.
regional_accounts[$HOST]=1
HOST_OUTPUT='account.blob.core.windows.net has address 20.60.0.3'
: > "$HOST_LOG"
cycle
check test ! -s "$HOST_LOG"
check test ! -s "$SOCKET_LOG"
check test "${private_endpoint_public_ips[$KEY]}" = $'20.60.0.1\n20.60.0.2'
AZNFS_SKIP_IP_CHANGE_DETECTION_FOR_REGIONAL_ACCOUNTS=0
cycle
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.3
check test -s "$SOCKET_LOG"
AZNFS_SKIP_IP_CHANGE_DETECTION_FOR_REGIONAL_ACCOUNTS=1
regional_accounts=()
ip_change_count=()
last_ip_change_time=()

# Failed DNS, including NXDOMAIN, must not delete the private mapping or baseline.
: > "$SOCKET_LOG"
HOST_STATUS=1
HOST_OUTPUT=NXDOMAIN
cycle
check test ! -s "$SOCKET_LOG"
check test "$(cat "$MOUNTMAPv3")" = "$KEY"
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.3
check grep -q 'Public DNS lookup.*failed' "$ERROR_LOG"
HOST_STATUS=0
for HOST_OUTPUT in 'no A records' \
    'account.blob.core.windows.net has address 10.20.0.4' \
    'account.blob.core.windows.net has address 999.1.2.3'; do
    reset_dns_backoff
    cycle
    check test ! -s "$SOCKET_LOG"
    check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.3
done

# Failed lookups back off, and an unreachable resolver backs off for every endpoint.
reset_dns_backoff
: > "$HOST_LOG"
HOST_STATUS=1
HOST_OUTPUT=';; connection timed out; no servers could be reached'
cycle
check test "$(line_count "$HOST_LOG")" = 1
check test "${public_dns_failures[resolver]}" = 1
check test -z "${public_dns_failures[$KEY]}"
cycle
check test "$(line_count "$HOST_LOG")" = 2
cycle
check test "$(line_count "$HOST_LOG")" = 2
HOST_STATUS=124
HOST_OUTPUT=
reset_dns_backoff
cycle
check test "${public_dns_failures[resolver]}" = 1
HOST_STATUS=0
HOST_OUTPUT='account.blob.core.windows.net has address 20.60.0.3'
cycle
check test "$(line_count "$HOST_LOG")" = 4
cycle
check test "$(line_count "$HOST_LOG")" = 5
check test -z "${public_dns_failures[resolver]}"
check test "$public_dns_resolver_retry_epoch" = 0

# A lookup failing for one name only delays that name.
HOST_STATUS=1
HOST_OUTPUT=NXDOMAIN
cycle
check test "${public_dns_failures[$KEY]}" = 1
check test -z "${public_dns_failures[resolver]}"
check test "$public_dns_resolver_retry_epoch" = 0
reset_dns_backoff
HOST_STATUS=0

# Both command failures and per-socket errors must leave the change pending.
HOST_OUTPUT='account.blob.core.windows.net has address 20.60.0.4'
SOCKET_STATUS=1
SOCKET_ERROR='ss failed'
cycle
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.3
check test -z "${ip_change_count[$HOST]}"
SOCKET_STATUS=0
SOCKET_ERROR='SOCK_DESTROY answers: Operation not supported'
cycle
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.3
check test -z "${ip_change_count[$HOST]}"
check grep -q 'Failed to reset TCP connections' "$ERROR_LOG"
SOCKET_ERROR=
cycle
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.4
check test "${ip_change_count[$HOST]}" = 1

# A socket that disappeared on its own is not a failed reset, but a silent ss failure is.
HOST_OUTPUT='account.blob.core.windows.net has address 20.60.0.6'
SOCKET_STATUS=1
SOCKET_ERROR='SOCK_DESTROY answers: No such file or directory'
cycle
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.6
SOCKET_ERROR=
HOST_OUTPUT='account.blob.core.windows.net has address 20.60.0.7'
cycle
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.6
check grep -q 'ss exited with status 1' "$ERROR_LOG"
SOCKET_STATUS=0

# A reset that keeps failing is attempted a bounded number of times, then the change is accepted.
private_endpoint_reset_failures=()
: > "$SOCKET_LOG"
SOCKET_ERROR='SOCK_DESTROY answers: Operation not supported'
HOST_OUTPUT='account.blob.core.windows.net has address 20.60.0.8'
cycle
cycle
check test "$(line_count "$SOCKET_LOG")" = 2
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.6
cycle
check test "$(line_count "$SOCKET_LOG")" = 3
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.8
check test -z "${private_endpoint_reset_failures[$KEY]}"
check grep -q 'Giving up resetting connections' "$ERROR_LOG"
cycle
check test "$(line_count "$SOCKET_LOG")" = 3

# After giving up, a further change is handled normally.
SOCKET_ERROR=
HOST_OUTPUT='account.blob.core.windows.net has address 20.60.0.4'
cycle
check test "$(line_count "$SOCKET_LOG")" = 4
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.4
regional_accounts=()
ip_change_count=()
last_ip_change_time=()
reset_dns_backoff

# Use the configurable resolver and normalize explicit privatelink hostnames.
AZNFS_PUBLIC_DNS_SERVER=8.8.8.8
resolve_public_ipv4 account.privatelink.blob.core.windows.net >/dev/null
check grep -Fxq -- '-W|3|-R|1|-4|-t|A|account.blob.core.windows.net|8.8.8.8|' "$HOST_LOG"

# Do not query public DNS more often than the existing detection interval.
: > "$HOST_LOG"
process_nfsv3_mounts
check test ! -s "$HOST_LOG"

# A private IP change still uses the original DNAT update path.
LOCAL_DNS_IP=10.20.0.5
: > "$SOCKET_LOG"
cycle
check test -s "$UPDATE_LOG"
check test "$(cat "$MOUNTMAPv3")" = "$HOST $PROXY 10.20.0.5"
check test -z "${private_endpoint_public_ips[$KEY]}"
check test ! -s "$SOCKET_LOG"
cycle
NEW_KEY="$HOST $PROXY $LOCAL_DNS_IP"
check test "${private_endpoint_public_ips[$NEW_KEY]}" = 20.60.0.4
check test ! -s "$SOCKET_LOG"

# Garbage collection forgets the baseline, so a later remount starts fresh.
MOUNT_OUTPUT=
cycle
check test ! -s "$MOUNTMAPv3"
check test -z "${private_endpoint_public_ips[$NEW_KEY]}"

# Ordinary public mounts must retain their existing DNS/DNAT behavior.
regional_accounts=()
LOCAL_DNS_IP=20.60.0.10
LOCAL_HOST_OUTPUT="$PUBLIC_CHAIN"$'\nblob.byaprdstr18a.store.core.windows.net has address 20.60.0.10'
echo "$HOST $PROXY 20.60.0.9" > "$MOUNTMAPv3"
MOUNT_OUTPUT="0:1 nfs $PROXY:/account/container /mnt/test rw,vers=3,port=2048"
: > "$HOST_LOG"
: > "$UPDATE_LOG"
cycle
check test "$(cat "$MOUNTMAPv3")" = "$HOST $PROXY 20.60.0.10"
check test -s "$UPDATE_LOG"
check test ! -s "$HOST_LOG"
regional_accounts[$HOST]=1
LOCAL_DNS_IP=20.60.0.11
: > "$UPDATE_LOG"
cycle
check test ! -s "$UPDATE_LOG"

# Custom DNS without a visible chain still receives private-endpoint recovery when overridden.
regional_accounts=()
AZNFS_PRIVATE_ENDPOINT_HOSTS="$HOST"
LOCAL_DNS_IP=100.64.0.4
LOCAL_HOST_OUTPUT="$HOST has address $LOCAL_DNS_IP"
echo "$KEY" > "$MOUNTMAPv3"
: > "$HOST_LOG"
: > "$SOCKET_LOG"
: > "$UPDATE_LOG"
cycle
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.4
HOST_OUTPUT='account.blob.core.windows.net has address 20.60.0.5'
cycle
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.5
check test -s "$SOCKET_LOG"
check test ! -s "$UPDATE_LOG"
check test "$(cat "$MOUNTMAPv3")" = "$KEY"

# Switching back to a public path clears the old private baseline, even if the IP is unchanged.
AZNFS_PRIVATE_ENDPOINT_HOSTS=
LOCAL_HOST_OUTPUT="$PUBLIC_CHAIN"$'\nblob.byaprdstr18a.store.core.windows.net has address 100.64.0.4'
: > "$HOST_LOG"
: > "$SOCKET_LOG"
cycle
check test -z "${private_endpoint_public_ips[$KEY]}"
check test ! -s "$HOST_LOG"
check test ! -s "$SOCKET_LOG"

# Private endpoints are classified from public DNS changes, with no DNAT updates.
regional_accounts=()
ip_change_count=()
last_ip_change_time=()
private_endpoint_public_ips=()
LOCAL_HOST_OUTPUT=
HOST_OUTPUT='account.blob.core.windows.net has address 20.60.0.100'
cycle
check test -z "${ip_change_count[$HOST]}"
: > "$UPDATE_LOG"
for suffix in 101 102; do
    HOST_OUTPUT="$HOST has address 20.60.0.$suffix"
    cycle
    check test "${regional_accounts[$HOST]:-0}" = 0
done
HOST_OUTPUT="$HOST has address 20.60.0.103"
cycle
check test "${ip_change_count[$HOST]}" = 3
check test "${regional_accounts[$HOST]}" = 1
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.103
check test ! -s "$UPDATE_LOG"

HOST_OUTPUT="$HOST has address 20.60.0.104"
: > "$HOST_LOG"
: > "$LOCAL_HOST_LOG"
: > "$SOCKET_LOG"
cycle
check test ! -s "$HOST_LOG"
check test ! -s "$LOCAL_HOST_LOG"
check test ! -s "$SOCKET_LOG"
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.103
AZNFS_SKIP_IP_CHANGE_DETECTION_FOR_REGIONAL_ACCOUNTS=0
cycle
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.104
check test -s "$SOCKET_LOG"
check test ! -s "$UPDATE_LOG"
AZNFS_SKIP_IP_CHANGE_DETECTION_FOR_REGIONAL_ACCOUNTS=1

# The daily reset allows a private account to be evaluated and recovered again.
next_daily_run_epoch=$((TEST_EPOCH + 1))
HOST_OUTPUT="$HOST has address 20.60.0.105"
: > "$SOCKET_LOG"
cycle
check test "${regional_accounts[$HOST]:-0}" = 0
check test "${ip_change_count[$HOST]}" = 1
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.105
check test -s "$SOCKET_LOG"

# Public endpoints use the same three-change threshold and skip opt-out.
regional_accounts=()
ip_change_count=()
last_ip_change_time=()
LOCAL_DNS_IP=20.60.0.200
echo "$HOST $PROXY $LOCAL_DNS_IP" > "$MOUNTMAPv3"
LOCAL_HOST_OUTPUT="$PUBLIC_CHAIN"$'\nblob.byaprdstr18a.store.core.windows.net has address 20.60.0.200'
for suffix in 201 202 203; do
    LOCAL_DNS_IP="20.60.0.$suffix"
    cycle
done
check test "${ip_change_count[$HOST]}" = 3
check test "${regional_accounts[$HOST]}" = 1
LOCAL_DNS_IP=20.60.0.204
: > "$UPDATE_LOG"
cycle
check test ! -s "$UPDATE_LOG"
AZNFS_SKIP_IP_CHANGE_DETECTION_FOR_REGIONAL_ACCOUNTS=0
cycle
check test "$(cat "$MOUNTMAPv3")" = "$HOST $PROXY 20.60.0.204"

# Backoff doubles from the detection interval and is capped, as documented.
reset_dns_backoff
expected_backoffs=(60 120 240 480 600 600)
for expected in "${expected_backoffs[@]}"; do
    note_public_dns_failure "$KEY" 1
    check test "$((public_dns_retry_epoch[$KEY] - TEST_EPOCH))" = "$expected"
done
reset_dns_backoff

# Failing to classify an endpoint must never block the DNAT update for a changed endpoint IP.
regional_accounts=()
ip_change_count=()
last_ip_change_time=()
LOCAL_HOST_STATUS=1
LOCAL_HOST_OUTPUT='DNS query timed out'
echo "$HOST $PROXY 20.60.1.44" > "$MOUNTMAPv3"
LOCAL_DNS_IP=20.60.1.45
: > "$UPDATE_LOG"
cycle
check test "$(cat "$MOUNTMAPv3")" = "$HOST $PROXY 20.60.1.45"
check test -s "$UPDATE_LOG"
# An unknown classification also leaves an existing private endpoint baseline untouched.
LOCAL_HOST_OUTPUT=
LOCAL_HOST_STATUS=0
LOCAL_DNS_IP=100.64.0.4
echo "$KEY" > "$MOUNTMAPv3"
AZNFS_PRIVATE_ENDPOINT_HOSTS=
HOST_OUTPUT='account.blob.core.windows.net has address 20.60.0.4'
cycle
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.4
LOCAL_HOST_STATUS=1
LOCAL_HOST_OUTPUT='DNS query timed out'
: > "$SOCKET_LOG"
cycle
check test "${private_endpoint_public_ips[$KEY]}" = 20.60.0.4
check test ! -s "$SOCKET_LOG"
LOCAL_HOST_STATUS=0
LOCAL_HOST_OUTPUT=

# Classification is reused for ENDPOINT_TYPE_CACHE_SECS, not looked up every cycle.
ENDPOINT_TYPE_CACHE_SECS=300
forget_private_endpoint "$KEY"
: > "$LOCAL_HOST_LOG"
cycle
cycle
check test "$(line_count "$LOCAL_HOST_LOG")" = 1
TEST_EPOCH=$((TEST_EPOCH + 300))
cycle
check test "$(line_count "$LOCAL_HOST_LOG")" = 2
# A failed classification is not cached, so it is retried next cycle.
forget_private_endpoint "$KEY"
LOCAL_HOST_STATUS=1
LOCAL_HOST_OUTPUT='DNS query timed out'
: > "$LOCAL_HOST_LOG"
cycle
cycle
check test "$(line_count "$LOCAL_HOST_LOG")" = 2
check test -z "${endpoint_type_cache[$KEY]}"
LOCAL_HOST_STATUS=0
LOCAL_HOST_OUTPUT=
ENDPOINT_TYPE_CACHE_SECS=0

exit "$FAILED"
