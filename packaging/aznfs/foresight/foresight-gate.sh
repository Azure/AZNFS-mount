#!/bin/bash

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

#
# nfs-foresight package gate + activation helper (shared by deb postinst/prerm/postrm
# and rpm %post/%preun/%postun).
#
# The aznfs package family (rpm) spans BOTH kernel 4.18 (RHEL8/CentOS8/Rocky8 ->
# "legacy" build) and kernel >=5.x (RHEL9/10/Rocky9 -> "default" build), and the deb
# family spans Ubuntu 18.04 (kernel 4.15, no BTF -> unsupported) through Ubuntu >=20.04.
# A single package therefore cannot pick the right binary at build time, so this helper
# selects the correct variant on the ACTUAL host at install time (postinst), symlinks it
# to /usr/sbin/nfs-foresight, installs the unit, and lays down default config -- but does
# NOT enable or start the service (off by default; the operator runs `systemctl start`).
#
# CO-RE eBPF requires kernel BTF; on hosts without it (e.g. RHEL7/3.10, Ubuntu 18.04/4.15)
# this helper installs nothing and exits cleanly. It must NEVER fail the package
# transaction -- every path returns 0.
#

LIBEXEC=/usr/lib/nfs-foresight
BIN_DEFAULT=$LIBEXEC/nfs-foresight
BIN_LEGACY=$LIBEXEC/nfs-foresight-legacy
UNIT_SRC=$LIBEXEC/nfs-foresight.service
CONF_SRC=$LIBEXEC/foresight.conf

SBIN=/usr/sbin/nfs-foresight
UNIT=/lib/systemd/system/nfs-foresight.service
CONF_DIR=/etc/nfs-foresight
CONF=$CONF_DIR/foresight.conf
ENABLED=$CONF_DIR/enabled

log() { echo "nfs-foresight: $*"; }

#
# Echo the variant to install for THIS host: "default", "legacy", or "" (unsupported).
# CO-RE needs readable kernel BTF. Kernel >=5.0 uses the default build; the RHEL8-class
# 4.18 (which backported BTF+CO-RE) uses the legacy build; anything else is unsupported.
#
select_variant() {
	local m major minor
	m=$(uname -m)
	[ "$m" = x86_64 ] || [ "$m" = aarch64 ] || { echo ""; return; }
	[ -r /sys/kernel/btf/vmlinux ] || { echo ""; return; }

	# kernel major.minor from `uname -r` (e.g. 5.14.21-... -> 5 14)
	local kr; kr=$(uname -r)
	major=${kr%%.*}
	minor=${kr#*.}; minor=${minor%%.*}
	[ -n "$major" ] && [ -n "$minor" ] || { echo ""; return; }

	if [ "$major" -gt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -ge 0 ]; }; then
		[ -x "$BIN_DEFAULT" ] && { echo default; return; }
	fi
	if [ "$major" -eq 4 ] && [ "$minor" -eq 18 ]; then
		[ -x "$BIN_LEGACY" ] && { echo legacy; return; }
	fi
	echo ""
}

remove_runtime() {
	# stop+disable if present; ignore all errors (may be inactive/never-enabled).
	if command -v systemctl >/dev/null 2>&1; then
		systemctl stop    nfs-foresight.service >/dev/null 2>&1 || true
		systemctl disable nfs-foresight.service >/dev/null 2>&1 || true
	fi
	rm -f "$SBIN" "$UNIT" 2>/dev/null || true
	if command -v systemctl >/dev/null 2>&1; then
		systemctl daemon-reload >/dev/null 2>&1 || true
	fi
}

do_install() {
	local variant bin
	variant=$(select_variant)
	if [ -z "$variant" ]; then
		log "kernel lacks BTF/CO-RE (or unsupported arch); nfs-foresight not installed on this host"
		remove_runtime           # clean up any stale install from a previous, capable kernel
		return 0
	fi
	[ "$variant" = legacy ] && bin=$BIN_LEGACY || bin=$BIN_DEFAULT

	# Select the right binary (symlink so upgrades/kernel changes just re-point it).
	ln -sf "$bin" "$SBIN" 2>/dev/null || true

	# Install the unit, off by default: NOT enabled, NOT started.
	if [ -f "$UNIT_SRC" ]; then
		install -m 0644 "$UNIT_SRC" "$UNIT" 2>/dev/null || cp -f "$UNIT_SRC" "$UNIT" 2>/dev/null || true
	fi

	mkdir -p "$CONF_DIR" 2>/dev/null || true
	# Preserve an operator's existing config; only lay down the default if absent.
	if [ ! -f "$CONF" ] && [ -f "$CONF_SRC" ]; then
		install -m 0644 "$CONF_SRC" "$CONF" 2>/dev/null || cp -f "$CONF_SRC" "$CONF" 2>/dev/null || true
	fi
	# Activation switch: 0 = observer (default), 1 = active (prewarm). Create if absent.
	if [ ! -f "$ENABLED" ]; then
		printf '0\n' > "$ENABLED" 2>/dev/null || true
		chmod 0644 "$ENABLED" 2>/dev/null || true
	fi

	if command -v systemctl >/dev/null 2>&1; then
		systemctl daemon-reload >/dev/null 2>&1 || true
	fi
	log "installed ($variant build), off by default -- 'systemctl start nfs-foresight' for observer; 'echo 1 > $ENABLED' for active"
	return 0
}

do_remove() {
	remove_runtime
	return 0
}

do_purge() {
	remove_runtime
	rm -rf "$LIBEXEC" "$CONF_DIR" 2>/dev/null || true
	return 0
}

case "${1:-}" in
	install) do_install ;;
	remove)  do_remove ;;
	purge)   do_purge ;;
	*) log "usage: $0 {install|remove|purge}" ;;
esac

# Never fail the enclosing package transaction.
exit 0
