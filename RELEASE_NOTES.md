# aznfs 3.0.21

- Security: verify the stunnel source against its published SHA-256 checksum and build
  it in a private directory (RHEL/CentOS 7 RPM install).
- Log NFSv4 (incl. stunnel) to syslog by default, or optionally to files in
  `AZNFS_LOGDIR` rotated via logrotate. See the [Logs](README.md#logs) section.
- Fix a race at NFSv4 watchdog startup that could fail concurrent NFSv4 mounts.
- Add Debian 12 and 13 support.

**Upgrade note:** NFSv4 mounts made before the upgrade use the new logging only after
being unmounted and mounted again, and after `aznfswatchdogv4` is restarted (auto-update
does not restart it).

# aznfs 3.0.20

- Security: install `mount.aznfs` without the setuid bit.

**Upgrade note:** Mounting with aznfs now requires root.
