# AZNFS Mount Helper

The mount helper discussed here is designed to work seamlessly with both NFSv3 and NFSv4 protocols. Its functionality spans across use cases that ensure robust handling of endpoint IP address changes for Azure Blob NFSv3 mounts and provision of a secure communication channel for Azure File NFSv4 mounts:

> **Mount helper use case for correctly handling endpoint IP address changes for Azure Blob NFSv3 mounts.**

Azure Blob NFSv3 is a highly available clustered NFSv3 server for providing NFSv3 access to Azure Blobs. To maintain availability
in case of infrequent-but-likely events like hardware failures, hardware decommissioning, etc, the endpoint IP of the Azure Blob
NFS endpoint may change. This change in IP is mostly transparent to applications because the DNS records are updated such that the
Azure Blob NFS FQDN always resolves to the updated IP. This works fine for new mounts as they will automatically connect to the new IP,
but this change in IP is not handled by Linux NFS client for already mounted shares, as it only resolves the IP at the time of mount
and any change in the server IP after mount will cause it to indefinitely attempt reconnect to the old IP. Also NFSv3 protocol doesn't
provide a way for server to convey such change in IP to the clients. This means that this change in IP has to be detected by a userspace
process and conveyed to the kernel through some supported interface. Using a mount helper is a supported way in Linux to do "something
extra" during a mount, hence this AZNFS mount helper is needed so that Linux NFS clients can reliably access Azure Blob NFS shares even
when their IP changes. Current version of this mount helper uses iptables DNAT functionality to map a stable proxy IP
which is mounted by the NFS client to the correct Blob NFS endpoint IP. This may change in future versions.

User has to install AZNFS package and mount the NFSv3 share using `-t aznfs` flag.  This package will run a background job called
**aznfswatchdog** to detect change in endpoint IP address for the mounted shares. If there will be any change in endpoint IP,
aznfswatchdog will update the DNAT rules appropriately.

This package picks a free private IP which is not in use by user's machine and mount the NFSv3 share using that IP and
create a DNAT rule to route the traffic from the chosen private IP to original endpoint IP.

> **Mount helper use case for a secure communication channel for Azure File NFSv4 mounts.**

The mount helper can be used to provide a secure communication channel for NFSv4 traffic. This is achieved by implementing TLS encryption for
NFS traffic using stunnel. Stunnel is a proxy designed to add TLS encryption functionality to existing services: [https://www.stunnel.org/](https://www.stunnel.org/)

The aznfs mount helper will be used to mount the NFS shares with TLS support. The mount helper initializes dedicated stunnel client
process for each storage account's IP address. The stunnel client process listens on a local port for inbound traffic, and then stunnel redirects
nfs client traffic to the 2049 port where NFS server is listening on.

User has to install AZNFS package and mount the NFSv4 shares using `-t aznfs` flag. During the mounting process, user can decide if
they want to mount shares with TLS encryption or without it using `notls` option. For a given endpoint, all the mounts should either use TLS encryption or clear-text using `notls` option as they share the same connection.

To ensure security and consistency, it’s strongly recommended to use the mount helper for both TLS and clear-text mounts

The AZNFS package runs a background job called **aznfswatchdog**. It ensures that stunnel processes are running for each storage account
and cleanup after all shares from the storage account are unmounted. If for some reason a stunnel process is terminated unexpectedly,
the watchdog process restarts it.


## Supported Distros

AZNFS is supported on following Linux distros:

- Ubuntu (18.04 LTS, 20.04 LTS, 22.04 LTS, 26.04 LTS)
- Centos7, Centos8
- RedHat7, RedHat8, RedHat9
- Rocky8, Rocky9
- SUSE (SLES 15, SLES 16)


## Install Instructions

- Run the following command to download and install **AZNFS**:
	```
	wget -O - -q https://github.com/Azure/AZNFS-mount/releases/latest/download/aznfs_install.sh | bash
	```
	It will install the aznfs mount helper program and the aznfswatchdog service.

## Auto Update

- Upon running the installation command, you will be prompted to configure automatic updates for AZNFS. Enabling automatic updates ensures that you 
  stay current with the latest features, improvements, and security patches, providing you with the best and most seamless AZNFS experience.

> [!NOTE]
> 1. You can also turn off/on auto-update at any time by changing the value of AUTO_UPDATE_AZNFS to false/true respectively in `/opt/microsoft/aznfs/data/config`.
> 2. Existing mounts will not be effected by auto update.

## Non-Interactive Installation
- If your setup requires a noninteractive install, set the following environment variables before installing AZNFS:
  
  For all distros, you can use:
  ```
	export AZNFS_NONINTERACTIVE_INSTALL=1
	```
  For DEBIAN based distos, you can additionally use:
  ```
	export DEBIAN_FRONTEND=noninteractive
	```
> [!NOTE]
> Installing noninteractively will set `AUTO_UPDATE_AZNFS=true` by default.

## Usage Instructions

### NFSv3

- Mount the Azure Blob NFSv3 share using following command:
	```
	sudo mount -t aznfs -o vers=3 <account-name>.blob.core.windows.net:/<account-name>/<container-name> /mountpoint
	```
### NFSv4

- Mount the Azure File NFSv4 share using following command:
	```
	sudo mount -t aznfs -o vers=4.1 <account-name>.file.core.windows.net:/<account-name>/<container-name> /mountpoint
	```
   Remember to set environment variable "AZURE_ENDPOINT_OVERRIDE" for mounting non-Public Azure Cloud regions and when using Custom DNS. For example, for Azure China Cloud:
	```
	export AZURE_ENDPOINT_OVERRIDE="chinacloudapi.cn"
	```
- Mount Azure File NFSv4 share without TLS:
	```
	sudo mount -t aznfs -o vers=4.1,notls <account-name>.file.core.windows.net:/<account-name>/<container-name> /mountpoint
	```
- Mount Azure File NFSv4 share without TLS with clean option:

	If a TLS mount is terminated, the watchdog may take some time to complete cleanup. If the user attempts a “notls” mount on the same endpoint before this process finishes, the mount will fail. To resolve this, the user should include the “clean” option when mounting:
	```
	sudo mount -t aznfs -o vers=4.1,notls,clean <account-name>.file.core.windows.net:/<account-name>/<container-name> /mountpoint
	```
### Logs:
- Logs generated from AZNFS watchdog and mount helper will be in `/opt/microsoft/aznfs/data/aznfs.log` by default.
- Logs generated by the Turbo client will be in `/opt/microsoft/aznfs/data/turbo<mountpoint>.log` by default, one log
  file per mount.
- Logs generated by Stunnel will be in `/etc/stunnel/microsoft/aznfs/nfsv4_fileShare/logs`.

#### Settings:
Logging is configured in `/opt/microsoft/aznfs/data/config`, one `KEY=value` per line. There is no command for this,
edit the file.

| Setting | Default | What it does |
| --- | --- | --- |
| `AZNFS_LOGDIR` | `/opt/microsoft/aznfs/data` | Where `aznfs.log` and the Turbo logs are written |
| `AZNFS_LOGSIZE` | `100M` | Rotate a log once it grows past this. `500k`, `100M`, `2G`, or a plain number of bytes |
| `AZNFS_LOGCOUNT` | `7` | How many rotated logs to keep. `0` keeps none |

For example:
```
AZNFS_LOGDIR=/var/log/aznfs
AZNFS_LOGSIZE=200M
AZNFS_LOGCOUNT=10
```

Changes take effect on the next mount. If you changed `AZNFS_LOGDIR`, also restart the watchdogs so they log to the
new directory too:
```
sudo systemctl restart aznfswatchdog aznfswatchdogv4
```

A value AZNFS cannot use is ignored with a warning and the default is used instead, so a mount does not fail because a
log directory was set wrongly.

There is one exception. If the Turbo log file that the mount is about to write to already exists and is a symlink, is
not a regular file, or cannot be appended to, the mount fails rather than starting. At that point there is nowhere safe
to write, and the alternative would be for `root` to append through whatever the file points at.

#### Choosing a log directory:
The directory is created if it doesn't exist. It has to be a path that only `root` can write to:

- the directory itself must be owned by `root` and must not be writable by group or others
- every directory above it must be owned by `root` and must not be world writable. Group writable is allowed only
  when the group is `root` or `syslog`, which is how `/var/log` is shipped (`root:syslog 0775`)
- no part of the path may be a symlink
- `/tmp` and `/var/tmp` are refused, and so is anything under them

`/var/log/aznfs` is a good choice. AZNFS writes its logs as `root`, so if anyone else could create files along that
path they could make `root` write somewhere it shouldn't.

#### After changing the log directory:
- Logs already in the old directory stay there and are no longer rotated. Delete them once you don't need them.
- A Turbo mount that is already running keeps writing to its existing log file. Unmount and mount it again to move it,
  otherwise that one log keeps growing in the old directory with nothing rotating it.

#### Log rotation:
AZNFS generates `/etc/logrotate.d/aznfs` from the three settings above, so logrotate handles the rest. Nothing needs
to be run by hand.

- Logs are rotated by size only, there is no daily or weekly rotation, so how much history you keep depends on how
  much is actually logged rather than on how much time has passed.
- Rotated logs are compressed, except the newest rotation is left uncompressed until the next one.
- Budget roughly `AZNFS_LOGSIZE` × (`AZNFS_LOGCOUNT` + 2) of disk per log file once rotation has settled. Remember
  there is one Turbo log per Turbo mount.
- `AZNFS_LOGSIZE` bounds the log at the moment logrotate runs, not continuously. logrotate runs daily on most
  distros, so between runs a busy mount can take the live log well past it. Rotating with `copytruncate` also needs
  as much free space again as the live log for the duration of the copy. If you need a tighter bound, run logrotate
  more often, for example with a `logrotate.timer` override or an hourly drop-in.

You can also edit `/etc/logrotate.d/aznfs` directly. AZNFS only regenerates it when `AZNFS_LOGDIR`, `AZNFS_LOGSIZE` or
`AZNFS_LOGCOUNT` changes, so your edits survive mounts and package upgrades. If you add a time based directive such as
`daily`, remove the `size` directive as well, logrotate ignores time directives when `size` is set.

#### Environment variable overrides:
`AZNFS_LOGDIR`, and `AZNFSC_LOGDIR` for the Turbo logs alone, can also be set as environment variables when the mount
scripts are invoked directly. `mount.aznfs` drops both, so `mount -t aznfs` always uses the config file. Logs written
to a directory set this way are not rotated.

## Implementation Details

This version of **AZNFS** mount helper uses iptables DNAT rules to forward NFS traffic directed to a local proxy IP
endpoint to actual Azure Blob NFS endpoint. It sets up a local IP endpoint which is used by the NFS client to
mount. A free local IP address is picked from the following range of private IP addresses in the given order:
  ```
  10.161.100.100 - 10.161.254.254
  192.168.100.100 - 192.168.254.254
  172.16.100.100 - 172.16.254.254
  ```

It will try its best to pick an IP address which is not in use but in case the free IP selection clashes with any
of client machines IP addresses, the `AZNFS_IP_PREFIXES` environment variable can be used to override the default IP range.
IP prefixes with either 2 or 3 octets can be set `f.e. 10.100 10.100.100 172.16 172.16.100 192.168 192.168.100`.
  ```
  export AZNFS_IP_PREFIXES="172.16 10.161"
  ```
  This will pick the IP addresses in the range `172.16.100.100 - 172.16.254.254` and `10.161.100.100 - 10.161.254.254`.

It starts a systemd service named **aznfswatchdog** which monitors the change in IP address for all the mounted Azure
Blob NFS shares. If it detects a change in endpoint IP, aznfswatchdog will update the iptables DNAT rule and NFS
traffic will be forwarded to new endpoint IP.
> [!NOTE]
> 1. Ensure that all mounted Azure Blob NFS shares are unmounted before setting the AZNFS_IP_PREFIXES environment variable.
> 2. After an Azure Blob NFS endpoint is unmounted, the local proxy IP-to-endpoint mapping remains cached in the mountmap. **aznfswatchdog** takes 5 minutes from the last unmount to remove this entry. Once the entry is cleared, a fresh mount will honor the `AZNFS_IP_PREFIXES` variable, but only for 2 or 3 octets. If the same endpoint is remounted within this 5-minute period, it will automatically reuse the previous proxy IP address and ignore the `AZNFS_IP_PREFIXES` environment variable if it is set.

## Limitations

- Lazy unmount doesn't work as expected. Lazy unmount allows a share to be unmounted even if it's in use by some application and the way it works is that kernel detaches the mounted filesystem from the file hierarchy and performs other cleanup lazily when the filesystem is not busy anymore. This means applications which have files opened on the filesystem can continue to access the files using the already opened fds but no new fds can be opened. Since aznfswatchdog deletes the DNAT rule as soon as it detects that a mountpoint is no longer present, applications accessing the files using the fds already opened will not work since NFS requests will not make it to the Blob NFS server.
Unmount cleanup can be disabled by setting the env variable `AZNFS_SKIP_UNMOUNT_CLEANUP` to 1 and restarting the
aznfswatchdog service.


## Troubleshoot

- Check the status of aznfswatchdog and aznfswatchdogv4 service using `systemctl status aznfswatchdog*`. If any of the services are not active, start
  it using `systemctl start aznfswatchdog` or `systemctl start aznfswatchdogv4`.
- Enable verbose logs to console by setting `AZNFS_VERBOSE` env variable with `export AZNFS_VERBOSE=1`.
- Provide the IP prefix in the range which is not in use by the machine by setting `AZNFS_IP_PREFIXES` env variable.
- If the problem is with assigning local private IP, set `AZNFS_PING_LOCAL_IP_BEFORE_USE` env variable to 1 using
  `export AZNFS_PING_LOCAL_IP_BEFORE_USE=1`.
- Check https://learn.microsoft.com/en-us/azure/storage/blobs/network-file-system-protocol-support-how-to for more
  information regarding NFSv3 mount.


## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.


## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
