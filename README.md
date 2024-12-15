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

- Ubuntu (18.04 LTS, 20.04 LTS, 22.04 LTS)
- Centos7, Centos8
- RedHat7, RedHat8, RedHat9
- Rocky8, Rocky9
- SUSE (SLES 15)


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
   For isolated environments, ensure that the environment variable "AZURE_ENDPOINT_OVERRIDE" is set to the appropriate endpoint before running the mount command:
	```
	export AZURE_ENDPOINT_OVERRIDE="example.end.point"
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
- Logs generated from AZNFS watchdog and mount helper will be in `/opt/microsoft/aznfs/data/aznfs.log`.
- Logs generated by Stunnel will be in `/etc/stunnel/microsoft/aznfs/nfsv4_fileShare/logs`.

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
> After an Azure Blob NFS endpoint is unmounted, the local proxy IP-to-endpoint mapping remains cached in the mountmap for 5 minutes. If the same endpoint is remounted within this period, it will automatically reuse the previous proxy IP address. During this period, it will ignore `AZNFS_IP_PREFIXES` environment variable if it is set.


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
