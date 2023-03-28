# AZNFS Mount Helper

> **Mount helper program for correctly handling endpoint IP address changes for Azure Blob NFS mounts.**

Azure Blob NFS is a highly available clustered NFSv3 server for providing NFSv3 access to Azure Blobs. To maintain availability 
in case of infrequent-but-likely events like hardware failures, hardware decommissioning, etc, the endpoint IP of the Azure Blob 
NFS endpoint may change. This change in IP is mostly transparent to applications because the DNS records are updated such that the
Azure Blob NFS FQDN now resolves to this new IP. This works fine for new mounts as they will automatically connect to the new IP,
but this change in IP is not handled by Linux NFS client for already mounted shares, as it only resolves the IP at the time of mount
and any change in the server IP after mount will cause it to indefinitely attempt reconnect to the old IP. Also NFSv3 protocol doesn't 
provide a way for server to convey such change in IP to the clients. This means that this change in IP has to be detected by a userspace
process and conveyed to the kernel through some supported interface. Using a mount helper is a supported way in Linux to do "something 
extra" during a mount, hence this AZNFS mount helper is needed so that Linux NFS clients can reliably access Azure Blob NFS shares even 
when their IP changes.

User has to install AZNFS package and mount the NFSv3 share using `-t aznfs` flag.  This package will run a background job called 
**aznfswatchdog** to detect change in endpoint IP address for the mounted shares. If there will be any change in endpoint IP, 
AZNFS will update the DNAT rules in the client machine to run IOps smoothly for the mounted shares.

This package picks a free private IP which is not in use by user's machine and mount the NFSv3 share using that IP and
create a DNAT rule to route the traffic from the chosen private IP to original endpoint IP.

## Supported Distros

AZNFS is supported on following Linux distros: 

- Ubuntu
- RedHat
- Rocky
- SUSE
- Centos


## Install Instructions

- Run the following command to download and install **AZNFS**:
	```
	wget -O - -q https://github.com/Azure/BlobNFS-mount/releases/latest/download/aznfs_install.sh | sh
	```
 	It will install the aznfs mount helper program and the aznfswatchdog service.


## Usage Instructions

- Mount the Azure Blob NFS share using following command: 
	```
	sudo mount -t aznfs -o vers=3,proto=tcp <account-name>.blob.core.windows.net:/<account-name>/<container-name> /mountpoint
	```
- Logs generated from AZNFS will be in `/opt/microsoft/aznfs/aznfs.log`.

## Implementation Details

This version of **AZNFS** mount helper uses iptables DNAT rules to forward NFS traffic directed to a local IP
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

## Limitations

- Lazy unmount doesn't work as expected. This is because the AZNFS mount helper deletes the DNAT rule as soon as the mount goes away.
- Writing to the same file from different AZNFS mounts may result in reduced performance. Reading the same file from from different AZNFS mounts on the other hand does not have this limitation. 


## TroubleShoot

- Check the status of aznfswatchdog service using `systemctl status aznfswatchdog`. If the service is not active, start
  it using `systemctl start aznfswatchdog`.
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
