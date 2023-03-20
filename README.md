# AZNFS Mount Helper

> Mount helper program for correctly handling endpoint IP address changes for Azure Blob NFS mounts.

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

User has to install AZNFS package and mount the NFSv3 share using `-t aznfs` flag. This package will run a background job called 
**aznfswatchdog** to detect change in endpoint IP address for the mounted shares. If there will be any change in endpoint IP, 
AZNFS will update the DNAT rules in the client machine to run IOps smoothly for the mounted shares.

This package picks a free private IP which is not in use by user's machine and mount the NFSv3 share using that IP and
create a DNAT rule to route the traffic from the chosen private IP to original endpoint IP.

## Supported Distros

AZNFS is supported on linux based distros which are listed below: 

- Ubuntu
- RedHat
- Rocky
- SUSE
- Centos


## Install Instructions

- Download the latest **aznfs_install.sh** from https://github.com/Azure/BlobNFS-mount/releases/latest.
- Make **aznfs_install.sh** execuatable and run it in linux machine. This will install AZNFS package by correctly
  identifying the distro.
	```
	wget https://github.com/Azure/BlobNFS-mount/releases/download/<RELEASE_NUMBER>/aznfs_install.sh
	chmod +x ./aznfs_install.sh
	./aznfs_install.sh
	```


## Usage Instructions

- After installing the AZNFS package, user can mount the NFSv3 share using below command: 
	```
	sudo mount -t aznfs -o vers=3,proto=tcp <account-name>.blob.core.windows.net:/<account-name>/<container-name> /mountpoint
	```
- User can mount the same _/account/continer_ to multiple mountpoints which will create multiple connections from the 
  same machine. This improves the performance since user has multiple connecitons to run IOps.
- User can set `AZNFS_IP_PREFIXES` env variable to set IP prefix in range which is not in use by the machine. User can 
  set IP prefix with either 2 or 3 octets. `f.e. 10.100 10.100.100 172.16 172.16.100 192.168 192.168.100`
  ```
  export AZNFS_IP_PREFIXES="172.16.105"
  ```
- Logs generated from AZNFS will be in `/opt/microsoft/aznfs/aznfs.log`.


## Limitations

- Lazy unmount doesn't work as expected.
- Do not try to access/edit same file from multiple connection. This will not increase the overall throughput.


## TroubleShoot

- Check the status of aznfswatchdog service using `systemctl status aznfswatchdog`. If the service is not active, start
  it using `systemctl start aznfswatchdog`.
- Enable verbose logs to console by setting `AZNFS_VERBOSE` env variable with `export AZNFS_VERBOSE=0`.
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
