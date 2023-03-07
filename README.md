# AZNFS Mount Helper

> Mount helper program for correctly handling endpoint IP address changes for Azure Blob NFS mounts. 

## Install Instructions

- Download the aznfs_install.sh from https://github.com/Azure/BlobNFS-mount/releases/latest.
- Run aznfs_install.sh in your linux machine. This will install aznfs package by correctly identifying the distro.

## Usage Instructions

- Once the package is installed use below command to mount your nfs share: 
	sudo mount -t aznfs -o vers=3,proto=tcp account.blob.core.windows.net:/account/container /mountpoint
- With this, you can have multiple connection for the same share with NFSv3 for increased throughput.
- Do not try to access the same file from multiple connection. 
- Logs generated from this package are in /opt/microsoft/aznfs/aznfs.log

## Limitations

- Lazy unmount doesn't work as expected.

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
