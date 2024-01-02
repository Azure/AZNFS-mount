## [2.0.3]- December 2023
- [AZNFS-mount #98](https://github.com/Azure/AZNFS-mount/pull/98)
  (NFSv3) Fixed a bug when reconciling conntrack entries with multiple mounts to different accounts.
  (NFSv3) Fixed a bug to accurately fetch the mountpoint in case of multiple mounts to different containers on the same account.
  (NFSv3) Now we consult the mountmap for resolving regional account FQDN before we do the host lookup to ensure that multiple container mounts resolve to same the IP.

## [2.0.2]- December 2023
- [AZNFS-mount #97](https://github.com/Azure/AZNFS-mount/pull/97)
  (NFSv3) Avoid user interaction completely in case of non-interactive setup. [Issue #96](https://github.com/Azure/AZNFS-mount/issues/96)

## [2.0.1]- December 2023
- [AZNFS-mount #94](https://github.com/Azure/AZNFS-mount/pull/94)
  (NFSv3) Adding support for non-interactive installation for the package.
- [AZNFS-mount #93](https://github.com/Azure/AZNFS-mount/pull/93)
  (NFSv3) aznfswatchdog now logs version number on startup.

## [2.0.0]- December 2023
- [AZNFS-mount #89](https://github.com/Azure/AZNFS-mount/pull/89)
  (NFSv3) Adding the resiliency and addressing hang issue for Regional Accounts with AZNFS-mount.
- [AZNFS-mount #84](https://github.com/Azure/AZNFS-mount/pull/84)
  (NFSv3) Introducing Auto-Update feature for AZNFS.

## [1.0.10]- September 2023
- [AZNFS-mount #79](https://github.com/Azure/AZNFS-mount/pull/79)
  (NFSv3) Resolved a bug in aznfswatchdog introduced in an older version of bash.
- [AZNFS-mount #78](https://github.com/Azure/AZNFS-mount/pull/78)
  (NFSv3) Prevent mounting of shares when the Blob IP->FQDN entry is present in /etc/hosts.

## [1.0.8] - August 2023
- [AZNFS-mount #77](https://github.com/Azure/AZNFS-mount/pull/77)
  (NFSv3) Added support for packaging a tarball for the arm64 architecture, specifically for the AKS CSI driver.

## [1.0.7] - August 2023
- [AZNFS-mount #76](https://github.com/Azure/AZNFS-mount/pull/76)
  (NFSv3) Introduced support for AZNFS when used with the AKS CSI driver, packaging a tarball for amd64 architecture.