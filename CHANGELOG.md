## [2.0.0]- 2023-12-08

### Added
- [AZNFS-mount #89](https://github.com/Azure/AZNFS-mount/pull/89)
  Adding the resiliency and addressing hung issue for Regional Accounts with AZNFS-mount.
- [AZNFS-mount #84](https://github.com/Azure/AZNFS-mount/pull/84)
  Introducing Auto-Update feature for AZNFS.
- [AZNFS-mount #92](https://github.com/Azure/AZNFS-mount/pull/92)
  Adding Dialog Box for user consent for Auto-update feature of AZNFS-mount.

## [1.0.10]- 2023-09-12
### Added
- [AZNFS-mount #78](https://github.com/Azure/AZNFS-mount/pull/78)
  Prevent mounting of shares when the Blob IP->FQDN entry is present in /etc/hosts.

### Fixed
- [AZNFS-mount #83](https://github.com/Azure/AZNFS-mount/pull/83)
  Corrected syntax error in the code
- [AZNFS-mount #79](https://github.com/Azure/AZNFS-mount/pull/79)
  Resolved a bug in aznfswatchdog introduced in an older version of bash.

## [1.0.8] - 2023-08-16
### Added
- [AZNFS-mount #77](https://github.com/Azure/AZNFS-mount/pull/77)
  Added support for packaging a tarball for the arm64 architecture, specifically for the AKS CSI driver.

## [1.0.7] - 2023-08-08
### Added
- [AZNFS-mount #76](https://github.com/Azure/AZNFS-mount/pull/76)
  Introduced support for AZNFS when used with the AKS CSI driver.
