# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased](https://github.com/Azure/AZNFS-mount/pull/84)

- Introducing Auto-Update feature for AZNFS

## [1.0.10]- 2023-09-12

Enhanced mounting of shares by introducing a mechanism to prevent mounting when the Blob IP-to-FQDN entry is detected in the /etc/hosts file. This modification aims to ensure that IP change detection remains effective. Additionally, the system now logs warnings when such an entry is added after aznfswatchdog has been initiated, allowing for proactive monitoring and issue resolution.

### Added
- [AZNFS-mount #78](https://github.com/Azure/AZNFS-mount/pull/78)
  Prevent mounting of shares when the Blob IP->FQDN entry is present in /etc/hosts

### Fixed
- [AZNFS-mount #83](https://github.com/Azure/AZNFS-mount/pull/83)
  Corrected syntax error in the code
- [AZNFS-mount #79](https://github.com/Azure/AZNFS-mount/pull/79)
  Resolved a bug in aznfswatchdog introduced in an older version of bash