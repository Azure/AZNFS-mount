# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

- Add Auto-Update feature for AZNFS

## [1.0.10] - 2023-09-12

To fail the mounting of shares if the Blob IP->FQDN entry is present in /etc/hosts file and log warnings if entry is added after aznfswatchdog is started running.

### Added
- [AZNFS-mount](https://github.com/Azure/AZNFS-mount/pull/78)
  Throw Error/Warning if entry is present in /etc/hosts

### Fixed

- [AZNFS-mount](https://github.com/Azure/AZNFS-mount/pull/83)
  Syntax Error
- [AZNFS-mount](https://github.com/Azure/AZNFS-mount/pull/79)
  Bug fix in aznfswatchdog