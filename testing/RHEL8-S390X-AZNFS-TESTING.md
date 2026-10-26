# AZNFS validation on RHEL 8.10 s390x

This test validates the AlmaLinux 8.10-built AZNFS RPM on a disposable RHEL
8.10 `s390x` system. It covers package validation, encrypted and unencrypted
Azure Files NFS 4.1 mounts, basic I/O, and pinned xfstests smoke and quick
suites.

> **Warning:** xfstests is destructive. Use two dedicated, empty Azure Files
> NFS shares with `NoRootSquash`. Never use shares containing valuable data.

## Required inputs

- A disposable RHEL 8.10 `s390x` host with active BaseOS and AppStream
  repositories.
- `aznfs-0.0.0-1.s390x.rpm`.
- Two different, dedicated Azure Files NFS shares with `NoRootSquash`:
  - one test share;
  - one scratch share.
- Network access to the storage endpoint on TCP 2049.
- A user with passwordless `sudo`, or a root shell.

The supplied RPM has SHA-256:

```text
c9be4eeb1e8c7c4e83e15521a2dfe94ab455d3138a0395707a0f7a85fccff057
```

## Copy the test files

Copy these two files and the RPM to the RHEL system:

- `run-rhel8-s390x-aznfs-tests.sh`
- `aznfs-0.0.0-1.s390x.rpm`

Make the script executable:

```bash
chmod +x run-rhel8-s390x-aznfs-tests.sh
```

## Run basic validation

Use `--basic` to validate the package, services, encrypted mount,
unencrypted mount, and basic I/O without installing, building, or running
xfstests. A scratch share and destructive confirmation are not required:

```bash
./run-rhel8-s390x-aznfs-tests.sh \
  --basic \
  --rpm ./aznfs-0.0.0-1.s390x.rpm \
  --account "<storage-account>" \
  --test-share "<dedicated-test-share>"
```

For the prepared Azure environment:

```bash
./run-rhel8-s390x-aznfs-tests.sh \
  --basic \
  --rpm ./aznfs-0.0.0-1.s390x.rpm \
  --account "sprasadzlinux1a55ef16" \
  --test-share "aznfs-s390x"
```

## Optional: run complete xfstests validation

The complete run adds pinned xfstests smoke and `quick` suites in both TLS
modes. It is destructive and requires a separate, empty scratch share.
Replace the four environment-specific values:

```bash
./run-rhel8-s390x-aznfs-tests.sh \
  --rpm ./aznfs-0.0.0-1.s390x.rpm \
  --account "<storage-account>" \
  --test-share "<dedicated-test-share>" \
  --scratch-share "<dedicated-scratch-share>" \
  --confirm-destructive
```

The complete script run will:

1. Perform all basic validation.
2. Install xfstests build dependencies from RHEL and EPEL repositories.
3. Build xfstests commit
   `22348afe338c0f6d540c0d7ef0db749eaa51b218`.
4. Run smoke and `quick` groups with TLS.
5. Run smoke and `quick` groups with `notls`.
6. Collect logs, package inventory, test results, and `.out.bad` files.

The complete run can take several hours, depending on the available CPU and
memory resources.

## Results

The script prints the result directory and archive path when it finishes.
By default they are:

```text
/var/tmp/aznfs-rhel810-s390x-<UTC timestamp>/
/var/tmp/aznfs-rhel810-s390x-<UTC timestamp>.tar.gz
```

Inspect:

- `xfstests-*-smoke.rc`
- `xfstests-*-quick.rc`
- `xfstests-*-quick.log`
- `xfstests-results-*/**/*.out.bad`
- `aznfs.log`
- `aznfs-watchdog-journal.log`
- `environment.txt`
- `packages.txt`

An xfstests `[not run]` result can be expected when a test requires a local
block device or an unsupported NFS operation. Investigate every failed test
and every `.out.bad` file.

## Options

Display all options:

```bash
./run-rhel8-s390x-aznfs-tests.sh --help
```

Useful overrides include:

```text
--basic
--rpm-sha256 SHA256
--results-root DIR
--xfstests-dir DIR
--io-size-mib N
```

The test runner exits immediately on setup, package, mount, or basic I/O
errors. Individual xfstests return codes are recorded so both TLS modes can be
attempted and compared in one run.
