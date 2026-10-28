# NFSv4 ZRS Failover — Overview & Changes

## Problem Statement

Azure Files ZRS (Zone Redundant Storage) accounts have 3 physical tenants across availability zones, each with its own IP address returned by DNS. For NFSv3, AZNFS already handles failover automatically — when DNS routing changes (e.g., due to a zone failure), the watchdog detects the IP change and transparently updates the DNAT rule so the mount reconnects to a healthy tenant. **For NFSv4, no such failover existed.** If a physical tenant failed, the mount hung indefinitely, wasting the 2 available backup tenants.

## Customer Perspective

From the customer's point of view, **nothing changes in how they mount, and nothing new is required of them.** The failover is fully automatic, zero-configuration, and transparent to the application.

### What the customer experiences

```mermaid
graph TD
    A["Customer mounts ZRS Azure Files share<br/>(same mount command as always)"] --> B[Application does normal file I/O]
    B --> C{Availability-zone<br/>tenant failure?}
    C -->|No — normal operation| B
    C -->|Yes| D["⚡ Brief I/O pause<br/>(seconds, no error surfaced)"]
    D --> E["AZNFS watchdog auto-detects<br/>unreachable tenant"]
    E --> F["Traffic rerouted to a healthy<br/>zone automatically"]
    F --> G["✅ I/O resumes on its own<br/>— no remount, no customer action"]
    G --> B

    style A fill:#d5e8ff,stroke:#333
    style D fill:#ffe0b3,stroke:#333
    style G fill:#c8f7c5,stroke:#333
```

### Before vs after — the customer-visible difference

| Aspect | Before (no NFSv4 failover) | After (this change) |
|--------|----------------------------|---------------------|
| Zone/tenant failure on a ZRS share | Mount **hangs indefinitely**; app I/O stalls until manual remount | Mount **self-heals**; I/O resumes automatically |
| Customer action required | Manual intervention (unmount/remount, possibly reboot) | **None** — fully automatic |
| Mount command / configuration | — | **Unchanged** — no new flags or setup |
| Recovery time | Never (until manual fix) | **~60 seconds** (typical) |
| Applies to | — | NFSv4 **TLS and non-TLS**, public endpoints only |

### What customers should know

- **No opt-in needed.** Failover is handled by the AZNFS watchdog that already runs for every mount. Just keep the AZNFS package up to date.
- **Only affects public-endpoint ZRS accounts.** Private endpoints are intentionally skipped — Azure's networking handles private-endpoint resiliency internally, so AZNFS treats them as a no-op (no behavior change, no risk).
- **Non-ZRS (LRS/GRS) accounts are unaffected.** DNS returns a single IP, so the failover logic simply no-ops.
- **Brief pause, not an error.** During the ~60s detection window the app may see I/O block momentarily; it is not returned an error, and it resumes once traffic is rerouted.

## Before: NFSv3 vs NFSv4

### NFSv3 — Working Failover

```mermaid
graph LR
    A1[Mount Command] --> B1[resolve_ipv4<br/>gets all 3 ZRS IPs]
    B1 --> C1[Allocate proxy IP<br/>+ DNAT rule]
    C1 --> D1[Mount against<br/>proxy IP]
    D1 --> E1[Watchdog monitors<br/>DNS every 60s]
    E1 -->|IP changed| F1[Swap DNAT rule<br/>to new IP]
    F1 --> G1[Mount recovers<br/>transparently ✅]
```

### NFSv4 Non-TLS — No Failover

```mermaid
graph LR
    A2[Mount Command] --> B2[getent hosts<br/>returns 1 IP]
    B2 --> C2[Mount directly<br/>to hostname]
    C2 --> D2[No watchdog<br/>tracking]
    D2 -->|Tenant fails| E2[Mount hangs<br/>forever ❌]
```

### NFSv4 TLS — No Failover

```mermaid
graph LR
    A3[Mount Command] --> B3[getent hosts<br/>returns 1 IP]
    B3 --> C3[Create stunnel<br/>to storage IP]
    C3 --> D3[Mount via<br/>127.0.0.1:stunnel_port]
    D3 --> E3[Watchdog monitors<br/>stunnel health only]
    E3 -->|Tenant fails| F3[Stunnel hangs<br/>mount hangs forever ❌]
```

## After: NFSv4 ZRS Failover

### NFSv4 Non-TLS — Fixed

```mermaid
graph LR
    A1[Mount Command] --> B1["resolve_ipv4(port 2049)<br/>gets all 3 ZRS IPs<br/>picks first reachable"]
    B1 --> C1[Allocate proxy IP<br/>+ DNAT rule]
    C1 --> D1[Mount against<br/>proxy IP]
    D1 --> E1[Write to<br/>MOUNTMAPv4NOTLS]
    E1 --> F1[Watchdog monitors<br/>every 5-60s]

    F1 --> G1{Layer 1: Conntrack<br/>stuck SYN_SENT/UNREPLIED<br/>every 5s passive}
    F1 --> H1{Layer 2: TCP probe<br/>nc -z storage_ip 2049<br/>every 60s}

    G1 -->|stuck >25s| I1[FAILURE DETECTED]
    H1 -->|timeout 3s| I1

    I1 --> J1["resolve_ipv4<br/>exclude dead IP"]
    J1 --> K1[Swap DNAT rule<br/>to new IP]
    K1 --> L1[Update<br/>MOUNTMAPv4NOTLS]
    L1 --> M1["ping_new_endpoint<br/>stat mount"]
    M1 --> N1[Mount recovers ✅]
```

### NFSv4 TLS — Fixed

```mermaid
graph LR
    A2[Mount Command] --> B2["resolve_ipv4(port 2049)<br/>gets all 3 ZRS IPs"]
    B2 --> C2[Create stunnel<br/>to storage IP]
    C2 --> D2[Mount via<br/>127.0.0.1:stunnel_port]
    D2 --> E2["Write to MOUNTMAPv4<br/>now includes hostname"]
    E2 --> F2[Watchdog monitors<br/>stunnel + IP reachability]

    F2 --> G2[Existing: stunnel process<br/>+ checksum check]
    F2 --> H2{NEW: TCP probe<br/>nc -z storage_ip 2049<br/>every 60s}

    H2 -->|timeout 3s| I2[FAILURE DETECTED]
    I2 --> J2["resolve_ipv4<br/>exclude dead IP"]
    J2 --> K2[Create new stunnel conf<br/>with new IP]
    K2 --> L2[Kill old stunnel<br/>+ delete old files]
    L2 --> M2[Start new stunnel<br/>on SAME port]
    M2 --> N2["Update MOUNTMAPv4<br/>new IP paths checksum"]
    N2 --> O2["ping_new_endpoint<br/>force NFS reconnect"]
    O2 --> P2[Mount recovers ✅]
```

## Detection Flow

```mermaid
sequenceDiagram
    participant WD as Watchdog (every 5s)
    participant CT as Conntrack (kernel)
    participant NC as TCP Probe (nc)
    participant DNS as DNS Server
    participant IPT as iptables/stunnel
    participant NFS as NFS Client

    Note over WD: Normal operation - all healthy
    
    rect rgb(255, 200, 200)
        Note over NFS: ⚡ Physical tenant fails
    end

    WD->>CT: Check SYN_SENT/UNREPLIED (port 2049)
    CT-->>WD: Stuck entries found >25s
    Note over WD: OR (every 60s):
    WD->>NC: nc -z storage_ip 2049
    NC-->>WD: Timeout (3s) — unreachable

    rect rgb(200, 255, 200)
        Note over WD: FAILURE DETECTED
    end

    WD->>DNS: resolve_ipv4(hostname, exclude dead IP)
    DNS-->>WD: Returns 3 IPs, skips dead one
    WD->>NC: Test alternative IPs
    NC-->>WD: IP-B reachable

    alt Non-TLS (DNAT swap)
        WD->>IPT: Delete DNAT proxy→dead_IP
        WD->>IPT: Create DNAT proxy→new_IP
        WD->>NFS: stat(mount_point) — force reconnect
    else TLS (Stunnel restart)
        WD->>IPT: Create new stunnel conf with new IP
        WD->>IPT: Kill old stunnel, start new on same port
        WD->>NFS: stat(mount_point) — force reconnect
    end

    Note over NFS: Mount recovers ✅
```

## What Changed — Summary

### Files Modified

| File | Changes |
|------|---------|
| `lib/common.sh` | Added `MOUNTMAPv4NOTLS`, generic mountmap functions, moved IP allocation helpers, parameterized `resolve_ipv4` with `probe_port` and `exclude_ip` |
| `src/nfsv4mountscript.sh` | Non-TLS: proxy IP + DNAT + MOUNTMAPv4NOTLS. TLS: hostname in MOUNTMAPv4, `resolve_ipv4` with port 2049 |
| `src/nfsv3mountscript.sh` | Functions moved to common.sh, `$MOUNTMAP_WRITE_FN` for parameterized writes |
| `src/aznfswatchdogv4` | Conntrack monitoring (port 2049), TCP probe, `process_nfsv4_notls_mounts()`, `failover_stunnel()`, TLS failover detection, `ping_new_endpoint()` |
| `packaging/aznfs/DEBIAN/postrm` | Cleanup for `mountmapv4notls` |
| `packaging/aznfs/RPM/aznfs.spec` | Cleanup for `mountmapv4notls` |

### New Files

| File | Purpose |
|------|---------|
| `/opt/microsoft/aznfs/data/mountmapv4notls` | Tracks non-TLS NFSv4 mounts: `hostname localip storageip` |
| `testing/simulate_zrs_failover.sh` | Test script: blocks storage IP to simulate zone failure |
| `docs/nfsv4-zrs-failover-plan.md` | Detailed implementation plan |

### Key Design Decisions

1. **Non-TLS uses DNAT** (same as NFSv3) — proxy IP allocated, iptables redirects traffic, watchdog swaps DNAT on failure
2. **TLS uses stunnel restart** — new conf/log/pid files created with new IP, stunnel restarted on same port, NFS client reconnects transparently
3. **Failure-based trigger** (not DNS-change-based) — NFSv4 is stateful, swapping on every DNS rotation would break connections. Only swap when current IP is confirmed unreachable.
4. **Private endpoints excluded** — `is_private_ip()` gate ensures failover only runs for public endpoints (Azure networking handles private endpoint failover internally)
5. **Separate mountmap file** (`mountmapv4notls`) for non-TLS — avoids mixing with TLS semicolon-delimited entries in `mountmapv4`

## Timing, Detection vs. Recovery, and Pacemaker Guidance

**Important distinction:** the `60s` figure is the *detection cadence*, **not** the total client-visible failover time. Plan HA timeouts against the worst-case end-to-end recovery, not the probe interval.

### Two-layer detection

| Layer | Mechanism | Cadence | Tunable |
|-------|-----------|---------|---------|
| L1 — Conntrack (passive) | Kernel `conntrack` scan for stuck `SYN_SENT`/`UNREPLIED` entries to port 2049 | every **5s** (`MONITOR_INTERVAL_SECS`) | not currently exposed |
| L2 — Active TCP probe | `nc -w 3 -z <storage_ip> 2049` (single SYN, 3s timeout) | every **60s** (`HEALTH_CHECK_FREQUENCY`) | **`AZNFS_HEALTH_CHECK_FREQUENCY`** |

L1 depends on kernel conntrack/TCP retransmit timing (only fires once an entry is actually stuck). L2 is independent of the mount's TCP stack.

### End-to-end client-visible failover budget

```
total ≈ detection latency  +  recovery actions  +  NFS client reconnect
```

| Phase | Typical cost |
|-------|--------------|
| Detection latency (L2) | **0–60s** (depends where in the probe cycle the failure lands) + up to 3s probe timeout |
| Detection latency (L1, stuck-SYN case) | ~5s cycles, but gated by kernel conntrack/TCP retransmit timing |
| Recovery — non-TLS | DNAT swap, **sub-second** |
| Recovery — TLS | stunnel kill + restart, **~1–3s** |
| NFS client reconnect | TCP re-handshake + NFS retransmit, governed by mount `timeo`/`retrans` |

**Worst case can exceed 60s** (≈ up to 60s detection + a few seconds recovery + client reconnect).

### Pacemaker / clustered-HA guidance

Azure's published Pacemaker guidance often uses a **60s** monitor/timeout for the storage resource. Because *detection alone* can take up to ~60s here, a failure landing early in the probe window plus recovery can overrun a 60s monitor and trigger an unnecessary fence/failover. Recommended options:

1. **Raise the Pacemaker resource monitor timeout** to cover worst case — e.g. `timeout ≥ 120s` (safest, no AZNFS change needed).
2. **Shorten AZNFS detection** by lowering the probe cadence. Create `/opt/microsoft/aznfs/data/config` with, for example:
   ```
   AZNFS_HEALTH_CHECK_FREQUENCY=15
   ```
   then `systemctl restart aznfswatchdogv4`. This reduces worst-case detection from ~60s to ~15s. (The watchdog unit reads this file via an optional `EnvironmentFile`; the default remains 60s if the file is absent.)
3. **Combine both** — a lower probe cadence *and* a monitor timeout with headroom.

> Trade-off: a lower `AZNFS_HEALTH_CHECK_FREQUENCY` means more frequent `nc` probes per mount. The cost is one lightweight SYN per mount per interval; keep it in the 10–20s range rather than very low single-digit values.

## Testing Method

### Simulation Approach
Since we cannot trigger an actual Azure zone failover on demand, we simulate it by blocking traffic to the current storage IP using iptables DROP rules. This makes the storage IP completely unreachable (silent packet loss), which is identical to what happens when a physical tenant fails.

### Test Steps

1. **Mount** the ZRS storage account (verify 3 DNS IPs, proxy IP/stunnel setup, mountmap entry)
2. **Start I/O loop** (`ls` every 2 seconds) to see the interruption in real time
3. **Block the storage IP**: `iptables -I OUTPUT -p tcp -d <storage_ip> --dport 2049 -j DROP`
4. **Observe** the watchdog logs for failure detection and failover
5. **Verify** mountmap updated with new IP, DNAT/stunnel updated, I/O loop resumes
6. **Unblock** the old IP

### Results

| Scenario | Detection Time | Recovery |
|----------|---------------|----------|
| Non-TLS failover | ~60s (TCP probe) | DNAT swapped, mount recovered, I/O resumed |
| TLS failover | ~60s (TCP probe) | Stunnel restarted with new IP, new files created, mount recovered |

### What the Logs Show

```
Storage IP 52.239.239.8 is unreachable on port 2049 for daniewozrs5.file.core.windows.net
Failure detected for daniewozrs5.file.core.windows.net [... -> 52.239.239.8], attempting failover...
IP for daniewozrs5.file.core.windows.net changed [52.239.239.8 -> 52.239.239.40], updating DNAT.
Failover complete for daniewozrs5.file.core.windows.net [52.239.239.8 -> 52.239.239.40]
```
