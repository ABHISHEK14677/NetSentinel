# NetSentinel: Advanced Active Threat Protection & Automated Response Engine
### Complete Architecture, Working Principles, Technical Implementation & Operational Guide

---

## 1. Executive Summary & Project Overview

**NetSentinel** is an intelligent, capability-aware Network Intrusion Detection and Prevention System (NIDS/NIPS). Traditional network monitoring systems operate passively—they log malicious packets or trigger notification fatigue while attacks execute unimpeded. Conversely, naive automated response engines frequently lock out legitimate users, block DNS or critical gateways on false positives, or destabilize network routing.

NetSentinel bridges this divide by delivering a **policy-controlled, multi-layered threat protection engine** that:
1. **Detects & Correlates** complex attack patterns across network streams, host events, and threat intelligence.
2. **Evaluates Risk** using an objective 0–100 mathematical scoring model calibrated against event frequency, confidence, and freshness.
3. **Selects Calibrated Protective Actions** (scoped IP blocking, rate-limiting, DNS sinkholing, device quarantine).
4. **Verifies Kernel State** post-execution to guarantee that firewall policies actually took effect.
5. **Enforces Mandatory Expiration & Rollback** on all temporary blocks to prevent stale firewall rules.
6. **Maintains a Tamper-Evident Audit Trail** cryptographically chained using SHA-256 hashes.
7. **Supports Multi-Platform Deployments**: ESP32 auxiliary hardware, Raspberry Pi (passive monitor or security gateway), Kali Linux / Debian PC hosts, and Android endpoints via ADB.

---

## 2. System Architecture & Platform Adapters

NetSentinel employs a unified core response engine with specialized platform adapters:

```
                                  +---------------------------------------+
                                  |         NetSentinel Web UI            |
                                  |   (Port 8000: FastAPI + Vanilla JS)   |
                                  +---------------------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |         FastAPI REST API Layer        |
                                  |  (Modes, Approvals, Emergency Stop)   |
                                  +---------------------------------------+
                                                      |
                         +----------------------------+----------------------------+
                         |                                                         |
                         v                                                         v
         +-------------------------------+                         +-------------------------------+
         |     Threat Detection Engine   |                         |     Response Policy Engine    |
         |  - Multi-Indicator Correlator |                         |  - 4 Protection Modes (A-D)   |
         |  - 0-100 Risk Scorer          |                         |  - Infrastructure Safeguards  |
         |  - Threat Intel Validator     |                         |  - Idempotent Action Registry |
         |  - Monitored Device Inventory |                         |  - 11-Step Protection Manager |
         +-------------------------------+                         +-------------------------------+
                         |                                                         |
                         +----------------------------+----------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |      Platform Response Adapters       |
                                  +---------------------------------------+
                                    |          |             |          |
         +--------------------------+          |             |          +--------------------------+
         |                                     |             |                                     |
         v                                     v             v                                     v
+------------------+         +-------------------+  +------------------+         +-------------------+
|   PC Host (Kali) |         |  Raspberry Pi GW  |  |  ESP32 Auxiliary |         |    Android ADB    |
| - Scoped Host FW |         | - Forward Transit |  | - HMAC Authent.  |         | - Device Telemetry|
| - Outbound Alert |         | - Bridge Drops    |  | - RGB/Buzzer LED |         | - Endpoint Tests  |
| - Dashboard Auth |         | - Recovery Wizard |  | - Tamper Sensor  |         | - Block Probing   |
+------------------+         +-------------------+  +------------------+         +-------------------+
```

### 2.1. ESP32 Auxiliary Security Controller (`platforms/esp32/`)
- Acts as a physical security indicator and hardware sentinel—*does not independently claim firewall blocking*.
- **Cryptographic Authentication**: Every message between the Linux node and the ESP32 is signed using **HMAC-SHA256** to prevent spoofing.
- **Physical Alert Patterns**:
  - *Critical*: Fast flashing red LED (5Hz) + continuous 2800Hz high-pitch siren.
  - *High*: Solid red LED + pulsed 2000Hz alarm tone.
  - *Medium*: Solid yellow LED + double chirp tone (1200Hz).
  - *Low*: Blue pulse + single low beep (800Hz).
  - *Informational*: Solid green LED (normal status).
- **Enclosure Tamper Sensor**: Hardware interrupt on GPIO pin triggers instant alerts if physical casing is opened.
- **Fail-Safe Offline Alarm**: Flashes amber warning if heartbeat from Linux host ceases.

### 2.2. Raspberry Pi Deployment Profiles (`platforms/raspberry_pi/`)
- **Profile 1: Passive Monitoring Node**: Runs packet capture, Suricata, threat correlation, and web dashboard without modifying external router configuration.
- **Profile 2: Authorized Security Gateway**: Operates on bridged/dual-NIC interfaces (`eth0` WAN <-> `eth1` LAN), dropping forwarding traffic via `nftables` forward chains while preserving SSH (Port 22), DNS (Port 53), and DHCP (Ports 67/68). Includes automated recovery procedures.

### 2.3. Kali Linux / Debian PC Workstation (`platforms/pc_host/`)
- Protects local workstation stack using dedicated `inet netsentinel` table.
- Enforces honest communication: host firewall protects the host itself; subnet-wide quarantine requires inline gateway or switch integration.

### 2.4. Android ADB Endpoint Testing Subsystem (`platforms/android_adb/`)
- Connects to Android devices via USB or Wireless ADB (`adb connect <IP>:5555`).
- Extracts hardware identity (IP on `wlan0`, MAC address, model, Android version).
- Automatically registers device in Monitored Device Inventory.
- Launches controlled attack traffic from the phone shell to test detection, blocking, and rollback.

---

## 3. Threat Detection & Correlation (Section 14.2)

NetSentinel classifies network anomalies into 11 distinct categories:
1. `PORT_SCAN`: SYN/Connect sweeps, horizontal and vertical port reconnaissance.
2. `BRUTE_FORCE`: Repeated failed authentications on SSH, FTP, or web logins.
3. `DOS_RATE_ANOMALY`: Connection velocity spikes and SYN flood indicators.
4. `SUSPICIOUS_DNS`: Queries to newly registered or suspicious domain names.
5. `MALWARE_C2`: Verified connections to malware botnet command-and-control servers.
6. `UNEXPECTED_OUTBOUND`: Unauthorized outbound connections from local servers.
7. `DATA_EXFILTRATION`: Unusual outbound data transfer volumes.
8. `UNAUTHORIZED_DEVICE`: Unknown MAC or IP discovery on the monitored subnet.
9. `THREAT_INTEL_MATCH`: Connections to IPs/domains flagged in active threat intelligence feeds.
10. `AI_ANOMALY`: Outlier connection patterns identified by machine learning models.
11. `REPEATED_IDS_ALERT`: Repeated alerts matching identical source/destination pairs.

### Multi-Indicator Correlation Rule
Isolated unusual events (such as a single port probe) **never trigger aggressive blocking**. NetSentinel aggregates indicators over a 300-second sliding correlation window. High-impact blocking requires multi-indicator confirmation (e.g. port scan followed by authentication failure) or high-frequency repetition.

---

## 4. Threat Risk Scoring Mathematical Model (Section 14.3)

NetSentinel evaluates risk through a normalized 0–100 scoring model:

$$\text{RawScore} = (W_{\text{ids}} \times S_{\text{ids}}) + (W_{\text{freq}} \times F) + (W_{\text{intel}} \times S_{\text{intel}}) + (W_{\text{ai}} \times S_{\text{ai}})$$

$$\text{FinalScore} = \min(100.0, \max(0.0, \text{RawScore} \times C \times D_{\text{freshness}}))$$

Where:
- $W_{\text{ids}} = 0.35$ (IDS signature severity weight)
- $W_{\text{freq}} = 0.20$ (Event frequency & velocity factor)
- $W_{\text{intel}} = 0.25$ (Verified threat intelligence reputation)
- $W_{\text{ai}} = 0.20$ (AI anomaly model score)
- $C$ = Confidence multiplier (0.0 to 1.0)
- $D_{\text{freshness}}$ = Freshness decay factor (decays evidence older than 15 minutes)

### Severity Bands:
- `0–19`: **Informational** &rarr; Logged for visibility.
- `20–39`: **Low** &rarr; Observed and monitored.
- `40–59`: **Medium** &rarr; Rate-limited or placed under observation policy.
- `60–79`: **High** &rarr; Temporary firewall block or operator approval requested.
- `80–100`: **Critical** &rarr; Immediate boundary block or high-impact quarantine.

> **AI Anomaly Safeguard**: If an event is driven solely by an AI anomaly score without corroborating IDS signatures or verified threat intelligence, the score is capped at **65.0 (Medium-High)** and **cannot authorize critical autonomous blocking**.

---

## 5. The Four Selectable Protection Levels (Section 14.5)

| Level | Name | Automated Changes | Approval Required | Expiry Mandatory | Description |
| :---: | :--- | :---: | :---: | :---: | :--- |
| **Mode A** | **Monitor Only** | **NO** | N/A | N/A | Observes traffic, classifies threats, and logs alerts. **Never modifies firewall rules.** |
| **Mode B** | **Assisted Protection** | Only after approval | **YES** | Yes | Generates proposed rule, scope, and impact preview. Waits for operator sign-off. |
| **Mode C** | **Auto Temporary** | **YES** | For critical single-indicators | **YES** | Automatically applies temporary blocks with **mandatory expiry** (default 300s). Excludes allowlisted assets. |
| **Mode D** | **Strict Prevention** | **YES** | Pre-authorized boundaries | Configurable | Strict boundary firewall enforcement on designated transit interfaces. |

---

## 6. Response Architecture & Modules (Section 14.4)

The protection subsystem is located in `response/`:

- [`response_engine.py`](file:///home/kali/NetSentinel/response/response_engine.py): Orchestrates the 11-step lifecycle from evidence intake to verified blocking.
- [`response_policy.py`](file:///home/kali/NetSentinel/response/response_policy.py): Evaluates protection modes (A–D), threat thresholds, and protected asset safeguards.
- [`action_registry.py`](file:///home/kali/NetSentinel/response/action_registry.py): Idempotent registry preventing redundant firewall updates for already-blocked targets.
- [`linux_firewall.py`](file:///home/kali/NetSentinel/response/linux_firewall.py): Manages dedicated `inet netsentinel` nftables tables, timed sets (`flags timeout`), and dry-run execution.
- [`gateway_blocker.py`](file:///home/kali/NetSentinel/response/gateway_blocker.py): Gateway forward-chain packet filtering for transit traffic.
- [`dns_protection.py`](file:///home/kali/NetSentinel/response/dns_protection.py): Sinkholes malicious C2 and phishing domains to `0.0.0.0`.
- [`device_quarantine.py`](file:///home/kali/NetSentinel/response/device_quarantine.py): End-station containment with network topology awareness.
- [`connection_limiter.py`](file:///home/kali/NetSentinel/response/connection_limiter.py): Per-source connection rate throttling (`meter ratelimit`).
- [`notification_service.py`](file:///home/kali/NetSentinel/response/notification_service.py): Dispatches real-time alerts to the dashboard, syslog, and ESP32.
- [`rollback_manager.py`](file:///home/kali/NetSentinel/response/rollback_manager.py): Background expiration worker, manual unblocking, and instant **Emergency Stop**.
- [`audit_logger.py`](file:///home/kali/NetSentinel/response/audit_logger.py): Cryptographic SHA-256 hash-chained tamper-evident audit trail.
- [`approval_manager.py`](file:///home/kali/NetSentinel/response/approval_manager.py): Interactive human-in-the-loop approval workflow for Mode B.
- [`response_verifier.py`](file:///home/kali/NetSentinel/response/response_verifier.py): Post-enforcement kernel state verification with honest degradation reporting.

---

## 7. The 11-Step Protection Lifecycle (Section 14.11)

Every event processed by NetSentinel undergoes this mandatory sequence:

```
  [1] Validate Evidence & Check Idempotency Cache
                     |
  [2] Evaluate Response Policy (Thresholds & Mode A-D)
                     |
  [3] Check Protected Infrastructure (Gateway, DNS, Loopback, SSH)
                     |
  [4] Confirm Mode Authorization (Autonomous vs Approval Required)
                     |
  [5] Preview Rule & Request Operator Sign-off (Mode B)
                     |
  [6] Apply Action via Linux nftables / DNS / Quarantine Adapter
                     |
  [7] Query Kernel State to Verify Rule Presence
                     |
  [8] Record Outcome Honestly (Flag DEGRADED if Verification Fails)
                     |
  [9] Monitor Effects & Dropped Packet Counters
                     |
 [10] Background Expiration Worker Automatically Rolls Back Timed Rule
                     |
 [11] Notify Operator via Dashboard & ESP32 Auxiliary LED/Buzzer
```

---

## 8. Tamper-Evident Audit Trail (Section 14.13)

NetSentinel stores all security decisions, policy shifts, rule insertions, and rollbacks in a cryptographically linked SQLite table using SHA-256 hash chaining:

$$\text{Hash}_n = \text{SHA256}(\text{Hash}_{n-1} \parallel \text{Timestamp} \parallel \text{Operator} \parallel \text{EventType} \parallel \text{Details} \parallel \text{SecretKey})$$

Any modification, deletion, or out-of-order insertion immediately invalidates the hash chain:
```bash
curl http://127.0.0.1:8000/api/audit/verify
```
*Returns:*
```json
{
  "valid": true,
  "entries_checked": 24,
  "latest_hash": "6f16fff45351b069124c0ec5cf77487ee67b9144602f5010702ab4e9a2a6b781",
  "message": "Audit chain verified. Cryptographic integrity confirmed."
}
```

---

## 9. Monitored Device Inventory (Section 14.7)

Tracks internal network endpoints across their complete security lifecycle:
- **Attributes**: IP address, MAC address, hostname, interface, first/last seen, observed protocols, risk score, alert count, current enforcement state.
- **States**: `Trusted` &harr; `Unknown` &harr; `Under observation` &harr; `Suspicious` &harr; `Restricted` &harr; `Quarantined` &harr; `Released`.
- **Safe Discovery Default**: An unknown device appearing on the LAN triggers an **observation policy by default—never immediate disconnection**.

---

## 10. Complete Usage Guide

### 10.1. Launching NetSentinel
Run the startup script:
```bash
/home/kali/NetSentinel/scripts/start_netsentinel.sh
```
*NetSentinel initializes the SQLite schema, seeds essential allowlisted assets, configures `inet netsentinel` nftables tables, and launches on `http://0.0.0.0:8000`.*

### 10.2. Accessing the Active Protection Web Dashboard
Open your browser to:
👉 **`http://127.0.0.1:8000`**

- **Mode Indicator & Switcher**: View and select operating modes (Mode A, B, C, D).
- **Dry-Run Toggle**: Switch between safe simulated rule generation and live enforcement.
- **Emergency Stop**: Instantly flush all active blocks and halt automated actions with one click.
- **Live Block Countdowns**: View active firewall blocks with live second-by-second countdowns and manual **Unblock** buttons.
- **Pending Approvals**: In Mode B, review proposed actions with full impact analysis and approve/reject with one click.
- **Device Inventory**: View all tracked LAN devices and assign trust status.
- **Allowlist Manager**: Add protected servers, management stations, or subnets.

### 10.3. Generating Simulated Threat Traffic
Test NetSentinel's response using the CLI simulator:
```bash
python3 /home/kali/NetSentinel/scripts/simulate_traffic.py
```
Select a scenario:
- `1`: Port Scan (Nmap SYN reconnaissance) &rarr; Triggers Rate-Limiting.
- `2`: SSH Brute Force &rarr; Triggers Temporary Firewall Block.
- `3`: Malware C2 Domain &rarr; Triggers DNS Sinkholing.
- `4`: Unauthorized Device Discovery &rarr; Triggers Observation Policy.
- `5`: AI Anomaly Alone &rarr; Verifies score cap and absence of critical blocks.
- `6`: Allowlisted Gateway Traffic &rarr; Verifies infrastructure safeguard protection.

### 10.4. Testing with an Android Device via ADB
1. **Connect phone via Wi-Fi**:
   ```bash
   adb connect <PHONE_IP>:5555
   ```
2. **Run Interactive Tester**:
   ```bash
   python3 /home/kali/NetSentinel/scripts/adb_device_tester.py
   ```
   - Automatically detects phone model, Android OS version, Wi-Fi IP, and MAC.
   - Registers phone into Device Inventory.
   - Launches simulated attacks from the phone shell.
   - Verifies that NetSentinel blocks the phone in kernel state.
   - Probes from the phone to prove traffic was dropped.
   - Safely rolls back the rule and restores phone connectivity.

### 10.5. Emergency Recovery Procedure
If administrative connectivity is lost or a misconfiguration occurs, execute the offline recovery script:
```bash
/home/kali/NetSentinel/scripts/emergency_recover.sh
```
*Safely flushes the dedicated `inet netsentinel` table without touching system firewall rules and resets database block entries.*

---

## 11. REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/status` | Returns mode, dry-run state, active blocks, and counts |
| `POST` | `/api/protection-mode` | Changes protection mode (`MONITOR_ONLY`, `ASSISTED_PROTECTION`, `AUTOMATIC_TEMPORARY`, `STRICT_PREVENTION`) |
| `POST` | `/api/dry-run/toggle` | Toggles dry-run mode on/off |
| `POST` | `/api/emergency-stop` | Revokes all active blocks and halts automated enforcement |
| `POST` | `/api/emergency-stop/clear`| Clears emergency stop and resumes normal operation |
| `POST` | `/api/threats/ingest` | Ingests security event through complete 11-step engine |
| `GET` | `/api/approvals` | Lists pending approval requests for Mode B |
| `POST` | `/api/approvals/{uuid}/decide`| Approves or rejects a pending action |
| `GET` | `/api/blocked-targets` | Lists active and historical blocked targets with countdowns |
| `POST` | `/api/blocked-targets/{target}/unblock` | Manually releases an active block immediately |
| `GET` | `/api/devices` | Lists monitored device inventory |
| `POST` | `/api/devices/{id}/trust-status` | Updates device trust status (`Trusted`, `Suspicious`, etc.) |
| `GET` | `/api/allowlist` | Lists protected infrastructure allowlist |
| `POST` | `/api/allowlist` | Adds an IP, subnet, or MAC to the allowlist |
| `GET` | `/api/audit/verify` | Verifies SHA-256 hash chaining of the audit trail |
| `GET` | `/api/esp32/status` | Reports ESP32 connection health and tamper switch state |

---

## 12. Verification & Automated Test Suite (Section 14.15)

NetSentinel includes an automated test suite verifying all 15 acceptance criteria from Section 14.15, plus 5 dedicated Android ADB integration tests (20 tests total):

```bash
pytest -v /home/kali/NetSentinel/tests/test_protection_engine.py /home/kali/NetSentinel/tests/test_adb_device.py
```

### Test Suite Execution Output:
```text
tests/test_protection_engine.py::test_1_suspicious_event_generates_alert PASSED               [  5%]
tests/test_protection_engine.py::test_2_repeated_events_are_correlated_and_deduplicated PASSED [ 10%]
tests/test_protection_engine.py::test_3_monitor_only_mode_never_modifies_firewall PASSED     [ 15%]
tests/test_protection_engine.py::test_4_assisted_mode_requires_approval PASSED               [ 20%]
tests/test_protection_engine.py::test_5_automatic_protection_follows_configured_policies PASSED [ 25%]
tests/test_protection_engine.py::test_6_allowlisted_devices_are_not_blocked PASSED           [ 30%]
tests/test_protection_engine.py::test_7_temporary_rules_expire_correctly PASSED              [ 35%]
tests/test_protection_engine.py::test_8_invalid_or_stale_threat_intel_does_not_trigger_blocking PASSED [ 40%]
tests/test_protection_engine.py::test_9_dry_run_mode_performs_no_enforcement PASSED         [ 45%]
tests/test_protection_engine.py::test_10_firewall_failures_are_reported_honestly PASSED       [ 50%]
tests/test_protection_engine.py::test_11_esp32_disconnection_does_not_stop_monitoring PASSED [ 55%]
tests/test_protection_engine.py::test_12_gateway_mode_failure_triggers_recovery PASSED       [ 60%]
tests/test_protection_engine.py::test_13_emergency_stop_prevents_new_automated_actions PASSED [ 65%]
tests/test_protection_engine.py::test_14_rollback_restores_expected_previous_state PASSED   [ 70%]
tests/test_protection_engine.py::test_15_failed_enforcement_never_reported_as_successful PASSED [ 75%]
tests/test_adb_device.py::test_adb_device_discovery PASSED                                  [ 80%]
tests/test_adb_device.py::test_adb_device_identity_extraction PASSED                        [ 85%]
tests/test_adb_device.py::test_adb_device_inventory_registration PASSED                     [ 90%]
tests/test_adb_device.py::test_adb_device_brute_force_attack_and_block PASSED                [ 95%]
tests/test_adb_device.py::test_adb_device_port_scan_detection PASSED                        [100%]

======================== 20 passed in 4.72s ========================
```

---

## 13. File & Repository Structure

```
NetSentinel/
├── DESCRIPTION.md                 # Complete Architecture, Working & Usage Reference
├── README.md                      # Quick Reference & Getting Started Guide
├── .gitignore                     # Repository ignore file
├── main.py                        # Application entrypoint & background expiration worker
├── config/
│   └── config.py                  # Section 14.14 safe default settings & thresholds
├── database/
│   ├── models.py                  # Section 14.13 SQLAlchemy database models
│   └── db_service.py              # Database initialization & session management
├── threat_engine/
│   ├── detector.py                # Section 14.2 detection categories
│   ├── correlator.py              # Multi-indicator correlation engine
│   ├── risk_scorer.py             # Section 14.3 risk scoring formula & severity bands
│   ├── threat_intel.py            # Reputation validator with freshness TTL
│   └── device_inventory.py        # Section 14.7 monitored device lifecycle
├── response/
│   ├── response_engine.py         # Section 14.11 11-step response coordinator
│   ├── response_policy.py         # Section 14.5 Protection Mode evaluator (A–D)
│   ├── action_registry.py         # Section 14.4 idempotent action system
│   ├── linux_firewall.py          # Section 14.6 nftables manager & timed sets
│   ├── gateway_blocker.py         # Gateway transit forward-drop adapter
│   ├── dns_protection.py          # Malicious domain sinkhole manager
│   ├── device_quarantine.py       # End-station quarantine & boundary verification
│   ├── connection_limiter.py      # Per-source connection rate throttler
│   ├── notification_service.py    # Alert broadcaster & ESP32 signaling
│   ├── rollback_manager.py        # Scheduled expiry & Emergency Stop
│   ├── audit_logger.py            # Section 14.13 SHA-256 hash-chained audit log
│   ├── approval_manager.py        # Mode B human operator approval manager
│   └── response_verifier.py       # Post-enforcement kernel state verifier
├── platforms/
│   ├── esp32/
│   │   ├── esp32_controller.py    # HMAC-authenticated Linux controller
│   │   └── esp32_firmware.ino     # C++/Arduino ESP32 firmware
│   ├── raspberry_pi/
│   │   └── gateway_manager.py     # Setup wizard for passive monitor vs gateway
│   ├── pc_host/
│   │   └── host_protector.py      # Kali/Debian host-level defense module
│   └── android_adb/
│       └── adb_controller.py      # Android ADB security testing controller
├── dashboard/
│   ├── templates/
│   │   └── index.html             # Dedicated Active Protection Panel
│   └── static/
│       ├── css/style.css          # Modern cyber defense styling
│       └── js/app.js              # Real-time polling, countdowns & actions
├── api/
│   ├── auth.py                    # API token authentication
│   └── routes.py                  # REST API control plane endpoints
├── scripts/
│   ├── start_netsentinel.sh       # Production startup script
│   ├── emergency_recover.sh       # Section 14.11 offline recovery script
│   ├── simulate_traffic.py        # Lab threat traffic generator
│   └── adb_device_tester.py       # Interactive Android ADB device tester
└── tests/
    ├── test_protection_engine.py  # Section 14.15 15 acceptance criteria tests
    └── test_adb_device.py         # Android ADB security test suite
```
