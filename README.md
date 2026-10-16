# NetSentinel: Advanced Active Threat Protection & Automated Response Engine

**NetSentinel** is an intelligent, policy-controlled Network Intrusion Detection and Prevention System (NIDS/NIPS). It bridges the gap between passive network monitoring and automated active threat response by integrating multi-factor correlation, calibrated risk scoring, kernel-level `nftables` prevention, post-enforcement state verification, tamper-evident cryptographic audit logging, and hardware auxiliary signaling.

---

## 1. System Architecture & Platform Adapters

NetSentinel operates across three deployment profiles with platform-specific response adapters:

1. **ESP32 Auxiliary Alert & Telemetry Controller**:
   - Cryptographically authenticated (HMAC-SHA256) hardware warning controller.
   - Severity-based RGB LED patterns and PWM buzzer frequencies.
   - Enclosure tamper switch interrupt detection.
   - Fail-safe offline alarm if the Linux monitoring host disconnects.
   - Auxiliary visual/audible alert controller—*does not independently claim firewall enforcement*.

2. **Raspberry Pi**:
   - **Mode 1 — Passive Monitoring Node**: Runs packet inspection, Suricata alert processing, threat correlation, and web dashboard without modifying external router state.
   - **Mode 2 — Authorized Security Gateway**: Operates on bridged/routed interfaces (`eth0` WAN <-> `eth1` LAN), enforcing forward-chain drops, rate limits, and client containment while preserving SSH (Port 22), DNS (Port 53), and DHCP (Ports 67/68). Includes a documented recovery wizard.

3. **Existing PC (Kali Linux / Debian)**:
   - Host-level defense protecting the local workstation stack via dedicated `inet netsentinel` nftables tables.
   - Clear architectural boundary communication: host firewall restricts traffic to/from the host, explaining when switch/router infrastructure is needed for subnet-wide isolation.

---

## 2. Threat Detection Categories (Section 14.2)

NetSentinel implements multi-factor event correlation for:
- Port scanning & network reconnaissance (`PORT_SCAN`)
- Repeated failed authentication & brute-force indicators (`BRUTE_FORCE`)
- Abnormal connection rates & DoS indicators (`DOS_RATE_ANOMALY`)
- Suspicious DNS queries & known malicious domains (`SUSPICIOUS_DNS`)
- Known malware C2 communication patterns (`MALWARE_C2`)
- Unexpected outbound connections (`UNEXPECTED_OUTBOUND`)
- High traffic volume & data exfiltration indicators (`DATA_EXFILTRATION`)
- Unauthorized device appearances on monitored networks (`UNAUTHORIZED_DEVICE`)
- Repeated connections to destinations flagged by threat intelligence (`THREAT_INTEL_MATCH`)
- Unusual connection patterns identified by AI anomaly models (`AI_ANOMALY`)
- Repeated IDS alerts associated with the same source or destination (`REPEATED_IDS_ALERT`)

> **Multi-Indicator Correlation Rule**: High-impact actions require correlation across multiple indicators or sustained event frequency. Isolated port scans or benign anomalies do not trigger aggressive blocking.

---

## 3. Threat Risk Scoring Engine (Section 14.3)

Evaluates:
- IDS signature severity (0–100)
- Event frequency and burst velocity
- Number of distinct correlated indicators
- Verified threat intelligence reputation with freshness TTL validation
- AI anomaly score (0–100)
- Confidence score and evidence freshness decay
- Asset criticality and protected infrastructure allowlists

### Severity Bands:
- `0–19`: **Informational** (Log only)
- `20–39`: **Low** (Observe and alert)
- `40–59`: **Medium** (Rate-limit or observation policy)
- `60–79`: **High** (Temporary block or assisted approval)
- `80–100`: **Critical** (Immediate active boundary block)

> **AI Anomaly Safeguard**: AI anomalies alone are capped at 65 (Medium-High) and **must never** authorize critical blocking actions without corroborating IDS signatures or verified threat intelligence.

---

## 4. Four Selectable Protection Levels (Section 14.5)

- **Mode A — Monitor Only**:
  - Collects traffic and IDS events.
  - Classifies threats and logs alerts to dashboard.
  - **Never alters network traffic or firewall rules.**
- **Mode B — Assisted Protection**:
  - Recommends an action, displays target, evidence, impact preview, and duration.
  - **Requires operator sign-off** before applying blocking or isolation.
- **Mode C — Automatic Temporary Protection**:
  - Automatically applies predefined, low-risk protective policies.
  - Uses temporary blocks with **mandatory expiry and automatic rollback**.
  - Excludes management devices, default gateway, allowlisted assets, and essential infrastructure.
  - Immediate emergency stop control.
- **Mode D — Strict Prevention**:
  - Enforces strict firewall policies on designated interfaces.
  - Enforces approved DNS restrictions and connection rate limiting.
  - Preserves administrative access and essential network services.

---

## 5. Response Architecture & Modules (Section 14.4)

Located in `response/`:
```
response/
├── response_engine.py       # Core orchestrator of the 11-step protection lifecycle
├── response_policy.py       # Mode evaluator (Modes A-D) and infrastructure safeguards
├── action_registry.py       # Idempotent action cache preventing duplicate rule creation
├── linux_firewall.py        # Dedicated nftables manager with timed sets & dry-run
├── gateway_blocker.py       # Gateway forward-chain transit isolation
├── dns_protection.py        # Malicious domain sinkholing (0.0.0.0)
├── device_quarantine.py     # Monitored LAN device containment & topology checks
├── connection_limiter.py    # Per-source connection rate throttling
├── notification_service.py  # Real-time alert broadcaster & ESP32 signaling
├── rollback_manager.py      # Scheduled expiry, manual rollback, and Emergency Stop
├── audit_logger.py          # Cryptographic SHA-256 hash-chained tamper-evident log
├── approval_manager.py      # Operator approval requests with impact previews
└── response_verifier.py     # Post-enforcement kernel state verification
```

---

## 6. The 11-Step Response Lifecycle (Section 14.11)

Every protective action follows this strict workflow:
1. **Validate Evidence**: Check target IP/domain format, confidence, and freshness.
2. **Evaluate Policy**: Check Mode (A, B, C, D) and matching rule thresholds.
3. **Check Safeguards**: Ensure target is not the default gateway, loopback, DNS server, or allowlisted device.
4. **Confirm Authorization**: Validate whether mode permits autonomous enforcement or requires operator sign-off.
5. **Preview / Request Approval**: Generate exact `nftables` rule specification and scope impact.
6. **Apply Action**: Insert timed element into dedicated `inet netsentinel` set.
7. **Verify Kernel State**: Query kernel set state directly to confirm element presence.
8. **Record Result Honestly**: If verification fails, flag system as degraded. Never report a threat as blocked if verification failed.
9. **Monitor Effect**: Track connection rate or packet drop counters.
10. **Automatic Expiry & Rollback**: Background worker expires timed entries or reverts state upon expiration.
11. **Notify Operator**: Update dashboard and broadcast alert across channels.

---

## 7. Emergency Stop & Recovery

### Immediate GUI Emergency Stop:
Click the **EMERGENCY STOP** button in the dashboard top navigation bar, or call:
```bash
curl -X POST http://127.0.0.1:8000/api/emergency-stop
```
This immediately:
- Flushes all active firewall blocks.
- Revokes all active quarantine records.
- Disables automated response actions.
- **Keeps threat detection and monitoring active.**

### CLI Emergency Recovery Script:
If the host becomes disconnected or inaccessible, run the offline recovery script:
```bash
/home/kali/NetSentinel/scripts/emergency_recover.sh
```

---

## 8. Monitored Device Inventory (Section 14.7)

Tracks LAN endpoints with:
- IP Address, MAC Address, Hostname, Network Interface, Observed Protocols
- Trust States: `Trusted`, `Unknown`, `Under observation`, `Suspicious`, `Restricted`, `Quarantined`, `Released`
- **Safe Discovery Rule**: Unknown devices trigger an observation policy by default—**not automatic disconnection**.

---

## 9. Tamper-Evident Audit Trail (Section 14.13)

Every policy change, firewall enforcement, approval decision, and rollback is recorded in an immutable SQLite database table linked by SHA-256 cryptographic hash chaining:
$$\text{Hash}_n = \text{SHA256}(\text{Hash}_{n-1} \parallel \text{Timestamp} \parallel \text{Operator} \parallel \text{EventType} \parallel \text{Details} \parallel \text{SecretKey})$$
Verify the integrity of the audit log at any time:
```bash
curl http://127.0.0.1:8000/api/audit/verify
```

---

## 10. Verification Test Suite (Section 14.15)

NetSentinel includes an automated pytest suite validating all 15 acceptance criteria:
```bash
pytest -v /home/kali/NetSentinel/tests/test_protection_engine.py
```
Test results:
- `test_1_suspicious_event_generates_alert`: PASSED
- `test_2_repeated_events_are_correlated_and_deduplicated`: PASSED
- `test_3_monitor_only_mode_never_modifies_firewall`: PASSED
- `test_4_assisted_mode_requires_approval`: PASSED
- `test_5_automatic_protection_follows_configured_policies`: PASSED
- `test_6_allowlisted_devices_are_not_blocked`: PASSED
- `test_7_temporary_rules_expire_correctly`: PASSED
- `test_8_invalid_or_stale_threat_intel_does_not_trigger_blocking`: PASSED
- `test_9_dry_run_mode_performs_no_enforcement`: PASSED
- `test_10_firewall_failures_are_reported_honestly`: PASSED
- `test_11_esp32_disconnection_does_not_stop_monitoring`: PASSED
- `test_12_gateway_mode_failure_triggers_recovery`: PASSED
- `test_13_emergency_stop_prevents_new_automated_actions`: PASSED
- `test_14_rollback_restores_expected_previous_state`: PASSED
- `test_15_failed_enforcement_never_reported_as_successful`: PASSED

---

## 11. Quick Start

1. **Launch NetSentinel Server**:
   ```bash
   sudo /home/kali/NetSentinel/scripts/start_netsentinel.sh
   ```
2. **Access Web Dashboard**:
   Open browser at [http://127.0.0.1:8000](http://127.0.0.1:8000).
   
3. **Simulate Lab Traffic**:
   ```bash
   python3 /home/kali/NetSentinel/scripts/simulate_traffic.py
   ```


## 12. Easy startup :

```bash
    # Navigate to the project directory
    cd /home/abhi/NetSentinel

    # Run the full test suite (20 tests)
    ./scripts/test_runner.sh

    # Run synthetic threat simulations (e.g., scenario 1: Port Scan, 2: Brute Force)
    python3 scripts/simulate_traffic.py 1
    python3 scripts/simulate_traffic.py 2

    # Verify SHA-256 cryptographic audit trail integrity
    python3 scripts/verify_audit_chain.py

    # Emergency recovery script (flushes rules and restores state if needed)
    ./scripts/emergency_recover.sh
```

