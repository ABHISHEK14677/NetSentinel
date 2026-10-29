# NetSentinel: Lab Testing & Real-Time Verification Guide

To test NetSentinel on other systems and verify detection, firewall enforcement, rollback, and cryptographic auditing in real-time, follow this end-to-end testing and verification guide.

---

### 1. Test Lab Architecture & Topology Options

Choose the topology matching your hardware setup:

```
[System 2: Attacker / Client / Phone] ─── (LAN / Wi-Fi / Bridged) ───► [System 1: NetSentinel Defense Host]
       (e.g., Kali / Ubuntu / Android)                                  (Kali Linux / Debian / Raspberry Pi)
```

| Setup Mode | System 1 (NetSentinel) | System 2 (Other System / Target) | Use Case |
|---|---|---|---|
| **Host Defense (Recommended)** | Linux PC / VM (IP: `192.168.1.50`) | Secondary PC, Laptop, or VM (IP: `192.168.1.100`) | Direct host protection, port scan & brute force drops |
| **Android ADB Mode** | Linux PC running NetSentinel | Android Phone (connected via Wi-Fi or USB) | Mobile endpoint scanning and containment |
| **Inline Gateway Mode** | Raspberry Pi (2 NICs: `eth0` WAN, `eth1` LAN) | Client devices connected behind Pi | Subnet-wide isolation and transit drops |

---

### 2. Prepare & Launch NetSentinel on System 1

#### Step 2.1: Clone & Configure on System 1

Ensure Python 3.10+, `nftables`, and `scapy` are installed:
```bash
sudo apt update && sudo apt install -y python3 python3-pip nftables tshark
git clone <your-repo-url> NetSentinel
cd NetSentinel
pip install -r requirements.txt  # Or: ./netsentinel.sh install-deps
```

#### Step 2.2: Configure Monitored Interface
Check your active network interface name (`ip -brief address` or `ip link`):
```bash
ip -brief addr
# Example output: eth0 or wlan0 or enp3s0
```
If your interface is not `eth0`, update `monitored_interface` in `config/config.py` (line 93) or launch with environment variables:
```bash
export NETSENTINEL_CAPTURE_ENABLED=true
```

#### Step 2.3: Start NetSentinel as Root (For Kernel nftables & Raw Sniffing)
NetSentinel requires root privileges (`sudo`) to program the Linux kernel firewall (`nftables`) and capture raw network packets:
```bash
sudo ./netsentinel.sh start
```
The web dashboard is now live and accessible across the LAN at `http://<System-1-IP>:8000`.

---

### 3. Switch from Safe Defaults to Active Protection

By default, NetSentinel boots with safety guardrails (Mode A: Monitor Only, Dry-Run ON). To test real-time active blocking:

1. Open the Dashboard in a browser on System 2: `http://<System-1-IP>:8000`
2. **Disable Dry-Run**: In the dashboard header, switch the **Dry Run** toggle to **OFF** (or call `curl -X POST http://<System-1-IP>:8000/api/dry-run/toggle`).
3. **Select Mode C or Mode D**:
   - **Mode C (Automatic Temporary Protection)**: Automatically blocks attacker with a timed expiry (e.g., 300s) and rollback.
   - **Mode B (Assisted Protection)**: If you want to test manual operator approval before enforcement.

(You can also set this via curl):
```bash
curl -X POST http://<System-1-IP>:8000/api/protection-mode \
     -H "Content-Type: application/json" \
     -d '{"mode": "AUTOMATIC_TEMPORARY", "operator": "ADMIN"}'
```

---

### 4. Execute Real-Time Attacks from System 2

From System 2 (IP: `192.168.1.100`), run any of the following tests against System 1 (`192.168.1.50`):

#### Method A: Live Network Reconnaissance (Nmap SYN Scan)
```bash
# Verify baseline connectivity first
ping -c 3 192.168.1.50

# Launch aggressive SYN scan (triggers PORT_SCAN detection)
sudo nmap -sS -p 1-1000 -T4 192.168.1.50
```

#### Method B: Live SSH Brute-Force
```bash
# Fast repeated failed logins (triggers BRUTE_FORCE detection)
hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.1.50
```

#### Method C: Synthetic Remote Ingestion (Direct API Test)
You can inject high-fidelity threat payloads remotely from System 2 using `simulate_traffic.py`:
```bash
# From System 2 (point API_URL to System 1's IP):
curl -X POST http://192.168.1.50:8000/api/threats/ingest \
     -H "Content-Type: application/json" \
     -d '{
       "category": "PORT_SCAN",
       "src_ip": "192.168.1.100",
       "dst_ip": "192.168.1.50",
       "dst_port": 445,
       "ids_severity": 85.0,
       "ai_anomaly_score": 70.0,
       "confidence": 0.95,
       "proto": "TCP"
     }'
```

#### Method D: Android Mobile Device via ADB
If testing against an Android smartphone connected to the Wi-Fi:
```bash
python3 scripts/adb_device_tester.py
# Select the device IP; it runs brute force/port scan simulations and verifies network quarantine.
```

---

### 5. The 7-Point Real-Time Verification Checklist

Follow this checklist to verify that NetSentinel handled the threat end-to-end:

#### ✅ 1. Attacker Perspective Verification (Immediate Network Drop)
Immediately after the attack triggers, run a ping or curl from System 2:
```bash
ping -c 4 192.168.1.50
# Expected: 100% packet loss (traffic is dropped at the Linux kernel boundary)

curl --connect-timeout 3 http://192.168.1.50:8000
# Expected: Operation timed out / Connection refused
```

#### ✅ 2. Kernel Firewall (nftables) State Verification
On System 1, inspect the dedicated `inet netsentinel` table:
```bash
sudo nft list table inet netsentinel
```

Expected Output:
```nft
table inet netsentinel {
    set blocked_ipv4 {
        type ipv4_addr
        flags timeout
        elements = { 192.168.1.100 timeout 5m expires 4m42s }
    }
    chain netsentinel_input {
        type filter hook input priority -10; policy accept;
        ip saddr @blocked_ipv4 drop
    }
}
```
Notice that `192.168.1.100` is present with an active countdown timer (`expires 4m42s`).

#### ✅ 3. Live Dashboard Telemetry
Open `http://<System-1-IP>:8000`:
- **Threat Event Stream**: Shows category `PORT_SCAN` or `BRUTE_FORCE` with risk score.
- **Active Blocks**: Lists `192.168.1.100` with the remaining duration and enforcement status `VERIFIED`.
- **System Safeguards**: Confirms protected gateway/DNS IPs are excluded from being blocked.

#### ✅ 4. Automated Expiry & Self-Healing Rollback
- Watch the countdown timer on the Dashboard or via `sudo nft list set inet netsentinel blocked_ipv4`.
- Once the timeout finishes (e.g. 5 minutes, or configured TTL), the kernel automatically evicts the IP from the set.
- On System 2, verify connectivity automatically resumes:
  ```bash
  ping -c 2 192.168.1.50  # Packets succeed again with 0% loss
  ```

#### ✅ 5. Emergency Stop Verification
While an active block is in place, test the instant fail-safe:
- Click **EMERGENCY STOP** in the top navigation bar of the Dashboard, OR run on System 1:
  ```bash
  ./netsentinel.sh recover
  ```
- Re-check `sudo nft list table inet netsentinel`: all blocks are immediately flushed, and System 2 regain immediate access.

#### ✅ 6. Cryptographic Audit Chain Verification
NetSentinel signs every action into an immutable SHA-256 hash-chained ledger:
```bash
./netsentinel.sh verify
```

Expected Output:
```
[+] Verifying tamper-evident audit log chain...
[✓] Cryptographic Hash Chain Verified: 14 entries intact. No tampering detected.
```

Or via REST API:
```bash
curl http://127.0.0.1:8000/api/audit/verify
```

#### ✅ 7. PCAP Evidence Storage Verification
If BUM packet capture is enabled (`NETSENTINEL_CAPTURE_ENABLED=true`), inspect generated forensic PCAPs:
```bash
ls -la evidence/
# View captured packet data using tcpdump / tshark:
tshark -r evidence/anomaly_*.pcap
```

---

### 6. Quick Reference Summary of Operational Commands

| Objective | Command |
|---|---|
| Run full automated unit & integration test suite | `./netsentinel.sh test` |
| Start NetSentinel server | `sudo ./netsentinel.sh start` |
| Inject synthetic attack scenarios (1 through 6) | `./netsentinel.sh simulate <1-6>` |
| Inspect active kernel firewall rules | `sudo ./netsentinel.sh export` |
| Disaster recovery / Flush all blocks | `sudo ./netsentinel.sh recover` |
| Verify cryptographic audit chain integrity | `./netsentinel.sh verify` |
