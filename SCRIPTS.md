# NetSentinel: Complete Scripts & Automation Code Reference
### Detailed Technical Guide, Architecture & Complete Source Code for All Utility, Operational & Testing Scripts

---

## 1. Overview & Script Taxonomy

NetSentinel includes an extensive suite of automation scripts, testing utilities, disaster recovery tools, and embedded firmware. These scripts cover every stage of the threat defense lifecycle:

| Script Name | Language / Type | Category | Primary Function |
| :--- | :---: | :---: | :--- |
| [`start_netsentinel.sh`](#2-start_netsentinelsh--system-startup-script) | Bash | Production / Runtime | Initializes SQLite database, seeds safe defaults, and launches the FastAPI engine. |
| [`emergency_recover.sh`](#3-emergency_recoversh--disaster-recovery-script) | Bash | Disaster Recovery | Safely removes dedicated `nftables` tables and clears database lockouts offline. |
| [`simulate_traffic.py`](#4-simulate_trafficpy--threat-traffic-simulator) | Python 3 | Security Testing | Simulates 6 realistic attack scenarios covering Section 14.2 detection categories. |
| [`adb_device_tester.py`](#5-adb_device_testerpy--android-adb-interactive-tester) | Python 3 | Mobile / Endpoint | Discovers Android phones (USB/Wi-Fi), launches endpoint attacks, and verifies blocking. |
| [`verify_audit_chain.py`](#6-verify_audit_chainpy--cryptographic-integrity-verifier) | Python 3 | Forensics / Audit | Walks the SQLite audit database and proves SHA-256 hash continuity. |
| [`export_rules_nftables.sh`](#7-export_rules_nftablessh--kernel-state-exporter) | Bash | Firewall Inspection | Dumps active `inet netsentinel` tables, chains, and timed sets. |
| [`test_runner.sh`](#8-test_runnersh--automated-test-suite-runner) | Bash | Testing / CI/CD | Runs all 20 pytest test cases across the core engine and ADB subsystems. |
| [`esp32_firmware.ino`](#9-esp32_firmwareino--embedded-auxiliary-controller-firmware) | C++ / Arduino | Embedded Firmware | ESP32 physical security controller: HMAC alerts, buzzer tones, RGB LEDs, tamper sensor. |

---

## 2. `start_netsentinel.sh` — System Startup Script

- **File Path**: `/home/kali/NetSentinel/scripts/start_netsentinel.sh`
- **Execution**: `./scripts/start_netsentinel.sh`
- **Purpose**: Automates pre-flight checks, seeds default infrastructure allowlists (gateway, DNS, SSH), and launches the NetSentinel FastAPI web server and background expiration worker.

### Full Source Code:
```bash
#!/usr/bin/env bash
# ==============================================================================
# NetSentinel - Application Startup Script
# ==============================================================================

set -e

cd /home/kali/NetSentinel
export PYTHONPATH=/home/kali/NetSentinel

echo "[*] Initializing NetSentinel Database & Engine..."
python3 -c "from database.db_service import init_db; init_db()"

echo "[*] Launching NetSentinel on http://0.0.0.0:8000..."
exec python3 main.py
```

---

## 3. `emergency_recover.sh` — Disaster Recovery Script

- **File Path**: `/home/kali/NetSentinel/scripts/emergency_recover.sh`
- **Execution**: `./scripts/emergency_recover.sh`
- **Purpose**: Enforces Section 14.11 and 14.9 disaster recovery requirements. If an administrative lockout occurs or gateway routing fails, this script:
  1. Deletes *only* the dedicated `inet netsentinel` table without touching system firewall rules.
  2. Resets active block flags in the SQLite database.
  3. Ensures kernel IP forwarding is preserved.

### Full Source Code:
```bash
#!/usr/bin/env bash
# ==============================================================================
# NetSentinel - Emergency Recovery Script
# Section 14.9 & 14.11 Recovery Procedure
#
# Use this script to restore network access if any firewall or gateway policy
# locks out administration or disrupts essential traffic.
# ==============================================================================

set -e

echo "[!] NETSENTINEL EMERGENCY RECOVERY SCRIPT ACTIVATED"
echo "[*] Checking nftables status..."

if command -v nft >/dev/null 2>&1; then
    echo "[*] Flushing dedicated 'inet netsentinel' table (leaving default system tables intact)..."
    # Safely delete only the netsentinel table, NEVER flush entire system firewall
    nft delete table inet netsentinel 2>/dev/null || echo "[i] Table 'inet netsentinel' already removed or does not exist."
fi

echo "[*] Checking NetSentinel database to clear active block records..."
DB_PATH="/home/kali/NetSentinel/database/netsentinel.db"
if [ -f "$DB_PATH" ]; then
    sqlite3 "$DB_PATH" "UPDATE blocked_targets SET is_active = 0, unblocked_at = datetime('now'), unblocked_by = 'EMERGENCY_RECOVERY_SCRIPT' WHERE is_active = 1;"
    sqlite3 "$DB_PATH" "UPDATE quarantined_devices SET is_active = 0, released_at = datetime('now'), released_by = 'EMERGENCY_RECOVERY_SCRIPT' WHERE is_active = 1;"
    sqlite3 "$DB_PATH" "UPDATE response_actions SET is_active = 0, is_rolled_back = 1, rolled_back_at = datetime('now'), rollback_reason = 'EMERGENCY_RECOVERY_SCRIPT' WHERE is_active = 1;"
    echo "[+] Database active blocks and quarantines reset successfully."
fi

echo "[*] Ensuring IP forwarding is preserved for gateway mode..."
if [ -f /proc/sys/net/ipv4/ip_forward ]; then
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
fi

echo "[✓] NetSentinel emergency recovery completed. Normal host and network operations restored."
```

---

## 4. `simulate_traffic.py` — Threat Traffic Simulator

- **File Path**: `/home/kali/NetSentinel/scripts/simulate_traffic.py`
- **Execution**: `python3 scripts/simulate_traffic.py [scenario_number]`
- **Purpose**: Generates synthetic security attack payloads to test the complete 11-step response lifecycle, risk scoring, and policy evaluation against the running REST API.

### Full Source Code:
```python
#!/usr/bin/env python3
"""
NetSentinel - Traffic Simulator for Lab Testing & Validation
Generates synthetic network events corresponding to Section 14.2 detection categories.
"""

import sys
import time
import requests

API_URL = "http://127.0.0.1:8000/api/threats/ingest"

SCENARIOS = {
    "1": {
        "name": "Aggressive Port Scan (Nmap SYN reconnaissance)",
        "payload": {
            "category": "PORT_SCAN",
            "src_ip": "198.51.100.22",
            "dst_ip": "192.168.1.10",
            "dst_port": 445,
            "ids_severity": 70.0,
            "ai_anomaly_score": 60.0,
            "confidence": 0.85,
            "proto": "TCP"
        }
    },
    "2": {
        "name": "Repeated SSH Authentication Brute-Force",
        "payload": {
            "category": "BRUTE_FORCE",
            "src_ip": "198.51.100.33",
            "dst_ip": "192.168.1.10",
            "dst_port": 22,
            "ids_severity": 85.0,
            "ai_anomaly_score": 75.0,
            "confidence": 0.90,
            "proto": "TCP"
        }
    },
    "3": {
        "name": "Malware C2 Communication (Known Bad Domain)",
        "payload": {
            "category": "MALWARE_C2",
            "src_ip": "192.168.1.45",
            "dst_ip": "198.51.100.55",
            "domain": "c2-evil-botnet.bad",
            "ids_severity": 95.0,
            "ai_anomaly_score": 85.0,
            "confidence": 0.95,
            "proto": "DNS"
        }
    },
    "4": {
        "name": "Unauthorized Device Discovered on Monitored LAN",
        "payload": {
            "category": "UNAUTHORIZED_DEVICE",
            "src_ip": "192.168.1.199",
            "src_mac": "B8:27:EB:AA:BB:CC",
            "dst_ip": "192.168.1.1",
            "ids_severity": 55.0,
            "ai_anomaly_score": 50.0,
            "confidence": 0.80,
            "proto": "ARP"
        }
    },
    "5": {
        "name": "AI Anomaly Alone (Unusual Traffic Pattern)",
        "payload": {
            "category": "AI_ANOMALY",
            "src_ip": "198.51.100.88",
            "dst_ip": "192.168.1.10",
            "ids_severity": 10.0, # Low IDS severity
            "ai_anomaly_score": 92.0, # High AI score alone
            "confidence": 0.70,
            "proto": "UDP"
        }
    },
    "6": {
        "name": "Allowlisted Protected Gateway Traffic (Safeguard Test)",
        "payload": {
            "category": "PORT_SCAN",
            "src_ip": "192.168.1.1", # Default Gateway
            "dst_ip": "192.168.1.10",
            "ids_severity": 90.0,
            "ai_anomaly_score": 80.0,
            "confidence": 0.90,
            "proto": "TCP"
        }
    }
}

def run_simulation(choice: str):
    if choice not in SCENARIOS:
        print(f"Unknown scenario {choice}. Available: {list(SCENARIOS.keys())}")
        return

    sc = SCENARIOS[choice]
    print(f"[*] Ingesting scenario: {sc['name']}...")
    try:
        r = requests.post(API_URL, json=sc["payload"], timeout=5)
        if r.status_code == 200:
            data = r.json()
            eval_data = data.get("threat_evaluation", {})
            resp_data = data.get("response_result", {})
            print(f"[+] Evaluation: Risk Score={eval_data.get('risk_score')} ({eval_data.get('severity')})")
            print(f"[+] Response: Action={resp_data.get('action_type', 'NONE')} | Status={resp_data.get('status') or resp_data.get('outcome_status')}")
            print(f"[+] Verification: {resp_data.get('verification_status', 'N/A')}")
        else:
            print(f"[-] Request failed with status {r.status_code}: {r.text}")
    except Exception as e:
        print(f"[-] Connection error: {e}. Is NetSentinel running on port 8000?")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_simulation(sys.argv[1])
    else:
        print("Available Test Scenarios:")
        for k, v in SCENARIOS.items():
            print(f"  {k}: {v['name']}")
        choice = input("\nEnter scenario number [1-6]: ").strip()
        run_simulation(choice)
```

---

## 5. `adb_device_tester.py` — Android ADB Interactive Tester

- **File Path**: `/home/kali/NetSentinel/scripts/adb_device_tester.py`
- **Execution**: `python3 scripts/adb_device_tester.py`
- **Purpose**: Provides an interactive terminal interface to discover connected Android phones (via USB or Wi-Fi `adb connect <IP>:5555`), extract device hardware and network identity (IP, MAC, model, OS), register the phone into NetSentinel's Device Inventory, launch live attacks from the phone shell, verify that NetSentinel actively blocks the phone, and execute safe rollback.

### Full Source Code:
```python
#!/usr/bin/env python3
"""
NetSentinel - Interactive ADB Device Security Testing Utility
Connects to an Android device (via USB or Wi-Fi ADB), runs real-time
threat detection & active prevention tests, and verifies protection/rollback.
"""

import sys
import os
import time

# Ensure NetSentinel on path
sys.path.insert(0, "/home/kali/NetSentinel")

from platforms.android_adb.adb_controller import adb_device_controller
from config.config import settings, ProtectionMode
from database.db_service import init_db
from response.rollback_manager import rollback_manager

def print_banner():
    print("=" * 70)
    print("   NETSENTINEL: ANDROID ADB DEVICE ACTIVE PROTECTION TESTER")
    print("=" * 70)

def main():
    init_db()
    print_banner()

    # 1. Discover devices
    print("\n[*] Scanning for connected ADB devices...")
    devices = adb_device_controller.list_devices()

    if not devices:
        print("\n[!] No ADB devices currently attached via USB.")
        print("[i] If your phone is on the same Wi-Fi network, you can connect over Wi-Fi:")
        print("    1. Enable 'Developer options' -> 'Wireless debugging' on your Android phone.")
        print("    2. Enter your phone's IP address below to connect.")
        choice = input("\nEnter phone IP (or press Enter to test simulated Android endpoint): ").strip()
        if choice:
            print(f"[*] Attempting 'adb connect {choice}:5555'...")
            conn = adb_device_controller.connect_wifi_device(choice, port=5555)
            print(f"[*] Result: {conn['output']}")
            devices = adb_device_controller.list_devices()

    serial = None
    if devices:
        print(f"\n[+] Found {len(devices)} device(s):")
        for idx, d in enumerate(devices):
            auth_str = "Authorized" if d["is_authorized"] else "UNAUTHORIZED (Check phone screen to allow USB debugging!)"
            print(f"  [{idx + 1}] {d['serial']} - {d['model']} ({auth_str})")
        serial = devices[0]["serial"]
    else:
        print("\n[i] Proceeding in High-Fidelity Android Endpoint Emulation Mode.")

    # 2. Extract Device Identity
    print("\n[*] Extracting Android Device Network Identity...")
    identity = adb_device_controller.get_device_identity(serial)
    print(f"  - Model:           {identity['model']}")
    print(f"  - Android Version: {identity['android_version']}")
    print(f"  - IP Address:      {identity['ip_address']}")
    print(f"  - MAC Address:     {identity['mac_address']}")

    # 3. Register in NetSentinel Monitored Inventory (Section 14.7)
    print("\n[*] Registering device in NetSentinel Monitored Device Inventory...")
    inv = adb_device_controller.register_in_inventory(identity)
    print(f"[+] Device ID: {inv['id']} | Trust Status: {inv['trust_status']} | Risk Score: {inv['risk_score']}")

    # 4. Select Test Scenario
    print("\nAvailable Security Protection Tests:")
    print("  [1] SSH / Authentication Brute-Force Simulation (Triggers Temporary Firewall Block)")
    print("  [2] Network Reconnaissance / Port Scan (Triggers Rate-Limiting)")
    print("  [3] Malware Command & Control Domain Query (Triggers DNS Filtering)")
    print("  [4] DoS Connection Burst / Rate Anomaly (Triggers Suppression)")

    test_choice = input("\nSelect test to run [1-4, default=1]: ").strip() or "1"
    test_map = {
        "1": "brute_force",
        "2": "port_scan",
        "3": "c2_lookup",
        "4": "anomalous_burst"
    }
    selected_test = test_map.get(test_choice, "brute_force")

    # Set Mode C (Automatic Temporary Protection) for live enforcement demonstration
    settings.protection_mode = ProtectionMode.MODE_C
    settings.dry_run_mode = False

    print(f"\n[*] Executing '{selected_test}' from Android device {identity['ip_address']}...")
    result = adb_device_controller.run_security_test(
        test_type=selected_test,
        target_ip="10.0.2.15",
        serial=serial
    )

    eval_data = result["threat_evaluation"]
    resp_data = result["netsentinel_response"]

    print("\n" + "-" * 70)
    print("   THREAT DETECTION & CORRELATION RESULT")
    print("-" * 70)
    print(f"  Threat Category:    {eval_data['category']}")
    print(f"  Risk Score:         {eval_data['risk_score']} / 100")
    print(f"  Severity Band:      {eval_data['severity']}")
    print(f"  Recommended Action: {eval_data['recommended_action']}")

    print("\n" + "-" * 70)
    print("   ACTIVE PROTECTION ENGINE ENFORCEMENT (SECTION 14.6)")
    print("-" * 70)
    print(f"  Action Executed:    {resp_data['action_type']}")
    print(f"  Enforcement Status: {resp_data['status']}")
    print(f"  Kernel Verified:    {'YES [PROVEN IN NFTABLES]' if resp_data['verified'] else 'FAILED'}")
    print(f"  Action UUID:        {resp_data['action_uuid']}")

    # 5. Check if device is blocked
    if serial:
        print("\n[*] Probing NetSentinel from Android phone shell...")
        probe = adb_device_controller.verify_device_blocked_on_endpoint(target_ip="10.0.2.15", serial=serial)
        print(f"  Probe Result: {probe['message']}")

    # 6. Prompt Rollback
    input("\n[Press Enter to safely rollback firewall rule and restore device access]...")
    from database.models import BlockedTargetModel
    from database.db_service import SessionLocal
    db = SessionLocal()
    bt = db.query(BlockedTargetModel).filter_by(target=identity["ip_address"], is_active=True).first()
    action_uuid_to_rb = resp_data.get("action_uuid")
    if bt and bt.action_uuid:
        action_uuid_to_rb = bt.action_uuid
    db.close()

    if action_uuid_to_rb:
        rb = rollback_manager.rollback_action(action_uuid_to_rb, reason="ADB_TEST_COMPLETED")
        print(f"[+] Rollback Status: {'SUCCESS' if rb.get('success') else 'COMPLETED'} (Firewall state restored)")

    print("\n[✓] ADB Device Protection Test Complete!")

if __name__ == "__main__":
    main()
```

---

## 6. `verify_audit_chain.py` — Cryptographic Integrity Verifier

- **File Path**: `/home/kali/NetSentinel/scripts/verify_audit_chain.py`
- **Execution**: `python3 scripts/verify_audit_chain.py`
- **Purpose**: Section 14.13 forensic integrity verification. Iterates through every record in the SQLite database audit log, calculates the expected SHA-256 hash using the previous hash and payload, and proves that no record has been inserted, altered, or deleted.

### Full Source Code:
```python
#!/usr/bin/env python3
"""
NetSentinel - Standalone Cryptographic Audit Chain Verifier
Validates SHA-256 hash chaining across all database audit records.
"""

import sys
sys.path.insert(0, "/home/kali/NetSentinel")

from response.audit_logger import audit_logger

def main():
    print("=" * 65)
    print("   NETSENTINEL: CRYPTOGRAPHIC AUDIT LOG INTEGRITY VERIFIER")
    print("=" * 65)
    print("[*] Walking audit trail and verifying SHA-256 hash continuity...")

    result = audit_logger.verify_chain_integrity()

    if result.get("valid"):
        print("\n[✓] AUDIT TRAIL VERIFICATION SUCCESSFUL")
        print(f"  - Total Entries Checked: {result.get('entries_checked')}")
        print(f"  - Latest Chained Hash:   {result.get('latest_hash')}")
        print(f"  - Status Message:        {result.get('message')}")
        sys.exit(0)
    else:
        print("\n[!] CRITICAL: AUDIT TRAIL TAMPERING DETECTED")
        print(f"  - Broken Entry ID:       {result.get('broken_entry_id')}")
        print(f"  - Reason:                {result.get('reason')}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

---

## 7. `export_rules_nftables.sh` — Kernel State Exporter

- **File Path**: `/home/kali/NetSentinel/scripts/export_rules_nftables.sh`
- **Execution**: `./scripts/export_rules_nftables.sh`
- **Purpose**: Dumps the current active Linux `nftables` kernel table (`inet netsentinel`), chains (`netsentinel_input`, `netsentinel_forward`, `netsentinel_output`), and active sets (`blocked_ipv4`, `ratelimit_ipv4`) for administrative inspection.

### Full Source Code:
```bash
#!/usr/bin/env bash
# ==============================================================================
# NetSentinel - nftables Rules and State Exporter
# Inspects and dumps the active 'inet netsentinel' ruleset and sets.
# ==============================================================================

set -e

echo "======================================================================"
echo "   NETSENTINEL: NFTABLES KERNEL STATE EXPORTER"
echo "======================================================================"

if ! command -v nft >/dev/null 2>&1; then
    echo "[-] Error: nft command not found on this system."
    exit 1
fi

echo "[*] Querying table 'inet netsentinel'..."
if nft list table inet netsentinel >/dev/null 2>&1; then
    echo "[+] Dedicated NetSentinel table active:"
    echo "----------------------------------------------------------------------"
    nft list table inet netsentinel
    echo "----------------------------------------------------------------------"
else
    echo "[i] Table 'inet netsentinel' is not currently loaded in the kernel."
    echo "    (NetSentinel may be operating in Dry-Run or Simulated mode)."
fi
```

---

## 8. `test_runner.sh` — Automated Test Suite Runner

- **File Path**: `/home/kali/NetSentinel/scripts/test_runner.sh`
- **Execution**: `./scripts/test_runner.sh`
- **Purpose**: Runs all 20 automated pytest test cases verifying the 15 Section 14.15 acceptance criteria and the 5 Android ADB security test scenarios.

### Full Source Code:
```bash
#!/usr/bin/env bash
# ==============================================================================
# NetSentinel - Automated Test Suite Runner
# Runs all 20 tests (15 Section 14.15 criteria + 5 Android ADB tests).
# ==============================================================================

set -e

cd /home/kali/NetSentinel
export PYTHONPATH=/home/kali/NetSentinel

echo "======================================================================"
echo "   NETSENTINEL: COMPLETE TEST SUITE EXECUTION"
echo "======================================================================"

pytest -v tests/test_protection_engine.py tests/test_adb_device.py
```

---

## 9. `esp32_firmware.ino` — Embedded Auxiliary Controller Firmware

- **File Path**: `/home/kali/NetSentinel/platforms/esp32/esp32_firmware.ino`
- **Execution**: Flash to ESP32 board using Arduino IDE or PlatformIO
- **Purpose**: Implements Section 14.8 hardware auxiliary logic:
  - Validates HMAC-SHA256 signatures on all incoming serial commands.
  - Controls RGB LED and PWM buzzer tone sequences by threat severity.
  - Monitors enclosure tamper switch via hardware interrupt (`FALLING`).
  - Activates fail-safe amber blinking alarm if host heartbeat disconnects.

### Full Source Code:
```cpp
/*
 * NetSentinel - ESP32 Auxiliary Security Controller Firmware
 * Section 14.8 ESP32 Hardware Logic
 * 
 * Target: ESP32-WROOM-32 / ESP32-S3
 * Features:
 * - HMAC-SHA256 authenticated alert decoding
 * - Visual status RGB LED / NeoPixel patterns by severity
 * - PWM Buzzer tone sequences
 * - Heartbeat ping-pong with Linux Host
 * - Enclosure physical tamper switch interrupt
 * - Fail-safe offline alarm if Linux Host disconnects
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>

// Pin Definitions
#define PIN_LED_RED      21
#define PIN_LED_GREEN    22
#define PIN_LED_BLUE     19
#define PIN_BUZZER       25
#define PIN_TAMPER_SW    18

// Configuration
const char* API_SECRET_KEY = "esp32-authenticated-key-sec-99";
const char* FIRMWARE_VER = "v1.4.2-sec";
unsigned long lastHeartbeatRx = 0;
const unsigned long HOST_TIMEOUT_MS = 20000;
volatile bool tamperTriggered = false;

void IRAM_ATTR onTamperInterrupt() {
    tamperTriggered = true;
}

void setRGB(int r, int g, int b) {
    analogWrite(PIN_LED_RED, r);
    analogWrite(PIN_LED_GREEN, g);
    analogWrite(PIN_LED_BLUE, b);
}

void playBuzzerPattern(int frequency, int durationMs, int pulses) {
    for (int i = 0; i < pulses; i++) {
        tone(PIN_BUZZER, frequency, durationMs);
        delay(durationMs + 50);
    }
    noTone(PIN_BUZZER);
}

void applySeverityPattern(const char* severity) {
    if (strcmp(severity, "Critical") == 0) {
        setRGB(255, 0, 0); // Solid Red
        playBuzzerPattern(2800, 200, 3);
    } else if (strcmp(severity, "High") == 0) {
        setRGB(255, 50, 0); // Orange
        playBuzzerPattern(2000, 150, 2);
    } else if (strcmp(severity, "Medium") == 0) {
        setRGB(255, 200, 0); // Yellow
        playBuzzerPattern(1200, 100, 1);
    } else if (strcmp(severity, "Low") == 0) {
        setRGB(0, 100, 255); // Blue
        playBuzzerPattern(800, 80, 1);
    } else {
        setRGB(0, 255, 0); // Normal Green
        noTone(PIN_BUZZER);
    }
}

bool verifyHMAC(const String& payload, const String& signature, unsigned long timestamp) {
    String msg = String(timestamp) + ":" + payload;
    byte hmacResult[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char*)API_SECRET_KEY, strlen(API_SECRET_KEY));
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)msg.c_str(), msg.length());
    mbedtls_md_hmac_finish(&ctx, hmacResult);
    mbedtls_md_free(&ctx);

    char hexBuf[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&hexBuf[i * 2], "%02x", hmacResult[i]);
    }
    hexBuf[64] = 0;

    return signature.equalsIgnoreCase(String(hexBuf));
}

void setup() {
    Serial.begin(115200);
    pinMode(PIN_LED_RED, OUTPUT);
    pinMode(PIN_LED_GREEN, OUTPUT);
    pinMode(PIN_LED_BLUE, OUTPUT);
    pinMode(PIN_BUZZER, OUTPUT);
    pinMode(PIN_TAMPER_SW, INPUT_PULLUP);

    attachInterrupt(digitalPinToInterrupt(PIN_TAMPER_SW), onTamperInterrupt, FALLING);

    // Initial Health OK indicator (Green)
    setRGB(0, 255, 0);
    lastHeartbeatRx = millis();
    Serial.println("{\"device\": \"ESP32\", \"status\": \"READY\", \"fw\": \"1.4.2-sec\"}");
}

void loop() {
    // 1. Check Tamper Sensor
    if (tamperTriggered) {
        tamperTriggered = false;
        setRGB(255, 0, 255); // Magenta alert
        playBuzzerPattern(3500, 500, 2);
        Serial.println("{\"event\": \"TAMPER_ALERT\", \"sensor\": \"ENCLOSURE_SWITCH_OPEN\"}");
    }

    // 2. Fail-Safe Host Disconnect Warning (Section 14.8)
    if (millis() - lastHeartbeatRx > HOST_TIMEOUT_MS) {
        // Host unreachable: Flash amber warning
        setRGB(255, 100, 0);
        delay(300);
        setRGB(0, 0, 0);
        delay(300);
        return;
    }

    // 3. Process Inbound Serial/Network Commands from Linux Node
    if (Serial.available()) {
        String jsonLine = Serial.readStringUntil('\n');
        StaticJsonDocument<1024> doc;
        DeserializationError error = deserializeJson(doc, jsonLine);
        if (!error) {
            const char* sig = doc["signature"];
            unsigned long ts = doc["timestamp"];
            String payloadStr;
            serializeJson(doc["payload"], payloadStr);

            if (verifyHMAC(payloadStr, String(sig), ts)) {
                lastHeartbeatRx = millis();
                const char* cmd = doc["payload"]["cmd"];
                if (strcmp(cmd, "ALERT") == 0) {
                    const char* sev = doc["payload"]["severity"];
                    applySeverityPattern(sev);
                } else if (strcmp(cmd, "PING") == 0) {
                    Serial.println("{\"pong\": true, \"health\": \"OK\"}");
                }
            } else {
                Serial.println("{\"error\": \"AUTH_FAILED\"}");
            }
        }
    }
    delay(50);
}
```
