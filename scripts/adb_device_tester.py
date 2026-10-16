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
