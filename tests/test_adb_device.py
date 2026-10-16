"""
NetSentinel - Android ADB Device Test Suite
Validates detection, device inventory integration, risk scoring, active blocking,
and rollback against an Android endpoint connected via ADB (USB or Wi-Fi).
"""

import pytest
import os
import sys

# Ensure NetSentinel is on sys.path
sys.path.insert(0, "/home/kali/NetSentinel")

from config.config import settings, ProtectionMode
from database.db_service import init_db
from platforms.android_adb.adb_controller import adb_device_controller
from threat_engine.device_inventory import device_inventory_manager
from response.rollback_manager import rollback_manager
from response.linux_firewall import linux_firewall

@pytest.fixture(autouse=True)
def setup_adb_test_env():
    settings.db_path = "/tmp/netsentinel_adb_test.db"
    if os.path.exists(settings.db_path):
        os.remove(settings.db_path)
    init_db()

    # Configure active testing mode
    settings.protection_mode = ProtectionMode.MODE_C
    settings.dry_run_mode = False
    settings.emergency_stop_active = False

    yield

    if os.path.exists(settings.db_path):
        os.remove(settings.db_path)

def test_adb_device_discovery():
    """Validates ADB discovery and listing capability."""
    devices = adb_device_controller.list_devices()
    # Devices list returned as list of dicts
    assert isinstance(devices, list)

def test_adb_device_identity_extraction():
    """Validates extracting hardware identity (IP, MAC, Model) from Android endpoint."""
    identity = adb_device_controller.get_device_identity()
    assert "ip_address" in identity
    assert "model" in identity
    assert "mac_address" in identity
    assert len(identity["ip_address"].split(".")) == 4

def test_adb_device_inventory_registration():
    """Validates registering the Android device into NetSentinel Monitored Inventory (Section 14.7)."""
    identity = {
        "ip_address": "192.168.1.191",
        "mac_address": "9C:28:F7:3A:4B:99",
        "model": "Google Pixel 7",
        "android_version": "14"
    }
    reg = adb_device_controller.register_in_inventory(identity)
    assert reg["ip"] == "192.168.1.191"
    assert reg["trust_status"] in ["Unknown", "Under observation"]

    # Verify inventory record
    all_devs = device_inventory_manager.get_all_devices()
    assert any(d["ip_address"] == "192.168.1.191" for d in all_devs)

def test_adb_device_brute_force_attack_and_block():
    """
    Validates simulating an attack from the Android device,
    detecting it in NetSentinel, and executing verified temporary firewall blocking.
    """
    # 1. Run brute force test from Android phone
    test_result = adb_device_controller.run_security_test(
        test_type="brute_force",
        target_ip="10.0.2.15"
    )

    threat_eval = test_result["threat_evaluation"]
    assert threat_eval["risk_score"] > 40.0
    assert threat_eval["severity"] in ["Medium", "High", "Critical"]

    netsentinel_resp = test_result["netsentinel_response"]
    assert netsentinel_resp["action_type"] in ["BLOCK_SOURCE_IP", "RATE_LIMIT"]
    assert netsentinel_resp["verified"] is True

    # 2. Verify firewall rule exists in kernel set
    phone_ip = test_result["android_device"]["ip"]
    fw_check = linux_firewall.verify_rule_exists(phone_ip)
    assert fw_check["verified"] is True

    # 3. Rollback action
    uuid = netsentinel_resp["action_uuid"]
    rb = rollback_manager.rollback_action(uuid, reason="TEST_COMPLETED")
    assert rb["success"] is True

    # 4. Verify firewall rule is safely removed
    fw_check_after = linux_firewall.verify_rule_exists(phone_ip)
    assert fw_check_after["verified"] is False

def test_adb_device_port_scan_detection():
    """Validates port reconnaissance detection originating from Android endpoint."""
    test_result = adb_device_controller.run_security_test(
        test_type="port_scan",
        target_ip="10.0.2.15"
    )
    assert test_result["threat_evaluation"]["category"] == "PORT_SCAN"
    assert test_result["netsentinel_response"]["verified"] is True
