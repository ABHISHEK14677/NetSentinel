"""
NetSentinel - Comprehensive Test Suite
Validates all 15 scenarios mandated by Section 14.15 Additional Testing Requirements.
"""

import pytest
import time
import os
import datetime

# Ensure NetSentinel is on sys.path
import sys
sys.path.insert(0, "/home/kali/NetSentinel")

from config.config import settings, ProtectionMode, GatewayMode
from database.db_service import init_db, SessionLocal
from database.models import BlockedTargetModel, ResponseActionModel, ApprovalRequestModel
from threat_engine.detector import threat_detector, ThreatCategory
from threat_engine.correlator import threat_correlator
from threat_engine.risk_scorer import risk_scorer
from threat_engine.threat_intel import threat_intel_service
from response.response_engine import response_engine
from response.response_policy import response_policy_engine
from response.rollback_manager import rollback_manager
from response.approval_manager import approval_manager
from response.linux_firewall import linux_firewall
from response.action_registry import action_registry
from response.audit_logger import audit_logger
from platforms.esp32.esp32_controller import esp32_controller
from platforms.raspberry_pi.gateway_manager import raspberry_pi_manager

@pytest.fixture(autouse=True)
def setup_test_environment():
    """Sets up a clean test state before each test."""
    settings.db_path = "/tmp/netsentinel_test.db"
    if os.path.exists(settings.db_path):
        os.remove(settings.db_path)
    init_db()

    # Reset default settings
    settings.protection_mode = ProtectionMode.MODE_A
    settings.dry_run_mode = True
    settings.emergency_stop_active = False
    settings.firewall_modification_enabled = False
    action_registry._active_actions_cache.clear()
    threat_correlator.active_incidents.clear()
    threat_correlator._dedup_cache.clear()

    yield

    # Clean up test database
    if os.path.exists(settings.db_path):
        os.remove(settings.db_path)

# ------------------------------------------------------------------------------
# Test 1: Suspicious event generates an alert
# ------------------------------------------------------------------------------
def test_1_suspicious_event_generates_alert():
    raw_event = {
        "category": ThreatCategory.PORT_SCAN,
        "src_ip": "198.51.100.11",
        "dst_ip": "192.168.1.10",
        "ids_severity": 60.0,
        "ai_anomaly_score": 40.0,
        "confidence": 0.8
    }
    evaluation = threat_detector.process_event(raw_event)
    assert evaluation["risk_score"] > 0
    assert evaluation["severity"] in ["Low", "Medium", "High"]

    res = response_engine.process_threat(evaluation)
    assert res["target"] == "198.51.100.11"
    assert "action_uuid" in res

# ------------------------------------------------------------------------------
# Test 2: Repeated events are correlated and deduplicated
# ------------------------------------------------------------------------------
def test_2_repeated_events_are_correlated_and_deduplicated():
    ip = "198.51.100.25"
    # First event
    ev1 = threat_detector.process_event({"src_ip": ip, "category": ThreatCategory.PORT_SCAN, "ids_severity": 40.0})
    assert ev1["event_count"] == 1
    assert not ev1["is_multi_indicator"]

    # Second event from same source
    ev2 = threat_detector.process_event({"src_ip": ip, "category": ThreatCategory.PORT_SCAN, "ids_severity": 50.0})
    assert ev2["event_count"] == 2

    # Add different category (multi-indicator correlation)
    ev3 = threat_detector.process_event({"src_ip": ip, "category": ThreatCategory.BRUTE_FORCE, "ids_severity": 70.0})
    assert ev3["event_count"] == 3
    assert ev3["indicator_count"] >= 2
    assert ev3["is_multi_indicator"] is True

# ------------------------------------------------------------------------------
# Test 3: Monitor-only mode never modifies firewall rules
# ------------------------------------------------------------------------------
def test_3_monitor_only_mode_never_modifies_firewall():
    settings.protection_mode = ProtectionMode.MODE_A # Monitor Only
    settings.dry_run_mode = False

    raw_event = {
        "category": ThreatCategory.BRUTE_FORCE,
        "src_ip": "198.51.100.99",
        "ids_severity": 95.0,
        "confidence": 0.95
    }
    evaluation = threat_detector.process_event(raw_event)
    result = response_engine.process_threat(evaluation)

    assert result["status"] == "MONITORED_ONLY"
    assert result["enforced"] is False
    assert "Monitor Only" in result["reason"]

    # Ensure target is NOT present in firewall set
    check = linux_firewall.verify_rule_exists("198.51.100.99")
    assert check["verified"] is False

# ------------------------------------------------------------------------------
# Test 4: Assisted mode requires operator approval
# ------------------------------------------------------------------------------
def test_4_assisted_mode_requires_approval():
    settings.protection_mode = ProtectionMode.MODE_B # Assisted Protection

    raw_event = {
        "category": ThreatCategory.BRUTE_FORCE,
        "src_ip": "198.51.100.66",
        "ids_severity": 85.0,
        "confidence": 0.90
    }
    evaluation = threat_detector.process_event(raw_event)
    result = response_engine.process_threat(evaluation)

    assert result["status"] == "AWAITING_APPROVAL"
    assert "request_uuid" in result

    # Check pending approvals
    pending = approval_manager.get_pending_requests()
    assert any(p["request_uuid"] == result["request_uuid"] for p in pending)

    # Approve request
    dec = approval_manager.decide_request(result["request_uuid"], approve=True)
    assert dec["status"] == "APPROVED"

# ------------------------------------------------------------------------------
# Test 5: Automatic protection follows configured policies
# ------------------------------------------------------------------------------
def test_5_automatic_protection_follows_configured_policies():
    settings.protection_mode = ProtectionMode.MODE_C # Auto Temporary
    settings.dry_run_mode = False

    # Correlate multiple indicators so it qualifies for high-impact automatic action
    ip = "198.51.100.44"
    threat_detector.process_event({"src_ip": ip, "category": ThreatCategory.PORT_SCAN, "ids_severity": 75.0})
    eval2 = threat_detector.process_event({"src_ip": ip, "category": ThreatCategory.BRUTE_FORCE, "ids_severity": 85.0})

    result = response_engine.process_threat(eval2)
    assert result["action_type"] == "BLOCK_SOURCE_IP"
    assert result["outcome_status"] == "VERIFIED_BLOCKED"
    assert result["verified"] is True

# ------------------------------------------------------------------------------
# Test 6: Allowlisted devices are not blocked
# ------------------------------------------------------------------------------
def test_6_allowlisted_devices_are_not_blocked():
    settings.protection_mode = ProtectionMode.MODE_C
    settings.dry_run_mode = False

    # Test default gateway 192.168.1.1 (seeded as protected essential infrastructure)
    gateway_ip = "192.168.1.1"
    raw_event = {
        "category": ThreatCategory.PORT_SCAN,
        "src_ip": gateway_ip,
        "ids_severity": 99.0, # Even extreme severity cannot block gateway
        "confidence": 1.0
    }
    evaluation = threat_detector.process_event(raw_event, is_protected_asset_cb=response_policy_engine.is_protected_asset)
    result = response_engine.process_threat(evaluation)

    assert result["status"] == "MONITORED_ONLY"
    assert "protected infrastructure or allowlisted" in result["reason"]
    check = linux_firewall.verify_rule_exists(gateway_ip)
    assert check["verified"] is False

# ------------------------------------------------------------------------------
# Test 7: Temporary rules expire correctly
# ------------------------------------------------------------------------------
def test_7_temporary_rules_expire_correctly():
    settings.protection_mode = ProtectionMode.MODE_C
    settings.dry_run_mode = False

    ip = "198.51.100.77"
    linux_firewall.apply_temporary_block(ip, duration_seconds=1)
    assert linux_firewall.verify_rule_exists(ip)["verified"] is True

    # Manually expire
    time.sleep(1.2)
    check = linux_firewall.verify_rule_exists(ip)
    assert check["verified"] is False

# ------------------------------------------------------------------------------
# Test 8: Invalid or stale threat-intelligence entries do not trigger blocking
# ------------------------------------------------------------------------------
def test_8_invalid_or_stale_threat_intel_does_not_trigger_blocking():
    stale_ip = "198.51.100.99" # Seeded as 48-hours old stale intel in threat_intel.py
    intel = threat_intel_service.check_indicator(stale_ip)

    assert intel is not None
    assert intel["is_fresh"] is False
    assert intel["is_valid"] is False

    # Compute risk: Stale intel should decay/not inflate score
    score = risk_scorer.compute_risk(
        category=ThreatCategory.THREAT_INTEL_MATCH,
        target_indicator=stale_ip,
        ids_severity=10.0
    )
    assert score["evidence_breakdown"]["threat_intel_valid"] is False
    assert score["severity"] in ["Informational", "Low"]

# ------------------------------------------------------------------------------
# Test 9: Dry-run mode performs no enforcement
# ------------------------------------------------------------------------------
def test_9_dry_run_mode_performs_no_enforcement():
    settings.protection_mode = ProtectionMode.MODE_C
    settings.dry_run_mode = True # Dry-run active

    ip = "198.51.100.105"
    raw_event = {"src_ip": ip, "category": ThreatCategory.PORT_SCAN, "ids_severity": 80.0}
    threat_detector.process_event(raw_event)
    ev = threat_detector.process_event({"src_ip": ip, "category": ThreatCategory.BRUTE_FORCE, "ids_severity": 85.0})

    result = response_engine.process_threat(ev)
    assert result["dry_run"] is True
    assert result["execution_status"] == "DRY_RUN"

    # Live firewall must not contain this rule
    check = linux_firewall.verify_rule_exists(ip)
    assert check["verified"] is False

# ------------------------------------------------------------------------------
# Test 10: Firewall failures are reported honestly
# ------------------------------------------------------------------------------
def test_10_firewall_failures_are_reported_honestly():
    # Simulate a broken firewall manager by overriding executor to fail
    class FailingFirewall:
        def verify_rule_exists(self, ip, direction="INBOUND"):
            return {"verified": False, "in_kernel": False, "details": "Simulated hardware kernel failure"}

    import response.response_verifier
    orig = response.response_verifier.linux_firewall
    response.response_verifier.linux_firewall = FailingFirewall()

    try:
        ver = response.response_verifier.response_verifier.verify_action(
            action_id=1,
            target="198.51.100.111",
            action_type="BLOCK_SOURCE_IP",
            dry_run=False
        )
        assert ver["verified"] is False
        assert ver["status"] == "FAILED"
        assert "CRITICAL VERIFICATION FAILURE" in ver["details"]
    finally:
        response.response_verifier.linux_firewall = orig

# ------------------------------------------------------------------------------
# Test 11: ESP32 disconnection does not stop monitoring
# ------------------------------------------------------------------------------
def test_11_esp32_disconnection_does_not_stop_monitoring():
    esp32_controller.last_heartbeat_time = time.time() - 100 # Heartbeat expired long ago
    health = esp32_controller.check_connection_health()

    assert health["connected"] is False
    assert health["monitoring_state"] == "ACTIVE_UNINTERRUPTED"

    # Monitoring continues unaffected
    ev = threat_detector.process_event({"src_ip": "198.51.100.120", "ids_severity": 50.0})
    assert ev["risk_score"] > 0

# ------------------------------------------------------------------------------
# Test 12: Gateway-mode failure triggers a recovery procedure
# ------------------------------------------------------------------------------
def test_12_gateway_mode_failure_triggers_recovery():
    settings.gateway_mode = GatewayMode.AUTHORIZED_GATEWAY
    rec = raspberry_pi_manager.run_gateway_recovery()

    assert rec["recovery_executed"] is True
    assert rec["status"] == "PASSIVE_MONITOR_RESTORED"
    assert settings.gateway_mode == GatewayMode.PASSIVE_MONITOR

# ------------------------------------------------------------------------------
# Test 13: Emergency stop prevents new automated actions
# ------------------------------------------------------------------------------
def test_13_emergency_stop_prevents_new_automated_actions():
    settings.protection_mode = ProtectionMode.MODE_C

    # Activate emergency stop
    em_res = rollback_manager.emergency_stop(operator="TEST_ADMIN")
    assert em_res["emergency_stop_active"] is True
    assert settings.emergency_stop_active is True

    # Try processing high severity threat
    raw_event = {"src_ip": "198.51.100.130", "category": ThreatCategory.BRUTE_FORCE, "ids_severity": 99.0}
    ev = threat_detector.process_event(raw_event)
    res = response_engine.process_threat(ev)

    assert res["status"] == "MONITORED_ONLY"
    assert "EMERGENCY STOP ACTIVE" in res["reason"]

    # Clear emergency stop
    rollback_manager.clear_emergency_stop(operator="TEST_ADMIN")
    assert settings.emergency_stop_active is False

# ------------------------------------------------------------------------------
# Test 14: Rollback restores the expected previous state
# ------------------------------------------------------------------------------
def test_14_rollback_restores_expected_previous_state():
    settings.protection_mode = ProtectionMode.MODE_C
    settings.dry_run_mode = False

    ip = "198.51.100.140"
    threat_detector.process_event({"src_ip": ip, "ids_severity": 80.0})
    ev = threat_detector.process_event({"src_ip": ip, "category": ThreatCategory.BRUTE_FORCE, "ids_severity": 90.0})
    res = response_engine.process_threat(ev)

    uuid = res["action_uuid"]
    assert linux_firewall.verify_rule_exists(ip)["verified"] is True

    # Execute rollback
    rb = rollback_manager.rollback_action(uuid, reason="TEST_ROLLBACK")
    assert rb["success"] is True

    # Verify firewall rule is gone
    assert linux_firewall.verify_rule_exists(ip)["verified"] is False

# ------------------------------------------------------------------------------
# Test 15: A failed enforcement action is never reported as a successful block
# ------------------------------------------------------------------------------
def test_15_failed_enforcement_never_reported_as_successful():
    settings.protection_mode = ProtectionMode.MODE_C
    settings.dry_run_mode = False

    # Mock firewall execution to fail
    orig_apply = linux_firewall.apply_temporary_block
    linux_firewall.apply_temporary_block = lambda *args, **kwargs: {"success": False, "error": "Hardware kernel fault"}

    try:
        ip = "198.51.100.150"
        threat_detector.process_event({"src_ip": ip, "ids_severity": 80.0})
        ev = threat_detector.process_event({"src_ip": ip, "category": ThreatCategory.BRUTE_FORCE, "ids_severity": 90.0})
        res = response_engine.process_threat(ev)

        assert res["verified"] is False
        assert res["outcome_status"] != "VERIFIED_BLOCKED"
        assert res["outcome_status"] == "ENFORCEMENT_FAILED"
    finally:
        linux_firewall.apply_temporary_block = orig_apply
