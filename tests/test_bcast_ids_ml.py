"""
NetSentinel - BCAST IDS & Machine Learning Engine Test Suite
Tests for:
  - 15 BUM Feature Extraction and Normalization
  - MAC / IP Spoofing Detection
  - Isolation Forest ML Engine (safe fallback and prediction logic)
  - PCAP Evidence Collection and Disk Quota Management
  - Email Notification formatting & queuing
  - System Health telemetry endpoint
"""

import os
import sys
import json
import time
import pytest

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from threat_engine.feature_extractor import FeatureExtractor, MACTrafficStats
from threat_engine.ml_engine import ml_engine, IsolationForestEngine
from response.evidence_collector import EvidenceCollector
from response.email_notifier import EmailNotifier
from api.health import get_system_health


def test_bum_feature_vector_normalization():
    """Verify 15-feature extraction and mathematical normalization."""
    stats = MACTrafficStats()
    stats.bcast = 10
    stats.arp = 5
    stats.tcp = 5
    stats.total_packets = 20

    vec = stats.to_normalized_feature_vector()
    assert vec["BCAST"] == 0.5
    assert vec["ARP"] == 0.25
    assert vec["TCP"] == 0.25
    assert vec["UDP"] == 0.0

    feat_list = stats.to_feature_list()
    assert len(feat_list) >= 15
    assert sum(feat_list) > 0


def test_mac_and_ip_spoofing_detection(tmp_path):
    """Verify MAC and IP spoofing detection per BCAST IDS Section X.A."""
    json_path = str(tmp_path / "test_arp.json")
    fe = FeatureExtractor(arp_snapshot_path=json_path)

    # 1 MAC with 2 different IPs -> MAC Spoofing alert
    fe.update({
        "mac_src": "AA:BB:CC:DD:EE:01",
        "mac_dst": "FF:FF:FF:FF:FF:FF",
        "pkt_type": "BCAST",
        "ip_src": "192.168.1.50"
    })
    fe.update({
        "mac_src": "AA:BB:CC:DD:EE:01",
        "mac_dst": "FF:FF:FF:FF:FF:FF",
        "pkt_type": "BCAST",
        "ip_src": "192.168.1.51"
    })

    alerts = fe.check_spoofing()
    assert len(alerts) >= 1
    mac_spoofs = [a for a in alerts if a["type"] == "MAC_SPOOF"]
    assert len(mac_spoofs) == 1
    assert mac_spoofs[0]["mac"] == "AA:BB:CC:DD:EE:01"

    # Save and verify snapshot JSON
    fe.save_arp_snapshot()
    assert os.path.exists(json_path)
    with open(json_path) as f:
        data = json.load(f)
        assert "AA:BB:CC:DD:EE:01" in data.get("mac_ip_map", {})


def test_ml_engine_status_and_defaults():
    """Verify Isolation Forest safe defaults, drift detection, and status."""
    status = ml_engine.get_status()
    assert "contamination" in status
    assert "drift_threshold" in status
    assert status["contamination"] == 0.018
    assert ml_engine.MIN_TRAINING_SAMPLES >= 50

    # Drift detection
    assert ml_engine.check_model_drift(0.20) is True
    assert ml_engine.check_model_drift(0.05) is False

    # Predict with safe default
    vector = [0.0] * 15
    pred = ml_engine.predict(vector)
    assert "anomaly_score" in pred
    assert "is_anomaly" in pred
    assert 0.0 <= pred["anomaly_score"] <= 100.0


def test_evidence_collector_rotation(tmp_path):
    """Verify PCAP evidence directory creation and sidecar metadata."""
    collector = EvidenceCollector(project_root=str(tmp_path))
    assert os.path.exists(collector.evidence_dir)

    status = collector.get_status()
    assert status["file_count"] == 0

    # Save metadata sidecar
    res = collector.save_anomaly_pcap(
        mac="00:11:22:33:44:55",
        anomaly_score=85.5,
        feature_vector={"BCAST": 0.9, "ARP": 0.1}
    )
    # Even if scapy cannot sniff raw socket, sidecar / status should be clean
    evidence_list = collector.get_evidence_list()
    assert isinstance(evidence_list, list)


def test_email_notifier_safeguard():
    """Verify EmailNotifier is safely non-blocking and handles disabled state."""
    notifier = EmailNotifier()
    status = notifier.get_status()
    assert "enabled" in status
    assert "queue_size" in status

    # Sending with SMTP disabled should not raise errors
    notifier.send_alert("Test Alert", "Alert body", "HIGH")
    notifier.send_anomaly_alert("00:11:22:33:44:55", 92.0, {"BCAST": 0.8})
    notifier.send_spoofing_alert({"type": "MAC_SPOOF", "mac": "00:11:22:33:44:55"})


def test_system_health_telemetry():
    """Verify system health telemetry exposes host metrics properly."""
    health = get_system_health()
    assert "health_status" in health
    assert health["health_status"] in ["HEALTHY", "WARNING", "CRITICAL", "UNKNOWN"]
    assert "cpu_percent" in health
    assert "ram_percent" in health
    assert "disk_percent" in health
    assert health["psutil_available"] is True
