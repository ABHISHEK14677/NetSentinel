"""
NetSentinel - Threat Detector
Implements Section 14.2 Threat Detection Categories:
- PORT_SCAN
- BRUTE_FORCE
- DOS_RATE_ANOMALY
- SUSPICIOUS_DNS
- MALWARE_C2
- UNEXPECTED_OUTBOUND
- DATA_EXFILTRATION
- UNAUTHORIZED_DEVICE
- THREAT_INTEL_MATCH
- AI_ANOMALY
- REPEATED_IDS_ALERT
"""

import time
import uuid
from typing import Dict, Any, List, Optional
from threat_engine.threat_intel import threat_intel_service
from threat_engine.correlator import threat_correlator, CorrelatedThreatIncident
from threat_engine.risk_scorer import risk_scorer
from threat_engine.device_inventory import device_inventory_manager

class ThreatCategory:
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE = "BRUTE_FORCE"
    DOS_RATE_ANOMALY = "DOS_RATE_ANOMALY"
    SUSPICIOUS_DNS = "SUSPICIOUS_DNS"
    MALWARE_C2 = "MALWARE_C2"
    UNEXPECTED_OUTBOUND = "UNEXPECTED_OUTBOUND"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    UNAUTHORIZED_DEVICE = "UNAUTHORIZED_DEVICE"
    THREAT_INTEL_MATCH = "THREAT_INTEL_MATCH"
    AI_ANOMALY = "AI_ANOMALY"
    REPEATED_IDS_ALERT = "REPEATED_IDS_ALERT"

class ThreatDetector:
    """
    Ingests raw network events, telemetry, Suricata/Snort alerts, or AI model scores,
    classifies them into threat categories, passes them to correlator and risk scorer.
    """

    def process_event(self, raw_event: Dict[str, Any], is_protected_asset_cb=None) -> Dict[str, Any]:
        """
        Processes an event, correlates with prior indicators, evaluates risk,
        and outputs a unified threat evaluation.
        """
        category = raw_event.get("category", ThreatCategory.REPEATED_IDS_ALERT)
        src_ip = raw_event.get("src_ip", "0.0.0.0")
        dst_ip = raw_event.get("dst_ip", "0.0.0.0")
        src_mac = raw_event.get("src_mac")
        domain = raw_event.get("domain")
        ids_sev = float(raw_event.get("ids_severity", 20.0))
        ai_score = float(raw_event.get("ai_anomaly_score", 0.0))
        confidence = float(raw_event.get("confidence", 0.8))

        # Check threat intel for destination or source
        target_indicator = domain if domain else (dst_ip if dst_ip != "0.0.0.0" else src_ip)
        intel_info = threat_intel_service.check_indicator(target_indicator)
        if intel_info and intel_info.get("is_valid"):
            raw_event["threat_intel_match"] = target_indicator

        # Register or update device inventory if LAN source
        if src_ip and not src_ip.startswith("127."):
            device_inventory_manager.register_or_update_device(
                ip_address=src_ip,
                mac_address=src_mac,
                hostname=raw_event.get("hostname"),
                interface=raw_event.get("interface", "eth0"),
                observed_protocol=raw_event.get("proto", "TCP"),
                risk_increment=ids_sev * 0.1
            )

        # Correlate incident
        incident: CorrelatedThreatIncident = threat_correlator.ingest_event(raw_event)

        # Check if target is on protected allowlist
        is_protected = False
        if is_protected_asset_cb:
            is_protected = is_protected_asset_cb(src_ip) or is_protected_asset_cb(dst_ip)

        # Calculate risk score
        risk_result = risk_scorer.compute_risk(
            category=category,
            ids_severity=incident.max_ids_severity,
            event_frequency=incident.event_count,
            correlated_indicators_count=incident.indicator_count,
            target_indicator=target_indicator,
            ai_anomaly_score=incident.max_ai_anomaly,
            confidence=confidence,
            evidence_freshness_seconds=time.time() - incident.last_seen,
            is_protected_asset=is_protected
        )

        return {
            "incident_id": incident.incident_key,
            "category": category,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "domain": domain,
            "src_mac": src_mac,
            "event_count": incident.event_count,
            "indicator_count": incident.indicator_count,
            "is_multi_indicator": incident.is_multi_indicator,
            "categories_involved": list(incident.categories),
            "risk_score": risk_result["risk_score"],
            "severity": risk_result["severity"],
            "confidence": risk_result["confidence"],
            "recommended_action": risk_result["recommended_action"],
            "can_execute_critical_block": risk_result["can_execute_critical_block"],
            "evidence_breakdown": risk_result["evidence_breakdown"],
            "timestamp": time.time(),
            "raw_event": raw_event
        }

threat_detector = ThreatDetector()
