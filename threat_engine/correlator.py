"""
NetSentinel - Threat Correlation Engine
Implements Section 14.2 Multi-Indicator Correlation and Deduplication.
Prevents isolated events or single port scans from triggering active blocking.
"""

import time
import collections
from typing import Dict, List, Any, Optional

class CorrelatedThreatIncident:
    def __init__(self, incident_key: str, primary_ip: str):
        self.incident_key = incident_key
        self.primary_ip = primary_ip
        self.categories: set = set()
        self.events: List[Dict[str, Any]] = []
        self.first_seen: float = time.time()
        self.last_seen: float = time.time()
        self.max_ids_severity: float = 0.0
        self.max_ai_anomaly: float = 0.0
        self.threat_intel_matches: List[str] = []
        self.ports_targeted: set = set()

    def add_event(self, event: Dict[str, Any]):
        now = time.time()
        self.last_seen = now
        self.events.append(event)
        
        category = event.get("category", "UNKNOWN")
        self.categories.add(category)

        ids_sev = float(event.get("ids_severity", 0.0))
        if ids_sev > self.max_ids_severity:
            self.max_ids_severity = ids_sev

        ai_score = float(event.get("ai_anomaly_score", 0.0))
        if ai_score > self.max_ai_anomaly:
            self.max_ai_anomaly = ai_score

        intel = event.get("threat_intel_match")
        if intel and intel not in self.threat_intel_matches:
            self.threat_intel_matches.append(intel)

        dst_port = event.get("dst_port")
        if dst_port:
            self.ports_targeted.add(dst_port)

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def indicator_count(self) -> int:
        # Correlated indicator count (categories + intel matches + distinct anomalous ports)
        count = len(self.categories)
        if self.threat_intel_matches:
            count += len(self.threat_intel_matches)
        if len(self.ports_targeted) > 5:
            count += 1
        return max(1, count)

    @property
    def is_multi_indicator(self) -> bool:
        """Section 14.2: Correlate multiple indicators before taking high-impact actions."""
        return self.indicator_count >= 2 or (self.event_count >= 5 and self.max_ids_severity >= 50.0)

class ThreatCorrelator:
    """
    Maintains active correlation windows per source/destination IP.
    Aggregates disparate indicators across time to prevent single false-positive blocks.
    """

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self.active_incidents: Dict[str, CorrelatedThreatIncident] = {}
        # Deduplication tracker for exact recent alerts
        self._dedup_cache: Dict[str, float] = {}

    def is_duplicate(self, dedup_key: str, throttle_seconds: int = 10) -> bool:
        """Returns True if the identical event was received within throttle window."""
        now = time.time()
        last_time = self._dedup_cache.get(dedup_key)
        if last_time and (now - last_time) < throttle_seconds:
            return True
        self._dedup_cache[dedup_key] = now
        return False

    def ingest_event(self, event: Dict[str, Any]) -> CorrelatedThreatIncident:
        """
        Ingests an incoming detection event and returns the correlated incident context.
        """
        source_ip = event.get("src_ip", "0.0.0.0")
        target_ip = event.get("dst_ip", "0.0.0.0")
        
        # Primary correlation key: source IP (or destination for outbound C2)
        correlation_key = source_ip if source_ip not in ["0.0.0.0", "127.0.0.1"] else target_ip

        now = time.time()
        # Clean expired incidents
        expired_keys = [
            k for k, inc in self.active_incidents.items()
            if (now - inc.last_seen) > self.window_seconds
        ]
        for k in expired_keys:
            del self.active_incidents[k]

        if correlation_key not in self.active_incidents:
            self.active_incidents[correlation_key] = CorrelatedThreatIncident(correlation_key, correlation_key)

        incident = self.active_incidents[correlation_key]
        incident.add_event(event)
        return incident

threat_correlator = ThreatCorrelator()
