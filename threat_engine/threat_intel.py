"""
NetSentinel - Threat Intelligence Validator
Validates threat feeds, destination reputations, confidence, and freshness TTL.
Ensures invalid or stale entries do not trigger active blocking (Section 14.15 #8).
"""

import time
from typing import Dict, Any, Optional

class ThreatIntelRecord:
    def __init__(self, indicator: str, indicator_type: str, reputation_score: float, confidence: float, source: str, timestamp: float, ttl_seconds: int = 3600):
        self.indicator = indicator
        self.indicator_type = indicator_type # IP, DOMAIN, HASH
        self.reputation_score = reputation_score # 0.0 (benign) to 1.0 (confirmed malicious)
        self.confidence = confidence # 0.0 to 1.0
        self.source = source
        self.timestamp = timestamp
        self.ttl_seconds = ttl_seconds

    @property
    def is_fresh(self) -> bool:
        """Checks if threat intelligence is still valid and not expired."""
        return (time.time() - self.timestamp) <= self.ttl_seconds

class ThreatIntelService:
    def __init__(self):
        self.feed_cache: Dict[str, ThreatIntelRecord] = {}
        self._seed_default_reputations()

    def _seed_default_reputations(self):
        now = time.time()
        # Seeded known malicious indicators (fresh)
        fresh_samples = [
            ("198.51.100.55", "IP", 0.95, 0.90, "AbuseIPDB_Verified", now, 7200),
            ("203.0.113.88", "IP", 0.85, 0.80, "EmergingThreats_Active", now, 7200),
            ("c2-evil-botnet.bad", "DOMAIN", 0.98, 0.95, "MalwareBazaar", now, 7200),
            ("phishing-login-update.cc", "DOMAIN", 0.90, 0.85, "OpenPhish", now, 7200),
        ]
        for ind, itype, rep, conf, src, ts, ttl in fresh_samples:
            self.feed_cache[ind] = ThreatIntelRecord(ind, itype, rep, conf, src, ts, ttl)

        # Seeded stale indicator (expired 24 hours ago) for testing 14.15 #8
        stale_ts = now - 86400 * 2
        self.feed_cache["198.51.100.99"] = ThreatIntelRecord(
            "198.51.100.99", "IP", 0.95, 0.90, "Old_Threat_Feed", stale_ts, 3600
        )

    def register_indicator(self, indicator: str, indicator_type: str, score: float, confidence: float, source: str, ttl_seconds: int = 3600):
        self.feed_cache[indicator] = ThreatIntelRecord(
            indicator, indicator_type, score, confidence, source, time.time(), ttl_seconds
        )

    def check_indicator(self, indicator: str) -> Optional[Dict[str, Any]]:
        """
        Validates indicator against threat intel.
        Returns None or {reputation, confidence, valid: True/False, stale: True/False}
        """
        if indicator not in self.feed_cache:
            return None

        record = self.feed_cache[indicator]
        is_fresh = record.is_fresh

        return {
            "indicator": record.indicator,
            "indicator_type": record.indicator_type,
            "reputation_score": record.reputation_score,
            "confidence": record.confidence,
            "source": record.source,
            "is_fresh": is_fresh,
            "is_valid": is_fresh and (record.confidence >= 0.6)
        }

threat_intel_service = ThreatIntelService()
