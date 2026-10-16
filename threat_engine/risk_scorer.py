"""
NetSentinel - Threat Risk Scoring Engine
Implements Section 14.3 Risk Evaluation and Scoring Rules.
"""

from typing import Dict, Any, List, Optional
from config.config import settings
from threat_engine.threat_intel import threat_intel_service

class SeverityBand:
    INFORMATIONAL = "Informational" # 0-19
    LOW = "Low"                     # 20-39
    MEDIUM = "Medium"               # 40-59
    HIGH = "High"                   # 60-79
    CRITICAL = "Critical"           # 80-100

class RiskScorer:
    """
    Evaluates:
    - IDS signature severity (0-100 scale)
    - Frequency of suspicious events
    - Number of correlated indicators
    - Destination reputation via verified threat intel
    - AI anomaly score (0-100 scale)
    - Confidence and freshness of evidence
    - Asset criticality and exceptions
    """

    def __init__(self):
        # Weights for multi-factor correlation
        self.w_ids = 0.35
        self.w_freq = 0.20
        self.w_intel = 0.25
        self.w_anomaly = 0.20

    def compute_risk(
        self,
        category: str,
        ids_severity: float = 0.0,       # 0.0 to 100.0
        event_frequency: int = 1,        # Event count in time window
        correlated_indicators_count: int = 1,
        target_indicator: Optional[str] = None,
        ai_anomaly_score: float = 0.0,   # 0.0 to 100.0
        confidence: float = 0.7,         # 0.0 to 1.0
        evidence_freshness_seconds: float = 0.0,
        is_protected_asset: bool = False
    ) -> Dict[str, Any]:
        """
        Calculates normalized risk score (0-100), severity band, evidence breakdown,
        and recommended protective action.
        """
        # Asset exception safeguard: Protected assets cannot have severe response actions
        if is_protected_asset:
            return {
                "risk_score": 0.0,
                "severity": SeverityBand.INFORMATIONAL,
                "confidence": 1.0,
                "recommended_action": "NO_ACTION_ALLOWLISTED",
                "evidence_breakdown": {
                    "reason": "Target is on allowlist / protected infrastructure",
                    "ids_score": 0.0,
                    "intel_score": 0.0,
                    "ai_score": 0.0
                },
                "can_execute_critical_block": False
            }

        # 1. Frequency Score component (asymptotic curve up to 100)
        # 1 event = 20, 5 events = 60, 10+ events = 90-100
        freq_factor = min(100.0, (event_frequency * 8.0) + (correlated_indicators_count * 12.0))

        # 2. Destination Reputation / Threat Intel
        intel_score = 0.0
        intel_valid = False
        intel_fresh = False
        intel_source = "None"

        if target_indicator:
            intel = threat_intel_service.check_indicator(target_indicator)
            if intel:
                intel_source = intel["source"]
                intel_fresh = intel["is_fresh"]
                if intel["is_valid"]: # fresh and confident
                    intel_score = intel["reputation_score"] * 100.0
                    intel_valid = True
                elif not intel_fresh:
                    # Explicitly flag stale intel - do not use it to inflate score
                    intel_score = 0.0
                    intel_valid = False

        # 3. Evidence Freshness Decay: if evidence is older than 15 minutes, decay by up to 40%
        freshness_decay = 1.0
        if evidence_freshness_seconds > 900:
            freshness_decay = max(0.5, 1.0 - ((evidence_freshness_seconds - 900) / 3600.0))

        # 4. Raw Score Weighted Combination
        # If no threat intel available, re-normalize between IDS, frequency, anomaly
        if intel_score > 0:
            raw_score = (
                (ids_severity * self.w_ids) +
                (freq_factor * self.w_freq) +
                (intel_score * self.w_intel) +
                (ai_anomaly_score * self.w_anomaly)
            )
        else:
            w_sum = self.w_ids + self.w_freq + self.w_anomaly
            raw_score = (
                (ids_severity * (self.w_ids / w_sum)) +
                (freq_factor * (self.w_freq / w_sum)) +
                (ai_anomaly_score * (self.w_anomaly / w_sum))
            )

        # Apply confidence and freshness decay
        normalized_score = min(100.0, max(0.0, raw_score * confidence * freshness_decay))

        # 5. Core Constraint Enforcement (Section 14.3 & 14.6):
        # "AI anomalies alone must not authorize critical blocking actions."
        # If AI anomaly is the ONLY significant driver (e.g. ids_severity < 30 and no verified intel),
        # cap the score at High ceiling or restrict critical authorization.
        only_ai_driven = (ai_anomaly_score >= 70.0 and ids_severity < 30.0 and not intel_valid)
        can_execute_critical_block = True

        if only_ai_driven:
            # AI anomaly alone is capped at 65 (Medium-High) and CANNOT execute critical block
            if normalized_score > 65.0:
                normalized_score = 65.0
            can_execute_critical_block = False

        # 6. Classify Severity Band
        if normalized_score <= settings.score_informational_max:
            severity = SeverityBand.INFORMATIONAL
            recommended_action = "LOG_INFORMATIONAL"
        elif normalized_score <= settings.score_low_max:
            severity = SeverityBand.LOW
            recommended_action = "MONITOR_AND_ALERT"
        elif normalized_score <= settings.score_medium_max:
            severity = SeverityBand.MEDIUM
            recommended_action = "RATE_LIMIT_OR_OBSERVE"
        elif normalized_score <= settings.score_high_max:
            severity = SeverityBand.HIGH
            recommended_action = "TEMPORARY_BLOCK_OR_ASSISTED"
        else:
            severity = SeverityBand.CRITICAL
            if can_execute_critical_block:
                recommended_action = "IMMEDIATE_ACTIVE_BLOCK"
            else:
                recommended_action = "ASSISTED_REVIEW_REQUIRED"

        return {
            "risk_score": round(normalized_score, 1),
            "severity": severity,
            "confidence": round(confidence, 2),
            "recommended_action": recommended_action,
            "can_execute_critical_block": can_execute_critical_block,
            "evidence_breakdown": {
                "ids_severity": round(ids_severity, 1),
                "frequency_factor": round(freq_factor, 1),
                "threat_intel_score": round(intel_score, 1),
                "threat_intel_source": intel_source,
                "threat_intel_valid": intel_valid,
                "threat_intel_fresh": intel_fresh,
                "ai_anomaly_score": round(ai_anomaly_score, 1),
                "freshness_decay": round(freshness_decay, 2),
                "is_only_ai_driven": only_ai_driven
            }
        }

risk_scorer = RiskScorer()
