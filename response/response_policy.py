"""
NetSentinel - Response Policy Evaluation Engine
Implements Section 14.5 Protection Modes (Modes A, B, C, D) & Section 14.11 Policy Safeguards.
Checks allowlists, protected infrastructure, evidence confidence, and correlation rules.
"""

from typing import Dict, Any, List, Optional
from config.config import settings, ProtectionMode
from database.models import AllowlistedAssetModel
from database.db_service import SessionLocal

class ResponseDecision:
    def __init__(
        self,
        can_execute: bool,
        requires_approval: bool,
        action_type: str,
        reason: str,
        duration_seconds: int = 300,
        is_dry_run: bool = False
    ):
        self.can_execute = can_execute
        self.requires_approval = requires_approval
        self.action_type = action_type
        self.reason = reason
        self.duration_seconds = duration_seconds
        self.is_dry_run = is_dry_run

class ResponsePolicyEngine:
    """
    Evaluates threat indicators against configured protection mode and safety boundaries.
    """

    def is_protected_asset(self, target: str) -> bool:
        """
        Safeguard check (Section 14.11): Checks if target is default gateway,
        localhost, DNS server, or allowlisted management address.
        """
        # Hardcoded critical local loopbacks
        if target in ["127.0.0.1", "::1", "localhost", "0.0.0.0"]:
            return True

        db = SessionLocal()
        try:
            # Check exact match
            asset = db.query(AllowlistedAssetModel).filter_by(asset_value=target).first()
            if asset:
                return True

            # Check subnet matches (e.g. 127.0.0.0/8)
            subnets = db.query(AllowlistedAssetModel).filter_by(asset_type="SUBNET").all()
            import ipaddress
            try:
                target_ip = ipaddress.ip_address(target)
                for s in subnets:
                    if target_ip in ipaddress.ip_network(s.asset_value, strict=False):
                        return True
            except ValueError:
                pass

            return False
        finally:
            db.close()

    def evaluate_response(self, threat_evaluation: Dict[str, Any]) -> ResponseDecision:
        """
        Evaluates the threat according to Section 14.5 rules:
        - Mode A (Monitor Only): NEVER alter traffic or rules.
        - Mode B (Assisted Protection): Recommend action, requires human approval.
        - Mode C (Automatic Temporary): Auto apply low/medium risk actions if not protected, require expiry.
        - Mode D (Strict Prevention): Enforce strict firewall policies on supported boundary.
        """
        current_mode = settings.protection_mode
        target = threat_evaluation.get("src_ip") or threat_evaluation.get("dst_ip") or threat_evaluation.get("domain")
        risk_score = threat_evaluation.get("risk_score", 0.0)
        severity = threat_evaluation.get("severity", "Informational")
        is_multi_indicator = threat_evaluation.get("is_multi_indicator", False)
        can_crit_block = threat_evaluation.get("can_execute_critical_block", True)
        category = threat_evaluation.get("category", "")

        # Emergency Stop Check
        if settings.emergency_stop_active:
            return ResponseDecision(
                can_execute=False,
                requires_approval=False,
                action_type="NONE",
                reason="EMERGENCY STOP ACTIVE: All automated responses are disabled."
            )

        # Allowlist / Protected Infrastructure Safeguard (14.11)
        if target and self.is_protected_asset(target):
            return ResponseDecision(
                can_execute=False,
                requires_approval=False,
                action_type="NONE",
                reason=f"Target {target} is protected infrastructure or allowlisted. Enforcement prohibited."
            )

        # Determine proposed action type based on category
        if category in ["PORT_SCAN", "DOS_RATE_ANOMALY"]:
            proposed_action = "RATE_LIMIT"
            default_duration = 300
        elif category in ["MALWARE_C2", "SUSPICIOUS_DNS"] and threat_evaluation.get("domain"):
            proposed_action = "DNS_BLOCK"
            default_duration = 1800
        elif category in ["UNAUTHORIZED_DEVICE"]:
            proposed_action = "ISOLATE_DEVICE"
            default_duration = 900
        else:
            proposed_action = "BLOCK_SOURCE_IP"
            default_duration = settings.default_block_duration_seconds

        # MODE A: MONITOR ONLY
        # Section 14.5: "Never alter network traffic or firewall rules."
        if current_mode == ProtectionMode.MODE_A:
            return ResponseDecision(
                can_execute=False,
                requires_approval=False,
                action_type="NONE",
                reason="Mode A (Monitor Only) active. Network traffic and firewall rules will never be modified.",
                is_dry_run=True
            )

        # MODE B: ASSISTED PROTECTION
        # Section 14.5: "Require operator approval before applying blocking or isolation."
        if current_mode == ProtectionMode.MODE_B:
            # Low severity / informational doesn't warrant blocking approval
            if risk_score <= settings.score_low_max:
                return ResponseDecision(
                    can_execute=False,
                    requires_approval=False,
                    action_type="LOG_ONLY",
                    reason="Assisted Mode: Risk score below threshold for intervention."
                )
            return ResponseDecision(
                can_execute=False,
                requires_approval=True,
                action_type=proposed_action,
                duration_seconds=default_duration,
                reason=f"Assisted Mode: Recommended response {proposed_action} generated. Awaiting operator approval."
            )

        # MODE C: AUTOMATIC TEMPORARY PROTECTION
        # Section 14.5: "Automatically apply predefined, low-risk protective policies. Restrict to configured targets. Mandatory expiry."
        if current_mode == ProtectionMode.MODE_C:
            # High-impact actions require multi-indicator correlation (Section 14.2 & 14.5)
            if severity == "Critical" and not is_multi_indicator:
                # Without multi-indicator correlation, downgrade to Assisted approval
                return ResponseDecision(
                    can_execute=False,
                    requires_approval=True,
                    action_type=proposed_action,
                    duration_seconds=default_duration,
                    reason="Mode C: Critical single-indicator event requires multi-indicator confirmation or manual approval."
                )

            # AI anomalies alone cannot execute critical block (Section 14.3)
            if not can_crit_block and severity == "Critical":
                return ResponseDecision(
                    can_execute=False,
                    requires_approval=True,
                    action_type=proposed_action,
                    duration_seconds=default_duration,
                    reason="Mode C: AI anomaly score alone cannot authorize critical blocking. Operator approval required."
                )

            if risk_score >= settings.score_low_max:
                return ResponseDecision(
                    can_execute=True,
                    requires_approval=False,
                    action_type=proposed_action,
                    duration_seconds=min(default_duration, settings.max_block_duration_seconds),
                    reason=f"Mode C: Automatic temporary protection triggered (Score: {risk_score}). Mandatory expiry: {default_duration}s."
                )
            else:
                return ResponseDecision(
                    can_execute=False,
                    requires_approval=False,
                    action_type="MONITOR",
                    reason="Mode C: Risk score low. Monitored without intervention."
                )

        # MODE D: STRICT PREVENTION
        # Section 14.5: "Apply explicitly configured firewall policies to supported traffic paths."
        if current_mode == ProtectionMode.MODE_D:
            if not can_crit_block and severity == "Critical":
                return ResponseDecision(
                    can_execute=False,
                    requires_approval=True,
                    action_type=proposed_action,
                    duration_seconds=default_duration,
                    reason="Mode D: AI anomaly alone cannot trigger critical prevention without verified threat signature."
                )

            return ResponseDecision(
                can_execute=True,
                requires_approval=False,
                action_type=proposed_action,
                duration_seconds=default_duration,
                reason=f"Mode D: Strict prevention policy active. Enforcing boundary protection on target {target}."
            )

        # Fallback safe default
        return ResponseDecision(
            can_execute=False,
            requires_approval=False,
            action_type="NONE",
            reason="Protection mode unrecognized or unconfigured. Defaulting to safe monitor-only."
        )

response_policy_engine = ResponsePolicyEngine()
