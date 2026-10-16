"""
NetSentinel - Response Engine
Implements the 11-Step Complete Protection Workflow (Section 14.11)
and Orchestrates Policy, Execution, Verification, Rollback, and Audit Logging (Section 14.4).
"""

import uuid
import json
import time
import datetime
import logging
from typing import Dict, Any, Optional

from config.config import settings, ProtectionMode
from database.models import ResponseActionModel, BlockedTargetModel
from database.db_service import SessionLocal
from response.response_policy import response_policy_engine, ResponseDecision
from response.action_registry import action_registry
from response.linux_firewall import linux_firewall
from response.gateway_blocker import gateway_blocker
from response.dns_protection import dns_protection
from response.device_quarantine import device_quarantine_manager
from response.connection_limiter import connection_limiter
from response.response_verifier import response_verifier
from response.approval_manager import approval_manager
from response.notification_service import notification_service
from response.audit_logger import audit_logger

logger = logging.getLogger("netsentinel.response_engine")

class ResponseEngine:
    """
    Central coordinator executing Section 14.11 11-Step Protection Lifecycle.
    """

    def process_threat(self, threat_evaluation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes complete response workflow for an evaluated threat.
        """
        action_uuid = str(uuid.uuid4())
        target = threat_evaluation.get("src_ip") or threat_evaluation.get("dst_ip") or threat_evaluation.get("domain") or "UNKNOWN"
        risk_score = threat_evaluation.get("risk_score", 0.0)
        confidence = threat_evaluation.get("confidence", 0.8)
        severity = threat_evaluation.get("severity", "Informational")
        category = threat_evaluation.get("category", "REPEATED_IDS_ALERT")
        triggering_event = json.dumps(threat_evaluation.get("raw_event", {}))
        evidence_json = json.dumps(threat_evaluation.get("evidence_breakdown", {}))

        # STEP 1: Validate the evidence
        if not target or target in ["0.0.0.0", "UNKNOWN"]:
            return {
                "action_uuid": action_uuid,
                "status": "SKIPPED",
                "reason": "Invalid or missing threat target."
            }

        # Check idempotency: If this target already has an active block, skip redundant rule creation
        if action_registry.is_action_already_active(target, "BLOCK_SOURCE_IP"):
            return {
                "action_uuid": action_uuid,
                "target": target,
                "status": "IDEMPOTENT_SKIPPED",
                "message": f"Target {target} already has an active enforcement restriction. Skipping redundant rule creation."
            }

        # STEP 2: Evaluate the response policy
        # STEP 3: Check target against allowlists and protected infrastructure (inside policy evaluator)
        # STEP 4: Confirm that the action is permitted in the current protection mode
        decision: ResponseDecision = response_policy_engine.evaluate_response(threat_evaluation)

        # Notify operator of detection
        notification_service.send_alert(
            severity=severity,
            title=f"Threat Detected: {category}",
            message=f"Target: {target} (Risk Score: {risk_score}) - Policy: {decision.reason}",
            target=target,
            risk_score=risk_score
        )

        # If policy prevents action (e.g. Mode A, or Protected Infrastructure)
        if not decision.can_execute and not decision.requires_approval:
            self._record_action_in_db(
                action_uuid=action_uuid,
                target=target,
                action_type=decision.action_type,
                risk_score=risk_score,
                confidence=confidence,
                threat_category=category,
                triggering_event=triggering_event,
                evidence_json=evidence_json,
                protection_mode=settings.protection_mode.value,
                authorization_status="POLICY_BLOCKED",
                dry_run=True,
                execution_status="SKIPPED",
                execution_details=decision.reason,
                verification_status="NOT_APPLICABLE",
                duration_seconds=0
            )
            return {
                "action_uuid": action_uuid,
                "target": target,
                "protection_mode": settings.protection_mode.value,
                "status": "MONITORED_ONLY",
                "reason": decision.reason,
                "enforced": False
            }

        # STEP 5: Preview or request approval when required (Assisted Mode B)
        rule_preview = linux_firewall.format_proposed_rule(target, decision.action_type, decision.duration_seconds)
        if decision.requires_approval:
            req = approval_manager.create_approval_request(
                action_uuid=action_uuid,
                target=target,
                action_type=decision.action_type,
                risk_score=risk_score,
                severity=severity,
                proposed_rule=rule_preview["nftables_command"],
                potential_impact=rule_preview["scope_description"],
                duration_seconds=decision.duration_seconds
            )
            self._record_action_in_db(
                action_uuid=action_uuid,
                target=target,
                action_type=decision.action_type,
                risk_score=risk_score,
                confidence=confidence,
                threat_category=category,
                triggering_event=triggering_event,
                evidence_json=evidence_json,
                protection_mode=settings.protection_mode.value,
                authorization_status="PENDING_APPROVAL",
                dry_run=False,
                execution_status="PENDING",
                execution_details="Awaiting operator sign-off in Assisted Protection mode",
                verification_status="UNVERIFIED",
                duration_seconds=decision.duration_seconds
            )
            return {
                "action_uuid": action_uuid,
                "target": target,
                "protection_mode": settings.protection_mode.value,
                "status": "AWAITING_APPROVAL",
                "request_uuid": req.request_uuid,
                "proposed_rule": rule_preview["nftables_command"],
                "potential_impact": rule_preview["scope_description"],
                "duration_seconds": decision.duration_seconds
            }

        # Dry-Run Mode check: If global dry-run toggle is active, preview only (Section 14.6)
        is_dry_run = settings.dry_run_mode

        # STEP 6: Apply the supported action
        exec_result = self._execute_action(target, decision.action_type, decision.duration_seconds, is_dry_run)
        exec_status = "DRY_RUN" if is_dry_run else ("SUCCESS" if exec_result.get("success") else "FAILED")

        # Record in DB first to get action_id for verification record
        action_record = self._record_action_in_db(
            action_uuid=action_uuid,
            target=target,
            action_type=decision.action_type,
            risk_score=risk_score,
            confidence=confidence,
            threat_category=category,
            triggering_event=triggering_event,
            evidence_json=evidence_json,
            protection_mode=settings.protection_mode.value,
            authorization_status="AUTO_AUTHORIZED",
            dry_run=is_dry_run,
            execution_status=exec_status,
            execution_details=json.dumps(exec_result),
            verification_status="PENDING",
            duration_seconds=decision.duration_seconds
        )

        # STEP 7: Verify that the intended rule or restriction exists
        # STEP 8: Record success or failure (honest reporting)
        ver_result = response_verifier.verify_action(
            action_id=action_record.id,
            target=target,
            action_type=decision.action_type,
            dry_run=is_dry_run
        )

        # Register in active action cache & active blocked targets table
        if exec_status == "SUCCESS" and ver_result.get("verified"):
            action_registry.register_active_action(target, decision.action_type, action_uuid, decision.duration_seconds)
            self._record_blocked_target(target, category, risk_score, decision.duration_seconds, action_uuid)

        # STEP 9 & 10: Automatic expiry is handled by RollbackManager and timed nftables sets.
        # STEP 11: Notify operator of outcome
        outcome_status = "VERIFIED_BLOCKED" if ver_result.get("verified") and not is_dry_run else ("DRY_RUN_PREVIEW" if is_dry_run else "ENFORCEMENT_FAILED")
        notification_service.send_alert(
            severity="High" if outcome_status == "VERIFIED_BLOCKED" else "Medium",
            title=f"Response Action: {decision.action_type} -> {outcome_status}",
            message=f"Target: {target} | Status: {outcome_status} | Reason: {decision.reason}",
            target=target,
            risk_score=risk_score,
            action_taken=decision.action_type
        )

        # Tamper-evident audit log
        audit_logger.log_event(
            event_type="RESPONSE_EXECUTION",
            details=f"Executed {decision.action_type} on target {target}. Result: {outcome_status}. Duration: {decision.duration_seconds}s.",
            result=outcome_status,
            operator="SYSTEM_ENGINE",
            policy_name=category,
            target=target
        )

        return {
            "action_uuid": action_uuid,
            "target": target,
            "action_type": decision.action_type,
            "execution_status": exec_status,
            "verification_status": ver_result.get("status"),
            "verified": ver_result.get("verified", False),
            "outcome_status": outcome_status,
            "dry_run": is_dry_run,
            "duration_seconds": decision.duration_seconds,
            "details": exec_result
        }

    def execute_approved_action(self, action_uuid: str, operator: str = "ADMIN") -> Dict[str, Any]:
        """
        Executes an action that was approved by a human operator in Assisted mode.
        """
        db = SessionLocal()
        try:
            action = db.query(ResponseActionModel).filter_by(action_uuid=action_uuid).first()
            if not action:
                return {"success": False, "error": f"Action UUID {action_uuid} not found."}

            target = action.target
            action_type = action.action_type
            duration_seconds = settings.default_block_duration_seconds
            if action.expires_at and action.created_at:
                duration_seconds = int((action.expires_at - action.created_at).total_seconds())

            is_dry_run = settings.dry_run_mode

            exec_result = self._execute_action(target, action_type, duration_seconds, is_dry_run)
            exec_status = "DRY_RUN" if is_dry_run else ("SUCCESS" if exec_result.get("success") else "FAILED")

            action.authorization_status = "APPROVED"
            action.authorized_by = operator
            action.authorized_at = datetime.datetime.utcnow()
            action.execution_status = exec_status
            action.execution_details = json.dumps(exec_result)

            db.commit()

            # Verify
            ver_result = response_verifier.verify_action(
                action_id=action.id,
                target=target,
                action_type=action_type,
                dry_run=is_dry_run
            )

            if exec_status == "SUCCESS" and ver_result.get("verified"):
                action_registry.register_active_action(target, action_type, action_uuid, duration_seconds)
                self._record_blocked_target(target, action.threat_category, action.risk_score, duration_seconds, action_uuid)

            outcome_status = "VERIFIED_BLOCKED" if ver_result.get("verified") and not is_dry_run else ("DRY_RUN_PREVIEW" if is_dry_run else "ENFORCEMENT_FAILED")

            audit_logger.log_event(
                event_type="APPROVED_EXECUTION",
                details=f"Approved action {action_uuid} executed by {operator} on {target}. Outcome: {outcome_status}",
                result=outcome_status,
                operator=operator,
                target=target
            )

            return {
                "success": ver_result.get("verified", False),
                "action_uuid": action_uuid,
                "target": target,
                "outcome_status": outcome_status,
                "verification": ver_result
            }
        finally:
            db.close()

    def _execute_action(self, target: str, action_type: str, duration_seconds: int, dry_run: bool) -> Dict[str, Any]:
        """
        Dispatches action to the appropriate adapter.
        """
        if action_type == "BLOCK_SOURCE_IP":
            return linux_firewall.apply_temporary_block(target, duration_seconds=duration_seconds, direction="INBOUND", dry_run=dry_run)
        elif action_type == "RESTRICT_OUTBOUND" or action_type == "BLOCK_MALICIOUS_DEST":
            return linux_firewall.apply_temporary_block(target, duration_seconds=duration_seconds, direction="OUTBOUND", dry_run=dry_run)
        elif action_type == "RATE_LIMIT":
            return connection_limiter.apply_rate_limit(target, rate_per_sec=5, duration_seconds=duration_seconds, dry_run=dry_run)
        elif action_type == "DNS_BLOCK":
            return dns_protection.block_domain(target, duration_seconds=duration_seconds, dry_run=dry_run)
        elif action_type == "ISOLATE_DEVICE":
            return device_quarantine_manager.quarantine_device(mac_address=target, ip_address=target, duration_seconds=duration_seconds, dry_run=dry_run)
        else:
            return {"success": False, "error": f"Unsupported action type: {action_type}"}

    def _record_action_in_db(self, **kwargs) -> ResponseActionModel:
        db = SessionLocal()
        try:
            duration = kwargs.pop("duration_seconds", 300)
            now = datetime.datetime.utcnow()
            expires = now + datetime.timedelta(seconds=duration) if duration > 0 else None

            action = ResponseActionModel(
                action_uuid=kwargs.get("action_uuid"),
                target=kwargs.get("target"),
                action_type=kwargs.get("action_type"),
                risk_score=kwargs.get("risk_score"),
                confidence=kwargs.get("confidence"),
                threat_category=kwargs.get("threat_category"),
                triggering_event=kwargs.get("triggering_event"),
                evidence_json=kwargs.get("evidence_json"),
                protection_mode=kwargs.get("protection_mode"),
                authorization_status=kwargs.get("authorization_status"),
                dry_run=kwargs.get("dry_run", False),
                execution_status=kwargs.get("execution_status"),
                execution_details=kwargs.get("execution_details"),
                verification_status=kwargs.get("verification_status"),
                created_at=now,
                expires_at=expires,
                is_active=True
            )
            db.add(action)
            db.commit()
            db.refresh(action)
            return action
        finally:
            db.close()

    def _record_blocked_target(self, target: str, reason: str, risk_score: float, duration_seconds: int, action_uuid: str):
        db = SessionLocal()
        try:
            now = datetime.datetime.utcnow()
            expires = now + datetime.timedelta(seconds=duration_seconds)
            bt = db.query(BlockedTargetModel).filter_by(target=target).first()
            if not bt:
                bt = BlockedTargetModel(
                    target=target,
                    reason=reason,
                    risk_score=risk_score,
                    blocked_at=now,
                    expires_at=expires,
                    is_active=True,
                    action_uuid=action_uuid
                )
                db.add(bt)
            else:
                bt.is_active = True
                bt.expires_at = expires
                bt.blocked_at = now
                bt.unblocked_at = None
                bt.reason = reason
            db.commit()
        finally:
            db.close()

response_engine = ResponseEngine()
