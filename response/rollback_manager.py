"""
NetSentinel - Rollback & Expiration Manager
Implements Section 14.11 Step 10 and Section 14.15 #7, #13, #14.
Handles automatic expiry of temporary blocks, manual single-action rollback,
and Emergency Stop global revocation.
"""

import datetime
import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from database.models import (
    ResponseActionModel, BlockedTargetModel, QuarantinedDeviceModel,
    RollbackRecordModel, DeviceInventoryModel
)
from database.db_service import SessionLocal
from response.linux_firewall import linux_firewall
from response.action_registry import action_registry
from response.audit_logger import audit_logger
from config.config import settings

logger = logging.getLogger("netsentinel.rollback")

class RollbackManager:
    """
    Manages lifecycle expiration, rollback execution, and emergency system restoration.
    """

    def process_expired_actions(self) -> int:
        """
        Scans database for expired temporary actions and revokes them safely.
        """
        db = SessionLocal()
        count = 0
        try:
            now = datetime.datetime.utcnow()
            # Find active response actions whose expiry has passed
            expired_actions = db.query(ResponseActionModel).filter(
                ResponseActionModel.is_active == True,
                ResponseActionModel.expires_at != None,
                ResponseActionModel.expires_at <= now,
                ResponseActionModel.is_rolled_back == False
            ).all()

            for act in expired_actions:
                self.rollback_action(
                    action_uuid=act.action_uuid,
                    reason="SCHEDULED_EXPIRATION",
                    operator="SYSTEM_EXPIRER",
                    db=db
                )
                count += 1

            # Check BlockedTargetModel as well
            expired_targets = db.query(BlockedTargetModel).filter(
                BlockedTargetModel.is_active == True,
                BlockedTargetModel.expires_at != None,
                BlockedTargetModel.expires_at <= now
            ).all()

            for bt in expired_targets:
                bt.is_active = False
                bt.unblocked_at = now
                bt.unblocked_by = "SYSTEM_EXPIRER"
                linux_firewall.remove_rule(bt.target)
                action_registry.deregister_action(bt.target, "BLOCK_SOURCE_IP")

            db.commit()
            return count
        finally:
            db.close()

    def rollback_action(
        self,
        action_uuid: str,
        reason: str = "MANUAL_OPERATOR_ROLLBACK",
        operator: str = "ADMIN",
        db: Optional[Session] = None
    ) -> Dict[str, Any]:
        """
        Rolls back a specific protective action by UUID.
        """
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True

        try:
            action = db.query(ResponseActionModel).filter_by(action_uuid=action_uuid).first()
            if not action:
                return {"success": False, "error": f"Action UUID {action_uuid} not found."}

            if action.is_rolled_back:
                return {"success": True, "message": "Action was already rolled back."}

            now = datetime.datetime.utcnow()
            target = action.target
            action_type = action.action_type

            # 1. Revert firewall rule if applicable
            fw_res = None
            if not action.dry_run:
                if action_type in ["BLOCK_SOURCE_IP", "RATE_LIMIT", "SUPPRESS_CONNECTION"]:
                    fw_res = linux_firewall.remove_rule(target, direction=action.direction or "INBOUND")
                elif action_type in ["RESTRICT_OUTBOUND", "BLOCK_MALICIOUS_DEST"]:
                    fw_res = linux_firewall.remove_rule(target, direction="OUTBOUND")

            # 2. De-register from action registry cache
            action_registry.deregister_action(target, action_type)

            # 3. Update database records
            action.is_active = False
            action.is_rolled_back = True
            action.rolled_back_at = now
            action.rollback_reason = reason

            # Update BlockedTargetModel if exists
            bt = db.query(BlockedTargetModel).filter_by(target=target, is_active=True).first()
            if bt:
                bt.is_active = False
                bt.unblocked_at = now
                bt.unblocked_by = operator

            # Record in RollbackRecordModel
            rec = RollbackRecordModel(
                action_uuid=action_uuid,
                target=target,
                action_type=action_type,
                reason=reason,
                initiated_by=operator,
                success=True,
                details=f"Reverted {action_type} on target {target}. Firewall result: {fw_res}",
                timestamp=now
            )
            db.add(rec)

            # Tamper-evident audit log
            audit_logger.log_event(
                event_type="ROLLBACK",
                details=f"Rolled back action {action_uuid} on target {target}. Reason: {reason}",
                result="SUCCESS",
                operator=operator,
                policy_name=str(action.policy_id),
                target=target,
                db=db
            )

            db.commit()
            return {
                "success": True,
                "action_uuid": action_uuid,
                "target": target,
                "reason": reason,
                "message": f"Successfully rolled back action on {target}."
            }
        finally:
            if close_db:
                db.close()

    def emergency_stop(self, operator: str = "ADMIN") -> Dict[str, Any]:
        """
        EMERGENCY STOP (Section 14.5, 14.11, 14.15 #13):
        Immediately revokes all active blocks and disables automated responses,
        WITHOUT stopping threat detection or monitoring.
        """
        settings.emergency_stop_active = True
        settings.automatic_temporary_blocking_enabled = False
        settings.automatic_permanent_blocking_enabled = False

        db = SessionLocal()
        reverted_count = 0
        try:
            # Revoke all active blocked targets
            active_targets = db.query(BlockedTargetModel).filter_by(is_active=True).all()
            for t in active_targets:
                linux_firewall.remove_rule(t.target)
                action_registry.deregister_action(t.target, "BLOCK_SOURCE_IP")
                t.is_active = False
                t.unblocked_at = datetime.datetime.utcnow()
                t.unblocked_by = f"EMERGENCY_STOP_{operator}"
                reverted_count += 1

            # Revoke all active actions
            active_actions = db.query(ResponseActionModel).filter_by(is_active=True).all()
            for a in active_actions:
                a.is_active = False
                a.is_rolled_back = True
                a.rolled_back_at = datetime.datetime.utcnow()
                a.rollback_reason = f"EMERGENCY_STOP by {operator}"

            audit_logger.log_event(
                event_type="EMERGENCY_STOP",
                details=f"EMERGENCY STOP activated by {operator}. Revoked {reverted_count} active blocks. Automated response disabled.",
                result="SUCCESS",
                operator=operator,
                target="GLOBAL",
                db=db
            )

            db.commit()
            return {
                "emergency_stop_active": True,
                "reverted_rules_count": reverted_count,
                "detection_running": True,
                "message": "EMERGENCY STOP EXECUTED: All active blocks revoked. Automated actions halted. Detection remains active."
            }
        finally:
            db.close()

    def clear_emergency_stop(self, operator: str = "ADMIN") -> Dict[str, Any]:
        """Restores normal operation from Emergency Stop."""
        settings.emergency_stop_active = False
        audit_logger.log_event(
            event_type="EMERGENCY_STOP_CLEARED",
            details=f"Emergency stop cleared by {operator}.",
            result="SUCCESS",
            operator=operator,
            target="GLOBAL"
        )
        return {"emergency_stop_active": False, "message": "Emergency stop cleared. Ready for policy operations."}

rollback_manager = RollbackManager()
