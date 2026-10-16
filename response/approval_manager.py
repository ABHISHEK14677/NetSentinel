"""
NetSentinel - Human Operator Approval Manager
Implements Section 14.5 Mode B Assisted Protection & Section 14.12 Approval Workflows.
Generates proposed actions with impact analysis and waits for human operator sign-off.
"""

import uuid
import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from database.models import ApprovalRequestModel
from database.db_service import SessionLocal
from config.config import settings
from response.audit_logger import audit_logger

class ApprovalStatus:
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"

class ApprovalManager:
    """
    Manages operator approval requests for high-impact actions in Assisted Protection mode.
    """

    def create_approval_request(
        self,
        action_uuid: str,
        target: str,
        action_type: str,
        risk_score: float,
        severity: str,
        proposed_rule: str,
        potential_impact: str,
        duration_seconds: int = 300,
        db: Optional[Session] = None
    ) -> ApprovalRequestModel:
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True

        try:
            req_uuid = str(uuid.uuid4())
            now = datetime.datetime.utcnow()
            expires = now + datetime.timedelta(seconds=settings.approval_timeout_seconds)

            req = ApprovalRequestModel(
                request_uuid=req_uuid,
                action_uuid=action_uuid,
                target=target,
                action_type=action_type,
                risk_score=risk_score,
                severity=severity,
                proposed_rule=proposed_rule,
                potential_impact=potential_impact,
                duration_seconds=duration_seconds,
                status=ApprovalStatus.PENDING,
                created_at=now,
                expires_at=expires
            )
            db.add(req)

            audit_logger.log_event(
                event_type="APPROVAL_REQUEST_CREATED",
                details=f"Assisted mode approval request {req_uuid} created for {action_type} on {target}",
                result="PENDING",
                operator="SYSTEM_POLICY",
                target=target,
                db=db
            )

            db.commit()
            db.refresh(req)
            return req
        finally:
            if close_db:
                db.close()

    def decide_request(
        self,
        request_uuid: str,
        approve: bool,
        operator: str = "ADMIN"
    ) -> Dict[str, Any]:
        """
        Processes operator approval or rejection.
        """
        db = SessionLocal()
        try:
            req = db.query(ApprovalRequestModel).filter_by(request_uuid=request_uuid).first()
            if not req:
                return {"success": False, "error": f"Approval request {request_uuid} not found."}

            if req.status != ApprovalStatus.PENDING:
                return {"success": False, "error": f"Request is already in state {req.status}."}

            now = datetime.datetime.utcnow()
            if req.expires_at and now > req.expires_at:
                req.status = ApprovalStatus.EXPIRED
                db.commit()
                return {"success": False, "error": "Approval request has expired."}

            new_status = ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED
            req.status = new_status
            req.decision_by = operator
            req.decision_at = now

            audit_logger.log_event(
                event_type="APPROVAL_DECISION",
                details=f"Operator {operator} decided: {new_status} for request {request_uuid} ({req.action_type} on {req.target})",
                result=new_status,
                operator=operator,
                target=req.target,
                db=db
            )

            db.commit()

            return {
                "success": True,
                "request_uuid": request_uuid,
                "action_uuid": req.action_uuid,
                "status": new_status,
                "target": req.target,
                "action_type": req.action_type,
                "duration_seconds": req.duration_seconds
            }
        finally:
            db.close()

    def get_pending_requests(self) -> List[Dict[str, Any]]:
        db = SessionLocal()
        try:
            now = datetime.datetime.utcnow()
            # Mark expired
            expired = db.query(ApprovalRequestModel).filter(
                ApprovalRequestModel.status == ApprovalStatus.PENDING,
                ApprovalRequestModel.expires_at <= now
            ).all()
            for exp in expired:
                exp.status = ApprovalStatus.EXPIRED
            db.commit()

            pending = db.query(ApprovalRequestModel).filter_by(status=ApprovalStatus.PENDING).all()
            return [
                {
                    "request_uuid": r.request_uuid,
                    "action_uuid": r.action_uuid,
                    "target": r.target,
                    "action_type": r.action_type,
                    "risk_score": r.risk_score,
                    "severity": r.severity,
                    "proposed_rule": r.proposed_rule,
                    "potential_impact": r.potential_impact,
                    "duration_seconds": r.duration_seconds,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "expires_at": r.expires_at.isoformat() if r.expires_at else None
                }
                for r in pending
            ]
        finally:
            db.close()

approval_manager = ApprovalManager()
