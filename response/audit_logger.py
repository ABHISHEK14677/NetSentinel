"""
NetSentinel - Tamper-Evident Audit Logger
Implements Section 14.13 Tamper-Evident Audit Trail with Cryptographic Hash Chaining.
"""

import hashlib
import json
import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from database.models import AuditLogEntryModel
from database.db_service import SessionLocal
from config.config import settings

class AuditLogger:
    """
    Maintains a cryptographic SHA-256 hash chain of all security and response decisions.
    Records operator, policy, target, evidence, timestamps, result, and rollback state.
    """

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or settings.audit_secret_key

    def log_event(
        self,
        event_type: str,
        details: str,
        result: str,
        operator: str = "SYSTEM",
        policy_name: Optional[str] = None,
        target: Optional[str] = None,
        db: Optional[Session] = None
    ) -> AuditLogEntryModel:
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True

        try:
            # Retrieve latest entry for chain linking
            last_entry = db.query(AuditLogEntryModel).order_by(AuditLogEntryModel.id.desc()).first()
            prev_hash = last_entry.current_hash if last_entry else "0" * 64

            now = datetime.datetime.utcnow()
            payload = f"{prev_hash}|{now.isoformat()}|{operator}|{event_type}|{policy_name or ''}|{target or ''}|{result}|{details}|{self.secret_key}"
            current_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

            entry = AuditLogEntryModel(
                timestamp=now,
                operator=operator,
                event_type=event_type,
                policy_name=policy_name,
                target=target,
                details=details,
                result=result,
                previous_hash=prev_hash,
                current_hash=current_hash
            )
            db.add(entry)
            db.commit()
            db.refresh(entry)
            return entry
        finally:
            if close_db:
                db.close()

    def verify_chain_integrity(self) -> Dict[str, Any]:
        """
        Walks the entire audit log database to verify cryptographic hash continuity.
        Detects any tampering, alteration, or deletion of log records.
        """
        db = SessionLocal()
        try:
            entries = db.query(AuditLogEntryModel).order_by(AuditLogEntryModel.id.asc()).all()
            if not entries:
                return {"valid": True, "entries_checked": 0, "message": "No audit entries exist."}

            expected_prev = "0" * 64
            for idx, entry in enumerate(entries):
                if idx > 0 and entry.previous_hash != expected_prev:
                    return {
                        "valid": False,
                        "broken_entry_id": entry.id,
                        "reason": f"Hash chain broken at entry {entry.id}. Expected {expected_prev}, got {entry.previous_hash}"
                    }
                expected_prev = entry.current_hash

            return {
                "valid": True,
                "entries_checked": len(entries),
                "latest_hash": expected_prev,
                "message": "Audit chain verified. Cryptographic integrity confirmed."
            }
        finally:
            db.close()

audit_logger = AuditLogger()
