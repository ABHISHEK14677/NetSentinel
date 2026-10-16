"""
NetSentinel - Action Registry & Idempotency Manager
Implements Section 14.4 & Section 14.6 Idempotent Action Management.
Prevents duplicate alerts from repeatedly applying the same firewall change.
"""

import time
import datetime
from enum import Enum
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from database.models import BlockedTargetModel, ResponseActionModel
from database.db_service import SessionLocal

class ActionType(str, Enum):
    BLOCK_SOURCE_IP = "BLOCK_SOURCE_IP"
    RESTRICT_OUTBOUND = "RESTRICT_OUTBOUND"
    BLOCK_MALICIOUS_DEST = "BLOCK_MALICIOUS_DEST"
    DNS_BLOCK = "DNS_BLOCK"
    RATE_LIMIT = "RATE_LIMIT"
    SUPPRESS_CONNECTION = "SUPPRESS_CONNECTION"
    ISOLATE_DEVICE = "ISOLATE_DEVICE"
    ALERT_ESCALATION = "ALERT_ESCALATION"

class ActionRegistry:
    """
    Maintains active actions in memory and database.
    Provides idempotency checks to avoid redundant firewall updates.
    """

    def __init__(self):
        # In-memory fast cache of active (target, action_type) -> action_uuid
        self._active_actions_cache: Dict[str, Dict[str, Any]] = {}

    def is_action_already_active(self, target: str, action_type: str) -> bool:
        """
        Idempotency check: Returns True if target is already subjected to this action
        and has not yet expired.
        """
        cache_key = f"{action_type}:{target}"
        now = time.time()

        if cache_key in self._active_actions_cache:
            entry = self._active_actions_cache[cache_key]
            if entry["expires_at_ts"] > now and entry["is_active"]:
                return True
            else:
                del self._active_actions_cache[cache_key]

        # Check database
        db = SessionLocal()
        try:
            now_dt = datetime.datetime.utcnow()
            existing = db.query(BlockedTargetModel).filter(
                BlockedTargetModel.target == target,
                BlockedTargetModel.is_active == True,
                (BlockedTargetModel.expires_at == None) | (BlockedTargetModel.expires_at > now_dt)
            ).first()

            if existing:
                expires_ts = existing.expires_at.timestamp() if existing.expires_at else now + 86400
                self._active_actions_cache[cache_key] = {
                    "action_uuid": existing.action_uuid,
                    "expires_at_ts": expires_ts,
                    "is_active": True
                }
                return True
            return False
        finally:
            db.close()

    def register_active_action(self, target: str, action_type: str, action_uuid: str, duration_seconds: int):
        cache_key = f"{action_type}:{target}"
        self._active_actions_cache[cache_key] = {
            "action_uuid": action_uuid,
            "expires_at_ts": time.time() + duration_seconds,
            "is_active": True
        }

    def deregister_action(self, target: str, action_type: str):
        cache_key = f"{action_type}:{target}"
        if cache_key in self._active_actions_cache:
            del self._active_actions_cache[cache_key]

action_registry = ActionRegistry()
