"""
NetSentinel - Response Verification Engine
Implements Section 14.11 Step 7-8 and Section 14.15 #10, #15.
Verifies kernel state after enforcement and ensures failed actions are NEVER reported as successful blocks.
"""

import datetime
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from database.models import EnforcementVerificationModel, ResponseActionModel
from database.db_service import SessionLocal
from response.linux_firewall import linux_firewall

class VerificationStatus:
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    DEGRADED = "DEGRADED"
    NOT_APPLICABLE = "NOT_APPLICABLE"

class ResponseVerifier:
    """
    Validates whether applied firewall rules or blocks actually exist in the kernel state.
    Reports honest degradation on failures.
    """

    def verify_action(
        self,
        action_id: int,
        target: str,
        action_type: str,
        direction: str = "INBOUND",
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Queries system/kernel state to prove rule was installed.
        """
        if dry_run:
            return {
                "status": VerificationStatus.NOT_APPLICABLE,
                "verified": True,
                "checked_kernel_state": False,
                "details": "Dry-run action: No live kernel modification requested or expected."
            }

        # Query live firewall state
        check_res = linux_firewall.verify_rule_exists(target, direction=direction)

        if check_res.get("verified", False):
            status = VerificationStatus.VERIFIED
            details = f"Verified: Rule for target {target} actively present in {check_res.get('target_set')}."
        else:
            status = VerificationStatus.FAILED
            details = f"CRITICAL VERIFICATION FAILURE: Target {target} was NOT found in kernel set. System degraded."

        # Record in database
        db = SessionLocal()
        try:
            ver_record = EnforcementVerificationModel(
                action_id=action_id,
                verification_time=datetime.datetime.utcnow(),
                method="NFT_SET_QUERY",
                status=status,
                details=details,
                checked_kernel_state=True
            )
            db.add(ver_record)

            # Update action model
            action = db.query(ResponseActionModel).filter_by(id=action_id).first()
            if action:
                action.verification_status = status
                action.verification_details = details

            db.commit()

            return {
                "status": status,
                "verified": (status == VerificationStatus.VERIFIED),
                "checked_kernel_state": True,
                "details": details
            }
        finally:
            db.close()

response_verifier = ResponseVerifier()
