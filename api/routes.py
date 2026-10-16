"""
NetSentinel - API Endpoints
Provides full control plane for Active Protection, Policy Management, Approvals, and Monitoring.
"""

import time
import datetime
from fastapi import APIRouter, HTTPException, Depends, Query, Body
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional

from config.config import settings, ProtectionMode, GatewayMode
from database.models import (
    ResponseActionModel, BlockedTargetModel, QuarantinedDeviceModel,
    ApprovalRequestModel, AllowlistedAssetModel, RollbackRecordModel,
    AuditLogEntryModel, DeviceInventoryModel
)
from database.db_service import SessionLocal
from response.response_engine import response_engine
from response.rollback_manager import rollback_manager
from response.approval_manager import approval_manager
from response.action_registry import action_registry
from response.audit_logger import audit_logger
from response.notification_service import notification_service
from threat_engine.detector import threat_detector, ThreatCategory
from threat_engine.device_inventory import device_inventory_manager
from platforms.esp32.esp32_controller import esp32_controller
from platforms.raspberry_pi.gateway_manager import raspberry_pi_manager
from platforms.pc_host.host_protector import pc_host_protector
from api.auth import verify_api_token

router = APIRouter(prefix="/api", tags=["Active Protection"])

# Request models
class ProtectionModeRequest(BaseModel):
    mode: ProtectionMode
    operator: str = "ADMIN"

class ThreatEventRequest(BaseModel):
    category: str = ThreatCategory.PORT_SCAN
    src_ip: str = "192.168.1.150"
    dst_ip: str = "192.168.1.5"
    src_mac: Optional[str] = "00:1A:2B:3C:4D:5E"
    domain: Optional[str] = None
    dst_port: Optional[int] = 80
    ids_severity: float = 65.0
    ai_anomaly_score: float = 40.0
    confidence: float = 0.85
    proto: str = "TCP"
    notes: Optional[str] = None

class ApprovalDecisionRequest(BaseModel):
    approve: bool
    operator: str = "ADMIN"

class AllowlistAssetRequest(BaseModel):
    asset_value: str
    asset_type: str = "IP" # IP, SUBNET, MAC, DOMAIN
    description: str
    is_essential: bool = False

@router.get("/status")
def get_system_status():
    """Returns comprehensive real-time status of the protection engine."""
    # Run routine expiration check
    rollback_manager.process_expired_actions()

    db = SessionLocal()
    try:
        active_blocks = db.query(BlockedTargetModel).filter_by(is_active=True).count()
        quarantined = db.query(QuarantinedDeviceModel).filter_by(is_active=True).count()
        pending_approvals = db.query(ApprovalRequestModel).filter_by(status="PENDING").count()
        total_actions = db.query(ResponseActionModel).count()
        verified_actions = db.query(ResponseActionModel).filter_by(verification_status="VERIFIED").count()
        failed_actions = db.query(ResponseActionModel).filter_by(verification_status="FAILED").count()

        return {
            "app_name": settings.app_name,
            "version": settings.version,
            "protection_mode": settings.protection_mode.value,
            "dry_run_mode": settings.dry_run_mode,
            "emergency_stop_active": settings.emergency_stop_active,
            "platform": settings.platform.value,
            "gateway_mode": settings.gateway_mode.value,
            "counts": {
                "active_blocks": active_blocks,
                "quarantined_devices": quarantined,
                "pending_approvals": pending_approvals,
                "total_actions": total_actions,
                "verified_enforcements": verified_actions,
                "failed_enforcements": failed_actions
            },
            "esp32_status": esp32_controller.check_connection_health(),
            "notifications": notification_service.get_recent_alerts(10)
        }
    finally:
        db.close()

@router.post("/protection-mode")
def set_protection_mode(payload: ProtectionModeRequest, auth: bool = Depends(verify_api_token)):
    """Changes operating protection mode (Mode A, B, C, D) with full audit logging."""
    old_mode = settings.protection_mode
    settings.protection_mode = payload.mode

    if payload.mode == ProtectionMode.MODE_A:
        settings.firewall_modification_enabled = False
        settings.automatic_temporary_blocking_enabled = False
    elif payload.mode == ProtectionMode.MODE_B:
        settings.firewall_modification_enabled = True
        settings.automatic_temporary_blocking_enabled = False
    elif payload.mode == ProtectionMode.MODE_C:
        settings.firewall_modification_enabled = True
        settings.automatic_temporary_blocking_enabled = True
    elif payload.mode == ProtectionMode.MODE_D:
        settings.firewall_modification_enabled = True
        settings.automatic_temporary_blocking_enabled = True

    audit_logger.log_event(
        event_type="PROTECTION_MODE_CHANGE",
        details=f"Protection mode transitioned from {old_mode.value} to {payload.mode.value} by {payload.operator}",
        result="SUCCESS",
        operator=payload.operator,
        target="SYSTEM_PROTECTION_MODE"
    )

    return {
        "success": True,
        "previous_mode": old_mode.value,
        "current_mode": payload.mode.value,
        "message": f"Protection mode switched to {payload.mode.value}."
    }

@router.post("/dry-run/toggle")
def toggle_dry_run(auth: bool = Depends(verify_api_token)):
    """Toggles dry run mode on/off."""
    settings.dry_run_mode = not settings.dry_run_mode
    audit_logger.log_event(
        event_type="DRY_RUN_TOGGLE",
        details=f"Dry-run mode set to {settings.dry_run_mode}",
        result="SUCCESS",
        operator="ADMIN",
        target="DRY_RUN_SETTING"
    )
    return {
        "dry_run_mode": settings.dry_run_mode,
        "message": f"Dry-run mode is now {'ENABLED' if settings.dry_run_mode else 'DISABLED'}."
    }

@router.post("/emergency-stop")
def trigger_emergency_stop(operator: str = "ADMIN", auth: bool = Depends(verify_api_token)):
    """Instantly revokes all active blocks and halts automated protection actions."""
    return rollback_manager.emergency_stop(operator=operator)

@router.post("/emergency-stop/clear")
def clear_emergency_stop(operator: str = "ADMIN", auth: bool = Depends(verify_api_token)):
    """Clears emergency stop and restores normal mode."""
    return rollback_manager.clear_emergency_stop(operator=operator)

@router.post("/threats/ingest")
def ingest_threat_event(event: ThreatEventRequest, auth: bool = Depends(verify_api_token)):
    """
    Ingests network threat event, runs correlation, risk assessment,
    policy evaluation, enforcement, and verification.
    """
    raw_event = event.dict()
    # 1. Detection & Risk Assessment
    threat_eval = threat_detector.process_event(raw_event, is_protected_asset_cb=None)

    # 2. Response Engine Execution
    response_result = response_engine.process_threat(threat_eval)

    return {
        "threat_evaluation": threat_eval,
        "response_result": response_result
    }

@router.get("/approvals")
def list_pending_approvals():
    """Lists pending human approval requests for Mode B."""
    return approval_manager.get_pending_requests()

@router.post("/approvals/{request_uuid}/decide")
def decide_approval(request_uuid: str, decision: ApprovalDecisionRequest, auth: bool = Depends(verify_api_token)):
    """Approves or rejects a pending response action."""
    res = approval_manager.decide_request(request_uuid, approve=decision.approve, operator=decision.operator)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))

    # If approved, trigger execution
    if decision.approve:
        exec_res = response_engine.execute_approved_action(res["action_uuid"], operator=decision.operator)
        return {"decision": res, "execution": exec_res}

    return {"decision": res, "message": "Action rejected by operator."}

@router.get("/blocked-targets")
def list_blocked_targets():
    """Lists active and recent blocked IP/domain targets with countdowns."""
    rollback_manager.process_expired_actions()
    db = SessionLocal()
    try:
        now = datetime.datetime.utcnow()
        targets = db.query(BlockedTargetModel).order_by(BlockedTargetModel.id.desc()).limit(100).all()
        result = []
        for t in targets:
            time_left = 0
            if t.is_active and t.expires_at:
                diff = (t.expires_at - now).total_seconds()
                time_left = max(0, int(diff))

            result.append({
                "id": t.id,
                "target": t.target,
                "target_type": t.target_type,
                "reason": t.reason,
                "risk_score": t.risk_score,
                "blocked_at": t.blocked_at.isoformat() if t.blocked_at else None,
                "expires_at": t.expires_at.isoformat() if t.expires_at else None,
                "seconds_remaining": time_left,
                "is_active": t.is_active,
                "unblocked_at": t.unblocked_at.isoformat() if t.unblocked_at else None,
                "unblocked_by": t.unblocked_by
            })
        return result
    finally:
        db.close()

@router.post("/blocked-targets/{target}/unblock")
def unblock_target(target: str, operator: str = "ADMIN", auth: bool = Depends(verify_api_token)):
    """Manually releases a blocked target immediately."""
    db = SessionLocal()
    try:
        bt = db.query(BlockedTargetModel).filter_by(target=target, is_active=True).first()
        if not bt:
            raise HTTPException(status_code=404, detail=f"Active block on target {target} not found.")

        if bt.action_uuid:
            res = rollback_manager.rollback_action(bt.action_uuid, reason="MANUAL_UNBLOCK", operator=operator)
            return res
        else:
            from response.linux_firewall import linux_firewall
            linux_firewall.remove_rule(target)
            action_registry.deregister_action(target, "BLOCK_SOURCE_IP")
            bt.is_active = False
            bt.unblocked_at = datetime.datetime.utcnow()
            bt.unblocked_by = operator
            db.commit()
            return {"success": True, "message": f"Target {target} unblocked."}
    finally:
        db.close()

@router.get("/quarantined-devices")
def list_quarantined_devices():
    """Lists quarantined LAN devices."""
    db = SessionLocal()
    try:
        devices = db.query(QuarantinedDeviceModel).order_by(QuarantinedDeviceModel.id.desc()).all()
        return [
            {
                "id": d.id,
                "mac_address": d.mac_address,
                "ip_address": d.ip_address,
                "hostname": d.hostname,
                "quarantine_method": d.quarantine_method,
                "enforcement_point": d.enforcement_point,
                "reason": d.reason,
                "quarantined_at": d.quarantined_at.isoformat() if d.quarantined_at else None,
                "expires_at": d.expires_at.isoformat() if d.expires_at else None,
                "is_active": d.is_active,
                "released_at": d.released_at.isoformat() if d.released_at else None,
                "released_by": d.released_by
            }
            for d in devices
        ]
    finally:
        db.close()

@router.post("/quarantined-devices/{mac_address}/release")
def release_device_quarantine(mac_address: str, operator: str = "ADMIN", auth: bool = Depends(verify_api_token)):
    """Releases device from quarantine containment."""
    return device_quarantine_manager.release_device(mac_address, operator=operator)

@router.get("/devices")
def list_inventory_devices():
    """Lists monitored devices inventory per Section 14.7."""
    return device_inventory_manager.get_all_devices()

@router.post("/devices/{device_id}/trust-status")
def update_device_trust_status(device_id: int, status: str = Body(..., embed=True), auth: bool = Depends(verify_api_token)):
    """Updates device trust status."""
    dev = device_inventory_manager.set_trust_status(device_id, status)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"success": True, "device_id": device_id, "new_status": dev.trust_status}

@router.get("/actions/recent")
def list_recent_actions(limit: int = 50):
    """Lists recent response actions, verification status, and rollback state."""
    db = SessionLocal()
    try:
        actions = db.query(ResponseActionModel).order_by(ResponseActionModel.id.desc()).limit(limit).all()
        return [
            {
                "action_uuid": a.action_uuid,
                "target": a.target,
                "action_type": a.action_type,
                "risk_score": a.risk_score,
                "threat_category": a.threat_category,
                "protection_mode": a.protection_mode,
                "authorization_status": a.authorization_status,
                "dry_run": a.dry_run,
                "execution_status": a.execution_status,
                "verification_status": a.verification_status,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "expires_at": a.expires_at.isoformat() if a.expires_at else None,
                "is_active": a.is_active,
                "is_rolled_back": a.is_rolled_back,
                "rollback_reason": a.rollback_reason
            }
            for a in actions
        ]
    finally:
        db.close()

@router.post("/actions/{action_uuid}/rollback")
def rollback_action_endpoint(action_uuid: str, operator: str = "ADMIN", auth: bool = Depends(verify_api_token)):
    """Rolls back a specific response action."""
    res = rollback_manager.rollback_action(action_uuid, reason="OPERATOR_REQUESTED_ROLLBACK", operator=operator)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res

@router.get("/allowlist")
def get_allowlist():
    """Lists protected assets, gateways, and infrastructure."""
    db = SessionLocal()
    try:
        assets = db.query(AllowlistedAssetModel).all()
        return [
            {
                "id": a.id,
                "asset_value": a.asset_value,
                "asset_type": a.asset_type,
                "description": a.description,
                "is_essential": a.is_essential_infrastructure,
                "added_by": a.added_by
            }
            for a in assets
        ]
    finally:
        db.close()

@router.post("/allowlist")
def add_allowlist_asset(payload: AllowlistAssetRequest, auth: bool = Depends(verify_api_token)):
    """Adds a new asset to protected infrastructure allowlist."""
    db = SessionLocal()
    try:
        existing = db.query(AllowlistedAssetModel).filter_by(asset_value=payload.asset_value).first()
        if existing:
            return {"success": False, "message": "Asset already allowlisted."}

        asset = AllowlistedAssetModel(
            asset_value=payload.asset_value,
            asset_type=payload.asset_type,
            description=payload.description,
            is_essential_infrastructure=payload.is_essential,
            added_by="ADMIN"
        )
        db.add(asset)
        db.commit()
        return {"success": True, "message": f"Asset {payload.asset_value} added to allowlist."}
    finally:
        db.close()

@router.get("/audit/verify")
def verify_audit_chain():
    """Verifies SHA-256 hash chaining integrity of the entire audit trail."""
    return audit_logger.verify_chain_integrity()

@router.get("/esp32/status")
def get_esp32_status():
    """Returns ESP32 auxiliary controller health, connection, and tamper sensor state."""
    return esp32_controller.check_connection_health()

@router.post("/esp32/telemetry")
def receive_esp32_telemetry(payload: Dict[str, Any]):
    """Ingests authenticated telemetry from ESP32."""
    return esp32_controller.process_esp32_telemetry(payload)
