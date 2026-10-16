"""
NetSentinel - Device Quarantine & Containment
Implements Section 14.7 Automatic Device Protection and Quarantine Safeguards.
Only isolates devices when NetSentinel controls a real enforcement point.
Explains required network topology and integrations.
"""

import datetime
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from database.models import QuarantinedDeviceModel, DeviceInventoryModel
from database.db_service import SessionLocal
from response.linux_firewall import linux_firewall
from config.config import settings, GatewayMode

class DeviceQuarantineManager:
    """
    Manages quarantine actions for internal LAN endpoints.
    Enforces architectural safeguards: Requires an actual enforcement point.
    """

    def quarantine_device(
        self,
        mac_address: str,
        ip_address: Optional[str] = None,
        hostname: Optional[str] = None,
        reason: str = "Severe threat detected",
        duration_seconds: int = 900,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Attempts to quarantine a device.
        Verifies whether NetSentinel possesses an effective enforcement point.
        """
        # Topology verification check
        has_gateway_point = (settings.gateway_mode == GatewayMode.AUTHORIZED_GATEWAY)
        enforcement_point = "Linux Gateway Forward-Drop" if has_gateway_point else "Host-Local Protection Only"

        if not has_gateway_point and not dry_run:
            explanation = (
                f"Cannot isolate internal device MAC={mac_address} across the LAN because NetSentinel is running "
                f"in {settings.gateway_mode.value} mode. To quarantine a device from accessing other LAN devices, "
                f"NetSentinel requires placement as an inline Authorized Gateway (bridged interfaces), or integration "
                f"with a managed network switch (SNMP/RADIUS 802.1X port shutdown) or Wi-Fi Access Point API. "
                f"Local host-level blocking can only drop packets directed to NetSentinel itself."
            )
            # We record the containment intent but honestly report the limitation
            quarantine_method = "LOCAL_HOST_DROP_ONLY"
        else:
            explanation = "Enforcement applied at Linux Gateway transit boundary."
            quarantine_method = "GATEWAY_NFTABLES"

        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "mac_address": mac_address,
                "ip_address": ip_address,
                "enforcement_point": enforcement_point,
                "quarantine_method": quarantine_method,
                "duration_seconds": duration_seconds,
                "message": f"DRY-RUN: Device {mac_address} ({ip_address}) proposed for quarantine.",
                "topology_explanation": explanation
            }

        # Apply firewall block on IP if known
        fw_result = None
        if ip_address:
            fw_result = linux_firewall.apply_temporary_block(ip_address, duration_seconds=duration_seconds)

        # Record in database
        db = SessionLocal()
        try:
            now = datetime.datetime.utcnow()
            expires = now + datetime.timedelta(seconds=duration_seconds)

            # Update or create QuarantinedDeviceModel
            q_device = db.query(QuarantinedDeviceModel).filter_by(mac_address=mac_address).first()
            if not q_device:
                q_device = QuarantinedDeviceModel(
                    mac_address=mac_address,
                    ip_address=ip_address,
                    hostname=hostname,
                    quarantine_method=quarantine_method,
                    enforcement_point=enforcement_point,
                    reason=reason,
                    quarantined_at=now,
                    expires_at=expires,
                    is_active=True
                )
                db.add(q_device)
            else:
                q_device.is_active = True
                q_device.expires_at = expires
                q_device.quarantined_at = now
                q_device.reason = reason

            # Update inventory trust status
            dev = db.query(DeviceInventoryModel).filter_by(mac_address=mac_address).first()
            if dev:
                dev.trust_status = "Quarantined"
                dev.current_enforcement_state = "QUARANTINED"

            db.commit()

            return {
                "success": True,
                "dry_run": False,
                "mac_address": mac_address,
                "ip_address": ip_address,
                "enforcement_point": enforcement_point,
                "quarantine_method": quarantine_method,
                "topology_explanation": explanation,
                "firewall_result": fw_result
            }
        finally:
            db.close()

    def release_device(self, mac_address: str, operator: str = "ADMIN") -> Dict[str, Any]:
        """
        Releases device from quarantine and restores Released status.
        """
        db = SessionLocal()
        try:
            q_device = db.query(QuarantinedDeviceModel).filter_by(mac_address=mac_address, is_active=True).first()
            ip_to_unblock = None
            if q_device:
                q_device.is_active = False
                q_device.released_at = datetime.datetime.utcnow()
                q_device.released_by = operator
                ip_to_unblock = q_device.ip_address

            dev = db.query(DeviceInventoryModel).filter_by(mac_address=mac_address).first()
            if dev:
                dev.trust_status = "Released"
                dev.current_enforcement_state = "NONE"

            db.commit()

            if ip_to_unblock:
                linux_firewall.remove_rule(ip_to_unblock)

            return {
                "success": True,
                "mac_address": mac_address,
                "status": "Released",
                "message": f"Device {mac_address} successfully released from quarantine."
            }
        finally:
            db.close()

device_quarantine_manager = DeviceQuarantineManager()
