"""
NetSentinel - Monitored Device Inventory Management
Implements Section 14.7 Automatic Device Protection requirements.
"""

import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from database.models import DeviceInventoryModel
from database.db_service import SessionLocal

class DeviceTrustStatus:
    TRUSTED = "Trusted"
    UNKNOWN = "Unknown"
    UNDER_OBSERVATION = "Under observation"
    SUSPICIOUS = "Suspicious"
    RESTRICTED = "Restricted"
    QUARANTINED = "Quarantined"
    RELEASED = "Released"

class DeviceInventoryManager:
    """
    Tracks LAN devices, network identity, trust status, and enforcement states.
    Enforces rule: Unknown devices trigger observation/alert by default, NOT automatic disconnection.
    """

    def register_or_update_device(
        self,
        ip_address: str,
        mac_address: Optional[str] = None,
        hostname: Optional[str] = None,
        interface: str = "eth0",
        observed_protocol: str = "TCP",
        risk_increment: float = 0.0,
        db: Optional[Session] = None
    ) -> DeviceInventoryModel:
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True

        try:
            # Match primarily on MAC address if available (IP addresses can change or be spoofed)
            device = None
            if mac_address:
                device = db.query(DeviceInventoryModel).filter_by(mac_address=mac_address).first()
            if not device and ip_address:
                device = db.query(DeviceInventoryModel).filter_by(ip_address=ip_address).first()

            now = datetime.datetime.utcnow()

            if not device:
                # New device discovered: Default to "Unknown" with observation policy (Section 14.7)
                device = DeviceInventoryModel(
                    ip_address=ip_address,
                    mac_address=mac_address,
                    hostname=hostname or f"host-{ip_address.replace('.', '-')}",
                    interface=interface,
                    first_seen=now,
                    last_seen=now,
                    observed_protocols=observed_protocol,
                    trust_status=DeviceTrustStatus.UNKNOWN,
                    risk_score=min(100.0, risk_increment),
                    related_alerts_count=1 if risk_increment > 0 else 0,
                    current_enforcement_state="NONE",
                    notes="Discovered on network. Observation policy activated."
                )
                db.add(device)
            else:
                # Update existing record
                device.last_seen = now
                if ip_address:
                    device.ip_address = ip_address
                if hostname and not device.hostname:
                    device.hostname = hostname
                if mac_address and not device.mac_address:
                    device.mac_address = mac_address

                if observed_protocol and observed_protocol not in (device.observed_protocols or ""):
                    device.observed_protocols = f"{device.observed_protocols},{observed_protocol}"

                if risk_increment > 0:
                    device.risk_score = min(100.0, device.risk_score + risk_increment)
                    device.related_alerts_count += 1
                    # Progress state if risk escalates
                    if device.risk_score >= 60.0 and device.trust_status not in [DeviceTrustStatus.QUARANTINED, DeviceTrustStatus.RESTRICTED]:
                        device.trust_status = DeviceTrustStatus.SUSPICIOUS
                    elif device.risk_score >= 30.0 and device.trust_status == DeviceTrustStatus.UNKNOWN:
                        device.trust_status = DeviceTrustStatus.UNDER_OBSERVATION

            db.commit()
            db.refresh(device)
            return device
        finally:
            if close_db:
                db.close()

    def set_trust_status(self, device_id: int, new_status: str, notes: Optional[str] = None) -> Optional[DeviceInventoryModel]:
        db = SessionLocal()
        try:
            device = db.query(DeviceInventoryModel).filter_by(id=device_id).first()
            if device:
                device.trust_status = new_status
                if notes:
                    device.notes = notes
                if new_status == DeviceTrustStatus.RELEASED:
                    device.current_enforcement_state = "NONE"
                    device.risk_score = max(0.0, device.risk_score - 40.0)
                elif new_status == DeviceTrustStatus.TRUSTED:
                    device.current_enforcement_state = "NONE"
                    device.risk_score = 0.0
                db.commit()
                db.refresh(device)
            return device
        finally:
            db.close()

    def get_all_devices(self) -> List[Dict[str, Any]]:
        db = SessionLocal()
        try:
            devices = db.query(DeviceInventoryModel).all()
            return [
                {
                    "id": d.id,
                    "ip_address": d.ip_address,
                    "mac_address": d.mac_address,
                    "hostname": d.hostname,
                    "interface": d.interface,
                    "first_seen": d.first_seen.isoformat() if d.first_seen else None,
                    "last_seen": d.last_seen.isoformat() if d.last_seen else None,
                    "observed_protocols": d.observed_protocols,
                    "trust_status": d.trust_status,
                    "risk_score": d.risk_score,
                    "related_alerts_count": d.related_alerts_count,
                    "current_enforcement_state": d.current_enforcement_state,
                    "notes": d.notes
                }
                for d in devices
            ]
        finally:
            db.close()

device_inventory_manager = DeviceInventoryManager()
