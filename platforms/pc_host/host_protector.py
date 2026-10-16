"""
NetSentinel - Existing PC Protection Logic (Kali Linux / Debian)
Implements Section 14.10 Host-Level Protection.
Manages scoped host-firewall boundaries, local IDS event parsing, and host scope explanations.
"""

from typing import Dict, Any, List, Optional
from config.config import settings
from response.linux_firewall import linux_firewall
from response.notification_service import notification_service
from response.rollback_manager import rollback_manager

class PCHostProtector:
    """
    Manages host-level threat protection on Kali Linux / Debian workstations and servers.
    Enforces honest communication: Blocking on this host only shields this host, not the entire LAN.
    """

    def __init__(self):
        self.host_scope_explanation = (
            "IMPORTANT ARCHITECTURAL SCOPE NOTE: When NetSentinel executes an active block on a "
            "standalone Kali Linux / Debian host, the resulting nftables drop rule is applied "
            "strictly to the local network stack (INPUT and OUTPUT chains of this PC). "
            "It DOES NOT prevent the attacker from communicating with other separate devices on your LAN. "
            "To protect the entire subnet, deploy NetSentinel on an inline Linux Gateway / Bridge "
            "or integrate with network infrastructure ACLs."
        )

    def get_protection_scope(self) -> Dict[str, Any]:
        return {
            "platform": "Kali Linux / Debian PC",
            "enforcement_boundary": "Host-Local (Localhost & Local NIC Input/Output)",
            "lan_wide_protection": False,
            "architecture_note": self.host_scope_explanation,
            "dashboard_authentication_active": True,
            "safe_rollback_supported": True
        }

    def notify_malicious_outbound(self, destination: str, process_name: Optional[str] = None, details: str = "") -> Dict[str, Any]:
        """
        Specialized handler for malicious outbound connections originating from the PC host.
        """
        title = f"MALICIOUS OUTBOUND CONNECTION: {destination}"
        msg = f"Host process '{process_name or 'Unknown'}' attempted connection to suspicious destination {destination}. {details}"
        
        return notification_service.send_alert(
            severity="Critical",
            title=title,
            message=msg,
            target=destination,
            risk_score=88.0,
            action_taken="OUTBOUND_RESTRICTION_EVALUATED"
        )

pc_host_protector = PCHostProtector()
