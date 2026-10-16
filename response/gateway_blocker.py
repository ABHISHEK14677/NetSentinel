"""
NetSentinel - Gateway Blocker
Implements Section 14.6 #7 & Section 14.9 Authorized Security Gateway Isolation.
Applies forward-chain isolation for transit traffic passing through Linux gateway / router interfaces.
Explains when router/bridge enforcement point is required vs passive monitoring.
"""

from typing import Dict, Any, Optional
from response.linux_firewall import linux_firewall
from config.config import settings, GatewayMode

class GatewayBlocker:
    """
    Manages gateway-level inline transit blocking.
    Refuses inline prevention if system is configured only as passive monitor.
    """

    def __init__(self):
        pass

    def isolate_transit_client(
        self,
        client_ip: str,
        duration_seconds: int = 300,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Isolates transit client passing through gateway.
        """
        # Guard: If NetSentinel is in PASSIVE_MONITOR mode, explain why inline gateway blocking cannot occur
        if settings.gateway_mode == GatewayMode.PASSIVE_MONITOR:
            return {
                "success": False,
                "can_enforce": False,
                "reason": (
                    "NetSentinel is operating as a PASSIVE MONITOR NODE. A passive monitoring interface "
                    "cannot enforce inline gateway packet dropping on other LAN clients traversing an external router. "
                    "Requires deployment as an Authorized Security Gateway (e.g. Raspberry Pi or dual-NIC Linux bridge) "
                    "or managed switch/router 802.1X / ACL integration."
                )
            }

        # In Authorized Gateway mode, apply to forward chain
        rule_spec = f"nft add rule inet netsentinel netsentinel_forward ip saddr {client_ip} drop"
        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "rule_spec": rule_spec,
                "message": f"DRY-RUN: Would isolate gateway forwarding for client {client_ip} for {duration_seconds}s."
            }

        res = linux_firewall.apply_temporary_block(client_ip, duration_seconds=duration_seconds, direction="INBOUND")
        return {
            "success": res.get("success", False),
            "enforcement_point": "Linux Security Gateway (Forward Chain)",
            "details": res
        }

    def release_transit_client(self, client_ip: str) -> Dict[str, Any]:
        return linux_firewall.remove_rule(client_ip, direction="INBOUND")

gateway_blocker = GatewayBlocker()
