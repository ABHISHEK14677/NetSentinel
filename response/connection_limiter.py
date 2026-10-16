"""
NetSentinel - Connection Limiter & Suppression Engine
Implements Section 14.6 #5 Per-Source Connection-Rate Limiting & #6 Suspicious Connection Suppression.
"""

from typing import Dict, Any
from response.linux_firewall import linux_firewall

class ConnectionLimiter:
    """
    Applies connection rate limits and suppression for anomalous bursts or port scans.
    """

    def apply_rate_limit(
        self,
        ip_address: str,
        rate_per_sec: int = 5,
        duration_seconds: int = 300,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Throttles connection rate from an aggressive source IP.
        """
        rule_spec = f"nft add rule inet netsentinel netsentinel_input ip saddr {ip_address} limit rate over {rate_per_sec}/second drop"

        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "target": ip_address,
                "rate": f"{rate_per_sec}/s",
                "duration_seconds": duration_seconds,
                "rule_spec": rule_spec,
                "message": f"DRY-RUN: Would throttle {ip_address} to max {rate_per_sec} conn/sec for {duration_seconds}s."
            }

        # Apply timed entry to rate limit set
        fw_res = linux_firewall.apply_temporary_block(ip_address, duration_seconds=duration_seconds, direction="INBOUND")
        return {
            "success": fw_res.get("success", False),
            "target": ip_address,
            "rate": f"{rate_per_sec}/s",
            "duration_seconds": duration_seconds,
            "details": fw_res
        }

    def suppress_suspicious_connections(
        self,
        ip_address: str,
        duration_seconds: int = 180,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Suppresses rapid SYN bursts or repeated failed handshakes.
        """
        return self.apply_rate_limit(ip_address, rate_per_sec=2, duration_seconds=duration_seconds, dry_run=dry_run)

connection_limiter = ConnectionLimiter()
