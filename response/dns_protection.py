"""
NetSentinel - DNS Protection & Filtering
Implements Section 14.6 #4 Configured DNS Filtering for Malicious Domains.
Blocks or sinkholes resolution of confirmed C2 and phishing domains.
"""

from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("netsentinel.dns")

class DNSProtectionManager:
    """
    Manages DNS-level blocking and sinkholing of malicious domains.
    """

    def __init__(self):
        # In-memory active blocked domains with expiry timestamp
        self._blocked_domains: Dict[str, float] = {}

    def block_domain(self, domain: str, duration_seconds: int = 1800, dry_run: bool = False) -> Dict[str, Any]:
        """
        Applies DNS resolution block / sinkhole for malicious domain.
        """
        import time
        domain_clean = domain.strip().lower()

        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "domain": domain_clean,
                "action": "SINKHOLE_0.0.0.0",
                "duration_seconds": duration_seconds,
                "message": f"DRY-RUN: Domain '{domain_clean}' would be sinkholed to 0.0.0.0 for {duration_seconds}s."
            }

        self._blocked_domains[domain_clean] = time.time() + duration_seconds
        return {
            "success": True,
            "dry_run": False,
            "domain": domain_clean,
            "action": "SINKHOLE_0.0.0.0",
            "duration_seconds": duration_seconds,
            "message": f"Domain '{domain_clean}' actively sinkholed to 0.0.0.0 for {duration_seconds}s."
        }

    def is_domain_blocked(self, domain: str) -> bool:
        import time
        domain_clean = domain.strip().lower()
        if domain_clean in self._blocked_domains:
            if self._blocked_domains[domain_clean] > time.time():
                return True
            else:
                del self._blocked_domains[domain_clean]
        return False

    def unblock_domain(self, domain: str) -> Dict[str, Any]:
        domain_clean = domain.strip().lower()
        if domain_clean in self._blocked_domains:
            del self._blocked_domains[domain_clean]
            return {"success": True, "message": f"Domain '{domain_clean}' unblocked."}
        return {"success": True, "message": f"Domain '{domain_clean}' was not actively blocked."}

dns_protection = DNSProtectionManager()
