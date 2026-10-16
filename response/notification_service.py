"""
NetSentinel - Notification & Alert Escalation Service
Implements Section 14.6 #8 Alert Escalation & Section 14.8 ESP32 Alert Integration.
"""

import time
import logging
from typing import Dict, Any, List, Optional
import collections

logger = logging.getLogger("netsentinel.notifications")

class NotificationService:
    """
    Dispatches alerts to:
    - Web Dashboard real-time feed
    - ESP32 Auxiliary Security Controller
    - System log
    - Webhook / Admin channels
    """

    def __init__(self):
        # Ring buffer of recent notifications for dashboard display
        self.recent_notifications = collections.deque(maxlen=100)
        self.esp32_listener = None # Reference to ESP32 controller if loaded

    def attach_esp32_controller(self, controller):
        self.esp32_listener = controller

    def send_alert(
        self,
        severity: str,
        title: str,
        message: str,
        target: Optional[str] = None,
        risk_score: float = 0.0,
        action_taken: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Broadcasts an alert across all active channels.
        """
        alert_payload = {
            "id": int(time.time() * 1000),
            "timestamp": time.time(),
            "severity": severity,
            "title": title,
            "message": message,
            "target": target,
            "risk_score": risk_score,
            "action_taken": action_taken or "NONE"
        }

        # Store in memory for dashboard
        self.recent_notifications.appendleft(alert_payload)

        # Log
        log_level = logging.INFO
        if severity in ["High", "Critical"]:
            log_level = logging.WARNING
        logger.log(log_level, f"[{severity.upper()}] {title} - Target: {target} - {message}")

        # Trigger ESP32 auxiliary hardware alert (Buzzer/LEDs) if configured
        if self.esp32_listener:
            try:
                self.esp32_listener.trigger_alert(severity=severity, target=target, score=risk_score)
            except Exception as e:
                logger.error(f"Failed to signal ESP32: {e}")

        return alert_payload

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(self.recent_notifications)[:limit]

notification_service = NotificationService()
