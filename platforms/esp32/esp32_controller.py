"""
NetSentinel - ESP32 Auxiliary Security Controller
Implements Section 14.8 ESP32 Alert and Telemetry Controller Integration.
Enforces message authentication (HMAC-SHA256), heartbeats, tamper detection,
and fail-safe disconnect behavior.
"""

import hmac
import hashlib
import time
import json
import logging
from typing import Dict, Any, Optional
from config.config import settings
from response.notification_service import notification_service

logger = logging.getLogger("netsentinel.esp32")

class ESP32Controller:
    """
    Manages communication with ESP32 auxiliary unit.
    - Transmits authenticated alert payloads with LED/Buzzer patterns
    - Listens for heartbeats and enclosure tamper switch events
    - Warns if ESP32 disconnects
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.esp32_api_key
        self.is_connected = False
        self.last_heartbeat_time = 0.0
        self.tamper_detected = False
        self.firmware_version = "v1.4.2-sec"
        self.device_health = "HEALTHY"
        self.active_alert_pattern = "OFF"

    def generate_auth_signature(self, payload: str, timestamp: float) -> str:
        """Generates HMAC-SHA256 signature for authenticating alert messages to ESP32."""
        msg = f"{timestamp}:{payload}"
        return hmac.new(self.api_key.encode(), msg.encode(), hashlib.sha256).hexdigest()

    def verify_esp32_signature(self, payload: str, timestamp: float, signature: str) -> bool:
        expected = self.generate_auth_signature(payload, timestamp)
        return hmac.compare_digest(expected, signature)

    def trigger_alert(self, severity: str, target: Optional[str], score: float) -> Dict[str, Any]:
        """
        Sends authenticated alert command to ESP32 to activate LED color & buzzer tone.
        Severity Patterns:
        - Critical: Red LED blinking 5Hz, Continuous high-pitch siren (2800Hz)
        - High: Red LED solid, pulsed alarm tone (2000Hz)
        - Medium: Yellow LED solid, double-chirp tone (1200Hz)
        - Low: Blue LED pulse, single low beep (800Hz)
        - Informational: Green LED steady, mute
        """
        severity_map = {
            "Critical": {"led": "RED_FLASH_FAST", "buzzer": "SIREN_CONTINUOUS", "code": 4},
            "High": {"led": "RED_SOLID", "buzzer": "PULSED_ALARM", "code": 3},
            "Medium": {"led": "YELLOW_SOLID", "buzzer": "DOUBLE_CHIRP", "code": 2},
            "Low": {"led": "BLUE_PULSE", "buzzer": "SINGLE_BEEP", "code": 1},
            "Informational": {"led": "GREEN_STEADY", "buzzer": "NONE", "code": 0}
        }
        pattern = severity_map.get(severity, severity_map["Informational"])
        self.active_alert_pattern = pattern["led"]

        now = time.time()
        payload_data = {
            "cmd": "ALERT",
            "severity": severity,
            "target": target or "N/A",
            "score": score,
            "pattern": pattern
        }
        payload_str = json.dumps(payload_data)
        sig = self.generate_auth_signature(payload_str, now)

        # The ESP32 is explicitly prevented from claiming it blocked anything itself (Section 14.8)
        message = {
            "timestamp": now,
            "signature": sig,
            "payload": payload_data,
            "auxiliary_note": "Auxiliary physical alert indicator only; not an independent firewall enforcement point."
        }
        return message

    def process_esp32_telemetry(self, telemetry_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Receives telemetry from ESP32: Heartbeats, tamper alerts, temperature/health.
        """
        ts = telemetry_data.get("timestamp", time.time())
        sig = telemetry_data.get("signature", "")
        payload = telemetry_data.get("payload", {})
        payload_str = json.dumps(payload)

        # Authenticate telemetry message
        if not self.verify_esp32_signature(payload_str, ts, sig):
            return {"authenticated": False, "error": "Invalid HMAC signature"}

        self.last_heartbeat_time = time.time()
        self.is_connected = True
        self.firmware_version = payload.get("firmware_version", self.firmware_version)
        self.device_health = payload.get("health", "HEALTHY")

        # Hardware tamper detection (Section 14.8)
        if payload.get("tamper_switch_triggered"):
            self.tamper_detected = True
            notification_service.send_alert(
                severity="Critical",
                title="HARDWARE TAMPER DETECTED",
                message="ESP32 Enclosure sensor tripped! Physical security violation on monitoring hardware.",
                target="ESP32_PHYSICAL_ENCLOSURE",
                risk_score=95.0
            )

        return {
            "authenticated": True,
            "status": "TELEMETRY_RECORDED",
            "connected": True,
            "tamper": self.tamper_detected
        }

    def check_connection_health(self) -> Dict[str, Any]:
        """
        Verifies ESP32 heartbeat freshness. Warns if disconnected.
        """
        now = time.time()
        if (now - self.last_heartbeat_time) > settings.esp32_heartbeat_timeout_seconds:
            was_connected = self.is_connected
            self.is_connected = False
            if was_connected:
                notification_service.send_alert(
                    severity="High",
                    title="ESP32 Auxiliary Node Disconnected",
                    message="ESP32 auxiliary controller heartbeat timed out. Monitoring continues uninterrupted on host.",
                    target="ESP32_CONTROLLER",
                    risk_score=40.0
                )
            return {
                "connected": False,
                "seconds_since_heartbeat": round(now - self.last_heartbeat_time, 1),
                "status": "DISCONNECTED",
                "monitoring_state": "ACTIVE_UNINTERRUPTED"
            }
        return {
            "connected": True,
            "seconds_since_heartbeat": round(now - self.last_heartbeat_time, 1),
            "status": "CONNECTED",
            "tamper": self.tamper_detected,
            "firmware_version": self.firmware_version,
            "health": self.device_health
        }

esp32_controller = ESP32Controller()
# Connect to notification service
notification_service.attach_esp32_controller(esp32_controller)
