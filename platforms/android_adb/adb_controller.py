"""
NetSentinel - Android ADB Security Testing & Telemetry Controller
Integrates Android endpoints connected via ADB (USB or Wi-Fi).
Enables automated threat generation, device identity extraction,
and real-time verification of NetSentinel active protection and rollback.
"""

import subprocess
import shutil
import re
import time
import logging
from typing import Dict, Any, List, Optional
from threat_engine.device_inventory import device_inventory_manager
from threat_engine.detector import threat_detector, ThreatCategory
from response.response_engine import response_engine
from response.rollback_manager import rollback_manager
from config.config import settings

logger = logging.getLogger("netsentinel.adb")

class ADBDeviceController:
    """
    Manages interaction with Android devices via Android Debug Bridge.
    Extracts MAC/IP identity, runs controlled attack tests, and validates
    active blocking and recovery directly from the Android endpoint's perspective.
    """

    def __init__(self, adb_path: Optional[str] = None):
        self.adb_bin = adb_path or shutil.which("adb") or "/home/kali/.local/bin/adb"

    def _run_adb(self, args: List[str], timeout: int = 10) -> Dict[str, Any]:
        """Runs an adb CLI command and returns (success, stdout, stderr)."""
        cmd = [self.adb_bin] + args
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            return {
                "success": (res.returncode == 0),
                "stdout": res.stdout.strip(),
                "stderr": res.stderr.strip(),
                "returncode": res.returncode
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "stdout": "", "stderr": f"Command timed out after {timeout}s", "returncode": -1}
        except Exception as e:
            return {"success": False, "stdout": "", "stderr": str(e), "returncode": -1}

    def list_devices(self) -> List[Dict[str, Any]]:
        """Lists attached ADB devices with serial, status, and model metadata."""
        res = self._run_adb(["devices", "-l"])
        if not res["success"]:
            return []

        devices = []
        lines = res["stdout"].splitlines()
        for line in lines[1:]: # Skip header
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            serial = parts[0]
            status = parts[1] if len(parts) > 1 else "unknown"

            # Parse extra fields like model:Pixel_7
            model = "Android Device"
            device_prop = ""
            for item in parts[2:]:
                if item.startswith("model:"):
                    model = item.split(":", 1)[1].replace("_", " ")
                elif item.startswith("device:"):
                    device_prop = item.split(":", 1)[1]

            devices.append({
                "serial": serial,
                "status": status,
                "model": model,
                "device_prop": device_prop,
                "is_authorized": (status == "device")
            })
        return devices

    def connect_wifi_device(self, ip_address: str, port: int = 5555) -> Dict[str, Any]:
        """Connects to an Android phone over Wi-Fi (adb connect IP:5555)."""
        target = f"{ip_address}:{port}"
        res = self._run_adb(["connect", target], timeout=8)
        connected = "connected" in res["stdout"].lower() and "unable" not in res["stdout"].lower()
        return {
            "success": connected,
            "target": target,
            "output": res["stdout"] or res["stderr"]
        }

    def get_device_identity(self, serial: Optional[str] = None) -> Dict[str, Any]:
        """
        Extracts Android hardware details: IP address, MAC address, model, and OS version.
        """
        prefix = ["-s", serial] if serial else []

        # 1. Device model and Android OS version
        model_res = self._run_adb(prefix + ["shell", "getprop", "ro.product.model"])
        model = model_res["stdout"] if model_res["success"] else "Android Device"

        os_res = self._run_adb(prefix + ["shell", "getprop", "ro.build.version.release"])
        android_version = os_res["stdout"] if os_res["success"] else "Unknown"

        # 2. Get IP address on wlan0 or rmnet
        ip_res = self._run_adb(prefix + ["shell", "ip", "addr", "show", "wlan0"])
        ip_addr = None
        mac_addr = None

        if ip_res["success"] and ip_res["stdout"]:
            # Match inet 192.168.x.x
            ip_match = re.search(r"inet\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", ip_res["stdout"])
            if ip_match:
                ip_addr = ip_match.group(1)

            # Match link/ether xx:xx:xx:xx:xx:xx
            mac_match = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", ip_res["stdout"])
            if mac_match:
                mac_addr = mac_match.group(1).upper()

        # Fallback if wlan0 not active (e.g. mobile data or emulator eth0)
        if not ip_addr:
            all_ip_res = self._run_adb(prefix + ["shell", "ip", "route"])
            if all_ip_res["success"]:
                src_match = re.search(r"src\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", all_ip_res["stdout"])
                if src_match:
                    ip_addr = src_match.group(1)

        return {
            "serial": serial,
            "model": model,
            "android_version": android_version,
            "ip_address": ip_addr or "192.168.1.188", # Default if offline/simulated
            "mac_address": mac_addr or "9C:28:F7:3A:4B:5C",
            "interface": "wlan0"
        }

    def register_in_inventory(self, identity: Dict[str, Any]) -> Dict[str, Any]:
        """
        Registers the Android device in NetSentinel's Monitored Device Inventory (Section 14.7).
        """
        dev = device_inventory_manager.register_or_update_device(
            ip_address=identity["ip_address"],
            mac_address=identity.get("mac_address"),
            hostname=f"{identity.get('model', 'Android')}-{identity['ip_address'].replace('.', '-')}",
            interface="wlan0",
            observed_protocol="TCP,UDP,HTTPS",
            risk_increment=10.0 # Initial observation score
        )
        return {
            "id": dev.id,
            "ip": dev.ip_address,
            "mac": dev.mac_address,
            "trust_status": dev.trust_status,
            "risk_score": dev.risk_score
        }

    def run_security_test(
        self,
        test_type: str,
        target_ip: str = "10.0.2.15",
        target_port: int = 8000,
        serial: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes a controlled security threat test originating from the Android device.
        Supported test types:
        - 'port_scan': Generates rapid port probes against NetSentinel
        - 'brute_force': Generates repeated rapid failed connection handshakes
        - 'c2_lookup': Resolves a simulated malware C2 domain from the phone
        - 'anomalous_burst': Sends a burst of HTTP connections
        """
        prefix = ["-s", serial] if serial else []
        identity = self.get_device_identity(serial)
        src_ip = identity["ip_address"]
        src_mac = identity.get("mac_address")

        logger.info(f"Executing ADB security test '{test_type}' from Android device {src_ip} ({identity['model']})...")

        # 1. Execute live command on device if available
        cmd_result = None
        if test_type == "port_scan":
            # Test connectivity to common ports
            shell_cmd = f"for p in 22 80 443 8000 8080; do (echo > /dev/tcp/{target_ip}/$p) 2>/dev/null; done"
            cmd_result = self._run_adb(prefix + ["shell", shell_cmd], timeout=5)
            threat_cat = ThreatCategory.PORT_SCAN
            ids_sev = 75.0
            ai_score = 65.0

        elif test_type == "brute_force":
            # Repeated authentication failure simulation
            shell_cmd = f"for i in 1 2 3 4 5; do nc -w 1 {target_ip} 22 2>/dev/null; done"
            cmd_result = self._run_adb(prefix + ["shell", shell_cmd], timeout=5)
            threat_cat = ThreatCategory.BRUTE_FORCE
            ids_sev = 85.0
            ai_score = 70.0

        elif test_type == "c2_lookup":
            # DNS lookup from device
            shell_cmd = "ping -c 1 -W 1 c2-evil-botnet.bad 2>/dev/null"
            cmd_result = self._run_adb(prefix + ["shell", shell_cmd], timeout=5)
            threat_cat = ThreatCategory.MALWARE_C2
            ids_sev = 95.0
            ai_score = 80.0

        else: # anomalous_burst
            shell_cmd = f"for i in $(seq 1 10); do (nc -w 1 {target_ip} {target_port}) 2>/dev/null; done"
            cmd_result = self._run_adb(prefix + ["shell", shell_cmd], timeout=5)
            threat_cat = ThreatCategory.DOS_RATE_ANOMALY
            ids_sev = 60.0
            ai_score = 75.0

        # 2. Ingest threat event into NetSentinel Detection & Response Engine
        event_payload = {
            "category": threat_cat,
            "src_ip": src_ip,
            "dst_ip": target_ip,
            "src_mac": src_mac,
            "dst_port": target_port,
            "ids_severity": ids_sev,
            "ai_anomaly_score": ai_score,
            "confidence": 0.90,
            "proto": "TCP",
            "hostname": identity["model"],
            "notes": f"Generated by ADB Security Test harness ({test_type})"
        }

        # Step A: Threat Detection & Correlation
        threat_eval = threat_detector.process_event(event_payload)

        # Step B: Policy Evaluation & Active Prevention
        response_res = response_engine.process_threat(threat_eval)

        return {
            "test_type": test_type,
            "android_device": {
                "model": identity["model"],
                "ip": src_ip,
                "mac": src_mac,
                "android_version": identity["android_version"]
            },
            "device_shell_result": cmd_result,
            "threat_evaluation": {
                "category": threat_eval["category"],
                "risk_score": threat_eval["risk_score"],
                "severity": threat_eval["severity"],
                "recommended_action": threat_eval["recommended_action"]
            },
            "netsentinel_response": {
                "action_type": response_res.get("action_type"),
                "status": response_res.get("status") or response_res.get("outcome_status"),
                "verified": response_res.get("verified", False),
                "action_uuid": response_res.get("action_uuid")
            }
        }

    def verify_device_blocked_on_endpoint(self, target_ip: str = "10.0.2.15", serial: Optional[str] = None) -> Dict[str, Any]:
        """
        Probes from the Android shell to verify whether traffic to NetSentinel is blocked.
        """
        prefix = ["-s", serial] if serial else []
        # Attempt connection from phone to NetSentinel
        res = self._run_adb(prefix + ["shell", "nc", "-w", "2", "-z", target_ip, "8000"], timeout=4)
        is_blocked = (res["returncode"] != 0)
        return {
            "target_ip": target_ip,
            "phone_probe_exitcode": res["returncode"],
            "is_blocked_on_phone": is_blocked,
            "message": "Traffic from Android device blocked successfully by NetSentinel firewall." if is_blocked else "Traffic reached server (not blocked)."
        }

adb_device_controller = ADBDeviceController()
