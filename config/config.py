"""
NetSentinel - Configuration Module
Enforces Safe Defaults as mandated by Section 14.14
"""

import os
from enum import Enum
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class ProtectionMode(str, Enum):
    MODE_A = "MONITOR_ONLY"              # Mode A: Monitor Only
    MODE_B = "ASSISTED_PROTECTION"       # Mode B: Assisted Protection (approval required)
    MODE_C = "AUTOMATIC_TEMPORARY"       # Mode C: Automatic Temporary Protection
    MODE_D = "STRICT_PREVENTION"         # Mode D: Strict Prevention

class DeploymentPlatform(str, Enum):
    PC_KALI = "PC_KALI"                  # Kali Linux / Debian host
    RASPBERRY_PI = "RASPBERRY_PI"        # Raspberry Pi (Passive or Gateway)
    ESP32 = "ESP32"                      # ESP32 Auxiliary controller

class GatewayMode(str, Enum):
    PASSIVE_MONITOR = "PASSIVE_MONITOR"
    AUTHORIZED_GATEWAY = "AUTHORIZED_GATEWAY"

class Settings(BaseModel):
    # Deployment & Identity
    app_name: str = "NetSentinel"
    version: str = "14.0.0"
    platform: DeploymentPlatform = DeploymentPlatform.PC_KALI
    gateway_mode: GatewayMode = GatewayMode.PASSIVE_MONITOR

    # 14.14 Safe Default Configuration
    # Safe defaults: Monitor Only mode, firewall modification disabled, dry-run enabled
    protection_mode: ProtectionMode = ProtectionMode.MODE_A
    firewall_modification_enabled: bool = False
    automatic_device_quarantine_enabled: bool = False
    automatic_permanent_blocking_enabled: bool = False
    automatic_temporary_blocking_enabled: bool = False
    dry_run_mode: bool = True
    emergency_stop_active: bool = False

    # Database
    db_path: str = os.getenv(
        "NETSENTINEL_DB_PATH",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "database", "netsentinel.db")
    )
    
    # Audit Log Secret Key for HMAC Integrity Chaining
    audit_secret_key: str = os.getenv("NETSENTINEL_AUDIT_SECRET", "netsentinel-tamper-evident-chain-secret-key-2026")

    # Timeouts & Expirations (seconds)
    default_block_duration_seconds: int = 300    # 5 minutes default temporary block
    max_block_duration_seconds: int = 3600       # 1 hour maximum temporary block
    approval_timeout_seconds: int = 600          # 10 minutes before pending approval expires
    threat_intel_cache_ttl_seconds: int = 3600   # 1 hour threat intel freshness TTL

    # Risk Scoring Thresholds (Section 14.3)
    score_informational_max: int = 19
    score_low_max: int = 39
    score_medium_max: int = 59
    score_high_max: int = 79
    score_critical_min: int = 80

    # Protected Infrastructure & Allowlists (Crucial Safeguard: Never block these)
    protected_subnets: List[str] = Field(default_factory=lambda: [
        "127.0.0.0/8",
        "::1/128"
    ])
    protected_ips: List[str] = Field(default_factory=lambda: [
        "127.0.0.1",
        "0.0.0.0"
    ])
    protected_ports: List[int] = Field(default_factory=lambda: [
        22,    # SSH Management
        53,    # DNS Essential
        67,    # DHCP Server
        68,    # DHCP Client
        8000   # NetSentinel Dashboard/API
    ])

    # ESP32 Auxiliary Settings
    esp32_enabled: bool = True
    esp32_api_key: str = os.getenv("ESP32_API_KEY", "esp32-authenticated-key-sec-99")
    esp32_heartbeat_timeout_seconds: int = 15

    # Web Dashboard Auth
    dashboard_username: str = os.getenv("DASHBOARD_USER", "admin")
    dashboard_password_hash: str = os.getenv("DASHBOARD_PASS_HASH", "$2b$12$e88yR.3Z7W.k0uVvE/U2mO59K13K3l6N/bV3X1G4bV5Y1Z3l6N/bV") # Default admin bcrypt
    jwt_secret: str = os.getenv("JWT_SECRET", "netsentinel-super-secure-jwt-secret-2026")

    # Network Interfaces
    monitored_interface: str = "eth0"
    gateway_internal_interface: Optional[str] = "eth1"
    gateway_external_interface: Optional[str] = "eth0"

    # ── Live Packet Capture & ML Engine (BCAST IDS paper) ──────────────────
    packet_capture_enabled: bool = os.getenv("NETSENTINEL_CAPTURE_ENABLED", "false").lower() == "true"
    bum_window_seconds: int = 10          # Feature extraction window (paper: 10s)
    ml_min_training_samples: int = 50     # Min MAC-windows before first train
    ml_contamination: float = 0.018       # Isolation Forest contamination (~1.8%)
    ml_drift_threshold: float = 0.15      # Anomaly rate above this triggers retrain
    ml_model_path: str = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "database", "isolation_forest_model.pkl"
    )

    # ── Evidence / PCAP Storage ─────────────────────────────────────────────
    evidence_dir: str = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evidence"
    )
    evidence_max_disk_gb: float = float(os.getenv("NETSENTINEL_EVIDENCE_MAX_GB", "2.0"))

    # ── Email Alerts ────────────────────────────────────────────────────────
    smtp_enabled: bool = os.getenv("NETSENTINEL_SMTP_ENABLED", "false").lower() == "true"
    smtp_host: str = os.getenv("NETSENTINEL_SMTP_HOST", "smtp.gmail.com")
    smtp_port: int = int(os.getenv("NETSENTINEL_SMTP_PORT", "587"))
    smtp_user: str = os.getenv("NETSENTINEL_SMTP_USER", "")
    smtp_password: str = os.getenv("NETSENTINEL_SMTP_PASS", "")
    smtp_from: str = os.getenv("NETSENTINEL_SMTP_FROM", "netsentinel@localhost")
    smtp_to: List[str] = Field(
        default_factory=lambda: [x for x in os.getenv("NETSENTINEL_SMTP_TO", "").split(",") if x]
    )
    email_min_severity: str = os.getenv("NETSENTINEL_EMAIL_MIN_SEVERITY", "HIGH")

    # ── ARP Association Snapshot ────────────────────────────────────────────
    arp_snapshot_path: str = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "database", "arp_associations.json"
    )

# Global settings instance
settings = Settings()
