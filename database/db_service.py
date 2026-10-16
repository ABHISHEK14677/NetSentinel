"""
NetSentinel - Database Service
Manages SQLite engine, sessions, initialization, and default fixtures.
"""

import os
import hashlib
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from database.models import Base, AllowlistedAssetModel, ResponsePolicyModel, AuditLogEntryModel
from config.config import settings

# Engine setup
engine = create_engine(
    f"sqlite:///{settings.db_path}",
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """Dependency for obtaining database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initializes schema and seeds required safe fixtures."""
    os.makedirs(os.path.dirname(settings.db_path), exist_ok=True)
    Base.metadata.create_all(bind=engine)
    
    db: Session = SessionLocal()
    try:
        # 1. Seed Essential Protected Infrastructure (Section 14.11 / 14.14)
        default_protected = [
            ("127.0.0.1", "IP", "Localhost Loopback", True),
            ("127.0.0.0/8", "SUBNET", "Loopback IPv4 Subnet", True),
            ("::1", "IP", "IPv6 Loopback", True),
            ("192.168.1.1", "IP", "Default Gateway / Router (Configured)", True),
            ("192.168.1.254", "IP", "Alternative Default Gateway", True),
            ("10.0.0.1", "IP", "Private Network Gateway", True),
            ("1.1.1.1", "IP", "Essential DNS (Cloudflare)", True),
            ("8.8.8.8", "IP", "Essential DNS (Google)", True),
        ]
        for val, atype, desc, ess in default_protected:
            exists = db.query(AllowlistedAssetModel).filter_by(asset_value=val).first()
            if not exists:
                db.add(AllowlistedAssetModel(
                    asset_value=val,
                    asset_type=atype,
                    description=desc,
                    is_essential_infrastructure=ess,
                    added_by="SYSTEM_DEFAULT"
                ))

        # 2. Seed Default Response Policies
        default_policies = [
            ResponsePolicyModel(
                name="Severe Brute-Force IP Block",
                description="Temporary block for confirmed repeated authentication failures",
                min_risk_score=70.0,
                max_risk_score=100.0,
                min_confidence=0.75,
                threat_category="BRUTE_FORCE",
                action_type="BLOCK_SOURCE_IP",
                default_duration_seconds=600,
                is_active=True,
                requires_approval=False
            ),
            ResponsePolicyModel(
                name="Reconnaissance Port Scan Rate Limit",
                description="Connection rate-limiting for aggressive port scanning",
                min_risk_score=45.0,
                max_risk_score=75.0,
                min_confidence=0.6,
                threat_category="PORT_SCAN",
                action_type="RATE_LIMIT",
                default_duration_seconds=300,
                is_active=True,
                requires_approval=False
            ),
            ResponsePolicyModel(
                name="Malicious Command & Control Domain Suppression",
                description="DNS block for verified threat-intelligence malware C2 domains",
                min_risk_score=80.0,
                max_risk_score=100.0,
                min_confidence=0.85,
                threat_category="MALWARE_C2",
                action_type="DNS_BLOCK",
                default_duration_seconds=1800,
                is_active=True,
                requires_approval=True
            ),
            ResponsePolicyModel(
                name="Suspicious Device Quarantine",
                description="Gateway isolation for unauthorized or compromised internal endpoints",
                min_risk_score=85.0,
                max_risk_score=100.0,
                min_confidence=0.90,
                threat_category="UNAUTHORIZED_DEVICE",
                action_type="ISOLATE_DEVICE",
                default_duration_seconds=900,
                is_active=True,
                requires_approval=True
            )
        ]
        for p in default_policies:
            exists = db.query(ResponsePolicyModel).filter_by(name=p.name).first()
            if not exists:
                db.add(p)

        # 3. Initialize Genesis Audit Log if table empty
        if db.query(AuditLogEntryModel).count() == 0:
            genesis_payload = "GENESIS_ENTRY: NetSentinel 14 Active Protection Engine Initialized"
            genesis_hash = hashlib.sha256(genesis_payload.encode()).hexdigest()
            db.add(AuditLogEntryModel(
                operator="SYSTEM_INIT",
                event_type="ENGINE_START",
                policy_name="N/A",
                target="ALL",
                details=genesis_payload,
                result="SUCCESS",
                previous_hash="0" * 64,
                current_hash=genesis_hash
            ))

        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()
