"""
NetSentinel - Database Models
Mandated by Section 14.13 & Section 14.7
"""

import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, Enum as SqlEnum
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class ResponsePolicyModel(Base):
    """Stores configured response policies matching conditions to actions."""
    __tablename__ = "response_policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    min_risk_score = Column(Float, default=0.0)
    max_risk_score = Column(Float, default=100.0)
    min_confidence = Column(Float, default=0.5)
    threat_category = Column(String(100), nullable=True) # e.g. PORT_SCAN, BRUTE_FORCE, etc.
    action_type = Column(String(50), nullable=False)     # e.g. BLOCK_SOURCE_IP, RATE_LIMIT
    default_duration_seconds = Column(Integer, default=300)
    is_active = Column(Boolean, default=True)
    requires_approval = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class ResponseActionModel(Base):
    """
    Every response record per Section 14.4:
    - Triggering event and evidence
    - Risk score and confidence
    - Selected response action
    - Target address, domain or device
    - Scope and expiry time
    - Authorization status
    - Execution result
    - Verification result
    - Rollback information
    - Audit timestamp
    """
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    action_uuid = Column(String(64), unique=True, nullable=False, index=True)
    policy_id = Column(Integer, ForeignKey("response_policies.id"), nullable=True)
    action_type = Column(String(50), nullable=False) # BLOCK_SOURCE_IP, DNS_BLOCK, etc.
    target = Column(String(255), nullable=False, index=True) # IP, MAC, Domain
    target_type = Column(String(30), default="IP") # IP, MAC, DOMAIN, SUBNET
    direction = Column(String(20), default="INBOUND") # INBOUND, OUTBOUND, FORWARD
    interface = Column(String(50), default="eth0")

    # Risk and Evidence
    risk_score = Column(Float, nullable=False)
    confidence = Column(Float, nullable=False)
    threat_category = Column(String(100), nullable=False)
    triggering_event = Column(Text, nullable=False)
    evidence_json = Column(Text, nullable=False) # Structured evidence payload

    # Lifecycle & Authorization
    protection_mode = Column(String(50), nullable=False)
    authorization_status = Column(String(30), default="PENDING") # APPROVED, REJECTED, AUTO_AUTHORIZED, PENDING
    authorized_by = Column(String(100), default="SYSTEM")
    authorized_at = Column(DateTime, nullable=True)

    # Execution & Verification
    dry_run = Column(Boolean, default=False)
    execution_status = Column(String(30), default="PENDING") # SUCCESS, FAILED, SKIPPED, DRY_RUN
    execution_details = Column(Text, nullable=True)
    verification_status = Column(String(30), default="UNVERIFIED") # VERIFIED, FAILED, NOT_APPLICABLE
    verification_details = Column(Text, nullable=True)

    # Scope & Expiration
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=True, index=True)
    is_active = Column(Boolean, default=True)

    # Rollback Information
    is_rolled_back = Column(Boolean, default=False)
    rolled_back_at = Column(DateTime, nullable=True)
    rollback_reason = Column(String(255), nullable=True)

    # Relationships
    verifications = relationship("EnforcementVerificationModel", back_populates="action")
    firewall_rules = relationship("FirewallRuleRecordModel", back_populates="action")

class BlockedTargetModel(Base):
    """Tracks currently active or historically blocked IP/domain targets."""
    __tablename__ = "blocked_targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(255), unique=True, nullable=False, index=True)
    target_type = Column(String(30), default="IP")
    reason = Column(Text, nullable=False)
    risk_score = Column(Float, default=0.0)
    blocked_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=True, index=True)
    is_active = Column(Boolean, default=True)
    action_uuid = Column(String(64), nullable=True)
    unblocked_at = Column(DateTime, nullable=True)
    unblocked_by = Column(String(100), nullable=True)

class QuarantinedDeviceModel(Base):
    """Tracks quarantined LAN devices per Section 14.7."""
    __tablename__ = "quarantined_devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String(30), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    hostname = Column(String(100), nullable=True)
    quarantine_method = Column(String(50), default="GATEWAY_NFTABLES") # GATEWAY_NFTABLES, ARP_ISOLATION, HOST_BLOCK
    enforcement_point = Column(String(100), default="Linux Gateway / Monitored Interface")
    reason = Column(Text, nullable=False)
    quarantined_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    released_at = Column(DateTime, nullable=True)
    released_by = Column(String(100), nullable=True)

class ApprovalRequestModel(Base):
    """Tracks pending human operator approvals for Mode B / Assisted Protection."""
    __tablename__ = "approval_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_uuid = Column(String(64), unique=True, nullable=False, index=True)
    action_uuid = Column(String(64), nullable=False)
    target = Column(String(255), nullable=False)
    action_type = Column(String(50), nullable=False)
    risk_score = Column(Float, nullable=False)
    severity = Column(String(20), nullable=False)
    proposed_rule = Column(Text, nullable=False)
    potential_impact = Column(Text, nullable=False)
    duration_seconds = Column(Integer, default=300)
    status = Column(String(30), default="PENDING") # PENDING, APPROVED, REJECTED, EXPIRED
    decision_by = Column(String(100), nullable=True)
    decision_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

class AllowlistedAssetModel(Base):
    """Protected devices, gateways, DNS, and management stations."""
    __tablename__ = "allowlisted_assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_value = Column(String(255), unique=True, nullable=False) # IP, Subnet, or MAC
    asset_type = Column(String(30), default="IP") # IP, SUBNET, MAC, DOMAIN
    description = Column(String(255), nullable=False)
    is_essential_infrastructure = Column(Boolean, default=False) # True for gateway/DNS/SSH
    added_by = Column(String(100), default="ADMIN")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class FirewallRuleRecordModel(Base):
    """Low-level firewall rules managed by NetSentinel in nftables."""
    __tablename__ = "firewall_rule_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    action_id = Column(Integer, ForeignKey("response_actions.id"), nullable=True)
    table_name = Column(String(50), default="inet netsentinel")
    chain_name = Column(String(50), default="netsentinel_input")
    set_name = Column(String(50), nullable=True)
    rule_spec = Column(Text, nullable=False)
    handle = Column(Integer, nullable=True)
    is_active = Column(Boolean, default=True)
    applied_at = Column(DateTime, default=datetime.datetime.utcnow)
    removed_at = Column(DateTime, nullable=True)

    action = relationship("ResponseActionModel", back_populates="firewall_rules")

class EnforcementVerificationModel(Base):
    """Verification results validating that firewall / restriction took effect."""
    __tablename__ = "enforcement_verifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    action_id = Column(Integer, ForeignKey("response_actions.id"), nullable=False)
    verification_time = Column(DateTime, default=datetime.datetime.utcnow)
    method = Column(String(50), default="NFT_SET_QUERY") # NFT_SET_QUERY, PACKET_PROBE, STATE_CHECK
    status = Column(String(30), nullable=False) # SUCCESS, FAILED, DEGRADED
    details = Column(Text, nullable=True)
    checked_kernel_state = Column(Boolean, default=True)

    action = relationship("ResponseActionModel", back_populates="verifications")

class RollbackRecordModel(Base):
    """Auditable rollback logs of reverted firewall and restriction changes."""
    __tablename__ = "rollback_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    action_uuid = Column(String(64), nullable=False)
    target = Column(String(255), nullable=False)
    action_type = Column(String(50), nullable=False)
    reason = Column(String(255), nullable=False) # EXPIRED, OPERATOR_MANUAL, EMERGENCY_STOP
    initiated_by = Column(String(100), default="SYSTEM_EXPIRER")
    success = Column(Boolean, default=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class DeviceInventoryModel(Base):
    """
    Monitored-device inventory mandated by Section 14.7:
    Device IP, MAC, hostname, first/last seen, interface, protocols,
    trust status, risk score, related alerts, current enforcement state.
    """
    __tablename__ = "device_inventory"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False, index=True)
    mac_address = Column(String(30), nullable=True, index=True)
    hostname = Column(String(100), nullable=True)
    interface = Column(String(50), default="eth0")
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    observed_protocols = Column(String(255), default="TCP,UDP,DNS")
    
    # States per 14.7: Trusted, Unknown, Under observation, Suspicious, Restricted, Quarantined, Released
    trust_status = Column(String(50), default="Unknown")
    risk_score = Column(Float, default=0.0)
    related_alerts_count = Column(Integer, default=0)
    current_enforcement_state = Column(String(50), default="NONE") # NONE, RATE_LIMITED, BLOCKED, QUARANTINED
    notes = Column(Text, nullable=True)

class AuditLogEntryModel(Base):
    """
    Tamper-evident audit trail with SHA-256 cryptographic hash-chaining.
    Records operator, policy, evidence, timestamps, result and rollback state.
    """
    __tablename__ = "audit_log_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    operator = Column(String(100), default="SYSTEM")
    event_type = Column(String(50), nullable=False) # POLICY_CHANGE, FIREWALL_APPLY, ROLLBACK, EMERGENCY_STOP
    policy_name = Column(String(100), nullable=True)
    target = Column(String(255), nullable=True)
    details = Column(Text, nullable=False)
    result = Column(String(50), nullable=False)
    
    # Hash Chaining
    previous_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False)
