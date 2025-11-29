from sqlalchemy import Boolean, Integer, String, DateTime, ForeignKey, JSON, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import Optional, List
from datetime import datetime
from app.db.base import Base

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    full_name: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    role: Mapped[str] = mapped_column(String, default="user", nullable=False)  # admin, user, viewer
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    resolved_threats: Mapped[List["ThreatEvent"]] = relationship("ThreatEvent", back_populates="resolver")
    response_actions: Mapped[List["ResponseAction"]] = relationship("ResponseAction", back_populates="performer")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.created_at is None:
            self.created_at = datetime.utcnow()

class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    severity: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(String)
    indicators: Mapped[dict] = mapped_column(JSON)
    confidence_score: Mapped[float] = mapped_column(Float)
    source_ip: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    target_systems: Mapped[dict] = mapped_column(JSON)
    mitre_techniques: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String, default="OPEN")
    resolved_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    resolver: Mapped[Optional["User"]] = relationship("User", back_populates="resolved_threats")

class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    threat_id: Mapped[str] = mapped_column(String, ForeignKey("threat_events.id"))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    action_type: Mapped[str] = mapped_column(String)
    action_details: Mapped[dict] = mapped_column(JSON)
    performer_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)

    performer: Mapped[Optional["User"]] = relationship("User", back_populates="response_actions")


class Agent(Base):
    """Connected security agents (Windows, Linux, etc.)"""
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    hostname: Mapped[str] = mapped_column(String, unique=True, index=True)
    platform: Mapped[str] = mapped_column(String)  # Windows, Linux, etc.
    platform_version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    agent_version: Mapped[str] = mapped_column(String)
    capabilities: Mapped[dict] = mapped_column(JSON, default=list)  # List of capabilities
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    registered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    status: Mapped[str] = mapped_column(String, default="online")  # online, offline, error
    ip_address: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    system_info: Mapped[dict] = mapped_column(JSON, default=dict)  # Full system info (CPU, RAM, disk, etc.)
    
    # Relationships
    events: Mapped[List["SecurityEvent"]] = relationship("SecurityEvent", back_populates="agent")


class SecurityEvent(Base):
    """Security events from agents"""
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    agent_id: Mapped[int] = mapped_column(Integer, ForeignKey("agents.id"), index=True)
    event_type: Mapped[str] = mapped_column(String, index=True)  # process, network, registry, etc.
    severity: Mapped[str] = mapped_column(String, default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    description: Mapped[str] = mapped_column(String)
    details: Mapped[dict] = mapped_column(JSON, default=dict)  # Event-specific data
    source_ip: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    process_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    is_threat: Mapped[bool] = mapped_column(Boolean, default=False)
    threat_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("threat_events.id"), nullable=True)
    
    # Relationships
    agent: Mapped["Agent"] = relationship("Agent", back_populates="events")


class BlockedIP(Base):
    """IPs blocked by auto-response"""
    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ip_address: Mapped[str] = mapped_column(String, unique=True, index=True)
    reason: Mapped[str] = mapped_column(String)
    blocked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    blocked_by: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # auto or username
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    threat_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class AuditLog(Base):
    """Audit log for all system activities"""
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    source: Mapped[str] = mapped_column(String, index=True)  # agent, dashboard, tauri, api
    action: Mapped[str] = mapped_column(String, index=True)  # login, threat_detected, ip_blocked, etc.
    severity: Mapped[str] = mapped_column(String, default="INFO")  # INFO, WARNING, ERROR, CRITICAL
    description: Mapped[str] = mapped_column(String)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    agent_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("agents.id"), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class APIKey(Base):
    """API keys for agent authentication"""
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    key_hash: Mapped[str] = mapped_column(String, unique=True, index=True)  # SHA256 hash of the key
    name: Mapped[str] = mapped_column(String)  # Friendly name
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_used: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    permissions: Mapped[dict] = mapped_column(JSON, default=dict)  # {"agents": ["read", "write"], ...}
    rate_limit: Mapped[int] = mapped_column(Integer, default=1000)  # Requests per hour


class AgentLicense(Base):
    """Per-agent licensing"""
    __tablename__ = "agent_licenses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    license_key: Mapped[str] = mapped_column(String, unique=True, index=True)
    agent_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("agents.id"), nullable=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    tier: Mapped[str] = mapped_column(String, default="free")  # free, pro, enterprise
    max_agents: Mapped[int] = mapped_column(Integer, default=1)  # Max agents allowed
    max_events_per_day: Mapped[int] = mapped_column(Integer, default=1000)
    ai_analysis_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class UsageMetric(Base):
    """Usage analytics for agents and API"""
    __tablename__ = "usage_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    metric_type: Mapped[str] = mapped_column(String, index=True)  # api_call, event_received, ai_analysis, etc.
    agent_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("agents.id"), nullable=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    count: Mapped[int] = mapped_column(Integer, default=1)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class SystemHealth(Base):
    """System health monitoring for autonomous operations"""
    __tablename__ = "system_health"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    component: Mapped[str] = mapped_column(String, index=True)  # web, db, redis, agent
    status: Mapped[str] = mapped_column(String)  # healthy, unhealthy, degraded
    response_time_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    auto_action_taken: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # restart, alert, etc.


class UserSettings(Base):
    """User-specific settings"""
    __tablename__ = "user_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), unique=True)
    
    # Auto-response settings
    auto_response_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    severity_threshold: Mapped[str] = mapped_column(String, default="HIGH")  # HIGH, MEDIUM, LOW
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=300)
    ip_whitelist: Mapped[str] = mapped_column(String, default="127.0.0.1\n192.168.1.1\n10.0.0.0/8")
    
    # AI settings
    ai_analysis_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Monitoring settings
    process_monitor_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    network_monitor_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    log_collector_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    file_scanner_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Notification settings
    browser_notifications: Mapped[bool] = mapped_column(Boolean, default=True)
    sound_alerts: Mapped[bool] = mapped_column(Boolean, default=False)
    email_alerts: Mapped[bool] = mapped_column(Boolean, default=False)
    
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AgentCommand(Base):
    """Commands queued for agents to execute (autonomous response)"""
    __tablename__ = "agent_commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    agent_id: Mapped[int] = mapped_column(Integer, ForeignKey("agents.id"), index=True)
    command_type: Mapped[str] = mapped_column(String, index=True)  # block_ip, kill_process, quarantine_file, scan_path
    target: Mapped[str] = mapped_column(String)  # IP address, PID, file path, etc.
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)  # Additional parameters
    priority: Mapped[int] = mapped_column(Integer, default=5)  # 1=highest, 10=lowest
    status: Mapped[str] = mapped_column(String, default="pending")  # pending, sent, executed, failed
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    result: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # success, failed, error message
    threat_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("threat_events.id"), nullable=True)
    
    # Relationships
    agent: Mapped["Agent"] = relationship("Agent")
