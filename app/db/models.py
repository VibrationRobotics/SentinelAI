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
