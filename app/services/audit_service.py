"""
Audit Service - Centralized audit logging for all system activities
Logs to PostgreSQL audit_logs table for persistence
"""
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.db.models import AuditLog

logger = logging.getLogger(__name__)


class AuditService:
    """Service for logging audit events to database"""
    
    # Action types
    ACTION_LOGIN = "login"
    ACTION_LOGOUT = "logout"
    ACTION_REGISTER = "register"
    ACTION_THREAT_DETECTED = "threat_detected"
    ACTION_THREAT_RESOLVED = "threat_resolved"
    ACTION_THREAT_BLOCKED = "threat_blocked"
    ACTION_IP_BLOCKED = "ip_blocked"
    ACTION_IP_UNBLOCKED = "ip_unblocked"
    ACTION_AGENT_REGISTERED = "agent_registered"
    ACTION_AGENT_HEARTBEAT = "agent_heartbeat"
    ACTION_AGENT_OFFLINE = "agent_offline"
    ACTION_API_KEY_CREATED = "api_key_created"
    ACTION_API_KEY_REVOKED = "api_key_revoked"
    ACTION_USER_UPDATED = "user_updated"
    ACTION_TIER_CHANGED = "tier_changed"
    ACTION_SETTINGS_CHANGED = "settings_changed"
    ACTION_AI_ANALYSIS = "ai_analysis"
    ACTION_VIRUSTOTAL_CHECK = "virustotal_check"
    ACTION_WHITELIST_ADDED = "whitelist_added"
    ACTION_SCAN_STARTED = "scan_started"
    ACTION_SCAN_COMPLETED = "scan_completed"
    ACTION_AUTO_RESPONSE = "auto_response"
    ACTION_REMEDIATION = "remediation"
    
    # Sources
    SOURCE_DASHBOARD = "dashboard"
    SOURCE_AGENT = "agent"
    SOURCE_API = "api"
    SOURCE_SYSTEM = "system"
    SOURCE_AUTO = "auto"
    
    @staticmethod
    async def log(
        db: AsyncSession,
        action: str,
        description: str,
        source: str = "system",
        severity: str = "INFO",
        user_id: Optional[int] = None,
        agent_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        hostname: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> Optional[AuditLog]:
        """
        Log an audit event to the database
        
        Args:
            db: Database session
            action: Type of action (use ACTION_* constants)
            description: Human-readable description
            source: Where the action originated (use SOURCE_* constants)
            severity: INFO, WARNING, ERROR, CRITICAL
            user_id: User who performed the action (if applicable)
            agent_id: Agent involved (if applicable)
            ip_address: IP address involved
            hostname: Hostname involved
            details: Additional JSON details
        """
        try:
            audit_log = AuditLog(
                timestamp=datetime.utcnow(),
                source=source,
                action=action,
                severity=severity,
                description=description,
                details=details or {},
                user_id=user_id,
                agent_id=agent_id,
                ip_address=ip_address,
                hostname=hostname
            )
            db.add(audit_log)
            await db.commit()
            logger.debug(f"Audit log: [{severity}] {action} - {description}")
            return audit_log
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
            await db.rollback()
            return None
    
    @staticmethod
    async def get_recent(
        db: AsyncSession,
        limit: int = 100,
        source: Optional[str] = None,
        action: Optional[str] = None,
        severity: Optional[str] = None,
        user_id: Optional[int] = None,
        agent_id: Optional[int] = None
    ) -> list:
        """Get recent audit logs with optional filters"""
        try:
            query = select(AuditLog).order_by(desc(AuditLog.timestamp))
            
            if source:
                query = query.where(AuditLog.source == source)
            if action:
                query = query.where(AuditLog.action == action)
            if severity:
                query = query.where(AuditLog.severity == severity)
            if user_id:
                query = query.where(AuditLog.user_id == user_id)
            if agent_id:
                query = query.where(AuditLog.agent_id == agent_id)
            
            query = query.limit(limit)
            result = await db.execute(query)
            return result.scalars().all()
        except Exception as e:
            logger.error(f"Failed to fetch audit logs: {e}")
            return []


# Singleton-like helper functions for convenience
async def log_audit(
    db: AsyncSession,
    action: str,
    description: str,
    **kwargs
) -> Optional[AuditLog]:
    """Convenience function to log audit events"""
    return await AuditService.log(db, action, description, **kwargs)


async def log_threat_detected(
    db: AsyncSession,
    threat_id: str,
    source_ip: str,
    severity: str,
    description: str,
    agent_id: Optional[int] = None
):
    """Log a threat detection event"""
    return await AuditService.log(
        db,
        action=AuditService.ACTION_THREAT_DETECTED,
        description=description,
        source=AuditService.SOURCE_AGENT if agent_id else AuditService.SOURCE_API,
        severity=severity,
        agent_id=agent_id,
        ip_address=source_ip,
        details={"threat_id": threat_id}
    )


async def log_user_action(
    db: AsyncSession,
    user_id: int,
    action: str,
    description: str,
    details: Optional[Dict] = None
):
    """Log a user action"""
    return await AuditService.log(
        db,
        action=action,
        description=description,
        source=AuditService.SOURCE_DASHBOARD,
        severity="INFO",
        user_id=user_id,
        details=details
    )


async def log_agent_action(
    db: AsyncSession,
    agent_id: int,
    action: str,
    description: str,
    hostname: Optional[str] = None,
    severity: str = "INFO",
    details: Optional[Dict] = None
):
    """Log an agent action"""
    return await AuditService.log(
        db,
        action=action,
        description=description,
        source=AuditService.SOURCE_AGENT,
        severity=severity,
        agent_id=agent_id,
        hostname=hostname,
        details=details
    )


async def log_ai_analysis(
    db: AsyncSession,
    threat_id: str,
    result: str,
    confidence: float,
    details: Optional[Dict] = None
):
    """Log an AI analysis event"""
    return await AuditService.log(
        db,
        action=AuditService.ACTION_AI_ANALYSIS,
        description=f"AI analyzed threat {threat_id}: {result} (confidence: {confidence:.0%})",
        source=AuditService.SOURCE_SYSTEM,
        severity="INFO",
        details={"threat_id": threat_id, "result": result, "confidence": confidence, **(details or {})}
    )


async def log_auto_response(
    db: AsyncSession,
    action_taken: str,
    target: str,
    threat_id: Optional[str] = None,
    details: Optional[Dict] = None
):
    """Log an auto-response action"""
    return await AuditService.log(
        db,
        action=AuditService.ACTION_AUTO_RESPONSE,
        description=f"Auto-response: {action_taken} on {target}",
        source=AuditService.SOURCE_AUTO,
        severity="WARNING",
        details={"action": action_taken, "target": target, "threat_id": threat_id, **(details or {})}
    )
