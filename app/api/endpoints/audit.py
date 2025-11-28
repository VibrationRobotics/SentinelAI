"""
Audit Log API Endpoints
Provides endpoints for logging and retrieving audit events
"""
from fastapi import APIRouter, HTTPException, status, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

# In-memory storage (will be replaced with DB)
_audit_logs: List[Dict] = []
_MAX_LOGS = 10000


class AuditLogEntry(BaseModel):
    """Audit log entry model"""
    source: str = Field(..., description="Source of the log (agent, dashboard, tauri, api)")
    action: str = Field(..., description="Action performed")
    severity: str = Field(default="INFO", description="Severity level")
    description: str = Field(..., description="Description of the event")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional details")
    hostname: Optional[str] = Field(default=None, description="Hostname if from agent")
    ip_address: Optional[str] = Field(default=None, description="IP address")


@router.post("")
async def create_audit_log(entry: AuditLogEntry) -> JSONResponse:
    """Create a new audit log entry"""
    try:
        log_entry = {
            "id": len(_audit_logs) + 1,
            "timestamp": datetime.utcnow().isoformat(),
            "source": entry.source,
            "action": entry.action,
            "severity": entry.severity,
            "description": entry.description,
            "details": entry.details,
            "hostname": entry.hostname,
            "ip_address": entry.ip_address
        }
        
        _audit_logs.insert(0, log_entry)
        
        # Trim logs if too many
        if len(_audit_logs) > _MAX_LOGS:
            _audit_logs.pop()
        
        logger.info(f"Audit log: [{entry.severity}] {entry.source} - {entry.action}: {entry.description}")
        
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"success": True, "id": log_entry["id"]}
        )
    except Exception as e:
        logger.error(f"Error creating audit log: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("")
async def get_audit_logs(
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0),
    source: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    hostname: Optional[str] = Query(default=None),
    hours: Optional[int] = Query(default=None, description="Filter logs from last N hours")
) -> JSONResponse:
    """Get audit logs with optional filtering"""
    try:
        logs = _audit_logs.copy()
        
        # Filter by time
        if hours:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            logs = [l for l in logs if datetime.fromisoformat(l["timestamp"]) > cutoff]
        
        # Filter by source
        if source:
            logs = [l for l in logs if l.get("source") == source]
        
        # Filter by action
        if action:
            logs = [l for l in logs if l.get("action") == action]
        
        # Filter by severity
        if severity:
            logs = [l for l in logs if l.get("severity") == severity]
        
        # Filter by hostname
        if hostname:
            logs = [l for l in logs if l.get("hostname") == hostname]
        
        # Paginate
        total = len(logs)
        logs = logs[offset:offset + limit]
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "logs": logs,
                "total": total,
                "limit": limit,
                "offset": offset
            }
        )
    except Exception as e:
        logger.error(f"Error getting audit logs: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/stats")
async def get_audit_stats() -> JSONResponse:
    """Get audit log statistics"""
    try:
        now = datetime.utcnow()
        last_hour = now - timedelta(hours=1)
        last_24h = now - timedelta(hours=24)
        
        # Count by severity
        severity_counts = {"INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0}
        source_counts = {}
        action_counts = {}
        last_hour_count = 0
        last_24h_count = 0
        
        for log in _audit_logs:
            severity = log.get("severity", "INFO")
            source = log.get("source", "unknown")
            action = log.get("action", "unknown")
            timestamp = datetime.fromisoformat(log["timestamp"])
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            source_counts[source] = source_counts.get(source, 0) + 1
            action_counts[action] = action_counts.get(action, 0) + 1
            
            if timestamp > last_hour:
                last_hour_count += 1
            if timestamp > last_24h:
                last_24h_count += 1
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "total": len(_audit_logs),
                "last_hour": last_hour_count,
                "last_24h": last_24h_count,
                "by_severity": severity_counts,
                "by_source": source_counts,
                "by_action": dict(list(action_counts.items())[:10])  # Top 10 actions
            }
        )
    except Exception as e:
        logger.error(f"Error getting audit stats: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.delete("")
async def clear_audit_logs() -> JSONResponse:
    """Clear all audit logs (admin only)"""
    global _audit_logs
    count = len(_audit_logs)
    _audit_logs = []
    
    logger.warning(f"Audit logs cleared: {count} entries removed")
    
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"success": True, "cleared": count}
    )


# Helper function to log from other parts of the app
def log_audit(source: str, action: str, description: str, 
              severity: str = "INFO", details: Dict = None,
              hostname: str = None, ip_address: str = None):
    """Helper function to create audit log entries programmatically"""
    log_entry = {
        "id": len(_audit_logs) + 1,
        "timestamp": datetime.utcnow().isoformat(),
        "source": source,
        "action": action,
        "severity": severity,
        "description": description,
        "details": details,
        "hostname": hostname,
        "ip_address": ip_address
    }
    
    _audit_logs.insert(0, log_entry)
    
    if len(_audit_logs) > _MAX_LOGS:
        _audit_logs.pop()
    
    logger.info(f"Audit: [{severity}] {source}/{action}: {description}")
