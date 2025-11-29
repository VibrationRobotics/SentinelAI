"""
Windows Integration API endpoints for SentinelAI.
Provides native Windows firewall and system control.
Uses PostgreSQL for persistent storage.
"""
from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc, select, update
import logging

from app.services.windows_firewall import get_windows_firewall, FirewallRule
from app.db.base import get_session
from app.db.models import Agent, SecurityEvent, BlockedIP, AuditLog, APIKey, AgentCommand
from app.api.deps import validate_api_key

logger = logging.getLogger(__name__)
router = APIRouter()


class BlockIPRequest(BaseModel):
    """Request to block an IP address."""
    ip: str
    rule_name: Optional[str] = None
    direction: str = "Inbound"


class FirewallRuleCreate(BaseModel):
    """Request to create a firewall rule."""
    name: str
    direction: str = "Inbound"
    action: str = "Block"
    protocol: str = "Any"
    local_port: Optional[str] = None
    remote_port: Optional[str] = None
    local_address: Optional[str] = None
    remote_address: Optional[str] = None
    program: Optional[str] = None
    enabled: bool = True
    profile: str = "Any"


# ============== Firewall Endpoints ==============

@router.get("/firewall/status")
async def get_firewall_status() -> JSONResponse:
    """Get Windows Firewall status and statistics."""
    try:
        firewall = get_windows_firewall()
        stats = firewall.get_stats()
        return JSONResponse(status_code=status.HTTP_200_OK, content=stats)
    except Exception as e:
        logger.error(f"Error getting firewall status: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/firewall/block-ip")
async def block_ip(request: BlockIPRequest) -> JSONResponse:
    """Block an IP address in Windows Firewall."""
    try:
        firewall = get_windows_firewall()
        result = firewall.block_ip(
            ip=request.ip,
            rule_name=request.rule_name,
            direction=request.direction
        )
        
        status_code = status.HTTP_200_OK if result["success"] else status.HTTP_400_BAD_REQUEST
        return JSONResponse(status_code=status_code, content=result)
    except Exception as e:
        logger.error(f"Error blocking IP: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/firewall/unblock-ip")
async def unblock_ip(ip: str) -> JSONResponse:
    """Remove block rules for an IP address."""
    try:
        firewall = get_windows_firewall()
        result = firewall.unblock_ip(ip)
        
        status_code = status.HTTP_200_OK if result["success"] else status.HTTP_400_BAD_REQUEST
        return JSONResponse(status_code=status_code, content=result)
    except Exception as e:
        logger.error(f"Error unblocking IP: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/firewall/blocked-ips")
async def get_blocked_ips() -> JSONResponse:
    """Get list of IPs blocked by SentinelAI."""
    try:
        firewall = get_windows_firewall()
        ips = firewall.get_blocked_ips()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"blocked_ips": ips, "count": len(ips)}
        )
    except Exception as e:
        logger.error(f"Error getting blocked IPs: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/firewall/rules")
async def create_firewall_rule(rule: FirewallRuleCreate) -> JSONResponse:
    """Create a custom firewall rule."""
    try:
        firewall = get_windows_firewall()
        
        fw_rule = FirewallRule(
            name=rule.name,
            direction=rule.direction,
            action=rule.action,
            protocol=rule.protocol,
            local_port=rule.local_port,
            remote_port=rule.remote_port,
            local_address=rule.local_address,
            remote_address=rule.remote_address,
            program=rule.program,
            enabled=rule.enabled,
            profile=rule.profile
        )
        
        result = firewall.add_rule(fw_rule)
        
        status_code = status.HTTP_201_CREATED if result["success"] else status.HTTP_400_BAD_REQUEST
        return JSONResponse(status_code=status_code, content=result)
    except Exception as e:
        logger.error(f"Error creating firewall rule: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/firewall/rules")
async def list_firewall_rules(sentinel_only: bool = True) -> JSONResponse:
    """List firewall rules."""
    try:
        firewall = get_windows_firewall()
        rules = firewall.list_rules(sentinel_only)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"rules": rules, "count": len(rules)}
        )
    except Exception as e:
        logger.error(f"Error listing firewall rules: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.delete("/firewall/rules/{rule_name}")
async def delete_firewall_rule(rule_name: str) -> JSONResponse:
    """Delete a firewall rule."""
    try:
        firewall = get_windows_firewall()
        result = firewall.delete_rule(rule_name)
        
        status_code = status.HTTP_200_OK if result["success"] else status.HTTP_400_BAD_REQUEST
        return JSONResponse(status_code=status_code, content=result)
    except Exception as e:
        logger.error(f"Error deleting firewall rule: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/firewall/cleanup")
async def cleanup_firewall_rules() -> JSONResponse:
    """Remove all SentinelAI firewall rules."""
    try:
        firewall = get_windows_firewall()
        result = firewall.cleanup_rules()
        return JSONResponse(status_code=status.HTTP_200_OK, content=result)
    except Exception as e:
        logger.error(f"Error cleaning up firewall rules: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


# ============== System Info Endpoints ==============

@router.get("/system/info")
async def get_system_info() -> JSONResponse:
    """Get Windows system information."""
    try:
        import platform
        import psutil
        
        info = {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "processor": platform.processor(),
            "cpu_count": psutil.cpu_count(),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "memory_available_gb": round(psutil.virtual_memory().available / (1024**3), 2),
            "disk_total_gb": round(psutil.disk_usage('/').total / (1024**3), 2) if platform.system() != "Windows" else None
        }
        
        # Windows-specific info
        if platform.system() == "Windows":
            try:
                info["disk_total_gb"] = round(psutil.disk_usage('C:\\').total / (1024**3), 2)
                info["disk_free_gb"] = round(psutil.disk_usage('C:\\').free / (1024**3), 2)
            except:
                pass
        
        return JSONResponse(status_code=status.HTTP_200_OK, content=info)
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/system/network")
async def get_network_info() -> JSONResponse:
    """Get network interface information."""
    try:
        import psutil
        
        interfaces = []
        for name, addrs in psutil.net_if_addrs().items():
            iface = {"name": name, "addresses": []}
            for addr in addrs:
                iface["addresses"].append({
                    "family": str(addr.family),
                    "address": addr.address,
                    "netmask": addr.netmask,
                    "broadcast": addr.broadcast
                })
            interfaces.append(iface)
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"interfaces": interfaces}
        )
    except Exception as e:
        logger.error(f"Error getting network info: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


# ============== Windows Agent Endpoints ==============

class AgentRegistration(BaseModel):
    """Agent registration request."""
    hostname: str
    platform: str
    platform_version: str
    agent_version: str
    capabilities: List[str]
    is_admin: Optional[bool] = False


@router.post("/agent/register")
async def register_agent(
    registration: AgentRegistration, 
    db: AsyncSession = Depends(get_session),
    api_key: Optional[APIKey] = Depends(validate_api_key)
) -> JSONResponse:
    """Register a Windows agent with the dashboard (PostgreSQL persistent storage).
    
    Requires a valid API key in the X-API-Key header.
    Get an API key from Dashboard > Settings > API Keys.
    """
    # Require API key for agent registration
    if not api_key:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "success": False, 
                "error": "API key required",
                "detail": "Get an API key from Dashboard > Settings > API Keys"
            }
        )
    
    try:
        # Check if agent already exists
        result = await db.execute(select(Agent).filter(Agent.hostname == registration.hostname))
        existing_agent = result.scalar_one_or_none()
        
        if existing_agent:
            # Update existing agent
            existing_agent.platform = registration.platform
            existing_agent.platform_version = registration.platform_version
            existing_agent.agent_version = registration.agent_version
            existing_agent.capabilities = registration.capabilities
            existing_agent.is_admin = registration.is_admin
            existing_agent.last_seen = datetime.utcnow()
            existing_agent.status = "online"
            await db.commit()
            agent_id = existing_agent.id
            logger.info(f"Windows agent updated: {registration.hostname}")
        else:
            # Create new agent
            new_agent = Agent(
                hostname=registration.hostname,
                platform=registration.platform,
                platform_version=registration.platform_version,
                agent_version=registration.agent_version,
                capabilities=registration.capabilities,
                is_admin=registration.is_admin,
                registered_at=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                status="online"
            )
            db.add(new_agent)
            await db.commit()
            await db.refresh(new_agent)
            agent_id = new_agent.id
            logger.info(f"Windows agent registered: {registration.hostname}")
        
        # Log to audit
        audit_log = AuditLog(
            source="agent",
            action="agent_registered",
            severity="INFO",
            description=f"Agent {registration.hostname} registered/updated",
            hostname=registration.hostname,
            details={"agent_version": registration.agent_version, "capabilities": registration.capabilities}
        )
        db.add(audit_log)
        await db.commit()
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"success": True, "agent_id": str(agent_id)}
        )
    except Exception as e:
        logger.error(f"Error registering agent: {e}")
        await db.rollback()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/agent/list")
async def list_agents(db: AsyncSession = Depends(get_session)) -> JSONResponse:
    """List all registered Windows agents (from PostgreSQL)."""
    try:
        # Mark agents as offline if not seen in 2 minutes
        offline_threshold = datetime.utcnow() - timedelta(minutes=2)
        await db.execute(
            update(Agent).where(Agent.last_seen < offline_threshold).values(status="offline")
        )
        await db.commit()
        
        result = await db.execute(select(Agent).order_by(desc(Agent.last_seen)))
        agents = result.scalars().all()
        
        agent_list = []
        for agent in agents:
            agent_list.append({
                "id": agent.id,
                "hostname": agent.hostname,
                "platform": agent.platform,
                "platform_version": agent.platform_version,
                "agent_version": agent.agent_version,
                "capabilities": agent.capabilities,
                "is_admin": agent.is_admin,
                "registered_at": agent.registered_at.isoformat() if agent.registered_at else None,
                "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
                "status": agent.status,
                "ip_address": agent.ip_address
            })
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"agents": agent_list, "count": len(agent_list)}
        )
    except Exception as e:
        logger.error(f"Error listing agents: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/agent/{agent_id}/status")
async def get_agent_status(agent_id: str, db: AsyncSession = Depends(get_session)) -> JSONResponse:
    """Get status of a specific agent (from PostgreSQL)."""
    try:
        # Try to find by hostname or id
        if agent_id.isdigit():
            result = await db.execute(select(Agent).filter((Agent.hostname == agent_id) | (Agent.id == int(agent_id))))
        else:
            result = await db.execute(select(Agent).filter(Agent.hostname == agent_id))
        agent = result.scalar_one_or_none()
        
        if not agent:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": "Agent not found"}
            )
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "id": agent.id,
                "hostname": agent.hostname,
                "platform": agent.platform,
                "platform_version": agent.platform_version,
                "agent_version": agent.agent_version,
                "capabilities": agent.capabilities,
                "is_admin": agent.is_admin,
                "registered_at": agent.registered_at.isoformat() if agent.registered_at else None,
                "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
                "status": agent.status
            }
        )
    except Exception as e:
        logger.error(f"Error getting agent status: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/agent/heartbeat")
async def agent_heartbeat(hostname: str, db: AsyncSession = Depends(get_session)) -> JSONResponse:
    """Update agent heartbeat (PostgreSQL persistent)."""
    try:
        result = await db.execute(select(Agent).filter(Agent.hostname == hostname))
        agent = result.scalar_one_or_none()
        if agent:
            agent.last_seen = datetime.utcnow()
            agent.status = "online"
            await db.commit()
        
        return JSONResponse(status_code=status.HTTP_200_OK, content={"success": True})
    except Exception as e:
        logger.error(f"Error updating heartbeat: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/agent/event")
async def receive_agent_event(event_data: Dict[str, Any], db: AsyncSession = Depends(get_session)) -> JSONResponse:
    """Receive and store security event from agent (PostgreSQL persistent)."""
    try:
        # Find agent
        hostname = event_data.get("hostname", "unknown")
        result = await db.execute(select(Agent).filter(Agent.hostname == hostname))
        agent = result.scalar_one_or_none()
        
        if not agent:
            # Auto-register agent if not found
            agent = Agent(
                hostname=hostname,
                platform=event_data.get("platform", "Unknown"),
                platform_version="",
                agent_version="1.0.0",
                capabilities=[],
                status="online"
            )
            db.add(agent)
            await db.commit()
            await db.refresh(agent)
        
        # Create security event
        security_event = SecurityEvent(
            agent_id=agent.id,
            event_type=event_data.get("event_type", "unknown"),
            severity=event_data.get("severity", "LOW"),
            description=event_data.get("description", ""),
            details=event_data.get("details", {}),
            source_ip=event_data.get("source_ip"),
            destination_ip=event_data.get("destination_ip"),
            process_name=event_data.get("process_name"),
            is_threat=event_data.get("severity", "LOW") in ["HIGH", "CRITICAL"]
        )
        db.add(security_event)
        
        # Also log to audit
        audit_log = AuditLog(
            source="agent",
            action="security_event",
            severity=event_data.get("severity", "INFO"),
            description=event_data.get("description", "Security event received"),
            hostname=hostname,
            details=event_data.get("details", {})
        )
        db.add(audit_log)
        
        await db.commit()
        
        logger.info(f"Security event stored: {event_data.get('event_type')} from {hostname}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"success": True, "event_id": security_event.id}
        )
    except Exception as e:
        logger.error(f"Error storing event: {e}")
        await db.rollback()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/events")
async def get_security_events(
    limit: int = 100,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    hostname: Optional[str] = None,
    db: AsyncSession = Depends(get_session)
) -> JSONResponse:
    """Get security events from PostgreSQL database."""
    try:
        query = select(SecurityEvent).join(Agent)
        
        if severity:
            query = query.filter(SecurityEvent.severity == severity.upper())
        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)
        if hostname:
            query = query.filter(Agent.hostname == hostname)
        
        query = query.order_by(desc(SecurityEvent.timestamp)).limit(limit)
        result = await db.execute(query)
        events = result.scalars().all()
        
        event_list = []
        for event in events:
            # Need to load agent relationship
            agent_result = await db.execute(select(Agent).filter(Agent.id == event.agent_id))
            agent = agent_result.scalar_one_or_none()
            
            event_list.append({
                "id": event.id,
                "agent_id": event.agent_id,
                "hostname": agent.hostname if agent else "unknown",
                "event_type": event.event_type,
                "severity": event.severity,
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "description": event.description,
                "details": event.details,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "process_name": event.process_name,
                "is_threat": event.is_threat
            })
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"events": event_list, "count": len(event_list)}
        )
    except Exception as e:
        logger.error(f"Error getting events: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


# ============== AGENT COMMAND QUEUE (Autonomous Response) ==============

class CommandRequest(BaseModel):
    """Request to queue a command for an agent."""
    command_type: str  # block_ip, kill_process, quarantine_file, scan_path, unblock_ip
    target: str  # IP address, PID, file path
    parameters: Optional[Dict[str, Any]] = {}
    priority: Optional[int] = 5  # 1=highest, 10=lowest
    threat_id: Optional[str] = None


class CommandResult(BaseModel):
    """Result of command execution from agent."""
    command_id: int
    status: str  # success, failed
    result: Optional[str] = None
    error: Optional[str] = None


@router.get("/agent/{hostname}/commands")
async def get_pending_commands(
    hostname: str,
    db: AsyncSession = Depends(get_session),
    api_key: Optional[APIKey] = Depends(validate_api_key)
) -> JSONResponse:
    """Get pending commands for an agent to execute.
    
    Called by agents to poll for new commands.
    Returns commands ordered by priority (1=highest).
    """
    if not api_key:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "API key required"}
        )
    
    try:
        # Find agent
        result = await db.execute(select(Agent).filter(Agent.hostname == hostname))
        agent = result.scalar_one_or_none()
        
        if not agent:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": "Agent not found"}
            )
        
        # Update last_seen
        agent.last_seen = datetime.utcnow()
        agent.status = "online"
        
        # Get pending commands ordered by priority
        cmd_result = await db.execute(
            select(AgentCommand)
            .filter(AgentCommand.agent_id == agent.id)
            .filter(AgentCommand.status == "pending")
            .order_by(AgentCommand.priority, AgentCommand.created_at)
            .limit(10)
        )
        commands = cmd_result.scalars().all()
        
        # Mark as sent
        command_list = []
        for cmd in commands:
            cmd.status = "sent"
            cmd.sent_at = datetime.utcnow()
            command_list.append({
                "id": cmd.id,
                "command_type": cmd.command_type,
                "target": cmd.target,
                "parameters": cmd.parameters or {},
                "priority": cmd.priority,
                "threat_id": cmd.threat_id
            })
        
        await db.commit()
        
        if command_list:
            logger.info(f"Sending {len(command_list)} commands to agent {hostname}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"commands": command_list, "count": len(command_list)}
        )
    except Exception as e:
        logger.error(f"Error getting commands: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/agent/{hostname}/commands/result")
async def report_command_result(
    hostname: str,
    result: CommandResult,
    db: AsyncSession = Depends(get_session),
    api_key: Optional[APIKey] = Depends(validate_api_key)
) -> JSONResponse:
    """Report the result of a command execution.
    
    Called by agents after executing a command.
    """
    if not api_key:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "API key required"}
        )
    
    try:
        # Find command
        cmd_result = await db.execute(
            select(AgentCommand).filter(AgentCommand.id == result.command_id)
        )
        command = cmd_result.scalar_one_or_none()
        
        if not command:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": "Command not found"}
            )
        
        # Update command status
        command.status = "executed" if result.status == "success" else "failed"
        command.executed_at = datetime.utcnow()
        command.result = result.result or result.error
        
        # Log to audit
        audit_log = AuditLog(
            source="agent",
            action=f"command_{result.status}",
            severity="INFO" if result.status == "success" else "WARNING",
            description=f"Command {command.command_type} on {command.target}: {result.status}",
            hostname=hostname,
            details={
                "command_id": command.id,
                "command_type": command.command_type,
                "target": command.target,
                "result": result.result,
                "error": result.error
            }
        )
        db.add(audit_log)
        
        await db.commit()
        
        logger.info(f"Command {command.id} result from {hostname}: {result.status}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"success": True}
        )
    except Exception as e:
        logger.error(f"Error reporting command result: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/agent/{hostname}/commands/queue")
async def queue_command(
    hostname: str,
    command: CommandRequest,
    db: AsyncSession = Depends(get_session),
    api_key: Optional[APIKey] = Depends(validate_api_key)
) -> JSONResponse:
    """Queue a command for an agent to execute.
    
    Can be called by dashboard or auto-response service.
    """
    try:
        # Find agent
        result = await db.execute(select(Agent).filter(Agent.hostname == hostname))
        agent = result.scalar_one_or_none()
        
        if not agent:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": "Agent not found"}
            )
        
        # Create command
        new_command = AgentCommand(
            agent_id=agent.id,
            command_type=command.command_type,
            target=command.target,
            parameters=command.parameters or {},
            priority=command.priority or 5,
            threat_id=command.threat_id
        )
        db.add(new_command)
        
        # Log to audit
        audit_log = AuditLog(
            source="dashboard" if api_key else "auto",
            action="command_queued",
            severity="INFO",
            description=f"Queued {command.command_type} command for {hostname}: {command.target}",
            hostname=hostname,
            details={
                "command_type": command.command_type,
                "target": command.target,
                "parameters": command.parameters
            }
        )
        db.add(audit_log)
        
        await db.commit()
        await db.refresh(new_command)
        
        logger.info(f"Queued command {new_command.id} for agent {hostname}: {command.command_type} -> {command.target}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"success": True, "command_id": new_command.id}
        )
    except Exception as e:
        logger.error(f"Error queuing command: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )
