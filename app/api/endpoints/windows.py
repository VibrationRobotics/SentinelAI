"""
Windows Integration API endpoints for SentinelAI.
Provides native Windows firewall and system control.
"""
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

from app.services.windows_firewall import get_windows_firewall, FirewallRule

logger = logging.getLogger(__name__)
router = APIRouter()

# Store registered agents
_registered_agents: Dict[str, Dict[str, Any]] = {}
_agent_events: List[Dict[str, Any]] = []


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


@router.post("/agent/register")
async def register_agent(registration: AgentRegistration) -> JSONResponse:
    """Register a Windows agent with the dashboard."""
    try:
        agent_id = registration.hostname
        
        _registered_agents[agent_id] = {
            "hostname": registration.hostname,
            "platform": registration.platform,
            "platform_version": registration.platform_version,
            "agent_version": registration.agent_version,
            "capabilities": registration.capabilities,
            "registered_at": datetime.utcnow().isoformat(),
            "last_seen": datetime.utcnow().isoformat(),
            "status": "online"
        }
        
        logger.info(f"Windows agent registered: {agent_id}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"success": True, "agent_id": agent_id}
        )
    except Exception as e:
        logger.error(f"Error registering agent: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/agent/list")
async def list_agents() -> JSONResponse:
    """List all registered Windows agents."""
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "agents": list(_registered_agents.values()),
            "count": len(_registered_agents)
        }
    )


@router.get("/agent/{agent_id}/status")
async def get_agent_status(agent_id: str) -> JSONResponse:
    """Get status of a specific agent."""
    if agent_id not in _registered_agents:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "Agent not found"}
        )
    
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=_registered_agents[agent_id]
    )


@router.post("/agent/heartbeat")
async def agent_heartbeat(hostname: str) -> JSONResponse:
    """Update agent heartbeat."""
    if hostname in _registered_agents:
        _registered_agents[hostname]["last_seen"] = datetime.utcnow().isoformat()
        _registered_agents[hostname]["status"] = "online"
    
    return JSONResponse(status_code=status.HTTP_200_OK, content={"success": True})
