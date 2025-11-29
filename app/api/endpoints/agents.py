"""
Multi-Agent Management API
Centralized management for all connected security agents
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, func
from sqlalchemy.orm import selectinload
from typing import List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel
import secrets
import hashlib
import logging

from app.api.deps import get_db
from app.db.models import Agent, SecurityEvent, APIKey, AgentLicense, UsageMetric, SystemHealth

logger = logging.getLogger(__name__)
router = APIRouter()


# Pydantic models
class AgentResponse(BaseModel):
    id: int
    hostname: str
    platform: str
    platform_version: Optional[str]
    agent_version: str
    capabilities: List[str]
    is_admin: bool
    registered_at: datetime
    last_seen: datetime
    status: str
    ip_address: Optional[str]
    events_today: int = 0
    threats_detected: int = 0

    class Config:
        from_attributes = True


class AgentUpdate(BaseModel):
    status: Optional[str] = None
    is_admin: Optional[bool] = None


class APIKeyCreate(BaseModel):
    name: str
    expires_in_days: Optional[int] = 365
    permissions: dict = {"agents": ["read", "write"], "events": ["read", "write"]}


class APIKeyResponse(BaseModel):
    id: int
    name: str
    key_prefix: str  # First 8 chars for identification
    created_at: datetime
    expires_at: Optional[datetime]
    last_used: Optional[datetime]
    is_active: bool
    permissions: dict

    class Config:
        from_attributes = True


class LicenseCreate(BaseModel):
    tier: str = "free"  # free, pro, enterprise
    max_events_per_day: int = 1000
    ai_analysis_enabled: bool = True
    expires_in_days: Optional[int] = 365


class LicenseResponse(BaseModel):
    id: int
    license_key: str
    agent_id: Optional[int]
    tier: str
    max_events_per_day: int
    ai_analysis_enabled: bool
    created_at: datetime
    expires_at: Optional[datetime]
    is_active: bool

    class Config:
        from_attributes = True


class SystemHealthResponse(BaseModel):
    component: str
    status: str
    last_check: datetime
    response_time_ms: Optional[int]
    auto_actions: int = 0


class UsageStatsResponse(BaseModel):
    total_agents: int
    online_agents: int
    offline_agents: int
    events_today: int
    events_this_week: int
    ai_analyses_today: int
    threats_detected_today: int


# ============== Usage Analytics (must be before /{agent_id}) ==============

@router.get("/stats", response_model=UsageStatsResponse)
async def get_usage_stats(db: AsyncSession = Depends(get_db)):
    """Get overall usage statistics."""
    # Count agents
    total_result = await db.execute(select(func.count(Agent.id)))
    total_agents = total_result.scalar() or 0
    
    online_result = await db.execute(
        select(func.count(Agent.id)).where(Agent.status == "online")
    )
    online_agents = online_result.scalar() or 0
    
    # Count events
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago = today - timedelta(days=7)
    
    events_today_result = await db.execute(
        select(func.count(SecurityEvent.id)).where(SecurityEvent.timestamp >= today)
    )
    events_today = events_today_result.scalar() or 0
    
    events_week_result = await db.execute(
        select(func.count(SecurityEvent.id)).where(SecurityEvent.timestamp >= week_ago)
    )
    events_this_week = events_week_result.scalar() or 0
    
    # Count threats
    threats_result = await db.execute(
        select(func.count(SecurityEvent.id)).where(
            SecurityEvent.timestamp >= today,
            SecurityEvent.is_threat == True
        )
    )
    threats_today = threats_result.scalar() or 0
    
    # Count AI analyses (from usage metrics)
    ai_result = await db.execute(
        select(func.sum(UsageMetric.count)).where(
            UsageMetric.timestamp >= today,
            UsageMetric.metric_type == "ai_analysis"
        )
    )
    ai_analyses = ai_result.scalar() or 0
    
    return UsageStatsResponse(
        total_agents=total_agents,
        online_agents=online_agents,
        offline_agents=total_agents - online_agents,
        events_today=events_today,
        events_this_week=events_this_week,
        ai_analyses_today=ai_analyses,
        threats_detected_today=threats_today
    )


@router.get("/health-status", response_model=List[SystemHealthResponse])
async def get_system_health(db: AsyncSession = Depends(get_db)):
    """Get system health status for all components."""
    components = ["web", "db", "redis", "agents"]
    health_data = []
    
    for component in components:
        result = await db.execute(
            select(SystemHealth)
            .where(SystemHealth.component == component)
            .order_by(SystemHealth.timestamp.desc())
            .limit(1)
        )
        health = result.scalar_one_or_none()
        
        if health:
            actions_result = await db.execute(
                select(func.count(SystemHealth.id)).where(
                    SystemHealth.component == component,
                    SystemHealth.auto_action_taken.isnot(None)
                )
            )
            auto_actions = actions_result.scalar() or 0
            
            health_data.append(SystemHealthResponse(
                component=component,
                status=health.status,
                last_check=health.timestamp,
                response_time_ms=health.response_time_ms,
                auto_actions=auto_actions
            ))
        else:
            health_data.append(SystemHealthResponse(
                component=component,
                status="unknown",
                last_check=datetime.utcnow(),
                response_time_ms=None,
                auto_actions=0
            ))
    
    return health_data


# ============== Agent Management ==============

@router.get("/", response_model=List[AgentResponse])
async def list_agents(
    status: Optional[str] = Query(None, description="Filter by status"),
    platform: Optional[str] = Query(None, description="Filter by platform"),
    db: AsyncSession = Depends(get_db)
):
    """List all registered agents with their stats."""
    query = select(Agent)
    
    if status:
        query = query.where(Agent.status == status)
    if platform:
        query = query.where(Agent.platform == platform)
    
    result = await db.execute(query.order_by(Agent.last_seen.desc()))
    agents = result.scalars().all()
    
    # Get event counts for each agent
    agent_responses = []
    for agent in agents:
        # Count today's events
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        events_query = select(func.count(SecurityEvent.id)).where(
            SecurityEvent.agent_id == agent.id,
            SecurityEvent.timestamp >= today
        )
        events_result = await db.execute(events_query)
        events_today = events_result.scalar() or 0
        
        # Count threats
        threats_query = select(func.count(SecurityEvent.id)).where(
            SecurityEvent.agent_id == agent.id,
            SecurityEvent.is_threat == True
        )
        threats_result = await db.execute(threats_query)
        threats_detected = threats_result.scalar() or 0
        
        agent_responses.append(AgentResponse(
            id=agent.id,
            hostname=agent.hostname,
            platform=agent.platform,
            platform_version=agent.platform_version,
            agent_version=agent.agent_version,
            capabilities=agent.capabilities or [],
            is_admin=agent.is_admin,
            registered_at=agent.registered_at,
            last_seen=agent.last_seen,
            status=agent.status,
            ip_address=agent.ip_address,
            events_today=events_today,
            threats_detected=threats_detected
        ))
    
    return agent_responses


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(agent_id: int, db: AsyncSession = Depends(get_db)):
    """Get details of a specific agent."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return agent


@router.patch("/{agent_id}")
async def update_agent(
    agent_id: int,
    update_data: AgentUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update agent settings."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    if update_data.status is not None:
        agent.status = update_data.status
    if update_data.is_admin is not None:
        agent.is_admin = update_data.is_admin
    
    await db.commit()
    return {"message": "Agent updated", "agent_id": agent_id}


@router.delete("/{agent_id}")
async def delete_agent(agent_id: int, db: AsyncSession = Depends(get_db)):
    """Remove an agent from the system."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    await db.execute(delete(Agent).where(Agent.id == agent_id))
    await db.commit()
    
    return {"message": "Agent deleted", "agent_id": agent_id}


@router.post("/{agent_id}/command")
async def send_agent_command(
    agent_id: int,
    command: str = Query(..., description="Command to send"),
    db: AsyncSession = Depends(get_db)
):
    """Send a command to an agent (for future agent-side implementation)."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Store command in Redis for agent to pick up
    # This would be implemented with a proper command queue
    logger.info(f"Command '{command}' queued for agent {agent.hostname}")
    
    return {
        "message": "Command queued",
        "agent_id": agent_id,
        "command": command
    }


# ============== API Key Management ==============

@router.post("/api-keys", response_model=dict)
async def create_api_key(
    key_data: APIKeyCreate,
    user_id: int = Query(1, description="User ID"),  # TODO: Get from auth
    db: AsyncSession = Depends(get_db)
):
    """Create a new API key for agent authentication."""
    # Generate a secure API key
    raw_key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    
    expires_at = None
    if key_data.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=key_data.expires_in_days)
    
    api_key = APIKey(
        key_hash=key_hash,
        name=key_data.name,
        user_id=user_id,
        expires_at=expires_at,
        permissions=key_data.permissions
    )
    
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    
    # Return the raw key only once - it cannot be retrieved again
    return {
        "id": api_key.id,
        "name": api_key.name,
        "api_key": raw_key,  # Only shown once!
        "key_prefix": raw_key[:8],
        "expires_at": expires_at.isoformat() if expires_at else None,
        "message": "Save this API key - it cannot be retrieved again!"
    }


@router.get("/api-keys", response_model=List[APIKeyResponse])
async def list_api_keys(
    user_id: int = Query(1, description="User ID"),
    db: AsyncSession = Depends(get_db)
):
    """List all API keys for a user."""
    result = await db.execute(
        select(APIKey).where(APIKey.user_id == user_id).order_by(APIKey.created_at.desc())
    )
    keys = result.scalars().all()
    
    return [
        APIKeyResponse(
            id=k.id,
            name=k.name,
            key_prefix=k.key_hash[:8],  # Show hash prefix for identification
            created_at=k.created_at,
            expires_at=k.expires_at,
            last_used=k.last_used,
            is_active=k.is_active,
            permissions=k.permissions
        )
        for k in keys
    ]


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(key_id: int, db: AsyncSession = Depends(get_db)):
    """Revoke an API key."""
    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    api_key.is_active = False
    await db.commit()
    
    return {"message": "API key revoked", "key_id": key_id}


# ============== License Management ==============

@router.post("/licenses", response_model=LicenseResponse)
async def create_license(
    license_data: LicenseCreate,
    user_id: int = Query(1, description="User ID"),
    db: AsyncSession = Depends(get_db)
):
    """Create a new agent license."""
    license_key = f"SENT-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
    
    expires_at = None
    if license_data.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=license_data.expires_in_days)
    
    license = AgentLicense(
        license_key=license_key,
        user_id=user_id,
        tier=license_data.tier,
        max_events_per_day=license_data.max_events_per_day,
        ai_analysis_enabled=license_data.ai_analysis_enabled,
        expires_at=expires_at
    )
    
    db.add(license)
    await db.commit()
    await db.refresh(license)
    
    return license


@router.get("/licenses", response_model=List[LicenseResponse])
async def list_licenses(
    user_id: int = Query(1, description="User ID"),
    db: AsyncSession = Depends(get_db)
):
    """List all licenses for a user."""
    result = await db.execute(
        select(AgentLicense).where(AgentLicense.user_id == user_id)
    )
    return result.scalars().all()


@router.post("/licenses/{license_id}/assign/{agent_id}")
async def assign_license(
    license_id: int,
    agent_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Assign a license to an agent."""
    license_result = await db.execute(
        select(AgentLicense).where(AgentLicense.id == license_id)
    )
    license = license_result.scalar_one_or_none()
    
    if not license:
        raise HTTPException(status_code=404, detail="License not found")
    
    agent_result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = agent_result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    license.agent_id = agent_id
    await db.commit()
    
    return {"message": "License assigned", "license_id": license_id, "agent_id": agent_id}
