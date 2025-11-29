"""
User Settings API
Manages user preferences, API keys, and subscriptions
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional, List
from datetime import datetime, timedelta
from pydantic import BaseModel
import secrets
import hashlib
import logging

from app.api.deps import get_db, get_current_user
from app.db.models import User, UserSettings, APIKey, AgentLicense, SecurityEvent, ThreatEvent, Agent

logger = logging.getLogger(__name__)
router = APIRouter()


# Pydantic models
class SettingsResponse(BaseModel):
    auto_response_enabled: bool = False
    severity_threshold: str = "HIGH"
    cooldown_seconds: int = 300
    ip_whitelist: str = "127.0.0.1\n192.168.1.1\n10.0.0.0/8"
    ai_analysis_enabled: bool = True
    process_monitor_enabled: bool = True
    network_monitor_enabled: bool = True
    log_collector_enabled: bool = True
    file_scanner_enabled: bool = False
    browser_notifications: bool = True
    sound_alerts: bool = False
    email_alerts: bool = False

    class Config:
        from_attributes = True


class SettingsUpdate(BaseModel):
    auto_response_enabled: Optional[bool] = None
    severity_threshold: Optional[str] = None
    cooldown_seconds: Optional[int] = None
    ip_whitelist: Optional[str] = None
    ai_analysis_enabled: Optional[bool] = None
    process_monitor_enabled: Optional[bool] = None
    network_monitor_enabled: Optional[bool] = None
    log_collector_enabled: Optional[bool] = None
    file_scanner_enabled: Optional[bool] = None
    browser_notifications: Optional[bool] = None
    sound_alerts: Optional[bool] = None
    email_alerts: Optional[bool] = None


class APIKeyCreate(BaseModel):
    name: str
    expires_in_days: Optional[int] = 365


class APIKeyResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    created_at: datetime
    expires_at: Optional[datetime]
    last_used: Optional[datetime]
    is_active: bool

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    alerts_count: int
    threats_today: int
    events_today: int
    agents_online: int
    user_name: str
    user_email: str


# ============== Settings ==============

@router.get("/", response_model=SettingsResponse)
async def get_settings(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get current user's settings."""
    result = await db.execute(
        select(UserSettings).where(UserSettings.user_id == current_user.id)
    )
    settings = result.scalar_one_or_none()
    
    if not settings:
        # Create default settings
        settings = UserSettings(user_id=current_user.id)
        db.add(settings)
        await db.commit()
        await db.refresh(settings)
    
    return settings


@router.put("/", response_model=SettingsResponse)
async def update_settings(
    settings_data: SettingsUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update current user's settings."""
    result = await db.execute(
        select(UserSettings).where(UserSettings.user_id == current_user.id)
    )
    settings = result.scalar_one_or_none()
    
    if not settings:
        settings = UserSettings(user_id=current_user.id)
        db.add(settings)
    
    # Update only provided fields
    update_data = settings_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(settings, field, value)
    
    await db.commit()
    await db.refresh(settings)
    
    logger.info(f"Settings updated for user {current_user.email}")
    return settings


# ============== Dashboard Stats ==============

@router.get("/dashboard-stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get real-time dashboard statistics."""
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Count high severity events (alerts)
    alerts_result = await db.execute(
        select(func.count(SecurityEvent.id)).where(
            SecurityEvent.severity.in_(["HIGH", "CRITICAL"])
        )
    )
    alerts_count = alerts_result.scalar() or 0
    
    # Count today's threats
    threats_result = await db.execute(
        select(func.count(ThreatEvent.id)).where(
            ThreatEvent.timestamp >= today
        )
    )
    threats_today = threats_result.scalar() or 0
    
    # Count today's events
    events_result = await db.execute(
        select(func.count(SecurityEvent.id)).where(
            SecurityEvent.timestamp >= today
        )
    )
    events_today = events_result.scalar() or 0
    
    # Count online agents
    from app.db.models import Agent
    agents_result = await db.execute(
        select(func.count(Agent.id)).where(Agent.status == "online")
    )
    agents_online = agents_result.scalar() or 0
    
    return DashboardStats(
        alerts_count=alerts_count,
        threats_today=threats_today,
        events_today=events_today,
        agents_online=agents_online,
        user_name=current_user.full_name,
        user_email=current_user.email
    )


# ============== API Keys ==============

@router.get("/api-keys", response_model=List[APIKeyResponse])
async def list_api_keys(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all API keys for current user."""
    result = await db.execute(
        select(APIKey).where(APIKey.user_id == current_user.id).order_by(APIKey.created_at.desc())
    )
    keys = result.scalars().all()
    
    return [
        APIKeyResponse(
            id=k.id,
            name=k.name,
            key_prefix=k.key_hash[:8],
            created_at=k.created_at,
            expires_at=k.expires_at,
            last_used=k.last_used,
            is_active=k.is_active
        )
        for k in keys
    ]


@router.post("/api-keys")
async def create_api_key(
    key_data: APIKeyCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new API key."""
    # Generate secure key
    raw_key = f"sk_live_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    
    expires_at = None
    if key_data.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=key_data.expires_in_days)
    
    api_key = APIKey(
        key_hash=key_hash,
        name=key_data.name,
        user_id=current_user.id,
        expires_at=expires_at,
        permissions={"agents": ["read", "write"], "events": ["read", "write"]}
    )
    
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    
    logger.info(f"API key created for user {current_user.email}: {key_data.name}")
    
    return {
        "id": api_key.id,
        "name": api_key.name,
        "api_key": raw_key,
        "key_prefix": raw_key[:12],
        "expires_at": expires_at.isoformat() if expires_at else None,
        "message": "Save this API key securely - it will not be shown again!"
    }


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Revoke an API key."""
    result = await db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.user_id == current_user.id)
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    api_key.is_active = False
    await db.commit()
    
    logger.info(f"API key revoked for user {current_user.email}: {api_key.name}")
    return {"message": "API key revoked", "key_id": key_id}


# ============== Subscription/License ==============

@router.get("/subscription")
async def get_subscription(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get current user's subscription status."""
    result = await db.execute(
        select(AgentLicense).where(
            AgentLicense.user_id == current_user.id,
            AgentLicense.is_active == True
        ).order_by(AgentLicense.created_at.desc())
    )
    licenses = result.scalars().all()
    
    # Determine tier based on licenses
    if not licenses:
        tier = "free"
        max_agents = 1
        max_events = 1000
        ai_enabled = True
    else:
        # Get highest tier
        tiers = {"free": 0, "pro": 1, "enterprise": 2}
        best_license = max(licenses, key=lambda l: tiers.get(l.tier, 0))
        tier = best_license.tier
        max_agents = 5 if tier == "pro" else 100 if tier == "enterprise" else 1
        max_events = best_license.max_events_per_day
        ai_enabled = best_license.ai_analysis_enabled
    
    return {
        "tier": tier,
        "max_agents": max_agents,
        "max_events_per_day": max_events,
        "ai_analysis_enabled": ai_enabled,
        "licenses": [
            {
                "id": l.id,
                "license_key": l.license_key,
                "tier": l.tier,
                "expires_at": l.expires_at.isoformat() if l.expires_at else None,
                "is_active": l.is_active
            }
            for l in licenses
        ]
    }


# ============== Admin Endpoints ==============

async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require admin role."""
    if getattr(current_user, 'role', 'user') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


@router.get("/admin/users")
async def list_users(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """List all users with their subscription tier (admin only)."""
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    
    user_list = []
    for u in users:
        # Get user's tier
        license_result = await db.execute(
            select(AgentLicense).where(AgentLicense.user_id == u.id, AgentLicense.is_active == True)
        )
        license = license_result.scalar_one_or_none()
        
        user_list.append({
            "id": u.id,
            "email": u.email,
            "full_name": u.full_name,
            "role": getattr(u, 'role', 'user'),
            "tier": license.tier if license else "free",
            "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None
        })
    
    return user_list


@router.put("/admin/users/{user_id}/role")
async def update_user_role(
    user_id: int,
    role: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Update a user's role (admin only)."""
    if role not in ['admin', 'user', 'viewer']:
        raise HTTPException(status_code=400, detail="Invalid role. Must be admin, user, or viewer")
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.role = role
    await db.commit()
    
    logger.info(f"User {user.email} role changed to {role} by {current_user.email}")
    return {"message": f"User role updated to {role}", "user_id": user_id}


@router.put("/admin/users/{user_id}/tier")
async def update_user_tier(
    user_id: int,
    tier: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Update a user's subscription tier (admin only)."""
    if tier not in ['free', 'pro', 'enterprise']:
        raise HTTPException(status_code=400, detail="Invalid tier. Must be free, pro, or enterprise")
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check for existing license
    license_result = await db.execute(
        select(AgentLicense).where(AgentLicense.user_id == user_id, AgentLicense.is_active == True)
    )
    existing_license = license_result.scalar_one_or_none()
    
    # Tier configurations
    tier_config = {
        'free': {'max_agents': 1, 'max_events': 1000, 'ai_enabled': True},
        'pro': {'max_agents': 5, 'max_events': 10000, 'ai_enabled': True},
        'enterprise': {'max_agents': 100, 'max_events': 100000, 'ai_enabled': True}
    }
    config = tier_config[tier]
    
    if existing_license:
        # Update existing license
        existing_license.tier = tier
        existing_license.max_agents = config['max_agents']
        existing_license.max_events_per_day = config['max_events']
        existing_license.ai_analysis_enabled = config['ai_enabled']
    else:
        # Create new license
        new_license = AgentLicense(
            license_key=f"LIC-{secrets.token_hex(8).upper()}",
            user_id=user_id,
            tier=tier,
            max_agents=config['max_agents'],
            max_events_per_day=config['max_events'],
            ai_analysis_enabled=config['ai_enabled'],
            is_active=True
        )
        db.add(new_license)
    
    await db.commit()
    
    logger.info(f"User {user.email} tier changed to {tier} by {current_user.email}")
    return {"message": f"User tier updated to {tier}", "user_id": user_id, "tier": tier}


@router.put("/admin/users/{user_id}/status")
async def update_user_status(
    user_id: int,
    is_active: bool,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Enable/disable a user account (admin only)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent admin from disabling themselves
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot disable your own account")
    
    user.is_active = is_active
    await db.commit()
    
    status = "enabled" if is_active else "disabled"
    logger.info(f"User {user.email} {status} by {current_user.email}")
    return {"message": f"User {status}", "user_id": user_id}


@router.get("/admin/users/{user_id}")
async def get_user_details(
    user_id: int,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get detailed user info including subscription (admin only)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get user's license/tier
    license_result = await db.execute(
        select(AgentLicense).where(AgentLicense.user_id == user_id, AgentLicense.is_active == True)
    )
    license = license_result.scalar_one_or_none()
    
    # Get user's API keys count
    keys_result = await db.execute(
        select(func.count(APIKey.id)).where(APIKey.user_id == user_id, APIKey.is_active == True)
    )
    api_keys_count = keys_result.scalar() or 0
    
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": getattr(user, 'role', 'user'),
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "subscription": {
            "tier": license.tier if license else "free",
            "max_agents": license.max_agents if license else 1,
            "max_events_per_day": license.max_events_per_day if license else 1000,
            "expires_at": license.expires_at.isoformat() if license and license.expires_at else None
        },
        "api_keys_count": api_keys_count
    }
