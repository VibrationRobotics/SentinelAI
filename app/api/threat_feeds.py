"""
Threat Feed API endpoints
Query and manage threat intelligence feeds.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_session
from app.services.threat_feed_service import (
    ThreatFeedService,
    ThreatFeedConfig,
    get_threat_feed_service,
    configure_threat_feeds
)

router = APIRouter(prefix="/threat-feeds", tags=["threat-feeds"])


# ==================== SCHEMAS ====================

class ThreatFeedConfigSchema(BaseModel):
    otx_enabled: bool = False
    otx_api_key: str = ""
    abusech_enabled: bool = True
    update_interval_hours: int = 6


class IOCCheckRequest(BaseModel):
    indicator: str
    indicator_type: str = "auto"  # ip, domain, url, hash, auto


class IOCBatchCheckRequest(BaseModel):
    indicators: List[str]
    indicator_type: str = "auto"


# ==================== ENDPOINTS ====================

@router.get("/stats")
async def get_feed_stats():
    """Get current threat feed statistics."""
    service = get_threat_feed_service()
    return service.get_stats()


@router.post("/update")
async def update_feeds(
    background_tasks: BackgroundTasks,
    force: bool = False
):
    """
    Trigger threat feed update.
    
    Args:
        force: Force update even if recently updated
    """
    service = get_threat_feed_service()
    
    # Run update in background
    async def do_update():
        return await service.update_feeds(force=force)
    
    background_tasks.add_task(do_update)
    
    return {
        "message": "Feed update started",
        "current_stats": service.get_stats()
    }


@router.post("/update/sync")
async def update_feeds_sync(
    force: bool = False
):
    """
    Trigger threat feed update and wait for completion.
    
    Args:
        force: Force update even if recently updated
    """
    service = get_threat_feed_service()
    result = await service.update_feeds(force=force)
    return result


@router.post("/check")
async def check_indicator(
    request: IOCCheckRequest
):
    """
    Check a single indicator against threat feeds.
    
    Args:
        indicator: The IOC to check (IP, domain, URL, or hash)
        indicator_type: Type of indicator or "auto" to detect
    """
    service = get_threat_feed_service()
    
    # Ensure feeds are loaded
    if service.stats.get("total_ips", 0) == 0:
        await service.update_feeds()
    
    result = service.check_indicator(request.indicator, request.indicator_type)
    
    if result:
        return {
            "found": True,
            **result
        }
    else:
        return {
            "found": False,
            "indicator": request.indicator,
            "indicator_type": request.indicator_type,
            "message": "Indicator not found in threat feeds"
        }


@router.post("/check/batch")
async def check_indicators_batch(
    request: IOCBatchCheckRequest
):
    """
    Check multiple indicators against threat feeds.
    
    Returns list of results for each indicator.
    """
    service = get_threat_feed_service()
    
    # Ensure feeds are loaded
    if service.stats.get("total_ips", 0) == 0:
        await service.update_feeds()
    
    results = []
    malicious_count = 0
    
    for indicator in request.indicators[:1000]:  # Limit to 1000
        result = service.check_indicator(indicator, request.indicator_type)
        if result:
            results.append({"indicator": indicator, "found": True, **result})
            malicious_count += 1
        else:
            results.append({"indicator": indicator, "found": False})
    
    return {
        "total_checked": len(results),
        "malicious_found": malicious_count,
        "results": results
    }


@router.get("/config")
async def get_feed_config():
    """Get current threat feed configuration."""
    service = get_threat_feed_service()
    config = service.config
    
    return {
        "otx_enabled": config.otx_enabled,
        "otx_api_key": "***" if config.otx_api_key else "",
        "abusech_enabled": config.abusech_enabled,
        "update_interval_hours": config.update_interval_hours
    }


@router.post("/config")
async def update_feed_config(
    config: ThreatFeedConfigSchema
):
    """Update threat feed configuration."""
    new_config = ThreatFeedConfig(
        otx_enabled=config.otx_enabled,
        otx_api_key=config.otx_api_key,
        abusech_enabled=config.abusech_enabled,
        update_interval_hours=config.update_interval_hours
    )
    
    configure_threat_feeds(new_config)
    
    return {"success": True, "message": "Configuration updated"}


# ==================== QUICK CHECK ENDPOINTS ====================

@router.get("/check/ip/{ip}")
async def quick_check_ip(
    ip: str
):
    """Quick check if an IP is malicious."""
    service = get_threat_feed_service()
    
    if service.stats.get("total_ips", 0) == 0:
        await service.update_feeds()
    
    result = service.check_ip(ip)
    return {"ip": ip, "malicious": result is not None, "details": result}


@router.get("/check/domain/{domain}")
async def quick_check_domain(
    domain: str
):
    """Quick check if a domain is malicious."""
    service = get_threat_feed_service()
    
    if service.stats.get("total_domains", 0) == 0:
        await service.update_feeds()
    
    result = service.check_domain(domain)
    return {"domain": domain, "malicious": result is not None, "details": result}


@router.get("/check/hash/{file_hash}")
async def quick_check_hash(
    file_hash: str
):
    """Quick check if a file hash is malicious."""
    service = get_threat_feed_service()
    
    if service.stats.get("total_hashes", 0) == 0:
        await service.update_feeds()
    
    result = service.check_hash(file_hash)
    return {"hash": file_hash, "malicious": result is not None, "details": result}
