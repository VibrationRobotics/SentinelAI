"""
VirusTotal API endpoints for SentinelAI.
Provides hash, URL, IP, and domain reputation lookups.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
import logging

from app.services.virustotal_service import get_virustotal_service
from app.api.deps import get_current_user
from app.db.models import User

logger = logging.getLogger(__name__)
router = APIRouter()


class HashCheckRequest(BaseModel):
    hash: str  # MD5, SHA1, or SHA256


class UrlCheckRequest(BaseModel):
    url: str


class IpCheckRequest(BaseModel):
    ip: str


class DomainCheckRequest(BaseModel):
    domain: str


@router.get("/status")
async def get_virustotal_status():
    """Get VirusTotal service status."""
    vt = get_virustotal_service()
    return vt.get_status()


@router.post("/check/hash")
async def check_hash(
    request: HashCheckRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Check a file hash against VirusTotal.
    
    Supports MD5, SHA1, and SHA256 hashes.
    """
    vt = get_virustotal_service()
    
    if not vt.enabled:
        raise HTTPException(
            status_code=503,
            detail="VirusTotal API key not configured. Add VIRUSTOTAL_API_KEY to .env"
        )
    
    result = vt.check_hash(request.hash)
    
    if "error" in result and "Rate limit" in result["error"]:
        raise HTTPException(status_code=429, detail=result["error"])
    
    return result


@router.post("/check/url")
async def check_url(
    request: UrlCheckRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Check a URL against VirusTotal.
    """
    vt = get_virustotal_service()
    
    if not vt.enabled:
        raise HTTPException(
            status_code=503,
            detail="VirusTotal API key not configured. Add VIRUSTOTAL_API_KEY to .env"
        )
    
    result = vt.check_url(request.url)
    
    if "error" in result and "Rate limit" in result["error"]:
        raise HTTPException(status_code=429, detail=result["error"])
    
    return result


@router.post("/check/ip")
async def check_ip(
    request: IpCheckRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Check an IP address reputation against VirusTotal.
    """
    vt = get_virustotal_service()
    
    if not vt.enabled:
        raise HTTPException(
            status_code=503,
            detail="VirusTotal API key not configured. Add VIRUSTOTAL_API_KEY to .env"
        )
    
    result = vt.check_ip(request.ip)
    
    if "error" in result and "Rate limit" in result["error"]:
        raise HTTPException(status_code=429, detail=result["error"])
    
    return result


@router.post("/check/domain")
async def check_domain(
    request: DomainCheckRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Check a domain reputation against VirusTotal.
    """
    vt = get_virustotal_service()
    
    if not vt.enabled:
        raise HTTPException(
            status_code=503,
            detail="VirusTotal API key not configured. Add VIRUSTOTAL_API_KEY to .env"
        )
    
    result = vt.check_domain(request.domain)
    
    if "error" in result and "Rate limit" in result["error"]:
        raise HTTPException(status_code=429, detail=result["error"])
    
    return result
