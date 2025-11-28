"""
Auto-Response API endpoints for SentinelAI.
"""
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import logging

from app.services.auto_response_service import get_auto_response_service

logger = logging.getLogger(__name__)
router = APIRouter()


class AutoResponseConfigUpdate(BaseModel):
    """Model for updating auto-response configuration."""
    enabled: Optional[bool] = None
    severity_threshold: Optional[str] = None
    auto_block_ips: Optional[bool] = None
    auto_update_firewall: Optional[bool] = None
    cooldown_minutes: Optional[int] = None
    max_blocks_per_hour: Optional[int] = None
    notify_on_action: Optional[bool] = None
    dry_run: Optional[bool] = None


class WhitelistUpdate(BaseModel):
    """Model for whitelist updates."""
    ip: str
    action: str  # "add" or "remove"


@router.get("/config")
async def get_auto_response_config() -> JSONResponse:
    """Get current auto-response configuration."""
    try:
        service = get_auto_response_service()
        config = service.get_config()
        return JSONResponse(status_code=status.HTTP_200_OK, content=config)
    except Exception as e:
        logger.error(f"Error getting auto-response config: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/config")
async def update_auto_response_config(config: AutoResponseConfigUpdate) -> JSONResponse:
    """Update auto-response configuration."""
    try:
        service = get_auto_response_service()
        
        # Build update dict from non-None values
        updates = {k: v for k, v in config.dict().items() if v is not None}
        
        if not updates:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "No configuration values provided"}
            )
        
        new_config = service.update_config(**updates)
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": "Configuration updated",
                "config": new_config
            }
        )
    except Exception as e:
        logger.error(f"Error updating auto-response config: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/toggle")
async def toggle_auto_response(enabled: Optional[bool] = None) -> JSONResponse:
    """Toggle auto-response on/off."""
    try:
        service = get_auto_response_service()
        
        if enabled is None:
            # Toggle current state
            enabled = not service.config.enabled
        
        service.update_config(enabled=enabled)
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": f"Auto-response {'enabled' if enabled else 'disabled'}",
                "enabled": enabled
            }
        )
    except Exception as e:
        logger.error(f"Error toggling auto-response: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/stats")
async def get_auto_response_stats() -> JSONResponse:
    """Get auto-response statistics."""
    try:
        service = get_auto_response_service()
        stats = service.get_stats()
        return JSONResponse(status_code=status.HTTP_200_OK, content=stats)
    except Exception as e:
        logger.error(f"Error getting auto-response stats: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/history")
async def get_auto_response_history(limit: int = 50) -> JSONResponse:
    """Get auto-response action history."""
    try:
        service = get_auto_response_service()
        history = service.get_action_history(limit)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"actions": history, "count": len(history)}
        )
    except Exception as e:
        logger.error(f"Error getting auto-response history: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/whitelist")
async def update_whitelist(update: WhitelistUpdate) -> JSONResponse:
    """Add or remove IP from whitelist."""
    try:
        service = get_auto_response_service()
        
        if update.action.lower() == "add":
            service.add_to_whitelist(update.ip)
            message = f"Added {update.ip} to whitelist"
        elif update.action.lower() == "remove":
            service.remove_from_whitelist(update.ip)
            message = f"Removed {update.ip} from whitelist"
        else:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Action must be 'add' or 'remove'"}
            )
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": message,
                "whitelist": list(service.config.whitelist_ips)
            }
        )
    except Exception as e:
        logger.error(f"Error updating whitelist: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/whitelist")
async def get_whitelist() -> JSONResponse:
    """Get current whitelist."""
    try:
        service = get_auto_response_service()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"whitelist": list(service.config.whitelist_ips)}
        )
    except Exception as e:
        logger.error(f"Error getting whitelist: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/clear-cooldowns")
async def clear_cooldowns() -> JSONResponse:
    """Clear all cooldown entries."""
    try:
        service = get_auto_response_service()
        service.clear_cooldowns()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "All cooldowns cleared"}
        )
    except Exception as e:
        logger.error(f"Error clearing cooldowns: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


class SettingsUpdate(BaseModel):
    """Model for frontend settings update."""
    enabled: Optional[bool] = None
    threshold: Optional[str] = None
    cooldown: Optional[int] = None
    whitelist: Optional[List[str]] = None


@router.get("/settings")
async def get_settings() -> JSONResponse:
    """Get settings in frontend-friendly format."""
    try:
        service = get_auto_response_service()
        config = service.get_config()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "enabled": config.get("enabled", False),
                "threshold": config.get("severity_threshold", "HIGH"),
                "cooldown": config.get("cooldown_minutes", 5) * 60,
                "whitelist": list(config.get("whitelist_ips", []))
            }
        )
    except Exception as e:
        logger.error(f"Error getting settings: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/settings")
async def update_settings(settings: SettingsUpdate) -> JSONResponse:
    """Update settings from frontend."""
    try:
        service = get_auto_response_service()
        
        updates = {}
        if settings.enabled is not None:
            updates["enabled"] = settings.enabled
        if settings.threshold is not None:
            updates["severity_threshold"] = settings.threshold
        if settings.cooldown is not None:
            updates["cooldown_minutes"] = settings.cooldown // 60
        
        if updates:
            service.update_config(**updates)
        
        # Update whitelist if provided
        if settings.whitelist is not None:
            # Clear and re-add whitelist
            current = list(service.config.whitelist_ips)
            for ip in current:
                service.remove_from_whitelist(ip)
            for ip in settings.whitelist:
                if ip.strip():
                    service.add_to_whitelist(ip.strip())
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Settings saved"}
        )
    except Exception as e:
        logger.error(f"Error updating settings: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )
