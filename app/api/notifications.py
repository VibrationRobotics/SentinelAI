"""
Notification API endpoints
Configure and test Email, Discord, and Webhook notifications.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.services.notification_service import (
    NotificationService, 
    NotificationConfig,
    get_notification_service,
    configure_notifications
)

router = APIRouter(prefix="/notifications", tags=["notifications"])


# ==================== SCHEMAS ====================

class EmailConfigSchema(BaseModel):
    enabled: bool = False
    recipients: List[str] = []
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_tls: bool = True


class DiscordConfigSchema(BaseModel):
    enabled: bool = False
    webhook_url: str = ""


class WebhookConfigSchema(BaseModel):
    enabled: bool = False
    urls: List[str] = []
    secret: str = ""


class NotificationConfigSchema(BaseModel):
    email: EmailConfigSchema = EmailConfigSchema()
    discord: DiscordConfigSchema = DiscordConfigSchema()
    webhook: WebhookConfigSchema = WebhookConfigSchema()
    min_severity: str = "HIGH"


class TestNotificationRequest(BaseModel):
    channel: str  # "email", "discord", or "webhook"


class NotificationResponse(BaseModel):
    success: bool
    message: str


# ==================== ENDPOINTS ====================

@router.get("/config")
async def get_notification_config(
    current_user: User = Depends(get_current_user)
):
    """Get current notification configuration."""
    service = get_notification_service()
    config = service.config
    
    return {
        "email": {
            "enabled": config.email_enabled,
            "recipients": config.email_recipients,
            "smtp_host": config.smtp_host,
            "smtp_port": config.smtp_port,
            "smtp_user": config.smtp_user,
            "smtp_password": "***" if config.smtp_password else "",
            "smtp_from": config.smtp_from,
            "smtp_tls": config.smtp_tls
        },
        "discord": {
            "enabled": config.discord_enabled,
            "webhook_url": config.discord_webhook_url[:50] + "..." if len(config.discord_webhook_url) > 50 else config.discord_webhook_url
        },
        "webhook": {
            "enabled": config.webhook_enabled,
            "urls": config.webhook_urls,
            "secret": "***" if config.webhook_secret else ""
        },
        "min_severity": config.min_severity
    }


@router.post("/config")
async def update_notification_config(
    config: NotificationConfigSchema,
    current_user: User = Depends(get_current_user)
):
    """Update notification configuration."""
    try:
        new_config = NotificationConfig(
            # Email
            email_enabled=config.email.enabled,
            email_recipients=config.email.recipients,
            smtp_host=config.email.smtp_host,
            smtp_port=config.email.smtp_port,
            smtp_user=config.email.smtp_user,
            smtp_password=config.email.smtp_password,
            smtp_from=config.email.smtp_from,
            smtp_tls=config.email.smtp_tls,
            # Discord
            discord_enabled=config.discord.enabled,
            discord_webhook_url=config.discord.webhook_url,
            # Webhook
            webhook_enabled=config.webhook.enabled,
            webhook_urls=config.webhook.urls,
            webhook_secret=config.webhook.secret,
            # Threshold
            min_severity=config.min_severity
        )
        
        configure_notifications(new_config)
        
        return {"success": True, "message": "Notification configuration updated"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to update configuration: {str(e)}"
        )


@router.post("/test/{channel}")
async def test_notification(
    channel: str,
    current_user: User = Depends(get_current_user)
):
    """
    Test a notification channel.
    
    Args:
        channel: "email", "discord", or "webhook"
    """
    service = get_notification_service()
    
    if channel == "email":
        if not service.config.email_enabled:
            raise HTTPException(status_code=400, detail="Email notifications not enabled")
        success = await service.test_email()
        
    elif channel == "discord":
        if not service.config.discord_enabled:
            raise HTTPException(status_code=400, detail="Discord notifications not enabled")
        success = await service.test_discord()
        
    elif channel == "webhook":
        if not service.config.webhook_enabled:
            raise HTTPException(status_code=400, detail="Webhook notifications not enabled")
        success = await service.test_webhook()
        
    else:
        raise HTTPException(status_code=400, detail=f"Unknown channel: {channel}")
    
    if success:
        return {"success": True, "message": f"Test {channel} notification sent successfully"}
    else:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send test {channel} notification. Check logs for details."
        )


@router.post("/send")
async def send_manual_notification(
    threat_data: dict,
    current_user: User = Depends(get_current_user)
):
    """
    Manually send a notification for a threat.
    
    Body should contain:
    - severity: str
    - threat_type: str
    - description: str
    - hostname: str (optional)
    - source_ip: str (optional)
    """
    service = get_notification_service()
    results = await service.notify_threat(threat_data)
    
    return {
        "success": any(results.values()),
        "results": results,
        "message": "Notification sent to enabled channels"
    }


# ==================== QUICK SETUP ENDPOINTS ====================

@router.post("/setup/discord")
async def quick_setup_discord(
    webhook_url: str,
    min_severity: str = "HIGH",
    current_user: User = Depends(get_current_user)
):
    """
    Quick setup for Discord notifications.
    
    To get a webhook URL:
    1. Go to your Discord server
    2. Server Settings > Integrations > Webhooks
    3. Create a new webhook
    4. Copy the webhook URL
    """
    if not webhook_url.startswith("https://discord.com/api/webhooks/"):
        raise HTTPException(
            status_code=400,
            detail="Invalid Discord webhook URL. It should start with https://discord.com/api/webhooks/"
        )
    
    service = get_notification_service()
    service.config.discord_enabled = True
    service.config.discord_webhook_url = webhook_url
    service.config.min_severity = min_severity
    
    # Test it
    success = await service.test_discord()
    
    if success:
        return {
            "success": True,
            "message": "Discord notifications configured and tested successfully!"
        }
    else:
        service.config.discord_enabled = False
        raise HTTPException(
            status_code=500,
            detail="Failed to send test message. Please check your webhook URL."
        )


@router.post("/setup/email")
async def quick_setup_email(
    recipients: List[str],
    smtp_host: str = "smtp.gmail.com",
    smtp_port: int = 587,
    smtp_user: str = "",
    smtp_password: str = "",
    min_severity: str = "HIGH",
    current_user: User = Depends(get_current_user)
):
    """
    Quick setup for Email notifications.
    
    For Gmail:
    1. Enable 2FA on your Google account
    2. Generate an App Password: Google Account > Security > App Passwords
    3. Use that password here (not your regular password)
    """
    service = get_notification_service()
    service.config.email_enabled = True
    service.config.email_recipients = recipients
    service.config.smtp_host = smtp_host
    service.config.smtp_port = smtp_port
    service.config.smtp_user = smtp_user
    service.config.smtp_password = smtp_password
    service.config.smtp_from = smtp_user
    service.config.min_severity = min_severity
    
    # Test it
    success = await service.test_email()
    
    if success:
        return {
            "success": True,
            "message": f"Email notifications configured! Test email sent to {', '.join(recipients)}"
        }
    else:
        service.config.email_enabled = False
        raise HTTPException(
            status_code=500,
            detail="Failed to send test email. Check SMTP credentials and settings."
        )
