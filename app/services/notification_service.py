"""
Notification Service
Handles Email, Discord, and Webhook notifications for threat alerts.
"""

import asyncio
import aiohttp
import aiosmtplib
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class NotificationType(Enum):
    EMAIL = "email"
    DISCORD = "discord"
    WEBHOOK = "webhook"


class SeverityLevel(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class NotificationConfig:
    """Configuration for notification channels."""
    # Email settings
    email_enabled: bool = False
    email_recipients: List[str] = None
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_tls: bool = True
    
    # Discord settings
    discord_enabled: bool = False
    discord_webhook_url: str = ""
    
    # Generic webhook settings
    webhook_enabled: bool = False
    webhook_urls: List[str] = None
    webhook_secret: str = ""
    
    # Alert thresholds
    min_severity: str = "HIGH"  # Minimum severity to trigger notifications
    
    def __post_init__(self):
        if self.email_recipients is None:
            self.email_recipients = []
        if self.webhook_urls is None:
            self.webhook_urls = []


class NotificationService:
    """
    Unified notification service for sending alerts via multiple channels.
    """
    
    def __init__(self, config: NotificationConfig = None):
        self.config = config or NotificationConfig()
        self._session: Optional[aiohttp.ClientSession] = None
        
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def close(self):
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    def _should_notify(self, severity: str) -> bool:
        """Check if severity meets threshold for notification."""
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            current_idx = severity_order.index(severity.upper())
            threshold_idx = severity_order.index(self.config.min_severity.upper())
            return current_idx >= threshold_idx
        except ValueError:
            return True  # Unknown severity, notify anyway
    
    async def notify_threat(self, threat_data: Dict[str, Any]) -> Dict[str, bool]:
        """
        Send threat notification to all configured channels.
        
        Args:
            threat_data: Dictionary containing threat information
                - severity: str (INFO, LOW, MEDIUM, HIGH, CRITICAL)
                - threat_type: str
                - description: str
                - source_ip: str (optional)
                - hostname: str (optional)
                - timestamp: str (optional)
                - mitre_techniques: list (optional)
                - ai_analysis: dict (optional)
                
        Returns:
            Dict with success status for each channel
        """
        results = {
            "email": False,
            "discord": False,
            "webhook": False
        }
        
        severity = threat_data.get("severity", "MEDIUM")
        
        if not self._should_notify(severity):
            logger.debug(f"Skipping notification for {severity} severity (threshold: {self.config.min_severity})")
            return results
        
        # Send to all enabled channels concurrently
        tasks = []
        
        if self.config.email_enabled and self.config.email_recipients:
            tasks.append(self._send_email_alert(threat_data))
        
        if self.config.discord_enabled and self.config.discord_webhook_url:
            tasks.append(self._send_discord_alert(threat_data))
        
        if self.config.webhook_enabled and self.config.webhook_urls:
            tasks.append(self._send_webhook_alert(threat_data))
        
        if tasks:
            task_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            idx = 0
            if self.config.email_enabled and self.config.email_recipients:
                results["email"] = task_results[idx] if not isinstance(task_results[idx], Exception) else False
                idx += 1
            if self.config.discord_enabled and self.config.discord_webhook_url:
                results["discord"] = task_results[idx] if not isinstance(task_results[idx], Exception) else False
                idx += 1
            if self.config.webhook_enabled and self.config.webhook_urls:
                results["webhook"] = task_results[idx] if not isinstance(task_results[idx], Exception) else False
        
        return results
    
    # ==================== EMAIL ====================
    
    async def _send_email_alert(self, threat_data: Dict[str, Any]) -> bool:
        """Send email alert for threat."""
        try:
            severity = threat_data.get("severity", "MEDIUM")
            threat_type = threat_data.get("threat_type", "Unknown Threat")
            description = threat_data.get("description", "No description")
            hostname = threat_data.get("hostname", "Unknown")
            source_ip = threat_data.get("source_ip", "N/A")
            timestamp = threat_data.get("timestamp", datetime.utcnow().isoformat())
            mitre = threat_data.get("mitre_techniques", [])
            
            # Build HTML email
            html_content = self._build_email_html(
                severity=severity,
                threat_type=threat_type,
                description=description,
                hostname=hostname,
                source_ip=source_ip,
                timestamp=timestamp,
                mitre_techniques=mitre,
                ai_analysis=threat_data.get("ai_analysis")
            )
            
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = f"🚨 [{severity}] Security Alert: {threat_type}"
            message["From"] = self.config.smtp_from or self.config.smtp_user
            message["To"] = ", ".join(self.config.email_recipients)
            
            # Plain text fallback
            plain_text = f"""
SECURITY ALERT - {severity}

Threat Type: {threat_type}
Description: {description}
Hostname: {hostname}
Source IP: {source_ip}
Time: {timestamp}
MITRE Techniques: {', '.join(mitre) if mitre else 'N/A'}

This is an automated alert from SentinelAI.
            """
            
            message.attach(MIMEText(plain_text, "plain"))
            message.attach(MIMEText(html_content, "html"))
            
            # Send email
            await aiosmtplib.send(
                message,
                hostname=self.config.smtp_host,
                port=self.config.smtp_port,
                username=self.config.smtp_user,
                password=self.config.smtp_password,
                use_tls=self.config.smtp_tls,
            )
            
            logger.info(f"Email alert sent to {len(self.config.email_recipients)} recipients")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False
    
    def _build_email_html(self, severity: str, threat_type: str, description: str,
                          hostname: str, source_ip: str, timestamp: str,
                          mitre_techniques: List[str], ai_analysis: Dict = None) -> str:
        """Build HTML email content."""
        
        severity_colors = {
            "INFO": "#17a2b8",
            "LOW": "#28a745",
            "MEDIUM": "#ffc107",
            "HIGH": "#fd7e14",
            "CRITICAL": "#dc3545"
        }
        color = severity_colors.get(severity.upper(), "#6c757d")
        
        mitre_html = ""
        if mitre_techniques:
            mitre_html = f"""
            <tr>
                <td style="padding: 10px; border-bottom: 1px solid #eee;"><strong>MITRE ATT&CK</strong></td>
                <td style="padding: 10px; border-bottom: 1px solid #eee;">{', '.join(mitre_techniques)}</td>
            </tr>
            """
        
        ai_html = ""
        if ai_analysis:
            ai_html = f"""
            <tr>
                <td style="padding: 10px; border-bottom: 1px solid #eee;"><strong>AI Analysis</strong></td>
                <td style="padding: 10px; border-bottom: 1px solid #eee;">{ai_analysis.get('summary', 'N/A')}</td>
            </tr>
            """
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Security Alert</title>
</head>
<body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5;">
    <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
        <!-- Header -->
        <div style="background: {color}; color: white; padding: 20px; text-align: center;">
            <h1 style="margin: 0; font-size: 24px;">🚨 Security Alert</h1>
            <p style="margin: 10px 0 0 0; font-size: 18px;">{severity} - {threat_type}</p>
        </div>
        
        <!-- Content -->
        <div style="padding: 20px;">
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #eee; width: 140px;"><strong>Description</strong></td>
                    <td style="padding: 10px; border-bottom: 1px solid #eee;">{description}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #eee;"><strong>Hostname</strong></td>
                    <td style="padding: 10px; border-bottom: 1px solid #eee;">{hostname}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #eee;"><strong>Source IP</strong></td>
                    <td style="padding: 10px; border-bottom: 1px solid #eee;">{source_ip}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #eee;"><strong>Time</strong></td>
                    <td style="padding: 10px; border-bottom: 1px solid #eee;">{timestamp}</td>
                </tr>
                {mitre_html}
                {ai_html}
            </table>
        </div>
        
        <!-- Footer -->
        <div style="background: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #666;">
            <p style="margin: 0;">This is an automated alert from <strong>SentinelAI</strong></p>
            <p style="margin: 5px 0 0 0;">View full details in your dashboard</p>
        </div>
    </div>
</body>
</html>
        """
    
    # ==================== DISCORD ====================
    
    async def _send_discord_alert(self, threat_data: Dict[str, Any]) -> bool:
        """Send Discord webhook alert."""
        try:
            severity = threat_data.get("severity", "MEDIUM")
            threat_type = threat_data.get("threat_type", "Unknown Threat")
            description = threat_data.get("description", "No description")
            hostname = threat_data.get("hostname", "Unknown")
            source_ip = threat_data.get("source_ip", "N/A")
            timestamp = threat_data.get("timestamp", datetime.utcnow().isoformat())
            mitre = threat_data.get("mitre_techniques", [])
            
            # Discord embed colors (decimal)
            severity_colors = {
                "INFO": 1752220,      # Cyan
                "LOW": 5763719,       # Green
                "MEDIUM": 16776960,   # Yellow
                "HIGH": 15105570,     # Orange
                "CRITICAL": 15158332  # Red
            }
            color = severity_colors.get(severity.upper(), 9807270)
            
            # Build Discord embed
            embed = {
                "title": f"🚨 {severity} Alert: {threat_type}",
                "description": description[:2000],  # Discord limit
                "color": color,
                "timestamp": timestamp if 'T' in str(timestamp) else datetime.utcnow().isoformat(),
                "fields": [
                    {"name": "🖥️ Hostname", "value": hostname, "inline": True},
                    {"name": "🌐 Source IP", "value": source_ip, "inline": True},
                    {"name": "⚠️ Severity", "value": severity, "inline": True},
                ],
                "footer": {
                    "text": "SentinelAI Security Alert"
                }
            }
            
            # Add MITRE techniques if present
            if mitre:
                embed["fields"].append({
                    "name": "🎯 MITRE ATT&CK",
                    "value": ", ".join(mitre[:10]),  # Limit to 10
                    "inline": False
                })
            
            # Add AI analysis if present
            ai_analysis = threat_data.get("ai_analysis")
            if ai_analysis and ai_analysis.get("summary"):
                embed["fields"].append({
                    "name": "🤖 AI Analysis",
                    "value": ai_analysis["summary"][:1000],
                    "inline": False
                })
            
            payload = {
                "username": "SentinelAI",
                "avatar_url": "https://raw.githubusercontent.com/VibrationRobotics/SentinelAI/main/app/static/img/logo.png",
                "embeds": [embed]
            }
            
            session = await self._get_session()
            async with session.post(
                self.config.discord_webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status in [200, 204]:
                    logger.info("Discord alert sent successfully")
                    return True
                else:
                    logger.error(f"Discord webhook failed: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to send Discord alert: {e}")
            return False
    
    # ==================== WEBHOOK ====================
    
    async def _send_webhook_alert(self, threat_data: Dict[str, Any]) -> bool:
        """Send generic webhook alert."""
        try:
            import hashlib
            import hmac
            import json
            
            payload = {
                "event": "threat_detected",
                "timestamp": threat_data.get("timestamp", datetime.utcnow().isoformat()),
                "data": {
                    "severity": threat_data.get("severity", "MEDIUM"),
                    "threat_type": threat_data.get("threat_type", "Unknown"),
                    "description": threat_data.get("description", ""),
                    "hostname": threat_data.get("hostname", "Unknown"),
                    "source_ip": threat_data.get("source_ip", ""),
                    "mitre_techniques": threat_data.get("mitre_techniques", []),
                    "confidence": threat_data.get("confidence", 0),
                    "ai_analysis": threat_data.get("ai_analysis"),
                }
            }
            
            payload_json = json.dumps(payload)
            
            # Generate signature if secret is configured
            headers = {"Content-Type": "application/json"}
            if self.config.webhook_secret:
                signature = hmac.new(
                    self.config.webhook_secret.encode(),
                    payload_json.encode(),
                    hashlib.sha256
                ).hexdigest()
                headers["X-Sentinel-Signature"] = f"sha256={signature}"
            
            session = await self._get_session()
            success_count = 0
            
            for url in self.config.webhook_urls:
                try:
                    async with session.post(
                        url,
                        data=payload_json,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        if response.status < 400:
                            success_count += 1
                            logger.info(f"Webhook sent to {url}")
                        else:
                            logger.warning(f"Webhook to {url} failed: {response.status}")
                except Exception as e:
                    logger.error(f"Webhook to {url} error: {e}")
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False
    
    # ==================== TEST METHODS ====================
    
    async def test_email(self) -> bool:
        """Send a test email."""
        test_data = {
            "severity": "INFO",
            "threat_type": "Test Alert",
            "description": "This is a test notification from SentinelAI. If you received this, email alerts are working correctly!",
            "hostname": "test-system",
            "source_ip": "127.0.0.1",
            "timestamp": datetime.utcnow().isoformat(),
            "mitre_techniques": ["T1059.001", "T1003"]
        }
        return await self._send_email_alert(test_data)
    
    async def test_discord(self) -> bool:
        """Send a test Discord message."""
        test_data = {
            "severity": "INFO",
            "threat_type": "Test Alert",
            "description": "This is a test notification from SentinelAI. If you see this, Discord alerts are working correctly! 🎉",
            "hostname": "test-system",
            "source_ip": "127.0.0.1",
            "timestamp": datetime.utcnow().isoformat(),
            "mitre_techniques": ["T1059.001", "T1003"]
        }
        return await self._send_discord_alert(test_data)
    
    async def test_webhook(self) -> bool:
        """Send a test webhook."""
        test_data = {
            "severity": "INFO",
            "threat_type": "Test Alert",
            "description": "This is a test notification from SentinelAI.",
            "hostname": "test-system",
            "source_ip": "127.0.0.1",
            "timestamp": datetime.utcnow().isoformat()
        }
        return await self._send_webhook_alert(test_data)


# Global instance
_notification_service: Optional[NotificationService] = None


def get_notification_service() -> NotificationService:
    """Get the global notification service instance."""
    global _notification_service
    if _notification_service is None:
        _notification_service = NotificationService()
    return _notification_service


def configure_notifications(config: NotificationConfig):
    """Configure the global notification service."""
    global _notification_service
    _notification_service = NotificationService(config)
    return _notification_service
