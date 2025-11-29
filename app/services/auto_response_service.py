"""
Auto-Response Service for SentinelAI.
Automatically responds to threats based on severity and configured rules.
"""
import os
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

from app.services.remediation_service import get_remediation_service

logger = logging.getLogger(__name__)


class ResponseAction(Enum):
    """Available auto-response actions."""
    BLOCK_IP = "block_ip"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    UPDATE_FIREWALL = "update_firewall"
    ALERT_ONLY = "alert_only"
    LOG_ONLY = "log_only"


@dataclass
class AutoResponseConfig:
    """Configuration for auto-response behavior."""
    enabled: bool = True
    severity_threshold: str = "HIGH"  # HIGH, MEDIUM, LOW
    auto_block_ips: bool = True
    auto_update_firewall: bool = True
    cooldown_minutes: int = 5  # Don't re-block same IP within this time
    max_blocks_per_hour: int = 50  # Rate limit
    whitelist_ips: Set[str] = field(default_factory=set)
    notify_on_action: bool = True
    dry_run: bool = False  # Log but don't execute


class AutoResponseService:
    """
    Service for automatic threat response.
    Monitors incoming threats and takes action based on severity.
    """
    
    def __init__(self):
        """Initialize the auto-response service."""
        self.config = AutoResponseConfig(
            enabled=os.getenv("AUTO_RESPONSE_ENABLED", "true").lower() == "true",
            severity_threshold=os.getenv("AUTO_RESPONSE_THRESHOLD", "HIGH"),
            auto_block_ips=os.getenv("AUTO_BLOCK_IPS", "true").lower() == "true",
            cooldown_minutes=int(os.getenv("AUTO_RESPONSE_COOLDOWN", "5")),
            dry_run=os.getenv("AUTO_RESPONSE_DRY_RUN", "false").lower() == "true"
        )
        
        # Load whitelist from env (comma-separated)
        whitelist = os.getenv("AUTO_RESPONSE_WHITELIST", "")
        if whitelist:
            self.config.whitelist_ips = set(ip.strip() for ip in whitelist.split(","))
        
        # Add common safe IPs to whitelist
        self.config.whitelist_ips.update([
            "127.0.0.1",
            "localhost",
            "::1"
        ])
        
        # Track recent actions to prevent duplicates
        self.recent_blocks: Dict[str, datetime] = {}
        self.actions_this_hour: List[datetime] = []
        self.action_history: List[Dict[str, Any]] = []
        
        # Get remediation service
        self.remediation_service = get_remediation_service()
        
        logger.info(f"Auto-response service initialized. Enabled: {self.config.enabled}, "
                   f"Threshold: {self.config.severity_threshold}")
    
    def update_config(self, **kwargs) -> Dict[str, Any]:
        """Update auto-response configuration."""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                logger.info(f"Auto-response config updated: {key} = {value}")
        
        return self.get_config()
    
    def get_config(self) -> Dict[str, Any]:
        """Get current configuration."""
        return {
            "enabled": self.config.enabled,
            "severity_threshold": self.config.severity_threshold,
            "auto_block_ips": self.config.auto_block_ips,
            "auto_update_firewall": self.config.auto_update_firewall,
            "cooldown_minutes": self.config.cooldown_minutes,
            "max_blocks_per_hour": self.config.max_blocks_per_hour,
            "whitelist_ips": list(self.config.whitelist_ips),
            "notify_on_action": self.config.notify_on_action,
            "dry_run": self.config.dry_run
        }
    
    def _severity_meets_threshold(self, severity: str) -> bool:
        """Check if severity meets or exceeds threshold."""
        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threat_level = severity_order.get(severity.upper(), 0)
        threshold_level = severity_order.get(self.config.severity_threshold.upper(), 3)
        return threat_level >= threshold_level
    
    def _is_ip_whitelisted(self, ip: str) -> bool:
        """Check if IP is in whitelist."""
        if ip in self.config.whitelist_ips:
            return True
        
        # Check for local network ranges
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            # Could add config option to whitelist all local IPs
            pass
        
        return False
    
    def _is_in_cooldown(self, ip: str) -> bool:
        """Check if IP was recently blocked (in cooldown period)."""
        if ip in self.recent_blocks:
            last_block = self.recent_blocks[ip]
            cooldown_end = last_block + timedelta(minutes=self.config.cooldown_minutes)
            if datetime.utcnow() < cooldown_end:
                return True
        return False
    
    def _check_rate_limit(self) -> bool:
        """Check if we've exceeded the hourly rate limit."""
        now = datetime.utcnow()
        hour_ago = now - timedelta(hours=1)
        
        # Clean old entries
        self.actions_this_hour = [t for t in self.actions_this_hour if t > hour_ago]
        
        return len(self.actions_this_hour) < self.config.max_blocks_per_hour
    
    def _record_action(self, ip: str, action: str, result: Dict[str, Any]):
        """Record an auto-response action."""
        self.recent_blocks[ip] = datetime.utcnow()
        self.actions_this_hour.append(datetime.utcnow())
        
        self.action_history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "ip": ip,
            "action": action,
            "result": result,
            "dry_run": self.config.dry_run
        })
        
        # Keep only last 100 actions in memory
        if len(self.action_history) > 100:
            self.action_history = self.action_history[-100:]
    
    async def evaluate_threat(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate a threat and take automatic action if warranted.
        
        Args:
            threat: Threat data dictionary
            
        Returns:
            Response dictionary with action taken (if any)
        """
        response = {
            "auto_response_enabled": self.config.enabled,
            "action_taken": None,
            "reason": None,
            "result": None
        }
        
        if not self.config.enabled:
            response["reason"] = "Auto-response is disabled"
            return response
        
        source_ip = threat.get("source_ip", "")
        severity = threat.get("severity", "LOW")
        threat_id = threat.get("id", "unknown")
        
        # Check whitelist
        if self._is_ip_whitelisted(source_ip):
            response["reason"] = f"IP {source_ip} is whitelisted"
            logger.info(f"Auto-response skipped: {source_ip} is whitelisted")
            return response
        
        # Check severity threshold
        if not self._severity_meets_threshold(severity):
            response["reason"] = f"Severity {severity} below threshold {self.config.severity_threshold}"
            return response
        
        # Check cooldown
        if self._is_in_cooldown(source_ip):
            response["reason"] = f"IP {source_ip} is in cooldown period"
            logger.info(f"Auto-response skipped: {source_ip} in cooldown")
            return response
        
        # Check rate limit
        if not self._check_rate_limit():
            response["reason"] = "Hourly rate limit exceeded"
            logger.warning("Auto-response rate limit exceeded")
            return response
        
        # Determine action based on threat type and config
        threat_type = threat.get("threat_type", "")
        hostname = threat.get("hostname")  # Agent hostname if from agent
        process_info = threat.get("process_info", {})
        file_path = threat.get("file_path")
        
        actions_to_take = []
        
        if self.config.auto_block_ips and source_ip and source_ip not in ["127.0.0.1", "localhost"]:
            actions_to_take.append((ResponseAction.BLOCK_IP, source_ip))
        
        # If it's a process threat, queue kill command
        if process_info.get("pid") and threat_type in ["suspicious_process", "malware", "reverse_shell", "crypto_miner"]:
            actions_to_take.append((ResponseAction.KILL_PROCESS, str(process_info.get("pid"))))
        
        # If it's a file threat, queue quarantine command
        if file_path and threat_type in ["malware", "suspicious_file", "ransomware"]:
            actions_to_take.append((ResponseAction.QUARANTINE_FILE, file_path))
        
        if not actions_to_take:
            actions_to_take.append((ResponseAction.ALERT_ONLY, ""))
        
        # Execute actions
        logger.info(f"Auto-response triggered for threat {threat_id} (severity: {severity})")
        
        results = []
        commands_queued = []
        
        for action, target in actions_to_take:
            if self.config.dry_run:
                result = {
                    "success": True,
                    "dry_run": True,
                    "message": f"Would execute {action.value} on {target}"
                }
            else:
                if action == ResponseAction.BLOCK_IP:
                    # Block on server side
                    result = self.remediation_service.block_ip(target, threat_id)
                    # Also queue command for agent if we know the hostname
                    if hostname:
                        commands_queued.append({
                            "hostname": hostname,
                            "command_type": "block_ip",
                            "target": target,
                            "threat_id": threat_id
                        })
                elif action == ResponseAction.KILL_PROCESS:
                    result = {"success": True, "action": "kill_process", "target": target}
                    if hostname:
                        commands_queued.append({
                            "hostname": hostname,
                            "command_type": "kill_process",
                            "target": target,
                            "threat_id": threat_id
                        })
                elif action == ResponseAction.QUARANTINE_FILE:
                    result = {"success": True, "action": "quarantine_file", "target": target}
                    if hostname:
                        commands_queued.append({
                            "hostname": hostname,
                            "command_type": "quarantine_file",
                            "target": target,
                            "threat_id": threat_id
                        })
                elif action == ResponseAction.UPDATE_FIREWALL:
                    result = self.remediation_service.update_firewall(target, "", threat_id)
                else:
                    result = {"success": True, "action": "alert_only"}
            
            results.append({"action": action.value, "target": target, "result": result})
            self._record_action(target or source_ip, action.value, result)
        
        response["action_taken"] = [r["action"] for r in results]
        response["result"] = results
        response["commands_queued"] = commands_queued
        response["reason"] = f"Severity {severity} >= threshold {self.config.severity_threshold}"
        
        return response
    
    def get_action_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent auto-response actions."""
        return self.action_history[-limit:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get auto-response statistics."""
        now = datetime.utcnow()
        hour_ago = now - timedelta(hours=1)
        
        actions_last_hour = len([t for t in self.actions_this_hour if t > hour_ago])
        
        return {
            "enabled": self.config.enabled,
            "threshold": self.config.severity_threshold,
            "actions_last_hour": actions_last_hour,
            "rate_limit": self.config.max_blocks_per_hour,
            "total_actions": len(self.action_history),
            "blocked_ips": len(self.recent_blocks),
            "dry_run": self.config.dry_run
        }
    
    def add_to_whitelist(self, ip: str) -> bool:
        """Add an IP to the whitelist."""
        self.config.whitelist_ips.add(ip)
        logger.info(f"Added {ip} to auto-response whitelist")
        return True
    
    def remove_from_whitelist(self, ip: str) -> bool:
        """Remove an IP from the whitelist."""
        if ip in self.config.whitelist_ips:
            self.config.whitelist_ips.remove(ip)
            logger.info(f"Removed {ip} from auto-response whitelist")
            return True
        return False
    
    def clear_cooldowns(self):
        """Clear all cooldown entries."""
        self.recent_blocks.clear()
        logger.info("Cleared all auto-response cooldowns")


# Singleton instance
_auto_response_service = None


def get_auto_response_service() -> AutoResponseService:
    """Get or create the auto-response service singleton."""
    global _auto_response_service
    if _auto_response_service is None:
        _auto_response_service = AutoResponseService()
    return _auto_response_service
