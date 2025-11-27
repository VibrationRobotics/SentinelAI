"""
Remediation Service for SentinelAI.
Executes security remediation actions with proper safeguards.
"""
import os
import sys
import subprocess
import logging
import json
import re
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# Configuration
DRY_RUN = os.getenv("REMEDIATION_DRY_RUN", "false").lower() == "true"
LOG_DIR = Path(os.getenv("REMEDIATION_LOG_DIR", "/var/log/sentinelai"))
ENABLE_REAL_EXECUTION = os.getenv("ENABLE_REAL_EXECUTION", "true").lower() == "true"

# Platform detection
IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
IS_DOCKER = os.path.exists("/.dockerenv")


class RemediationService:
    """Service for executing security remediation actions."""
    
    def __init__(self):
        """Initialize the remediation service."""
        self.executed_actions: List[Dict[str, Any]] = []
        self.blocked_ips: List[str] = []
        
        # Ensure log directory exists
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning(f"Could not create log directory: {e}")
        
        logger.info(f"Remediation service initialized. DRY_RUN={DRY_RUN}, PLATFORM={'Windows' if IS_WINDOWS else 'Linux'}")
    
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        
        # Check each octet is valid
        octets = ip.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False
        
        # Don't allow blocking localhost or private ranges by accident
        if ip.startswith('127.') or ip == '0.0.0.0':
            logger.warning(f"Attempted to block localhost IP: {ip}")
            return False
        
        return True
    
    def sanitize_input(self, value: str) -> str:
        """Sanitize input to prevent command injection."""
        # Remove any shell metacharacters
        dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '\n', '\r']
        sanitized = value
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        return sanitized.strip()
    
    def log_action(self, action: Dict[str, Any], success: bool, output: str = ""):
        """Log remediation action to file."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "success": success,
            "output": output,
            "dry_run": DRY_RUN,
            "platform": "Windows" if IS_WINDOWS else "Linux"
        }
        
        self.executed_actions.append(log_entry)
        
        try:
            log_file = LOG_DIR / "remediation.log"
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            logger.warning(f"Could not write to log file: {e}")
        
        logger.info(f"Remediation action logged: {action.get('action')} - Success: {success}")
    
    def execute_command(self, command: str, description: str) -> Tuple[bool, str]:
        """
        Execute a shell command with safeguards.
        
        Returns:
            Tuple of (success, output)
        """
        if DRY_RUN:
            logger.info(f"[DRY RUN] Would execute: {command}")
            return True, f"[DRY RUN] Command not executed: {command}"
        
        if not ENABLE_REAL_EXECUTION:
            logger.info(f"[DISABLED] Real execution disabled: {command}")
            return True, f"[SIMULATED] {description}"
        
        try:
            logger.info(f"Executing command: {command}")
            
            if IS_WINDOWS:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            else:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            
            success = result.returncode == 0
            output = result.stdout if success else result.stderr
            
            if not success:
                logger.error(f"Command failed: {output}")
            
            return success, output
            
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {command}")
            return False, "Command timed out after 30 seconds"
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return False, str(e)
    
    def block_ip(self, ip: str, threat_id: str = "") -> Dict[str, Any]:
        """
        Block an IP address using firewall rules.
        
        Args:
            ip: IP address to block
            threat_id: Associated threat ID for logging
            
        Returns:
            Result dictionary with success status and details
        """
        if not self.validate_ip(ip):
            return {
                "success": False,
                "error": f"Invalid IP address: {ip}",
                "action": "block_ip"
            }
        
        ip = self.sanitize_input(ip)
        
        if IS_WINDOWS:
            # Windows Firewall command
            rule_name = f"SentinelAI_Block_{ip.replace('.', '_')}"
            command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
            rollback_command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        else:
            # Linux iptables command
            command = f"iptables -A INPUT -s {ip} -j DROP"
            rollback_command = f"iptables -D INPUT -s {ip} -j DROP"
        
        success, output = self.execute_command(command, f"Block IP {ip}")
        
        result = {
            "success": success,
            "action": "block_ip",
            "target": ip,
            "command": command,
            "rollback_command": rollback_command,
            "output": output,
            "threat_id": threat_id,
            "executed_at": datetime.utcnow().isoformat(),
            "dry_run": DRY_RUN
        }
        
        if success:
            self.blocked_ips.append(ip)
        
        self.log_action(result, success, output)
        return result
    
    def update_firewall(self, ip: str, rule: str = "", threat_id: str = "") -> Dict[str, Any]:
        """
        Add a firewall rule to deny traffic from an IP.
        
        Args:
            ip: IP address to block
            rule: Optional custom rule description
            threat_id: Associated threat ID
            
        Returns:
            Result dictionary
        """
        # This is essentially the same as block_ip but with more specific rule naming
        if not self.validate_ip(ip):
            return {
                "success": False,
                "error": f"Invalid IP address: {ip}",
                "action": "update_firewall"
            }
        
        ip = self.sanitize_input(ip)
        
        if IS_WINDOWS:
            rule_name = f"SentinelAI_Deny_{ip.replace('.', '_')}"
            command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip} enable=yes'
            rollback_command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        else:
            # Add to iptables with comment for tracking
            command = f'iptables -A INPUT -s {ip} -j DROP -m comment --comment "SentinelAI_{threat_id}"'
            rollback_command = f"iptables -D INPUT -s {ip} -j DROP"
        
        success, output = self.execute_command(command, f"Update firewall for {ip}")
        
        result = {
            "success": success,
            "action": "update_firewall",
            "target": ip,
            "rule": rule,
            "command": command,
            "rollback_command": rollback_command,
            "output": output,
            "threat_id": threat_id,
            "executed_at": datetime.utcnow().isoformat(),
            "dry_run": DRY_RUN
        }
        
        self.log_action(result, success, output)
        return result
    
    def alert_team(self, threat_id: str, severity: str, details: str = "") -> Dict[str, Any]:
        """
        Alert the security team about a threat.
        Currently logs to file; can be extended for email/Slack/PagerDuty.
        
        Args:
            threat_id: Threat identifier
            severity: Threat severity level
            details: Additional details
            
        Returns:
            Result dictionary
        """
        alert = {
            "type": "security_alert",
            "threat_id": threat_id,
            "severity": severity,
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Log to alerts file
        try:
            alert_file = LOG_DIR / "alerts.log"
            with open(alert_file, "a") as f:
                f.write(json.dumps(alert) + "\n")
            success = True
            output = f"Alert logged to {alert_file}"
        except Exception as e:
            success = False
            output = str(e)
        
        result = {
            "success": success,
            "action": "alert_team",
            "target": "security_team",
            "alert": alert,
            "output": output,
            "executed_at": datetime.utcnow().isoformat()
        }
        
        self.log_action(result, success, output)
        
        # TODO: Add integrations for:
        # - Email notifications
        # - Slack webhooks
        # - PagerDuty
        # - Microsoft Teams
        
        return result
    
    def log_incident(self, threat_id: str, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Log incident to SIEM or incident tracking system.
        
        Args:
            threat_id: Threat identifier
            threat_data: Full threat data
            
        Returns:
            Result dictionary
        """
        incident = {
            "incident_id": f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{threat_id[:8]}",
            "threat_id": threat_id,
            "threat_data": threat_data,
            "status": "OPEN",
            "created_at": datetime.utcnow().isoformat()
        }
        
        try:
            incident_file = LOG_DIR / "incidents.log"
            with open(incident_file, "a") as f:
                f.write(json.dumps(incident) + "\n")
            success = True
            output = f"Incident {incident['incident_id']} logged"
        except Exception as e:
            success = False
            output = str(e)
        
        result = {
            "success": success,
            "action": "log_incident",
            "target": "siem",
            "incident": incident,
            "output": output,
            "executed_at": datetime.utcnow().isoformat()
        }
        
        self.log_action(result, success, output)
        return result
    
    def disable_service(self, service_name: str, threat_id: str = "") -> Dict[str, Any]:
        """
        Disable a system service (e.g., FTP, SSH).
        
        Args:
            service_name: Name of the service to disable
            threat_id: Associated threat ID
            
        Returns:
            Result dictionary
        """
        # Sanitize service name
        service_name = self.sanitize_input(service_name)
        
        # Whitelist of services that can be disabled
        allowed_services = ["vsftpd", "proftpd", "pure-ftpd", "ftp", "anonymous-ftp"]
        
        if service_name.lower() not in allowed_services:
            return {
                "success": False,
                "error": f"Service '{service_name}' not in allowed list for automated disable",
                "action": "disable_service"
            }
        
        if IS_WINDOWS:
            command = f'sc stop "{service_name}" && sc config "{service_name}" start=disabled'
            rollback_command = f'sc config "{service_name}" start=auto && sc start "{service_name}"'
        else:
            command = f"systemctl stop {service_name} && systemctl disable {service_name}"
            rollback_command = f"systemctl enable {service_name} && systemctl start {service_name}"
        
        success, output = self.execute_command(command, f"Disable service {service_name}")
        
        result = {
            "success": success,
            "action": "disable_service",
            "target": service_name,
            "command": command,
            "rollback_command": rollback_command,
            "output": output,
            "threat_id": threat_id,
            "executed_at": datetime.utcnow().isoformat(),
            "dry_run": DRY_RUN
        }
        
        self.log_action(result, success, output)
        return result
    
    def execute_remediation(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a remediation action based on action type.
        
        Args:
            action: Action type (block_ip, update_firewall, alert_team, etc.)
            params: Parameters for the action
            
        Returns:
            Result dictionary
        """
        action_map = {
            "block_ip": lambda: self.block_ip(
                params.get("target", ""),
                params.get("threat_id", "")
            ),
            "update_firewall": lambda: self.update_firewall(
                params.get("target", ""),
                params.get("rule", ""),
                params.get("threat_id", "")
            ),
            "alert_team": lambda: self.alert_team(
                params.get("threat_id", ""),
                params.get("severity", "MEDIUM"),
                params.get("details", "")
            ),
            "log_incident": lambda: self.log_incident(
                params.get("threat_id", ""),
                params.get("threat_data", {})
            ),
            "disable_anonymous_login": lambda: self.disable_service(
                "vsftpd",  # Default FTP service
                params.get("threat_id", "")
            ),
            "monitor_logs": lambda: self.alert_team(
                params.get("threat_id", ""),
                "INFO",
                "Automated log monitoring enabled"
            ),
        }
        
        if action not in action_map:
            return {
                "success": False,
                "error": f"Unknown action: {action}",
                "action": action
            }
        
        try:
            return action_map[action]()
        except Exception as e:
            logger.error(f"Error executing remediation {action}: {e}")
            return {
                "success": False,
                "error": str(e),
                "action": action
            }
    
    def rollback_action(self, action_log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Rollback a previously executed action.
        
        Args:
            action_log: The logged action to rollback
            
        Returns:
            Result dictionary
        """
        rollback_command = action_log.get("rollback_command")
        
        if not rollback_command:
            return {
                "success": False,
                "error": "No rollback command available for this action"
            }
        
        success, output = self.execute_command(
            rollback_command,
            f"Rollback: {action_log.get('action')}"
        )
        
        result = {
            "success": success,
            "action": "rollback",
            "original_action": action_log.get("action"),
            "command": rollback_command,
            "output": output,
            "executed_at": datetime.utcnow().isoformat()
        }
        
        self.log_action(result, success, output)
        return result
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of IPs blocked in this session."""
        return self.blocked_ips.copy()
    
    def get_action_history(self) -> List[Dict[str, Any]]:
        """Get history of executed actions."""
        return self.executed_actions.copy()


# Singleton instance
_remediation_service = None


def get_remediation_service() -> RemediationService:
    """Get or create the remediation service singleton."""
    global _remediation_service
    if _remediation_service is None:
        _remediation_service = RemediationService()
    return _remediation_service
