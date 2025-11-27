"""
Windows Firewall Service for SentinelAI.
Controls Windows Firewall for native host protection.
"""
import os
import sys
import logging
import subprocess
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Check if running on Windows
IS_WINDOWS = sys.platform == "win32"


@dataclass
class FirewallRule:
    """Represents a Windows Firewall rule."""
    name: str
    direction: str  # Inbound, Outbound
    action: str  # Allow, Block
    protocol: str  # TCP, UDP, Any
    local_port: Optional[str] = None
    remote_port: Optional[str] = None
    local_address: Optional[str] = None
    remote_address: Optional[str] = None
    program: Optional[str] = None
    enabled: bool = True
    profile: str = "Any"  # Domain, Private, Public, Any


class WindowsFirewallService:
    """
    Service for managing Windows Firewall rules.
    Uses netsh and PowerShell for firewall control.
    """
    
    def __init__(self):
        """Initialize the Windows Firewall service."""
        self.available = IS_WINDOWS
        self.rule_prefix = "SentinelAI_"
        
        # Track rules we've created
        self.managed_rules: List[str] = []
        
        # Statistics
        self.stats = {
            "rules_created": 0,
            "rules_deleted": 0,
            "ips_blocked": 0,
            "last_action": None
        }
        
        if self.available:
            logger.info("Windows Firewall service initialized")
        else:
            logger.warning("Windows Firewall service not available (not running on Windows)")
    
    def _run_netsh(self, args: List[str]) -> Tuple[bool, str]:
        """Run a netsh command."""
        if not self.available:
            return False, "Not running on Windows"
        
        try:
            cmd = ["netsh"] + args
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            success = result.returncode == 0
            output = result.stdout if success else result.stderr
            
            return success, output.strip()
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)
    
    def _run_powershell(self, command: str) -> Tuple[bool, str]:
        """Run a PowerShell command."""
        if not self.available:
            return False, "Not running on Windows"
        
        try:
            result = subprocess.run(
                ["powershell", "-Command", command],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            success = result.returncode == 0
            output = result.stdout if success else result.stderr
            
            return success, output.strip()
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)
    
    def is_enabled(self) -> Dict[str, bool]:
        """Check if Windows Firewall is enabled for each profile."""
        if not self.available:
            return {"domain": False, "private": False, "public": False}
        
        result = {}
        for profile in ["domain", "private", "public"]:
            success, output = self._run_netsh([
                "advfirewall", "show", f"{profile}profile", "state"
            ])
            
            if success:
                result[profile] = "ON" in output.upper()
            else:
                result[profile] = False
        
        return result
    
    def block_ip(self, ip: str, rule_name: Optional[str] = None, 
                 direction: str = "Inbound") -> Dict[str, Any]:
        """
        Block an IP address in Windows Firewall.
        
        Args:
            ip: IP address to block
            rule_name: Optional custom rule name
            direction: Inbound or Outbound
            
        Returns:
            Result dictionary
        """
        if not self.available:
            return {"success": False, "error": "Not running on Windows"}
        
        # Validate IP
        if not self._validate_ip(ip):
            return {"success": False, "error": f"Invalid IP address: {ip}"}
        
        # Generate rule name
        if not rule_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rule_name = f"{self.rule_prefix}Block_{ip.replace('.', '_')}_{timestamp}"
        
        # Create the rule using netsh
        success, output = self._run_netsh([
            "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            f"dir={direction.lower()}",
            "action=block",
            f"remoteip={ip}",
            "enable=yes"
        ])
        
        if success:
            self.managed_rules.append(rule_name)
            self.stats["rules_created"] += 1
            self.stats["ips_blocked"] += 1
            self.stats["last_action"] = datetime.utcnow().isoformat()
            
            logger.info(f"Blocked IP {ip} with rule {rule_name}")
            
            return {
                "success": True,
                "rule_name": rule_name,
                "ip": ip,
                "direction": direction,
                "action": "block"
            }
        else:
            logger.error(f"Failed to block IP {ip}: {output}")
            return {"success": False, "error": output}
    
    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        """
        Remove block rules for an IP address.
        
        Args:
            ip: IP address to unblock
            
        Returns:
            Result dictionary
        """
        if not self.available:
            return {"success": False, "error": "Not running on Windows"}
        
        # Find and delete rules for this IP
        rules_deleted = 0
        
        # Delete by IP pattern
        success, output = self._run_netsh([
            "advfirewall", "firewall", "delete", "rule",
            f"name=all",
            f"remoteip={ip}"
        ])
        
        if success:
            rules_deleted += 1
            self.stats["rules_deleted"] += 1
            self.stats["last_action"] = datetime.utcnow().isoformat()
        
        # Also try to delete by our naming convention
        rule_pattern = f"{self.rule_prefix}Block_{ip.replace('.', '_')}"
        for rule_name in list(self.managed_rules):
            if rule_pattern in rule_name:
                self._run_netsh([
                    "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ])
                self.managed_rules.remove(rule_name)
                rules_deleted += 1
        
        return {
            "success": rules_deleted > 0,
            "ip": ip,
            "rules_deleted": rules_deleted
        }
    
    def add_rule(self, rule: FirewallRule) -> Dict[str, Any]:
        """
        Add a custom firewall rule.
        
        Args:
            rule: FirewallRule object
            
        Returns:
            Result dictionary
        """
        if not self.available:
            return {"success": False, "error": "Not running on Windows"}
        
        # Build netsh command
        args = [
            "advfirewall", "firewall", "add", "rule",
            f"name={self.rule_prefix}{rule.name}",
            f"dir={rule.direction.lower()}",
            f"action={rule.action.lower()}",
            f"enable={'yes' if rule.enabled else 'no'}"
        ]
        
        if rule.protocol and rule.protocol.lower() != "any":
            args.append(f"protocol={rule.protocol.lower()}")
        
        if rule.local_port:
            args.append(f"localport={rule.local_port}")
        
        if rule.remote_port:
            args.append(f"remoteport={rule.remote_port}")
        
        if rule.remote_address:
            args.append(f"remoteip={rule.remote_address}")
        
        if rule.local_address:
            args.append(f"localip={rule.local_address}")
        
        if rule.program:
            args.append(f"program={rule.program}")
        
        if rule.profile and rule.profile.lower() != "any":
            args.append(f"profile={rule.profile.lower()}")
        
        success, output = self._run_netsh(args)
        
        if success:
            full_name = f"{self.rule_prefix}{rule.name}"
            self.managed_rules.append(full_name)
            self.stats["rules_created"] += 1
            self.stats["last_action"] = datetime.utcnow().isoformat()
            
            return {"success": True, "rule_name": full_name}
        else:
            return {"success": False, "error": output}
    
    def delete_rule(self, rule_name: str) -> Dict[str, Any]:
        """Delete a firewall rule by name."""
        if not self.available:
            return {"success": False, "error": "Not running on Windows"}
        
        # Add prefix if not present
        if not rule_name.startswith(self.rule_prefix):
            rule_name = f"{self.rule_prefix}{rule_name}"
        
        success, output = self._run_netsh([
            "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ])
        
        if success:
            if rule_name in self.managed_rules:
                self.managed_rules.remove(rule_name)
            self.stats["rules_deleted"] += 1
            self.stats["last_action"] = datetime.utcnow().isoformat()
            
            return {"success": True, "rule_name": rule_name}
        else:
            return {"success": False, "error": output}
    
    def list_rules(self, sentinel_only: bool = True) -> List[Dict[str, Any]]:
        """
        List firewall rules.
        
        Args:
            sentinel_only: Only show rules created by SentinelAI
            
        Returns:
            List of rule dictionaries
        """
        if not self.available:
            return []
        
        # Use PowerShell for better parsing
        if sentinel_only:
            command = f"Get-NetFirewallRule -Name '{self.rule_prefix}*' | Select-Object Name, Enabled, Direction, Action | ConvertTo-Json"
        else:
            command = "Get-NetFirewallRule | Select-Object Name, Enabled, Direction, Action | ConvertTo-Json"
        
        success, output = self._run_powershell(command)
        
        if not success:
            return []
        
        try:
            import json
            rules = json.loads(output)
            
            # Handle single rule case
            if isinstance(rules, dict):
                rules = [rules]
            
            return [
                {
                    "name": r.get("Name", ""),
                    "enabled": r.get("Enabled", False),
                    "direction": str(r.get("Direction", "")),
                    "action": str(r.get("Action", ""))
                }
                for r in rules
            ]
        except Exception as e:
            logger.error(f"Error parsing firewall rules: {e}")
            return []
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of IPs blocked by SentinelAI rules."""
        if not self.available:
            return []
        
        blocked_ips = []
        
        # Get rules and extract IPs
        command = f"""
        Get-NetFirewallRule -Name '{self.rule_prefix}*' | 
        Where-Object {{ $_.Action -eq 'Block' }} |
        Get-NetFirewallAddressFilter |
        Select-Object -ExpandProperty RemoteAddress
        """
        
        success, output = self._run_powershell(command)
        
        if success and output:
            for line in output.split('\n'):
                ip = line.strip()
                if ip and self._validate_ip(ip):
                    blocked_ips.append(ip)
        
        return blocked_ips
    
    def cleanup_rules(self) -> Dict[str, Any]:
        """Remove all SentinelAI firewall rules."""
        if not self.available:
            return {"success": False, "error": "Not running on Windows"}
        
        success, output = self._run_netsh([
            "advfirewall", "firewall", "delete", "rule",
            f"name={self.rule_prefix}*"
        ])
        
        deleted_count = len(self.managed_rules)
        self.managed_rules.clear()
        self.stats["rules_deleted"] += deleted_count
        
        return {
            "success": True,
            "rules_deleted": deleted_count,
            "message": "All SentinelAI firewall rules removed"
        }
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate an IP address."""
        # Simple IPv4 validation
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics."""
        return {
            **self.stats,
            "available": self.available,
            "managed_rules": len(self.managed_rules),
            "firewall_enabled": self.is_enabled() if self.available else {}
        }


# Singleton instance
_windows_firewall = None


def get_windows_firewall() -> WindowsFirewallService:
    """Get or create the Windows Firewall service singleton."""
    global _windows_firewall
    if _windows_firewall is None:
        _windows_firewall = WindowsFirewallService()
    return _windows_firewall
