#!/usr/bin/env python3
"""
SentinelAI Linux/macOS Agent
Native agent for Unix-based systems that monitors and reports to the Docker dashboard.
"""

import os
import sys
import time
import json
import queue
import logging
import platform
import threading
import subprocess
import argparse
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

# Check for required modules
try:
    import psutil
    import requests
except ImportError:
    print("Missing dependencies. Install with: pip install psutil requests")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SentinelAgent')


@dataclass
class SecurityEvent:
    """Security event data structure."""
    timestamp: str
    event_type: str
    severity: str
    source: str
    description: str
    details: dict


class LinuxAgent:
    """SentinelAI Linux/macOS Agent for native system monitoring."""
    
    def __init__(self, dashboard_url: str = "http://localhost:8015"):
        self.dashboard_url = dashboard_url.rstrip('/')
        self.api_base = f"{self.dashboard_url}/api/v1"
        self.running = False
        self.event_queue = queue.Queue()
        self.platform = platform.system()  # 'Linux' or 'Darwin' (macOS)
        
        # Monitoring state
        self.known_processes: Dict[int, Dict] = {}
        self.suspicious_ips: set = set()
        self.blocked_ips: set = set()
        
        # Suspicious patterns
        self.suspicious_executables = [
            'mimikatz', 'pwdump', 'lazagne', 'keylogger',
            'nc', 'ncat', 'netcat', 'socat',
            'meterpreter', 'cobaltstrike', 'beacon',
            'xmrig', 'minerd', 'cpuminer',  # Crypto miners
        ]
        
        self.suspicious_cmdline_patterns = [
            'bash -i', '/dev/tcp/', '/dev/udp/',  # Reverse shells
            'curl | bash', 'wget | bash', 'curl | sh',  # Download and execute
            'base64 -d', 'base64 --decode',  # Encoded commands
            'chmod 777', 'chmod +x /tmp/',  # Suspicious permissions
            '/etc/passwd', '/etc/shadow',  # Credential access
            'iptables -F', 'ufw disable',  # Firewall tampering
        ]
        
        # Whitelist common safe processes
        self.whitelisted_processes = [
            'python', 'python3', 'node', 'npm', 'docker',
            'code', 'cursor', 'chrome', 'firefox', 'safari',
            'systemd', 'init', 'bash', 'zsh', 'fish',
            'sshd', 'cron', 'rsyslogd', 'journald',
        ]
        
        # Suspicious ports to monitor
        self.suspicious_ports = [4444, 5555, 6666, 1337, 31337, 8080, 9001]
        
        # Statistics
        self.stats = {
            'processes_monitored': 0,
            'suspicious_processes': 0,
            'network_connections': 0,
            'suspicious_connections': 0,
            'events_sent': 0,
            'start_time': None
        }
        
        # AI Analysis
        self.use_ai = True
        self.ai_cache: Dict[str, Dict] = {}
        
        logger.info(f"Linux/macOS Agent initialized - Dashboard: {self.dashboard_url}")
        logger.info(f"Platform: {self.platform}")
    
    def start(self):
        """Start the agent."""
        self.running = True
        self.stats['start_time'] = datetime.utcnow().isoformat()
        
        logger.info("=" * 50)
        logger.info("SentinelAI Linux/macOS Agent Starting")
        logger.info(f"Platform: {platform.system()} {platform.release()}")
        logger.info(f"Hostname: {platform.node()}")
        logger.info(f"Dashboard: {self.dashboard_url}")
        logger.info("=" * 50)
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self._process_monitor_loop, daemon=True),
            threading.Thread(target=self._network_monitor_loop, daemon=True),
            threading.Thread(target=self._auth_log_monitor_loop, daemon=True),
            threading.Thread(target=self._event_sender_loop, daemon=True),
            threading.Thread(target=self._heartbeat_loop, daemon=True),
        ]
        
        for t in threads:
            t.start()
        
        # Register with dashboard
        self._register_agent()
        
        # Main loop
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.running = False
    
    def _heartbeat_loop(self):
        """Send periodic heartbeat to dashboard."""
        while self.running:
            try:
                time.sleep(30)
                self._register_agent()
            except Exception as e:
                logger.debug(f"Heartbeat error: {e}")
    
    def _register_agent(self):
        """Register this agent with the dashboard."""
        try:
            data = {
                'hostname': platform.node(),
                'platform': platform.system(),
                'platform_version': platform.release(),
                'agent_version': '1.0.0',
                'capabilities': ['process', 'network', 'authlog', 'firewall', 'ai']
            }
            
            response = requests.post(
                f"{self.api_base}/windows/agent/register",  # Same endpoint works for all agents
                json=data,
                timeout=5
            )
            
            if response.status_code == 200:
                logger.info("Successfully registered with dashboard")
            else:
                logger.warning(f"Could not register: {response.status_code}")
        except Exception as e:
            logger.warning(f"Dashboard not reachable: {e}")
    
    def _send_event(self, event: SecurityEvent):
        """Queue an event to be sent to the dashboard."""
        self.event_queue.put(event)
    
    def _event_sender_loop(self):
        """Background thread to send events to dashboard."""
        while self.running:
            try:
                event = self.event_queue.get(timeout=1)
                
                # Send to dashboard
                try:
                    payload = {
                        'source_ip': '127.0.0.1',
                        'threat_type': event.event_type,
                        'severity': event.severity,
                        'description': event.description,
                        'payload': json.dumps(event.details)
                    }
                    
                    response = requests.post(
                        f"{self.api_base}/threats/analyze",
                        json=payload,
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        self.stats['events_sent'] += 1
                        logger.debug(f"Event sent: {event.event_type}")
                    
                except Exception as e:
                    logger.error(f"Failed to send event: {e}")
                    
            except queue.Empty:
                continue
    
    def _process_monitor_loop(self):
        """Monitor running processes."""
        logger.info("Process monitor started")
        
        while self.running:
            try:
                current_pids = set()
                
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
                    try:
                        pid = proc.info['pid']
                        current_pids.add(pid)
                        
                        if pid in self.known_processes:
                            continue
                        
                        proc_info = {
                            'pid': pid,
                            'name': proc.info['name'] or 'Unknown',
                            'exe': proc.info['exe'] or '',
                            'cmdline': ' '.join(proc.info['cmdline'] or []),
                            'username': proc.info['username'] or '',
                            'create_time': proc.info['create_time']
                        }
                        
                        self.known_processes[pid] = proc_info
                        self.stats['processes_monitored'] += 1
                        
                        # Check if suspicious
                        is_suspicious, reason = self._is_suspicious_process(proc_info)
                        
                        if is_suspicious:
                            self.stats['suspicious_processes'] += 1
                            
                            event = SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type='suspicious_process',
                                severity='HIGH',
                                source='process',
                                description=f"Suspicious process: {proc_info['name']} - {reason}",
                                details=proc_info
                            )
                            self._send_event(event)
                            logger.warning(f"SUSPICIOUS: {proc_info['name']} (PID: {pid}) - {reason}")
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Clean up dead processes
                dead_pids = set(self.known_processes.keys()) - current_pids
                for pid in dead_pids:
                    del self.known_processes[pid]
                
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Process monitor error: {e}")
                time.sleep(5)
    
    def _is_suspicious_process(self, proc_info: Dict) -> tuple:
        """Check if a process is suspicious."""
        name = proc_info['name'].lower()
        exe = (proc_info['exe'] or '').lower()
        cmdline = (proc_info['cmdline'] or '').lower()
        
        # Whitelist check
        for safe in self.whitelisted_processes:
            if safe in name:
                return False, ""
        
        # Check for known malicious executables
        for suspicious in self.suspicious_executables:
            if suspicious in name or suspicious in exe:
                return True, f"Known malicious tool: {suspicious}"
        
        # Check command line for suspicious patterns
        for pattern in self.suspicious_cmdline_patterns:
            if pattern.lower() in cmdline:
                return True, f"Suspicious command: {pattern}"
        
        # Check for reverse shell patterns
        if 'bash -i' in cmdline and '/dev/tcp' in cmdline:
            return True, "Reverse shell detected"
        
        # Check for processes running from /tmp
        if '/tmp/' in exe:
            return True, "Executable running from /tmp"
        
        return False, ""
    
    def _network_monitor_loop(self):
        """Monitor network connections."""
        logger.info("Network monitor started")
        
        while self.running:
            try:
                connections = psutil.net_connections(kind='inet')
                self.stats['network_connections'] = len(connections)
                
                for conn in connections:
                    if conn.status != 'ESTABLISHED':
                        continue
                    
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        
                        # Check for suspicious ports
                        if remote_port in self.suspicious_ports:
                            if remote_ip not in self.suspicious_ips:
                                self.suspicious_ips.add(remote_ip)
                                self.stats['suspicious_connections'] += 1
                                
                                event = SecurityEvent(
                                    timestamp=datetime.utcnow().isoformat(),
                                    event_type='suspicious_connection',
                                    severity='HIGH',
                                    source='network',
                                    description=f"Connection to suspicious port {remote_port}",
                                    details={
                                        'remote_ip': remote_ip,
                                        'remote_port': remote_port,
                                        'local_port': conn.laddr.port if conn.laddr else None
                                    }
                                )
                                self._send_event(event)
                                logger.warning(f"SUSPICIOUS CONNECTION: {remote_ip}:{remote_port}")
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Network monitor error: {e}")
                time.sleep(10)
    
    def _auth_log_monitor_loop(self):
        """Monitor authentication logs (Linux only)."""
        logger.info("Auth log monitor started")
        
        # Determine log file based on platform
        if self.platform == 'Linux':
            auth_log = '/var/log/auth.log'
            if not os.path.exists(auth_log):
                auth_log = '/var/log/secure'  # RHEL/CentOS
        elif self.platform == 'Darwin':
            auth_log = '/var/log/system.log'
        else:
            logger.warning("Auth log monitoring not supported on this platform")
            return
        
        if not os.path.exists(auth_log):
            logger.warning(f"Auth log not found: {auth_log}")
            return
        
        try:
            # Start at end of file
            with open(auth_log, 'r') as f:
                f.seek(0, 2)  # Go to end
                
                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(1)
                        continue
                    
                    # Check for failed login attempts
                    if 'Failed password' in line or 'authentication failure' in line:
                        event = SecurityEvent(
                            timestamp=datetime.utcnow().isoformat(),
                            event_type='failed_login',
                            severity='MEDIUM',
                            source='authlog',
                            description='Failed login attempt detected',
                            details={'log_line': line.strip()}
                        )
                        self._send_event(event)
                        logger.warning(f"FAILED LOGIN: {line.strip()[:100]}")
                    
                    # Check for sudo usage
                    elif 'sudo:' in line and 'COMMAND=' in line:
                        # Log sudo commands for audit
                        logger.debug(f"Sudo command: {line.strip()[:100]}")
                        
        except PermissionError:
            logger.warning(f"Permission denied reading {auth_log}. Run as root for full monitoring.")
        except Exception as e:
            logger.error(f"Auth log monitor error: {e}")
    
    def block_ip(self, ip: str) -> bool:
        """Block an IP address using iptables (Linux) or pf (macOS)."""
        if ip in self.blocked_ips:
            return True
        
        try:
            if self.platform == 'Linux':
                # Use iptables
                cmd = ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
            elif self.platform == 'Darwin':
                # Use pf (requires root)
                cmd = ['pfctl', '-t', 'blocklist', '-T', 'add', ip]
            else:
                logger.warning(f"IP blocking not supported on {self.platform}")
                return False
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                logger.info(f"Blocked IP: {ip}")
                return True
            else:
                logger.error(f"Failed to block IP: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='SentinelAI Linux/macOS Agent')
    parser.add_argument('--dashboard', '-d', default='http://localhost:8015',
                        help='Dashboard URL (default: http://localhost:8015)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('--no-ai', action='store_true',
                        help='Disable AI-powered analysis')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    ai_status = "DISABLED" if args.no_ai else "ENABLED"
    
    print(f"""
    ╔═══════════════════════════════════════════════════════════╗
    ║         SentinelAI Linux/macOS Agent v1.0                 ║
    ║       Native Unix Protection & Threat Detection           ║
    ║                                                           ║
    ║     AI Analysis: {ai_status:^10}                            ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    agent = LinuxAgent(dashboard_url=args.dashboard)
    agent.use_ai = not args.no_ai
    agent.start()


if __name__ == '__main__':
    main()
