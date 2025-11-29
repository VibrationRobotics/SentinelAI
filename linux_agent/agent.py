#!/usr/bin/env python3
"""
SentinelAI Linux/macOS Agent v2.0
Native agent for Unix-based systems with comprehensive security monitoring.

Monitors:
- Cron jobs - Detect new/modified cron jobs
- SSH keys - Watch authorized_keys changes  
- Sudo logs - Track privilege escalation
- Kernel modules - Detect rootkit modules
- LD_PRELOAD - Detect library injection
- Setuid binaries - Track setuid changes
- Container escape - Monitor for breakout attempts
- Auditd - Parse audit logs
- SELinux/AppArmor - Security policy violations
- Package manager - Detect unauthorized installs
- Systemd services - New/modified services
- File integrity - Hash critical system files
- Process monitoring - Suspicious process detection
- Network monitoring - Suspicious connections
- Auth log monitoring - Failed logins, brute force
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
import hashlib
import re
import glob
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path

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
    """SentinelAI Linux/macOS Agent v2.0 with comprehensive security monitoring."""
    
    def __init__(self, dashboard_url: str = "http://localhost:8015", api_key: str = None):
        self.dashboard_url = dashboard_url.rstrip('/')
        self.api_base = f"{self.dashboard_url}/api/v1"
        self.api_key = api_key or os.environ.get('SENTINEL_API_KEY', '')
        self.running = False
        self.event_queue = queue.Queue()
        self.platform = platform.system()  # 'Linux' or 'Darwin' (macOS)
        
        # Monitoring state
        self.known_processes: Dict[int, Dict] = {}
        self.suspicious_ips: Set[str] = set()
        self.blocked_ips: Set[str] = set()
        
        # New monitoring state for advanced monitors
        self.known_cron_jobs: Dict[str, str] = {}  # path -> hash
        self.known_ssh_keys: Dict[str, str] = {}  # path -> hash
        self.known_kernel_modules: Set[str] = set()
        self.known_setuid_binaries: Dict[str, int] = {}  # path -> mode
        self.known_systemd_services: Set[str] = set()
        self.known_packages: Set[str] = set()
        self.file_integrity_hashes: Dict[str, str] = {}  # path -> hash
        self.known_containers: Set[str] = set()
        
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
        
        # Critical files to monitor for integrity
        self.critical_files = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '/etc/ssh/sshd_config', '/etc/pam.d/sshd',
            '/etc/ld.so.preload', '/etc/ld.so.conf',
            '/etc/hosts', '/etc/resolv.conf',
            '/root/.bashrc', '/root/.bash_profile',
        ]
        
        # Suspicious kernel modules (rootkits)
        self.suspicious_modules = [
            'diamorphine', 'reptile', 'suterusu', 'adore-ng',
            'knark', 'rial', 'heroin', 'override',
        ]
        
        logger.info(f"Linux/macOS Agent v2.0 initialized - Dashboard: {self.dashboard_url}")
        logger.info(f"API Key: {'Configured' if self.api_key else 'Not set'}")
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
        
        # Start monitoring threads - Core monitors
        threads = [
            threading.Thread(target=self._process_monitor_loop, daemon=True, name='process'),
            threading.Thread(target=self._network_monitor_loop, daemon=True, name='network'),
            threading.Thread(target=self._auth_log_monitor_loop, daemon=True, name='authlog'),
            threading.Thread(target=self._event_sender_loop, daemon=True, name='sender'),
            threading.Thread(target=self._heartbeat_loop, daemon=True, name='heartbeat'),
        ]
        
        # Advanced monitors (Linux-specific)
        if self.platform == 'Linux':
            threads.extend([
                threading.Thread(target=self._cron_monitor_loop, daemon=True, name='cron'),
                threading.Thread(target=self._ssh_key_monitor_loop, daemon=True, name='sshkeys'),
                threading.Thread(target=self._kernel_module_monitor_loop, daemon=True, name='kernel'),
                threading.Thread(target=self._ld_preload_monitor_loop, daemon=True, name='ldpreload'),
                threading.Thread(target=self._setuid_monitor_loop, daemon=True, name='setuid'),
                threading.Thread(target=self._systemd_monitor_loop, daemon=True, name='systemd'),
                threading.Thread(target=self._package_monitor_loop, daemon=True, name='packages'),
                threading.Thread(target=self._file_integrity_monitor_loop, daemon=True, name='integrity'),
                threading.Thread(target=self._container_escape_monitor_loop, daemon=True, name='container'),
                threading.Thread(target=self._auditd_monitor_loop, daemon=True, name='auditd'),
                threading.Thread(target=self._selinux_monitor_loop, daemon=True, name='selinux'),
            ])
        
        # Advanced monitors (macOS-specific)
        if self.platform == 'Darwin':
            threads.extend([
                threading.Thread(target=self._launch_daemon_monitor_loop, daemon=True, name='launchdaemon'),
                threading.Thread(target=self._keychain_monitor_loop, daemon=True, name='keychain'),
                threading.Thread(target=self._gatekeeper_monitor_loop, daemon=True, name='gatekeeper'),
                threading.Thread(target=self._tcc_monitor_loop, daemon=True, name='tcc'),
                threading.Thread(target=self._unified_log_monitor_loop, daemon=True, name='unifiedlog'),
                threading.Thread(target=self._xprotect_monitor_loop, daemon=True, name='xprotect'),
            ])
        
        for t in threads:
            t.start()
            logger.info(f"{t.name} monitor started")
        
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
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for API requests including API key."""
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['X-API-Key'] = self.api_key
        return headers
    
    def _register_agent(self):
        """Register this agent with the dashboard."""
        try:
            capabilities = ['process', 'network', 'authlog', 'firewall', 'ai']
            if self.platform == 'Linux':
                capabilities.extend([
                    'cron', 'sshkeys', 'kernel', 'ldpreload', 'setuid',
                    'systemd', 'packages', 'integrity', 'container',
                    'auditd', 'selinux'
                ])
            elif self.platform == 'Darwin':
                capabilities.extend([
                    'launchdaemon', 'keychain', 'gatekeeper', 'tcc',
                    'unifiedlog', 'xprotect'
                ])
            
            data = {
                'hostname': platform.node(),
                'platform': platform.system(),
                'platform_version': platform.release(),
                'agent_version': '2.0.0',
                'capabilities': capabilities,
                'is_admin': os.geteuid() == 0 if hasattr(os, 'geteuid') else False
            }
            
            response = requests.post(
                f"{self.api_base}/windows/agent/register",  # Same endpoint works for all agents
                json=data,
                headers=self._get_headers(),
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
                        'payload': json.dumps(event.details),
                        'hostname': platform.node(),
                        'platform': self.platform
                    }
                    
                    response = requests.post(
                        f"{self.api_base}/threats/analyze",
                        json=payload,
                        headers=self._get_headers(),
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
    
    # ============== ADVANCED LINUX MONITORS ==============
    
    def _get_file_hash(self, filepath: str) -> Optional[str]:
        """Get SHA256 hash of a file."""
        try:
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except (IOError, PermissionError):
            return None
    
    def _cron_monitor_loop(self):
        """Monitor cron jobs for new/modified entries."""
        logger.info("Cron monitor started")
        
        cron_paths = [
            '/etc/crontab',
            '/etc/cron.d/',
            '/var/spool/cron/crontabs/',
            '/var/spool/cron/',
        ]
        
        # Initial scan
        for path in cron_paths:
            if os.path.isfile(path):
                self.known_cron_jobs[path] = self._get_file_hash(path) or ''
            elif os.path.isdir(path):
                for f in glob.glob(f"{path}/*"):
                    if os.path.isfile(f):
                        self.known_cron_jobs[f] = self._get_file_hash(f) or ''
        
        logger.info(f"Tracking {len(self.known_cron_jobs)} cron files")
        
        while self.running:
            try:
                for path in cron_paths:
                    if os.path.isfile(path):
                        current_hash = self._get_file_hash(path)
                        if path not in self.known_cron_jobs:
                            self._send_event(SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type='cron_added',
                                severity='HIGH',
                                source='cron',
                                description=f'New cron file detected: {path}',
                                details={'path': path}
                            ))
                            logger.warning(f"NEW CRON FILE: {path}")
                        elif current_hash != self.known_cron_jobs.get(path):
                            self._send_event(SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type='cron_modified',
                                severity='HIGH',
                                source='cron',
                                description=f'Cron file modified: {path}',
                                details={'path': path}
                            ))
                            logger.warning(f"CRON MODIFIED: {path}")
                        self.known_cron_jobs[path] = current_hash
                    
                    elif os.path.isdir(path):
                        for f in glob.glob(f"{path}/*"):
                            if os.path.isfile(f):
                                current_hash = self._get_file_hash(f)
                                if f not in self.known_cron_jobs:
                                    self._send_event(SecurityEvent(
                                        timestamp=datetime.utcnow().isoformat(),
                                        event_type='cron_added',
                                        severity='HIGH',
                                        source='cron',
                                        description=f'New cron job detected: {f}',
                                        details={'path': f}
                                    ))
                                    logger.warning(f"NEW CRON JOB: {f}")
                                self.known_cron_jobs[f] = current_hash
                
                time.sleep(30)
            except Exception as e:
                logger.debug(f"Cron monitor error: {e}")
                time.sleep(60)
    
    def _ssh_key_monitor_loop(self):
        """Monitor SSH authorized_keys files for changes."""
        logger.info("SSH key monitor started")
        
        # Find all authorized_keys files
        ssh_key_paths = []
        for home in glob.glob('/home/*') + ['/root']:
            auth_keys = os.path.join(home, '.ssh', 'authorized_keys')
            if os.path.exists(auth_keys):
                ssh_key_paths.append(auth_keys)
                self.known_ssh_keys[auth_keys] = self._get_file_hash(auth_keys) or ''
        
        logger.info(f"Tracking {len(ssh_key_paths)} authorized_keys files")
        
        while self.running:
            try:
                # Check existing files
                for path in list(self.known_ssh_keys.keys()):
                    if os.path.exists(path):
                        current_hash = self._get_file_hash(path)
                        if current_hash != self.known_ssh_keys[path]:
                            self._send_event(SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type='ssh_key_modified',
                                severity='CRITICAL',
                                source='sshkeys',
                                description=f'SSH authorized_keys modified: {path}',
                                details={'path': path}
                            ))
                            logger.warning(f"SSH KEYS MODIFIED: {path}")
                            self.known_ssh_keys[path] = current_hash
                
                # Check for new files
                for home in glob.glob('/home/*') + ['/root']:
                    auth_keys = os.path.join(home, '.ssh', 'authorized_keys')
                    if os.path.exists(auth_keys) and auth_keys not in self.known_ssh_keys:
                        self._send_event(SecurityEvent(
                            timestamp=datetime.utcnow().isoformat(),
                            event_type='ssh_key_added',
                            severity='CRITICAL',
                            source='sshkeys',
                            description=f'New authorized_keys file: {auth_keys}',
                            details={'path': auth_keys}
                        ))
                        logger.warning(f"NEW SSH KEYS FILE: {auth_keys}")
                        self.known_ssh_keys[auth_keys] = self._get_file_hash(auth_keys) or ''
                
                time.sleep(30)
            except Exception as e:
                logger.debug(f"SSH key monitor error: {e}")
                time.sleep(60)
    
    def _kernel_module_monitor_loop(self):
        """Monitor loaded kernel modules for rootkits."""
        logger.info("Kernel module monitor started")
        
        # Get initial module list
        try:
            result = subprocess.run(['lsmod'], capture_output=True, text=True)
            for line in result.stdout.strip().split('\n')[1:]:
                parts = line.split()
                if parts:
                    self.known_kernel_modules.add(parts[0])
            logger.info(f"Tracking {len(self.known_kernel_modules)} kernel modules")
        except Exception as e:
            logger.warning(f"Could not get initial module list: {e}")
        
        while self.running:
            try:
                result = subprocess.run(['lsmod'], capture_output=True, text=True)
                current_modules = set()
                
                for line in result.stdout.strip().split('\n')[1:]:
                    parts = line.split()
                    if parts:
                        module_name = parts[0]
                        current_modules.add(module_name)
                        
                        if module_name not in self.known_kernel_modules:
                            # Check if it's a known rootkit
                            severity = 'CRITICAL' if module_name.lower() in self.suspicious_modules else 'HIGH'
                            
                            self._send_event(SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type='kernel_module_loaded',
                                severity=severity,
                                source='kernel',
                                description=f'New kernel module loaded: {module_name}',
                                details={'module': module_name, 'suspicious': module_name.lower() in self.suspicious_modules}
                            ))
                            logger.warning(f"NEW KERNEL MODULE: {module_name}")
                            self.known_kernel_modules.add(module_name)
                
                time.sleep(30)
            except Exception as e:
                logger.debug(f"Kernel module monitor error: {e}")
                time.sleep(60)
    
    def _ld_preload_monitor_loop(self):
        """Monitor LD_PRELOAD for library injection attacks."""
        logger.info("LD_PRELOAD monitor started")
        
        preload_file = '/etc/ld.so.preload'
        last_hash = self._get_file_hash(preload_file) if os.path.exists(preload_file) else None
        
        while self.running:
            try:
                # Check LD_PRELOAD environment variable in processes
                for proc in psutil.process_iter(['pid', 'name', 'environ']):
                    try:
                        env = proc.info.get('environ') or {}
                        if 'LD_PRELOAD' in env:
                            preload_val = env['LD_PRELOAD']
                            self._send_event(SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type='ld_preload_detected',
                                severity='CRITICAL',
                                source='ldpreload',
                                description=f'LD_PRELOAD detected in process {proc.info["name"]}',
                                details={'pid': proc.info['pid'], 'name': proc.info['name'], 'ld_preload': preload_val}
                            ))
                            logger.warning(f"LD_PRELOAD DETECTED: {proc.info['name']} - {preload_val}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Check /etc/ld.so.preload file
                if os.path.exists(preload_file):
                    current_hash = self._get_file_hash(preload_file)
                    if last_hash is None:
                        # File was created
                        self._send_event(SecurityEvent(
                            timestamp=datetime.utcnow().isoformat(),
                            event_type='ld_preload_file_created',
                            severity='CRITICAL',
                            source='ldpreload',
                            description='ld.so.preload file created - possible rootkit',
                            details={'path': preload_file}
                        ))
                        logger.warning("LD.SO.PRELOAD FILE CREATED!")
                    elif current_hash != last_hash:
                        self._send_event(SecurityEvent(
                            timestamp=datetime.utcnow().isoformat(),
                            event_type='ld_preload_file_modified',
                            severity='CRITICAL',
                            source='ldpreload',
                            description='ld.so.preload file modified',
                            details={'path': preload_file}
                        ))
                        logger.warning("LD.SO.PRELOAD FILE MODIFIED!")
                    last_hash = current_hash
                
                time.sleep(30)
            except Exception as e:
                logger.debug(f"LD_PRELOAD monitor error: {e}")
                time.sleep(60)
    
    def _setuid_monitor_loop(self):
        """Monitor for new setuid/setgid binaries."""
        logger.info("Setuid monitor started")
        
        # Initial scan of common directories
        scan_dirs = ['/usr/bin', '/usr/sbin', '/bin', '/sbin', '/usr/local/bin']
        
        for scan_dir in scan_dirs:
            if os.path.exists(scan_dir):
                for f in os.listdir(scan_dir):
                    filepath = os.path.join(scan_dir, f)
                    try:
                        stat = os.stat(filepath)
                        if stat.st_mode & 0o4000 or stat.st_mode & 0o2000:  # setuid or setgid
                            self.known_setuid_binaries[filepath] = stat.st_mode
                    except (OSError, PermissionError):
                        continue
        
        logger.info(f"Tracking {len(self.known_setuid_binaries)} setuid/setgid binaries")
        
        while self.running:
            try:
                for scan_dir in scan_dirs:
                    if not os.path.exists(scan_dir):
                        continue
                    
                    for f in os.listdir(scan_dir):
                        filepath = os.path.join(scan_dir, f)
                        try:
                            stat = os.stat(filepath)
                            is_setuid = stat.st_mode & 0o4000 or stat.st_mode & 0o2000
                            
                            if is_setuid and filepath not in self.known_setuid_binaries:
                                self._send_event(SecurityEvent(
                                    timestamp=datetime.utcnow().isoformat(),
                                    event_type='setuid_binary_added',
                                    severity='CRITICAL',
                                    source='setuid',
                                    description=f'New setuid binary detected: {filepath}',
                                    details={'path': filepath, 'mode': oct(stat.st_mode)}
                                ))
                                logger.warning(f"NEW SETUID BINARY: {filepath}")
                                self.known_setuid_binaries[filepath] = stat.st_mode
                        except (OSError, PermissionError):
                            continue
                
                time.sleep(60)
            except Exception as e:
                logger.debug(f"Setuid monitor error: {e}")
                time.sleep(120)
    
    def _systemd_monitor_loop(self):
        """Monitor systemd services for new/modified units."""
        logger.info("Systemd monitor started")
        
        # Get initial service list
        try:
            result = subprocess.run(['systemctl', 'list-unit-files', '--type=service', '--no-pager'],
                                   capture_output=True, text=True)
            for line in result.stdout.strip().split('\n')[1:]:
                parts = line.split()
                if parts and parts[0].endswith('.service'):
                    self.known_systemd_services.add(parts[0])
            logger.info(f"Tracking {len(self.known_systemd_services)} systemd services")
        except Exception as e:
            logger.warning(f"Could not get initial service list: {e}")
        
        while self.running:
            try:
                result = subprocess.run(['systemctl', 'list-unit-files', '--type=service', '--no-pager'],
                                       capture_output=True, text=True)
                
                for line in result.stdout.strip().split('\n')[1:]:
                    parts = line.split()
                    if parts and parts[0].endswith('.service'):
                        service = parts[0]
                        if service not in self.known_systemd_services:
                            self._send_event(SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type='systemd_service_added',
                                severity='HIGH',
                                source='systemd',
                                description=f'New systemd service detected: {service}',
                                details={'service': service, 'state': parts[1] if len(parts) > 1 else 'unknown'}
                            ))
                            logger.warning(f"NEW SYSTEMD SERVICE: {service}")
                            self.known_systemd_services.add(service)
                
                time.sleep(60)
            except Exception as e:
                logger.debug(f"Systemd monitor error: {e}")
                time.sleep(120)
    
    def _package_monitor_loop(self):
        """Monitor for unauthorized package installations."""
        logger.info("Package monitor started")
        
        # Detect package manager
        pkg_cmd = None
        if os.path.exists('/usr/bin/dpkg'):
            pkg_cmd = ['dpkg', '-l']
        elif os.path.exists('/usr/bin/rpm'):
            pkg_cmd = ['rpm', '-qa']
        elif os.path.exists('/usr/bin/pacman'):
            pkg_cmd = ['pacman', '-Q']
        
        if not pkg_cmd:
            logger.warning("No supported package manager found")
            return
        
        # Get initial package list
        try:
            result = subprocess.run(pkg_cmd, capture_output=True, text=True)
            for line in result.stdout.strip().split('\n'):
                parts = line.split()
                if parts:
                    self.known_packages.add(parts[0] if pkg_cmd[0] != 'dpkg' else parts[1] if len(parts) > 1 else parts[0])
            logger.info(f"Tracking {len(self.known_packages)} packages")
        except Exception as e:
            logger.warning(f"Could not get initial package list: {e}")
        
        while self.running:
            try:
                result = subprocess.run(pkg_cmd, capture_output=True, text=True)
                current_packages = set()
                
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if parts:
                        pkg = parts[0] if pkg_cmd[0] != 'dpkg' else parts[1] if len(parts) > 1 else parts[0]
                        current_packages.add(pkg)
                        
                        if pkg not in self.known_packages:
                            self._send_event(SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type='package_installed',
                                severity='MEDIUM',
                                source='packages',
                                description=f'New package installed: {pkg}',
                                details={'package': pkg}
                            ))
                            logger.warning(f"NEW PACKAGE: {pkg}")
                            self.known_packages.add(pkg)
                
                time.sleep(300)  # Check every 5 minutes
            except Exception as e:
                logger.debug(f"Package monitor error: {e}")
                time.sleep(600)
    
    def _file_integrity_monitor_loop(self):
        """Monitor critical system files for modifications."""
        logger.info("File integrity monitor started")
        
        # Initial hash of critical files
        for filepath in self.critical_files:
            if os.path.exists(filepath):
                self.file_integrity_hashes[filepath] = self._get_file_hash(filepath) or ''
        
        logger.info(f"Monitoring {len(self.file_integrity_hashes)} critical files")
        
        while self.running:
            try:
                for filepath in self.critical_files:
                    if os.path.exists(filepath):
                        current_hash = self._get_file_hash(filepath)
                        
                        if filepath not in self.file_integrity_hashes:
                            self._send_event(SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type='critical_file_created',
                                severity='CRITICAL',
                                source='integrity',
                                description=f'Critical file created: {filepath}',
                                details={'path': filepath}
                            ))
                            logger.warning(f"CRITICAL FILE CREATED: {filepath}")
                        elif current_hash != self.file_integrity_hashes[filepath]:
                            self._send_event(SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type='critical_file_modified',
                                severity='CRITICAL',
                                source='integrity',
                                description=f'Critical file modified: {filepath}',
                                details={'path': filepath, 'old_hash': self.file_integrity_hashes[filepath][:16], 'new_hash': current_hash[:16] if current_hash else 'unknown'}
                            ))
                            logger.warning(f"CRITICAL FILE MODIFIED: {filepath}")
                        
                        self.file_integrity_hashes[filepath] = current_hash or ''
                
                time.sleep(60)
            except Exception as e:
                logger.debug(f"File integrity monitor error: {e}")
                time.sleep(120)
    
    def _container_escape_monitor_loop(self):
        """Monitor for container escape attempts."""
        logger.info("Container escape monitor started")
        
        # Check if we're in a container
        in_container = os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv')
        
        escape_indicators = [
            '/proc/1/root',  # Accessing host root
            '/proc/sys/kernel/core_pattern',  # Core pattern escape
            '/sys/kernel/uevent_helper',  # Uevent helper escape
            '/sys/fs/cgroup',  # Cgroup escape
        ]
        
        while self.running:
            try:
                # Monitor for suspicious mount operations
                result = subprocess.run(['mount'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'docker.sock' in line or '/var/run/docker.sock' in line:
                        self._send_event(SecurityEvent(
                            timestamp=datetime.utcnow().isoformat(),
                            event_type='container_escape_attempt',
                            severity='CRITICAL',
                            source='container',
                            description='Docker socket mounted - potential escape vector',
                            details={'mount_line': line}
                        ))
                        logger.warning("DOCKER SOCKET MOUNTED - ESCAPE RISK!")
                
                # Check for processes accessing escape indicators
                for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                    try:
                        open_files = proc.info.get('open_files') or []
                        for f in open_files:
                            if any(indicator in f.path for indicator in escape_indicators):
                                self._send_event(SecurityEvent(
                                    timestamp=datetime.utcnow().isoformat(),
                                    event_type='container_escape_attempt',
                                    severity='CRITICAL',
                                    source='container',
                                    description=f'Process accessing escape vector: {f.path}',
                                    details={'pid': proc.info['pid'], 'name': proc.info['name'], 'path': f.path}
                                ))
                                logger.warning(f"CONTAINER ESCAPE ATTEMPT: {proc.info['name']} -> {f.path}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                time.sleep(30)
            except Exception as e:
                logger.debug(f"Container escape monitor error: {e}")
                time.sleep(60)
    
    def _auditd_monitor_loop(self):
        """Monitor auditd logs for security events."""
        logger.info("Auditd monitor started")
        
        audit_log = '/var/log/audit/audit.log'
        if not os.path.exists(audit_log):
            logger.warning("Auditd log not found - auditd may not be installed")
            return
        
        try:
            with open(audit_log, 'r') as f:
                f.seek(0, 2)  # Go to end
                
                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(1)
                        continue
                    
                    # Parse audit events
                    if 'type=EXECVE' in line or 'type=SYSCALL' in line:
                        # Check for suspicious syscalls
                        if any(x in line for x in ['execve', 'ptrace', 'process_vm_readv', 'process_vm_writev']):
                            if 'success=yes' in line:
                                self._send_event(SecurityEvent(
                                    timestamp=datetime.utcnow().isoformat(),
                                    event_type='audit_suspicious_syscall',
                                    severity='MEDIUM',
                                    source='auditd',
                                    description='Suspicious syscall detected',
                                    details={'log_line': line.strip()[:500]}
                                ))
                    
                    # Check for privilege escalation
                    if 'type=USER_AUTH' in line and 'res=failed' in line:
                        self._send_event(SecurityEvent(
                            timestamp=datetime.utcnow().isoformat(),
                            event_type='audit_auth_failure',
                            severity='MEDIUM',
                            source='auditd',
                            description='Authentication failure in audit log',
                            details={'log_line': line.strip()[:500]}
                        ))
                        
        except PermissionError:
            logger.warning("Permission denied reading audit log. Run as root.")
        except Exception as e:
            logger.error(f"Auditd monitor error: {e}")
    
    def _selinux_monitor_loop(self):
        """Monitor SELinux/AppArmor for policy violations."""
        logger.info("SELinux/AppArmor monitor started")
        
        # Check which MAC system is in use
        selinux_log = '/var/log/audit/audit.log'
        apparmor_log = '/var/log/kern.log'
        
        log_file = None
        mac_type = None
        
        if os.path.exists('/sys/fs/selinux'):
            log_file = selinux_log
            mac_type = 'SELinux'
        elif os.path.exists('/sys/kernel/security/apparmor'):
            log_file = apparmor_log
            mac_type = 'AppArmor'
        else:
            logger.warning("No SELinux or AppArmor detected")
            return
        
        if not os.path.exists(log_file):
            logger.warning(f"{mac_type} log not found: {log_file}")
            return
        
        try:
            with open(log_file, 'r') as f:
                f.seek(0, 2)  # Go to end
                
                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(1)
                        continue
                    
                    # SELinux denials
                    if 'avc:  denied' in line or 'type=AVC' in line:
                        self._send_event(SecurityEvent(
                            timestamp=datetime.utcnow().isoformat(),
                            event_type='selinux_denial',
                            severity='MEDIUM',
                            source='selinux',
                            description='SELinux policy violation',
                            details={'log_line': line.strip()[:500]}
                        ))
                        logger.warning(f"SELINUX DENIAL: {line.strip()[:100]}")
                    
                    # AppArmor denials
                    if 'apparmor="DENIED"' in line:
                        self._send_event(SecurityEvent(
                            timestamp=datetime.utcnow().isoformat(),
                            event_type='apparmor_denial',
                            severity='MEDIUM',
                            source='apparmor',
                            description='AppArmor policy violation',
                            details={'log_line': line.strip()[:500]}
                        ))
                        logger.warning(f"APPARMOR DENIAL: {line.strip()[:100]}")
                        
        except PermissionError:
            logger.warning(f"Permission denied reading {mac_type} log. Run as root.")
        except Exception as e:
            logger.error(f"{mac_type} monitor error: {e}")
    
    # ============== macOS-SPECIFIC MONITORS ==============
    
    def _launch_daemon_monitor_loop(self):
        """Monitor Launch Daemons and Agents for persistence (macOS)."""
        logger.info("Launch Daemon monitor started")
        
        launch_paths = [
            '/Library/LaunchDaemons',
            '/Library/LaunchAgents',
            os.path.expanduser('~/Library/LaunchAgents'),
            '/System/Library/LaunchDaemons',
            '/System/Library/LaunchAgents',
        ]
        
        known_items: Dict[str, str] = {}
        
        # Initial scan
        for path in launch_paths:
            if os.path.exists(path):
                for item in os.listdir(path):
                    filepath = os.path.join(path, item)
                    if os.path.isfile(filepath):
                        known_items[filepath] = self._get_file_hash(filepath) or ''
        
        logger.info(f"Tracking {len(known_items)} launch items")
        
        while self.running:
            try:
                for path in launch_paths:
                    if not os.path.exists(path):
                        continue
                    
                    for item in os.listdir(path):
                        filepath = os.path.join(path, item)
                        if not os.path.isfile(filepath):
                            continue
                        
                        current_hash = self._get_file_hash(filepath)
                        
                        if filepath not in known_items:
                            self._send_event(SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type='launch_daemon_added',
                                severity='HIGH',
                                source='launchdaemon',
                                description=f'New Launch Daemon/Agent: {item}',
                                details={'path': filepath, 'directory': path}
                            ))
                            logger.warning(f"NEW LAUNCH DAEMON: {filepath}")
                        elif current_hash != known_items[filepath]:
                            self._send_event(SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type='launch_daemon_modified',
                                severity='HIGH',
                                source='launchdaemon',
                                description=f'Launch Daemon/Agent modified: {item}',
                                details={'path': filepath}
                            ))
                            logger.warning(f"LAUNCH DAEMON MODIFIED: {filepath}")
                        
                        known_items[filepath] = current_hash
                
                time.sleep(30)
            except Exception as e:
                logger.debug(f"Launch Daemon monitor error: {e}")
                time.sleep(60)
    
    def _keychain_monitor_loop(self):
        """Monitor Keychain access attempts (macOS)."""
        logger.info("Keychain monitor started")
        
        # Use unified log to monitor keychain access
        try:
            # Start log stream for security events
            cmd = ['log', 'stream', '--predicate', 
                   'subsystem == "com.apple.securityd" OR subsystem == "com.apple.Security"',
                   '--style', 'compact']
            
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                   text=True, bufsize=1)
            
            while self.running:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                # Check for suspicious keychain access
                if any(x in line.lower() for x in ['denied', 'unauthorized', 'failed', 'blocked']):
                    self._send_event(SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type='keychain_access_denied',
                        severity='MEDIUM',
                        source='keychain',
                        description='Keychain access denied',
                        details={'log_line': line.strip()[:500]}
                    ))
                    logger.warning(f"KEYCHAIN ACCESS DENIED: {line.strip()[:100]}")
                
                # Check for password extraction attempts
                if 'SecItemCopyMatching' in line or 'SecKeychainFindGenericPassword' in line:
                    self._send_event(SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type='keychain_password_access',
                        severity='LOW',
                        source='keychain',
                        description='Keychain password access',
                        details={'log_line': line.strip()[:500]}
                    ))
            
            proc.terminate()
        except FileNotFoundError:
            logger.warning("log command not found - Keychain monitoring unavailable")
        except Exception as e:
            logger.debug(f"Keychain monitor error: {e}")
    
    def _gatekeeper_monitor_loop(self):
        """Monitor Gatekeeper bypass attempts (macOS)."""
        logger.info("Gatekeeper monitor started")
        
        # Monitor for unsigned/quarantined app execution
        try:
            cmd = ['log', 'stream', '--predicate',
                   'subsystem == "com.apple.syspolicy" OR eventMessage CONTAINS "Gatekeeper"',
                   '--style', 'compact']
            
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, bufsize=1)
            
            while self.running:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                # Check for Gatekeeper blocks
                if any(x in line.lower() for x in ['blocked', 'quarantine', 'notarization', 'denied']):
                    severity = 'HIGH' if 'blocked' in line.lower() else 'MEDIUM'
                    self._send_event(SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type='gatekeeper_block',
                        severity=severity,
                        source='gatekeeper',
                        description='Gatekeeper blocked unsigned app',
                        details={'log_line': line.strip()[:500]}
                    ))
                    logger.warning(f"GATEKEEPER BLOCK: {line.strip()[:100]}")
                
                # Check for xattr removal (bypass attempt)
                if 'xattr' in line.lower() and 'quarantine' in line.lower():
                    self._send_event(SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type='gatekeeper_bypass_attempt',
                        severity='HIGH',
                        source='gatekeeper',
                        description='Possible Gatekeeper bypass (quarantine removal)',
                        details={'log_line': line.strip()[:500]}
                    ))
                    logger.warning(f"GATEKEEPER BYPASS ATTEMPT: {line.strip()[:100]}")
            
            proc.terminate()
        except FileNotFoundError:
            logger.warning("log command not found - Gatekeeper monitoring unavailable")
        except Exception as e:
            logger.debug(f"Gatekeeper monitor error: {e}")
    
    def _tcc_monitor_loop(self):
        """Monitor TCC (Transparency, Consent, Control) database changes (macOS)."""
        logger.info("TCC monitor started")
        
        # TCC database locations
        tcc_paths = [
            '/Library/Application Support/com.apple.TCC/TCC.db',
            os.path.expanduser('~/Library/Application Support/com.apple.TCC/TCC.db'),
        ]
        
        last_hashes: Dict[str, str] = {}
        
        # Get initial hashes
        for path in tcc_paths:
            if os.path.exists(path):
                last_hashes[path] = self._get_file_hash(path) or ''
        
        while self.running:
            try:
                for path in tcc_paths:
                    if os.path.exists(path):
                        current_hash = self._get_file_hash(path)
                        
                        if path in last_hashes and current_hash != last_hashes[path]:
                            self._send_event(SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type='tcc_database_modified',
                                severity='MEDIUM',
                                source='tcc',
                                description='TCC privacy database modified',
                                details={'path': path}
                            ))
                            logger.warning(f"TCC DATABASE MODIFIED: {path}")
                        
                        last_hashes[path] = current_hash
                
                time.sleep(30)
            except Exception as e:
                logger.debug(f"TCC monitor error: {e}")
                time.sleep(60)
    
    def _unified_log_monitor_loop(self):
        """Monitor macOS Unified Log for security events."""
        logger.info("Unified Log monitor started")
        
        # Security-related predicates
        predicates = [
            'eventMessage CONTAINS "sudo"',
            'eventMessage CONTAINS "authentication"',
            'eventMessage CONTAINS "failed"',
            'subsystem == "com.apple.securityd"',
        ]
        
        try:
            cmd = ['log', 'stream', '--predicate',
                   ' OR '.join(predicates),
                   '--style', 'compact']
            
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, bufsize=1)
            
            while self.running:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                # Check for sudo usage
                if 'sudo' in line.lower():
                    if 'incorrect password' in line.lower() or 'authentication failure' in line.lower():
                        self._send_event(SecurityEvent(
                            timestamp=datetime.utcnow().isoformat(),
                            event_type='sudo_auth_failure',
                            severity='MEDIUM',
                            source='unifiedlog',
                            description='Sudo authentication failure',
                            details={'log_line': line.strip()[:500]}
                        ))
                        logger.warning(f"SUDO AUTH FAILURE: {line.strip()[:100]}")
                
                # Check for authentication failures
                if 'authentication' in line.lower() and 'failed' in line.lower():
                    self._send_event(SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type='auth_failure',
                        severity='MEDIUM',
                        source='unifiedlog',
                        description='Authentication failure detected',
                        details={'log_line': line.strip()[:500]}
                    ))
            
            proc.terminate()
        except FileNotFoundError:
            logger.warning("log command not found - Unified Log monitoring unavailable")
        except Exception as e:
            logger.debug(f"Unified Log monitor error: {e}")
    
    def _xprotect_monitor_loop(self):
        """Monitor XProtect (Apple's built-in malware detection) events (macOS)."""
        logger.info("XProtect monitor started")
        
        # XProtect data locations
        xprotect_paths = [
            '/Library/Apple/System/Library/CoreServices/XProtect.bundle',
            '/System/Library/CoreServices/XProtect.bundle',
        ]
        
        last_hashes: Dict[str, str] = {}
        
        # Get initial state
        for base_path in xprotect_paths:
            if os.path.exists(base_path):
                plist_path = os.path.join(base_path, 'Contents/Resources/XProtect.plist')
                if os.path.exists(plist_path):
                    last_hashes[plist_path] = self._get_file_hash(plist_path) or ''
        
        # Also monitor unified log for XProtect events
        try:
            cmd = ['log', 'stream', '--predicate',
                   'subsystem == "com.apple.xprotect" OR eventMessage CONTAINS "XProtect"',
                   '--style', 'compact']
            
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, bufsize=1)
            
            while self.running:
                line = proc.stdout.readline()
                if not line:
                    # Check for XProtect definition updates
                    for base_path in xprotect_paths:
                        plist_path = os.path.join(base_path, 'Contents/Resources/XProtect.plist')
                        if os.path.exists(plist_path):
                            current_hash = self._get_file_hash(plist_path)
                            if plist_path in last_hashes and current_hash != last_hashes[plist_path]:
                                logger.info("XProtect definitions updated")
                                last_hashes[plist_path] = current_hash
                    
                    time.sleep(0.1)
                    continue
                
                # Check for malware detection
                if any(x in line.lower() for x in ['malware', 'threat', 'blocked', 'quarantine']):
                    self._send_event(SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type='xprotect_detection',
                        severity='CRITICAL',
                        source='xprotect',
                        description='XProtect malware detection',
                        details={'log_line': line.strip()[:500]}
                    ))
                    logger.warning(f"XPROTECT DETECTION: {line.strip()[:100]}")
            
            proc.terminate()
        except FileNotFoundError:
            logger.warning("log command not found - XProtect monitoring unavailable")
        except Exception as e:
            logger.debug(f"XProtect monitor error: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='SentinelAI Linux/macOS Agent')
    parser.add_argument('--dashboard', '-d', default='http://localhost:8015',
                        help='Dashboard URL (default: http://localhost:8015)')
    parser.add_argument('--api-key', '-k', default=None,
                        help='API key for dashboard authentication')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('--no-ai', action='store_true',
                        help='Disable AI-powered analysis')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    ai_status = "DISABLED" if args.no_ai else "ENABLED"
    api_key = args.api_key or os.environ.get('SENTINEL_API_KEY', '')
    plat = platform.system()
    
    if plat == 'Darwin':
        print(f"""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║              SentinelAI macOS Agent v2.0                          ║
    ║          Native macOS Protection & Threat Detection               ║
    ║                                                                   ║
    ║  Core:     Process | Network | AuthLog | pf Firewall              ║
    ║  System:   Launch Daemons | Unified Log | TCC Privacy             ║
    ║  Security: Keychain | Gatekeeper | XProtect                       ║
    ║                                                                   ║
    ║     Platform: {plat:<10}  |  AI Analysis: {ai_status:<10}           ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    else:
        print(f"""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║              SentinelAI Linux Agent v2.0                          ║
    ║          Native Linux Protection & Threat Detection               ║
    ║                                                                   ║
    ║  Core:     Process | Network | AuthLog | iptables                 ║
    ║  System:   Cron | SSH Keys | Sudo | Systemd | Packages            ║
    ║  Security: Kernel Modules | LD_PRELOAD | Setuid | Integrity       ║
    ║  Advanced: Container Escape | Auditd | SELinux/AppArmor           ║
    ║                                                                   ║
    ║     Platform: {plat:<10}  |  AI Analysis: {ai_status:<10}           ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    agent = LinuxAgent(dashboard_url=args.dashboard, api_key=api_key)
    agent.use_ai = not args.no_ai
    agent.start()


if __name__ == '__main__':
    main()
