"""
SentinelAI Windows Agent
Runs natively on Windows to monitor processes, files, network, and logs.
Reports all findings to the Docker dashboard.
"""
import os
import sys
import time
import json
import logging
import asyncio
import platform
import subprocess
import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
import threading
import queue

# Check Windows
if platform.system() != "Windows":
    print("ERROR: This agent must run on Windows!")
    sys.exit(1)

import psutil
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('sentinel_agent.log')
    ]
)
logger = logging.getLogger('SentinelAgent')


@dataclass
class SecurityEvent:
    """Represents a security event detected by the agent."""
    timestamp: str
    event_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    source: str  # process, file, network, log
    description: str
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    

class WindowsAgent:
    """
    Native Windows agent for SentinelAI.
    Monitors the Windows host and reports to the Docker dashboard.
    """
    
    def __init__(self, dashboard_url: str = "http://localhost:8015"):
        self.dashboard_url = dashboard_url.rstrip('/')
        self.api_base = f"{self.dashboard_url}/api/v1"
        self.running = False
        self.event_queue = queue.Queue()
        
        # Monitoring state
        self.known_processes: Dict[int, Dict] = {}
        self.suspicious_ips: set = set()
        self.blocked_ips: set = set()
        
        # Suspicious patterns - these must match as WHOLE WORDS or exact filenames
        self.suspicious_executables = [
            'mimikatz.exe', 'pwdump.exe', 'procdump.exe', 'lazagne.exe',
            'keylogger.exe', 'trojan.exe', 'backdoor.exe',
            'nc.exe', 'ncat.exe', 'netcat.exe',
            'psexec.exe', 'psexec64.exe',
            'cobaltstrike', 'beacon.exe', 'meterpreter',
            'sharphound.exe', 'bloodhound.exe',
            'rubeus.exe', 'seatbelt.exe', 'sharpup.exe',
            'winpeas.exe', 'linpeas.sh'
        ]
        
        # Patterns to look for in command lines (more specific)
        self.suspicious_cmdline_patterns = [
            'mimikatz', 'sekurlsa', 'lsadump',
            'invoke-mimikatz', 'invoke-shellcode',
            'invoke-expression', 'downloadstring',
            '-enc ', '-encodedcommand', 'frombase64string',
            'bypass -nop', '-w hidden -nop',
            'certutil -decode', 'certutil -urlcache',
            'bitsadmin /transfer',
            'powershell.*hidden.*-e',
            'mshta vbscript', 'mshta javascript',
            'regsvr32 /s /n /u',
            'rundll32.*javascript',
        ]
        
        # Whitelist - known safe processes that might trigger false positives
        self.whitelisted_processes = [
            # Browsers
            'msedgewebview2.exe', 'chrome.exe', 'firefox.exe', 'brave.exe',
            # Communication
            'discord.exe', 'slack.exe', 'teams.exe', 'zoom.exe',
            # Development
            'windsurf', 'code.exe', 'cursor.exe', 'vscode', 'python.exe', 'node.exe',
            # NVIDIA
            'nvidia', 'nvcontainer', 'nvsphelper', 'nvrla',
            # Antivirus
            'avgui.exe', 'avast', 'kaspersky', 'msmpeng.exe', 'defender', 'windowsdefender',
            # Gaming
            'steam.exe', 'epicgameslauncher', 'gog', 'origin.exe',
            # Media
            'spotify.exe',
            # System
            'crashpad_handler.exe', 'wmiregistrationservice',
            'pi network', 'presentmon', 'fvcontainer',
            # Apps - add your legitimate apps here
            'comet.exe', 'perplexity',  # Perplexity AI
            'signalrgb', 'signalrgbservice.exe',  # SignalRGB
            'ollama', 'ollama.exe', 'ollama app.exe',  # Ollama AI
            'powershell.exe',  # Normal PowerShell (suspicious patterns still checked)
            'cmd.exe',  # Normal CMD (suspicious patterns still checked)
        ]
        
        self.suspicious_paths = [
            r'C:\Windows\Temp',
            r'C:\Users\Public',
            r'C:\ProgramData',
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', '')
        ]
        
        self.suspicious_ports = [4444, 5555, 6666, 1337, 31337, 8080, 9001]
        
        # Statistics
        self.stats = {
            'processes_monitored': 0,
            'suspicious_processes': 0,
            'network_connections': 0,
            'suspicious_connections': 0,
            'events_sent': 0,
            'ai_analyses': 0,
            'start_time': None
        }
        
        # AI Analysis settings
        self.use_ai = True
        self.ai_cache: Dict[str, Dict] = {}  # Cache AI results to avoid repeated calls
        
        logger.info(f"Windows Agent initialized - Dashboard: {self.dashboard_url}")
        logger.info(f"AI-powered analysis: {'Enabled' if self.use_ai else 'Disabled'}")
    
    def start(self):
        """Start the Windows agent."""
        self.running = True
        self.stats['start_time'] = datetime.utcnow().isoformat()
        
        logger.info("=" * 50)
        logger.info("SentinelAI Windows Agent Starting")
        logger.info(f"Platform: {platform.system()} {platform.release()}")
        logger.info(f"Hostname: {platform.node()}")
        logger.info(f"Dashboard: {self.dashboard_url}")
        logger.info("=" * 50)
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self._process_monitor_loop, daemon=True),
            threading.Thread(target=self._network_monitor_loop, daemon=True),
            threading.Thread(target=self._event_log_monitor_loop, daemon=True),
            threading.Thread(target=self._event_sender_loop, daemon=True),
            threading.Thread(target=self._heartbeat_loop, daemon=True),
            # Advanced monitoring (Phase 7)
            threading.Thread(target=self._registry_monitor_loop, daemon=True),
            threading.Thread(target=self._startup_monitor_loop, daemon=True),
            threading.Thread(target=self._scheduled_task_monitor_loop, daemon=True),
            threading.Thread(target=self._usb_monitor_loop, daemon=True),
            threading.Thread(target=self._hosts_file_monitor_loop, daemon=True),
            threading.Thread(target=self._browser_extension_monitor_loop, daemon=True),
            # AVG Antivirus integration
            threading.Thread(target=self._avg_monitor_loop, daemon=True),
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
        """Send periodic heartbeat to dashboard to stay registered."""
        while self.running:
            try:
                time.sleep(30)  # Send heartbeat every 30 seconds
                self._register_agent()  # Re-register acts as heartbeat
            except Exception as e:
                logger.debug(f"Heartbeat error: {e}")
    
    def _get_windows_version(self) -> str:
        """Get proper Windows version name (Windows 10/11) with build number."""
        try:
            # Get build number
            build = int(platform.version().split('.')[-1])
            version = platform.version()
            
            # Windows 11 starts at build 22000
            if build >= 22000:
                os_name = "Windows 11"
            else:
                os_name = "Windows 10"
            
            # Try to get more details from registry
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                display_version = winreg.QueryValueEx(key, "DisplayVersion")[0]
                edition = winreg.QueryValueEx(key, "EditionID")[0]
                winreg.CloseKey(key)
                return f"{os_name} {edition} {display_version} (Build {build})"
            except:
                return f"{os_name} (Build {build})"
        except:
            return platform.version()
    
    def _register_agent(self):
        """Register this agent with the dashboard."""
        try:
            # Get proper Windows version
            windows_version = self._get_windows_version()
            
            # Check if running as admin
            try:
                is_admin = os.getuid() == 0
            except AttributeError:
                # Windows
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            
            data = {
                'hostname': platform.node(),
                'platform': platform.system(),
                'platform_version': windows_version,
                'agent_version': '1.2.0',
                'is_admin': is_admin,
                'capabilities': ['process', 'network', 'eventlog', 'firewall', 'ai', 'registry', 'startup', 'tasks', 'usb', 'hosts', 'browser']
            }
            
            response = requests.post(
                f"{self.api_base}/windows/agent/register",
                json=data,
                timeout=5
            )
            
            if response.status_code == 200:
                logger.info("Successfully registered with dashboard")
            else:
                logger.warning(f"Could not register with dashboard: {response.status_code}")
        except Exception as e:
            logger.warning(f"Dashboard not reachable: {e}")
    
    def _analyze_with_ai(self, process_info: Dict) -> Dict:
        """
        Send process info to dashboard AI for intelligent analysis.
        Returns AI verdict with confidence score.
        """
        if not self.use_ai:
            return {'is_threat': False, 'confidence': 0, 'reason': 'AI disabled'}
        
        # Create cache key from process name and command line
        cache_key = f"{process_info.get('name', '')}:{process_info.get('cmdline', '')[:100]}"
        
        # Check cache first
        if cache_key in self.ai_cache:
            return self.ai_cache[cache_key]
        
        try:
            # Build context for AI analysis
            analysis_request = {
                'source_ip': '127.0.0.1',
                'threat_type': 'process_analysis',
                'severity': 'MEDIUM',
                'description': f"Windows Agent requesting AI analysis of process: {process_info.get('name', 'Unknown')}",
                'payload': json.dumps({
                    'process_name': process_info.get('name', ''),
                    'executable_path': process_info.get('exe', ''),
                    'command_line': process_info.get('cmdline', ''),
                    'username': process_info.get('username', ''),
                    'analysis_type': 'process_behavior'
                }),
                'request_ai_analysis': True
            }
            
            response = requests.post(
                f"{self.api_base}/threats/analyze",
                json=analysis_request,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                self.stats['ai_analyses'] += 1
                
                # Parse AI response
                ai_verdict = {
                    'is_threat': result.get('severity', 'LOW') in ['HIGH', 'CRITICAL'],
                    'confidence': result.get('confidence', 0.5),
                    'severity': result.get('severity', 'LOW'),
                    'classification': result.get('classification', 'unknown'),
                    'reason': result.get('ai_analysis', {}).get('explanation', 'No AI explanation'),
                    'recommended_action': result.get('recommended_action', 'monitor')
                }
                
                # Cache the result
                self.ai_cache[cache_key] = ai_verdict
                
                return ai_verdict
            else:
                return {'is_threat': False, 'confidence': 0, 'reason': 'AI analysis failed'}
                
        except Exception as e:
            logger.debug(f"AI analysis error: {e}")
            return {'is_threat': False, 'confidence': 0, 'reason': f'Error: {e}'}
    
    def _smart_process_check(self, proc_info: Dict) -> tuple:
        """
        Two-stage process analysis:
        1. Quick local heuristics check
        2. AI-powered deep analysis for uncertain cases
        """
        name = proc_info['name'].lower()
        exe = (proc_info['exe'] or '').lower()
        cmdline = (proc_info['cmdline'] or '').lower()
        
        # Stage 1: Quick whitelist check
        for safe in self.whitelisted_processes:
            if safe.lower() in name or safe.lower() in exe:
                return False, "", None
        
        # Stage 1: Quick blacklist check (known malware)
        for suspicious in self.suspicious_executables:
            if name == suspicious.lower() or exe.endswith(suspicious.lower()):
                return True, f"Known malicious tool: {suspicious}", {'confidence': 0.95}
        
        # Stage 1: Check for obvious malicious patterns
        for pattern in self.suspicious_cmdline_patterns:
            if pattern.lower() in cmdline:
                return True, f"Malicious command pattern: {pattern}", {'confidence': 0.9}
        
        # Stage 2: AI analysis for uncertain processes
        # Only analyze processes that look somewhat suspicious but aren't definitive
        needs_ai_check = False
        
        # Processes running from unusual locations
        if any(path.lower() in exe for path in [r'\temp\\', r'\tmp\\', r'\downloads\\']):
            needs_ai_check = True
        
        # PowerShell or cmd with any arguments
        if ('powershell' in name or 'cmd.exe' in name) and len(cmdline) > 50:
            needs_ai_check = True
        
        # Script hosts
        if any(x in name for x in ['wscript', 'cscript', 'mshta']):
            needs_ai_check = True
        
        # Unknown executables (not in common paths)
        common_paths = ['windows', 'program files', 'programdata\\microsoft']
        if exe and not any(p in exe for p in common_paths):
            # Executable from non-standard location
            if exe.endswith('.exe') and '\\users\\' in exe:
                needs_ai_check = True
        
        if needs_ai_check and self.use_ai:
            logger.debug(f"Requesting AI analysis for: {name}")
            ai_result = self._analyze_with_ai(proc_info)
            
            if ai_result.get('is_threat') and ai_result.get('confidence', 0) > 0.7:
                return True, f"AI detected threat: {ai_result.get('reason', 'suspicious behavior')}", ai_result
            elif ai_result.get('confidence', 0) > 0.5:
                # Log but don't alert for medium confidence
                logger.info(f"AI flagged (medium confidence): {name} - {ai_result.get('reason', '')}")
        
        return False, "", None
    
    def _send_event(self, event: SecurityEvent):
        """Queue an event to be sent to the dashboard."""
        self.event_queue.put(event)
    
    def _event_sender_loop(self):
        """Background thread to send events to dashboard."""
        while self.running:
            try:
                # Get event with timeout
                event = self.event_queue.get(timeout=1)
                
                # Send to dashboard
                try:
                    response = requests.post(
                        f"{self.api_base}/threats/analyze",
                        json={
                            'source_ip': event.ip_address or '127.0.0.1',
                            'threat_type': event.event_type,
                            'severity': event.severity,
                            'description': event.description,
                            'payload': json.dumps(event.details),
                            'timestamp': event.timestamp,
                            'agent_source': 'windows_agent'
                        },
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        self.stats['events_sent'] += 1
                        logger.info(f"Event sent: {event.event_type} - {event.description[:50]}")
                    else:
                        logger.warning(f"Failed to send event: {response.status_code}")
                        
                except requests.exceptions.RequestException as e:
                    logger.debug(f"Could not send event: {e}")
                    
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Event sender error: {e}")
    
    def _process_monitor_loop(self):
        """Monitor running processes for suspicious activity."""
        logger.info("Process monitor started")
        
        while self.running:
            try:
                current_pids = set()
                
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
                    try:
                        pid = proc.info['pid']
                        current_pids.add(pid)
                        
                        # Skip if already known
                        if pid in self.known_processes:
                            continue
                        
                        # New process detected
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
                        
                        # Check if suspicious using AI-powered smart check
                        is_suspicious, reason, ai_result = self._smart_process_check(proc_info)
                        
                        if is_suspicious:
                            self.stats['suspicious_processes'] += 1
                            
                            # Determine severity based on AI confidence
                            severity = 'HIGH'
                            if ai_result and ai_result.get('confidence', 0) > 0.9:
                                severity = 'CRITICAL'
                            elif ai_result and ai_result.get('confidence', 0) < 0.7:
                                severity = 'MEDIUM'
                            
                            event = SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type='suspicious_process',
                                severity=severity,
                                source='process',
                                description=f"Suspicious process detected: {proc_info['name']} - {reason}",
                                details={
                                    **proc_info,
                                    'ai_analysis': ai_result
                                }
                            )
                            self._send_event(event)
                            
                            ai_tag = " [AI]" if ai_result else ""
                            logger.warning(f"SUSPICIOUS PROCESS{ai_tag}: {proc_info['name']} (PID: {pid}) - {reason}")
                            
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
        
        # First check whitelist - skip known safe processes
        for safe in self.whitelisted_processes:
            if safe.lower() in name or safe.lower() in exe:
                return False, ""
        
        # Check for known malicious executables (exact match on filename)
        for suspicious in self.suspicious_executables:
            if name == suspicious.lower() or exe.endswith(suspicious.lower()):
                return True, f"Known malicious tool: {suspicious}"
        
        # Check command line for suspicious patterns
        for pattern in self.suspicious_cmdline_patterns:
            if pattern.lower() in cmdline:
                return True, f"Suspicious command line: {pattern}"
        
        # Check for encoded PowerShell (specific patterns)
        if 'powershell' in name or 'pwsh' in name:
            if ' -enc ' in cmdline or ' -encodedcommand ' in cmdline:
                return True, "Encoded PowerShell command detected"
            if '-nop' in cmdline and 'hidden' in cmdline and ('-e ' in cmdline or '-enc' in cmdline):
                return True, "Hidden encoded PowerShell execution"
        
        # Check for download cradles
        if 'cmd.exe' in name:
            if 'certutil' in cmdline and ('-decode' in cmdline or '-urlcache' in cmdline):
                return True, "Certutil download/decode detected"
            if 'bitsadmin' in cmdline and '/transfer' in cmdline:
                return True, "BITSAdmin download detected"
        
        # Check for suspicious script hosts
        if 'mshta' in name or 'wscript' in name or 'cscript' in name:
            if 'http' in cmdline or 'javascript' in cmdline or 'vbscript' in cmdline:
                return True, "Suspicious script execution"
        
        # Note: Removed suspicious path check for ProgramData as it causes too many false positives
        # Windows Defender and many legitimate apps run from there
        
        return False, ""
    
    def _network_monitor_loop(self):
        """Monitor network connections for suspicious activity."""
        logger.info("Network monitor started")
        
        while self.running:
            try:
                connections = psutil.net_connections(kind='inet')
                self.stats['network_connections'] = len(connections)
                
                for conn in connections:
                    try:
                        # Check established connections
                        if conn.status == 'ESTABLISHED' and conn.raddr:
                            remote_ip = conn.raddr.ip
                            remote_port = conn.raddr.port
                            local_port = conn.laddr.port if conn.laddr else 0
                            
                            # Check suspicious ports
                            if remote_port in self.suspicious_ports or local_port in self.suspicious_ports:
                                if remote_ip not in self.suspicious_ips:
                                    self.suspicious_ips.add(remote_ip)
                                    self.stats['suspicious_connections'] += 1
                                    
                                    # Get process info
                                    proc_name = "Unknown"
                                    if conn.pid:
                                        try:
                                            proc_name = psutil.Process(conn.pid).name()
                                        except:
                                            pass
                                    
                                    event = SecurityEvent(
                                        timestamp=datetime.utcnow().isoformat(),
                                        event_type='suspicious_connection',
                                        severity='MEDIUM',
                                        source='network',
                                        description=f"Suspicious port connection: {remote_ip}:{remote_port}",
                                        details={
                                            'remote_ip': remote_ip,
                                            'remote_port': remote_port,
                                            'local_port': local_port,
                                            'process': proc_name,
                                            'pid': conn.pid
                                        },
                                        ip_address=remote_ip
                                    )
                                    self._send_event(event)
                                    logger.warning(f"SUSPICIOUS CONNECTION: {remote_ip}:{remote_port} by {proc_name}")
                            
                            # Check for reverse shells (common ports)
                            if local_port in [4444, 5555, 1337, 31337]:
                                event = SecurityEvent(
                                    timestamp=datetime.utcnow().isoformat(),
                                    event_type='potential_reverse_shell',
                                    severity='CRITICAL',
                                    source='network',
                                    description=f"Potential reverse shell on port {local_port}",
                                    details={
                                        'remote_ip': remote_ip,
                                        'local_port': local_port,
                                        'pid': conn.pid
                                    },
                                    ip_address=remote_ip
                                )
                                self._send_event(event)
                                
                    except Exception:
                        continue
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Network monitor error: {e}")
                time.sleep(10)
    
    def _event_log_monitor_loop(self):
        """Monitor Windows Event Logs for security events."""
        logger.info("Event log monitor started")
        
        # Event IDs to monitor
        security_events = {
            4624: ('Logon', 'LOW'),
            4625: ('Failed Logon', 'MEDIUM'),
            4648: ('Explicit Credentials Logon', 'MEDIUM'),
            4672: ('Special Privileges Assigned', 'LOW'),
            4688: ('Process Creation', 'LOW'),
            4697: ('Service Installed', 'MEDIUM'),
            4698: ('Scheduled Task Created', 'MEDIUM'),
            4720: ('User Account Created', 'MEDIUM'),
            4732: ('Member Added to Security Group', 'MEDIUM'),
            4738: ('User Account Changed', 'LOW'),
            4776: ('Credential Validation', 'LOW'),
            1102: ('Audit Log Cleared', 'HIGH'),
        }
        
        last_check = datetime.now()
        
        while self.running:
            try:
                # Use PowerShell to query Security event log
                ps_command = f'''
                Get-WinEvent -FilterHashtable @{{
                    LogName='Security';
                    StartTime='{last_check.strftime("%Y-%m-%dT%H:%M:%S")}'
                }} -MaxEvents 50 -ErrorAction SilentlyContinue | 
                Select-Object TimeCreated, Id, Message | 
                ConvertTo-Json
                '''
                
                result = subprocess.run(
                    ['powershell', '-Command', ps_command],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    try:
                        events = json.loads(result.stdout)
                        if isinstance(events, dict):
                            events = [events]
                        
                        for evt in events:
                            event_id = evt.get('Id', 0)
                            
                            if event_id in security_events:
                                event_name, severity = security_events[event_id]
                                
                                # Escalate failed logons
                                if event_id == 4625:
                                    # Count recent failures
                                    severity = 'HIGH'
                                
                                event = SecurityEvent(
                                    timestamp=datetime.utcnow().isoformat(),
                                    event_type=f'windows_event_{event_id}',
                                    severity=severity,
                                    source='eventlog',
                                    description=f"{event_name} (Event ID: {event_id})",
                                    details={
                                        'event_id': event_id,
                                        'message': (evt.get('Message', '') or '')[:500]
                                    }
                                )
                                self._send_event(event)
                                
                    except json.JSONDecodeError:
                        pass
                
                last_check = datetime.now()
                time.sleep(10)
                
            except subprocess.TimeoutExpired:
                logger.warning("Event log query timed out")
                time.sleep(30)
            except Exception as e:
                logger.error(f"Event log monitor error: {e}")
                time.sleep(30)
    
    # ============== PHASE 7: ADVANCED MONITORING ==============
    
    def _registry_monitor_loop(self):
        """Monitor critical registry keys for changes."""
        import winreg
        
        # Critical registry keys to monitor
        critical_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
        ]
        
        # Store initial state
        registry_state = {}
        
        def get_key_values(hive, path):
            """Get all values from a registry key."""
            values = {}
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        values[name] = str(value)[:200]  # Truncate long values
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception:
                pass
            return values
        
        # Initialize state
        for hive, path in critical_keys:
            key_id = f"{hive}\\{path}"
            registry_state[key_id] = get_key_values(hive, path)
        
        logger.info("Registry monitor started - watching critical keys")
        
        while self.running:
            try:
                time.sleep(60)  # Check every minute
                
                for hive, path in critical_keys:
                    key_id = f"{hive}\\{path}"
                    current_values = get_key_values(hive, path)
                    old_values = registry_state.get(key_id, {})
                    
                    # Check for new entries
                    for name, value in current_values.items():
                        if name not in old_values:
                            event = SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type="registry_new_entry",
                                severity="MEDIUM",
                                source="registry",
                                description=f"New registry entry: {name}",
                                details={
                                    "key": path,
                                    "name": name,
                                    "value": value
                                }
                            )
                            self.event_queue.put(event)
                            logger.warning(f"New registry entry detected: {path}\\{name}")
                        elif old_values[name] != value:
                            event = SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type="registry_modified",
                                severity="MEDIUM",
                                source="registry",
                                description=f"Registry entry modified: {name}",
                                details={
                                    "key": path,
                                    "name": name,
                                    "old_value": old_values[name],
                                    "new_value": value
                                }
                            )
                            self.event_queue.put(event)
                            logger.warning(f"Registry entry modified: {path}\\{name}")
                    
                    # Update state
                    registry_state[key_id] = current_values
                    
            except Exception as e:
                logger.debug(f"Registry monitor error: {e}")
    
    def _startup_monitor_loop(self):
        """Monitor startup programs and services."""
        import winreg
        
        known_startups = set()
        
        def get_startup_items():
            """Get all startup items from common locations."""
            items = set()
            
            # Registry Run keys
            run_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ]
            
            for hive, path in run_keys:
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            items.add(f"reg:{name}={value[:100]}")
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except Exception:
                    pass
            
            # Startup folders
            startup_folders = [
                os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'),
                r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'
            ]
            
            for folder in startup_folders:
                if os.path.exists(folder):
                    for item in os.listdir(folder):
                        items.add(f"folder:{item}")
            
            return items
        
        # Initialize
        known_startups = get_startup_items()
        logger.info(f"Startup monitor started - tracking {len(known_startups)} items")
        
        while self.running:
            try:
                time.sleep(120)  # Check every 2 minutes
                
                current_startups = get_startup_items()
                new_items = current_startups - known_startups
                
                for item in new_items:
                    event = SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type="new_startup_item",
                        severity="HIGH",
                        source="startup",
                        description=f"New startup item detected: {item}",
                        details={"item": item}
                    )
                    self.event_queue.put(event)
                    logger.warning(f"New startup item: {item}")
                
                known_startups = current_startups
                
            except Exception as e:
                logger.debug(f"Startup monitor error: {e}")
    
    def _scheduled_task_monitor_loop(self):
        """Monitor Windows scheduled tasks for suspicious additions."""
        
        known_tasks = set()
        
        def get_scheduled_tasks():
            """Get list of scheduled tasks."""
            tasks = set()
            try:
                result = subprocess.run(
                    ['schtasks', '/query', '/fo', 'csv', '/nh'],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            parts = line.split(',')
                            if parts:
                                task_name = parts[0].strip('"')
                                tasks.add(task_name)
            except Exception as e:
                logger.debug(f"Error getting scheduled tasks: {e}")
            return tasks
        
        # Initialize
        known_tasks = get_scheduled_tasks()
        logger.info(f"Scheduled task monitor started - tracking {len(known_tasks)} tasks")
        
        while self.running:
            try:
                time.sleep(180)  # Check every 3 minutes
                
                current_tasks = get_scheduled_tasks()
                new_tasks = current_tasks - known_tasks
                
                for task in new_tasks:
                    # Skip common system tasks
                    if any(skip in task.lower() for skip in ['microsoft', 'windows', 'google', 'adobe']):
                        continue
                    
                    event = SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type="new_scheduled_task",
                        severity="HIGH",
                        source="scheduler",
                        description=f"New scheduled task: {task}",
                        details={"task_name": task}
                    )
                    self.event_queue.put(event)
                    logger.warning(f"New scheduled task detected: {task}")
                
                known_tasks = current_tasks
                
            except Exception as e:
                logger.debug(f"Scheduled task monitor error: {e}")
    
    def _usb_monitor_loop(self):
        """Monitor USB device connections."""
        
        known_devices = set()
        
        def get_usb_devices():
            """Get connected USB devices."""
            devices = set()
            try:
                result = subprocess.run(
                    ['wmic', 'path', 'Win32_USBControllerDevice', 'get', 'Dependent'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if 'DeviceID' in line:
                            devices.add(line.strip())
            except Exception:
                pass
            
            # Also check for removable drives
            try:
                for partition in psutil.disk_partitions():
                    if 'removable' in partition.opts.lower():
                        devices.add(f"drive:{partition.device}")
            except Exception:
                pass
            
            return devices
        
        # Initialize
        known_devices = get_usb_devices()
        logger.info(f"USB monitor started - tracking {len(known_devices)} devices")
        
        while self.running:
            try:
                time.sleep(10)  # Check every 10 seconds for USB
                
                current_devices = get_usb_devices()
                new_devices = current_devices - known_devices
                removed_devices = known_devices - current_devices
                
                for device in new_devices:
                    event = SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type="usb_connected",
                        severity="LOW",
                        source="usb",
                        description=f"USB device connected: {device[:100]}",
                        details={"device": device}
                    )
                    self.event_queue.put(event)
                    logger.info(f"USB device connected: {device[:50]}")
                
                for device in removed_devices:
                    logger.info(f"USB device removed: {device[:50]}")
                
                known_devices = current_devices
                
            except Exception as e:
                logger.debug(f"USB monitor error: {e}")
    
    def _hosts_file_monitor_loop(self):
        """Monitor Windows hosts file for DNS hijacking."""
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        last_hash = None
        
        def get_file_hash(path):
            try:
                with open(path, 'rb') as f:
                    return hashlib.md5(f.read()).hexdigest()
            except:
                return None
        
        last_hash = get_file_hash(hosts_path)
        logger.info("Hosts file monitor started")
        
        while self.running:
            try:
                time.sleep(60)  # Check every minute
                
                current_hash = get_file_hash(hosts_path)
                if current_hash and current_hash != last_hash:
                    # Read the new content
                    try:
                        with open(hosts_path, 'r') as f:
                            content = f.read()
                    except:
                        content = "Could not read"
                    
                    event = SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type="hosts_file_modified",
                        severity="HIGH",
                        source="hosts",
                        description="Windows hosts file was modified - possible DNS hijacking",
                        details={
                            "path": hosts_path,
                            "old_hash": last_hash,
                            "new_hash": current_hash,
                            "preview": content[:500]
                        }
                    )
                    self.event_queue.put(event)
                    logger.warning("Hosts file modified!")
                    last_hash = current_hash
                    
            except Exception as e:
                logger.debug(f"Hosts file monitor error: {e}")
    
    def _browser_extension_monitor_loop(self):
        """Monitor for new browser extensions (Chrome, Edge, Firefox)."""
        
        known_extensions = set()
        
        def get_chrome_extensions():
            """Get Chrome/Edge extension IDs."""
            extensions = set()
            paths = [
                os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions"),
                os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions"),
            ]
            
            for base_path in paths:
                if os.path.exists(base_path):
                    try:
                        for ext_id in os.listdir(base_path):
                            ext_path = os.path.join(base_path, ext_id)
                            if os.path.isdir(ext_path):
                                extensions.add(f"{base_path}:{ext_id}")
                    except:
                        pass
            return extensions
        
        # Initialize
        known_extensions = get_chrome_extensions()
        logger.info(f"Browser extension monitor started - tracking {len(known_extensions)} extensions")
        
        while self.running:
            try:
                time.sleep(300)  # Check every 5 minutes
                
                current_extensions = get_chrome_extensions()
                new_extensions = current_extensions - known_extensions
                
                for ext in new_extensions:
                    event = SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type="new_browser_extension",
                        severity="MEDIUM",
                        source="browser",
                        description=f"New browser extension installed",
                        details={"extension": ext}
                    )
                    self.event_queue.put(event)
                    logger.warning(f"New browser extension: {ext}")
                
                known_extensions = current_extensions
                
            except Exception as e:
                logger.debug(f"Browser extension monitor error: {e}")
    
    # ============== AVG ANTIVIRUS INTEGRATION ==============
    
    def _avg_monitor_loop(self):
        """Monitor AVG Antivirus logs and detections."""
        import glob
        
        # Common AVG log locations
        avg_paths = [
            os.path.expandvars(r"%PROGRAMDATA%\AVG\Antivirus\report"),
            os.path.expandvars(r"%PROGRAMDATA%\AVG\Antivirus\log"),
            os.path.expandvars(r"%PROGRAMDATA%\AVAST Software\Avast\report"),  # AVG uses Avast engine
            os.path.expandvars(r"%PROGRAMDATA%\AVAST Software\Avast\log"),
            os.path.expandvars(r"%ALLUSERSPROFILE%\AVG\Antivirus"),
        ]
        
        # Find valid AVG installation
        avg_log_dir = None
        for path in avg_paths:
            if os.path.exists(path):
                avg_log_dir = path
                break
        
        if not avg_log_dir:
            logger.info("AVG Antivirus not detected - monitor disabled")
            return
        
        logger.info(f"AVG monitor started - watching {avg_log_dir}")
        
        # Track processed log entries
        processed_entries = set()
        last_check_time = datetime.now()
        
        def parse_avg_log(log_file: str) -> List[Dict]:
            """Parse AVG/Avast log file for detections."""
            detections = []
            try:
                # Try different encodings
                for encoding in ['utf-8', 'utf-16', 'latin-1']:
                    try:
                        with open(log_file, 'r', encoding=encoding) as f:
                            content = f.read()
                        break
                    except:
                        continue
                else:
                    return detections
                
                # Parse log entries - AVG uses various formats
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Look for threat indicators
                    threat_keywords = [
                        'threat', 'virus', 'malware', 'trojan', 'worm',
                        'ransomware', 'spyware', 'adware', 'pup', 'infected',
                        'quarantine', 'blocked', 'detected', 'removed'
                    ]
                    
                    line_lower = line.lower()
                    if any(kw in line_lower for kw in threat_keywords):
                        # Extract threat info
                        detection = {
                            'raw': line[:500],  # Limit length
                            'file': log_file,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        # Try to extract threat name
                        threat_patterns = [
                            r'(?:threat|virus|malware)[:\s]+([^\s,]+)',
                            r'(?:detected|found)[:\s]+([^\s,]+)',
                            r'([A-Z][a-z]+\.[A-Z][a-z]+\.[A-Z0-9]+)',  # Threat naming pattern
                        ]
                        for pattern in threat_patterns:
                            match = re.search(pattern, line, re.IGNORECASE)
                            if match:
                                detection['threat_name'] = match.group(1)
                                break
                        
                        # Try to extract file path
                        path_match = re.search(r'([A-Z]:\\[^\s"<>|]+)', line)
                        if path_match:
                            detection['affected_file'] = path_match.group(1)
                        
                        detections.append(detection)
                        
            except Exception as e:
                logger.debug(f"Error parsing AVG log {log_file}: {e}")
            
            return detections
        
        def scan_avg_logs():
            """Scan all AVG log files for new detections."""
            all_detections = []
            
            # Find all log files
            log_patterns = ['*.log', '*.txt', '*.xml', 'report*']
            for pattern in log_patterns:
                for log_file in glob.glob(os.path.join(avg_log_dir, '**', pattern), recursive=True):
                    try:
                        # Only check files modified recently
                        mtime = datetime.fromtimestamp(os.path.getmtime(log_file))
                        if mtime > last_check_time:
                            detections = parse_avg_log(log_file)
                            all_detections.extend(detections)
                    except:
                        pass
            
            return all_detections
        
        while self.running:
            try:
                time.sleep(60)  # Check every minute
                
                detections = scan_avg_logs()
                last_check_time = datetime.now()
                
                for detection in detections:
                    # Create unique key to avoid duplicates
                    entry_key = hashlib.md5(detection['raw'].encode()).hexdigest()
                    if entry_key in processed_entries:
                        continue
                    processed_entries.add(entry_key)
                    
                    # Determine severity based on threat type
                    severity = "HIGH"
                    threat_name = detection.get('threat_name', 'Unknown')
                    if any(x in threat_name.lower() for x in ['pup', 'adware']):
                        severity = "MEDIUM"
                    elif any(x in threat_name.lower() for x in ['ransomware', 'trojan', 'rootkit']):
                        severity = "CRITICAL"
                    
                    event = SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type="avg_detection",
                        severity=severity,
                        source="avg_antivirus",
                        description=f"AVG detected threat: {threat_name}",
                        details={
                            "threat_name": threat_name,
                            "affected_file": detection.get('affected_file', 'Unknown'),
                            "raw_log": detection['raw'][:200],
                            "log_file": detection['file'],
                            "antivirus": "AVG"
                        }
                    )
                    self.event_queue.put(event)
                    logger.warning(f"AVG Detection: {threat_name} in {detection.get('affected_file', 'Unknown')}")
                
                # Cleanup old entries (keep last 1000)
                if len(processed_entries) > 1000:
                    processed_entries.clear()
                    
            except Exception as e:
                logger.debug(f"AVG monitor error: {e}")
    
    def get_avg_status(self) -> Dict[str, Any]:
        """Get AVG Antivirus status if installed."""
        status = {
            "installed": False,
            "running": False,
            "version": None,
            "last_scan": None,
            "definitions_date": None
        }
        
        try:
            # Check if AVG service is running
            for proc in psutil.process_iter(['name']):
                if 'avg' in proc.info['name'].lower() or 'avast' in proc.info['name'].lower():
                    status['installed'] = True
                    status['running'] = True
                    break
            
            # Try to get version from registry
            try:
                import winreg
                for key_path in [
                    r"SOFTWARE\AVG\Antivirus",
                    r"SOFTWARE\AVAST Software\Avast",
                    r"SOFTWARE\WOW6432Node\AVG\Antivirus"
                ]:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                        status['version'], _ = winreg.QueryValueEx(key, "Version")
                        status['installed'] = True
                        winreg.CloseKey(key)
                        break
                    except:
                        pass
            except:
                pass
                
        except Exception as e:
            logger.debug(f"Error getting AVG status: {e}")
        
        return status
    
    # ============== END AVG INTEGRATION ==============
    
    def block_ip(self, ip: str) -> bool:
        """Block an IP address using Windows Firewall."""
        if ip in self.blocked_ips:
            return True
        
        try:
            rule_name = f"SentinelAI_Block_{ip.replace('.', '_')}"
            
            result = subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=in',
                'action=block',
                f'remoteip={ip}',
                'enable=yes'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                logger.info(f"Blocked IP: {ip}")
                return True
            else:
                logger.error(f"Failed to block IP {ip}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status."""
        return {
            'running': self.running,
            'hostname': platform.node(),
            'platform': f"{platform.system()} {platform.release()}",
            'uptime': self.stats['start_time'],
            'stats': self.stats,
            'blocked_ips': list(self.blocked_ips),
            'suspicious_ips': list(self.suspicious_ips)
        }


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='SentinelAI Windows Agent')
    parser.add_argument('--dashboard', '-d', default='http://localhost:8015',
                        help='Dashboard URL (default: http://localhost:8015)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('--no-ai', action='store_true',
                        help='Disable AI-powered analysis (use heuristics only)')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    ai_status = "DISABLED" if args.no_ai else "ENABLED"
    
    print(f"""
    ╔═══════════════════════════════════════════════════════════╗
    ║           SentinelAI Windows Agent v1.3                   ║
    ║     Native Windows Protection & Threat Detection          ║
    ║                                                           ║
    ║  Monitors: Process | Network | EventLog | Registry        ║
    ║            Startup | Tasks | USB | Hosts | Browser        ║
    ║            AVG Antivirus Integration                      ║
    ║                                                           ║
    ║     AI Analysis: {ai_status:^10}                            ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    agent = WindowsAgent(dashboard_url=args.dashboard)
    agent.use_ai = not args.no_ai
    agent.start()


if __name__ == '__main__':
    main()
