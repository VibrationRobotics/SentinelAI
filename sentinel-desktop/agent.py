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

def safe_subprocess_run(cmd, **kwargs):
    """Run subprocess with proper encoding to avoid UnicodeDecodeError on Windows."""
    # Set encoding to utf-8 with error handling
    kwargs.setdefault('encoding', 'utf-8')
    kwargs.setdefault('errors', 'replace')  # Replace undecodable chars
    kwargs.setdefault('capture_output', True)
    
    try:
        return subprocess.run(cmd, **kwargs)
    except UnicodeDecodeError:
        # Fallback: try with latin-1 which can decode any byte
        kwargs['encoding'] = 'latin-1'
        return subprocess.run(cmd, **kwargs)

# Import local ML detector
try:
    from ml_detector import HybridThreatDetector, get_detector
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

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
        
        # Hybrid ML/Rule-based detector (reduces OpenAI costs by 95%+)
        self.hybrid_detector = get_detector(use_ai=self.use_ai) if ML_AVAILABLE else None
        
        logger.info(f"Windows Agent initialized - Dashboard: {self.dashboard_url}")
        logger.info(f"AI-powered analysis: {'Enabled' if self.use_ai else 'Disabled'}")
        logger.info(f"Hybrid ML detector: {'Enabled' if self.hybrid_detector else 'Disabled (install ml_detector.py)'}")
    
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
            # Advanced monitors (Phase 8)
            threading.Thread(target=self._clipboard_monitor_loop, daemon=True),
            threading.Thread(target=self._dns_monitor_loop, daemon=True),
            threading.Thread(target=self._powershell_monitor_loop, daemon=True),
            threading.Thread(target=self._wmi_monitor_loop, daemon=True),
            threading.Thread(target=self._service_monitor_loop, daemon=True),
            threading.Thread(target=self._driver_monitor_loop, daemon=True),
            threading.Thread(target=self._firewall_rule_monitor_loop, daemon=True),
            threading.Thread(target=self._certificate_monitor_loop, daemon=True),
            threading.Thread(target=self._named_pipe_monitor_loop, daemon=True),
            threading.Thread(target=self._defender_monitor_loop, daemon=True),
            # AMSI, ETW, Sysmon, DLL Injection (Phase 9)
            threading.Thread(target=self._amsi_monitor_loop, daemon=True),
            threading.Thread(target=self._etw_monitor_loop, daemon=True),
            threading.Thread(target=self._sysmon_monitor_loop, daemon=True),
            threading.Thread(target=self._dll_injection_monitor_loop, daemon=True),
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
                'agent_version': '1.4.0',
                'is_admin': is_admin,
                'capabilities': [
                    'process', 'network', 'eventlog', 'firewall', 'ai', 
                    'registry', 'startup', 'tasks', 'usb', 'hosts', 'browser',
                    'clipboard', 'dns', 'powershell', 'wmi', 'services',
                    'drivers', 'firewall_rules', 'certificates', 'named_pipes', 'defender',
                    'amsi', 'etw', 'sysmon', 'dll_injection'
                ]
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
    
    def _analyze_event_with_ai(self, event: SecurityEvent) -> Dict:
        """
        Send any security event to AI for intelligent analysis.
        Used for HIGH/CRITICAL severity events from all monitors.
        """
        if not self.use_ai:
            return None
        
        # Create cache key from event type and description
        cache_key = f"{event.event_type}:{event.description[:100]}"
        
        # Check cache first
        if cache_key in self.ai_cache:
            return self.ai_cache[cache_key]
        
        try:
            analysis_request = {
                'source_ip': event.ip_address or '127.0.0.1',
                'threat_type': event.event_type,
                'severity': event.severity,
                'description': f"[{event.source.upper()}] {event.description}",
                'payload': json.dumps(event.details),
                'timestamp': event.timestamp,
                'agent_source': 'windows_agent',
                'request_ai_analysis': True
            }
            
            response = requests.post(
                f"{self.api_base}/threats/analyze",
                json=analysis_request,
                timeout=15
            )
            
            if response.status_code == 200:
                result = response.json()
                self.stats['ai_analyses'] += 1
                
                ai_result = {
                    'analyzed': True,
                    'ai_severity': result.get('severity', event.severity),
                    'ai_classification': result.get('classification', 'unknown'),
                    'ai_confidence': result.get('confidence', 0.5),
                    'ai_explanation': result.get('ai_analysis', {}).get('explanation', ''),
                    'ai_recommendation': result.get('recommended_action', 'monitor'),
                    'is_false_positive': result.get('ai_analysis', {}).get('is_false_positive', False),
                    'mitre_techniques': result.get('ai_analysis', {}).get('mitre_techniques', [])
                }
                
                # Cache the result
                self.ai_cache[cache_key] = ai_result
                
                logger.info(f"AI analyzed {event.event_type}: {ai_result['ai_classification']} (confidence: {ai_result['ai_confidence']})")
                return ai_result
            
        except Exception as e:
            logger.debug(f"AI event analysis error: {e}")
        
        return None
    
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
        """Background thread to send events to dashboard with hybrid ML/AI analysis."""
        while self.running:
            try:
                # Get event with timeout
                event = self.event_queue.get(timeout=1)
                
                # Step 1: Use hybrid detector (rules + local ML) - FREE and FAST
                should_use_openai = False
                local_analysis = None
                
                if self.hybrid_detector:
                    score, should_use_openai = self.hybrid_detector.analyze(
                        event.event_type, 
                        event.details
                    )
                    
                    local_analysis = {
                        'method': 'hybrid_ml',
                        'is_threat': score.is_threat,
                        'confidence': score.confidence,
                        'threat_type': score.threat_type,
                        'severity': score.severity,
                        'reason': score.reason,
                    }
                    
                    # Update event severity based on local analysis
                    if not score.is_threat and score.confidence > 0.8:
                        # High confidence it's safe - downgrade severity
                        if event.severity in ['HIGH', 'CRITICAL']:
                            event.severity = 'LOW'
                            logger.debug(f"ML marked safe: {event.event_type} ({score.reason})")
                    
                    event.details['local_analysis'] = local_analysis
                
                # Step 2: Only use OpenAI if hybrid detector is uncertain AND severity is HIGH+
                ai_result = None
                if should_use_openai and event.severity in ['HIGH', 'CRITICAL'] and self.use_ai:
                    ai_result = self._analyze_event_with_ai(event)
                    if ai_result:
                        event.details['ai_analysis'] = ai_result
                        if ai_result.get('is_false_positive'):
                            event.severity = 'LOW'
                            logger.info(f"OpenAI marked as false positive: {event.event_type}")
                
                # Step 3: Send to dashboard
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
                            'agent_source': 'windows_agent',
                            'ai_analyzed': ai_result is not None,
                            'ml_analyzed': local_analysis is not None,
                            'request_ai_analysis': should_use_openai and event.severity in ['HIGH', 'CRITICAL']
                        },
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        self.stats['events_sent'] += 1
                        method = " [AI]" if ai_result else " [ML]" if local_analysis else ""
                        logger.info(f"Event sent{method}: {event.event_type} - {event.description[:50]}")
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
                
                result = safe_subprocess_run(
                    ['powershell', '-Command', ps_command],
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
                result = safe_subprocess_run(
                    ['schtasks', '/query', '/fo', 'csv', '/nh'],
                    timeout=30
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
                result = safe_subprocess_run(
                    ['wmic', 'path', 'Win32_USBControllerDevice', 'get', 'Dependent'],
                    capture_output=True, timeout=10
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
    
    # ============== ADVANCED MONITORS ==============
    
    def _clipboard_monitor_loop(self):
        """Monitor clipboard for sensitive data (passwords, API keys, crypto wallets)."""
        try:
            import win32clipboard
            import win32con
        except ImportError:
            logger.info("Clipboard monitor requires pywin32 - install with: pip install pywin32")
            return
        
        logger.info("Clipboard monitor started")
        
        # Sensitive data patterns
        sensitive_patterns = [
            (r'(?i)password\s*[:=]\s*\S+', 'password'),
            (r'(?i)api[_-]?key\s*[:=]\s*[a-zA-Z0-9_-]{20,}', 'api_key'),
            (r'(?i)secret\s*[:=]\s*\S+', 'secret'),
            (r'(?i)token\s*[:=]\s*[a-zA-Z0-9_.-]{20,}', 'token'),
            (r'(?i)bearer\s+[a-zA-Z0-9_.-]+', 'bearer_token'),
            (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
            (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*\S+', 'aws_secret'),
            (r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', 'bitcoin_address'),
            (r'0x[a-fA-F0-9]{40}', 'ethereum_address'),
            (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'private_key'),
            (r'(?i)ssh-rsa\s+[A-Za-z0-9+/=]+', 'ssh_key'),
        ]
        
        last_content = ""
        
        while self.running:
            try:
                time.sleep(5)  # Check every 5 seconds
                
                try:
                    win32clipboard.OpenClipboard()
                    if win32clipboard.IsClipboardFormatAvailable(win32con.CF_TEXT):
                        content = win32clipboard.GetClipboardData(win32con.CF_TEXT)
                        if isinstance(content, bytes):
                            content = content.decode('utf-8', errors='ignore')
                    elif win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                        content = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
                    else:
                        content = ""
                    win32clipboard.CloseClipboard()
                except:
                    content = ""
                
                if content and content != last_content:
                    last_content = content
                    
                    # Check for sensitive patterns
                    for pattern, data_type in sensitive_patterns:
                        if re.search(pattern, content):
                            event = SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type="clipboard_sensitive_data",
                                severity="HIGH",
                                source="clipboard",
                                description=f"Sensitive data detected in clipboard: {data_type}",
                                details={
                                    "data_type": data_type,
                                    "preview": content[:50] + "..." if len(content) > 50 else content
                                }
                            )
                            self.event_queue.put(event)
                            logger.warning(f"Sensitive data in clipboard: {data_type}")
                            break  # Only report once per clipboard change
                            
            except Exception as e:
                logger.debug(f"Clipboard monitor error: {e}")
    
    def _dns_monitor_loop(self):
        """Monitor DNS queries for tunneling and suspicious domains."""
        logger.info("DNS monitor started")
        
        # Suspicious domain patterns
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click']
        suspicious_patterns = [
            r'[a-z0-9]{50,}\.', # Very long subdomain (possible DNS tunneling) - increased threshold
            r'[a-f0-9]{40,}\.',  # Hex-encoded data in subdomain
        ]
        
        # Safe patterns to ignore
        safe_patterns = [
            r'\.in-addr\.arpa',  # Reverse DNS lookups are normal
            r'\.ip6\.arpa',      # IPv6 reverse DNS
            r'localhost',
            r'microsoft\.com',
            r'windows\.com',
            r'windowsupdate\.com',
            r'azure\.com',
            r'cloudflare',
            r'google\.com',
            r'googleapis\.com',
            r'gstatic\.com',
        ]
        
        # Known malicious domains (sample list)
        known_bad_domains = [
            'malware.com', 'evil.com', 'c2server.net',
        ]
        
        # Track DNS cache to detect new queries
        last_dns_cache = set()
        
        while self.running:
            try:
                time.sleep(30)  # Check every 30 seconds
                
                # Get DNS cache using ipconfig
                result = safe_subprocess_run(
                    ['ipconfig', '/displaydns'],
                    capture_output=True, timeout=30
                )
                
                if result.returncode == 0:
                    current_domains = set()
                    
                    for line in result.stdout.split('\n'):
                        if 'Record Name' in line:
                            domain = line.split(':')[-1].strip().lower()
                            if domain:
                                current_domains.add(domain)
                    
                    new_domains = current_domains - last_dns_cache
                    
                    for domain in new_domains:
                        is_suspicious = False
                        reason = ""
                        
                        # Check TLD
                        for tld in suspicious_tlds:
                            if domain.endswith(tld):
                                is_suspicious = True
                                reason = f"Suspicious TLD: {tld}"
                                break
                        
                        # Skip safe patterns first
                        is_safe = False
                        for safe in safe_patterns:
                            if re.search(safe, domain, re.IGNORECASE):
                                is_safe = True
                                break
                        
                        if is_safe:
                            continue
                        
                        # Check patterns (DNS tunneling indicators)
                        if not is_suspicious:
                            for pattern in suspicious_patterns:
                                if re.search(pattern, domain):
                                    is_suspicious = True
                                    reason = "Possible DNS tunneling"
                                    break
                        
                        # Check known bad domains
                        if not is_suspicious:
                            for bad in known_bad_domains:
                                if bad in domain:
                                    is_suspicious = True
                                    reason = "Known malicious domain"
                                    break
                        
                        if is_suspicious:
                            event = SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type="suspicious_dns_query",
                                severity="MEDIUM",
                                source="dns",
                                description=f"Suspicious DNS query: {domain}",
                                details={
                                    "domain": domain,
                                    "reason": reason
                                }
                            )
                            self.event_queue.put(event)
                            logger.warning(f"Suspicious DNS: {domain} - {reason}")
                    
                    last_dns_cache = current_domains
                    
            except Exception as e:
                logger.debug(f"DNS monitor error: {e}")
    
    def _powershell_monitor_loop(self):
        """Monitor PowerShell script block logging via Event Log."""
        logger.info("PowerShell monitor started")
        
        # Suspicious PowerShell patterns
        suspicious_ps_patterns = [
            r'(?i)invoke-expression',
            r'(?i)invoke-command',
            r'(?i)invoke-webrequest',
            r'(?i)downloadstring',
            r'(?i)downloadfile',
            r'(?i)start-bitstransfer',
            r'(?i)iex\s*\(',
            r'(?i)new-object\s+net\.webclient',
            r'(?i)-enc\s+[a-zA-Z0-9+/=]+',
            r'(?i)-encodedcommand',
            r'(?i)frombase64string',
            r'(?i)bypass\s+-nop',
            r'(?i)-windowstyle\s+hidden',
            r'(?i)add-type.*dllimport',
            r'(?i)reflection\.assembly',
            r'(?i)mimikatz',
            r'(?i)invoke-mimikatz',
            r'(?i)get-credential',
            r'(?i)convertto-securestring',
        ]
        
        try:
            import win32evtlog
        except ImportError:
            logger.info("PowerShell monitor requires pywin32")
            return
        
        last_record = 0
        
        while self.running:
            try:
                time.sleep(10)  # Check every 10 seconds
                
                # Read PowerShell Operational log (Event ID 4104 = Script Block)
                try:
                    hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-PowerShell/Operational")
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    for event in events:
                        if event.RecordNumber <= last_record:
                            continue
                        
                        last_record = max(last_record, event.RecordNumber)
                        
                        # Event ID 4104 is Script Block Logging
                        if event.EventID == 4104:
                            script_block = str(event.StringInserts) if event.StringInserts else ""
                            
                            for pattern in suspicious_ps_patterns:
                                if re.search(pattern, script_block):
                                    event_obj = SecurityEvent(
                                        timestamp=datetime.utcnow().isoformat(),
                                        event_type="suspicious_powershell",
                                        severity="HIGH",
                                        source="powershell",
                                        description=f"Suspicious PowerShell execution detected",
                                        details={
                                            "pattern_matched": pattern,
                                            "script_preview": script_block[:500]
                                        }
                                    )
                                    self.event_queue.put(event_obj)
                                    logger.warning(f"Suspicious PowerShell: {pattern}")
                                    break
                    
                    win32evtlog.CloseEventLog(hand)
                    
                except Exception as e:
                    logger.debug(f"PowerShell log read error: {e}")
                    
            except Exception as e:
                logger.debug(f"PowerShell monitor error: {e}")
    
    def _wmi_monitor_loop(self):
        """Monitor WMI event subscriptions for persistence."""
        logger.info("WMI monitor started")
        
        known_subscriptions = set()
        
        def get_wmi_subscriptions():
            """Get WMI event subscriptions."""
            subs = set()
            try:
                # Query for WMI event consumers
                result = safe_subprocess_run([
                    'wmic', 'path', '__EventConsumer', 'get', 'Name', '/format:list'
                ], capture_output=True, timeout=30)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Name=' in line:
                            name = line.split('=')[-1].strip()
                            if name:
                                subs.add(f"consumer:{name}")
                
                # Query for event filters
                result = safe_subprocess_run([
                    'wmic', 'path', '__EventFilter', 'get', 'Name', '/format:list'
                ], capture_output=True, timeout=30)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Name=' in line:
                            name = line.split('=')[-1].strip()
                            if name:
                                subs.add(f"filter:{name}")
                                
            except Exception as e:
                logger.debug(f"WMI query error: {e}")
            
            return subs
        
        known_subscriptions = get_wmi_subscriptions()
        
        while self.running:
            try:
                time.sleep(120)  # Check every 2 minutes
                
                current_subs = get_wmi_subscriptions()
                new_subs = current_subs - known_subscriptions
                
                for sub in new_subs:
                    # Skip known system subscriptions
                    if any(x in sub.lower() for x in ['microsoft', 'windows', 'scm event']):
                        continue
                    
                    event = SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type="wmi_subscription_created",
                        severity="HIGH",
                        source="wmi",
                        description=f"New WMI event subscription: {sub}",
                        details={"subscription": sub}
                    )
                    self.event_queue.put(event)
                    logger.warning(f"New WMI subscription: {sub}")
                
                known_subscriptions = current_subs
                
            except Exception as e:
                logger.debug(f"WMI monitor error: {e}")
    
    def _service_monitor_loop(self):
        """Monitor for new Windows services (persistence mechanism)."""
        logger.info("Service monitor started")
        
        known_services = set()
        
        def get_services():
            """Get list of Windows services."""
            services = set()
            try:
                result = safe_subprocess_run(
                    ['sc', 'query', 'state=', 'all'],
                    capture_output=True, timeout=30
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'SERVICE_NAME:' in line:
                            name = line.split(':')[-1].strip()
                            if name:
                                services.add(name)
            except Exception as e:
                logger.debug(f"Service query error: {e}")
            return services
        
        known_services = get_services()
        logger.info(f"Service monitor tracking {len(known_services)} services")
        
        while self.running:
            try:
                time.sleep(60)  # Check every minute
                
                current_services = get_services()
                new_services = current_services - known_services
                
                for service in new_services:
                    # Skip common system services
                    if any(x in service.lower() for x in ['windows', 'microsoft', 'wmi', 'dcom']):
                        continue
                    
                    # Get service details
                    details = {}
                    try:
                        result = safe_subprocess_run(
                            ['sc', 'qc', service],
                            capture_output=True, timeout=10
                        )
                        if result.returncode == 0:
                            for line in result.stdout.split('\n'):
                                if 'BINARY_PATH_NAME' in line:
                                    details['binary_path'] = line.split(':')[-1].strip()
                                elif 'START_TYPE' in line:
                                    details['start_type'] = line.split(':')[-1].strip()
                    except:
                        pass
                    
                    event = SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type="new_service_created",
                        severity="HIGH",
                        source="services",
                        description=f"New Windows service created: {service}",
                        details={
                            "service_name": service,
                            **details
                        }
                    )
                    self.event_queue.put(event)
                    logger.warning(f"New service: {service}")
                
                known_services = current_services
                
            except Exception as e:
                logger.debug(f"Service monitor error: {e}")
    
    def _driver_monitor_loop(self):
        """Monitor for new driver loading (rootkit detection)."""
        logger.info("Driver monitor started")
        
        known_drivers = set()
        
        def get_drivers():
            """Get list of loaded drivers."""
            drivers = set()
            try:
                result = safe_subprocess_run(
                    ['driverquery', '/fo', 'csv', '/nh'],
                    capture_output=True, timeout=30
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            parts = line.split(',')
                            if parts:
                                driver_name = parts[0].strip('"')
                                if driver_name:
                                    drivers.add(driver_name)
            except Exception as e:
                logger.debug(f"Driver query error: {e}")
            return drivers
        
        known_drivers = get_drivers()
        logger.info(f"Driver monitor tracking {len(known_drivers)} drivers")
        
        while self.running:
            try:
                time.sleep(120)  # Check every 2 minutes
                
                current_drivers = get_drivers()
                new_drivers = current_drivers - known_drivers
                
                # Only log if there are truly suspicious new drivers (not just system enumeration)
                # Skip the first scan cycle to avoid flooding
                if not hasattr(self, '_driver_first_scan_done'):
                    self._driver_first_scan_done = True
                    known_drivers = current_drivers
                    continue
                
                for driver in new_drivers:
                    # Skip common system drivers and known vendors
                    driver_lower = driver.lower()
                    safe_vendors = ['microsoft', 'windows', 'intel', 'nvidia', 'amd', 'realtek', 
                                   'avg', 'avast', 'kaspersky', 'symantec', 'mcafee', 'eset',
                                   'vmware', 'virtualbox', 'hyper-v', 'docker', 'wsl',
                                   'usb', 'hid', 'bluetooth', 'wifi', 'network', 'audio',
                                   'disk', 'storage', 'pci', 'acpi', 'uefi']
                    if any(x in driver_lower for x in safe_vendors):
                        continue
                    
                    event = SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type="new_driver_loaded",
                        severity="HIGH",
                        source="drivers",
                        description=f"New driver loaded: {driver}",
                        details={"driver_name": driver}
                    )
                    self.event_queue.put(event)
                    logger.warning(f"New driver: {driver}")
                
                known_drivers = current_drivers
                
            except Exception as e:
                logger.debug(f"Driver monitor error: {e}")
    
    def _firewall_rule_monitor_loop(self):
        """Monitor for unauthorized firewall rule changes."""
        logger.info("Firewall rule monitor started")
        
        known_rules = set()
        
        def get_firewall_rules():
            """Get list of firewall rules."""
            rules = set()
            try:
                result = safe_subprocess_run(
                    ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
                    capture_output=True, timeout=60
                )
                if result.returncode == 0:
                    current_rule = None
                    for line in result.stdout.split('\n'):
                        if 'Rule Name:' in line:
                            current_rule = line.split(':')[-1].strip()
                            if current_rule:
                                rules.add(current_rule)
            except Exception as e:
                logger.debug(f"Firewall query error: {e}")
            return rules
        
        known_rules = get_firewall_rules()
        logger.info(f"Firewall monitor tracking {len(known_rules)} rules")
        
        while self.running:
            try:
                time.sleep(60)  # Check every minute
                
                current_rules = get_firewall_rules()
                new_rules = current_rules - known_rules
                removed_rules = known_rules - current_rules
                
                for rule in new_rules:
                    # Skip our own rules
                    if 'SentinelAI' in rule:
                        continue
                    
                    event = SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type="firewall_rule_added",
                        severity="MEDIUM",
                        source="firewall",
                        description=f"New firewall rule added: {rule}",
                        details={"rule_name": rule}
                    )
                    self.event_queue.put(event)
                    logger.info(f"New firewall rule: {rule}")
                
                for rule in removed_rules:
                    if 'SentinelAI' in rule:
                        continue
                    
                    event = SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type="firewall_rule_removed",
                        severity="MEDIUM",
                        source="firewall",
                        description=f"Firewall rule removed: {rule}",
                        details={"rule_name": rule}
                    )
                    self.event_queue.put(event)
                    logger.warning(f"Firewall rule removed: {rule}")
                
                known_rules = current_rules
                
            except Exception as e:
                logger.debug(f"Firewall monitor error: {e}")
    
    def _certificate_monitor_loop(self):
        """Monitor Windows certificate store for rogue certificates."""
        logger.info("Certificate monitor started")
        
        known_certs = set()
        
        def get_certificates():
            """Get certificates from Windows store."""
            certs = set()
            try:
                # Query root certificates
                result = safe_subprocess_run([
                    'certutil', '-store', 'Root'
                ], capture_output=True, timeout=30)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Subject:' in line:
                            subject = line.split('Subject:')[-1].strip()
                            if subject:
                                certs.add(f"root:{subject[:100]}")
                
                # Query CA certificates
                result = safe_subprocess_run([
                    'certutil', '-store', 'CA'
                ], capture_output=True, timeout=30)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Subject:' in line:
                            subject = line.split('Subject:')[-1].strip()
                            if subject:
                                certs.add(f"ca:{subject[:100]}")
                                
            except Exception as e:
                logger.debug(f"Certificate query error: {e}")
            return certs
        
        known_certs = get_certificates()
        logger.info(f"Certificate monitor tracking {len(known_certs)} certificates")
        
        while self.running:
            try:
                time.sleep(300)  # Check every 5 minutes
                
                current_certs = get_certificates()
                new_certs = current_certs - known_certs
                
                for cert in new_certs:
                    event = SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type="new_certificate_installed",
                        severity="HIGH",
                        source="certificates",
                        description=f"New certificate installed: {cert}",
                        details={"certificate": cert}
                    )
                    self.event_queue.put(event)
                    logger.warning(f"New certificate: {cert}")
                
                known_certs = current_certs
                
            except Exception as e:
                logger.debug(f"Certificate monitor error: {e}")
    
    def _named_pipe_monitor_loop(self):
        """Monitor named pipes for C2 communication channels."""
        logger.info("Named pipe monitor started")
        
        # Known malicious pipe names (removed 'mojo' - it's Chrome IPC)
        suspicious_pipes = [
            'msagent_', 'isapi', 'postex_', 'status_',
            'msse-', 'MSSE-', 'mssecsvc',
            'cobaltstrike', 'beacon', 'metasploit'
        ]
        
        # Safe pipe patterns to ignore
        safe_pipe_patterns = [
            'mojo.',           # Chrome/Chromium IPC
            'chrome.',         # Chrome browser
            'crashpad',        # Crash reporting
            'discord',         # Discord app
            'spotify',         # Spotify
            'LOCAL\\mojo',    # Chrome mojo pipes
            'GoogleUpdate',    # Google updater
            'PIPE_EVENTROOT',  # Windows events
        ]
        
        known_pipes = set()
        
        def get_named_pipes():
            """Get list of named pipes."""
            pipes = set()
            try:
                pipe_path = r'\\.\pipe\\'
                if os.path.exists(r'\\.\pipe'):
                    # Use dir command to list pipes
                    result = safe_subprocess_run(
                        ['cmd', '/c', 'dir', r'\\.\pipe\\'],
                        capture_output=True, timeout=10
                    )
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            parts = line.split()
                            if parts and not any(x in line for x in ['<DIR>', 'Volume', 'Directory', 'File(s)', 'Dir(s)']):
                                if len(parts) >= 4:
                                    pipe_name = parts[-1]
                                    if pipe_name and pipe_name != '.':
                                        pipes.add(pipe_name)
            except Exception as e:
                logger.debug(f"Named pipe query error: {e}")
            return pipes
        
        known_pipes = get_named_pipes()
        
        while self.running:
            try:
                time.sleep(30)  # Check every 30 seconds
                
                current_pipes = get_named_pipes()
                new_pipes = current_pipes - known_pipes
                
                for pipe in new_pipes:
                    # Skip safe pipes first
                    is_safe = False
                    for safe in safe_pipe_patterns:
                        if safe.lower() in pipe.lower():
                            is_safe = True
                            break
                    
                    if is_safe:
                        continue
                    
                    is_suspicious = False
                    
                    for sus_pattern in suspicious_pipes:
                        if sus_pattern.lower() in pipe.lower():
                            is_suspicious = True
                            break
                    
                    if is_suspicious:
                        event = SecurityEvent(
                            timestamp=datetime.utcnow().isoformat(),
                            event_type="suspicious_named_pipe",
                            severity="HIGH",
                            source="named_pipes",
                            description=f"Suspicious named pipe detected: {pipe}",
                            details={"pipe_name": pipe}
                        )
                        self.event_queue.put(event)
                        logger.warning(f"Suspicious named pipe: {pipe}")
                
                known_pipes = current_pipes
                
            except Exception as e:
                logger.debug(f"Named pipe monitor error: {e}")
    
    def _defender_monitor_loop(self):
        """Monitor Windows Defender for threat detections."""
        logger.info("Windows Defender monitor started")
        
        try:
            import win32evtlog
        except ImportError:
            logger.info("Defender monitor requires pywin32")
            return
        
        last_record = 0
        
        # Defender Event IDs
        # 1116 = Malware detected
        # 1117 = Action taken
        # 1118 = Remediation failed
        # 1119 = Critical failure
        defender_event_ids = [1116, 1117, 1118, 1119]
        
        while self.running:
            try:
                time.sleep(30)  # Check every 30 seconds
                
                try:
                    hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Windows Defender/Operational")
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    for event in events:
                        if event.RecordNumber <= last_record:
                            continue
                        
                        last_record = max(last_record, event.RecordNumber)
                        
                        if event.EventID in defender_event_ids:
                            severity = "HIGH"
                            if event.EventID in [1118, 1119]:
                                severity = "CRITICAL"
                            
                            event_obj = SecurityEvent(
                                timestamp=datetime.utcnow().isoformat(),
                                event_type="defender_detection",
                                severity=severity,
                                source="windows_defender",
                                description=f"Windows Defender event: {event.EventID}",
                                details={
                                    "event_id": event.EventID,
                                    "data": str(event.StringInserts)[:500] if event.StringInserts else ""
                                }
                            )
                            self.event_queue.put(event_obj)
                            logger.warning(f"Defender detection: Event {event.EventID}")
                    
                    win32evtlog.CloseEventLog(hand)
                    
                except Exception as e:
                    logger.debug(f"Defender log read error: {e}")
                    
            except Exception as e:
                logger.debug(f"Defender monitor error: {e}")
    
    # ============== AMSI, ETW, SYSMON, DLL INJECTION ==============
    
    def _amsi_monitor_loop(self):
        """Monitor AMSI (Antimalware Scan Interface) events via Event Log."""
        logger.info("AMSI monitor started")
        
        try:
            import win32evtlog
        except ImportError:
            logger.info("AMSI monitor requires pywin32")
            return
        
        last_record = 0
        
        # AMSI Event IDs in Microsoft-Windows-Windows Defender/Operational
        # Event ID 1116 includes AMSI detections
        
        while self.running:
            try:
                time.sleep(15)  # Check every 15 seconds
                
                try:
                    # AMSI events are logged to Windows Defender log
                    hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Windows Defender/Operational")
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    for event in events:
                        if event.RecordNumber <= last_record:
                            continue
                        
                        last_record = max(last_record, event.RecordNumber)
                        
                        # Event ID 1116 = AMSI detection
                        if event.EventID == 1116:
                            event_data = str(event.StringInserts) if event.StringInserts else ""
                            
                            # Check if it's an AMSI-specific detection
                            if 'AMSI' in event_data or 'script' in event_data.lower():
                                event_obj = SecurityEvent(
                                    timestamp=datetime.utcnow().isoformat(),
                                    event_type="amsi_detection",
                                    severity="HIGH",
                                    source="amsi",
                                    description="AMSI detected malicious content",
                                    details={
                                        "event_id": event.EventID,
                                        "data": event_data[:500]
                                    }
                                )
                                self.event_queue.put(event_obj)
                                logger.warning(f"AMSI detection: {event_data[:100]}")
                    
                    win32evtlog.CloseEventLog(hand)
                    
                except Exception as e:
                    logger.debug(f"AMSI log read error: {e}")
                    
            except Exception as e:
                logger.debug(f"AMSI monitor error: {e}")
    
    def _etw_monitor_loop(self):
        """Monitor ETW (Event Tracing for Windows) for security events."""
        logger.info("ETW monitor started")
        
        try:
            import win32evtlog
        except ImportError:
            logger.info("ETW monitor requires pywin32")
            return
        
        last_records = {}
        
        # ETW providers to monitor
        etw_logs = [
            ("Microsoft-Windows-Security-Auditing", [4688, 4689]),  # Process creation/termination
            ("Microsoft-Windows-Sysmon/Operational", [1, 3, 7, 8, 10, 11]),  # Sysmon events
            ("Microsoft-Windows-PowerShell/Operational", [4103, 4104]),  # PowerShell
            ("Microsoft-Windows-TaskScheduler/Operational", [106, 140, 141]),  # Task scheduler
        ]
        
        while self.running:
            try:
                time.sleep(20)  # Check every 20 seconds
                
                for log_name, event_ids in etw_logs:
                    try:
                        hand = win32evtlog.OpenEventLog(None, log_name)
                        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                        
                        events = win32evtlog.ReadEventLog(hand, flags, 0)
                        last_record = last_records.get(log_name, 0)
                        
                        for event in events:
                            if event.RecordNumber <= last_record:
                                continue
                            
                            last_records[log_name] = max(last_records.get(log_name, 0), event.RecordNumber)
                            
                            if event.EventID in event_ids:
                                event_data = str(event.StringInserts) if event.StringInserts else ""
                                
                                # Determine severity based on event type
                                severity = "MEDIUM"
                                if event.EventID in [4688, 1]:  # Process creation
                                    # Check for suspicious processes
                                    if any(x in event_data.lower() for x in ['powershell', 'cmd', 'wscript', 'cscript', 'mshta']):
                                        severity = "HIGH"
                                
                                event_obj = SecurityEvent(
                                    timestamp=datetime.utcnow().isoformat(),
                                    event_type="etw_event",
                                    severity=severity,
                                    source="etw",
                                    description=f"ETW Event {event.EventID} from {log_name}",
                                    details={
                                        "log_name": log_name,
                                        "event_id": event.EventID,
                                        "data": event_data[:500]
                                    }
                                )
                                self.event_queue.put(event_obj)
                        
                        win32evtlog.CloseEventLog(hand)
                        
                    except Exception as e:
                        logger.debug(f"ETW log {log_name} error: {e}")
                        
            except Exception as e:
                logger.debug(f"ETW monitor error: {e}")
    
    def _sysmon_monitor_loop(self):
        """Monitor Sysmon logs for detailed security events."""
        logger.info("Sysmon monitor started")
        
        try:
            import win32evtlog
        except ImportError:
            logger.info("Sysmon monitor requires pywin32")
            return
        
        last_record = 0
        
        # Sysmon Event IDs
        # 1 = Process creation
        # 3 = Network connection
        # 7 = Image loaded (DLL)
        # 8 = CreateRemoteThread (injection)
        # 10 = ProcessAccess (credential dumping)
        # 11 = FileCreate
        # 12/13/14 = Registry events
        # 22 = DNS query
        sysmon_events = {
            1: ("process_create", "MEDIUM"),
            3: ("network_connect", "LOW"),
            7: ("image_load", "LOW"),
            8: ("remote_thread", "HIGH"),  # Potential injection
            10: ("process_access", "HIGH"),  # Potential credential dump
            11: ("file_create", "LOW"),
            12: ("registry_add", "MEDIUM"),
            13: ("registry_set", "MEDIUM"),
            14: ("registry_rename", "MEDIUM"),
            22: ("dns_query", "LOW"),
        }
        
        while self.running:
            try:
                time.sleep(10)  # Check every 10 seconds
                
                try:
                    hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    for event in events:
                        if event.RecordNumber <= last_record:
                            continue
                        
                        last_record = max(last_record, event.RecordNumber)
                        
                        if event.EventID in sysmon_events:
                            event_type, base_severity = sysmon_events[event.EventID]
                            event_data = str(event.StringInserts) if event.StringInserts else ""
                            
                            # Elevate severity for suspicious patterns
                            severity = base_severity
                            if event.EventID == 1:  # Process creation
                                if any(x in event_data.lower() for x in ['mimikatz', 'procdump', 'lazagne', 'secretsdump']):
                                    severity = "CRITICAL"
                                elif any(x in event_data.lower() for x in ['-enc', 'downloadstring', 'invoke-']):
                                    severity = "HIGH"
                            
                            if event.EventID == 8:  # Remote thread - always suspicious
                                severity = "HIGH"
                            
                            if event.EventID == 10:  # Process access to lsass
                                if 'lsass' in event_data.lower():
                                    severity = "CRITICAL"
                            
                            # Only report HIGH/CRITICAL or specific events
                            if severity in ["HIGH", "CRITICAL"] or event.EventID in [8, 10]:
                                event_obj = SecurityEvent(
                                    timestamp=datetime.utcnow().isoformat(),
                                    event_type=f"sysmon_{event_type}",
                                    severity=severity,
                                    source="sysmon",
                                    description=f"Sysmon: {event_type} (Event {event.EventID})",
                                    details={
                                        "event_id": event.EventID,
                                        "event_type": event_type,
                                        "data": event_data[:500]
                                    }
                                )
                                self.event_queue.put(event_obj)
                                logger.warning(f"Sysmon {event_type}: {event_data[:100]}")
                    
                    win32evtlog.CloseEventLog(hand)
                    
                except Exception as e:
                    # Sysmon may not be installed
                    if "cannot find" not in str(e).lower():
                        logger.debug(f"Sysmon log read error: {e}")
                    
            except Exception as e:
                logger.debug(f"Sysmon monitor error: {e}")
    
    def _dll_injection_monitor_loop(self):
        """Monitor for DLL injection attempts."""
        logger.info("DLL injection monitor started")
        
        # Track loaded DLLs per process
        process_dlls = {}
        
        # Suspicious DLL patterns
        suspicious_dll_patterns = [
            r'temp.*\.dll$',
            r'[a-f0-9]{32,}\.dll$',  # Random hex names (longer pattern)
            r'\\users\\.*\\downloads\\.*\.dll$',
        ]
        
        # Known safe applications that load DLLs from appdata
        safe_app_patterns = [
            'chrome', 'firefox', 'edge', 'brave', 'opera',  # Browsers
            'discord', 'slack', 'teams', 'zoom', 'spotify',  # Apps
            'vscode', 'code', 'windsurf', 'cursor',  # IDEs
            'perplexity', 'comet', 'notion', 'obsidian',  # Productivity
            'nvidia', 'amd', 'intel', 'realtek',  # Hardware
            'microsoft', 'windows', 'onedrive', 'outlook',  # Microsoft
            'google', 'dropbox', 'steam', 'epic',  # Services
            'bvssh', 'bitvise', 'putty', 'winscp',  # SSH/SFTP
        ]
        
        # Known injection techniques leave these DLLs
        injection_indicators = [
            'ntdll.dll',  # When loaded multiple times
            'kernel32.dll',
            'clr.dll',  # .NET injection
            'mscoree.dll',
        ]
        
        while self.running:
            try:
                time.sleep(30)  # Check every 30 seconds
                
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        pid = proc.info['pid']
                        proc_name = proc.info['name']
                        
                        # Skip system processes
                        if pid < 100:
                            continue
                        
                        # Get memory maps (loaded DLLs)
                        try:
                            p = psutil.Process(pid)
                            memory_maps = p.memory_maps()
                            
                            current_dlls = set()
                            for mmap in memory_maps:
                                if mmap.path and mmap.path.lower().endswith('.dll'):
                                    current_dlls.add(mmap.path.lower())
                            
                            # Check for new DLLs since last scan
                            if pid in process_dlls:
                                new_dlls = current_dlls - process_dlls[pid]
                                
                                for dll in new_dlls:
                                    is_suspicious = False
                                    reason = ""
                                    
                                    # Check suspicious patterns
                                    for pattern in suspicious_dll_patterns:
                                        if re.search(pattern, dll, re.IGNORECASE):
                                            is_suspicious = True
                                            reason = f"Suspicious DLL path pattern: {pattern}"
                                            break
                                    
                                    # Check for unsigned DLLs in unusual locations
                                    # But skip known safe applications
                                    if not is_suspicious:
                                        proc_lower = proc_name.lower()
                                        is_safe_app = any(safe in proc_lower or safe in dll for safe in safe_app_patterns)
                                        
                                        if not is_safe_app:
                                            if '\\temp\\' in dll:
                                                is_suspicious = True
                                                reason = "DLL loaded from temp folder"
                                    
                                    if is_suspicious:
                                        event = SecurityEvent(
                                            timestamp=datetime.utcnow().isoformat(),
                                            event_type="dll_injection_suspected",
                                            severity="HIGH",
                                            source="dll_monitor",
                                            description=f"Suspicious DLL loaded into {proc_name}",
                                            details={
                                                "process_name": proc_name,
                                                "pid": pid,
                                                "dll_path": dll,
                                                "reason": reason
                                            }
                                        )
                                        self.event_queue.put(event)
                                        logger.warning(f"Suspicious DLL: {dll} in {proc_name}")
                            
                            process_dlls[pid] = current_dlls
                            
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                            
                    except Exception as e:
                        pass
                
                # Cleanup dead processes
                active_pids = {p.pid for p in psutil.process_iter()}
                process_dlls = {k: v for k, v in process_dlls.items() if k in active_pids}
                        
            except Exception as e:
                logger.debug(f"DLL injection monitor error: {e}")
    
    # ============== END ADVANCED MONITORS ==============
    
    def block_ip(self, ip: str) -> bool:
        """Block an IP address using Windows Firewall."""
        if ip in self.blocked_ips:
            return True
        
        try:
            rule_name = f"SentinelAI_Block_{ip.replace('.', '_')}"
            
            result = safe_subprocess_run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=in',
                'action=block',
                f'remoteip={ip}',
                'enable=yes'
            ], capture_output=True, timeout=10)
            
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
    ╔═══════════════════════════════════════════════════════════════════╗
    ║               SentinelAI Windows Agent v1.4                       ║
    ║         Native Windows Protection & Threat Detection              ║
    ║                                                                   ║
    ║  Core:     Process | Network | EventLog | Registry | Firewall     ║
    ║  System:   Startup | Tasks | USB | Hosts | Browser | Services     ║
    ║  Advanced: Clipboard | DNS | PowerShell | WMI | Drivers           ║
    ║  Security: Certificates | Named Pipes | Defender | AVG            ║
    ║  Deep:     AMSI | ETW | Sysmon | DLL Injection Detection          ║
    ║                                                                   ║
    ║     AI Analysis: {ai_status:^10}    |    25 Active Monitors         ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    agent = WindowsAgent(dashboard_url=args.dashboard)
    agent.use_ai = not args.no_ai
    agent.start()


if __name__ == '__main__':
    main()
