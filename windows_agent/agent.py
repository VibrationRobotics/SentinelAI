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

# Import local ML detector (legacy)
try:
    from ml_detector import HybridThreatDetector, get_detector
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# Import Advanced ML v2.0
try:
    from ml import AdvancedThreatDetector, get_advanced_detector, ThreatPrediction
    from ml.training_data import generate_and_train
    ADVANCED_ML_AVAILABLE = True
except ImportError:
    ADVANCED_ML_AVAILABLE = False

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
    
    def __init__(self, dashboard_url: str = "http://localhost:8015", api_key: str = None):
        self.dashboard_url = dashboard_url.rstrip('/')
        self.api_base = f"{self.dashboard_url}/api/v1"
        self.api_key = api_key or os.environ.get('SENTINEL_API_KEY')
        self.running = False
        self.event_queue = queue.Queue()
        
        # Log API key status
        if self.api_key:
            logger.info(f"API key configured: {self.api_key[:12]}...")
        else:
            logger.warning("No API key configured - using unauthenticated mode")
        
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
        
        # Hybrid ML/Rule-based detector (legacy - reduces OpenAI costs by 95%+)
        self.hybrid_detector = get_detector(use_ai=self.use_ai) if ML_AVAILABLE else None
        
        # Advanced ML v2.0 detector (150+ features, behavioral analysis, anomaly detection)
        self.advanced_detector = None
        if ADVANCED_ML_AVAILABLE:
            try:
                self.advanced_detector = get_advanced_detector(use_ai=self.use_ai)
                logger.info("Advanced ML v2.0 detector initialized")
            except Exception as e:
                logger.warning(f"Could not initialize Advanced ML: {e}")
        
        logger.info(f"Windows Agent initialized - Dashboard: {self.dashboard_url}")
        logger.info(f"AI-powered analysis: {'Enabled' if self.use_ai else 'Disabled'}")
        logger.info(f"Advanced ML v2.0: {'Enabled' if self.advanced_detector else 'Disabled'}")
        logger.info(f"Legacy ML detector: {'Enabled' if self.hybrid_detector else 'Disabled'}")
    
    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers including API key if configured."""
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['X-API-Key'] = self.api_key
        return headers
    
    def _api_post(self, endpoint: str, data: Dict, timeout: int = 10) -> Optional[requests.Response]:
        """Make authenticated POST request to API."""
        try:
            return requests.post(
                f"{self.api_base}/{endpoint}",
                json=data,
                headers=self._get_headers(),
                timeout=timeout
            )
        except Exception as e:
            logger.debug(f"API request failed: {e}")
            return None
    
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
        """Send periodic heartbeat to dashboard and poll for commands."""
        while self.running:
            try:
                time.sleep(30)  # Send heartbeat every 30 seconds
                self._register_agent()  # Re-register acts as heartbeat
                self._poll_and_execute_commands()  # Check for pending commands
            except Exception as e:
                logger.debug(f"Heartbeat error: {e}")
    
    def _poll_and_execute_commands(self):
        """Poll dashboard for pending commands and execute them."""
        try:
            hostname = platform.node()
            response = requests.get(
                f"{self.api_base}/windows/agent/{hostname}/commands",
                headers=self._get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                commands = data.get("commands", [])
                
                for cmd in commands:
                    self._execute_command(cmd)
            elif response.status_code == 401:
                logger.debug("Command poll: API key required")
            elif response.status_code != 404:
                logger.debug(f"Command poll returned: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            logger.debug(f"Command poll error: {e}")
        except Exception as e:
            logger.error(f"Command execution error: {e}")
    
    def _execute_command(self, cmd: Dict[str, Any]):
        """Execute a command from the dashboard."""
        command_id = cmd.get("id")
        command_type = cmd.get("command_type")
        target = cmd.get("target")
        parameters = cmd.get("parameters", {})
        
        logger.info(f"Executing command {command_id}: {command_type} -> {target}")
        
        result = {"status": "failed", "error": "Unknown command type"}
        
        try:
            if command_type == "block_ip":
                success = self.block_ip(target)
                result = {"status": "success" if success else "failed", "result": f"IP {target} blocked" if success else "Failed to block IP"}
            
            elif command_type == "kill_process":
                success = self._kill_process(int(target))
                result = {"status": "success" if success else "failed", "result": f"Process {target} terminated" if success else "Failed to kill process"}
            
            elif command_type == "quarantine_file":
                success = self._quarantine_file(target)
                result = {"status": "success" if success else "failed", "result": f"File {target} quarantined" if success else "Failed to quarantine file"}
            
            elif command_type == "unblock_ip":
                success = self._unblock_ip(target)
                result = {"status": "success" if success else "failed", "result": f"IP {target} unblocked" if success else "Failed to unblock IP"}
            
            elif command_type == "scan_path":
                # Trigger a scan of a specific path
                scan_result = self._scan_path(target)
                result = {"status": "success", "result": scan_result}
            
            elif command_type == "get_system_info":
                # Return current system info
                sys_info = self._get_system_info()
                result = {"status": "success", "result": sys_info}
            
            elif command_type == "list_connections":
                # List current network connections
                connections = self._list_connections()
                result = {"status": "success", "result": connections}
            
            elif command_type == "list_processes":
                # List running processes
                processes = self._list_processes()
                result = {"status": "success", "result": processes}
            
            else:
                result = {"status": "failed", "error": f"Unknown command type: {command_type}"}
            
            logger.info(f"Command {command_id} result: {result['status']}")
            
        except Exception as e:
            result = {"status": "failed", "error": str(e)}
            logger.error(f"Command {command_id} failed: {e}")
        
        # Report result back to dashboard
        self._report_command_result(command_id, result)
    
    def _report_command_result(self, command_id: int, result: Dict[str, Any]):
        """Report command execution result to dashboard."""
        try:
            hostname = platform.node()
            response = requests.post(
                f"{self.api_base}/windows/agent/{hostname}/commands/result",
                json={
                    "command_id": command_id,
                    "status": result.get("status", "failed"),
                    "result": result.get("result"),
                    "error": result.get("error")
                },
                headers=self._get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                logger.debug(f"Command {command_id} result reported successfully")
            else:
                logger.warning(f"Failed to report command result: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error reporting command result: {e}")
    
    def _kill_process(self, pid: int) -> bool:
        """Kill a process by PID."""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.terminate()
            proc.wait(timeout=5)
            logger.info(f"Terminated process {pid} ({proc_name})")
            return True
        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} not found")
            return False
        except psutil.AccessDenied:
            logger.error(f"Access denied killing process {pid}")
            return False
        except Exception as e:
            logger.error(f"Error killing process {pid}: {e}")
            return False
    
    def _quarantine_file(self, file_path: str) -> bool:
        """Quarantine a file by moving it to a quarantine folder."""
        try:
            if not os.path.exists(file_path):
                logger.warning(f"File not found: {file_path}")
                return False
            
            # Create quarantine folder
            quarantine_dir = os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'SentinelAI', 'Quarantine')
            os.makedirs(quarantine_dir, exist_ok=True)
            
            # Generate unique quarantine name
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            original_name = os.path.basename(file_path)
            quarantine_name = f"{timestamp}_{original_name}.quarantine"
            quarantine_path = os.path.join(quarantine_dir, quarantine_name)
            
            # Move file to quarantine
            import shutil
            shutil.move(file_path, quarantine_path)
            
            # Log the quarantine action
            logger.info(f"Quarantined file: {file_path} -> {quarantine_path}")
            
            # Save metadata
            metadata_path = quarantine_path + ".meta"
            with open(metadata_path, 'w') as f:
                json.dump({
                    "original_path": file_path,
                    "quarantine_time": datetime.now().isoformat(),
                    "quarantine_path": quarantine_path
                }, f)
            
            return True
        except Exception as e:
            logger.error(f"Error quarantining file {file_path}: {e}")
            return False
    
    def _unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address from Windows Firewall."""
        try:
            rule_name = f"SentinelAI_Block_{ip.replace('.', '_')}"
            
            result = safe_subprocess_run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}'
            ], capture_output=True, timeout=10)
            
            if result.returncode == 0:
                self.blocked_ips.discard(ip)
                logger.info(f"Unblocked IP: {ip}")
                return True
            else:
                logger.warning(f"Failed to unblock IP {ip}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error unblocking IP {ip}: {e}")
            return False
    
    def _scan_path(self, path: str) -> Dict[str, Any]:
        """Scan a path for suspicious files."""
        results = {
            "path": path,
            "scanned_files": 0,
            "suspicious_files": [],
            "errors": []
        }
        
        try:
            if not os.path.exists(path):
                results["errors"].append(f"Path not found: {path}")
                return results
            
            # Suspicious file extensions
            suspicious_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.scr']
            
            # Scan directory or single file
            if os.path.isfile(path):
                files_to_scan = [path]
            else:
                files_to_scan = []
                for root, dirs, files in os.walk(path):
                    for f in files[:1000]:  # Limit to 1000 files
                        files_to_scan.append(os.path.join(root, f))
            
            for file_path in files_to_scan:
                try:
                    results["scanned_files"] += 1
                    ext = os.path.splitext(file_path)[1].lower()
                    
                    # Check for suspicious extensions in unusual locations
                    if ext in suspicious_extensions:
                        # Check if in temp or downloads
                        lower_path = file_path.lower()
                        if 'temp' in lower_path or 'tmp' in lower_path or 'download' in lower_path:
                            results["suspicious_files"].append({
                                "path": file_path,
                                "reason": f"Executable in suspicious location",
                                "extension": ext
                            })
                except Exception as e:
                    results["errors"].append(f"Error scanning {file_path}: {str(e)}")
            
            logger.info(f"Scan complete: {results['scanned_files']} files, {len(results['suspicious_files'])} suspicious")
            
        except Exception as e:
            results["errors"].append(str(e))
            logger.error(f"Scan error: {e}")
        
        return results
    
    def _list_connections(self) -> List[Dict[str, Any]]:
        """List current network connections."""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    proc_name = "Unknown"
                    if conn.pid:
                        try:
                            proc_name = psutil.Process(conn.pid).name()
                        except:
                            pass
                    
                    conn_info = {
                        "status": conn.status,
                        "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        "pid": conn.pid,
                        "process": proc_name
                    }
                    connections.append(conn_info)
                except:
                    pass
        except Exception as e:
            logger.error(f"Error listing connections: {e}")
        
        return connections[:100]  # Limit to 100
    
    def _list_processes(self) -> List[Dict[str, Any]]:
        """List running processes."""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    info = proc.info
                    processes.append({
                        "pid": info['pid'],
                        "name": info['name'],
                        "username": info['username'],
                        "cpu_percent": info['cpu_percent'],
                        "memory_percent": round(info['memory_percent'], 2) if info['memory_percent'] else 0
                    })
                except:
                    pass
        except Exception as e:
            logger.error(f"Error listing processes: {e}")
        
        # Sort by CPU usage and return top 50
        processes.sort(key=lambda x: x.get('cpu_percent', 0) or 0, reverse=True)
        return processes[:50]
    
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
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Gather comprehensive system information for dashboard display."""
        info = {}
        
        try:
            # CPU info
            info['cpu'] = {
                'cores_physical': psutil.cpu_count(logical=False),
                'cores_logical': psutil.cpu_count(logical=True),
                'usage_percent': psutil.cpu_percent(interval=0.1),
                'frequency_mhz': psutil.cpu_freq().current if psutil.cpu_freq() else 0
            }
            
            # Try to get CPU name
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                    r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
                info['cpu']['name'] = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
                winreg.CloseKey(key)
            except:
                info['cpu']['name'] = platform.processor()
            
            # Memory info
            mem = psutil.virtual_memory()
            info['memory'] = {
                'total_gb': round(mem.total / (1024**3), 2),
                'available_gb': round(mem.available / (1024**3), 2),
                'used_gb': round(mem.used / (1024**3), 2),
                'percent_used': mem.percent
            }
            
            # Disk info
            disks = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disks.append({
                        'drive': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total_gb': round(usage.total / (1024**3), 2),
                        'used_gb': round(usage.used / (1024**3), 2),
                        'free_gb': round(usage.free / (1024**3), 2),
                        'percent_used': usage.percent
                    })
                except:
                    pass
            info['disks'] = disks
            
            # Network interfaces
            interfaces = []
            for iface, addrs in psutil.net_if_addrs().items():
                iface_info = {'name': iface, 'addresses': []}
                for addr in addrs:
                    if addr.family.name == 'AF_INET':
                        iface_info['addresses'].append({
                            'type': 'IPv4',
                            'address': addr.address,
                            'netmask': addr.netmask
                        })
                    elif addr.family.name == 'AF_INET6':
                        iface_info['addresses'].append({
                            'type': 'IPv6',
                            'address': addr.address
                        })
                if iface_info['addresses']:
                    interfaces.append(iface_info)
            info['network_interfaces'] = interfaces
            
            # Get public IP
            try:
                public_ip = requests.get('https://api.ipify.org', timeout=3).text
                info['public_ip'] = public_ip
                # Store for auto-block whitelist
                self._own_public_ip = public_ip
            except:
                info['public_ip'] = 'Unknown'
            
            # Boot time
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            info['boot_time'] = boot_time.isoformat()
            info['uptime_hours'] = round(uptime.total_seconds() / 3600, 1)
            
            # Current user
            info['current_user'] = os.getlogin() if hasattr(os, 'getlogin') else os.environ.get('USERNAME', 'Unknown')
            
            # Process count
            info['process_count'] = len(list(psutil.process_iter()))
            
            # Active connections count
            try:
                connections = psutil.net_connections(kind='inet')
                info['connections'] = {
                    'total': len(connections),
                    'established': len([c for c in connections if c.status == 'ESTABLISHED']),
                    'listening': len([c for c in connections if c.status == 'LISTEN'])
                }
            except:
                info['connections'] = {'total': 0, 'established': 0, 'listening': 0}
            
            # Installed security software
            security_software = []
            try:
                result = safe_subprocess_run(
                    ['powershell', '-Command', 
                     'Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName | ConvertTo-Json'],
                    timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    av_data = json.loads(result.stdout)
                    if isinstance(av_data, dict):
                        av_data = [av_data]
                    for av in av_data:
                        if av.get('displayName'):
                            security_software.append(av['displayName'])
            except:
                pass
            info['security_software'] = security_software
            
            # Firewall status
            try:
                result = safe_subprocess_run(
                    ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                    timeout=5
                )
                info['firewall_enabled'] = 'ON' in result.stdout.upper() if result.returncode == 0 else False
            except:
                info['firewall_enabled'] = False
            
            # Listening ports summary
            listening_ports = []
            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'LISTEN' and conn.laddr:
                        port = conn.laddr.port
                        proc_name = 'Unknown'
                        if conn.pid:
                            try:
                                proc_name = psutil.Process(conn.pid).name()
                            except:
                                pass
                        listening_ports.append({'port': port, 'process': proc_name})
            except:
                pass
            info['listening_ports'] = listening_ports[:50]  # Limit to 50
            
            # Blocked IPs count
            info['blocked_ips_count'] = len(self.blocked_ips) if hasattr(self, 'blocked_ips') else 0
            
        except Exception as e:
            logger.debug(f"Error gathering system info: {e}")
        
        return info
    
    def _register_agent(self):
        """Register this agent with the dashboard including full system info."""
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
            
            # Gather comprehensive system info
            system_info = self._get_system_info()
            
            data = {
                'hostname': platform.node(),
                'platform': platform.system(),
                'platform_version': windows_version,
                'agent_version': '1.5.0',
                'is_admin': is_admin,
                'capabilities': [
                    'process', 'network', 'network_inbound', 'eventlog', 'firewall', 'ai', 
                    'registry', 'startup', 'tasks', 'usb', 'hosts', 'browser',
                    'clipboard', 'dns', 'powershell', 'wmi', 'services',
                    'drivers', 'firewall_rules', 'certificates', 'named_pipes', 'defender',
                    'amsi', 'etw', 'sysmon', 'dll_injection', 'brute_force', 'port_scan',
                    'auto_block', 'command_execution'
                ],
                'system_info': system_info
            }
            
            response = requests.post(
                f"{self.api_base}/windows/agent/register",
                json=data,
                headers=self._get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Successfully registered with dashboard")
            elif response.status_code == 401:
                logger.error("API key rejected - check your SENTINEL_API_KEY is valid")
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
                
                # Step 1: Use Advanced ML v2.0 if available (150+ features, behavioral, anomaly)
                should_use_openai = False
                local_analysis = None
                advanced_analysis = None
                
                if self.advanced_detector:
                    try:
                        prediction = self.advanced_detector.analyze(event.details, event.event_type)
                        
                        advanced_analysis = {
                            'method': 'advanced_ml_v2',
                            'is_threat': prediction.is_threat,
                            'confidence': prediction.confidence,
                            'threat_type': prediction.threat_type,
                            'severity': prediction.severity,
                            'reason': prediction.reason,
                            'mitre_techniques': prediction.mitre_techniques,
                            'anomaly_score': prediction.anomaly_score,
                            'behavioral_score': prediction.behavioral_score,
                            'attack_chains': prediction.attack_chains[:2] if prediction.attack_chains else [],
                            'model_scores': prediction.model_scores,
                        }
                        
                        # Use Advanced ML result
                        local_analysis = advanced_analysis
                        should_use_openai = prediction.needs_ai_review
                        
                        # Update event severity based on ML prediction
                        if prediction.is_threat and prediction.confidence > 0.6:
                            if prediction.severity in ['CRITICAL', 'HIGH']:
                                event.severity = prediction.severity
                        elif not prediction.is_threat and prediction.confidence > 0.7:
                            if event.severity in ['HIGH', 'CRITICAL']:
                                event.severity = 'LOW'
                                logger.debug(f"Advanced ML marked safe: {event.event_type}")
                        
                        event.details['advanced_ml_analysis'] = advanced_analysis
                        
                    except Exception as e:
                        logger.debug(f"Advanced ML error: {e}")
                
                # Step 1b: Fallback to legacy hybrid detector if Advanced ML not available
                if not local_analysis and self.hybrid_detector:
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
                    # Include hostname and process info for autonomous response
                    payload_data = event.details.copy()
                    payload_data['hostname'] = platform.node()
                    if 'pid' in event.details:
                        payload_data['process_info'] = {'pid': event.details.get('pid')}
                    if 'file_path' in event.details:
                        payload_data['file_path'] = event.details.get('file_path')
                    
                    response = requests.post(
                        f"{self.api_base}/threats/analyze",
                        json={
                            'source_ip': event.ip_address or '127.0.0.1',
                            'threat_type': event.event_type,
                            'severity': event.severity,
                            'description': event.description,
                            'payload': json.dumps(payload_data),
                            'timestamp': event.timestamp,
                            'agent_source': 'windows_agent',
                            'hostname': platform.node(),
                            'ai_analyzed': ai_result is not None,
                            'ml_analyzed': local_analysis is not None,
                            'request_ai_analysis': should_use_openai and event.severity in ['HIGH', 'CRITICAL']
                        },
                        headers=self._get_headers(),
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
        """Monitor network connections for suspicious activity (outbound + inbound)."""
        logger.info("Network monitor started (outbound + inbound monitoring)")
        
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
                
                # Monitor LISTENING ports and INBOUND connections
                self._check_inbound_connections(connections)
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Network monitor error: {e}")
                time.sleep(10)
    
    def _check_inbound_connections(self, connections):
        """Monitor inbound connections - critical for servers hosting services."""
        # Track connection counts per IP for rate limiting detection
        if not hasattr(self, '_inbound_tracker'):
            self._inbound_tracker = {}  # {ip: {'count': n, 'first_seen': time, 'ports': set()}}
            self._known_listening_ports = set()
            self._inbound_alerts = set()  # Prevent duplicate alerts
        
        current_time = time.time()
        
        # Clean old tracking data (older than 5 minutes)
        old_ips = [ip for ip, data in self._inbound_tracker.items() 
                   if current_time - data['first_seen'] > 300]
        for ip in old_ips:
            del self._inbound_tracker[ip]
        
        # Clear old alerts (older than 10 minutes)
        self._inbound_alerts = {a for a in self._inbound_alerts 
                                if current_time - a[1] < 600}
        
        # Known safe/expected ports for your server
        expected_server_ports = {
            80, 443,      # HTTP/HTTPS
            8000, 8080, 8443, 8015,  # Common app ports
            3000, 3001, 5000, 5173,  # Dev servers (React, Flask, Vite)
            22,           # SSH
            3306, 5432,   # MySQL, PostgreSQL
            6379,         # Redis
            27017,        # MongoDB
        }
        
        # Suspicious inbound ports (shouldn't have external connections)
        dangerous_inbound_ports = {
            445,    # SMB - ransomware target
            135, 139,  # RPC/NetBIOS
            1433, 1434,  # MSSQL
            3389,   # RDP - brute force target
            5985, 5986,  # WinRM
            23,     # Telnet
            21,     # FTP
            4444, 5555, 1337, 31337,  # Reverse shell ports
        }
        
        # Track listening ports
        listening_ports = set()
        for conn in connections:
            if conn.status == 'LISTEN' and conn.laddr:
                listening_ports.add(conn.laddr.port)
        
        # Alert on new listening ports (potential backdoor)
        new_listeners = listening_ports - self._known_listening_ports
        for port in new_listeners:
            if port not in expected_server_ports:
                alert_key = (f"new_listener_{port}", current_time)
                if not any(k[0] == f"new_listener_{port}" for k in self._inbound_alerts):
                    # Get process info
                    proc_name = "Unknown"
                    for conn in connections:
                        if conn.status == 'LISTEN' and conn.laddr and conn.laddr.port == port:
                            if conn.pid:
                                try:
                                    proc_name = psutil.Process(conn.pid).name()
                                except:
                                    pass
                            break
                    
                    event = SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type='new_listening_port',
                        severity='MEDIUM',
                        source='network_inbound',
                        description=f"New listening port detected: {port} ({proc_name})",
                        details={
                            'port': port,
                            'process': proc_name,
                            'expected_ports': list(expected_server_ports)
                        }
                    )
                    self._send_event(event)
                    self._inbound_alerts.add(alert_key)
                    logger.info(f"New listening port: {port} ({proc_name})")
        
        self._known_listening_ports = listening_ports
        
        # Check inbound ESTABLISHED connections
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                local_port = conn.laddr.port
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                
                # Skip localhost
                if remote_ip in ['127.0.0.1', '::1', 'localhost']:
                    continue
                
                # Skip private IPs for some checks (but still track)
                is_private = (remote_ip.startswith('192.168.') or 
                             remote_ip.startswith('10.') or 
                             remote_ip.startswith('172.16.') or
                             remote_ip.startswith('172.17.') or
                             remote_ip.startswith('172.18.'))
                
                # Track this IP
                if remote_ip not in self._inbound_tracker:
                    self._inbound_tracker[remote_ip] = {
                        'count': 0,
                        'first_seen': current_time,
                        'ports': set(),
                        'is_private': is_private
                    }
                
                self._inbound_tracker[remote_ip]['count'] += 1
                self._inbound_tracker[remote_ip]['ports'].add(local_port)
                
                # Check for dangerous inbound ports
                if local_port in dangerous_inbound_ports:
                    alert_key = (f"dangerous_inbound_{remote_ip}_{local_port}", current_time)
                    if not any(k[0] == f"dangerous_inbound_{remote_ip}_{local_port}" for k in self._inbound_alerts):
                        proc_name = "Unknown"
                        if conn.pid:
                            try:
                                proc_name = psutil.Process(conn.pid).name()
                            except:
                                pass
                        
                        severity = 'CRITICAL' if local_port in [445, 3389, 4444] else 'HIGH'
                        
                        event = SecurityEvent(
                            timestamp=datetime.utcnow().isoformat(),
                            event_type='dangerous_inbound_connection',
                            severity=severity,
                            source='network_inbound',
                            description=f"Dangerous inbound connection on port {local_port} from {remote_ip}",
                            details={
                                'remote_ip': remote_ip,
                                'remote_port': remote_port,
                                'local_port': local_port,
                                'process': proc_name,
                                'pid': conn.pid,
                                'port_service': self._get_port_service(local_port)
                            },
                            ip_address=remote_ip
                        )
                        self._send_event(event)
                        self._inbound_alerts.add(alert_key)
                        logger.warning(f"DANGEROUS INBOUND: {remote_ip} -> port {local_port} ({proc_name})")
                        
                        # AUTO-BLOCK dangerous inbound connections from external IPs
                        if not is_private:
                            self._auto_block_threat(remote_ip, f"Dangerous port access: {self._get_port_service(local_port)}")
        
        # Check for port scanning (10+ ports from same external IP = suspicious)
        # Note: Many legitimate services (CDNs, cloud apps) use multiple ports
        for ip, data in self._inbound_tracker.items():
            # Skip private IPs for port scan detection (internal network is usually OK)
            if data.get('is_private'):
                continue
            
            # Skip own public IP
            if hasattr(self, '_own_public_ip') and ip == self._own_public_ip:
                continue
            
            # Skip known cloud providers (they legitimately use many ports)
            cloud_prefixes = [
                '35.', '34.', '142.250.', '172.217.',  # Google
                '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.', '104.23.', '104.24.', '104.25.', '104.26.', '104.27.', '104.28.', '104.29.', '104.30.', '104.31.',  # Cloudflare
                '172.64.', '172.65.', '172.66.', '172.67.',  # Cloudflare
                '20.', '40.', '52.', '13.', '23.',  # Microsoft Azure
                '151.101.',  # Fastly
                '185.199.',  # GitHub
                '138.68.', '167.172.', '138.197.', '159.65.', '165.22.', '68.183.', '134.209.', '157.245.', '164.90.',  # DigitalOcean
                '18.', '54.', '52.', '3.',  # AWS
                '199.232.',  # Fastly/Verizon
            ]
            if any(ip.startswith(prefix) for prefix in cloud_prefixes):
                continue
                
            num_ports = len(data['ports'])
            
            # 10+ ports = suspicious probing, 20+ = definite scan
            if num_ports >= 10:
                alert_key = (f"port_scan_{ip}", current_time)
                if not any(k[0] == f"port_scan_{ip}" for k in self._inbound_alerts):
                    severity = 'CRITICAL' if num_ports >= 20 else 'HIGH'
                    
                    event = SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type='port_scan_detected',
                        severity=severity,
                        source='network_inbound',
                        description=f"Port scan from {ip} - {num_ports} ports probed (AUTO-BLOCKING)",
                        details={
                            'remote_ip': ip,
                            'ports_scanned': list(data['ports']),
                            'connection_count': data['count'],
                            'duration_seconds': current_time - data['first_seen'],
                            'action': 'auto_blocked'
                        },
                        ip_address=ip
                    )
                    self._send_event(event)
                    self._inbound_alerts.add(alert_key)
                    logger.warning(f"PORT SCAN DETECTED: {ip} scanned {num_ports} ports - AUTO-BLOCKING")
                    
                    # AUTO-BLOCK the scanner
                    self._auto_block_threat(ip, f"Port scan: {num_ports} ports probed")
        
        # Check for connection flooding (many connections from same IP)
        for ip, data in self._inbound_tracker.items():
            if data.get('is_private'):
                continue
                
            duration = current_time - data['first_seen']
            if duration > 0 and data['count'] / duration > 5:  # More than 5 conn/sec = flood
                alert_key = (f"conn_flood_{ip}", current_time)
                if not any(k[0] == f"conn_flood_{ip}" for k in self._inbound_alerts):
                    rate = data['count'] / duration
                    severity = 'CRITICAL' if rate > 20 else 'HIGH'
                    
                    event = SecurityEvent(
                        timestamp=datetime.utcnow().isoformat(),
                        event_type='connection_flood',
                        severity=severity,
                        source='network_inbound',
                        description=f"Connection flood from {ip} - {data['count']} connections in {duration:.1f}s (AUTO-BLOCKING)",
                        details={
                            'remote_ip': ip,
                            'connection_count': data['count'],
                            'duration_seconds': duration,
                            'rate_per_second': rate,
                            'action': 'auto_blocked'
                        },
                        ip_address=ip
                    )
                    self._send_event(event)
                    self._inbound_alerts.add(alert_key)
                    logger.warning(f"CONNECTION FLOOD: {ip} - {data['count']} connections - AUTO-BLOCKING")
                    
                    # AUTO-BLOCK the flooder
                    self._auto_block_threat(ip, f"Connection flood: {rate:.1f} conn/sec")
    
    def _auto_block_threat(self, ip: str, reason: str):
        """Automatically block a threatening IP address."""
        try:
            # Skip if already blocked
            if ip in self.blocked_ips:
                return
            
            # Skip private IPs
            if (ip.startswith('192.168.') or ip.startswith('10.') or 
                ip.startswith('172.16.') or ip.startswith('172.17.') or
                ip.startswith('127.') or ip == 'localhost'):
                logger.debug(f"Skipping auto-block for private IP: {ip}")
                return
            
            # Skip our own public IP (get from system_info if available)
            if hasattr(self, '_own_public_ip') and ip == self._own_public_ip:
                logger.debug(f"Skipping auto-block for own public IP: {ip}")
                return
            
            # Known safe IPs (Google, Microsoft, Cloudflare, AWS, DigitalOcean, etc.)
            safe_prefixes = [
                '35.', '34.', '142.250.', '172.217.',  # Google Cloud/Services
                '20.', '40.', '52.', '13.', '23.',  # Microsoft Azure
                '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.', '104.23.', '104.24.', '104.25.', '104.26.', '104.27.', '104.28.', '104.29.', '104.30.', '104.31.',  # Cloudflare
                '172.64.', '172.65.', '172.66.', '172.67.',  # Cloudflare
                '151.101.',  # Fastly/Reddit
                '185.199.',  # GitHub
                '138.68.', '167.172.', '138.197.', '159.65.', '165.22.', '68.183.', '134.209.', '157.245.', '164.90.',  # DigitalOcean
                '18.', '54.', '3.',  # AWS
                '199.232.',  # Fastly/Verizon
            ]
            if any(ip.startswith(prefix) for prefix in safe_prefixes):
                logger.debug(f"Skipping auto-block for known safe IP range: {ip}")
                return
            
            # Block the IP
            success = self.block_ip(ip)
            
            if success:
                logger.warning(f"AUTO-BLOCKED {ip}: {reason}")
                
                # Send event about the auto-block
                event = SecurityEvent(
                    timestamp=datetime.utcnow().isoformat(),
                    event_type='auto_block_executed',
                    severity='HIGH',
                    source='autonomous_response',
                    description=f"Automatically blocked {ip}: {reason}",
                    details={
                        'blocked_ip': ip,
                        'reason': reason,
                        'action': 'firewall_rule_added'
                    },
                    ip_address=ip
                )
                self._send_event(event)
                
                # Gather intelligence about the attacker (async, non-blocking)
                self._handle_attacker_detected(ip, reason)
            else:
                logger.error(f"Failed to auto-block {ip}")
                
        except Exception as e:
            logger.error(f"Auto-block error for {ip}: {e}")
    
    def _get_port_service(self, port: int) -> str:
        """Get common service name for a port."""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 1434: 'MSSQL-UDP', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5985: 'WinRM-HTTP', 5986: 'WinRM-HTTPS',
            6379: 'Redis', 8080: 'HTTP-Proxy', 27017: 'MongoDB',
            4444: 'Metasploit', 5555: 'Android-ADB', 1337: 'Backdoor'
        }
        return services.get(port, f'Port-{port}')
    
    def _event_log_monitor_loop(self):
        """Monitor Windows Event Logs for security events with brute force detection."""
        logger.info("Event log monitor started (with brute force detection)")
        
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
        
        # Brute force tracking
        failed_logins = {}  # {ip_or_user: {'count': n, 'first_seen': time}}
        brute_force_alerts = set()  # Prevent duplicate alerts
        
        while self.running:
            try:
                current_time = time.time()
                
                # Clean old tracking data (older than 10 minutes)
                old_keys = [k for k, v in failed_logins.items() 
                           if current_time - v['first_seen'] > 600]
                for k in old_keys:
                    del failed_logins[k]
                
                # Clear old alerts
                brute_force_alerts = {a for a in brute_force_alerts 
                                     if current_time - a[1] < 1800}  # 30 min cooldown
                
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
                            message = evt.get('Message', '') or ''
                            
                            if event_id in security_events:
                                event_name, severity = security_events[event_id]
                                
                                # Track failed logons for brute force detection
                                if event_id == 4625:
                                    # Extract source IP from message
                                    source_ip = None
                                    target_user = None
                                    
                                    # Parse message for IP and username
                                    import re
                                    ip_match = re.search(r'Source Network Address:\s*(\d+\.\d+\.\d+\.\d+)', message)
                                    user_match = re.search(r'Account Name:\s*(\S+)', message)
                                    
                                    if ip_match:
                                        source_ip = ip_match.group(1)
                                    if user_match:
                                        target_user = user_match.group(1)
                                    
                                    # Track by IP if available, otherwise by user
                                    track_key = source_ip or target_user or 'unknown'
                                    
                                    if track_key not in failed_logins:
                                        failed_logins[track_key] = {
                                            'count': 0,
                                            'first_seen': current_time,
                                            'users': set(),
                                            'ips': set()
                                        }
                                    
                                    failed_logins[track_key]['count'] += 1
                                    if target_user:
                                        failed_logins[track_key]['users'].add(target_user)
                                    if source_ip:
                                        failed_logins[track_key]['ips'].add(source_ip)
                                    
                                    # Check for brute force (5+ failures in tracking window)
                                    if failed_logins[track_key]['count'] >= 5:
                                        alert_key = (f"brute_force_{track_key}", current_time)
                                        if not any(k[0] == f"brute_force_{track_key}" for k in brute_force_alerts):
                                            severity = 'CRITICAL'
                                            
                                            event = SecurityEvent(
                                                timestamp=datetime.utcnow().isoformat(),
                                                event_type='brute_force_attack',
                                                severity=severity,
                                                source='eventlog',
                                                description=f"Brute force attack detected: {failed_logins[track_key]['count']} failed logins from {track_key}",
                                                details={
                                                    'source': track_key,
                                                    'failed_count': failed_logins[track_key]['count'],
                                                    'target_users': list(failed_logins[track_key]['users']),
                                                    'source_ips': list(failed_logins[track_key]['ips']),
                                                    'duration_seconds': current_time - failed_logins[track_key]['first_seen']
                                                },
                                                ip_address=source_ip
                                            )
                                            self._send_event(event)
                                            brute_force_alerts.add(alert_key)
                                            logger.warning(f"BRUTE FORCE ATTACK: {failed_logins[track_key]['count']} failed logins from {track_key}")
                                            
                                            # AUTO-BLOCK brute force attacker if we have their IP
                                            if source_ip and not source_ip.startswith('127.'):
                                                self._auto_block_threat(source_ip, f"Brute force: {failed_logins[track_key]['count']} failed logins")
                                            
                                            continue  # Don't send individual failed login event
                                    
                                    severity = 'HIGH'
                                
                                event = SecurityEvent(
                                    timestamp=datetime.utcnow().isoformat(),
                                    event_type=f'windows_event_{event_id}',
                                    severity=severity,
                                    source='eventlog',
                                    description=f"{event_name} (Event ID: {event_id})",
                                    details={
                                        'event_id': event_id,
                                        'message': message[:500]
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
        """Block an IP address using Windows Firewall. Requires Administrator privileges."""
        if ip in self.blocked_ips:
            return True
        
        # Check if running as admin
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            is_admin = False
        
        if not is_admin:
            logger.warning(f"Cannot block IP {ip} - Agent not running as Administrator. Run run_agent.bat as Admin to enable auto-blocking.")
            return False
        
        try:
            rule_name = f"SentinelAI_Block_{ip.replace('.', '_')}"
            
            result = safe_subprocess_run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=in',
                'action=block',
                f'remoteip={ip}',
                'enable=yes'
            ], timeout=10)
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                logger.info(f"✓ BLOCKED IP: {ip} (firewall rule added)")
                return True
            else:
                error_msg = result.stderr.strip() if result.stderr else result.stdout.strip() if result.stdout else "Unknown error"
                logger.error(f"Failed to block IP {ip}: {error_msg}")
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
    
    def gather_attacker_intel(self, ip: str) -> Dict[str, Any]:
        """
        Gather OSINT intelligence about an attacker IP (LEGAL - no active scanning).
        Uses public APIs and databases to get reputation info.
        """
        intel = {
            "ip": ip,
            "gathered_at": datetime.now().isoformat(),
            "reputation": {},
            "geolocation": {},
            "reverse_dns": None,
            "is_known_bad": False,
            "threat_score": 0,
            "sources_checked": []
        }
        
        try:
            # 1. Reverse DNS lookup (legal)
            try:
                import socket
                intel["reverse_dns"] = socket.gethostbyaddr(ip)[0]
            except:
                intel["reverse_dns"] = None
            
            # 2. Check ip-api.com for geolocation (free, no key needed)
            try:
                resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,proxy,hosting", timeout=5)
                if resp.status_code == 200:
                    geo = resp.json()
                    if geo.get("status") == "success":
                        intel["geolocation"] = {
                            "country": geo.get("country"),
                            "region": geo.get("regionName"),
                            "city": geo.get("city"),
                            "isp": geo.get("isp"),
                            "org": geo.get("org"),
                            "asn": geo.get("as"),
                            "is_proxy": geo.get("proxy", False),
                            "is_hosting": geo.get("hosting", False)
                        }
                        intel["sources_checked"].append("ip-api.com")
                        # Hosting/proxy IPs are more suspicious
                        if geo.get("proxy") or geo.get("hosting"):
                            intel["threat_score"] += 20
            except:
                pass
            
            # 3. Check AbuseIPDB if API key is configured
            abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY")
            if abuseipdb_key:
                try:
                    headers = {"Key": abuseipdb_key, "Accept": "application/json"}
                    resp = requests.get(
                        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                        headers=headers, timeout=5
                    )
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        intel["reputation"]["abuseipdb"] = {
                            "abuse_confidence": data.get("abuseConfidenceScore", 0),
                            "total_reports": data.get("totalReports", 0),
                            "is_whitelisted": data.get("isWhitelisted", False),
                            "last_reported": data.get("lastReportedAt"),
                            "usage_type": data.get("usageType"),
                            "domain": data.get("domain")
                        }
                        intel["sources_checked"].append("AbuseIPDB")
                        # High abuse score = known bad
                        abuse_score = data.get("abuseConfidenceScore", 0)
                        if abuse_score >= 50:
                            intel["is_known_bad"] = True
                            intel["threat_score"] += abuse_score
                except:
                    pass
            
            # 4. Check VirusTotal if API key is configured
            vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
            if vt_key:
                try:
                    headers = {"x-apikey": vt_key}
                    resp = requests.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers=headers, timeout=5
                    )
                    if resp.status_code == 200:
                        data = resp.json().get("data", {}).get("attributes", {})
                        stats = data.get("last_analysis_stats", {})
                        intel["reputation"]["virustotal"] = {
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless": stats.get("harmless", 0),
                            "as_owner": data.get("as_owner"),
                            "country": data.get("country")
                        }
                        intel["sources_checked"].append("VirusTotal")
                        if stats.get("malicious", 0) > 0:
                            intel["is_known_bad"] = True
                            intel["threat_score"] += stats.get("malicious", 0) * 10
                except:
                    pass
            
            # 5. Basic threat classification
            if intel["threat_score"] >= 50:
                intel["classification"] = "HIGH_RISK"
            elif intel["threat_score"] >= 20:
                intel["classification"] = "SUSPICIOUS"
            else:
                intel["classification"] = "UNKNOWN"
            
            logger.info(f"Intel gathered for {ip}: score={intel['threat_score']}, known_bad={intel['is_known_bad']}")
            
        except Exception as e:
            logger.error(f"Error gathering intel for {ip}: {e}")
            intel["error"] = str(e)
        
        return intel
    
    def _handle_attacker_detected(self, ip: str, reason: str):
        """Enhanced attacker handling with intelligence gathering."""
        # Block the IP first (immediate response)
        blocked = self.block_ip(ip)
        
        # Gather intelligence in background (non-blocking)
        def gather_intel_async():
            intel = self.gather_attacker_intel(ip)
            
            # Send intel to dashboard
            try:
                requests.post(
                    f"{self.api_base}/api/v1/windows/agent/intel",
                    json={
                        "hostname": platform.node(),
                        "attacker_ip": ip,
                        "reason": reason,
                        "blocked": blocked,
                        "intel": intel
                    },
                    headers=self._get_headers(),
                    timeout=5
                )
            except:
                pass
            
            # Log detailed intel
            if intel.get("is_known_bad"):
                logger.warning(f"⚠️ KNOWN MALICIOUS IP: {ip} - Score: {intel['threat_score']}")
                if intel.get("geolocation"):
                    geo = intel["geolocation"]
                    logger.warning(f"   Location: {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}")
                    logger.warning(f"   ISP: {geo.get('isp', 'Unknown')} ({geo.get('org', '')})")
                if intel.get("reputation", {}).get("abuseipdb"):
                    abuse = intel["reputation"]["abuseipdb"]
                    logger.warning(f"   AbuseIPDB: {abuse.get('abuse_confidence', 0)}% confidence, {abuse.get('total_reports', 0)} reports")
        
        # Run intel gathering in background thread
        threading.Thread(target=gather_intel_async, daemon=True).start()


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
    
    # Check admin status
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        is_admin = False
    
    admin_status = "ADMIN ✓" if is_admin else "USER (no auto-block)"
    admin_color = "" if is_admin else "\033[93m"  # Yellow warning if not admin
    reset_color = "\033[0m" if not is_admin else ""
    
    print(f"""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║               SentinelAI Windows Agent v1.5                       ║
    ║       Native Windows Protection & Autonomous Threat Response      ║
    ║                                                                   ║
    ║  Core:     Process | Network (In+Out) | EventLog | Registry       ║
    ║  System:   Startup | Tasks | USB | Hosts | Browser | Services     ║
    ║  Network:  Inbound Monitor | Port Scan | Brute Force | Firewall   ║
    ║  Security: Certificates | Named Pipes | Defender | AVG            ║
    ║  Deep:     AMSI | ETW | Sysmon | DLL Injection | Command Exec     ║
    ║                                                                   ║
    ║     AI Analysis: {ai_status:^10}    |    26 Active Monitors         ║
    ║     {admin_color}Privileges: {admin_status:^15}{reset_color}                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    if not is_admin:
        print("    ⚠️  WARNING: Not running as Administrator!")
        print("    ⚠️  Auto-blocking of malicious IPs is DISABLED.")
        print("    ⚠️  Right-click run_agent.bat → 'Run as administrator' to enable.")
        print()
    
    agent = WindowsAgent(dashboard_url=args.dashboard)
    agent.use_ai = not args.no_ai
    agent.start()


if __name__ == '__main__':
    main()
