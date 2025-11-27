"""
Process Monitor Service for SentinelAI.
Monitors running processes for suspicious behavior.
"""
import os
import sys
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set, Callable
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)

# Try to import psutil
PSUTIL_AVAILABLE = False
try:
    import psutil
    PSUTIL_AVAILABLE = True
    logger.info("psutil is available for process monitoring")
except ImportError:
    logger.warning("psutil not available - process monitoring will be limited")


@dataclass
class ProcessInfo:
    """Information about a monitored process."""
    pid: int
    name: str
    exe: str
    cmdline: List[str]
    username: str
    create_time: datetime
    parent_pid: Optional[int]
    parent_name: Optional[str]
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    connections: int = 0
    children: List[int] = field(default_factory=list)
    suspicious: bool = False
    threat_score: int = 0
    threat_reasons: List[str] = field(default_factory=list)


@dataclass
class ProcessEvent:
    """A process-related security event."""
    event_type: str  # SUSPICIOUS_PROCESS, CRYPTO_MINER, REVERSE_SHELL, etc.
    pid: int
    process_name: str
    timestamp: datetime
    severity: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)


class ProcessMonitor:
    """
    Monitor running processes for suspicious behavior.
    """
    
    def __init__(self):
        """Initialize the process monitor."""
        self.running = False
        self.monitor_thread = None
        self.processes: Dict[int, ProcessInfo] = {}
        self.events: List[ProcessEvent] = []
        self.event_callbacks: List[Callable[[ProcessEvent], None]] = []
        
        # Configuration
        self.scan_interval = int(os.getenv("PROCESS_SCAN_INTERVAL", "5"))  # seconds
        self.cpu_threshold = float(os.getenv("CPU_ALERT_THRESHOLD", "80"))  # percent
        self.memory_threshold = float(os.getenv("MEMORY_ALERT_THRESHOLD", "80"))  # percent
        
        # Statistics
        self.stats = {
            "processes_monitored": 0,
            "suspicious_detected": 0,
            "events_generated": 0,
            "start_time": None
        }
        
        # Suspicious process patterns
        self.suspicious_processes = {
            # Known malicious tools
            "mimikatz", "pwdump", "procdump", "lazagne", "keylogger",
            "meterpreter", "cobaltstrike", "empire", "powersploit",
            
            # Crypto miners
            "xmrig", "minerd", "cpuminer", "cgminer", "bfgminer",
            "ethminer", "claymore", "phoenixminer", "nicehash",
            
            # Remote access tools
            "nc.exe", "ncat", "netcat", "plink", "psexec",
            "winexe", "wmic", "wmiexec",
            
            # Suspicious utilities
            "certutil", "bitsadmin", "mshta", "regsvr32",
            "rundll32", "msiexec", "cscript", "wscript"
        }
        
        # Suspicious command line patterns
        self.suspicious_cmdline_patterns = [
            # PowerShell suspicious patterns
            "-enc", "-encodedcommand", "-e ", "-ec ",
            "bypass", "-nop", "-noprofile", "-w hidden",
            "downloadstring", "downloadfile", "iex",
            "invoke-expression", "invoke-command",
            "new-object net.webclient", "bitstransfer",
            
            # Command injection patterns
            "cmd /c", "cmd.exe /c", "/c powershell",
            "bash -c", "/bin/sh -c", "sh -c",
            
            # Reverse shell patterns
            "nc -e", "ncat -e", "/dev/tcp/",
            "bash -i", "python -c", "perl -e",
            
            # Credential access
            "sekurlsa", "lsadump", "sam", "ntds",
            "hashdump", "kerberos",
            
            # Persistence
            "schtasks", "at ", "reg add", "startup",
            "run ", "runonce",
        ]
        
        # Legitimate parent-child relationships
        self.legitimate_parents = {
            "cmd.exe": {"explorer.exe", "services.exe", "svchost.exe"},
            "powershell.exe": {"explorer.exe", "services.exe", "svchost.exe", "cmd.exe"},
            "python.exe": {"explorer.exe", "cmd.exe", "powershell.exe", "code.exe", "pycharm64.exe"},
            "python": {"bash", "sh", "zsh", "code", "terminal"},
        }
        
        # Suspicious parent-child combinations
        self.suspicious_spawns = {
            # Web servers spawning shells
            ("httpd", "cmd.exe"), ("httpd", "powershell.exe"), ("httpd", "bash"),
            ("nginx", "cmd.exe"), ("nginx", "powershell.exe"), ("nginx", "bash"),
            ("apache", "cmd.exe"), ("apache", "powershell.exe"), ("apache", "bash"),
            ("iis", "cmd.exe"), ("iis", "powershell.exe"),
            ("w3wp.exe", "cmd.exe"), ("w3wp.exe", "powershell.exe"),
            
            # Office apps spawning shells
            ("winword.exe", "cmd.exe"), ("winword.exe", "powershell.exe"),
            ("excel.exe", "cmd.exe"), ("excel.exe", "powershell.exe"),
            ("outlook.exe", "cmd.exe"), ("outlook.exe", "powershell.exe"),
            
            # Browsers spawning shells
            ("chrome.exe", "cmd.exe"), ("chrome.exe", "powershell.exe"),
            ("firefox.exe", "cmd.exe"), ("firefox.exe", "powershell.exe"),
            ("msedge.exe", "cmd.exe"), ("msedge.exe", "powershell.exe"),
        }
        
        logger.info(f"Process monitor initialized. psutil available: {PSUTIL_AVAILABLE}")
    
    def add_event_callback(self, callback: Callable[[ProcessEvent], None]):
        """Add a callback for process events."""
        self.event_callbacks.append(callback)
    
    def _create_event(self, event_type: str, pid: int, name: str,
                      severity: str, description: str, **kwargs) -> ProcessEvent:
        """Create and store a process event."""
        event = ProcessEvent(
            event_type=event_type,
            pid=pid,
            process_name=name,
            timestamp=datetime.utcnow(),
            severity=severity,
            description=description,
            details=kwargs
        )
        
        self.events.append(event)
        self.stats["events_generated"] += 1
        
        # Keep only last 1000 events
        if len(self.events) > 1000:
            self.events = self.events[-1000:]
        
        # Call callbacks
        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Event callback error: {e}")
        
        return event
    
    def _analyze_process(self, proc: psutil.Process) -> Optional[ProcessInfo]:
        """Analyze a single process for suspicious behavior."""
        try:
            # Get process info
            try:
                name = proc.name().lower()
                exe = proc.exe() if proc.exe() else ""
                cmdline = proc.cmdline()
                username = proc.username()
                create_time = datetime.fromtimestamp(proc.create_time())
                parent = proc.parent()
                parent_pid = parent.pid if parent else None
                parent_name = parent.name().lower() if parent else None
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                return None
            
            info = ProcessInfo(
                pid=proc.pid,
                name=name,
                exe=exe,
                cmdline=cmdline,
                username=username,
                create_time=create_time,
                parent_pid=parent_pid,
                parent_name=parent_name
            )
            
            # Get resource usage
            try:
                info.cpu_percent = proc.cpu_percent()
                info.memory_percent = proc.memory_percent()
                info.connections = len(proc.connections())
                info.children = [c.pid for c in proc.children()]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # Check for suspicious indicators
            threat_score = 0
            threat_reasons = []
            
            # Check 1: Known suspicious process names
            for suspicious in self.suspicious_processes:
                if suspicious in name:
                    threat_score += 50
                    threat_reasons.append(f"Suspicious process name: {suspicious}")
                    break
            
            # Check 2: Suspicious command line
            cmdline_str = " ".join(cmdline).lower()
            for pattern in self.suspicious_cmdline_patterns:
                if pattern.lower() in cmdline_str:
                    threat_score += 30
                    threat_reasons.append(f"Suspicious command line: {pattern}")
                    break
            
            # Check 3: Suspicious parent-child relationship
            if parent_name and name:
                for parent_pattern, child_pattern in self.suspicious_spawns:
                    if parent_pattern in parent_name and child_pattern in name:
                        threat_score += 70
                        threat_reasons.append(f"Suspicious spawn: {parent_name} -> {name}")
                        break
            
            # Check 4: High resource usage (potential crypto miner)
            if info.cpu_percent > self.cpu_threshold:
                threat_score += 20
                threat_reasons.append(f"High CPU usage: {info.cpu_percent:.1f}%")
            
            # Check 5: Many network connections
            if info.connections > 50:
                threat_score += 15
                threat_reasons.append(f"Many network connections: {info.connections}")
            
            # Check 6: Process running from temp directory
            temp_dirs = ["/tmp", "/var/tmp", "\\temp", "\\tmp", "appdata\\local\\temp"]
            exe_lower = exe.lower()
            for temp_dir in temp_dirs:
                if temp_dir in exe_lower:
                    threat_score += 25
                    threat_reasons.append(f"Running from temp directory")
                    break
            
            info.threat_score = threat_score
            info.threat_reasons = threat_reasons
            info.suspicious = threat_score >= 50
            
            return info
            
        except Exception as e:
            logger.debug(f"Error analyzing process: {e}")
            return None
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        logger.info("Process monitor loop started")
        
        while self.running:
            try:
                current_pids = set()
                suspicious_count = 0
                
                for proc in psutil.process_iter():
                    try:
                        info = self._analyze_process(proc)
                        if info:
                            current_pids.add(info.pid)
                            self.processes[info.pid] = info
                            
                            if info.suspicious:
                                suspicious_count += 1
                                
                                # Generate event if this is a new suspicious process
                                if info.pid not in self.processes or not self.processes[info.pid].suspicious:
                                    severity = "CRITICAL" if info.threat_score >= 80 else "HIGH"
                                    self._create_event(
                                        event_type="SUSPICIOUS_PROCESS",
                                        pid=info.pid,
                                        name=info.name,
                                        severity=severity,
                                        description=f"Suspicious process detected: {info.name}",
                                        threat_score=info.threat_score,
                                        threat_reasons=info.threat_reasons,
                                        exe=info.exe,
                                        cmdline=info.cmdline,
                                        parent=info.parent_name,
                                        username=info.username
                                    )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Remove terminated processes
                terminated = set(self.processes.keys()) - current_pids
                for pid in terminated:
                    del self.processes[pid]
                
                # Update stats
                self.stats["processes_monitored"] = len(self.processes)
                self.stats["suspicious_detected"] = suspicious_count
                
                time.sleep(self.scan_interval)
                
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                time.sleep(1)
    
    def start(self):
        """Start the process monitor."""
        if self.running:
            logger.warning("Process monitor already running")
            return False
        
        if not PSUTIL_AVAILABLE:
            logger.error("Cannot start - psutil not available")
            return False
        
        self.running = True
        self.stats["start_time"] = datetime.utcnow().isoformat()
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("Process monitor started")
        return True
    
    def stop(self):
        """Stop the process monitor."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Process monitor stopped")
    
    def kill_process(self, pid: int) -> bool:
        """
        Kill a process by PID.
        
        Args:
            pid: Process ID to kill
            
        Returns:
            True if successful, False otherwise
        """
        if not PSUTIL_AVAILABLE:
            return False
        
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            
            # Wait for termination
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()  # Force kill
            
            logger.info(f"Process {pid} terminated")
            
            # Create event
            self._create_event(
                event_type="PROCESS_KILLED",
                pid=pid,
                name=proc.name() if proc.is_running() else "unknown",
                severity="INFO",
                description=f"Process {pid} was terminated by SentinelAI"
            )
            
            return True
            
        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} not found")
            return False
        except psutil.AccessDenied:
            logger.error(f"Access denied to kill process {pid}")
            return False
        except Exception as e:
            logger.error(f"Error killing process {pid}: {e}")
            return False
    
    def get_process_tree(self, pid: int) -> Dict[str, Any]:
        """Get process tree for a given PID."""
        if not PSUTIL_AVAILABLE:
            return {}
        
        try:
            proc = psutil.Process(pid)
            
            def get_children(p):
                result = {
                    "pid": p.pid,
                    "name": p.name(),
                    "children": []
                }
                for child in p.children():
                    result["children"].append(get_children(child))
                return result
            
            return get_children(proc)
            
        except Exception as e:
            logger.error(f"Error getting process tree: {e}")
            return {}
    
    def get_stats(self) -> Dict[str, Any]:
        """Get monitor statistics."""
        return {
            **self.stats,
            "events_in_memory": len(self.events),
            "running": self.running,
            "psutil_available": PSUTIL_AVAILABLE
        }
    
    def get_suspicious_processes(self) -> List[Dict[str, Any]]:
        """Get list of currently suspicious processes."""
        return [
            {
                "pid": p.pid,
                "name": p.name,
                "exe": p.exe,
                "cmdline": p.cmdline,
                "username": p.username,
                "parent": p.parent_name,
                "cpu_percent": p.cpu_percent,
                "memory_percent": p.memory_percent,
                "threat_score": p.threat_score,
                "threat_reasons": p.threat_reasons,
                "create_time": p.create_time.isoformat()
            }
            for p in self.processes.values()
            if p.suspicious
        ]
    
    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent process events."""
        return [
            {
                "event_type": e.event_type,
                "pid": e.pid,
                "process_name": e.process_name,
                "timestamp": e.timestamp.isoformat(),
                "severity": e.severity,
                "description": e.description,
                **e.details
            }
            for e in self.events[-limit:]
        ]
    
    def get_top_cpu_processes(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get processes with highest CPU usage."""
        sorted_procs = sorted(
            self.processes.values(),
            key=lambda p: p.cpu_percent,
            reverse=True
        )[:limit]
        
        return [
            {
                "pid": p.pid,
                "name": p.name,
                "cpu_percent": p.cpu_percent,
                "memory_percent": p.memory_percent,
                "suspicious": p.suspicious
            }
            for p in sorted_procs
        ]


# Singleton instance
_process_monitor = None


def get_process_monitor() -> ProcessMonitor:
    """Get or create the process monitor singleton."""
    global _process_monitor
    if _process_monitor is None:
        _process_monitor = ProcessMonitor()
    return _process_monitor
