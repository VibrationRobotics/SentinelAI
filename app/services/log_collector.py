"""
Log Collector Service for SentinelAI.
Collects and analyzes logs from multiple sources.
"""
import os
import sys
import logging
import threading
import time
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable, Generator
from dataclasses import dataclass, field
from pathlib import Path
from collections import deque
import json

logger = logging.getLogger(__name__)

# Try to import Windows-specific modules
WIN32_AVAILABLE = False
if sys.platform == "win32":
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
        WIN32_AVAILABLE = True
        logger.info("Windows Event Log support available")
    except ImportError:
        logger.warning("pywin32 not available - Windows Event Log support disabled")


@dataclass
class LogEntry:
    """Represents a parsed log entry."""
    timestamp: datetime
    source: str
    level: str  # INFO, WARNING, ERROR, CRITICAL
    message: str
    raw: str
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    threat_indicators: List[str] = field(default_factory=list)
    severity: str = "LOW"


@dataclass
class LogSource:
    """Configuration for a log source."""
    name: str
    source_type: str  # file, windows_event, syslog
    path: Optional[str] = None
    event_log_name: Optional[str] = None  # For Windows Event Logs
    enabled: bool = True
    parser: Optional[str] = None  # Parser to use


class LogParser:
    """Base class for log parsers."""
    
    # Common threat patterns
    THREAT_PATTERNS = {
        "failed_login": [
            r"failed password",
            r"authentication failure",
            r"invalid user",
            r"failed login",
            r"login failed",
            r"access denied",
        ],
        "brute_force": [
            r"repeated authentication failures",
            r"too many authentication failures",
            r"maximum authentication attempts",
        ],
        "privilege_escalation": [
            r"sudo:",
            r"su:",
            r"privilege escalation",
            r"root access",
            r"administrator",
        ],
        "malware_indicators": [
            r"malware",
            r"virus",
            r"trojan",
            r"ransomware",
            r"cryptolocker",
        ],
        "network_attack": [
            r"port scan",
            r"syn flood",
            r"ddos",
            r"denial of service",
        ],
        "suspicious_commands": [
            r"wget.*http",
            r"curl.*http",
            r"powershell.*-enc",
            r"base64.*decode",
            r"/etc/passwd",
            r"/etc/shadow",
        ],
    }
    
    @classmethod
    def detect_threats(cls, message: str) -> List[str]:
        """Detect threat indicators in a log message."""
        threats = []
        message_lower = message.lower()
        
        for threat_type, patterns in cls.THREAT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, message_lower):
                    threats.append(threat_type)
                    break
        
        return threats
    
    @classmethod
    def calculate_severity(cls, threats: List[str]) -> str:
        """Calculate severity based on detected threats."""
        if not threats:
            return "LOW"
        
        high_severity = {"brute_force", "privilege_escalation", "malware_indicators", "network_attack"}
        medium_severity = {"failed_login", "suspicious_commands"}
        
        for threat in threats:
            if threat in high_severity:
                return "HIGH"
        
        for threat in threats:
            if threat in medium_severity:
                return "MEDIUM"
        
        return "LOW"


class SyslogParser(LogParser):
    """Parser for syslog format logs."""
    
    # Syslog pattern: Month Day HH:MM:SS hostname process[pid]: message
    SYSLOG_PATTERN = re.compile(
        r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$'
    )
    
    @classmethod
    def parse(cls, line: str) -> Optional[LogEntry]:
        """Parse a syslog line."""
        match = cls.SYSLOG_PATTERN.match(line.strip())
        if not match:
            return None
        
        timestamp_str, hostname, process, pid, message = match.groups()
        
        # Parse timestamp (assume current year)
        try:
            current_year = datetime.now().year
            timestamp = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            timestamp = datetime.now()
        
        threats = cls.detect_threats(message)
        severity = cls.calculate_severity(threats)
        
        return LogEntry(
            timestamp=timestamp,
            source=f"{hostname}/{process}",
            level="INFO",
            message=message,
            raw=line,
            parsed_data={
                "hostname": hostname,
                "process": process,
                "pid": pid
            },
            threat_indicators=threats,
            severity=severity
        )


class AuthLogParser(LogParser):
    """Parser for SSH auth logs (/var/log/auth.log)."""
    
    # Patterns for extracting IPs and usernames
    IP_PATTERN = re.compile(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    USER_PATTERN = re.compile(r'(?:user|for)\s+(\S+)')
    
    @classmethod
    def parse(cls, line: str) -> Optional[LogEntry]:
        """Parse an auth log line."""
        # First try syslog format
        entry = SyslogParser.parse(line)
        if not entry:
            return None
        
        # Extract additional auth-specific data
        ip_match = cls.IP_PATTERN.search(line)
        user_match = cls.USER_PATTERN.search(line)
        
        if ip_match:
            entry.parsed_data["source_ip"] = ip_match.group(1)
        if user_match:
            entry.parsed_data["username"] = user_match.group(1)
        
        # Determine log level based on content
        line_lower = line.lower()
        if "failed" in line_lower or "invalid" in line_lower or "error" in line_lower:
            entry.level = "WARNING"
        elif "accepted" in line_lower:
            entry.level = "INFO"
        
        return entry


class ApacheLogParser(LogParser):
    """Parser for Apache/Nginx access logs."""
    
    # Combined log format pattern
    ACCESS_LOG_PATTERN = re.compile(
        r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"'
    )
    
    @classmethod
    def parse(cls, line: str) -> Optional[LogEntry]:
        """Parse an Apache/Nginx access log line."""
        match = cls.ACCESS_LOG_PATTERN.match(line.strip())
        if not match:
            return None
        
        ip, timestamp_str, request, status, size, referer, user_agent = match.groups()
        
        # Parse timestamp
        try:
            timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                timestamp = datetime.strptime(timestamp_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                timestamp = datetime.now()
        
        # Parse request
        request_parts = request.split()
        method = request_parts[0] if request_parts else ""
        path = request_parts[1] if len(request_parts) > 1 else ""
        
        # Detect threats in request
        threats = cls.detect_threats(request)
        
        # Check for SQL injection, XSS, path traversal
        if re.search(r"(union|select|insert|drop|delete|update)\s", path.lower()):
            threats.append("sql_injection")
        if re.search(r"(<script|javascript:|onerror)", path.lower()):
            threats.append("xss_attempt")
        if ".." in path:
            threats.append("path_traversal")
        
        severity = cls.calculate_severity(threats)
        
        # Determine level based on status code
        status_int = int(status)
        if status_int >= 500:
            level = "ERROR"
        elif status_int >= 400:
            level = "WARNING"
        else:
            level = "INFO"
        
        return LogEntry(
            timestamp=timestamp,
            source="webserver",
            level=level,
            message=f"{method} {path} - {status}",
            raw=line,
            parsed_data={
                "source_ip": ip,
                "method": method,
                "path": path,
                "status": status,
                "size": size,
                "referer": referer,
                "user_agent": user_agent
            },
            threat_indicators=threats,
            severity=severity
        )


class WindowsEventParser(LogParser):
    """Parser for Windows Event Logs."""
    
    # Security event IDs of interest
    SECURITY_EVENTS = {
        4624: ("Successful login", "INFO"),
        4625: ("Failed login", "WARNING"),
        4634: ("Logoff", "INFO"),
        4648: ("Explicit credential logon", "INFO"),
        4672: ("Special privileges assigned", "INFO"),
        4688: ("Process created", "INFO"),
        4689: ("Process terminated", "INFO"),
        4697: ("Service installed", "WARNING"),
        4698: ("Scheduled task created", "WARNING"),
        4720: ("User account created", "WARNING"),
        4722: ("User account enabled", "INFO"),
        4724: ("Password reset attempt", "WARNING"),
        4728: ("User added to security group", "WARNING"),
        4732: ("User added to local group", "WARNING"),
        4756: ("User added to universal group", "WARNING"),
        7045: ("Service installed", "WARNING"),
    }
    
    @classmethod
    def parse_event(cls, event) -> Optional[LogEntry]:
        """Parse a Windows event log entry."""
        if not WIN32_AVAILABLE:
            return None
        
        try:
            event_id = event.EventID & 0xFFFF  # Mask to get actual event ID
            timestamp = event.TimeGenerated
            source = event.SourceName
            
            # Get event description
            event_info = cls.SECURITY_EVENTS.get(event_id, (f"Event {event_id}", "INFO"))
            description, level = event_info
            
            # Build message
            message = f"{description}"
            if event.StringInserts:
                message += f": {' | '.join(str(s) for s in event.StringInserts[:5])}"
            
            # Detect threats
            threats = []
            if event_id == 4625:  # Failed login
                threats.append("failed_login")
            elif event_id in [4697, 4698, 7045]:  # Service/task creation
                threats.append("suspicious_commands")
            elif event_id in [4720, 4728, 4732, 4756]:  # Account changes
                threats.append("privilege_escalation")
            
            severity = cls.calculate_severity(threats)
            
            return LogEntry(
                timestamp=timestamp,
                source=f"Windows/{source}",
                level=level,
                message=message,
                raw=str(event),
                parsed_data={
                    "event_id": event_id,
                    "computer": event.ComputerName,
                    "category": event.EventCategory,
                },
                threat_indicators=threats,
                severity=severity
            )
        except Exception as e:
            logger.debug(f"Error parsing Windows event: {e}")
            return None


class LogCollector:
    """
    Collects and aggregates logs from multiple sources.
    """
    
    def __init__(self):
        """Initialize the log collector."""
        self.running = False
        self.collector_thread = None
        self.entries: deque = deque(maxlen=10000)  # Keep last 10k entries
        self.event_callbacks: List[Callable[[LogEntry], None]] = []
        
        # Log sources
        self.sources: List[LogSource] = []
        self._setup_default_sources()
        
        # File positions for tailing
        self.file_positions: Dict[str, int] = {}
        
        # Statistics
        self.stats = {
            "entries_collected": 0,
            "threats_detected": 0,
            "sources_active": 0,
            "start_time": None,
            "by_source": {},
            "by_severity": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        }
        
        # Parsers
        self.parsers = {
            "syslog": SyslogParser,
            "auth": AuthLogParser,
            "apache": ApacheLogParser,
            "nginx": ApacheLogParser,
        }
        
        logger.info(f"Log collector initialized. Windows support: {WIN32_AVAILABLE}")
    
    def _setup_default_sources(self):
        """Setup default log sources based on OS."""
        if sys.platform == "win32":
            # Windows Event Logs
            self.sources.append(LogSource(
                name="Windows Security",
                source_type="windows_event",
                event_log_name="Security",
                enabled=WIN32_AVAILABLE
            ))
            self.sources.append(LogSource(
                name="Windows System",
                source_type="windows_event",
                event_log_name="System",
                enabled=WIN32_AVAILABLE
            ))
            self.sources.append(LogSource(
                name="Windows Application",
                source_type="windows_event",
                event_log_name="Application",
                enabled=WIN32_AVAILABLE
            ))
        else:
            # Linux log files
            linux_logs = [
                ("/var/log/auth.log", "auth", "SSH Auth Log"),
                ("/var/log/secure", "auth", "Secure Log"),
                ("/var/log/syslog", "syslog", "Syslog"),
                ("/var/log/messages", "syslog", "Messages"),
                ("/var/log/apache2/access.log", "apache", "Apache Access"),
                ("/var/log/nginx/access.log", "nginx", "Nginx Access"),
            ]
            
            for path, parser, name in linux_logs:
                if os.path.exists(path):
                    self.sources.append(LogSource(
                        name=name,
                        source_type="file",
                        path=path,
                        parser=parser,
                        enabled=True
                    ))
    
    def add_event_callback(self, callback: Callable[[LogEntry], None]):
        """Add a callback for new log entries."""
        self.event_callbacks.append(callback)
    
    def add_source(self, source: LogSource):
        """Add a new log source."""
        self.sources.append(source)
        logger.info(f"Added log source: {source.name}")
    
    def _process_entry(self, entry: LogEntry, source_name: str):
        """Process a parsed log entry."""
        self.entries.append(entry)
        self.stats["entries_collected"] += 1
        
        # Update source stats
        if source_name not in self.stats["by_source"]:
            self.stats["by_source"][source_name] = 0
        self.stats["by_source"][source_name] += 1
        
        # Update severity stats
        self.stats["by_severity"][entry.severity] += 1
        
        # Count threats
        if entry.threat_indicators:
            self.stats["threats_detected"] += 1
        
        # Call callbacks for high-severity entries
        if entry.severity in ["HIGH", "CRITICAL"] or entry.threat_indicators:
            for callback in self.event_callbacks:
                try:
                    callback(entry)
                except Exception as e:
                    logger.error(f"Log callback error: {e}")
    
    def _tail_file(self, source: LogSource) -> Generator[str, None, None]:
        """Tail a log file for new lines."""
        path = source.path
        if not path or not os.path.exists(path):
            return
        
        # Get or initialize file position
        if path not in self.file_positions:
            # Start from end of file
            try:
                self.file_positions[path] = os.path.getsize(path)
            except OSError:
                self.file_positions[path] = 0
        
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.file_positions[path])
                
                for line in f:
                    if line.strip():
                        yield line
                
                self.file_positions[path] = f.tell()
        except Exception as e:
            logger.debug(f"Error tailing {path}: {e}")
    
    def _collect_file_logs(self, source: LogSource):
        """Collect logs from a file source."""
        parser_class = self.parsers.get(source.parser, SyslogParser)
        
        for line in self._tail_file(source):
            entry = parser_class.parse(line)
            if entry:
                self._process_entry(entry, source.name)
    
    def _collect_windows_events(self, source: LogSource):
        """Collect Windows Event Log entries."""
        if not WIN32_AVAILABLE or not source.event_log_name:
            return
        
        try:
            hand = win32evtlog.OpenEventLog(None, source.event_log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            # Read recent events (last 100)
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for event in events[:100]:
                entry = WindowsEventParser.parse_event(event)
                if entry:
                    # Only process recent events (last 5 minutes)
                    if datetime.now() - entry.timestamp < timedelta(minutes=5):
                        self._process_entry(entry, source.name)
            
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            logger.debug(f"Error reading Windows Event Log {source.event_log_name}: {e}")
    
    def _collection_loop(self):
        """Main collection loop."""
        logger.info("Log collection loop started")
        
        while self.running:
            try:
                active_sources = 0
                
                for source in self.sources:
                    if not source.enabled:
                        continue
                    
                    active_sources += 1
                    
                    if source.source_type == "file":
                        self._collect_file_logs(source)
                    elif source.source_type == "windows_event":
                        self._collect_windows_events(source)
                
                self.stats["sources_active"] = active_sources
                
                # Sleep between collection cycles
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Collection loop error: {e}")
                time.sleep(1)
    
    def start(self):
        """Start the log collector."""
        if self.running:
            logger.warning("Log collector already running")
            return False
        
        self.running = True
        self.stats["start_time"] = datetime.utcnow().isoformat()
        
        self.collector_thread = threading.Thread(target=self._collection_loop, daemon=True)
        self.collector_thread.start()
        
        logger.info("Log collector started")
        return True
    
    def stop(self):
        """Stop the log collector."""
        self.running = False
        if self.collector_thread:
            self.collector_thread.join(timeout=5)
        logger.info("Log collector stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics."""
        return {
            **self.stats,
            "entries_in_memory": len(self.entries),
            "running": self.running,
            "windows_support": WIN32_AVAILABLE,
            "configured_sources": len(self.sources)
        }
    
    def get_sources(self) -> List[Dict[str, Any]]:
        """Get configured log sources."""
        return [
            {
                "name": s.name,
                "type": s.source_type,
                "path": s.path,
                "event_log": s.event_log_name,
                "enabled": s.enabled,
                "parser": s.parser
            }
            for s in self.sources
        ]
    
    def get_recent_entries(self, limit: int = 100, 
                          severity: Optional[str] = None,
                          source: Optional[str] = None,
                          threats_only: bool = False) -> List[Dict[str, Any]]:
        """Get recent log entries with optional filtering."""
        entries = list(self.entries)
        
        # Apply filters
        if severity:
            entries = [e for e in entries if e.severity == severity]
        if source:
            entries = [e for e in entries if source.lower() in e.source.lower()]
        if threats_only:
            entries = [e for e in entries if e.threat_indicators]
        
        # Return most recent
        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "source": e.source,
                "level": e.level,
                "message": e.message,
                "severity": e.severity,
                "threats": e.threat_indicators,
                "data": e.parsed_data
            }
            for e in entries[-limit:]
        ]
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of detected threats."""
        threat_counts: Dict[str, int] = {}
        threat_entries: List[Dict[str, Any]] = []
        
        for entry in self.entries:
            for threat in entry.threat_indicators:
                threat_counts[threat] = threat_counts.get(threat, 0) + 1
            
            if entry.threat_indicators and len(threat_entries) < 50:
                threat_entries.append({
                    "timestamp": entry.timestamp.isoformat(),
                    "source": entry.source,
                    "message": entry.message[:200],
                    "threats": entry.threat_indicators,
                    "severity": entry.severity
                })
        
        return {
            "total_threats": self.stats["threats_detected"],
            "threat_types": threat_counts,
            "recent_threats": threat_entries[-20:],
            "by_severity": self.stats["by_severity"]
        }
    
    def search_logs(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search log entries by keyword."""
        query_lower = query.lower()
        results = []
        
        for entry in reversed(list(self.entries)):
            if query_lower in entry.message.lower() or query_lower in entry.raw.lower():
                results.append({
                    "timestamp": entry.timestamp.isoformat(),
                    "source": entry.source,
                    "level": entry.level,
                    "message": entry.message,
                    "severity": entry.severity,
                    "threats": entry.threat_indicators
                })
                
                if len(results) >= limit:
                    break
        
        return results


# Singleton instance
_log_collector = None


def get_log_collector() -> LogCollector:
    """Get or create the log collector singleton."""
    global _log_collector
    if _log_collector is None:
        _log_collector = LogCollector()
    return _log_collector
