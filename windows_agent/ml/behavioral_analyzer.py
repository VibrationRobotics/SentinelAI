"""
Behavioral Sequence Analyzer
Detects attack chains by analyzing sequences of events.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Any
from collections import defaultdict, deque
import logging

logger = logging.getLogger("SentinelAgent.ML")


@dataclass
class BehavioralEvent:
    """Event for behavioral sequence analysis."""
    timestamp: datetime
    event_type: str
    process_name: str
    details: Dict[str, Any]
    threat_score: float = 0.0


class BehavioralSequenceAnalyzer:
    """
    Analyze sequences of events to detect attack chains.
    Uses sliding window and pattern matching.
    """
    
    def __init__(self, window_size: int = 100, time_window_seconds: int = 300):
        self.window_size = window_size
        self.time_window = timedelta(seconds=time_window_seconds)
        self.event_buffer: deque = deque(maxlen=window_size)
        self.process_chains: Dict[str, List[BehavioralEvent]] = defaultdict(list)
        
        # Attack chain patterns (sequences of event types)
        self.attack_patterns = {
            "reconnaissance": {
                "sequence": ["discovery", "enumeration", "scan"],
                "indicators": ["systeminfo", "whoami", "ipconfig", "netstat", "tasklist", "dir /s"],
                "severity": "MEDIUM",
                "mitre": ["T1082", "T1083", "T1057", "T1049", "T1016"],
            },
            "credential_theft": {
                "sequence": ["process", "lsass", "dump"],
                "indicators": ["mimikatz", "sekurlsa", "lsass", "procdump", "sam", "ntds"],
                "severity": "CRITICAL",
                "mitre": ["T1003.001", "T1003.002", "T1003.003"],
            },
            "lateral_movement": {
                "sequence": ["network", "remote", "exec"],
                "indicators": ["psexec", "wmic /node", "winrm", "invoke-command", "net use \\\\"],
                "severity": "HIGH",
                "mitre": ["T1021.002", "T1021.006", "T1570"],
            },
            "persistence": {
                "sequence": ["registry", "scheduled", "service"],
                "indicators": ["schtasks /create", "reg add", "sc create", "startup", "runonce"],
                "severity": "HIGH",
                "mitre": ["T1547.001", "T1053.005", "T1543.003"],
            },
            "exfiltration": {
                "sequence": ["collect", "archive", "upload"],
                "indicators": ["compress", "7z", "rar", "zip", "upload", "ftp", "curl", "wget"],
                "severity": "CRITICAL",
                "mitre": ["T1560", "T1041", "T1048"],
            },
            "ransomware": {
                "sequence": ["enumerate", "encrypt", "delete"],
                "indicators": ["vssadmin delete", "bcdedit", "wbadmin", "cipher", "encrypt"],
                "severity": "CRITICAL",
                "mitre": ["T1486", "T1490", "T1489"],
            },
            "defense_evasion": {
                "sequence": ["disable", "delete", "clear"],
                "indicators": ["stop-service", "sc stop", "taskkill", "del /f", "clear-eventlog"],
                "severity": "HIGH",
                "mitre": ["T1562.001", "T1070.004", "T1070.001"],
            },
            "privilege_escalation": {
                "sequence": ["exploit", "elevate", "admin"],
                "indicators": ["fodhelper", "eventvwr", "sdclt", "uac", "runas", "token"],
                "severity": "HIGH",
                "mitre": ["T1548.002", "T1134"],
            },
        }
        
    def add_event(self, event: BehavioralEvent):
        """Add event to the buffer and process chains."""
        self.event_buffer.append(event)
        self.process_chains[event.process_name].append(event)
        self._cleanup_old_events()
    
    def _cleanup_old_events(self):
        """Remove events outside the time window."""
        now = datetime.now()
        cutoff = now - self.time_window
        
        while self.event_buffer and self.event_buffer[0].timestamp < cutoff:
            self.event_buffer.popleft()
        
        for proc_name in list(self.process_chains.keys()):
            self.process_chains[proc_name] = [
                e for e in self.process_chains[proc_name] if e.timestamp >= cutoff
            ]
            if not self.process_chains[proc_name]:
                del self.process_chains[proc_name]
    
    def detect_attack_chains(self) -> List[Dict[str, Any]]:
        """Detect attack chain patterns in recent events."""
        detected_chains = []
        events = list(self.event_buffer)
        
        if len(events) < 2:
            return detected_chains
        
        # Combine all event data for pattern matching
        all_text = ' '.join([
            f"{e.event_type} {e.process_name} {str(e.details)}"
            for e in events
        ]).lower()
        
        for pattern_name, pattern_info in self.attack_patterns.items():
            indicators = pattern_info.get('indicators', [])
            matched_indicators = [ind for ind in indicators if ind.lower() in all_text]
            
            if len(matched_indicators) >= 2:  # At least 2 indicators
                matching_events = self._find_matching_events(events, matched_indicators)
                confidence = self._calculate_chain_confidence(matching_events, matched_indicators, indicators)
                
                if confidence >= 0.3:  # Minimum confidence threshold
                    detected_chains.append({
                        "pattern": pattern_name,
                        "confidence": confidence,
                        "severity": pattern_info['severity'],
                        "mitre_techniques": pattern_info['mitre'],
                        "matched_indicators": matched_indicators,
                        "event_count": len(matching_events),
                        "time_span_seconds": self._get_time_span(matching_events),
                    })
        
        # Sort by confidence
        detected_chains.sort(key=lambda x: x['confidence'], reverse=True)
        return detected_chains
    
    def _find_matching_events(self, events: List[BehavioralEvent], 
                             indicators: List[str]) -> List[BehavioralEvent]:
        """Find events matching the indicators."""
        matching = []
        for event in events:
            event_text = f"{event.event_type} {event.process_name} {str(event.details)}".lower()
            if any(ind.lower() in event_text for ind in indicators):
                matching.append(event)
        return matching
    
    def _calculate_chain_confidence(self, events: List[BehavioralEvent],
                                   matched: List[str], all_indicators: List[str]) -> float:
        """Calculate confidence score for detected chain."""
        if not events or not matched:
            return 0.0
        
        # Indicator coverage (how many indicators matched)
        indicator_score = len(matched) / len(all_indicators)
        
        # Event count score
        event_score = min(len(events) / 5.0, 1.0)
        
        # Temporal proximity score
        time_span = self._get_time_span(events)
        time_score = 1.0 if time_span < 60 else 0.7 if time_span < 300 else 0.4
        
        # Threat score from individual events
        avg_threat = sum(e.threat_score for e in events) / len(events) if events else 0
        threat_score = min(avg_threat, 1.0)
        
        # Weighted combination
        confidence = (
            indicator_score * 0.35 +
            event_score * 0.25 +
            time_score * 0.20 +
            threat_score * 0.20
        )
        
        return min(confidence, 1.0)
    
    def _get_time_span(self, events: List[BehavioralEvent]) -> float:
        """Get time span of events in seconds."""
        if len(events) < 2:
            return 0.0
        try:
            return (events[-1].timestamp - events[0].timestamp).total_seconds()
        except:
            return 0.0
    
    def get_recent_events(self, count: int = 50) -> List[BehavioralEvent]:
        """Get recent events from buffer."""
        return list(self.event_buffer)[-count:]
    
    def get_process_chain(self, process_name: str) -> List[BehavioralEvent]:
        """Get event chain for a specific process."""
        return self.process_chains.get(process_name, [])
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        return {
            "buffer_size": len(self.event_buffer),
            "unique_processes": len(self.process_chains),
            "window_seconds": self.time_window.total_seconds(),
        }
