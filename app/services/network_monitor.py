"""
Network Monitor Service for SentinelAI.
Captures and analyzes network traffic to detect attacks in real-time.
"""
import os
import sys
import logging
import asyncio
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from collections import defaultdict
from dataclasses import dataclass, field
import socket
import struct

logger = logging.getLogger(__name__)

# Try to import scapy
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf
    # Disable scapy warnings
    conf.verb = 0
    SCAPY_AVAILABLE = True
    logger.info("Scapy is available for network monitoring")
except ImportError:
    logger.warning("Scapy not available - network monitoring will be limited")


@dataclass
class ConnectionTracker:
    """Track connections from an IP address."""
    ip: str
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    connection_count: int = 0
    failed_connections: int = 0
    ports_accessed: set = field(default_factory=set)
    protocols: set = field(default_factory=set)
    bytes_sent: int = 0
    bytes_received: int = 0
    suspicious_payloads: List[str] = field(default_factory=list)


@dataclass
class NetworkEvent:
    """Represents a network security event."""
    event_type: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    timestamp: datetime
    severity: str
    description: str
    payload: Optional[str] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)


class NetworkMonitor:
    """
    Real-time network traffic monitor for threat detection.
    """
    
    def __init__(self, interface: str = None):
        """
        Initialize the network monitor.
        
        Args:
            interface: Network interface to monitor (None = all interfaces)
        """
        self.interface = interface or os.getenv("NETWORK_INTERFACE", None)
        self.running = False
        self.monitor_thread = None
        
        # Detection thresholds
        self.port_scan_threshold = int(os.getenv("PORT_SCAN_THRESHOLD", "10"))
        self.brute_force_threshold = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
        self.ddos_threshold = int(os.getenv("DDOS_THRESHOLD", "100"))
        self.time_window = int(os.getenv("DETECTION_TIME_WINDOW", "60"))  # seconds
        
        # Connection tracking
        self.connections: Dict[str, ConnectionTracker] = {}
        self.events: List[NetworkEvent] = []
        self.event_callbacks: List[Callable[[NetworkEvent], None]] = []
        
        # Statistics
        self.stats = {
            "packets_captured": 0,
            "events_detected": 0,
            "port_scans": 0,
            "brute_force_attempts": 0,
            "suspicious_payloads": 0,
            "start_time": None
        }
        
        # Suspicious patterns
        self.suspicious_patterns = [
            b"SELECT", b"UNION", b"DROP TABLE", b"INSERT INTO",  # SQL Injection
            b"<script>", b"javascript:", b"onerror=",  # XSS
            b"/etc/passwd", b"/etc/shadow", b"../..",  # Path traversal
            b"cmd.exe", b"powershell", b"/bin/sh", b"/bin/bash",  # Command injection
            b"eval(", b"exec(", b"system(",  # Code execution
        ]
        
        # Ports to monitor closely
        self.sensitive_ports = {
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP-Alt",
            27017: "MongoDB"
        }
        
        logger.info(f"Network monitor initialized. Scapy available: {SCAPY_AVAILABLE}")
    
    def add_event_callback(self, callback: Callable[[NetworkEvent], None]):
        """Add a callback to be called when an event is detected."""
        self.event_callbacks.append(callback)
    
    def _get_or_create_tracker(self, ip: str) -> ConnectionTracker:
        """Get or create a connection tracker for an IP."""
        if ip not in self.connections:
            self.connections[ip] = ConnectionTracker(ip=ip)
        return self.connections[ip]
    
    def _cleanup_old_trackers(self):
        """Remove trackers older than the time window."""
        cutoff = datetime.utcnow() - timedelta(seconds=self.time_window * 2)
        old_ips = [ip for ip, tracker in self.connections.items() 
                   if tracker.last_seen < cutoff]
        for ip in old_ips:
            del self.connections[ip]
    
    def _check_suspicious_payload(self, payload: bytes) -> Optional[str]:
        """Check if payload contains suspicious patterns."""
        payload_upper = payload.upper()
        for pattern in self.suspicious_patterns:
            if pattern.upper() in payload_upper:
                return pattern.decode('utf-8', errors='ignore')
        return None
    
    def _create_event(self, event_type: str, source_ip: str, dest_ip: str,
                      src_port: int, dst_port: int, protocol: str,
                      severity: str, description: str, 
                      payload: str = None, **kwargs) -> NetworkEvent:
        """Create and store a network event."""
        event = NetworkEvent(
            event_type=event_type,
            source_ip=source_ip,
            destination_ip=dest_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=protocol,
            timestamp=datetime.utcnow(),
            severity=severity,
            description=description,
            payload=payload,
            additional_data=kwargs
        )
        
        self.events.append(event)
        self.stats["events_detected"] += 1
        
        # Keep only last 1000 events
        if len(self.events) > 1000:
            self.events = self.events[-1000:]
        
        # Call registered callbacks
        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Event callback error: {e}")
        
        return event
    
    def _analyze_packet(self, packet):
        """Analyze a captured packet for threats."""
        try:
            if not packet.haslayer(IP):
                return
            
            self.stats["packets_captured"] += 1
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = "OTHER"
            src_port = 0
            dst_port = 0
            payload = b""
            
            # Get protocol-specific info
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                protocol = "TCP"
                src_port = tcp.sport
                dst_port = tcp.dport
                
                # Check for SYN scan (SYN without ACK)
                if tcp.flags == 0x02:  # SYN only
                    tracker = self._get_or_create_tracker(src_ip)
                    tracker.ports_accessed.add(dst_port)
                    tracker.connection_count += 1
                    tracker.last_seen = datetime.utcnow()
                    
                    # Port scan detection
                    if len(tracker.ports_accessed) >= self.port_scan_threshold:
                        self.stats["port_scans"] += 1
                        self._create_event(
                            event_type="PORT_SCAN",
                            source_ip=src_ip,
                            dest_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol=protocol,
                            severity="HIGH",
                            description=f"Port scan detected from {src_ip}. "
                                       f"Scanned {len(tracker.ports_accessed)} ports",
                            ports_scanned=list(tracker.ports_accessed)
                        )
                        # Reset to avoid duplicate alerts
                        tracker.ports_accessed.clear()
                
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                protocol = "UDP"
                src_port = udp.sport
                dst_port = udp.dport
                
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            
            # Check for payload
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                
                # Check for suspicious patterns
                suspicious = self._check_suspicious_payload(payload)
                if suspicious:
                    self.stats["suspicious_payloads"] += 1
                    self._create_event(
                        event_type="SUSPICIOUS_PAYLOAD",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        severity="HIGH",
                        description=f"Suspicious payload detected: {suspicious}",
                        payload=payload[:500].decode('utf-8', errors='ignore'),
                        pattern_matched=suspicious
                    )
            
            # Track connection
            tracker = self._get_or_create_tracker(src_ip)
            tracker.connection_count += 1
            tracker.last_seen = datetime.utcnow()
            tracker.protocols.add(protocol)
            if dst_port:
                tracker.ports_accessed.add(dst_port)
            
            # Brute force detection (many connections to same port)
            if dst_port in [22, 23, 3389, 21]:  # SSH, Telnet, RDP, FTP
                if tracker.connection_count >= self.brute_force_threshold:
                    recent_window = datetime.utcnow() - timedelta(seconds=self.time_window)
                    if tracker.first_seen > recent_window:
                        self.stats["brute_force_attempts"] += 1
                        self._create_event(
                            event_type="BRUTE_FORCE",
                            source_ip=src_ip,
                            dest_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol=protocol,
                            severity="HIGH",
                            description=f"Possible brute force attack on "
                                       f"{self.sensitive_ports.get(dst_port, 'service')} "
                                       f"from {src_ip}. {tracker.connection_count} attempts",
                            connection_count=tracker.connection_count
                        )
                        # Reset counter
                        tracker.connection_count = 0
                        tracker.first_seen = datetime.utcnow()
            
            # DDoS detection (high volume from single IP)
            if tracker.connection_count >= self.ddos_threshold:
                recent_window = datetime.utcnow() - timedelta(seconds=self.time_window)
                if tracker.first_seen > recent_window:
                    self._create_event(
                        event_type="DDOS_SUSPECTED",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        severity="CRITICAL",
                        description=f"Possible DDoS attack from {src_ip}. "
                                   f"{tracker.connection_count} connections in "
                                   f"{self.time_window} seconds",
                        connection_count=tracker.connection_count
                    )
                    tracker.connection_count = 0
                    tracker.first_seen = datetime.utcnow()
            
            # Periodic cleanup
            if self.stats["packets_captured"] % 1000 == 0:
                self._cleanup_old_trackers()
                
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")
    
    def _capture_loop(self):
        """Main packet capture loop."""
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start capture - scapy not available")
            return
        
        logger.info(f"Starting packet capture on interface: {self.interface or 'all'}")
        self.stats["start_time"] = datetime.utcnow().isoformat()
        
        try:
            sniff(
                iface=self.interface,
                prn=self._analyze_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.running = False
    
    def start(self):
        """Start the network monitor."""
        if self.running:
            logger.warning("Network monitor already running")
            return False
        
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start - scapy not available")
            return False
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Network monitor started")
        return True
    
    def stop(self):
        """Stop the network monitor."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Network monitor stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        return {
            **self.stats,
            "active_trackers": len(self.connections),
            "events_in_memory": len(self.events),
            "running": self.running,
            "scapy_available": SCAPY_AVAILABLE
        }
    
    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent network events."""
        events = self.events[-limit:]
        return [
            {
                "event_type": e.event_type,
                "source_ip": e.source_ip,
                "destination_ip": e.destination_ip,
                "source_port": e.source_port,
                "destination_port": e.destination_port,
                "protocol": e.protocol,
                "timestamp": e.timestamp.isoformat(),
                "severity": e.severity,
                "description": e.description,
                "payload": e.payload,
                **e.additional_data
            }
            for e in events
        ]
    
    def get_top_sources(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top source IPs by connection count."""
        sorted_trackers = sorted(
            self.connections.values(),
            key=lambda t: t.connection_count,
            reverse=True
        )[:limit]
        
        return [
            {
                "ip": t.ip,
                "connection_count": t.connection_count,
                "ports_accessed": len(t.ports_accessed),
                "protocols": list(t.protocols),
                "first_seen": t.first_seen.isoformat(),
                "last_seen": t.last_seen.isoformat()
            }
            for t in sorted_trackers
        ]


# Singleton instance
_network_monitor = None


def get_network_monitor() -> NetworkMonitor:
    """Get or create the network monitor singleton."""
    global _network_monitor
    if _network_monitor is None:
        _network_monitor = NetworkMonitor()
    return _network_monitor
