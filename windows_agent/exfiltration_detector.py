"""
Data Exfiltration Detector
Monitors for large outbound data transfers that may indicate data theft.
"""

import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Set
from dataclasses import dataclass, field
from collections import defaultdict

import psutil

logger = logging.getLogger("SentinelAgent.Exfiltration")


@dataclass
class ConnectionStats:
    """Statistics for a network connection."""
    remote_ip: str
    remote_port: int
    process_name: str
    pid: int
    bytes_sent: int = 0
    bytes_received: int = 0
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    packet_count: int = 0


@dataclass
class ExfiltrationAlert:
    """Alert for potential data exfiltration."""
    alert_type: str
    severity: str
    process_name: str
    pid: int
    remote_ip: str
    remote_port: int
    bytes_sent: int
    duration_seconds: float
    transfer_rate_mbps: float
    timestamp: str
    description: str


class DataExfiltrationDetector:
    """
    Detects potential data exfiltration by monitoring:
    - Large outbound data transfers
    - Unusual transfer patterns
    - Connections to suspicious destinations
    - High-volume transfers from sensitive processes
    """
    
    # Thresholds (configurable)
    DEFAULT_THRESHOLDS = {
        "bytes_per_minute": 50 * 1024 * 1024,  # 50 MB/min triggers alert
        "bytes_per_hour": 500 * 1024 * 1024,   # 500 MB/hour triggers alert
        "bytes_single_connection": 100 * 1024 * 1024,  # 100 MB single connection
        "suspicious_ports": {21, 22, 23, 25, 53, 69, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432},
        "cloud_storage_ports": {443},  # HTTPS often used for cloud uploads
    }
    
    # Known cloud storage domains (partial matches)
    CLOUD_STORAGE_INDICATORS = [
        'dropbox', 'drive.google', 'onedrive', 'icloud', 'box.com',
        'mega.nz', 'mediafire', 'wetransfer', 'sendspace', 'zippyshare',
        's3.amazonaws', 'blob.core.windows', 'storage.googleapis',
        'pastebin', 'hastebin', 'ghostbin', 'privatebin'
    ]
    
    # Processes that commonly transfer large amounts of data (whitelist)
    WHITELIST_PROCESSES = {
        'chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe',  # Browsers
        'steam.exe', 'epicgameslauncher.exe',  # Gaming
        'onedrive.exe', 'dropbox.exe', 'googledrivesync.exe',  # Cloud sync
        'windowsupdate.exe', 'wuauclt.exe', 'trustedinstaller.exe',  # Updates
        'spotify.exe', 'discord.exe', 'teams.exe', 'zoom.exe',  # Communication
    }
    
    def __init__(self, callback: Optional[Callable] = None, thresholds: Dict = None):
        """
        Initialize the exfiltration detector.
        
        Args:
            callback: Function to call when exfiltration is detected
            thresholds: Custom threshold values
        """
        self.callback = callback
        self.thresholds = {**self.DEFAULT_THRESHOLDS, **(thresholds or {})}
        
        # Connection tracking
        self.connections: Dict[str, ConnectionStats] = {}
        self.process_bytes_sent: Dict[int, int] = defaultdict(int)  # pid -> bytes
        self.hourly_bytes_sent: Dict[str, int] = defaultdict(int)  # hour_key -> bytes
        
        # Monitoring state
        self.monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._check_interval = 10  # seconds
        
        # Alert deduplication
        self._recent_alerts: Set[str] = set()
        self._alert_cooldown = 300  # 5 minutes between same alerts
    
    def _get_connection_key(self, conn) -> str:
        """Generate unique key for a connection."""
        return f"{conn.pid}:{conn.raddr.ip}:{conn.raddr.port}"
    
    def _get_process_name(self, pid: int) -> str:
        """Get process name from PID."""
        try:
            proc = psutil.Process(pid)
            return proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"
    
    def _is_whitelisted(self, process_name: str) -> bool:
        """Check if process is whitelisted for large transfers."""
        return process_name.lower() in {p.lower() for p in self.WHITELIST_PROCESSES}
    
    def _check_cloud_storage(self, remote_ip: str) -> bool:
        """Check if IP might be cloud storage (heuristic)."""
        # This is a simplified check - in production you'd do reverse DNS
        # For now, we flag any large HTTPS transfer
        return False
    
    def scan_connections(self) -> List[ExfiltrationAlert]:
        """
        Scan current network connections for potential exfiltration.
        
        Returns:
            List of exfiltration alerts
        """
        alerts = []
        current_time = datetime.utcnow()
        hour_key = current_time.strftime("%Y-%m-%d-%H")
        
        try:
            # Get all network connections
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                # Skip if no remote address or not established
                if not conn.raddr or conn.status != 'ESTABLISHED':
                    continue
                
                # Skip local connections
                if conn.raddr.ip.startswith(('127.', '192.168.', '10.', '172.16.')):
                    continue
                
                conn_key = self._get_connection_key(conn)
                process_name = self._get_process_name(conn.pid)
                
                # Get or create connection stats
                if conn_key not in self.connections:
                    self.connections[conn_key] = ConnectionStats(
                        remote_ip=conn.raddr.ip,
                        remote_port=conn.raddr.port,
                        process_name=process_name,
                        pid=conn.pid
                    )
                
                stats = self.connections[conn_key]
                stats.last_seen = current_time
                
            # Get network IO per process
            try:
                net_io = psutil.net_io_counters(pernic=False)
                # Note: psutil doesn't give per-connection bytes easily
                # We track process-level IO instead
                
                for proc in psutil.process_iter(['pid', 'name', 'io_counters']):
                    try:
                        io = proc.info.get('io_counters')
                        if io:
                            pid = proc.info['pid']
                            name = proc.info['name']
                            
                            # Track bytes written (potential exfiltration)
                            current_bytes = io.write_bytes if hasattr(io, 'write_bytes') else 0
                            
                            if pid in self.process_bytes_sent:
                                bytes_delta = current_bytes - self.process_bytes_sent[pid]
                                
                                if bytes_delta > 0:
                                    # Update hourly tracking
                                    self.hourly_bytes_sent[hour_key] += bytes_delta
                                    
                                    # Check thresholds
                                    alert = self._check_thresholds(
                                        process_name=name,
                                        pid=pid,
                                        bytes_sent=bytes_delta,
                                        total_bytes=current_bytes
                                    )
                                    if alert:
                                        alerts.append(alert)
                            
                            self.process_bytes_sent[pid] = current_bytes
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
            except Exception as e:
                logger.debug(f"Error getting process IO: {e}")
            
            # Check hourly threshold
            hourly_total = self.hourly_bytes_sent.get(hour_key, 0)
            if hourly_total > self.thresholds["bytes_per_hour"]:
                alert_key = f"hourly_{hour_key}"
                if alert_key not in self._recent_alerts:
                    self._recent_alerts.add(alert_key)
                    alerts.append(ExfiltrationAlert(
                        alert_type="HIGH_HOURLY_TRANSFER",
                        severity="HIGH",
                        process_name="system-wide",
                        pid=0,
                        remote_ip="multiple",
                        remote_port=0,
                        bytes_sent=hourly_total,
                        duration_seconds=3600,
                        transfer_rate_mbps=hourly_total / (1024 * 1024 * 3600),
                        timestamp=current_time.isoformat(),
                        description=f"High hourly outbound transfer: {hourly_total / (1024*1024):.1f} MB in the last hour"
                    ))
            
            # Cleanup old data
            self._cleanup_old_data(current_time)
            
        except Exception as e:
            logger.error(f"Error scanning connections: {e}")
        
        return alerts
    
    def _check_thresholds(self, process_name: str, pid: int, bytes_sent: int, total_bytes: int) -> Optional[ExfiltrationAlert]:
        """Check if transfer exceeds thresholds."""
        
        # Skip whitelisted processes
        if self._is_whitelisted(process_name):
            return None
        
        # Check single transfer threshold
        if bytes_sent > self.thresholds["bytes_single_connection"]:
            alert_key = f"single_{pid}_{bytes_sent // (10*1024*1024)}"  # Group by 10MB chunks
            
            if alert_key not in self._recent_alerts:
                self._recent_alerts.add(alert_key)
                
                return ExfiltrationAlert(
                    alert_type="LARGE_OUTBOUND_TRANSFER",
                    severity="HIGH" if bytes_sent > 500*1024*1024 else "MEDIUM",
                    process_name=process_name,
                    pid=pid,
                    remote_ip="unknown",
                    remote_port=0,
                    bytes_sent=bytes_sent,
                    duration_seconds=self._check_interval,
                    transfer_rate_mbps=bytes_sent / (1024 * 1024 * self._check_interval),
                    timestamp=datetime.utcnow().isoformat(),
                    description=f"Large outbound transfer by {process_name}: {bytes_sent / (1024*1024):.1f} MB"
                )
        
        return None
    
    def _cleanup_old_data(self, current_time: datetime):
        """Clean up old tracking data."""
        # Remove old connections (not seen in 5 minutes)
        cutoff = current_time - timedelta(minutes=5)
        old_keys = [k for k, v in self.connections.items() if v.last_seen < cutoff]
        for key in old_keys:
            del self.connections[key]
        
        # Remove old hourly data (keep last 24 hours)
        current_hour = current_time.strftime("%Y-%m-%d-%H")
        old_hours = [k for k in self.hourly_bytes_sent.keys() if k < current_hour]
        for key in old_hours[-24:]:  # Keep some history
            pass
        for key in old_hours[:-24]:
            del self.hourly_bytes_sent[key]
        
        # Clear old alerts
        if len(self._recent_alerts) > 1000:
            self._recent_alerts.clear()
    
    def start_monitoring(self):
        """Start background monitoring."""
        if self.monitoring:
            return
        
        self.monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("Data exfiltration monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring."""
        self.monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        logger.info("Data exfiltration monitoring stopped")
    
    def _monitor_loop(self):
        """Background monitoring loop."""
        while self.monitoring:
            try:
                alerts = self.scan_connections()
                
                for alert in alerts:
                    logger.warning(f"EXFILTRATION ALERT: {alert.description}")
                    
                    if self.callback:
                        try:
                            self.callback({
                                "type": alert.alert_type,
                                "severity": alert.severity,
                                "process_name": alert.process_name,
                                "pid": alert.pid,
                                "remote_ip": alert.remote_ip,
                                "bytes_sent": alert.bytes_sent,
                                "transfer_rate_mbps": alert.transfer_rate_mbps,
                                "timestamp": alert.timestamp,
                                "description": alert.description
                            })
                        except Exception as e:
                            logger.error(f"Callback error: {e}")
                
                time.sleep(self._check_interval)
                
            except Exception as e:
                logger.error(f"Exfiltration monitor error: {e}")
                time.sleep(30)
    
    def get_stats(self) -> Dict:
        """Get current monitoring statistics."""
        current_hour = datetime.utcnow().strftime("%Y-%m-%d-%H")
        
        return {
            "monitoring": self.monitoring,
            "active_connections": len(self.connections),
            "tracked_processes": len(self.process_bytes_sent),
            "hourly_bytes_sent": self.hourly_bytes_sent.get(current_hour, 0),
            "hourly_mb_sent": self.hourly_bytes_sent.get(current_hour, 0) / (1024 * 1024),
            "thresholds": {
                "mb_per_minute": self.thresholds["bytes_per_minute"] / (1024 * 1024),
                "mb_per_hour": self.thresholds["bytes_per_hour"] / (1024 * 1024),
                "mb_single_connection": self.thresholds["bytes_single_connection"] / (1024 * 1024)
            }
        }
    
    def add_to_whitelist(self, process_name: str):
        """Add a process to the whitelist."""
        self.WHITELIST_PROCESSES.add(process_name.lower())
        logger.info(f"Added {process_name} to exfiltration whitelist")
    
    def remove_from_whitelist(self, process_name: str):
        """Remove a process from the whitelist."""
        self.WHITELIST_PROCESSES.discard(process_name.lower())
        logger.info(f"Removed {process_name} from exfiltration whitelist")


# Convenience function
def create_exfiltration_detector(callback: Optional[Callable] = None) -> DataExfiltrationDetector:
    """Create and initialize an exfiltration detector."""
    return DataExfiltrationDetector(callback=callback)
