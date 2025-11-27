"""
File Scanner Service for SentinelAI.
Monitors file system for malware and suspicious files.
"""
import os
import sys
import logging
import hashlib
import threading
import time
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Callable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Try to import watchdog
WATCHDOG_AVAILABLE = False
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
    logger.info("Watchdog is available for file monitoring")
except ImportError:
    logger.warning("Watchdog not available - file monitoring will be limited")

# Try to import yara
YARA_AVAILABLE = False
try:
    import yara
    YARA_AVAILABLE = True
    logger.info("YARA is available for pattern matching")
except ImportError:
    logger.warning("YARA not available - pattern matching will be limited")

# Try to import requests for VirusTotal
VIRUSTOTAL_AVAILABLE = False
try:
    import requests
    VIRUSTOTAL_AVAILABLE = True
except ImportError:
    pass


@dataclass
class ScanResult:
    """Result of a file scan."""
    file_path: str
    file_hash: str
    file_size: int
    scan_time: datetime
    is_malicious: bool
    threat_name: Optional[str] = None
    severity: str = "LOW"
    detection_method: str = "unknown"
    details: Dict[str, Any] = field(default_factory=dict)


class MalwareSignatures:
    """Known malware signatures and patterns."""
    
    # Known malicious file hashes (MD5) - sample list
    KNOWN_HASHES = {
        "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File",
        "e99a18c428cb38d5f260853678922e03": "Test-Malware-Sample",
    }
    
    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".jar", ".msi", ".hta", ".wsf", ".pif", ".com", ".reg"
    }
    
    # High-risk extensions (often used by ransomware)
    HIGH_RISK_EXTENSIONS = {
        ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
        ".locky", ".zepto", ".cerber", ".wallet"
    }
    
    # Suspicious file names
    SUSPICIOUS_NAMES = [
        "mimikatz", "pwdump", "procdump", "lazagne", "keylogger",
        "rat", "backdoor", "trojan", "rootkit", "exploit",
        "crack", "keygen", "patch", "loader", "injector"
    ]
    
    # Suspicious content patterns (for text-based files)
    SUSPICIOUS_CONTENT = [
        b"powershell -enc",
        b"powershell -e ",
        b"IEX(",
        b"Invoke-Expression",
        b"DownloadString",
        b"Net.WebClient",
        b"FromBase64String",
        b"cmd /c",
        b"cmd.exe /c",
        b"WScript.Shell",
        b"CreateObject",
        b"HKEY_LOCAL_MACHINE",
        b"reg add",
        b"schtasks /create",
    ]


class FileEventHandler(FileSystemEventHandler):
    """Handle file system events for real-time monitoring."""
    
    def __init__(self, scanner: 'FileScanner'):
        self.scanner = scanner
        super().__init__()
    
    def on_created(self, event):
        if not event.is_directory:
            self.scanner.queue_scan(event.src_path, "created")
    
    def on_modified(self, event):
        if not event.is_directory:
            self.scanner.queue_scan(event.src_path, "modified")


class FileScanner:
    """
    File system scanner for malware detection.
    """
    
    def __init__(self):
        """Initialize the file scanner."""
        self.running = False
        self.observer = None
        self.scan_queue: List[tuple] = []
        self.scan_thread = None
        self.results: List[ScanResult] = []
        self.event_callbacks: List[Callable[[ScanResult], None]] = []
        
        # Configuration
        self.quarantine_dir = Path(os.getenv("QUARANTINE_DIR", "/var/quarantine"))
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.max_file_size = int(os.getenv("MAX_SCAN_FILE_SIZE", str(50 * 1024 * 1024)))  # 50MB
        
        # Directories to monitor
        self.watch_dirs = self._get_watch_directories()
        
        # Statistics
        self.stats = {
            "files_scanned": 0,
            "threats_detected": 0,
            "files_quarantined": 0,
            "start_time": None
        }
        
        # Load YARA rules if available
        self.yara_rules = None
        if YARA_AVAILABLE:
            self._load_yara_rules()
        
        # Ensure quarantine directory exists
        try:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning(f"Could not create quarantine directory: {e}")
        
        logger.info(f"File scanner initialized. Watchdog: {WATCHDOG_AVAILABLE}, YARA: {YARA_AVAILABLE}")
    
    def _get_watch_directories(self) -> List[str]:
        """Get directories to monitor based on OS."""
        dirs = []
        
        if sys.platform == "win32":
            # Windows directories
            user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Default")
            dirs = [
                os.path.join(user_profile, "Downloads"),
                os.path.join(user_profile, "Desktop"),
                os.path.join(user_profile, "Documents"),
                os.environ.get("TEMP", "C:\\Windows\\Temp"),
                "C:\\Windows\\Temp",
            ]
        else:
            # Linux directories
            home = os.environ.get("HOME", "/root")
            dirs = [
                os.path.join(home, "Downloads"),
                os.path.join(home, "Desktop"),
                "/tmp",
                "/var/tmp",
            ]
        
        # Filter to existing directories
        return [d for d in dirs if os.path.exists(d)]
    
    def _load_yara_rules(self):
        """Load YARA rules from rules directory."""
        rules_dir = Path(__file__).parent.parent.parent / "yara_rules"
        
        if not rules_dir.exists():
            rules_dir.mkdir(parents=True, exist_ok=True)
            # Create a sample rule
            sample_rule = rules_dir / "sample.yar"
            sample_rule.write_text('''
rule SuspiciousPowerShell {
    meta:
        description = "Detects suspicious PowerShell commands"
        severity = "high"
    strings:
        $ps1 = "powershell" nocase
        $enc = "-enc" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $download = "DownloadString" nocase
        $iex = "IEX" nocase
    condition:
        $ps1 and ($enc or $bypass or $hidden or ($download and $iex))
}

rule EICARTestFile {
    meta:
        description = "EICAR test file"
        severity = "low"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
''')
        
        try:
            rule_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
            if rule_files:
                self.yara_rules = yara.compile(filepaths={
                    str(f.stem): str(f) for f in rule_files
                })
                logger.info(f"Loaded {len(rule_files)} YARA rule files")
        except Exception as e:
            logger.error(f"Error loading YARA rules: {e}")
    
    def add_event_callback(self, callback: Callable[[ScanResult], None]):
        """Add a callback for scan results."""
        self.event_callbacks.append(callback)
    
    def _calculate_hash(self, file_path: str) -> Optional[str]:
        """Calculate MD5 hash of a file."""
        try:
            hasher = hashlib.md5()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Error hashing file {file_path}: {e}")
            return None
    
    def _check_hash(self, file_hash: str) -> Optional[str]:
        """Check if hash matches known malware."""
        return MalwareSignatures.KNOWN_HASHES.get(file_hash.lower())
    
    def _check_extension(self, file_path: str) -> tuple:
        """Check file extension for suspicious types."""
        ext = Path(file_path).suffix.lower()
        
        if ext in MalwareSignatures.HIGH_RISK_EXTENSIONS:
            return True, "HIGH", f"High-risk extension: {ext}"
        elif ext in MalwareSignatures.SUSPICIOUS_EXTENSIONS:
            return True, "MEDIUM", f"Suspicious extension: {ext}"
        
        return False, "LOW", None
    
    def _check_filename(self, file_path: str) -> tuple:
        """Check filename for suspicious patterns."""
        name = Path(file_path).stem.lower()
        
        for suspicious in MalwareSignatures.SUSPICIOUS_NAMES:
            if suspicious in name:
                return True, "HIGH", f"Suspicious filename contains: {suspicious}"
        
        return False, "LOW", None
    
    def _check_content(self, file_path: str) -> tuple:
        """Check file content for suspicious patterns."""
        try:
            # Only check text-based files
            ext = Path(file_path).suffix.lower()
            if ext not in {".txt", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".wsf"}:
                return False, "LOW", None
            
            with open(file_path, 'rb') as f:
                content = f.read(1024 * 1024)  # Read first 1MB
            
            for pattern in MalwareSignatures.SUSPICIOUS_CONTENT:
                if pattern.lower() in content.lower():
                    return True, "HIGH", f"Suspicious content: {pattern.decode('utf-8', errors='ignore')}"
            
        except Exception as e:
            logger.debug(f"Could not check content of {file_path}: {e}")
        
        return False, "LOW", None
    
    def _check_yara(self, file_path: str) -> tuple:
        """Check file against YARA rules."""
        if not self.yara_rules:
            return False, "LOW", None
        
        try:
            matches = self.yara_rules.match(file_path)
            if matches:
                rule_names = [m.rule for m in matches]
                severities = [m.meta.get('severity', 'medium') for m in matches]
                max_severity = "HIGH" if "high" in severities else "MEDIUM"
                return True, max_severity, f"YARA match: {', '.join(rule_names)}"
        except Exception as e:
            logger.debug(f"YARA scan error for {file_path}: {e}")
        
        return False, "LOW", None
    
    def _check_virustotal(self, file_hash: str) -> tuple:
        """Check hash against VirusTotal."""
        if not self.virustotal_api_key or not VIRUSTOTAL_AVAILABLE:
            return False, "LOW", None
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": self.virustotal_api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                
                if malicious > 0:
                    return True, "CRITICAL", f"VirusTotal: {malicious} detections"
            
        except Exception as e:
            logger.debug(f"VirusTotal check error: {e}")
        
        return False, "LOW", None
    
    def scan_file(self, file_path: str, reason: str = "manual") -> Optional[ScanResult]:
        """
        Scan a single file for threats.
        
        Args:
            file_path: Path to the file to scan
            reason: Reason for the scan (manual, created, modified)
            
        Returns:
            ScanResult if scan completed, None if file couldn't be scanned
        """
        try:
            path = Path(file_path)
            
            if not path.exists():
                return None
            
            if not path.is_file():
                return None
            
            file_size = path.stat().st_size
            
            # Skip files that are too large
            if file_size > self.max_file_size:
                logger.debug(f"Skipping large file: {file_path}")
                return None
            
            # Calculate hash
            file_hash = self._calculate_hash(file_path)
            if not file_hash:
                return None
            
            self.stats["files_scanned"] += 1
            
            # Run all checks
            is_malicious = False
            threat_name = None
            severity = "LOW"
            detection_method = None
            details = {"reason": reason}
            
            # Check 1: Known hash
            known_threat = self._check_hash(file_hash)
            if known_threat:
                is_malicious = True
                threat_name = known_threat
                severity = "CRITICAL"
                detection_method = "hash_match"
                details["hash_match"] = known_threat
            
            # Check 2: Extension
            if not is_malicious:
                suspicious, sev, msg = self._check_extension(file_path)
                if suspicious:
                    is_malicious = True
                    threat_name = msg
                    severity = sev
                    detection_method = "extension"
                    details["extension_check"] = msg
            
            # Check 3: Filename
            if not is_malicious:
                suspicious, sev, msg = self._check_filename(file_path)
                if suspicious:
                    is_malicious = True
                    threat_name = msg
                    severity = sev
                    detection_method = "filename"
                    details["filename_check"] = msg
            
            # Check 4: Content patterns
            if not is_malicious:
                suspicious, sev, msg = self._check_content(file_path)
                if suspicious:
                    is_malicious = True
                    threat_name = msg
                    severity = sev
                    detection_method = "content"
                    details["content_check"] = msg
            
            # Check 5: YARA rules
            if not is_malicious:
                suspicious, sev, msg = self._check_yara(file_path)
                if suspicious:
                    is_malicious = True
                    threat_name = msg
                    severity = sev
                    detection_method = "yara"
                    details["yara_check"] = msg
            
            # Check 6: VirusTotal (only for suspicious files)
            if is_malicious or severity != "LOW":
                vt_malicious, vt_sev, vt_msg = self._check_virustotal(file_hash)
                if vt_malicious:
                    is_malicious = True
                    threat_name = vt_msg
                    severity = "CRITICAL"
                    detection_method = "virustotal"
                    details["virustotal_check"] = vt_msg
            
            result = ScanResult(
                file_path=file_path,
                file_hash=file_hash,
                file_size=file_size,
                scan_time=datetime.utcnow(),
                is_malicious=is_malicious,
                threat_name=threat_name,
                severity=severity,
                detection_method=detection_method or "clean",
                details=details
            )
            
            if is_malicious:
                self.stats["threats_detected"] += 1
                logger.warning(f"Threat detected: {file_path} - {threat_name}")
            
            self.results.append(result)
            
            # Keep only last 1000 results
            if len(self.results) > 1000:
                self.results = self.results[-1000:]
            
            # Call callbacks
            for callback in self.event_callbacks:
                try:
                    callback(result)
                except Exception as e:
                    logger.error(f"Scan callback error: {e}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return None
    
    def quarantine_file(self, file_path: str) -> bool:
        """
        Move a file to quarantine.
        
        Args:
            file_path: Path to the file to quarantine
            
        Returns:
            True if successful, False otherwise
        """
        try:
            source = Path(file_path)
            if not source.exists():
                return False
            
            # Create unique quarantine name
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            dest_name = f"{timestamp}_{source.name}.quarantine"
            dest = self.quarantine_dir / dest_name
            
            # Move file
            shutil.move(str(source), str(dest))
            
            # Log quarantine info
            info_file = dest.with_suffix(".info")
            info_file.write_text(json.dumps({
                "original_path": str(source),
                "quarantine_time": datetime.utcnow().isoformat(),
                "quarantine_path": str(dest)
            }))
            
            self.stats["files_quarantined"] += 1
            logger.info(f"File quarantined: {file_path} -> {dest}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error quarantining file {file_path}: {e}")
            return False
    
    def queue_scan(self, file_path: str, reason: str = "queued"):
        """Add a file to the scan queue."""
        self.scan_queue.append((file_path, reason))
    
    def _scan_loop(self):
        """Background scan loop."""
        while self.running:
            try:
                if self.scan_queue:
                    file_path, reason = self.scan_queue.pop(0)
                    self.scan_file(file_path, reason)
                else:
                    time.sleep(0.1)
            except Exception as e:
                logger.error(f"Scan loop error: {e}")
    
    def start(self):
        """Start the file scanner."""
        if self.running:
            logger.warning("File scanner already running")
            return False
        
        self.running = True
        self.stats["start_time"] = datetime.utcnow().isoformat()
        
        # Start scan thread
        self.scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.scan_thread.start()
        
        # Start file system observer
        if WATCHDOG_AVAILABLE and self.watch_dirs:
            self.observer = Observer()
            handler = FileEventHandler(self)
            
            for watch_dir in self.watch_dirs:
                try:
                    self.observer.schedule(handler, watch_dir, recursive=True)
                    logger.info(f"Watching directory: {watch_dir}")
                except Exception as e:
                    logger.error(f"Could not watch {watch_dir}: {e}")
            
            self.observer.start()
        
        logger.info("File scanner started")
        return True
    
    def stop(self):
        """Stop the file scanner."""
        self.running = False
        
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
        
        if self.scan_thread:
            self.scan_thread.join(timeout=5)
        
        logger.info("File scanner stopped")
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[ScanResult]:
        """
        Scan all files in a directory.
        
        Args:
            directory: Directory to scan
            recursive: Whether to scan subdirectories
            
        Returns:
            List of scan results
        """
        results = []
        path = Path(directory)
        
        if not path.exists():
            return results
        
        pattern = "**/*" if recursive else "*"
        
        for file_path in path.glob(pattern):
            if file_path.is_file():
                result = self.scan_file(str(file_path), "directory_scan")
                if result:
                    results.append(result)
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scanner statistics."""
        return {
            **self.stats,
            "queue_size": len(self.scan_queue),
            "results_in_memory": len(self.results),
            "running": self.running,
            "watchdog_available": WATCHDOG_AVAILABLE,
            "yara_available": YARA_AVAILABLE,
            "watch_directories": self.watch_dirs
        }
    
    def get_recent_results(self, limit: int = 50, threats_only: bool = False) -> List[Dict[str, Any]]:
        """Get recent scan results."""
        results = self.results
        if threats_only:
            results = [r for r in results if r.is_malicious]
        
        return [
            {
                "file_path": r.file_path,
                "file_hash": r.file_hash,
                "file_size": r.file_size,
                "scan_time": r.scan_time.isoformat(),
                "is_malicious": r.is_malicious,
                "threat_name": r.threat_name,
                "severity": r.severity,
                "detection_method": r.detection_method,
                "details": r.details
            }
            for r in results[-limit:]
        ]


# Singleton instance
_file_scanner = None


def get_file_scanner() -> FileScanner:
    """Get or create the file scanner singleton."""
    global _file_scanner
    if _file_scanner is None:
        _file_scanner = FileScanner()
    return _file_scanner
