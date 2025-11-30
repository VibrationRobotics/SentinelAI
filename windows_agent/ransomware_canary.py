"""
Ransomware Canary Files
Creates honeypot files that ransomware will try to encrypt.
If these files are modified, it's a strong indicator of ransomware activity.
"""

import os
import hashlib
import logging
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Callable
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger("SentinelAgent.Canary")


@dataclass
class CanaryFile:
    """Represents a canary file."""
    path: str
    original_hash: str
    original_size: int
    created_at: datetime
    last_checked: datetime
    status: str = "healthy"  # healthy, modified, deleted, encrypted


class RansomwareCanaryMonitor:
    """
    Creates and monitors canary files to detect ransomware.
    
    Canary files are placed in common locations that ransomware targets:
    - Desktop
    - Documents
    - Downloads
    - Pictures
    - Root of drives
    
    If any canary file is modified or deleted, it triggers an alert.
    """
    
    # Common ransomware extensions
    RANSOMWARE_EXTENSIONS = {
        '.encrypted', '.locked', '.crypto', '.crypt', '.enc',
        '.locky', '.zepto', '.cerber', '.cerber2', '.cerber3',
        '.wallet', '.dharma', '.onion', '.zzzzz', '.micro',
        '.cryptolocker', '.crypz', '.cryp1', '.crypted',
        '.r5a', '.WNCRY', '.wcry', '.wncrypt', '.wncryt',
        '.WNCRYT', '.WNCRY', '.WANNACRY', '.petya', '.notpetya',
        '.bad', '.globe', '.purge', '.djvu', '.djvuq', '.djvur',
        '.djvut', '.djvup', '.djvus', '.udjvu', '.pdff', '.tro',
        '.mado', '.shadow', '.shade', '.good', '.mogera', '.rumba',
        '.adobe', '.adobee', '.nesa', '.kvag', '.domn', '.karl',
        '.STOP', '.puma', '.pumax', '.pumas', '.coharos'
    }
    
    def __init__(self, callback: Optional[Callable] = None):
        """
        Initialize the canary monitor.
        
        Args:
            callback: Function to call when ransomware is detected.
                      Signature: callback(alert_data: dict)
        """
        self.callback = callback
        self.canary_files: Dict[str, CanaryFile] = {}
        self.monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._check_interval = 5  # seconds
        
        # Canary file content (looks like valuable data)
        self._canary_content = self._generate_canary_content()
    
    def _generate_canary_content(self) -> bytes:
        """Generate realistic-looking canary file content."""
        content = """
CONFIDENTIAL FINANCIAL RECORDS
==============================

Account Summary - Q4 2024
-------------------------

Account Number: 4532-8891-2234-5567
Routing Number: 021000021
Balance: $1,247,893.45

Recent Transactions:
- 2024-11-15: Wire Transfer - $50,000.00
- 2024-11-14: ACH Deposit - $125,000.00
- 2024-11-13: Check #4521 - $3,450.00

Investment Portfolio:
- AAPL: 500 shares @ $175.23
- MSFT: 300 shares @ $378.91
- GOOGL: 100 shares @ $141.56

Social Security Numbers (Authorized Personnel Only):
- John Smith: 123-45-6789
- Jane Doe: 987-65-4321

Credit Card Information:
- Visa: 4532-8891-2234-5567 Exp: 12/26 CVV: 123
- Mastercard: 5425-2334-5567-8890 Exp: 03/25 CVV: 456

DO NOT SHARE - INTERNAL USE ONLY
================================
""".strip()
        return content.encode('utf-8')
    
    def _get_canary_locations(self) -> List[Path]:
        """Get list of directories to place canary files."""
        locations = []
        
        # User directories
        user_home = Path.home()
        user_dirs = [
            user_home / "Desktop",
            user_home / "Documents",
            user_home / "Downloads",
            user_home / "Pictures",
            user_home / "Videos",
            user_home / "Music",
        ]
        
        for d in user_dirs:
            if d.exists():
                locations.append(d)
        
        # Drive roots (C:, D:, etc.)
        for letter in "CDEFGHIJ":
            drive = Path(f"{letter}:/")
            if drive.exists():
                locations.append(drive)
        
        return locations
    
    def _calculate_hash(self, filepath: Path) -> str:
        """Calculate SHA256 hash of a file."""
        try:
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""
    
    def deploy_canaries(self) -> int:
        """
        Deploy canary files to strategic locations.
        
        Returns:
            Number of canary files created
        """
        count = 0
        locations = self._get_canary_locations()
        
        # Canary filenames that look valuable
        canary_names = [
            "Financial_Records_2024.xlsx",
            "passwords_backup.txt",
            "tax_returns_2024.pdf",
            "bank_statements.docx",
            "crypto_wallet_keys.txt",
        ]
        
        for location in locations:
            for name in canary_names[:2]:  # 2 canaries per location
                canary_path = location / f".sentinel_canary_{name}"
                
                try:
                    # Create canary file
                    with open(canary_path, 'wb') as f:
                        f.write(self._canary_content)
                    
                    # Hide the file (Windows)
                    try:
                        import ctypes
                        ctypes.windll.kernel32.SetFileAttributesW(
                            str(canary_path), 0x02  # FILE_ATTRIBUTE_HIDDEN
                        )
                    except Exception:
                        pass
                    
                    # Record canary
                    file_hash = self._calculate_hash(canary_path)
                    self.canary_files[str(canary_path)] = CanaryFile(
                        path=str(canary_path),
                        original_hash=file_hash,
                        original_size=len(self._canary_content),
                        created_at=datetime.utcnow(),
                        last_checked=datetime.utcnow(),
                        status="healthy"
                    )
                    
                    count += 1
                    logger.debug(f"Deployed canary: {canary_path}")
                    
                except PermissionError:
                    logger.debug(f"Permission denied for canary at {location}")
                except Exception as e:
                    logger.debug(f"Failed to create canary at {location}: {e}")
        
        logger.info(f"Deployed {count} ransomware canary files")
        return count
    
    def check_canaries(self) -> List[Dict]:
        """
        Check all canary files for modifications.
        
        Returns:
            List of alerts for compromised canaries
        """
        alerts = []
        
        for path, canary in list(self.canary_files.items()):
            canary.last_checked = datetime.utcnow()
            filepath = Path(path)
            
            # Check if file exists
            if not filepath.exists():
                # Check for ransomware extension variants
                ransomware_found = None
                for ext in self.RANSOMWARE_EXTENSIONS:
                    encrypted_path = Path(str(filepath) + ext)
                    if encrypted_path.exists():
                        ransomware_found = ext
                        break
                
                if ransomware_found:
                    canary.status = "encrypted"
                    alert = {
                        "type": "RANSOMWARE_DETECTED",
                        "severity": "CRITICAL",
                        "canary_path": path,
                        "ransomware_extension": ransomware_found,
                        "timestamp": datetime.utcnow().isoformat(),
                        "description": f"Canary file encrypted with {ransomware_found} extension - RANSOMWARE ACTIVE!"
                    }
                else:
                    canary.status = "deleted"
                    alert = {
                        "type": "CANARY_DELETED",
                        "severity": "HIGH",
                        "canary_path": path,
                        "timestamp": datetime.utcnow().isoformat(),
                        "description": "Canary file deleted - possible ransomware or malicious activity"
                    }
                
                alerts.append(alert)
                continue
            
            # Check if file was modified
            try:
                current_hash = self._calculate_hash(filepath)
                current_size = filepath.stat().st_size
                
                if current_hash != canary.original_hash:
                    canary.status = "modified"
                    
                    # Check for encryption indicators
                    is_encrypted = False
                    try:
                        with open(filepath, 'rb') as f:
                            header = f.read(16)
                            # High entropy header suggests encryption
                            unique_bytes = len(set(header))
                            if unique_bytes > 14:  # Very random = likely encrypted
                                is_encrypted = True
                    except Exception:
                        pass
                    
                    if is_encrypted:
                        alert = {
                            "type": "RANSOMWARE_DETECTED",
                            "severity": "CRITICAL",
                            "canary_path": path,
                            "timestamp": datetime.utcnow().isoformat(),
                            "description": "Canary file content encrypted in-place - RANSOMWARE ACTIVE!",
                            "original_hash": canary.original_hash,
                            "current_hash": current_hash
                        }
                    else:
                        alert = {
                            "type": "CANARY_MODIFIED",
                            "severity": "HIGH",
                            "canary_path": path,
                            "timestamp": datetime.utcnow().isoformat(),
                            "description": "Canary file modified - possible malicious activity",
                            "original_hash": canary.original_hash,
                            "current_hash": current_hash,
                            "size_change": current_size - canary.original_size
                        }
                    
                    alerts.append(alert)
                    
            except Exception as e:
                logger.warning(f"Error checking canary {path}: {e}")
        
        return alerts
    
    def start_monitoring(self):
        """Start background monitoring of canary files."""
        if self.monitoring:
            return
        
        self.monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("Ransomware canary monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring."""
        self.monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        logger.info("Ransomware canary monitoring stopped")
    
    def _monitor_loop(self):
        """Background monitoring loop."""
        while self.monitoring:
            try:
                alerts = self.check_canaries()
                
                for alert in alerts:
                    logger.critical(f"RANSOMWARE ALERT: {alert['description']}")
                    
                    if self.callback:
                        try:
                            self.callback(alert)
                        except Exception as e:
                            logger.error(f"Callback error: {e}")
                
                time.sleep(self._check_interval)
                
            except Exception as e:
                logger.error(f"Canary monitor error: {e}")
                time.sleep(10)
    
    def cleanup(self):
        """Remove all canary files."""
        self.stop_monitoring()
        
        for path in list(self.canary_files.keys()):
            try:
                filepath = Path(path)
                if filepath.exists():
                    # Remove hidden attribute first
                    try:
                        import ctypes
                        ctypes.windll.kernel32.SetFileAttributesW(str(filepath), 0x80)
                    except Exception:
                        pass
                    filepath.unlink()
                    logger.debug(f"Removed canary: {path}")
            except Exception as e:
                logger.warning(f"Failed to remove canary {path}: {e}")
        
        self.canary_files.clear()
        logger.info("Canary files cleaned up")
    
    def get_status(self) -> Dict:
        """Get current canary status."""
        status_counts = {"healthy": 0, "modified": 0, "deleted": 0, "encrypted": 0}
        for canary in self.canary_files.values():
            status_counts[canary.status] = status_counts.get(canary.status, 0) + 1
        
        return {
            "total_canaries": len(self.canary_files),
            "monitoring": self.monitoring,
            "status_counts": status_counts,
            "canary_locations": [c.path for c in self.canary_files.values()]
        }


# Convenience function
def create_canary_monitor(callback: Optional[Callable] = None) -> RansomwareCanaryMonitor:
    """Create and initialize a canary monitor."""
    monitor = RansomwareCanaryMonitor(callback=callback)
    monitor.deploy_canaries()
    return monitor
