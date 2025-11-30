"""
Threat Feed Service
Integrates with external threat intelligence feeds:
- AlienVault OTX (Open Threat Exchange)
- Abuse.ch (URLhaus, MalwareBazaar, ThreatFox)
- FeodoTracker (C2 servers)
"""

import asyncio
import aiohttp
import logging
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import hashlib
import json
import os

logger = logging.getLogger(__name__)


@dataclass
class ThreatIndicator:
    """A single threat indicator (IOC)."""
    indicator_type: str  # ip, domain, url, hash_md5, hash_sha256, hash_sha1
    value: str
    source: str  # otx, abusech, feodo
    threat_type: str  # malware, c2, phishing, etc.
    confidence: float  # 0-1
    description: str = ""
    tags: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    reference_url: str = ""


@dataclass
class ThreatFeedConfig:
    """Configuration for threat feeds."""
    # AlienVault OTX
    otx_enabled: bool = False
    otx_api_key: str = ""
    
    # Abuse.ch feeds (no API key needed)
    abusech_enabled: bool = True
    
    # Update intervals (hours)
    update_interval_hours: int = 6
    
    # Cache settings
    cache_dir: str = "threat_feeds"


class ThreatFeedService:
    """
    Service for fetching and querying threat intelligence feeds.
    """
    
    def __init__(self, config: ThreatFeedConfig = None):
        self.config = config or ThreatFeedConfig()
        self._session: Optional[aiohttp.ClientSession] = None
        
        # In-memory IOC cache
        self._malicious_ips: Set[str] = set()
        self._malicious_domains: Set[str] = set()
        self._malicious_urls: Set[str] = set()
        self._malicious_hashes: Dict[str, Dict] = {}  # hash -> info
        self._c2_servers: Set[str] = set()
        
        # Last update times
        self._last_update: Optional[datetime] = None
        self._update_lock = asyncio.Lock()
        
        # Stats
        self.stats = {
            "total_ips": 0,
            "total_domains": 0,
            "total_urls": 0,
            "total_hashes": 0,
            "total_c2": 0,
            "last_update": None,
            "sources": []
        }
        
        # Ensure cache directory exists
        os.makedirs(self.config.cache_dir, exist_ok=True)
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def close(self):
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    # ==================== FEED UPDATES ====================
    
    async def update_feeds(self, force: bool = False) -> Dict[str, Any]:
        """
        Update all enabled threat feeds.
        
        Args:
            force: Force update even if recently updated
            
        Returns:
            Dict with update results
        """
        async with self._update_lock:
            # Check if update is needed
            if not force and self._last_update:
                time_since_update = datetime.utcnow() - self._last_update
                if time_since_update < timedelta(hours=self.config.update_interval_hours):
                    return {
                        "updated": False,
                        "reason": f"Last update was {time_since_update.total_seconds() / 3600:.1f}h ago",
                        "stats": self.stats
                    }
            
            results = {
                "updated": True,
                "sources": [],
                "errors": []
            }
            
            # Update Abuse.ch feeds (free, no API key)
            if self.config.abusech_enabled:
                try:
                    await self._update_abusech_feeds()
                    results["sources"].append("abuse.ch")
                except Exception as e:
                    logger.error(f"Abuse.ch update failed: {e}")
                    results["errors"].append(f"abuse.ch: {str(e)}")
            
            # Update AlienVault OTX (requires API key)
            if self.config.otx_enabled and self.config.otx_api_key:
                try:
                    await self._update_otx_feeds()
                    results["sources"].append("otx")
                except Exception as e:
                    logger.error(f"OTX update failed: {e}")
                    results["errors"].append(f"otx: {str(e)}")
            
            # Update stats
            self._last_update = datetime.utcnow()
            self.stats = {
                "total_ips": len(self._malicious_ips),
                "total_domains": len(self._malicious_domains),
                "total_urls": len(self._malicious_urls),
                "total_hashes": len(self._malicious_hashes),
                "total_c2": len(self._c2_servers),
                "last_update": self._last_update.isoformat(),
                "sources": results["sources"]
            }
            
            results["stats"] = self.stats
            logger.info(f"Threat feeds updated: {self.stats}")
            
            return results
    
    async def _update_abusech_feeds(self):
        """Update Abuse.ch threat feeds."""
        session = await self._get_session()
        
        # URLhaus - Malicious URLs
        try:
            async with session.get(
                "https://urlhaus.abuse.ch/downloads/text_recent/",
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    text = await response.text()
                    for line in text.strip().split('\n'):
                        if line and not line.startswith('#'):
                            self._malicious_urls.add(line.strip())
                    logger.info(f"URLhaus: loaded {len(self._malicious_urls)} URLs")
        except Exception as e:
            logger.warning(f"URLhaus fetch failed: {e}")
        
        # FeodoTracker - C2 servers (IPs)
        try:
            async with session.get(
                "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    text = await response.text()
                    for line in text.strip().split('\n'):
                        if line and not line.startswith('#'):
                            ip = line.strip()
                            self._c2_servers.add(ip)
                            self._malicious_ips.add(ip)
                    logger.info(f"FeodoTracker: loaded {len(self._c2_servers)} C2 IPs")
        except Exception as e:
            logger.warning(f"FeodoTracker fetch failed: {e}")
        
        # ThreatFox - IOCs (IPs and domains)
        try:
            async with session.get(
                "https://threatfox.abuse.ch/downloads/hostfile/",
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    text = await response.text()
                    for line in text.strip().split('\n'):
                        if line and not line.startswith('#') and '127.0.0.1' in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                domain = parts[1].strip()
                                if domain and domain != 'localhost':
                                    self._malicious_domains.add(domain)
                    logger.info(f"ThreatFox: loaded {len(self._malicious_domains)} domains")
        except Exception as e:
            logger.warning(f"ThreatFox fetch failed: {e}")
        
        # MalwareBazaar - Recent malware hashes
        try:
            async with session.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_recent", "selector": "100"},
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("query_status") == "ok":
                        for sample in data.get("data", []):
                            sha256 = sample.get("sha256_hash")
                            if sha256:
                                self._malicious_hashes[sha256.lower()] = {
                                    "sha256": sha256,
                                    "md5": sample.get("md5_hash"),
                                    "sha1": sample.get("sha1_hash"),
                                    "file_type": sample.get("file_type"),
                                    "signature": sample.get("signature"),
                                    "tags": sample.get("tags", [])
                                }
                        logger.info(f"MalwareBazaar: loaded {len(self._malicious_hashes)} hashes")
        except Exception as e:
            logger.warning(f"MalwareBazaar fetch failed: {e}")
    
    async def _update_otx_feeds(self):
        """Update AlienVault OTX feeds."""
        session = await self._get_session()
        headers = {"X-OTX-API-KEY": self.config.otx_api_key}
        
        try:
            # Get subscribed pulses
            async with session.get(
                "https://otx.alienvault.com/api/v1/pulses/subscribed",
                headers=headers,
                params={"limit": 50, "modified_since": (datetime.utcnow() - timedelta(days=7)).isoformat()},
                timeout=aiohttp.ClientTimeout(total=60)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    for pulse in data.get("results", []):
                        for indicator in pulse.get("indicators", []):
                            ioc_type = indicator.get("type", "").lower()
                            value = indicator.get("indicator", "")
                            
                            if ioc_type == "ipv4":
                                self._malicious_ips.add(value)
                            elif ioc_type == "domain":
                                self._malicious_domains.add(value)
                            elif ioc_type == "url":
                                self._malicious_urls.add(value)
                            elif ioc_type in ["filehash-sha256", "sha256"]:
                                self._malicious_hashes[value.lower()] = {
                                    "sha256": value,
                                    "source": "otx",
                                    "pulse": pulse.get("name")
                                }
                    
                    logger.info(f"OTX: processed {len(data.get('results', []))} pulses")
                elif response.status == 403:
                    logger.error("OTX API key invalid or expired")
        except Exception as e:
            logger.warning(f"OTX fetch failed: {e}")
    
    # ==================== IOC LOOKUPS ====================
    
    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Check if an IP is in threat feeds.
        
        Returns:
            Dict with threat info if malicious, None if clean
        """
        if ip in self._malicious_ips:
            is_c2 = ip in self._c2_servers
            return {
                "malicious": True,
                "indicator_type": "ip",
                "value": ip,
                "is_c2": is_c2,
                "threat_type": "c2_server" if is_c2 else "malicious_ip",
                "confidence": 0.9 if is_c2 else 0.7,
                "sources": self.stats.get("sources", [])
            }
        return None
    
    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check if a domain is in threat feeds."""
        domain = domain.lower().strip()
        if domain in self._malicious_domains:
            return {
                "malicious": True,
                "indicator_type": "domain",
                "value": domain,
                "threat_type": "malicious_domain",
                "confidence": 0.8,
                "sources": self.stats.get("sources", [])
            }
        return None
    
    def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Check if a URL is in threat feeds."""
        if url in self._malicious_urls:
            return {
                "malicious": True,
                "indicator_type": "url",
                "value": url,
                "threat_type": "malicious_url",
                "confidence": 0.9,
                "sources": self.stats.get("sources", [])
            }
        return None
    
    def check_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check if a file hash is in threat feeds."""
        file_hash = file_hash.lower().strip()
        if file_hash in self._malicious_hashes:
            info = self._malicious_hashes[file_hash]
            return {
                "malicious": True,
                "indicator_type": "hash",
                "value": file_hash,
                "threat_type": "malware",
                "confidence": 0.95,
                "details": info,
                "sources": self.stats.get("sources", [])
            }
        return None
    
    def check_indicator(self, indicator: str, indicator_type: str = "auto") -> Optional[Dict[str, Any]]:
        """
        Check any indicator against threat feeds.
        
        Args:
            indicator: The IOC value to check
            indicator_type: "ip", "domain", "url", "hash", or "auto" to detect
        """
        if indicator_type == "auto":
            # Auto-detect type
            indicator_type = self._detect_indicator_type(indicator)
        
        if indicator_type == "ip":
            return self.check_ip(indicator)
        elif indicator_type == "domain":
            return self.check_domain(indicator)
        elif indicator_type == "url":
            return self.check_url(indicator)
        elif indicator_type == "hash":
            return self.check_hash(indicator)
        
        return None
    
    def _detect_indicator_type(self, indicator: str) -> str:
        """Auto-detect indicator type."""
        import re
        
        # IP address pattern
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, indicator):
            return "ip"
        
        # URL pattern
        if indicator.startswith(('http://', 'https://')):
            return "url"
        
        # Hash patterns
        if len(indicator) == 32 and all(c in '0123456789abcdefABCDEF' for c in indicator):
            return "hash"  # MD5
        if len(indicator) == 40 and all(c in '0123456789abcdefABCDEF' for c in indicator):
            return "hash"  # SHA1
        if len(indicator) == 64 and all(c in '0123456789abcdefABCDEF' for c in indicator):
            return "hash"  # SHA256
        
        # Default to domain
        return "domain"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current threat feed statistics."""
        return self.stats


# Global instance
_threat_feed_service: Optional[ThreatFeedService] = None


def get_threat_feed_service() -> ThreatFeedService:
    """Get the global threat feed service instance."""
    global _threat_feed_service
    if _threat_feed_service is None:
        _threat_feed_service = ThreatFeedService()
    return _threat_feed_service


def configure_threat_feeds(config: ThreatFeedConfig) -> ThreatFeedService:
    """Configure the global threat feed service."""
    global _threat_feed_service
    _threat_feed_service = ThreatFeedService(config)
    return _threat_feed_service
