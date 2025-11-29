"""
VirusTotal Integration Service for SentinelAI.
Provides hash, URL, and IP reputation checking.
"""
import os
import logging
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import asyncio

logger = logging.getLogger(__name__)

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    logger.warning("aiohttp not available - VirusTotal async calls disabled")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class VirusTotalService:
    """
    VirusTotal API integration for threat intelligence.
    
    Features:
    - File hash lookup
    - URL scanning
    - IP reputation
    - Domain reputation
    - Rate limiting (4 requests/minute for free tier)
    """
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
        self.enabled = bool(self.api_key)
        self._last_request = datetime.min
        self._request_count = 0
        self._daily_count = 0
        self._daily_reset = datetime.utcnow().date()
        
        # Free tier limits: 4 req/min, 500/day, 15.5K/month
        self._rate_limit = 4  # requests per minute
        self._daily_limit = 500  # requests per day
        
        self._cache: Dict[str, Dict] = {}  # Simple in-memory cache
        self._cache_ttl = timedelta(hours=24)  # Cache longer to save quota
        
        if self.enabled:
            logger.info("VirusTotal service initialized")
        else:
            logger.warning("VirusTotal API key not configured - service disabled")
    
    def _get_headers(self) -> Dict[str, str]:
        return {"x-apikey": self.api_key}
    
    def _check_rate_limit(self) -> bool:
        """Check if we can make a request (rate limiting)."""
        now = datetime.utcnow()
        today = now.date()
        
        # Reset daily counter if new day
        if today > self._daily_reset:
            self._daily_count = 0
            self._daily_reset = today
        
        # Check daily limit (500/day)
        if self._daily_count >= self._daily_limit:
            logger.warning("VirusTotal daily quota reached (500/day)")
            return False
        
        # Reset minute counter if new minute
        if (now - self._last_request) > timedelta(minutes=1):
            self._request_count = 0
        
        # Check per-minute limit (4/min)
        if self._request_count >= self._rate_limit:
            logger.warning("VirusTotal rate limit reached (4/min)")
            return False
        
        self._request_count += 1
        self._daily_count += 1
        self._last_request = now
        return True
    
    def _get_cached(self, key: str) -> Optional[Dict]:
        """Get cached result if still valid."""
        if key in self._cache:
            cached = self._cache[key]
            if datetime.utcnow() - cached["timestamp"] < self._cache_ttl:
                return cached["data"]
            del self._cache[key]
        return None
    
    def _set_cached(self, key: str, data: Dict):
        """Cache a result."""
        self._cache[key] = {
            "timestamp": datetime.utcnow(),
            "data": data
        }
    
    def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check a file hash against VirusTotal.
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash
            
        Returns:
            Dict with detection results
        """
        if not self.enabled or not REQUESTS_AVAILABLE:
            return {"error": "VirusTotal not configured", "malicious": False}
        
        # Check cache
        cached = self._get_cached(f"hash:{file_hash}")
        if cached:
            return cached
        
        if not self._check_rate_limit():
            return {"error": "Rate limit exceeded", "malicious": False}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/files/{file_hash}",
                headers=self._get_headers(),
                timeout=10
            )
            
            if response.status_code == 404:
                result = {"found": False, "malicious": False, "hash": file_hash}
            elif response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                result = {
                    "found": True,
                    "malicious": stats.get("malicious", 0) > 0,
                    "suspicious": stats.get("suspicious", 0) > 0,
                    "detections": stats.get("malicious", 0),
                    "total_engines": sum(stats.values()),
                    "hash": file_hash,
                    "threat_names": self._extract_threat_names(data),
                    "severity": self._calculate_severity(stats)
                }
            else:
                result = {"error": f"API error: {response.status_code}", "malicious": False}
            
            self._set_cached(f"hash:{file_hash}", result)
            return result
            
        except Exception as e:
            logger.error(f"VirusTotal hash check error: {e}")
            return {"error": str(e), "malicious": False}
    
    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check a URL against VirusTotal.
        
        Args:
            url: URL to check
            
        Returns:
            Dict with detection results
        """
        if not self.enabled or not REQUESTS_AVAILABLE:
            return {"error": "VirusTotal not configured", "malicious": False}
        
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # Check cache
        cached = self._get_cached(f"url:{url_id}")
        if cached:
            return cached
        
        if not self._check_rate_limit():
            return {"error": "Rate limit exceeded", "malicious": False}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/urls/{url_id}",
                headers=self._get_headers(),
                timeout=10
            )
            
            if response.status_code == 404:
                result = {"found": False, "malicious": False, "url": url}
            elif response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                result = {
                    "found": True,
                    "malicious": stats.get("malicious", 0) > 0,
                    "suspicious": stats.get("suspicious", 0) > 0,
                    "detections": stats.get("malicious", 0),
                    "total_engines": sum(stats.values()),
                    "url": url,
                    "severity": self._calculate_severity(stats)
                }
            else:
                result = {"error": f"API error: {response.status_code}", "malicious": False}
            
            self._set_cached(f"url:{url_id}", result)
            return result
            
        except Exception as e:
            logger.error(f"VirusTotal URL check error: {e}")
            return {"error": str(e), "malicious": False}
    
    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Check an IP address reputation.
        
        Args:
            ip_address: IP to check
            
        Returns:
            Dict with reputation results
        """
        if not self.enabled or not REQUESTS_AVAILABLE:
            return {"error": "VirusTotal not configured", "malicious": False}
        
        # Check cache
        cached = self._get_cached(f"ip:{ip_address}")
        if cached:
            return cached
        
        if not self._check_rate_limit():
            return {"error": "Rate limit exceeded", "malicious": False}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/ip_addresses/{ip_address}",
                headers=self._get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                
                result = {
                    "found": True,
                    "malicious": stats.get("malicious", 0) > 0,
                    "suspicious": stats.get("suspicious", 0) > 0,
                    "detections": stats.get("malicious", 0),
                    "total_engines": sum(stats.values()),
                    "ip": ip_address,
                    "country": attrs.get("country", "Unknown"),
                    "as_owner": attrs.get("as_owner", "Unknown"),
                    "severity": self._calculate_severity(stats)
                }
            else:
                result = {"error": f"API error: {response.status_code}", "malicious": False}
            
            self._set_cached(f"ip:{ip_address}", result)
            return result
            
        except Exception as e:
            logger.error(f"VirusTotal IP check error: {e}")
            return {"error": str(e), "malicious": False}
    
    def check_domain(self, domain: str) -> Dict[str, Any]:
        """
        Check a domain reputation.
        
        Args:
            domain: Domain to check
            
        Returns:
            Dict with reputation results
        """
        if not self.enabled or not REQUESTS_AVAILABLE:
            return {"error": "VirusTotal not configured", "malicious": False}
        
        # Check cache
        cached = self._get_cached(f"domain:{domain}")
        if cached:
            return cached
        
        if not self._check_rate_limit():
            return {"error": "Rate limit exceeded", "malicious": False}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/domains/{domain}",
                headers=self._get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                
                result = {
                    "found": True,
                    "malicious": stats.get("malicious", 0) > 0,
                    "suspicious": stats.get("suspicious", 0) > 0,
                    "detections": stats.get("malicious", 0),
                    "total_engines": sum(stats.values()),
                    "domain": domain,
                    "registrar": attrs.get("registrar", "Unknown"),
                    "creation_date": attrs.get("creation_date"),
                    "severity": self._calculate_severity(stats)
                }
            else:
                result = {"error": f"API error: {response.status_code}", "malicious": False}
            
            self._set_cached(f"domain:{domain}", result)
            return result
            
        except Exception as e:
            logger.error(f"VirusTotal domain check error: {e}")
            return {"error": str(e), "malicious": False}
    
    def _extract_threat_names(self, data: Dict) -> list:
        """Extract threat names from VT response."""
        names = []
        results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
        for engine, result in results.items():
            if result.get("category") == "malicious" and result.get("result"):
                names.append(result["result"])
        return list(set(names))[:5]  # Return top 5 unique names
    
    def _calculate_severity(self, stats: Dict) -> str:
        """Calculate severity based on detection stats."""
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        if malicious >= 10:
            return "CRITICAL"
        elif malicious >= 5:
            return "HIGH"
        elif malicious >= 1 or suspicious >= 5:
            return "MEDIUM"
        elif suspicious >= 1:
            return "LOW"
        return "NONE"
    
    def get_status(self) -> Dict[str, Any]:
        """Get service status."""
        # Reset daily counter if needed
        today = datetime.utcnow().date()
        if today > self._daily_reset:
            self._daily_count = 0
            self._daily_reset = today
            
        return {
            "enabled": self.enabled,
            "api_key_configured": bool(self.api_key),
            "limits": {
                "per_minute": self._rate_limit,
                "per_day": self._daily_limit
            },
            "usage": {
                "requests_this_minute": self._request_count,
                "requests_today": self._daily_count,
                "daily_remaining": self._daily_limit - self._daily_count
            },
            "cache_size": len(self._cache),
            "cache_ttl_hours": self._cache_ttl.total_seconds() / 3600
        }


# Singleton instance
_vt_service: Optional[VirusTotalService] = None

def get_virustotal_service() -> VirusTotalService:
    """Get or create VirusTotal service instance."""
    global _vt_service
    if _vt_service is None:
        _vt_service = VirusTotalService()
    return _vt_service
