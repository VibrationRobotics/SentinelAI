"""
IP Geolocation Service for SentinelAI.
Provides coordinates for IP addresses to display on the threat map.
"""
import logging
import httpx
from typing import Dict, Any, Optional, Tuple
from functools import lru_cache

logger = logging.getLogger(__name__)

# Cache for IP lookups to avoid repeated API calls
IP_CACHE: Dict[str, Dict[str, Any]] = {}

# Known private IP ranges (these won't have real geolocation)
PRIVATE_RANGES = [
    ("10.", "10.255.255.255"),
    ("172.16.", "172.31.255.255"),
    ("192.168.", "192.168.255.255"),
    ("127.", "127.255.255.255"),
]

# Simulated locations for demo/testing (maps private IPs to interesting locations)
SIMULATED_LOCATIONS = {
    "10.0.0": {"lat": 37.7749, "lon": -122.4194, "city": "San Francisco", "country": "US"},
    "192.168.1": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
    "192.168.0": {"lat": 51.5074, "lon": -0.1278, "city": "London", "country": "GB"},
    "172.16": {"lat": 35.6762, "lon": 139.6503, "city": "Tokyo", "country": "JP"},
}

# Known malicious IP location simulations (for demo purposes)
THREAT_LOCATIONS = {
    # Russia
    "185.": {"lat": 55.7558, "lon": 37.6173, "city": "Moscow", "country": "RU"},
    # China  
    "103.": {"lat": 39.9042, "lon": 116.4074, "city": "Beijing", "country": "CN"},
    "116.": {"lat": 31.2304, "lon": 121.4737, "city": "Shanghai", "country": "CN"},
    # North Korea
    "175.45": {"lat": 39.0392, "lon": 125.7625, "city": "Pyongyang", "country": "KP"},
    # Iran
    "5.": {"lat": 35.6892, "lon": 51.3890, "city": "Tehran", "country": "IR"},
    # Eastern Europe
    "91.": {"lat": 50.4501, "lon": 30.5234, "city": "Kyiv", "country": "UA"},
    "77.": {"lat": 52.2297, "lon": 21.0122, "city": "Warsaw", "country": "PL"},
    # South America
    "200.": {"lat": -23.5505, "lon": -46.6333, "city": "São Paulo", "country": "BR"},
    "201.": {"lat": -34.6037, "lon": -58.3816, "city": "Buenos Aires", "country": "AR"},
    # Default for unknown
    "default": {"lat": 0, "lon": 0, "city": "Unknown", "country": "XX"},
}


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private range."""
    for prefix, _ in PRIVATE_RANGES:
        if ip.startswith(prefix):
            return True
    return False


def get_simulated_location(ip: str) -> Optional[Dict[str, Any]]:
    """Get a simulated location for an IP address."""
    # Check private IP simulations
    for prefix, location in SIMULATED_LOCATIONS.items():
        if ip.startswith(prefix):
            return location
    
    # Check threat location simulations
    for prefix, location in THREAT_LOCATIONS.items():
        if ip.startswith(prefix):
            return location
    
    # Generate a pseudo-random location based on IP octets
    try:
        octets = ip.split(".")
        if len(octets) >= 2:
            # Use octets to generate coordinates
            lat = (int(octets[0]) % 180) - 90  # -90 to 90
            lon = (int(octets[1]) % 360) - 180  # -180 to 180
            return {
                "lat": lat + (int(octets[2]) if len(octets) > 2 else 0) / 255 * 10,
                "lon": lon + (int(octets[3]) if len(octets) > 3 else 0) / 255 * 10,
                "city": f"Location {octets[0]}.{octets[1]}",
                "country": "XX"
            }
    except (ValueError, IndexError):
        pass
    
    return THREAT_LOCATIONS["default"]


async def get_ip_location(ip: str, use_api: bool = True) -> Optional[Dict[str, Any]]:
    """
    Get geolocation data for an IP address.
    
    Args:
        ip: The IP address to look up
        use_api: Whether to use the real API (False = simulation only)
        
    Returns:
        Dictionary with lat, lon, city, country, etc.
    """
    # Check cache first
    if ip in IP_CACHE:
        return IP_CACHE[ip]
    
    # For private IPs, use simulation
    if is_private_ip(ip):
        location = get_simulated_location(ip)
        if location:
            IP_CACHE[ip] = location
            return location
    
    # Try real API lookup
    if use_api:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                # Using ip-api.com (free, no API key needed, 45 requests/minute)
                response = await client.get(f"http://ip-api.com/json/{ip}")
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get("status") == "success":
                        location = {
                            "lat": data.get("lat", 0),
                            "lon": data.get("lon", 0),
                            "city": data.get("city", "Unknown"),
                            "region": data.get("regionName", ""),
                            "country": data.get("countryCode", "XX"),
                            "country_name": data.get("country", "Unknown"),
                            "isp": data.get("isp", ""),
                            "org": data.get("org", ""),
                            "as": data.get("as", ""),
                        }
                        IP_CACHE[ip] = location
                        logger.info(f"Geolocated {ip} to {location['city']}, {location['country']}")
                        return location
        except Exception as e:
            logger.warning(f"IP geolocation API failed for {ip}: {e}")
    
    # Fallback to simulation
    location = get_simulated_location(ip)
    if location:
        IP_CACHE[ip] = location
    return location


def get_ip_location_sync(ip: str) -> Optional[Dict[str, Any]]:
    """Synchronous version of get_ip_location using simulation only."""
    if ip in IP_CACHE:
        return IP_CACHE[ip]
    
    location = get_simulated_location(ip)
    if location:
        IP_CACHE[ip] = location
    return location


def enrich_threat_with_location(threat: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add geolocation data to a threat object.
    
    Args:
        threat: Threat dictionary with source_ip
        
    Returns:
        Threat dictionary with added latitude, longitude, location fields
    """
    source_ip = threat.get("source_ip", "")
    
    if source_ip:
        location = get_ip_location_sync(source_ip)
        if location:
            threat["latitude"] = location.get("lat")
            threat["longitude"] = location.get("lon")
            threat["location"] = {
                "city": location.get("city", "Unknown"),
                "country": location.get("country", "XX"),
                "country_name": location.get("country_name", location.get("country", "Unknown")),
            }
    
    return threat
