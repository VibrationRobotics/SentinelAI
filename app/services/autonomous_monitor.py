"""
Autonomous System Health Monitor
Self-healing capabilities for SentinelAI infrastructure
"""
import asyncio
import logging
import subprocess
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, List
import httpx
import redis.asyncio as redis

logger = logging.getLogger(__name__)


class AutonomousMonitor:
    """
    Autonomous multi-agent system monitor with self-healing capabilities.
    Monitors Docker containers, services, and agents - auto-restarts unhealthy components.
    """
    
    def __init__(
        self,
        redis_url: str = None,
        check_interval: int = 30,
        max_restart_attempts: int = 3,
        restart_cooldown: int = 300  # 5 minutes between restart attempts
    ):
        # Use Docker-internal hostname if running in container, else localhost
        import os
        if os.environ.get("DOCKER_CONTAINER") or os.path.exists("/.dockerenv"):
            self.redis_url = redis_url or "redis://redis:6379"
            self.internal_api_url = "http://web:8000"
        else:
            self.redis_url = redis_url or "redis://localhost:6379"
            self.internal_api_url = "http://localhost:8015"
        self.check_interval = check_interval
        self.max_restart_attempts = max_restart_attempts
        self.restart_cooldown = restart_cooldown
        self.redis_client: Optional[redis.Redis] = None
        self.running = False
        
        # Track restart attempts per component
        self.restart_attempts: Dict[str, List[datetime]] = {}
        
        # Components to monitor
        self.docker_containers = [
            "sentinelai-web-1",
            "sentinelai-db-1", 
            "sentinelai-redis-1"
        ]
        
        # Health check endpoints (set after init)
        self.health_endpoints = {
            "web": f"{self.internal_api_url}/api/v1/health",
            "db": None,  # Checked via container status
            "redis": None  # Checked via ping
        }
    
    async def start(self):
        """Start the autonomous monitoring loop."""
        self.running = True
        logger.info("🤖 Autonomous Monitor starting...")
        
        try:
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            logger.info("✅ Connected to Redis for health tracking")
        except Exception as e:
            logger.warning(f"Redis not available for health tracking: {e}")
            self.redis_client = None
        
        while self.running:
            try:
                await self._check_all_components()
                await asyncio.sleep(self.check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                await asyncio.sleep(10)
        
        logger.info("Autonomous Monitor stopped")
    
    async def stop(self):
        """Stop the monitoring loop."""
        self.running = False
        if self.redis_client:
            await self.redis_client.close()
    
    async def _check_all_components(self):
        """Check health of all monitored components."""
        results = {}
        
        # Check Docker containers
        for container in self.docker_containers:
            status = await self._check_docker_container(container)
            results[container] = status
            
            if status["status"] == "unhealthy":
                await self._handle_unhealthy_container(container, status)
        
        # Check web API health
        web_health = await self._check_web_health()
        results["web_api"] = web_health
        
        # Check Redis health
        redis_health = await self._check_redis_health()
        results["redis"] = redis_health
        
        # Check agent connectivity
        agent_health = await self._check_agents()
        results["agents"] = agent_health
        
        # Store health status in Redis
        if self.redis_client:
            await self._store_health_status(results)
        
        return results
    
    async def _check_docker_container(self, container_name: str) -> Dict:
        """Check if a Docker container is healthy."""
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", container_name],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode != 0:
                # Try getting just the status
                result = subprocess.run(
                    ["docker", "inspect", "--format", "{{.State.Status}}", container_name],
                    capture_output=True, text=True, timeout=10
                )
            
            status = result.stdout.strip()
            
            if status in ["healthy", "running"]:
                return {"status": "healthy", "container_status": status}
            elif status == "unhealthy":
                return {"status": "unhealthy", "container_status": status}
            else:
                return {"status": "unknown", "container_status": status}
                
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "error": "Docker command timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _handle_unhealthy_container(self, container_name: str, status: Dict):
        """Handle an unhealthy container - attempt restart if within limits."""
        logger.warning(f"🔴 Container {container_name} is unhealthy: {status}")
        
        # Check restart cooldown
        if not self._can_restart(container_name):
            logger.warning(f"⏳ Container {container_name} in cooldown, skipping restart")
            return
        
        # Attempt restart
        logger.info(f"🔄 Attempting to restart {container_name}...")
        
        try:
            result = subprocess.run(
                ["docker", "restart", container_name],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                logger.info(f"✅ Successfully restarted {container_name}")
                self._record_restart(container_name)
                
                # Log to audit
                await self._log_auto_action(
                    component=container_name,
                    action="restart",
                    reason=f"Container was unhealthy: {status.get('container_status', 'unknown')}",
                    success=True
                )
            else:
                logger.error(f"❌ Failed to restart {container_name}: {result.stderr}")
                await self._log_auto_action(
                    component=container_name,
                    action="restart",
                    reason=f"Container was unhealthy",
                    success=False,
                    error=result.stderr
                )
                
        except Exception as e:
            logger.error(f"❌ Exception restarting {container_name}: {e}")
    
    def _can_restart(self, component: str) -> bool:
        """Check if we can restart a component (respecting cooldown and max attempts)."""
        if component not in self.restart_attempts:
            return True
        
        # Filter to recent attempts within cooldown period
        cutoff = datetime.now() - timedelta(seconds=self.restart_cooldown)
        recent_attempts = [t for t in self.restart_attempts[component] if t > cutoff]
        self.restart_attempts[component] = recent_attempts
        
        return len(recent_attempts) < self.max_restart_attempts
    
    def _record_restart(self, component: str):
        """Record a restart attempt."""
        if component not in self.restart_attempts:
            self.restart_attempts[component] = []
        self.restart_attempts[component].append(datetime.now())
    
    async def _check_web_health(self) -> Dict:
        """Check web API health endpoint."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                start = time.time()
                response = await client.get(self.health_endpoints["web"])
                elapsed = int((time.time() - start) * 1000)
                
                if response.status_code == 200:
                    return {"status": "healthy", "response_time_ms": elapsed}
                else:
                    return {"status": "degraded", "status_code": response.status_code}
                    
        except httpx.TimeoutException:
            return {"status": "unhealthy", "error": "timeout"}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    async def _check_redis_health(self) -> Dict:
        """Check Redis health via ping."""
        if not self.redis_client:
            return {"status": "unknown", "error": "No Redis client"}
        
        try:
            start = time.time()
            await self.redis_client.ping()
            elapsed = int((time.time() - start) * 1000)
            return {"status": "healthy", "response_time_ms": elapsed}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    async def _check_agents(self) -> Dict:
        """Check connected agents status."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.internal_api_url}/api/v1/windows/agent/list")
                
                if response.status_code == 200:
                    data = response.json()
                    agents = data.get("agents", [])
                    
                    online = sum(1 for a in agents if a.get("status") == "online")
                    offline = sum(1 for a in agents if a.get("status") == "offline")
                    
                    return {
                        "status": "healthy" if online > 0 else "degraded",
                        "total": len(agents),
                        "online": online,
                        "offline": offline
                    }
                else:
                    return {"status": "error", "status_code": response.status_code}
                    
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _store_health_status(self, results: Dict):
        """Store health status in Redis for dashboard display."""
        if not self.redis_client:
            return
        
        try:
            await self.redis_client.hset(
                "sentinel:health",
                mapping={
                    "last_check": datetime.now().isoformat(),
                    "status": "healthy" if all(
                        r.get("status") == "healthy" 
                        for r in results.values() 
                        if isinstance(r, dict)
                    ) else "degraded",
                    "details": str(results)
                }
            )
            await self.redis_client.expire("sentinel:health", 120)  # 2 minute TTL
        except Exception as e:
            logger.debug(f"Failed to store health status: {e}")
    
    async def _log_auto_action(
        self,
        component: str,
        action: str,
        reason: str,
        success: bool,
        error: Optional[str] = None
    ):
        """Log autonomous action to the database via API."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    f"{self.internal_api_url}/api/v1/audit",
                    json={
                        "source": "autonomous_monitor",
                        "action": f"auto_{action}",
                        "severity": "WARNING" if success else "ERROR",
                        "description": f"Auto-{action} {component}: {reason}",
                        "details": {
                            "component": component,
                            "action": action,
                            "success": success,
                            "error": error
                        }
                    }
                )
        except Exception as e:
            logger.debug(f"Failed to log auto action: {e}")


# Singleton instance
_monitor: Optional[AutonomousMonitor] = None


def get_autonomous_monitor() -> AutonomousMonitor:
    """Get or create the autonomous monitor instance."""
    global _monitor
    if _monitor is None:
        _monitor = AutonomousMonitor()
    return _monitor


async def start_autonomous_monitor():
    """Start the autonomous monitor in the background."""
    monitor = get_autonomous_monitor()
    asyncio.create_task(monitor.start())
    logger.info("🤖 Autonomous Monitor task created")
