"""
Monitoring API endpoints for SentinelAI.
Provides access to network, file, and process monitoring services.
"""
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import logging

from app.services.network_monitor import get_network_monitor
from app.services.file_scanner import get_file_scanner
from app.services.process_monitor import get_process_monitor

logger = logging.getLogger(__name__)
router = APIRouter()


# ============== Network Monitor Endpoints ==============

@router.get("/network/stats")
async def get_network_stats() -> JSONResponse:
    """Get network monitoring statistics."""
    try:
        monitor = get_network_monitor()
        return JSONResponse(status_code=status.HTTP_200_OK, content=monitor.get_stats())
    except Exception as e:
        logger.error(f"Error getting network stats: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/network/start")
async def start_network_monitor() -> JSONResponse:
    """Start the network monitor."""
    try:
        monitor = get_network_monitor()
        success = monitor.start()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Network monitor started" if success else "Failed to start", "success": success}
        )
    except Exception as e:
        logger.error(f"Error starting network monitor: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/network/stop")
async def stop_network_monitor() -> JSONResponse:
    """Stop the network monitor."""
    try:
        monitor = get_network_monitor()
        monitor.stop()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Network monitor stopped"}
        )
    except Exception as e:
        logger.error(f"Error stopping network monitor: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/network/events")
async def get_network_events(limit: int = 50) -> JSONResponse:
    """Get recent network events."""
    try:
        monitor = get_network_monitor()
        events = monitor.get_recent_events(limit)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"events": events, "count": len(events)}
        )
    except Exception as e:
        logger.error(f"Error getting network events: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/network/top-sources")
async def get_top_sources(limit: int = 10) -> JSONResponse:
    """Get top source IPs by connection count."""
    try:
        monitor = get_network_monitor()
        sources = monitor.get_top_sources(limit)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"sources": sources}
        )
    except Exception as e:
        logger.error(f"Error getting top sources: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


# ============== File Scanner Endpoints ==============

@router.get("/files/stats")
async def get_file_scanner_stats() -> JSONResponse:
    """Get file scanner statistics."""
    try:
        scanner = get_file_scanner()
        return JSONResponse(status_code=status.HTTP_200_OK, content=scanner.get_stats())
    except Exception as e:
        logger.error(f"Error getting file scanner stats: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/files/start")
async def start_file_scanner() -> JSONResponse:
    """Start the file scanner."""
    try:
        scanner = get_file_scanner()
        success = scanner.start()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "File scanner started" if success else "Failed to start", "success": success}
        )
    except Exception as e:
        logger.error(f"Error starting file scanner: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/files/stop")
async def stop_file_scanner() -> JSONResponse:
    """Stop the file scanner."""
    try:
        scanner = get_file_scanner()
        scanner.stop()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "File scanner stopped"}
        )
    except Exception as e:
        logger.error(f"Error stopping file scanner: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


class ScanRequest(BaseModel):
    path: str
    recursive: bool = True


@router.post("/files/scan")
async def scan_path(request: ScanRequest) -> JSONResponse:
    """Scan a file or directory."""
    try:
        scanner = get_file_scanner()
        
        import os
        if os.path.isfile(request.path):
            result = scanner.scan_file(request.path, "api_request")
            if result:
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={
                        "file_path": result.file_path,
                        "is_malicious": result.is_malicious,
                        "threat_name": result.threat_name,
                        "severity": result.severity,
                        "detection_method": result.detection_method
                    }
                )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Could not scan file"}
            )
        elif os.path.isdir(request.path):
            results = scanner.scan_directory(request.path, request.recursive)
            threats = [r for r in results if r.is_malicious]
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "files_scanned": len(results),
                    "threats_found": len(threats),
                    "threats": [
                        {
                            "file_path": r.file_path,
                            "threat_name": r.threat_name,
                            "severity": r.severity
                        }
                        for r in threats
                    ]
                }
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": "Path not found"}
            )
    except Exception as e:
        logger.error(f"Error scanning path: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/files/results")
async def get_scan_results(limit: int = 50, threats_only: bool = False) -> JSONResponse:
    """Get recent scan results."""
    try:
        scanner = get_file_scanner()
        results = scanner.get_recent_results(limit, threats_only)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"results": results, "count": len(results)}
        )
    except Exception as e:
        logger.error(f"Error getting scan results: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


class QuarantineRequest(BaseModel):
    file_path: str


@router.post("/files/quarantine")
async def quarantine_file(request: QuarantineRequest) -> JSONResponse:
    """Quarantine a file."""
    try:
        scanner = get_file_scanner()
        success = scanner.quarantine_file(request.file_path)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "File quarantined" if success else "Failed to quarantine", "success": success}
        )
    except Exception as e:
        logger.error(f"Error quarantining file: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


# ============== Process Monitor Endpoints ==============

@router.get("/processes/stats")
async def get_process_stats() -> JSONResponse:
    """Get process monitor statistics."""
    try:
        monitor = get_process_monitor()
        return JSONResponse(status_code=status.HTTP_200_OK, content=monitor.get_stats())
    except Exception as e:
        logger.error(f"Error getting process stats: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/processes/start")
async def start_process_monitor() -> JSONResponse:
    """Start the process monitor."""
    try:
        monitor = get_process_monitor()
        success = monitor.start()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Process monitor started" if success else "Failed to start", "success": success}
        )
    except Exception as e:
        logger.error(f"Error starting process monitor: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/processes/stop")
async def stop_process_monitor() -> JSONResponse:
    """Stop the process monitor."""
    try:
        monitor = get_process_monitor()
        monitor.stop()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Process monitor stopped"}
        )
    except Exception as e:
        logger.error(f"Error stopping process monitor: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/processes/suspicious")
async def get_suspicious_processes() -> JSONResponse:
    """Get list of suspicious processes."""
    try:
        monitor = get_process_monitor()
        processes = monitor.get_suspicious_processes()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"processes": processes, "count": len(processes)}
        )
    except Exception as e:
        logger.error(f"Error getting suspicious processes: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/processes/events")
async def get_process_events(limit: int = 50) -> JSONResponse:
    """Get recent process events."""
    try:
        monitor = get_process_monitor()
        events = monitor.get_recent_events(limit)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"events": events, "count": len(events)}
        )
    except Exception as e:
        logger.error(f"Error getting process events: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/processes/top-cpu")
async def get_top_cpu_processes(limit: int = 10) -> JSONResponse:
    """Get processes with highest CPU usage."""
    try:
        monitor = get_process_monitor()
        processes = monitor.get_top_cpu_processes(limit)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"processes": processes}
        )
    except Exception as e:
        logger.error(f"Error getting top CPU processes: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


class KillProcessRequest(BaseModel):
    pid: int


@router.post("/processes/kill")
async def kill_process(request: KillProcessRequest) -> JSONResponse:
    """Kill a process by PID."""
    try:
        monitor = get_process_monitor()
        success = monitor.kill_process(request.pid)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": f"Process {request.pid} killed" if success else "Failed to kill process", "success": success}
        )
    except Exception as e:
        logger.error(f"Error killing process: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


# ============== Combined Status Endpoint ==============

@router.get("/status")
async def get_all_monitoring_status() -> JSONResponse:
    """Get status of all monitoring services."""
    try:
        network = get_network_monitor()
        files = get_file_scanner()
        processes = get_process_monitor()
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "network_monitor": network.get_stats(),
                "file_scanner": files.get_stats(),
                "process_monitor": processes.get_stats()
            }
        )
    except Exception as e:
        logger.error(f"Error getting monitoring status: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/start-all")
async def start_all_monitors() -> JSONResponse:
    """Start all monitoring services."""
    try:
        results = {}
        
        network = get_network_monitor()
        results["network_monitor"] = network.start()
        
        files = get_file_scanner()
        results["file_scanner"] = files.start()
        
        processes = get_process_monitor()
        results["process_monitor"] = processes.start()
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Monitors started", "results": results}
        )
    except Exception as e:
        logger.error(f"Error starting monitors: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/stop-all")
async def stop_all_monitors() -> JSONResponse:
    """Stop all monitoring services."""
    try:
        network = get_network_monitor()
        network.stop()
        
        files = get_file_scanner()
        files.stop()
        
        processes = get_process_monitor()
        processes.stop()
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "All monitors stopped"}
        )
    except Exception as e:
        logger.error(f"Error stopping monitors: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )
