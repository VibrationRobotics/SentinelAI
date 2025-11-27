"""
Log Collection API endpoints for SentinelAI.
"""
from fastapi import APIRouter, HTTPException, status, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import logging

from app.services.log_collector import get_log_collector, LogSource

logger = logging.getLogger(__name__)
router = APIRouter()


class LogSourceCreate(BaseModel):
    """Model for creating a new log source."""
    name: str
    source_type: str  # file, windows_event, syslog
    path: Optional[str] = None
    event_log_name: Optional[str] = None
    parser: Optional[str] = None
    enabled: bool = True


class SearchRequest(BaseModel):
    """Model for log search."""
    query: str
    limit: int = 100


@router.get("/stats")
async def get_log_stats() -> JSONResponse:
    """Get log collector statistics."""
    try:
        collector = get_log_collector()
        return JSONResponse(status_code=status.HTTP_200_OK, content=collector.get_stats())
    except Exception as e:
        logger.error(f"Error getting log stats: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/start")
async def start_log_collector() -> JSONResponse:
    """Start the log collector."""
    try:
        collector = get_log_collector()
        success = collector.start()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Log collector started" if success else "Already running", "success": success}
        )
    except Exception as e:
        logger.error(f"Error starting log collector: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/stop")
async def stop_log_collector() -> JSONResponse:
    """Stop the log collector."""
    try:
        collector = get_log_collector()
        collector.stop()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Log collector stopped"}
        )
    except Exception as e:
        logger.error(f"Error stopping log collector: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/sources")
async def get_log_sources() -> JSONResponse:
    """Get configured log sources."""
    try:
        collector = get_log_collector()
        sources = collector.get_sources()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"sources": sources, "count": len(sources)}
        )
    except Exception as e:
        logger.error(f"Error getting log sources: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/sources")
async def add_log_source(source: LogSourceCreate) -> JSONResponse:
    """Add a new log source."""
    try:
        collector = get_log_collector()
        
        new_source = LogSource(
            name=source.name,
            source_type=source.source_type,
            path=source.path,
            event_log_name=source.event_log_name,
            parser=source.parser,
            enabled=source.enabled
        )
        
        collector.add_source(new_source)
        
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"message": f"Log source '{source.name}' added", "source": source.dict()}
        )
    except Exception as e:
        logger.error(f"Error adding log source: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/entries")
async def get_log_entries(
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    source: Optional[str] = Query(None, description="Filter by source name"),
    threats_only: bool = Query(False, description="Only show entries with threat indicators")
) -> JSONResponse:
    """Get recent log entries with optional filtering."""
    try:
        collector = get_log_collector()
        entries = collector.get_recent_entries(
            limit=limit,
            severity=severity,
            source=source,
            threats_only=threats_only
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"entries": entries, "count": len(entries)}
        )
    except Exception as e:
        logger.error(f"Error getting log entries: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/threats")
async def get_threat_summary() -> JSONResponse:
    """Get summary of detected threats from logs."""
    try:
        collector = get_log_collector()
        summary = collector.get_threat_summary()
        return JSONResponse(status_code=status.HTTP_200_OK, content=summary)
    except Exception as e:
        logger.error(f"Error getting threat summary: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/search")
async def search_logs(request: SearchRequest) -> JSONResponse:
    """Search log entries by keyword."""
    try:
        collector = get_log_collector()
        results = collector.search_logs(request.query, request.limit)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"results": results, "count": len(results), "query": request.query}
        )
    except Exception as e:
        logger.error(f"Error searching logs: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/by-severity")
async def get_logs_by_severity() -> JSONResponse:
    """Get log counts grouped by severity."""
    try:
        collector = get_log_collector()
        stats = collector.get_stats()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"by_severity": stats.get("by_severity", {})}
        )
    except Exception as e:
        logger.error(f"Error getting logs by severity: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.get("/by-source")
async def get_logs_by_source() -> JSONResponse:
    """Get log counts grouped by source."""
    try:
        collector = get_log_collector()
        stats = collector.get_stats()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"by_source": stats.get("by_source", {})}
        )
    except Exception as e:
        logger.error(f"Error getting logs by source: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )
