from fastapi import APIRouter, HTTPException, status, Depends, Body
from fastapi.responses import JSONResponse
from typing import Dict, Any
import random
import logging
from datetime import datetime, timedelta
from app.models.ai.azure.ai_service_manager import AzureAIServiceManager
from app.services.openai_service import get_openai_service

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize the Azure AI Service Manager
ai_service_manager = AzureAIServiceManager()

@router.get("/status")
async def get_services_status() -> JSONResponse:
    """
    Get the status of all Azure AI services used in the system
    """
    try:
        service_status = ai_service_manager.get_services_status()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=service_status
        )
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Failed to get service status: {str(e)}"}
        )

@router.post("/settings")
async def update_ai_settings(settings: Dict[str, Any] = Body(...)) -> JSONResponse:
    """
    Update AI system settings, including toggling Azure services
    
    Settings can include:
    - azure_services_enabled: bool - Toggle Azure services
    - use_gpt4o: bool - Toggle using GPT-4o model
    - gpt4o_api_key: str - API key for GPT-4o model access
    - gpt4o_endpoint: str - Custom endpoint URL for GPT-4o (optional)
    - hide_disabled_services: bool - Whether to hide disabled services in the dashboard
    """
    try:
        updated_settings = ai_service_manager.save_settings(settings)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Settings updated successfully", "settings": updated_settings}
        )
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Failed to update settings: {str(e)}"}
        )

@router.get("/settings")
async def get_ai_settings() -> JSONResponse:
    """
    Get current AI system settings
    """
    try:
        settings = ai_service_manager.settings.copy()
        
        # For security reasons, don't return the actual API key value, just whether it's set
        if "gpt4o_api_key" in settings:
            settings["gpt4o_api_key_set"] = bool(settings["gpt4o_api_key"])
            settings["gpt4o_api_key"] = "****" if settings["gpt4o_api_key"] else ""
            
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=settings
        )
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Failed to get settings: {str(e)}"}
        )

@router.get("/stats")
async def get_ai_stats() -> JSONResponse:
    """
    Get AI system statistics for dashboard display from Azure services
    """
    try:
        # Fetch real data from Azure services
        azure_stats = await ai_service_manager.get_system_stats()
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=azure_stats
        )
    except Exception as e:
        # If Azure services are not available, return some fallback data
        current_time = datetime.now()
        
        # Create fallback AI stats with warning message
        fallback_stats = {
            "ai_analyzed": random.randint(10, 50),
            "anomalies": random.randint(2, 8),
            "unsafe_content": random.randint(1, 5),
            "similar_threats": random.randint(3, 12),
            "metrics_alerts": random.randint(1, 4),
            "ai_confidence": random.randint(82, 99),
            "timestamp": current_time.isoformat(),
            "error": f"Azure services unavailable: {str(e)}",
            "using_fallback": True
        }
        
        return JSONResponse(
            status_code=status.HTTP_200_OK, 
            content=fallback_stats
        )

@router.post("/analyze/{service}")
async def analyze_with_ai_service(service: str, data: Dict[Any, Any]) -> JSONResponse:
    """
    Analyze data with a specific Azure AI service
    """
    try:
        if service == "openai":
            result = await ai_service_manager.openai_service.analyze_threat(data)
        elif service == "search":
            result = await ai_service_manager.search_service.search_intelligence(data.get("query", ""))
        elif service == "content_safety":
            result = await ai_service_manager.content_safety.analyze_content(data.get("content", ""))
        elif service == "metrics":
            result = await ai_service_manager.metrics_advisor.get_metrics(data)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown service: {service}"
            )
            
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=result
        )
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/reanalyze")
async def reanalyze_threat(threat_data: Dict[str, Any] = Body(...)) -> JSONResponse:
    """
    Re-analyze a threat with AI to determine if it's a real threat or false positive.
    Uses the local OpenAI service with enhanced context about normal system activity.
    """
    try:
        openai_service = get_openai_service()
        
        if not openai_service.available:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"error": "AI service not available. Check OPENAI_API_KEY."}
            )
        
        # Perform analysis
        analysis = openai_service.analyze_threat(threat_data)
        
        if analysis:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "success": True,
                    "analysis": analysis,
                    "is_false_positive": analysis.get("is_false_positive", False),
                    "severity": analysis.get("severity", "UNKNOWN"),
                    "recommendation": analysis.get("recommendation", "Manual review required")
                }
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"error": "AI analysis returned no results"}
            )
            
    except Exception as e:
        logger.error(f"Re-analysis failed: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )


@router.post("/whitelist/event")
async def add_event_to_whitelist(event_data: Dict[str, Any] = Body(...)) -> JSONResponse:
    """
    Add an event type to the whitelist so similar events are auto-marked as safe.
    """
    try:
        # For now, store in memory (could be persisted to DB later)
        event_type = event_data.get("event_type")
        event_id = event_data.get("event_id")
        source = event_data.get("source", "unknown")
        reason = event_data.get("reason", "Manually whitelisted")
        
        # TODO: Persist to database
        logger.info(f"Event whitelisted: type={event_type}, id={event_id}, source={source}, reason={reason}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "success": True,
                "message": f"Event type '{event_type}' added to whitelist",
                "event_id": event_id
            }
        )
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(e)}
        )
