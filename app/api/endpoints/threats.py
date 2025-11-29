from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import uuid
import logging
import time
import random
import asyncio
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.domain.threat import ThreatData, ThreatResponse
from app.services.threat_detection import ThreatDetectionService
from app.services.openai_service import get_openai_service
from app.services.geolocation_service import enrich_threat_with_location
from app.services.remediation_service import get_remediation_service
from app.services.auto_response_service import get_auto_response_service
from app.db.models import User, ThreatEvent, Agent, AgentCommand
from app.api.deps import get_current_user, get_db
from app.db.base import get_session
from app.services.audit_service import AuditService, log_threat_detected, log_ai_analysis, log_user_action

logger = logging.getLogger(__name__)
router = APIRouter()

# Get OpenAI service
openai_service = get_openai_service()

class ThreatData(BaseModel):
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: Optional[str] = Field(None, description="Destination IP address")
    protocol: Optional[str] = Field(None, description="Network protocol")
    payload: Optional[str] = Field(None, description="Data payload")
    behavior: Optional[str] = Field(None, description="Observed behavior")
    timestamp: Optional[str] = Field(None, description="Time of event")
    additional_data: Optional[Dict[str, Any]] = Field(None, description="Any additional data")

class ThreatResponse(BaseModel):
    severity: str = Field(..., description="Threat severity level (NORMAL, LOW, MEDIUM, HIGH)")
    confidence: float = Field(..., description="Confidence score between 0 and 1")
    techniques: List[str] = Field(default=[], description="MITRE ATT&CK techniques identified")
    recommendation: Optional[str] = Field(None, description="Recommended action")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional analysis details")

# Initialize the threat detection service
threat_service = ThreatDetectionService()

# Job statuses still in memory (short-lived)
_job_statuses = {}
_MAX_RECENT_THREATS = 100

# Helper to convert ThreatEvent to dict
def threat_event_to_dict(event: ThreatEvent) -> dict:
    return {
        "id": event.id,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "severity": event.severity,
        "description": event.description,
        "source_ip": event.source_ip,
        "confidence": event.confidence_score,
        "techniques": event.mitre_techniques.get("techniques", []) if event.mitre_techniques else [],
        "status": event.status,
        "resolved": event.status == "RESOLVED",
        "blocked": event.status == "BLOCKED",
        "resolved_by": event.resolved_by,
        "resolved_at": event.resolved_at.isoformat() if event.resolved_at else None,
        "latitude": event.indicators.get("latitude") if event.indicators else None,
        "longitude": event.indicators.get("longitude") if event.indicators else None,
        "location": event.indicators.get("location") if event.indicators else None,
        "threat_type": event.indicators.get("threat_type") if event.indicators else "Unknown",
        "ai_analyzed": event.indicators.get("ai_analyzed", False) if event.indicators else False,
    }

@router.post("/analyze")
async def analyze_threat(
    threat_data: ThreatData,
    db: AsyncSession = Depends(get_db)
) -> JSONResponse:
    """
    Analyze potential security threat data using AI
    """
    try:
        logger.info(f"Analyzing threat from {threat_data.source_ip}")
        
        threat_dict = threat_data.dict()
        
        # Try OpenAI analysis first
        ai_analysis = None
        if openai_service.available:
            logger.info("Using OpenAI for threat analysis")
            ai_analysis = openai_service.analyze_threat(threat_dict)
        
        if ai_analysis:
            # Use OpenAI analysis results
            severity = ai_analysis.get("severity", "MEDIUM")
            confidence = ai_analysis.get("risk_score", 50) / 100.0
            techniques = ai_analysis.get("mitre_techniques", [])
            recommendation = ai_analysis.get("recommendation", "Review and investigate")
            remediation_steps = ai_analysis.get("remediation_steps", [])
            threat_type = ai_analysis.get("threat_type", threat_dict.get("behavior", "Unknown"))
            description = ai_analysis.get("description", "")
        else:
            # Fallback to basic threat detection service
            severity, confidence, techniques = await threat_service.analyze_threat(threat_dict)
            recommendation = generate_recommendation(severity)
            remediation_steps = generate_default_remediation(severity, threat_dict.get("source_ip"))
            threat_type = threat_dict.get("behavior", "Unknown")
            description = ""
        
        # Generate threat ID
        threat_id = str(uuid.uuid4())
        
        # Build analyzed threat with geolocation
        analyzed_threat = {
            **threat_dict,
            "id": threat_id,
            "severity": severity,
            "confidence": confidence,
            "techniques": techniques,
            "recommendation": recommendation,
            "remediation_steps": remediation_steps,
            "threat_type": threat_type,
            "description": description,
            "ai_analyzed": ai_analysis is not None,
            "analysis_time": datetime.utcnow().isoformat()
        }
        
        # Add geolocation data
        analyzed_threat = enrich_threat_with_location(analyzed_threat)
        
        # Save to database
        try:
            threat_event = ThreatEvent(
                id=threat_id,
                timestamp=datetime.utcnow(),
                severity=severity,
                description=description or f"Threat from {threat_data.source_ip}",
                source_ip=threat_data.source_ip,
                confidence_score=confidence,
                indicators={
                    "latitude": analyzed_threat.get("latitude"),
                    "longitude": analyzed_threat.get("longitude"),
                    "location": analyzed_threat.get("location"),
                    "threat_type": threat_type,
                    "ai_analyzed": ai_analysis is not None,
                    "recommendation": recommendation,
                    "remediation_steps": remediation_steps,
                },
                target_systems=[],
                mitre_techniques={"techniques": techniques},
                status="OPEN"
            )
            db.add(threat_event)
            await db.commit()
            logger.info(f"Threat {threat_id} saved to database")
            
            # Audit log: threat detected
            await log_threat_detected(
                db, threat_id, threat_data.source_ip, severity,
                f"Threat detected from {threat_data.source_ip}: {description or threat_type}"
            )
            
            # Audit log: AI analysis (if used)
            if ai_analysis:
                await log_ai_analysis(db, threat_id, severity, confidence, {"techniques": techniques})
        except Exception as db_error:
            logger.error(f"Failed to save threat to database: {db_error}")
            await db.rollback()
        
        # Evaluate for auto-response
        auto_response_result = None
        try:
            auto_response_service = get_auto_response_service()
            
            # Add hostname and process info for agent command queuing
            analyzed_threat["hostname"] = threat_data.payload.get("hostname") if threat_data.payload else None
            analyzed_threat["process_info"] = threat_data.payload.get("process_info", {}) if threat_data.payload else {}
            analyzed_threat["file_path"] = threat_data.payload.get("file_path") if threat_data.payload else None
            
            auto_response_result = await auto_response_service.evaluate_threat(analyzed_threat)
            
            if auto_response_result.get("action_taken"):
                analyzed_threat["auto_response"] = auto_response_result
                logger.info(f"Auto-response triggered for threat {threat_id}: {auto_response_result.get('action_taken')}")
                
                # Queue commands for agents
                commands_queued = auto_response_result.get("commands_queued", [])
                if commands_queued:
                    try:
                        async for session in get_session():
                            for cmd in commands_queued:
                                # Find agent
                                result = await session.execute(
                                    select(Agent).filter(Agent.hostname == cmd["hostname"])
                                )
                                agent = result.scalar_one_or_none()
                                
                                if agent:
                                    new_command = AgentCommand(
                                        agent_id=agent.id,
                                        command_type=cmd["command_type"],
                                        target=cmd["target"],
                                        parameters={},
                                        priority=1,  # High priority for auto-response
                                        threat_id=cmd.get("threat_id")
                                    )
                                    session.add(new_command)
                                    logger.info(f"Queued {cmd['command_type']} command for agent {cmd['hostname']}")
                            
                            await session.commit()
                            break
                    except Exception as cmd_error:
                        logger.error(f"Failed to queue agent commands: {cmd_error}")
        except Exception as ar_error:
            logger.error(f"Auto-response evaluation error: {ar_error}")
        
        # Return the response
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "severity": severity,
                "confidence": confidence,
                "techniques": techniques,
                "recommendation": recommendation,
                "remediation_steps": remediation_steps,
                "id": threat_id,
                "ai_analyzed": ai_analysis is not None,
                "latitude": analyzed_threat.get("latitude"),
                "longitude": analyzed_threat.get("longitude"),
                "location": analyzed_threat.get("location"),
                "auto_response": auto_response_result
            }
        )
    except Exception as e:
        logger.error(f"Error analyzing threat: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Failed to analyze threat: {str(e)}"}
        )

@router.post("/batch-analyze")
async def batch_analyze_threats(
    threats: List[ThreatData],
    background_tasks: BackgroundTasks,
) -> JSONResponse:
    """
    Submit multiple threats for background analysis
    """
    try:
        # Generate a job ID
        job_id = str(uuid.uuid4())
        _job_statuses[job_id] = {
            "status": "PENDING",
            "total": len(threats),
            "completed": 0,
            "results": [],
            "start_time": datetime.utcnow().isoformat()
        }
        
        # Schedule the background task
        background_tasks.add_task(
            process_batch, 
            job_id=job_id, 
            threats=threats
        )
        
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "job_id": job_id,
                "message": f"Batch job started with {len(threats)} threats",
                "status_endpoint": f"/api/v1/threats/status/{job_id}"
            }
        )
    except Exception as e:
        logger.error(f"Error starting batch job: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Failed to process batch request: {str(e)}"}
        )

@router.get("/status/{job_id}")
async def check_analysis_status(
    job_id: str,
) -> JSONResponse:
    """
    Check the status of a batch analysis job
    """
    if job_id not in _job_statuses:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": f"Job ID {job_id} not found"}
        )
    
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=_job_statuses[job_id]
    )

@router.get("")
async def get_all_threats(db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """
    Get all threats from database
    """
    try:
        result = await db.execute(
            select(ThreatEvent).order_by(desc(ThreatEvent.timestamp)).limit(_MAX_RECENT_THREATS)
        )
        threats = result.scalars().all()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=[threat_event_to_dict(t) for t in threats]
        )
    except Exception as e:
        logger.error(f"Error fetching threats: {e}")
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=[]
        )

@router.get("/recent")
async def get_recent_threats(db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """
    Get recent threats from database
    """
    try:
        result = await db.execute(
            select(ThreatEvent).order_by(desc(ThreatEvent.timestamp)).limit(_MAX_RECENT_THREATS)
        )
        threats = result.scalars().all()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=[threat_event_to_dict(t) for t in threats]
        )
    except Exception as e:
        logger.error(f"Error fetching recent threats: {e}")
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=[]
        )

@router.post("/{threat_id}/resolve")
async def resolve_threat(
    threat_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> JSONResponse:
    """
    Mark a threat as resolved after investigation
    """
    try:
        # Find the threat in database
        result = await db.execute(select(ThreatEvent).where(ThreatEvent.id == threat_id))
        threat = result.scalar_one_or_none()
        
        if threat is None:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": f"Threat with ID {threat_id} not found"}
            )
        
        # Update the threat status
        threat.status = "RESOLVED"
        threat.resolved_by = current_user.id
        threat.resolved_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(threat)
        
        logger.info(f"Threat {threat_id} resolved by {current_user.email}")
        
        # Audit log: threat resolved
        await AuditService.log(
            db,
            action=AuditService.ACTION_THREAT_RESOLVED,
            description=f"Threat {threat_id} resolved by {current_user.email}",
            source=AuditService.SOURCE_DASHBOARD,
            severity="INFO",
            user_id=current_user.id,
            ip_address=threat.source_ip,
            details={"threat_id": threat_id}
        )
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": f"Threat {threat_id} marked as resolved",
                "threat": threat_event_to_dict(threat)
            }
        )
    except Exception as e:
        logger.error(f"Error resolving threat: {str(e)}")
        await db.rollback()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Failed to resolve threat: {str(e)}"}
        )

@router.post("/{threat_id}/block")
async def block_threat(
    threat_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> JSONResponse:
    """
    Block the source IP of a threat
    """
    try:
        # Find the threat in database
        result = await db.execute(select(ThreatEvent).where(ThreatEvent.id == threat_id))
        threat = result.scalar_one_or_none()
        
        if threat is None:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": f"Threat with ID {threat_id} not found"}
            )
        
        # Get the source IP
        source_ip = threat.source_ip
        if not source_ip:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Threat doesn't have a source IP to block"}
            )
        
        # Update the threat status
        threat.status = "BLOCKED"
        
        await db.commit()
        await db.refresh(threat)
        
        # In a real-world scenario, you would integrate with a firewall or IPS here
        logger.info(f"Source IP {source_ip} from threat {threat_id} blocked by {current_user.email}")
        
        # Audit log: IP blocked
        await AuditService.log(
            db,
            action=AuditService.ACTION_IP_BLOCKED,
            description=f"IP {source_ip} blocked by {current_user.email} (threat {threat_id})",
            source=AuditService.SOURCE_DASHBOARD,
            severity="WARNING",
            user_id=current_user.id,
            ip_address=source_ip,
            details={"threat_id": threat_id, "blocked_ip": source_ip}
        )
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": f"Source IP {source_ip} from threat {threat_id} has been blocked",
                "threat": threat_event_to_dict(threat)
            }
        )
    except Exception as e:
        logger.error(f"Error blocking threat: {str(e)}")
        await db.rollback()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Failed to block threat: {str(e)}"}
        )

@router.post("/{threat_id}/escalate")
async def escalate_threat(
    threat_id: str,
    current_user: User = Depends(get_current_user)
) -> JSONResponse:
    """
    Escalate a threat to an incident for further investigation
    """
    try:
        # Find the threat in our temporary storage
        threat_index = next((i for i, t in enumerate(_recent_threats) if t.get("id") == threat_id), None)
        
        if threat_index is None:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": f"Threat with ID {threat_id} not found"}
            )
        
        # Update the threat status
        _recent_threats[threat_index]["status"] = "ESCALATED"
        _recent_threats[threat_index]["escalated_by"] = current_user.username
        _recent_threats[threat_index]["escalated_at"] = datetime.utcnow().isoformat()
        
        # In a real scenario, this would create a new incident record in the database
        # and trigger notifications to the incident response team
        logger.info(f"Threat {threat_id} escalated to incident by {current_user.username}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": f"Threat {threat_id} escalated to incident",
                "threat": _recent_threats[threat_index]
            }
        )
    except Exception as e:
        logger.error(f"Error escalating threat: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Failed to escalate threat: {str(e)}"}
        )

# Background task for processing batches
async def process_batch(job_id: str, threats: List[ThreatData]):
    """Process a batch of threats in the background"""
    if job_id not in _job_statuses:
        logger.error(f"Job ID {job_id} not found in status map")
        return
    
    # Update job status
    _job_statuses[job_id]["status"] = "PROCESSING"
    
    try:
        results = []
        
        for i, threat in enumerate(threats):
            # Process each threat
            try:
                # Call the threat detection service
                severity, confidence, techniques = await threat_service.analyze_threat(threat.dict())
                
                # Generate recommendation
                recommendation = generate_recommendation(severity)
                
                # Add to results
                threat_id = str(uuid.uuid4())
                result = {
                    **threat.dict(),
                    "id": threat_id,
                    "severity": severity,
                    "confidence": confidence,
                    "techniques": techniques,
                    "recommendation": recommendation,
                    "analysis_time": datetime.utcnow().isoformat()
                }
                results.append(result)
                
                # Add to recent threats
                _recent_threats.append(result)
                # Trim the list if needed
                if len(_recent_threats) > _MAX_RECENT_THREATS:
                    _recent_threats.pop(0)
                
                # Update job progress
                _job_statuses[job_id]["completed"] = i + 1
                
                # Simulate some processing time
                await asyncio.sleep(0.1)
            
            except Exception as e:
                logger.error(f"Error processing threat in batch: {str(e)}")
                # Add failed result
                results.append({
                    **threat.dict(),
                    "error": str(e),
                    "severity": "UNKNOWN",
                    "confidence": 0.0,
                    "techniques": [],
                    "recommendation": "Failed to analyze"
                })
        
        # Update job status
        _job_statuses[job_id]["status"] = "COMPLETED"
        _job_statuses[job_id]["results"] = results
        _job_statuses[job_id]["end_time"] = datetime.utcnow().isoformat()
        
    except Exception as e:
        logger.error(f"Error processing batch job {job_id}: {str(e)}")
        _job_statuses[job_id]["status"] = "FAILED"
        _job_statuses[job_id]["error"] = str(e)
        _job_statuses[job_id]["end_time"] = datetime.utcnow().isoformat()

def generate_recommendation(severity: str) -> str:
    """Generate a recommended action based on threat severity"""
    recommendations = {
        "HIGH": "Immediate action required. Isolate affected systems and investigate.",
        "MEDIUM": "Investigate promptly. Implement additional monitoring and controls.",
        "LOW": "Monitor the situation. No immediate action required.",
        "NORMAL": "No action required. Part of normal operations.",
        "UNKNOWN": "Unable to assess severity. Manual investigation recommended."
    }
    return recommendations.get(severity, "Unable to determine recommended action.")


def generate_default_remediation(severity: str, source_ip: str) -> List[Dict[str, Any]]:
    """Generate default remediation steps when OpenAI is not available"""
    steps = []
    
    if severity in ["HIGH", "MEDIUM"]:
        steps.append({
            "action": "block_ip",
            "target": source_ip,
            "description": f"Block IP address {source_ip} at firewall",
            "automated": True,
            "command": f"iptables -A INPUT -s {source_ip} -j DROP"
        })
    
    if severity == "HIGH":
        steps.append({
            "action": "isolate_system",
            "target": "affected_host",
            "description": "Isolate affected system from network",
            "automated": False
        })
        steps.append({
            "action": "alert_team",
            "target": "security_team",
            "description": "Alert security team for immediate response",
            "automated": True
        })
    
    if severity in ["HIGH", "MEDIUM", "LOW"]:
        steps.append({
            "action": "log_incident",
            "target": "siem",
            "description": "Log incident to SIEM for tracking",
            "automated": True
        })
    
    return steps


@router.post("/{threat_id}/apply-fix")
async def apply_fix(
    threat_id: str,
    fix_index: int = 0,
) -> JSONResponse:
    """
    Apply a remediation fix for a threat.
    Executes real security commands with proper safeguards.
    """
    try:
        # Find the threat
        threat = next((t for t in _recent_threats if t.get("id") == threat_id), None)
        
        if not threat:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": f"Threat {threat_id} not found"}
            )
        
        remediation_steps = threat.get("remediation_steps", [])
        
        if not remediation_steps:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "No remediation steps available for this threat"}
            )
        
        if fix_index >= len(remediation_steps):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": f"Invalid fix index. Available: 0-{len(remediation_steps)-1}"}
            )
        
        fix = remediation_steps[fix_index]
        action = fix.get("action", "")
        
        logger.info(f"Applying fix '{action}' for threat {threat_id}")
        
        # Get remediation service and execute the action
        remediation_service = get_remediation_service()
        
        # Prepare parameters for remediation
        params = {
            "target": fix.get("target") or threat.get("source_ip"),
            "rule": fix.get("rule", ""),
            "threat_id": threat_id,
            "severity": threat.get("severity", "MEDIUM"),
            "details": fix.get("description", ""),
            "threat_data": threat
        }
        
        # Execute the remediation action
        result = remediation_service.execute_remediation(action, params)
        
        # Build fix result
        fix_result = {
            "success": result.get("success", False),
            "action": action,
            "target": params.get("target"),
            "description": fix.get("description"),
            "executed_at": result.get("executed_at", datetime.utcnow().isoformat()),
            "command": result.get("command", fix.get("command", "N/A")),
            "output": result.get("output", ""),
            "rollback_command": result.get("rollback_command"),
            "dry_run": result.get("dry_run", False)
        }
        
        if not result.get("success"):
            fix_result["error"] = result.get("error", "Unknown error")
        
        # Update threat status
        if "applied_fixes" not in threat:
            threat["applied_fixes"] = []
        threat["applied_fixes"].append(fix_result)
        
        # Update status based on action success
        if result.get("success"):
            if action == "block_ip":
                threat["status"] = "MITIGATED"
            else:
                threat["status"] = "IN_PROGRESS"
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": f"Fix {'applied' if result.get('success') else 'failed'}: {action}",
                "fix": fix_result,
                "threat_status": threat.get("status")
            }
        )
        
    except Exception as e:
        logger.error(f"Error applying fix: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Failed to apply fix: {str(e)}"}
        )
