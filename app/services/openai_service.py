"""
Local OpenAI Service for SentinelAI.
Uses regular OpenAI API (not Azure) for threat analysis.
"""
import os
import json
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# Check if OpenAI SDK is available
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logger.warning("OpenAI SDK not installed.")


class LocalOpenAIService:
    """OpenAI service for intelligent threat analysis."""
    
    def __init__(self):
        """Initialize the OpenAI service."""
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.base_url = os.getenv("OPENAI_API_BASE_URL", "https://api.openai.com/v1")
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        
        self.available = OPENAI_AVAILABLE and bool(self.api_key)
        self.client = None
        
        if self.available:
            try:
                # Initialize without proxies for compatibility
                self.client = OpenAI(
                    api_key=self.api_key,
                    base_url=self.base_url,
                    http_client=None  # Use default http client
                )
                logger.info(f"OpenAI service initialized with model: {self.model}")
            except TypeError as e:
                # Fallback for older versions
                try:
                    self.client = OpenAI(api_key=self.api_key)
                    logger.info(f"OpenAI service initialized (fallback) with model: {self.model}")
                except Exception as e2:
                    logger.error(f"Failed to initialize OpenAI (fallback): {e2}")
                    self.available = False
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI: {e}")
                self.available = False
        else:
            logger.warning("OpenAI service not available - check OPENAI_API_KEY")
    
    def analyze_threat(self, threat_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analyze a threat using OpenAI and provide detailed analysis with fix suggestions.
        
        Args:
            threat_data: Dictionary containing threat information
            
        Returns:
            Analysis results with severity, description, and fix suggestions
        """
        if not self.available or not self.client:
            logger.warning("OpenAI not available, using fallback analysis")
            return None
        
        try:
            prompt = self._build_analysis_prompt(threat_data)
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": """You are an expert cybersecurity analyst AI for SentinelAI, a threat detection system.

IMPORTANT CONTEXT - NORMAL WINDOWS EVENTS (NOT THREATS):
- Event ID 4672 (Special privileges assigned) for SYSTEM, LOCAL SERVICE, NETWORK SERVICE accounts is NORMAL
- Event ID 4624 (Successful logon) for system accounts is NORMAL
- Event ID 4648 (Explicit credential logon) for scheduled tasks is NORMAL
- 127.0.0.1 (localhost) traffic is usually internal/safe
- NT AUTHORITY\\SYSTEM performing privileged operations is NORMAL Windows behavior
- Services starting with elevated privileges is NORMAL

SENTINELAI AGENT CONTEXT:
- SentinelAI has Windows and Linux agents that monitor processes, network, and logs
- Agent processes (python.exe running agent.py) are part of our system
- Dashboard runs on port 8015

YOUR TASK:
1. Determine if this is a REAL THREAT or NORMAL SYSTEM ACTIVITY
2. If NORMAL: Set severity to "NORMAL" or "LOW" and explain why it's safe
3. If THREAT: Provide severity (HIGH, MEDIUM), threat type, MITRE techniques, and remediation
4. Risk score: 0-20 for normal activity, 21-50 for suspicious, 51-100 for confirmed threats

Respond in JSON format only."""
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1000
            )
            
            content = response.choices[0].message.content
            
            # Parse JSON response
            try:
                # Clean up response if needed
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0]
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0]
                
                analysis = json.loads(content.strip())
                logger.info(f"OpenAI analysis complete: {analysis.get('severity', 'UNKNOWN')}")
                return analysis
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse OpenAI response as JSON: {content[:200]}")
                return {
                    "severity": "MEDIUM",
                    "description": content,
                    "remediation_steps": ["Review the threat manually"],
                    "risk_score": 50
                }
                
        except Exception as e:
            logger.error(f"OpenAI analysis failed: {e}")
            return None
    
    def _build_analysis_prompt(self, threat_data: Dict[str, Any]) -> str:
        """Build the analysis prompt from threat data."""
        # Extract payload for better context
        payload = threat_data.get('payload', 'None')
        if isinstance(payload, str):
            try:
                payload_dict = json.loads(payload)
                payload = json.dumps(payload_dict, indent=2)
            except:
                pass
        
        return f"""Analyze this security event and determine if it's a REAL THREAT or NORMAL SYSTEM ACTIVITY:

Source IP: {threat_data.get('source_ip', 'Unknown')}
Destination IP: {threat_data.get('destination_ip', 'Unknown')}
Protocol: {threat_data.get('protocol', 'Unknown')}
Behavior/Type: {threat_data.get('behavior', threat_data.get('threat_type', 'Unknown'))}
Description: {threat_data.get('description', 'None')}

PAYLOAD/EVENT DATA:
{payload}

Additional Context: {json.dumps(threat_data.get('additional_data', {}), indent=2)}

IMPORTANT: Check if this is normal Windows/Linux system activity before classifying as a threat.
- Windows Event 4672 for SYSTEM account = NORMAL (not a threat)
- Localhost (127.0.0.1) activity = Usually safe
- NT AUTHORITY\\SYSTEM = Windows system account (normal)

Provide your analysis in this JSON format:
{{
    "severity": "NORMAL|LOW|MEDIUM|HIGH",
    "threat_type": "normal_system_activity|suspicious_activity|malware|intrusion|etc",
    "is_false_positive": true/false,
    "description": "detailed explanation of what this event means",
    "why_safe_or_dangerous": "explain why this is safe OR why it's dangerous",
    "mitre_techniques": ["T1234"] or [],
    "risk_score": 0-100,
    "indicators_of_compromise": [],
    "remediation_steps": [
        {{
            "action": "no_action_needed|add_to_whitelist|block_ip|kill_process|etc",
            "description": "what to do",
            "automated": true/false
        }}
    ],
    "recommendation": "summary - is action needed or can this be safely ignored?"
}}"""

    def generate_fix_script(self, threat_data: Dict[str, Any], fix_action: str) -> Optional[str]:
        """
        Generate a fix script for a specific remediation action.
        
        Args:
            threat_data: The threat information
            fix_action: The type of fix to generate
            
        Returns:
            Shell script or command to execute the fix
        """
        if not self.available or not self.client:
            return None
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": """You are a security automation expert. Generate safe, 
reversible shell commands or scripts to remediate security threats. 
Always include comments explaining what each command does.
Prefer iptables for firewall rules on Linux."""
                    },
                    {
                        "role": "user",
                        "content": f"""Generate a fix script for this threat:
Source IP: {threat_data.get('source_ip')}
Action requested: {fix_action}

Provide only the shell script/commands, no explanation."""
                    }
                ],
                temperature=0.2,
                max_tokens=500
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"Failed to generate fix script: {e}")
            return None


# Singleton instance
_openai_service = None

def get_openai_service() -> LocalOpenAIService:
    """Get or create the OpenAI service singleton."""
    global _openai_service
    if _openai_service is None:
        _openai_service = LocalOpenAIService()
    return _openai_service
