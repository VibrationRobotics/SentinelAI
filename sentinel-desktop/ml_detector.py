"""
SentinelAI Local ML Threat Detector
Lightweight machine learning for fast, free threat detection.
Uses scikit-learn for local inference - no API costs.
"""

import os
import json
import pickle
import logging
import hashlib
from typing import Dict, Tuple, List, Optional
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger("SentinelAgent")

@dataclass
class ThreatScore:
    """Result from ML threat analysis."""
    is_threat: bool
    confidence: float
    threat_type: str
    severity: str
    reason: str
    needs_ai_review: bool  # Only escalate to OpenAI if uncertain


class RuleBasedDetector:
    """
    Fast rule-based detection for known patterns.
    Handles 95%+ of cases without any ML or API calls.
    """
    
    def __init__(self):
        # === WHITELISTS (known safe) ===
        self.safe_processes = {
            'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
            'lsass.exe', 'svchost.exe', 'explorer.exe', 'taskhostw.exe',
            'runtimebroker.exe', 'applicationframehost.exe', 'shellexperiencehost.exe',
            'searchui.exe', 'searchhost.exe', 'startmenuexperiencehost.exe',
            'textinputhost.exe', 'ctfmon.exe', 'conhost.exe', 'dwm.exe',
            'fontdrvhost.exe', 'sihost.exe', 'taskmgr.exe', 'mmc.exe',
            'dllhost.exe', 'wmiprvse.exe', 'spoolsv.exe', 'lsm.exe',
            # Security software
            'msmpeng.exe', 'nissrv.exe', 'securityhealthservice.exe',
            'msseces.exe', 'avgnt.exe', 'avguard.exe', 'avscan.exe',
            # Common apps
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'code.exe',
            'python.exe', 'pythonw.exe', 'node.exe', 'git.exe',
            'notepad.exe', 'notepad++.exe', 'winword.exe', 'excel.exe',
            'outlook.exe', 'teams.exe', 'slack.exe', 'discord.exe',
            'spotify.exe', 'steam.exe', 'steamwebhelper.exe',
        }
        
        self.safe_paths = [
            r'c:\windows\system32',
            r'c:\windows\syswow64',
            r'c:\windows\explorer.exe',
            r'c:\program files',
            r'c:\program files (x86)',
        ]
        
        self.safe_publishers = [
            'microsoft', 'google', 'mozilla', 'adobe', 'oracle',
            'nvidia', 'amd', 'intel', 'realtek', 'logitech',
        ]
        
        # === BLACKLISTS (known bad) ===
        self.malicious_processes = {
            'mimikatz.exe', 'procdump.exe', 'psexec.exe', 'psexec64.exe',
            'lazagne.exe', 'bloodhound.exe', 'sharphound.exe', 'rubeus.exe',
            'covenant.exe', 'cobaltstrike.exe', 'beacon.exe',
            'nc.exe', 'nc64.exe', 'ncat.exe', 'netcat.exe',
            'pwdump.exe', 'fgdump.exe', 'wce.exe', 'gsecdump.exe',
            'cachedump.exe', 'pth-winexe.exe', 'incognito.exe',
        }
        
        self.malicious_cmdline_patterns = [
            # Credential theft
            'sekurlsa::logonpasswords', 'lsadump::sam', 'lsadump::dcsync',
            'invoke-mimikatz', 'get-credential', 'mimikatz',
            # PowerShell attacks
            '-encodedcommand', '-enc ', '-e ', 'frombase64string',
            'invoke-expression', 'iex(', 'downloadstring', 'downloadfile',
            'invoke-webrequest', 'invoke-shellcode', 'invoke-dllinjection',
            'bypass -nop', '-windowstyle hidden', '-w hidden',
            'reflection.assembly', 'add-type.*dllimport',
            # Lateral movement
            'psexec', 'wmic /node:', 'winrm', 'invoke-wmimethod',
            'invoke-command -computername', 'enter-pssession',
            # Persistence
            'schtasks /create', 'reg add.*run', 'new-service',
            'sc create', 'at \\\\', 'wmic process call create',
            # Evasion
            'set-mppreference -disablerealtimemonitoring',
            'add-mppreference -exclusionpath',
            'stop-service windefend', 'sc stop windefend',
        ]
        
        self.suspicious_paths = [
            r'\temp\\', r'\tmp\\', r'\downloads\\',
            r'\appdata\local\temp', r'\users\public',
            r'\programdata\\', r'c:\perflogs',
        ]
        
        # === DNS RULES ===
        self.safe_dns_patterns = [
            '.in-addr.arpa', '.ip6.arpa',  # Reverse DNS
            'microsoft.com', 'windows.com', 'windowsupdate.com',
            'google.com', 'googleapis.com', 'gstatic.com', 'youtube.com',
            'cloudflare.com', 'cloudflare-dns.com',
            'amazon.com', 'amazonaws.com', 'aws.amazon.com',
            'github.com', 'githubusercontent.com',
            'apple.com', 'icloud.com',
            'facebook.com', 'fbcdn.net',
            'twitter.com', 'twimg.com',
            'linkedin.com', 'licdn.com',
            'office.com', 'office365.com', 'outlook.com',
            'live.com', 'msn.com', 'bing.com',
            'akamai.net', 'akamaiedge.net', 'akamaitechnologies.com',
            'fastly.net', 'jsdelivr.net', 'unpkg.com',
            'localhost', '127.0.0.1',
        ]
        
        self.malicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.loan', '.racing']
        
        # === NAMED PIPE RULES ===
        self.safe_pipe_patterns = [
            'mojo.', 'chrome.', 'crashpad', 'discord', 'spotify',
            'GoogleUpdate', 'PIPE_EVENTROOT', 'wkssvc', 'srvsvc',
            'browser', 'lsass', 'ntsvcs', 'spoolss', 'samr',
        ]
        
        self.malicious_pipe_patterns = [
            'cobaltstrike', 'beacon', 'metasploit', 'meterpreter',
            'postex_', 'msagent_', 'status_', 'msse-', 'MSSE-',
            'isapi_http', 'isapi_dg', 'isapi_dg2',
            'sdlrpc', 'ahexec', 'winsock', 'ntsvcs_',
        ]
        
        # === NETWORK RULES ===
        self.safe_ports = {80, 443, 53, 123, 67, 68}  # HTTP, HTTPS, DNS, NTP, DHCP
        self.suspicious_ports = {4444, 5555, 6666, 1337, 31337, 12345, 54321}  # Common backdoor ports
        
        self.safe_ips = ['127.0.0.1', '::1', 'localhost']
        
    def analyze_process(self, proc_info: Dict) -> ThreatScore:
        """Analyze a process using rules."""
        name = (proc_info.get('name', '') or '').lower()
        exe = (proc_info.get('exe', '') or '').lower()
        cmdline = (proc_info.get('cmdline', '') or '').lower()
        
        # Check whitelist first
        if name in self.safe_processes:
            return ThreatScore(False, 0.95, 'safe', 'NORMAL', 'Known safe process', False)
        
        for safe_path in self.safe_paths:
            if safe_path in exe:
                return ThreatScore(False, 0.9, 'safe', 'NORMAL', f'Safe path: {safe_path}', False)
        
        # Check blacklist
        if name in self.malicious_processes:
            return ThreatScore(True, 0.99, 'malware', 'CRITICAL', f'Known malicious: {name}', False)
        
        for pattern in self.malicious_cmdline_patterns:
            if pattern.lower() in cmdline:
                return ThreatScore(True, 0.95, 'attack', 'HIGH', f'Malicious pattern: {pattern}', False)
        
        # Check suspicious paths
        for sus_path in self.suspicious_paths:
            if sus_path in exe:
                # Suspicious but not definitive - might need AI
                return ThreatScore(True, 0.6, 'suspicious', 'MEDIUM', f'Suspicious path: {sus_path}', True)
        
        # Unknown process - low confidence
        return ThreatScore(False, 0.5, 'unknown', 'LOW', 'Unknown process', False)
    
    def analyze_dns(self, domain: str) -> ThreatScore:
        """Analyze DNS query using rules."""
        domain = domain.lower()
        
        # Check safe patterns
        for safe in self.safe_dns_patterns:
            if safe in domain:
                return ThreatScore(False, 0.95, 'safe', 'NORMAL', f'Safe domain pattern', False)
        
        # Check malicious TLDs
        for tld in self.malicious_tlds:
            if domain.endswith(tld):
                return ThreatScore(True, 0.7, 'suspicious_dns', 'MEDIUM', f'Suspicious TLD: {tld}', True)
        
        # Check for DNS tunneling indicators
        if len(domain) > 60:
            return ThreatScore(True, 0.6, 'dns_tunneling', 'MEDIUM', 'Very long domain', True)
        
        # Check for high entropy (random-looking) subdomains
        parts = domain.split('.')
        for part in parts:
            if len(part) > 30 and len(set(part)) > 15:
                return ThreatScore(True, 0.7, 'dns_tunneling', 'MEDIUM', 'High entropy subdomain', True)
        
        return ThreatScore(False, 0.8, 'safe', 'NORMAL', 'Normal DNS query', False)
    
    def analyze_named_pipe(self, pipe_name: str) -> ThreatScore:
        """Analyze named pipe using rules."""
        pipe = pipe_name.lower()
        
        # Check safe patterns
        for safe in self.safe_pipe_patterns:
            if safe.lower() in pipe:
                return ThreatScore(False, 0.95, 'safe', 'NORMAL', 'Known safe pipe', False)
        
        # Check malicious patterns
        for mal in self.malicious_pipe_patterns:
            if mal.lower() in pipe:
                return ThreatScore(True, 0.9, 'c2_channel', 'HIGH', f'Malicious pipe: {mal}', False)
        
        return ThreatScore(False, 0.7, 'unknown', 'LOW', 'Unknown pipe', False)
    
    def analyze_network(self, conn_info: Dict) -> ThreatScore:
        """Analyze network connection using rules."""
        remote_ip = conn_info.get('remote_ip', '')
        remote_port = conn_info.get('remote_port', 0)
        
        # Check safe IPs
        if remote_ip in self.safe_ips:
            return ThreatScore(False, 0.95, 'safe', 'NORMAL', 'Localhost connection', False)
        
        # Check suspicious ports
        if remote_port in self.suspicious_ports:
            return ThreatScore(True, 0.8, 'backdoor', 'HIGH', f'Suspicious port: {remote_port}', True)
        
        # Check safe ports
        if remote_port in self.safe_ports:
            return ThreatScore(False, 0.8, 'safe', 'NORMAL', 'Standard port', False)
        
        return ThreatScore(False, 0.6, 'unknown', 'LOW', 'Unknown connection', False)


class LocalMLDetector:
    """
    Lightweight ML model for threat detection.
    Uses pre-trained model or simple heuristics if model not available.
    """
    
    def __init__(self, model_path: str = None):
        self.model = None
        self.vectorizer = None
        self.model_path = model_path or os.path.join(os.path.dirname(__file__), 'threat_model.pkl')
        self._load_model()
    
    def _load_model(self):
        """Load pre-trained model if available."""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.model = data.get('model')
                    self.vectorizer = data.get('vectorizer')
                logger.info("ML model loaded successfully")
        except Exception as e:
            logger.debug(f"No ML model available: {e}")
    
    def extract_features(self, event_data: Dict) -> List[float]:
        """Extract numerical features from event data."""
        features = []
        
        # Process features
        name = str(event_data.get('name', '')).lower()
        exe = str(event_data.get('exe', '')).lower()
        cmdline = str(event_data.get('cmdline', '')).lower()
        
        # Length features
        features.append(len(name))
        features.append(len(exe))
        features.append(len(cmdline))
        
        # Path features
        features.append(1 if 'temp' in exe else 0)
        features.append(1 if 'appdata' in exe else 0)
        features.append(1 if 'system32' in exe else 0)
        features.append(1 if 'program files' in exe else 0)
        
        # Command line features
        features.append(1 if 'powershell' in cmdline else 0)
        features.append(1 if 'cmd' in cmdline else 0)
        features.append(1 if '-enc' in cmdline or 'encoded' in cmdline else 0)
        features.append(1 if 'hidden' in cmdline else 0)
        features.append(1 if 'bypass' in cmdline else 0)
        features.append(1 if 'invoke' in cmdline else 0)
        features.append(1 if 'download' in cmdline else 0)
        features.append(1 if 'http' in cmdline else 0)
        
        # Entropy of name (randomness indicator)
        if name:
            unique_chars = len(set(name))
            features.append(unique_chars / len(name) if len(name) > 0 else 0)
        else:
            features.append(0)
        
        return features
    
    def predict(self, event_data: Dict) -> ThreatScore:
        """Predict threat using ML model or heuristics."""
        if self.model is not None:
            try:
                features = [self.extract_features(event_data)]
                prediction = self.model.predict(features)[0]
                probability = self.model.predict_proba(features)[0]
                
                is_threat = prediction == 1
                confidence = max(probability)
                
                return ThreatScore(
                    is_threat=is_threat,
                    confidence=confidence,
                    threat_type='ml_detected' if is_threat else 'safe',
                    severity='HIGH' if is_threat and confidence > 0.8 else 'MEDIUM' if is_threat else 'LOW',
                    reason='ML model prediction',
                    needs_ai_review=0.4 < confidence < 0.7  # Uncertain range
                )
            except Exception as e:
                logger.debug(f"ML prediction error: {e}")
        
        # Fallback to heuristic scoring
        return self._heuristic_score(event_data)
    
    def _heuristic_score(self, event_data: Dict) -> ThreatScore:
        """Simple heuristic scoring when ML model not available."""
        score = 0
        reasons = []
        
        cmdline = str(event_data.get('cmdline', '')).lower()
        exe = str(event_data.get('exe', '')).lower()
        
        # Suspicious indicators
        if 'powershell' in cmdline and '-enc' in cmdline:
            score += 30
            reasons.append('Encoded PowerShell')
        
        if 'temp' in exe or 'tmp' in exe:
            score += 15
            reasons.append('Temp directory')
        
        if 'hidden' in cmdline:
            score += 20
            reasons.append('Hidden window')
        
        if 'download' in cmdline or 'http' in cmdline:
            score += 15
            reasons.append('Network activity')
        
        if 'invoke' in cmdline:
            score += 10
            reasons.append('Invoke command')
        
        # Determine result
        if score >= 50:
            return ThreatScore(True, score/100, 'suspicious', 'HIGH', '; '.join(reasons), score < 70)
        elif score >= 25:
            return ThreatScore(True, score/100, 'suspicious', 'MEDIUM', '; '.join(reasons), True)
        else:
            return ThreatScore(False, 1 - score/100, 'safe', 'LOW', 'No suspicious indicators', False)


class HybridThreatDetector:
    """
    Hybrid threat detection combining:
    1. Rule-based (fast, free) - 95% of cases
    2. Local ML (fast, free) - uncertain cases  
    3. OpenAI (slow, costly) - only when truly needed
    """
    
    def __init__(self, use_ai: bool = True, ai_threshold: float = 0.7):
        self.rule_detector = RuleBasedDetector()
        self.ml_detector = LocalMLDetector()
        self.use_ai = use_ai
        self.ai_threshold = ai_threshold  # Only use AI if confidence below this
        
        # Stats
        self.stats = {
            'rule_detections': 0,
            'ml_detections': 0,
            'ai_escalations': 0,
            'total_analyzed': 0,
        }
    
    def analyze(self, event_type: str, event_data: Dict) -> Tuple[ThreatScore, bool]:
        """
        Analyze event and return (score, should_use_ai).
        
        Returns:
            ThreatScore: The threat assessment
            bool: Whether to escalate to OpenAI for deeper analysis
        """
        self.stats['total_analyzed'] += 1
        
        # Step 1: Rule-based detection (instant, free)
        if event_type == 'process' or event_type == 'suspicious_process':
            score = self.rule_detector.analyze_process(event_data)
        elif event_type == 'dns' or event_type == 'suspicious_dns_query':
            domain = event_data.get('domain', event_data.get('description', ''))
            score = self.rule_detector.analyze_dns(domain)
        elif event_type == 'named_pipe' or event_type == 'suspicious_named_pipe':
            pipe = event_data.get('pipe_name', '')
            score = self.rule_detector.analyze_named_pipe(pipe)
        elif event_type == 'network' or event_type == 'suspicious_connection':
            score = self.rule_detector.analyze_network(event_data)
        else:
            # For other event types, use ML
            score = self.ml_detector.predict(event_data)
            self.stats['ml_detections'] += 1
            
            # Determine if AI is needed
            should_use_ai = (
                self.use_ai and 
                score.needs_ai_review and 
                score.confidence < self.ai_threshold and
                score.severity in ['HIGH', 'CRITICAL']
            )
            return score, should_use_ai
        
        self.stats['rule_detections'] += 1
        
        # Step 2: If rules are uncertain, try ML
        if score.confidence < 0.7 and score.needs_ai_review:
            ml_score = self.ml_detector.predict(event_data)
            self.stats['ml_detections'] += 1
            
            # Use ML score if more confident
            if ml_score.confidence > score.confidence:
                score = ml_score
        
        # Step 3: Determine if AI escalation is needed
        should_use_ai = (
            self.use_ai and
            score.needs_ai_review and
            score.confidence < self.ai_threshold and
            score.severity in ['HIGH', 'CRITICAL', 'MEDIUM']
        )
        
        if should_use_ai:
            self.stats['ai_escalations'] += 1
        
        return score, should_use_ai
    
    def get_stats(self) -> Dict:
        """Get detection statistics."""
        total = self.stats['total_analyzed']
        if total == 0:
            return self.stats
        
        return {
            **self.stats,
            'rule_percentage': round(self.stats['rule_detections'] / total * 100, 1),
            'ml_percentage': round(self.stats['ml_detections'] / total * 100, 1),
            'ai_percentage': round(self.stats['ai_escalations'] / total * 100, 1),
            'cost_savings': f"{100 - self.stats['ai_escalations'] / total * 100:.1f}%"
        }


# Singleton instance
_detector = None

def get_detector(use_ai: bool = True) -> HybridThreatDetector:
    """Get or create the hybrid detector instance."""
    global _detector
    if _detector is None:
        _detector = HybridThreatDetector(use_ai=use_ai)
    return _detector
