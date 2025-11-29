"""
Advanced Threat Detector v2.0
Main interface for ML-based threat detection.
Combines feature extraction, behavioral analysis, anomaly detection, and ensemble prediction.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime

from .feature_extractor import AdvancedFeatureExtractor
from .behavioral_analyzer import BehavioralSequenceAnalyzer, BehavioralEvent
from .anomaly_detector import BaselineAnomalyDetector
from .ensemble_model import EnsembleThreatModel
from .mitre_mapping import map_to_mitre

logger = logging.getLogger("SentinelAgent.ML")


@dataclass
class ThreatPrediction:
    """Result from ML threat analysis."""
    is_threat: bool
    confidence: float
    threat_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    reason: str
    mitre_techniques: List[str] = field(default_factory=list)
    feature_importance: Dict[str, float] = field(default_factory=dict)
    anomaly_score: float = 0.0
    behavioral_score: float = 0.0
    attack_chains: List[Dict] = field(default_factory=list)
    needs_ai_review: bool = False
    model_used: str = "ensemble"
    model_scores: Dict[str, float] = field(default_factory=dict)


class AdvancedThreatDetector:
    """
    Advanced ML-based threat detector.
    Combines multiple detection methods for robust threat identification.
    """
    
    def __init__(self, model_dir: str = None, use_ai_escalation: bool = True):
        self.model_dir = model_dir
        self.use_ai_escalation = use_ai_escalation
        
        # Initialize components
        self.feature_extractor = AdvancedFeatureExtractor()
        self.behavioral_analyzer = BehavioralSequenceAnalyzer()
        self.anomaly_detector = BaselineAnomalyDetector(model_dir=model_dir)
        self.ensemble_model = EnsembleThreatModel(model_dir=model_dir)
        
        # Statistics
        self.stats = {
            'total_analyzed': 0,
            'threats_detected': 0,
            'ai_escalations': 0,
            'attack_chains_detected': 0,
        }
        
        logger.info("Advanced Threat Detector v2.0 initialized")
    
    def analyze(self, event: Dict, event_type: str = 'process') -> ThreatPrediction:
        """
        Analyze an event for threats.
        
        Args:
            event: Event data dictionary
            event_type: Type of event (process, network, file, registry)
            
        Returns:
            ThreatPrediction with full analysis results
        """
        self.stats['total_analyzed'] += 1
        
        # Get recent behavioral events
        behavioral_events = self.behavioral_analyzer.get_recent_events()
        
        # Get baseline for anomaly detection
        baseline = self.anomaly_detector.get_baseline()
        
        # Extract features
        features = self.feature_extractor.extract_all_features(
            event, behavioral_events, baseline
        )
        
        # Update baseline
        self.anomaly_detector.update_baseline(event)
        self.anomaly_detector.add_features(features)
        
        # Add to behavioral analyzer
        behav_event = BehavioralEvent(
            timestamp=datetime.now(),
            event_type=event_type,
            process_name=str(event.get('name', 'unknown')),
            details=event,
            threat_score=0.0
        )
        self.behavioral_analyzer.add_event(behav_event)
        
        # Get ensemble prediction
        is_threat, confidence, model_scores = self.ensemble_model.predict(features)
        
        # Get anomaly score
        anomaly_score = self.anomaly_detector.get_anomaly_score(features)
        stat_anomaly = self.anomaly_detector.get_statistical_anomaly_score(event)
        combined_anomaly = max(anomaly_score, stat_anomaly)
        
        # Detect attack chains
        attack_chains = self.behavioral_analyzer.detect_attack_chains()
        
        # Get MITRE mappings
        mitre_matches = map_to_mitre(event)
        mitre_techniques = [m['technique_id'] for m in mitre_matches[:5]]
        
        # Calculate behavioral score from attack chains
        behavioral_score = 0.0
        if attack_chains:
            behavioral_score = max(chain['confidence'] for chain in attack_chains)
            self.stats['attack_chains_detected'] += 1
        
        # Combine scores for final decision
        final_confidence = self._combine_scores(
            confidence, combined_anomaly, behavioral_score
        )
        
        # Determine severity
        severity = self._determine_severity(
            final_confidence, is_threat, attack_chains, mitre_techniques
        )
        
        # Determine threat type
        threat_type = self._determine_threat_type(
            event, attack_chains, mitre_matches
        )
        
        # Build reason
        reason = self._build_reason(
            is_threat, confidence, combined_anomaly, 
            behavioral_score, attack_chains, mitre_matches
        )
        
        # Determine if AI review is needed
        needs_ai = self._needs_ai_review(
            final_confidence, severity, is_threat
        )
        
        if is_threat:
            self.stats['threats_detected'] += 1
        if needs_ai:
            self.stats['ai_escalations'] += 1
        
        # Update behavioral event with threat score
        behav_event.threat_score = final_confidence
        
        return ThreatPrediction(
            is_threat=is_threat or final_confidence > 0.6,
            confidence=final_confidence,
            threat_type=threat_type,
            severity=severity,
            reason=reason,
            mitre_techniques=mitre_techniques,
            feature_importance=self.ensemble_model.get_feature_importance(),
            anomaly_score=combined_anomaly,
            behavioral_score=behavioral_score,
            attack_chains=attack_chains,
            needs_ai_review=needs_ai,
            model_used="ensemble_v2",
            model_scores=model_scores,
        )
    
    def _combine_scores(self, ml_confidence: float, anomaly_score: float,
                       behavioral_score: float) -> float:
        """Combine different scores into final confidence."""
        # Weighted combination
        weights = {
            'ml': 0.50,
            'anomaly': 0.25,
            'behavioral': 0.25,
        }
        
        combined = (
            ml_confidence * weights['ml'] +
            anomaly_score * weights['anomaly'] +
            behavioral_score * weights['behavioral']
        )
        
        # Boost if multiple signals agree
        if ml_confidence > 0.6 and anomaly_score > 0.6:
            combined = min(combined * 1.2, 1.0)
        if behavioral_score > 0.6:
            combined = min(combined * 1.15, 1.0)
        
        return min(combined, 1.0)
    
    def _determine_severity(self, confidence: float, is_threat: bool,
                           attack_chains: List[Dict], 
                           mitre_techniques: List[str]) -> str:
        """Determine threat severity."""
        # Check attack chain severity
        if attack_chains:
            chain_severities = [c.get('severity', 'MEDIUM') for c in attack_chains]
            if 'CRITICAL' in chain_severities:
                return 'CRITICAL'
            if 'HIGH' in chain_severities:
                return 'HIGH'
        
        # Check for critical MITRE techniques
        critical_techniques = ['T1003', 'T1486', 'T1490', 'T1558']
        if any(t.startswith(tuple(critical_techniques)) for t in mitre_techniques):
            return 'CRITICAL'
        
        # Based on confidence
        if confidence >= 0.9:
            return 'CRITICAL'
        elif confidence >= 0.7:
            return 'HIGH'
        elif confidence >= 0.5:
            return 'MEDIUM'
        elif confidence >= 0.3:
            return 'LOW'
        else:
            return 'INFO'
    
    def _determine_threat_type(self, event: Dict, attack_chains: List[Dict],
                              mitre_matches: List[Dict]) -> str:
        """Determine the type of threat."""
        # From attack chains
        if attack_chains:
            return attack_chains[0]['pattern']
        
        # From MITRE matches
        if mitre_matches:
            tactic = mitre_matches[0].get('tactic', '')
            if 'Credential' in tactic:
                return 'credential_theft'
            elif 'Execution' in tactic:
                return 'malicious_execution'
            elif 'Persistence' in tactic:
                return 'persistence'
            elif 'Lateral' in tactic:
                return 'lateral_movement'
            elif 'Exfiltration' in tactic:
                return 'data_exfiltration'
            elif 'Impact' in tactic:
                return 'destructive'
        
        # From event data
        cmdline = str(event.get('cmdline', '')).lower()
        if any(p in cmdline for p in ['mimikatz', 'sekurlsa', 'lsass']):
            return 'credential_theft'
        if any(p in cmdline for p in ['-enc', 'encoded', 'base64']):
            return 'obfuscated_execution'
        if any(p in cmdline for p in ['download', 'http', 'wget', 'curl']):
            return 'downloader'
        
        return 'suspicious_activity'
    
    def _build_reason(self, is_threat: bool, ml_confidence: float,
                     anomaly_score: float, behavioral_score: float,
                     attack_chains: List[Dict], 
                     mitre_matches: List[Dict]) -> str:
        """Build human-readable reason for the detection."""
        reasons = []
        
        if ml_confidence > 0.6:
            reasons.append(f"ML model: {ml_confidence:.0%} threat probability")
        
        if anomaly_score > 0.5:
            reasons.append(f"Anomaly detected: {anomaly_score:.0%} deviation from baseline")
        
        if behavioral_score > 0.5:
            reasons.append(f"Behavioral pattern: {behavioral_score:.0%} match")
        
        if attack_chains:
            chain_names = [c['pattern'] for c in attack_chains[:2]]
            reasons.append(f"Attack chain: {', '.join(chain_names)}")
        
        if mitre_matches:
            techniques = [f"{m['technique_id']} ({m['technique_name']})" 
                         for m in mitre_matches[:3]]
            reasons.append(f"MITRE: {', '.join(techniques)}")
        
        if not reasons:
            if is_threat:
                reasons.append("Multiple weak indicators combined")
            else:
                reasons.append("No significant threat indicators")
        
        return "; ".join(reasons)
    
    def _needs_ai_review(self, confidence: float, severity: str,
                        is_threat: bool) -> bool:
        """Determine if event needs AI review for deeper analysis."""
        if not self.use_ai_escalation:
            return False
        
        # Uncertain predictions need review
        if 0.4 < confidence < 0.7:
            return True
        
        # High severity threats should be reviewed
        if severity in ['CRITICAL', 'HIGH'] and is_threat:
            return True
        
        return False
    
    def train_on_data(self, X: List[List[float]], y: List[int],
                     feature_names: List[str] = None):
        """Train the ensemble model on labeled data."""
        if feature_names is None:
            feature_names = self.feature_extractor.feature_names
        
        self.ensemble_model.train(X, y, feature_names)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return {
            **self.stats,
            'ensemble_stats': self.ensemble_model.get_stats(),
            'anomaly_stats': self.anomaly_detector.get_stats(),
            'behavioral_stats': self.behavioral_analyzer.get_stats(),
            'feature_count': len(self.feature_extractor.feature_names),
        }
    
    def save_state(self):
        """Save all model states."""
        self.ensemble_model.save_models()
        self.anomaly_detector.save_baseline()
        logger.info("Saved detector state")


# Singleton instance
_detector: Optional[AdvancedThreatDetector] = None


def get_advanced_detector(model_dir: str = None, 
                         use_ai: bool = True) -> AdvancedThreatDetector:
    """Get or create the advanced detector instance."""
    global _detector
    if _detector is None:
        _detector = AdvancedThreatDetector(model_dir=model_dir, use_ai_escalation=use_ai)
    return _detector
