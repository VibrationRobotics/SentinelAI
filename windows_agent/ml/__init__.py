"""
SentinelAI Advanced ML Threat Detection System v2.0
State-of-the-art machine learning for endpoint security.
"""

from .feature_extractor import AdvancedFeatureExtractor
from .behavioral_analyzer import BehavioralSequenceAnalyzer, BehavioralEvent
from .anomaly_detector import BaselineAnomalyDetector
from .ensemble_model import EnsembleThreatModel
from .threat_detector import AdvancedThreatDetector, ThreatPrediction, get_advanced_detector
from .mitre_mapping import MITRE_TECHNIQUES, map_to_mitre
from .online_learning import OnlineLearningManager, get_learning_manager

__all__ = [
    'AdvancedFeatureExtractor',
    'BehavioralSequenceAnalyzer', 
    'BehavioralEvent',
    'BaselineAnomalyDetector',
    'EnsembleThreatModel',
    'AdvancedThreatDetector',
    'ThreatPrediction',
    'get_advanced_detector',
    'MITRE_TECHNIQUES',
    'map_to_mitre',
    'OnlineLearningManager',
    'get_learning_manager',
]

__version__ = '2.0.0'
