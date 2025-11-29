"""
Online Learning Module for SentinelAI ML v2.0
Enables autonomous learning from real-world events.

Features:
- Collects labeled events over time
- Periodically retrains models with new data
- Learns from user feedback (false positive/negative corrections)
- Maintains training history for reproducibility
"""

import os
import json
import pickle
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import deque

logger = logging.getLogger("SentinelAgent.ML.OnlineLearning")


class OnlineLearningManager:
    """
    Manages autonomous learning from real-world events.
    Collects data, labels events, and periodically retrains.
    """
    
    def __init__(self, 
                 model_dir: str = None,
                 min_samples_for_retrain: int = 500,
                 retrain_interval_hours: int = 24,
                 max_stored_samples: int = 50000):
        
        self.model_dir = model_dir or os.path.join(os.path.dirname(__file__), 'models')
        os.makedirs(self.model_dir, exist_ok=True)
        
        self.min_samples_for_retrain = min_samples_for_retrain
        self.retrain_interval = timedelta(hours=retrain_interval_hours)
        self.max_stored_samples = max_stored_samples
        
        # Training data storage
        self.training_data_path = os.path.join(self.model_dir, 'online_training_data.pkl')
        self.training_samples: List[Tuple[List[float], int, Dict]] = []  # (features, label, metadata)
        
        # Feedback storage
        self.feedback_path = os.path.join(self.model_dir, 'user_feedback.json')
        self.user_feedback: Dict[str, Dict] = {}  # event_hash -> feedback
        
        # Stats
        self.stats = {
            'samples_collected': 0,
            'samples_from_feedback': 0,
            'auto_labeled_threats': 0,
            'auto_labeled_benign': 0,
            'retrains_completed': 0,
            'last_retrain': None,
        }
        
        # Background thread
        self._running = False
        self._thread = None
        self._lock = threading.Lock()
        
        # Load existing data
        self._load_training_data()
        self._load_feedback()
        
        logger.info(f"Online Learning initialized with {len(self.training_samples)} existing samples")
    
    def _load_training_data(self):
        """Load existing training data."""
        if os.path.exists(self.training_data_path):
            try:
                with open(self.training_data_path, 'rb') as f:
                    data = pickle.load(f)
                    self.training_samples = data.get('samples', [])
                    self.stats = data.get('stats', self.stats)
                logger.info(f"Loaded {len(self.training_samples)} training samples")
            except Exception as e:
                logger.warning(f"Could not load training data: {e}")
    
    def _save_training_data(self):
        """Save training data to disk."""
        try:
            with open(self.training_data_path, 'wb') as f:
                pickle.dump({
                    'samples': self.training_samples,
                    'stats': self.stats,
                }, f)
        except Exception as e:
            logger.error(f"Could not save training data: {e}")
    
    def _load_feedback(self):
        """Load user feedback."""
        if os.path.exists(self.feedback_path):
            try:
                with open(self.feedback_path, 'r') as f:
                    self.user_feedback = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load feedback: {e}")
    
    def _save_feedback(self):
        """Save user feedback."""
        try:
            with open(self.feedback_path, 'w') as f:
                json.dump(self.user_feedback, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save feedback: {e}")
    
    def add_sample(self, features: List[float], label: int, metadata: Dict = None):
        """
        Add a labeled sample for training.
        
        Args:
            features: Feature vector (150 features)
            label: 0 for benign, 1 for malicious
            metadata: Optional metadata about the sample
        """
        with self._lock:
            metadata = metadata or {}
            metadata['timestamp'] = datetime.now().isoformat()
            
            self.training_samples.append((features, label, metadata))
            self.stats['samples_collected'] += 1
            
            if label == 1:
                self.stats['auto_labeled_threats'] += 1
            else:
                self.stats['auto_labeled_benign'] += 1
            
            # Trim if too many samples
            if len(self.training_samples) > self.max_stored_samples:
                # Remove oldest samples
                self.training_samples = self.training_samples[-self.max_stored_samples:]
            
            # Periodic save
            if self.stats['samples_collected'] % 100 == 0:
                self._save_training_data()
    
    def add_event_for_learning(self, event: Dict, features: List[float], 
                               prediction_is_threat: bool, prediction_confidence: float):
        """
        Add an event for autonomous learning.
        Uses high-confidence predictions as labels.
        
        Args:
            event: Original event data
            features: Extracted features
            prediction_is_threat: ML prediction
            prediction_confidence: Confidence of prediction
        """
        # Only learn from high-confidence predictions
        if prediction_confidence < 0.8:
            return
        
        # Create event hash for deduplication
        event_hash = self._hash_event(event)
        
        # Check if user provided feedback for this event
        if event_hash in self.user_feedback:
            feedback = self.user_feedback[event_hash]
            label = 1 if feedback.get('is_threat', prediction_is_threat) else 0
            self.stats['samples_from_feedback'] += 1
        else:
            # Use high-confidence prediction as label
            label = 1 if prediction_is_threat else 0
        
        metadata = {
            'event_type': event.get('event_type', 'unknown'),
            'process_name': event.get('name', ''),
            'confidence': prediction_confidence,
            'source': 'auto_label' if event_hash not in self.user_feedback else 'user_feedback',
        }
        
        self.add_sample(features, label, metadata)
    
    def add_user_feedback(self, event: Dict, is_threat: bool, is_false_positive: bool = False):
        """
        Add user feedback for an event.
        This is used to correct ML mistakes.
        
        Args:
            event: Original event data
            is_threat: User's determination
            is_false_positive: True if ML was wrong
        """
        event_hash = self._hash_event(event)
        
        self.user_feedback[event_hash] = {
            'is_threat': is_threat,
            'is_false_positive': is_false_positive,
            'timestamp': datetime.now().isoformat(),
        }
        
        self._save_feedback()
        logger.info(f"User feedback recorded: {'threat' if is_threat else 'benign'} (FP: {is_false_positive})")
    
    def _hash_event(self, event: Dict) -> str:
        """Create a hash for event deduplication."""
        import hashlib
        key_parts = [
            str(event.get('name', '')),
            str(event.get('exe', ''))[:100],
            str(event.get('cmdline', ''))[:200],
        ]
        return hashlib.md5('|'.join(key_parts).encode()).hexdigest()
    
    def should_retrain(self) -> bool:
        """Check if it's time to retrain."""
        # Check sample count
        if len(self.training_samples) < self.min_samples_for_retrain:
            return False
        
        # Check time since last retrain
        if self.stats['last_retrain']:
            last_retrain = datetime.fromisoformat(self.stats['last_retrain'])
            if datetime.now() - last_retrain < self.retrain_interval:
                return False
        
        return True
    
    def retrain_model(self, detector) -> bool:
        """
        Retrain the model with collected data.
        
        Args:
            detector: AdvancedThreatDetector instance
            
        Returns:
            True if retrain was successful
        """
        with self._lock:
            if len(self.training_samples) < self.min_samples_for_retrain:
                logger.warning(f"Not enough samples for retrain: {len(self.training_samples)}")
                return False
            
            try:
                logger.info(f"Starting model retrain with {len(self.training_samples)} samples...")
                
                # Prepare data
                X = [s[0] for s in self.training_samples]
                y = [s[1] for s in self.training_samples]
                
                # Get feature names
                feature_names = detector.feature_extractor.feature_names
                
                # Train
                detector.ensemble_model.train(X, y, feature_names)
                
                # Update stats
                self.stats['retrains_completed'] += 1
                self.stats['last_retrain'] = datetime.now().isoformat()
                
                # Save
                self._save_training_data()
                detector.save_state()
                
                logger.info(f"Model retrain complete! Accuracy improved with {len(X)} samples")
                return True
                
            except Exception as e:
                logger.error(f"Retrain failed: {e}")
                return False
    
    def start_background_learning(self, detector):
        """Start background thread for autonomous learning."""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._learning_loop, args=(detector,), daemon=True)
        self._thread.start()
        logger.info("Background learning started")
    
    def stop_background_learning(self):
        """Stop background learning thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Background learning stopped")
    
    def _learning_loop(self, detector):
        """Background loop for autonomous retraining."""
        while self._running:
            try:
                # Check every hour
                time.sleep(3600)
                
                if self.should_retrain():
                    logger.info("Autonomous retrain triggered")
                    self.retrain_model(detector)
                    
            except Exception as e:
                logger.error(f"Learning loop error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get learning statistics."""
        return {
            **self.stats,
            'total_samples': len(self.training_samples),
            'feedback_count': len(self.user_feedback),
            'ready_for_retrain': self.should_retrain(),
        }


# Singleton instance
_learning_manager: Optional[OnlineLearningManager] = None


def get_learning_manager(model_dir: str = None) -> OnlineLearningManager:
    """Get or create the learning manager instance."""
    global _learning_manager
    if _learning_manager is None:
        _learning_manager = OnlineLearningManager(model_dir=model_dir)
    return _learning_manager
