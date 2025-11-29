"""
Baseline Anomaly Detector
Learns normal behavior and detects anomalies.
Uses statistical methods and Isolation Forest.
"""

import os
import pickle
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
from collections import defaultdict

logger = logging.getLogger("SentinelAgent.ML")

# Try to import ML libraries
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class BaselineAnomalyDetector:
    """
    Detect anomalies by learning baseline behavior.
    Uses statistical methods and Isolation Forest.
    """
    
    def __init__(self, learning_period_hours: int = 24, model_dir: str = None):
        self.learning_period = timedelta(hours=learning_period_hours)
        self.baseline_start = datetime.now()
        self.is_learning = True
        
        # Model directory
        self.model_dir = model_dir or os.path.join(os.path.dirname(__file__), 'models')
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Baseline statistics
        self.process_frequency: Dict[str, int] = defaultdict(int)
        self.cmdline_frequency: Dict[str, int] = defaultdict(int)
        self.path_frequency: Dict[str, int] = defaultdict(int)
        self.port_frequency: Dict[int, int] = defaultdict(int)
        self.ip_frequency: Dict[str, int] = defaultdict(int)
        self.hourly_activity: Dict[int, int] = defaultdict(int)
        self.parent_child_pairs: Dict[str, int] = defaultdict(int)
        
        # Event counts
        self.total_events = 0
        
        # Isolation Forest
        self.isolation_forest = None
        self.scaler = None
        self.feature_buffer: List[List[float]] = []
        self.min_samples_for_training = 100
        
        if SKLEARN_AVAILABLE:
            self.isolation_forest = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )
            self.scaler = StandardScaler()
        
        # Try to load existing baseline
        self._load_baseline()
    
    def _load_baseline(self):
        """Load existing baseline if available."""
        baseline_path = os.path.join(self.model_dir, 'baseline.pkl')
        if os.path.exists(baseline_path):
            try:
                with open(baseline_path, 'rb') as f:
                    data = pickle.load(f)
                    self.process_frequency = defaultdict(int, data.get('process_frequency', {}))
                    self.cmdline_frequency = defaultdict(int, data.get('cmdline_frequency', {}))
                    self.path_frequency = defaultdict(int, data.get('path_frequency', {}))
                    self.port_frequency = defaultdict(int, data.get('port_frequency', {}))
                    self.ip_frequency = defaultdict(int, data.get('ip_frequency', {}))
                    self.hourly_activity = defaultdict(int, data.get('hourly_activity', {}))
                    self.parent_child_pairs = defaultdict(int, data.get('parent_child_pairs', {}))
                    self.total_events = data.get('total_events', 0)
                    self.is_learning = data.get('is_learning', True)
                    
                    # Try to load isolation forest, but don't fail if version mismatch
                    if data.get('isolation_forest') and SKLEARN_AVAILABLE:
                        try:
                            self.isolation_forest = data['isolation_forest']
                        except Exception:
                            # Version mismatch - create new one
                            self.isolation_forest = IsolationForest(
                                n_estimators=100,
                                contamination=0.1,
                                random_state=42,
                                n_jobs=-1
                            )
                        self.scaler = data.get('scaler', StandardScaler())
                    
                    logger.info(f"Loaded baseline with {self.total_events} events")
            except Exception as e:
                logger.warning(f"Could not load baseline: {e}")
    
    def save_baseline(self):
        """Save current baseline."""
        baseline_path = os.path.join(self.model_dir, 'baseline.pkl')
        try:
            with open(baseline_path, 'wb') as f:
                pickle.dump({
                    'process_frequency': dict(self.process_frequency),
                    'cmdline_frequency': dict(self.cmdline_frequency),
                    'path_frequency': dict(self.path_frequency),
                    'port_frequency': dict(self.port_frequency),
                    'ip_frequency': dict(self.ip_frequency),
                    'hourly_activity': dict(self.hourly_activity),
                    'parent_child_pairs': dict(self.parent_child_pairs),
                    'total_events': self.total_events,
                    'is_learning': self.is_learning,
                    'isolation_forest': self.isolation_forest if SKLEARN_AVAILABLE else None,
                    'scaler': self.scaler if SKLEARN_AVAILABLE else None,
                }, f)
            logger.debug("Saved baseline")
        except Exception as e:
            logger.error(f"Could not save baseline: {e}")
    
    def update_baseline(self, event: Dict):
        """Update baseline statistics with new event."""
        self.total_events += 1
        
        # Update frequencies
        process_name = str(event.get('name', '')).lower()
        if process_name:
            self.process_frequency[process_name] += 1
        
        cmdline = str(event.get('cmdline', ''))[:50].lower()
        if cmdline:
            self.cmdline_frequency[cmdline] += 1
        
        path = str(event.get('exe', '')).lower()
        if path:
            self.path_frequency[path] += 1
        
        port = event.get('remote_port', 0)
        if port:
            self.port_frequency[port] += 1
        
        ip = event.get('remote_ip', '')
        if ip:
            self.ip_frequency[ip] += 1
        
        hour = datetime.now().hour
        self.hourly_activity[hour] += 1
        
        # Parent-child relationship
        parent = str(event.get('parent_name', '')).lower()
        if parent and process_name:
            pair = f"{parent}->{process_name}"
            self.parent_child_pairs[pair] += 1
        
        # Check if learning period is over
        if self.is_learning and datetime.now() - self.baseline_start > self.learning_period:
            self.is_learning = False
            self._train_isolation_forest()
            self.save_baseline()
            logger.info("Baseline learning complete - anomaly detection active")
        
        # Periodic save
        if self.total_events % 1000 == 0:
            self.save_baseline()
    
    def _train_isolation_forest(self):
        """Train Isolation Forest on collected features."""
        if not SKLEARN_AVAILABLE or not NUMPY_AVAILABLE:
            return
        
        if len(self.feature_buffer) < self.min_samples_for_training:
            logger.warning(f"Not enough samples for training: {len(self.feature_buffer)}")
            return
        
        try:
            X = np.array(self.feature_buffer)
            X_scaled = self.scaler.fit_transform(X)
            self.isolation_forest.fit(X_scaled)
            logger.info(f"Isolation Forest trained on {len(self.feature_buffer)} samples")
        except Exception as e:
            logger.error(f"Failed to train Isolation Forest: {e}")
    
    def add_features(self, features: List[float]):
        """Add features to buffer for Isolation Forest training."""
        if len(self.feature_buffer) < 10000:
            self.feature_buffer.append(features)
    
    def get_anomaly_score(self, features: List[float]) -> float:
        """Get anomaly score for features using Isolation Forest."""
        if not SKLEARN_AVAILABLE or not NUMPY_AVAILABLE:
            return 0.0
        
        if self.isolation_forest is None or self.is_learning:
            return 0.0
        
        try:
            X = np.array([features])
            X_scaled = self.scaler.transform(X)
            # Isolation Forest returns -1 for anomalies, 1 for normal
            score = -self.isolation_forest.score_samples(X_scaled)[0]
            return max(0.0, min(1.0, (score + 0.5)))
        except Exception as e:
            logger.debug(f"Anomaly scoring error: {e}")
            return 0.0
    
    def get_statistical_anomaly_score(self, event: Dict) -> float:
        """Get anomaly score based on statistical rarity."""
        if self.total_events < 100:
            return 0.0
        
        scores = []
        
        # Process rarity
        process_name = str(event.get('name', '')).lower()
        if process_name:
            freq = self.process_frequency.get(process_name, 0)
            rarity = 1.0 - (freq / max(self.total_events, 1))
            scores.append(rarity)
        
        # Path rarity
        path = str(event.get('exe', '')).lower()
        if path:
            freq = self.path_frequency.get(path, 0)
            rarity = 1.0 - (freq / max(self.total_events, 1))
            scores.append(rarity)
        
        # Parent-child rarity
        parent = str(event.get('parent_name', '')).lower()
        if parent and process_name:
            pair = f"{parent}->{process_name}"
            freq = self.parent_child_pairs.get(pair, 0)
            rarity = 1.0 - (freq / max(self.total_events, 1))
            scores.append(rarity * 1.5)  # Weight parent-child more
        
        # Time anomaly
        hour = datetime.now().hour
        hour_freq = self.hourly_activity.get(hour, 0)
        total_hourly = sum(self.hourly_activity.values())
        if total_hourly > 0:
            expected = total_hourly / 24
            time_anomaly = abs(hour_freq - expected) / max(expected, 1)
            scores.append(min(time_anomaly, 1.0))
        
        if not scores:
            return 0.0
        
        return min(sum(scores) / len(scores), 1.0)
    
    def is_parent_child_unusual(self, parent: str, child: str) -> bool:
        """Check if parent-child relationship is unusual."""
        if self.total_events < 100:
            return False
        
        pair = f"{parent.lower()}->{child.lower()}"
        freq = self.parent_child_pairs.get(pair, 0)
        
        # If we've never seen this pair and have enough data, it's unusual
        return freq == 0 and self.total_events > 500
    
    def get_baseline(self) -> Dict:
        """Get current baseline statistics."""
        return {
            'process_frequency': dict(self.process_frequency),
            'cmdline_frequency': dict(self.cmdline_frequency),
            'path_frequency': dict(self.path_frequency),
            'port_frequency': dict(self.port_frequency),
            'ip_frequency': dict(self.ip_frequency),
            'hourly_activity': dict(self.hourly_activity),
            'avg_activity_hour': self._get_avg_activity_hour(),
            'total_events': self.total_events,
            'is_learning': self.is_learning,
            'unique_processes': len(self.process_frequency),
            'unique_paths': len(self.path_frequency),
        }
    
    def _get_avg_activity_hour(self) -> float:
        """Calculate average activity hour."""
        if not self.hourly_activity:
            return 12.0
        
        total_weight = sum(self.hourly_activity.values())
        if total_weight == 0:
            return 12.0
        
        weighted_sum = sum(hour * count for hour, count in self.hourly_activity.items())
        return weighted_sum / total_weight
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return {
            'total_events': self.total_events,
            'is_learning': self.is_learning,
            'unique_processes': len(self.process_frequency),
            'unique_paths': len(self.path_frequency),
            'unique_ports': len(self.port_frequency),
            'unique_ips': len(self.ip_frequency),
            'feature_buffer_size': len(self.feature_buffer),
            'isolation_forest_trained': not self.is_learning and self.isolation_forest is not None,
        }
