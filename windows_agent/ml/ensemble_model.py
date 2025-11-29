"""
Ensemble Threat Model
Combines LightGBM, XGBoost, and Random Forest for robust predictions.
"""

import os
import pickle
import logging
from typing import Dict, List, Tuple, Any

logger = logging.getLogger("SentinelAgent.ML")

# Try to import ML libraries
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import lightgbm as lgb
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False


class EnsembleThreatModel:
    """
    Ensemble model combining multiple ML algorithms.
    Uses LightGBM, XGBoost, and Random Forest with weighted voting.
    """
    
    def __init__(self, model_dir: str = None):
        self.model_dir = model_dir or os.path.join(os.path.dirname(__file__), 'models')
        os.makedirs(self.model_dir, exist_ok=True)
        
        self.models = {}
        self.scaler = None
        self.feature_names = []
        self.is_trained = False
        
        # Model weights for ensemble voting
        self.weights = {
            'lightgbm': 0.40,
            'xgboost': 0.35,
            'random_forest': 0.25,
        }
        
        self._initialize_models()
        self._load_models()
    
    def _initialize_models(self):
        """Initialize ML models."""
        if SKLEARN_AVAILABLE:
            self.models['random_forest'] = RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                n_jobs=-1,
                random_state=42
            )
            self.scaler = StandardScaler()
        
        if LIGHTGBM_AVAILABLE:
            self.models['lightgbm'] = lgb.LGBMClassifier(
                n_estimators=100,
                max_depth=10,
                learning_rate=0.1,
                num_leaves=31,
                n_jobs=-1,
                random_state=42,
                verbose=-1
            )
        
        if XGBOOST_AVAILABLE:
            self.models['xgboost'] = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=10,
                learning_rate=0.1,
                n_jobs=-1,
                random_state=42,
                verbosity=0,
                use_label_encoder=False,
                eval_metric='logloss'
            )
    
    def _load_models(self):
        """Load pre-trained models if available."""
        model_path = os.path.join(self.model_dir, 'ensemble_model.pkl')
        
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    data = pickle.load(f)
                    saved_models = data.get('models', {})
                    
                    # Only load models that are available
                    for name, model in saved_models.items():
                        if name in self.models:
                            self.models[name] = model
                    
                    self.scaler = data.get('scaler', self.scaler)
                    self.feature_names = data.get('feature_names', [])
                    self.is_trained = data.get('is_trained', False)
                    
                logger.info("Loaded pre-trained ensemble model")
            except Exception as e:
                logger.warning(f"Could not load model: {e}")
    
    def save_models(self):
        """Save trained models."""
        model_path = os.path.join(self.model_dir, 'ensemble_model.pkl')
        
        try:
            with open(model_path, 'wb') as f:
                pickle.dump({
                    'models': self.models,
                    'scaler': self.scaler,
                    'feature_names': self.feature_names,
                    'is_trained': self.is_trained,
                }, f)
            logger.info("Saved ensemble model")
        except Exception as e:
            logger.error(f"Could not save model: {e}")
    
    def train(self, X: List[List[float]], y: List[int], feature_names: List[str] = None):
        """Train all models in the ensemble."""
        if not SKLEARN_AVAILABLE or not NUMPY_AVAILABLE:
            logger.warning("scikit-learn/numpy not available - cannot train")
            return
        
        if len(X) < 100:
            logger.warning(f"Not enough samples for training: {len(X)}")
            return
        
        self.feature_names = feature_names or []
        
        X_array = np.array(X)
        y_array = np.array(y)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X_array)
        
        # Train each model
        for name, model in self.models.items():
            try:
                logger.info(f"Training {name}...")
                model.fit(X_scaled, y_array)
                logger.info(f"Trained {name}")
            except Exception as e:
                logger.error(f"Failed to train {name}: {e}")
        
        self.is_trained = True
        self.save_models()
        logger.info(f"Ensemble training complete on {len(X)} samples")
    
    def predict(self, features: List[float]) -> Tuple[bool, float, Dict[str, float]]:
        """
        Predict using ensemble voting.
        
        Returns:
            Tuple of (is_threat, confidence, model_scores)
        """
        if not self.is_trained or not self.models:
            return self._fallback_predict(features)
        
        if not NUMPY_AVAILABLE:
            return self._fallback_predict(features)
        
        try:
            X = np.array([features])
            X_scaled = self.scaler.transform(X)
            
            predictions = {}
            probabilities = {}
            
            for name, model in self.models.items():
                try:
                    pred = model.predict(X_scaled)[0]
                    prob = model.predict_proba(X_scaled)[0]
                    predictions[name] = int(pred)
                    probabilities[name] = float(prob[1]) if len(prob) > 1 else float(prob[0])
                except Exception as e:
                    logger.debug(f"Prediction error for {name}: {e}")
            
            if not probabilities:
                return self._fallback_predict(features)
            
            # Weighted ensemble voting
            weighted_prob = 0.0
            total_weight = 0.0
            
            for name, prob in probabilities.items():
                weight = self.weights.get(name, 0.33)
                weighted_prob += prob * weight
                total_weight += weight
            
            final_prob = weighted_prob / total_weight if total_weight > 0 else 0.5
            is_threat = final_prob > 0.5
            
            return is_threat, final_prob, probabilities
            
        except Exception as e:
            logger.error(f"Ensemble prediction error: {e}")
            return self._fallback_predict(features)
    
    def _fallback_predict(self, features: List[float]) -> Tuple[bool, float, Dict[str, float]]:
        """Fallback prediction using heuristics when ML is not available."""
        # Simple heuristic based on feature values
        score = 0.0
        
        # Check some key feature indices (process features)
        if len(features) > 16:
            # Encoded command
            if features[16] > 0: score += 0.3
            # Hidden window
            if features[17] > 0: score += 0.2
            # Bypass
            if features[18] > 0: score += 0.2
            # Download
            if features[19] > 0: score += 0.15
            # HTTP in cmdline
            if features[21] > 0: score += 0.1
            # LOLBin
            if features[29] > 0: score += 0.2
        
        is_threat = score > 0.4
        return is_threat, min(score, 1.0), {'heuristic': score}
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from models."""
        importance = {}
        
        if not self.is_trained or not self.feature_names:
            return importance
        
        try:
            # Get importance from Random Forest
            if 'random_forest' in self.models:
                rf = self.models['random_forest']
                if hasattr(rf, 'feature_importances_'):
                    rf_imp = rf.feature_importances_
                    for i, name in enumerate(self.feature_names):
                        if i < len(rf_imp):
                            importance[name] = float(rf_imp[i])
            
            # Get importance from LightGBM
            if 'lightgbm' in self.models:
                lgbm = self.models['lightgbm']
                if hasattr(lgbm, 'feature_importances_'):
                    lgbm_imp = lgbm.feature_importances_
                    for i, name in enumerate(self.feature_names):
                        if i < len(lgbm_imp):
                            if name in importance:
                                importance[name] = (importance[name] + float(lgbm_imp[i])) / 2
                            else:
                                importance[name] = float(lgbm_imp[i])
        except Exception as e:
            logger.debug(f"Error getting feature importance: {e}")
        
        # Sort by importance
        importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))
        return importance
    
    def get_stats(self) -> Dict[str, Any]:
        """Get model statistics."""
        return {
            'is_trained': self.is_trained,
            'models_available': list(self.models.keys()),
            'feature_count': len(self.feature_names),
            'sklearn_available': SKLEARN_AVAILABLE,
            'lightgbm_available': LIGHTGBM_AVAILABLE,
            'xgboost_available': XGBOOST_AVAILABLE,
        }
