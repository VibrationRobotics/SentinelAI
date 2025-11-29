"""
Train the Advanced ML v2.0 Threat Detection System
Run this script to train the models on synthetic threat data.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml import get_advanced_detector
from ml.training_data import SyntheticDataGenerator

def main():
    print("=" * 60)
    print("  SentinelAI Advanced ML v2.0 - Training")
    print("=" * 60)
    print()
    
    # Initialize detector
    print("[1/4] Initializing detector...")
    detector = get_advanced_detector()
    print(f"      Feature count: {len(detector.feature_extractor.feature_names)}")
    print(f"      Models: {list(detector.ensemble_model.models.keys())}")
    print()
    
    # Generate synthetic data
    print("[2/4] Generating synthetic training data...")
    generator = SyntheticDataGenerator()
    n_samples = 5000
    X, y = generator.generate_dataset(n_samples=n_samples, malicious_ratio=0.3)
    
    n_malicious = sum(y)
    n_benign = len(y) - n_malicious
    print(f"      Total samples: {len(X)}")
    print(f"      Malicious: {n_malicious} ({n_malicious/len(y)*100:.1f}%)")
    print(f"      Benign: {n_benign} ({n_benign/len(y)*100:.1f}%)")
    print()
    
    # Train models
    print("[3/4] Training ensemble models...")
    detector.train_on_data(X, y, generator.get_feature_names())
    print()
    
    # Test prediction
    print("[4/4] Testing predictions...")
    
    # Test benign
    benign_event = {
        'name': 'chrome.exe',
        'exe': 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'cmdline': 'chrome.exe --type=renderer',
        'user': 'User',
        'parent_name': 'explorer.exe'
    }
    result = detector.analyze(benign_event, 'process')
    print(f"      Benign test: is_threat={result.is_threat}, confidence={result.confidence:.2f}, severity={result.severity}")
    
    # Test malicious
    malicious_event = {
        'name': 'powershell.exe',
        'exe': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        'cmdline': 'powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA== -windowstyle hidden',
        'user': 'User',
        'parent_name': 'cmd.exe'
    }
    result = detector.analyze(malicious_event, 'process')
    print(f"      Malicious test: is_threat={result.is_threat}, confidence={result.confidence:.2f}, severity={result.severity}")
    print(f"      MITRE techniques: {result.mitre_techniques[:3]}")
    print()
    
    # Save state
    print("Saving trained models...")
    detector.save_state()
    
    # Final stats
    stats = detector.get_stats()
    print()
    print("=" * 60)
    print("  Training Complete!")
    print("=" * 60)
    print(f"  Ensemble trained: {stats['ensemble_stats']['is_trained']}")
    print(f"  Models: {stats['ensemble_stats']['models_available']}")
    print(f"  Total analyzed: {stats['total_analyzed']}")
    print(f"  Threats detected: {stats['threats_detected']}")
    print()
    print("  Models saved to: windows_agent/ml/models/")
    print("=" * 60)

if __name__ == '__main__':
    main()
