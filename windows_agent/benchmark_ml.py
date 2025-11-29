"""
ML Model Benchmark Suite
Tests accuracy, precision, recall, F1 score, and speed.
"""

import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml import get_advanced_detector
from ml.training_data import SyntheticDataGenerator


def benchmark_model():
    print("=" * 70)
    print("  SentinelAI ML v2.0 - Benchmark Suite")
    print("=" * 70)
    print()
    
    # Initialize
    print("[1/5] Initializing...")
    detector = get_advanced_detector()
    generator = SyntheticDataGenerator()
    print(f"      Models: {detector.ensemble_model.get_stats()['models_available']}")
    print()
    
    # Generate test set (separate from training)
    print("[2/5] Generating test dataset (1000 samples)...")
    X_test, y_test = generator.generate_dataset(n_samples=1000, malicious_ratio=0.3)
    n_malicious = sum(y_test)
    n_benign = len(y_test) - n_malicious
    print(f"      Benign: {n_benign}, Malicious: {n_malicious}")
    print()
    
    # Run predictions
    print("[3/5] Running predictions...")
    predictions = []
    confidences = []
    start_time = time.time()
    
    for i, (features, label) in enumerate(zip(X_test, y_test)):
        # Create dummy event for prediction
        event = {'name': 'test', 'exe': '', 'cmdline': ''}
        
        # Get prediction from ensemble model directly
        is_threat, confidence, _ = detector.ensemble_model.predict(features)
        predictions.append(1 if is_threat else 0)
        confidences.append(confidence)
        
        if (i + 1) % 200 == 0:
            print(f"      Processed {i + 1}/1000...")
    
    elapsed = time.time() - start_time
    print(f"      Completed in {elapsed:.2f}s ({1000/elapsed:.0f} predictions/sec)")
    print()
    
    # Calculate metrics
    print("[4/5] Calculating metrics...")
    
    # Confusion matrix
    tp = sum(1 for p, a in zip(predictions, y_test) if p == 1 and a == 1)  # True Positive
    tn = sum(1 for p, a in zip(predictions, y_test) if p == 0 and a == 0)  # True Negative
    fp = sum(1 for p, a in zip(predictions, y_test) if p == 1 and a == 0)  # False Positive
    fn = sum(1 for p, a in zip(predictions, y_test) if p == 0 and a == 1)  # False Negative
    
    # Metrics
    accuracy = (tp + tn) / len(y_test)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # False positive rate
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    # Average confidence
    avg_conf_threats = sum(c for c, a in zip(confidences, y_test) if a == 1) / n_malicious if n_malicious > 0 else 0
    avg_conf_benign = sum(c for c, a in zip(confidences, y_test) if a == 0) / n_benign if n_benign > 0 else 0
    
    print()
    print("[5/5] Results")
    print()
    print("=" * 70)
    print("  CONFUSION MATRIX")
    print("=" * 70)
    print(f"                    Predicted")
    print(f"                 Benign  Threat")
    print(f"  Actual Benign   {tn:4d}    {fp:4d}")
    print(f"  Actual Threat   {fn:4d}    {tp:4d}")
    print()
    print("=" * 70)
    print("  PERFORMANCE METRICS")
    print("=" * 70)
    print(f"  Accuracy:           {accuracy:.1%}")
    print(f"  Precision:          {precision:.1%}  (of predicted threats, how many were real)")
    print(f"  Recall/Detection:   {recall:.1%}  (of real threats, how many did we catch)")
    print(f"  F1 Score:           {f1:.1%}  (harmonic mean of precision & recall)")
    print(f"  False Positive Rate: {fpr:.1%}  (benign flagged as threat)")
    print()
    print("=" * 70)
    print("  CONFIDENCE ANALYSIS")
    print("=" * 70)
    print(f"  Avg confidence on threats: {avg_conf_threats:.1%}")
    print(f"  Avg confidence on benign:  {avg_conf_benign:.1%}")
    print()
    print("=" * 70)
    print("  SPEED")
    print("=" * 70)
    print(f"  Total time:         {elapsed:.2f} seconds")
    print(f"  Predictions/sec:    {1000/elapsed:.0f}")
    print(f"  Avg per prediction: {elapsed/1000*1000:.2f} ms")
    print()
    
    # Rating
    print("=" * 70)
    print("  OVERALL RATING")
    print("=" * 70)
    if f1 >= 0.9:
        rating = "EXCELLENT"
    elif f1 >= 0.8:
        rating = "GOOD"
    elif f1 >= 0.7:
        rating = "ACCEPTABLE"
    elif f1 >= 0.6:
        rating = "NEEDS IMPROVEMENT"
    else:
        rating = "POOR"
    
    print(f"  F1 Score: {f1:.1%} - {rating}")
    
    if fpr > 0.1:
        print(f"  WARNING: High false positive rate ({fpr:.1%}) - may cause alert fatigue")
    if recall < 0.8:
        print(f"  WARNING: Low recall ({recall:.1%}) - missing too many threats")
    
    print("=" * 70)
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'fpr': fpr,
    }


if __name__ == '__main__':
    benchmark_model()
