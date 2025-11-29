"""
Comprehensive ML v2.0 Test Suite
Tests all components and integration.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime

def test_ml_system():
    print("=" * 60)
    print("  SentinelAI ML v2.0 - Comprehensive Test")
    print("=" * 60)
    print()

    # 1. Test ML Module Import
    print("[1/6] Testing ML module imports...")
    from ml import (
        AdvancedThreatDetector, 
        get_advanced_detector,
        ThreatPrediction,
        AdvancedFeatureExtractor,
        BehavioralSequenceAnalyzer,
        BaselineAnomalyDetector,
        EnsembleThreatModel,
        MITRE_TECHNIQUES
    )
    print("      All imports successful!")
    print(f"      MITRE techniques loaded: {len(MITRE_TECHNIQUES)}")
    print()

    # 2. Test Feature Extraction
    print("[2/6] Testing feature extraction...")
    extractor = AdvancedFeatureExtractor()
    test_event = {
        'name': 'powershell.exe',
        'exe': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        'cmdline': 'powershell.exe -enc SGVsbG8gV29ybGQ= -windowstyle hidden',
        'user': 'Admin',
        'parent_name': 'cmd.exe'
    }
    features = extractor.extract_all_features(test_event)
    print(f"      Features extracted: {len(features)}")
    print(f"      Feature names: {len(extractor.feature_names)}")
    assert len(features) == 150, f"Expected 150 features, got {len(features)}"
    print("      Feature extraction: PASS")
    print()

    # 3. Test Detector Initialization
    print("[3/6] Testing detector initialization...")
    detector = get_advanced_detector()
    stats = detector.get_stats()
    print(f"      Ensemble trained: {stats['ensemble_stats']['is_trained']}")
    print(f"      Models: {stats['ensemble_stats']['models_available']}")
    print()

    # 4. Test Predictions
    print("[4/6] Testing threat predictions...")
    
    test_cases = [
        {
            'name': 'Chrome (benign)',
            'event': {
                'name': 'chrome.exe',
                'exe': 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
                'cmdline': 'chrome.exe --type=renderer --lang=en-US',
                'user': 'User',
                'parent_name': 'explorer.exe'
            },
            'expected_threat': False
        },
        {
            'name': 'Mimikatz (credential theft)',
            'event': {
                'name': 'mimikatz.exe',
                'exe': 'C:\\Temp\\mimikatz.exe',
                'cmdline': 'mimikatz.exe sekurlsa::logonpasswords',
                'user': 'Admin',
                'parent_name': 'cmd.exe'
            },
            'expected_threat': True
        },
        {
            'name': 'Encoded PowerShell (obfuscation)',
            'event': {
                'name': 'powershell.exe',
                'exe': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                'cmdline': 'powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwA= -windowstyle hidden -nop',
                'user': 'User',
                'parent_name': 'mshta.exe'
            },
            'expected_threat': True
        },
        {
            'name': 'PsExec (lateral movement)',
            'event': {
                'name': 'psexec.exe',
                'exe': 'C:\\Temp\\psexec.exe',
                'cmdline': 'psexec.exe \\\\192.168.1.100 -u admin cmd.exe',
                'user': 'Admin',
                'parent_name': 'cmd.exe'
            },
            'expected_threat': True
        },
        {
            'name': 'VSS Delete (ransomware)',
            'event': {
                'name': 'vssadmin.exe',
                'exe': 'C:\\Windows\\System32\\vssadmin.exe',
                'cmdline': 'vssadmin.exe delete shadows /all /quiet',
                'user': 'SYSTEM',
                'parent_name': 'cmd.exe'
            },
            'expected_threat': True
        },
        {
            'name': 'Notepad (benign)',
            'event': {
                'name': 'notepad.exe',
                'exe': 'C:\\Windows\\System32\\notepad.exe',
                'cmdline': 'notepad.exe document.txt',
                'user': 'User',
                'parent_name': 'explorer.exe'
            },
            'expected_threat': False
        },
    ]
    
    passed = 0
    failed = 0
    
    for tc in test_cases:
        result = detector.analyze(tc['event'], 'process')
        status = "PASS" if result.is_threat == tc['expected_threat'] else "FAIL"
        if status == "PASS":
            passed += 1
        else:
            failed += 1
        
        print(f"      {tc['name']}: threat={result.is_threat}, conf={result.confidence:.2f}, sev={result.severity} [{status}]")
        if result.mitre_techniques:
            print(f"        MITRE: {result.mitre_techniques[:3]}")
    
    print(f"\n      Results: {passed}/{len(test_cases)} passed")
    print()

    # 5. Test Behavioral Analysis
    print("[5/6] Testing behavioral analysis...")
    from ml.behavioral_analyzer import BehavioralEvent
    
    # Simulate reconnaissance pattern
    analyzer = BehavioralSequenceAnalyzer()
    recon_commands = ['whoami', 'ipconfig /all', 'netstat -an', 'tasklist', 'systeminfo']
    
    for cmd in recon_commands:
        event = BehavioralEvent(
            timestamp=datetime.now(),
            event_type='process_discovery',
            process_name='cmd.exe',
            details={'cmdline': cmd},
            threat_score=0.3
        )
        analyzer.add_event(event)
    
    chains = analyzer.detect_attack_chains()
    print(f"      Events in buffer: {len(analyzer.event_buffer)}")
    print(f"      Attack chains detected: {len(chains)}")
    if chains:
        for chain in chains[:2]:
            print(f"        - {chain['pattern']}: confidence={chain['confidence']:.2f}, severity={chain['severity']}")
    print()

    # 6. Final Stats
    print("[6/6] Final statistics...")
    final_stats = detector.get_stats()
    print(f"      Total analyzed: {final_stats['total_analyzed']}")
    print(f"      Threats detected: {final_stats['threats_detected']}")
    print(f"      Attack chains: {final_stats['attack_chains_detected']}")
    print()

    print("=" * 60)
    if failed == 0:
        print("  ALL TESTS PASSED!")
    else:
        print(f"  {failed} TESTS FAILED - Review detection thresholds")
    print("=" * 60)
    
    return failed == 0


if __name__ == '__main__':
    success = test_ml_system()
    sys.exit(0 if success else 1)
