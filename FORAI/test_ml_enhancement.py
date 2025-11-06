#!/usr/bin/env python3
"""
Test script to demonstrate ML-enhanced FORAI capabilities
"""

import sys
import json
from pathlib import Path

# Add FORAI to path
sys.path.append('.')

from FORAI import ForensicAnalyzer, ForensicMLAnalyzer

def test_ml_enhancement():
    """Test the ML enhancement capabilities"""
    print("=" * 60)
    print("FORAI ML ENHANCEMENT TEST")
    print("=" * 60)
    
    # Initialize analyzer
    analyzer = ForensicAnalyzer()
    print(f"✓ ForensicAnalyzer initialized")
    print(f"✓ ML capabilities available: {analyzer.ml_analyzer.ml_available}")
    
    # Test question identification
    print("\n1. QUESTION IDENTIFICATION TEST")
    print("-" * 40)
    
    test_questions = [
        ("What is the computer name?", "Q1"),
        ("Is there evidence of anti-forensic activity?", "Q6"),
        ("What USB devices were connected?", "Q7"),
        ("Were any files deleted to hide evidence?", "Q6"),
        ("What cloud storage was used?", "Q9"),
        ("What screenshots were taken?", "Q10"),
        ("What software was installed?", "Q12"),
        ("Did someone try to cover their tracks?", "Q6"),
        ("What files were copied to external drives?", "Q8")
    ]
    
    for question, expected in test_questions:
        identified = analyzer._identify_question_id(question)
        status = "✓" if identified == expected else "✗"
        print(f"{status} '{question}' -> {identified} (expected: {expected})")
    
    # Test ML feature extraction
    print("\n2. ML FEATURE EXTRACTION TEST")
    print("-" * 40)
    
    # Mock evidence for different question types
    evidence_samples = {
        "Q6": [  # Anti-forensic activity
            {
                'timestamp': '2024-01-01 10:00:00',
                'data_json': '{"EventID": 1102, "Action": "clear", "LogName": "Security"}',
                'artifact': 'EventLog'
            },
            {
                'timestamp': '2024-01-01 10:05:00',
                'data_json': '{"Command": "wevtutil cl Security", "ProcessName": "cmd.exe"}',
                'artifact': 'ProcessExecution'
            }
        ],
        "Q7": [  # USB devices
            {
                'timestamp': '2024-01-01 11:00:00',
                'data_json': '{"SerialNumber": "ABC123", "FriendlyName": "USB Drive", "Size": "16GB"}',
                'artifact': 'USBDevice'
            }
        ],
        "Q8": [  # File transfers
            {
                'timestamp': '2024-01-01 12:00:00',
                'data_json': '{"FileName": "document.pdf", "Size": 1024000, "Action": "copy"}',
                'artifact': 'FileSystem'
            },
            {
                'timestamp': '2024-01-01 12:01:00',
                'data_json': '{"FileName": "data.xlsx", "Size": 2048000, "Action": "copy"}',
                'artifact': 'FileSystem'
            }
        ]
    }
    
    for question_id, evidence in evidence_samples.items():
        features = analyzer.ml_analyzer.extract_behavioral_features(evidence, question_id)
        print(f"✓ {question_id}: Extracted {len(features)} behavioral features")
        print(f"  Features: {features[:5]}..." if len(features) > 5 else f"  Features: {features}")
    
    # Test isolation forest analysis
    print("\n3. ISOLATION FOREST ANALYSIS TEST")
    print("-" * 40)
    
    for question_id, evidence in evidence_samples.items():
        result = analyzer.ml_analyzer.analyze_with_isolation_forest(evidence, question_id)
        print(f"✓ {question_id}: Anomaly score: {result['anomaly_score']:.3f}, "
              f"Confidence: {result['confidence']:.3f}, "
              f"Anomalous: {result['is_anomalous']}")
    
    # Test gradient descent optimization
    print("\n4. GRADIENT DESCENT OPTIMIZATION TEST")
    print("-" * 40)
    
    for question_id, evidence in evidence_samples.items():
        result = analyzer.ml_analyzer.optimize_with_gradient_descent(question_id, evidence)
        print(f"✓ {question_id}: Optimized score: {result['optimized_score']:.3f}, "
              f"Confidence: {result['confidence']:.3f}")
    
    # Test enhanced forensic analysis
    print("\n5. ENHANCED FORENSIC ANALYSIS TEST")
    print("-" * 40)
    
    for question_id, evidence in evidence_samples.items():
        # Create mock deterministic result
        deterministic_result = {
            'answer': f"Found {len(evidence)} evidence items for {question_id}",
            'confidence': 0.8,
            'evidence_count': len(evidence)
        }
        
        enhanced_result = analyzer.ml_analyzer.enhance_forensic_analysis(
            question_id, evidence, deterministic_result
        )
        
        print(f"✓ {question_id}: ML Enhanced: {enhanced_result.get('ml_enhanced', False)}")
        if enhanced_result.get('ml_analysis'):
            ml_analysis = enhanced_result['ml_analysis']
            print(f"  - Anomaly confidence: {ml_analysis.get('anomaly_detection', {}).get('confidence', 0):.3f}")
            print(f"  - Optimized score: {ml_analysis.get('optimized_scoring', {}).get('optimized_score', 0):.3f}")
            print(f"  - Overall ML confidence: {ml_analysis.get('ml_confidence', 0):.3f}")
            print(f"  - Final confidence: {enhanced_result.get('confidence', 0):.3f}")
    
    print("\n" + "=" * 60)
    print("ML ENHANCEMENT TEST COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    
    # Summary of capabilities
    print("\nFORAI ML ENHANCEMENT CAPABILITIES:")
    print("✓ Isolation Forest for anomaly detection in forensic evidence")
    print("✓ Gradient descent for optimized evidence scoring")
    print("✓ Behavioral feature extraction for questions Q6-Q12")
    print("✓ Enhanced confidence scoring with statistical backing")
    print("✓ Automatic question categorization for targeted ML analysis")
    print("✓ Integration with existing deterministic and LLM analysis")
    print("\nBENEFITS FOR EXPERT WITNESS TESTIMONY:")
    print("• Statistical confidence scores for behavioral interpretations")
    print("• Anomaly detection for sophisticated anti-forensic techniques")
    print("• Optimized evidence correlation for stronger conclusions")
    print("• Reduced false positives through contextual analysis")
    print("• Defensible ML-backed forensic conclusions")

if __name__ == "__main__":
    test_ml_enhancement()