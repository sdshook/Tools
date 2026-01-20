#!/usr/bin/env python3
"""
WebGuard Comprehensive Multipass Testing Suite
Demonstrates adaptive self-learning through benign training followed by threat detection.
"""

import json
import os
import sys
import random
import math
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Tuple, Any

# Configuration
RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'results')
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')

class WebGuardSimulator:
    """Simulates WebGuard's cognitive learning behavior"""
    
    def __init__(self):
        self.memory_traces = []
        self.learned_patterns = defaultdict(float)
        self.benign_baseline = []
        self.threat_signatures = defaultdict(list)
        self.valence = 0.5  # Aggression level
        self.learning_rate = 0.1
        self.threshold = 0.6
        self.experience_count = 0
        self.eq_iq_balance = 0.5  # Balance between emotional and analytical
        
        # Metrics tracking
        self.true_positives = 0
        self.true_negatives = 0
        self.false_positives = 0
        self.false_negatives = 0
        
    def extract_features(self, request: str) -> List[float]:
        """Extract feature vector from request"""
        features = []
        
        # Length-based features
        features.append(min(len(request) / 500.0, 1.0))
        
        # Special character density
        special_chars = sum(1 for c in request if not c.isalnum() and c not in ' /')
        features.append(min(special_chars / 50.0, 1.0))
        
        # SQL injection indicators
        sql_keywords = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'exec', 'execute', '--', '/*', '*/', 'or 1=1', 'and 1=1']
        sql_score = sum(1 for kw in sql_keywords if kw.lower() in request.lower()) / len(sql_keywords)
        features.append(sql_score)
        
        # XSS indicators
        xss_patterns = ['<script', 'javascript:', 'onerror', 'onload', 'onclick', 'alert(', 'eval(', 'document.']
        xss_score = sum(1 for p in xss_patterns if p.lower() in request.lower()) / len(xss_patterns)
        features.append(xss_score)
        
        # Command injection indicators
        cmd_patterns = ['|', ';', '`', '$(' , '&&', '||', 'cat ', 'ls ', 'rm ', '/bin/', '/etc/']
        cmd_score = sum(1 for p in cmd_patterns if p in request) / len(cmd_patterns)
        features.append(cmd_score)
        
        # Path traversal indicators
        traversal_patterns = ['../', '..\\', '%2e%2e', '/etc/passwd', '/windows/', 'file://']
        traversal_score = sum(1 for p in traversal_patterns if p.lower() in request.lower()) / len(traversal_patterns)
        features.append(traversal_score)
        
        # LDAP injection indicators
        ldap_patterns = [')(', '*)(' , 'cn=', 'uid=', 'objectclass', '|(', '&(']
        ldap_score = sum(1 for p in ldap_patterns if p.lower() in request.lower()) / len(ldap_patterns)
        features.append(ldap_score)
        
        # Entropy calculation
        char_freq = defaultdict(int)
        for c in request:
            char_freq[c] += 1
        entropy = 0.0
        for freq in char_freq.values():
            p = freq / len(request) if request else 0
            if p > 0:
                entropy -= p * math.log2(p)
        features.append(min(entropy / 6.0, 1.0))
        
        # URL encoding density
        encoding_count = request.count('%')
        features.append(min(encoding_count / 20.0, 1.0))
        
        # Quote character density
        quote_count = request.count("'") + request.count('"')
        features.append(min(quote_count / 10.0, 1.0))
        
        # Numeric density in parameters
        numeric_count = sum(1 for c in request if c.isdigit())
        features.append(min(numeric_count / 50.0, 1.0))
        
        # Pad to 32 features
        while len(features) < 32:
            features.append(0.0)
            
        return features[:32]
    
    def cosine_similarity(self, v1: List[float], v2: List[float]) -> float:
        """Calculate cosine similarity between two vectors"""
        dot = sum(a * b for a, b in zip(v1, v2))
        norm1 = math.sqrt(sum(a * a for a in v1))
        norm2 = math.sqrt(sum(b * b for b in v2))
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return dot / (norm1 * norm2)
    
    def train_benign(self, request: str):
        """Train on benign sample - build baseline"""
        features = self.extract_features(request)
        self.benign_baseline.append(features)
        self.memory_traces.append({
            'features': features,
            'valence': 0.0,  # Benign = neutral valence
            'type': 'benign'
        })
        self.experience_count += 1
        
    def train_threat(self, request: str, attack_type: str):
        """Train on known threat - build threat signatures"""
        features = self.extract_features(request)
        self.threat_signatures[attack_type].append(features)
        self.memory_traces.append({
            'features': features,
            'valence': 1.0,  # Threat = high valence
            'type': attack_type
        })
        # Increase aggression when learning threats
        self.valence = min(1.0, self.valence + 0.05)
        self.experience_count += 1
        
    def detect(self, request: str) -> Tuple[bool, float, str]:
        """Detect if request is a threat"""
        features = self.extract_features(request)
        
        # Calculate similarity to benign baseline
        benign_similarity = 0.0
        if self.benign_baseline:
            similarities = [self.cosine_similarity(features, b) for b in self.benign_baseline[-100:]]
            benign_similarity = max(similarities) if similarities else 0.0
        
        # Calculate similarity to threat signatures
        threat_scores = {}
        for attack_type, signatures in self.threat_signatures.items():
            if signatures:
                sims = [self.cosine_similarity(features, s) for s in signatures[-20:]]
                threat_scores[attack_type] = max(sims) if sims else 0.0
        
        # Calculate anomaly score based on feature analysis
        anomaly_score = 0.0
        # SQL injection features
        anomaly_score += features[2] * 0.3
        # XSS features
        anomaly_score += features[3] * 0.25
        # Command injection
        anomaly_score += features[4] * 0.2
        # Path traversal
        anomaly_score += features[5] * 0.15
        # LDAP injection
        anomaly_score += features[6] * 0.1
        
        # Combine scores with learning adjustments
        max_threat_score = max(threat_scores.values()) if threat_scores else 0.0
        max_threat_type = max(threat_scores.keys(), key=lambda k: threat_scores[k]) if threat_scores else None
        
        # Final threat score combines pattern matching with cognitive analysis
        final_score = (
            anomaly_score * 0.4 +
            max_threat_score * 0.4 +
            (1.0 - benign_similarity) * 0.2
        ) * (1.0 + self.valence * 0.2)  # Valence modulates sensitivity
        
        # Apply EQ/IQ balance - more IQ = stricter threshold
        adjusted_threshold = self.threshold * (0.8 + self.eq_iq_balance * 0.4)
        
        is_threat = final_score > adjusted_threshold
        
        return is_threat, final_score, max_threat_type
    
    def provide_feedback(self, was_correct: bool, was_threat: bool):
        """Learn from feedback"""
        if was_correct:
            # Reinforce current behavior
            if was_threat:
                self.valence = min(1.0, self.valence + 0.02)
        else:
            # Adjust for mistakes
            if was_threat:
                # False negative - increase sensitivity
                self.threshold *= 0.98
                self.valence = min(1.0, self.valence + 0.05)
            else:
                # False positive - decrease sensitivity
                self.threshold *= 1.02
                self.valence = max(0.0, self.valence - 0.02)
                
    def get_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        total = self.true_positives + self.true_negatives + self.false_positives + self.false_negatives
        accuracy = (self.true_positives + self.true_negatives) / total if total > 0 else 0
        
        precision = self.true_positives / (self.true_positives + self.false_positives) if (self.true_positives + self.false_positives) > 0 else 0
        recall = self.true_positives / (self.true_positives + self.false_negatives) if (self.true_positives + self.false_negatives) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'true_positives': self.true_positives,
            'true_negatives': self.true_negatives,
            'false_positives': self.false_positives,
            'false_negatives': self.false_negatives,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'threshold': self.threshold,
            'valence': self.valence,
            'experience_count': self.experience_count
        }
    
    def reset_metrics(self):
        """Reset detection metrics for new pass"""
        self.true_positives = 0
        self.true_negatives = 0
        self.false_positives = 0
        self.false_negatives = 0


def run_comprehensive_test():
    """Run comprehensive multipass testing"""
    
    # Load test data
    with open(os.path.join(DATA_DIR, 'test_samples.json')) as f:
        all_samples = json.load(f)
    
    # Separate benign and threat samples
    benign_samples = [s for s in all_samples if not s['is_threat']]
    threat_samples = [s for s in all_samples if s['is_threat']]
    
    # Shuffle for randomness
    random.seed(42)  # Reproducibility
    random.shuffle(benign_samples)
    random.shuffle(threat_samples)
    
    # Initialize WebGuard simulator
    webguard = WebGuardSimulator()
    
    results = {
        'test_name': 'WebGuard Comprehensive Adaptive Learning Test',
        'timestamp': datetime.now().isoformat(),
        'data_summary': {
            'total_samples': len(all_samples),
            'benign_samples': len(benign_samples),
            'threat_samples': len(threat_samples)
        },
        'phases': [],
        'learning_progression': [],
        'attack_type_performance': defaultdict(lambda: {'tp': 0, 'fn': 0})
    }
    
    print("=" * 70)
    print("WebGuard Comprehensive Adaptive Learning Test")
    print("=" * 70)
    print(f"\nTotal samples: {len(all_samples)}")
    print(f"Benign samples: {len(benign_samples)}")
    print(f"Threat samples: {len(threat_samples)}")
    print()
    
    # Phase 1: Benign Training (first 500 benign samples)
    print("-" * 70)
    print("PHASE 1: Benign Baseline Training")
    print("-" * 70)
    
    training_benign = benign_samples[:500]
    for i, sample in enumerate(training_benign):
        webguard.train_benign(sample['request'])
        if (i + 1) % 100 == 0:
            print(f"  Trained on {i + 1} benign samples...")
            results['learning_progression'].append({
                'phase': 'benign_training',
                'samples_processed': i + 1,
                'memory_traces': len(webguard.memory_traces),
                'threshold': webguard.threshold,
                'valence': webguard.valence
            })
    
    results['phases'].append({
        'name': 'Benign Baseline Training',
        'samples': len(training_benign),
        'memory_traces_after': len(webguard.memory_traces)
    })
    print(f"  Completed: {len(training_benign)} benign samples processed")
    print(f"  Memory traces: {len(webguard.memory_traces)}")
    print()
    
    # Phase 2: Initial Detection (remaining benign + some threats)
    print("-" * 70)
    print("PHASE 2: Initial Detection Pass (No Prior Threat Learning)")
    print("-" * 70)
    
    test_benign = benign_samples[500:700]
    test_threats_p2 = threat_samples[:20]
    test_set_p2 = test_benign + test_threats_p2
    random.shuffle(test_set_p2)
    
    webguard.reset_metrics()
    phase2_details = []
    
    for sample in test_set_p2:
        is_threat_pred, score, detected_type = webguard.detect(sample['request'])
        is_threat_actual = sample['is_threat']
        
        if is_threat_actual and is_threat_pred:
            webguard.true_positives += 1
            results['attack_type_performance'][sample.get('attack_type', 'Unknown')]['tp'] += 1
        elif not is_threat_actual and not is_threat_pred:
            webguard.true_negatives += 1
        elif is_threat_actual and not is_threat_pred:
            webguard.false_negatives += 1
            results['attack_type_performance'][sample.get('attack_type', 'Unknown')]['fn'] += 1
        else:
            webguard.false_positives += 1
        
        # Provide feedback to learn
        was_correct = is_threat_pred == is_threat_actual
        webguard.provide_feedback(was_correct, is_threat_actual)
        
        phase2_details.append({
            'description': sample['description'],
            'is_threat': is_threat_actual,
            'predicted': is_threat_pred,
            'score': score,
            'correct': was_correct
        })
    
    metrics_p2 = webguard.get_metrics()
    results['phases'].append({
        'name': 'Initial Detection (Pre-Threat Learning)',
        'metrics': metrics_p2,
        'details': phase2_details[:10]  # Sample details
    })
    
    print(f"  Samples tested: {len(test_set_p2)} (Benign: {len(test_benign)}, Threats: {len(test_threats_p2)})")
    print(f"  True Positives: {metrics_p2['true_positives']}")
    print(f"  True Negatives: {metrics_p2['true_negatives']}")
    print(f"  False Positives: {metrics_p2['false_positives']}")
    print(f"  False Negatives: {metrics_p2['false_negatives']}")
    print(f"  Accuracy: {metrics_p2['accuracy']:.2%}")
    print(f"  Precision: {metrics_p2['precision']:.2%}")
    print(f"  Recall: {metrics_p2['recall']:.2%}")
    print(f"  F1 Score: {metrics_p2['f1_score']:.2%}")
    print()
    
    results['learning_progression'].append({
        'phase': 'initial_detection',
        'samples_processed': len(test_set_p2),
        'metrics': metrics_p2.copy(),
        'threshold': webguard.threshold,
        'valence': webguard.valence
    })
    
    # Phase 3: Threat Learning
    print("-" * 70)
    print("PHASE 3: Threat Pattern Learning")
    print("-" * 70)
    
    # Train on some threat samples
    training_threats = threat_samples[20:35]
    for sample in training_threats:
        webguard.train_threat(sample['request'], sample.get('attack_type', 'Unknown'))
    
    results['phases'].append({
        'name': 'Threat Pattern Learning',
        'samples': len(training_threats),
        'threat_types_learned': list(webguard.threat_signatures.keys())
    })
    
    print(f"  Trained on {len(training_threats)} threat samples")
    print(f"  Attack types learned: {list(webguard.threat_signatures.keys())}")
    print(f"  Valence (aggression) after training: {webguard.valence:.3f}")
    print()
    
    # Phase 4: Post-Learning Detection
    print("-" * 70)
    print("PHASE 4: Detection Pass (After Threat Learning)")
    print("-" * 70)
    
    test_benign_p4 = benign_samples[700:850]
    test_threats_p4 = threat_samples[35:]
    test_set_p4 = test_benign_p4 + test_threats_p4
    random.shuffle(test_set_p4)
    
    webguard.reset_metrics()
    phase4_details = []
    
    for sample in test_set_p4:
        is_threat_pred, score, detected_type = webguard.detect(sample['request'])
        is_threat_actual = sample['is_threat']
        
        if is_threat_actual and is_threat_pred:
            webguard.true_positives += 1
            results['attack_type_performance'][sample.get('attack_type', 'Unknown')]['tp'] += 1
        elif not is_threat_actual and not is_threat_pred:
            webguard.true_negatives += 1
        elif is_threat_actual and not is_threat_pred:
            webguard.false_negatives += 1
            results['attack_type_performance'][sample.get('attack_type', 'Unknown')]['fn'] += 1
        else:
            webguard.false_positives += 1
        
        was_correct = is_threat_pred == is_threat_actual
        webguard.provide_feedback(was_correct, is_threat_actual)
        
        phase4_details.append({
            'description': sample['description'],
            'attack_type': sample.get('attack_type'),
            'is_threat': is_threat_actual,
            'predicted': is_threat_pred,
            'score': score,
            'correct': was_correct
        })
    
    metrics_p4 = webguard.get_metrics()
    results['phases'].append({
        'name': 'Post-Learning Detection',
        'metrics': metrics_p4,
        'details': phase4_details[:10]
    })
    
    print(f"  Samples tested: {len(test_set_p4)} (Benign: {len(test_benign_p4)}, Threats: {len(test_threats_p4)})")
    print(f"  True Positives: {metrics_p4['true_positives']}")
    print(f"  True Negatives: {metrics_p4['true_negatives']}")
    print(f"  False Positives: {metrics_p4['false_positives']}")
    print(f"  False Negatives: {metrics_p4['false_negatives']}")
    print(f"  Accuracy: {metrics_p4['accuracy']:.2%}")
    print(f"  Precision: {metrics_p4['precision']:.2%}")
    print(f"  Recall: {metrics_p4['recall']:.2%}")
    print(f"  F1 Score: {metrics_p4['f1_score']:.2%}")
    print()
    
    results['learning_progression'].append({
        'phase': 'post_learning_detection',
        'samples_processed': len(test_set_p4),
        'metrics': metrics_p4.copy(),
        'threshold': webguard.threshold,
        'valence': webguard.valence
    })
    
    # Phase 5: Final Multipass Validation
    print("-" * 70)
    print("PHASE 5: Final Multipass Validation (3 Passes)")
    print("-" * 70)
    
    remaining_benign = benign_samples[850:]
    all_remaining = remaining_benign + threat_samples  # Include all threats for validation
    
    multipass_results = []
    
    for pass_num in range(1, 4):
        random.shuffle(all_remaining)
        webguard.reset_metrics()
        
        pass_details = []
        for sample in all_remaining:
            is_threat_pred, score, detected_type = webguard.detect(sample['request'])
            is_threat_actual = sample['is_threat']
            
            if is_threat_actual and is_threat_pred:
                webguard.true_positives += 1
            elif not is_threat_actual and not is_threat_pred:
                webguard.true_negatives += 1
            elif is_threat_actual and not is_threat_pred:
                webguard.false_negatives += 1
            else:
                webguard.false_positives += 1
            
            was_correct = is_threat_pred == is_threat_actual
            webguard.provide_feedback(was_correct, is_threat_actual)
        
        metrics = webguard.get_metrics()
        multipass_results.append(metrics)
        
        print(f"  Pass {pass_num}:")
        print(f"    TP: {metrics['true_positives']}, TN: {metrics['true_negatives']}, FP: {metrics['false_positives']}, FN: {metrics['false_negatives']}")
        print(f"    Accuracy: {metrics['accuracy']:.2%}, F1: {metrics['f1_score']:.2%}")
        print(f"    Threshold: {metrics['threshold']:.4f}, Valence: {metrics['valence']:.4f}")
        
        results['learning_progression'].append({
            'phase': f'multipass_validation_{pass_num}',
            'samples_processed': len(all_remaining),
            'metrics': metrics.copy(),
            'threshold': webguard.threshold,
            'valence': webguard.valence
        })
    
    results['phases'].append({
        'name': 'Final Multipass Validation',
        'passes': multipass_results
    })
    
    # Attack type breakdown
    print()
    print("-" * 70)
    print("ATTACK TYPE PERFORMANCE SUMMARY")
    print("-" * 70)
    
    attack_breakdown = {}
    for attack_type, perf in results['attack_type_performance'].items():
        if attack_type:
            total = perf['tp'] + perf['fn']
            detection_rate = perf['tp'] / total if total > 0 else 0
            attack_breakdown[attack_type] = {
                'detected': perf['tp'],
                'missed': perf['fn'],
                'total': total,
                'detection_rate': detection_rate
            }
            print(f"  {attack_type}:")
            print(f"    Detected: {perf['tp']}, Missed: {perf['fn']}, Detection Rate: {detection_rate:.2%}")
    
    results['attack_type_breakdown'] = attack_breakdown
    
    # Learning demonstration summary
    print()
    print("=" * 70)
    print("ADAPTIVE LEARNING DEMONSTRATION")
    print("=" * 70)
    
    if len(results['learning_progression']) >= 3:
        pre_learning = next((p for p in results['learning_progression'] if p['phase'] == 'initial_detection'), None)
        post_learning = next((p for p in results['learning_progression'] if p['phase'] == 'post_learning_detection'), None)
        
        if pre_learning and post_learning:
            print("\nComparison: Before vs After Threat Learning")
            print("-" * 50)
            
            pre_m = pre_learning['metrics']
            post_m = post_learning['metrics']
            
            print(f"  Metric          | Before    | After     | Change")
            print(f"  ----------------|-----------|-----------|--------")
            print(f"  Accuracy        | {pre_m['accuracy']:.2%}    | {post_m['accuracy']:.2%}    | {(post_m['accuracy']-pre_m['accuracy'])*100:+.1f}%")
            print(f"  Precision       | {pre_m['precision']:.2%}    | {post_m['precision']:.2%}    | {(post_m['precision']-pre_m['precision'])*100:+.1f}%")
            print(f"  Recall          | {pre_m['recall']:.2%}    | {post_m['recall']:.2%}    | {(post_m['recall']-pre_m['recall'])*100:+.1f}%")
            print(f"  F1 Score        | {pre_m['f1_score']:.2%}    | {post_m['f1_score']:.2%}    | {(post_m['f1_score']-pre_m['f1_score'])*100:+.1f}%")
            print(f"  False Negatives | {pre_m['false_negatives']}         | {post_m['false_negatives']}         | {post_m['false_negatives']-pre_m['false_negatives']:+d}")
            
            results['learning_demonstration'] = {
                'pre_learning': pre_m,
                'post_learning': post_m,
                'improvements': {
                    'accuracy_change': post_m['accuracy'] - pre_m['accuracy'],
                    'precision_change': post_m['precision'] - pre_m['precision'],
                    'recall_change': post_m['recall'] - pre_m['recall'],
                    'f1_change': post_m['f1_score'] - pre_m['f1_score'],
                    'fn_reduction': pre_m['false_negatives'] - post_m['false_negatives']
                }
            }
    
    # Save results
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    # Main results JSON
    results_file = os.path.join(RESULTS_DIR, 'comprehensive_test_results.json')
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to: {results_file}")
    
    # Learning progression CSV
    progression_file = os.path.join(RESULTS_DIR, 'learning_progression.csv')
    with open(progression_file, 'w') as f:
        f.write("phase,samples_processed,accuracy,precision,recall,f1_score,threshold,valence,tp,tn,fp,fn\n")
        for prog in results['learning_progression']:
            metrics = prog.get('metrics', {})
            f.write(f"{prog['phase']},{prog['samples_processed']},{metrics.get('accuracy', 0):.4f},{metrics.get('precision', 0):.4f},{metrics.get('recall', 0):.4f},{metrics.get('f1_score', 0):.4f},{prog['threshold']:.4f},{prog['valence']:.4f},{metrics.get('true_positives', 0)},{metrics.get('true_negatives', 0)},{metrics.get('false_positives', 0)},{metrics.get('false_negatives', 0)}\n")
    print(f"Learning progression saved to: {progression_file}")
    
    # Attack breakdown CSV
    attack_file = os.path.join(RESULTS_DIR, 'attack_type_breakdown.csv')
    with open(attack_file, 'w') as f:
        f.write("attack_type,detected,missed,total,detection_rate\n")
        for attack_type, stats in attack_breakdown.items():
            f.write(f"{attack_type},{stats['detected']},{stats['missed']},{stats['total']},{stats['detection_rate']:.4f}\n")
    print(f"Attack breakdown saved to: {attack_file}")
    
    # Multipass results CSV
    multipass_file = os.path.join(RESULTS_DIR, 'multipass_results.csv')
    with open(multipass_file, 'w') as f:
        f.write("pass,accuracy,precision,recall,f1_score,tp,tn,fp,fn,threshold,valence\n")
        for i, m in enumerate(multipass_results, 1):
            f.write(f"{i},{m['accuracy']:.4f},{m['precision']:.4f},{m['recall']:.4f},{m['f1_score']:.4f},{m['true_positives']},{m['true_negatives']},{m['false_positives']},{m['false_negatives']},{m['threshold']:.4f},{m['valence']:.4f}\n")
    print(f"Multipass results saved to: {multipass_file}")
    
    print("\n" + "=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)
    
    return results


if __name__ == '__main__':
    results = run_comprehensive_test()
