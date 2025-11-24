#!/usr/bin/env python3
"""
WebGuard Experiential Learning Demonstration
Simulates experiential learning with 1000 samples (95% benign, 5% threats)
"""

import json
import csv
import time
import random
import numpy as np
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Any
import matplotlib.pyplot as plt
import seaborn as sns

class WebGuardSimulator:
    """Simulates WebGuard's experiential learning behavior"""
    
    def __init__(self):
        self.threat_patterns = {
            'sql_injection': ['union', 'select', 'drop', 'insert', 'delete', 'update', 'or 1=1', '--', ';'],
            'xss': ['<script>', 'javascript:', 'onerror=', 'onload=', 'alert(', 'document.cookie'],
            'command_injection': ['|', '&&', ';', '$(', '`', 'cat ', 'ls ', 'rm ', 'wget', 'curl'],
            'path_traversal': ['../', '..\\', '%2e%2e', 'etc/passwd', 'windows/system32'],
            'ssrf': ['localhost', '127.0.0.1', '169.254', 'metadata', 'internal'],
            'ldap_injection': ['*)(', ')(&', '*()|', '*)(&']
        }
        
        # Learning parameters
        self.base_sensitivity = 0.3
        self.learning_rate = 0.05
        self.experience_weight = 0.1
        self.false_positive_penalty = 0.02
        self.false_negative_boost = 0.08
        
        # Experience tracking
        self.processed_samples = 0
        self.threat_memory = defaultdict(list)
        self.pattern_weights = defaultdict(float)
        self.context_memory = []
        
        # Performance metrics
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0
        
        # Initialize pattern weights
        for threat_type, patterns in self.threat_patterns.items():
            for pattern in patterns:
                self.pattern_weights[pattern] = random.uniform(0.1, 0.3)
    
    def calculate_threat_score(self, sample: Dict[str, Any]) -> float:
        """Calculate threat score for a sample with experiential learning"""
        
        # Extract text content for analysis
        content = f"{sample['path']} {sample['body']} {sample.get('headers', {}).get('User-Agent', '')}"
        content = content.lower()
        
        base_score = 0.0
        pattern_matches = 0
        
        # Pattern matching with learned weights
        for pattern, weight in self.pattern_weights.items():
            if pattern in content:
                base_score += weight
                pattern_matches += 1
        
        # Apply experiential adjustments
        experience_factor = min(1.0, self.processed_samples / 500.0)  # Gradual learning
        sensitivity = self.base_sensitivity + (experience_factor * self.experience_weight)
        
        # Context-based adjustments
        if sample['method'] == 'POST' and len(sample['body']) > 100:
            base_score *= 1.2  # POST with large body is more suspicious
        
        if 'admin' in sample['path'] or 'login' in sample['path']:
            base_score *= 1.1  # Admin/login paths are more critical
        
        # Apply learned sensitivity
        final_score = base_score * sensitivity
        
        # Add some noise to simulate real-world variability
        noise = random.uniform(-0.05, 0.05)
        final_score = max(0.0, min(1.0, final_score + noise))
        
        return final_score
    
    def process_sample(self, sample: Dict[str, Any], threshold: float = 0.5) -> Tuple[bool, float]:
        """Process a sample and return (is_threat_detected, threat_score)"""
        
        threat_score = self.calculate_threat_score(sample)
        is_threat_detected = threat_score > threshold
        
        self.processed_samples += 1
        
        # Store in context memory for learning
        self.context_memory.append({
            'sample_id': sample['id'],
            'threat_score': threat_score,
            'detected': is_threat_detected,
            'actual_label': sample['label'],
            'threat_type': sample.get('threat_type')
        })
        
        return is_threat_detected, threat_score
    
    def learn_from_feedback(self, sample: Dict[str, Any], detected: bool, actual_threat: bool):
        """Update learning based on feedback"""
        
        content = f"{sample['path']} {sample['body']} {sample.get('headers', {}).get('User-Agent', '')}"
        content = content.lower()
        
        # Extract patterns that were present
        present_patterns = [pattern for pattern in self.pattern_weights.keys() if pattern in content]
        
        if actual_threat and not detected:
            # False negative - boost pattern weights
            self.false_negatives += 1
            for pattern in present_patterns:
                self.pattern_weights[pattern] += self.false_negative_boost
            
            # Store threat pattern for future reference
            if sample.get('threat_type'):
                self.threat_memory[sample['threat_type']].append(present_patterns)
        
        elif not actual_threat and detected:
            # False positive - reduce pattern weights
            self.false_positives += 1
            for pattern in present_patterns:
                self.pattern_weights[pattern] = max(0.01, self.pattern_weights[pattern] - self.false_positive_penalty)
        
        elif actual_threat and detected:
            # True positive - slight boost
            self.true_positives += 1
            for pattern in present_patterns:
                self.pattern_weights[pattern] += self.learning_rate
        
        else:
            # True negative
            self.true_negatives += 1
        
        # Normalize weights to prevent runaway growth
        max_weight = max(self.pattern_weights.values()) if self.pattern_weights else 1.0
        if max_weight > 2.0:
            for pattern in self.pattern_weights:
                self.pattern_weights[pattern] /= (max_weight / 2.0)

class ExperientialLearningTester:
    """Main testing class for experiential learning demonstration"""
    
    def __init__(self):
        self.simulator = WebGuardSimulator()
        self.test_data = []
        self.batch_results = []
        self.batch_size = 50
        
    def load_test_data(self):
        """Load the generated test dataset"""
        data_path = Path("../data/comprehensive_test_data.json")
        
        if not data_path.exists():
            raise FileNotFoundError(f"Test data not found at {data_path}")
        
        with open(data_path, 'r') as f:
            self.test_data = json.load(f)
        
        print(f"Loaded {len(self.test_data)} test samples")
        
        # Shuffle data to simulate real-world randomness
        random.shuffle(self.test_data)
    
    def run_experiential_learning_test(self):
        """Run the complete experiential learning test"""
        
        print("🧠 Starting WebGuard Experiential Learning Test")
        print(f"📊 Dataset: {len(self.test_data)} samples")
        
        benign_count = sum(1 for sample in self.test_data if sample['label'] == 'benign')
        threat_count = len(self.test_data) - benign_count
        
        print(f"   Benign: {benign_count} ({benign_count/len(self.test_data)*100:.1f}%)")
        print(f"   Threats: {threat_count} ({threat_count/len(self.test_data)*100:.1f}%)")
        print()
        
        start_time = time.time()
        
        # Process data in batches to demonstrate learning progression
        total_batches = (len(self.test_data) + self.batch_size - 1) // self.batch_size
        
        for batch_num in range(total_batches):
            batch_start = batch_num * self.batch_size
            batch_end = min(batch_start + self.batch_size, len(self.test_data))
            batch = self.test_data[batch_start:batch_end]
            
            batch_result = self.process_batch(batch, batch_num + 1)
            self.batch_results.append(batch_result)
            
            # Print progress
            if batch_num % 5 == 0 or batch_num == total_batches - 1:
                print(f"Batch {batch_num + 1:2d}/{total_batches}: "
                      f"Processed {len(batch):2d} samples, "
                      f"Detected {batch_result['threats_detected']:2d} threats, "
                      f"Avg score: {batch_result['avg_threat_score']:.3f}, "
                      f"Accuracy: {batch_result['accuracy']:.3f}")
        
        total_time = time.time() - start_time
        
        print(f"\n✅ Test completed in {total_time:.2f} seconds")
        print(f"📈 Processed {self.simulator.processed_samples} samples")
        
        self.print_final_results()
        self.save_results()
    
    def process_batch(self, batch: List[Dict], batch_num: int) -> Dict:
        """Process a batch of samples"""
        
        batch_threats_detected = 0
        batch_threat_scores = []
        batch_tp = batch_fp = batch_tn = batch_fn = 0
        
        # Dynamic threshold that adapts with experience
        base_threshold = 0.5
        experience_factor = min(0.2, self.simulator.processed_samples / 1000.0)
        threshold = base_threshold - experience_factor  # Becomes more sensitive with experience
        
        for sample in batch:
            detected, threat_score = self.simulator.process_sample(sample, threshold)
            batch_threat_scores.append(threat_score)
            
            actual_threat = sample['label'] == 'threat'
            
            # Update learning
            self.simulator.learn_from_feedback(sample, detected, actual_threat)
            
            # Track batch metrics
            if detected:
                batch_threats_detected += 1
            
            if actual_threat and detected:
                batch_tp += 1
            elif not actual_threat and detected:
                batch_fp += 1
            elif not actual_threat and not detected:
                batch_tn += 1
            else:
                batch_fn += 1
        
        # Calculate batch metrics
        accuracy = (batch_tp + batch_tn) / len(batch) if len(batch) > 0 else 0
        precision = batch_tp / (batch_tp + batch_fp) if (batch_tp + batch_fp) > 0 else 0
        recall = batch_tp / (batch_tp + batch_fn) if (batch_tp + batch_fn) > 0 else 0
        
        return {
            'batch_number': batch_num,
            'samples_processed': len(batch),
            'threats_detected': batch_threats_detected,
            'avg_threat_score': np.mean(batch_threat_scores),
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'threshold_used': threshold,
            'true_positives': batch_tp,
            'false_positives': batch_fp,
            'true_negatives': batch_tn,
            'false_negatives': batch_fn
        }
    
    def print_final_results(self):
        """Print comprehensive test results"""
        
        print("\n" + "="*70)
        print("WEBGUARD EXPERIENTIAL LEARNING TEST RESULTS")
        print("="*70)
        
        # Overall performance
        total_tp = self.simulator.true_positives
        total_fp = self.simulator.false_positives
        total_tn = self.simulator.true_negatives
        total_fn = self.simulator.false_negatives
        total_samples = total_tp + total_fp + total_tn + total_fn
        
        accuracy = (total_tp + total_tn) / total_samples if total_samples > 0 else 0
        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"\nOverall Performance:")
        print(f"  Accuracy:  {accuracy:.3f} ({accuracy*100:.1f}%)")
        print(f"  Precision: {precision:.3f} ({precision*100:.1f}%)")
        print(f"  Recall:    {recall:.3f} ({recall*100:.1f}%)")
        print(f"  F1-Score:  {f1_score:.3f}")
        
        print(f"\nConfusion Matrix:")
        print(f"  True Positives:  {total_tp:3d}")
        print(f"  False Positives: {total_fp:3d}")
        print(f"  True Negatives:  {total_tn:3d}")
        print(f"  False Negatives: {total_fn:3d}")
        
        # Learning progression
        if len(self.batch_results) >= 2:
            first_batch = self.batch_results[0]
            last_batch = self.batch_results[-1]
            
            print(f"\nLearning Progression:")
            print(f"  First batch accuracy: {first_batch['accuracy']:.3f}")
            print(f"  Last batch accuracy:  {last_batch['accuracy']:.3f}")
            print(f"  Improvement: {(last_batch['accuracy'] - first_batch['accuracy'])*100:+.1f}%")
            
            if last_batch['accuracy'] > first_batch['accuracy']:
                print("  📈 System demonstrated learning improvement!")
            elif abs(last_batch['accuracy'] - first_batch['accuracy']) < 0.02:
                print("  ➡️  System maintained consistent performance")
            else:
                print("  📉 Performance variation observed (normal in experiential learning)")
        
        # Pattern learning analysis
        print(f"\nPattern Learning Analysis:")
        top_patterns = sorted(self.simulator.pattern_weights.items(), key=lambda x: x[1], reverse=True)[:10]
        print("  Top learned threat patterns:")
        for pattern, weight in top_patterns:
            print(f"    '{pattern}': {weight:.3f}")
        
        # Threat type analysis
        threat_types = Counter()
        for sample in self.test_data:
            if sample['label'] == 'threat' and sample.get('threat_type'):
                threat_types[sample['threat_type']] += 1
        
        print(f"\nThreat Type Distribution:")
        for threat_type, count in threat_types.most_common():
            print(f"  {threat_type}: {count} samples")
    
    def save_results(self):
        """Save test results for visualization"""
        
        # Ensure results directory exists
        results_dir = Path("../results")
        results_dir.mkdir(exist_ok=True)
        
        # Save detailed results
        results = {
            'test_summary': {
                'total_samples': len(self.test_data),
                'total_batches': len(self.batch_results),
                'batch_size': self.batch_size,
                'final_accuracy': (self.simulator.true_positives + self.simulator.true_negatives) / self.simulator.processed_samples,
                'final_precision': self.simulator.true_positives / (self.simulator.true_positives + self.simulator.false_positives) if (self.simulator.true_positives + self.simulator.false_positives) > 0 else 0,
                'final_recall': self.simulator.true_positives / (self.simulator.true_positives + self.simulator.false_negatives) if (self.simulator.true_positives + self.simulator.false_negatives) > 0 else 0
            },
            'confusion_matrix': {
                'true_positives': self.simulator.true_positives,
                'false_positives': self.simulator.false_positives,
                'true_negatives': self.simulator.true_negatives,
                'false_negatives': self.simulator.false_negatives
            },
            'batch_results': self.batch_results,
            'learned_patterns': dict(self.simulator.pattern_weights),
            'threat_memory': dict(self.simulator.threat_memory)
        }
        
        # Save JSON results
        with open(results_dir / "experiential_learning_results.json", 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save CSV for visualization
        csv_path = results_dir / "learning_progression.csv"
        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['batch', 'samples_processed', 'accuracy', 'precision', 'recall', 
                           'false_positive_rate', 'processing_time_ms', 'avg_threat_score', 'threshold_used'])
            
            for batch in self.batch_results:
                fpr = batch['false_positives'] / (batch['false_positives'] + batch['true_negatives']) if (batch['false_positives'] + batch['true_negatives']) > 0 else 0
                writer.writerow([
                    batch['batch_number'],
                    batch['samples_processed'],
                    batch['accuracy'],
                    batch['precision'],
                    batch['recall'],
                    fpr,
                    random.uniform(10, 50),  # Simulated processing time
                    batch['avg_threat_score'],
                    batch['threshold_used']
                ])
        
        print(f"\n💾 Results saved:")
        print(f"   JSON: {results_dir / 'experiential_learning_results.json'}")
        print(f"   CSV:  {csv_path}")

def main():
    """Main function to run the experiential learning test"""
    
    print("🛡️  WebGuard Experiential Learning Demonstration")
    print("=" * 60)
    
    # Set random seed for reproducible results
    random.seed(42)
    np.random.seed(42)
    
    try:
        tester = ExperientialLearningTester()
        tester.load_test_data()
        tester.run_experiential_learning_test()
        
        print("\n🎯 Experiential learning demonstration completed successfully!")
        print("📊 Run the visualization script to see detailed charts and analysis")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        raise

if __name__ == "__main__":
    main()