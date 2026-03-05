#!/usr/bin/env python3
"""
BHSM Comprehensive Test Suite
=============================

Demonstrates experiential learning and regulation mechanisms:
1. Multi-pass learning progression
2. One-shot classification
3. EQ/IQ regulation dynamics
4. Memory consolidation and retrieval
5. Confidence calibration

Generates a 5-panel dashboard and saves results to test/ folder.

Usage:
    python test.py                  # Run full test suite
    python test.py --quick          # Quick test (fewer iterations)
    python test.py --verbose        # Verbose output

(c) 2025 - Shane D. Shook, PhD, All Rights Reserved
"""

import os
import sys
import json
import time
import argparse
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
from typing import Dict, List, Tuple, Any

# Import BHSM components
from BHSM import (
    BHSMClassifier, BDHMemory, PSIIndex, TextFeatureExtractor,
    ConfidenceCalibrator, ValenceController, Action, ActionThresholds,
    get_shared_psi, EMBED_DIM, ETA, ETA_MIN
)
from eq_iq_regulator import ExperientialBehavioralRegulator, ContextEvent, FeedbackEvent


class BHSMTestSuite:
    """Comprehensive test suite for BHSM experiential learning."""
    
    def __init__(self, output_dir: str = "test", verbose: bool = False):
        self.output_dir = output_dir
        self.verbose = verbose
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Load test data
        self.test_data = self._load_test_data()
        
        # Results storage
        self.results = {
            "multipass": {},
            "oneshot": {},
            "regulation": {},
            "memory": {},
            "summary": {}
        }
        
    def _load_test_data(self) -> Dict:
        """Load test data from JSON file."""
        test_data_path = os.path.join(os.path.dirname(__file__), "test_data.json")
        with open(test_data_path, 'r') as f:
            return json.load(f)
    
    def _log(self, message: str, level: str = "INFO"):
        """Log message if verbose mode is enabled."""
        if self.verbose:
            print(f"[{level}] {message}")
    
    def run_multipass_learning_test(self, n_passes: int = 3, samples_per_pass: int = 15) -> Dict:
        """
        Test learning progression over multiple passes.
        
        Demonstrates how accuracy improves with repeated exposure to patterns.
        The classifier persists across passes, accumulating learned memories.
        """
        print("\n" + "="*60)
        print("MULTI-PASS LEARNING TEST")
        print("="*60)
        
        # Initialize fresh classifier - PERSISTS across all passes
        classifier = BHSMClassifier(name="multipass_test")
        
        # Get all patterns
        threat_patterns = self.test_data["scenarios"]["threat_patterns"].copy()
        benign_patterns = self.test_data["scenarios"]["benign_patterns"].copy()
        
        # Track metrics across passes
        pass_results = []
        accuracy_history = []
        confidence_history = []
        eq_iq_history = []
        memory_size_history = []
        
        for pass_num in range(n_passes):
            print(f"\n--- Pass {pass_num + 1}/{n_passes} ---")
            
            # Build balanced sample set for this pass
            # Take equal number of threats and benign for balance
            n_per_class = samples_per_pass // 2
            np.random.shuffle(threat_patterns)
            np.random.shuffle(benign_patterns)
            
            samples = (
                threat_patterns[:n_per_class] + 
                benign_patterns[:n_per_class]
            )
            np.random.shuffle(samples)  # Mix them up
            
            pass_correct = 0
            pass_confidences = []
            pass_eq_iq = []
            
            for i, sample in enumerate(samples):
                # FIRST: Learn from the sample (train on it)
                # This ensures the classifier builds memory BEFORE being evaluated
                true_label = sample["label"]
                
                # For training, we tell the classifier the correct label
                # Extract features and add to memory
                features = classifier.feature_extractor.extract(sample["input"])
                
                # Create content-based trace ID
                import hashlib
                content_hash = hashlib.md5(sample["input"].encode()).hexdigest()[:12]
                trace_id = f"{true_label}_{content_hash}"
                
                # Set valence based on true label
                valence = 0.9 if true_label == "threat" else -0.9
                
                # Add directly to BDH and PSI
                classifier.bdh.add_or_update(trace_id, features, valence=valence, label=true_label)
                classifier.psi.add_doc(
                    trace_id,
                    sample["input"][:200],
                    features,
                    tags=[true_label, "training"],
                    valence=valence
                )
                
                # NOW: Classify to evaluate (this tests if learning worked)
                verdict = classifier.classify(sample["input"], return_details=True)
                
                # Determine if correct using threat_score threshold
                # threat_score > 0.5 means predicted threat
                predicted_is_threat = verdict.threat_score > 0.5
                true_is_threat = true_label == "threat"
                is_correct = (true_is_threat == predicted_is_threat)
                
                if is_correct:
                    pass_correct += 1
                
                # Provide feedback for reinforcement learning
                classifier.learn_from_feedback(
                    sample["input"],
                    was_correct=is_correct,
                    true_label=true_label
                )
                
                pass_confidences.append(verdict.confidence)
                
                # Track EQ/IQ
                eq_iq_stats = classifier.bdh.get_eq_iq_stats()
                pass_eq_iq.append({
                    "alpha": eq_iq_stats.get("alpha", 0.6),
                    "beta": eq_iq_stats.get("beta", 0.4)
                })
                
                self._log(f"Sample {i+1}: {sample['id']} -> score={verdict.threat_score:.3f} "
                         f"(correct={is_correct}, conf={verdict.confidence:.3f})")
            
            # Calculate pass metrics
            pass_accuracy = pass_correct / len(samples) if samples else 0
            avg_confidence = np.mean(pass_confidences) if pass_confidences else 0
            memory_size = len(classifier.bdh.storage)
            
            accuracy_history.append(pass_accuracy)
            confidence_history.append(avg_confidence)
            memory_size_history.append(memory_size)
            eq_iq_history.append({
                "alpha": np.mean([e["alpha"] for e in pass_eq_iq]) if pass_eq_iq else 0.6,
                "beta": np.mean([e["beta"] for e in pass_eq_iq]) if pass_eq_iq else 0.4
            })
            
            pass_results.append({
                "pass": pass_num + 1,
                "accuracy": pass_accuracy,
                "avg_confidence": avg_confidence,
                "samples_processed": len(samples),
                "correct": pass_correct,
                "memory_size": memory_size
            })
            
            print(f"Pass {pass_num + 1} Accuracy: {pass_accuracy:.1%} "
                  f"(Confidence: {avg_confidence:.3f}, Memory: {memory_size})")
        
        # Calculate improvement
        if len(accuracy_history) > 1:
            improvement = accuracy_history[-1] - accuracy_history[0]
        else:
            improvement = 0.0
        
        results = {
            "passes": pass_results,
            "accuracy_history": accuracy_history,
            "confidence_history": confidence_history,
            "memory_size_history": memory_size_history,
            "eq_iq_history": eq_iq_history,
            "improvement": improvement,
            "final_accuracy": accuracy_history[-1],
            "classifier_stats": classifier.get_stats()
        }
        
        self.results["multipass"] = results
        
        print(f"\nLearning Improvement: {improvement:+.1%}")
        print(f"Final Accuracy: {accuracy_history[-1]:.1%}")
        print(f"Final Memory Size: {memory_size_history[-1]}")
        
        return results
    
    def run_oneshot_test(self) -> Dict:
        """
        Test one-shot classification without prior learning.
        
        Demonstrates baseline statistical classification.
        """
        print("\n" + "="*60)
        print("ONE-SHOT CLASSIFICATION TEST")
        print("="*60)
        
        # Fresh classifier with no prior learning
        classifier = BHSMClassifier(name="oneshot_test")
        
        oneshot_results = []
        
        # Test predefined oneshot scenarios
        for test in self.test_data["oneshot_tests"]:
            verdict = classifier.classify(test["input"], return_details=True)
            
            result = {
                "name": test["name"],
                "input": test["input"][:50] + "..." if len(test["input"]) > 50 else test["input"],
                "expected": test["expected_action"],
                "predicted": verdict.action.name,
                "correct": verdict.action.name == test["expected_action"],
                "threat_score": verdict.threat_score,
                "confidence": verdict.confidence,
                "metadata": verdict.metadata
            }
            oneshot_results.append(result)
            
            print(f"\n{test['name']}:")
            print(f"  Input: {result['input']}")
            print(f"  Expected: {test['expected_action']} | Got: {verdict.action.name}")
            print(f"  Score: {verdict.threat_score:.3f} | Confidence: {verdict.confidence:.3f}")
            print(f"  Correct: {'✓' if result['correct'] else '✗'}")
        
        # Also test some samples from each category
        print("\n--- Statistical Baseline Tests ---")
        
        categories = ["threat_patterns", "benign_patterns", "ambiguous_patterns"]
        category_results = {}
        
        for category in categories:
            samples = self.test_data["scenarios"].get(category, [])[:3]
            cat_results = []
            
            for sample in samples:
                verdict = classifier.classify(sample["input"], return_details=True)
                cat_results.append({
                    "id": sample["id"],
                    "action": verdict.action.name,
                    "score": verdict.threat_score,
                    "confidence": verdict.confidence
                })
                
                self._log(f"{category}/{sample['id']}: {verdict.action.name} "
                         f"(score={verdict.threat_score:.3f})")
            
            category_results[category] = cat_results
            avg_score = np.mean([r["score"] for r in cat_results])
            print(f"  {category}: avg_score={avg_score:.3f}")
        
        results = {
            "oneshot_tests": oneshot_results,
            "category_results": category_results,
            "baseline_stats": classifier.get_stats()
        }
        
        self.results["oneshot"] = results
        return results
    
    def run_regulation_test(self, n_iterations: int = 50) -> Dict:
        """
        Test EQ/IQ regulation dynamics.
        
        Demonstrates adaptive parameter adjustment based on performance.
        """
        print("\n" + "="*60)
        print("EQ/IQ REGULATION TEST")
        print("="*60)
        
        # Initialize regulator
        regulator = ExperientialBehavioralRegulator(alpha=0.6, beta=0.4, learning_rate=0.01)
        
        # Track regulation history
        alpha_history = [regulator.alpha]
        beta_history = [regulator.beta]
        eq_history = []
        iq_history = []
        balance_history = []
        performance_history = []
        
        # Simulate varying performance scenarios
        np.random.seed(42)
        
        for i in range(n_iterations):
            # Simulate context (varying stability)
            if i < n_iterations // 3:
                # Low stability phase
                stability = 0.3 + np.random.random() * 0.2
                accuracy = 0.4 + np.random.random() * 0.2
            elif i < 2 * n_iterations // 3:
                # Improving phase
                stability = 0.5 + np.random.random() * 0.3
                accuracy = 0.6 + np.random.random() * 0.2
            else:
                # High performance phase
                stability = 0.7 + np.random.random() * 0.2
                accuracy = 0.8 + np.random.random() * 0.15
            
            # Create events
            context = ContextEvent(
                timestamp=time.time(),
                context_stability=stability,
                threat_level=1.0 - accuracy,
                response_appropriateness=stability * 0.8 + 0.2
            )
            
            feedback = FeedbackEvent(
                timestamp=time.time(),
                predicted_threat=0.5,
                actual_threat=0.5 + (np.random.random() - 0.5) * (1 - accuracy),
                accuracy=accuracy
            )
            
            # Calculate balance
            balance = regulator.calculate_eq_iq_balance(context, feedback)
            
            eq_history.append(balance.eq)
            iq_history.append(balance.iq)
            balance_history.append(balance.balance)
            
            # Adapt parameters based on performance
            performance = (stability + accuracy) / 2
            performance_history.append(performance)
            regulator.adapt_parameters(performance)
            
            alpha_history.append(regulator.alpha)
            beta_history.append(regulator.beta)
            
            if i % 10 == 0:
                self._log(f"Iteration {i}: α={regulator.alpha:.3f}, β={regulator.beta:.3f}, "
                         f"perf={performance:.3f}")
        
        results = {
            "alpha_history": alpha_history,
            "beta_history": beta_history,
            "eq_history": eq_history,
            "iq_history": iq_history,
            "balance_history": balance_history,
            "performance_history": performance_history,
            "final_alpha": regulator.alpha,
            "final_beta": regulator.beta,
            "regulator_stats": regulator.get_stats()
        }
        
        self.results["regulation"] = results
        
        print(f"\nInitial: α=0.600, β=0.400")
        print(f"Final:   α={regulator.alpha:.3f}, β={regulator.beta:.3f}")
        print(f"Avg Performance: {np.mean(performance_history):.3f}")
        
        return results
    
    def run_memory_test(self) -> Dict:
        """
        Test memory consolidation and retrieval.
        
        Demonstrates PSI and BDH memory dynamics.
        """
        print("\n" + "="*60)
        print("MEMORY CONSOLIDATION TEST")
        print("="*60)
        
        # Initialize memory systems
        psi = PSIIndex()
        bdh = BDHMemory("memory_test", max_traces=100)
        extractor = TextFeatureExtractor()
        
        # Track memory growth
        psi_size_history = []
        bdh_size_history = []
        consolidation_events = []
        
        # Process all samples
        all_samples = (
            self.test_data["scenarios"]["threat_patterns"] +
            self.test_data["scenarios"]["benign_patterns"] +
            self.test_data["scenarios"]["ambiguous_patterns"]
        )
        
        for i, sample in enumerate(all_samples):
            # Extract features
            features = extractor.extract(sample["input"])
            
            # Determine valence from label
            if sample["label"] == "threat":
                valence = 0.8
            elif sample["label"] == "benign":
                valence = -0.8
            else:
                valence = 0.0
            
            # Add to BDH
            bdh.add_or_update(
                sample["id"],
                features,
                valence=valence,
                label=sample["label"]
            )
            
            # Simulate reward-gated update
            reward = valence * 0.5 + np.random.random() * 0.2
            bdh.reward_gated_update(
                sample["id"],
                features,
                reward=reward,
                confidence=0.7
            )
            
            # Add significant samples to PSI
            if abs(valence) > 0.5:
                psi.add_doc(
                    sample["id"],
                    sample["input"],
                    features,
                    tags=[sample["label"], sample.get("category", "unknown")],
                    valence=valence
                )
                consolidation_events.append({
                    "iteration": i,
                    "id": sample["id"],
                    "valence": valence
                })
            
            psi_size_history.append(len(psi.docs))
            bdh_size_history.append(len(bdh.storage))
            
            self._log(f"Sample {i+1}: {sample['id']} -> BDH={len(bdh.storage)}, PSI={len(psi.docs)}")
        
        # Test retrieval
        print("\n--- Memory Retrieval Tests ---")
        test_queries = [
            "SELECT * FROM users",
            "GET /api/status",
            "<script>alert(1)</script>"
        ]
        
        retrieval_results = []
        for query in test_queries:
            query_features = extractor.extract(query)
            
            # PSI retrieval
            psi_results = psi.search(query_features, top_k=3)
            psi_valence = psi.compute_valence_weighted_average(query_features, top_k=3)
            
            # BDH retrieval
            bdh_results = bdh.retrieve_similar(query_features, top_k=3)
            bdh_differential = bdh.compute_differential_similarity(query_features)
            
            retrieval_results.append({
                "query": query[:30] + "..." if len(query) > 30 else query,
                "psi_matches": len(psi_results),
                "psi_valence": psi_valence,
                "bdh_matches": len(bdh_results),
                "bdh_differential": bdh_differential
            })
            
            print(f"  Query: '{query[:30]}...'")
            print(f"    PSI: {len(psi_results)} matches, valence={psi_valence:.3f}")
            print(f"    BDH: {len(bdh_results)} matches, differential={bdh_differential:.3f}")
        
        results = {
            "psi_size_history": psi_size_history,
            "bdh_size_history": bdh_size_history,
            "consolidation_events": consolidation_events,
            "retrieval_results": retrieval_results,
            "final_psi_stats": psi.get_stats(),
            "final_bdh_stats": bdh.get_stats()
        }
        
        self.results["memory"] = results
        
        print(f"\nFinal PSI Size: {len(psi.docs)}")
        print(f"Final BDH Size: {len(bdh.storage)}")
        print(f"Consolidation Events: {len(consolidation_events)}")
        
        return results
    
    def create_dashboard(self) -> str:
        """
        Create 5-panel dashboard visualization.
        
        Panels:
        1. Multi-pass Learning Progression
        2. One-shot Classification Results
        3. EQ/IQ Regulation Dynamics
        4. Memory Growth Over Time
        5. Summary Statistics
        """
        print("\n" + "="*60)
        print("GENERATING DASHBOARD")
        print("="*60)
        
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle('BHSM Experiential Learning Dashboard', fontsize=16, fontweight='bold')
        
        # Panel 1: Multi-pass Learning Progression
        ax1 = axes[0, 0]
        if self.results["multipass"]:
            passes = [p["pass"] for p in self.results["multipass"]["passes"]]
            accuracies = self.results["multipass"]["accuracy_history"]
            confidences = self.results["multipass"]["confidence_history"]
            
            ax1.plot(passes, accuracies, 'b-o', linewidth=2, markersize=8, label='Accuracy')
            ax1.plot(passes, confidences, 'g--s', linewidth=2, markersize=6, label='Confidence')
            ax1.axhline(y=0.5, color='r', linestyle=':', alpha=0.5, label='Random Baseline')
            ax1.fill_between(passes, accuracies, alpha=0.3)
            
            ax1.set_xlabel('Pass Number')
            ax1.set_ylabel('Score')
            ax1.set_title('Panel 1: Multi-Pass Learning Progression')
            ax1.legend(loc='lower right')
            ax1.set_ylim(0, 1)
            ax1.grid(True, alpha=0.3)
            
            # Add improvement annotation
            improvement = self.results["multipass"]["improvement"]
            ax1.annotate(f'Improvement: {improvement:+.1%}', 
                        xy=(0.02, 0.98), xycoords='axes fraction',
                        fontsize=10, fontweight='bold',
                        verticalalignment='top')
        else:
            ax1.text(0.5, 0.5, 'No multi-pass data', ha='center', va='center')
            ax1.set_title('Panel 1: Multi-Pass Learning')
        
        # Panel 2: One-shot Classification Results
        ax2 = axes[0, 1]
        if self.results["oneshot"] and self.results["oneshot"]["category_results"]:
            categories = list(self.results["oneshot"]["category_results"].keys())
            scores = []
            for cat in categories:
                cat_data = self.results["oneshot"]["category_results"][cat]
                avg_score = np.mean([r["score"] for r in cat_data]) if cat_data else 0
                scores.append(avg_score)
            
            colors = ['red', 'green', 'orange']
            bars = ax2.bar(range(len(categories)), scores, color=colors, alpha=0.7)
            ax2.set_xticks(range(len(categories)))
            ax2.set_xticklabels([c.replace('_patterns', '') for c in categories], rotation=15)
            ax2.set_ylabel('Average Threat Score')
            ax2.set_title('Panel 2: One-Shot Classification by Category')
            ax2.set_ylim(0, 1)
            ax2.axhline(y=0.5, color='gray', linestyle='--', alpha=0.5)
            ax2.grid(True, alpha=0.3, axis='y')
            
            # Add value labels
            for bar, score in zip(bars, scores):
                ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                        f'{score:.2f}', ha='center', va='bottom', fontsize=9)
        else:
            ax2.text(0.5, 0.5, 'No one-shot data', ha='center', va='center')
            ax2.set_title('Panel 2: One-Shot Classification')
        
        # Panel 3: EQ/IQ Regulation Dynamics
        ax3 = axes[0, 2]
        if self.results["regulation"]:
            iterations = range(len(self.results["regulation"]["alpha_history"]))
            
            ax3.plot(iterations, self.results["regulation"]["alpha_history"], 
                    'b-', linewidth=2, label='α (EQ weight)')
            ax3.plot(iterations, self.results["regulation"]["beta_history"], 
                    'r-', linewidth=2, label='β (IQ weight)')
            
            # Add performance as background
            if self.results["regulation"]["performance_history"]:
                perf = [0] + self.results["regulation"]["performance_history"]  # Align with alpha/beta
                ax3_twin = ax3.twinx()
                ax3_twin.fill_between(iterations, perf, alpha=0.2, color='gray', label='Performance')
                ax3_twin.set_ylabel('Performance', color='gray')
                ax3_twin.tick_params(axis='y', labelcolor='gray')
                ax3_twin.set_ylim(0, 1)
            
            ax3.set_xlabel('Iteration')
            ax3.set_ylabel('Weight')
            ax3.set_title('Panel 3: EQ/IQ Regulation Dynamics')
            ax3.legend(loc='upper left')
            ax3.set_ylim(0, 1)
            ax3.grid(True, alpha=0.3)
        else:
            ax3.text(0.5, 0.5, 'No regulation data', ha='center', va='center')
            ax3.set_title('Panel 3: EQ/IQ Regulation')
        
        # Panel 4: Memory Growth Over Time
        ax4 = axes[1, 0]
        if self.results["memory"]:
            samples = range(len(self.results["memory"]["psi_size_history"]))
            
            ax4.plot(samples, self.results["memory"]["bdh_size_history"], 
                    'b-', linewidth=2, label='BDH Traces')
            ax4.plot(samples, self.results["memory"]["psi_size_history"], 
                    'g-', linewidth=2, label='PSI Documents')
            
            ax4.fill_between(samples, self.results["memory"]["bdh_size_history"], alpha=0.3)
            ax4.fill_between(samples, self.results["memory"]["psi_size_history"], alpha=0.3, color='green')
            
            ax4.set_xlabel('Samples Processed')
            ax4.set_ylabel('Memory Size')
            ax4.set_title('Panel 4: Memory Growth Over Time')
            ax4.legend(loc='upper left')
            ax4.grid(True, alpha=0.3)
        else:
            ax4.text(0.5, 0.5, 'No memory data', ha='center', va='center')
            ax4.set_title('Panel 4: Memory Growth')
        
        # Panel 5: EQ vs IQ Balance History
        ax5 = axes[1, 1]
        if self.results["regulation"] and self.results["regulation"]["eq_history"]:
            iterations = range(len(self.results["regulation"]["eq_history"]))
            
            ax5.plot(iterations, self.results["regulation"]["eq_history"], 
                    'b-', linewidth=1.5, alpha=0.7, label='EQ Score')
            ax5.plot(iterations, self.results["regulation"]["iq_history"], 
                    'r-', linewidth=1.5, alpha=0.7, label='IQ Score')
            ax5.plot(iterations, self.results["regulation"]["balance_history"], 
                    'purple', linewidth=2, label='Balance')
            
            ax5.set_xlabel('Iteration')
            ax5.set_ylabel('Score')
            ax5.set_title('Panel 5: EQ vs IQ Balance Over Time')
            ax5.legend(loc='lower right')
            ax5.set_ylim(0, 1)
            ax5.grid(True, alpha=0.3)
        else:
            ax5.text(0.5, 0.5, 'No balance data', ha='center', va='center')
            ax5.set_title('Panel 5: EQ vs IQ Balance')
        
        # Panel 6: Summary Statistics Table
        ax6 = axes[1, 2]
        ax6.axis('off')
        
        # Create summary text
        summary_text = "SUMMARY STATISTICS\n" + "="*30 + "\n\n"
        
        if self.results["multipass"]:
            summary_text += f"Multi-Pass Learning:\n"
            summary_text += f"  • Final Accuracy: {self.results['multipass']['final_accuracy']:.1%}\n"
            summary_text += f"  • Improvement: {self.results['multipass']['improvement']:+.1%}\n"
            summary_text += f"  • Passes: {len(self.results['multipass']['passes'])}\n\n"
        
        if self.results["regulation"]:
            summary_text += f"EQ/IQ Regulation:\n"
            summary_text += f"  • Final α: {self.results['regulation']['final_alpha']:.3f}\n"
            summary_text += f"  • Final β: {self.results['regulation']['final_beta']:.3f}\n"
            summary_text += f"  • Avg Performance: {np.mean(self.results['regulation']['performance_history']):.3f}\n\n"
        
        if self.results["memory"]:
            summary_text += f"Memory System:\n"
            summary_text += f"  • Final BDH Size: {self.results['memory']['bdh_size_history'][-1]}\n"
            summary_text += f"  • Final PSI Size: {self.results['memory']['psi_size_history'][-1]}\n"
            summary_text += f"  • Consolidations: {len(self.results['memory']['consolidation_events'])}\n\n"
        
        if self.results["oneshot"]:
            correct = sum(1 for t in self.results["oneshot"]["oneshot_tests"] if t["correct"])
            total = len(self.results["oneshot"]["oneshot_tests"])
            summary_text += f"One-Shot Tests:\n"
            summary_text += f"  • Correct: {correct}/{total}\n"
        
        ax6.text(0.1, 0.95, summary_text, transform=ax6.transAxes,
                fontsize=11, verticalalignment='top', fontfamily='monospace',
                bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.8))
        ax6.set_title('Summary Statistics', pad=20)
        
        plt.tight_layout()
        
        # Save dashboard
        dashboard_path = os.path.join(self.output_dir, f"bhsm_dashboard_{self.timestamp}.png")
        plt.savefig(dashboard_path, dpi=150, bbox_inches='tight')
        print(f"Dashboard saved: {dashboard_path}")
        
        plt.close()
        
        return dashboard_path
    
    def save_results(self) -> str:
        """Save all results to JSON file."""
        # Compute summary
        self.results["summary"] = {
            "timestamp": self.timestamp,
            "test_data_version": self.test_data.get("version", "unknown"),
            "multipass_final_accuracy": self.results["multipass"].get("final_accuracy", None),
            "multipass_improvement": self.results["multipass"].get("improvement", None),
            "regulation_final_alpha": self.results["regulation"].get("final_alpha", None),
            "regulation_final_beta": self.results["regulation"].get("final_beta", None),
            "memory_final_bdh_size": self.results["memory"]["bdh_size_history"][-1] if self.results["memory"] else None,
            "memory_final_psi_size": self.results["memory"]["psi_size_history"][-1] if self.results["memory"] else None
        }
        
        # Convert numpy types for JSON serialization
        def convert_numpy(obj):
            if isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, (np.float32, np.float64)):
                return float(obj)
            elif isinstance(obj, (np.int32, np.int64)):
                return int(obj)
            elif isinstance(obj, dict):
                return {k: convert_numpy(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_numpy(i) for i in obj]
            return obj
        
        results_clean = convert_numpy(self.results)
        
        results_path = os.path.join(self.output_dir, f"bhsm_results_{self.timestamp}.json")
        with open(results_path, 'w') as f:
            json.dump(results_clean, f, indent=2)
        
        print(f"Results saved: {results_path}")
        return results_path
    
    def run_all_tests(self, quick: bool = False) -> Dict:
        """Run all tests and generate outputs."""
        print("\n" + "="*60)
        print("BHSM COMPREHENSIVE TEST SUITE")
        print(f"Timestamp: {self.timestamp}")
        print("="*60)
        
        # Adjust parameters for quick mode
        if quick:
            n_passes = 2
            samples_per_pass = 8
            regulation_iterations = 25
        else:
            n_passes = 3
            samples_per_pass = 15
            regulation_iterations = 50
        
        # Run tests
        self.run_multipass_learning_test(n_passes=n_passes, samples_per_pass=samples_per_pass)
        self.run_oneshot_test()
        self.run_regulation_test(n_iterations=regulation_iterations)
        self.run_memory_test()
        
        # Generate outputs
        dashboard_path = self.create_dashboard()
        results_path = self.save_results()
        
        print("\n" + "="*60)
        print("TEST SUITE COMPLETE")
        print("="*60)
        print(f"Dashboard: {dashboard_path}")
        print(f"Results: {results_path}")
        print("="*60)
        
        return {
            "dashboard_path": dashboard_path,
            "results_path": results_path,
            "summary": self.results["summary"]
        }


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="BHSM Comprehensive Test Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--quick", action="store_true",
                       help="Run quick test with fewer iterations")
    parser.add_argument("--verbose", action="store_true",
                       help="Enable verbose output")
    parser.add_argument("--output-dir", type=str, default="test",
                       help="Output directory for results (default: test)")
    
    args = parser.parse_args()
    
    # Run test suite
    suite = BHSMTestSuite(output_dir=args.output_dir, verbose=args.verbose)
    results = suite.run_all_tests(quick=args.quick)
    
    return results


if __name__ == "__main__":
    main()
