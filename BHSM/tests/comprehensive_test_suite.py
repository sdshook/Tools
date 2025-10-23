"""
Comprehensive Test Suite for TinyLLaMA + BHSM Integration
========================================================

This test suite demonstrates the value proposition of BHSM by comparing:
1. Baseline TinyLLaMA performance (no memory enhancement)
2. TinyLLaMA + BHSM integration performance

Test scenarios include:
- Context window extension (long conversations)
- Memory consolidation and retrieval
- Learning from feedback
- Consistency across sessions
- Performance metrics and analysis

(c) 2025 - Shane D. Shook, All Rights Reserved
"""

import time
import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from typing import Dict, List, Tuple, Any
import os
import sys
from pathlib import Path

# Import our integration system
from tinyllama_bhsm_integration import TinyLLaMABHSMSystem, MemoryBridge, ExperientialMemorySystem
from BHSM import PSIIndex, BDHMemory, SimEmbedder

class BaselineTinyLLaMA:
    """
    Baseline TinyLLaMA system without BHSM enhancement for comparison.
    """
    
    def __init__(self, model_name: str = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"):
        print("Initializing Baseline TinyLLaMA...")
        
        try:
            from transformers import AutoTokenizer, AutoModelForCausalLM
            import torch
            
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                device_map="auto" if torch.cuda.is_available() else None
            )
            
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
                
            self.conversation_history = []
            print("Baseline TinyLLaMA initialized successfully!")
            
        except Exception as e:
            print(f"Error initializing baseline model: {e}")
            raise
    
    def generate_response(self, user_input: str, max_context_turns: int = 3) -> Tuple[str, Dict]:
        """Generate response using only TinyLLaMA without memory enhancement."""
        import torch
        
        start_time = time.time()
        
        # Use only recent conversation history (limited context window)
        recent_history = self.conversation_history[-max_context_turns:]
        conversation_context = "\n".join([
            f"User: {turn['user']}\nAssistant: {turn['assistant']}" 
            for turn in recent_history
        ])
        
        prompt = f"""You are a helpful AI assistant.

{conversation_context}

User: {user_input}
Assistant:"""
        
        inputs = self.tokenizer(
            prompt, 
            return_tensors="pt", 
            truncation=True, 
            max_length=2048 - 200
        )
        
        with torch.no_grad():
            outputs = self.model.generate(
                inputs.input_ids,
                max_new_tokens=150,
                temperature=0.7,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id,
                attention_mask=inputs.attention_mask
            )
        
        full_response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        response = full_response[len(prompt):].strip()
        
        # Store in conversation history
        self.conversation_history.append({
            "user": user_input,
            "assistant": response,
            "timestamp": time.time()
        })
        
        metadata = {
            "generation_time": time.time() - start_time,
            "context_turns_used": len(recent_history),
            "memory_enhanced": False
        }
        
        return response, metadata

class ComprehensiveTestSuite:
    """
    Comprehensive test suite comparing baseline vs BHSM-enhanced systems.
    """
    
    def __init__(self):
        self.results = {
            "baseline": {"responses": [], "metadata": [], "scores": []},
            "enhanced": {"responses": [], "metadata": [], "scores": []}
        }
        self.test_scenarios = []
        self.embedder = SimEmbedder()
        
    def initialize_systems(self):
        """Initialize both baseline and enhanced systems."""
        print("Initializing test systems...")
        
        try:
            print("Setting up baseline TinyLLaMA...")
            self.baseline_system = BaselineTinyLLaMA()
            
            print("Setting up BHSM-enhanced TinyLLaMA...")
            self.enhanced_system = TinyLLaMABHSMSystem()
            
            print("Both systems initialized successfully!")
            return True
            
        except Exception as e:
            print(f"Error initializing systems: {e}")
            return False
    
    def create_test_scenarios(self) -> List[Dict]:
        """Create comprehensive test scenarios."""
        
        scenarios = [
            # Context Window Extension Tests
            {
                "category": "context_extension",
                "name": "Long Conversation Memory",
                "description": "Test ability to remember information from early in a long conversation",
                "conversations": [
                    "Hi, I'm working on a project about renewable energy. My name is Alex and I'm particularly interested in solar panel efficiency.",
                    "That's interesting! Can you tell me more about different types of solar panels?",
                    "I'm also curious about wind energy. How do wind turbines work?",
                    "What about energy storage solutions for renewable energy?",
                    "Let's talk about something else. What's your favorite color?",
                    "Actually, going back to our earlier discussion - what was my name and what project was I working on?"
                ],
                "evaluation_criteria": ["memory_recall", "context_consistency"]
            },
            
            # Learning and Adaptation Tests
            {
                "category": "learning_adaptation",
                "name": "Preference Learning",
                "description": "Test ability to learn and adapt to user preferences over time",
                "conversations": [
                    "I prefer detailed technical explanations over simple ones.",
                    "Can you explain how machine learning works?",
                    "That was too simple. I said I prefer detailed technical explanations.",
                    "Can you explain neural networks?",
                    "Perfect! That level of detail is exactly what I like.",
                    "Now explain quantum computing."
                ],
                "evaluation_criteria": ["adaptation", "preference_learning", "response_quality"]
            },
            
            # Knowledge Consolidation Tests
            {
                "category": "knowledge_consolidation",
                "name": "Fact Integration",
                "description": "Test ability to integrate and consolidate information across conversations",
                "conversations": [
                    "I'm learning Python programming. I know variables and basic syntax.",
                    "Can you teach me about functions in Python?",
                    "Now I want to learn about classes and objects.",
                    "How do I handle errors in Python?",
                    "Can you create a simple program that uses everything we've discussed - variables, functions, classes, and error handling?"
                ],
                "evaluation_criteria": ["knowledge_integration", "coherence", "practical_application"]
            },
            
            # Consistency Tests
            {
                "category": "consistency",
                "name": "Information Consistency",
                "description": "Test consistency of information across multiple interactions",
                "conversations": [
                    "What's the capital of France?",
                    "Tell me about French culture.",
                    "What's the population of Paris?",
                    "Earlier you mentioned the capital of France. What was it again?",
                    "Is Paris really the capital of France?"
                ],
                "evaluation_criteria": ["factual_consistency", "reliability"]
            },
            
            # Complex Reasoning Tests
            {
                "category": "complex_reasoning",
                "name": "Multi-step Problem Solving",
                "description": "Test ability to maintain context through complex multi-step problems",
                "conversations": [
                    "I need to plan a trip to Japan. I have a budget of $3000 and 10 days.",
                    "I'm interested in both traditional culture and modern technology.",
                    "I don't speak Japanese. Will that be a problem?",
                    "What cities should I visit given my interests?",
                    "Can you create a day-by-day itinerary based on everything we've discussed?"
                ],
                "evaluation_criteria": ["context_maintenance", "problem_solving", "integration"]
            }
        ]
        
        self.test_scenarios = scenarios
        return scenarios
    
    def run_scenario(self, scenario: Dict, system_type: str) -> Dict:
        """Run a single test scenario on the specified system."""
        
        system = self.baseline_system if system_type == "baseline" else self.enhanced_system
        scenario_results = {
            "scenario": scenario["name"],
            "category": scenario["category"],
            "system_type": system_type,
            "responses": [],
            "metadata": [],
            "start_time": time.time()
        }
        
        print(f"\nRunning scenario '{scenario['name']}' on {system_type} system...")
        
        for i, user_input in enumerate(scenario["conversations"]):
            print(f"  Turn {i+1}: {user_input[:50]}...")
            
            try:
                if system_type == "baseline":
                    response, metadata = system.generate_response(user_input)
                else:
                    response, metadata = system.generate_response(user_input, use_memory=True)
                
                scenario_results["responses"].append({
                    "turn": i + 1,
                    "user_input": user_input,
                    "response": response,
                    "timestamp": time.time()
                })
                
                scenario_results["metadata"].append(metadata)
                
                # Small delay to prevent overwhelming the system
                time.sleep(0.5)
                
            except Exception as e:
                print(f"    Error in turn {i+1}: {e}")
                scenario_results["responses"].append({
                    "turn": i + 1,
                    "user_input": user_input,
                    "response": f"ERROR: {str(e)}",
                    "timestamp": time.time()
                })
        
        scenario_results["end_time"] = time.time()
        scenario_results["total_time"] = scenario_results["end_time"] - scenario_results["start_time"]
        
        return scenario_results
    
    def evaluate_scenario_results(self, scenario: Dict, baseline_results: Dict, enhanced_results: Dict) -> Dict:
        """Evaluate and compare results from both systems for a scenario."""
        
        evaluation = {
            "scenario": scenario["name"],
            "category": scenario["category"],
            "criteria": scenario["evaluation_criteria"],
            "baseline_score": 0.0,
            "enhanced_score": 0.0,
            "detailed_scores": {},
            "analysis": {}
        }
        
        # Evaluate based on criteria
        for criterion in scenario["evaluation_criteria"]:
            baseline_score = self._evaluate_criterion(criterion, scenario, baseline_results)
            enhanced_score = self._evaluate_criterion(criterion, scenario, enhanced_results)
            
            evaluation["detailed_scores"][criterion] = {
                "baseline": baseline_score,
                "enhanced": enhanced_score,
                "improvement": enhanced_score - baseline_score
            }
            
            evaluation["baseline_score"] += baseline_score
            evaluation["enhanced_score"] += enhanced_score
        
        # Normalize scores
        num_criteria = len(scenario["evaluation_criteria"])
        evaluation["baseline_score"] /= num_criteria
        evaluation["enhanced_score"] /= num_criteria
        evaluation["improvement"] = evaluation["enhanced_score"] - evaluation["baseline_score"]
        
        # Generate analysis
        evaluation["analysis"] = self._generate_analysis(scenario, baseline_results, enhanced_results, evaluation)
        
        return evaluation
    
    def _evaluate_criterion(self, criterion: str, scenario: Dict, results: Dict) -> float:
        """Evaluate a specific criterion for the results."""
        
        if criterion == "memory_recall":
            return self._evaluate_memory_recall(scenario, results)
        elif criterion == "context_consistency":
            return self._evaluate_context_consistency(results)
        elif criterion == "adaptation":
            return self._evaluate_adaptation(results)
        elif criterion == "preference_learning":
            return self._evaluate_preference_learning(results)
        elif criterion == "response_quality":
            return self._evaluate_response_quality(results)
        elif criterion == "knowledge_integration":
            return self._evaluate_knowledge_integration(results)
        elif criterion == "coherence":
            return self._evaluate_coherence(results)
        elif criterion == "practical_application":
            return self._evaluate_practical_application(results)
        elif criterion == "factual_consistency":
            return self._evaluate_factual_consistency(results)
        elif criterion == "reliability":
            return self._evaluate_reliability(results)
        elif criterion == "context_maintenance":
            return self._evaluate_context_maintenance(results)
        elif criterion == "problem_solving":
            return self._evaluate_problem_solving(results)
        elif criterion == "integration":
            return self._evaluate_integration(results)
        else:
            return 0.5  # Default neutral score
    
    def _evaluate_memory_recall(self, scenario: Dict, results: Dict) -> float:
        """Evaluate memory recall capability."""
        # Look for specific information recall in the last response
        last_response = results["responses"][-1]["response"].lower()
        
        # For the context extension scenario, check if name and project are recalled
        if "alex" in last_response and ("renewable" in last_response or "solar" in last_response):
            return 1.0
        elif "alex" in last_response or ("renewable" in last_response or "solar" in last_response):
            return 0.7
        else:
            return 0.2
    
    def _evaluate_context_consistency(self, results: Dict) -> float:
        """Evaluate consistency of context across responses."""
        # Simple heuristic: longer responses with relevant content suggest better context use
        avg_response_length = np.mean([len(r["response"]) for r in results["responses"]])
        
        if avg_response_length > 100:
            return 0.8
        elif avg_response_length > 50:
            return 0.6
        else:
            return 0.4
    
    def _evaluate_adaptation(self, results: Dict) -> float:
        """Evaluate adaptation to user feedback."""
        # Look for changes in response style after feedback
        if len(results["responses"]) < 4:
            return 0.5
        
        early_responses = results["responses"][:2]
        later_responses = results["responses"][3:]
        
        early_avg_length = np.mean([len(r["response"]) for r in early_responses])
        later_avg_length = np.mean([len(r["response"]) for r in later_responses])
        
        # If later responses are longer (more detailed), adaptation occurred
        if later_avg_length > early_avg_length * 1.3:
            return 0.9
        elif later_avg_length > early_avg_length * 1.1:
            return 0.7
        else:
            return 0.4
    
    def _evaluate_preference_learning(self, results: Dict) -> float:
        """Evaluate learning of user preferences."""
        # Similar to adaptation but more specific to preference signals
        return self._evaluate_adaptation(results)
    
    def _evaluate_response_quality(self, results: Dict) -> float:
        """Evaluate overall response quality."""
        # Heuristic based on response length and variety
        responses = [r["response"] for r in results["responses"]]
        avg_length = np.mean([len(r) for r in responses])
        
        # Check for variety in responses (not repetitive)
        unique_words = set()
        for response in responses:
            unique_words.update(response.lower().split())
        
        variety_score = min(len(unique_words) / 100, 1.0)  # Normalize to 0-1
        length_score = min(avg_length / 200, 1.0)  # Normalize to 0-1
        
        return (variety_score + length_score) / 2
    
    def _evaluate_knowledge_integration(self, results: Dict) -> float:
        """Evaluate integration of knowledge across conversation."""
        # Look for references to earlier topics in later responses
        last_response = results["responses"][-1]["response"].lower()
        
        # Count mentions of key programming concepts
        concepts = ["variable", "function", "class", "error", "exception"]
        mentions = sum(1 for concept in concepts if concept in last_response)
        
        return min(mentions / len(concepts), 1.0)
    
    def _evaluate_coherence(self, results: Dict) -> float:
        """Evaluate coherence of responses."""
        # Simple coherence measure based on response consistency
        return self._evaluate_response_quality(results)
    
    def _evaluate_practical_application(self, results: Dict) -> float:
        """Evaluate practical application of knowledge."""
        # Look for code or practical examples in responses
        last_response = results["responses"][-1]["response"].lower()
        
        if "def " in last_response or "class " in last_response:
            return 0.9
        elif "example" in last_response or "code" in last_response:
            return 0.7
        else:
            return 0.4
    
    def _evaluate_factual_consistency(self, results: Dict) -> float:
        """Evaluate factual consistency."""
        # Look for consistent facts across responses
        responses = [r["response"].lower() for r in results["responses"]]
        
        # Check for Paris/France consistency
        paris_mentions = sum(1 for r in responses if "paris" in r)
        france_mentions = sum(1 for r in responses if "france" in r)
        
        if paris_mentions > 0 and france_mentions > 0:
            return 0.9
        elif paris_mentions > 0 or france_mentions > 0:
            return 0.6
        else:
            return 0.3
    
    def _evaluate_reliability(self, results: Dict) -> float:
        """Evaluate reliability of information."""
        return self._evaluate_factual_consistency(results)
    
    def _evaluate_context_maintenance(self, results: Dict) -> float:
        """Evaluate maintenance of context through complex scenarios."""
        # Look for references to budget, timeframe, and interests in final response
        last_response = results["responses"][-1]["response"].lower()
        
        context_elements = ["3000", "10 days", "japan", "culture", "technology"]
        mentions = sum(1 for element in context_elements if element in last_response)
        
        return min(mentions / len(context_elements), 1.0)
    
    def _evaluate_problem_solving(self, results: Dict) -> float:
        """Evaluate problem-solving capability."""
        # Look for structured, comprehensive responses
        last_response = results["responses"][-1]["response"]
        
        if len(last_response) > 300 and ("day" in last_response.lower() or "itinerary" in last_response.lower()):
            return 0.9
        elif len(last_response) > 150:
            return 0.6
        else:
            return 0.3
    
    def _evaluate_integration(self, results: Dict) -> float:
        """Evaluate integration of multiple conversation elements."""
        return self._evaluate_context_maintenance(results)
    
    def _generate_analysis(self, scenario: Dict, baseline_results: Dict, enhanced_results: Dict, evaluation: Dict) -> Dict:
        """Generate detailed analysis of the comparison."""
        
        analysis = {
            "summary": f"Enhanced system scored {evaluation['enhanced_score']:.2f} vs baseline {evaluation['baseline_score']:.2f}",
            "improvement": f"{evaluation['improvement']:.2f} point improvement ({evaluation['improvement']/evaluation['baseline_score']*100:.1f}% relative improvement)" if evaluation['baseline_score'] > 0 else "Significant improvement",
            "strengths": [],
            "areas_for_improvement": [],
            "response_comparison": {
                "baseline_avg_length": np.mean([len(r["response"]) for r in baseline_results["responses"]]),
                "enhanced_avg_length": np.mean([len(r["response"]) for r in enhanced_results["responses"]]),
                "baseline_total_time": baseline_results["total_time"],
                "enhanced_total_time": enhanced_results["total_time"]
            }
        }
        
        # Identify strengths and areas for improvement
        for criterion, scores in evaluation["detailed_scores"].items():
            if scores["improvement"] > 0.2:
                analysis["strengths"].append(f"Strong improvement in {criterion} (+{scores['improvement']:.2f})")
            elif scores["improvement"] < -0.1:
                analysis["areas_for_improvement"].append(f"Needs work on {criterion} ({scores['improvement']:.2f})")
        
        return analysis
    
    def run_comprehensive_test(self) -> Dict:
        """Run the complete test suite."""
        
        print("="*80)
        print("COMPREHENSIVE TINYLLAMA + BHSM TEST SUITE")
        print("="*80)
        
        # Initialize systems
        if not self.initialize_systems():
            return {"error": "Failed to initialize systems"}
        
        # Create test scenarios
        scenarios = self.create_test_scenarios()
        print(f"\nCreated {len(scenarios)} test scenarios")
        
        # Run all scenarios
        all_evaluations = []
        
        for scenario in scenarios:
            print(f"\n{'='*60}")
            print(f"TESTING: {scenario['name']}")
            print(f"Category: {scenario['category']}")
            print(f"Description: {scenario['description']}")
            print(f"{'='*60}")
            
            # Run on baseline system
            baseline_results = self.run_scenario(scenario, "baseline")
            
            # Run on enhanced system
            enhanced_results = self.run_scenario(scenario, "enhanced")
            
            # Evaluate results
            evaluation = self.evaluate_scenario_results(scenario, baseline_results, enhanced_results)
            all_evaluations.append(evaluation)
            
            # Print summary
            print(f"\nRESULTS:")
            print(f"  Baseline Score: {evaluation['baseline_score']:.2f}")
            print(f"  Enhanced Score: {evaluation['enhanced_score']:.2f}")
            print(f"  Improvement: {evaluation['improvement']:.2f}")
            print(f"  Analysis: {evaluation['analysis']['summary']}")
        
        # Generate overall results
        overall_results = self._generate_overall_results(all_evaluations)
        
        # Save results
        self._save_results(overall_results, all_evaluations)
        
        return overall_results
    
    def _generate_overall_results(self, evaluations: List[Dict]) -> Dict:
        """Generate overall test results summary."""
        
        overall = {
            "test_date": datetime.now().isoformat(),
            "total_scenarios": len(evaluations),
            "overall_baseline_score": np.mean([e["baseline_score"] for e in evaluations]),
            "overall_enhanced_score": np.mean([e["enhanced_score"] for e in evaluations]),
            "overall_improvement": np.mean([e["improvement"] for e in evaluations]),
            "category_breakdown": {},
            "best_improvements": [],
            "summary": ""
        }
        
        # Category breakdown
        categories = set(e["category"] for e in evaluations)
        for category in categories:
            category_evals = [e for e in evaluations if e["category"] == category]
            overall["category_breakdown"][category] = {
                "baseline_score": np.mean([e["baseline_score"] for e in category_evals]),
                "enhanced_score": np.mean([e["enhanced_score"] for e in category_evals]),
                "improvement": np.mean([e["improvement"] for e in category_evals])
            }
        
        # Best improvements
        sorted_evals = sorted(evaluations, key=lambda x: x["improvement"], reverse=True)
        overall["best_improvements"] = [
            {"scenario": e["scenario"], "improvement": e["improvement"]} 
            for e in sorted_evals[:3]
        ]
        
        # Generate summary
        improvement_pct = (overall["overall_improvement"] / overall["overall_baseline_score"] * 100) if overall["overall_baseline_score"] > 0 else 0
        overall["summary"] = f"BHSM enhancement provides {improvement_pct:.1f}% average improvement across all test scenarios"
        
        return overall
    
    def _save_results(self, overall_results: Dict, detailed_evaluations: List[Dict]):
        """Save test results to files."""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save overall results
        overall_file = f"test_results_overall_{timestamp}.json"
        with open(overall_file, 'w') as f:
            json.dump(overall_results, f, indent=2)
        
        # Save detailed results
        detailed_file = f"test_results_detailed_{timestamp}.json"
        with open(detailed_file, 'w') as f:
            json.dump(detailed_evaluations, f, indent=2)
        
        # Create visualization
        self._create_visualization(overall_results, detailed_evaluations, timestamp)
        
        print(f"\nResults saved:")
        print(f"  Overall: {overall_file}")
        print(f"  Detailed: {detailed_file}")
        print(f"  Visualization: test_results_visualization_{timestamp}.png")
    
    def _create_visualization(self, overall_results: Dict, detailed_evaluations: List[Dict], timestamp: str):
        """Create visualization of test results."""
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        
        # Overall comparison
        categories = ['Overall']
        baseline_scores = [overall_results["overall_baseline_score"]]
        enhanced_scores = [overall_results["overall_enhanced_score"]]
        
        x = np.arange(len(categories))
        width = 0.35
        
        ax1.bar(x - width/2, baseline_scores, width, label='Baseline TinyLLaMA', alpha=0.8)
        ax1.bar(x + width/2, enhanced_scores, width, label='TinyLLaMA + BHSM', alpha=0.8)
        ax1.set_ylabel('Average Score')
        ax1.set_title('Overall Performance Comparison')
        ax1.set_xticks(x)
        ax1.set_xticklabels(categories)
        ax1.legend()
        ax1.set_ylim(0, 1)
        
        # Category breakdown
        categories = list(overall_results["category_breakdown"].keys())
        baseline_scores = [overall_results["category_breakdown"][cat]["baseline_score"] for cat in categories]
        enhanced_scores = [overall_results["category_breakdown"][cat]["enhanced_score"] for cat in categories]
        
        x = np.arange(len(categories))
        ax2.bar(x - width/2, baseline_scores, width, label='Baseline', alpha=0.8)
        ax2.bar(x + width/2, enhanced_scores, width, label='Enhanced', alpha=0.8)
        ax2.set_ylabel('Average Score')
        ax2.set_title('Performance by Category')
        ax2.set_xticks(x)
        ax2.set_xticklabels(categories, rotation=45, ha='right')
        ax2.legend()
        ax2.set_ylim(0, 1)
        
        # Improvement by scenario
        scenarios = [e["scenario"] for e in detailed_evaluations]
        improvements = [e["improvement"] for e in detailed_evaluations]
        
        ax3.bar(range(len(scenarios)), improvements, alpha=0.8)
        ax3.set_ylabel('Improvement Score')
        ax3.set_title('Improvement by Scenario')
        ax3.set_xticks(range(len(scenarios)))
        ax3.set_xticklabels(scenarios, rotation=45, ha='right')
        ax3.axhline(y=0, color='r', linestyle='--', alpha=0.5)
        
        # Summary statistics
        stats_text = f"""
Test Summary:
• Total Scenarios: {overall_results['total_scenarios']}
• Overall Improvement: {overall_results['overall_improvement']:.3f}
• Relative Improvement: {(overall_results['overall_improvement']/overall_results['overall_baseline_score']*100):.1f}%
• Best Category: {max(overall_results['category_breakdown'].items(), key=lambda x: x[1]['improvement'])[0]}
• Test Date: {overall_results['test_date'][:10]}
        """
        
        ax4.text(0.1, 0.5, stats_text, transform=ax4.transAxes, fontsize=10,
                verticalalignment='center', bbox=dict(boxstyle="round,pad=0.3", facecolor="lightgray"))
        ax4.set_xlim(0, 1)
        ax4.set_ylim(0, 1)
        ax4.axis('off')
        ax4.set_title('Test Summary')
        
        plt.tight_layout()
        plt.savefig(f'test_results_visualization_{timestamp}.png', dpi=300, bbox_inches='tight')
        plt.close()

def main():
    """Run the comprehensive test suite."""
    
    print("Starting Comprehensive TinyLLaMA + BHSM Test Suite...")
    
    try:
        test_suite = ComprehensiveTestSuite()
        results = test_suite.run_comprehensive_test()
        
        if "error" in results:
            print(f"Test failed: {results['error']}")
            return
        
        print("\n" + "="*80)
        print("FINAL RESULTS SUMMARY")
        print("="*80)
        print(f"Overall Baseline Score: {results['overall_baseline_score']:.3f}")
        print(f"Overall Enhanced Score: {results['overall_enhanced_score']:.3f}")
        print(f"Overall Improvement: {results['overall_improvement']:.3f}")
        print(f"Relative Improvement: {(results['overall_improvement']/results['overall_baseline_score']*100):.1f}%")
        print(f"\n{results['summary']}")
        
        print("\nCategory Breakdown:")
        for category, scores in results["category_breakdown"].items():
            print(f"  {category}: {scores['improvement']:.3f} improvement")
        
        print("\nTop Improvements:")
        for improvement in results["best_improvements"]:
            print(f"  {improvement['scenario']}: +{improvement['improvement']:.3f}")
        
        print("\n" + "="*80)
        print("Test completed successfully! Check generated files for detailed results.")
        
    except Exception as e:
        print(f"Test suite failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()