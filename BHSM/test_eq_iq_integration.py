#!/usr/bin/env python3
"""
Comprehensive test suite for BHSM EQ/IQ integration
Tests the ExperientialBehavioralRegulator and BDHMemory integration
"""

import unittest
import numpy as np
import tempfile
import os
import time
from pathlib import Path

from BHSM import BDHMemory, SimEmbedder, PSIIndex
from eq_iq_regulator import ExperientialBehavioralRegulator, ContextEvent, FeedbackEvent


def create_context_event(stability=0.5, threat_level=0.5, appropriateness=0.5):
    """Helper to create ContextEvent with proper field names"""
    return ContextEvent(
        timestamp=time.time(),
        context_stability=stability,
        threat_level=threat_level,
        response_appropriateness=appropriateness
    )


def create_feedback_event(predicted=0.5, actual=0.5, accuracy=0.5):
    """Helper to create FeedbackEvent with proper field names"""
    return FeedbackEvent(
        timestamp=time.time(),
        predicted_threat=predicted,
        actual_threat=actual,
        accuracy=accuracy
    )


class TestEQIQRegulator(unittest.TestCase):
    """Test the EQ/IQ regulator functionality"""
    
    def setUp(self):
        self.regulator = ExperientialBehavioralRegulator(alpha=0.6, beta=0.4, learning_rate=0.01)
    
    def test_initialization(self):
        """Test regulator initialization"""
        stats = self.regulator.get_stats()
        self.assertEqual(stats['alpha'], 0.6)
        self.assertEqual(stats['beta'], 0.4)
        self.assertEqual(stats['learning_rate'], 0.01)
        self.assertEqual(stats['context_history_size'], 0)
        self.assertEqual(stats['feedback_history_size'], 0)
    
    def test_context_event_creation(self):
        """Test ContextEvent creation and validation"""
        context = create_context_event(stability=0.8, threat_level=0.7, appropriateness=0.9)
        self.assertEqual(context.context_stability, 0.8)
        self.assertEqual(context.threat_level, 0.7)
        self.assertEqual(context.response_appropriateness, 0.9)
    
    def test_feedback_event_creation(self):
        """Test FeedbackEvent creation and validation"""
        feedback = create_feedback_event(predicted=0.85, actual=0.75, accuracy=0.9)
        self.assertEqual(feedback.predicted_threat, 0.85)
        self.assertEqual(feedback.actual_threat, 0.75)
        self.assertEqual(feedback.accuracy, 0.9)
    
    def test_reward_calculation(self):
        """Test EQ/IQ balanced reward calculation"""
        context = create_context_event(stability=0.8, threat_level=0.7, appropriateness=0.9)
        feedback = create_feedback_event(predicted=0.85, actual=0.75, accuracy=0.9)
        
        reward = self.regulator.calculate_reward(context, feedback)
        
        # Reward should be between 0 and 1
        self.assertGreaterEqual(reward, 0.0)
        self.assertLessEqual(reward, 1.0)
        
        # With high values, reward should be substantial
        self.assertGreater(reward, 0.5)
    
    def test_empathy_vs_accuracy_balance(self):
        """Test that EQ/IQ balance affects reward calculation"""
        empathy_regulator = ExperientialBehavioralRegulator(alpha=0.9, beta=0.1, learning_rate=0.01)
        accuracy_regulator = ExperientialBehavioralRegulator(alpha=0.1, beta=0.9, learning_rate=0.01)
        
        high_empathy_context = create_context_event(stability=0.9, threat_level=0.8, appropriateness=0.9)
        low_accuracy_feedback = create_feedback_event(predicted=0.3, actual=0.4, accuracy=0.5)
        
        empathy_reward = empathy_regulator.calculate_reward(high_empathy_context, low_accuracy_feedback)
        accuracy_reward = accuracy_regulator.calculate_reward(high_empathy_context, low_accuracy_feedback)
        
        # Empathy-focused regulator should give higher reward for good context despite poor accuracy
        self.assertGreater(empathy_reward, accuracy_reward)
    
    def test_parameter_adaptation(self):
        """Test parameter adaptation based on performance feedback"""
        initial_stats = self.regulator.get_stats()
        initial_alpha = initial_stats['alpha']
        initial_beta = initial_stats['beta']
        
        # Adapt with high performance feedback
        self.regulator.adapt_parameters(0.9)
        
        adapted_stats = self.regulator.get_stats()
        adapted_alpha = adapted_stats['alpha']
        adapted_beta = adapted_stats['beta']
        
        # Parameters should remain valid
        self.assertGreaterEqual(adapted_alpha, 0.0)
        self.assertLessEqual(adapted_alpha, 1.0)
        self.assertGreaterEqual(adapted_beta, 0.0)
        self.assertLessEqual(adapted_beta, 1.0)
        self.assertAlmostEqual(adapted_alpha + adapted_beta, 1.0, places=3)


class TestBDHMemoryEQIQIntegration(unittest.TestCase):
    """Test BDHMemory integration with EQ/IQ regulator"""
    
    def setUp(self):
        self.memory = BDHMemory()
    
    def test_bdh_memory_has_eq_iq_regulator(self):
        """Test that BDHMemory has integrated EQ/IQ regulator"""
        stats = self.memory.get_eq_iq_stats()
        self.assertIn('alpha', stats)
        self.assertIn('beta', stats)
        self.assertIn('learning_rate', stats)
    
    def test_eq_iq_adaptation(self):
        """Test EQ/IQ parameter adaptation in BDH memory"""
        initial_stats = self.memory.get_eq_iq_stats()
        initial_alpha = initial_stats['alpha']
        
        # Adapt parameters
        self.memory.adapt_eq_iq_parameters(0.8)
        
        adapted_stats = self.memory.get_eq_iq_stats()
        adapted_alpha = adapted_stats['alpha']
        
        # Parameters should remain valid
        self.assertGreaterEqual(adapted_alpha, 0.0)
        self.assertLessEqual(adapted_alpha, 1.0)
    
    def test_reward_gated_update_with_eq_iq(self):
        """Test reward-gated update with EQ/IQ modulation"""
        trace_id = "test_trace_001"
        vector = np.array([0.1, 0.2, 0.3, 0.4, 0.5])
        
        # Add initial memory trace
        self.memory.add_or_update(trace_id, vector, 0.5)
        
        # Create context and feedback events
        context = create_context_event(stability=0.8, coherence=0.7, relevance=0.9)
        feedback = create_feedback_event(predicted=0.5, actual=0.5, accuracy=0.85, precision=0.75, confidence=0.9)
        
        # Apply reward-gated update
        state_vec = np.array([0.2, 0.3, 0.4, 0.5, 0.6])
        self.memory.reward_gated_update(trace_id, state_vec, 0.8, context, feedback)
        
        # Verify the trace was updated
        self.assertIn(trace_id, self.memory.storage)
        entry = self.memory.storage[trace_id]
        
        self.assertGreater(entry["cumulative_reward"], 0.0)
        self.assertGreater(len(entry["eq_iq_history"]), 0)
        
        # Check EQ/IQ history structure
        latest_metrics = entry["eq_iq_history"][-1]
        self.assertIn("eq", latest_metrics)
        self.assertIn("iq", latest_metrics)
        self.assertIn("balance", latest_metrics)
        self.assertIn("timestamp", latest_metrics)
        
        # Verify metrics are in valid range
        self.assertGreaterEqual(latest_metrics["eq"], 0.0)
        self.assertLessEqual(latest_metrics["eq"], 1.0)
        self.assertGreaterEqual(latest_metrics["iq"], 0.0)
        self.assertLessEqual(latest_metrics["iq"], 1.0)
        self.assertGreaterEqual(latest_metrics["balance"], 0.0)
        self.assertLessEqual(latest_metrics["balance"], 1.0)
    
    def test_eq_iq_history_tracking(self):
        """Test EQ/IQ history tracking over multiple updates"""
        trace_id = "history_test_trace"
        vector = np.array([0.1, 0.2, 0.3])
        
        self.memory.add_or_update(trace_id, vector, 0.0)
        
        # Apply multiple updates to build history
        for i in range(5):
            context = ContextEvent(
                stability=0.5 + i * 0.1,
                coherence=0.6 + i * 0.05,
                relevance=0.7 + i * 0.02
            )
            
            feedback = FeedbackEvent(
                accuracy=0.4 + i * 0.1,
                precision=0.5 + i * 0.08,
                confidence=0.6 + i * 0.06
            )
            
            state_vec = np.array([0.1 + i * 0.1, 0.2, 0.3])
            self.memory.reward_gated_update(trace_id, state_vec, 0.5 + i * 0.1, context, feedback)
        
        # Check that history was recorded
        entry = self.memory.storage[trace_id]
        self.assertEqual(len(entry["eq_iq_history"]), 5)
        
        # Verify history is chronologically ordered
        for i in range(1, len(entry["eq_iq_history"])):
            self.assertGreaterEqual(
                entry["eq_iq_history"][i]["timestamp"],
                entry["eq_iq_history"][i-1]["timestamp"]
            )
    
    def test_memory_eq_iq_summary(self):
        """Test memory-wide EQ/IQ summary statistics"""
        # Add multiple traces with EQ/IQ history
        for i in range(3):
            trace_id = f"summary_test_trace_{i}"
            vector = np.array([0.1 * (i+1), 0.2 * (i+1), 0.3 * (i+1)])
            self.memory.add_or_update(trace_id, vector, 0.1 * i)
            
            context = create_context_event(stability=0.6 + i * 0.1, coherence=0.7 + i * 0.05, relevance=0.8)
            feedback = create_feedback_event(predicted=0.5, actual=0.5, accuracy=0.5 + i * 0.15, precision=0.6 + i * 0.1, confidence=0.7 + i * 0.05)
            
            state_vec = np.array([0.2 * (i+1), 0.3 * (i+1), 0.4 * (i+1)])
            self.memory.reward_gated_update(trace_id, state_vec, 0.6 + i * 0.1, context, feedback)
        
        # Get summary statistics
        summary = self.memory.get_memory_eq_iq_summary()
        
        self.assertIn("avg_eq", summary)
        self.assertIn("avg_iq", summary)
        self.assertIn("avg_balance", summary)
        self.assertIn("trace_count", summary)
        self.assertIn("eq_std", summary)
        self.assertIn("iq_std", summary)
        
        self.assertEqual(summary["trace_count"], 3)
        self.assertGreaterEqual(summary["avg_eq"], 0.0)
        self.assertLessEqual(summary["avg_eq"], 1.0)
        self.assertGreaterEqual(summary["avg_iq"], 0.0)
        self.assertLessEqual(summary["avg_iq"], 1.0)


class TestComprehensiveEQIQWorkflow(unittest.TestCase):
    """Test comprehensive EQ/IQ workflow scenarios"""
    
    def setUp(self):
        self.memory = BDHMemory()
    
    def test_complete_learning_workflow(self):
        """Test a complete learning workflow with EQ/IQ modulation"""
        trace_id = "workflow_test"
        initial_vector = np.array([0.2, 0.4, 0.6, 0.8])
        self.memory.add_or_update(trace_id, initial_vector, 0.1)
        
        # Simulate multiple learning episodes with varying contexts and feedback
        scenarios = [
            # High empathy scenario (stable context, moderate accuracy)
            (create_context_event(stability=0.9, coherence=0.8, relevance=0.85),
             create_feedback_event(predicted=0.5, actual=0.5, accuracy=0.6, precision=0.65, confidence=0.7), 0.7),
            
            # High accuracy scenario (unstable context, high accuracy)
            (create_context_event(stability=0.4, coherence=0.5, relevance=0.6),
             create_feedback_event(predicted=0.5, actual=0.5, accuracy=0.95, precision=0.9, confidence=0.85), 0.8),
            
            # Balanced scenario
            (create_context_event(stability=0.7, coherence=0.75, relevance=0.8),
             create_feedback_event(predicted=0.5, actual=0.5, accuracy=0.8, precision=0.75, confidence=0.8), 0.85),
        ]
        
        for i, (context, feedback, reward) in enumerate(scenarios):
            state_vec = np.array([0.1 + i * 0.1, 0.3, 0.5, 0.7])
            self.memory.reward_gated_update(trace_id, state_vec, reward, context, feedback)
        
        # Verify comprehensive learning occurred
        entry = self.memory.storage[trace_id]
        self.assertEqual(len(entry["eq_iq_history"]), 3)
        self.assertGreater(entry["cumulative_reward"], 0.0)
        
        # Check that EQ/IQ balance evolved over time
        first_balance = entry["eq_iq_history"][0]["balance"]
        last_balance = entry["eq_iq_history"][2]["balance"]
        
        # Balance should be within valid range
        self.assertGreaterEqual(first_balance, 0.0)
        self.assertLessEqual(first_balance, 1.0)
        self.assertGreaterEqual(last_balance, 0.0)
        self.assertLessEqual(last_balance, 1.0)
        
        # Test adaptation based on overall performance
        initial_stats = self.memory.get_eq_iq_stats()
        self.memory.adapt_eq_iq_parameters(0.85)  # Good overall performance
        adapted_stats = self.memory.get_eq_iq_stats()
        
        # Adaptation should maintain parameter validity
        self.assertGreaterEqual(adapted_stats["alpha"], 0.0)
        self.assertGreaterEqual(adapted_stats["beta"], 0.0)
        self.assertAlmostEqual(adapted_stats["alpha"] + adapted_stats["beta"], 1.0, places=3)
    
    def test_bidirectional_hebbian_learning(self):
        """Test bidirectional Hebbian learning with EQ/IQ modulation"""
        trace_id = "hebbian_test"
        vector = np.array([0.5, 0.5, 0.5])
        self.memory.add_or_update(trace_id, vector, 0.0)
        
        # Apply updates with different EQ/IQ balances
        high_eq_context = create_context_event(stability=0.9, coherence=0.8, relevance=0.9)
        low_iq_feedback = create_feedback_event(predicted=0.5, actual=0.5, accuracy=0.3, precision=0.4, confidence=0.5)
        
        high_iq_context = create_context_event(stability=0.3, coherence=0.4, relevance=0.5)
        high_iq_feedback = create_feedback_event(predicted=0.5, actual=0.5, accuracy=0.9, precision=0.8, confidence=0.9)
        
        state_vec = np.array([0.6, 0.6, 0.6])
        
        # Apply high EQ scenario
        self.memory.reward_gated_update(trace_id, state_vec, 0.6, high_eq_context, low_iq_feedback)
        
        # Apply high IQ scenario
        self.memory.reward_gated_update(trace_id, state_vec, 0.8, high_iq_context, high_iq_feedback)
        
        # Verify both updates were processed
        entry = self.memory.storage[trace_id]
        self.assertEqual(len(entry["eq_iq_history"]), 2)
        
        # Check that different scenarios produced different EQ/IQ balances
        first_eq = entry["eq_iq_history"][0]["eq"]
        first_iq = entry["eq_iq_history"][0]["iq"]
        second_eq = entry["eq_iq_history"][1]["eq"]
        second_iq = entry["eq_iq_history"][1]["iq"]
        
        # First scenario should have higher EQ, second should have higher IQ
        self.assertGreater(first_eq, second_eq)
        self.assertLess(first_iq, second_iq)


if __name__ == '__main__':
    # Run all tests
    unittest.main(verbosity=2)