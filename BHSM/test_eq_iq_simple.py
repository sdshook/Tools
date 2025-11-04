#!/usr/bin/env python3
"""
Simple test suite for BHSM EQ/IQ integration
Tests basic functionality of the ExperientialBehavioralRegulator and BDHMemory integration
"""

import unittest
import numpy as np
import time
from BHSM import BDHMemory
from eq_iq_regulator import ExperientialBehavioralRegulator, ContextEvent, FeedbackEvent


class TestBHSMEQIQIntegration(unittest.TestCase):
    """Test BHSM EQ/IQ integration"""
    
    def setUp(self):
        self.memory = BDHMemory()
        self.regulator = ExperientialBehavioralRegulator(alpha=0.6, beta=0.4, learning_rate=0.01)
    
    def test_regulator_initialization(self):
        """Test EQ/IQ regulator initialization"""
        stats = self.regulator.get_stats()
        self.assertEqual(stats['alpha'], 0.6)
        self.assertEqual(stats['beta'], 0.4)
        self.assertEqual(stats['learning_rate'], 0.01)
    
    def test_bdh_memory_has_eq_iq_regulator(self):
        """Test that BDHMemory has integrated EQ/IQ regulator"""
        stats = self.memory.get_eq_iq_stats()
        self.assertIn('alpha', stats)
        self.assertIn('beta', stats)
        self.assertIn('learning_rate', stats)
    
    def test_context_and_feedback_events(self):
        """Test creating context and feedback events"""
        context = ContextEvent(
            timestamp=time.time(),
            context_stability=0.8,
            threat_level=0.7,
            response_appropriateness=0.9
        )
        
        feedback = FeedbackEvent(
            timestamp=time.time(),
            predicted_threat=0.85,
            actual_threat=0.75,
            accuracy=0.9
        )
        
        self.assertEqual(context.context_stability, 0.8)
        self.assertEqual(feedback.predicted_threat, 0.85)
    
    def test_reward_calculation(self):
        """Test EQ/IQ balanced reward calculation"""
        context = ContextEvent(
            timestamp=time.time(),
            context_stability=0.8,
            threat_level=0.7,
            response_appropriateness=0.9
        )
        
        feedback = FeedbackEvent(
            timestamp=time.time(),
            predicted_threat=0.85,
            actual_threat=0.75,
            accuracy=0.9
        )
        
        balance = self.regulator.calculate_eq_iq_balance(context, feedback)
        
        # Balance should be between 0 and 1
        self.assertGreaterEqual(balance.balance, 0.0)
        self.assertLessEqual(balance.balance, 1.0)
        self.assertGreaterEqual(balance.eq, 0.0)
        self.assertLessEqual(balance.eq, 1.0)
        self.assertGreaterEqual(balance.iq, 0.0)
        self.assertLessEqual(balance.iq, 1.0)
    
    def test_bdh_memory_reward_gated_update(self):
        """Test reward-gated update with EQ/IQ modulation"""
        trace_id = "test_trace_001"
        vector = np.random.random(32) * 0.5 + 0.25  # Use 32-dimensional vector
        
        # Add initial memory trace
        self.memory.add_or_update(trace_id, vector, 0.5)
        
        # Create context and feedback events
        context = ContextEvent(
            timestamp=time.time(),
            context_stability=0.8,
            threat_level=0.7,
            response_appropriateness=0.9
        )
        
        feedback = FeedbackEvent(
            timestamp=time.time(),
            predicted_threat=0.85,
            actual_threat=0.75,
            accuracy=0.9
        )
        
        # Apply reward-gated update with correct method signature
        state_vec = vector + np.random.random(32) * 0.1  # Similar vector with small variation
        self.memory.reward_gated_update(
            trace_id, 
            state_vec, 
            0.8,  # reward
            context.context_stability,
            context.threat_level,
            context.response_appropriateness,
            feedback.predicted_threat,
            feedback.actual_threat
        )
        
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
    
    def test_eq_iq_parameter_adaptation(self):
        """Test EQ/IQ parameter adaptation"""
        initial_stats = self.memory.get_eq_iq_stats()
        initial_alpha = initial_stats['alpha']
        
        # Adapt parameters
        self.memory.adapt_eq_iq_parameters(0.8)
        
        adapted_stats = self.memory.get_eq_iq_stats()
        adapted_alpha = adapted_stats['alpha']
        
        # Parameters should remain valid
        self.assertGreaterEqual(adapted_alpha, 0.0)
        self.assertLessEqual(adapted_alpha, 1.0)
    
    def test_memory_eq_iq_summary(self):
        """Test memory-wide EQ/IQ summary statistics"""
        # Add a trace with EQ/IQ history
        trace_id = "summary_test_trace"
        vector = np.random.random(32) * 0.5 + 0.25  # Use 32-dimensional vector
        self.memory.add_or_update(trace_id, vector, 0.1)
        
        context = ContextEvent(
            timestamp=time.time(),
            context_stability=0.6,
            threat_level=0.7,
            response_appropriateness=0.8
        )
        
        feedback = FeedbackEvent(
            timestamp=time.time(),
            predicted_threat=0.5,
            actual_threat=0.6,
            accuracy=0.7
        )
        
        state_vec = vector + np.random.random(32) * 0.1  # Similar vector with small variation
        self.memory.reward_gated_update(
            trace_id, 
            state_vec, 
            0.6,  # reward
            context.context_stability,
            context.threat_level,
            context.response_appropriateness,
            feedback.predicted_threat,
            feedback.actual_threat
        )
        
        # Get summary statistics
        summary = self.memory.get_memory_eq_iq_summary()
        
        self.assertIn("avg_eq", summary)
        self.assertIn("avg_iq", summary)
        self.assertIn("avg_balance", summary)
        self.assertIn("trace_count", summary)
        self.assertIn("eq_std", summary)
        self.assertIn("iq_std", summary)
        
        self.assertEqual(summary["trace_count"], 1)
        self.assertGreaterEqual(summary["avg_eq"], 0.0)
        self.assertLessEqual(summary["avg_eq"], 1.0)


if __name__ == '__main__':
    unittest.main(verbosity=2)