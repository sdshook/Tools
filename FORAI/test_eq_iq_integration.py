#!/usr/bin/env python3
"""
Comprehensive test suite for FORAI EQ/IQ integration
Tests the ExperientialBehavioralRegulator and BDHMemory integration in forensic context
"""

import unittest
import numpy as np
import tempfile
import os
import sqlite3
import json
from pathlib import Path

from FORAI import BDHMemory, SimEmbedder, PSIIndex
from eq_iq_regulator import ExperientialBehavioralRegulator, ContextEvent, FeedbackEvent


class TestFORAIEQIQRegulator(unittest.TestCase):
    """Test the EQ/IQ regulator functionality in FORAI context"""
    
    def setUp(self):
        self.regulator = ExperientialBehavioralRegulator(alpha=0.6, beta=0.4, learning_rate=0.01)
    
    def test_forensic_context_modeling(self):
        """Test EQ/IQ regulator with forensic-specific context events"""
        # Forensic context: stable evidence, high coherence, high relevance
        forensic_context = ContextEvent(
            stability=0.9,  # Evidence integrity
            coherence=0.85,  # Timeline consistency
            relevance=0.9   # Case relevance
        )
        
        # Forensic feedback: high accuracy detection, high precision, high confidence
        forensic_feedback = FeedbackEvent(
            accuracy=0.9,   # Threat detection accuracy
            precision=0.85, # False positive rate
            confidence=0.8  # Analysis confidence
        )
        
        reward = self.regulator.calculate_reward(forensic_context, forensic_feedback)
        
        # High-quality forensic analysis should yield high reward
        self.assertGreater(reward, 0.7)
        self.assertLessEqual(reward, 1.0)
    
    def test_forensic_empathy_vs_accuracy_balance(self):
        """Test EQ/IQ balance in forensic analysis scenarios"""
        empathy_regulator = ExperientialBehavioralRegulator(alpha=0.8, beta=0.2, learning_rate=0.01)
        accuracy_regulator = ExperientialBehavioralRegulator(alpha=0.2, beta=0.8, learning_rate=0.01)
        
        # Scenario: Stable evidence context but uncertain threat detection
        stable_context = ContextEvent(stability=0.9, coherence=0.8, relevance=0.85)
        uncertain_feedback = FeedbackEvent(accuracy=0.5, precision=0.6, confidence=0.4)
        
        empathy_reward = empathy_regulator.calculate_reward(stable_context, uncertain_feedback)
        accuracy_reward = accuracy_regulator.calculate_reward(stable_context, uncertain_feedback)
        
        # Empathy-focused should value stable context despite uncertain detection
        self.assertGreater(empathy_reward, accuracy_reward)


class TestFORAIBDHMemoryEQIQIntegration(unittest.TestCase):
    """Test FORAI BDHMemory integration with EQ/IQ regulator"""
    
    def setUp(self):
        # Create temporary database for testing
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_forai_bdh.db"
        self.memory = BDHMemory("forai", self.db_path)
    
    def tearDown(self):
        # Clean up temporary files
        if self.db_path.exists():
            self.db_path.unlink()
        os.rmdir(self.temp_dir)
    
    def test_database_schema_with_eq_iq(self):
        """Test that database schema includes EQ/IQ history column"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("PRAGMA table_info(bdh_traces)")
            columns = [row[1] for row in cursor.fetchall()]
            
            self.assertIn("eq_iq_history", columns)
    
    def test_forai_bdh_memory_has_eq_iq_regulator(self):
        """Test that FORAI BDHMemory has integrated EQ/IQ regulator"""
        stats = self.memory.get_eq_iq_stats()
        self.assertIn('alpha', stats)
        self.assertIn('beta', stats)
        self.assertIn('learning_rate', stats)
        self.assertEqual(stats['alpha'], 0.6)
        self.assertEqual(stats['beta'], 0.4)
    
    def test_forensic_reward_gated_update(self):
        """Test reward-gated update with forensic context"""
        trace_id = "forensic_trace_001"
        vector = np.array([0.1, 0.2, 0.3, 0.4, 0.5], dtype=np.float32)
        
        # Add initial forensic memory trace
        self.memory.add_or_update(trace_id, vector, 0.5)
        
        # Forensic context: evidence analysis
        context = ContextEvent(
            stability=0.85,  # Evidence integrity
            coherence=0.8,   # Timeline consistency
            relevance=0.9    # Case relevance
        )
        
        # Forensic feedback: threat detection results
        feedback = FeedbackEvent(
            accuracy=0.9,    # Detection accuracy
            precision=0.85,  # False positive control
            confidence=0.8   # Analysis confidence
        )
        
        # Apply forensic reward-gated update
        state_vec = np.array([0.2, 0.3, 0.4, 0.5, 0.6], dtype=np.float32)
        self.memory.reward_gated_update(trace_id, state_vec, 0.8, context, feedback)
        
        # Verify database update
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT reward_count, consolidation_score, eq_iq_history 
                FROM bdh_traces WHERE trace_id = ?
            """, (trace_id,))
            
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            
            reward_count, consolidation_score, eq_iq_history_str = row
            self.assertEqual(reward_count, 1)
            self.assertGreater(consolidation_score, 0.0)
            
            # Parse and verify EQ/IQ history
            eq_iq_history = json.loads(eq_iq_history_str)
            self.assertEqual(len(eq_iq_history), 1)
            
            metrics = eq_iq_history[0]
            self.assertIn("eq", metrics)
            self.assertIn("iq", metrics)
            self.assertIn("balance", metrics)
            self.assertIn("timestamp", metrics)
            self.assertIn("reward", metrics)
            self.assertIn("modulated_reward", metrics)
            
            # Verify forensic metrics are in valid range
            self.assertGreaterEqual(metrics["eq"], 0.0)
            self.assertLessEqual(metrics["eq"], 1.0)
            self.assertGreaterEqual(metrics["iq"], 0.0)
            self.assertLessEqual(metrics["iq"], 1.0)
    
    def test_forensic_eq_iq_history_persistence(self):
        """Test EQ/IQ history persistence in database"""
        trace_id = "persistence_test_trace"
        vector = np.array([0.3, 0.6, 0.9], dtype=np.float32)
        
        self.memory.add_or_update(trace_id, vector, 0.0)
        
        # Apply multiple forensic updates
        forensic_scenarios = [
            # High-confidence malware detection
            (ContextEvent(stability=0.9, coherence=0.85, relevance=0.95),
             FeedbackEvent(accuracy=0.95, precision=0.9, confidence=0.9), 0.9),
            
            # Uncertain network activity analysis
            (ContextEvent(stability=0.6, coherence=0.7, relevance=0.8),
             FeedbackEvent(accuracy=0.6, precision=0.65, confidence=0.5), 0.6),
            
            # Clear evidence of data exfiltration
            (ContextEvent(stability=0.95, coherence=0.9, relevance=0.9),
             FeedbackEvent(accuracy=0.9, precision=0.85, confidence=0.85), 0.85),
        ]
        
        for i, (context, feedback, reward) in enumerate(forensic_scenarios):
            state_vec = np.array([0.2 + i * 0.1, 0.4, 0.6], dtype=np.float32)
            self.memory.reward_gated_update(trace_id, state_vec, reward, context, feedback)
        
        # Verify persistence in database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT eq_iq_history FROM bdh_traces WHERE trace_id = ?", (trace_id,))
            eq_iq_history_str = cursor.fetchone()[0]
            
            eq_iq_history = json.loads(eq_iq_history_str)
            self.assertEqual(len(eq_iq_history), 3)
            
            # Verify chronological ordering
            for i in range(1, len(eq_iq_history)):
                self.assertGreaterEqual(
                    eq_iq_history[i]["timestamp"],
                    eq_iq_history[i-1]["timestamp"]
                )
    
    def test_forensic_memory_eq_iq_summary(self):
        """Test memory-wide EQ/IQ summary for forensic analysis"""
        # Create multiple forensic traces
        forensic_traces = [
            ("malware_detection", np.array([0.8, 0.9, 0.7], dtype=np.float32)),
            ("network_analysis", np.array([0.6, 0.7, 0.8], dtype=np.float32)),
            ("data_recovery", np.array([0.9, 0.8, 0.6], dtype=np.float32)),
        ]
        
        for trace_id, vector in forensic_traces:
            self.memory.add_or_update(trace_id, vector, 0.1)
            
            # Apply forensic context and feedback
            context = ContextEvent(
                stability=0.8 + np.random.random() * 0.15,
                coherence=0.7 + np.random.random() * 0.2,
                relevance=0.85 + np.random.random() * 0.1
            )
            
            feedback = FeedbackEvent(
                accuracy=0.7 + np.random.random() * 0.25,
                precision=0.6 + np.random.random() * 0.3,
                confidence=0.65 + np.random.random() * 0.25
            )
            
            state_vec = vector + np.random.random(3) * 0.1
            self.memory.reward_gated_update(trace_id, state_vec, 0.7 + np.random.random() * 0.2, context, feedback)
        
        # Get forensic analysis summary
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
    
    def test_eq_iq_adaptation_in_forensic_context(self):
        """Test EQ/IQ parameter adaptation based on forensic performance"""
        initial_stats = self.memory.get_eq_iq_stats()
        initial_alpha = initial_stats['alpha']
        initial_beta = initial_stats['beta']
        
        # Simulate high forensic analysis performance
        self.memory.adapt_eq_iq_parameters(0.9)
        
        adapted_stats = self.memory.get_eq_iq_stats()
        adapted_alpha = adapted_stats['alpha']
        adapted_beta = adapted_stats['beta']
        
        # Parameters should remain valid after adaptation
        self.assertGreaterEqual(adapted_alpha, 0.0)
        self.assertLessEqual(adapted_alpha, 1.0)
        self.assertGreaterEqual(adapted_beta, 0.0)
        self.assertLessEqual(adapted_beta, 1.0)
        self.assertAlmostEqual(adapted_alpha + adapted_beta, 1.0, places=3)


class TestForensicEQIQWorkflow(unittest.TestCase):
    """Test comprehensive forensic EQ/IQ workflow scenarios"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_forensic_workflow.db"
        self.memory = BDHMemory("forai", self.db_path)
    
    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()
        os.rmdir(self.temp_dir)
    
    def test_complete_forensic_investigation_workflow(self):
        """Test complete forensic investigation with EQ/IQ modulation"""
        case_id = "forensic_case_001"
        initial_evidence = np.array([0.5, 0.7, 0.6, 0.8], dtype=np.float32)
        self.memory.add_or_update(case_id, initial_evidence, 0.2)
        
        # Simulate forensic investigation phases
        investigation_phases = [
            # Phase 1: Initial evidence collection (high stability, moderate accuracy)
            ("evidence_collection", 
             ContextEvent(stability=0.9, coherence=0.7, relevance=0.8),
             FeedbackEvent(accuracy=0.7, precision=0.75, confidence=0.6), 0.7),
            
            # Phase 2: Malware analysis (moderate stability, high accuracy)
            ("malware_analysis",
             ContextEvent(stability=0.6, coherence=0.8, relevance=0.95),
             FeedbackEvent(accuracy=0.9, precision=0.85, confidence=0.8), 0.85),
            
            # Phase 3: Timeline reconstruction (high stability, high accuracy)
            ("timeline_reconstruction",
             ContextEvent(stability=0.95, coherence=0.9, relevance=0.9),
             FeedbackEvent(accuracy=0.85, precision=0.8, confidence=0.9), 0.9),
            
            # Phase 4: Report generation (very high stability, moderate accuracy)
            ("report_generation",
             ContextEvent(stability=0.98, coherence=0.95, relevance=0.85),
             FeedbackEvent(accuracy=0.75, precision=0.8, confidence=0.95), 0.8),
        ]
        
        for i, (phase, context, feedback, reward) in enumerate(investigation_phases):
            evidence_state = initial_evidence + np.random.random(4) * 0.1
            self.memory.reward_gated_update(case_id, evidence_state, reward, context, feedback)
        
        # Verify comprehensive forensic learning occurred
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT reward_count, consolidation_score, eq_iq_history 
                FROM bdh_traces WHERE trace_id = ?
            """, (case_id,))
            
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            
            reward_count, consolidation_score, eq_iq_history_str = row
            self.assertEqual(reward_count, 4)  # Four investigation phases
            self.assertGreater(consolidation_score, 0.0)
            
            eq_iq_history = json.loads(eq_iq_history_str)
            self.assertEqual(len(eq_iq_history), 4)
            
            # Verify forensic investigation progression
            for i, metrics in enumerate(eq_iq_history):
                self.assertIn("eq", metrics)
                self.assertIn("iq", metrics)
                self.assertIn("balance", metrics)
                
                # All metrics should be valid
                self.assertGreaterEqual(metrics["eq"], 0.0)
                self.assertLessEqual(metrics["eq"], 1.0)
                self.assertGreaterEqual(metrics["iq"], 0.0)
                self.assertLessEqual(metrics["iq"], 1.0)
                self.assertGreaterEqual(metrics["balance"], 0.0)
                self.assertLessEqual(metrics["balance"], 1.0)
        
        # Test adaptation based on overall investigation performance
        initial_stats = self.memory.get_eq_iq_stats()
        self.memory.adapt_eq_iq_parameters(0.85)  # Good investigation performance
        adapted_stats = self.memory.get_eq_iq_stats()
        
        # Adaptation should maintain parameter validity
        self.assertGreaterEqual(adapted_stats["alpha"], 0.0)
        self.assertGreaterEqual(adapted_stats["beta"], 0.0)
        self.assertAlmostEqual(adapted_stats["alpha"] + adapted_stats["beta"], 1.0, places=3)
    
    def test_forensic_threat_detection_scenarios(self):
        """Test EQ/IQ balance in various threat detection scenarios"""
        threat_scenarios = [
            # APT detection: High empathy needed for context, high accuracy for detection
            ("apt_detection", 
             ContextEvent(stability=0.7, coherence=0.8, relevance=0.95),
             FeedbackEvent(accuracy=0.9, precision=0.85, confidence=0.8)),
            
            # Insider threat: Very high empathy for behavioral context
            ("insider_threat",
             ContextEvent(stability=0.9, coherence=0.85, relevance=0.9),
             FeedbackEvent(accuracy=0.7, precision=0.6, confidence=0.65)),
            
            # Malware family classification: High accuracy focus
            ("malware_classification",
             ContextEvent(stability=0.6, coherence=0.7, relevance=0.8),
             FeedbackEvent(accuracy=0.95, precision=0.9, confidence=0.85)),
        ]
        
        for threat_type, context, feedback in threat_scenarios:
            vector = np.random.random(5).astype(np.float32)
            self.memory.add_or_update(threat_type, vector, 0.1)
            
            state_vec = vector + np.random.random(5).astype(np.float32) * 0.1
            reward = 0.6 + np.random.random() * 0.3
            
            self.memory.reward_gated_update(threat_type, state_vec, reward, context, feedback)
        
        # Verify all threat scenarios were processed
        summary = self.memory.get_memory_eq_iq_summary()
        self.assertEqual(summary["trace_count"], 3)
        
        # Check that different threat types produced varied EQ/IQ balances
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT trace_id, eq_iq_history FROM bdh_traces")
            
            eq_balances = {}
            iq_balances = {}
            
            for trace_id, eq_iq_history_str in cursor.fetchall():
                eq_iq_history = json.loads(eq_iq_history_str)
                if eq_iq_history:
                    metrics = eq_iq_history[0]
                    eq_balances[trace_id] = metrics["eq"]
                    iq_balances[trace_id] = metrics["iq"]
            
            # Insider threat should have higher EQ (contextual understanding)
            # Malware classification should have higher IQ (accuracy focus)
            if "insider_threat" in eq_balances and "malware_classification" in eq_balances:
                self.assertGreater(eq_balances["insider_threat"], eq_balances["malware_classification"])
                self.assertLess(iq_balances["insider_threat"], iq_balances["malware_classification"])


if __name__ == '__main__':
    # Run all tests
    unittest.main(verbosity=2)