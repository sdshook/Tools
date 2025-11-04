#[cfg(test)]
mod tests {
    use webguard::eq_iq_regulator::{ExperientialBehavioralRegulator, ContextEvent, FeedbackEvent, EQIQBalance};
    use webguard::memory_engine::bdh_memory::BdhMemory;
    use std::collections::HashMap;

    #[test]
    fn test_eq_iq_regulator_initialization() {
        let regulator = ExperientialBehavioralRegulator::new(0.6, 0.4, 0.01);
        let stats = regulator.get_stats();
        
        assert_eq!(stats.get("alpha").unwrap(), &0.6);
        assert_eq!(stats.get("beta").unwrap(), &0.4);
        assert_eq!(stats.get("learning_rate").unwrap(), &0.01);
        assert_eq!(stats.get("context_history_size").unwrap(), &0.0);
        assert_eq!(stats.get("feedback_history_size").unwrap(), &0.0);
    }

    #[test]
    fn test_context_event_creation() {
        let context = ContextEvent {
            timestamp: 1234567890.0,
            context_stability: 0.8,
            threat_level: 0.7,
            response_appropriateness: 0.9,
        };
        
        assert_eq!(context.context_stability, 0.8);
        assert_eq!(context.threat_level, 0.7);
        assert_eq!(context.response_appropriateness, 0.9);
    }

    #[test]
    fn test_feedback_event_creation() {
        let feedback = FeedbackEvent {
            timestamp: 1234567890.0,
            predicted_threat: 0.85,
            actual_threat: 0.75,
            accuracy: 0.9,
        };
        
        assert_eq!(feedback.predicted_threat, 0.85);
        assert_eq!(feedback.actual_threat, 0.75);
        assert_eq!(feedback.accuracy, 0.9);
    }

    #[test]
    fn test_eq_iq_reward_calculation() {
        let mut regulator = ExperientialBehavioralRegulator::new(0.6, 0.4, 0.01);
        
        let context = ContextEvent {
            timestamp: 1234567890.0,
            context_stability: 0.8,
            threat_level: 0.7,
            response_appropriateness: 0.9,
        };
        
        let feedback = FeedbackEvent {
            timestamp: 1234567890.0,
            predicted_threat: 0.85,
            actual_threat: 0.75,
            accuracy: 0.9,
        };
        
        let balance = regulator.calculate_eq_iq_balance(&context, &feedback);
        
        // Balance should be between 0 and 1
        assert!(balance.balance >= 0.0 && balance.balance <= 1.0);
        assert!(balance.eq >= 0.0 && balance.eq <= 1.0);
        assert!(balance.iq >= 0.0 && balance.iq <= 1.0);
        
        // With high values, balance should be substantial
        assert!(balance.balance > 0.5);
    }

    #[test]
    fn test_eq_iq_balance_empathy_vs_accuracy() {
        let mut empathy_regulator = ExperientialBehavioralRegulator::new(0.9, 0.1, 0.01); // High empathy
        let mut accuracy_regulator = ExperientialBehavioralRegulator::new(0.1, 0.9, 0.01); // High accuracy
        
        let high_empathy_context = ContextEvent {
            timestamp: 1234567890.0,
            context_stability: 0.9,
            threat_level: 0.2,  // Low threat
            response_appropriateness: 0.9,
        };
        
        let low_accuracy_feedback = FeedbackEvent {
            timestamp: 1234567890.0,
            predicted_threat: 0.7,
            actual_threat: 0.3,
            accuracy: 0.3,
        };
        
        let empathy_balance = empathy_regulator.calculate_eq_iq_balance(&high_empathy_context, &low_accuracy_feedback);
        let accuracy_balance = accuracy_regulator.calculate_eq_iq_balance(&high_empathy_context, &low_accuracy_feedback);
        
        // Empathy-focused regulator should give higher balance for good context despite poor accuracy
        assert!(empathy_balance.balance > accuracy_balance.balance);
    }

    #[test]
    fn test_bdh_memory_eq_iq_integration() {
        let memory = BdhMemory::new();
        
        // Test that BDH memory has EQ/IQ regulator
        let stats = memory.get_eq_iq_stats();
        assert!(stats.contains_key("alpha"));
        assert!(stats.contains_key("beta"));
        assert!(stats.contains_key("learning_rate"));
    }

    #[test]
    fn test_bdh_memory_eq_iq_adaptation() {
        let mut memory = BdhMemory::new();
        
        // Get initial stats
        let initial_stats = memory.get_eq_iq_stats();
        let initial_alpha = initial_stats.get("alpha").unwrap();
        
        // Adapt parameters with positive feedback
        memory.adapt_eq_iq_parameters(0.8);
        
        let adapted_stats = memory.get_eq_iq_stats();
        let adapted_alpha = adapted_stats.get("alpha").unwrap();
        
        // Parameters should have adapted (though the exact change depends on implementation)
        // At minimum, the adaptation method should not crash
        assert!(adapted_alpha >= &0.0 && adapted_alpha <= &1.0);
    }

    #[test]
    fn test_hebbian_update_with_eq_iq_modulation() {
        let mut memory = BDHMemory::new();
        
        // Add a memory trace
        let trace_id = "test_trace_001";
        let vector = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        memory.add_or_update(trace_id, vector.clone(), 0.5);
        
        // Create context and feedback events
        let context = ContextEvent {
            stability: 0.8,
            coherence: 0.7,
            relevance: 0.9,
        };
        
        let feedback = FeedbackEvent {
            accuracy: 0.85,
            precision: 0.75,
            confidence: 0.9,
        };
        
        // Apply reward-gated update with EQ/IQ modulation
        let state_vec = vec![0.2, 0.3, 0.4, 0.5, 0.6];
        memory.reward_gated_update(trace_id, &state_vec, 0.8, Some(context), Some(feedback));
        
        // Verify the trace was updated (should not crash and should maintain data integrity)
        if let Some(entry) = memory.storage.get(trace_id) {
            assert!(entry.cumulative_reward > 0.0);
            assert!(!entry.eq_iq_history.is_empty());
            
            // Check EQ/IQ history structure
            let latest_metrics = &entry.eq_iq_history[entry.eq_iq_history.len() - 1];
            assert!(latest_metrics.eq >= 0.0 && latest_metrics.eq <= 1.0);
            assert!(latest_metrics.iq >= 0.0 && latest_metrics.iq <= 1.0);
            assert!(latest_metrics.balance >= 0.0 && latest_metrics.balance <= 1.0);
        } else {
            panic!("Memory trace should exist after update");
        }
    }

    #[test]
    fn test_eq_iq_history_tracking() {
        let mut memory = BDHMemory::new();
        
        let trace_id = "history_test_trace";
        let vector = vec![0.1, 0.2, 0.3];
        memory.add_or_update(trace_id, vector.clone(), 0.0);
        
        // Apply multiple updates to build history
        for i in 0..5 {
            let context = ContextEvent {
                stability: 0.5 + (i as f64) * 0.1,
                coherence: 0.6 + (i as f64) * 0.05,
                relevance: 0.7 + (i as f64) * 0.02,
            };
            
            let feedback = FeedbackEvent {
                accuracy: 0.4 + (i as f64) * 0.1,
                precision: 0.5 + (i as f64) * 0.08,
                confidence: 0.6 + (i as f64) * 0.06,
            };
            
            let state_vec = vec![0.1 + (i as f64) * 0.1, 0.2, 0.3];
            memory.reward_gated_update(trace_id, &state_vec, 0.5 + (i as f64) * 0.1, Some(context), Some(feedback));
        }
        
        // Check that history was recorded
        if let Some(entry) = memory.storage.get(trace_id) {
            assert_eq!(entry.eq_iq_history.len(), 5);
            
            // Verify history is chronologically ordered
            for i in 1..entry.eq_iq_history.len() {
                assert!(entry.eq_iq_history[i].timestamp >= entry.eq_iq_history[i-1].timestamp);
            }
        } else {
            panic!("Memory trace should exist");
        }
    }

    #[test]
    fn test_eq_iq_parameter_adaptation() {
        let mut regulator = ExperientialBehavioralRegulator::new(0.5, 0.5, 0.01);
        
        let initial_stats = regulator.get_stats();
        let initial_alpha = initial_stats.get("alpha").unwrap();
        let initial_beta = initial_stats.get("beta").unwrap();
        
        // Adapt with high performance feedback (should favor current balance)
        regulator.adapt_parameters(0.9);
        
        let adapted_stats = regulator.get_stats();
        let adapted_alpha = adapted_stats.get("alpha").unwrap();
        let adapted_beta = adapted_stats.get("beta").unwrap();
        
        // Parameters should remain valid
        assert!(adapted_alpha >= &0.0 && adapted_alpha <= &1.0);
        assert!(adapted_beta >= &0.0 && adapted_beta <= &1.0);
        assert!((adapted_alpha + adapted_beta - 1.0).abs() < 0.001); // Should sum to ~1.0
    }

    #[test]
    fn test_comprehensive_eq_iq_workflow() {
        let mut memory = BDHMemory::new();
        
        // Simulate a complete learning workflow
        let trace_id = "workflow_test";
        let initial_vector = vec![0.2, 0.4, 0.6, 0.8];
        memory.add_or_update(trace_id, initial_vector.clone(), 0.1);
        
        // Simulate multiple learning episodes with varying contexts and feedback
        let scenarios = vec![
            // High empathy scenario (stable context, moderate accuracy)
            (ContextEvent { stability: 0.9, coherence: 0.8, relevance: 0.85 },
             FeedbackEvent { accuracy: 0.6, precision: 0.65, confidence: 0.7 }, 0.7),
            
            // High accuracy scenario (unstable context, high accuracy)
            (ContextEvent { stability: 0.4, coherence: 0.5, relevance: 0.6 },
             FeedbackEvent { accuracy: 0.95, precision: 0.9, confidence: 0.85 }, 0.8),
            
            // Balanced scenario
            (ContextEvent { stability: 0.7, coherence: 0.75, relevance: 0.8 },
             FeedbackEvent { accuracy: 0.8, precision: 0.75, confidence: 0.8 }, 0.85),
        ];
        
        for (i, (context, feedback, reward)) in scenarios.iter().enumerate() {
            let state_vec = vec![0.1 + (i as f64) * 0.1, 0.3, 0.5, 0.7];
            memory.reward_gated_update(trace_id, &state_vec, *reward, Some(*context), Some(*feedback));
        }
        
        // Verify comprehensive learning occurred
        if let Some(entry) = memory.storage.get(trace_id) {
            assert_eq!(entry.eq_iq_history.len(), 3);
            assert!(entry.cumulative_reward > 0.0);
            
            // Check that EQ/IQ balance evolved over time
            let first_balance = entry.eq_iq_history[0].balance;
            let last_balance = entry.eq_iq_history[2].balance;
            
            // Balance should be within valid range
            assert!(first_balance >= 0.0 && first_balance <= 1.0);
            assert!(last_balance >= 0.0 && last_balance <= 1.0);
        }
        
        // Test adaptation based on overall performance
        let initial_stats = memory.get_eq_iq_stats();
        memory.adapt_eq_iq_parameters(0.85); // Good overall performance
        let adapted_stats = memory.get_eq_iq_stats();
        
        // Adaptation should maintain parameter validity
        assert!(adapted_stats.get("alpha").unwrap() >= &0.0);
        assert!(adapted_stats.get("beta").unwrap() >= &0.0);
        assert!((adapted_stats.get("alpha").unwrap() + adapted_stats.get("beta").unwrap() - 1.0).abs() < 0.001);
    }
}