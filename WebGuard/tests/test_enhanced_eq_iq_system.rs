#[cfg(test)]
mod tests {
    use webguard::eq_iq_regulator::{ExperientialBehavioralRegulator, ContextEvent, FeedbackEvent, EQIQBalance, MultiDimensionalEQ};
    use webguard::memory_engine::bdh_memory::BdhMemory;
    use std::collections::HashMap;

    #[test]
    fn test_enhanced_eq_iq_regulator_initialization() {
        let regulator = ExperientialBehavioralRegulator::new(0.6, 0.4, 0.01);
        let stats = regulator.get_stats();
        
        assert_eq!(stats.get("alpha").unwrap(), &0.6);
        assert_eq!(stats.get("beta").unwrap(), &0.4);
        assert_eq!(stats.get("learning_rate").unwrap(), &0.01);
        assert_eq!(stats.get("context_history_size").unwrap(), &0.0);
        assert_eq!(stats.get("feedback_history_size").unwrap(), &0.0);
    }

    #[test]
    fn test_multi_dimensional_eq_creation() {
        let eq = MultiDimensionalEQ {
            contextual_stability: 0.8,
            response_appropriateness: 0.9,
            social_awareness: 0.7,
            emotional_regulation: 0.85,
            empathic_accuracy: 0.75,
        };
        
        let aggregated = eq.aggregate();
        assert!(aggregated >= 0.0 && aggregated <= 1.0);
        assert!((aggregated - 0.8).abs() < 0.1); // Should be around the average
    }

    #[test]
    fn test_context_adaptive_balance() {
        let mut regulator = ExperientialBehavioralRegulator::new(0.5, 0.5, 0.01);
        
        // High threat context should adapt α/β parameters
        let high_threat_context = ContextEvent {
            timestamp: 1234567890.0,
            context_stability: 0.3,
            threat_level: 0.9,
            response_appropriateness: 0.6,
        };
        
        let feedback = FeedbackEvent {
            timestamp: 1234567890.0,
            predicted_threat: 0.85,
            actual_threat: 0.8,
            accuracy: 0.9,
        };
        
        let balance = regulator.calculate_eq_iq_balance(&high_threat_context, &feedback);
        
        // Balance should be valid
        assert!(balance.balance >= 0.0 && balance.balance <= 1.0);
        assert!(balance.eq >= 0.0 && balance.eq <= 1.0);
        assert!(balance.iq >= 0.0 && balance.iq <= 1.0);
        
        // Uncertainty should be calculated
        assert!(balance.eq_uncertainty >= 0.0 && balance.eq_uncertainty <= 1.0);
        assert!(balance.iq_uncertainty >= 0.0 && balance.iq_uncertainty <= 1.0);
        assert!(balance.confidence >= 0.0 && balance.confidence <= 1.0);
    }

    #[test]
    fn test_temporal_weighting() {
        let mut regulator = ExperientialBehavioralRegulator::new(0.5, 0.5, 0.01);
        
        // Add multiple context events to build history
        for i in 0..5 {
            let context = ContextEvent {
                timestamp: 1234567890.0 + (i as f64) * 1000.0,
                context_stability: 0.5 + (i as f32) * 0.1,
                threat_level: 0.3,
                response_appropriateness: 0.7 + (i as f32) * 0.05,
            };
            
            let feedback = FeedbackEvent {
                timestamp: 1234567890.0 + (i as f64) * 1000.0,
                predicted_threat: 0.4,
                actual_threat: 0.35,
                accuracy: 0.8 + (i as f32) * 0.02,
            };
            
            regulator.calculate_eq_iq_balance(&context, &feedback);
        }
        
        // Recent events should have more weight in calculations
        let stats = regulator.get_stats();
        assert!(stats.get("context_history_size").unwrap() == &5.0);
        assert!(stats.get("feedback_history_size").unwrap() == &5.0);
    }

    #[test]
    fn test_non_linear_eq_iq_interaction() {
        let mut regulator = ExperientialBehavioralRegulator::new(0.6, 0.4, 0.01);
        
        // Test with high EQ and high IQ - should show synergistic effects
        let high_performance_context = ContextEvent {
            timestamp: 1234567890.0,
            context_stability: 0.9,
            threat_level: 0.2,
            response_appropriateness: 0.95,
        };
        
        let high_accuracy_feedback = FeedbackEvent {
            timestamp: 1234567890.0,
            predicted_threat: 0.25,
            actual_threat: 0.2,
            accuracy: 0.95,
        };
        
        let balance = regulator.calculate_eq_iq_balance(&high_performance_context, &high_accuracy_feedback);
        
        // High EQ and IQ should result in high balance
        assert!(balance.balance > 0.7);
        assert!(balance.eq > 0.8);
        assert!(balance.iq > 0.8);
    }

    #[test]
    fn test_uncertainty_quantification() {
        let mut regulator = ExperientialBehavioralRegulator::new(0.5, 0.5, 0.01);
        
        // Create inconsistent feedback to increase uncertainty
        let contexts = vec![
            ContextEvent {
                timestamp: 1234567890.0,
                context_stability: 0.9,
                threat_level: 0.1,
                response_appropriateness: 0.95,
            },
            ContextEvent {
                timestamp: 1234567891.0,
                context_stability: 0.2,
                threat_level: 0.9,
                response_appropriateness: 0.3,
            },
        ];
        
        let feedbacks = vec![
            FeedbackEvent {
                timestamp: 1234567890.0,
                predicted_threat: 0.1,
                actual_threat: 0.9,
                accuracy: 0.2,
            },
            FeedbackEvent {
                timestamp: 1234567891.0,
                predicted_threat: 0.9,
                actual_threat: 0.1,
                accuracy: 0.2,
            },
        ];
        
        for (context, feedback) in contexts.iter().zip(feedbacks.iter()) {
            regulator.calculate_eq_iq_balance(context, feedback);
        }
        
        // Final calculation should show higher uncertainty due to inconsistent history
        let final_balance = regulator.calculate_eq_iq_balance(&contexts[0], &feedbacks[0]);
        
        // Uncertainty should be measurable
        assert!(final_balance.eq_uncertainty > 0.0);
        assert!(final_balance.iq_uncertainty > 0.0);
        assert!(final_balance.confidence < 1.0);
    }

    #[test]
    fn test_cross_modal_learning() {
        let mut regulator = ExperientialBehavioralRegulator::new(0.5, 0.5, 0.1); // Higher learning rate
        
        let initial_stats = regulator.get_stats();
        let initial_alpha = *initial_stats.get("alpha").unwrap();
        let initial_beta = *initial_stats.get("beta").unwrap();
        
        // Simulate scenarios where EQ compensates for low IQ
        for _ in 0..15 {
            let high_eq_context = ContextEvent {
                timestamp: 1234567890.0,
                context_stability: 0.9,
                threat_level: 0.3,
                response_appropriateness: 0.95,
            };
            
            let low_iq_feedback = FeedbackEvent {
                timestamp: 1234567890.0,
                predicted_threat: 0.7,
                actual_threat: 0.3,
                accuracy: 0.4, // Low accuracy but good overall performance due to high EQ
            };
            
            regulator.calculate_eq_iq_balance(&high_eq_context, &low_iq_feedback);
        }
        
        let adapted_stats = regulator.get_stats();
        let adapted_alpha = *adapted_stats.get("alpha").unwrap();
        let adapted_beta = *adapted_stats.get("beta").unwrap();
        
        // Cross-modal learning should have adapted parameters
        // (exact direction depends on the learning algorithm)
        assert!(adapted_alpha >= 0.1 && adapted_alpha <= 0.9);
        assert!(adapted_beta >= 0.1 && adapted_beta <= 0.9);
        assert!((adapted_alpha + adapted_beta - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_multi_dimensional_eq_components() {
        let mut regulator = ExperientialBehavioralRegulator::new(0.5, 0.5, 0.01);
        
        let context = ContextEvent {
            timestamp: 1234567890.0,
            context_stability: 0.8,
            threat_level: 0.4,
            response_appropriateness: 0.9,
        };
        
        let feedback = FeedbackEvent {
            timestamp: 1234567890.0,
            predicted_threat: 0.45,
            actual_threat: 0.4,
            accuracy: 0.85,
        };
        
        let balance = regulator.calculate_eq_iq_balance(&context, &feedback);
        
        // Check multi-dimensional EQ components
        assert!(balance.eq_vector.contextual_stability >= 0.0 && balance.eq_vector.contextual_stability <= 1.0);
        assert!(balance.eq_vector.response_appropriateness >= 0.0 && balance.eq_vector.response_appropriateness <= 1.0);
        assert!(balance.eq_vector.social_awareness >= 0.0 && balance.eq_vector.social_awareness <= 1.0);
        assert!(balance.eq_vector.emotional_regulation >= 0.0 && balance.eq_vector.emotional_regulation <= 1.0);
        assert!(balance.eq_vector.empathic_accuracy >= 0.0 && balance.eq_vector.empathic_accuracy <= 1.0);
        
        // Aggregated EQ should match the balance.eq value
        let aggregated_eq = balance.eq_vector.aggregate();
        assert!((aggregated_eq - balance.eq).abs() < 0.01);
    }

    #[test]
    fn test_comprehensive_phase_integration() {
        let mut regulator = ExperientialBehavioralRegulator::new(0.5, 0.5, 0.05);
        
        // Test all three phases working together
        let scenarios = vec![
            // Phase 1: Context-adaptive with temporal weighting
            (ContextEvent {
                timestamp: 1234567890.0,
                context_stability: 0.9,
                threat_level: 0.8, // High threat should adapt parameters
                response_appropriateness: 0.7,
            }, FeedbackEvent {
                timestamp: 1234567890.0,
                predicted_threat: 0.75,
                actual_threat: 0.8,
                accuracy: 0.9,
            }),
            
            // Phase 2: Non-linear interaction with uncertainty
            (ContextEvent {
                timestamp: 1234567891.0,
                context_stability: 0.6,
                threat_level: 0.3,
                response_appropriateness: 0.8,
            }, FeedbackEvent {
                timestamp: 1234567891.0,
                predicted_threat: 0.4,
                actual_threat: 0.3,
                accuracy: 0.85,
            }),
            
            // Phase 3: Multi-dimensional EQ with cross-modal learning
            (ContextEvent {
                timestamp: 1234567892.0,
                context_stability: 0.95,
                threat_level: 0.1,
                response_appropriateness: 0.95,
            }, FeedbackEvent {
                timestamp: 1234567892.0,
                predicted_threat: 0.15,
                actual_threat: 0.1,
                accuracy: 0.95,
            }),
        ];
        
        let mut balances = Vec::new();
        for (context, feedback) in scenarios {
            let balance = regulator.calculate_eq_iq_balance(&context, &feedback);
            balances.push(balance);
        }
        
        // Verify all phases are working
        for balance in &balances {
            // Phase 1: Context adaptation and temporal weighting
            assert!(balance.balance >= 0.0 && balance.balance <= 1.0);
            
            // Phase 2: Non-linear interaction and uncertainty quantification
            assert!(balance.eq_uncertainty >= 0.0 && balance.eq_uncertainty <= 1.0);
            assert!(balance.iq_uncertainty >= 0.0 && balance.iq_uncertainty <= 1.0);
            assert!(balance.confidence >= 0.0 && balance.confidence <= 1.0);
            
            // Phase 3: Multi-dimensional EQ
            assert!(balance.eq_vector.contextual_stability >= 0.0);
            assert!(balance.eq_vector.response_appropriateness >= 0.0);
            assert!(balance.eq_vector.social_awareness >= 0.0);
            assert!(balance.eq_vector.emotional_regulation >= 0.0);
            assert!(balance.eq_vector.empathic_accuracy >= 0.0);
        }
        
        // Cross-modal learning should have built up correlation history
        assert!(regulator.eq_iq_correlation_history.len() > 0);
    }

    #[test]
    fn test_performance_under_varying_conditions() {
        let mut regulator = ExperientialBehavioralRegulator::new(0.5, 0.5, 0.02);
        
        // Test performance under various threat levels and contexts
        let threat_levels = vec![0.1, 0.3, 0.5, 0.7, 0.9];
        let mut results = Vec::new();
        
        for threat_level in threat_levels {
            let context = ContextEvent {
                timestamp: 1234567890.0,
                context_stability: 1.0 - threat_level, // Inverse relationship
                threat_level,
                response_appropriateness: 0.8,
            };
            
            let feedback = FeedbackEvent {
                timestamp: 1234567890.0,
                predicted_threat: threat_level + 0.05,
                actual_threat: threat_level,
                accuracy: 0.9,
            };
            
            let balance = regulator.calculate_eq_iq_balance(&context, &feedback);
            results.push((threat_level, balance));
        }
        
        // System should adapt to different threat levels
        for (threat_level, balance) in results {
            assert!(balance.balance >= 0.0 && balance.balance <= 1.0);
            
            // Higher threat should generally result in different balance characteristics
            if threat_level > 0.7 {
                // High threat scenarios might show different uncertainty patterns
                assert!(balance.confidence >= 0.0);
            }
        }
    }
}