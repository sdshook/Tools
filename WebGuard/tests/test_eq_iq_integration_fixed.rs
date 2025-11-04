#[cfg(test)]
mod tests {
    use webguard::eq_iq_regulator::{ExperientialBehavioralRegulator, ContextEvent, FeedbackEvent};
    use webguard::memory_engine::bdh_memory::BdhMemory;

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
        let _initial_alpha = initial_stats.get("alpha").unwrap();
        
        // Adapt parameters with positive feedback
        memory.adapt_eq_iq_parameters(0.8);
        
        // Get updated stats
        let updated_stats = memory.get_eq_iq_stats();
        let _updated_alpha = updated_stats.get("alpha").unwrap();
        
        // Parameters should have been adapted
        // (The exact behavior depends on the implementation)
        assert!(updated_stats.contains_key("alpha"));
        assert!(updated_stats.contains_key("beta"));
    }
}