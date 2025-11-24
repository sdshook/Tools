use webguard::retrospective_learning::{RetrospectiveLearningSystem, MissedThreatEvent, FalsePositiveEvent, ThreatDiscoveryMethod};
use webguard::eq_iq_regulator::ContextEvent;

#[test]
fn test_balanced_retrospective_learning() {
    let mut system = RetrospectiveLearningSystem::new();
    
    // Verify balanced learning rates
    assert_eq!(system.false_negative_learning_rate, 1.2);
    assert_eq!(system.false_positive_learning_rate, 1.0);
    assert_eq!(system.regularization_factor, 0.1);
    assert_eq!(system.max_adjustment_magnitude, 0.3);
    
    // Test feature vector
    let features = vec![0.1, 0.2, 0.3, 0.4, 0.5];
    let base_score = 0.5;
    
    // Initially, no adjustments should be made
    let initial_adjustment = system.calculate_threat_score_adjustment(&features, base_score);
    assert_eq!(initial_adjustment, base_score);
    
    // Add a missed threat (false negative)
    let missed_threat = MissedThreatEvent {
        original_timestamp: 1000.0,
        discovery_timestamp: 2000.0,
        original_threat_score: 0.2,
        actual_threat_level: 0.8,
        feature_vector: features.clone(),
        original_context: ContextEvent {
            timestamp: 1000.0,
            context_stability: 0.7,
            threat_level: 0.8,
            response_appropriateness: 0.3,
        },
        discovery_method: ThreatDiscoveryMethod::SecurityAudit,
        consequence_severity: 0.9,
    };
    
    system.add_missed_threat(missed_threat);
    
    // Now the system should increase threat scores for similar patterns
    let adjusted_score_after_fn = system.calculate_threat_score_adjustment(&features, base_score);
    assert!(adjusted_score_after_fn > base_score, "Score should increase after false negative");
    
    // Add a false positive to balance the learning
    let false_positive = FalsePositiveEvent {
        timestamp: 3000.0,
        original_threat_score: 0.8,
        actual_threat_level: 0.1,
        feature_vector: features.clone(),
        context: ContextEvent {
            timestamp: 3000.0,
            context_stability: 0.8,
            threat_level: 0.1,
            response_appropriateness: 0.2,
        },
        impact_severity: 0.7,
    };
    
    system.add_false_positive(false_positive);
    
    // The adjustment should now be more balanced
    let balanced_score = system.calculate_threat_score_adjustment(&features, base_score);
    
    // The balanced score should be between the original and the FN-only adjustment
    assert!(balanced_score >= base_score, "Balanced score should not be below base");
    assert!(balanced_score <= adjusted_score_after_fn, "Balanced score should be moderated by FP learning");
    
    // Verify statistics are tracked
    let stats = system.get_learning_stats();
    assert_eq!(stats.total_missed_threats_processed, 1);
    assert_eq!(stats.total_false_positives_processed, 1);
    assert_eq!(stats.learning_balance_ratio, 0.5); // 1 FN out of 2 total events
}

#[test]
fn test_adjustment_magnitude_capping() {
    let mut system = RetrospectiveLearningSystem::new();
    let features = vec![0.1, 0.2, 0.3];
    let base_score = 0.5;
    
    // Add an extreme missed threat
    let extreme_missed_threat = MissedThreatEvent {
        original_timestamp: 1000.0,
        discovery_timestamp: 2000.0,
        original_threat_score: 0.0,
        actual_threat_level: 1.0,
        feature_vector: features.clone(),
        original_context: ContextEvent {
            timestamp: 1000.0,
            context_stability: 0.5,
            threat_level: 1.0,
            response_appropriateness: 0.1,
        },
        discovery_method: ThreatDiscoveryMethod::IncidentResponse,
        consequence_severity: 1.0,
    };
    
    system.add_missed_threat(extreme_missed_threat);
    
    let adjusted_score = system.calculate_threat_score_adjustment(&features, base_score);
    
    // The adjustment should be capped at max_adjustment_magnitude (0.3)
    let max_possible_score = base_score + system.max_adjustment_magnitude;
    assert!(adjusted_score <= max_possible_score, 
            "Adjustment should be capped at max magnitude: {} <= {}", 
            adjusted_score, max_possible_score);
}

#[test]
fn test_regularization_effect() {
    let mut system = RetrospectiveLearningSystem::new();
    let features = vec![0.5, 0.5, 0.5];
    let base_score = 0.5;
    
    // Add a moderate missed threat
    let missed_threat = MissedThreatEvent {
        original_timestamp: 1000.0,
        discovery_timestamp: 2000.0,
        original_threat_score: 0.3,
        actual_threat_level: 0.7,
        feature_vector: features.clone(),
        original_context: ContextEvent {
            timestamp: 1000.0,
            context_stability: 0.6,
            threat_level: 0.7,
            response_appropriateness: 0.4,
        },
        discovery_method: ThreatDiscoveryMethod::ExternalDetection,
        consequence_severity: 0.6,
    };
    
    system.add_missed_threat(missed_threat);
    
    let adjusted_score = system.calculate_threat_score_adjustment(&features, base_score);
    
    // Due to regularization (0.1), the adjustment should be reduced
    // The raw adjustment would be larger without regularization
    let raw_adjustment_estimate = (0.7 - 0.3) * 0.6 * 1.2; // (actual - original) * severity * learning_rate
    let expected_regularized = raw_adjustment_estimate * (1.0 - 0.1); // Apply regularization
    
    // The actual adjustment should be less than what it would be without regularization
    assert!(adjusted_score - base_score < raw_adjustment_estimate, 
            "Regularization should reduce the adjustment magnitude");
}