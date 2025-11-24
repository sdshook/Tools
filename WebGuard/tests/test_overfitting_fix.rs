use webguard::retrospective_learning::{RetrospectiveLearningSystem, MissedThreatEvent, FalsePositiveEvent, ThreatDiscoveryMethod};
use webguard::eq_iq_regulator::ContextEvent;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_overfitting_prevention() {
    let mut system = RetrospectiveLearningSystem::new();
    
    // Verify initial balanced learning rates
    assert_eq!(system.false_negative_learning_rate, 1.2);
    assert_eq!(system.false_positive_learning_rate, 1.0);
    assert_eq!(system.regularization_factor, 0.1);
    assert_eq!(system.max_adjustment_magnitude, 0.3);
    
    // Create test feature vector
    let feature_vector = vec![0.5; 27];
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as f64;
    
    // Create test context
    let context = ContextEvent {
        timestamp,
        context_stability: 0.8,
        threat_level: 0.5,
        response_appropriateness: 0.7,
    };
    
    // Simulate the old overfitting scenario: many false negatives followed by false positives
    
    // Add several missed threats (false negatives)
    for i in 0..5 {
        let missed_threat = MissedThreatEvent {
            original_timestamp: timestamp,
            discovery_timestamp: timestamp + 100.0,
            original_threat_score: 0.3,
            actual_threat_level: 0.8,
            feature_vector: feature_vector.clone(),
            original_context: context.clone(),
            discovery_method: ThreatDiscoveryMethod::SecurityAudit,
            consequence_severity: 0.7,
        };
        system.add_missed_threat(missed_threat);
    }
    
    // Calculate adjustment after false negatives
    let fn_adjustment = system.calculate_threat_score_adjustment(&feature_vector, 0.5);
    println!("Adjustment after false negatives: {}", fn_adjustment);
    
    // Now add false positives to simulate overcorrection
    for i in 0..5 {
        let false_positive = FalsePositiveEvent {
            timestamp,
            original_threat_score: 0.8,
            actual_threat_level: 0.2,
            feature_vector: feature_vector.clone(),
            context: context.clone(),
            impact_severity: 0.6,
        };
        system.add_false_positive(false_positive);
    }
    
    // Calculate adjustment after both false negatives and false positives
    let balanced_adjustment = system.calculate_threat_score_adjustment(&feature_vector, 0.5);
    println!("Balanced adjustment after FN + FP: {}", balanced_adjustment);
    
    // The balanced adjustment should be smaller than the false negative only adjustment
    // due to the false positive learning counteracting the false negative learning
    assert!(balanced_adjustment.abs() < fn_adjustment.abs(), 
           "Balanced learning should reduce extreme adjustments. FN-only: {}, Balanced: {}", 
           fn_adjustment, balanced_adjustment);
    
    // Verify adjustment is capped by max_adjustment_magnitude
    assert!(balanced_adjustment.abs() <= system.max_adjustment_magnitude + 0.01, 
           "Adjustment should be capped at max_adjustment_magnitude: {} vs {}", 
           balanced_adjustment.abs(), system.max_adjustment_magnitude);
    
    println!("✅ Overfitting prevention test passed!");
    println!("   - False negative learning rate: {}", system.false_negative_learning_rate);
    println!("   - False positive learning rate: {}", system.false_positive_learning_rate);
    println!("   - Regularization factor: {}", system.regularization_factor);
    println!("   - Max adjustment magnitude: {}", system.max_adjustment_magnitude);
    println!("   - FN-only adjustment: {:.3}", fn_adjustment);
    println!("   - Balanced adjustment: {:.3}", balanced_adjustment);
}

#[test]
fn test_false_positive_learning() {
    let mut system = RetrospectiveLearningSystem::new();
    let feature_vector = vec![0.7; 27];
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as f64;
    
    // Create test context
    let context = ContextEvent {
        timestamp,
        context_stability: 0.8,
        threat_level: 0.5,
        response_appropriateness: 0.7,
    };
    
    // Add false positive events
    for i in 0..3 {
        let false_positive = FalsePositiveEvent {
            timestamp,
            original_threat_score: 0.9,
            actual_threat_level: 0.1,
            feature_vector: feature_vector.clone(),
            context: context.clone(),
            impact_severity: 0.8,
        };
        system.add_false_positive(false_positive);
    }
    
    // Calculate adjustment - should be negative to reduce future threat scores
    let adjustment = system.calculate_threat_score_adjustment(&feature_vector, 0.5);
    
    // Should be negative (reducing threat scores) and within bounds
    assert!(adjustment < 0.0, "False positive learning should reduce threat scores");
    assert!(adjustment.abs() <= system.max_adjustment_magnitude + 0.01, 
           "Adjustment should be within bounds");
    
    println!("✅ False positive learning test passed!");
    println!("   - Adjustment: {:.3} (negative = reducing threat scores)", adjustment);
}

#[test]
fn test_regularization_effect() {
    let mut system = RetrospectiveLearningSystem::new();
    let feature_vector = vec![0.6; 27];
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as f64;
    
    // Create test context
    let context = ContextEvent {
        timestamp,
        context_stability: 0.8,
        threat_level: 0.5,
        response_appropriateness: 0.7,
    };
    
    // Add many missed threats to create large adjustment
    for i in 0..10 {
        let missed_threat = MissedThreatEvent {
            original_timestamp: timestamp,
            discovery_timestamp: timestamp + 100.0,
            original_threat_score: 0.2,
            actual_threat_level: 0.9,
            feature_vector: feature_vector.clone(),
            original_context: context.clone(),
            discovery_method: ThreatDiscoveryMethod::SecurityAudit,
            consequence_severity: 1.0,
        };
        system.add_missed_threat(missed_threat);
    }
    
    let adjustment = system.calculate_threat_score_adjustment(&feature_vector, 0.5);
    
    // Even with many high-severity missed threats, regularization should prevent extreme adjustments
    assert!(adjustment <= system.max_adjustment_magnitude + 0.01, 
           "Regularization should prevent extreme adjustments: {} vs max {}", 
           adjustment, system.max_adjustment_magnitude);
    
    println!("✅ Regularization test passed!");
    println!("   - Adjustment with 10 high-severity missed threats: {:.3}", adjustment);
    println!("   - Max allowed: {:.3}", system.max_adjustment_magnitude);
}