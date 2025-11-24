use webguard::retrospective_learning::RetrospectiveLearningSystem;

#[test]
fn test_balanced_learning_rates() {
    let system = RetrospectiveLearningSystem::new();
    
    // Verify the balanced learning rates are set correctly
    assert_eq!(system.false_negative_learning_rate, 1.2, "False negative learning rate should be 1.2");
    assert_eq!(system.false_positive_learning_rate, 1.0, "False positive learning rate should be 1.0");
    assert_eq!(system.regularization_factor, 0.1, "Regularization factor should be 0.1");
    assert_eq!(system.max_adjustment_magnitude, 0.3, "Max adjustment magnitude should be 0.3");
    
    println!("✅ Balanced learning configuration verified:");
    println!("   - False negative learning rate: {}", system.false_negative_learning_rate);
    println!("   - False positive learning rate: {}", system.false_positive_learning_rate);
    println!("   - Regularization factor: {}", system.regularization_factor);
    println!("   - Max adjustment magnitude: {}", system.max_adjustment_magnitude);
}

#[test]
fn test_adjustment_capping() {
    let mut system = RetrospectiveLearningSystem::new();
    let feature_vector = vec![0.5; 27];
    
    // Add many high-severity missed threats to try to create extreme adjustments
    for _ in 0..20 {
        let missed_threat = webguard::retrospective_learning::MissedThreatEvent {
            original_timestamp: 1000.0,
            discovery_timestamp: 1100.0,
            original_threat_score: 0.1,
            actual_threat_level: 0.9,
            feature_vector: feature_vector.clone(),
            original_context: webguard::eq_iq_regulator::ContextEvent {
                timestamp: 1000.0,
                context_stability: 0.5,
                threat_level: 0.1,
                response_appropriateness: 0.2,
            },
            discovery_method: webguard::retrospective_learning::ThreatDiscoveryMethod::SecurityAudit,
            consequence_severity: 1.0,
        };
        system.add_missed_threat(missed_threat);
    }
    
    // Calculate adjustment - should be capped despite many high-severity events
    let adjustment = system.calculate_threat_score_adjustment(&feature_vector, 0.5);
    
    // Verify adjustment is capped
    assert!(adjustment.abs() <= system.max_adjustment_magnitude + 0.01, 
           "Adjustment should be capped: {} vs max {}", 
           adjustment.abs(), system.max_adjustment_magnitude);
    
    println!("✅ Adjustment capping test passed:");
    println!("   - Adjustment with 20 high-severity missed threats: {:.3}", adjustment);
    println!("   - Max allowed: {:.3}", system.max_adjustment_magnitude);
    println!("   - Properly capped: {}", adjustment.abs() <= system.max_adjustment_magnitude + 0.01);
}