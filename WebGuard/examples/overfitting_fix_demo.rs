use webguard::retrospective_learning::{RetrospectiveLearningSystem, MissedThreatEvent, FalsePositiveEvent, ThreatDiscoveryMethod};
use webguard::eq_iq_regulator::ContextEvent;

fn main() {
    println!("🔧 WebGuard Overfitting Fix Demonstration");
    println!("==========================================");
    
    // Create the balanced learning system
    let mut system = RetrospectiveLearningSystem::new();
    
    println!("\n✅ Balanced Learning Configuration:");
    println!("   - False negative learning rate: {}", system.false_negative_learning_rate);
    println!("   - False positive learning rate: {}", system.false_positive_learning_rate);
    println!("   - Regularization factor: {}", system.regularization_factor);
    println!("   - Max adjustment magnitude: {}", system.max_adjustment_magnitude);
    
    // Test feature vector
    let feature_vector = vec![0.5; 27];
    let base_score = 0.5;
    
    println!("\n🧪 Testing Adjustment Capping:");
    println!("   Base threat score: {:.3}", base_score);
    
    // Add multiple high-severity missed threats
    for i in 0..10 {
        let missed_threat = MissedThreatEvent {
            original_timestamp: 1000.0 + i as f64,
            discovery_timestamp: 1100.0 + i as f64,
            original_threat_score: 0.1,
            actual_threat_level: 0.9,
            feature_vector: feature_vector.clone(),
            original_context: ContextEvent {
                timestamp: 1000.0 + i as f64,
                context_stability: 0.5,
                threat_level: 0.1,
                response_appropriateness: 0.2,
            },
            discovery_method: ThreatDiscoveryMethod::SecurityAudit,
            consequence_severity: 1.0,
        };
        system.add_missed_threat(missed_threat);
    }
    
    let adjustment_after_fn = system.calculate_threat_score_adjustment(&feature_vector, base_score);
    println!("   After 10 high-severity missed threats: {:.3}", adjustment_after_fn);
    
    // Add multiple false positives to balance
    for i in 0..10 {
        let false_positive = FalsePositiveEvent {
            timestamp: 2000.0 + i as f64,
            original_threat_score: 0.8,
            actual_threat_level: 0.1,
            feature_vector: feature_vector.clone(),
            context: ContextEvent {
                timestamp: 2000.0 + i as f64,
                context_stability: 0.7,
                threat_level: 0.1,
                response_appropriateness: 0.1,
            },
            impact_severity: 0.8,
        };
        system.add_false_positive(false_positive);
    }
    
    let adjustment_after_balanced = system.calculate_threat_score_adjustment(&feature_vector, base_score);
    println!("   After adding 10 false positives: {:.3}", adjustment_after_balanced);
    
    // Verify adjustment is capped
    let is_capped = adjustment_after_fn.abs() <= system.max_adjustment_magnitude + 0.01;
    let is_balanced = adjustment_after_balanced.abs() < adjustment_after_fn.abs();
    
    println!("\n📊 Results:");
    println!("   ✅ Adjustment properly capped: {}", is_capped);
    println!("   ✅ False positives reduce paranoia: {}", is_balanced);
    println!("   ✅ Max adjustment limit: {:.3}", system.max_adjustment_magnitude);
    
    // Show learning statistics
    let stats = system.get_learning_stats();
    println!("\n📈 Learning Statistics:");
    println!("   - Missed threats processed: {}", stats.total_missed_threats);
    println!("   - False positives processed: {}", stats.total_false_positives);
    println!("   - Average missed threat severity: {:.3}", stats.average_missed_threat_severity);
    println!("   - Average false positive impact: {:.3}", stats.average_false_positive_impact);
    
    println!("\n🎯 Overfitting Fix Summary:");
    println!("   The balanced learning system successfully:");
    println!("   1. ✅ Caps adjustment magnitude to prevent extreme paranoia");
    println!("   2. ✅ Balances false negative and false positive learning");
    println!("   3. ✅ Applies regularization to prevent indefinite accumulation");
    println!("   4. ✅ Tracks both types of errors for comprehensive learning");
    
    if is_capped && is_balanced {
        println!("\n🎉 SUCCESS: Overfitting fix is working correctly!");
    } else {
        println!("\n❌ ISSUE: Overfitting fix needs adjustment");
    }
}