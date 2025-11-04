/// Comprehensive test suite for WebGuard's Retrospective Learning System
/// 
/// Tests the system's ability to learn from false negatives - missed threats
/// that are discovered later, mimicking how humans learn more from mistakes.

use webguard::retrospective_learning::{
    RetrospectiveLearningSystem, MissedThreatEvent, ThreatDiscoveryMethod
};
use webguard::eq_iq_regulator::{ExperientialBehavioralRegulator, ContextEvent, FeedbackEvent};
use webguard::memory_engine::bdh_memory::BdhMemory;
use webguard::mesh_cognition::{HostMeshCognition, WebServiceType};

#[test]
fn test_retrospective_learning_system_creation() {
    let system = RetrospectiveLearningSystem::new();
    let stats = system.get_learning_stats();
    
    assert_eq!(stats.total_missed_threats_processed, 0);
    assert_eq!(stats.patterns_reinforced, 0);
    assert_eq!(stats.eq_iq_adjustments_made, 0);
    assert_eq!(stats.memory_corrections_applied, 0);
}

#[test]
fn test_missed_threat_addition_and_statistics() {
    let mut system = RetrospectiveLearningSystem::new();
    
    let missed_threat = create_test_missed_threat(1000.0, 2000.0, 0.1, 0.9, 0.8);
    system.add_missed_threat(missed_threat);
    
    let stats = system.get_learning_stats();
    assert_eq!(stats.total_missed_threats_processed, 1);
    assert_eq!(stats.avg_discovery_delay, 1000.0); // 2000 - 1000
    assert_eq!(stats.avg_consequence_severity, 0.8);
}

#[test]
fn test_retrospective_eq_iq_learning() {
    let mut system = RetrospectiveLearningSystem::new();
    let mut regulator = ExperientialBehavioralRegulator::new(0.1);
    
    // Add a missed threat with high consequence severity
    let missed_threat = create_test_missed_threat(1000.0, 2000.0, 0.2, 0.9, 0.9);
    system.add_missed_threat(missed_threat);
    
    // Get initial EQ/IQ balance
    let initial_balance = regulator.get_current_balance();
    
    // Apply retrospective learning
    system.apply_retrospective_eq_iq_learning(&mut regulator, 3000.0);
    
    // Check that learning was applied
    let stats = system.get_learning_stats();
    assert!(stats.eq_iq_adjustments_made > 0);
    
    // The regulator should have learned from the mistake
    let updated_balance = regulator.get_current_balance();
    // EQ should be lower due to missing the threat
    assert!(updated_balance.eq <= initial_balance.eq);
}

#[test]
fn test_retrospective_memory_learning() {
    let mut system = RetrospectiveLearningSystem::new();
    let mut memory = BdhMemory::new();
    
    // Add a missed threat
    let missed_threat = create_test_missed_threat(1000.0, 2000.0, 0.1, 0.8, 0.7);
    system.add_missed_threat(missed_threat);
    
    // Apply retrospective learning to memory
    system.apply_retrospective_memory_learning(&mut memory, 3000.0);
    
    // Check that memory corrections were applied
    let stats = system.get_learning_stats();
    assert!(stats.memory_corrections_applied > 0);
    
    // The memory should now contain the corrective trace
    assert!(memory.traces.len() > 0);
    
    // The trace should have negative valence (threat pattern)
    let trace = &memory.traces[0];
    assert!(trace.valence < 0.0);
}

#[test]
fn test_similar_pattern_detection() {
    let mut system = RetrospectiveLearningSystem::new();
    
    // Add a missed threat with specific feature pattern
    let feature_vector = vec![1.0, 0.5, 0.2, 0.8, 0.1];
    let missed_threat = MissedThreatEvent {
        original_timestamp: 1000.0,
        discovery_timestamp: 2000.0,
        original_threat_score: 0.1,
        actual_threat_level: 0.9,
        feature_vector: feature_vector.clone(),
        original_context: ContextEvent {
            timestamp: 1000.0,
            context_stability: 0.8,
            threat_level: 0.1,
            response_appropriateness: 0.7,
        },
        discovery_method: ThreatDiscoveryMethod::SecurityAudit,
        consequence_severity: 0.8,
    };
    
    system.add_missed_threat(missed_threat);
    
    // Test similar pattern detection
    let similar_features = vec![0.9, 0.6, 0.1, 0.7, 0.2]; // Similar but not identical
    let similar_threats = system.find_similar_missed_threat_patterns(&similar_features);
    
    assert!(similar_threats.len() > 0);
    
    // Test dissimilar pattern
    let dissimilar_features = vec![0.1, 0.1, 0.9, 0.1, 0.9]; // Very different
    let dissimilar_threats = system.find_similar_missed_threat_patterns(&dissimilar_features);
    
    // Should find fewer or no similar threats
    assert!(dissimilar_threats.len() <= similar_threats.len());
}

#[test]
fn test_threat_score_adjustment() {
    let mut system = RetrospectiveLearningSystem::new();
    
    // Add a missed threat that was originally scored low but was actually high
    let feature_vector = vec![0.8, 0.7, 0.6, 0.9, 0.5];
    let missed_threat = MissedThreatEvent {
        original_timestamp: 1000.0,
        discovery_timestamp: 2000.0,
        original_threat_score: 0.2, // Originally scored low
        actual_threat_level: 0.9,   // Actually high threat
        feature_vector: feature_vector.clone(),
        original_context: ContextEvent {
            timestamp: 1000.0,
            context_stability: 0.8,
            threat_level: 0.2,
            response_appropriateness: 0.7,
        },
        discovery_method: ThreatDiscoveryMethod::IncidentResponse,
        consequence_severity: 0.9, // High consequence
    };
    
    system.add_missed_threat(missed_threat);
    
    // Test adjustment for similar pattern
    let similar_features = vec![0.8, 0.7, 0.6, 0.9, 0.5];
    let base_score = 0.3;
    let adjusted_score = system.calculate_threat_score_adjustment(&similar_features, base_score);
    
    // Score should be increased due to similar missed threat
    assert!(adjusted_score > base_score);
    assert!(adjusted_score <= 1.0);
    
    // Test adjustment for dissimilar pattern
    let dissimilar_features = vec![0.1, 0.1, 0.1, 0.1, 0.1];
    let adjusted_score_dissimilar = system.calculate_threat_score_adjustment(&dissimilar_features, base_score);
    
    // Should have little to no adjustment
    assert!((adjusted_score_dissimilar - base_score).abs() < 0.1);
}

#[test]
fn test_temporal_decay_in_learning() {
    let mut system = RetrospectiveLearningSystem::new();
    let mut regulator = ExperientialBehavioralRegulator::new(0.1);
    
    // Add an old missed threat
    let old_threat = create_test_missed_threat(1000.0, 2000.0, 0.1, 0.9, 0.8);
    system.add_missed_threat(old_threat);
    
    // Add a recent missed threat
    let recent_threat = create_test_missed_threat(10000.0, 11000.0, 0.1, 0.9, 0.8);
    system.add_missed_threat(recent_threat);
    
    // Apply learning at a much later time
    let current_time = 20000.0;
    system.apply_retrospective_eq_iq_learning(&mut regulator, current_time);
    
    // The system should have applied learning, with recent threats having more impact
    let stats = system.get_learning_stats();
    assert_eq!(stats.total_missed_threats_processed, 2);
    assert!(stats.eq_iq_adjustments_made > 0);
}

#[test]
fn test_mesh_cognition_integration() {
    let mut mesh = HostMeshCognition::new(0.1, 0.7, 0.5);
    
    // Register a service
    let service_id = mesh.register_service(WebServiceType::Apache, 1234);
    
    // Report a missed threat
    let feature_vector = vec![0.8, 0.6, 0.4, 0.9, 0.3];
    mesh.report_missed_threat(
        1000.0,                                    // original_timestamp
        2000.0,                                    // discovery_timestamp
        0.2,                                       // original_threat_score
        0.9,                                       // actual_threat_level
        feature_vector.clone(),                    // feature_vector
        ThreatDiscoveryMethod::SecurityAudit,      // discovery_method
        0.8                                        // consequence_severity
    );
    
    // Apply retrospective learning
    mesh.apply_retrospective_learning(3000.0);
    
    // Check that learning was applied
    let stats = mesh.get_retrospective_learning_stats();
    assert!(stats.is_some());
    let stats = stats.unwrap();
    assert_eq!(stats.total_missed_threats_processed, 1);
    assert!(stats.eq_iq_adjustments_made > 0);
    assert!(stats.memory_corrections_applied > 0);
    
    // Test threat score adjustment
    let base_score = 0.3;
    let adjusted_score = mesh.get_retrospective_threat_adjustment(&feature_vector, base_score);
    assert!(adjusted_score > base_score);
}

#[test]
fn test_different_discovery_methods() {
    let mut system = RetrospectiveLearningSystem::new();
    
    let discovery_methods = vec![
        ThreatDiscoveryMethod::SecurityAudit,
        ThreatDiscoveryMethod::IncidentResponse,
        ThreatDiscoveryMethod::ExternalDetection,
        ThreatDiscoveryMethod::UserReport,
        ThreatDiscoveryMethod::ForensicAnalysis,
        ThreatDiscoveryMethod::ThreatIntelligence,
    ];
    
    // Add missed threats with different discovery methods
    for (i, method) in discovery_methods.iter().enumerate() {
        let missed_threat = MissedThreatEvent {
            original_timestamp: 1000.0 + i as f64 * 100.0,
            discovery_timestamp: 2000.0 + i as f64 * 100.0,
            original_threat_score: 0.1,
            actual_threat_level: 0.8,
            feature_vector: vec![0.5, 0.5, 0.5],
            original_context: ContextEvent {
                timestamp: 1000.0 + i as f64 * 100.0,
                context_stability: 0.8,
                threat_level: 0.1,
                response_appropriateness: 0.7,
            },
            discovery_method: method.clone(),
            consequence_severity: 0.7,
        };
        
        system.add_missed_threat(missed_threat);
    }
    
    let stats = system.get_learning_stats();
    assert_eq!(stats.total_missed_threats_processed, discovery_methods.len());
}

#[test]
fn test_export_missed_threat_patterns() {
    let mut system = RetrospectiveLearningSystem::new();
    
    // Add a few missed threats
    for i in 0..3 {
        let missed_threat = create_test_missed_threat(
            1000.0 + i as f64 * 100.0,
            2000.0 + i as f64 * 100.0,
            0.1 + i as f32 * 0.1,
            0.8 + i as f32 * 0.05,
            0.7 + i as f32 * 0.1
        );
        system.add_missed_threat(missed_threat);
    }
    
    // Export patterns
    let patterns = system.export_missed_threat_patterns();
    assert_eq!(patterns.len(), 3);
    
    // Check that exported data contains expected fields
    for pattern in patterns {
        assert!(pattern.contains_key("original_timestamp"));
        assert!(pattern.contains_key("discovery_timestamp"));
        assert!(pattern.contains_key("original_threat_score"));
        assert!(pattern.contains_key("actual_threat_level"));
        assert!(pattern.contains_key("consequence_severity"));
        assert!(pattern.contains_key("discovery_method"));
        assert!(pattern.contains_key("discovery_delay_hours"));
    }
}

#[test]
fn test_cleanup_old_threats() {
    let mut system = RetrospectiveLearningSystem::new();
    
    // Add old and new threats
    let old_threat = create_test_missed_threat(1000.0, 2000.0, 0.1, 0.9, 0.8);
    let new_threat = create_test_missed_threat(10000.0, 11000.0, 0.1, 0.9, 0.8);
    
    system.add_missed_threat(old_threat);
    system.add_missed_threat(new_threat);
    
    assert_eq!(system.get_learning_stats().total_missed_threats_processed, 2);
    
    // Cleanup threats older than 1 day (86400 seconds)
    let current_time = 12000.0; // 1000 seconds after new threat discovery
    system.cleanup_old_threats(current_time, 1.0); // 1 day retention
    
    // Old threat should be cleaned up, new threat should remain
    // Note: The cleanup affects the internal history but stats remain cumulative
    let exported_patterns = system.export_missed_threat_patterns();
    assert_eq!(exported_patterns.len(), 1); // Only new threat should remain
}

#[test]
fn test_high_consequence_severity_learning() {
    let mut system = RetrospectiveLearningSystem::new();
    let mut regulator = ExperientialBehavioralRegulator::new(0.1);
    
    // Add a missed threat with very high consequence severity
    let high_consequence_threat = create_test_missed_threat(1000.0, 2000.0, 0.1, 0.95, 1.0);
    system.add_missed_threat(high_consequence_threat);
    
    // Add a missed threat with low consequence severity
    let low_consequence_threat = create_test_missed_threat(1100.0, 2100.0, 0.1, 0.9, 0.2);
    system.add_missed_threat(low_consequence_threat);
    
    // Apply learning
    system.apply_retrospective_eq_iq_learning(&mut regulator, 3000.0);
    
    // High consequence threats should have more impact on learning
    let stats = system.get_learning_stats();
    assert_eq!(stats.total_missed_threats_processed, 2);
    assert!(stats.avg_consequence_severity > 0.5); // Average should be influenced by high severity
}

// Helper function to create test missed threat events
fn create_test_missed_threat(
    original_timestamp: f64,
    discovery_timestamp: f64,
    original_threat_score: f32,
    actual_threat_level: f32,
    consequence_severity: f32
) -> MissedThreatEvent {
    MissedThreatEvent {
        original_timestamp,
        discovery_timestamp,
        original_threat_score,
        actual_threat_level,
        feature_vector: vec![0.5, 0.6, 0.4, 0.7, 0.3],
        original_context: ContextEvent {
            timestamp: original_timestamp,
            context_stability: 0.8,
            threat_level: original_threat_score,
            response_appropriateness: 0.7,
        },
        discovery_method: ThreatDiscoveryMethod::SecurityAudit,
        consequence_severity,
    }
}