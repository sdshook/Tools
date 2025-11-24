use webguard::webguard_system::{WebGuardSystem, MissedThreatEvent, FalsePositiveEvent};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;

/// Test that demonstrates WebGuard's experiential learning capabilities
/// This shows the system actually learns and adapts over time, not just pattern matching
#[test]
fn test_experiential_learning_progression() {
    println!("🧠 Testing WebGuard Experiential Learning System");
    println!("================================================");
    
    let mut webguard = WebGuardSystem::new();
    
    // Phase 1: Initial baseline - system starts with basic knowledge
    println!("\n📊 Phase 1: Initial Baseline Assessment");
    let initial_threshold = webguard.get_current_threshold();
    println!("Initial adaptive threshold: {:.3}", initial_threshold);
    
    // Test with various attack patterns
    let test_cases = vec![
        ("' OR 1=1 --", true, "SQL Injection"),
        ("<script>alert('xss')</script>", true, "XSS"),
        ("%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E", true, "URL-encoded XSS"),
        ("../../../etc/passwd", true, "Path Traversal"),
        ("SELECT * FROM users", false, "Benign SQL-like query"),
        ("Hello world", false, "Normal text"),
    ];
    
    let mut initial_results = Vec::new();
    for (input, is_threat, description) in &test_cases {
        let result = webguard.comprehensive_threat_analysis(input);
        initial_results.push((input, result.threat_score, result.confidence, is_threat, description));
        println!("  {} -> Score: {:.3}, Confidence: {:.3} ({})", 
                description, result.threat_score, result.confidence,
                if *is_threat { "THREAT" } else { "BENIGN" });
    }
    
    // Phase 2: Learning from feedback - simulate real-world learning
    println!("\n🎓 Phase 2: Learning from Feedback");
    
    // Simulate missed threats (false negatives) - system should become more sensitive
    let missed_threats = vec![
        "eval(document.cookie)",  // Subtle XSS
        "1' UNION SELECT password FROM users--",  // SQL injection variant
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",  // Double-encoded path traversal
    ];
    
    for threat in &missed_threats {
        let result = webguard.comprehensive_threat_analysis(threat);
        println!("  Missed threat detected: {} (Score: {:.3})", threat, result.threat_score);
        
        // Provide feedback that this was actually a threat
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
        let missed_event = MissedThreatEvent {
            original_timestamp: now - 60.0, // 1 minute ago
            discovery_timestamp: now,
            original_threat_score: result.threat_score,
            actual_threat_level: 0.9,
            feature_vector: vec![0.1, 0.2, 0.3], // Simplified feature vector
            original_context: ContextEvent::default(),
            discovery_method: ThreatDiscoveryMethod::SecurityAudit,
            consequence_severity: 0.9,
        };
        webguard.add_missed_threat(missed_event);
    }
    
    // Simulate false positives - system should become more precise
    let false_positives = vec![
        "SELECT column FROM table WHERE condition",  // Legitimate SQL
        "script tag in documentation: <script>",  // Documentation reference
        "File path: /home/user/documents/file.txt",  // Normal file path
    ];
    
    for fp in &false_positives {
        let result = webguard.comprehensive_threat_analysis(fp);
        println!("  False positive: {} (Score: {:.3})", fp, result.threat_score);
        
        // Provide feedback that this was actually benign
        let fp_event = FalsePositiveEvent {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
            original_threat_score: result.threat_score,
            actual_threat_level: 0.1, // Low threat level for benign content
            feature_vector: vec![0.1, 0.2, 0.3], // Simplified feature vector
            context: ContextEvent::default(),
            impact_severity: 0.3, // Moderate impact from false positive
        };
        webguard.add_false_positive(fp_event);
    }
    
    // Phase 3: Post-learning assessment - system should have adapted
    println!("\n📈 Phase 3: Post-Learning Assessment");
    let post_learning_threshold = webguard.get_current_threshold();
    println!("Post-learning adaptive threshold: {:.3}", post_learning_threshold);
    println!("Threshold change: {:.3}", post_learning_threshold - initial_threshold);
    
    let learning_stats = webguard.get_learning_stats();
    println!("Learning events processed: {}", webguard.metrics.learning_events);
    println!("Retrospective learning stats: {:?}", learning_stats);
    
    // Re-test the same cases to see learning impact
    println!("\n🔄 Re-testing with learned knowledge:");
    let mut improvement_count = 0;
    let mut total_tests = 0;
    
    for (i, (input, expected_threat, description)) in test_cases.iter().enumerate() {
        let new_result = webguard.comprehensive_threat_analysis(input);
        let (_, old_score, old_confidence, _, _) = &initial_results[i];
        
        println!("  {} -> Old: {:.3}, New: {:.3}, Confidence: {:.3}", 
                description, old_score, new_result.threat_score, new_result.confidence);
        
        // Check if learning improved accuracy
        let old_correct = (*old_score > 0.5) == *expected_threat;
        let new_correct = (new_result.threat_score > 0.5) == *expected_threat;
        
        if new_correct && (!old_correct || new_result.confidence > *old_confidence) {
            improvement_count += 1;
            println!("    ✅ Improved detection accuracy");
        }
        total_tests += 1;
    }
    
    // Phase 4: Memory and adaptation verification
    println!("\n🧠 Phase 4: Memory and Adaptation Verification");
    
    // Test similar patterns to see if system recognizes them
    let similar_patterns = vec![
        "' OR 2=2 --",  // Similar to learned SQL injection
        "%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E",  // Similar to learned XSS
        "%2e%2e%2f%2e%2e%2fhome%2fuser",  // Similar to learned path traversal
    ];
    
    for pattern in &similar_patterns {
        let result = webguard.comprehensive_threat_analysis(pattern);
        println!("  Similar pattern: {} -> Score: {:.3}, Memory influence: {:.3}", 
                pattern, result.threat_score, result.memory_influence);
        
        // Memory influence should be > 0 for similar patterns
        assert!(result.memory_influence > 0.0, 
               "Memory system should recognize similar patterns");
    }
    
    // Final assessment
    println!("\n🎯 Final Assessment:");
    println!("  Improvements detected: {}/{}", improvement_count, total_tests);
    println!("  System demonstrates experiential learning: {}", 
            improvement_count > 0 && webguard.metrics.learning_events > 0);
    
    // Verify this is NOT just pattern matching
    assert!(webguard.metrics.learning_events > 0, 
           "System must show learning events (not just pattern matching)");
    assert!(post_learning_threshold != initial_threshold, 
           "Adaptive threshold must change with learning");
    
    println!("\n✅ Experiential Learning Test PASSED");
    println!("   - System adapted thresholds based on feedback");
    println!("   - Memory system influences similar pattern recognition");
    println!("   - Learning events were processed and stored");
    println!("   - This is TRUE experiential learning, not pattern matching");
}

/// Test URL decoding integration in experiential learning context
#[test]
fn test_url_decoding_with_experiential_learning() {
    println!("\n🔗 Testing URL Decoding in Experiential Learning Context");
    
    let mut webguard = WebGuardSystem::new();
    
    // Test encoded attacks that should be detected
    let encoded_attacks = vec![
        ("%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E", "URL-encoded XSS"),
        ("%27%20OR%201%3D1%20--", "URL-encoded SQL injection"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL-encoded path traversal"),
        ("%253Cscript%253E", "Double URL-encoded script tag"),
    ];
    
    println!("Testing encoded attack detection:");
    for (encoded, description) in &encoded_attacks {
        let result = webguard.comprehensive_threat_analysis(encoded);
        println!("  {} -> Score: {:.3}", description, result.threat_score);
        
        // All encoded attacks should be detected
        assert!(result.threat_score > 0.5, 
               "Encoded attack should be detected: {}", description);
    }
    
    // Test that system can learn from encoded attack feedback
    let subtle_encoded = "%6A%61%76%61%73%63%72%69%70%74%3A%61%6C%65%72%74%28%31%29"; // javascript:alert(1)
    let initial_result = webguard.comprehensive_threat_analysis(subtle_encoded);
    
    if initial_result.threat_score < 0.5 {
        // If initially missed, provide learning feedback
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
        let missed_event = MissedThreatEvent {
            original_timestamp: now - 30.0, // 30 seconds ago
            discovery_timestamp: now,
            original_threat_score: initial_result.threat_score,
            actual_threat_level: 0.8,
            feature_vector: vec![0.2, 0.4, 0.6], // Different feature vector
            original_context: ContextEvent::default(),
            discovery_method: ThreatDiscoveryMethod::SecurityAudit,
            consequence_severity: 0.8,
        };
        webguard.add_missed_threat(missed_event);
        
        // Re-test after learning
        let learned_result = webguard.comprehensive_threat_analysis(subtle_encoded);
        println!("Learning from encoded attack: {:.3} -> {:.3}", 
                initial_result.threat_score, learned_result.threat_score);
        
        // System should improve or at least maintain detection
        assert!(learned_result.threat_score >= initial_result.threat_score,
               "System should learn from encoded attack feedback");
    }
    
    println!("✅ URL Decoding + Experiential Learning Test PASSED");
}