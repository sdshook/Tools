use webguard::{
    advanced_feature_extractor::AdvancedFeatureExtractor,
    adaptive_threshold::{AdaptiveThreshold, ThreatAssessment},
    enhanced_pattern_recognition::{ExperientialKnowledgeBase, PatternRequestContext},
};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone)]
struct TestScenario {
    name: String,
    request_data: String,
    expected_threat: bool,
    threat_type: String,
    description: String,
}

#[derive(Debug)]
struct EnhancedTestResults {
    scenario_name: String,
    processing_time_ms: f64,
    
    // Feature extraction results
    features: [f32; 32],
    
    // Adaptive threshold results
    threat_assessment: ThreatAssessment,
    
    // Pattern recognition results
    pattern_analysis_score: f32,
    detected_patterns_count: usize,
    behavioral_anomalies_count: usize,
    
    // Final decision
    threat_detected: bool,
    confidence_score: f32,
    
    // Accuracy metrics
    correct_detection: bool,
    false_positive: bool,
    false_negative: bool,
}

fn main() {
    println!("🔍 WebGuard Enhanced Diagnostic Suite");
    println!("=====================================");
    
    // Initialize enhanced components
    let feature_extractor = AdvancedFeatureExtractor::new();
    let mut adaptive_threshold = AdaptiveThreshold::new();
    let pattern_recognition = ExperientialKnowledgeBase::new();
    // Mesh cognition integration will be added later
    
    // Create comprehensive test scenarios
    let test_scenarios = create_comprehensive_test_scenarios();
    
    println!("\n📊 Running Enhanced Diagnostic Tests...\n");
    
    let mut all_results = Vec::new();
    
    for scenario in &test_scenarios {
        let start_time = Instant::now();
        
        // Extract advanced features
        let features = feature_extractor.extract_features(&scenario.request_data);
        
        // Perform adaptive threshold assessment
        let threat_assessment = adaptive_threshold.assess_threat(&features);
        
        // Perform pattern recognition analysis
        let context = PatternRequestContext {
            method: "POST".to_string(),
            url: "/test".to_string(),
            content_type: Some("application/x-www-form-urlencoded".to_string()),
            user_agent: Some("TestAgent/1.0".to_string()),
            headers: HashMap::new(),
        };
        
        let pattern_analysis = pattern_recognition.analyze_patterns(&scenario.request_data, &context);
        
        // Process through mesh cognition for learning
        let service_id = "enhanced_diagnostic_service";
        // Mesh cognition processing will be integrated later
        // let _mesh_result = mesh_cognition.process_request(features, &context_event);
        
        let processing_time = start_time.elapsed();
        
        // Combine results for final decision
        let combined_score = (threat_assessment.base_similarity + pattern_analysis.overall_threat_score) / 2.0;
        let final_threat_detected = combined_score > threat_assessment.adjusted_threshold;
        let final_confidence = (threat_assessment.confidence_score + pattern_analysis.confidence_level) / 2.0;
        
        // Calculate accuracy metrics
        let correct_detection = final_threat_detected == scenario.expected_threat;
        let false_positive = final_threat_detected && !scenario.expected_threat;
        let false_negative = !final_threat_detected && scenario.expected_threat;
        
        let results = EnhancedTestResults {
            scenario_name: scenario.name.clone(),
            processing_time_ms: processing_time.as_secs_f64() * 1000.0,
            features,
            threat_assessment: threat_assessment.clone(),
            pattern_analysis_score: pattern_analysis.overall_threat_score,
            detected_patterns_count: pattern_analysis.matched_learned_patterns.len(),
            behavioral_anomalies_count: pattern_analysis.triggered_indicators.len(),
            threat_detected: final_threat_detected,
            confidence_score: final_confidence,
            correct_detection,
            false_positive,
            false_negative,
        };
        
        // Update adaptive threshold with feedback
        adaptive_threshold.update_performance(&threat_assessment, scenario.expected_threat);
        
        all_results.push(results);
    }
    
    // Display detailed results
    display_detailed_results(&all_results);
    
    // Display performance summary
    display_performance_summary(&all_results);
    
    // Display feature analysis
    display_feature_analysis(&all_results);
    
    // Display threshold analysis
    display_threshold_analysis(&adaptive_threshold);
    
    println!("\n✅ Enhanced diagnostic complete!");
}

fn create_comprehensive_test_scenarios() -> Vec<TestScenario> {
    vec![
        // SQL Injection Tests
        TestScenario {
            name: "Classic SQL Injection".to_string(),
            request_data: "username=' OR '1'='1' --&password=anything".to_string(),
            expected_threat: true,
            threat_type: "SQL Injection".to_string(),
            description: "Classic SQL injection with OR condition".to_string(),
        },
        TestScenario {
            name: "Union-based SQL Injection".to_string(),
            request_data: "id=1 UNION SELECT username,password FROM users--".to_string(),
            expected_threat: true,
            threat_type: "SQL Injection".to_string(),
            description: "Union-based SQL injection attempt".to_string(),
        },
        TestScenario {
            name: "Blind SQL Injection".to_string(),
            request_data: "id=1 AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a'".to_string(),
            expected_threat: true,
            threat_type: "SQL Injection".to_string(),
            description: "Blind SQL injection with substring".to_string(),
        },
        TestScenario {
            name: "Time-based SQL Injection".to_string(),
            request_data: "id=1; WAITFOR DELAY '00:00:05'--".to_string(),
            expected_threat: true,
            threat_type: "SQL Injection".to_string(),
            description: "Time-based SQL injection".to_string(),
        },
        
        // XSS Tests
        TestScenario {
            name: "Basic XSS Script Tag".to_string(),
            request_data: "comment=<script>alert('XSS')</script>".to_string(),
            expected_threat: true,
            threat_type: "XSS".to_string(),
            description: "Basic XSS with script tag".to_string(),
        },
        TestScenario {
            name: "XSS with Event Handler".to_string(),
            request_data: "name=<img src=x onerror=alert('XSS')>".to_string(),
            expected_threat: true,
            threat_type: "XSS".to_string(),
            description: "XSS using image onerror event".to_string(),
        },
        TestScenario {
            name: "JavaScript URL XSS".to_string(),
            request_data: "url=javascript:alert('XSS')".to_string(),
            expected_threat: true,
            threat_type: "XSS".to_string(),
            description: "XSS using javascript: URL".to_string(),
        },
        
        // Path Traversal Tests
        TestScenario {
            name: "Basic Path Traversal".to_string(),
            request_data: "file=../../../etc/passwd".to_string(),
            expected_threat: true,
            threat_type: "Path Traversal".to_string(),
            description: "Basic path traversal attempt".to_string(),
        },
        TestScenario {
            name: "Encoded Path Traversal".to_string(),
            request_data: "file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd".to_string(),
            expected_threat: true,
            threat_type: "Path Traversal".to_string(),
            description: "URL-encoded path traversal".to_string(),
        },
        
        // Command Injection Tests
        TestScenario {
            name: "Command Injection with Semicolon".to_string(),
            request_data: "cmd=ping 127.0.0.1; cat /etc/passwd".to_string(),
            expected_threat: true,
            threat_type: "Command Injection".to_string(),
            description: "Command injection using semicolon".to_string(),
        },
        TestScenario {
            name: "Command Injection with Pipe".to_string(),
            request_data: "input=test | whoami".to_string(),
            expected_threat: true,
            threat_type: "Command Injection".to_string(),
            description: "Command injection using pipe".to_string(),
        },
        
        // Encoding Attack Tests
        TestScenario {
            name: "Double URL Encoding".to_string(),
            request_data: "data=%252527%252520OR%2525201%25253D1".to_string(),
            expected_threat: true,
            threat_type: "Encoding Attack".to_string(),
            description: "Double URL encoded SQL injection".to_string(),
        },
        TestScenario {
            name: "Unicode Encoding XSS".to_string(),
            request_data: "input=\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e".to_string(),
            expected_threat: true,
            threat_type: "Encoding Attack".to_string(),
            description: "Unicode encoded XSS attempt".to_string(),
        },
        
        // Legitimate Requests
        TestScenario {
            name: "Normal Login Request".to_string(),
            request_data: "username=john.doe&password=mypassword123".to_string(),
            expected_threat: false,
            threat_type: "Legitimate".to_string(),
            description: "Normal login form submission".to_string(),
        },
        TestScenario {
            name: "API JSON Request".to_string(),
            request_data: r#"{"user_id": 123, "action": "update_profile", "data": {"name": "John Doe", "email": "john@example.com"}}"#.to_string(),
            expected_threat: false,
            threat_type: "Legitimate".to_string(),
            description: "Legitimate API JSON request".to_string(),
        },
        TestScenario {
            name: "Search Query".to_string(),
            request_data: "q=how to configure web server&category=tutorials".to_string(),
            expected_threat: false,
            threat_type: "Legitimate".to_string(),
            description: "Normal search query".to_string(),
        },
        TestScenario {
            name: "File Upload Request".to_string(),
            request_data: "filename=document.pdf&content_type=application/pdf&size=1024".to_string(),
            expected_threat: false,
            threat_type: "Legitimate".to_string(),
            description: "Legitimate file upload metadata".to_string(),
        },
        
        // Complex/Composite Attacks
        TestScenario {
            name: "SQL Injection + XSS Combo".to_string(),
            request_data: "input=' UNION SELECT '<script>alert(\"XSS\")</script>' --".to_string(),
            expected_threat: true,
            threat_type: "Composite Attack".to_string(),
            description: "Combined SQL injection and XSS attack".to_string(),
        },
        TestScenario {
            name: "Encoded Command Injection".to_string(),
            request_data: "cmd=%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64".to_string(),
            expected_threat: true,
            threat_type: "Composite Attack".to_string(),
            description: "URL-encoded command injection".to_string(),
        },
    ]
}

fn display_detailed_results(results: &[EnhancedTestResults]) {
    println!("📋 Detailed Test Results");
    println!("========================");
    
    for result in results {
        println!("\n🔍 Test: {}", result.scenario_name);
        println!("   Processing Time: {:.3}ms", result.processing_time_ms);
        println!("   Threat Detected: {} (Confidence: {:.3})", 
                result.threat_detected, result.confidence_score);
        println!("   Adaptive Threshold: {:.3}", result.threat_assessment.adjusted_threshold);
        println!("   Base Similarity: {:.3}", result.threat_assessment.base_similarity);
        println!("   Pattern Analysis Score: {:.3}", result.pattern_analysis_score);
        println!("   Detected Patterns: {}", result.detected_patterns_count);
        println!("   Behavioral Anomalies: {}", result.behavioral_anomalies_count);
        println!("   Threat Type: {:?}", result.threat_assessment.threat_type);
        println!("   Confidence Level: {:?}", result.threat_assessment.confidence_level);
        
        let status = if result.correct_detection {
            "✅ CORRECT"
        } else if result.false_positive {
            "❌ FALSE POSITIVE"
        } else {
            "❌ FALSE NEGATIVE"
        };
        println!("   Result: {}", status);
    }
}

fn display_performance_summary(results: &[EnhancedTestResults]) {
    println!("\n📊 Performance Summary");
    println!("=====================");
    
    let total_tests = results.len();
    let correct_detections = results.iter().filter(|r| r.correct_detection).count();
    let false_positives = results.iter().filter(|r| r.false_positive).count();
    let false_negatives = results.iter().filter(|r| r.false_negative).count();
    let true_positives = results.iter().filter(|r| r.threat_detected && !r.false_positive).count();
    let true_negatives = results.iter().filter(|r| !r.threat_detected && !r.false_negative).count();
    
    let accuracy = correct_detections as f32 / total_tests as f32 * 100.0;
    let precision = if true_positives + false_positives > 0 {
        true_positives as f32 / (true_positives + false_positives) as f32 * 100.0
    } else {
        0.0
    };
    let recall = if true_positives + false_negatives > 0 {
        true_positives as f32 / (true_positives + false_negatives) as f32 * 100.0
    } else {
        0.0
    };
    let f1_score = if precision + recall > 0.0 {
        2.0 * (precision * recall) / (precision + recall)
    } else {
        0.0
    };
    let false_positive_rate = if true_negatives + false_positives > 0 {
        false_positives as f32 / (true_negatives + false_positives) as f32 * 100.0
    } else {
        0.0
    };
    
    let avg_processing_time = results.iter().map(|r| r.processing_time_ms).sum::<f64>() / total_tests as f64;
    let avg_confidence = results.iter().map(|r| r.confidence_score).sum::<f32>() / total_tests as f32;
    
    println!("Total Tests: {}", total_tests);
    println!("Correct Detections: {} ({:.1}%)", correct_detections, accuracy);
    println!("False Positives: {} ({:.1}%)", false_positives, false_positive_rate);
    println!("False Negatives: {}", false_negatives);
    println!("True Positives: {}", true_positives);
    println!("True Negatives: {}", true_negatives);
    println!();
    println!("📈 Key Metrics:");
    println!("   Accuracy: {:.1}%", accuracy);
    println!("   Precision: {:.1}%", precision);
    println!("   Recall: {:.1}%", recall);
    println!("   F1-Score: {:.1}", f1_score);
    println!("   False Positive Rate: {:.1}%", false_positive_rate);
    println!("   Average Processing Time: {:.3}ms", avg_processing_time);
    println!("   Average Confidence: {:.3}", avg_confidence);
    
    // Performance assessment
    println!("\n🎯 Performance Assessment:");
    if accuracy >= 90.0 {
        println!("   ✅ Accuracy: EXCELLENT ({:.1}%)", accuracy);
    } else if accuracy >= 80.0 {
        println!("   ⚠️  Accuracy: GOOD ({:.1}%)", accuracy);
    } else {
        println!("   ❌ Accuracy: NEEDS IMPROVEMENT ({:.1}%)", accuracy);
    }
    
    if precision >= 90.0 {
        println!("   ✅ Precision: EXCELLENT ({:.1}%)", precision);
    } else if precision >= 80.0 {
        println!("   ⚠️  Precision: GOOD ({:.1}%)", precision);
    } else {
        println!("   ❌ Precision: NEEDS IMPROVEMENT ({:.1}%)", precision);
    }
    
    if false_positive_rate <= 5.0 {
        println!("   ✅ False Positive Rate: EXCELLENT ({:.1}%)", false_positive_rate);
    } else if false_positive_rate <= 10.0 {
        println!("   ⚠️  False Positive Rate: ACCEPTABLE ({:.1}%)", false_positive_rate);
    } else {
        println!("   ❌ False Positive Rate: TOO HIGH ({:.1}%)", false_positive_rate);
    }
    
    if avg_processing_time <= 1.0 {
        println!("   ✅ Processing Speed: EXCELLENT ({:.3}ms)", avg_processing_time);
    } else if avg_processing_time <= 5.0 {
        println!("   ⚠️  Processing Speed: GOOD ({:.3}ms)", avg_processing_time);
    } else {
        println!("   ❌ Processing Speed: SLOW ({:.3}ms)", avg_processing_time);
    }
}

fn display_feature_analysis(results: &[EnhancedTestResults]) {
    println!("\n🔬 Feature Analysis");
    println!("==================");
    
    // Analyze feature effectiveness
    let mut feature_effectiveness = vec![0.0; 32];
    let threat_results: Vec<_> = results.iter().filter(|r| r.threat_detected).collect();
    let benign_results: Vec<_> = results.iter().filter(|r| !r.threat_detected).collect();
    
    for i in 0..32 {
        let threat_avg = if !threat_results.is_empty() {
            threat_results.iter().map(|r| r.features[i]).sum::<f32>() / threat_results.len() as f32
        } else {
            0.0
        };
        
        let benign_avg = if !benign_results.is_empty() {
            benign_results.iter().map(|r| r.features[i]).sum::<f32>() / benign_results.len() as f32
        } else {
            0.0
        };
        
        feature_effectiveness[i] = (threat_avg - benign_avg).abs();
    }
    
    let feature_names = [
        "Request Length", "SQL Basic", "SQL Advanced", "SQL Union", "SQL Blind", "SQL Time",
        "XSS Basic", "XSS Advanced", "XSS Events", "XSS Encoded", "DOM XSS",
        "Path Traversal", "File Inclusion", "Directory Listing", "File Upload", "Null Byte",
        "Command Injection", "Shell Meta", "System Commands", "PowerShell", "Bash",
        "URL Encoding", "Hex Encoding", "Base64", "Unicode", "Double Encoding",
        "Entropy", "Char Diversity", "Suspicious Ratio", "Legitimate Patterns", "Complexity", "Composite Score"
    ];
    
    println!("Top 10 Most Effective Features:");
    let mut indexed_effectiveness: Vec<_> = feature_effectiveness.iter().enumerate().collect();
    indexed_effectiveness.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());
    
    for (i, (idx, &effectiveness)) in indexed_effectiveness.iter().take(10).enumerate() {
        println!("   {}. {} ({:.3})", i + 1, feature_names[*idx], effectiveness);
    }
}

fn display_threshold_analysis(adaptive_threshold: &AdaptiveThreshold) {
    println!("\n🎚️  Adaptive Threshold Analysis");
    println!("===============================");
    
    let performance = adaptive_threshold.get_performance_metrics();
    
    println!("Current Performance Metrics:");
    println!("   True Positives: {}", performance.true_positives);
    println!("   False Positives: {}", performance.false_positives);
    println!("   True Negatives: {}", performance.true_negatives);
    println!("   False Negatives: {}", performance.false_negatives);
    println!("   Recent Accuracy: {:.3}", performance.recent_accuracy);
    println!("   Recent Precision: {:.3}", performance.recent_precision);
    println!("   Recent Recall: {:.3}", performance.recent_recall);
    println!("   False Positive Rate: {:.3}", performance.false_positive_rate);
    println!("   F1-Score: {:.3}", performance.get_f1_score());
    
    println!("\nThreat-Specific Thresholds:");
    println!("   SQL Injection: {:.3}", adaptive_threshold.get_threshold_for_threat(&webguard::adaptive_threshold::ThreatType::SqlInjection));
    println!("   XSS Attack: {:.3}", adaptive_threshold.get_threshold_for_threat(&webguard::adaptive_threshold::ThreatType::XssAttack));
    println!("   Path Traversal: {:.3}", adaptive_threshold.get_threshold_for_threat(&webguard::adaptive_threshold::ThreatType::PathTraversal));
    println!("   Command Injection: {:.3}", adaptive_threshold.get_threshold_for_threat(&webguard::adaptive_threshold::ThreatType::CommandInjection));
    println!("   File Inclusion: {:.3}", adaptive_threshold.get_threshold_for_threat(&webguard::adaptive_threshold::ThreatType::FileInclusion));
    println!("   Encoding Attack: {:.3}", adaptive_threshold.get_threshold_for_threat(&webguard::adaptive_threshold::ThreatType::EncodingAttack));
    println!("   Composite Attack: {:.3}", adaptive_threshold.get_threshold_for_threat(&webguard::adaptive_threshold::ThreatType::CompositeAttack));
    println!("   Legitimate Request: {:.3}", adaptive_threshold.get_threshold_for_threat(&webguard::adaptive_threshold::ThreatType::LegitimateRequest));
}