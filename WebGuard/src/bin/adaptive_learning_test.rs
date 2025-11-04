use webguard::{
    advanced_feature_extractor::AdvancedFeatureExtractor,
    adaptive_threshold::{AdaptiveThreshold, ThreatType},
    enhanced_pattern_recognition::{EnhancedPatternRecognition, RequestContext},
};
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct TestScenario {
    name: String,
    request_data: String,
    expected_threat: bool,
    threat_type: ThreatType,
}

#[derive(Debug)]
struct PassResults {
    pass_number: usize,
    correct_detections: usize,
    false_positives: usize,
    false_negatives: usize,
    accuracy: f32,
    precision: f32,
    recall: f32,
}

fn main() {
    println!("🧠 WebGuard Cognitive Learning & Memory System Test");
    println!("===================================================");
    println!("🎯 Security Priority: FALSE POSITIVES > FALSE NEGATIVES");
    println!("📚 Testing multi-pass adaptive learning with memory retention\n");
    
    // Initialize components
    let feature_extractor = AdvancedFeatureExtractor::new();
    let mut adaptive_threshold = AdaptiveThreshold::new();
    let pattern_recognition = EnhancedPatternRecognition::new();
    
    // Test scenarios focusing on the false negatives
    let test_scenarios = vec![
        TestScenario {
            name: "Basic XSS Script Tag".to_string(),
            request_data: "<script>alert('XSS')</script>".to_string(),
            expected_threat: true,
            threat_type: ThreatType::XssAttack,
        },
        TestScenario {
            name: "XSS with Event Handler".to_string(),
            request_data: "<img src=x onerror=alert('XSS')>".to_string(),
            expected_threat: true,
            threat_type: ThreatType::XssAttack,
        },
        TestScenario {
            name: "Basic Path Traversal".to_string(),
            request_data: "../../../etc/passwd".to_string(),
            expected_threat: true,
            threat_type: ThreatType::PathTraversal,
        },
        TestScenario {
            name: "Command Injection with Semicolon".to_string(),
            request_data: "; cat /etc/passwd".to_string(),
            expected_threat: true,
            threat_type: ThreatType::CommandInjection,
        },
        TestScenario {
            name: "Command Injection with Pipe".to_string(),
            request_data: "| ls -la".to_string(),
            expected_threat: true,
            threat_type: ThreatType::CommandInjection,
        },
        TestScenario {
            name: "Unicode Encoding XSS".to_string(),
            request_data: "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e".to_string(),
            expected_threat: true,
            threat_type: ThreatType::XssAttack,
        },
        // Add some legitimate requests for balance
        TestScenario {
            name: "Normal Login Request".to_string(),
            request_data: "username=john&password=secret123".to_string(),
            expected_threat: false,
            threat_type: ThreatType::LegitimateRequest,
        },
        TestScenario {
            name: "Search Query".to_string(),
            request_data: "q=rust programming tutorial".to_string(),
            expected_threat: false,
            threat_type: ThreatType::LegitimateRequest,
        },
    ];
    
    let mut pass_results = Vec::new();
    
    // Run multiple passes to demonstrate cognitive learning and memory retention
    for pass in 1..=5 {
        println!("\n🔄 LEARNING PASS {}: Cognitive Adaptation in Progress", pass);
        println!("{}", "=".repeat(60));
        
        if pass == 1 {
            println!("🧠 Initial cognitive state - baseline thresholds");
        } else {
            println!("🧠 Memory-enhanced cognitive state - learned from {} previous passes", pass - 1);
        }
        
        let mut correct_detections = 0;
        let mut false_positives = 0;
        let mut false_negatives = 0;
        let mut true_positives = 0;
        let mut true_negatives = 0;
        
        for scenario in &test_scenarios {
            // Extract features
            let features = feature_extractor.extract_features(&scenario.request_data);
            
            // Get adaptive threshold assessment
            let threat_assessment = adaptive_threshold.assess_threat(&features);
            
            // Pattern recognition analysis
            let context = RequestContext {
                method: "POST".to_string(),
                url: "/test".to_string(),
                content_type: Some("application/x-www-form-urlencoded".to_string()),
                user_agent: Some("TestAgent".to_string()),
                headers: HashMap::new(),
            };
            let pattern_result = pattern_recognition.analyze_patterns(&scenario.request_data, &context);
            
            // Combine scores for final decision with security-first bias
            // Prioritize catching threats over avoiding false positives
            let combined_confidence = (threat_assessment.confidence_score + pattern_result.overall_threat_score) / 2.0;
            
            // Apply security-first threshold adjustment (lower threshold = more sensitive)
            let security_adjusted_threshold = threat_assessment.adjusted_threshold * 0.8; // 20% more sensitive
            let threat_detected = combined_confidence > security_adjusted_threshold;
            
            // Determine correctness
            let correct = threat_detected == scenario.expected_threat;
            let is_false_positive = threat_detected && !scenario.expected_threat;
            let is_false_negative = !threat_detected && scenario.expected_threat;
            
            if correct {
                correct_detections += 1;
                if scenario.expected_threat {
                    true_positives += 1;
                } else {
                    true_negatives += 1;
                }
            } else if is_false_positive {
                false_positives += 1;
            } else if is_false_negative {
                false_negatives += 1;
            }
            
            let status_icon = if is_false_negative { "🚨" } else if is_false_positive { "⚠️" } else if correct { "✅" } else { "❌" };
            let priority_note = if is_false_negative { " ⚠️ CRITICAL MISS!" } else if is_false_positive { " (Acceptable FP)" } else { "" };
            
            println!("   {} {}: {} (Conf: {:.3}, Adj-Thresh: {:.3}){}",
                status_icon,
                scenario.name,
                if threat_detected { "THREAT" } else { "SAFE" },
                combined_confidence,
                security_adjusted_threshold,
                priority_note
            );
            
            // Provide feedback to adaptive threshold system for learning
            adaptive_threshold.update_performance(&threat_assessment, scenario.expected_threat);
        }
        
        let total_tests = test_scenarios.len();
        let accuracy = correct_detections as f32 / total_tests as f32;
        let precision = if (true_positives + false_positives) > 0 {
            true_positives as f32 / (true_positives + false_positives) as f32
        } else { 0.0 };
        let recall = if (true_positives + false_negatives) > 0 {
            true_positives as f32 / (true_positives + false_negatives) as f32
        } else { 0.0 };
        
        let results = PassResults {
            pass_number: pass,
            correct_detections,
            false_positives,
            false_negatives,
            accuracy,
            precision,
            recall,
        };
        
        println!("\n📊 COGNITIVE LEARNING RESULTS - Pass {}:", pass);
        println!("   🎯 Security-First Metrics:");
        println!("      Threat Detection Rate (Recall): {:.1}% (Higher = Better)", recall * 100.0);
        println!("      False Negatives: {} 🚨 (Lower = Better)", false_negatives);
        println!("      False Positives: {} ⚠️ (Acceptable trade-off)", false_positives);
        println!("   📈 Overall Performance:");
        println!("      Accuracy: {:.1}% ({}/{})", accuracy * 100.0, correct_detections, total_tests);
        println!("      Precision: {:.1}%", precision * 100.0);
        
        pass_results.push(results);
    }
    
    // Show cognitive learning progression
    println!("\n🧠 COGNITIVE LEARNING & MEMORY PROGRESSION");
    println!("==========================================");
    println!("Pass | Threat Detection | False Negatives | False Positives | Accuracy");
    println!("     |    (Recall)      |   🚨 CRITICAL   |  ⚠️ Acceptable  |         ");
    println!("-----|------------------|-----------------|-----------------|----------");
    
    for result in &pass_results {
        let fn_status = if result.false_negatives == 0 { "✅ NONE" } else { &format!("🚨 {}", result.false_negatives) };
        let fp_status = if result.false_positives <= 2 { "✅ LOW" } else { &format!("⚠️ {}", result.false_positives) };
        
        println!("  {}  |     {:.1}%       |    {}     |     {}      |  {:.1}%",
            result.pass_number,
            result.recall * 100.0,
            fn_status,
            fp_status,
            result.accuracy * 100.0
        );
    }
    
    // Show cognitive learning improvement
    if pass_results.len() >= 2 {
        let first_pass = &pass_results[0];
        let last_pass = &pass_results[pass_results.len() - 1];
        
        println!("\n🧠 COGNITIVE LEARNING ACHIEVEMENTS:");
        println!("=====================================");
        
        let fn_improvement = first_pass.false_negatives as i32 - last_pass.false_negatives as i32;
        let recall_improvement = (last_pass.recall - first_pass.recall) * 100.0;
        
        if fn_improvement > 0 {
            println!("🎯 CRITICAL SUCCESS: Reduced false negatives by {} ({}% improvement)", 
                fn_improvement, 
                if first_pass.false_negatives > 0 { (fn_improvement as f32 / first_pass.false_negatives as f32 * 100.0) } else { 0.0 }
            );
        } else if fn_improvement == 0 {
            println!("🎯 MAINTAINED: Zero false negative improvement (already optimal or stable)");
        } else {
            println!("⚠️ REGRESSION: False negatives increased by {} (needs attention)", fn_improvement.abs());
        }
        
        println!("📈 Threat Detection Rate: {:.1}% → {:.1}% ({:+.1}% change)",
            first_pass.recall * 100.0,
            last_pass.recall * 100.0,
            recall_improvement
        );
        
        println!("📊 Overall Accuracy: {:.1}% → {:.1}% ({:+.1}% change)",
            first_pass.accuracy * 100.0,
            last_pass.accuracy * 100.0,
            (last_pass.accuracy - first_pass.accuracy) * 100.0
        );
        
        // Assess learning effectiveness
        if fn_improvement > 0 || recall_improvement > 5.0 {
            println!("\n🧠 LEARNING ASSESSMENT: ✅ EFFECTIVE COGNITIVE ADAPTATION");
            println!("   Memory system successfully retained and applied threat patterns");
        } else if fn_improvement == 0 && recall_improvement.abs() < 2.0 {
            println!("\n🧠 LEARNING ASSESSMENT: ⚖️ STABLE COGNITIVE STATE");
            println!("   System maintains consistent threat detection capabilities");
        } else {
            println!("\n🧠 LEARNING ASSESSMENT: ⚠️ LEARNING OPPORTUNITY IDENTIFIED");
            println!("   Cognitive adaptation could benefit from enhanced memory retention");
        }
    }
    
    println!("\n✅ Multi-pass cognitive learning analysis complete!");
    println!("🔒 Security-first approach: Prioritizing threat detection over false positive avoidance");
}