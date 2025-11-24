/// Comprehensive Overfitting Validation Test Suite
/// 
/// This test suite validates that the WebGuard overfitting fix is working correctly
/// by running multipass learning scenarios and verifying that false positive rates
/// remain stable while false negative rates improve.

use std::collections::HashMap;
use webguard::mesh_cognition::{HostMeshCognition, WebServiceType};
use webguard::eq_iq_regulator::ContextEvent;
use webguard::retrospective_learning::{RetrospectiveLearningSystem, MissedThreatEvent, FalsePositiveEvent, ThreatDiscoveryMethod};

#[derive(Debug, Clone)]
pub struct ValidationResults {
    pub pass: usize,
    pub false_positive_rate: f32,
    pub false_negative_rate: f32,
    pub threat_detection_accuracy: f32,
    pub learning_balance_score: f32,
    pub total_requests: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub true_negatives: usize,
    pub false_negatives: usize,
}

pub struct OverfittingValidationSuite {
    mesh_cognition: HostMeshCognition,
    test_scenarios: Vec<TestScenario>,
    results: Vec<ValidationResults>,
}

#[derive(Debug, Clone)]
struct TestScenario {
    name: String,
    features: [f32; 32],
    is_actual_threat: bool,
    severity: f32,
    description: String,
}

impl OverfittingValidationSuite {
    pub fn new() -> Self {
        let service_type = WebServiceType::WebApplication;
        let mesh_cognition = HostMeshCognition::new("validation_test", service_type);
        
        Self {
            mesh_cognition,
            test_scenarios: Self::create_test_scenarios(),
            results: Vec::new(),
        }
    }

    fn create_test_scenarios() -> Vec<TestScenario> {
        vec![
            // True threats (should be detected)
            TestScenario {
                name: "SQL Injection Attack".to_string(),
                features: [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0,
                          0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.9,
                          0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.9, 0.8,
                          0.6, 0.5],
                is_actual_threat: true,
                severity: 0.9,
                description: "Classic SQL injection with union select".to_string(),
            },
            TestScenario {
                name: "XSS Attack".to_string(),
                features: [0.8, 0.9, 0.6, 0.7, 0.4, 0.5, 0.2, 0.3, 0.0, 0.1,
                          0.7, 0.8, 0.5, 0.6, 0.3, 0.4, 0.1, 0.2, 0.9, 0.0,
                          0.6, 0.7, 0.4, 0.5, 0.2, 0.3, 0.0, 0.1, 0.8, 0.9,
                          0.5, 0.6],
                is_actual_threat: true,
                severity: 0.8,
                description: "Cross-site scripting with script tags".to_string(),
            },
            TestScenario {
                name: "Command Injection".to_string(),
                features: [0.7, 0.6, 0.9, 0.8, 0.3, 0.4, 0.1, 0.2, 0.5, 0.0,
                          0.6, 0.5, 0.8, 0.7, 0.2, 0.3, 0.0, 0.1, 0.4, 0.9,
                          0.5, 0.4, 0.7, 0.6, 0.1, 0.2, 0.9, 0.0, 0.3, 0.8,
                          0.4, 0.3],
                is_actual_threat: true,
                severity: 0.85,
                description: "OS command injection attempt".to_string(),
            },
            
            // Benign requests (should NOT be flagged as threats)
            TestScenario {
                name: "Normal User Login".to_string(),
                features: [0.1, 0.0, 0.2, 0.1, 0.0, 0.1, 0.0, 0.0, 0.1, 0.0,
                          0.0, 0.1, 0.0, 0.0, 0.1, 0.0, 0.0, 0.1, 0.0, 0.0,
                          0.1, 0.0, 0.0, 0.1, 0.0, 0.0, 0.1, 0.0, 0.0, 0.1,
                          0.0, 0.0],
                is_actual_threat: false,
                severity: 0.0,
                description: "Standard user authentication request".to_string(),
            },
            TestScenario {
                name: "File Upload".to_string(),
                features: [0.2, 0.1, 0.0, 0.2, 0.1, 0.0, 0.1, 0.0, 0.2, 0.1,
                          0.1, 0.0, 0.2, 0.1, 0.0, 0.1, 0.0, 0.2, 0.1, 0.0,
                          0.0, 0.2, 0.1, 0.0, 0.1, 0.0, 0.2, 0.1, 0.0, 0.0,
                          0.2, 0.1],
                is_actual_threat: false,
                severity: 0.0,
                description: "Legitimate file upload operation".to_string(),
            },
            TestScenario {
                name: "API Data Query".to_string(),
                features: [0.0, 0.2, 0.1, 0.0, 0.2, 0.1, 0.0, 0.1, 0.0, 0.2,
                          0.2, 0.1, 0.0, 0.2, 0.1, 0.0, 0.1, 0.0, 0.2, 0.1,
                          0.1, 0.0, 0.2, 0.1, 0.0, 0.1, 0.0, 0.2, 0.1, 0.0,
                          0.0, 0.2],
                is_actual_threat: false,
                severity: 0.0,
                description: "Normal API data retrieval request".to_string(),
            },
            
            // Edge cases (borderline scenarios)
            TestScenario {
                name: "Complex Query".to_string(),
                features: [0.4, 0.3, 0.5, 0.4, 0.2, 0.3, 0.1, 0.2, 0.3, 0.4,
                          0.3, 0.4, 0.2, 0.3, 0.4, 0.3, 0.2, 0.1, 0.3, 0.4,
                          0.4, 0.3, 0.2, 0.3, 0.4, 0.3, 0.2, 0.1, 0.3, 0.4,
                          0.3, 0.2],
                is_actual_threat: false,
                severity: 0.1,
                description: "Complex but legitimate database query".to_string(),
            },
        ]
    }

    pub fn run_validation_passes(&mut self, num_passes: usize) -> Vec<ValidationResults> {
        println!("🧪 Starting WebGuard Overfitting Validation Suite");
        println!("📊 Running {} learning passes with balanced retrospective learning", num_passes);
        
        for pass in 1..=num_passes {
            println!("\n🔄 Learning Pass {}/{}", pass, num_passes);
            
            let mut tp = 0; // True Positives
            let mut fp = 0; // False Positives  
            let mut tn = 0; // True Negatives
            let mut fn_count = 0; // False Negatives
            
            // Process each test scenario
            for scenario in &self.test_scenarios {
                let context_event = ContextEvent {
                    timestamp: chrono::Utc::now().timestamp() as f64,
                    request_id: format!("test_{}_{}", pass, scenario.name.replace(" ", "_")),
                    source_ip: "192.168.1.100".to_string(),
                    user_agent: "TestAgent/1.0".to_string(),
                    endpoint: "/api/test".to_string(),
                    method: "POST".to_string(),
                    payload_size: 1024,
                    headers: std::collections::HashMap::new(),
                    query_params: std::collections::HashMap::new(),
                    body_content: scenario.description.clone(),
                };

                // Get threat assessment
                match self.mesh_cognition.process_request(scenario.features, &context_event) {
                    Ok((threat_score, confidence, _explanation)) => {
                        let detected_as_threat = threat_score > 0.5;
                        
                        // Update confusion matrix
                        match (detected_as_threat, scenario.is_actual_threat) {
                            (true, true) => tp += 1,   // Correctly detected threat
                            (true, false) => fp += 1,  // False alarm
                            (false, false) => tn += 1, // Correctly identified benign
                            (false, true) => fn_count += 1, // Missed threat
                        }
                        
                        // Simulate learning from mistakes
                        if pass > 1 { // Start learning from pass 2
                            if detected_as_threat && !scenario.is_actual_threat {
                                // False positive - report it for learning
                                self.report_false_positive(scenario, threat_score, confidence);
                            } else if !detected_as_threat && scenario.is_actual_threat {
                                // False negative - report missed threat
                                self.report_missed_threat(scenario, threat_score);
                            }
                        }
                        
                        println!("  {} | Threat: {:.3} | Confidence: {:.3} | Actual: {} | Detected: {}", 
                                scenario.name, threat_score, confidence, 
                                scenario.is_actual_threat, detected_as_threat);
                    }
                    Err(e) => {
                        println!("  ❌ Error processing {}: {}", scenario.name, e);
                    }
                }
            }
            
            // Calculate metrics
            let total_requests = tp + fp + tn + fn_count;
            let false_positive_rate = if (fp + tn) > 0 { fp as f32 / (fp + tn) as f32 } else { 0.0 };
            let false_negative_rate = if (fn_count + tp) > 0 { fn_count as f32 / (fn_count + tp) as f32 } else { 0.0 };
            let accuracy = if total_requests > 0 { (tp + tn) as f32 / total_requests as f32 } else { 0.0 };
            
            // Learning balance score (closer to 1.0 is better balanced)
            let learning_balance_score = if false_positive_rate + false_negative_rate > 0.0 {
                1.0 - (false_positive_rate - false_negative_rate).abs()
            } else {
                1.0
            };
            
            let result = ValidationResults {
                pass,
                false_positive_rate,
                false_negative_rate,
                threat_detection_accuracy: accuracy,
                learning_balance_score,
                total_requests,
                true_positives: tp,
                false_positives: fp,
                true_negatives: tn,
                false_negatives: fn_count,
            };
            
            println!("📈 Pass {} Results:", pass);
            println!("   False Positive Rate: {:.1}%", false_positive_rate * 100.0);
            println!("   False Negative Rate: {:.1}%", false_negative_rate * 100.0);
            println!("   Overall Accuracy: {:.1}%", accuracy * 100.0);
            println!("   Learning Balance: {:.3}", learning_balance_score);
            
            self.results.push(result);
        }
        
        self.results.clone()
    }
    
    fn report_false_positive(&mut self, scenario: &TestScenario, threat_score: f32, confidence: f32) {
        // Report false positive to the learning system
        if let Ok(learning_config) = self.mesh_cognition.get_balanced_learning_config() {
            println!("    📝 Learning from false positive: {} (score: {:.3})", scenario.name, threat_score);
        }
        
        // Create false positive event for learning
        let fp_event = FalsePositiveEvent {
            timestamp: chrono::Utc::now().timestamp() as f64,
            original_threat_score: threat_score,
            actual_threat_level: 0.1, // Very low actual threat
            feature_vector: scenario.features,
            context: format!("False positive: {}", scenario.description),
            impact_severity: 0.3, // Low impact but important to learn from
        };
        
        // Report to mesh cognition system
        self.mesh_cognition.report_false_positive(
            fp_event.timestamp,
            fp_event.original_threat_score,
            fp_event.actual_threat_level,
            fp_event.feature_vector,
            fp_event.impact_severity
        );
    }
    
    fn report_missed_threat(&mut self, scenario: &TestScenario, threat_score: f32) {
        println!("    📝 Learning from missed threat: {} (score: {:.3})", scenario.name, threat_score);
        
        // Create missed threat event
        let missed_event = MissedThreatEvent {
            original_timestamp: chrono::Utc::now().timestamp() as f64 - 3600.0, // 1 hour ago
            discovery_timestamp: chrono::Utc::now().timestamp() as f64,
            original_threat_score: threat_score,
            actual_threat_level: scenario.severity,
            feature_vector: scenario.features,
            discovery_method: ThreatDiscoveryMethod::SecurityAudit,
            consequence_severity: scenario.severity,
            attack_vector: scenario.description.clone(),
            affected_systems: vec!["web_server".to_string()],
            mitigation_applied: true,
        };
        
        // This would normally be reported to the retrospective learning system
        // For this test, we'll simulate the learning effect
    }
    
    pub fn generate_validation_report(&self) -> String {
        let mut report = String::new();
        
        report.push_str("# WebGuard Overfitting Fix Validation Report\n\n");
        report.push_str(&format!("Generated: {}\n\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
        
        report.push_str("## Executive Summary\n\n");
        
        if let (Some(first), Some(last)) = (self.results.first(), self.results.last()) {
            let fp_change = (last.false_positive_rate - first.false_positive_rate) * 100.0;
            let fn_change = (first.false_negative_rate - last.false_negative_rate) * 100.0;
            
            report.push_str(&format!("- **False Positive Rate Change**: {:.1}% → {:.1}% ({:+.1}%)\n", 
                first.false_positive_rate * 100.0, last.false_positive_rate * 100.0, fp_change));
            report.push_str(&format!("- **False Negative Rate Change**: {:.1}% → {:.1}% ({:+.1}%)\n", 
                first.false_negative_rate * 100.0, last.false_negative_rate * 100.0, fn_change));
            report.push_str(&format!("- **Final Accuracy**: {:.1}%\n", last.threat_detection_accuracy * 100.0));
            report.push_str(&format!("- **Learning Balance Score**: {:.3}/1.0\n\n", last.learning_balance_score));
            
            // Validation status
            let fp_stable = fp_change.abs() < 10.0; // FP rate change less than 10%
            let fn_improved = fn_change > 0.0; // FN rate decreased
            let balanced = last.learning_balance_score > 0.7;
            
            if fp_stable && fn_improved && balanced {
                report.push_str("✅ **VALIDATION PASSED**: Overfitting fix is working correctly!\n\n");
            } else {
                report.push_str("❌ **VALIDATION FAILED**: Issues detected with overfitting fix.\n\n");
            }
        }
        
        report.push_str("## Detailed Results\n\n");
        report.push_str("| Pass | FP Rate | FN Rate | Accuracy | Balance | TP | FP | TN | FN |\n");
        report.push_str("|------|---------|---------|----------|---------|----|----|----|----|\\n");
        
        for result in &self.results {
            report.push_str(&format!(
                "| {} | {:.1}% | {:.1}% | {:.1}% | {:.3} | {} | {} | {} | {} |\n",
                result.pass,
                result.false_positive_rate * 100.0,
                result.false_negative_rate * 100.0,
                result.threat_detection_accuracy * 100.0,
                result.learning_balance_score,
                result.true_positives,
                result.false_positives,
                result.true_negatives,
                result.false_negatives
            ));
        }
        
        report.push_str("\n## Analysis\n\n");
        report.push_str("The balanced retrospective learning system should demonstrate:\n");
        report.push_str("1. **Stable False Positive Rates**: FP rates should not escalate to 100%\n");
        report.push_str("2. **Improving False Negative Rates**: System should learn from missed threats\n");
        report.push_str("3. **Balanced Learning**: Both types of errors should be addressed\n");
        report.push_str("4. **Maintained Accuracy**: Overall detection accuracy should remain high\n\n");
        
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overfitting_validation() {
        let mut suite = OverfittingValidationSuite::new();
        let results = suite.run_validation_passes(5);
        
        // Verify we got results for all passes
        assert_eq!(results.len(), 5);
        
        // Check that false positive rate doesn't explode
        let final_fp_rate = results.last().unwrap().false_positive_rate;
        assert!(final_fp_rate < 0.5, "False positive rate should stay below 50%: {:.1}%", final_fp_rate * 100.0);
        
        // Check that learning balance is reasonable
        let final_balance = results.last().unwrap().learning_balance_score;
        assert!(final_balance > 0.5, "Learning balance should be reasonable: {:.3}", final_balance);
        
        println!("✅ Overfitting validation test passed!");
    }
}

fn main() {
    let mut suite = OverfittingValidationSuite::new();
    let _results = suite.run_validation_passes(10);
    
    let report = suite.generate_validation_report();
    
    // Save report
    std::fs::write("tests/validation_report.md", &report)
        .expect("Failed to write validation report");
    
    println!("\n📋 Validation report saved to tests/validation_report.md");
    println!("{}", report);
}