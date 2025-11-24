use webguard::advanced_feature_extractor::AdvancedFeatureExtractor;
use webguard::enhanced_pattern_recognition::{ExperientialKnowledgeBase, PatternRequestContext};
use std::collections::HashMap;

fn main() {
    let extractor = AdvancedFeatureExtractor::new();
    let pattern_recognition = ExperientialKnowledgeBase::new();
    
    // Test with a simple SQL injection
    let test_payload = "username=' OR '1'='1' --&password=anything";
    println!("Testing payload: {}", test_payload);
    
    let features = extractor.extract_features(test_payload);
    
    println!("\nFeature extraction results:");
    for (i, feature) in features.iter().enumerate() {
        if *feature > 0.0 {
            println!("Feature {}: {:.3}", i, feature);
        }
    }
    
    // Test pattern recognition
    let context = PatternRequestContext {
        method: "POST".to_string(),
        url: "/login".to_string(),
        content_type: Some("application/x-www-form-urlencoded".to_string()),
        user_agent: Some("TestAgent/1.0".to_string()),
        headers: HashMap::new(),
    };
    
    let pattern_analysis = pattern_recognition.analyze_patterns(test_payload, &context);
    println!("\nPattern Analysis Results:");
    println!("Overall threat score: {:.3}", pattern_analysis.overall_threat_score);
    println!("Matched patterns: {}", pattern_analysis.matched_learned_patterns.len());
    println!("Triggered indicators: {}", pattern_analysis.triggered_indicators.len());
    
    // Test XSS payload
    let xss_payload = "<script>alert('XSS')</script>";
    println!("\nTesting XSS payload: {}", xss_payload);
    let xss_features = extractor.extract_features(xss_payload);
    
    for (i, feature) in xss_features.iter().enumerate() {
        if *feature > 0.0 {
            println!("XSS Feature {}: {:.3}", i, feature);
        }
    }
    
    let xss_pattern_analysis = pattern_recognition.analyze_patterns(xss_payload, &context);
    println!("\nXSS Pattern Analysis Results:");
    println!("Overall threat score: {:.3}", xss_pattern_analysis.overall_threat_score);
    println!("Matched patterns: {}", xss_pattern_analysis.matched_learned_patterns.len());
    println!("Triggered indicators: {}", xss_pattern_analysis.triggered_indicators.len());
}