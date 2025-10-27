use shaneguard::{featurizer, config::Config};
use serde_json::{Value, json};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ShaneGuard Feature Extraction Debug");
    
    let config = Config::load_default();
    println!("Config loaded - embed_dim: {}", config.embed_dim);
    
    // Create sample telemetry data
    let telemetry = json!({
        "pid": 1001,
        "process_name": "apache",
        "network_connections": 5,
        "file_operations": 12,
        "memory_usage": 85.2,
        "cpu_usage": 45.1,
        "suspicious_patterns": ["ObjectInputStream", "readObject", "serialVersionUID"],
        "payload_size": 2048,
        "entropy": 7.8
    });
    
    println!("Sample telemetry: {}", serde_json::to_string_pretty(&telemetry)?);
    
    // Test feature extraction
    match featurizer::featurize_from_telemetry(&telemetry, &config) {
        Ok(features) => {
            println!("Feature extraction successful!");
            println!("Feature vector length: {}", features.len());
            println!("First 10 features: {:?}", &features[..10.min(features.len())]);
            
            // Check if features are all zeros
            let non_zero_count = features.iter().filter(|&&x| x != 0.0).count();
            println!("Non-zero features: {} / {}", non_zero_count, features.len());
            
            if non_zero_count == 0 {
                println!("⚠️  WARNING: All features are zero! This indicates a problem with feature extraction.");
            } else {
                println!("✅ Feature extraction working - {} non-zero features", non_zero_count);
            }
            
            // Show feature statistics
            let sum: f32 = features.iter().sum();
            let mean = sum / features.len() as f32;
            let variance: f32 = features.iter().map(|x| (x - mean).powi(2)).sum::<f32>() / features.len() as f32;
            let std_dev = variance.sqrt();
            
            println!("Feature statistics:");
            println!("  Mean: {:.6}", mean);
            println!("  Std Dev: {:.6}", std_dev);
            println!("  Min: {:.6}", features.iter().fold(f32::INFINITY, |a, &b| a.min(b)));
            println!("  Max: {:.6}", features.iter().fold(f32::NEG_INFINITY, |a, &b| a.max(b)));
        },
        Err(e) => {
            println!("❌ Feature extraction failed: {}", e);
        }
    }
    
    // Test with different telemetry types
    let test_cases = vec![
        ("High Threat", json!({
            "pid": 2001,
            "process_name": "vulnerable_app",
            "network_connections": 1,
            "file_operations": 2,
            "memory_usage": 95.8,
            "cpu_usage": 78.4,
            "suspicious_patterns": ["strcpy", "gets", "sprintf"],
            "payload_size": 4096,
            "entropy": 8.2,
            "stack_canary_violations": 3
        })),
        ("Benign Traffic", json!({
            "pid": 4001,
            "process_name": "apache",
            "network_connections": 2,
            "file_operations": 3,
            "memory_usage": 25.4,
            "cpu_usage": 12.8,
            "suspicious_patterns": [],
            "payload_size": 64,
            "entropy": 2.1,
            "session_duration": 1800
        })),
    ];
    
    for (name, telemetry) in test_cases {
        println!("\n--- Testing {} ---", name);
        match featurizer::featurize_from_telemetry(&telemetry, &config) {
            Ok(features) => {
                let non_zero = features.iter().filter(|&&x| x != 0.0).count();
                let sum: f32 = features.iter().sum();
                println!("{}: {} non-zero features, sum = {:.6}", name, non_zero, sum);
            },
            Err(e) => {
                println!("{}: Error - {}", name, e);
            }
        }
    }
    
    Ok(())
}