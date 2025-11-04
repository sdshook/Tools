use std::time::Instant;
use webguard::mesh_cognition::{HostMeshCognition, WebServiceType};
use webguard::eq_iq_regulator::ContextEvent;

fn main() {
    println!("🔍 WebGuard Diagnostic Analysis");
    println!("================================");
    
    // Initialize WebGuard system
    let mut mesh_cognition = HostMeshCognition::new(0.1, 0.7, 0.5);
    
    // Register a test service
    let service_id = mesh_cognition.register_service(
        WebServiceType::Generic,
        1234,
    );
    
    println!("\n📊 Testing Detection Thresholds and Learning");
    
    // Test different types of requests
    let test_cases = vec![
        ("SELECT * FROM users WHERE id='1' OR '1'='1'", true, "SQL Injection"),
        ("<script>alert('xss')</script>", true, "XSS Attack"),
        ("../../../etc/passwd", true, "Path Traversal"),
        ("GET /api/users HTTP/1.1", false, "Legitimate Request"),
        ("POST /login username=admin&password=secret", false, "Normal Login"),
    ];
    
    for (i, (request, is_threat, description)) in test_cases.iter().enumerate() {
        println!("\n🧪 Test {}: {}", i + 1, description);
        println!("   Request: {}", request);
        println!("   Expected Threat: {}", is_threat);
        
        // Extract features
        let features = extract_simple_features(request);
        println!("   Features: {:?}", &features[0..8]); // Show first 8 features
        
        // Create context event
        let context_event = ContextEvent {
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64(),
            context_stability: if *is_threat { 0.3 } else { 0.8 },
            threat_level: if *is_threat { 0.8 } else { 0.1 },
            response_appropriateness: if *is_threat { 0.9 } else { 0.5 },
        };
        
        // Get memory count before
        let memory_before = if let Some(memory) = mesh_cognition.get_service_memory(&service_id) {
            if let Ok(bdh) = memory.try_lock() {
                bdh.get_trace_count()
            } else { 0 }
        } else { 0 };
        
        // Process request
        let start_time = Instant::now();
        let result = mesh_cognition.process_request(features, &context_event);
        let processing_time = start_time.elapsed();
        
        // Get memory count after
        let memory_after = if let Some(memory) = mesh_cognition.get_service_memory(&service_id) {
            if let Ok(bdh) = memory.try_lock() {
                bdh.get_trace_count()
            } else { 0 }
        } else { 0 };
        
        match result {
            Ok((similarity, valence, trace_id)) => {
                println!("   ✅ Processing successful:");
                println!("      Similarity: {:.4}", similarity);
                println!("      Valence: {:.4}", valence);
                println!("      Trace ID: {}", trace_id);
                println!("      Processing Time: {:.4}ms", processing_time.as_secs_f64() * 1000.0);
                println!("      Memory Before: {}", memory_before);
                println!("      Memory After: {}", memory_after);
                println!("      Memory Growth: {}", memory_after - memory_before);
                
                // Analyze detection with different thresholds
                println!("   🎯 Detection Analysis:");
                for threshold in [0.1, 0.3, 0.5, 0.7, 0.9] {
                    let detected = similarity > threshold;
                    let correct = detected == *is_threat;
                    let status = if correct { "✅" } else { "❌" };
                    println!("      Threshold {:.1}: {} (detected: {}, correct: {})", 
                             threshold, status, detected, correct);
                }
            }
            Err(e) => {
                println!("   ❌ Processing failed: {}", e);
            }
        }
    }
    
    // Final memory analysis
    println!("\n📈 Final Memory Analysis");
    if let Some(memory) = mesh_cognition.get_service_memory(&service_id) {
        if let Ok(bdh) = memory.try_lock() {
            let final_count = bdh.get_trace_count();
            println!("   Total Memory Traces: {}", final_count);
            if final_count == 0 {
                println!("   ⚠️  WARNING: No memory traces stored - learning system not working!");
            } else {
                println!("   ✅ Memory traces stored successfully");
            }
        }
    }
    
    println!("\n🔍 Diagnostic Complete");
}

// Simple feature extraction for testing
fn extract_simple_features(request_data: &str) -> [f32; 32] {
    let mut features = [0.0; 32];
    
    // Basic feature extraction
    features[0] = request_data.len() as f32 / 1000.0; // Length feature
    features[1] = if request_data.contains("'") { 1.0 } else { 0.0 }; // SQL injection indicator
    features[2] = if request_data.contains("<script>") { 1.0 } else { 0.0 }; // XSS indicator
    features[3] = if request_data.contains("../") { 1.0 } else { 0.0 }; // Path traversal
    features[4] = if request_data.contains(";") { 1.0 } else { 0.0 }; // Command injection
    features[5] = if request_data.contains("HTTP/1.1") { 1.0 } else { 0.0 }; // Valid HTTP
    features[6] = if request_data.contains("GET") || request_data.contains("POST") { 1.0 } else { 0.0 }; // HTTP method
    
    // Add some entropy-based features
    let entropy = calculate_entropy(request_data.as_bytes());
    features[7] = entropy;
    
    features
}

fn calculate_entropy(data: &[u8]) -> f32 {
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    
    let len = data.len() as f32;
    let mut entropy = 0.0;
    
    for &count in &counts {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }
    
    entropy / 8.0 // Normalize to 0-1 range
}