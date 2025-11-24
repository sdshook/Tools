use std::fs;
use webguard::mesh_cognition::HostMeshCognition;
use webguard::memory_engine::bdh_memory::BdhMemory;

/// Demonstrates how to export learned knowledge from WebGuard
/// for use in other security systems
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧠 WebGuard Knowledge Export Demo");
    println!("==================================");
    
    // Create a cognitive mesh and simulate some learning
    let mut mesh_cognition = HostMeshCognition::new(0.1, 0.5, 0.3);
    
    // Simulate learning some threat patterns
    println!("\n📚 Simulating pattern learning...");
    
    let threat_patterns = vec![
        "' OR 1=1 --",
        "<script>alert('xss')</script>",
        "../../../etc/passwd",
        "UNION SELECT * FROM users",
        "javascript:alert(1)",
    ];
    
    let benign_patterns = vec![
        "SELECT * FROM products WHERE id = ?",
        "<div>Welcome to our site</div>",
        "user/profile/settings",
    ];
    
    // Initialize service memory for learning
    let service_id = mesh_cognition.register_service(
        webguard::mesh_cognition::WebServiceType::Apache, 
        1001
    );
    
    // Learn threat patterns
    for pattern in threat_patterns {
        // Simulate feature extraction (simplified)
        let features = [0.8f32; 32]; // High threat features
        if let Some(service_memory) = mesh_cognition.get_service_memory(&service_id) {
            if let Ok(mut bdh) = service_memory.try_lock() {
                bdh.add_trace(features, 1.0); // 1.0 = threat
            }
        }
        println!("  ✅ Learned threat pattern: {}", pattern);
    }
    
    // Learn benign patterns
    for pattern in benign_patterns {
        // Simulate feature extraction (simplified)
        let features = [0.2f32; 32]; // Low threat features
        if let Some(service_memory) = mesh_cognition.get_service_memory(&service_id) {
            if let Ok(mut bdh) = service_memory.try_lock() {
                bdh.add_trace(features, 0.0); // 0.0 = benign
            }
        }
        println!("  ✅ Learned benign pattern: {}", pattern);
    }
    
    // Simulate multiple validations to increase confidence
    println!("\n🔄 Simulating pattern validation...");
    
    // Learn each threat pattern multiple times to build confidence
    let validation_patterns = vec![
        ("' OR 1=1 --", "SQL injection"),
        ("<script>alert('xss')</script>", "XSS"),
        ("../../../etc/passwd", "Path traversal"),
        ("UNION SELECT * FROM users", "SQL union"),
        ("javascript:alert(1)", "JavaScript XSS"),
    ];
    
    for (pattern, description) in validation_patterns {
        for _ in 0..10 {  // Learn each pattern 10 times to build confidence
            let features = [0.9f32; 32]; // High confidence threat features
            if let Some(service_memory) = mesh_cognition.get_service_memory(&service_id) {
                if let Ok(mut bdh) = service_memory.try_lock() {
                    bdh.add_trace(features, 1.0); // 1.0 = threat
                }
            }
        }
        println!("  ✅ Increased confidence for {} pattern", description);
    }
    
    // Display cognitive mesh statistics
    println!("\n📊 Cognitive Mesh Statistics:");
    if let Some(service_memory) = mesh_cognition.get_service_memory(&service_id) {
        if let Ok(bdh) = service_memory.try_lock() {
            println!("  • Memory traces stored: {}", bdh.traces.len());
            println!("  • Service initialized: {}", service_id);
        }
    }
    
    // Demonstrate pattern recognition
    println!("\n🔍 Testing pattern recognition...");
    let test_patterns = vec![
        ([0.9f32; 32], "High threat pattern"),
        ([0.1f32; 32], "Low threat pattern"),
        ([0.5f32; 32], "Medium threat pattern"),
    ];
    
    for (features, description) in test_patterns {
        if let Some(service_memory) = mesh_cognition.get_service_memory(&service_id) {
            if let Ok(bdh) = service_memory.try_lock() {
                let similarity = bdh.max_similarity(&features);
                println!("  • {}: similarity score {:.3}", description, similarity);
            }
        }
    }
    
    println!("\n🔧 Integration Examples:");
    println!("  • ModSecurity: Convert cognitive patterns to SecRule format");
    println!("  • Snort: Generate alert rules with similarity thresholds");
    println!("  • YARA: Create detection rules based on feature vectors");
    println!("  • SIEM: Import cognitive mesh data as threat intelligence");
    println!("  • ML Pipeline: Use BDH memory traces as training data");
    
    println!("\n🎉 Cognitive knowledge export demo completed!");
    println!("The cognitive mesh now contains learned threat patterns.");
    
    Ok(())
}