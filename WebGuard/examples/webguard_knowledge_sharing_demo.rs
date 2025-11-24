use webguard::mesh_cognition::HostMeshCognition;

/// Demonstrates WebGuard cognitive mesh knowledge sharing
/// for rapid deployment and collaborative learning
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔄 WebGuard Cognitive Knowledge Sharing Demo");
    println!("============================================");
    println!("Demonstrating cognitive mesh knowledge transfer\n");
    
    // Create experienced WebGuard cognitive mesh
    println!("🏭 Creating Experienced WebGuard Cognitive Mesh");
    println!("-----------------------------------------------");
    let mut experienced_mesh = HostMeshCognition::new(0.1, 0.5, 0.3);
    let experienced_service_id = experienced_mesh.register_service(
        webguard::mesh_cognition::WebServiceType::Apache, 
        1001
    );
    
    // Train with production threat patterns
    println!("📚 Training with production threat patterns...");
    let threat_patterns = vec![
        // SQL injection patterns
        [0.9, 0.8, 0.7, 0.9, 0.8, 0.6, 0.7, 0.8, 0.9, 0.7, 0.8, 0.9, 0.6, 0.7, 0.8, 0.9,
         0.7, 0.8, 0.6, 0.9, 0.8, 0.7, 0.6, 0.8, 0.9, 0.7, 0.8, 0.6, 0.9, 0.7, 0.8, 0.9],
        // XSS patterns
        [0.8, 0.9, 0.6, 0.8, 0.7, 0.9, 0.8, 0.7, 0.6, 0.8, 0.9, 0.7, 0.8, 0.6, 0.9, 0.8,
         0.7, 0.6, 0.9, 0.8, 0.7, 0.6, 0.9, 0.7, 0.8, 0.6, 0.9, 0.8, 0.7, 0.6, 0.8, 0.9],
        // Command injection patterns
        [0.85, 0.75, 0.65, 0.85, 0.75, 0.55, 0.65, 0.75, 0.85, 0.65, 0.75, 0.85, 0.55, 0.65, 0.75, 0.85,
         0.65, 0.75, 0.55, 0.85, 0.75, 0.65, 0.55, 0.75, 0.85, 0.65, 0.75, 0.55, 0.85, 0.65, 0.75, 0.85],
    ];
    
    if let Some(service_memory) = experienced_mesh.get_service_memory(&experienced_service_id) {
        if let Ok(mut bdh) = service_memory.try_lock() {
            for pattern in threat_patterns {
                bdh.add_trace(pattern, 1.0); // 1.0 = threat
            }
            println!("  • Learned {} threat patterns", bdh.traces.len());
        }
    }
    
    // Add benign patterns for balance
    println!("📚 Training with benign patterns...");
    let benign_patterns = vec![
        [0.1, 0.2, 0.3, 0.1, 0.2, 0.4, 0.3, 0.2, 0.1, 0.3, 0.2, 0.1, 0.4, 0.3, 0.2, 0.1,
         0.3, 0.2, 0.4, 0.1, 0.2, 0.3, 0.4, 0.2, 0.1, 0.3, 0.2, 0.4, 0.1, 0.3, 0.2, 0.1],
        [0.2, 0.1, 0.4, 0.2, 0.3, 0.1, 0.2, 0.3, 0.4, 0.2, 0.1, 0.3, 0.2, 0.4, 0.1, 0.2,
         0.3, 0.4, 0.1, 0.2, 0.3, 0.4, 0.1, 0.3, 0.2, 0.4, 0.1, 0.2, 0.3, 0.4, 0.2, 0.1],
    ];
    
    if let Some(service_memory) = experienced_mesh.get_service_memory(&experienced_service_id) {
        if let Ok(mut bdh) = service_memory.try_lock() {
            for pattern in benign_patterns {
                bdh.add_trace(pattern, 0.0); // 0.0 = benign
            }
            println!("  • Total patterns in memory: {}", bdh.traces.len());
        }
    }
    
    // Create new WebGuard instance for knowledge transfer
    println!("\n🆕 Creating New WebGuard Instance (Deployment Target)");
    println!("----------------------------------------------------");
    let mut new_mesh = HostMeshCognition::new(0.1, 0.5, 0.3);
    let new_service_id = new_mesh.register_service(
        webguard::mesh_cognition::WebServiceType::Nginx, 
        2001
    );
    
    // Simulate knowledge transfer (in a real implementation, this would involve
    // serializing and transferring the cognitive patterns)
    println!("🔄 Transferring cognitive knowledge...");
    
    // For demonstration, we'll copy some patterns from experienced to new mesh
    if let (Some(exp_memory), Some(new_memory)) = (
        experienced_mesh.get_service_memory(&experienced_service_id),
        new_mesh.get_service_memory(&new_service_id)
    ) {
        if let (Ok(exp_bdh), Ok(mut new_bdh)) = (exp_memory.try_lock(), new_memory.try_lock()) {
            // Transfer a subset of patterns
            let transfer_count = exp_bdh.traces.len().min(3);
            for i in 0..transfer_count {
                if let Some(trace) = exp_bdh.traces.get(i) {
                    new_bdh.add_trace(trace.vec, trace.valence);
                }
            }
            println!("  • Transferred {} cognitive patterns", transfer_count);
            println!("  • New instance now has {} patterns", new_bdh.traces.len());
        }
    }
    
    // Test both instances on a sample threat
    println!("\n🔍 Testing Both Instances");
    println!("-------------------------");
    let test_pattern = [0.82, 0.78, 0.68, 0.82, 0.78, 0.58, 0.68, 0.78, 0.82, 0.68, 0.78, 0.82, 0.58, 0.68, 0.78, 0.82,
                       0.68, 0.78, 0.58, 0.82, 0.78, 0.68, 0.58, 0.78, 0.82, 0.68, 0.78, 0.58, 0.82, 0.68, 0.78, 0.82];
    
    // Test experienced instance
    if let Some(service_memory) = experienced_mesh.get_service_memory(&experienced_service_id) {
        if let Ok(bdh) = service_memory.try_lock() {
            let similarity = bdh.max_similarity(&test_pattern);
            println!("  • Experienced instance similarity: {:.3}", similarity);
        }
    }
    
    // Test new instance
    if let Some(service_memory) = new_mesh.get_service_memory(&new_service_id) {
        if let Ok(bdh) = service_memory.try_lock() {
            let similarity = bdh.max_similarity(&test_pattern);
            println!("  • New instance similarity: {:.3}", similarity);
        }
    }
    
    println!("\n✅ Knowledge sharing demonstration completed!");
    println!("The new WebGuard instance can now leverage cognitive patterns");
    println!("learned by the experienced instance, enabling rapid deployment");
    println!("with pre-trained threat recognition capabilities.");
    
    Ok(())
}