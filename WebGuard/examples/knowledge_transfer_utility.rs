use std::env;
use webguard::mesh_cognition::HostMeshCognition;

/// Simple utility for WebGuard cognitive knowledge operations
/// Usage:
///   cargo run --bin knowledge_transfer_utility demo
///   cargo run --bin knowledge_transfer_utility info
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }
    
    match args[1].as_str() {
        "demo" => {
            run_cognitive_demo()?;
        }
        "info" => {
            show_cognitive_info()?;
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
        }
    }
    
    Ok(())
}

fn print_usage() {
    println!("WebGuard Cognitive Knowledge Transfer Utility");
    println!("Usage:");
    println!("  knowledge_transfer_utility demo    - Run cognitive mesh demo");
    println!("  knowledge_transfer_utility info    - Show cognitive architecture info");
}

fn run_cognitive_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧠 WebGuard Cognitive Mesh Demo");
    println!("================================");
    
    // Create cognitive mesh
    let mut mesh = HostMeshCognition::new(0.1, 0.5, 0.3);
    let service_id = mesh.register_service(
        webguard::mesh_cognition::WebServiceType::Generic, 
        2001
    );
    
    // Add some sample patterns
    println!("\n📚 Learning threat patterns...");
    let threat_patterns = vec![
        [0.9, 0.8, 0.7, 0.9, 0.8, 0.6, 0.7, 0.8, 0.9, 0.7, 0.8, 0.9, 0.6, 0.7, 0.8, 0.9,
         0.7, 0.8, 0.6, 0.9, 0.8, 0.7, 0.6, 0.8, 0.9, 0.7, 0.8, 0.6, 0.9, 0.7, 0.8, 0.9],
        [0.8, 0.9, 0.6, 0.8, 0.7, 0.9, 0.8, 0.7, 0.6, 0.8, 0.9, 0.7, 0.8, 0.6, 0.9, 0.8,
         0.7, 0.6, 0.9, 0.8, 0.7, 0.6, 0.9, 0.7, 0.8, 0.6, 0.9, 0.8, 0.7, 0.6, 0.8, 0.9],
    ];
    
    if let Some(service_memory) = mesh.get_service_memory(&service_id) {
        if let Ok(mut bdh) = service_memory.try_lock() {
            for pattern in threat_patterns {
                bdh.add_trace(pattern, 1.0); // 1.0 = threat
            }
        }
    }
    
    // Add benign patterns
    println!("📚 Learning benign patterns...");
    let benign_patterns = vec![
        [0.1, 0.2, 0.3, 0.1, 0.2, 0.4, 0.3, 0.2, 0.1, 0.3, 0.2, 0.1, 0.4, 0.3, 0.2, 0.1,
         0.3, 0.2, 0.4, 0.1, 0.2, 0.3, 0.4, 0.2, 0.1, 0.3, 0.2, 0.4, 0.1, 0.3, 0.2, 0.1],
        [0.2, 0.1, 0.4, 0.2, 0.3, 0.1, 0.2, 0.3, 0.4, 0.2, 0.1, 0.3, 0.2, 0.4, 0.1, 0.2,
         0.3, 0.4, 0.1, 0.2, 0.3, 0.4, 0.1, 0.3, 0.2, 0.4, 0.1, 0.2, 0.3, 0.4, 0.2, 0.1],
    ];
    
    if let Some(service_memory) = mesh.get_service_memory(&service_id) {
        if let Ok(mut bdh) = service_memory.try_lock() {
            for pattern in benign_patterns {
                bdh.add_trace(pattern, 0.0); // 0.0 = benign
            }
        }
    }
    
    // Test pattern recognition
    println!("\n🔍 Testing pattern recognition...");
    let test_pattern = [0.85, 0.75, 0.65, 0.85, 0.75, 0.55, 0.65, 0.75, 0.85, 0.65, 0.75, 0.85, 0.55, 0.65, 0.75, 0.85,
                       0.65, 0.75, 0.55, 0.85, 0.75, 0.65, 0.55, 0.75, 0.85, 0.65, 0.75, 0.55, 0.85, 0.65, 0.75, 0.85];
    
    if let Some(service_memory) = mesh.get_service_memory(&service_id) {
        if let Ok(bdh) = service_memory.try_lock() {
            let similarity = bdh.max_similarity(&test_pattern);
            println!("  • Test pattern similarity: {:.3}", similarity);
            println!("  • Memory traces: {}", bdh.traces.len());
        }
    }
    
    println!("\n✅ Cognitive demo completed!");
    Ok(())
}

fn show_cognitive_info() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧠 WebGuard Cognitive Architecture Info");
    println!("=======================================");
    println!();
    println!("🔧 Core Components:");
    println!("  • HostMeshCognition: Main cognitive mesh controller");
    println!("  • BdhMemory: Behavioral Dynamic Hebbian memory system");
    println!("  • ServiceMemory: Per-service memory isolation");
    println!("  • ValenceController: Emotional valence regulation");
    println!();
    println!("🧮 Architecture:");
    println!("  • PSI (Psi): Cognitive processing framework");
    println!("  • BHSM: Behavioral Hebbian State Memory");
    println!("  • CMNN: Cognitive Mesh Neural Network");
    println!();
    println!("💾 Memory Features:");
    println!("  • 32-dimensional feature vectors");
    println!("  • Hebbian learning connections");
    println!("  • Similarity-based pattern matching");
    println!("  • Dynamic trace management");
    println!();
    println!("🎯 Use Cases:");
    println!("  • Threat pattern recognition");
    println!("  • Behavioral anomaly detection");
    println!("  • Adaptive security learning");
    println!("  • False positive reduction");
    
    Ok(())
}