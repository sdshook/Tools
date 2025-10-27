use shaneguard::*;
use serde_json::{json, Value};
use std::fs::File;
use std::io::Write;
use rand::Rng;

fn main() -> anyhow::Result<()> {
    println!("🧠 QUICK MEMORY SYSTEM TEST - Trace Creation Validation");
    println!("{}", "=".repeat(60));
    
    let mut cfg = config::Config::load_default();
    cfg.embed_dim = 32;
    
    let mut engine = memory_engine::MemoryEngine::new(&cfg)?;
    
    // Test parameters
    let test_iterations = 5;
    let events_per_iteration = 100;
    
    println!("📋 TEST CONFIGURATION:");
    println!("   • Iterations: {}", test_iterations);
    println!("   • Events per Iteration: {}", events_per_iteration);
    println!("   • Focus: Memory trace creation and connection building");
    println!("");
    
    for iteration in 1..=test_iterations {
        println!("🔄 Iteration {}", iteration);
        
        let mut correct_predictions = 0;
        let mut total_predictions = 0;
        
        // Generate diverse events to test memory creation
        for event_idx in 0..events_per_iteration {
            let is_attack = event_idx % 3 == 0; // 33% attacks
            
            // Generate diverse telemetry
            let telemetry = if is_attack {
                generate_diverse_attack_scenario(event_idx)
            } else {
                generate_diverse_benign_scenario(event_idx)
            };
            
            // Enhanced feature extraction
            let features = featurizer::featurize_from_telemetry_enhanced(
                &telemetry, &cfg, None // No temporal context for this test
            )?;
            
            // Process through memory engine
            let (similarity, valence, trace_id) = engine.process_features(&features)?;
            
            // Simple policy decision
            let predicted_attack = valence < -0.1 || similarity > 0.7;
            
            // Calculate reward
            let reward = if is_attack == predicted_attack { 1.0 } else { -1.0 };
            
            // Update memory with reward feedback
            if let Some(id) = trace_id {
                engine.reward_update(&id, reward, 0.1)?;
            }
            
            // Meta-learning update
            let performance_score = if is_attack == predicted_attack { 1.0 } else { 0.0 };
            engine.meta_learning_update(performance_score);
            
            // Track statistics
            total_predictions += 1;
            if is_attack == predicted_attack {
                correct_predictions += 1;
            }
        }
        
        // Get memory statistics
        let memory_stats = engine.get_memory_stats();
        let psi_stats = engine.get_psi_stats();
        let overall_accuracy = correct_predictions as f32 / total_predictions as f32;
        
        println!("   📈 Accuracy: {:.1}%", overall_accuracy * 100.0);
        println!("   🧠 Memory: {} traces, {} connections ({:.1}% usage)", 
                 memory_stats.trace_count, memory_stats.connection_count, 
                 memory_stats.memory_usage * 100.0);
        println!("   🔄 PSI: {} entries ({:.1}% usage)", 
                 psi_stats.entry_count, psi_stats.memory_usage * 100.0);
        println!("   📊 Learning Rate: {:.4}, Performance Trend: {:.3}", 
                 memory_stats.learning_rate, memory_stats.performance_trend);
        println!("");
    }
    
    // Final memory analysis
    let final_memory_stats = engine.get_memory_stats();
    let final_psi_stats = engine.get_psi_stats();
    
    println!("📊 FINAL MEMORY ANALYSIS:");
    println!("   • Total Traces Created: {}", final_memory_stats.trace_count);
    println!("   • Hebbian Connections: {}", final_memory_stats.connection_count);
    println!("   • PSI Entries: {}", final_psi_stats.entry_count);
    println!("   • Memory Usage: {:.1}%", final_memory_stats.memory_usage * 100.0);
    println!("   • Average Connection Weight: {:.3}", final_memory_stats.avg_connection_weight);
    println!("");
    
    if final_memory_stats.trace_count > 1 {
        println!("✅ SUCCESS: Memory system is creating multiple traces!");
    } else {
        println!("❌ ISSUE: Memory system only created {} trace(s)", final_memory_stats.trace_count);
    }
    
    if final_memory_stats.connection_count > 0 {
        println!("✅ SUCCESS: Hebbian connections are being formed!");
    } else {
        println!("❌ ISSUE: No Hebbian connections formed");
    }
    
    if final_psi_stats.entry_count > 0 {
        println!("✅ SUCCESS: PSI system is active!");
    } else {
        println!("❌ ISSUE: PSI system not utilized");
    }
    
    Ok(())
}

fn generate_diverse_attack_scenario(seed: usize) -> Value {
    let mut rng = rand::thread_rng();
    
    // Create diverse attack patterns based on seed
    let attack_type = seed % 4;
    
    match attack_type {
        0 => { // Network-based attack
            json!({
                "timestamp": chrono::Utc::now().timestamp() as f64,
                "process_name": "malware_net",
                "pid": rng.gen_range(2000..9999),
                "network_connections": rng.gen_range(25..60),
                "file_operations": rng.gen_range(10..30),
                "memory_usage": rng.gen_range(40.0..80.0),
                "cpu_usage": rng.gen_range(30.0..70.0),
                "payload_size": rng.gen_range(8000..20000),
                "entropy": rng.gen_range(7.0..9.5),
                "write_remote": rng.gen_range(5..15),
                "mprotect_rwx": rng.gen_range(2..8),
                "new_threads_unexpected": rng.gen_range(3..10),
                "unique_endpoints": rng.gen_range(10..25),
                "system_calls": rng.gen_range(30..80),
                "suspicious_patterns": ["network_scan", "port_probe"],
                "request_body": "GET /admin/users HTTP/1.1",
                "admin_api_flag": 1,
            })
        },
        1 => { // Memory-based attack
            json!({
                "timestamp": chrono::Utc::now().timestamp() as f64,
                "process_name": "buffer_overflow",
                "pid": rng.gen_range(1500..8000),
                "network_connections": rng.gen_range(1..5),
                "file_operations": rng.gen_range(5..15),
                "memory_usage": rng.gen_range(70.0..95.0),
                "cpu_usage": rng.gen_range(50.0..90.0),
                "payload_size": rng.gen_range(15000..50000),
                "entropy": rng.gen_range(6.0..8.5),
                "mprotect_rwx": rng.gen_range(5..15),
                "stack_canary_violations": rng.gen_range(2..8),
                "heap_allocations": rng.gen_range(2000..5000),
                "memory_violations": rng.gen_range(3..12),
                "process_vm_writev": rng.gen_range(4..12),
                "system_calls": rng.gen_range(40..100),
                "suspicious_patterns": ["buffer_overflow", "heap_spray"],
                "request_body": "AAAA".repeat(100),
            })
        },
        2 => { // File system attack
            json!({
                "timestamp": chrono::Utc::now().timestamp() as f64,
                "process_name": "file_manipulator",
                "pid": rng.gen_range(1000..7000),
                "network_connections": rng.gen_range(2..8),
                "file_operations": rng.gen_range(80..200),
                "memory_usage": rng.gen_range(30.0..60.0),
                "cpu_usage": rng.gen_range(40.0..80.0),
                "payload_size": rng.gen_range(5000..15000),
                "entropy": rng.gen_range(5.5..8.0),
                "module_loads_unusual": rng.gen_range(3..10),
                "new_threads_unexpected": rng.gen_range(2..6),
                "system_calls": rng.gen_range(50..120),
                "suspicious_patterns": ["file_injection", "dll_hijack"],
                "request_body": "../../etc/passwd",
            })
        },
        _ => { // Process manipulation attack
            json!({
                "timestamp": chrono::Utc::now().timestamp() as f64,
                "process_name": "proc_injector",
                "pid": rng.gen_range(3000..9500),
                "network_connections": rng.gen_range(3..12),
                "file_operations": rng.gen_range(20..50),
                "memory_usage": rng.gen_range(60.0..85.0),
                "cpu_usage": rng.gen_range(45.0..75.0),
                "payload_size": rng.gen_range(3000..12000),
                "entropy": rng.gen_range(6.5..9.0),
                "ptrace_attempts": rng.gen_range(2..8),
                "open_proc_vmwrite": rng.gen_range(3..10),
                "process_vm_writev": rng.gen_range(5..15),
                "new_threads_unexpected": rng.gen_range(4..12),
                "system_calls": rng.gen_range(35..90),
                "suspicious_patterns": ["process_injection", "privilege_escalation"],
                "request_body": "shellcode_payload",
            })
        }
    }
}

fn generate_diverse_benign_scenario(seed: usize) -> Value {
    let mut rng = rand::thread_rng();
    
    // Create diverse benign patterns based on seed
    let benign_type = seed % 3;
    
    match benign_type {
        0 => { // Web server activity
            json!({
                "timestamp": chrono::Utc::now().timestamp() as f64,
                "process_name": "apache",
                "pid": rng.gen_range(1000..3000),
                "network_connections": rng.gen_range(1..8),
                "file_operations": rng.gen_range(5..20),
                "memory_usage": rng.gen_range(15.0..35.0),
                "cpu_usage": rng.gen_range(10.0..30.0),
                "payload_size": rng.gen_range(200..2000),
                "entropy": rng.gen_range(3.0..5.5),
                "system_calls": rng.gen_range(8..25),
                "suspicious_patterns": [],
                "request_body": "GET /index.html HTTP/1.1",
            })
        },
        1 => { // Database activity
            json!({
                "timestamp": chrono::Utc::now().timestamp() as f64,
                "process_name": "mysql",
                "pid": rng.gen_range(1200..2500),
                "network_connections": rng.gen_range(2..6),
                "file_operations": rng.gen_range(10..40),
                "memory_usage": rng.gen_range(25.0..45.0),
                "cpu_usage": rng.gen_range(15.0..35.0),
                "payload_size": rng.gen_range(500..3000),
                "entropy": rng.gen_range(2.5..4.5),
                "heap_allocations": rng.gen_range(200..800),
                "system_calls": rng.gen_range(12..30),
                "suspicious_patterns": [],
                "request_body": "SELECT * FROM users WHERE id = 1",
            })
        },
        _ => { // Application activity
            json!({
                "timestamp": chrono::Utc::now().timestamp() as f64,
                "process_name": "java",
                "pid": rng.gen_range(1500..4000),
                "network_connections": rng.gen_range(1..4),
                "file_operations": rng.gen_range(8..25),
                "memory_usage": rng.gen_range(20.0..40.0),
                "cpu_usage": rng.gen_range(12.0..28.0),
                "payload_size": rng.gen_range(300..1500),
                "entropy": rng.gen_range(2.8..4.8),
                "heap_allocations": rng.gen_range(300..1000),
                "system_calls": rng.gen_range(10..28),
                "suspicious_patterns": [],
                "request_body": "{\"action\": \"process_data\"}",
            })
        }
    }
}