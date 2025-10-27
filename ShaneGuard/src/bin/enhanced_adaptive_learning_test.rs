use shaneguard::*;
use serde_json::{json, Value};
// use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use rand::Rng;
use chrono;
use base64::prelude::*;

fn main() -> anyhow::Result<()> {
    println!("🧠 ENHANCED ADAPTIVE LEARNING TEST - ShaneGuard Evolution");
    println!("{}", "=".repeat(80));
    
    let mut cfg = config::Config::load_default();
    cfg.embed_dim = 32;
    
    let mut engine = memory_engine::MemoryEngine::new(&cfg)?;
    // Note: We'll focus on the memory engine for this test
    
    // Enhanced test parameters
    let total_iterations = 25; // Increased for better learning observation
    let events_per_iteration = 1000;
    let mut attack_ratio = 0.30; // Start with 30% attacks for better learning signal
    let curriculum_phases = 3; // Progressive difficulty phases
    
    let mut results = Vec::new();
    let mut temporal_context = Vec::new(); // For temporal feature extraction
    let mut performance_history = Vec::new();
    
    println!("📋 TEST CONFIGURATION:");
    println!("   • Total Iterations: {}", total_iterations);
    println!("   • Events per Iteration: {}", events_per_iteration);
    println!("   • Initial Attack Ratio: {:.0}%", attack_ratio * 100.0);
    println!("   • Curriculum Phases: {}", curriculum_phases);
    println!("   • Enhanced Features: Temporal + Behavioral Analysis");
    println!("   • Memory Management: PSI (Persistent Semantic Index) guided with dynamic pruning");
    println!("");
    
    for iteration in 1..=total_iterations {
        println!("🔄 Iteration {} - Curriculum Phase {}", iteration, get_curriculum_phase(iteration, total_iterations, curriculum_phases));
        
        // Adjust attack ratio based on curriculum phase
        attack_ratio = calculate_curriculum_attack_ratio(iteration, total_iterations, curriculum_phases);
        
        let attack_count = (events_per_iteration as f32 * attack_ratio) as usize;
        let benign_count = events_per_iteration - attack_count;
        
        println!("   📊 Attack Events: {} ({:.1}%), Benign Events: {} ({:.1}%)", 
                 attack_count, attack_ratio * 100.0, benign_count, (1.0 - attack_ratio) * 100.0);
        
        let mut correct_predictions = 0;
        let mut total_predictions = 0;
        let mut attack_detections = 0;
        let mut benign_correct = 0;
        let mut false_positives = 0;
        let mut false_negatives = 0;
        
        // Generate events with curriculum-based difficulty
        let difficulty_level = get_difficulty_level(iteration, total_iterations, curriculum_phases);
        
        for event_idx in 0..events_per_iteration {
            let is_attack = event_idx < attack_count;
            
            // Generate enhanced telemetry with temporal context
            let telemetry = if is_attack {
                generate_enhanced_attack_scenario(difficulty_level, &temporal_context)
            } else {
                generate_enhanced_benign_scenario(difficulty_level, &temporal_context)
            };
            
            // Add to temporal context (keep last 10 events)
            temporal_context.push(telemetry.clone());
            if temporal_context.len() > 10 {
                temporal_context.remove(0);
            }
            
            // Enhanced feature extraction with temporal context
            let features = featurizer::featurize_from_telemetry_enhanced(
                &telemetry, &cfg, Some(&temporal_context)
            )?;
            
            // Process through memory engine
            let (similarity, valence, trace_id) = engine.process_features(&features)?;
            
            // Enhanced policy decision with meta-learning feedback
            let action = policy::choose_action(similarity, valence, 0.5, -2.0, 1.0, 0.01);
            let predicted_attack = matches!(action, policy::Action::Throttle | 
                                                  policy::Action::Isolate | 
                                                  policy::Action::Restart | 
                                                  policy::Action::SnapshotAndKill);
            
            // Calculate reward with enhanced feedback
            let reward = calculate_enhanced_reward(is_attack, predicted_attack, similarity, valence);
            
            // Update memory with reward feedback
            if let Some(id) = trace_id {
                engine.reward_update(&id, reward, 0.1)?;
            }
            
            // Meta-learning: provide performance feedback to memory system
            let performance_score = if is_attack == predicted_attack { 1.0 } else { 0.0 };
            engine.meta_learning_update(performance_score);
            
            // Track statistics
            total_predictions += 1;
            if is_attack == predicted_attack {
                correct_predictions += 1;
            }
            
            if is_attack {
                if predicted_attack {
                    attack_detections += 1;
                } else {
                    false_negatives += 1;
                }
            } else {
                if predicted_attack {
                    false_positives += 1;
                } else {
                    benign_correct += 1;
                }
            }
        }
        
        // Calculate comprehensive metrics
        let overall_accuracy = correct_predictions as f32 / total_predictions as f32;
        let attack_accuracy = if attack_count > 0 { 
            attack_detections as f32 / attack_count as f32 
        } else { 
            0.0 
        };
        let benign_accuracy = if benign_count > 0 { 
            benign_correct as f32 / benign_count as f32 
        } else { 
            0.0 
        };
        
        // Get enhanced memory statistics
        let memory_stats = engine.get_memory_stats();
        let psi_stats = engine.get_psi_stats();
        
        performance_history.push(overall_accuracy);
        
        // Store detailed results
        let result = json!({
            "iteration": iteration,
            "curriculum_phase": get_curriculum_phase(iteration, total_iterations, curriculum_phases),
            "difficulty_level": difficulty_level,
            "attack_ratio": attack_ratio,
            "attack_count": attack_count,
            "benign_count": benign_count,
            "overall_accuracy": overall_accuracy,
            "attack_accuracy": attack_accuracy,
            "benign_accuracy": benign_accuracy,
            "attack_detections": attack_detections,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "memory_stats": {
                "trace_count": memory_stats.trace_count,
                "connection_count": memory_stats.connection_count,
                "memory_usage": memory_stats.memory_usage,
                "avg_connection_weight": memory_stats.avg_connection_weight,
                "learning_rate": memory_stats.learning_rate,
                "activation_threshold": memory_stats.activation_threshold,
                "performance_trend": memory_stats.performance_trend
            },
            "psi_stats": {
                "entry_count": psi_stats.entry_count,
                "avg_valence": psi_stats.avg_valence,
                "memory_usage": psi_stats.memory_usage,
                "quality_threshold": psi_stats.quality_threshold
            }
        });
        
        results.push(result);
        
        // Progress reporting
        println!("   📈 Overall Accuracy: {:.1}% | Attack Detection: {:.1}% | Benign Accuracy: {:.1}%", 
                 overall_accuracy * 100.0, attack_accuracy * 100.0, benign_accuracy * 100.0);
        println!("   🧠 Memory: {} traces, {} connections ({:.1}% usage) | Learning Rate: {:.4}", 
                 memory_stats.trace_count, memory_stats.connection_count, 
                 memory_stats.memory_usage * 100.0, memory_stats.learning_rate);
        println!("   🔄 PSI: {} entries ({:.1}% usage) | Performance Trend: {:.3}", 
                 psi_stats.entry_count, psi_stats.memory_usage * 100.0, memory_stats.performance_trend);
        println!("");
    }
    
    // Save comprehensive results
    save_enhanced_results(&results)?;
    
    // Generate learning analysis
    analyze_learning_progression(&results, &performance_history)?;
    
    println!("✅ Enhanced Adaptive Learning Test Complete!");
    println!("📊 Results saved to tests/results/enhanced_adaptive_learning_results.json");
    println!("📈 Analysis saved to tests/reports/ENHANCED_LEARNING_ANALYSIS.md");
    
    Ok(())
}

fn get_curriculum_phase(iteration: usize, total_iterations: usize, phases: usize) -> usize {
    ((iteration - 1) * phases / total_iterations) + 1
}

fn calculate_curriculum_attack_ratio(iteration: usize, total_iterations: usize, phases: usize) -> f32 {
    let phase = get_curriculum_phase(iteration, total_iterations, phases);
    match phase {
        1 => 0.30, // Phase 1: 30% attacks (strong learning signal)
        2 => 0.20, // Phase 2: 20% attacks (balanced learning)
        3 => 0.10, // Phase 3: 10% attacks (realistic deployment)
        _ => 0.15,
    }
}

fn get_difficulty_level(iteration: usize, total_iterations: usize, phases: usize) -> f32 {
    let phase = get_curriculum_phase(iteration, total_iterations, phases);
    let phase_progress = ((iteration - 1) % (total_iterations / phases)) as f32 / (total_iterations / phases) as f32;
    
    match phase {
        1 => 0.3 + phase_progress * 0.3, // Easy to medium (0.3 - 0.6)
        2 => 0.6 + phase_progress * 0.3, // Medium to hard (0.6 - 0.9)
        3 => 0.9 + phase_progress * 0.1, // Hard to expert (0.9 - 1.0)
        _ => 0.5,
    }
}

fn generate_enhanced_attack_scenario(difficulty: f32, temporal_context: &[Value]) -> Value {
    let mut rng = rand::thread_rng();
    
    // Base attack characteristics scaled by difficulty
    let base_intensity = 1.0 + difficulty * 2.0;
    
    // Analyze temporal context for adaptive attacks
    let context_activity = if temporal_context.len() > 3 {
        temporal_context.iter().rev().take(3)
            .map(|event| {
                event.get("network_connections").and_then(|x| x.as_i64()).unwrap_or(0) as f32 +
                event.get("file_operations").and_then(|x| x.as_i64()).unwrap_or(0) as f32
            })
            .sum::<f32>() / 3.0
    } else {
        0.0
    };
    
    // Adaptive attack based on recent activity
    let adaptive_multiplier = if context_activity > 50.0 { 0.7 } else { 1.3 }; // Evade or escalate
    
    json!({
        "timestamp": chrono::Utc::now().timestamp() as f64,
        "process_name": choose_attack_process(difficulty),
        "pid": rng.gen_range(1000..9999),
        
        // Multi-vector attack indicators (scaled by difficulty)
        "network_connections": ((rng.gen_range(15..50) as f32) * base_intensity * adaptive_multiplier) as i64,
        "file_operations": ((rng.gen_range(60..150) as f32) * base_intensity) as i64,
        "memory_usage": rng.gen_range(70.0..95.0) * difficulty,
        "cpu_usage": rng.gen_range(60.0..90.0) * difficulty,
        "payload_size": ((rng.gen_range(5000..15000) as f32) * base_intensity) as i64,
        "entropy": rng.gen_range(6.5..9.5) * difficulty,
        
        // Advanced attack patterns
        "write_remote": ((rng.gen_range(3..12) as f32) * base_intensity) as i64,
        "mprotect_rwx": ((rng.gen_range(1..6) as f32) * difficulty) as i64,
        "new_threads_unexpected": ((rng.gen_range(2..8) as f32) * difficulty) as i64,
        "addr_entropy": rng.gen_range(0.7..0.95) * difficulty,
        "unique_endpoints": ((rng.gen_range(8..20) as f32) * base_intensity) as i64,
        "module_loads_unusual": ((rng.gen_range(2..8) as f32) * difficulty) as i64,
        "open_proc_vmwrite": ((rng.gen_range(1..5) as f32) * difficulty) as i64,
        "ptrace_attempts": ((rng.gen_range(1..4) as f32) * difficulty) as i64,
        "process_vm_writev": ((rng.gen_range(2..8) as f32) * difficulty) as i64,
        
        // Memory and system violations
        "stack_canary_violations": ((rng.gen_range(0..3) as f32) * difficulty) as i64,
        "heap_allocations": ((rng.gen_range(1500..3000) as f32) * base_intensity) as i64,
        "memory_violations": ((rng.gen_range(1..5) as f32) * difficulty) as i64,
        "system_calls": ((rng.gen_range(25..60) as f32) * base_intensity) as i64,
        
        // Suspicious patterns and payloads
        "suspicious_patterns": generate_attack_patterns(difficulty),
        "request_body": generate_malicious_payload(difficulty),
        "admin_api_flag": if rng.gen::<f32>() < difficulty * 0.3 { 1 } else { 0 },
        "endpoint_rarity": rng.gen_range(0.7..0.95) * difficulty,
    })
}

fn generate_enhanced_benign_scenario(difficulty: f32, _temporal_context: &[Value]) -> Value {
    let mut rng = rand::thread_rng();
    
    // Benign scenarios become more realistic (harder to distinguish) with higher difficulty
    let noise_factor = difficulty * 0.3; // Add some suspicious-looking but benign activity
    
    json!({
        "timestamp": chrono::Utc::now().timestamp() as f64,
        "process_name": choose_benign_process(),
        "pid": rng.gen_range(1000..5000),
        
        // Normal activity levels with some noise
        "network_connections": rng.gen_range(1..8) + ((noise_factor * 10.0) as i64),
        "file_operations": rng.gen_range(5..25) + ((noise_factor * 20.0) as i64),
        "memory_usage": rng.gen_range(10.0..40.0) + (noise_factor * 30.0),
        "cpu_usage": rng.gen_range(5.0..30.0) + (noise_factor * 20.0),
        "payload_size": rng.gen_range(100..2000) + ((noise_factor * 1000.0) as i64),
        "entropy": rng.gen_range(2.0..5.5) + (noise_factor * 2.0),
        
        // Minimal system-level indicators
        "write_remote": if rng.gen::<f32>() < noise_factor { rng.gen_range(0..2) } else { 0 },
        "mprotect_rwx": 0,
        "new_threads_unexpected": if rng.gen::<f32>() < noise_factor * 0.5 { 1 } else { 0 },
        "addr_entropy": rng.gen_range(0.1..0.4),
        "unique_endpoints": rng.gen_range(1..4),
        "module_loads_unusual": 0,
        "open_proc_vmwrite": 0,
        "ptrace_attempts": 0,
        "process_vm_writev": 0,
        
        // Clean memory and system behavior
        "stack_canary_violations": 0,
        "heap_allocations": rng.gen_range(100..800),
        "memory_violations": 0,
        "system_calls": rng.gen_range(5..15) + ((noise_factor * 10.0) as i64),
        
        // Benign patterns
        "suspicious_patterns": [],
        "request_body": generate_benign_payload(),
        "admin_api_flag": 0,
        "endpoint_rarity": rng.gen_range(0.1..0.3),
    })
}

fn choose_attack_process(difficulty: f32) -> &'static str {
    let mut rng = rand::thread_rng();
    if difficulty > 0.7 {
        // Advanced attacks use legitimate-looking processes
        match rng.gen_range(0..4) {
            0 => "apache",
            1 => "nginx", 
            2 => "java",
            _ => "python",
        }
    } else {
        // Basic attacks use obvious malicious processes
        match rng.gen_range(0..3) {
            0 => "vulnerable_app",
            1 => "browser",
            _ => "media_player",
        }
    }
}

fn choose_benign_process() -> &'static str {
    let mut rng = rand::thread_rng();
    match rng.gen_range(0..4) {
        0 => "apache",
        1 => "nginx",
        2 => "java",
        _ => "python",
    }
}

fn generate_attack_patterns(difficulty: f32) -> Vec<String> {
    let mut patterns = Vec::new();
    let mut rng = rand::thread_rng();
    
    let pattern_count = (difficulty * 5.0) as usize;
    for _ in 0..pattern_count {
        match rng.gen_range(0..6) {
            0 => patterns.push("sql_injection".to_string()),
            1 => patterns.push("xss_attempt".to_string()),
            2 => patterns.push("buffer_overflow".to_string()),
            3 => patterns.push("deserialization".to_string()),
            4 => patterns.push("memory_corruption".to_string()),
            _ => patterns.push("privilege_escalation".to_string()),
        }
    }
    
    patterns
}

fn generate_malicious_payload(difficulty: f32) -> String {
    let mut rng = rand::thread_rng();
    let base_payload = match rng.gen_range(0..4) {
        0 => "'; DROP TABLE users; --",
        1 => "<script>alert('xss')</script>",
        2 => &"AAAA".repeat((50.0 * difficulty) as usize),
        _ => "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", // Serialized object
    };
    
    // Add obfuscation based on difficulty
    if difficulty > 0.6 {
        format!("{}_{}", base64::prelude::BASE64_STANDARD.encode(base_payload), "obfuscated")
    } else {
        base_payload.to_string()
    }
}

fn generate_benign_payload() -> String {
    let mut rng = rand::thread_rng();
    match rng.gen_range(0..4) {
        0 => "GET /api/users HTTP/1.1",
        1 => "{\"user_id\": 123, \"action\": \"login\"}",
        2 => "username=john&password=secret",
        _ => "Hello, this is a normal request",
    }.to_string()
}

fn calculate_enhanced_reward(is_attack: bool, predicted_attack: bool, similarity: f32, valence: f32) -> f32 {
    let base_reward = if is_attack == predicted_attack { 1.0 } else { -1.0 };
    
    // Enhanced reward based on confidence and context
    let confidence_bonus = if is_attack {
        // For attacks, reward high similarity to negative patterns
        if valence < 0.0 && similarity > 0.5 { 0.5 } else { 0.0 }
    } else {
        // For benign, reward high similarity to positive patterns
        if valence > 0.0 && similarity > 0.5 { 0.5 } else { 0.0 }
    };
    
    // Penalty for overconfident wrong predictions
    let overconfidence_penalty = if is_attack != predicted_attack && similarity > 0.8 {
        -0.3
    } else {
        0.0
    };
    
    let result: f32 = base_reward + confidence_bonus + overconfidence_penalty;
    result.max(-2.0).min(2.0)
}

fn save_enhanced_results(results: &[Value]) -> anyhow::Result<()> {
    std::fs::create_dir_all("tests/results")?;
    
    let mut file = File::create("tests/results/enhanced_adaptive_learning_results.json")?;
    let json_output = serde_json::to_string_pretty(results)?;
    file.write_all(json_output.as_bytes())?;
    
    Ok(())
}

fn analyze_learning_progression(results: &[Value], performance_history: &[f32]) -> anyhow::Result<()> {
    std::fs::create_dir_all("tests/reports")?;
    
    let mut file = File::create("tests/reports/ENHANCED_LEARNING_ANALYSIS.md")?;
    
    writeln!(file, "# Enhanced Adaptive Learning Analysis Report")?;
    writeln!(file, "")?;
    writeln!(file, "**Generated:** {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"))?;
    writeln!(file, "**Test Type:** Enhanced Adaptive Learning with Curriculum Training")?;
    writeln!(file, "**Total Iterations:** {}", results.len())?;
    writeln!(file, "")?;
    
    // Calculate learning metrics
    let initial_performance = performance_history[0];
    let final_performance = performance_history[performance_history.len() - 1];
    let improvement = final_performance - initial_performance;
    
    let max_performance = performance_history.iter().fold(0.0f32, |a, &b| a.max(b));
    let min_performance = performance_history.iter().fold(1.0f32, |a, &b| a.min(b));
    
    writeln!(file, "## Learning Performance Summary")?;
    writeln!(file, "")?;
    writeln!(file, "- **Initial Performance:** {:.1}%", initial_performance * 100.0)?;
    writeln!(file, "- **Final Performance:** {:.1}%", final_performance * 100.0)?;
    writeln!(file, "- **Total Improvement:** {:.1} percentage points", improvement * 100.0)?;
    writeln!(file, "- **Peak Performance:** {:.1}%", max_performance * 100.0)?;
    writeln!(file, "- **Performance Range:** {:.1}% - {:.1}%", min_performance * 100.0, max_performance * 100.0)?;
    writeln!(file, "")?;
    
    // Memory evolution analysis
    let initial_memory = &results[0]["memory_stats"];
    let final_memory = &results[results.len() - 1]["memory_stats"];
    
    writeln!(file, "## Memory System Evolution")?;
    writeln!(file, "")?;
    writeln!(file, "### Initial State")?;
    writeln!(file, "- **Traces:** {}", initial_memory["trace_count"])?;
    writeln!(file, "- **Connections:** {}", initial_memory["connection_count"])?;
    writeln!(file, "- **Learning Rate:** {:.4}", initial_memory["learning_rate"])?;
    writeln!(file, "")?;
    writeln!(file, "### Final State")?;
    writeln!(file, "- **Traces:** {}", final_memory["trace_count"])?;
    writeln!(file, "- **Connections:** {}", final_memory["connection_count"])?;
    writeln!(file, "- **Learning Rate:** {:.4}", final_memory["learning_rate"])?;
    writeln!(file, "- **Memory Usage:** {:.1}%", final_memory["memory_usage"].as_f64().unwrap() * 100.0)?;
    writeln!(file, "")?;
    
    // Curriculum learning analysis
    writeln!(file, "## Curriculum Learning Analysis")?;
    writeln!(file, "")?;
    for phase in 1..=3 {
        let phase_results: Vec<&Value> = results.iter()
            .filter(|r| r["curriculum_phase"].as_u64().unwrap() == phase as u64)
            .collect();
        
        if !phase_results.is_empty() {
            let phase_avg_accuracy: f32 = phase_results.iter()
                .map(|r| r["overall_accuracy"].as_f64().unwrap() as f32)
                .sum::<f32>() / phase_results.len() as f32;
            
            let phase_attack_ratio = phase_results[0]["attack_ratio"].as_f64().unwrap();
            
            writeln!(file, "### Phase {} Results", phase)?;
            writeln!(file, "- **Attack Ratio:** {:.0}%", phase_attack_ratio * 100.0)?;
            writeln!(file, "- **Average Accuracy:** {:.1}%", phase_avg_accuracy * 100.0)?;
            writeln!(file, "- **Iterations:** {}", phase_results.len())?;
            writeln!(file, "")?;
        }
    }
    
    writeln!(file, "## Conclusions")?;
    writeln!(file, "")?;
    if improvement > 0.05 {
        writeln!(file, "✅ **SUCCESSFUL LEARNING DETECTED** - System shows significant improvement over time")?;
    } else if improvement > 0.01 {
        writeln!(file, "⚠️ **MODERATE LEARNING** - System shows some improvement but may need parameter tuning")?;
    } else {
        writeln!(file, "❌ **LIMITED LEARNING** - System requires further enhancement for autonomous learning")?;
    }
    writeln!(file, "")?;
    
    Ok(())
}