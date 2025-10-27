use std::sync::{Arc, Mutex};
use tracing::{info, warn};
use shaneguard::mesh_cognition::{HostMeshCognition, WebServiceType};
use shaneguard::config::Config;
use shaneguard::memory_engine::bdh_memory::{BdhMemory, EMBED_DIM};
use shaneguard::featurizer;
use shaneguard::policy;
use serde_json::json;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    info!("ShaneGuard Integration Testing Suite Starting...");

    // Test 1: Memory Consolidation and Pattern Recognition
    test_memory_consolidation().await?;
    
    // Test 2: Cross-Process Intelligence Sharing
    test_cross_process_sharing().await?;
    
    // Test 3: Learning Progression Validation
    test_learning_progression().await?;
    
    // Test 4: Real-World Attack Simulation
    test_realistic_attack_scenarios().await?;
    
    info!("Integration testing complete!");
    Ok(())
}

async fn test_memory_consolidation() -> Result<(), Box<dyn std::error::Error>> {
    info!("=== Testing Memory Consolidation and Pattern Recognition ===");
    
    let cfg = Config::load_default();
    let mut bdh = BdhMemory::new();
    
    // Simulate repeated attack patterns to test consolidation
    let attack_patterns = vec![
        ("Java Deserialization", json!({
            "write_remote": 12, "mprotect_rwx": 2, "addr_entropy": 0.85,
            "request_body": "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAACdAAEY2FsY3QABGV4aXQ=",
            "admin_api_flag": 1, "endpoint_rarity": 0.9
        })),
        ("Python Pickle", json!({
            "write_remote": 8, "mprotect_rwx": 1, "addr_entropy": 0.8,
            "request_body": "gASVNAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwYX19pbXBvcnRfXygib3MiKS5zeXN0ZW0oImxzIimUhZRSlC4=",
            "admin_api_flag": 1, "endpoint_rarity": 0.85
        })),
        (".NET BinaryFormatter", json!({
            "write_remote": 15, "mprotect_rwx": 3, "addr_entropy": 0.9,
            "request_body": "AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAAA=",
            "admin_api_flag": 1, "endpoint_rarity": 0.95
        })),
    ];
    
    let mut pattern_memories = HashMap::new();
    
    // Process each pattern multiple times to build memory
    for iteration in 1..=10 {
        info!("Memory consolidation iteration {}", iteration);
        
        for (pattern_name, telemetry) in &attack_patterns {
            if let Ok(features) = featurizer::featurize_from_telemetry(telemetry, &cfg) {
                let features_array: [f32; EMBED_DIM] = features.try_into().unwrap_or([0.0; EMBED_DIM]);
                
                // Check if we recognize this pattern
                let similar = bdh.retrieve_similar(&features_array, 1);
                let (similarity, existing_valence) = if let Some((trace, sim)) = similar.first() {
                    (*sim, trace.valence)
                } else {
                    (0.0, 0.0)
                };
                
                // Add trace if new or reinforce existing
                let trace_id = if similarity > 0.8 {
                    // Reinforce existing pattern
                    if let Some((trace, _)) = similar.first() {
                        let trace_id = trace.id.clone();
                        let reward: f32 = -0.8; // Strong negative reward for attack
                        bdh.reward_update(&trace_id, reward, cfg.eta);
                        trace_id
                    } else {
                        bdh.add_trace(features_array, -0.7)
                    }
                } else {
                    // New pattern
                    bdh.add_trace(features_array, -0.7)
                };
                
                pattern_memories.insert(pattern_name.to_string(), (trace_id, similarity, existing_valence));
                
                info!("  {}: similarity={:.3}, valence={:.3}", pattern_name, similarity, existing_valence);
            }
        }
        
        let (conn_count, avg_weight, avg_self_weight) = bdh.get_hebbian_stats();
        info!("  Consolidation progress: {} connections, avg_weight={:.4}, self_weight={:.4}", 
              conn_count, avg_weight, avg_self_weight);
    }
    
    // Test pattern recognition after consolidation
    info!("Testing pattern recognition after consolidation:");
    for (pattern_name, telemetry) in &attack_patterns {
        if let Ok(features) = featurizer::featurize_from_telemetry(telemetry, &cfg) {
            let features_array: [f32; EMBED_DIM] = features.try_into().unwrap_or([0.0; EMBED_DIM]);
            let similar = bdh.retrieve_similar(&features_array, 1);
            
            if let Some((trace, similarity)) = similar.first() {
                info!("  {} -> similarity={:.4}, valence={:.3}, uses={}", 
                      pattern_name, similarity, trace.valence, trace.uses);
                
                if *similarity < 0.9 {
                    warn!("⚠️  Pattern recognition issue: {} similarity too low ({:.4})", pattern_name, similarity);
                } else {
                    info!("✅ Pattern recognized: {} ({:.4})", pattern_name, similarity);
                }
            }
        }
    }
    
    Ok(())
}

async fn test_cross_process_sharing() -> Result<(), Box<dyn std::error::Error>> {
    info!("=== Testing Cross-Process Intelligence Sharing ===");
    
    let cfg = Config::load_default();
    
    // Create mesh with multiple services
    let mesh = Arc::new(Mutex::new(HostMeshCognition::new(
        cfg.mesh_learning_rate,
        cfg.cross_service_threshold,
        cfg.aggression_init,
    )));
    
    // Register different service types
    let service_ids = {
        let mut m = mesh.lock().unwrap();
        vec![
            m.register_service(WebServiceType::IIS, 1001),    // E-commerce
            m.register_service(WebServiceType::IIS, 1002),    // User Portal
            m.register_service(WebServiceType::Apache, 2001), // API Gateway
            m.register_service(WebServiceType::Apache, 2002), // Admin Panel
        ]
    };
    
    info!("Registered services: {:?}", service_ids);
    
    // Simulate attack on first service
    let attack_telemetry = json!({
        "write_remote": 20, "mprotect_rwx": 4, "addr_entropy": 0.95,
        "request_body": "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAACdAAEY2FsY3QABGV4aXQ=",
        "admin_api_flag": 1, "endpoint_rarity": 0.98
    });
    
    // Process attack on service 1
    let (_similarity, _valence, _action) = {
        let m = mesh.lock().unwrap();
        if let Ok(features) = featurizer::featurize_from_telemetry(&attack_telemetry, &cfg) {
            let features_array: [f32; EMBED_DIM] = features.try_into().unwrap_or([0.0; EMBED_DIM]);
            
            if let Some(service_memory) = m.get_service_memory(&service_ids[0]) {
                let (top_sim, avg_valence) = {
                    let bdh = service_memory.lock().unwrap();
                    let sims = bdh.retrieve_similar(&features_array, 5);
                    if !sims.is_empty() {
                        let top = sims[0].1;
                        let sum_val: f32 = sims.iter().map(|(t, s)| t.valence * s).sum();
                        let sum_s: f32 = sims.iter().map(|(_t, s)| *s).sum();
                        let avg = if sum_s > 0.0 { sum_val / (sum_s + 1e-6) } else { 0.0 };
                        (top, avg)
                    } else {
                        (0.0, 0.0)
                    }
                };

                let aggression = m.get_host_aggression();
                let action = policy::choose_action(top_sim, avg_valence, aggression, cfg.beta, cfg.gamma, cfg.eps_explore);
                
                info!("Service {} attack processing: similarity={:.3}, valence={:.3}, action={:?}", 
                      service_ids[0], top_sim, avg_valence, action);
                
                // Update memory based on action appropriateness
                let reward: f32 = match action {
                    policy::Action::Log => -0.8,
                    policy::Action::Notify => -0.5,
                    policy::Action::Throttle => -0.2,
                    policy::Action::Isolate => 0.3,
                    policy::Action::Restart => 0.6,
                    policy::Action::SnapshotAndKill => 1.0,
                };
                
                drop(m); // Release mesh lock
                
                // Update service memory
                {
                    let mut bdh = service_memory.lock().unwrap();
                    let maxsim = bdh.max_similarity(&features_array);
                    if maxsim < cfg.tau_novel {
                        let init_val = reward.max(-1.0).min(1.0);
                        let _id = bdh.add_trace(features_array, init_val);
                    } else {
                        let similar_traces: Vec<(String, f32)> = {
                            let sims = bdh.retrieve_similar(&features_array, 5);
                            sims.into_iter()
                                .take(5)
                                .map(|(trace, similarity)| (trace.id.clone(), similarity))
                                .collect()
                        };
                        
                        for (trace_id, similarity) in similar_traces {
                            let scaled = reward * similarity;
                            bdh.reward_update(&trace_id, scaled, cfg.eta);
                        }
                    }
                }
                
                (top_sim, avg_valence, action)
            } else {
                (0.0, 0.0, policy::Action::Log)
            }
        } else {
            (0.0, 0.0, policy::Action::Log)
        }
    };
    
    // Test if other services learned from the attack
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    info!("Testing cross-service learning:");
    for service_id in service_ids.iter().skip(1) {
        let m = mesh.lock().unwrap();
        if let Ok(features) = featurizer::featurize_from_telemetry(&attack_telemetry, &cfg) {
            let features_array: [f32; EMBED_DIM] = features.try_into().unwrap_or([0.0; EMBED_DIM]);
            
            if let Some(service_memory) = m.get_service_memory(service_id) {
                let (similarity, valence) = {
                    let bdh = service_memory.lock().unwrap();
                    let sims = bdh.retrieve_similar(&features_array, 1);
                    if !sims.is_empty() {
                        (sims[0].1, sims[0].0.valence)
                    } else {
                        (0.0, 0.0)
                    }
                };
                
                let aggression = m.get_host_aggression();
                let action = policy::choose_action(similarity, valence, aggression, cfg.beta, cfg.gamma, cfg.eps_explore);
                
                info!("  Service {} (cross-learned): similarity={:.3}, valence={:.3}, action={:?}", 
                      service_id, similarity, valence, action);
                
                if similarity > 0.5 {
                    info!("✅ Cross-service learning successful for service {}", service_id);
                } else {
                    warn!("⚠️  Cross-service learning weak for service {} (similarity={:.3})", service_id, similarity);
                }
            }
        }
    }
    
    // Test PSI Index sharing
    {
        let m = mesh.lock().unwrap();
        let shared_psi = m.get_shared_psi();
        let psi_entry_count = if let Ok(psi) = shared_psi.try_lock() {
            psi.len()
        } else {
            0
        };
        
        info!("PSI Index stats: {} entries", psi_entry_count);
        
        if psi_entry_count > 0 {
            info!("✅ PSI Index sharing active");
        } else {
            warn!("⚠️  PSI Index not populated");
        }
    }
    
    Ok(())
}

async fn test_learning_progression() -> Result<(), Box<dyn std::error::Error>> {
    info!("=== Testing Learning Progression Validation ===");
    
    let cfg = Config::load_default();
    let mesh = Arc::new(Mutex::new(HostMeshCognition::new(
        cfg.mesh_learning_rate,
        cfg.cross_service_threshold,
        cfg.aggression_init,
    )));
    
    let service_id = {
        let mut m = mesh.lock().unwrap();
        m.register_service(WebServiceType::IIS, 3001)
    };
    
    let mut learning_metrics = Vec::new();
    
    // Progressive learning simulation
    for iteration in 1..=10 {
        info!("Learning progression iteration {}", iteration);
        
        // Generate increasingly sophisticated attack
        let attack_intensity = 0.5 + (iteration as f32 * 0.05);
        let attack_telemetry = json!({
            "write_remote": (10.0 * attack_intensity) as i64,
            "mprotect_rwx": (2.0 * attack_intensity) as i64,
            "addr_entropy": 0.7 + (attack_intensity * 0.2),
            "request_body": format!("rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAACdAAEY2FsY3QABGV4aXQ={}", iteration),
            "admin_api_flag": 1,
            "endpoint_rarity": 0.8 + (attack_intensity * 0.15)
        });
        
        let (similarity, valence, action, aggression) = {
            let m = mesh.lock().unwrap();
            if let Ok(features) = featurizer::featurize_from_telemetry(&attack_telemetry, &cfg) {
                let features_array: [f32; EMBED_DIM] = features.try_into().unwrap_or([0.0; EMBED_DIM]);
                
                if let Some(service_memory) = m.get_service_memory(&service_id) {
                    let (sim, val) = {
                        let bdh = service_memory.lock().unwrap();
                        let sims = bdh.retrieve_similar(&features_array, 5);
                        if !sims.is_empty() {
                            let top = sims[0].1;
                            let sum_val: f32 = sims.iter().map(|(t, s)| t.valence * s).sum();
                            let sum_s: f32 = sims.iter().map(|(_t, s)| *s).sum();
                            let avg = if sum_s > 0.0 { sum_val / (sum_s + 1e-6) } else { 0.0 };
                            (top, avg)
                        } else {
                            (0.0, 0.0)
                        }
                    };

                    let aggr = m.get_host_aggression();
                    let act = policy::choose_action(sim, val, aggr, cfg.beta, cfg.gamma, cfg.eps_explore);
                    
                    // Reward based on action appropriateness
                    let reward: f32 = match act {
                        policy::Action::Log => -0.7,
                        policy::Action::Notify => -0.4,
                        policy::Action::Throttle => -0.1,
                        policy::Action::Isolate => 0.4,
                        policy::Action::Restart => 0.7,
                        policy::Action::SnapshotAndKill => 1.0,
                    };
                    
                    drop(m); // Release mesh lock
                    
                    // Update service memory
                    {
                        let mut bdh = service_memory.lock().unwrap();
                        let maxsim = bdh.max_similarity(&features_array);
                        if maxsim < cfg.tau_novel {
                            let init_val = reward.max(-1.0).min(1.0);
                            let _id = bdh.add_trace(features_array, init_val);
                        } else {
                            let similar_traces: Vec<(String, f32)> = {
                                let sims = bdh.retrieve_similar(&features_array, 5);
                                sims.into_iter()
                                    .take(5)
                                    .map(|(trace, similarity)| (trace.id.clone(), similarity))
                                    .collect()
                            };
                            
                            for (trace_id, similarity) in similar_traces {
                                let scaled = reward * similarity;
                                bdh.reward_update(&trace_id, scaled, cfg.eta);
                            }
                        }
                    }
                    
                    (sim, val, act, aggr)
                } else {
                    (0.0, 0.0, policy::Action::Log, 0.0)
                }
            } else {
                (0.0, 0.0, policy::Action::Log, 0.0)
            }
        };
        
        info!("  Metrics: similarity={:.3}, valence={:.3}, aggression={:.3}, action={:?}", 
              similarity, valence, aggression, action);
        learning_metrics.push((iteration, similarity, valence, action, aggression));
    }
    
    // Analyze learning progression
    info!("Learning progression analysis:");
    
    let initial_similarity = learning_metrics[0].1;
    let final_similarity = learning_metrics.last().unwrap().1;
    let similarity_improvement = final_similarity - initial_similarity;
    
    let initial_valence = learning_metrics[0].2;
    let final_valence = learning_metrics.last().unwrap().2;
    let valence_change = final_valence - initial_valence;
    
    let initial_aggression = learning_metrics[0].4;
    let final_aggression = learning_metrics.last().unwrap().4;
    let aggression_increase = final_aggression - initial_aggression;
    
    info!("  Similarity: {:.3} -> {:.3} (Δ{:.3})", initial_similarity, final_similarity, similarity_improvement);
    info!("  Valence: {:.3} -> {:.3} (Δ{:.3})", initial_valence, final_valence, valence_change);
    info!("  Aggression: {:.3} -> {:.3} (Δ{:.3})", initial_aggression, final_aggression, aggression_increase);
    
    // Count action escalations
    let mut action_escalations = 0;
    for i in 1..learning_metrics.len() {
        let prev_action = &learning_metrics[i-1].3;
        let curr_action = &learning_metrics[i].3;
        
        let prev_severity = action_severity(prev_action);
        let curr_severity = action_severity(curr_action);
        
        if curr_severity > prev_severity {
            action_escalations += 1;
        }
    }
    
    info!("  Action escalations: {}", action_escalations);
    
    // Validation
    if similarity_improvement > 0.3 {
        info!("✅ Similarity learning: Excellent improvement ({:.3})", similarity_improvement);
    } else if similarity_improvement > 0.1 {
        info!("✅ Similarity learning: Good improvement ({:.3})", similarity_improvement);
    } else {
        warn!("⚠️  Similarity learning: Limited improvement ({:.3})", similarity_improvement);
    }
    
    if valence_change < -0.2 {
        info!("✅ Threat recognition: Strong negative valence development ({:.3})", valence_change);
    } else if valence_change < -0.1 {
        info!("✅ Threat recognition: Moderate negative valence development ({:.3})", valence_change);
    } else {
        warn!("⚠️  Threat recognition: Insufficient valence development ({:.3})", valence_change);
    }
    
    if aggression_increase > 0.2 {
        info!("✅ Aggression escalation: Strong increase ({:.3})", aggression_increase);
    } else if aggression_increase > 0.1 {
        info!("✅ Aggression escalation: Moderate increase ({:.3})", aggression_increase);
    } else {
        warn!("⚠️  Aggression escalation: Limited increase ({:.3})", aggression_increase);
    }
    
    if action_escalations >= 3 {
        info!("✅ Action escalation: Multiple escalations observed ({})", action_escalations);
    } else if action_escalations >= 1 {
        info!("✅ Action escalation: Some escalations observed ({})", action_escalations);
    } else {
        warn!("⚠️  Action escalation: No escalations observed");
    }
    
    Ok(())
}

async fn test_realistic_attack_scenarios() -> Result<(), Box<dyn std::error::Error>> {
    info!("=== Testing Realistic Attack Scenarios ===");
    
    let cfg = Config::load_default();
    let mesh = Arc::new(Mutex::new(HostMeshCognition::new(
        cfg.mesh_learning_rate,
        cfg.cross_service_threshold,
        cfg.aggression_init,
    )));
    
    let service_id = {
        let mut m = mesh.lock().unwrap();
        m.register_service(WebServiceType::Apache, 4001)
    };
    
    // Realistic attack scenarios
    let scenarios = vec![
        ("SQL Injection", json!({
            "write_remote": 0, "mprotect_rwx": 0, "addr_entropy": 0.3,
            "request_body": "' OR '1'='1'; DROP TABLE users; --",
            "admin_api_flag": 0, "endpoint_rarity": 0.2
        })),
        ("XSS Attack", json!({
            "write_remote": 0, "mprotect_rwx": 0, "addr_entropy": 0.4,
            "request_body": "<script>alert('XSS')</script>",
            "admin_api_flag": 0, "endpoint_rarity": 0.1
        })),
        ("Command Injection", json!({
            "write_remote": 5, "mprotect_rwx": 1, "addr_entropy": 0.6,
            "request_body": "file.txt; rm -rf /",
            "admin_api_flag": 1, "endpoint_rarity": 0.8
        })),
        ("Buffer Overflow", json!({
            "write_remote": 25, "mprotect_rwx": 5, "addr_entropy": 0.95,
            "request_body": "A".repeat(1000),
            "admin_api_flag": 0, "endpoint_rarity": 0.3
        })),
        ("Legitimate Request", json!({
            "write_remote": 0, "mprotect_rwx": 0, "addr_entropy": 0.2,
            "request_body": "username=john&password=secret123",
            "admin_api_flag": 0, "endpoint_rarity": 0.05
        })),
    ];
    
    let mut scenario_results = Vec::new();
    
    for (scenario_name, telemetry) in &scenarios {
        let m = mesh.lock().unwrap();
        if let Ok(features) = featurizer::featurize_from_telemetry(telemetry, &cfg) {
            let features_array: [f32; EMBED_DIM] = features.try_into().unwrap_or([0.0; EMBED_DIM]);
            
            if let Some(service_memory) = m.get_service_memory(&service_id) {
                let (similarity, valence) = {
                    let bdh = service_memory.lock().unwrap();
                    let sims = bdh.retrieve_similar(&features_array, 5);
                    if !sims.is_empty() {
                        let top = sims[0].1;
                        let sum_val: f32 = sims.iter().map(|(t, s)| t.valence * s).sum();
                        let sum_s: f32 = sims.iter().map(|(_t, s)| *s).sum();
                        let avg = if sum_s > 0.0 { sum_val / (sum_s + 1e-6) } else { 0.0 };
                        (top, avg)
                    } else {
                        (0.0, 0.0)
                    }
                };

                let aggression = m.get_host_aggression();
                let action = policy::choose_action(similarity, valence, aggression, cfg.beta, cfg.gamma, cfg.eps_explore);
                
                info!("  {}: similarity={:.3}, valence={:.3}, action={:?}", 
                      scenario_name, similarity, valence, action);
                scenario_results.push((scenario_name.clone(), similarity, valence, action));
                
                // Provide appropriate rewards
                let reward: f32 = match scenario_name.as_ref() {
                    "SQL Injection" | "XSS Attack" | "Command Injection" | "Buffer Overflow" => {
                        match action {
                            policy::Action::Log => -0.8,
                            policy::Action::Notify => -0.4,
                            policy::Action::Throttle => 0.2,
                            policy::Action::Isolate => 0.6,
                            policy::Action::Restart => 0.8,
                            policy::Action::SnapshotAndKill => 1.0,
                        }
                    },
                    "Legitimate Request" => {
                        match action {
                            policy::Action::Log => 1.0,
                            policy::Action::Notify => 0.5,
                            policy::Action::Throttle => -0.2,
                            policy::Action::Isolate => -0.6,
                            policy::Action::Restart => -0.8,
                            policy::Action::SnapshotAndKill => -1.0,
                        }
                    },
                    _ => 0.0,
                };
                
                drop(m); // Release mesh lock
                
                // Update service memory
                {
                    let mut bdh = service_memory.lock().unwrap();
                    let maxsim = bdh.max_similarity(&features_array);
                    if maxsim < cfg.tau_novel {
                        let init_val = reward.max(-1.0).min(1.0);
                        let _id = bdh.add_trace(features_array, init_val);
                    } else {
                        let similar_traces: Vec<(String, f32)> = {
                            let sims = bdh.retrieve_similar(&features_array, 5);
                            sims.into_iter()
                                .take(5)
                                .map(|(trace, similarity)| (trace.id.clone(), similarity))
                                .collect()
                        };
                        
                        for (trace_id, similarity) in similar_traces {
                            let scaled = reward * similarity;
                            bdh.reward_update(&trace_id, scaled, cfg.eta);
                        }
                    }
                }
            }
        }
    }
    
    // Analyze scenario handling
    info!("Scenario analysis:");
    let attacks: Vec<_> = scenario_results.iter().filter(|(name, _, _, _)| *name != "Legitimate Request").collect();
    let benign: Vec<_> = scenario_results.iter().filter(|(name, _, _, _)| *name == "Legitimate Request").collect();
    
    let avg_attack_valence: f32 = attacks.iter().map(|(_, _, v, _)| *v).sum::<f32>() / attacks.len() as f32;
    let avg_benign_valence: f32 = benign.iter().map(|(_, _, v, _)| *v).sum::<f32>() / benign.len() as f32;
    
    info!("  Average attack valence: {:.3}", avg_attack_valence);
    info!("  Average benign valence: {:.3}", avg_benign_valence);
    
    let valence_separation = avg_benign_valence - avg_attack_valence;
    info!("  Valence separation: {:.3}", valence_separation);
    
    if valence_separation > 0.5 {
        info!("✅ Excellent threat discrimination (separation: {:.3})", valence_separation);
    } else if valence_separation > 0.2 {
        info!("✅ Good threat discrimination (separation: {:.3})", valence_separation);
    } else {
        warn!("⚠️  Poor threat discrimination (separation: {:.3})", valence_separation);
    }
    
    Ok(())
}

fn action_severity(action: &policy::Action) -> u8 {
    match action {
        policy::Action::Log => 0,
        policy::Action::Notify => 1,
        policy::Action::Throttle => 2,
        policy::Action::Isolate => 3,
        policy::Action::Restart => 4,
        policy::Action::SnapshotAndKill => 5,
    }
}