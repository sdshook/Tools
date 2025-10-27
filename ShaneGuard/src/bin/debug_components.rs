use shaneguard::memory_engine::bdh_memory::{BdhMemory, EMBED_DIM};
use shaneguard::policy;
use shaneguard::featurizer;
use shaneguard::config::Config;
use serde_json::json;
use tracing::{info, warn, error};

fn main() {
    tracing_subscriber::fmt::init();
    info!("ShaneGuard Component Debugging Suite Starting...");

    // Test 1: BDH Memory System
    test_bdh_memory_system();
    
    // Test 2: Feature Extraction
    test_feature_extraction();
    
    // Test 3: Policy Engine
    test_policy_engine();
    
    // Test 4: End-to-End Learning
    test_end_to_end_learning();
    
    info!("Component debugging complete!");
}

fn test_bdh_memory_system() {
    info!("=== Testing BDH Memory System ===");
    
    let mut bdh = BdhMemory::new();
    info!("Initial BDH state: {} traces, learning_rate: {}, activation_threshold: {}", 
          bdh.get_trace_count(), bdh.hebbian_learning_rate, bdh.activation_threshold);
    
    // Create test vectors with clear patterns
    let attack_vector1 = create_test_vector("deserialization_high");
    let attack_vector2 = create_test_vector("deserialization_medium");
    let benign_vector = create_test_vector("benign");
    
    info!("Test vectors created:");
    info!("  Attack1: {:?}", &attack_vector1[0..5]);
    info!("  Attack2: {:?}", &attack_vector2[0..5]);
    info!("  Benign:  {:?}", &benign_vector[0..5]);
    
    // Add traces with different valences
    let trace1_id = bdh.add_trace(attack_vector1, -0.8); // Strong negative valence for attack
    let trace2_id = bdh.add_trace(attack_vector2, -0.6); // Medium negative valence
    let trace3_id = bdh.add_trace(benign_vector, 0.2);   // Positive valence for benign
    
    info!("Added traces: {}, {}, {}", trace1_id, trace2_id, trace3_id);
    info!("Trace count: {}", bdh.get_trace_count());
    
    // Test similarity retrieval
    let similar_attack = create_test_vector("deserialization_high"); // Should be very similar to attack1
    let results = bdh.retrieve_similar(&similar_attack, 3);
    
    info!("Similarity retrieval results:");
    for (i, (trace, similarity)) in results.iter().enumerate() {
        info!("  {}: ID={}, similarity={:.4}, valence={:.3}, uses={}", 
              i+1, trace.id, similarity, trace.valence, trace.uses);
    }
    
    // Test reward updates (simulating learning)
    info!("Testing reward updates...");
    bdh.reward_update(&trace1_id, -1.0, 0.3); // Strong negative reward
    bdh.reward_update(&trace2_id, -0.5, 0.3); // Medium negative reward
    bdh.reward_update(&trace3_id, 0.8, 0.3);  // Positive reward
    
    // Check updated valences
    let results_after = bdh.retrieve_similar(&similar_attack, 3);
    info!("After reward updates:");
    for (i, (trace, similarity)) in results_after.iter().enumerate() {
        info!("  {}: ID={}, similarity={:.4}, valence={:.3}, uses={}", 
              i+1, trace.id, similarity, trace.valence, trace.uses);
    }
    
    // Test Hebbian connections
    let (conn_count, avg_weight, avg_self_weight) = bdh.get_hebbian_stats();
    info!("Hebbian stats: {} connections, avg_weight={:.4}, avg_self_weight={:.4}", 
          conn_count, avg_weight, avg_self_weight);
    
    let strongest = bdh.get_strongest_connections(5);
    info!("Strongest connections:");
    for (i, conn) in strongest.iter().enumerate() {
        info!("  {}: {} -> {}, weight={:.4}", i+1, conn.source_id, conn.target_id, conn.weight);
    }
    
    // Test max similarity
    let max_sim = bdh.max_similarity(&similar_attack);
    info!("Max similarity to attack vector: {:.4}", max_sim);
    
    if max_sim < 0.1 {
        error!("❌ BDH Memory Issue: Max similarity too low ({:.4})", max_sim);
    } else {
        info!("✅ BDH Memory: Max similarity acceptable ({:.4})", max_sim);
    }
}

fn test_feature_extraction() {
    info!("=== Testing Feature Extraction ===");
    
    let cfg = Config::load_default();
    
    // Test different types of telemetry
    let attack_telemetry = json!({
        "write_remote": 15,
        "mprotect_rwx": 3,
        "new_threads_unexpected": 2,
        "addr_entropy": 0.85,
        "unique_endpoints": 8,
        "module_loads_unusual": 5,
        "open_proc_vmwrite": 2,
        "ptrace_attempts": 1,
        "process_vm_writev": 3,
        "request_body": "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAACdAAEY2FsY3QABGV4aXQ=",
        "admin_api_flag": 1,
        "endpoint_rarity": 0.95
    });
    
    let benign_telemetry = json!({
        "write_remote": 0,
        "mprotect_rwx": 0,
        "new_threads_unexpected": 0,
        "addr_entropy": 0.2,
        "unique_endpoints": 2,
        "module_loads_unusual": 0,
        "open_proc_vmwrite": 0,
        "ptrace_attempts": 0,
        "process_vm_writev": 0,
        "request_body": "username=john&password=secret123",
        "admin_api_flag": 0,
        "endpoint_rarity": 0.1
    });
    
    match featurizer::featurize_from_telemetry(&attack_telemetry, &cfg) {
        Ok(attack_features) => {
            info!("Attack features: {:?}", &attack_features[0..10]);
            let norm: f32 = attack_features.iter().map(|x| x*x).sum::<f32>().sqrt();
            info!("Attack feature norm: {:.4}", norm);
            
            if norm < 0.1 {
                error!("❌ Feature Extraction Issue: Attack vector norm too small ({:.4})", norm);
            } else {
                info!("✅ Feature Extraction: Attack vector norm acceptable ({:.4})", norm);
            }
        }
        Err(e) => error!("Failed to extract attack features: {}", e),
    }
    
    match featurizer::featurize_from_telemetry(&benign_telemetry, &cfg) {
        Ok(benign_features) => {
            info!("Benign features: {:?}", &benign_features[0..10]);
            let norm: f32 = benign_features.iter().map(|x| x*x).sum::<f32>().sqrt();
            info!("Benign feature norm: {:.4}", norm);
            
            if norm < 0.1 {
                error!("❌ Feature Extraction Issue: Benign vector norm too small ({:.4})", norm);
            } else {
                info!("✅ Feature Extraction: Benign vector norm acceptable ({:.4})", norm);
            }
        }
        Err(e) => error!("Failed to extract benign features: {}", e),
    }
}

fn test_policy_engine() {
    info!("=== Testing Policy Engine ===");
    
    // Test different combinations of score, valence, and aggression
    let test_cases = vec![
        (0.8, -0.9, 0.8, "High threat, high aggression"),
        (0.6, -0.7, 0.5, "Medium threat, medium aggression"),
        (0.3, -0.3, 0.2, "Low threat, low aggression"),
        (0.1, 0.1, 0.1, "Benign traffic"),
        (0.0, 0.0, 0.0, "Neutral baseline"),
    ];
    
    let beta = 0.8;  // Valence weight
    let gamma = 0.6; // Similarity weight
    let eps = 0.05;  // Exploration rate
    
    info!("Policy parameters: beta={}, gamma={}, eps={}", beta, gamma, eps);
    
    for (score, valence, aggression, description) in test_cases {
        let action = policy::choose_action(score, valence, aggression, beta, gamma, eps);
        let policy_score = beta * valence + gamma * score;
        info!("  {}: score={:.2}, valence={:.2}, aggr={:.2} -> policy_score={:.3} -> {:?}", 
              description, score, valence, aggression, policy_score, action);
    }
    
    // Test if we can get action escalation
    let mut escalation_found = false;
    for aggression in [0.1, 0.3, 0.5, 0.7, 0.9] {
        let action = policy::choose_action(0.8, -0.8, aggression, beta, gamma, 0.0);
        match action {
            policy::Action::Isolate | policy::Action::Restart | policy::Action::SnapshotAndKill => {
                escalation_found = true;
                info!("✅ Policy escalation found at aggression {}: {:?}", aggression, action);
                break;
            }
            _ => {}
        }
    }
    
    if !escalation_found {
        error!("❌ Policy Engine Issue: No action escalation found even with high threat/aggression");
    }
}

fn test_end_to_end_learning() {
    info!("=== Testing End-to-End Learning ===");
    
    let mut bdh = BdhMemory::new();
    let cfg = Config::load_default();
    
    // Simulate learning iterations
    for iteration in 1..=5 {
        info!("Learning iteration {}", iteration);
        
        // Process attack scenario
        let attack_telemetry = json!({
            "write_remote": 10 + iteration * 2,
            "mprotect_rwx": iteration,
            "addr_entropy": 0.8 + iteration as f64 * 0.02,
            "request_body": format!("rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAACdAAEY2FsY3QABGV4aXQ={}", iteration),
            "admin_api_flag": 1,
            "endpoint_rarity": 0.9
        });
        
        if let Ok(features) = featurizer::featurize_from_telemetry(&attack_telemetry, &cfg) {
            let features_array: [f32; EMBED_DIM] = features.try_into().unwrap_or([0.0; EMBED_DIM]);
            
            // Retrieve similar traces
            let similar = bdh.retrieve_similar(&features_array, 1);
            let (max_similarity, best_valence) = if let Some((trace, sim)) = similar.first() {
                (*sim, trace.valence)
            } else {
                (0.0, 0.0)
            };
            
            info!("  Attack processing: max_similarity={:.4}, best_valence={:.3}", max_similarity, best_valence);
            
            // Make policy decision
            let aggression = 0.2 + (iteration as f32 * 0.1);
            let action = policy::choose_action(max_similarity, best_valence, aggression, 0.8, 0.6, 0.05);
            info!("  Policy decision: aggression={:.2} -> {:?}", aggression, action);
            
            // Add trace and reward based on action appropriateness
            let trace_id = bdh.add_trace(features_array, -0.7); // Negative valence for attack
            let reward = match action {
                policy::Action::Log => -0.5, // Poor response to attack
                policy::Action::Notify => -0.2,
                policy::Action::Throttle => 0.1,
                policy::Action::Isolate => 0.5,
                policy::Action::Restart => 0.7,
                policy::Action::SnapshotAndKill => 1.0, // Best response
            };
            
            bdh.reward_update(&trace_id, reward, 0.3);
            info!("  Learning update: reward={:.2}", reward);
        }
        
        // Show learning progress
        let avg_valence = bdh.get_average_valence();
        let (conn_count, avg_weight, _) = bdh.get_hebbian_stats();
        info!("  Progress: avg_valence={:.3}, connections={}, avg_weight={:.4}", 
              avg_valence, conn_count, avg_weight);
    }
    
    // Final assessment
    let final_avg_valence = bdh.get_average_valence();
    let (final_conn_count, final_avg_weight, _) = bdh.get_hebbian_stats();
    
    info!("Final learning state:");
    info!("  Average valence: {:.3}", final_avg_valence);
    info!("  Hebbian connections: {}", final_conn_count);
    info!("  Average connection weight: {:.4}", final_avg_weight);
    
    if final_avg_valence > -0.1 {
        warn!("⚠️  Learning Issue: Average valence not sufficiently negative ({:.3})", final_avg_valence);
    } else {
        info!("✅ Learning: Average valence shows threat recognition ({:.3})", final_avg_valence);
    }
    
    if final_conn_count == 0 {
        error!("❌ Learning Issue: No Hebbian connections formed");
    } else {
        info!("✅ Learning: Hebbian connections formed ({})", final_conn_count);
    }
}

fn create_test_vector(pattern_type: &str) -> [f32; EMBED_DIM] {
    let mut vec = [0.0; EMBED_DIM];
    
    match pattern_type {
        "deserialization_high" => {
            vec[0] = 0.8;  // write_remote
            vec[1] = 0.6;  // mprotect_rwx
            vec[9] = 0.9;  // serialized_score
            vec[10] = 0.85; // payload_entropy
            vec[12] = 1.0; // admin_flag
            vec[13] = 0.95; // endpoint_rarity
        }
        "deserialization_medium" => {
            vec[0] = 0.6;  // write_remote
            vec[1] = 0.4;  // mprotect_rwx
            vec[9] = 0.7;  // serialized_score
            vec[10] = 0.7; // payload_entropy
            vec[12] = 1.0; // admin_flag
            vec[13] = 0.8; // endpoint_rarity
        }
        "benign" => {
            vec[0] = 0.1;  // write_remote
            vec[1] = 0.0;  // mprotect_rwx
            vec[9] = 0.0;  // serialized_score
            vec[10] = 0.3; // payload_entropy
            vec[12] = 0.0; // admin_flag
            vec[13] = 0.1; // endpoint_rarity
        }
        _ => {}
    }
    
    // L2 normalize
    let norm: f32 = vec.iter().map(|x| x*x).sum::<f32>().sqrt().max(1e-6);
    for i in 0..vec.len() { 
        vec[i] = vec[i] / norm; 
    }
    
    vec
}