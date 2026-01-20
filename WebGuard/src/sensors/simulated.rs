use serde_json::json;
use tokio::time::{sleep, Duration};
use tracing::info;
use crate::featurizer;
use crate::config::Config;
use crate::mesh_cognition::{HostMeshCognition, WebServiceType};
use crate::policy;
use crate::actuators;
use crate::evidence;
use std::sync::{Arc, Mutex};

// helper: produce a medium-length base64 payload string for the simulator
fn base64_payload() -> String {
    // generate a deterministic-ish pseudo-base64 chunk for compile-time safety (not random)
    let mut s = String::new();
    for i in 0..4000 {
        let c = match i % 64 {
            62 => '+',
            63 => '/',
            n => {
                let n = n as u8;
                if n < 26 { (b'A' + n) as char } else if n < 52 { (b'a' + (n-26)) as char } else { (b'0' + (n-52)) as char }
            }
        };
        s.push(c);
    }
    s.push_str("==");
    s
}

pub async fn start_multi_service_simulator(mesh: Arc<Mutex<HostMeshCognition>>) {
    let cfg = Config::load_default();
    info!("Starting multi-service mesh cognition simulator...");
    
    let mut counter: u64 = 0;
    // Simulate multiple IIS w3wp.exe processes serving different applications
    let services = vec![
        ("w3wp.exe", WebServiceType::IIS), // Process ID 1001 - ECommerce App
        ("w3wp.exe", WebServiceType::IIS), // Process ID 1002 - User Portal  
        ("w3wp.exe", WebServiceType::IIS), // Process ID 1003 - Admin Dashboard
        ("w3wp.exe", WebServiceType::IIS), // Process ID 1004 - API Gateway
        ("w3wp.exe", WebServiceType::IIS), // Process ID 1005 - Auth Service
        ("w3wp.exe", WebServiceType::IIS), // Process ID 1006 - Payment Service
    ];
    
    loop {
        // Rotate through services for telemetry generation
        let (service_id, service_type) = &services[counter as usize % services.len()];
        
        // Generate telemetry - make every 10th event suspicious
        let is_suspicious = counter % 10 == 0;
        let process_pid = 1001 + (counter as usize % services.len()) as i64;
        let telemetry = if is_suspicious {
            json!({
                "pid": process_pid,
                "service_type": service_type.as_str(),
                "write_remote": if counter % 20 == 0 { 2 } else { 0 },
                "mprotect_rwx": if counter % 15 == 0 { 1 } else { 0 },
                "new_threads_unexpected": 0,
                "addr_entropy": 0.3,
                "unique_endpoints": 2,
                "module_loads_unusual": if counter % 25 == 0 { 1 } else { 0 },
                "open_proc_vmwrite": 0,
                "ptrace_attempts": 0,
                "process_vm_writev": 0,
                "request_body": base64_payload(),
                "admin_api_flag": 1,
                "endpoint_rarity": 0.85
            })
        } else {
            json!({
                "pid": process_pid,
                "service_type": service_type.as_str(),
                "write_remote": 0,
                "mprotect_rwx": 0,
                "new_threads_unexpected": 0,
                "addr_entropy": 0.1,
                "unique_endpoints": 1,
                "module_loads_unusual": 0,
                "open_proc_vmwrite": 0,
                "ptrace_attempts": 0,
                "process_vm_writev": 0,
                "request_body": "normal=1&foo=bar",
                "admin_api_flag": 0,
                "endpoint_rarity": 0.1
            })
        };
        
        counter += 1;
        
        // Featurize the telemetry
        let vec = featurizer::featurize_from_telemetry(&telemetry, &cfg)
            .unwrap_or(vec![0.0_f32; cfg.embed_dim]);
        let mut qarr = [0.0_f32; 32];
        for i in 0..vec.len().min(32) { qarr[i] = vec[i]; }
        
        // Process through mesh cognition system
        let (service_memory_opt, action_str_owned, top_sim, avg_valence, conn_count, avg_conn_weight, avg_self_weight) = {
            if let Ok(m) = mesh.try_lock() {
                // Get service memory
                if let Some(service_memory) = m.get_service_memory(service_id) {
                let (top_sim, avg_valence) = {
                    let bdh = service_memory.lock().unwrap();
                    let sims = bdh.retrieve_similar(&qarr, 5);
                    if sims.len() > 0 {
                        let top = sims[0].1;
                        let sum_val: f32 = sims.iter().map(|(t, s)| t.valence * s).sum();
                        let sum_s: f32 = sims.iter().map(|(_t, s)| *s).sum();
                        let avg = if sum_s > 0.0 { sum_val / (sum_s + 1e-6) } else { 0.0 };
                        (top, avg)
                    } else { (0.0, 0.0) }
                };
                
                // Policy decision using host aggression
                let host_aggression = m.get_host_aggression();
                let action = policy::choose_action(top_sim, avg_valence, host_aggression, 
                                                 cfg.beta, cfg.gamma, cfg.eps_explore);
                
                let _pid = telemetry["pid"].as_i64().unwrap() as i32;
                let action_str = match action {
                    policy::Action::Log => "log",
                    policy::Action::Notify => "notify", 
                    policy::Action::Throttle => "throttle",
                    policy::Action::Isolate => "isolate",
                    policy::Action::Restart => "restart",
                    policy::Action::SnapshotAndKill => "snapshot",
                };
                
                // Get Hebbian learning stats
                let (conn_count, avg_conn_weight, avg_self_weight) = {
                    let bdh = service_memory.lock().unwrap();
                    bdh.get_hebbian_stats()
                };
                
                    (Some(service_memory.clone()), action_str.to_string(), top_sim, avg_valence, conn_count, avg_conn_weight, avg_self_weight)
                } else {
                    (None, "log".to_string(), 0.0, 0.0, 0, 0.0, 0.0)
                }
            } else {
                (None, "log".to_string(), 0.0, 0.0, 0, 0.0, 0.0)
            }
        };
        
        if let Some(service_memory_clone) = service_memory_opt {
            let pid = telemetry["pid"].as_i64().unwrap() as i32;
            info!("Service: {} | PID: {} | Sim: {:.3} | Valence: {:.3} | Action: {} | Suspicious: {} | Hebbian: {}conn/{:.3}w/{:.3}sw", 
                  service_id, pid, top_sim, avg_valence, &action_str_owned, is_suspicious, 
                  conn_count, avg_conn_weight, avg_self_weight);
            
            // Apply mitigation
            let _ = actuators::apply_nginx_mitigation(pid, &action_str_owned).await;
                if &action_str_owned == "snapshot" {
                    let _ = evidence::snapshot_evidence(pid, "mesh_policy_snapshot").await;
                }
                
                // Calculate reward based on action appropriateness
                let reward: f32 = if is_suspicious {
                    match action_str_owned.as_str() {
                        "isolate" | "snapshot" => 1.0,
                        "throttle" => 0.5,
                        "notify" => 0.2,
                        "log" => -0.3,
                        _ => 0.0,
                    }
                } else {
                    match action_str_owned.as_str() {
                        "log" => 0.1,
                        "notify" => -0.1,
                        "throttle" => -0.5,
                        "isolate" | "snapshot" => -1.0,
                        _ => 0.0,
                    }
                };
                
                // Update service memory
                {
                    let mut bdh = service_memory_clone.lock().unwrap();
                    let maxsim = bdh.max_similarity(&qarr);
                    if maxsim < cfg.tau_novel {
                        let init_val = reward.max(-1.0).min(1.0);
                        let _id = bdh.add_trace(qarr, init_val);
                    } else {
                        let similar_traces: Vec<(String, f32)> = {
                            let sims = bdh.retrieve_similar(&qarr, 5);
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
                
                // Cross-service learning through mesh cognition (reacquire lock)
                if reward.abs() > 0.3 { // Only propagate significant experiences
                    if let Ok(m) = mesh.try_lock() {
                        m.cross_service_learning(service_id, &qarr, avg_valence, reward);
                        m.consolidate_to_psi(service_id, cfg.promote_threshold);
                        m.update_host_aggression(reward);
                    }
                }
        }
        
        sleep(Duration::from_secs(2)).await;
    }
}
