
use serde_json::json;
use tokio::time::{sleep, Duration};
use tracing::info;
use crate::featurizer;
use crate::config::Config;
use crate::memory_engine::bdh_memory::BdhMemory;
use crate::memory_engine::psi_index::PsiIndex;
use crate::memory_engine::valence::ValenceController;
use crate::policy;
use crate::actuators;
use crate::evidence;
use std::sync::{Arc, Mutex};

pub async fn start_simulator(bdh: Arc<Mutex<BdhMemory>>, psi: Arc<Mutex<PsiIndex>>, valence: Arc<Mutex<ValenceController>>) {
    let cfg = Config::load_default();
    info!( "Starting simulated telemetry sensor with Hebbian RL loop..." );
    let mut counter: u64 = 0;
    loop {
        let telemetry = if counter % 15 == 0 {
            json!({
                "pid": 1000 + (counter % 5),
                "write_remote": 0,
                "mprotect_rwx": 0,
                "new_threads_unexpected": 0,
                "addr_entropy": 0.2,
                "unique_endpoints": 1,
                "module_loads_unusual": 0,
                "open_proc_vmwrite": 0,
                "ptrace_attempts": 0,
                "process_vm_writev": 0,
                "request_body": base64_payload(),
                "admin_api_flag": 1,
                "endpoint_rarity": 0.9
            })
        } else {
            json!({
                "pid": 1000 + (counter % 5),
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
        // featurize
        let vec = featurizer::featurize_from_telemetry(&telemetry, &cfg).unwrap_or(vec![0.0_f32; cfg.embed_dim]);
        let mut qarr = [0.0_f32; 32];
        for i in 0..vec.len().min(32) { qarr[i] = vec[i]; }

        // Query BDH and compute similarity/valence
        let (top_sim, avg_valence) = {
            let b = bdh.lock().unwrap();
            let sims = b.retrieve_similar(&qarr, 5);
            if sims.len() > 0 {
                let top = sims[0].1;
                let sum_val: f32 = sims.iter().map(|(t, s)| t.valence * s).sum();
                let sum_s: f32 = sims.iter().map(|(_t, s)| *s).sum();
                let avg = if sum_s > 0.0 { sum_val / (sum_s + 1e-6) } else { 0.0 };
                (top, avg)
            } else { (0.0, 0.0) }
        };

        // Policy decision
        let action = policy::choose_action(top_sim, avg_valence, valence.lock().unwrap().aggression, cfg.beta, cfg.gamma, cfg.eps_explore);
        let pid = telemetry["pid"].as_i64().unwrap() as i32;
        let action_str = match action {
            policy::Action::Log => "log",
            policy::Action::Notify => "notify",
            policy::Action::Throttle => "throttle",
            policy::Action::Isolate => "isolate",
            policy::Action::Restart => "restart",
            policy::Action::SnapshotAndKill => "snapshot",
        };
        info!( "Telemetry pid={} sim_score={} avg_valence={:?} action={:?}", telemetry["pid"], top_sim, avg_valence, action );
        let _ = actuators::apply_nginx_mitigation(pid, action_str).await;
        if action_str == "snapshot" {
            let _ = evidence::snapshot_evidence(pid, "policy_snapshot").await;
        }

        // Simplified reward logic
        let write_remote = telemetry["write_remote"].as_i64().unwrap() as i32;
        let mut reward = 0.0_f32;
        if telemetry["admin_api_flag"].as_i64().unwrap() == 1 && action_str=="isolate" {
            reward = 1.0;
        } else if telemetry["admin_api_flag"].as_i64().unwrap() == 1 && action_str=="log" {
            reward = -0.5;
        }

        // Update BDH memory
        {
            let mut b = bdh.lock().unwrap();
            let maxsim = b.max_similarity(&qarr);
            if maxsim < cfg.tau_novel {
                let init_val = reward.max(-1.0).min(1.0);
                let _id = b.add_trace(qarr, init_val);
            } else {
                let sims = b.retrieve_similar(&qarr, 5);
                for (t, s) in sims.iter().take(5) {
                    let scaled = reward * *s;
                    b.reward_update(&t.id, scaled, cfg.eta);
                }
            }
            let prom = b.promote_candidates(cfg.promote_threshold);
            if prom.len() > 0 {
                let mut p = psi.lock().unwrap();
                for t in prom {
                    let mut veccopy = [0.0f32; 32];
                    for i in 0..32 { veccopy[i] = t.vec[i]; }
                    p.add(crate::memory_engine::psi_index::PsiEntry {
                        id: t.id.clone(),
                        vec: veccopy,
                        valence: t.valence,
                        uses: t.uses,
                        tags: vec!["promoted".to_string()],
                    });
                }
            }
        }

        // Update valence controller
        {
            let mut v = valence.lock().unwrap();
            v.record_reward(reward);
        }

        sleep(Duration::from_secs(1)).await;
    }
}

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
