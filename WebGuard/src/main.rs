
mod config;
mod featurizer;
mod memory_engine;
mod mesh_cognition;
mod policy;
mod sensors;
mod actuators;
mod evidence;
mod persistence;
mod eq_iq_regulator;
mod retrospective_learning;
mod advanced_feature_extractor;
mod adaptive_threshold;
mod enhanced_pattern_recognition;
mod experiential_anomaly;

use anyhow::Result;
use tracing::info;
use crate::mesh_cognition::{HostMeshCognition, WebServiceType};
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("WebGuard Host-Based Mesh Cognition starting up...");

    // Load config
    let cfg = config::Config::load_default();

    // Initialize host-based mesh cognition system
    let mesh = Arc::new(Mutex::new(HostMeshCognition::new(
        0.6,  // mesh_learning_rate: cross-service learning strength
        0.3,  // cross_service_threshold: minimum valence to propagate
        cfg.aggression_init,
    )));

    // Register multiple IIS w3wp.exe processes for demonstration
    {
        let mut m = mesh.lock().unwrap();
        let w3wp1_id = m.register_service(WebServiceType::IIS, 1001); // ECommerce App
        let w3wp2_id = m.register_service(WebServiceType::IIS, 1002); // User Portal
        let w3wp3_id = m.register_service(WebServiceType::IIS, 1003); // Admin Dashboard
        let w3wp4_id = m.register_service(WebServiceType::IIS, 1004); // API Gateway
        let w3wp5_id = m.register_service(WebServiceType::IIS, 1005); // Auth Service
        let w3wp6_id = m.register_service(WebServiceType::IIS, 1006); // Payment Service
        
        info!("Registered IIS w3wp processes: {}, {}, {}, {}, {}, {}", 
              w3wp1_id, w3wp2_id, w3wp3_id, w3wp4_id, w3wp5_id, w3wp6_id);
    }

    // Start multi-service simulator
    {
        let mesh_clone = mesh.clone();
        tokio::spawn(async move { 
            sensors::start_multi_service_simulator(mesh_clone).await 
        });
    }

    // Status reporting loop
    {
        let mesh_clone = mesh.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                if let Ok(m) = mesh_clone.try_lock() {
                    let stats = m.get_service_stats();
                    let aggression = m.get_host_aggression();
                    let services = m.get_active_services();
                    
                    // Get Hebbian learning stats for each service
                    let mut hebbian_summary = Vec::new();
                    for service_id in &services {
                        if let Some(service_memory) = m.get_service_memory(service_id) {
                            if let Ok(bdh) = service_memory.try_lock() {
                                let (conn_count, avg_weight, _avg_self) = bdh.get_hebbian_stats();
                                hebbian_summary.push(format!("{}:{}c/{:.2}w", service_id, conn_count, avg_weight));
                            }
                        }
                    }
                    
                    info!("Host Status - Aggression: {:.3} | Services: {:?} | Hebbian: [{}]", 
                          aggression, stats, hebbian_summary.join(", "));
                }
            }
        });
    }

    // Persist loop
    loop {
        persistence::persist()?;
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }
}
