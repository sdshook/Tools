
mod config;
mod featurizer;
mod memory_engine;
mod mesh_cognition;
mod policy;
mod sensors;
mod actuators;
mod evidence;
mod persistence;

use anyhow::Result;
use tracing::info;
use crate::mesh_cognition::{HostMeshCognition, WebServiceType};
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("ShaneGuard Host-Based Mesh Cognition starting up...");

    // Load config
    let cfg = config::Config::load_default();

    // Initialize host-based mesh cognition system
    let mesh = Arc::new(Mutex::new(HostMeshCognition::new(
        0.6,  // mesh_learning_rate: cross-service learning strength
        0.3,  // cross_service_threshold: minimum valence to propagate
        cfg.aggression_init,
    )));

    // Register simulated web services for demonstration
    {
        let mut m = mesh.lock().unwrap();
        let apache_id = m.register_service(WebServiceType::Apache, 1001);
        let nginx_id = m.register_service(WebServiceType::Nginx, 1002);
        let iis_id = m.register_service(WebServiceType::IIS, 1003);
        
        info!("Registered services: {}, {}, {}", apache_id, nginx_id, iis_id);
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
