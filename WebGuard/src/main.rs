//! WebGuard - Self-Learning Web Server EDR
//!
//! A neuromorphic endpoint detection and response system for web servers
//! with biological immunity-inspired collective protection.
//!
//! ## Operational Modes
//!
//! - **proxy**: HTTP reverse proxy with inline threat analysis
//! - **tail**: Real-time log file monitoring
//! - **audit**: Batch log analysis for forensic investigation
//! - **demo**: Demo mode with simulated telemetry (for testing only)
//!
//! ## Usage
//!
//! ```bash
//! # Run as HTTP proxy
//! webguard --mode proxy --listen 0.0.0.0:8080 --backend 127.0.0.1:80
//!
//! # Monitor nginx logs in real-time
//! webguard --mode tail --log /var/log/nginx/access.log
//!
//! # Audit Apache logs
//! webguard --mode audit --log /var/log/apache2/access.log --report audit.json
//!
//! # Run with config file
//! webguard --config /etc/webguard/config.toml
//! ```

// Core architecture - Harvard semantic/execution separation
mod harvard_architecture;

// Configuration
mod config;

// Semantic Layer (Harvard "Data Memory")
mod semantic_normalizer;  // Pre-processing: deterministic normalization
mod featurizer;
mod advanced_feature_extractor;
mod memory_engine;
mod experiential_anomaly;
mod embedding_learner;
mod log_parser;

// Execution Layer (Harvard "Instruction Memory")
mod policy;
mod actuators;
mod adaptive_threshold;

// Learning Systems
mod eq_iq_regulator;
mod retrospective_learning;

// Infrastructure
mod mesh_cognition;
mod sensors;
mod evidence;
mod persistence_engine;

// Operational Modes
mod modes;

use anyhow::Result;
use tracing::{info, error};
use crate::mesh_cognition::{HostMeshCognition, WebServiceType};
use webguard::runtime_config::{RuntimeConfig, OperationalMode};
use crate::persistence_engine::PersistenceEngine;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let runtime_config = RuntimeConfig::from_args();
    
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    info!("╔═══════════════════════════════════════════════════════════════════╗");
    info!("║        WebGuard - Self-Learning Web Server EDR v{}         ║", env!("CARGO_PKG_VERSION"));
    info!("║   Neuromorphic Defense with Biological Immunity Architecture      ║");
    info!("╚═══════════════════════════════════════════════════════════════════╝");
    info!("");
    info!("Mode: {:?}", runtime_config.mode);
    
    // Load application config
    let app_config = config::Config::load_default();

    // Initialize host-based mesh cognition system
    let mesh = Arc::new(Mutex::new(HostMeshCognition::new(
        0.6,  // mesh_learning_rate: cross-service learning strength
        0.3,  // cross_service_threshold: minimum valence to propagate
        app_config.aggression_init,
    )));
    
    // Load persisted state if available
    if runtime_config.persistence.enabled && runtime_config.persistence.load_on_startup {
        let persistence_engine = PersistenceEngine::new(runtime_config.persistence.clone());
        
        match persistence_engine.load() {
            Ok(Some(state)) => {
                let mut m = mesh.lock().unwrap();
                if let Err(e) = persistence_engine.restore(&mut m, &state) {
                    error!("Failed to restore state: {}", e);
                } else {
                    info!("Restored learning state from disk");
                }
            }
            Ok(None) => {
                info!("No existing state to restore - starting fresh");
            }
            Err(e) => {
                error!("Failed to load state: {}", e);
            }
        }
    }

    // Start auto-save if configured
    let _auto_save_handle = PersistenceEngine::start_auto_save(
        runtime_config.persistence.clone(),
        mesh.clone(),
    );

    // Run the appropriate mode
    match runtime_config.mode {
        OperationalMode::Proxy => {
            info!("Starting HTTP Proxy Mode...");
            if let Err(e) = modes::run_proxy_mode(
                runtime_config.proxy, 
                mesh.clone(),
                runtime_config.logging.clone(),
            ).await {
                error!("Proxy mode error: {}", e);
            }
        }
        
        OperationalMode::Tail => {
            info!("Starting Log Tail Mode...");
            if let Err(e) = modes::run_tail_mode(runtime_config.tail, mesh.clone()).await {
                error!("Tail mode error: {}", e);
            }
        }
        
        OperationalMode::Audit => {
            info!("Starting Log Audit Mode...");
            if let Err(e) = modes::run_audit_mode(runtime_config.audit, mesh.clone()).await {
                error!("Audit mode error: {}", e);
            }
            
            // Save state after audit if learning was enabled
            if runtime_config.persistence.enabled {
                let engine = PersistenceEngine::new(runtime_config.persistence);
                if let Ok(m) = mesh.lock() {
                    if let Err(e) = engine.save(&m) {
                        error!("Failed to save state after audit: {}", e);
                    }
                }
            }
        }
        
        OperationalMode::Demo => {
            info!("╔═══════════════════════════════════════════════════════════════════╗");
            info!("║  WARNING: Demo mode uses SIMULATED telemetry - NOT FOR PRODUCTION ║");
            info!("╚═══════════════════════════════════════════════════════════════════╝");
            run_demo_mode(mesh.clone(), app_config, runtime_config.persistence).await?;
        }
    }

    Ok(())
}

/// Run demo mode with simulated telemetry (FOR TESTING/DEMONSTRATION ONLY)
/// 
/// This mode generates synthetic web server telemetry to demonstrate
/// WebGuard's learning capabilities. It does NOT connect to real web servers.
/// 
/// For production use, select one of:
/// - `proxy`: Inline HTTP proxy protection
/// - `tail`: Real-time log monitoring
/// - `audit`: Batch log analysis
async fn run_demo_mode(
    mesh: Arc<Mutex<HostMeshCognition>>,
    _cfg: config::Config,
    persistence_config: webguard::runtime_config::PersistenceConfig,
) -> Result<()> {
    info!("Demo mode: Registering simulated IIS w3wp.exe processes...");
    
    // Register multiple IIS w3wp.exe processes for demonstration
    {
        let mut m = mesh.lock().unwrap();
        let w3wp1_id = m.register_service(WebServiceType::IIS, 1001); // ECommerce App
        let w3wp2_id = m.register_service(WebServiceType::IIS, 1002); // User Portal
        let w3wp3_id = m.register_service(WebServiceType::IIS, 1003); // Admin Dashboard
        let w3wp4_id = m.register_service(WebServiceType::IIS, 1004); // API Gateway
        let w3wp5_id = m.register_service(WebServiceType::IIS, 1005); // Auth Service
        let w3wp6_id = m.register_service(WebServiceType::IIS, 1006); // Payment Service
        
        info!("Demo: Registered simulated IIS processes: {}, {}, {}, {}, {}, {}", 
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
                    for (service_id, _service_type) in &services {
                        if let Some(service_memory) = m.get_service_memory(service_id) {
                            if let Ok(bdh) = service_memory.try_lock() {
                                let (conn_count, avg_weight, _avg_self) = bdh.get_hebbian_stats();
                                hebbian_summary.push(format!("{}:{}c/{:.2}w", service_id, conn_count, avg_weight));
                            }
                        }
                    }
                    
                    info!("[DEMO] Host Status - Aggression: {:.3} | Services: {:?} | Hebbian: [{}]", 
                          aggression, stats, hebbian_summary.join(", "));
                }
            }
        });
    }

    // Persistence engine for periodic saves
    let persistence_engine = PersistenceEngine::new(persistence_config.clone());

    // Main loop with proper persistence
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        
        // Save state periodically using real persistence engine
        if persistence_config.enabled {
            if let Ok(m) = mesh.lock() {
                if let Err(e) = persistence_engine.save(&m) {
                    error!("Failed to persist state: {}", e);
                }
            }
        }
    }
}
