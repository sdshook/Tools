
mod config;
mod featurizer;
mod memory_engine;
mod policy;
mod sensors;
mod actuators;
mod evidence;
mod persistence;

use anyhow::Result;
use tracing::info;
use crate::memory_engine::bdh_memory::BdhMemory;
use crate::memory_engine::psi_index::PsiIndex;
use crate::memory_engine::valence::ValenceController;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("Shaneguard PoC (enhanced) starting up...");

    // Load config
    let cfg = config::Config::load_default();

    // Initialize memory engine for PoC
    let bdh = Arc::new(Mutex::new(BdhMemory::new()));
    let psi = Arc::new(Mutex::new(PsiIndex::new()));
    let valence = Arc::new(Mutex::new(ValenceController::new(cfg.aggression_init)));

    // Start simulator sensor
    {
        let b = bdh.clone();
        let p = psi.clone();
        let v = valence.clone();
        tokio::spawn(async move { sensors::start_simulator(b, p, v).await });
    }

    // Persist loop
    loop {
        persistence::persist()?;
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }
}
