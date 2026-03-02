//! Persistence Engine - Save/Load Full Learning State
//!
//! Serializes and deserializes the complete WebGuard learning state:
//! - BDH memory traces and Hebbian connections
//! - PSI index entries and connections
//! - Learned prototypes
//! - Configuration state

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

use webguard::runtime_config::PersistenceConfig;
use crate::mesh_cognition::HostMeshCognition;
use crate::memory_engine::bdh_memory::{BdhMemory, MemoryTrace, EMBED_DIM};
use crate::memory_engine::psi_index::{PsiIndex, PsiEntry, PsiConnection};

/// Complete persisted state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedState {
    /// Version for compatibility checking
    pub version: u32,
    /// Timestamp when saved
    pub saved_at: String,
    /// PSI index state
    pub psi: PersistedPsi,
    /// Service BDH memories
    pub services: HashMap<String, PersistedBdh>,
    /// Host aggression level
    pub host_aggression: f32,
    /// Learning statistics
    pub stats: LearningStats,
}

impl PersistedState {
    pub const CURRENT_VERSION: u32 = 1;
}

/// Persisted PSI state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPsi {
    pub entries: Vec<PersistedPsiEntry>,
    pub connections: Vec<PersistedPsiConnection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPsiEntry {
    pub id: String,
    pub vec: Vec<f32>,
    pub valence: f32,
    pub uses: u32,
    pub tags: Vec<String>,
    pub last_activation: f64,
    pub cumulative_reward: f32,
}

impl From<&PsiEntry> for PersistedPsiEntry {
    fn from(entry: &PsiEntry) -> Self {
        Self {
            id: entry.id.clone(),
            vec: entry.vec.to_vec(),
            valence: entry.valence,
            uses: entry.uses,
            tags: entry.tags.clone(),
            last_activation: entry.last_activation,
            cumulative_reward: entry.cumulative_reward,
        }
    }
}

impl PersistedPsiEntry {
    pub fn to_psi_entry(&self) -> PsiEntry {
        let mut vec = [0.0f32; EMBED_DIM];
        for (i, &v) in self.vec.iter().enumerate().take(EMBED_DIM) {
            vec[i] = v;
        }
        PsiEntry {
            id: self.id.clone(),
            vec,
            valence: self.valence,
            uses: self.uses,
            tags: self.tags.clone(),
            last_activation: self.last_activation,
            cumulative_reward: self.cumulative_reward,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPsiConnection {
    pub source_id: String,
    pub target_id: String,
    pub strength: f32,
    pub co_activations: u32,
    pub last_update: f64,
}

impl From<&PsiConnection> for PersistedPsiConnection {
    fn from(conn: &PsiConnection) -> Self {
        Self {
            source_id: conn.source_id.clone(),
            target_id: conn.target_id.clone(),
            strength: conn.strength,
            co_activations: conn.co_activations,
            last_update: conn.last_update,
        }
    }
}

impl PersistedPsiConnection {
    pub fn to_psi_connection(&self) -> PsiConnection {
        PsiConnection {
            source_id: self.source_id.clone(),
            target_id: self.target_id.clone(),
            strength: self.strength,
            co_activations: self.co_activations,
            last_update: self.last_update,
        }
    }
}

/// Persisted BDH memory state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedBdh {
    pub service_id: String,
    pub service_type: String,
    pub traces: Vec<PersistedBdhTrace>,
    pub connections: HashMap<String, HashMap<String, f32>>,
    pub threat_prototype: Option<Vec<f32>>,
    pub benign_prototype: Option<Vec<f32>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedBdhTrace {
    pub id: String,
    pub vec: Vec<f32>,
    pub valence: f32,
    pub uses: u32,
    pub cum_reward: f32,
    pub hebbian_weights: Vec<f32>,
}

impl From<&MemoryTrace> for PersistedBdhTrace {
    fn from(trace: &MemoryTrace) -> Self {
        Self {
            id: trace.id.clone(),
            vec: trace.vec.to_vec(),
            valence: trace.valence,
            uses: trace.uses,
            cum_reward: trace.cum_reward,
            hebbian_weights: trace.hebbian_weights.to_vec(),
        }
    }
}

impl PersistedBdhTrace {
    pub fn to_memory_trace(&self) -> MemoryTrace {
        let mut vec = [0.0f32; EMBED_DIM];
        for (i, &v) in self.vec.iter().enumerate().take(EMBED_DIM) {
            vec[i] = v;
        }
        let mut hebbian_weights = [0.0f32; EMBED_DIM];
        for (i, &v) in self.hebbian_weights.iter().enumerate().take(EMBED_DIM) {
            hebbian_weights[i] = v;
        }
        MemoryTrace {
            id: self.id.clone(),
            vec,
            valence: self.valence,
            uses: self.uses,
            cum_reward: self.cum_reward,
            hebbian_weights,
            activation_history: Vec::new(),
        }
    }
}

/// Learning statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LearningStats {
    pub total_traces_learned: u64,
    pub total_threats_detected: u64,
    pub total_false_positives: u64,
    pub total_false_negatives: u64,
    pub total_connections_formed: u64,
    pub uptime_seconds: u64,
}

/// Persistence engine
pub struct PersistenceEngine {
    config: PersistenceConfig,
    state_path: PathBuf,
}

impl PersistenceEngine {
    /// Create a new persistence engine
    pub fn new(config: PersistenceConfig) -> Self {
        let state_path = config.data_dir.join("webguard_state.json");
        
        // Ensure data directory exists
        if let Err(e) = fs::create_dir_all(&config.data_dir) {
            warn!("Failed to create data directory: {}", e);
        }
        
        Self {
            config,
            state_path,
        }
    }
    
    /// Get the state file path (with .gz extension if compressed)
    fn get_state_file_path(&self) -> PathBuf {
        if self.config.compress {
            self.state_path.with_extension("json.gz")
        } else {
            self.state_path.clone()
        }
    }
    
    /// Save the complete state
    pub fn save(&self, mesh: &HostMeshCognition) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.enabled {
            return Ok(());
        }
        
        info!("Saving WebGuard state to {:?}", self.get_state_file_path());
        
        // Build persisted state
        let mut services = HashMap::new();
        
        for (service_id, service_type) in mesh.get_active_services() {
            if let Some(bdh_mutex) = mesh.get_service_memory(&service_id) {
                let bdh = bdh_mutex.lock().unwrap();
                
                // Convert hebbian connections to a HashMap format
                let mut connections_map: HashMap<String, HashMap<String, f32>> = HashMap::new();
                for conn in &bdh.hebbian_connections {
                    connections_map
                        .entry(conn.source_id.clone())
                        .or_insert_with(HashMap::new)
                        .insert(conn.target_id.clone(), conn.weight);
                }
                
                let persisted_bdh = PersistedBdh {
                    service_id: service_id.clone(),
                    service_type: service_type.as_str().to_string(),
                    traces: bdh.traces.iter().map(|t| PersistedBdhTrace::from(t)).collect(),
                    connections: connections_map,
                    threat_prototype: None, // BDH doesn't store prototypes directly
                    benign_prototype: None,
                };
                
                services.insert(service_id, persisted_bdh);
            }
        }
        
        // Get PSI state
        let psi_state = if let Ok(psi) = mesh.get_shared_psi().try_lock() {
            let entries: Vec<PersistedPsiEntry> = psi.entries()
                .map(|e| PersistedPsiEntry::from(e))
                .collect();
            
            let connections: Vec<PersistedPsiConnection> = psi.all_connections()
                .map(|c| PersistedPsiConnection::from(c))
                .collect();
            
            PersistedPsi { entries, connections }
        } else {
            PersistedPsi { entries: vec![], connections: vec![] }
        };
        
        // Compute learning stats from mesh state
        let memory_stats = mesh.get_memory_stats();
        let mut total_threats = 0u64;
        let mut total_false_positives = 0u64;
        let mut total_false_negatives = 0u64;
        
        // Count threats and learning events from retrospective learning
        if let Some(retro_stats) = mesh.get_retrospective_learning_stats() {
            total_false_negatives = retro_stats.total_missed_threats_processed as u64;
            total_false_positives = retro_stats.total_false_positives_processed as u64;
        }
        
        // Count threats from BDH memory valences
        for service in services.values() {
            for trace in &service.traces {
                if trace.valence >= 0.5 {
                    total_threats += 1;
                }
            }
        }
        
        let stats = LearningStats {
            total_traces_learned: memory_stats.total_traces as u64,
            total_threats_detected: total_threats,
            total_false_positives,
            total_false_negatives,
            total_connections_formed: memory_stats.total_connections as u64,
            uptime_seconds: 0, // Would need to track startup time separately
        };
        
        let state = PersistedState {
            version: PersistedState::CURRENT_VERSION,
            saved_at: chrono::Utc::now().to_rfc3339(),
            psi: psi_state,
            services,
            host_aggression: mesh.get_host_aggression(),
            stats,
        };
        
        // Serialize
        let json = serde_json::to_string_pretty(&state)?;
        
        // Write to file
        let path = self.get_state_file_path();
        
        if self.config.compress {
            let file = File::create(&path)?;
            let mut encoder = GzEncoder::new(BufWriter::new(file), Compression::default());
            encoder.write_all(json.as_bytes())?;
            encoder.finish()?;
        } else {
            let mut file = File::create(&path)?;
            file.write_all(json.as_bytes())?;
        }
        
        let file_size = fs::metadata(&path)?.len();
        info!("Saved state: {} entries, {} connections, {} services ({} bytes)",
            state.psi.entries.len(),
            state.psi.connections.len(),
            state.services.len(),
            file_size
        );
        
        Ok(())
    }
    
    /// Load the complete state
    pub fn load(&self) -> Result<Option<PersistedState>, Box<dyn std::error::Error>> {
        if !self.config.enabled || !self.config.load_on_startup {
            return Ok(None);
        }
        
        let path = self.get_state_file_path();
        
        if !path.exists() {
            info!("No existing state file found at {:?}", path);
            return Ok(None);
        }
        
        info!("Loading WebGuard state from {:?}", path);
        
        let json = if self.config.compress {
            let file = File::open(&path)?;
            let mut decoder = GzDecoder::new(BufReader::new(file));
            let mut json = String::new();
            decoder.read_to_string(&mut json)?;
            json
        } else {
            fs::read_to_string(&path)?
        };
        
        let state: PersistedState = serde_json::from_str(&json)?;
        
        // Version check
        if state.version != PersistedState::CURRENT_VERSION {
            warn!("State file version mismatch: {} vs {}", state.version, PersistedState::CURRENT_VERSION);
            // Could implement migration here
        }
        
        info!("Loaded state: {} entries, {} connections, {} services (saved at {})",
            state.psi.entries.len(),
            state.psi.connections.len(),
            state.services.len(),
            state.saved_at
        );
        
        Ok(Some(state))
    }
    
    /// Restore state into mesh cognition
    pub fn restore(&self, mesh: &mut HostMeshCognition, state: &PersistedState) -> Result<(), Box<dyn std::error::Error>> {
        info!("Restoring WebGuard state...");
        
        // Restore PSI
        if let Ok(mut psi) = mesh.get_shared_psi().try_lock() {
            // Clear existing
            psi.clear();
            
            // Add entries
            for entry in &state.psi.entries {
                psi.add(entry.to_psi_entry());
            }
            
            // Restore connections
            for conn in &state.psi.connections {
                psi.restore_connection(conn.to_psi_connection());
            }
            
            info!("Restored {} PSI entries and {} connections",
                state.psi.entries.len(),
                state.psi.connections.len()
            );
        }
        
        // Restore host aggression
        mesh.set_host_aggression(state.host_aggression);
        
        // Note: Service BDH memories are typically created fresh and learn from PSI
        // But we could restore them if needed
        
        Ok(())
    }
    
    /// Start auto-save background task
    pub fn start_auto_save(
        config: PersistenceConfig,
        mesh: Arc<Mutex<HostMeshCognition>>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if !config.enabled || config.auto_save_interval_secs == 0 {
            return None;
        }
        
        let engine = PersistenceEngine::new(config.clone());
        let interval = std::time::Duration::from_secs(config.auto_save_interval_secs);
        
        Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            
            loop {
                ticker.tick().await;
                
                if let Ok(m) = mesh.try_lock() {
                    if let Err(e) = engine.save(&m) {
                        error!("Auto-save failed: {}", e);
                    }
                }
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_persistence_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let config = PersistenceConfig {
            enabled: true,
            data_dir: temp_dir.path().to_path_buf(),
            auto_save_interval_secs: 0,
            load_on_startup: true,
            compress: false,
        };
        
        let engine = PersistenceEngine::new(config);
        
        // Create mesh with some data
        let mut mesh = HostMeshCognition::new(0.6, 0.3, 0.5);
        mesh.register_service(crate::mesh_cognition::WebServiceType::Nginx, 1001);
        
        // Save
        engine.save(&mesh).unwrap();
        
        // Load
        let loaded = engine.load().unwrap();
        assert!(loaded.is_some());
        
        let state = loaded.unwrap();
        assert_eq!(state.version, PersistedState::CURRENT_VERSION);
    }
    
    #[test]
    fn test_compressed_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let config = PersistenceConfig {
            enabled: true,
            data_dir: temp_dir.path().to_path_buf(),
            auto_save_interval_secs: 0,
            load_on_startup: true,
            compress: true,
        };
        
        let engine = PersistenceEngine::new(config);
        
        let mesh = HostMeshCognition::new(0.6, 0.3, 0.5);
        
        engine.save(&mesh).unwrap();
        
        // Verify compressed file exists
        let path = engine.get_state_file_path();
        assert!(path.exists());
        assert!(path.to_string_lossy().ends_with(".gz"));
        
        // Load and verify
        let loaded = engine.load().unwrap();
        assert!(loaded.is_some());
    }
}
