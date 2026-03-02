//! Tail Mode - Real-time Log File Monitoring
//!
//! Monitors web server log files in real-time, analyzing new entries as they appear.
//! Supports log rotation and multiple log files.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn, error, debug};

use webguard::runtime_config::TailConfig;
use crate::log_parser::{LogParser, ParsedLogEntry};
use crate::semantic_normalizer::SemanticNormalizer;
use crate::embedding_learner::EmbeddingLearner;
use crate::mesh_cognition::{HostMeshCognition, WebServiceType};
use crate::policy;
use crate::config::Config;

/// Log file state for tracking position
struct LogFileState {
    path: PathBuf,
    position: u64,
    inode: Option<u64>,
}

impl LogFileState {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            position: 0,
            inode: None,
        }
    }
    
    #[cfg(unix)]
    fn get_inode(path: &PathBuf) -> Option<u64> {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|m| m.ino())
    }
    
    #[cfg(not(unix))]
    fn get_inode(_path: &PathBuf) -> Option<u64> {
        None
    }
    
    fn check_rotation(&mut self) -> bool {
        let current_inode = Self::get_inode(&self.path);
        if self.inode.is_some() && current_inode != self.inode {
            // File was rotated
            self.position = 0;
            self.inode = current_inode;
            true
        } else {
            self.inode = current_inode;
            false
        }
    }
}

/// Real-time log analyzer
pub struct TailAnalyzer {
    config: TailConfig,
    app_config: Config,
    parser: LogParser,
    normalizer: SemanticNormalizer,
    embedding_learner: EmbeddingLearner,
    mesh: Arc<Mutex<HostMeshCognition>>,
    file_states: HashMap<PathBuf, LogFileState>,
    stats: TailStats,
}

/// Statistics for tail mode
#[derive(Debug, Default)]
pub struct TailStats {
    pub total_lines_processed: u64,
    pub total_threats_detected: u64,
    pub total_suspicious: u64,
    pub lines_per_second: f64,
}

impl TailAnalyzer {
    /// Create a new tail analyzer
    pub fn new(
        config: TailConfig,
        app_config: Config,
        mesh: Arc<Mutex<HostMeshCognition>>,
    ) -> Self {
        let mut file_states = HashMap::new();
        for path in &config.log_paths {
            file_states.insert(path.clone(), LogFileState::new(path.clone()));
        }
        
        Self {
            parser: LogParser::new(config.format.clone()),
            normalizer: SemanticNormalizer::new(),
            embedding_learner: EmbeddingLearner::new(),
            mesh,
            file_states,
            stats: TailStats::default(),
            config,
            app_config,
        }
    }
    
    /// Process new lines from a log file
    fn process_file(&mut self, path: &PathBuf) -> Result<usize, Box<dyn std::error::Error>> {
        // First, get the current position and check rotation
        let (mut current_position, follow_rotation) = {
            let state = self.file_states.get_mut(path).unwrap();
            if self.config.follow_rotation && state.check_rotation() {
                info!("Detected log rotation for {:?}, resetting position", path);
            }
            (state.position, self.config.follow_rotation)
        };
        
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                debug!("Could not open {:?}: {}", path, e);
                return Ok(0);
            }
        };
        
        let metadata = file.metadata()?;
        let file_size = metadata.len();
        
        // If file is smaller than our position, it was truncated/rotated
        if file_size < current_position {
            current_position = 0;
        }
        
        // If we're at the end, nothing to do
        if current_position >= file_size {
            return Ok(0);
        }
        
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(current_position))?;
        
        let mut lines_processed = 0;
        let mut line = String::new();
        let mut entries_to_analyze = Vec::new();
        
        // Collect entries first
        while reader.read_line(&mut line)? > 0 {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                if let Ok(entry) = self.parser.parse_line(trimmed) {
                    entries_to_analyze.push(entry);
                    lines_processed += 1;
                }
            }
            line.clear();
        }
        
        let final_position = reader.stream_position()?;
        
        // Now analyze each entry
        for entry in entries_to_analyze {
            self.analyze_entry(entry);
        }
        
        // Update state
        let state = self.file_states.get_mut(path).unwrap();
        state.position = final_position;
        self.stats.total_lines_processed += lines_processed as u64;
        
        Ok(lines_processed)
    }
    
    /// Analyze a single log entry
    fn analyze_entry(&mut self, entry: ParsedLogEntry) {
        let request_str = entry.to_analysis_string();
        
        // Normalize
        let normalized = self.normalizer.normalize(request_str.as_bytes());
        let normalized_str = String::from_utf8_lossy(&normalized);
        
        // Get embedding
        let embedding = self.embedding_learner.embed(&normalized_str);
        let threat_score = self.embedding_learner.threat_score(&embedding);
        
        // Convert to fixed array for mesh cognition
        let mut feature_arr = [0.0f32; 32];
        for i in 0..embedding.len().min(32) {
            feature_arr[i] = embedding[i];
        }
        
        // Query mesh cognition
        let (top_sim, avg_valence, action) = {
            if let Ok(m) = self.mesh.try_lock() {
                // Get a service to work with (use first registered or create default)
                let service_id = m.get_active_services().first()
                    .map(|s| s.0.clone())
                    .unwrap_or_else(|| "default".to_string());
                
                if let Some(service_memory) = m.get_service_memory(&service_id) {
                    let (top_sim, avg_valence) = {
                        let bdh = service_memory.lock().unwrap();
                        let sims = bdh.retrieve_similar(&feature_arr, 5);
                        if !sims.is_empty() {
                            let top = sims[0].1;
                            let sum_val: f32 = sims.iter().map(|(t, s)| t.valence * s).sum();
                            let sum_s: f32 = sims.iter().map(|(_, s)| *s).sum();
                            let avg = if sum_s > 0.0 { sum_val / (sum_s + 1e-6) } else { 0.0 };
                            (top, avg)
                        } else {
                            (0.0, threat_score)
                        }
                    };
                    
                    let host_aggression = m.get_host_aggression();
                    // BHSM RISC 3-action constraint: Detect, Allow, Block
                    let action = policy::choose_action(
                        top_sim,
                        avg_valence.max(threat_score),
                        host_aggression,
                        false,  // tail mode: monitoring only, no blocking
                        0.7,    // block threshold (not used in detect mode)
                    );
                    
                    (top_sim, avg_valence, action)
                } else {
                    (0.0, threat_score, policy::Action::Detect)
                }
            } else {
                (0.0, threat_score, policy::Action::Detect)
            }
        };
        
        // Determine if this is a threat
        let combined_score = (threat_score + avg_valence) / 2.0;
        let is_threat = combined_score > 0.7;
        let is_suspicious = combined_score > 0.4 && combined_score <= 0.7;
        
        if is_threat {
            self.stats.total_threats_detected += 1;
            warn!(
                "THREAT DETECTED: {} {} {} - score={:.3}, sim={:.3}, valence={:.3}, action={:?}",
                entry.remote_addr,
                entry.method,
                entry.uri,
                combined_score,
                top_sim,
                avg_valence,
                action
            );
            
            // Learn from this threat
            self.learn_from_entry(&entry, &feature_arr, combined_score, true);
        } else if is_suspicious {
            self.stats.total_suspicious += 1;
            info!(
                "SUSPICIOUS: {} {} {} - score={:.3}",
                entry.remote_addr,
                entry.method,
                entry.uri,
                combined_score
            );
        } else {
            debug!(
                "BENIGN: {} {} {} - score={:.3}",
                entry.remote_addr,
                entry.method,
                entry.uri,
                combined_score
            );
        }
    }
    
    /// Learn from an analyzed entry
    fn learn_from_entry(&mut self, entry: &ParsedLogEntry, features: &[f32; 32], score: f32, is_threat: bool) {
        if let Ok(m) = self.mesh.try_lock() {
            let service_id = m.get_active_services().first()
                .map(|s| s.0.clone())
                .unwrap_or_else(|| "default".to_string());
            
            if let Some(service_memory) = m.get_service_memory(&service_id) {
                let mut bdh = service_memory.lock().unwrap();
                
                let max_sim = bdh.max_similarity(features);
                if max_sim < self.app_config.tau_novel {
                    // Novel pattern - add new trace
                    let valence = if is_threat { score } else { -score };
                    let _id = bdh.add_trace(*features, valence);
                    debug!("Added new trace for {} (valence: {:.3})", entry.uri, valence);
                } else {
                    // Update existing similar traces
                    let reward = if is_threat { 1.0 } else { -0.5 };
                    let similar: Vec<(String, f32)> = bdh.retrieve_similar(features, 3)
                        .into_iter()
                        .map(|(t, s)| (t.id.clone(), s))
                        .collect();
                    
                    for (trace_id, similarity) in similar {
                        bdh.reward_update(&trace_id, reward * similarity, self.app_config.eta);
                    }
                }
            }
            
            // Cross-service learning for significant threats
            if is_threat && score > 0.6 {
                let service_id = m.get_active_services().first()
                    .map(|s| s.0.clone())
                    .unwrap_or_else(|| "default".to_string());
                m.cross_service_learning(&service_id, features, score, 1.0);
                m.consolidate_to_psi(&service_id, self.app_config.promote_threshold);
            }
        }
    }
    
    /// Start the tail loop
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting log tail for {:?}", self.config.log_paths);
        
        // Seek to end of files initially (don't process historical data)
        for path in &self.config.log_paths {
            if let Ok(metadata) = std::fs::metadata(path) {
                if let Some(state) = self.file_states.get_mut(path) {
                    state.position = metadata.len();
                    info!("Starting tail at position {} for {:?}", state.position, path);
                }
            }
        }
        
        let poll_duration = Duration::from_millis(self.config.poll_interval_ms);
        let mut last_stats_time = std::time::Instant::now();
        let mut last_line_count = 0u64;
        
        loop {
            let mut total_new_lines = 0;
            
            // Process each log file
            let paths: Vec<PathBuf> = self.config.log_paths.clone();
            for path in paths {
                match self.process_file(&path) {
                    Ok(lines) => total_new_lines += lines,
                    Err(e) => warn!("Error processing {:?}: {}", path, e),
                }
            }
            
            // Log statistics every 30 seconds
            let elapsed = last_stats_time.elapsed();
            if elapsed.as_secs() >= 30 {
                let lines_in_period = self.stats.total_lines_processed - last_line_count;
                self.stats.lines_per_second = lines_in_period as f64 / elapsed.as_secs_f64();
                
                info!(
                    "Tail Stats: {} lines ({:.1}/sec), {} threats, {} suspicious",
                    self.stats.total_lines_processed,
                    self.stats.lines_per_second,
                    self.stats.total_threats_detected,
                    self.stats.total_suspicious
                );
                
                last_stats_time = std::time::Instant::now();
                last_line_count = self.stats.total_lines_processed;
            }
            
            // If no new lines, sleep before next poll
            if total_new_lines == 0 {
                sleep(poll_duration).await;
            }
        }
    }
}

/// Run tail mode
pub async fn run_tail_mode(
    config: TailConfig,
    mesh: Arc<Mutex<HostMeshCognition>>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting WebGuard Tail Mode");
    
    // Ensure we have a service registered
    {
        let mut m = mesh.lock().unwrap();
        if m.get_active_services().is_empty() {
            m.register_service(WebServiceType::Nginx, std::process::id() as i32);
            info!("Registered default nginx service for tail mode");
        }
    }
    
    let app_config = Config::load_default();
    let mut analyzer = TailAnalyzer::new(config, app_config, mesh);
    
    analyzer.run().await
}
