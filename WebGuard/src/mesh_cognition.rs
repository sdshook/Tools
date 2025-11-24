use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use tracing::{info, debug};


use crate::memory_engine::bdh_memory::{BdhMemory, EMBED_DIM};
use crate::memory_engine::psi_index::{PsiIndex, PsiEntry};
use crate::memory_engine::valence::ValenceController;
use crate::retrospective_learning::{RetrospectiveLearningSystem, ThreatDiscoveryMethod, MissedThreatEvent, RetrospectiveLearningStats, FalsePositiveEvent};
use crate::eq_iq_regulator::ExperientialBehavioralRegulator;

/// Cognitive knowledge export structure for WebGuard-to-WebGuard sharing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveKnowledgeExport {
    pub export_timestamp: u64,
    pub source_instance_id: String,
    pub psi_semantic_patterns: Vec<PsiEntry>,
    pub hebbian_synaptic_connections: Vec<HebbianConnectionExport>,
    pub mesh_intelligence_stats: MeshIntelligenceStats,
    pub eq_iq_balance_profile: EqIqBalanceProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HebbianConnectionExport {
    pub source_pattern: [f32; EMBED_DIM],
    pub target_pattern: [f32; EMBED_DIM],
    pub synaptic_weight: f32,
    pub activation_frequency: u32,
    pub valence_association: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshIntelligenceStats {
    pub total_services: usize,
    pub cross_service_learning_events: u64,
    pub mesh_learning_rate: f32,
    pub collective_threat_detection_accuracy: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EqIqBalanceProfile {
    pub eq_weight: f32,
    pub iq_weight: f32,
    pub empathic_accuracy: f32,
    pub analytical_precision: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebServiceType {
    Apache,
    Nginx,
    IIS,
    NodeJS,
    Generic,
}

impl WebServiceType {
    pub fn as_str(&self) -> &str {
        match self {
            WebServiceType::Apache => "apache",
            WebServiceType::Nginx => "nginx",
            WebServiceType::IIS => "iis",
            WebServiceType::NodeJS => "nodejs",
            WebServiceType::Generic => "generic",
        }
    }
}

#[derive(Clone)]
pub struct ServiceMemory {
    pub service_type: WebServiceType,
    pub pid: i32,
    pub bdh_memory: Arc<Mutex<BdhMemory>>,
    pub active: bool,
}

pub struct HostMeshCognition {
    services: HashMap<String, ServiceMemory>,
    shared_psi: Arc<Mutex<PsiIndex>>,
    host_valence: Arc<Mutex<ValenceController>>,
    mesh_learning_rate: f32,
    cross_service_threshold: f32,
    retrospective_learning: Arc<Mutex<RetrospectiveLearningSystem>>,
    eq_iq_regulator: Arc<Mutex<ExperientialBehavioralRegulator>>,
}

impl HostMeshCognition {
    pub fn new(mesh_learning_rate: f32, cross_service_threshold: f32, aggression_init: f32) -> Self {
        Self {
            services: HashMap::new(),
            shared_psi: Arc::new(Mutex::new(PsiIndex::new())),
            host_valence: Arc::new(Mutex::new(ValenceController::new(aggression_init))),
            mesh_learning_rate,
            cross_service_threshold,
            retrospective_learning: Arc::new(Mutex::new(RetrospectiveLearningSystem::new())),
            eq_iq_regulator: Arc::new(Mutex::new(ExperientialBehavioralRegulator::new(0.5, 0.5, 0.1))),
        }
    }

    pub fn register_service(&mut self, service_type: WebServiceType, pid: i32) -> String {
        let service_id = format!("{}_{}", service_type.as_str(), pid);
        let service_memory = ServiceMemory {
            service_type: service_type.clone(),
            pid,
            bdh_memory: Arc::new(Mutex::new(BdhMemory::new())),
            active: true,
        };
        
        self.services.insert(service_id.clone(), service_memory);
        info!("Registered web service: {} (PID: {})", service_type.as_str(), pid);
        service_id
    }

    pub fn deregister_service(&mut self, service_id: &str) {
        if let Some(service) = self.services.remove(service_id) {
            info!("Deregistered web service: {} (PID: {})", 
                  service.service_type.as_str(), service.pid);
        }
    }

    pub fn get_service_memory(&self, service_id: &str) -> Option<Arc<Mutex<BdhMemory>>> {
        self.services.get(service_id).map(|s| s.bdh_memory.clone())
    }

    pub fn get_shared_psi(&self) -> Arc<Mutex<PsiIndex>> {
        self.shared_psi.clone()
    }

    pub fn get_host_valence(&self) -> Arc<Mutex<ValenceController>> {
        self.host_valence.clone()
    }

    pub fn cross_service_learning(&self, source_service_id: &str, vector: &[f32; EMBED_DIM], valence: f32, reward: f32) {
        // Only propagate if the signal is strong enough
        if valence.abs() < self.cross_service_threshold {
            return;
        }

        let mut propagated_count = 0;
        
        // Share learning with all other active services on the host
        for (service_id, service_memory) in &self.services {
            if service_id != source_service_id && service_memory.active {
                let dampened_valence = valence * self.mesh_learning_rate;
                let dampened_reward = reward * self.mesh_learning_rate * 0.5; // Further dampen reward
                
                if let Ok(mut bdh) = service_memory.bdh_memory.try_lock() {
                    // Check if this pattern is novel for the target service
                    let max_sim = bdh.max_similarity(vector);
                    if max_sim < 0.7 { // Novel pattern threshold
                        let _trace_id = bdh.add_trace(*vector, dampened_valence);
                        debug!("Cross-service learning: {} -> {} (valence: {:.3}, similarity: {:.3})", 
                               source_service_id, service_id, dampened_valence, max_sim);
                        propagated_count += 1;
                    } else {
                        // Update existing similar traces
                        let similar_traces: Vec<(String, f32)> = {
                            let similar = bdh.retrieve_similar(vector, 3);
                            similar.into_iter()
                                .filter(|(_, similarity)| *similarity > 0.7)
                                .map(|(trace, similarity)| (trace.id.clone(), similarity))
                                .collect()
                        };
                        
                        for (trace_id, similarity) in similar_traces {
                            bdh.reward_update(&trace_id, dampened_reward * similarity, 0.05);
                        }
                    }
                }
            }
        }

        if propagated_count > 0 {
            info!("Mesh cognition: propagated pattern from {} to {} services", 
                  source_service_id, propagated_count);
        }
    }

    pub fn consolidate_to_psi(&self, source_service_id: &str, promote_threshold: f32) {
        if let Some(service) = self.services.get(source_service_id) {
            if let Ok(bdh) = service.bdh_memory.try_lock() {
                let candidates = bdh.promote_candidates(promote_threshold);
                
                let candidate_count = candidates.len();
                if !candidates.is_empty() {
                    if let Ok(mut psi) = self.shared_psi.try_lock() {
                        for trace in &candidates {
                            let psi_entry = PsiEntry {
                                id: format!("{}_{}", source_service_id, trace.id),
                                vec: trace.vec,
                                valence: trace.valence,
                                uses: trace.uses,
                                tags: vec![
                                    "consolidated".to_string(),
                                    service.service_type.as_str().to_string(),
                                    format!("pid_{}", service.pid),
                                ],
                            };
                            psi.add(psi_entry);
                        }
                        info!("Consolidated {} patterns from {} to shared PSI", 
                              candidate_count, source_service_id);
                    }
                }
            }
        }
    }

    pub fn query_collective_memory(&self, vector: &[f32; EMBED_DIM], top_k: usize) -> Vec<(String, f32, f32)> {
        let mut results = Vec::new();

        // Query all service memories
        for (service_id, service_memory) in &self.services {
            if service_memory.active {
                if let Ok(bdh) = service_memory.bdh_memory.try_lock() {
                    let similar = bdh.retrieve_similar(vector, top_k);
                    for (trace, similarity) in similar {
                        results.push((service_id.clone(), similarity, trace.valence));
                    }
                }
            }
        }

        // Query shared PSI
        if let Ok(psi) = self.shared_psi.try_lock() {
            let psi_results = psi.search(vector, top_k);
            for (entry, similarity) in psi_results {
                results.push(("shared_psi".to_string(), similarity, entry.valence));
            }
        }

        // Sort by similarity and return top results
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.into_iter().take(top_k).collect()
    }

    pub fn update_host_aggression(&self, reward: f32) {
        if let Ok(mut valence) = self.host_valence.try_lock() {
            valence.record_reward(reward);
        }
    }

    pub fn get_host_aggression(&self) -> f32 {
        self.host_valence.lock().unwrap().aggression
    }

    pub fn get_active_services(&self) -> Vec<String> {
        self.services.iter()
            .filter(|(_, service)| service.active)
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn get_service_stats(&self) -> HashMap<String, (usize, f32)> {
        let mut stats = HashMap::new();
        
        for (service_id, service_memory) in &self.services {
            if let Ok(bdh) = service_memory.bdh_memory.try_lock() {
                let trace_count = bdh.traces.len();
                let avg_valence = if trace_count > 0 {
                    bdh.traces.iter().map(|t| t.valence).sum::<f32>() / trace_count as f32
                } else {
                    0.0
                };
                stats.insert(service_id.clone(), (trace_count, avg_valence));
            }
        }
        
        stats
    }

    /// Report a missed threat for retrospective learning
    pub fn report_missed_threat(&self, 
                                original_timestamp: f64,
                                discovery_timestamp: f64,
                                original_threat_score: f32,
                                actual_threat_level: f32,
                                feature_vector: Vec<f32>,
                                discovery_method: ThreatDiscoveryMethod,
                                consequence_severity: f32) {
        
        let missed_threat = MissedThreatEvent {
            original_timestamp,
            discovery_timestamp,
            original_threat_score,
            actual_threat_level,
            feature_vector,
            original_context: crate::eq_iq_regulator::ContextEvent {
                timestamp: original_timestamp,
                context_stability: 0.5, // Moderate stability assumption
                threat_level: original_threat_score,
                response_appropriateness: 0.2, // Low appropriateness for missing threat
            },
            discovery_method,
            consequence_severity,
        };

        if let Ok(mut retro_learning) = self.retrospective_learning.try_lock() {
            retro_learning.add_missed_threat(missed_threat);
            info!("Added missed threat to retrospective learning system: original_score={:.3}, actual_level={:.3}, severity={:.3}",
                  original_threat_score, actual_threat_level, consequence_severity);
        }
    }

    /// Apply retrospective learning to improve future threat detection
    pub fn apply_retrospective_learning(&self, current_timestamp: f64) {
        // Apply retrospective learning to EQ/IQ regulator
        if let (Ok(mut retro_learning), Ok(mut eq_iq_regulator)) = 
            (self.retrospective_learning.try_lock(), self.eq_iq_regulator.try_lock()) {
            retro_learning.apply_retrospective_eq_iq_learning(&mut eq_iq_regulator, current_timestamp);
        }

        // Apply retrospective learning to all service memories
        for (service_id, service_memory) in &self.services {
            if let (Ok(mut retro_learning), Ok(mut bdh_memory)) = 
                (self.retrospective_learning.try_lock(), service_memory.bdh_memory.try_lock()) {
                retro_learning.apply_retrospective_memory_learning(&mut bdh_memory, current_timestamp);
                debug!("Applied retrospective learning to service: {}", service_id);
            }
        }
    }

    /// Get threat score adjustment based on retrospective learning
    pub fn get_retrospective_threat_adjustment(&self, feature_vector: &[f32], base_score: f32) -> f32 {
        if let Ok(retro_learning) = self.retrospective_learning.try_lock() {
            retro_learning.calculate_threat_score_adjustment(feature_vector, base_score)
        } else {
            base_score
        }
    }

    /// Get retrospective learning statistics
    pub fn get_retrospective_learning_stats(&self) -> Option<RetrospectiveLearningStats> {
        if let Ok(retro_learning) = self.retrospective_learning.try_lock() {
            Some(retro_learning.get_learning_stats().clone())
        } else {
            None
        }
    }

    /// Clean up old retrospective learning data
    pub fn cleanup_retrospective_learning(&self, current_timestamp: f64, retention_days: f64) {
        if let Ok(mut retro_learning) = self.retrospective_learning.try_lock() {
            retro_learning.cleanup_old_threats(current_timestamp, retention_days);
        }
    }

    /// Get balanced learning configuration
    pub fn get_balanced_learning_config(&self) -> Option<(f32, f32, f32, f32)> {
        if let Ok(retro_learning) = self.retrospective_learning.try_lock() {
            Some((
                retro_learning.false_negative_learning_rate,
                retro_learning.false_positive_learning_rate,
                retro_learning.regularization_factor,
                retro_learning.max_adjustment_magnitude,
            ))
        } else {
            None
        }
    }

    /// Report a false positive for balanced learning
    pub fn report_false_positive(&self,
                                  timestamp: f64,
                                  original_threat_score: f32,
                                  actual_threat_level: f32,
                                  feature_vector: Vec<f32>,
                                  impact_severity: f32) {
        
        let false_positive = FalsePositiveEvent {
            timestamp,
            original_threat_score,
            actual_threat_level,
            feature_vector,
            context: crate::eq_iq_regulator::ContextEvent {
                timestamp,
                context_stability: 0.7, // Higher stability for false positives (normal behavior)
                threat_level: actual_threat_level,
                response_appropriateness: 0.1, // Low appropriateness for false positive
            },
            impact_severity,
        };

        if let Ok(mut retro_learning) = self.retrospective_learning.try_lock() {
            retro_learning.add_false_positive(false_positive);
            info!("Added false positive to retrospective learning system: original_score={:.3}, actual_level={:.3}, impact={:.3}",
                  original_threat_score, actual_threat_level, impact_severity);
        }
    }

    /// Add a false positive event for balanced learning (legacy method)
    pub fn add_false_positive(&self, false_positive: FalsePositiveEvent) {
        if let Ok(mut retro_learning) = self.retrospective_learning.try_lock() {
            retro_learning.add_false_positive(false_positive);
        }
    }

    /// Export missed threat patterns for analysis
    pub fn export_missed_threat_patterns(&self) -> Vec<std::collections::HashMap<String, serde_json::Value>> {
        if let Ok(retro_learning) = self.retrospective_learning.try_lock() {
            retro_learning.export_missed_threat_patterns()
        } else {
            Vec::new()
        }
    }

    /// Process a request through the mesh cognition system
    pub fn process_request(&mut self, features: [f32; 32], context_event: &crate::eq_iq_regulator::ContextEvent) -> Result<(f32, f32, String), Box<dyn std::error::Error>> {
        // Process through EQ/IQ regulator first
        if let Ok(mut eq_iq) = self.eq_iq_regulator.try_lock() {
            eq_iq.process_context_event(context_event.clone())?;
        }

        // Convert features to embedding dimension
        let mut embedding = [0.0; EMBED_DIM];
        for (i, &feature) in features.iter().enumerate() {
            if i < EMBED_DIM {
                embedding[i] = feature;
            }
        }

        // Process through memory system
        let similarity = self.calculate_similarity(&embedding)?;
        let valence = self.calculate_valence(&embedding)?;
        
        // Apply retrospective learning adjustment using balanced learning
        let feature_slice: Vec<f32> = features.iter().take(27).cloned().collect();
        let retrospective_adjustment = self.get_retrospective_threat_adjustment(&feature_slice, similarity);
        let adjusted_similarity = (similarity + retrospective_adjustment).clamp(0.0, 1.0);
        
        // Generate trace ID
        let trace_id = format!("trace_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis());
        
        // Store memory trace with learning-friendly thresholds
        let should_store = adjusted_similarity > 0.1 || 
                          valence.abs() > 0.2 || 
                          context_event.threat_level > 0.5; // Always store high threat events
        
        if should_store {
            // Use threat level as learning signal for valence
            let learning_valence = if context_event.threat_level > 0.5 { 
                0.8  // Positive valence for threats (to remember them)
            } else { 
                -0.2 // Slight negative valence for normal traffic
            };
            self.store_memory_trace(&embedding, adjusted_similarity, learning_valence)?;
        }

        Ok((adjusted_similarity, valence, trace_id))
    }

    /// Apply feedback for learning
    pub fn apply_feedback(&mut self, feedback_event: &crate::eq_iq_regulator::FeedbackEvent) -> Result<(), Box<dyn std::error::Error>> {
        // Apply feedback to EQ/IQ regulator
        if let Ok(mut eq_iq) = self.eq_iq_regulator.try_lock() {
            eq_iq.apply_feedback(feedback_event.clone())?;
        }

        // Update learning rate based on feedback
        if feedback_event.accuracy > 0.8 {
            self.mesh_learning_rate = (self.mesh_learning_rate * 0.95).max(0.001);
        } else {
            self.mesh_learning_rate = (self.mesh_learning_rate * 1.05).min(0.1);
        }

        Ok(())
    }

    /// Get memory system statistics
    pub fn get_memory_stats(&self) -> MemoryStats {
        let mut total_traces = 0;
        let mut total_connections = 0;
        let mut psi_entries = 0;

        // Count traces and connections from all services
        for service in self.services.values() {
            if let Ok(bdh) = service.bdh_memory.try_lock() {
                total_traces += bdh.get_trace_count();
                total_connections += bdh.get_connection_count();
            }
        }

        // Count PSI entries
        if let Ok(psi) = self.shared_psi.try_lock() {
            psi_entries = psi.get_entry_count();
        }

        MemoryStats {
            total_traces,
            total_connections,
            psi_entries,
            current_learning_rate: self.mesh_learning_rate,
        }
    }

    /// Get EQ/IQ balance information
    pub fn get_eq_iq_balance(&self) -> EqIqBalance {
        if let Ok(eq_iq) = self.eq_iq_regulator.try_lock() {
            eq_iq.get_balance_info()
        } else {
            EqIqBalance {
                eq_weight: 0.5,
                iq_weight: 0.5,
            }
        }
    }

    /// Get empathic accuracy score
    pub fn get_empathic_accuracy(&self) -> f32 {
        if let Ok(eq_iq) = self.eq_iq_regulator.try_lock() {
            eq_iq.get_empathic_accuracy()
        } else {
            0.5
        }
    }

    /// Helper method to calculate similarity
    fn calculate_similarity(&self, embedding: &[f32; EMBED_DIM]) -> Result<f32, Box<dyn std::error::Error>> {
        let mut max_similarity: f32 = 0.0;
        
        for service in self.services.values() {
            if let Ok(bdh) = service.bdh_memory.try_lock() {
                let similarity = bdh.calculate_similarity(embedding)?;
                max_similarity = max_similarity.max(similarity);
            }
        }
        
        Ok(max_similarity)
    }

    /// Helper method to calculate valence
    fn calculate_valence(&self, _embedding: &[f32; EMBED_DIM]) -> Result<f32, Box<dyn std::error::Error>> {
        if let Ok(valence_controller) = self.host_valence.try_lock() {
            // Use aggression as a proxy for valence (negative aggression = negative valence)
            Ok(-valence_controller.aggression)
        } else {
            Ok(0.0)
        }
    }

    /// Helper method to store memory trace
    fn store_memory_trace(&mut self, embedding: &[f32; EMBED_DIM], similarity: f32, valence: f32) -> Result<(), Box<dyn std::error::Error>> {
        // Store in the first available service (or create a generic one)
        if self.services.is_empty() {
            // Create a generic service if none exists
            let generic_service = ServiceMemory {
                service_type: WebServiceType::Generic,
                pid: 0,
                bdh_memory: Arc::new(Mutex::new(BdhMemory::new())),
                active: true,
            };
            self.services.insert("generic".to_string(), generic_service);
        }

        if let Some(service) = self.services.values().next() {
            if let Ok(mut bdh) = service.bdh_memory.try_lock() {
                bdh.store_trace(embedding.clone(), similarity, valence)?;
            }
        }

        Ok(())
    }

    /// Export cognitive knowledge for sharing with other WebGuard instances
    /// This leverages the PSI/BHSM/CMNN architecture for native knowledge transfer
    pub fn export_cognitive_knowledge(&self, instance_id: String) -> Result<CognitiveKnowledgeExport, Box<dyn std::error::Error>> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Export PSI semantic patterns
        let psi_patterns = if let Ok(psi) = self.shared_psi.try_lock() {
            psi.export_high_quality_patterns(0.3) // Export patterns with confidence > 0.3
        } else {
            Vec::new()
        };

        // Export Hebbian synaptic connections from all services
        let mut hebbian_connections = Vec::new();
        let mut total_cross_service_events = 0u64;
        let mut collective_accuracy = 0.0f32;

        for service in self.services.values() {
            if let Ok(bdh) = service.bdh_memory.try_lock() {
                let connections = bdh.export_synaptic_connections(0.2); // Export connections with weight > 0.2
                hebbian_connections.extend(connections);
                total_cross_service_events += bdh.get_learning_event_count();
                collective_accuracy += bdh.get_accuracy_score();
            }
        }

        if !self.services.is_empty() {
            collective_accuracy /= self.services.len() as f32;
        }

        // Export mesh intelligence stats
        let mesh_stats = MeshIntelligenceStats {
            total_services: self.services.len(),
            cross_service_learning_events: total_cross_service_events,
            mesh_learning_rate: self.mesh_learning_rate,
            collective_threat_detection_accuracy: collective_accuracy,
        };

        // Export EQ/IQ balance profile
        let eq_iq_profile = if let Ok(eq_iq) = self.eq_iq_regulator.try_lock() {
            let balance = eq_iq.get_balance_info();
            EqIqBalanceProfile {
                eq_weight: balance.eq_weight,
                iq_weight: balance.iq_weight,
                empathic_accuracy: eq_iq.get_empathic_accuracy(),
                analytical_precision: eq_iq.get_analytical_precision(),
            }
        } else {
            EqIqBalanceProfile {
                eq_weight: 0.5,
                iq_weight: 0.5,
                empathic_accuracy: 0.5,
                analytical_precision: 0.5,
            }
        };

        Ok(CognitiveKnowledgeExport {
            export_timestamp: current_time,
            source_instance_id: instance_id,
            psi_semantic_patterns: psi_patterns,
            hebbian_synaptic_connections: hebbian_connections,
            mesh_intelligence_stats: mesh_stats,
            eq_iq_balance_profile: eq_iq_profile,
        })
    }

    /// Import cognitive knowledge from another WebGuard instance
    /// This integrates learned patterns into the existing PSI/BHSM/CMNN architecture
    pub fn import_cognitive_knowledge(&mut self, knowledge: CognitiveKnowledgeExport) -> Result<(), Box<dyn std::error::Error>> {
        info!("Importing cognitive knowledge from instance: {}", knowledge.source_instance_id);

        // Import PSI semantic patterns
        let psi_pattern_count = knowledge.psi_semantic_patterns.len();
        if let Ok(mut psi) = self.shared_psi.try_lock() {
            for pattern in knowledge.psi_semantic_patterns {
                // Only import high-quality patterns to prevent knowledge degradation
                if pattern.valence.abs() > 0.3 && pattern.uses > 2 {
                    psi.add(pattern);
                }
            }
        }

        // Import Hebbian synaptic connections into service memories
        if !self.services.is_empty() {
            let service_count = self.services.len();
            let connections_per_service = knowledge.hebbian_synaptic_connections.len() / service_count.max(1);
            
            for (i, service) in self.services.values().enumerate() {
                if let Ok(mut bdh) = service.bdh_memory.try_lock() {
                    let start_idx = i * connections_per_service;
                    let end_idx = ((i + 1) * connections_per_service).min(knowledge.hebbian_synaptic_connections.len());
                    
                    for connection in &knowledge.hebbian_synaptic_connections[start_idx..end_idx] {
                        // Only import strong synaptic connections
                        if connection.synaptic_weight.abs() > 0.3 {
                            bdh.import_synaptic_connection(
                                &connection.source_pattern,
                                &connection.target_pattern,
                                connection.synaptic_weight,
                                connection.valence_association
                            )?;
                        }
                    }
                }
            }
        }

        // Adapt mesh learning rate based on imported intelligence
        let imported_accuracy = knowledge.mesh_intelligence_stats.collective_threat_detection_accuracy;
        let current_accuracy = if !self.services.is_empty() {
            let mut total_accuracy = 0.0f32;
            for service in self.services.values() {
                if let Ok(bdh) = service.bdh_memory.try_lock() {
                    total_accuracy += bdh.get_accuracy_score();
                }
            }
            total_accuracy / self.services.len() as f32
        } else {
            0.5
        };
        
        if imported_accuracy > current_accuracy {
            // If imported knowledge is more accurate, adapt our learning rate
            self.mesh_learning_rate = (self.mesh_learning_rate + knowledge.mesh_intelligence_stats.mesh_learning_rate) / 2.0;
        }

        // Import EQ/IQ balance adjustments
        if let Ok(mut eq_iq) = self.eq_iq_regulator.try_lock() {
            eq_iq.adapt_from_external_profile(
                knowledge.eq_iq_balance_profile.eq_weight,
                knowledge.eq_iq_balance_profile.iq_weight,
                knowledge.eq_iq_balance_profile.empathic_accuracy
            )?;
        }

        info!("Successfully imported {} PSI patterns and {} Hebbian connections", 
              psi_pattern_count, 
              knowledge.hebbian_synaptic_connections.len());

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub total_traces: usize,
    pub total_connections: usize,
    pub psi_entries: usize,
    pub current_learning_rate: f32,
}

#[derive(Debug, Clone)]
pub struct EqIqBalance {
    pub eq_weight: f32,
    pub iq_weight: f32,
}

// Helper function to detect web server type from process information
pub fn detect_service_type(process_name: &str, command_line: &str) -> WebServiceType {
    let process_lower = process_name.to_lowercase();
    let cmd_lower = command_line.to_lowercase();
    
    // Detect Apache processes
    if process_lower.contains("httpd") || process_lower.contains("apache") || 
       cmd_lower.contains("httpd") || cmd_lower.contains("apache") {
        WebServiceType::Apache
    }
    // Detect NGINX processes
    else if process_lower.contains("nginx") || cmd_lower.contains("nginx") {
        WebServiceType::Nginx
    }
    // Detect IIS processes (w3wp.exe, iisexpress.exe, etc.)
    else if process_lower.contains("w3wp") || process_lower.contains("iis") ||
            cmd_lower.contains("w3wp") || cmd_lower.contains("iis") {
        WebServiceType::IIS
    }
    // Detect Node.js processes
    else if process_lower.contains("node") || cmd_lower.contains("node") ||
            process_lower.contains("nodejs") || cmd_lower.contains("nodejs") {
        WebServiceType::NodeJS
    }
    // Default to generic
    else {
        WebServiceType::Generic
    }
}