use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use tracing::{info, debug};
use uuid::Uuid;

use crate::memory_engine::bdh_memory::{BdhMemory, EMBED_DIM};
use crate::memory_engine::psi_index::{PsiIndex, PsiEntry};
use crate::memory_engine::valence::ValenceController;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebServiceType {
    Apache,
    Nginx,
    IIS,
    NodeJS,
    Tomcat,
    Generic(String),
}

impl WebServiceType {
    pub fn as_str(&self) -> &str {
        match self {
            WebServiceType::Apache => "apache",
            WebServiceType::Nginx => "nginx", 
            WebServiceType::IIS => "iis",
            WebServiceType::NodeJS => "nodejs",
            WebServiceType::Tomcat => "tomcat",
            WebServiceType::Generic(name) => name,
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
}

impl HostMeshCognition {
    pub fn new(mesh_learning_rate: f32, cross_service_threshold: f32, aggression_init: f32) -> Self {
        Self {
            services: HashMap::new(),
            shared_psi: Arc::new(Mutex::new(PsiIndex::new())),
            host_valence: Arc::new(Mutex::new(ValenceController::new(aggression_init))),
            mesh_learning_rate,
            cross_service_threshold,
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
                        let trace_id = bdh.add_trace(*vector, dampened_valence);
                        debug!("Cross-service learning: {} -> {} (valence: {:.3}, similarity: {:.3})", 
                               source_service_id, service_id, dampened_valence, max_sim);
                        propagated_count += 1;
                    } else {
                        // Update existing similar traces
                        let similar = bdh.retrieve_similar(vector, 3);
                        for (trace, similarity) in similar {
                            if similarity > 0.7 {
                                bdh.reward_update(&trace.id, dampened_reward * similarity, 0.05);
                            }
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
                
                if !candidates.is_empty() {
                    if let Ok(mut psi) = self.shared_psi.try_lock() {
                        for trace in candidates {
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
                              candidates.len(), source_service_id);
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
}

// Helper function to detect web service type from process information
pub fn detect_service_type(process_name: &str, command_line: &str) -> WebServiceType {
    let process_lower = process_name.to_lowercase();
    let cmd_lower = command_line.to_lowercase();
    
    if process_lower.contains("apache") || process_lower.contains("httpd") {
        WebServiceType::Apache
    } else if process_lower.contains("nginx") {
        WebServiceType::Nginx
    } else if process_lower.contains("w3wp") || cmd_lower.contains("iis") {
        WebServiceType::IIS
    } else if process_lower.contains("node") && (cmd_lower.contains("express") || cmd_lower.contains("http")) {
        WebServiceType::NodeJS
    } else if process_lower.contains("tomcat") || process_lower.contains("catalina") {
        WebServiceType::Tomcat
    } else {
        WebServiceType::Generic(process_name.to_string())
    }
}