
use serde::{Serialize, Deserialize};
use uuid::Uuid;

pub const EMBED_DIM: usize = 32;

#[derive(Serialize, Deserialize, Clone)]
pub struct MemoryTrace {
    pub id: String,
    pub vec: [f32; EMBED_DIM],
    pub valence: f32,
    pub uses: u32,
    pub cum_reward: f32,
    pub hebbian_weights: [f32; EMBED_DIM], // Bidirectional Hebbian connection weights
    pub activation_history: Vec<f32>,      // Recent activation levels for temporal Hebbian learning
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HebbianConnection {
    pub source_id: String,
    pub target_id: String,
    pub weight: f32,
    pub last_update: f32,
}

pub struct BdhMemory {
    pub traces: Vec<MemoryTrace>,
    pub hebbian_connections: Vec<HebbianConnection>, // Explicit bidirectional connections
    pub hebbian_learning_rate: f32,
    pub decay_rate: f32,
    pub activation_threshold: f32,
}

impl BdhMemory {
    pub fn new() -> Self { 
        Self { 
            traces: Vec::new(),
            hebbian_connections: Vec::new(),
            hebbian_learning_rate: 0.01,
            decay_rate: 0.001,
            activation_threshold: 0.5,
        } 
    }

    pub fn add_trace(&mut self, vec: [f32; EMBED_DIM], valence: f32) -> String {
        let id = Uuid::new_v4().to_string();
        let trace = MemoryTrace { 
            id: id.clone(), 
            vec, 
            valence, 
            uses: 1, 
            cum_reward: valence,
            hebbian_weights: [0.0; EMBED_DIM], // Initialize Hebbian weights
            activation_history: vec![valence.abs()], // Initialize with current activation
        };
        
        // Create bidirectional Hebbian connections with existing traces
        self.create_hebbian_connections(&id, &vec, valence);
        
        self.traces.push(trace);
        id
    }

    pub fn retrieve_similar(&self, q: &[f32; EMBED_DIM], top_k: usize) -> Vec<(&MemoryTrace, f32)> {
        let mut out: Vec<(&MemoryTrace, f32)> = self.traces.iter()
            .map(|t| {
                let base_similarity = cosine_sim(&t.vec, q);
                let hebbian_boost = self.calculate_hebbian_boost(&t.id, q);
                let enhanced_similarity = base_similarity + hebbian_boost;
                (t, enhanced_similarity)
            })
            .collect();
        out.sort_by(|a,b| b.1.partial_cmp(&a.1).unwrap());
        out.into_iter().take(top_k).collect()
    }
    
    /// Calculate Hebbian connection boost for retrieval
    fn calculate_hebbian_boost(&self, trace_id: &str, query: &[f32; EMBED_DIM]) -> f32 {
        let mut boost = 0.0;
        
        // Find trace's Hebbian weights
        if let Some(trace) = self.traces.iter().find(|t| t.id == trace_id) {
            // Self-reinforcement boost from trace's own Hebbian weights
            for i in 0..EMBED_DIM {
                boost += trace.hebbian_weights[i] * query[i].abs() * 0.1; // Scale factor
            }
        }
        
        // Connection-based boost from other traces
        for conn in &self.hebbian_connections {
            if conn.target_id == trace_id {
                // This trace is a target, get boost from source activation
                let source_activation = self.get_trace_activation(&conn.source_id);
                boost += conn.weight * source_activation * 0.05; // Scale factor
            }
        }
        
        boost.max(-0.3).min(0.3) // Clamp boost to prevent overwhelming base similarity
    }

    /// Reinforced Hebbian Learning: Updates both valence and Hebbian weights based on reward
    pub fn reward_update(&mut self, id: &str, reward: f32, eta: f32) {
        if let Some(trace_idx) = self.traces.iter().position(|x| x.id == id) {
            let activation = reward.abs();
            let trace_id = self.traces[trace_idx].id.clone();
            
            // Traditional reward update
            {
                let trace = &mut self.traces[trace_idx];
                trace.cum_reward += reward;
                trace.valence = trace.valence + eta * (reward - trace.valence);
                trace.uses += 1;
                
                // Update activation history for temporal Hebbian learning
                trace.activation_history.push(activation);
                if trace.activation_history.len() > 10 {
                    trace.activation_history.remove(0); // Keep only recent history
                }
            }
            
            // Reinforced Hebbian Learning: Modulate Hebbian weight updates by reward
            self.hebbian_update_with_reinforcement(&trace_id, reward, activation);
        }
    }
    
    /// Core Bidirectional Hebbian Learning: "Neurons that fire together, wire together"
    fn hebbian_update_with_reinforcement(&mut self, trace_id: &str, reward: f32, activation: f32) {
        let learning_rate = self.hebbian_learning_rate * (1.0 + reward.abs()); // Reward modulates learning rate
        
        // Find all connections involving this trace
        let mut connections_to_update = Vec::new();
        
        for (i, conn) in self.hebbian_connections.iter().enumerate() {
            if conn.source_id == trace_id || conn.target_id == trace_id {
                connections_to_update.push(i);
            }
        }
        
        // Update bidirectional Hebbian connections
        for conn_idx in connections_to_update {
            let (source_id, target_id) = {
                let conn = &self.hebbian_connections[conn_idx];
                (conn.source_id.clone(), conn.target_id.clone())
            };
            
            // Get activation levels of both connected traces
            let source_activation = self.get_trace_activation(&source_id);
            let target_activation = self.get_trace_activation(&target_id);
            
            // Now update the connection
            let conn = &mut self.hebbian_connections[conn_idx];
            
            // Hebbian rule: Δw = η * activation_pre * activation_post * reward_modulation
            let hebbian_delta = learning_rate * source_activation * target_activation * reward.signum();
            
            // Bidirectional update: strengthen connection if both are active and reward is positive
            conn.weight += hebbian_delta;
            
            // Apply weight decay to prevent unbounded growth
            conn.weight *= 1.0 - self.decay_rate;
            
            // Clamp weights to reasonable bounds
            conn.weight = conn.weight.max(-2.0).min(2.0);
            
            conn.last_update = reward;
        }
        
        // Update the trace's own Hebbian weights based on its vector and reward
        if let Some(trace) = self.traces.iter_mut().find(|t| t.id == trace_id) {
            for i in 0..EMBED_DIM {
                // Self-reinforcement: strengthen weights for active dimensions
                let dimension_activity = trace.vec[i].abs();
                let hebbian_delta = learning_rate * dimension_activity * activation * reward.signum();
                trace.hebbian_weights[i] += hebbian_delta;
                
                // Apply decay
                trace.hebbian_weights[i] *= 1.0 - self.decay_rate;
                trace.hebbian_weights[i] = trace.hebbian_weights[i].max(-1.0).min(1.0);
            }
        }
    }
    
    fn get_trace_activation(&self, trace_id: &str) -> f32 {
        if let Some(trace) = self.traces.iter().find(|t| t.id == trace_id) {
            // Use recent average activation
            if trace.activation_history.is_empty() {
                trace.valence.abs()
            } else {
                trace.activation_history.iter().sum::<f32>() / trace.activation_history.len() as f32
            }
        } else {
            0.0
        }
    }
    
    fn create_hebbian_connections(&mut self, new_trace_id: &str, new_vec: &[f32; EMBED_DIM], _valence: f32) {
        
        // Create connections with existing traces that are sufficiently similar
        for existing_trace in &self.traces {
            let similarity = cosine_sim(&existing_trace.vec, new_vec);
            
            if similarity > self.activation_threshold {
                // Create bidirectional connections
                let forward_conn = HebbianConnection {
                    source_id: existing_trace.id.clone(),
                    target_id: new_trace_id.to_string(),
                    weight: similarity * self.hebbian_learning_rate,
                    last_update: 0.0,
                };
                
                let backward_conn = HebbianConnection {
                    source_id: new_trace_id.to_string(),
                    target_id: existing_trace.id.clone(),
                    weight: similarity * self.hebbian_learning_rate,
                    last_update: 0.0,
                };
                
                self.hebbian_connections.push(forward_conn);
                self.hebbian_connections.push(backward_conn);
            }
        }
    }

    pub fn promote_candidates(&self, threshold: f32) -> Vec<&MemoryTrace> {
        self.traces.iter().filter(|t| t.cum_reward.abs() >= threshold).collect()
    }

    pub fn max_similarity(&self, q: &[f32; EMBED_DIM]) -> f32 {
        self.traces.iter().map(|t| cosine_sim(&t.vec, q)).fold(0.0, |a,b| a.max(b))
    }

    pub fn add_mesh_trace(&mut self, vec: [f32; EMBED_DIM], valence: f32) -> String {
        let id = format!("mesh_{}", Uuid::new_v4().to_string()[..8].to_string());
        let trace = MemoryTrace { 
            id: id.clone(), 
            vec, 
            valence, 
            uses: 1, 
            cum_reward: valence,
            hebbian_weights: [0.0; EMBED_DIM], // Initialize Hebbian weights
            activation_history: vec![valence.abs()], // Initialize with current activation
        };
        
        // Create Hebbian connections for mesh traces too
        self.create_hebbian_connections(&id, &vec, valence);
        
        self.traces.push(trace);
        id
    }

    pub fn get_trace_count(&self) -> usize {
        self.traces.len()
    }

    pub fn get_average_valence(&self) -> f32 {
        if self.traces.is_empty() {
            0.0
        } else {
            self.traces.iter().map(|t| t.valence).sum::<f32>() / self.traces.len() as f32
        }
    }
    
    pub fn get_hebbian_stats(&self) -> (usize, f32, f32) {
        let connection_count = self.hebbian_connections.len();
        let avg_weight = if connection_count > 0 {
            self.hebbian_connections.iter().map(|c| c.weight).sum::<f32>() / connection_count as f32
        } else {
            0.0
        };
        
        let avg_self_weight = if !self.traces.is_empty() {
            let total_self_weight: f32 = self.traces.iter()
                .map(|t| t.hebbian_weights.iter().map(|w| w.abs()).sum::<f32>())
                .sum();
            total_self_weight / (self.traces.len() as f32 * EMBED_DIM as f32)
        } else {
            0.0
        };
        
        (connection_count, avg_weight, avg_self_weight)
    }
    
    pub fn get_strongest_connections(&self, limit: usize) -> Vec<&HebbianConnection> {
        let mut connections: Vec<&HebbianConnection> = self.hebbian_connections.iter().collect();
        connections.sort_by(|a, b| b.weight.abs().partial_cmp(&a.weight.abs()).unwrap());
        connections.into_iter().take(limit).collect()
    }
}

fn cosine_sim(a: &[f32; EMBED_DIM], b: &[f32; EMBED_DIM]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x,y)| x*y).sum();
    let an: f32 = a.iter().map(|x| x*x).sum::<f32>().sqrt();
    let bn: f32 = b.iter().map(|x| x*x).sum::<f32>().sqrt();
    if an==0.0 || bn==0.0 { return 0.0; }
    dot / (an*bn)
}
