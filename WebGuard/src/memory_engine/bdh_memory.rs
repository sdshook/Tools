
/// BDH (Bidirectional Hebbian) Memory System
/// Core component of RHLS (Reinforced Hebbian Learning System) that works with
/// PSI (Persistent Semantic Index) to enable experiential learning.
/// CMNN provides synaptic signal inputs with behavioral reward adjustments.

use serde::{Serialize, Deserialize};
use uuid::Uuid;
use crate::eq_iq_regulator::{ExperientialBehavioralRegulator, ContextEvent, FeedbackEvent};

/// Experiential context from memory retrieval with EQ/IQ regulation
#[derive(Debug, Clone)]
pub struct ExperientialContext {
    pub memory_id: String,
    pub similarity: f32,
    pub valence: f32,
    pub experience_type: String,
    pub relevance_score: f32,
    pub eq_iq_regulated: bool,
    pub fear_mitigation_applied: bool,
}

pub const EMBED_DIM: usize = 32;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MemoryTrace {
    pub id: String,
    pub vec: [f32; EMBED_DIM],
    pub valence: f32,
    pub uses: u32,
    pub cum_reward: f32,
    pub hebbian_weights: [f32; EMBED_DIM], // Bidirectional Hebbian connection weights
    pub activation_history: Vec<f32>,      // Recent activation levels for temporal Hebbian learning
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HebbianConnection {
    pub source_id: String,
    pub target_id: String,
    pub weight: f32,
    pub last_update: f32,
}

#[derive(Debug)]
pub struct BdhMemory {
    pub traces: Vec<MemoryTrace>,
    pub hebbian_connections: Vec<HebbianConnection>, // Explicit bidirectional connections
    pub hebbian_learning_rate: f32,
    pub decay_rate: f32,
    pub activation_threshold: f32,
    // Enhanced learning parameters
    pub max_memory_size: usize,
    pub memory_pressure_threshold: f32,
    pub learning_rate_decay: f32,
    pub adaptive_threshold: f32,
    pub connection_pruning_threshold: f32,
    pub temporal_window: usize,
    pub meta_learning_rate: f32,
    pub performance_history: Vec<f32>,
    // EQ/IQ Balanced Reward System
    pub eq_iq_regulator: ExperientialBehavioralRegulator,
}

impl BdhMemory {
    pub fn new() -> Self { 
        Self { 
            traces: Vec::new(),
            hebbian_connections: Vec::new(),
            hebbian_learning_rate: 0.05,  // Increased from 0.01 for faster learning
            decay_rate: 0.002,            // Slightly increased decay to prevent saturation
            activation_threshold: 0.3,    // Lowered from 0.5 for more connections
            // Enhanced learning parameters
            max_memory_size: 1000,        // Dynamic memory limit
            memory_pressure_threshold: 0.8, // Start pruning at 80% capacity
            learning_rate_decay: 0.995,   // Gradual learning rate decay
            adaptive_threshold: 0.3,      // Adaptive activation threshold
            connection_pruning_threshold: 0.01, // Prune weak connections
            temporal_window: 50,          // Window for temporal pattern analysis
            meta_learning_rate: 0.001,    // Rate for meta-parameter adaptation
            performance_history: Vec::new(),
            // Initialize EQ/IQ regulator with balanced parameters (α=0.6, β=0.4)
            eq_iq_regulator: ExperientialBehavioralRegulator::new(0.6, 0.4, 0.01),
        } 
    }

    pub fn add_trace(&mut self, vec: [f32; EMBED_DIM], valence: f32) -> String {
        // Check memory pressure and perform PSI-guided pruning if needed
        self.manage_memory_pressure();
        
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
        
        // Adaptive threshold adjustment based on memory growth
        self.adapt_learning_parameters();
        
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

    /// EQ/IQ Balanced Reinforced Hebbian Learning: Updates both valence and Hebbian weights based on balanced reward
    pub fn reward_update(&mut self, id: &str, reward: f32, eta: f32) {
        self.reward_update_with_context(id, reward, eta, 0.5, 0.2, 0.8, 0.9);
    }

    /// Enhanced reward update with EQ/IQ context
    pub fn reward_update_with_context(
        &mut self, 
        id: &str, 
        reward: f32, 
        eta: f32,
        context_stability: f32,
        threat_level: f32,
        predicted_threat: f32,
        actual_threat: f32,
    ) {
        if let Some(trace_idx) = self.traces.iter().position(|x| x.id == id) {
            let activation = reward.abs();
            let trace_id = self.traces[trace_idx].id.clone();
            
            // Create context and feedback events for EQ/IQ calculation
            let context = ContextEvent {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64(),
                context_stability,
                threat_level,
                response_appropriateness: if reward > 0.0 { 0.8 } else { 0.3 },
            };

            let feedback = FeedbackEvent {
                timestamp: context.timestamp,
                predicted_threat,
                actual_threat,
                accuracy: 1.0 - (predicted_threat - actual_threat).abs(),
            };

            // Calculate EQ/IQ balanced reward
            let eq_iq_balance = self.eq_iq_regulator.calculate_eq_iq_balance(&context, &feedback);
            let balanced_reward = reward * eq_iq_balance.balance;
            
            // FIXED: Traditional reward update with EQ/IQ balance and valence stabilization
            {
                let trace = &mut self.traces[trace_idx];
                trace.cum_reward += balanced_reward;
                
                // FIXED: More conservative valence update to prevent extreme swings
                let valence_learning_rate = eta * 0.5; // Reduce valence learning rate
                let valence_delta = valence_learning_rate * (balanced_reward - trace.valence);
                trace.valence = (trace.valence + valence_delta).max(-1.0).min(1.0); // Clamp valence
                trace.uses += 1;
                
                // Update activation history for temporal Hebbian learning
                trace.activation_history.push(activation);
                if trace.activation_history.len() > 10 {
                    trace.activation_history.remove(0); // Keep only recent history
                }
            }
            
            // EQ/IQ Balanced Hebbian Learning: Modulate Hebbian weight updates by balanced reward
            self.hebbian_update_with_eq_iq_reinforcement(&trace_id, balanced_reward, activation, &eq_iq_balance);
        }
    }
    
    /// EQ/IQ Balanced Bidirectional Hebbian Learning: "Neurons that fire together, wire together" with emotional and intellectual balance
    fn hebbian_update_with_eq_iq_reinforcement(&mut self, trace_id: &str, reward: f32, activation: f32, eq_iq_balance: &crate::eq_iq_regulator::EQIQBalance) {
        // FIXED: Reduce learning rate to prevent over-learning and add reward sign consideration
        let base_learning_rate = self.hebbian_learning_rate * 0.3; // Reduce by 70% to prevent over-learning
        let reward_modulation = if reward > 0.0 { 1.0 + reward * 0.5 } else { 1.0 - reward.abs() * 0.3 };
        let learning_rate = base_learning_rate * reward_modulation * eq_iq_balance.balance;
        
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
            
            // EQ/IQ Balanced Hebbian rule: Δw = η * (xi * yj) * (α * EQ + β * IQ) * reward_sign
            let hebbian_delta = self.eq_iq_regulator.bidirectional_hebbian_update(
                source_activation, 
                target_activation, 
                eq_iq_balance.eq, 
                eq_iq_balance.iq
            );
            
            // FIXED: Apply reward sign to Hebbian learning - positive rewards strengthen, negative weaken
            let signed_delta = hebbian_delta * reward.signum() * learning_rate;
            conn.weight += signed_delta;
            
            // Apply weight decay to prevent unbounded growth
            conn.weight *= 1.0 - self.decay_rate;
            
            // FIXED: Tighter weight bounds to prevent extreme values
            conn.weight = conn.weight.max(-1.0).min(1.0);
            
            conn.last_update = reward;
        }
        
        // Update the trace's own Hebbian weights based on its vector and reward
        if let Some(trace) = self.traces.iter_mut().find(|t| t.id == trace_id) {
            for i in 0..EMBED_DIM {
                // FIXED: EQ/IQ Balanced Self-reinforcement with reward sign consideration
                let dimension_activity = trace.vec[i].abs();
                let hebbian_delta = self.eq_iq_regulator.bidirectional_hebbian_update(
                    dimension_activity, 
                    activation, 
                    eq_iq_balance.eq, 
                    eq_iq_balance.iq
                );
                
                // FIXED: Apply reward sign and reduced learning rate to self-weights
                let signed_delta = hebbian_delta * reward.signum() * learning_rate;
                trace.hebbian_weights[i] += signed_delta;
                
                // Apply decay
                trace.hebbian_weights[i] *= 1.0 - self.decay_rate;
                // FIXED: Consistent bounds with connection weights
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
    
    fn create_hebbian_connections_legacy(&mut self, new_trace_id: &str, new_vec: &[f32; EMBED_DIM], _valence: f32) {
        
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
    
    /// Differential similarity using reinforcement learning principles:
    /// Returns threat_similarity - benign_similarity, creating a contrastive signal
    /// that rewards similarity to threats and suppresses similarity to benign patterns.
    pub fn differential_threat_similarity(&self, q: &[f32; EMBED_DIM]) -> f32 {
        // Calculate maximum similarity to threat patterns (valence > 0.5)
        let threat_sim = self.traces.iter()
            .filter(|t| t.valence > 0.5)
            .map(|t| cosine_sim(&t.vec, q))
            .fold(0.0f32, |a, b| a.max(b));
        
        // Calculate maximum similarity to benign patterns (valence <= 0.5)
        let benign_sim = self.traces.iter()
            .filter(|t| t.valence <= 0.5)
            .map(|t| cosine_sim(&t.vec, q))
            .fold(0.0f32, |a, b| a.max(b));
        
        // Differential: threat similarity minus benign similarity
        // The 0.8 factor controls how strongly benign patterns suppress threat scores
        // Higher factor = benign patterns have more suppressive effect
        let differential = threat_sim - (benign_sim * 0.8);
        
        // Clamp to [0, 1] range - negative means more benign than threat
        differential.max(0.0).min(1.0)
    }
    
    /// Weighted threat similarity incorporating cumulative reward history
    /// Patterns that have been repeatedly validated get stronger influence
    pub fn reward_weighted_threat_similarity(&self, q: &[f32; EMBED_DIM]) -> f32 {
        if self.traces.is_empty() {
            return 0.0;
        }
        
        let mut weighted_threat_sum = 0.0f32;
        let mut weighted_benign_sum = 0.0f32;
        let mut threat_weight_total = 0.0f32;
        let mut benign_weight_total = 0.0f32;
        
        for trace in &self.traces {
            let sim = cosine_sim(&trace.vec, q);
            // Use cumulative reward as confidence weight (more uses = more reliable)
            let confidence = (trace.uses as f32).sqrt().min(10.0) / 10.0;
            
            if trace.valence > 0.5 {
                // Threat pattern
                weighted_threat_sum += sim * confidence;
                threat_weight_total += confidence;
            } else {
                // Benign pattern
                weighted_benign_sum += sim * confidence;
                benign_weight_total += confidence;
            }
        }
        
        let avg_threat_sim = if threat_weight_total > 0.0 {
            weighted_threat_sum / threat_weight_total
        } else {
            0.0
        };
        
        let avg_benign_sim = if benign_weight_total > 0.0 {
            weighted_benign_sum / benign_weight_total
        } else {
            0.0
        };
        
        // Differential with reward weighting
        (avg_threat_sim - avg_benign_sim * 0.8).max(0.0).min(1.0)
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



    pub fn get_learning_event_count(&self) -> u64 {
        // Approximate learning events from trace usage
        self.traces.iter().map(|t| t.uses as u64).sum()
    }

    pub fn get_accuracy_score(&self) -> f32 {
        // Calculate accuracy based on valence consistency
        if self.traces.is_empty() {
            return 0.5;
        }
        
        let positive_valence_count = self.traces.iter().filter(|t| t.valence > 0.0).count();
        let total_traces = self.traces.len();
        
        // Simple accuracy approximation based on valence distribution
        let balance = (positive_valence_count as f32) / (total_traces as f32);
        1.0 - (balance - 0.5).abs() * 2.0 // Higher score for balanced valence
    }

    /// Export synaptic connections for knowledge sharing
    pub fn export_synaptic_connections(&self, min_weight_threshold: f32) -> Vec<crate::mesh_cognition::HebbianConnectionExport> {
        let mut exports = Vec::new();
        
        for connection in &self.hebbian_connections {
            if connection.weight.abs() > min_weight_threshold {
                // Find source and target traces
                if let (Some(source_trace), Some(target_trace)) = (
                    self.traces.iter().find(|t| t.id == connection.source_id),
                    self.traces.iter().find(|t| t.id == connection.target_id)
                ) {
                    exports.push(crate::mesh_cognition::HebbianConnectionExport {
                        source_pattern: source_trace.vec,
                        target_pattern: target_trace.vec,
                        synaptic_weight: connection.weight,
                        activation_frequency: source_trace.uses + target_trace.uses,
                        valence_association: (source_trace.valence + target_trace.valence) / 2.0,
                    });
                }
            }
        }
        
        exports
    }

    /// Import synaptic connection from another WebGuard instance
    pub fn import_synaptic_connection(
        &mut self, 
        source_pattern: &[f32; EMBED_DIM], 
        target_pattern: &[f32; EMBED_DIM], 
        synaptic_weight: f32,
        valence_association: f32
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create or find traces for the patterns
        let source_id = self.find_or_create_trace(source_pattern, valence_association * 0.5)?;
        let target_id = self.find_or_create_trace(target_pattern, valence_association * 0.5)?;
        
        // Create the Hebbian connection
        let connection = HebbianConnection {
            source_id: source_id.clone(),
            target_id: target_id.clone(),
            weight: synaptic_weight * 0.7, // Reduce imported weight to prevent overwhelming local learning
            last_update: valence_association,
        };
        
        self.hebbian_connections.push(connection);
        Ok(())
    }

    /// Helper method to find existing trace or create new one
    fn find_or_create_trace(&mut self, pattern: &[f32; EMBED_DIM], valence: f32) -> Result<String, Box<dyn std::error::Error>> {
        // Check if similar trace already exists
        let similar_traces = self.retrieve_similar(pattern, 1);
        if let Some((existing_trace, similarity)) = similar_traces.first() {
            if *similarity > 0.8 {
                return Ok(existing_trace.id.clone());
            }
        }
        
        // Create new trace
        let trace_id = self.add_trace(*pattern, valence);
        Ok(trace_id)
    }
    
    pub fn get_strongest_connections(&self, limit: usize) -> Vec<&HebbianConnection> {
        let mut connections: Vec<&HebbianConnection> = self.hebbian_connections.iter().collect();
        connections.sort_by(|a, b| b.weight.abs().partial_cmp(&a.weight.abs()).unwrap());
        connections.into_iter().take(limit).collect()
    }
    
    /// PSI-guided memory management to prevent exhaustion
    fn manage_memory_pressure(&mut self) {
        let memory_usage = self.traces.len() as f32 / self.max_memory_size as f32;
        
        if memory_usage > self.memory_pressure_threshold {
            // Calculate memory pressure level
            let pressure_level = (memory_usage - self.memory_pressure_threshold) / 
                                (1.0 - self.memory_pressure_threshold);
            
            // Prune least useful traces based on multiple criteria
            self.prune_memory_traces(pressure_level);
            
            // Prune weak Hebbian connections
            self.prune_weak_connections();
            
            // Adjust learning parameters to be more selective
            self.adaptive_threshold *= 1.0 + (pressure_level * 0.1);
            self.hebbian_learning_rate *= 0.95; // Reduce learning rate under pressure
        }
    }
    
    /// Intelligent memory pruning using PSI principles
    fn prune_memory_traces(&mut self, pressure_level: f32) {
        let target_removal_count = ((self.traces.len() as f32) * pressure_level * 0.2) as usize;
        
        if target_removal_count == 0 {
            return;
        }
        
        // Score traces for removal (lower score = more likely to be removed)
        let mut trace_scores: Vec<(usize, f32)> = self.traces.iter().enumerate()
            .map(|(idx, trace)| {
                let utility_score = self.calculate_trace_utility(trace);
                (idx, utility_score)
            })
            .collect();
        
        // Sort by utility score (ascending - worst first)
        trace_scores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        
        // Remove the least useful traces
        let mut indices_to_remove: Vec<usize> = trace_scores.iter()
            .take(target_removal_count)
            .map(|(idx, _)| *idx)
            .collect();
        
        // Sort indices in descending order to remove from back to front
        indices_to_remove.sort_by(|a, b| b.cmp(a));
        
        for idx in indices_to_remove {
            let removed_trace = self.traces.remove(idx);
            // Also remove associated Hebbian connections
            self.remove_connections_for_trace(&removed_trace.id);
        }
    }
    
    /// Calculate utility score for a memory trace (higher = more useful)
    fn calculate_trace_utility(&self, trace: &MemoryTrace) -> f32 {
        let recency_factor = 1.0; // Could be enhanced with timestamp
        let usage_factor = (trace.uses as f32).ln_1p(); // Logarithmic usage scaling
        let reward_factor = trace.cum_reward.abs();
        let connection_factor = self.count_connections_for_trace(&trace.id) as f32;
        let activation_factor = if trace.activation_history.is_empty() {
            0.0
        } else {
            trace.activation_history.iter().sum::<f32>() / trace.activation_history.len() as f32
        };
        
        // Weighted combination of factors
        recency_factor * 0.2 + 
        usage_factor * 0.3 + 
        reward_factor * 0.2 + 
        connection_factor * 0.2 + 
        activation_factor * 0.1
    }
    
    /// Count Hebbian connections for a specific trace
    fn count_connections_for_trace(&self, trace_id: &str) -> usize {
        self.hebbian_connections.iter()
            .filter(|conn| conn.source_id == trace_id || conn.target_id == trace_id)
            .count()
    }
    
    /// Remove all Hebbian connections associated with a trace
    fn remove_connections_for_trace(&mut self, trace_id: &str) {
        self.hebbian_connections.retain(|conn| 
            conn.source_id != trace_id && conn.target_id != trace_id
        );
    }
    
    /// Prune weak Hebbian connections
    fn prune_weak_connections(&mut self) {
        let initial_count = self.hebbian_connections.len();
        
        self.hebbian_connections.retain(|conn| 
            conn.weight.abs() > self.connection_pruning_threshold
        );
        
        let pruned_count = initial_count - self.hebbian_connections.len();
        
        // Adjust pruning threshold based on pruning effectiveness
        if pruned_count == 0 {
            self.connection_pruning_threshold *= 0.9; // Lower threshold if no pruning occurred
        } else if pruned_count > initial_count / 4 {
            self.connection_pruning_threshold *= 1.1; // Raise threshold if too much pruning
        }
    }
    
    /// Adaptive learning parameter adjustment
    fn adapt_learning_parameters(&mut self) {
        // Decay learning rate over time to stabilize learning
        self.hebbian_learning_rate *= self.learning_rate_decay;
        
        // Adapt activation threshold based on connection density
        let connection_density = self.hebbian_connections.len() as f32 / 
                                (self.traces.len() as f32).max(1.0);
        
        if connection_density > 2.0 {
            // Too many connections, raise threshold
            self.adaptive_threshold *= 1.01;
        } else if connection_density < 0.5 {
            // Too few connections, lower threshold
            self.adaptive_threshold *= 0.99;
        }
        
        // Clamp threshold to reasonable bounds
        self.adaptive_threshold = self.adaptive_threshold.max(0.1).min(0.8);
        self.activation_threshold = self.adaptive_threshold;
    }
    
    /// Meta-learning: adjust parameters based on performance feedback
    pub fn meta_learning_update(&mut self, performance_score: f32) {
        self.performance_history.push(performance_score);
        
        // Keep only recent performance history
        if self.performance_history.len() > self.temporal_window {
            self.performance_history.remove(0);
        }
        
        if self.performance_history.len() >= 10 {
            let recent_avg = self.performance_history.iter()
                .rev().take(5).sum::<f32>() / 5.0;
            let older_avg = self.performance_history.iter()
                .rev().skip(5).take(5).sum::<f32>() / 5.0;
            
            let performance_trend = recent_avg - older_avg;
            
            // Adjust learning parameters based on performance trend
            if performance_trend > 0.01 {
                // Performance improving, maintain current settings
                self.hebbian_learning_rate *= 1.001;
            } else if performance_trend < -0.01 {
                // Performance declining, adjust parameters
                self.hebbian_learning_rate *= 0.999;
                self.adaptive_threshold *= 0.99;
            }
            
            // Clamp parameters to reasonable bounds
            self.hebbian_learning_rate = self.hebbian_learning_rate.max(0.001).min(0.1);
        }
    }
    
    /// Enhanced connection creation with temporal awareness
    fn create_hebbian_connections(&mut self, new_trace_id: &str, new_vec: &[f32; EMBED_DIM], valence: f32) {
        let mut connections_created = 0;
        let max_new_connections = 10; // Limit connections per new trace
        
        // Create connections with existing traces that are sufficiently similar
        for existing_trace in &self.traces {
            if connections_created >= max_new_connections {
                break;
            }
            
            let similarity = cosine_sim(&existing_trace.vec, new_vec);
            
            // Enhanced connection criteria
            let valence_compatibility = if valence * existing_trace.valence > 0.0 {
                1.0 // Same sign valences are more compatible
            } else {
                0.7 // Different sign valences are less compatible
            };
            
            let connection_threshold = self.activation_threshold * valence_compatibility;
            
            if similarity > connection_threshold {
                // Create bidirectional connections with adaptive weights
                let base_weight = similarity * self.hebbian_learning_rate;
                let valence_modulated_weight = base_weight * (1.0 + valence.abs() * 0.1);
                
                let forward_conn = HebbianConnection {
                    source_id: existing_trace.id.clone(),
                    target_id: new_trace_id.to_string(),
                    weight: valence_modulated_weight,
                    last_update: 0.0,
                };
                
                let backward_conn = HebbianConnection {
                    source_id: new_trace_id.to_string(),
                    target_id: existing_trace.id.clone(),
                    weight: valence_modulated_weight,
                    last_update: 0.0,
                };
                
                self.hebbian_connections.push(forward_conn);
                self.hebbian_connections.push(backward_conn);
                connections_created += 1;
            }
        }
    }
    
    /// Get comprehensive memory statistics for monitoring
    pub fn get_memory_stats(&self) -> MemoryStats {
        let (connection_count, avg_weight, avg_self_weight) = self.get_hebbian_stats();
        let memory_usage = self.traces.len() as f32 / self.max_memory_size as f32;
        
        MemoryStats {
            trace_count: self.traces.len(),
            connection_count,
            memory_usage,
            avg_connection_weight: avg_weight,
            avg_self_weight,
            learning_rate: self.hebbian_learning_rate,
            activation_threshold: self.activation_threshold,
            performance_trend: self.calculate_performance_trend(),
        }
    }
    
    fn calculate_performance_trend(&self) -> f32 {
        if self.performance_history.len() < 6 {
            return 0.0;
        }
        
        let recent = self.performance_history.iter().rev().take(3).sum::<f32>() / 3.0;
        let older = self.performance_history.iter().rev().skip(3).take(3).sum::<f32>() / 3.0;
        recent - older
    }

    /// Get EQ/IQ regulator statistics
    pub fn get_eq_iq_stats(&self) -> std::collections::HashMap<String, f32> {
        self.eq_iq_regulator.get_stats()
    }

    /// Adapt EQ/IQ parameters based on system performance
    pub fn adapt_eq_iq_parameters(&mut self, performance_feedback: f32) {
        self.eq_iq_regulator.adapt_parameters(performance_feedback);
    }

    /// Get connection count for statistics
    pub fn get_connection_count(&self) -> usize {
        self.hebbian_connections.len()
    }

    /// Calculate similarity to existing traces
    pub fn calculate_similarity(&self, embedding: &[f32; EMBED_DIM]) -> Result<f32, Box<dyn std::error::Error>> {
        if self.traces.is_empty() {
            return Ok(0.0);
        }

        let mut max_similarity: f32 = 0.0;
        for trace in &self.traces {
            let similarity = cosine_sim(embedding, &trace.vec);
            max_similarity = max_similarity.max(similarity);
        }

        Ok(max_similarity)
    }

    /// Store a new memory trace
    pub fn store_trace(&mut self, embedding: [f32; EMBED_DIM], similarity: f32, valence: f32) -> Result<(), Box<dyn std::error::Error>> {
        // Create new trace
        let trace = MemoryTrace {
            id: format!("trace_{}", self.traces.len()),
            vec: embedding,
            valence,
            uses: 1,
            cum_reward: similarity,
            hebbian_weights: [0.0; EMBED_DIM],
            activation_history: vec![similarity],
        };

        self.traces.push(trace);

        // Manage memory pressure if needed
        self.manage_memory_pressure();

        Ok(())
    }

    /// Retrieve experiential context for anomaly analysis with EQ/IQ regulation
    pub fn retrieve_experiential_context(
        &self, 
        anomaly_embedding: &[f32; EMBED_DIM], 
        context_limit: usize,
        eq_iq_balance: &crate::eq_iq_regulator::EQIQBalance
    ) -> Vec<ExperientialContext> {
        let mut contexts = Vec::new();
        
        // Get similar traces
        let similar_traces = self.retrieve_similar(anomaly_embedding, context_limit * 2);
        
        for (trace, similarity) in similar_traces.iter().take(context_limit) {
            // EQ/IQ regulated relevance calculation
            let analytical_relevance = similarity * (1.0 + trace.cum_reward.abs() * 0.1);
            let emotional_relevance = if trace.valence < 0.0 {
                // Negative experiences need EQ regulation to prevent fear-based paralysis
                trace.valence.abs() * eq_iq_balance.eq * 0.5  // Reduced impact of negative experiences
            } else {
                trace.valence * eq_iq_balance.eq
            };
            
            // Balanced relevance score prevents experiential paralysis
            let regulated_relevance = analytical_relevance * eq_iq_balance.iq + 
                                    emotional_relevance * eq_iq_balance.eq;
            
            // Ensure negative experiences don't prevent necessary actions
            let action_confidence = if trace.valence < 0.0 {
                // For negative experiences, boost confidence if analytical assessment is strong
                regulated_relevance * (1.0 + eq_iq_balance.iq * 0.3)
            } else {
                regulated_relevance
            };
            
            contexts.push(ExperientialContext {
                memory_id: trace.id.clone(),
                similarity: *similarity,
                valence: trace.valence,
                experience_type: "BDH_Regulated".to_string(),
                relevance_score: action_confidence,
                eq_iq_regulated: true,
                fear_mitigation_applied: trace.valence < 0.0,
            });
        }
        
        // Sort by regulated relevance to prioritize actionable experiences
        contexts.sort_by(|a, b| b.relevance_score.partial_cmp(&a.relevance_score).unwrap());
        contexts
    }

    /// Add experiential anomaly trace with EQ/IQ regulation
    pub fn add_experiential_anomaly_trace(
        &mut self, 
        embedding: [f32; EMBED_DIM], 
        anomaly_score: f32,
        is_threat: bool,
        context_stability: f32,
        threat_level: f32
    ) -> String {
        // Create context event for EQ/IQ regulation
        let context = crate::eq_iq_regulator::ContextEvent {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
            context_stability,
            threat_level,
            response_appropriateness: if is_threat { 0.8 } else { 0.6 },
        };

        // Create feedback event
        let feedback = crate::eq_iq_regulator::FeedbackEvent {
            timestamp: context.timestamp,
            predicted_threat: anomaly_score,
            actual_threat: if is_threat { 1.0 } else { 0.0 },
            accuracy: 1.0 - (anomaly_score - if is_threat { 1.0 } else { 0.0 }).abs(),
        };

        // Calculate EQ/IQ balanced valence
        let eq_iq_balance = self.eq_iq_regulator.calculate_eq_iq_balance(&context, &feedback);
        
        // Regulate valence to prevent fear-based paralysis
        let base_valence = if is_threat { -anomaly_score } else { anomaly_score * 0.5 };
        let regulated_valence = base_valence * eq_iq_balance.balance;
        
        // Ensure negative experiences don't prevent future threat detection
        let final_valence = if regulated_valence < 0.0 {
            // Apply fear mitigation - negative experiences shouldn't paralyze the system
            regulated_valence * (0.7 + eq_iq_balance.iq * 0.3)  // IQ component reduces fear impact
        } else {
            regulated_valence
        };

        // Add the regulated trace
        self.add_trace(embedding, final_valence)
    }

    /// Update experiential trace with outcome feedback and EQ/IQ regulation
    pub fn update_experiential_outcome(
        &mut self,
        trace_id: &str,
        actual_outcome: f32,
        predicted_outcome: f32,
        action_taken: bool,
        was_correct: bool
    ) {
        if let Some(trace) = self.traces.iter_mut().find(|t| t.id == trace_id) {
            // Calculate outcome-based reward
            let accuracy_reward = 1.0 - (actual_outcome - predicted_outcome).abs();
            let action_reward = if action_taken && was_correct { 0.5 } else if !action_taken && !was_correct { 0.3 } else { -0.2 };
            
            // EQ/IQ regulated reward prevents fear-based learning
            let context = crate::eq_iq_regulator::ContextEvent {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64(),
                context_stability: 0.7,
                threat_level: actual_outcome,
                response_appropriateness: if was_correct { 0.9 } else { 0.4 },
            };

            let feedback = crate::eq_iq_regulator::FeedbackEvent {
                timestamp: context.timestamp,
                predicted_threat: predicted_outcome,
                actual_threat: actual_outcome,
                accuracy: accuracy_reward,
            };

            let eq_iq_balance = self.eq_iq_regulator.calculate_eq_iq_balance(&context, &feedback);
            
            // Regulated reward update
            let total_reward = (accuracy_reward + action_reward) * eq_iq_balance.balance;
            
            // Apply fear mitigation for negative outcomes
            let final_reward = if total_reward < 0.0 && !action_taken {
                // If we didn't act and it was wrong, don't create excessive fear
                total_reward * (0.6 + eq_iq_balance.iq * 0.4)  // IQ reduces fear impact
            } else {
                total_reward
            };
            
            // Update with EQ/IQ context
            self.reward_update_with_context(
                trace_id,
                final_reward,
                0.1,
                context.context_stability,
                context.threat_level,
                predicted_outcome,
                actual_outcome
            );
        }
    }
}

#[derive(Debug)]
pub struct MemoryStats {
    pub trace_count: usize,
    pub connection_count: usize,
    pub memory_usage: f32,
    pub avg_connection_weight: f32,
    pub avg_self_weight: f32,
    pub learning_rate: f32,
    pub activation_threshold: f32,
    pub performance_trend: f32,
}

fn cosine_sim(a: &[f32; EMBED_DIM], b: &[f32; EMBED_DIM]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x,y)| x*y).sum();
    let an: f32 = a.iter().map(|x| x*x).sum::<f32>().sqrt();
    let bn: f32 = b.iter().map(|x| x*x).sum::<f32>().sqrt();
    if an==0.0 || bn==0.0 { return 0.0; }
    dot / (an*bn)
}
