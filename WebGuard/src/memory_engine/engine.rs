/// RHLS (Reinforced Hebbian Learning System) Memory Engine
/// 
/// Integrates BDH (Bidirectional Hebbian) memory with PSI (Persistent Semantic Index)
/// to enable experiential learning beyond context window constraints.
/// 
/// Components:
/// - BDH: Core bidirectional Hebbian learning with synaptic plasticity
/// - PSI: Persistent semantic index for long-term memory caching
/// - CMNN: Provides synaptic signal inputs with behavioral reward adjustments

use crate::memory_engine::{bdh_memory::*, psi_index::*};
use crate::config::Config;
use anyhow::Result;

/// RHLS Memory Engine - Integrates BDH memory with PSI management
pub struct MemoryEngine {
    pub bdh_memory: BdhMemory,
    pub psi_index: PsiIndex,
    config: Config,
    event_counter: usize,
}

impl MemoryEngine {
    pub fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            bdh_memory: BdhMemory::new(),
            psi_index: PsiIndex::new(),
            config: config.clone(),
            event_counter: 0,
        })
    }
    
    /// Process features through the enhanced memory system
    pub fn process_features(&mut self, features: &[f32]) -> Result<(f32, f32, Option<String>)> {
        self.event_counter += 1;
        
        // Convert features to fixed-size array
        let mut feature_array = [0.0f32; 32]; // EMBED_DIM
        for (i, &val) in features.iter().enumerate() {
            if i < 32 {
                feature_array[i] = val;
            }
        }
        
        // Retrieve similar patterns from BDH memory
        let similar_traces = self.bdh_memory.retrieve_similar(&feature_array, 3);
        
        let similarity_threshold = 0.3; // Minimum similarity to reuse existing trace
        
        let (similarity, valence, trace_id) = if similar_traces.is_empty() {
            // No existing patterns - create new trace
            let initial_valence = 0.0; // Neutral until we get feedback
            let trace_id = self.bdh_memory.add_trace(feature_array, initial_valence);
            (0.0, 0.0, Some(trace_id))
        } else {
            let (best_trace, similarity) = &similar_traces[0];
            if *similarity > similarity_threshold {
                // Use existing similar trace
                (similarity.clone(), best_trace.valence, Some(best_trace.id.clone()))
            } else {
                // Similarity too low - create new trace
                let initial_valence = 0.0;
                let trace_id = self.bdh_memory.add_trace(feature_array, initial_valence);
                (0.0, 0.0, Some(trace_id))
            }
        };
        
        // Add to PSI index for potential promotion
        if self.event_counter % 10 == 0 {
            self.promote_psi_entries();
        }
        
        // Add new patterns to PSI for learning
        if similarity < 0.5 { // Novel or semi-novel patterns
            let tags = vec!["temporal".to_string(), "behavioral".to_string()];
            self.add_psi_entry(feature_array, valence, tags);
        }
        
        Ok((similarity, valence, trace_id))
    }
    
    /// Update memory with reward feedback
    pub fn reward_update(&mut self, trace_id: &str, reward: f32, learning_rate: f32) -> Result<()> {
        self.bdh_memory.reward_update(trace_id, reward, learning_rate);
        Ok(())
    }
    
    /// Meta-learning update for adaptive parameters
    pub fn meta_learning_update(&mut self, performance_score: f32) {
        self.bdh_memory.meta_learning_update(performance_score);
    }
    
    /// Get comprehensive memory statistics
    pub fn get_memory_stats(&self) -> MemoryStats {
        self.bdh_memory.get_memory_stats()
    }
    
    /// Get PSI statistics
    pub fn get_psi_stats(&self) -> PsiStats {
        self.psi_index.get_stats()
    }
    
    /// Promote high-quality PSI entries to BDH memory
    fn promote_psi_entries(&mut self) {
        let promotable_entries = self.psi_index.promote_to_bdh(0.5);
        
        for entry in promotable_entries {
            // Convert PSI entry to BDH trace
            self.bdh_memory.add_trace(entry.vec, entry.valence);
        }
    }
    
    /// Add entry to PSI index
    pub fn add_psi_entry(&mut self, features: [f32; 32], valence: f32, tags: Vec<String>) {
        let entry = PsiEntry {
            id: uuid::Uuid::new_v4().to_string(),
            vec: features,
            valence,
            uses: 1,
            tags,
        };
        
        self.psi_index.add(entry);
    }
    
    /// Get trace count for monitoring
    pub fn get_trace_count(&self) -> usize {
        self.bdh_memory.get_trace_count()
    }
    
    /// Get connection count for monitoring
    pub fn get_connection_count(&self) -> usize {
        let (count, _, _) = self.bdh_memory.get_hebbian_stats();
        count
    }
    
    /// Get average valence for monitoring
    pub fn get_average_valence(&self) -> f32 {
        self.bdh_memory.get_average_valence()
    }
}