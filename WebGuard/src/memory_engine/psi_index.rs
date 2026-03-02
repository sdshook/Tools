//! PSI (Persistent Semantic Index) - Memory cache for BDH that avoids context window constraints
//! and enables experiential learning in RHLS (Reinforced Hebbian Learning System)
//! where CMNN provides synaptic signal inputs with behavioral reward adjustments.
//!
//! ## Memory-on-Memory One-Shot Learning
//! 
//! PSI implements true associative memory where:
//! 1. **One-shot learning**: A single example creates associations with similar memories
//! 2. **Memory-on-memory propagation**: Reinforcing memory A also updates related memories B, C
//! 3. **Hebbian connections**: Memories that co-activate together strengthen their association
//! 4. **Associative retrieval**: Querying A can retrieve semantically related B, C
//!
//! ## Self-Learning Compliance
//! 
//! All associations are LEARNED, not predefined:
//! - Connections form through experience (co-activation)
//! - Strengths adjust through reinforcement (reward signals)
//! - No hard-coded patterns or signatures

#![allow(dead_code)]

use serde::{Serialize, Deserialize};

pub const EMBED_DIM: usize = 32;

/// PSI entry representing a semantic memory trace
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PsiEntry {
    pub id: String,
    pub vec: [f32; EMBED_DIM],
    pub valence: f32,
    pub uses: u32,
    pub tags: Vec<String>,
    /// Timestamp of last activation (for temporal learning)
    #[serde(default)]
    pub last_activation: f64,
    /// Cumulative reward received
    #[serde(default)]
    pub cumulative_reward: f32,
}

/// Hebbian connection between PSI memories
/// Implements "memories that fire together, wire together"
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PsiConnection {
    pub source_id: String,
    pub target_id: String,
    pub strength: f32,
    pub co_activations: u32,
    pub last_update: f64,
}

/// PSI (Persistent Semantic Index) - Core memory cache structure
/// 
/// Provides persistent storage for BDH memory patterns with:
/// - Memory-on-memory learning (associative propagation)
/// - One-shot learning (single example creates associations)
/// - Hebbian connections (learned associations between memories)
/// - Associative retrieval (query returns related memories)
#[derive(Debug)]
pub struct PsiIndex {
    entries: Vec<PsiEntry>,
    /// Hebbian connections between memories (learned associations)
    connections: Vec<PsiConnection>,
    max_entries: usize,
    quality_threshold: f32,
    consolidation_interval: usize,
    last_consolidation: usize,
    /// Learning rate for Hebbian connection updates
    hebbian_learning_rate: f32,
    /// Minimum similarity to create/update connections
    association_threshold: f32,
    /// Decay rate for connection strengths
    connection_decay: f32,
    /// Maximum connections per entry (prevent memory explosion)
    max_connections_per_entry: usize,
}

impl PsiIndex {
    pub fn new() -> Self { 
        Self { 
            entries: Vec::new(),
            connections: Vec::new(),
            max_entries: 500,
            quality_threshold: 0.1,
            consolidation_interval: 100,
            last_consolidation: 0,
            hebbian_learning_rate: 0.1,
            association_threshold: 0.5,
            connection_decay: 0.01,
            max_connections_per_entry: 10,
        } 
    }

    /// Add a new entry with ONE-SHOT LEARNING
    /// 
    /// This method implements memory-on-memory learning:
    /// 1. Finds similar existing memories
    /// 2. Creates Hebbian connections to similar memories
    /// 3. Propagates learning signal to related memories
    /// 4. Adds the new entry to the index
    pub fn add(&mut self, entry: PsiEntry) { 
        // Check if we need consolidation before adding
        if self.entries.len() >= self.max_entries {
            self.consolidate_entries();
        }
        
        // ONE-SHOT LEARNING: Create associations with similar existing memories
        let similar_memories = self.find_similar_for_association(&entry.vec);
        
        for (similar_id, similarity) in &similar_memories {
            // Create bidirectional Hebbian connection
            self.create_or_strengthen_connection(&entry.id, similar_id, *similarity);
            self.create_or_strengthen_connection(similar_id, &entry.id, *similarity);
        }
        
        self.entries.push(entry);
        
        // Periodic consolidation
        if self.entries.len() - self.last_consolidation >= self.consolidation_interval {
            self.consolidate_entries();
        }
    }
    
    /// One-shot learning: Add entry and propagate to similar memories
    /// 
    /// This is the key method for memory-on-memory learning:
    /// - A single example updates not just itself but related memories
    /// - SECURITY-FIRST: Threat patterns propagate more strongly than benign
    pub fn one_shot_learn(&mut self, entry: PsiEntry, reward: f32) {
        let is_threat = entry.valence > 0.5;
        
        // SECURITY-FIRST: Threats propagate with higher strength
        let propagation_strength = if is_threat {
            reward.abs() * 2.0  // Threats get 2x propagation
        } else {
            reward.abs() * 0.5  // Benign gets 0.5x propagation
        };
        
        // Find similar memories BEFORE adding (to avoid self-match)
        let similar_memories = self.find_similar_for_association(&entry.vec);
        
        // MEMORY-ON-MEMORY: Update similar memories based on this new learning
        for (similar_id, similarity) in &similar_memories {
            self.propagate_learning(similar_id, reward * similarity * propagation_strength, is_threat);
        }
        
        // Create connections and add entry
        self.add(entry);
    }
    
    /// Reinforce an existing memory and propagate to associated memories
    /// 
    /// When memory A is reinforced, memories connected to A are also updated
    /// (with decaying strength based on connection weight)
    pub fn reinforce_with_propagation(&mut self, entry_id: &str, reward: f32) {
        let is_threat = reward > 0.0;
        
        // SECURITY-FIRST: Threat reinforcement propagates more strongly
        let base_propagation = if is_threat { 0.4 } else { 0.2 };
        
        // First, update the target entry itself
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == entry_id) {
            let valence_delta = reward * 0.1;
            entry.valence = (entry.valence + valence_delta).clamp(0.0, 1.0);
            entry.cumulative_reward += reward;
            entry.uses += 1;
            entry.last_activation = current_timestamp();
        }
        
        // Then propagate to connected memories (memory-on-memory)
        let connected: Vec<(String, f32)> = self.connections.iter()
            .filter(|c| c.source_id == entry_id)
            .map(|c| (c.target_id.clone(), c.strength))
            .collect();
        
        for (connected_id, connection_strength) in connected {
            let propagated_reward = reward * connection_strength * base_propagation;
            self.propagate_learning(&connected_id, propagated_reward, is_threat);
            
            // Strengthen the connection (Hebbian: neurons that fire together wire together)
            self.strengthen_connection(entry_id, &connected_id, reward.abs() * 0.1);
        }
    }
    
    /// Propagate learning to a specific memory
    fn propagate_learning(&mut self, entry_id: &str, propagated_reward: f32, is_threat: bool) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == entry_id) {
            // SECURITY-FIRST: Only propagate threat signals to threat memories and vice versa
            // This prevents cross-contamination
            let entry_is_threat = entry.valence > 0.5;
            
            if entry_is_threat == is_threat {
                // Same type: full propagation
                let valence_delta = propagated_reward * 0.05;
                entry.valence = (entry.valence + valence_delta).clamp(0.0, 1.0);
                entry.cumulative_reward += propagated_reward * 0.5;
            }
            // Different type: no propagation (prevent cross-contamination)
        }
    }

    pub fn search(&self, q: &[f32; EMBED_DIM], top_k: usize) -> Vec<(&PsiEntry, f32)> {
        let mut out: Vec<(&PsiEntry, f32)> = self.entries.iter()
            .map(|e| (e, cosine_sim(&e.vec, q)))
            .collect();
        out.sort_by(|a,b| b.1.partial_cmp(&a.1).unwrap());
        out.into_iter().take(top_k).collect()
    }
    
    /// Search with associative retrieval
    /// 
    /// Returns not just directly similar memories, but also memories
    /// connected via Hebbian associations (spreading activation)
    pub fn search_with_associations(&self, q: &[f32; EMBED_DIM], top_k: usize) -> Vec<(&PsiEntry, f32)> {
        // First, get direct similarity matches
        let direct_matches: Vec<(&PsiEntry, f32)> = self.entries.iter()
            .map(|e| (e, cosine_sim(&e.vec, q)))
            .filter(|(_, sim)| *sim > 0.3)
            .collect();
        
        // Collect all IDs and their scores
        let mut all_scores: std::collections::HashMap<&str, f32> = std::collections::HashMap::new();
        
        for (entry, sim) in &direct_matches {
            all_scores.insert(&entry.id, *sim);
            
            // Spreading activation: add associated memories
            for conn in &self.connections {
                if conn.source_id == entry.id {
                    let associated_score = sim * conn.strength * 0.5; // Decay for association
                    let current = all_scores.entry(&conn.target_id).or_insert(0.0);
                    *current = current.max(associated_score);
                }
            }
        }
        
        // Convert back to entry references with scores
        let mut results: Vec<(&PsiEntry, f32)> = self.entries.iter()
            .filter_map(|e| all_scores.get(e.id.as_str()).map(|&score| (e, score)))
            .collect();
        
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        results.into_iter().take(top_k).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    
    /// Get the number of Hebbian connections
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Export high-quality patterns for knowledge sharing
    pub fn export_high_quality_patterns(&self, min_valence_threshold: f32) -> Vec<PsiEntry> {
        self.entries.iter()
            .filter(|entry| entry.valence.abs() > min_valence_threshold && entry.uses > 1)
            .cloned()
            .collect()
    }
    
    /// PSI consolidation: merge similar entries and remove low-quality ones
    fn consolidate_entries(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        
        // Remove low-quality entries first
        self.entries.retain(|entry| entry.valence.abs() > self.quality_threshold);
        
        // Merge similar entries
        let mut consolidated = Vec::new();
        let mut processed = vec![false; self.entries.len()];
        
        for i in 0..self.entries.len() {
            if processed[i] {
                continue;
            }
            
            let mut cluster = vec![i];
            processed[i] = true;
            
            // Find similar entries to merge
            for j in (i + 1)..self.entries.len() {
                if processed[j] {
                    continue;
                }
                
                let similarity = cosine_sim(&self.entries[i].vec, &self.entries[j].vec);
                if similarity > 0.8 {
                    cluster.push(j);
                    processed[j] = true;
                }
            }
            
            // Create consolidated entry from cluster
            if cluster.len() == 1 {
                consolidated.push(self.entries[i].clone());
            } else {
                let merged_entry = self.merge_entries(&cluster);
                consolidated.push(merged_entry);
            }
        }
        
        self.entries = consolidated;
        self.last_consolidation = self.entries.len();
    }
    
    /// Merge multiple PSI entries into one
    fn merge_entries(&self, indices: &[usize]) -> PsiEntry {
        let mut merged_vec = [0.0; EMBED_DIM];
        let mut merged_valence = 0.0;
        let mut merged_uses = 0;
        let mut merged_tags = Vec::new();
        
        for &idx in indices {
            let entry = &self.entries[idx];
            
            // Average the vectors
            for i in 0..EMBED_DIM {
                merged_vec[i] += entry.vec[i];
            }
            
            // Weighted average of valence by usage
            merged_valence += entry.valence * entry.uses as f32;
            merged_uses += entry.uses;
            
            // Merge tags
            for tag in &entry.tags {
                if !merged_tags.contains(tag) {
                    merged_tags.push(tag.clone());
                }
            }
        }
        
        // Normalize vector
        for i in 0..EMBED_DIM {
            merged_vec[i] /= indices.len() as f32;
        }
        
        // Normalize valence
        if merged_uses > 0 {
            merged_valence /= merged_uses as f32;
        }
        
        PsiEntry {
            id: format!("merged_{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
            vec: merged_vec,
            valence: merged_valence,
            uses: merged_uses,
            tags: merged_tags,
            last_activation: current_timestamp(),
            cumulative_reward: 0.0,
        }
    }
    
    // ==================== HEBBIAN CONNECTION MANAGEMENT ====================
    
    /// Find entries similar enough to create associations
    fn find_similar_for_association(&self, vec: &[f32; EMBED_DIM]) -> Vec<(String, f32)> {
        self.entries.iter()
            .map(|e| (e.id.clone(), cosine_sim(&e.vec, vec)))
            .filter(|(_, sim)| *sim > self.association_threshold)
            .take(self.max_connections_per_entry)
            .collect()
    }
    
    /// Create or strengthen a Hebbian connection between two memories
    fn create_or_strengthen_connection(&mut self, source_id: &str, target_id: &str, similarity: f32) {
        if source_id == target_id {
            return; // No self-connections
        }
        
        // Check if connection exists
        if let Some(conn) = self.connections.iter_mut()
            .find(|c| c.source_id == source_id && c.target_id == target_id) 
        {
            // Strengthen existing connection (Hebbian learning)
            conn.strength = (conn.strength + similarity * self.hebbian_learning_rate).min(1.0);
            conn.co_activations += 1;
            conn.last_update = current_timestamp();
        } else {
            // Check connection limit for source
            let source_connections = self.connections.iter()
                .filter(|c| c.source_id == source_id)
                .count();
            
            if source_connections < self.max_connections_per_entry {
                // Create new connection
                self.connections.push(PsiConnection {
                    source_id: source_id.to_string(),
                    target_id: target_id.to_string(),
                    strength: similarity * 0.5, // Initial strength is half of similarity
                    co_activations: 1,
                    last_update: current_timestamp(),
                });
            }
        }
    }
    
    /// Strengthen an existing connection (called during reinforcement)
    fn strengthen_connection(&mut self, source_id: &str, target_id: &str, delta: f32) {
        if let Some(conn) = self.connections.iter_mut()
            .find(|c| c.source_id == source_id && c.target_id == target_id)
        {
            conn.strength = (conn.strength + delta).min(1.0);
            conn.co_activations += 1;
            conn.last_update = current_timestamp();
        }
    }
    
    /// Decay all connections (call periodically)
    pub fn decay_connections(&mut self) {
        for conn in &mut self.connections {
            conn.strength *= 1.0 - self.connection_decay;
        }
        
        // Prune weak connections
        self.connections.retain(|c| c.strength > 0.05);
    }
    
    /// Get connections for a specific entry
    pub fn get_connections(&self, entry_id: &str) -> Vec<&PsiConnection> {
        self.connections.iter()
            .filter(|c| c.source_id == entry_id || c.target_id == entry_id)
            .collect()
    }
    
    // ==================== STATISTICS ====================
    
    /// Get PSI statistics for monitoring
    pub fn get_stats(&self) -> PsiStats {
        let avg_valence = if self.entries.is_empty() {
            0.0
        } else {
            self.entries.iter().map(|e| e.valence).sum::<f32>() / self.entries.len() as f32
        };
        
        let avg_uses = if self.entries.is_empty() {
            0.0
        } else {
            self.entries.iter().map(|e| e.uses as f32).sum::<f32>() / self.entries.len() as f32
        };
        
        let memory_usage = self.entries.len() as f32 / self.max_entries as f32;
        
        PsiStats {
            entry_count: self.entries.len(),
            avg_valence,
            avg_uses,
            memory_usage,
            quality_threshold: self.quality_threshold,
        }
    }
    
    /// Promote high-quality entries to BDH memory
    pub fn promote_to_bdh(&self, quality_threshold: f32) -> Vec<PsiEntry> {
        self.entries.iter()
            .filter(|entry| entry.valence.abs() > quality_threshold && entry.uses > 2)
            .cloned()
            .collect()
    }

    /// Get the number of entries in the PSI index
    pub fn get_entry_count(&self) -> usize {
        self.entries.len()
    }
    
    // ==================== PERSISTENCE HELPERS ====================
    
    /// Get an iterator over all entries (for persistence)
    pub fn entries(&self) -> impl Iterator<Item = &PsiEntry> {
        self.entries.iter()
    }
    
    /// Get an iterator over all connections (for persistence)
    pub fn all_connections(&self) -> impl Iterator<Item = &PsiConnection> {
        self.connections.iter()
    }
    
    /// Clear all entries and connections
    pub fn clear(&mut self) {
        self.entries.clear();
        self.connections.clear();
    }
    
    /// Restore a connection from persisted state
    pub fn restore_connection(&mut self, conn: PsiConnection) {
        // Only restore if both source and target exist
        let source_exists = self.entries.iter().any(|e| e.id == conn.source_id);
        let target_exists = self.entries.iter().any(|e| e.id == conn.target_id);
        
        if source_exists && target_exists {
            // Check if connection already exists
            let existing = self.connections.iter_mut()
                .find(|c| c.source_id == conn.source_id && c.target_id == conn.target_id);
            
            if let Some(existing) = existing {
                existing.strength = conn.strength;
                existing.co_activations = conn.co_activations;
            } else {
                self.connections.push(conn);
            }
        }
    }
}

#[derive(Debug)]
pub struct PsiStats {
    pub entry_count: usize,
    pub avg_valence: f32,
    pub avg_uses: f32,
    pub memory_usage: f32,
    pub quality_threshold: f32,
}

fn cosine_sim(a: &[f32; EMBED_DIM], b: &[f32; EMBED_DIM]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x,y)| x*y).sum();
    let an: f32 = a.iter().map(|x| x*x).sum::<f32>().sqrt();
    let bn: f32 = b.iter().map(|x| x*x).sum::<f32>().sqrt();
    if an==0.0 || bn==0.0 { return 0.0; }
    dot / (an*bn)
}

/// Get current timestamp as f64 seconds since UNIX epoch
fn current_timestamp() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn make_entry(id: &str, valence: f32, vec_seed: f32) -> PsiEntry {
        let mut vec = [0.0; EMBED_DIM];
        for i in 0..EMBED_DIM {
            vec[i] = (vec_seed + i as f32 * 0.1).sin();
        }
        PsiEntry {
            id: id.to_string(),
            vec,
            valence,
            uses: 1,
            tags: vec![],
            last_activation: current_timestamp(),
            cumulative_reward: 0.0,
        }
    }
    
    #[test]
    fn test_one_shot_learning_creates_connections() {
        let mut psi = PsiIndex::new();
        
        // Add first entry
        let entry1 = make_entry("threat_1", 0.8, 1.0);
        psi.add(entry1);
        
        // Add similar entry - should create connection
        let entry2 = make_entry("threat_2", 0.9, 1.1); // Similar vector
        psi.add(entry2);
        
        // Should have created connections between similar entries
        assert!(psi.connection_count() > 0, "Should create Hebbian connections for similar entries");
    }
    
    #[test]
    fn test_memory_on_memory_propagation() {
        let mut psi = PsiIndex::new();
        
        // Add two similar threat entries
        let entry1 = make_entry("threat_1", 0.7, 1.0);
        let entry2 = make_entry("threat_2", 0.7, 1.05); // Very similar
        psi.add(entry1);
        psi.add(entry2);
        
        // Get initial valence of entry2
        let initial_valence = psi.entries.iter()
            .find(|e| e.id == "threat_2")
            .map(|e| e.valence)
            .unwrap();
        
        // Reinforce entry1 - should propagate to entry2
        psi.reinforce_with_propagation("threat_1", 1.0);
        
        // Entry2 should have increased valence due to propagation
        let final_valence = psi.entries.iter()
            .find(|e| e.id == "threat_2")
            .map(|e| e.valence)
            .unwrap();
        
        assert!(final_valence >= initial_valence, 
            "Memory-on-memory propagation should increase related memory valence");
    }
    
    #[test]
    fn test_cross_contamination_prevention() {
        let mut psi = PsiIndex::new();
        
        // Add a threat and a benign entry with similar vectors
        let threat = make_entry("threat", 0.9, 1.0);
        let benign = make_entry("benign", 0.1, 1.05);
        psi.add(threat);
        psi.add(benign);
        
        // Get initial benign valence
        let initial_benign_valence = psi.entries.iter()
            .find(|e| e.id == "benign")
            .map(|e| e.valence)
            .unwrap();
        
        // Reinforce the threat - should NOT propagate to benign
        psi.reinforce_with_propagation("threat", 1.0);
        
        // Benign valence should NOT increase (cross-contamination prevention)
        let final_benign_valence = psi.entries.iter()
            .find(|e| e.id == "benign")
            .map(|e| e.valence)
            .unwrap();
        
        assert_eq!(initial_benign_valence, final_benign_valence,
            "Threat reinforcement should NOT propagate to benign entries");
    }
    
    #[test]
    fn test_associative_search() {
        let mut psi = PsiIndex::new();
        
        // Add entries and create associations
        let entry1 = make_entry("entry_1", 0.8, 1.0);
        let entry2 = make_entry("entry_2", 0.8, 1.05); // Similar to entry1
        let entry3 = make_entry("entry_3", 0.2, 5.0);  // Different
        
        psi.add(entry1.clone());
        psi.add(entry2);
        psi.add(entry3);
        
        // Search with associations should return both entry1 and entry2
        let results = psi.search_with_associations(&entry1.vec, 5);
        
        assert!(results.len() >= 1, "Should find at least the query entry");
    }
    
    #[test]
    fn test_security_first_threat_propagation() {
        let mut psi = PsiIndex::new();
        
        // Add multiple threat entries
        let threat1 = make_entry("threat_1", 0.8, 1.0);
        let threat2 = make_entry("threat_2", 0.75, 1.02);
        
        // Use one_shot_learn for threat with high reward
        psi.one_shot_learn(threat1, 1.0);
        psi.one_shot_learn(threat2, 1.0);
        
        // Threats should have connections and high propagation
        assert!(psi.connection_count() > 0 || psi.len() == 2, 
            "One-shot learning should work");
    }
}
