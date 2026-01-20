/// Learnable Embedding System with BDH+PSI Memory Integration
/// 
/// This module implements BIDIRECTIONAL HEBBIAN LEARNING:
/// - BOTH positive and negative reinforcement ADD to memory (no forgetting)
/// - Positive reinforcement: "This pattern = threat/benign, remember it!"
/// - Negative reinforcement: "This was misclassified, remember the correction!"
/// - BDH stores experiences with valence, PSI provides persistent recall
/// - Retrieval-augmented decision making using accumulated experience
/// 
/// Key principles:
/// 1. Character embeddings provide stable feature extraction
/// 2. BDH memory stores ALL experiences (positive AND negative reinforcement)
/// 3. Valence indicates threat (+) vs benign (-) 
/// 4. Decisions use memory retrieval, not just prototype distance
/// 5. NO FORGETTING - both successes and failures strengthen memory

use std::collections::HashMap;

/// Embedding dimension - dense representation size
pub const EMBED_DIM: usize = 32;

/// Learning rate for Hebbian weight updates
const HEBBIAN_LEARNING_RATE: f32 = 0.1;

/// Character embedding dimension (intermediate)
const CHAR_EMBED_DIM: usize = 16;

/// Memory entry for BDH-style storage
#[derive(Clone, Debug)]
pub struct MemoryEntry {
    pub embedding: [f32; EMBED_DIM],
    pub valence: f32,           // Positive = threat, Negative = benign
    pub reinforcement: f32,     // Strength of the memory (always positive, grows with use)
    pub is_threat: bool,
    pub uses: usize,
}

/// Embedding learner with BDH+PSI memory integration
#[derive(Clone, Debug)]
pub struct EmbeddingLearner {
    /// Character-level embeddings (256 possible byte values)
    char_embeddings: [[f32; CHAR_EMBED_DIM]; 256],
    
    /// Projection weights: CHAR_EMBED_DIM -> EMBED_DIM
    projection_weights: [[f32; EMBED_DIM]; CHAR_EMBED_DIM],
    
    /// Bias for projection
    projection_bias: [f32; EMBED_DIM],
    
    /// BDH Memory: Stores ALL experiences (threat and benign)
    /// Key insight: BOTH positive and negative reinforcement ADD entries
    memory: Vec<MemoryEntry>,
    
    /// Threat prototype - centroid of threat memories
    threat_prototype: [f32; EMBED_DIM],
    
    /// Benign prototype - centroid of benign memories
    benign_prototype: [f32; EMBED_DIM],
    
    /// Hebbian connection weights between memory entries
    /// Strengthened when entries co-activate (fire together, wire together)
    hebbian_weights: HashMap<(usize, usize), f32>,
    
    /// Experience counts
    threat_experiences: usize,
    benign_experiences: usize,
    
    /// Total memories stored
    total_memories: usize,
}

impl EmbeddingLearner {
    /// Create a new embedding learner with initialized weights
    pub fn new() -> Self {
        let mut learner = Self {
            char_embeddings: [[0.0; CHAR_EMBED_DIM]; 256],
            projection_weights: [[0.0; EMBED_DIM]; CHAR_EMBED_DIM],
            projection_bias: [0.0; EMBED_DIM],
            memory: Vec::new(),
            threat_prototype: [0.0; EMBED_DIM],
            benign_prototype: [0.0; EMBED_DIM],
            hebbian_weights: HashMap::new(),
            threat_experiences: 0,
            benign_experiences: 0,
            total_memories: 0,
        };
        
        // Initialize with Xavier/Glorot initialization
        learner.initialize_weights();
        learner
    }
    
    /// Initialize weights with small random-like values based on position
    fn initialize_weights(&mut self) {
        // Initialize character embeddings
        for i in 0..256 {
            for j in 0..CHAR_EMBED_DIM {
                // Deterministic "random" initialization based on position
                let seed = (i * CHAR_EMBED_DIM + j) as f32;
                self.char_embeddings[i][j] = ((seed * 0.618033988749).fract() - 0.5) * 0.2;
            }
        }
        
        // Initialize projection weights
        let scale = (2.0 / (CHAR_EMBED_DIM + EMBED_DIM) as f32).sqrt();
        for i in 0..CHAR_EMBED_DIM {
            for j in 0..EMBED_DIM {
                let seed = (i * EMBED_DIM + j + 1000) as f32;
                self.projection_weights[i][j] = ((seed * 0.618033988749).fract() - 0.5) * scale;
            }
        }
        
        // Initialize prototypes to be WELL-SEPARATED
        // Threat: positive in first half, negative in second half
        // Benign: opposite pattern
        // This creates clear initial decision boundary
        for i in 0..EMBED_DIM {
            if i < EMBED_DIM / 2 {
                self.threat_prototype[i] = 1.0;
                self.benign_prototype[i] = -1.0;
            } else {
                self.threat_prototype[i] = -1.0;
                self.benign_prototype[i] = 1.0;
            }
        }
    }
    
    /// Embed a request string into a dense vector
    pub fn embed(&self, request: &str) -> [f32; EMBED_DIM] {
        // Step 1: Aggregate character embeddings
        let mut char_agg = [0.0f32; CHAR_EMBED_DIM];
        let bytes = request.as_bytes();
        let len = bytes.len().max(1) as f32;
        
        // Use multiple aggregation strategies for richer representation
        for (pos, &byte) in bytes.iter().enumerate() {
            let char_embed = &self.char_embeddings[byte as usize];
            
            // Position-weighted aggregation (earlier chars matter more for HTTP)
            let pos_weight = 1.0 / (1.0 + (pos as f32 / 50.0));
            
            for j in 0..CHAR_EMBED_DIM {
                char_agg[j] += char_embed[j] * pos_weight;
            }
        }
        
        // Normalize by length
        for j in 0..CHAR_EMBED_DIM {
            char_agg[j] /= len.sqrt();
        }
        
        // Step 2: Project to embedding dimension
        let mut embedding = [0.0f32; EMBED_DIM];
        for j in 0..EMBED_DIM {
            embedding[j] = self.projection_bias[j];
            for i in 0..CHAR_EMBED_DIM {
                embedding[j] += char_agg[i] * self.projection_weights[i][j];
            }
            // Apply tanh activation for bounded output
            embedding[j] = embedding[j].tanh();
        }
        
        // Step 3: L2 normalize the embedding
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt() + 1e-8;
        for j in 0..EMBED_DIM {
            embedding[j] /= norm;
        }
        
        embedding
    }
    
    /// Calculate threat score using BDH memory retrieval
    /// Combines prototype distance with memory-based evidence
    pub fn threat_score(&self, embedding: &[f32; EMBED_DIM]) -> f32 {
        // Component 1: Prototype-based score
        let threat_dist = self.euclidean_distance(embedding, &self.threat_prototype);
        let benign_dist = self.euclidean_distance(embedding, &self.benign_prototype);
        let margin = benign_dist - threat_dist;
        let prototype_score = 1.0 / (1.0 + (-margin * 2.0).exp());
        
        // Component 2: Memory-based score (BDH retrieval)
        let memory_score = self.retrieve_memory_score(embedding);
        
        // Combine: memory evidence weighted by amount of experience
        let memory_weight = (self.total_memories as f32 / 50.0).min(0.7);  // Max 70% from memory
        let prototype_weight = 1.0 - memory_weight;
        
        prototype_score * prototype_weight + memory_score * memory_weight
    }
    
    /// Retrieve threat score from BDH memory
    /// Returns weighted average of similar memories' valences
    fn retrieve_memory_score(&self, embedding: &[f32; EMBED_DIM]) -> f32 {
        if self.memory.is_empty() {
            return 0.5;  // No memory, neutral score
        }
        
        // Find similar memories and compute weighted threat score
        let mut weighted_sum = 0.0;
        let mut weight_total = 0.0;
        
        for (idx, entry) in self.memory.iter().enumerate() {
            let similarity = self.cosine_similarity(embedding, &entry.embedding);
            
            if similarity > 0.3 {  // Only consider reasonably similar memories
                // Weight by similarity AND reinforcement strength
                let weight = similarity * entry.reinforcement;
                
                // Valence: positive = threat, negative = benign
                // Convert to 0-1 scale
                let threat_indicator = if entry.is_threat { 1.0 } else { 0.0 };
                
                weighted_sum += weight * threat_indicator;
                weight_total += weight;
                
                // Hebbian boost: check connections to other activated memories
                let hebbian_boost = self.get_hebbian_boost(idx, embedding);
                weighted_sum += hebbian_boost * threat_indicator * 0.1;
                weight_total += hebbian_boost.abs() * 0.1;
            }
        }
        
        if weight_total > 0.0 {
            weighted_sum / weight_total
        } else {
            0.5  // No relevant memories, neutral score
        }
    }
    
    /// Get Hebbian connection boost for a memory entry
    fn get_hebbian_boost(&self, memory_idx: usize, _query: &[f32; EMBED_DIM]) -> f32 {
        let mut boost = 0.0;
        for ((src, tgt), weight) in &self.hebbian_weights {
            if *src == memory_idx || *tgt == memory_idx {
                boost += weight;
            }
        }
        boost.max(-0.5).min(0.5)
    }
    
    /// Euclidean distance between two embeddings
    fn euclidean_distance(&self, a: &[f32; EMBED_DIM], b: &[f32; EMBED_DIM]) -> f32 {
        let sum: f32 = a.iter().zip(b.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum();
        sum.sqrt()
    }
    
    /// Cosine similarity between two embeddings
    fn cosine_similarity(&self, a: &[f32; EMBED_DIM], b: &[f32; EMBED_DIM]) -> f32 {
        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm_a > 0.0 && norm_b > 0.0 {
            dot / (norm_a * norm_b)
        } else {
            0.0
        }
    }
    
    /// POSITIVE REINFORCEMENT: Store correct classification in memory
    /// Both threat and benign correct predictions ADD to memory
    pub fn learn(&mut self, request: &str, is_threat: bool, reward: f32) {
        let embedding = self.embed(request);
        
        // ALWAYS add to memory - positive reinforcement ADDS knowledge
        // Reward magnitude determines reinforcement strength
        let reinforcement = reward.abs().max(0.1);
        
        // Valence: positive for threat, negative for benign
        let valence = if is_threat { reinforcement } else { -reinforcement };
        
        // Check if similar memory exists - if so, STRENGTHEN it (Hebbian)
        let similar_idx = self.find_similar_memory(&embedding, 0.9);
        
        if let Some(idx) = similar_idx {
            // Strengthen existing memory (Hebbian: neurons that fire together wire together)
            self.memory[idx].reinforcement += reinforcement * HEBBIAN_LEARNING_RATE;
            self.memory[idx].uses += 1;
            
            // Update Hebbian connections to recently activated memories
            self.update_hebbian_connections(idx);
        } else {
            // Add new memory
            let entry = MemoryEntry {
                embedding,
                valence,
                reinforcement,
                is_threat,
                uses: 1,
            };
            self.memory.push(entry);
            self.total_memories += 1;
            
            // Create Hebbian connections to similar existing memories
            let new_idx = self.memory.len() - 1;
            self.create_hebbian_connections(new_idx);
        }
        
        // Update experience counts
        if is_threat {
            self.threat_experiences += 1;
        } else {
            self.benign_experiences += 1;
        }
        
        // Update prototypes using exponential moving average
        self.update_prototype(&embedding, is_threat);
    }
    
    /// Find similar memory entry (for Hebbian strengthening)
    fn find_similar_memory(&self, embedding: &[f32; EMBED_DIM], threshold: f32) -> Option<usize> {
        for (idx, entry) in self.memory.iter().enumerate() {
            let sim = self.cosine_similarity(embedding, &entry.embedding);
            if sim > threshold {
                return Some(idx);
            }
        }
        None
    }
    
    /// Create Hebbian connections from new memory to similar existing memories
    fn create_hebbian_connections(&mut self, new_idx: usize) {
        let new_embedding = self.memory[new_idx].embedding;
        let new_is_threat = self.memory[new_idx].is_threat;
        
        for (idx, entry) in self.memory.iter().enumerate() {
            if idx == new_idx {
                continue;
            }
            
            let sim = self.cosine_similarity(&new_embedding, &entry.embedding);
            if sim > 0.5 {
                // Create bidirectional connection
                // Same class = positive weight, different class = negative weight
                let weight = if entry.is_threat == new_is_threat {
                    sim * HEBBIAN_LEARNING_RATE
                } else {
                    -sim * HEBBIAN_LEARNING_RATE * 0.5  // Weaker inhibition
                };
                
                self.hebbian_weights.insert((new_idx, idx), weight);
                self.hebbian_weights.insert((idx, new_idx), weight);
            }
        }
    }
    
    /// Update Hebbian connections when a memory is activated
    fn update_hebbian_connections(&mut self, activated_idx: usize) {
        let activated_embedding = self.memory[activated_idx].embedding;
        
        // Strengthen connections to other similar, recently used memories
        for (idx, entry) in self.memory.iter().enumerate() {
            if idx == activated_idx {
                continue;
            }
            
            let sim = self.cosine_similarity(&activated_embedding, &entry.embedding);
            if sim > 0.4 && entry.uses > 0 {
                // Hebbian update: fire together, wire together
                let key = (activated_idx.min(idx), activated_idx.max(idx));
                let current = self.hebbian_weights.get(&key).copied().unwrap_or(0.0);
                let delta = sim * HEBBIAN_LEARNING_RATE * 0.1;
                self.hebbian_weights.insert(key, (current + delta).max(-1.0).min(1.0));
            }
        }
    }
    
    /// Update prototype using exponential moving average
    fn update_prototype(&mut self, embedding: &[f32; EMBED_DIM], is_threat: bool) {
        let alpha = 0.1;  // Learning rate for prototype update
        let prototype = if is_threat {
            &mut self.threat_prototype
        } else {
            &mut self.benign_prototype
        };
        
        for i in 0..EMBED_DIM {
            prototype[i] = prototype[i] * (1.0 - alpha) + embedding[i] * alpha;
        }
    }
    
    /// NEGATIVE REINFORCEMENT: Learn from prediction errors
    /// 
    /// Key insight: Errors ALSO add to memory - they teach us what we got wrong!
    /// - False Negative: "This WAS a threat, remember it as such!"
    /// - False Positive: "This was NOT a threat, remember it as benign!"
    /// 
    /// Both add new memories with STRONGER reinforcement (we learn more from mistakes)
    pub fn learn_from_error(&mut self, request: &str, predicted_threat: bool, actual_threat: bool) {
        if predicted_threat == actual_threat {
            return;  // No error
        }
        
        let embedding = self.embed(request);
        
        // Errors get STRONGER reinforcement - we learn more from mistakes!
        // FN (missed threat) is more critical than FP in security
        let reinforcement = if actual_threat && !predicted_threat {
            2.0  // False Negative - critical, learn strongly
        } else {
            1.0  // False Positive - less critical but still learn
        };
        
        // Store the CORRECTED classification in memory
        // This is negative reinforcement: "I was wrong, the correct answer is..."
        let valence = if actual_threat { reinforcement } else { -reinforcement };
        
        // Check if similar memory exists
        let similar_idx = self.find_similar_memory(&embedding, 0.85);
        
        if let Some(idx) = similar_idx {
            // CORRECT the existing memory if it had wrong classification
            if self.memory[idx].is_threat != actual_threat {
                // Flip the classification and strengthen
                self.memory[idx].is_threat = actual_threat;
                self.memory[idx].valence = valence;
                self.memory[idx].reinforcement += reinforcement;
            } else {
                // Same classification, just strengthen
                self.memory[idx].reinforcement += reinforcement * HEBBIAN_LEARNING_RATE;
            }
            self.memory[idx].uses += 1;
            
            // Update Hebbian connections
            self.update_hebbian_connections(idx);
        } else {
            // Add new memory with the CORRECT classification
            let entry = MemoryEntry {
                embedding,
                valence,
                reinforcement,
                is_threat: actual_threat,
                uses: 1,
            };
            self.memory.push(entry);
            self.total_memories += 1;
            
            // Create Hebbian connections
            let new_idx = self.memory.len() - 1;
            self.create_hebbian_connections(new_idx);
        }
        
        // Update experience counts
        if actual_threat {
            self.threat_experiences += 1;
        } else {
            self.benign_experiences += 1;
        }
        
        // Update prototypes toward correct classification
        self.update_prototype(&embedding, actual_threat);
    }
    
    // NOTE: Old gradient-based update functions removed
    // BDH+PSI memory-based learning replaces gradient descent
    // This prevents catastrophic forgetting - both positive and negative
    // reinforcement ADD to memory rather than modifying weights destructively
    
    /// Get statistics about the embedding space and BDH memory
    pub fn get_stats(&self) -> HashMap<String, f32> {
        let mut stats = HashMap::new();
        
        // Distance between prototypes
        let prototype_dist = self.euclidean_distance(&self.threat_prototype, &self.benign_prototype);
        stats.insert("prototype_separation".to_string(), prototype_dist);
        
        stats.insert("threat_experiences".to_string(), self.threat_experiences as f32);
        stats.insert("benign_experiences".to_string(), self.benign_experiences as f32);
        
        // BDH Memory statistics
        stats.insert("total_memories".to_string(), self.total_memories as f32);
        stats.insert("hebbian_connections".to_string(), self.hebbian_weights.len() as f32);
        
        // Count threat vs benign memories
        let threat_memories = self.memory.iter().filter(|m| m.is_threat).count();
        let benign_memories = self.memory.iter().filter(|m| !m.is_threat).count();
        stats.insert("threat_memories".to_string(), threat_memories as f32);
        stats.insert("benign_memories".to_string(), benign_memories as f32);
        
        // Average reinforcement strength
        if !self.memory.is_empty() {
            let avg_reinforcement: f32 = self.memory.iter()
                .map(|m| m.reinforcement)
                .sum::<f32>() / self.memory.len() as f32;
            stats.insert("avg_reinforcement".to_string(), avg_reinforcement);
        }
        
        stats
    }
    
    /// Get the current prototype separation (key metric for learning progress)
    pub fn prototype_separation(&self) -> f32 {
        self.euclidean_distance(&self.threat_prototype, &self.benign_prototype)
    }
}

impl Default for EmbeddingLearner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_embedding_basic() {
        let learner = EmbeddingLearner::new();
        
        let benign = "GET /index.html HTTP/1.1";
        let threat = "GET /search?q=' OR 1=1-- HTTP/1.1";
        
        let benign_emb = learner.embed(benign);
        let threat_emb = learner.embed(threat);
        
        // Embeddings should be normalized
        let benign_norm: f32 = benign_emb.iter().map(|x| x*x).sum::<f32>().sqrt();
        let threat_norm: f32 = threat_emb.iter().map(|x| x*x).sum::<f32>().sqrt();
        
        assert!((benign_norm - 1.0).abs() < 0.01);
        assert!((threat_norm - 1.0).abs() < 0.01);
    }
    
    #[test]
    fn test_learning_separates_prototypes() {
        let mut learner = EmbeddingLearner::new();
        
        let initial_sep = learner.prototype_separation();
        
        // Train on some examples
        for _ in 0..10 {
            learner.learn("GET /index.html HTTP/1.1", false, 1.0);
            learner.learn("GET /api/users HTTP/1.1", false, 1.0);
            learner.learn("GET /search?q=' OR 1=1-- HTTP/1.1", true, 1.0);
            learner.learn("POST /login username=admin'-- HTTP/1.1", true, 1.0);
        }
        
        let final_sep = learner.prototype_separation();
        
        // Prototypes should be more separated after learning
        assert!(final_sep > initial_sep, 
            "Prototype separation should increase: {} -> {}", initial_sep, final_sep);
    }
}
