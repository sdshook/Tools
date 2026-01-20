/// Learnable Embedding System with BDH+PSI Memory Integration
/// 
/// This module implements BIDIRECTIONAL HEBBIAN LEARNING:
/// - BOTH positive and negative reinforcement ADD to memory (no forgetting)
/// - Character embeddings ADAPT based on reinforcement (Hebbian weight updates)
/// - Memory retrieval influences scoring, but embedding adaptation enables GENERALIZATION
/// 
/// Key principles for TRUE ADAPTIVE LEARNING:
/// 1. Character embeddings LEARN which characters indicate threats
/// 2. Both positive and negative reinforcement STRENGTHEN learning (no subtraction)
/// 3. Hebbian updates to char embeddings enable generalization to UNSEEN patterns
/// 4. Memory provides retrieval-augmented scoring
/// 5. Prototypes adapt toward learned class centroids

use std::collections::HashMap;

/// Embedding dimension - dense representation size
pub const EMBED_DIM: usize = 32;

/// Learning rate for Hebbian weight updates (char embeddings)
const HEBBIAN_LEARNING_RATE: f32 = 0.05;

/// Character embedding dimension (intermediate)
const CHAR_EMBED_DIM: usize = 16;

/// Learning rate for projection weight updates
const PROJECTION_LEARNING_RATE: f32 = 0.02;

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
        
        // Initialize prototypes to be NEUTRAL and let learning separate them
        // Both start at small random-like values - learning will push them apart
        for i in 0..EMBED_DIM {
            let seed = i as f32;
            self.threat_prototype[i] = ((seed * 0.618033988749).fract() - 0.5) * 0.1;
            self.benign_prototype[i] = -((seed * 0.618033988749).fract() - 0.5) * 0.1;
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
        
        // Scale margin more aggressively for better separation
        let prototype_score = 1.0 / (1.0 + (-margin * 5.0).exp());
        
        // Component 2: Memory-based score (BDH retrieval)
        let memory_score = self.retrieve_memory_score(embedding);
        
        // Combine: as memory grows, rely more on learned experience
        let memory_weight = (self.total_memories as f32 / 30.0).min(0.8);  // Up to 80% from memory
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
    
    /// POSITIVE REINFORCEMENT: Learn from correct classification
    /// Key: BOTH memory storage AND embedding weight updates for generalization
    pub fn learn(&mut self, request: &str, is_threat: bool, reward: f32) {
        let embedding = self.embed(request);
        let reinforcement = reward.abs().max(0.1);
        let valence = if is_threat { reinforcement } else { -reinforcement };
        
        // 1. MEMORY: Store/strengthen experience
        let similar_idx = self.find_similar_memory(&embedding, 0.9);
        
        if let Some(idx) = similar_idx {
            self.memory[idx].reinforcement += reinforcement * HEBBIAN_LEARNING_RATE;
            self.memory[idx].uses += 1;
            self.update_hebbian_connections(idx);
        } else {
            let entry = MemoryEntry {
                embedding,
                valence,
                reinforcement,
                is_threat,
                uses: 1,
            };
            self.memory.push(entry);
            self.total_memories += 1;
            let new_idx = self.memory.len() - 1;
            self.create_hebbian_connections(new_idx);
        }
        
        // 2. ADAPTIVE LEARNING: Update char embeddings via Hebbian learning
        // This is what enables GENERALIZATION to unseen patterns!
        // Characters that appear in threats should produce threat-like embeddings
        self.hebbian_char_update(request, is_threat, reinforcement);
        
        // 3. Update prototypes toward class centroids
        self.update_prototype(&embedding, is_threat);
        
        // Update experience counts
        if is_threat {
            self.threat_experiences += 1;
        } else {
            self.benign_experiences += 1;
        }
    }
    
    /// Hebbian update to character embeddings - enables generalization
    /// Uses GRADIENT-BASED Hebbian: compute how to change embeddings to move output toward target
    fn hebbian_char_update(&mut self, request: &str, is_threat: bool, strength: f32) {
        let bytes = request.as_bytes();
        if bytes.is_empty() {
            return;
        }
        
        // Get CURRENT embedding to compute gradient
        let current_embedding = self.embed(request);
        
        // Target: which prototype should this pattern move toward?
        let target = if is_threat { &self.threat_prototype } else { &self.benign_prototype };
        
        // Compute error signal: direction to move the embedding
        let mut error = [0.0f32; EMBED_DIM];
        for k in 0..EMBED_DIM {
            error[k] = target[k] - current_embedding[k];
        }
        
        // Learning rate scaled by strength (stronger for errors)
        let lr = HEBBIAN_LEARNING_RATE * strength.min(3.0);
        
        // Backprop the error through projection to get char embedding gradient
        let mut char_grad = [0.0f32; CHAR_EMBED_DIM];
        for j in 0..CHAR_EMBED_DIM {
            for k in 0..EMBED_DIM {
                char_grad[j] += error[k] * self.projection_weights[j][k];
            }
        }
        
        // Update char embeddings for characters in this request
        // Hebbian: strengthen connections in direction of gradient
        for &byte in bytes {
            let char_idx = byte as usize;
            for j in 0..CHAR_EMBED_DIM {
                // Additive update in gradient direction
                let delta = lr * char_grad[j] * 0.01;
                self.char_embeddings[char_idx][j] += delta.clamp(-0.1, 0.1);
            }
        }
        
        // Also update projection weights
        self.hebbian_projection_update(request, &error, strength);
    }
    
    /// Hebbian update to projection weights using error signal
    fn hebbian_projection_update(&mut self, request: &str, error: &[f32; EMBED_DIM], strength: f32) {
        let bytes = request.as_bytes();
        if bytes.is_empty() {
            return;
        }
        
        let lr = PROJECTION_LEARNING_RATE * strength.min(3.0);
        
        // Compute aggregated char embedding (input to projection)
        let mut char_agg = [0.0f32; CHAR_EMBED_DIM];
        for &byte in bytes {
            for j in 0..CHAR_EMBED_DIM {
                char_agg[j] += self.char_embeddings[byte as usize][j];
            }
        }
        let norm = (bytes.len() as f32).sqrt().max(1.0);
        for j in 0..CHAR_EMBED_DIM {
            char_agg[j] /= norm;
        }
        
        // Hebbian update: Δw_jk = η * input_j * error_k
        for j in 0..CHAR_EMBED_DIM {
            for k in 0..EMBED_DIM {
                let delta = lr * char_agg[j] * error[k] * 0.01;
                self.projection_weights[j][k] += delta.clamp(-0.05, 0.05);
            }
        }
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
    
    /// Update prototype using exponential moving average with L2 normalization
    /// Key: prototypes MUST stay bounded and separate for adaptive learning
    fn update_prototype(&mut self, embedding: &[f32; EMBED_DIM], is_threat: bool) {
        // Adaptive alpha: learn faster early, slower later
        let base_alpha = 0.05;  // Reduced for stability
        let experience_count = if is_threat { 
            self.threat_experiences 
        } else { 
            self.benign_experiences 
        };
        let alpha = base_alpha / (1.0 + experience_count as f32 * 0.001);
        
        let prototype = if is_threat {
            &mut self.threat_prototype
        } else {
            &mut self.benign_prototype
        };
        
        // Update with EMA
        for i in 0..EMBED_DIM {
            prototype[i] = prototype[i] * (1.0 - alpha) + embedding[i] * alpha;
        }
        
        // L2 normalize to keep bounded
        let norm: f32 = prototype.iter().map(|x| x * x).sum::<f32>().sqrt() + 1e-8;
        for i in 0..EMBED_DIM {
            prototype[i] /= norm;
        }
    }
    
    /// NEGATIVE REINFORCEMENT: Learn from prediction errors
    /// 
    /// CRITICAL: Errors teach us the most! We learn with STRONGER reinforcement.
    /// - False Negative: "This WAS a threat!" -> Strong Hebbian update toward threat
    /// - False Positive: "This was NOT a threat!" -> Update toward benign
    /// 
    /// Both update MEMORY and EMBEDDING WEIGHTS (for generalization)
    pub fn learn_from_error(&mut self, request: &str, predicted_threat: bool, actual_threat: bool) {
        if predicted_threat == actual_threat {
            return;  // No error
        }
        
        let embedding = self.embed(request);
        
        // Errors get STRONGER reinforcement - biological systems learn more from mistakes!
        // FN (missed threat) is CRITICAL in security
        let reinforcement = if actual_threat && !predicted_threat {
            3.0  // False Negative - CRITICAL, learn very strongly
        } else {
            1.5  // False Positive - still important
        };
        
        let valence = if actual_threat { reinforcement } else { -reinforcement };
        
        // 1. MEMORY: Store/update with correct classification
        let similar_idx = self.find_similar_memory(&embedding, 0.85);
        
        if let Some(idx) = similar_idx {
            if self.memory[idx].is_threat != actual_threat {
                self.memory[idx].is_threat = actual_threat;
                self.memory[idx].valence = valence;
                self.memory[idx].reinforcement += reinforcement;
            } else {
                self.memory[idx].reinforcement += reinforcement * HEBBIAN_LEARNING_RATE;
            }
            self.memory[idx].uses += 1;
            self.update_hebbian_connections(idx);
        } else {
            let entry = MemoryEntry {
                embedding,
                valence,
                reinforcement,
                is_threat: actual_threat,
                uses: 1,
            };
            self.memory.push(entry);
            self.total_memories += 1;
            let new_idx = self.memory.len() - 1;
            self.create_hebbian_connections(new_idx);
        }
        
        // 2. ADAPTIVE LEARNING: Stronger Hebbian update for errors!
        // This is what enables GENERALIZATION - learn from mistakes
        self.hebbian_char_update(request, actual_threat, reinforcement);
        
        // 3. Update prototypes
        self.update_prototype(&embedding, actual_threat);
        
        // Update experience counts
        if actual_threat {
            self.threat_experiences += 1;
        } else {
            self.benign_experiences += 1;
        }
    }
    
    // NOTE: Old gradient-based update functions removed
    // BDH+PSI memory-based learning replaces gradient descent
    // This prevents catastrophic forgetting - both positive and negative
    // reinforcement ADD to memory rather than modifying weights destructively
    
    /// Get statistics about the embedding space and BDH memory
    pub fn get_stats(&self) -> HashMap<String, f32> {
        let mut stats = HashMap::new();
        
        // Distance between prototypes - KEY METRIC for learning
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
    
    /// Debug: print learning state
    pub fn debug_print_state(&self) {
        let proto_dist = self.euclidean_distance(&self.threat_prototype, &self.benign_prototype);
        println!("  [DEBUG] Memories: {} | Proto sep: {:.4} | Threat exp: {} | Benign exp: {}",
                 self.total_memories, proto_dist, self.threat_experiences, self.benign_experiences);
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
