/// Learnable Embedding System for Experiential Reinforcement Learning
/// 
/// This module implements a trainable embedding system that learns to produce
/// dense vector representations from HTTP requests. The embeddings are updated
/// via reinforcement learning signals (rewards from correct/incorrect classifications).
/// 
/// Key principles:
/// 1. Dense embeddings (no sparse vectors) - every dimension carries signal
/// 2. Reward-based learning - positive rewards pull similar patterns together
/// 3. Contrastive learning - FP/FN errors push patterns apart
/// 4. PSI/BDH integration - embeddings are stored and retrieved from memory

use std::collections::HashMap;

/// Embedding dimension - dense representation size
pub const EMBED_DIM: usize = 32;

/// Learning rate for embedding weight updates (lower = more stable)
const BASE_LEARNING_RATE: f32 = 0.02;

/// Momentum for smoother learning
const MOMENTUM: f32 = 0.5;

/// Character embedding dimension (intermediate)
const CHAR_EMBED_DIM: usize = 16;

/// Learnable embedding system
#[derive(Clone, Debug)]
pub struct EmbeddingLearner {
    /// Character-level embeddings (256 possible byte values)
    char_embeddings: [[f32; CHAR_EMBED_DIM]; 256],
    
    /// Projection weights: CHAR_EMBED_DIM -> EMBED_DIM
    projection_weights: [[f32; EMBED_DIM]; CHAR_EMBED_DIM],
    
    /// Bias for projection
    projection_bias: [f32; EMBED_DIM],
    
    /// Threat prototype - learned center of threat cluster
    threat_prototype: [f32; EMBED_DIM],
    
    /// Benign prototype - learned center of benign cluster
    benign_prototype: [f32; EMBED_DIM],
    
    /// Momentum accumulators for char embeddings
    char_momentum: [[f32; CHAR_EMBED_DIM]; 256],
    
    /// Momentum accumulators for projection weights
    proj_momentum: [[f32; EMBED_DIM]; CHAR_EMBED_DIM],
    
    /// Adaptive learning rate (decreases over time)
    current_learning_rate: f32,
    
    /// Total updates performed
    update_count: usize,
    
    /// Running statistics for normalization
    running_mean: [f32; EMBED_DIM],
    running_var: [f32; EMBED_DIM],
    
    /// Experience counts for confidence
    threat_experiences: usize,
    benign_experiences: usize,
}

impl EmbeddingLearner {
    /// Create a new embedding learner with initialized weights
    pub fn new() -> Self {
        let mut learner = Self {
            char_embeddings: [[0.0; CHAR_EMBED_DIM]; 256],
            projection_weights: [[0.0; EMBED_DIM]; CHAR_EMBED_DIM],
            projection_bias: [0.0; EMBED_DIM],
            threat_prototype: [0.0; EMBED_DIM],
            benign_prototype: [0.0; EMBED_DIM],
            char_momentum: [[0.0; CHAR_EMBED_DIM]; 256],
            proj_momentum: [[0.0; EMBED_DIM]; CHAR_EMBED_DIM],
            current_learning_rate: BASE_LEARNING_RATE,
            update_count: 0,
            running_mean: [0.0; EMBED_DIM],
            running_var: [1.0; EMBED_DIM],
            threat_experiences: 0,
            benign_experiences: 0,
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
        
        // Initialize prototypes at SAME location (no initial separation)
        // This forces the system to LEARN the separation through experience
        for i in 0..EMBED_DIM {
            // Both prototypes start at origin - system must learn to separate them
            self.threat_prototype[i] = 0.0;
            self.benign_prototype[i] = 0.0;
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
    
    /// Calculate threat score based on embedding distances to prototypes
    pub fn threat_score(&self, embedding: &[f32; EMBED_DIM]) -> f32 {
        let threat_dist = self.euclidean_distance(embedding, &self.threat_prototype);
        let benign_dist = self.euclidean_distance(embedding, &self.benign_prototype);
        
        // Convert distances to score using softmax-like function
        // Closer to threat = higher score
        let threat_proximity = (-threat_dist).exp();
        let benign_proximity = (-benign_dist).exp();
        
        let score = threat_proximity / (threat_proximity + benign_proximity + 1e-8);
        
        // Apply experience-based confidence
        let total_exp = (self.threat_experiences + self.benign_experiences) as f32;
        if total_exp < 10.0 {
            // Low experience - temper the score toward 0.5
            let confidence = total_exp / 10.0;
            return 0.5 + (score - 0.5) * confidence;
        }
        
        score
    }
    
    /// Euclidean distance between two embeddings
    fn euclidean_distance(&self, a: &[f32; EMBED_DIM], b: &[f32; EMBED_DIM]) -> f32 {
        let sum: f32 = a.iter().zip(b.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum();
        sum.sqrt()
    }
    
    /// Learn from a labeled example using reinforcement signal
    /// This is the core experiential learning function
    pub fn learn(&mut self, request: &str, is_threat: bool, reward: f32) {
        let embedding = self.embed(request);
        
        // Update experience counts
        if is_threat {
            self.threat_experiences += 1;
        } else {
            self.benign_experiences += 1;
        }
        
        // Calculate learning rate with decay (slower decay for stability)
        self.update_count += 1;
        self.current_learning_rate = BASE_LEARNING_RATE / (1.0 + 0.0001 * self.update_count as f32);
        
        let lr = self.current_learning_rate * reward.abs();
        
        // Update prototypes using exponential moving average (more stable)
        let proto_lr = 0.05;  // Very slow prototype updates for stability
        
        if is_threat {
            for i in 0..EMBED_DIM {
                // EMA update: new = old * (1 - lr) + new_val * lr
                self.threat_prototype[i] = self.threat_prototype[i] * (1.0 - proto_lr) 
                                         + embedding[i] * proto_lr;
            }
        } else {
            for i in 0..EMBED_DIM {
                self.benign_prototype[i] = self.benign_prototype[i] * (1.0 - proto_lr) 
                                         + embedding[i] * proto_lr;
            }
        }
        
        // Update character embeddings via backprop-like gradient (conservative)
        self.update_char_embeddings(request, &embedding, is_threat, lr * 0.5);
    }
    
    /// Learn from a prediction error (FP or FN) with contrastive update
    /// THIS IS THE KEY FUNCTION FOR IMPROVEMENT OVER PASSES
    /// FN is weighted MORE heavily than FP (security principle)
    pub fn learn_from_error(&mut self, request: &str, predicted_threat: bool, actual_threat: bool) {
        if predicted_threat == actual_threat {
            return;  // No error
        }
        
        let embedding = self.embed(request);
        
        if actual_threat && !predicted_threat {
            // FALSE NEGATIVE: Missed a threat - CRITICAL (higher learning rate)
            let fn_lr = 0.15;  // More aggressive for FN
            
            // Move threat prototype toward this embedding
            for i in 0..EMBED_DIM {
                self.threat_prototype[i] = self.threat_prototype[i] * (1.0 - fn_lr) 
                                         + embedding[i] * fn_lr;
            }
            // Also move benign prototype away (contrastive)
            for i in 0..EMBED_DIM {
                let direction = self.benign_prototype[i] - embedding[i];
                self.benign_prototype[i] += direction * fn_lr * 0.5;
            }
            self.threat_experiences += 1;
            
            // Update char embeddings more aggressively for FN
            self.update_char_embeddings(request, &embedding, true, fn_lr);
            
        } else if !actual_threat && predicted_threat {
            // FALSE POSITIVE: Incorrectly flagged benign (lower learning rate)
            let fp_lr = 0.08;  // Less aggressive for FP
            
            // Move benign prototype toward this embedding
            for i in 0..EMBED_DIM {
                self.benign_prototype[i] = self.benign_prototype[i] * (1.0 - fp_lr) 
                                         + embedding[i] * fp_lr;
            }
            // Slightly move threat prototype away
            for i in 0..EMBED_DIM {
                let direction = self.threat_prototype[i] - embedding[i];
                self.threat_prototype[i] += direction * fp_lr * 0.3;
            }
            self.benign_experiences += 1;
            
            // Update char embeddings for FP
            self.update_char_embeddings(request, &embedding, false, fp_lr);
        }
    }
    
    /// Update character embeddings based on error gradient
    fn update_char_embeddings(&mut self, request: &str, embedding: &[f32; EMBED_DIM], 
                               is_threat: bool, lr: f32) {
        let bytes = request.as_bytes();
        let target = if is_threat { &self.threat_prototype } else { &self.benign_prototype };
        
        // Calculate gradient direction (toward correct prototype)
        let mut grad = [0.0f32; EMBED_DIM];
        for i in 0..EMBED_DIM {
            grad[i] = target[i] - embedding[i];
        }
        
        // Backprop through projection weights
        let mut char_grad = [0.0f32; CHAR_EMBED_DIM];
        for i in 0..CHAR_EMBED_DIM {
            for j in 0..EMBED_DIM {
                char_grad[i] += grad[j] * self.projection_weights[i][j];
                
                // Update projection weights with momentum
                let weight_update = grad[j] * lr * 0.01;
                self.proj_momentum[i][j] = MOMENTUM * self.proj_momentum[i][j] + weight_update;
                self.projection_weights[i][j] += self.proj_momentum[i][j];
            }
        }
        
        // Update character embeddings for chars in this request
        for (pos, &byte) in bytes.iter().enumerate() {
            let idx = byte as usize;
            let pos_weight = 1.0 / (1.0 + (pos as f32 / 50.0));
            
            for j in 0..CHAR_EMBED_DIM {
                let update = char_grad[j] * pos_weight * lr * 0.001;
                self.char_momentum[idx][j] = MOMENTUM * self.char_momentum[idx][j] + update;
                self.char_embeddings[idx][j] += self.char_momentum[idx][j];
            }
        }
    }
    
    /// Get statistics about the embedding space
    pub fn get_stats(&self) -> HashMap<String, f32> {
        let mut stats = HashMap::new();
        
        // Distance between prototypes (should increase with learning)
        let prototype_dist = self.euclidean_distance(&self.threat_prototype, &self.benign_prototype);
        stats.insert("prototype_separation".to_string(), prototype_dist);
        
        stats.insert("threat_experiences".to_string(), self.threat_experiences as f32);
        stats.insert("benign_experiences".to_string(), self.benign_experiences as f32);
        stats.insert("learning_rate".to_string(), self.current_learning_rate);
        stats.insert("total_updates".to_string(), self.update_count as f32);
        
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
