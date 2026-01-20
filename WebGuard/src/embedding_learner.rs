/// Learnable Embedding System for Experiential Reinforcement Learning
/// 
/// This module implements TRUE ADAPTIVE LEARNING:
/// - The embedding function (char embeddings + projection) learns from experience
/// - Errors cause weight updates that change HOW inputs are embedded
/// - Over time, threats and benign naturally separate in embedding space
/// - NO pattern storage, NO rules - pure learned representations
/// 
/// Key principles:
/// 1. Character embeddings learn which characters are threat-indicative
/// 2. Projection weights learn to amplify discriminative features
/// 3. Prototypes track cluster centers but the EMBEDDING FUNCTION does the real learning
/// 4. Contrastive updates ensure separation increases over time

use std::collections::HashMap;

/// Embedding dimension - dense representation size
pub const EMBED_DIM: usize = 32;

/// Learning rate for embedding weight updates (keep small for stability)
const BASE_LEARNING_RATE: f32 = 0.02;

/// Momentum for smoother learning
const MOMENTUM: f32 = 0.7;

/// Character embedding dimension (intermediate)
const CHAR_EMBED_DIM: usize = 16;

/// Pure adaptive embedding learner - no pattern storage
#[derive(Clone, Debug)]
pub struct EmbeddingLearner {
    /// Character-level embeddings (256 possible byte values)
    /// THESE ARE THE PRIMARY LEARNABLE WEIGHTS
    char_embeddings: [[f32; CHAR_EMBED_DIM]; 256],
    
    /// Projection weights: CHAR_EMBED_DIM -> EMBED_DIM
    /// Transform aggregated char embeddings to final embedding space
    projection_weights: [[f32; EMBED_DIM]; CHAR_EMBED_DIM],
    
    /// Bias for projection
    projection_bias: [f32; EMBED_DIM],
    
    /// Threat prototype - running average of threat embeddings
    threat_prototype: [f32; EMBED_DIM],
    
    /// Benign prototype - running average of benign embeddings
    benign_prototype: [f32; EMBED_DIM],
    
    /// Momentum accumulators for char embeddings (for stable learning)
    char_momentum: [[f32; CHAR_EMBED_DIM]; 256],
    
    /// Momentum accumulators for projection weights
    proj_momentum: [[f32; EMBED_DIM]; CHAR_EMBED_DIM],
    
    /// Current learning rate
    current_learning_rate: f32,
    
    /// Total updates performed
    update_count: usize,
    
    /// Experience counts
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
    
    /// Calculate threat score based purely on learned embedding distances
    /// Uses margin-based scoring for more stable decisions
    pub fn threat_score(&self, embedding: &[f32; EMBED_DIM]) -> f32 {
        let threat_dist = self.euclidean_distance(embedding, &self.threat_prototype);
        let benign_dist = self.euclidean_distance(embedding, &self.benign_prototype);
        
        // Margin-based scoring: positive margin = closer to threat
        let margin = benign_dist - threat_dist;
        
        // Sigmoid with scaling
        1.0 / (1.0 + (-margin * 2.0).exp())
    }
    
    /// Euclidean distance between two embeddings
    fn euclidean_distance(&self, a: &[f32; EMBED_DIM], b: &[f32; EMBED_DIM]) -> f32 {
        let sum: f32 = a.iter().zip(b.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum();
        sum.sqrt()
    }
    
    /// Learn from a labeled example using reinforcement signal
    /// For CORRECT predictions: reinforce the embedding weights
    /// Prototypes are FIXED - only the embedding function adapts
    pub fn learn(&mut self, request: &str, is_threat: bool, reward: f32) {
        // Only learn from positive rewards (correct predictions)
        if reward <= 0.0 {
            return;
        }
        
        let embedding = self.embed(request);
        
        // Update experience counts
        if is_threat {
            self.threat_experiences += 1;
        } else {
            self.benign_experiences += 1;
        }
        
        // Update learning rate with decay
        self.update_count += 1;
        self.current_learning_rate = BASE_LEARNING_RATE / (1.0 + 0.0001 * self.update_count as f32);
        
        let lr = self.current_learning_rate * reward.abs() * 0.5;  // Reduced for stability
        
        // Reinforce the embedding weights to continue producing this embedding
        // Use class-balanced learning: weight threat samples higher due to imbalance
        let class_weight = if is_threat { 2.0 } else { 0.5 };  // Oversample threats
        
        self.update_char_embeddings(request, &embedding, is_threat, lr * class_weight);
    }
    
    /// Learn from a prediction error - TRUE ADAPTIVE LEARNING
    /// 
    /// Key insight: The EMBEDDING FUNCTION learns, not the prototypes
    /// - Prototypes are FIXED reference points in embedding space
    /// - The embedding weights learn to map threats toward threat_prototype
    /// - The embedding weights learn to map benign toward benign_prototype
    /// 
    /// This is like learning a transformation that separates classes
    pub fn learn_from_error(&mut self, request: &str, predicted_threat: bool, actual_threat: bool) {
        if predicted_threat == actual_threat {
            return;  // No error
        }
        
        // Get current embedding BEFORE any updates
        let embedding = self.embed(request);
        
        // Compute distances to FIXED prototypes
        let threat_dist = self.euclidean_distance(&embedding, &self.threat_prototype);
        let benign_dist = self.euclidean_distance(&embedding, &self.benign_prototype);
        
        let base_lr = self.current_learning_rate;
        
        if actual_threat && !predicted_threat {
            // FALSE NEGATIVE: Missed a threat - CRITICAL ERROR
            // FN leads to breach, so we learn VERY aggressively
            
            // Learning rate scales with error + class weight (FN >> FP importance)
            let error_mag = (benign_dist - threat_dist + 1.0).max(0.5);
            let fn_weight = 3.0;  // FN is 3x worse than FP in security context
            let lr = base_lr * error_mag.min(2.0) * fn_weight;
            
            // Update embedding weights to move this input toward threat_prototype
            self.update_char_embeddings_for_class(request, true, lr);
            
            self.threat_experiences += 1;
            
        } else if !actual_threat && predicted_threat {
            // FALSE POSITIVE: Incorrectly flagged benign
            // Less critical than FN, but still learn
            
            let error_mag = (threat_dist - benign_dist + 1.0).max(0.5);
            let lr = base_lr * error_mag.min(1.5);  // Less aggressive for FP
            
            // Update embedding weights to move this input toward benign_prototype
            self.update_char_embeddings_for_class(request, false, lr);
            
            self.benign_experiences += 1;
        }
        
        self.update_count += 1;
    }
    
    /// Update character embeddings to make them more indicative of a class
    /// Simple but effective: characters in threats should produce threat-like embeddings
    fn update_char_embeddings_for_class(&mut self, request: &str, is_threat: bool, lr: f32) {
        let bytes = request.as_bytes();
        if bytes.is_empty() {
            return;
        }
        
        // Target prototype (fixed)
        let target = if is_threat { &self.threat_prototype } else { &self.benign_prototype };
        
        // For each character, update its embedding to be more like the target
        // This is a simple "label propagation" - characters in threat requests
        // should produce embeddings that are closer to threat_prototype
        
        let char_lr = lr / (bytes.len() as f32).max(1.0);  // Scale by frequency
        
        for &byte in bytes {
            let char_idx = byte as usize;
            
            // Update each dimension of the character embedding
            // to push the resulting document embedding toward the target
            for j in 0..CHAR_EMBED_DIM {
                // Compute how this character embedding affects the output
                // The effect goes through the projection weights
                let mut target_direction = 0.0f32;
                for k in 0..EMBED_DIM {
                    // We want embedding[k] to be closer to target[k]
                    // char_embeddings[j] contributes to embedding[k] via projection_weights[j][k]
                    target_direction += self.projection_weights[j][k] * target[k];
                }
                
                // Move char embedding toward producing target-like output
                let update = char_lr * (target_direction - self.char_embeddings[char_idx][j] * 0.1);
                self.char_embeddings[char_idx][j] += update.clamp(-0.1, 0.1);
            }
        }
        
        // Also update projection weights to amplify discriminative char embeddings
        // Characters that appear in threats should contribute more to threat dimensions
        let proj_lr = lr * 0.1;
        
        // Average char embedding for this request
        let mut char_avg = [0.0f32; CHAR_EMBED_DIM];
        for &byte in bytes {
            for j in 0..CHAR_EMBED_DIM {
                char_avg[j] += self.char_embeddings[byte as usize][j];
            }
        }
        for j in 0..CHAR_EMBED_DIM {
            char_avg[j] /= bytes.len() as f32;
        }
        
        // Update projection to map this char pattern toward target
        for j in 0..CHAR_EMBED_DIM {
            for k in 0..EMBED_DIM {
                // If char_avg[j] is high and target[k] is high, increase weight
                let update = proj_lr * char_avg[j] * target[k];
                self.projection_weights[j][k] += update.clamp(-0.05, 0.05);
            }
        }
    }
    
    /// Update embedding weights to produce embeddings closer to target
    /// This is the key to ADAPTIVE learning - the embedding function changes
    fn update_embedding_weights_toward_target(&mut self, request: &str, target: &[f32; EMBED_DIM], lr: f32) {
        let bytes = request.as_bytes();
        if bytes.is_empty() {
            return;
        }
        
        // Compute current embedding ONCE (before any updates)
        let current_embed = self.embed(request);
        
        // Compute direction vector (gradient direction)
        let mut direction = [0.0f32; EMBED_DIM];
        for k in 0..EMBED_DIM {
            direction[k] = target[k] - current_embed[k];
        }
        
        // Aggregate char embedding for this request (for projection weight update)
        let mut char_sum = [0.0f32; CHAR_EMBED_DIM];
        for &byte in bytes {
            let char_idx = byte as usize;
            for j in 0..CHAR_EMBED_DIM {
                char_sum[j] += self.char_embeddings[char_idx][j];
            }
        }
        let norm = (bytes.len() as f32).sqrt().max(1.0);
        for j in 0..CHAR_EMBED_DIM {
            char_sum[j] /= norm;
        }
        
        // Update character embeddings
        // Use a scaled learning rate based on character frequency in request
        let char_lr = lr / norm;  // Scale by request length
        
        for &byte in bytes {
            let char_idx = byte as usize;
            
            for j in 0..CHAR_EMBED_DIM {
                let mut grad = 0.0f32;
                for k in 0..EMBED_DIM {
                    // Gradient: projection_weight * direction
                    grad += self.projection_weights[j][k] * direction[k];
                }
                
                // Apply momentum for stability
                self.char_momentum[char_idx][j] = MOMENTUM * self.char_momentum[char_idx][j] 
                                                 + (1.0 - MOMENTUM) * grad;
                
                // Update with clipping to prevent explosion
                let update = (char_lr * self.char_momentum[char_idx][j]).clamp(-0.1, 0.1);
                self.char_embeddings[char_idx][j] += update;
            }
        }
        
        // Update projection weights
        let proj_lr = lr * 0.3;  // More conservative for projection
        for j in 0..CHAR_EMBED_DIM {
            for k in 0..EMBED_DIM {
                let grad = char_sum[j] * direction[k];
                
                self.proj_momentum[j][k] = MOMENTUM * self.proj_momentum[j][k] 
                                          + (1.0 - MOMENTUM) * grad;
                
                // Clipped update
                let update = (proj_lr * self.proj_momentum[j][k]).clamp(-0.05, 0.05);
                self.projection_weights[j][k] += update;
            }
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
        
        // Calculate average weight magnitude (indicator of learning)
        let mut avg_char_weight = 0.0f32;
        for i in 0..256 {
            for j in 0..CHAR_EMBED_DIM {
                avg_char_weight += self.char_embeddings[i][j].abs();
            }
        }
        avg_char_weight /= (256 * CHAR_EMBED_DIM) as f32;
        stats.insert("avg_char_weight".to_string(), avg_char_weight);
        
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
