/// N-gram + Skip-gram Embedding System with Contrastive Learning + BDH Memory
/// 
/// TRUE ADAPTIVE LEARNING through:
/// 1. Contiguous N-grams (2-4 chars): Capture sequential patterns like "' OR", "<script"
/// 2. Skip-grams: Capture co-occurrence patterns like c...m...d (chars together but not adjacent)
/// 3. Positional features: Where patterns appear (start, param boundary, etc.)
/// 4. Contrastive loss: Push threat patterns AWAY from benign embeddings
/// 5. BDH memory: Store n-gram -> threat/benign associations (no forgetting)
/// 
/// Key insight: Threats are defined by PATTERNS at multiple levels:
/// - Sequential: "' OR", "../", "<script>"
/// - Co-occurrence: presence of ';' AND 'cat' AND '/etc' anywhere
/// - Positional: special chars at parameter boundaries

use std::collections::HashMap;

/// Embedding dimension - dense representation size
pub const EMBED_DIM: usize = 64;

/// N-gram vocabulary size (hash buckets for contiguous n-grams)
const NGRAM_VOCAB_SIZE: usize = 8192;

/// Skip-gram vocabulary size (hash buckets for character co-occurrence)
const SKIPGRAM_VOCAB_SIZE: usize = 4096;

/// N-gram sizes to extract (contiguous)
const NGRAM_SIZES: [usize; 3] = [2, 3, 4];

/// Skip-gram max distance (for co-occurrence patterns)
const SKIPGRAM_MAX_DIST: usize = 8;

/// Contrastive margin - minimum separation between classes
const CONTRASTIVE_MARGIN: f32 = 0.5;

/// Learning rate for pattern embedding updates
const PATTERN_LEARNING_RATE: f32 = 0.1;

/// Learning rate for error corrections (stronger - learn more from mistakes)
const ERROR_LEARNING_RATE: f32 = 0.3;

/// Threat class weight (to counter class imbalance)
const THREAT_WEIGHT: f32 = 5.0;

/// Full request memory for BDH-style retrieval
#[derive(Clone, Debug)]
pub struct RequestMemory {
    pub embedding: [f32; EMBED_DIM],
    pub is_threat: bool,
    pub confidence: f32,
}

/// N-gram + Skip-gram Embedding Learner with Contrastive Learning
pub struct EmbeddingLearner {
    /// N-gram embeddings: hash -> embedding vector
    ngram_embeddings: Vec<[f32; EMBED_DIM]>,
    
    /// Skip-gram embeddings: hash -> embedding vector  
    skipgram_embeddings: Vec<[f32; EMBED_DIM]>,
    
    /// N-gram threat associations: hash -> (threat_score, benign_score, count)
    ngram_associations: HashMap<u64, (f32, f32, usize)>,
    
    /// Threat prototype - learned center of threat class
    threat_prototype: [f32; EMBED_DIM],
    
    /// Benign prototype - learned center of benign class
    benign_prototype: [f32; EMBED_DIM],
    
    /// BDH Memory: Full request memories for retrieval
    request_memory: Vec<RequestMemory>,
    
    /// Experience counts
    threat_experiences: usize,
    benign_experiences: usize,
    
    /// Running sums for prototype computation
    threat_sum: [f32; EMBED_DIM],
    benign_sum: [f32; EMBED_DIM],
}

impl Clone for EmbeddingLearner {
    fn clone(&self) -> Self {
        Self {
            ngram_embeddings: self.ngram_embeddings.clone(),
            skipgram_embeddings: self.skipgram_embeddings.clone(),
            ngram_associations: self.ngram_associations.clone(),
            threat_prototype: self.threat_prototype,
            benign_prototype: self.benign_prototype,
            request_memory: self.request_memory.clone(),
            threat_experiences: self.threat_experiences,
            benign_experiences: self.benign_experiences,
            threat_sum: self.threat_sum,
            benign_sum: self.benign_sum,
        }
    }
}

impl std::fmt::Debug for EmbeddingLearner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingLearner")
            .field("ngram_associations", &self.ngram_associations.len())
            .field("request_memories", &self.request_memory.len())
            .field("threat_exp", &self.threat_experiences)
            .field("benign_exp", &self.benign_experiences)
            .finish()
    }
}

impl EmbeddingLearner {
    /// Create a new n-gram embedding learner
    pub fn new() -> Self {
        let mut learner = Self {
            ngram_embeddings: vec![[0.0; EMBED_DIM]; NGRAM_VOCAB_SIZE],
            skipgram_embeddings: vec![[0.0; EMBED_DIM]; SKIPGRAM_VOCAB_SIZE],
            ngram_associations: HashMap::new(),
            threat_prototype: [0.0; EMBED_DIM],
            benign_prototype: [0.0; EMBED_DIM],
            request_memory: Vec::new(),
            threat_experiences: 0,
            benign_experiences: 0,
            threat_sum: [0.0; EMBED_DIM],
            benign_sum: [0.0; EMBED_DIM],
        };
        
        learner.initialize_embeddings();
        learner
    }
    
    /// Initialize n-gram and skip-gram embeddings
    fn initialize_embeddings(&mut self) {
        let scale = (2.0 / EMBED_DIM as f32).sqrt();
        
        // Initialize n-gram embeddings
        for i in 0..NGRAM_VOCAB_SIZE {
            for j in 0..EMBED_DIM {
                let seed = (i * EMBED_DIM + j) as f32;
                self.ngram_embeddings[i][j] = ((seed * 0.618033988749).fract() - 0.5) * scale;
            }
        }
        
        // Initialize skip-gram embeddings
        for i in 0..SKIPGRAM_VOCAB_SIZE {
            for j in 0..EMBED_DIM {
                let seed = (i * EMBED_DIM + j + 50000) as f32;
                self.skipgram_embeddings[i][j] = ((seed * 0.618033988749).fract() - 0.5) * scale;
            }
        }
        
        // Initialize prototypes to opposite directions
        for i in 0..EMBED_DIM {
            let seed = i as f32;
            self.threat_prototype[i] = ((seed * 0.618033988749).fract() - 0.5) * 0.5;
            self.benign_prototype[i] = -self.threat_prototype[i];
        }
    }
    
    // ==================== N-GRAM EXTRACTION ====================
    
    /// Hash an n-gram to a bucket index using FNV-1a
    fn hash_ngram(ngram: &[u8]) -> u64 {
        let mut hash: u64 = 14695981039346656037;
        for &byte in ngram {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(1099511628211);
        }
        hash
    }
    
    /// Extract all contiguous n-grams from a string
    fn extract_ngrams(request: &str) -> Vec<(u64, usize)> {
        let bytes = request.as_bytes();
        let mut ngrams = Vec::new();
        
        for &n in &NGRAM_SIZES {
            if bytes.len() >= n {
                for i in 0..=(bytes.len() - n) {
                    let ngram = &bytes[i..i+n];
                    let hash = Self::hash_ngram(ngram);
                    ngrams.push((hash, i));
                }
            }
        }
        ngrams
    }
    
    /// Extract skip-grams (character co-occurrence at distance)
    fn extract_skipgrams(request: &str) -> Vec<u64> {
        let bytes = request.as_bytes();
        let mut skipgrams = Vec::new();
        
        // Only consider "interesting" characters
        let interesting: Vec<(usize, u8)> = bytes.iter()
            .enumerate()
            .filter(|(_, &b)| {
                // Special chars that might indicate attacks
                b == b'\'' || b == b'"' || b == b';' || b == b'|' || 
                b == b'<' || b == b'>' || b == b'&' || b == b'=' ||
                b == b'/' || b == b'\\' || b == b'.' || b == b'-' ||
                b == b'(' || b == b')' || b == b'%' || b == b'$' ||
                b == b'[' || b == b']' || b == b'{' || b == b'}' ||
                // Lowercase letters for patterns like "cmd", "cat", "etc"
                (b >= b'a' && b <= b'z')
            })
            .map(|(i, &b)| (i, b))
            .collect();
        
        // Create skip-grams from pairs
        for i in 0..interesting.len() {
            for j in (i+1)..interesting.len().min(i + SKIPGRAM_MAX_DIST) {
                let (pos_i, char_i) = interesting[i];
                let (pos_j, char_j) = interesting[j];
                let dist = pos_j - pos_i;
                
                // Hash: (char1, char2, distance_bucket)
                let dist_bucket = (dist / 2).min(4) as u8;
                let skip_bytes = [char_i, char_j, dist_bucket];
                let hash = Self::hash_ngram(&skip_bytes);
                skipgrams.push(hash);
            }
        }
        skipgrams
    }
    
    // ==================== EMBEDDING ====================
    
    /// Embed a request using n-gram and skip-gram features
    pub fn embed(&self, request: &str) -> [f32; EMBED_DIM] {
        let mut embedding = [0.0f32; EMBED_DIM];
        let mut count = 0.0f32;
        
        // 1. Aggregate contiguous n-gram embeddings
        let ngrams = Self::extract_ngrams(request);
        for (hash, pos) in &ngrams {
            let idx = (*hash as usize) % NGRAM_VOCAB_SIZE;
            let ngram_emb = &self.ngram_embeddings[idx];
            
            // Position weight: patterns at start matter more
            let pos_weight = if *pos < 20 { 1.5 } 
                           else if *pos > 50 { 0.8 } 
                           else { 1.0 };
            
            // N-gram association weight
            let assoc_weight = self.get_ngram_weight(*hash);
            
            for j in 0..EMBED_DIM {
                embedding[j] += ngram_emb[j] * pos_weight * assoc_weight;
            }
            count += pos_weight * assoc_weight;
        }
        
        // 2. Aggregate skip-gram embeddings
        let skipgrams = Self::extract_skipgrams(request);
        for hash in &skipgrams {
            let idx = (*hash as usize) % SKIPGRAM_VOCAB_SIZE;
            let skip_emb = &self.skipgram_embeddings[idx];
            
            let assoc_weight = self.get_ngram_weight(*hash);
            
            for j in 0..EMBED_DIM {
                embedding[j] += skip_emb[j] * 0.5 * assoc_weight;
            }
            count += 0.5 * assoc_weight;
        }
        
        // Normalize
        if count > 0.0 {
            for j in 0..EMBED_DIM {
                embedding[j] /= count;
            }
        }
        
        // L2 normalize
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt() + 1e-8;
        for j in 0..EMBED_DIM {
            embedding[j] /= norm;
        }
        
        embedding
    }
    
    /// Get learned weight for an n-gram based on associations
    fn get_ngram_weight(&self, hash: u64) -> f32 {
        if let Some(&(threat, benign, count)) = self.ngram_associations.get(&hash) {
            if count > 0 {
                let diff = (threat - benign).abs();
                return 1.0 + diff * 0.5;
            }
        }
        1.0
    }
    
    // ==================== THREAT SCORING ====================
    
    /// Calculate threat score combining prototype distance and memory retrieval
    pub fn threat_score(&self, embedding: &[f32; EMBED_DIM]) -> f32 {
        // Component 1: Distance to prototypes
        let threat_dist = self.euclidean_distance(embedding, &self.threat_prototype);
        let benign_dist = self.euclidean_distance(embedding, &self.benign_prototype);
        let margin = benign_dist - threat_dist;
        let prototype_score = 1.0 / (1.0 + (-margin * 3.0).exp());
        
        // Component 2: Memory retrieval score
        let memory_score = self.retrieve_memory_score(embedding);
        
        // Combine based on experience
        let total_exp = (self.threat_experiences + self.benign_experiences) as f32;
        let memory_weight = (total_exp / 100.0).min(0.6);
        
        prototype_score * (1.0 - memory_weight) + memory_score * memory_weight
    }
    
    /// Retrieve threat score from similar memories
    fn retrieve_memory_score(&self, embedding: &[f32; EMBED_DIM]) -> f32 {
        if self.request_memory.is_empty() {
            return 0.5;
        }
        
        let mut weighted_sum = 0.0f32;
        let mut weight_total = 0.0f32;
        
        for mem in &self.request_memory {
            let sim = self.cosine_similarity(embedding, &mem.embedding);
            if sim > 0.5 {
                let weight = sim * mem.confidence;
                let threat_indicator = if mem.is_threat { 1.0 } else { 0.0 };
                weighted_sum += weight * threat_indicator;
                weight_total += weight;
            }
        }
        
        if weight_total > 0.0 {
            weighted_sum / weight_total
        } else {
            0.5
        }
    }
    
    /// Euclidean distance
    fn euclidean_distance(&self, a: &[f32; EMBED_DIM], b: &[f32; EMBED_DIM]) -> f32 {
        a.iter().zip(b.iter()).map(|(x, y)| (x - y).powi(2)).sum::<f32>().sqrt()
    }
    
    /// Cosine similarity
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
    
    // ==================== LEARNING ====================
    
    /// Learn from a correctly classified sample (POSITIVE REINFORCEMENT)
    /// Both threat and benign samples ADD to memory and update embeddings
    pub fn learn(&mut self, request: &str, is_threat: bool, reward: f32) {
        let embedding = self.embed(request);
        let strength = reward.abs().max(0.1);
        
        // Class-weighted learning rate (threats weighted higher to counter imbalance)
        let lr = if is_threat { 
            PATTERN_LEARNING_RATE * THREAT_WEIGHT 
        } else { 
            PATTERN_LEARNING_RATE 
        };
        
        // 1. Update n-gram associations (ADDITIVE - no forgetting)
        self.update_ngram_associations(request, is_threat, strength);
        
        // 2. Contrastive update to n-gram embeddings
        self.contrastive_update(request, is_threat, lr * strength);
        
        // 3. Update prototype (class centroid)
        self.update_prototype(&embedding, is_threat);
        
        // 4. Store in memory
        self.add_to_memory(embedding, is_threat, strength);
        
        // Update counts
        if is_threat {
            self.threat_experiences += 1;
        } else {
            self.benign_experiences += 1;
        }
    }
    
    /// Learn from an error (NEGATIVE REINFORCEMENT - stronger learning)
    pub fn learn_from_error(&mut self, request: &str, _predicted_threat: bool, actual_threat: bool) {
        let embedding = self.embed(request);
        
        // Errors get STRONGER learning (biological: we learn more from mistakes)
        // False negatives (missed threats) are CRITICAL in security
        let strength = if actual_threat { 3.0 } else { 1.5 };
        let lr = ERROR_LEARNING_RATE * strength;
        
        // 1. Strong update to n-gram associations
        self.update_ngram_associations(request, actual_threat, strength);
        
        // 2. Strong contrastive update
        self.contrastive_update(request, actual_threat, lr);
        
        // 3. Update prototype
        self.update_prototype(&embedding, actual_threat);
        
        // 4. Store corrected classification in memory
        self.add_to_memory(embedding, actual_threat, strength);
        
        // Update counts
        if actual_threat {
            self.threat_experiences += 1;
        } else {
            self.benign_experiences += 1;
        }
    }
    
    /// Update n-gram threat/benign associations (ADDITIVE - no forgetting)
    fn update_ngram_associations(&mut self, request: &str, is_threat: bool, strength: f32) {
        // Update contiguous n-grams
        let ngrams = Self::extract_ngrams(request);
        for (hash, _) in ngrams {
            let entry = self.ngram_associations.entry(hash).or_insert((0.0, 0.0, 0));
            if is_threat {
                entry.0 += strength;  // ADD to threat score
            } else {
                entry.1 += strength;  // ADD to benign score
            }
            entry.2 += 1;
        }
        
        // Update skip-grams
        let skipgrams = Self::extract_skipgrams(request);
        for hash in skipgrams {
            let entry = self.ngram_associations.entry(hash).or_insert((0.0, 0.0, 0));
            if is_threat {
                entry.0 += strength * 0.5;
            } else {
                entry.1 += strength * 0.5;
            }
            entry.2 += 1;
        }
    }
    
    /// Contrastive update: push n-gram embeddings toward own class, away from other
    fn contrastive_update(&mut self, request: &str, is_threat: bool, lr: f32) {
        let target = if is_threat { &self.threat_prototype } else { &self.benign_prototype };
        let opposite = if is_threat { &self.benign_prototype } else { &self.threat_prototype };
        
        // Update contiguous n-gram embeddings
        let ngrams = Self::extract_ngrams(request);
        for (hash, _) in &ngrams {
            let idx = (*hash as usize) % NGRAM_VOCAB_SIZE;
            let emb = &mut self.ngram_embeddings[idx];
            
            // Move toward target prototype
            for j in 0..EMBED_DIM {
                let toward_target = target[j] - emb[j];
                let away_from_opposite = emb[j] - opposite[j];
                
                // Contrastive: attract to target + repel from opposite
                let delta = lr * (toward_target * 0.6 + away_from_opposite * 0.4) * 0.01;
                emb[j] += delta.clamp(-0.1, 0.1);
            }
        }
        
        // Update skip-gram embeddings
        let skipgrams = Self::extract_skipgrams(request);
        for hash in &skipgrams {
            let idx = (*hash as usize) % SKIPGRAM_VOCAB_SIZE;
            let emb = &mut self.skipgram_embeddings[idx];
            
            for j in 0..EMBED_DIM {
                let toward_target = target[j] - emb[j];
                let away_from_opposite = emb[j] - opposite[j];
                let delta = lr * (toward_target * 0.6 + away_from_opposite * 0.4) * 0.005;
                emb[j] += delta.clamp(-0.05, 0.05);
            }
        }
    }
    
    /// Update prototype with CONTRASTIVE constraint
    /// Key: push prototypes APART, not just toward class embeddings
    fn update_prototype(&mut self, embedding: &[f32; EMBED_DIM], is_threat: bool) {
        let count = if is_threat { self.threat_experiences } else { self.benign_experiences };
        let alpha = 0.05 / (1.0 + count as f32 * 0.001);  // Slower decay
        
        // Update own prototype toward embedding
        {
            let prototype = if is_threat { &mut self.threat_prototype } else { &mut self.benign_prototype };
            for j in 0..EMBED_DIM {
                prototype[j] = prototype[j] * (1.0 - alpha) + embedding[j] * alpha;
            }
        }
        
        // CONTRASTIVE: Push OTHER prototype AWAY from this embedding
        {
            let other = if is_threat { &mut self.benign_prototype } else { &mut self.threat_prototype };
            let push_alpha = alpha * 0.3;  // Weaker push
            for j in 0..EMBED_DIM {
                // Move away from embedding
                other[j] = other[j] * (1.0 + push_alpha) - embedding[j] * push_alpha;
            }
        }
        
        // Normalize BOTH to unit vectors (but they're pushed in opposite directions)
        let norm_t: f32 = self.threat_prototype.iter().map(|x| x * x).sum::<f32>().sqrt() + 1e-8;
        let norm_b: f32 = self.benign_prototype.iter().map(|x| x * x).sum::<f32>().sqrt() + 1e-8;
        for j in 0..EMBED_DIM {
            self.threat_prototype[j] /= norm_t;
            self.benign_prototype[j] /= norm_b;
        }
    }
    
    /// Add to BDH memory
    fn add_to_memory(&mut self, embedding: [f32; EMBED_DIM], is_threat: bool, confidence: f32) {
        // Limit memory size
        if self.request_memory.len() > 1000 {
            // Remove oldest low-confidence memories
            self.request_memory.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
            self.request_memory.truncate(800);
        }
        
        self.request_memory.push(RequestMemory {
            embedding,
            is_threat,
            confidence,
        });
    }
    
    // ==================== STATISTICS ====================
    
    /// Get statistics for monitoring
    pub fn get_stats(&self) -> HashMap<String, f32> {
        let mut stats = HashMap::new();
        
        let proto_dist = self.euclidean_distance(&self.threat_prototype, &self.benign_prototype);
        stats.insert("prototype_separation".to_string(), proto_dist);
        stats.insert("threat_experiences".to_string(), self.threat_experiences as f32);
        stats.insert("benign_experiences".to_string(), self.benign_experiences as f32);
        stats.insert("ngram_associations".to_string(), self.ngram_associations.len() as f32);
        stats.insert("request_memories".to_string(), self.request_memory.len() as f32);
        
        // Count threat-indicative n-grams
        let threat_ngrams = self.ngram_associations.iter()
            .filter(|(_, (t, b, _))| t > b)
            .count();
        stats.insert("threat_indicative_ngrams".to_string(), threat_ngrams as f32);
        
        stats
    }
    
    /// Debug print state
    pub fn debug_print_state(&self) {
        let proto_dist = self.euclidean_distance(&self.threat_prototype, &self.benign_prototype);
        let threat_ngrams = self.ngram_associations.iter()
            .filter(|(_, (t, b, _))| t > b)
            .count();
        println!("  [DEBUG] Proto sep: {:.4} | Ngram assocs: {} | Threat ngrams: {} | Memories: {} | T_exp: {} | B_exp: {}",
                 proto_dist, self.ngram_associations.len(), threat_ngrams,
                 self.request_memory.len(), self.threat_experiences, self.benign_experiences);
    }
    
    /// Get prototype separation
    pub fn prototype_separation(&self) -> f32 {
        self.euclidean_distance(&self.threat_prototype, &self.benign_prototype)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ngram_extraction() {
        let ngrams = EmbeddingLearner::extract_ngrams("' OR 1=1--");
        assert!(!ngrams.is_empty());
        println!("Extracted {} n-grams", ngrams.len());
    }
    
    #[test]
    fn test_skipgram_extraction() {
        let skipgrams = EmbeddingLearner::extract_skipgrams("; cat /etc/passwd");
        assert!(!skipgrams.is_empty());
        println!("Extracted {} skip-grams", skipgrams.len());
    }
    
    #[test]
    fn test_contrastive_learning() {
        let mut learner = EmbeddingLearner::new();
        
        let initial_sep = learner.prototype_separation();
        
        // Learn some threats
        learner.learn("' OR 1=1--", true, 1.0);
        learner.learn("<script>alert(1)</script>", true, 1.0);
        learner.learn("../../../etc/passwd", true, 1.0);
        
        // Learn some benign
        learner.learn("GET /index.html HTTP/1.1", false, 1.0);
        learner.learn("POST /api/users HTTP/1.1", false, 1.0);
        
        let final_sep = learner.prototype_separation();
        
        println!("Initial separation: {:.4}", initial_sep);
        println!("Final separation: {:.4}", final_sep);
        
        // Prototypes should stay separated (contrastive learning)
        assert!(final_sep > 0.1, "Prototypes should remain separated");
    }
}
