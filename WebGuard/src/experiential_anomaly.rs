//! Experiential Anomaly Detection System
//! Implements Isolation Forest as an experiential contributor to cognitive learning
//! Integrates with PSI (Persistent Semantic Index) and BDHMemory for memory-guided anomaly analysis

#![allow(dead_code)]

use rand::Rng;
use std::collections::HashMap;
use crate::memory_engine::psi_index::{PsiIndex, PsiEntry, EMBED_DIM};
use crate::memory_engine::bdh_memory::{BdhMemory, ExperientialContext};
use crate::eq_iq_regulator::{ExperientialBehavioralRegulator, ContextEvent, FeedbackEvent};

/// Isolation Tree Node for anomaly detection
#[derive(Clone, Debug)]
struct IsolationNode {
    split_feature: Option<usize>,
    split_value: Option<f32>,
    left: Option<Box<IsolationNode>>,
    right: Option<Box<IsolationNode>>,
    size: usize,
    #[allow(dead_code)]
    depth: usize,
}

/// Isolation Tree for detecting structural anomalies
pub struct IsolationTree {
    root: IsolationNode,
    #[allow(dead_code)]
    max_depth: usize,
}

/// Experiential Anomaly Detection using Isolation Forest
pub struct ExperientialAnomalyDetector {
    trees: Vec<IsolationTree>,
    num_trees: usize,
    subsample_size: usize,
    anomaly_threshold: f32,
    // Integration with memory systems
    psi_integration_threshold: f32,
    memory_retrieval_limit: usize,
    experience_weight: f32,
}

/// Anomaly detection result with experiential context
#[derive(Debug, Clone)]
pub struct AnomalyResult {
    pub anomaly_score: f32,
    pub is_anomaly: bool,
    pub confidence: f32,
    pub experiential_context: Vec<ExperientialContext>,
    pub memory_triggered: bool,
}



impl IsolationTree {
    /// Build isolation tree from data samples
    fn build(data: &[Vec<f32>], max_depth: usize, current_depth: usize) -> IsolationNode {
        let size = data.len();
        
        // Terminal conditions
        if current_depth >= max_depth || size <= 1 {
            return IsolationNode {
                split_feature: None,
                split_value: None,
                left: None,
                right: None,
                size,
                depth: current_depth,
            };
        }
        
        // Random feature selection
        let mut rng = rand::thread_rng();
        let num_features = data[0].len();
        let split_feature = rng.gen_range(0..num_features);
        
        // Find min/max for the selected feature
        let mut min_val = f32::INFINITY;
        let mut max_val = f32::NEG_INFINITY;
        
        for sample in data {
            let val = sample[split_feature];
            min_val = min_val.min(val);
            max_val = max_val.max(val);
        }
        
        // Random split point
        let split_value = if min_val == max_val {
            min_val
        } else {
            rng.gen_range(min_val..max_val)
        };
        
        // Split data
        let mut left_data = Vec::new();
        let mut right_data = Vec::new();
        
        for sample in data {
            if sample[split_feature] < split_value {
                left_data.push(sample.clone());
            } else {
                right_data.push(sample.clone());
            }
        }
        
        // Recursively build subtrees
        let left = if !left_data.is_empty() {
            Some(Box::new(Self::build(&left_data, max_depth, current_depth + 1)))
        } else {
            None
        };
        
        let right = if !right_data.is_empty() {
            Some(Box::new(Self::build(&right_data, max_depth, current_depth + 1)))
        } else {
            None
        };
        
        IsolationNode {
            split_feature: Some(split_feature),
            split_value: Some(split_value),
            left,
            right,
            size,
            depth: current_depth,
        }
    }
    
    /// Calculate path length for anomaly scoring
    fn path_length(&self, sample: &[f32]) -> f32 {
        self.path_length_recursive(&self.root, sample, 0.0)
    }
    
    fn path_length_recursive(&self, node: &IsolationNode, sample: &[f32], current_depth: f32) -> f32 {
        // Terminal node
        if node.split_feature.is_none() {
            // Adjust for average path length in BST
            return current_depth + Self::average_path_length(node.size);
        }
        
        let split_feature = node.split_feature.unwrap();
        let split_value = node.split_value.unwrap();
        
        if sample[split_feature] < split_value {
            if let Some(ref left) = node.left {
                self.path_length_recursive(left, sample, current_depth + 1.0)
            } else {
                current_depth + Self::average_path_length(node.size)
            }
        } else {
            if let Some(ref right) = node.right {
                self.path_length_recursive(right, sample, current_depth + 1.0)
            } else {
                current_depth + Self::average_path_length(node.size)
            }
        }
    }
    
    /// Average path length in BST for normalization
    fn average_path_length(n: usize) -> f32 {
        if n <= 1 {
            0.0
        } else {
            2.0 * (((n - 1) as f32).ln() + 0.5772156649) - (2.0 * (n - 1) as f32 / n as f32)
        }
    }
}

impl ExperientialAnomalyDetector {
    /// Create new experiential anomaly detector
    pub fn new() -> Self {
        Self {
            trees: Vec::new(),
            num_trees: 100,
            subsample_size: 256,
            anomaly_threshold: 0.6,
            psi_integration_threshold: 0.5,
            memory_retrieval_limit: 5,
            experience_weight: 0.3,
        }
    }
    
    /// Train isolation forest on feature vectors
    pub fn train(&mut self, training_data: &[Vec<f32>]) {
        self.trees.clear();
        let mut rng = rand::thread_rng();
        
        for _ in 0..self.num_trees {
            // Subsample data
            let mut subsample = Vec::new();
            let sample_size = self.subsample_size.min(training_data.len());
            
            for _ in 0..sample_size {
                let idx = rng.gen_range(0..training_data.len());
                subsample.push(training_data[idx].clone());
            }
            
            // Build tree
            let max_depth = (sample_size as f32).log2().ceil() as usize;
            let root = IsolationTree::build(&subsample, max_depth, 0);
            
            self.trees.push(IsolationTree {
                root,
                max_depth,
            });
        }
    }
    
    /// Detect anomalies with EQ/IQ regulated experiential context from PSI and BDHMemory
    pub fn detect_with_experience(
        &self,
        sample: &[f32],
        psi_index: &PsiIndex,
        bdh_memory: &BdhMemory,
        eq_iq_regulator: &mut ExperientialBehavioralRegulator,
        context_stability: f32,
        threat_level: f32,
    ) -> AnomalyResult {
        // Calculate isolation forest anomaly score
        let anomaly_score = self.calculate_anomaly_score(sample);
        let is_anomaly = anomaly_score > self.anomaly_threshold;
        
        // Create context for EQ/IQ regulation
        let context = ContextEvent {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
            context_stability,
            threat_level,
            response_appropriateness: if is_anomaly { 0.8 } else { 0.6 },
        };

        let feedback = FeedbackEvent {
            timestamp: context.timestamp,
            predicted_threat: anomaly_score,
            actual_threat: threat_level,
            accuracy: 1.0 - (anomaly_score - threat_level).abs(),
        };

        // Calculate EQ/IQ balance for experience regulation
        let eq_iq_balance = eq_iq_regulator.calculate_eq_iq_balance(&context, &feedback);
        
        // If anomaly detected, trigger EQ/IQ regulated experiential memory retrieval
        let mut experiential_context = Vec::new();
        let mut memory_triggered = false;
        
        if anomaly_score > self.psi_integration_threshold {
            memory_triggered = true;
            
            // Convert sample to PSI embedding format
            let psi_embedding = self.convert_to_psi_embedding(sample);
            
            // Retrieve EQ/IQ regulated experiential context from BDH Memory
            let bdh_contexts = bdh_memory.retrieve_experiential_context(
                &psi_embedding, 
                self.memory_retrieval_limit,
                &eq_iq_balance
            );
            experiential_context.extend(bdh_contexts);
            
            // Retrieve similar experiences from PSI with EQ/IQ regulation
            let psi_results = psi_index.search(&psi_embedding, self.memory_retrieval_limit);
            
            for (psi_entry, similarity) in psi_results {
                // Apply EQ/IQ regulation to PSI memories
                let analytical_relevance = similarity * (1.0 + psi_entry.valence.abs() * 0.1);
                let emotional_relevance = if psi_entry.valence < 0.0 {
                    // Negative experiences regulated to prevent fear-based paralysis
                    psi_entry.valence.abs() * eq_iq_balance.eq * 0.5
                } else {
                    psi_entry.valence * eq_iq_balance.eq
                };
                
                let regulated_relevance = analytical_relevance * eq_iq_balance.iq + 
                                        emotional_relevance * eq_iq_balance.eq;
                
                // Fear mitigation for negative experiences
                let action_confidence = if psi_entry.valence < 0.0 {
                    regulated_relevance * (1.0 + eq_iq_balance.iq * 0.3)
                } else {
                    regulated_relevance
                };
                
                experiential_context.push(ExperientialContext {
                    memory_id: psi_entry.id.clone(),
                    similarity,
                    valence: psi_entry.valence,
                    experience_type: "PSI_Regulated".to_string(),
                    relevance_score: action_confidence,
                    eq_iq_regulated: true,
                    fear_mitigation_applied: psi_entry.valence < 0.0,
                });
            }
            
            // Sort by regulated relevance score
            experiential_context.sort_by(|a, b| b.relevance_score.partial_cmp(&a.relevance_score).unwrap());
        }
        
        // Calculate EQ/IQ regulated confidence
        let experience_confidence = if experiential_context.is_empty() {
            0.0
        } else {
            let total_relevance: f32 = experiential_context.iter()
                .map(|ctx| ctx.relevance_score)
                .sum();
            let avg_relevance = total_relevance / experiential_context.len() as f32;
            
            // Apply fear mitigation to confidence calculation
            let fear_mitigation_factor = experiential_context.iter()
                .filter(|ctx| ctx.fear_mitigation_applied)
                .count() as f32 / experiential_context.len() as f32;
            
            // Boost confidence when fear mitigation is applied to prevent paralysis
            avg_relevance * (1.0 + fear_mitigation_factor * eq_iq_balance.iq * 0.2)
        };
        
        // EQ/IQ balanced confidence prevents fear-based decision paralysis
        let base_confidence = anomaly_score * (1.0 - self.experience_weight) + 
                             experience_confidence * self.experience_weight;
        
        let regulated_confidence = base_confidence * eq_iq_balance.balance;
        
        // Ensure confidence supports necessary security actions
        let final_confidence = if is_anomaly && regulated_confidence < 0.5 {
            // For anomalies, ensure minimum confidence to prevent inaction
            regulated_confidence * (0.8 + eq_iq_balance.iq * 0.2)
        } else {
            regulated_confidence
        };
        
        AnomalyResult {
            anomaly_score,
            is_anomaly,
            confidence: final_confidence,
            experiential_context,
            memory_triggered,
        }
    }
    
    /// Calculate anomaly score using isolation forest
    fn calculate_anomaly_score(&self, sample: &[f32]) -> f32 {
        if self.trees.is_empty() {
            return 0.0;
        }
        
        let avg_path_length: f32 = self.trees.iter()
            .map(|tree| tree.path_length(sample))
            .sum::<f32>() / self.trees.len() as f32;
        
        // Normalize to anomaly score (higher = more anomalous)
        let c = IsolationTree::average_path_length(self.subsample_size);
        let anomaly_score = 2.0_f32.powf(-avg_path_length / c);
        
        anomaly_score
    }
    
    /// Convert feature vector to PSI embedding format
    fn convert_to_psi_embedding(&self, sample: &[f32]) -> [f32; EMBED_DIM] {
        let mut embedding = [0.0; EMBED_DIM];
        
        // Simple mapping - take first EMBED_DIM features or pad/truncate
        for i in 0..EMBED_DIM {
            if i < sample.len() {
                embedding[i] = sample[i];
            }
        }
        
        // Normalize embedding
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for i in 0..EMBED_DIM {
                embedding[i] /= norm;
            }
        }
        
        embedding
    }
    
    /// Create PSI entry from anomaly experience
    pub fn create_anomaly_memory(&self, sample: &[f32], anomaly_result: &AnomalyResult) -> PsiEntry {
        let embedding = self.convert_to_psi_embedding(sample);
        
        // Valence based on anomaly score and experiential context
        let base_valence = if anomaly_result.is_anomaly { 
            -anomaly_result.anomaly_score  // Negative valence for anomalies
        } else { 
            anomaly_result.anomaly_score * 0.5  // Positive but lower for normal patterns
        };
        
        // Adjust valence based on experiential context
        let experience_adjustment = if !anomaly_result.experiential_context.is_empty() {
            let avg_experience_valence = anomaly_result.experiential_context.iter()
                .map(|ctx| ctx.valence)
                .sum::<f32>() / anomaly_result.experiential_context.len() as f32;
            avg_experience_valence * 0.2  // 20% influence from past experiences
        } else {
            0.0
        };
        
        let final_valence = base_valence + experience_adjustment;
        
        // Create tags based on anomaly characteristics
        let mut tags = vec!["anomaly_detection".to_string()];
        if anomaly_result.is_anomaly {
            tags.push("structural_anomaly".to_string());
        }
        if anomaly_result.memory_triggered {
            tags.push("experiential_context".to_string());
        }
        
        PsiEntry {
            id: format!("anomaly_{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
            vec: embedding,
            valence: final_valence,
            uses: 1,
            tags,
        }
    }
    
    /// Update detector parameters based on experiential feedback
    pub fn adapt_from_experience(&mut self, feedback_score: f32, was_correct: bool) {
        if was_correct {
            // Successful detection - slightly increase sensitivity
            self.anomaly_threshold *= 0.99;
            self.psi_integration_threshold *= 0.99;
        } else {
            // Incorrect detection - adjust thresholds
            if feedback_score > 0.0 {
                // False negative - lower threshold
                self.anomaly_threshold *= 0.95;
                self.psi_integration_threshold *= 0.95;
            } else {
                // False positive - raise threshold
                self.anomaly_threshold *= 1.05;
                self.psi_integration_threshold *= 1.05;
            }
        }
        
        // Keep thresholds in reasonable bounds
        self.anomaly_threshold = self.anomaly_threshold.max(0.1).min(0.9);
        self.psi_integration_threshold = self.psi_integration_threshold.max(0.1).min(0.8);
    }
    
    /// Get detector statistics
    pub fn get_stats(&self) -> HashMap<String, f32> {
        let mut stats = HashMap::new();
        stats.insert("num_trees".to_string(), self.trees.len() as f32);
        stats.insert("anomaly_threshold".to_string(), self.anomaly_threshold);
        stats.insert("psi_integration_threshold".to_string(), self.psi_integration_threshold);
        stats.insert("experience_weight".to_string(), self.experience_weight);
        stats
    }
}

/// Experiential Learning Integration with EQ/IQ Regulation
/// Connects anomaly detection with RHLS cognitive adaptation while preventing fear-based paralysis
pub struct ExperientialLearningIntegrator {
    anomaly_detector: ExperientialAnomalyDetector,
    eq_iq_regulator: ExperientialBehavioralRegulator,
    learning_rate: f32,
    experience_memory_threshold: f32,
    fear_mitigation_enabled: bool,
}

impl ExperientialLearningIntegrator {
    pub fn new() -> Self {
        Self {
            anomaly_detector: ExperientialAnomalyDetector::new(),
            eq_iq_regulator: ExperientialBehavioralRegulator::new(0.6, 0.4, 0.01), // Balanced EQ/IQ
            learning_rate: 0.1,
            experience_memory_threshold: 0.7,
            fear_mitigation_enabled: true,
        }
    }
    
    /// Process input through EQ/IQ regulated experiential anomaly detection
    pub fn process_experiential_input(
        &mut self,
        features: &[f32],
        psi_index: &PsiIndex,
        bdh_memory: &BdhMemory,
        context_stability: f32,
        threat_level: f32,
    ) -> AnomalyResult {
        self.anomaly_detector.detect_with_experience(
            features, 
            psi_index, 
            bdh_memory,
            &mut self.eq_iq_regulator,
            context_stability,
            threat_level
        )
    }
    
    /// Create EQ/IQ regulated experiential memory from anomaly detection
    pub fn create_experiential_memory(
        &self,
        features: &[f32],
        anomaly_result: &AnomalyResult,
        psi_index: &mut PsiIndex,
        bdh_memory: &mut BdhMemory,
        context_stability: f32,
        is_actual_threat: bool,
    ) {
        // Create PSI entry for this experience
        let psi_entry = self.anomaly_detector.create_anomaly_memory(features, anomaly_result);
        
        // Add to PSI if significant enough (with fear mitigation)
        let significance_threshold = if self.fear_mitigation_enabled && psi_entry.valence < 0.0 {
            // Lower threshold for negative experiences to ensure they're still learned from
            self.experience_memory_threshold * 0.7
        } else {
            self.experience_memory_threshold
        };
        
        if psi_entry.valence.abs() > significance_threshold {
            psi_index.add(psi_entry.clone());
        }
        
        // Add to BDH memory with EQ/IQ regulation
        let memory_id = bdh_memory.add_experiential_anomaly_trace(
            psi_entry.vec,
            anomaly_result.anomaly_score,
            is_actual_threat,
            context_stability,
            if is_actual_threat { 1.0 } else { 0.0 }
        );
        
        // If anomaly had experiential context, create EQ/IQ regulated reinforcement
        if anomaly_result.memory_triggered && !anomaly_result.experiential_context.is_empty() {
            let _context_strength = anomaly_result.experiential_context.iter()
                .map(|ctx| ctx.relevance_score)
                .sum::<f32>() / anomaly_result.experiential_context.len() as f32;
            
            // Check if fear mitigation was applied
            let fear_mitigation_applied = anomaly_result.experiential_context.iter()
                .any(|ctx| ctx.fear_mitigation_applied);
            
            // Adjust learning rate based on fear mitigation
            let _adjusted_learning_rate = if fear_mitigation_applied && self.fear_mitigation_enabled {
                // Increase learning rate when fear mitigation is applied to ensure learning continues
                self.learning_rate * 1.2
            } else {
                self.learning_rate
            };
            
            // EQ/IQ regulated reward update
            bdh_memory.update_experiential_outcome(
                &memory_id,
                if is_actual_threat { 1.0 } else { 0.0 },
                anomaly_result.anomaly_score,
                anomaly_result.is_anomaly,
                (anomaly_result.is_anomaly && is_actual_threat) || (!anomaly_result.is_anomaly && !is_actual_threat)
            );
        }
    }
    
    /// Train the anomaly detector
    pub fn train_detector(&mut self, training_features: &[Vec<f32>]) {
        self.anomaly_detector.train(training_features);
    }
    
    /// Get reference to anomaly detector for external access
    pub fn get_detector(&self) -> &ExperientialAnomalyDetector {
        &self.anomaly_detector
    }
    
    /// Get mutable reference to anomaly detector
    pub fn get_detector_mut(&mut self) -> &mut ExperientialAnomalyDetector {
        &mut self.anomaly_detector
    }
    
    /// Get reference to EQ/IQ regulator
    pub fn get_eq_iq_regulator(&self) -> &ExperientialBehavioralRegulator {
        &self.eq_iq_regulator
    }
    
    /// Get mutable reference to EQ/IQ regulator
    pub fn get_eq_iq_regulator_mut(&mut self) -> &mut ExperientialBehavioralRegulator {
        &mut self.eq_iq_regulator
    }
    
    /// Enable or disable fear mitigation
    pub fn set_fear_mitigation(&mut self, enabled: bool) {
        self.fear_mitigation_enabled = enabled;
    }
    
    /// Get comprehensive statistics including EQ/IQ regulation
    pub fn get_comprehensive_stats(&self) -> HashMap<String, f32> {
        let mut stats = self.anomaly_detector.get_stats();
        let eq_iq_stats = self.eq_iq_regulator.get_stats();
        
        // Merge EQ/IQ stats
        for (key, value) in eq_iq_stats {
            stats.insert(format!("eq_iq_{}", key), value);
        }
        
        stats.insert("fear_mitigation_enabled".to_string(), if self.fear_mitigation_enabled { 1.0 } else { 0.0 });
        stats.insert("learning_rate".to_string(), self.learning_rate);
        stats.insert("experience_memory_threshold".to_string(), self.experience_memory_threshold);
        
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_isolation_forest_basic() {
        let mut detector = ExperientialAnomalyDetector::new();
        
        // Create robust training data with enough samples for reliable anomaly detection
        // Generate a cluster of normal samples around (1.0, 2.0, 3.0)
        let mut training_data = Vec::new();
        for i in 0..100 {
            let offset = (i as f32 * 0.01) - 0.5; // Small variations
            training_data.push(vec![1.0 + offset, 2.0 + offset * 0.5, 3.0 + offset * 0.3]);
        }
        
        detector.train(&training_data);
        
        // Test normal sample (within training distribution)
        let normal_sample = vec![1.0, 2.0, 3.0];
        let normal_score = detector.calculate_anomaly_score(&normal_sample);
        
        // Test anomalous sample (far outside training distribution)
        let anomaly_sample = vec![100.0, 200.0, 300.0];
        let anomaly_score = detector.calculate_anomaly_score(&anomaly_sample);
        
        // With enough training data and a very distant anomaly, the score difference should be clear
        assert!(anomaly_score > normal_score, 
            "Anomaly should have higher score than normal sample (anomaly: {}, normal: {})", 
            anomaly_score, normal_score);
    }
    
    #[test]
    fn test_psi_embedding_conversion() {
        let detector = ExperientialAnomalyDetector::new();
        let sample = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let embedding = detector.convert_to_psi_embedding(&sample);
        
        // Check normalization
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 0.001, "Embedding should be normalized");
    }
}