/// Retrospective Learning System for WebGuard
/// 
/// This module implements learning from false negatives - cases where threats were missed
/// and later discovered. In nature, we learn more from mistakes than successes, and this
/// system captures that principle for cybersecurity.

use std::collections::{HashMap, VecDeque};
use serde::{Serialize, Deserialize};
use tracing::{info, warn, debug};

use crate::eq_iq_regulator::{ExperientialBehavioralRegulator, ContextEvent, FeedbackEvent};
use crate::memory_engine::bdh_memory::BdhMemory;

/// Represents a threat that was initially missed but later discovered
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissedThreatEvent {
    /// When the threat originally occurred
    pub original_timestamp: f64,
    /// When the threat was discovered/confirmed
    pub discovery_timestamp: f64,
    /// Original threat score given (should be low for false negative)
    pub original_threat_score: f32,
    /// Actual threat level (should be high)
    pub actual_threat_level: f32,
    /// Feature vector of the missed threat
    pub feature_vector: Vec<f32>,
    /// Context when the threat occurred
    pub original_context: ContextEvent,
    /// How the threat was eventually discovered
    pub discovery_method: ThreatDiscoveryMethod,
    /// Severity of the consequences from missing this threat
    pub consequence_severity: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatDiscoveryMethod {
    /// Discovered through manual security audit
    SecurityAudit,
    /// Found through incident response investigation
    IncidentResponse,
    /// Detected by external security tools
    ExternalDetection,
    /// Reported by users/administrators
    UserReport,
    /// Found through forensic analysis
    ForensicAnalysis,
    /// Discovered through threat intelligence correlation
    ThreatIntelligence,
}

/// Retrospective learning system that learns from missed threats
#[derive(Debug)]
pub struct RetrospectiveLearningSystem {
    /// History of missed threats for learning
    missed_threat_history: VecDeque<MissedThreatEvent>,
    /// Maximum number of missed threats to remember
    max_history_size: usize,
    /// Learning rate multiplier for false negative corrections
    false_negative_learning_rate: f32,
    /// Temporal decay factor for retrospective learning
    temporal_decay_factor: f32,
    /// Pattern similarity threshold for retrospective pattern matching
    similarity_threshold: f32,
    /// Statistics on retrospective learning effectiveness
    learning_stats: RetrospectiveLearningStats,
}

#[derive(Debug, Default, Clone)]
pub struct RetrospectiveLearningStats {
    pub total_missed_threats_processed: usize,
    pub patterns_reinforced: usize,
    pub eq_iq_adjustments_made: usize,
    pub memory_corrections_applied: usize,
    pub avg_discovery_delay: f32,
    pub avg_consequence_severity: f32,
}

impl RetrospectiveLearningSystem {
    pub fn new() -> Self {
        Self {
            missed_threat_history: VecDeque::new(),
            max_history_size: 1000,
            false_negative_learning_rate: 2.0, // Higher learning rate for mistakes
            temporal_decay_factor: 0.95,
            similarity_threshold: 0.7,
            learning_stats: RetrospectiveLearningStats::default(),
        }
    }

    /// Add a newly discovered missed threat for retrospective learning
    pub fn add_missed_threat(&mut self, missed_threat: MissedThreatEvent) {
        info!("Adding missed threat for retrospective learning: discovery_delay={:.2}h, severity={:.3}", 
              (missed_threat.discovery_timestamp - missed_threat.original_timestamp) / 3600.0,
              missed_threat.consequence_severity);

        // Update statistics
        self.learning_stats.total_missed_threats_processed += 1;
        let discovery_delay = (missed_threat.discovery_timestamp - missed_threat.original_timestamp) as f32;
        self.learning_stats.avg_discovery_delay = 
            (self.learning_stats.avg_discovery_delay * (self.learning_stats.total_missed_threats_processed - 1) as f32 + discovery_delay) 
            / self.learning_stats.total_missed_threats_processed as f32;
        
        self.learning_stats.avg_consequence_severity = 
            (self.learning_stats.avg_consequence_severity * (self.learning_stats.total_missed_threats_processed - 1) as f32 + missed_threat.consequence_severity) 
            / self.learning_stats.total_missed_threats_processed as f32;

        // Add to history
        self.missed_threat_history.push_back(missed_threat);
        
        // Maintain history size limit
        if self.missed_threat_history.len() > self.max_history_size {
            self.missed_threat_history.pop_front();
        }
    }

    /// Apply retrospective learning to EQ/IQ regulator based on missed threats
    pub fn apply_retrospective_eq_iq_learning(&mut self, 
                                              regulator: &mut ExperientialBehavioralRegulator,
                                              current_timestamp: f64) {
        if self.missed_threat_history.is_empty() {
            return;
        }

        info!("Applying retrospective EQ/IQ learning from {} missed threats", 
              self.missed_threat_history.len());

        for missed_threat in &self.missed_threat_history {
            // Calculate temporal weight (more recent discoveries have higher impact)
            let time_since_discovery = current_timestamp - missed_threat.discovery_timestamp;
            let temporal_weight = self.temporal_decay_factor.powf((time_since_discovery / 86400.0) as f32); // Daily decay

            // Create corrective feedback event
            let corrective_feedback = FeedbackEvent {
                timestamp: missed_threat.discovery_timestamp,
                predicted_threat: missed_threat.original_threat_score,
                actual_threat: missed_threat.actual_threat_level,
                accuracy: 1.0 - (missed_threat.actual_threat_level - missed_threat.original_threat_score).abs(),
            };

            // Apply enhanced learning with higher learning rate for false negatives
            let enhanced_learning_rate = self.false_negative_learning_rate * temporal_weight * missed_threat.consequence_severity;
            
            // Create corrective context event to improve EQ
            let corrective_context = ContextEvent {
                timestamp: missed_threat.discovery_timestamp,
                context_stability: missed_threat.original_context.context_stability * 0.5, // Reduce stability due to missed threat
                threat_level: missed_threat.actual_threat_level,
                response_appropriateness: 0.1, // Very low appropriateness for missing the threat
            };
            
            // Apply the corrective learning through EQ/IQ balance calculation
            let _balance = regulator.calculate_eq_iq_balance(&corrective_context, &corrective_feedback);
            
            // Apply performance feedback based on the severity of the miss
            let performance_feedback = -missed_threat.consequence_severity * temporal_weight;
            regulator.adapt_parameters(performance_feedback);
            
            self.learning_stats.eq_iq_adjustments_made += 1;
        }

        debug!("Retrospective EQ/IQ learning complete: {} adjustments made", 
               self.learning_stats.eq_iq_adjustments_made);
    }

    /// Apply retrospective learning to memory system
    pub fn apply_retrospective_memory_learning(&mut self, 
                                               memory: &mut BdhMemory,
                                               current_timestamp: f64) {
        if self.missed_threat_history.is_empty() {
            return;
        }

        info!("Applying retrospective memory learning from {} missed threats", 
              self.missed_threat_history.len());

        for missed_threat in &self.missed_threat_history {
            // Calculate temporal weight
            let time_since_discovery = current_timestamp - missed_threat.discovery_timestamp;
            let temporal_weight = self.temporal_decay_factor.powf((time_since_discovery / 86400.0) as f32);

            // Create a corrective memory trace with high negative valence
            let feature_array: [f32; 32] = {
                let mut arr = [0.0; 32];
                for (i, &val) in missed_threat.feature_vector.iter().take(32).enumerate() {
                    arr[i] = val;
                }
                // Fill remaining slots with derived features if needed
                if missed_threat.feature_vector.len() < 32 {
                    for i in missed_threat.feature_vector.len()..32 {
                        arr[i] = missed_threat.actual_threat_level * 0.1; // Small threat-related values
                    }
                }
                arr
            };

            // Add the missed threat pattern with strong negative valence
            let corrective_valence = -missed_threat.consequence_severity * temporal_weight;
            let _trace_id = memory.add_trace(feature_array, corrective_valence);

            self.learning_stats.memory_corrections_applied += 1;
        }

        debug!("Retrospective memory learning complete: {} corrections applied", 
               self.learning_stats.memory_corrections_applied);
    }

    /// Find similar patterns to a missed threat in current feature vectors
    pub fn find_similar_missed_threat_patterns(&self, current_features: &[f32]) -> Vec<&MissedThreatEvent> {
        let mut similar_threats = Vec::new();

        for missed_threat in &self.missed_threat_history {
            let similarity = self.calculate_feature_similarity(current_features, &missed_threat.feature_vector);
            
            if similarity > self.similarity_threshold {
                similar_threats.push(missed_threat);
                debug!("Found similar missed threat pattern: similarity={:.3}, original_score={:.3}, actual_threat={:.3}",
                       similarity, missed_threat.original_threat_score, missed_threat.actual_threat_level);
            }
        }

        // Sort by similarity (highest first)
        similar_threats.sort_by(|a, b| {
            let sim_a = self.calculate_feature_similarity(current_features, &a.feature_vector);
            let sim_b = self.calculate_feature_similarity(current_features, &b.feature_vector);
            sim_b.partial_cmp(&sim_a).unwrap_or(std::cmp::Ordering::Equal)
        });

        similar_threats
    }

    /// Calculate threat score adjustment based on similar missed threats
    pub fn calculate_threat_score_adjustment(&self, current_features: &[f32], base_score: f32) -> f32 {
        let similar_threats = self.find_similar_missed_threat_patterns(current_features);
        
        if similar_threats.is_empty() {
            return base_score;
        }

        // Calculate weighted adjustment based on similar missed threats
        let mut total_weight = 0.0;
        let mut weighted_adjustment = 0.0;

        for missed_threat in similar_threats.iter().take(5) { // Consider top 5 similar threats
            let similarity = self.calculate_feature_similarity(current_features, &missed_threat.feature_vector);
            let weight = similarity * missed_threat.consequence_severity;
            
            // Adjustment should increase threat score for patterns similar to missed threats
            let adjustment = (missed_threat.actual_threat_level - missed_threat.original_threat_score) * weight;
            
            weighted_adjustment += adjustment;
            total_weight += weight;
        }

        let final_adjustment = if total_weight > 0.0 {
            weighted_adjustment / total_weight
        } else {
            0.0
        };

        let adjusted_score = (base_score + final_adjustment).clamp(0.0, 1.0);
        
        if final_adjustment > 0.1 {
            warn!("Retrospective learning adjustment: base_score={:.3} -> adjusted_score={:.3} (adjustment={:.3})",
                  base_score, adjusted_score, final_adjustment);
        }

        adjusted_score
    }

    /// Calculate cosine similarity between feature vectors
    fn calculate_feature_similarity(&self, features1: &[f32], features2: &[f32]) -> f32 {
        let min_len = features1.len().min(features2.len());
        if min_len == 0 {
            return 0.0;
        }

        let mut dot_product = 0.0;
        let mut norm1 = 0.0;
        let mut norm2 = 0.0;

        for i in 0..min_len {
            dot_product += features1[i] * features2[i];
            norm1 += features1[i] * features1[i];
            norm2 += features2[i] * features2[i];
        }

        if norm1 == 0.0 || norm2 == 0.0 {
            return 0.0;
        }

        dot_product / (norm1.sqrt() * norm2.sqrt())
    }

    /// Get statistics about retrospective learning
    pub fn get_learning_stats(&self) -> &RetrospectiveLearningStats {
        &self.learning_stats
    }

    /// Clear old missed threats beyond retention period
    pub fn cleanup_old_threats(&mut self, current_timestamp: f64, retention_days: f64) {
        let retention_seconds = retention_days * 86400.0;
        
        while let Some(front) = self.missed_threat_history.front() {
            if current_timestamp - front.discovery_timestamp > retention_seconds {
                self.missed_threat_history.pop_front();
            } else {
                break;
            }
        }
    }

    /// Export missed threat patterns for analysis
    pub fn export_missed_threat_patterns(&self) -> Vec<HashMap<String, serde_json::Value>> {
        self.missed_threat_history.iter().map(|threat| {
            let mut pattern = HashMap::new();
            pattern.insert("original_timestamp".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(threat.original_timestamp).unwrap()));
            pattern.insert("discovery_timestamp".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(threat.discovery_timestamp).unwrap()));
            pattern.insert("original_threat_score".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(threat.original_threat_score as f64).unwrap()));
            pattern.insert("actual_threat_level".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(threat.actual_threat_level as f64).unwrap()));
            pattern.insert("consequence_severity".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(threat.consequence_severity as f64).unwrap()));
            pattern.insert("discovery_method".to_string(), serde_json::Value::String(format!("{:?}", threat.discovery_method)));
            pattern.insert("discovery_delay_hours".to_string(), serde_json::Value::Number(serde_json::Number::from_f64((threat.discovery_timestamp - threat.original_timestamp) / 3600.0).unwrap()));
            pattern
        }).collect()
    }
}

impl Default for RetrospectiveLearningSystem {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retrospective_learning_system_creation() {
        let system = RetrospectiveLearningSystem::new();
        assert_eq!(system.missed_threat_history.len(), 0);
        assert_eq!(system.max_history_size, 1000);
        assert_eq!(system.false_negative_learning_rate, 2.0);
    }

    #[test]
    fn test_add_missed_threat() {
        let mut system = RetrospectiveLearningSystem::new();
        
        let missed_threat = MissedThreatEvent {
            original_timestamp: 1000.0,
            discovery_timestamp: 2000.0,
            original_threat_score: 0.1,
            actual_threat_level: 0.9,
            feature_vector: vec![0.1, 0.2, 0.3],
            original_context: ContextEvent {
                timestamp: 1000.0,
                context_stability: 0.8,
                threat_level: 0.1,
                response_appropriateness: 0.7,
            },
            discovery_method: ThreatDiscoveryMethod::SecurityAudit,
            consequence_severity: 0.8,
        };

        system.add_missed_threat(missed_threat);
        assert_eq!(system.missed_threat_history.len(), 1);
        assert_eq!(system.learning_stats.total_missed_threats_processed, 1);
    }

    #[test]
    fn test_feature_similarity_calculation() {
        let system = RetrospectiveLearningSystem::new();
        
        let features1 = vec![1.0, 0.0, 0.0];
        let features2 = vec![1.0, 0.0, 0.0];
        let features3 = vec![0.0, 1.0, 0.0];
        
        assert!((system.calculate_feature_similarity(&features1, &features2) - 1.0).abs() < 0.001);
        assert!((system.calculate_feature_similarity(&features1, &features3) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_threat_score_adjustment() {
        let mut system = RetrospectiveLearningSystem::new();
        
        // Add a missed threat
        let missed_threat = MissedThreatEvent {
            original_timestamp: 1000.0,
            discovery_timestamp: 2000.0,
            original_threat_score: 0.2,
            actual_threat_level: 0.9,
            feature_vector: vec![1.0, 0.0, 0.0],
            original_context: ContextEvent {
                timestamp: 1000.0,
                context_stability: 0.8,
                threat_level: 0.2,
                response_appropriateness: 0.7,
            },
            discovery_method: ThreatDiscoveryMethod::IncidentResponse,
            consequence_severity: 0.8,
        };
        
        system.add_missed_threat(missed_threat);
        
        // Test adjustment for similar pattern
        let similar_features = vec![1.0, 0.0, 0.0];
        let adjusted_score = system.calculate_threat_score_adjustment(&similar_features, 0.3);
        
        // Should increase the score due to similar missed threat
        assert!(adjusted_score > 0.3);
    }
}