#![allow(dead_code)]

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Adaptive threshold system for dynamic threat detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveThreshold {
    /// Base threshold for general threats
    pub base_threshold: f32,
    /// Threat-specific thresholds
    pub threat_thresholds: HashMap<ThreatType, f32>,
    /// Confidence-based threshold adjustments
    pub confidence_multipliers: HashMap<ConfidenceLevel, f32>,
    /// Historical performance metrics
    pub performance_history: PerformanceHistory,
    /// Dynamic adjustment parameters
    pub adjustment_params: AdjustmentParameters,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThreatType {
    SqlInjection,
    XssAttack,
    PathTraversal,
    CommandInjection,
    FileInclusion,
    EncodingAttack,
    CompositeAttack,
    LegitimateRequest,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    VeryHigh,    // 0.9-1.0
    High,        // 0.7-0.9
    Medium,      // 0.5-0.7
    Low,         // 0.3-0.5
    VeryLow,     // 0.0-0.3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceHistory {
    pub true_positives: u32,
    pub false_positives: u32,
    pub true_negatives: u32,
    pub false_negatives: u32,
    pub recent_accuracy: f32,
    pub recent_precision: f32,
    pub recent_recall: f32,
    pub false_positive_rate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdjustmentParameters {
    pub learning_rate: f32,
    pub min_threshold: f32,
    pub max_threshold: f32,
    pub adjustment_sensitivity: f32,
    pub performance_window: usize,
}

#[derive(Debug, Clone)]
pub struct ThreatAssessment {
    pub threat_type: ThreatType,
    pub confidence_level: ConfidenceLevel,
    pub base_similarity: f32,
    pub adjusted_threshold: f32,
    pub threat_detected: bool,
    pub confidence_score: f32,
}

impl AdaptiveThreshold {
    pub fn new() -> Self {
        let mut threat_thresholds = HashMap::new();
        
        // Initialize threat-specific thresholds based on diagnostic findings
        threat_thresholds.insert(ThreatType::SqlInjection, 0.25);      // Lower for better detection
        threat_thresholds.insert(ThreatType::XssAttack, 0.30);         // Moderate threshold
        threat_thresholds.insert(ThreatType::PathTraversal, 0.35);     // Slightly higher
        threat_thresholds.insert(ThreatType::CommandInjection, 0.28);  // Lower for security
        threat_thresholds.insert(ThreatType::FileInclusion, 0.32);     // Moderate
        threat_thresholds.insert(ThreatType::EncodingAttack, 0.40);    // Higher due to false positives
        threat_thresholds.insert(ThreatType::CompositeAttack, 0.20);   // Very low for complex attacks
        threat_thresholds.insert(ThreatType::LegitimateRequest, 0.70); // High to avoid false positives
        
        let mut confidence_multipliers = HashMap::new();
        confidence_multipliers.insert(ConfidenceLevel::VeryHigh, 0.8);  // Lower threshold for high confidence
        confidence_multipliers.insert(ConfidenceLevel::High, 0.9);      // Slightly lower
        confidence_multipliers.insert(ConfidenceLevel::Medium, 1.0);    // No adjustment
        confidence_multipliers.insert(ConfidenceLevel::Low, 1.2);       // Higher threshold for low confidence
        confidence_multipliers.insert(ConfidenceLevel::VeryLow, 1.5);   // Much higher threshold
        
        Self {
            base_threshold: 0.30, // Much lower than original 0.5
            threat_thresholds,
            confidence_multipliers,
            performance_history: PerformanceHistory::new(),
            adjustment_params: AdjustmentParameters::new(),
        }
    }

    /// Assess threat and determine if it should be flagged
    pub fn assess_threat(&self, features: &[f32; 32]) -> ThreatAssessment {
        let threat_type = self.classify_threat_type(features);
        let confidence_level = self.calculate_confidence_level(features);
        let base_similarity = features[31]; // Composite threat score
        
        let base_threshold = self.threat_thresholds.get(&threat_type)
            .unwrap_or(&self.base_threshold);
        
        let confidence_multiplier = self.confidence_multipliers.get(&confidence_level)
            .unwrap_or(&1.0);
        
        let adjusted_threshold = (base_threshold * confidence_multiplier)
            .max(self.adjustment_params.min_threshold)
            .min(self.adjustment_params.max_threshold);
        
        let threat_detected = base_similarity > adjusted_threshold;
        let confidence_score = self.calculate_confidence_score(base_similarity, adjusted_threshold);
        
        ThreatAssessment {
            threat_type,
            confidence_level,
            base_similarity,
            adjusted_threshold,
            threat_detected,
            confidence_score,
        }
    }

    /// Classify the primary threat type based on feature analysis
    fn classify_threat_type(&self, features: &[f32; 32]) -> ThreatType {
        // SQL Injection indicators (features 1-5)
        let sql_score = (features[1] + features[2] + features[3] + features[4] + features[5]) / 5.0;
        
        // XSS indicators (features 6-10)
        let xss_score = (features[6] + features[7] + features[8] + features[9] + features[10]) / 5.0;
        
        // Path traversal indicators (features 11-15)
        let path_score = (features[11] + features[12] + features[13] + features[14] + features[15]) / 5.0;
        
        // Command injection indicators (features 16-20)
        let cmd_score = (features[16] + features[17] + features[18] + features[19] + features[20]) / 5.0;
        
        // Encoding indicators (features 21-25)
        let encoding_score = (features[21] + features[22] + features[23] + features[24] + features[25]) / 5.0;
        
        // Legitimate request indicators
        let legitimate_score = features[29]; // Legitimate patterns feature
        
        // Determine primary threat type
        let max_score = sql_score.max(xss_score).max(path_score).max(cmd_score).max(encoding_score);
        
        // Check for composite attacks (multiple high scores)
        let high_scores = [sql_score, xss_score, path_score, cmd_score, encoding_score]
            .iter()
            .filter(|&&score| score > 0.4)
            .count();
        
        if high_scores >= 2 {
            return ThreatType::CompositeAttack;
        }
        
        // Check for legitimate request first
        if legitimate_score > 0.6 && max_score < 0.3 {
            return ThreatType::LegitimateRequest;
        }
        
        // Classify based on highest score
        if max_score == sql_score && sql_score > 0.2 {
            ThreatType::SqlInjection
        } else if max_score == xss_score && xss_score > 0.2 {
            ThreatType::XssAttack
        } else if max_score == path_score && path_score > 0.2 {
            ThreatType::PathTraversal
        } else if max_score == cmd_score && cmd_score > 0.2 {
            ThreatType::CommandInjection
        } else if max_score == encoding_score && encoding_score > 0.3 {
            ThreatType::EncodingAttack
        } else {
            ThreatType::LegitimateRequest
        }
    }

    /// Calculate confidence level based on feature consistency and strength
    fn calculate_confidence_level(&self, features: &[f32; 32]) -> ConfidenceLevel {
        let composite_score = features[31];
        let entropy = features[26];
        let complexity = features[30];
        
        // Calculate confidence based on multiple factors
        let mut confidence_factors = Vec::new();
        
        // Factor 1: Composite threat score strength
        confidence_factors.push(composite_score);
        
        // Factor 2: Feature consistency (how many features are active)
        let active_features = features.iter().filter(|&&f| f > 0.1).count() as f32 / 32.0;
        confidence_factors.push(active_features);
        
        // Factor 3: Entropy and complexity alignment
        let entropy_complexity_alignment = 1.0 - (entropy - complexity).abs();
        confidence_factors.push(entropy_complexity_alignment);
        
        // Factor 4: Pattern strength (strong patterns vs weak patterns)
        let strong_patterns = features.iter().filter(|&&f| f > 0.7).count() as f32;
        let weak_patterns = features.iter().filter(|&&f| f > 0.1 && f < 0.3).count() as f32;
        let pattern_strength = if strong_patterns + weak_patterns > 0.0 {
            strong_patterns / (strong_patterns + weak_patterns)
        } else {
            0.0
        };
        confidence_factors.push(pattern_strength);
        
        // Calculate overall confidence
        let overall_confidence = confidence_factors.iter().sum::<f32>() / confidence_factors.len() as f32;
        
        // Map to confidence levels
        if overall_confidence >= 0.8 {
            ConfidenceLevel::VeryHigh
        } else if overall_confidence >= 0.6 {
            ConfidenceLevel::High
        } else if overall_confidence >= 0.4 {
            ConfidenceLevel::Medium
        } else if overall_confidence >= 0.2 {
            ConfidenceLevel::Low
        } else {
            ConfidenceLevel::VeryLow
        }
    }

    /// Calculate confidence score for the detection decision
    fn calculate_confidence_score(&self, similarity: f32, threshold: f32) -> f32 {
        if similarity > threshold {
            // Threat detected - confidence based on how far above threshold
            let excess = similarity - threshold;
            let max_excess = 1.0 - threshold;
            if max_excess > 0.0 {
                0.5 + (excess / max_excess) * 0.5
            } else {
                1.0
            }
        } else {
            // No threat - confidence based on how far below threshold
            let deficit = threshold - similarity;
            let max_deficit = threshold;
            if max_deficit > 0.0 {
                0.5 + (deficit / max_deficit) * 0.5
            } else {
                1.0
            }
        }
    }

    /// Update performance metrics and adjust thresholds
    pub fn update_performance(&mut self, assessment: &ThreatAssessment, actual_threat: bool) {
        // Update performance history
        match (assessment.threat_detected, actual_threat) {
            (true, true) => self.performance_history.true_positives += 1,
            (true, false) => self.performance_history.false_positives += 1,
            (false, false) => self.performance_history.true_negatives += 1,
            (false, true) => self.performance_history.false_negatives += 1,
        }
        
        // Recalculate metrics
        self.performance_history.update_metrics();
        
        // Adjust thresholds based on performance
        self.adjust_thresholds(assessment, actual_threat);
    }

    /// Dynamically adjust thresholds based on performance feedback
    fn adjust_thresholds(&mut self, assessment: &ThreatAssessment, actual_threat: bool) {
        let learning_rate = self.adjustment_params.learning_rate;
        let current_threshold = assessment.adjusted_threshold;
        
        let adjustment = match (assessment.threat_detected, actual_threat) {
            (true, false) => {
                // False positive - increase threshold with balanced learning rate
                let fp_adjustment = learning_rate * 0.8; // Increased from 0.3 for balance
                // Apply regularization to prevent overcorrection
                fp_adjustment * (1.0 - self.performance_history.false_positive_rate * 0.3)
            },
            (false, true) => {
                // False negative - decrease threshold with moderated aggression
                let confidence_gap = current_threshold - assessment.base_similarity;
                let fn_adjustment = -learning_rate * (0.8 + confidence_gap * 1.0); // Reduced aggression
                fn_adjustment.max(-0.10) // Reduced cap from 15% to 10% per false negative
            },
            _ => {
                // Correct prediction - small adjustment toward optimal
                let optimal_threshold = if actual_threat {
                    assessment.base_similarity * 0.9 // Slightly below similarity for threats
                } else {
                    assessment.base_similarity * 1.1 // Slightly above similarity for non-threats
                };
                (optimal_threshold - current_threshold) * learning_rate * 0.1
            }
        };
        
        // Apply adjustment to threat-specific threshold
        if let Some(threshold) = self.threat_thresholds.get_mut(&assessment.threat_type) {
            *threshold = (*threshold + adjustment)
                .max(self.adjustment_params.min_threshold)
                .min(self.adjustment_params.max_threshold);
        }
        
        // Also adjust base threshold slightly
        self.base_threshold = (self.base_threshold + adjustment * 0.5)
            .max(self.adjustment_params.min_threshold)
            .min(self.adjustment_params.max_threshold);
    }

    /// Get current performance metrics
    pub fn get_performance_metrics(&self) -> &PerformanceHistory {
        &self.performance_history
    }

    /// Get threshold for specific threat type
    pub fn get_threshold_for_threat(&self, threat_type: &ThreatType) -> f32 {
        self.threat_thresholds.get(threat_type)
            .unwrap_or(&self.base_threshold)
            .clone()
    }

    /// Reset performance history
    pub fn reset_performance_history(&mut self) {
        self.performance_history = PerformanceHistory::new();
    }
}

impl PerformanceHistory {
    pub fn new() -> Self {
        Self {
            true_positives: 0,
            false_positives: 0,
            true_negatives: 0,
            false_negatives: 0,
            recent_accuracy: 0.0,
            recent_precision: 0.0,
            recent_recall: 0.0,
            false_positive_rate: 0.0,
        }
    }

    pub fn update_metrics(&mut self) {
        let total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives;
        
        if total > 0 {
            self.recent_accuracy = (self.true_positives + self.true_negatives) as f32 / total as f32;
        }
        
        let predicted_positives = self.true_positives + self.false_positives;
        if predicted_positives > 0 {
            self.recent_precision = self.true_positives as f32 / predicted_positives as f32;
        }
        
        let actual_positives = self.true_positives + self.false_negatives;
        if actual_positives > 0 {
            self.recent_recall = self.true_positives as f32 / actual_positives as f32;
        }
        
        let actual_negatives = self.true_negatives + self.false_positives;
        if actual_negatives > 0 {
            self.false_positive_rate = self.false_positives as f32 / actual_negatives as f32;
        }
    }

    pub fn get_f1_score(&self) -> f32 {
        if self.recent_precision + self.recent_recall > 0.0 {
            2.0 * (self.recent_precision * self.recent_recall) / (self.recent_precision + self.recent_recall)
        } else {
            0.0
        }
    }
}

impl AdjustmentParameters {
    pub fn new() -> Self {
        Self {
            learning_rate: 0.15,        // Aggressive learning rate for security-first approach
            min_threshold: 0.05,        // Minimum threshold to prevent over-sensitivity
            max_threshold: 0.85,        // Maximum threshold to ensure detection capability
            adjustment_sensitivity: 0.3, // High sensitivity to performance changes
            performance_window: 100,     // Number of samples to consider for adjustments
        }
    }
}

impl Default for AdaptiveThreshold {
    fn default() -> Self {
        Self::new()
    }
}