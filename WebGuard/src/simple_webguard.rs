use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::enhanced_pattern_recognition::{ExperientialKnowledgeBase, ExperientialAnalysisResult};
use crate::adaptive_threshold::{AdaptiveThreshold, ThreatAssessment};

/// Simplified WebGuard System Implementation
/// Uses only the working components for comprehensive threat detection
#[derive(Debug)]
pub struct SimpleWebGuardSystem {
    /// Experiential knowledge base
    pub experiential_kb: ExperientialKnowledgeBase,
    /// Adaptive threshold system
    pub adaptive_threshold: AdaptiveThreshold,
    /// System statistics
    pub stats: SystemStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStats {
    pub total_requests: u64,
    pub threats_detected: u64,
    pub false_positives: u64,
    pub false_negatives: u64,
    pub accuracy: f32,
    pub precision: f32,
    pub recall: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub is_threat: bool,
    pub confidence: f32,
    pub threat_type: Option<String>,
    pub threat_score: f32,
    pub patterns_matched: Vec<String>,
    pub analysis_details: String,
}

impl Default for SystemStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            threats_detected: 0,
            false_positives: 0,
            false_negatives: 0,
            accuracy: 0.0,
            precision: 0.0,
            recall: 0.0,
        }
    }
}

impl SimpleWebGuardSystem {
    /// Create a new WebGuard system instance
    pub fn new() -> Self {
        Self {
            experiential_kb: ExperientialKnowledgeBase::new(),
            adaptive_threshold: AdaptiveThreshold::new(),
            stats: SystemStats::default(),
        }
    }

    /// Analyze a request for threats
    pub fn analyze_request(&mut self, request: &str) -> AnalysisResult {
        self.stats.total_requests += 1;

        // Create a simple context for experiential analysis
        let context = crate::enhanced_pattern_recognition::PatternRequestContext {
            method: "GET".to_string(),
            url: request.to_string(),
            content_type: Some("text/plain".to_string()),
            user_agent: Some("WebGuard-Test".to_string()),
            headers: HashMap::new(),
        };

        // Analyze using experiential knowledge base
        let experiential_result = self.experiential_kb.analyze_experiential(request, &context);
        
        // Simple threshold-based detection (bypass complex adaptive system for now)
        let threat_threshold = 0.3; // Lower threshold for better detection
        let is_threat = experiential_result.overall_threat_score > threat_threshold;
        
        // Calculate confidence based on how far from threshold
        let confidence = if is_threat {
            // For threats, confidence increases with score above threshold
            ((experiential_result.overall_threat_score - threat_threshold) / (1.0 - threat_threshold)).min(1.0)
        } else {
            // For non-threats, confidence increases as score gets further below threshold
            (1.0 - (experiential_result.overall_threat_score / threat_threshold)).max(0.0)
        };

        // Update statistics
        if is_threat {
            self.stats.threats_detected += 1;
        }

        // Determine primary threat type from matched patterns
        let threat_type = if is_threat && !experiential_result.matched_learned_patterns.is_empty() {
            Some(experiential_result.matched_learned_patterns[0].pattern.pattern.clone())
        } else {
            None
        };

        // Create patterns matched list
        let patterns_matched: Vec<String> = experiential_result.matched_learned_patterns.iter()
            .map(|p| p.pattern.pattern.clone())
            .collect();

        // Create analysis details
        let analysis_details = format!(
            "Threat Score: {:.3}, Threshold: {:.3}, Patterns: {}, Indicators: {}",
            experiential_result.overall_threat_score,
            threat_threshold,
            patterns_matched.len(),
            experiential_result.triggered_indicators.len()
        );

        AnalysisResult {
            is_threat,
            confidence,
            threat_type,
            threat_score: experiential_result.overall_threat_score,
            patterns_matched,
            analysis_details,
        }
    }

    /// Update system statistics after validation
    pub fn update_stats(&mut self, predicted_threat: bool, actual_threat: bool) {
        match (predicted_threat, actual_threat) {
            (true, false) => self.stats.false_positives += 1,
            (false, true) => self.stats.false_negatives += 1,
            _ => {}
        }

        // Recalculate metrics
        let total_predictions = self.stats.total_requests;
        let true_positives = self.stats.threats_detected - self.stats.false_positives;
        let true_negatives = total_predictions - self.stats.threats_detected - self.stats.false_negatives;

        if total_predictions > 0 {
            self.stats.accuracy = (true_positives + true_negatives) as f32 / total_predictions as f32;
        }

        if (true_positives + self.stats.false_positives) > 0 {
            self.stats.precision = true_positives as f32 / (true_positives + self.stats.false_positives) as f32;
        }

        if (true_positives + self.stats.false_negatives) > 0 {
            self.stats.recall = true_positives as f32 / (true_positives + self.stats.false_negatives) as f32;
        }
    }

    /// Get current system statistics
    pub fn get_stats(&self) -> &SystemStats {
        &self.stats
    }

    /// Reset system statistics
    pub fn reset_stats(&mut self) {
        self.stats = SystemStats::default();
    }
}

impl Default for SimpleWebGuardSystem {
    fn default() -> Self {
        Self::new()
    }
}