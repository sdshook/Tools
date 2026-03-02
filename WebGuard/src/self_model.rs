/// Self-Model Node: Metacognitive monitoring for BHSM Cognitive Layer
/// 
/// The Self-Model Node continuously assesses three properties of the system's cognitive state:
/// - **Coherence**: How well reasoning is internally integrated
/// - **Confidence**: The system's self-assessed certainty
/// - **Arrogance**: Overconfidence detection (high confidence with poor outcomes)
/// 
/// This implements the BHSM requirement that the ValenceController penalizes 
/// high-confidence predictions that produce poor outcomes.

use std::collections::VecDeque;

/// Maximum history length for tracking predictions and outcomes
const HISTORY_SIZE: usize = 100;

/// Prediction outcome for learning
#[derive(Debug, Clone)]
pub struct PredictionOutcome {
    /// The confidence level when prediction was made (0.0 - 1.0)
    pub confidence: f32,
    /// The threat score predicted (0.0 - 1.0)
    pub predicted_threat: f32,
    /// Whether the prediction was correct (true positive or true negative)
    pub was_correct: bool,
    /// True if this was a false negative (missed threat - critical error)
    pub was_false_negative: bool,
    /// True if this was a false positive (blocked benign - operational error)
    pub was_false_positive: bool,
}

/// Self-Model Node for metacognitive monitoring
#[derive(Debug)]
pub struct SelfModelNode {
    /// Recent prediction outcomes for learning
    prediction_history: VecDeque<PredictionOutcome>,
    
    /// Current coherence score (0.0 - 1.0)
    /// Measures internal consistency of reasoning
    coherence: f32,
    
    /// Current confidence calibration
    /// Ratio of actual accuracy to stated confidence
    confidence_calibration: f32,
    
    /// Current arrogance score (0.0 - 1.0)
    /// High values indicate overconfidence (high confidence + poor outcomes)
    arrogance: f32,
    
    /// Running count of high-confidence errors
    high_confidence_errors: usize,
    
    /// Running count of high-confidence predictions
    high_confidence_predictions: usize,
    
    /// Arrogance penalty coefficient (applied to confidence)
    arrogance_penalty: f32,
    
    /// Threshold above which confidence is considered "high"
    high_confidence_threshold: f32,
}

impl Default for SelfModelNode {
    fn default() -> Self {
        Self::new()
    }
}

impl SelfModelNode {
    /// Create a new Self-Model Node
    pub fn new() -> Self {
        Self {
            prediction_history: VecDeque::with_capacity(HISTORY_SIZE),
            coherence: 1.0,           // Start with full coherence
            confidence_calibration: 1.0, // Start calibrated
            arrogance: 0.0,           // Start humble
            high_confidence_errors: 0,
            high_confidence_predictions: 0,
            arrogance_penalty: 0.0,
            high_confidence_threshold: 0.8,
        }
    }
    
    /// Record a prediction outcome for metacognitive learning
    pub fn record_outcome(&mut self, outcome: PredictionOutcome) {
        // Track high-confidence predictions specially for arrogance detection
        if outcome.confidence >= self.high_confidence_threshold {
            self.high_confidence_predictions += 1;
            if !outcome.was_correct {
                self.high_confidence_errors += 1;
            }
        }
        
        // Add to history
        if self.prediction_history.len() >= HISTORY_SIZE {
            self.prediction_history.pop_front();
        }
        self.prediction_history.push_back(outcome);
        
        // Update metacognitive metrics
        self.update_coherence();
        self.update_confidence_calibration();
        self.update_arrogance();
    }
    
    /// Update coherence based on prediction consistency
    fn update_coherence(&mut self) {
        if self.prediction_history.len() < 5 {
            return; // Need sufficient history
        }
        
        // Coherence measures how consistent our threat assessments are
        // Low coherence = erratic predictions, high variance in outcomes
        let recent: Vec<&PredictionOutcome> = self.prediction_history.iter()
            .rev().take(20).collect();
        
        if recent.is_empty() {
            return;
        }
        
        // Calculate variance in prediction accuracy
        let accuracy_sum: f32 = recent.iter()
            .map(|o| if o.was_correct { 1.0 } else { 0.0 })
            .sum();
        let accuracy = accuracy_sum / recent.len() as f32;
        
        // Calculate variance in confidence levels
        let conf_mean: f32 = recent.iter().map(|o| o.confidence).sum::<f32>() / recent.len() as f32;
        let conf_variance: f32 = recent.iter()
            .map(|o| (o.confidence - conf_mean).powi(2))
            .sum::<f32>() / recent.len() as f32;
        
        // High accuracy + low variance = high coherence
        let stability = 1.0 - conf_variance.sqrt().min(1.0);
        self.coherence = (accuracy * 0.7 + stability * 0.3).clamp(0.0, 1.0);
    }
    
    /// Update confidence calibration (are we as accurate as we claim?)
    fn update_confidence_calibration(&mut self) {
        if self.prediction_history.len() < 10 {
            return;
        }
        
        // Group predictions by confidence bucket and check actual accuracy
        let mut high_conf_correct = 0;
        let mut high_conf_total = 0;
        
        for outcome in &self.prediction_history {
            if outcome.confidence >= 0.7 {
                high_conf_total += 1;
                if outcome.was_correct {
                    high_conf_correct += 1;
                }
            }
        }
        
        // Calculate actual vs stated accuracy for high-confidence predictions
        let high_conf_accuracy = if high_conf_total > 0 {
            high_conf_correct as f32 / high_conf_total as f32
        } else {
            1.0
        };
        
        // Calibration = actual accuracy / average stated confidence for high-conf predictions
        let avg_high_conf: f32 = self.prediction_history.iter()
            .filter(|o| o.confidence >= 0.7)
            .map(|o| o.confidence)
            .sum::<f32>() / high_conf_total.max(1) as f32;
        
        self.confidence_calibration = if avg_high_conf > 0.0 {
            (high_conf_accuracy / avg_high_conf).clamp(0.0, 2.0)
        } else {
            1.0
        };
    }
    
    /// Update arrogance score (overconfidence detection)
    /// 
    /// Arrogance = high confidence + poor outcomes
    /// This is the key BHSM requirement: penalize predictions where we were
    /// confident but wrong, especially for false negatives (missed threats)
    fn update_arrogance(&mut self) {
        if self.high_confidence_predictions == 0 {
            self.arrogance = 0.0;
            self.arrogance_penalty = 0.0;
            return;
        }
        
        // Weight false negatives more heavily (missed threats while confident = very bad)
        let fn_weight: f32 = self.prediction_history.iter()
            .filter(|o| o.confidence >= self.high_confidence_threshold && o.was_false_negative)
            .count() as f32;
        
        let fp_weight: f32 = self.prediction_history.iter()
            .filter(|o| o.confidence >= self.high_confidence_threshold && o.was_false_positive)
            .count() as f32;
        
        // False negatives are 3x worse than false positives for arrogance
        let weighted_errors = fn_weight * 3.0 + fp_weight;
        let weighted_arrogance = weighted_errors / self.high_confidence_predictions.max(1) as f32;
        
        // Update arrogance with exponential moving average
        self.arrogance = self.arrogance * 0.9 + weighted_arrogance * 0.1;
        self.arrogance = self.arrogance.clamp(0.0, 1.0);
        
        // Calculate penalty to apply to future confidence scores
        // Higher arrogance = more confidence reduction
        self.arrogance_penalty = self.arrogance * 0.3; // Max 30% confidence reduction
    }
    
    /// Get adjusted confidence after applying arrogance penalty
    /// 
    /// This implements the BHSM requirement that the ValenceController
    /// penalizes high-confidence predictions that produce poor outcomes
    pub fn adjust_confidence(&self, raw_confidence: f32) -> f32 {
        // Apply arrogance penalty: reduce confidence when we've been overconfident
        let adjusted = raw_confidence * (1.0 - self.arrogance_penalty);
        
        // Also apply calibration correction
        let calibrated = adjusted * self.confidence_calibration.min(1.0);
        
        calibrated.clamp(0.0, 1.0)
    }
    
    /// Check if current arrogance level requires scrutiny bypass
    /// 
    /// When arrogance is high, even high-confidence predictions should
    /// be treated with suspicion and require additional scrutiny
    pub fn requires_scrutiny(&self, confidence: f32) -> bool {
        // High arrogance + high confidence = definitely needs scrutiny
        if self.arrogance > 0.3 && confidence > 0.7 {
            return true;
        }
        
        // Poor calibration = can't trust confidence scores
        if self.confidence_calibration < 0.7 && confidence > 0.8 {
            return true;
        }
        
        // Low coherence = erratic behavior, scrutinize everything
        if self.coherence < 0.5 {
            return true;
        }
        
        false
    }
    
    /// Get current metacognitive state
    pub fn get_state(&self) -> MetacognitiveState {
        MetacognitiveState {
            coherence: self.coherence,
            confidence_calibration: self.confidence_calibration,
            arrogance: self.arrogance,
            arrogance_penalty: self.arrogance_penalty,
            high_confidence_error_rate: if self.high_confidence_predictions > 0 {
                self.high_confidence_errors as f32 / self.high_confidence_predictions as f32
            } else {
                0.0
            },
            history_size: self.prediction_history.len(),
        }
    }
    
    /// Reset arrogance tracking (e.g., after model update)
    pub fn reset_arrogance_tracking(&mut self) {
        self.high_confidence_errors = 0;
        self.high_confidence_predictions = 0;
        self.arrogance = 0.0;
        self.arrogance_penalty = 0.0;
    }
    
    /// Get coherence score
    pub fn coherence(&self) -> f32 {
        self.coherence
    }
    
    /// Get confidence calibration
    pub fn confidence_calibration(&self) -> f32 {
        self.confidence_calibration
    }
    
    /// Get arrogance score
    pub fn arrogance(&self) -> f32 {
        self.arrogance
    }
}

/// Snapshot of metacognitive state
#[derive(Debug, Clone)]
pub struct MetacognitiveState {
    /// Coherence: internal consistency of reasoning (0.0 - 1.0)
    pub coherence: f32,
    
    /// Confidence calibration: actual accuracy / stated confidence
    pub confidence_calibration: f32,
    
    /// Arrogance: overconfidence score (0.0 - 1.0)
    pub arrogance: f32,
    
    /// Current penalty applied to confidence scores
    pub arrogance_penalty: f32,
    
    /// Error rate for high-confidence predictions
    pub high_confidence_error_rate: f32,
    
    /// Number of predictions in history
    pub history_size: usize,
}

impl std::fmt::Display for MetacognitiveState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Metacognitive[coherence={:.2}, calibration={:.2}, arrogance={:.2}, penalty={:.2}]",
            self.coherence, self.confidence_calibration, self.arrogance, self.arrogance_penalty
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_arrogance_detection() {
        let mut node = SelfModelNode::new();
        
        // Record several high-confidence correct predictions
        for _ in 0..10 {
            node.record_outcome(PredictionOutcome {
                confidence: 0.9,
                predicted_threat: 0.8,
                was_correct: true,
                was_false_negative: false,
                was_false_positive: false,
            });
        }
        
        // Arrogance should be low
        assert!(node.arrogance() < 0.1, "Arrogance should be low after correct predictions");
        
        // Now record high-confidence errors (especially false negatives)
        for _ in 0..5 {
            node.record_outcome(PredictionOutcome {
                confidence: 0.95,
                predicted_threat: 0.2, // Predicted benign
                was_correct: false,
                was_false_negative: true, // But was actually a threat!
                was_false_positive: false,
            });
        }
        
        // Arrogance should increase significantly
        assert!(node.arrogance() > 0.1, "Arrogance should increase after high-confidence FN");
        
        // Confidence should be penalized
        let raw = 0.9;
        let adjusted = node.adjust_confidence(raw);
        assert!(adjusted < raw, "Confidence should be reduced by arrogance penalty");
    }
    
    #[test]
    fn test_coherence_tracking() {
        let mut node = SelfModelNode::new();
        
        // Record consistent predictions
        for i in 0..20 {
            node.record_outcome(PredictionOutcome {
                confidence: 0.7 + (i as f32 * 0.01),
                predicted_threat: 0.5,
                was_correct: true,
                was_false_negative: false,
                was_false_positive: false,
            });
        }
        
        // Coherence should be high
        assert!(node.coherence() > 0.7, "Coherence should be high with consistent predictions");
    }
    
    #[test]
    fn test_scrutiny_requirement() {
        let mut node = SelfModelNode::new();
        
        // Make node arrogant
        for _ in 0..20 {
            node.record_outcome(PredictionOutcome {
                confidence: 0.95,
                predicted_threat: 0.1,
                was_correct: false,
                was_false_negative: true,
                was_false_positive: false,
            });
        }
        
        // High confidence should now require scrutiny
        assert!(node.requires_scrutiny(0.9), "High confidence should require scrutiny when arrogant");
    }
}
