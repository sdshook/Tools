#![allow(dead_code)]

use std::collections::HashMap;
use tracing::{debug, info};

/// EQ/IQ Balanced Reward System for RHLS
/// Implements experiential behavioral regulator with empathy (EQ) and accuracy (IQ) balance
/// Based on: Δwij = η · (xi · yj) · (α · EQ + β · IQ)

#[derive(Debug, Clone)]
pub struct ExperientialBehavioralRegulator {
    /// Historical context for empathy measurement
    context_history: Vec<ContextEvent>,
    /// Feedback accuracy tracking for IQ measurement
    feedback_history: Vec<FeedbackEvent>,
    /// Base EQ weight coefficient (α) - will be adapted based on context
    base_alpha: f32,
    /// Base IQ weight coefficient (β) - will be adapted based on context
    base_beta: f32,
    /// Learning rate (η)
    learning_rate: f32,
    /// Maximum history size to maintain
    max_history: usize,
    /// Temporal decay factor for weighting recent events more heavily
    temporal_decay: f32,
    /// Context adaptation sensitivity (how much threat level affects α/β balance)
    context_sensitivity: f32,
    /// Learning rate for EQ/IQ cross-modal adaptation
    cross_modal_learning_rate: f32,
    /// History of EQ/IQ correlations for cross-modal learning
    pub eq_iq_correlation_history: Vec<f32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContextEvent {
    pub timestamp: f64,
    pub context_stability: f32,
    pub threat_level: f32,
    pub response_appropriateness: f32,
}

#[derive(Debug, Clone)]
pub struct FeedbackEvent {
    pub timestamp: f64,
    pub predicted_threat: f32,
    pub actual_threat: f32,
    pub accuracy: f32,
}

#[derive(Debug, Clone)]
pub struct MultiDimensionalEQ {
    pub contextual_stability: f32,    // Stability in similar contexts
    pub response_appropriateness: f32, // Appropriateness of responses
    pub social_awareness: f32,        // Understanding of social/security context
    pub emotional_regulation: f32,    // Ability to regulate false positive/negative responses
    pub empathic_accuracy: f32,       // Accuracy in understanding benign vs malicious intent
}

impl MultiDimensionalEQ {
    pub fn aggregate(&self) -> f32 {
        (self.contextual_stability + self.response_appropriateness + 
         self.social_awareness + self.emotional_regulation + self.empathic_accuracy) / 5.0
    }

    pub fn weighted_aggregate(&self, weights: &[f32; 5]) -> f32 {
        self.contextual_stability * weights[0] +
        self.response_appropriateness * weights[1] +
        self.social_awareness * weights[2] +
        self.emotional_regulation * weights[3] +
        self.empathic_accuracy * weights[4]
    }
}

#[derive(Debug, Clone)]
pub struct EQIQBalance {
    pub eq: f32,  // Aggregated Emotional Intelligence
    pub eq_vector: MultiDimensionalEQ,  // Multi-dimensional EQ components
    pub iq: f32,  // Intelligence Quotient (threat precision/accuracy)
    pub balance: f32,  // Normalized balance factor
    pub eq_uncertainty: f32,  // Uncertainty in EQ measurement
    pub iq_uncertainty: f32,  // Uncertainty in IQ measurement
    pub confidence: f32,      // Overall confidence in the balance
}

impl ExperientialBehavioralRegulator {
    pub fn new(alpha: f32, beta: f32, learning_rate: f32) -> Self {
        Self {
            context_history: Vec::new(),
            feedback_history: Vec::new(),
            base_alpha: alpha,
            base_beta: beta,
            learning_rate,
            max_history: 1000,
            temporal_decay: 0.95, // Recent events weighted more heavily
            context_sensitivity: 0.6, // How much context affects α/β balance
            cross_modal_learning_rate: 0.1, // Learning rate for EQ/IQ adaptation
            eq_iq_correlation_history: Vec::new(),
        }
    }

    /// Calculate context-adaptive α/β parameters based on current threat level
    /// High threat = favor accuracy (higher β), Low threat = favor empathy (higher α)
    pub fn adaptive_alpha_beta(&self, threat_level: f32) -> (f32, f32) {
        let threat_factor = threat_level.clamp(0.0, 1.0);
        
        // Adaptive adjustment: high threat shifts toward accuracy (IQ)
        let threat_adjustment = self.context_sensitivity * threat_factor;
        
        // Calculate adaptive parameters
        let alpha = (self.base_alpha - threat_adjustment * 0.4).max(0.1);
        let beta = (self.base_beta + threat_adjustment * 0.6).min(0.9);
        
        // Normalize to ensure α + β ≈ 1.0
        let total = alpha + beta;
        (alpha / total, beta / total)
    }

    /// Measure empathy (EQ) based on contextual stability and benign response appropriateness
    pub fn measure_empathy(&self, context: &ContextEvent, history: &[ContextEvent]) -> f32 {
        if history.is_empty() {
            return 0.5; // Neutral starting point
        }

        // Calculate contextual stability over time
        let stability_trend = self.calculate_stability_trend(history);
        
        // Measure benign contextual stability (higher is better for EQ)
        let benign_stability = if context.threat_level < 0.3 {
            context.context_stability * context.response_appropriateness
        } else {
            // For high threat contexts, EQ is about measured, appropriate response
            context.response_appropriateness * (1.0 - context.threat_level.min(0.8))
        };

        // Combine with historical trend
        let eq = (benign_stability * 0.7 + stability_trend * 0.3).clamp(0.0, 1.0);
        
        debug!("EQ measurement: benign_stability={:.3}, stability_trend={:.3}, eq={:.3}", 
               benign_stability, stability_trend, eq);
        
        eq
    }

    /// Measure multi-dimensional empathy (EQ) with vector components
    pub fn measure_multidimensional_empathy(&self, context: &ContextEvent, history: &[ContextEvent]) -> MultiDimensionalEQ {
        if history.is_empty() {
            return MultiDimensionalEQ {
                contextual_stability: 0.5,
                response_appropriateness: context.response_appropriateness,
                social_awareness: 0.5,
                emotional_regulation: 0.5,
                empathic_accuracy: 0.5,
            };
        }

        // 1. Contextual Stability: How stable responses are in similar contexts
        let contextual_stability = self.calculate_stability_trend(history);
        
        // 2. Response Appropriateness: Direct from context
        let response_appropriateness = context.response_appropriateness;
        
        // 3. Social Awareness: Understanding of context type and severity
        let social_awareness = self.calculate_social_awareness(context, history);
        
        // 4. Emotional Regulation: Ability to avoid over/under-reactions
        let emotional_regulation = self.calculate_emotional_regulation(history);
        
        // 5. Empathic Accuracy: Accuracy in distinguishing benign from malicious
        let empathic_accuracy = self.calculate_empathic_accuracy(context, history);

        MultiDimensionalEQ {
            contextual_stability,
            response_appropriateness,
            social_awareness,
            emotional_regulation,
            empathic_accuracy,
        }
    }

    /// Calculate social awareness based on context understanding
    fn calculate_social_awareness(&self, context: &ContextEvent, history: &[ContextEvent]) -> f32 {
        // Measure how well the system understands different context types
        let context_diversity = self.calculate_context_diversity(history);
        let current_context_fit = context.context_stability;
        
        (context_diversity * 0.4 + current_context_fit * 0.6).clamp(0.0, 1.0)
    }

    /// Calculate emotional regulation based on response consistency
    fn calculate_emotional_regulation(&self, history: &[ContextEvent]) -> f32 {
        if history.len() < 3 {
            return 0.5;
        }

        let recent_responses: Vec<f32> = history.iter().rev().take(10)
            .map(|c| c.response_appropriateness).collect();
        
        // Calculate variance in responses (lower variance = better regulation)
        let mean_response = recent_responses.iter().sum::<f32>() / recent_responses.len() as f32;
        let variance = recent_responses.iter()
            .map(|r| (r - mean_response).powi(2))
            .sum::<f32>() / recent_responses.len() as f32;
        
        // Convert variance to regulation score (lower variance = higher regulation)
        (1.0 - variance.min(1.0)).clamp(0.0, 1.0)
    }

    /// Calculate empathic accuracy in distinguishing intent
    fn calculate_empathic_accuracy(&self, context: &ContextEvent, _history: &[ContextEvent]) -> f32 {
        // This would ideally correlate with actual threat detection accuracy
        // For now, use context stability as a proxy
        let stability_factor = context.context_stability;
        let appropriateness_factor = context.response_appropriateness;
        
        (stability_factor * 0.5 + appropriateness_factor * 0.5).clamp(0.0, 1.0)
    }

    /// Calculate diversity of contexts encountered
    fn calculate_context_diversity(&self, history: &[ContextEvent]) -> f32 {
        if history.len() < 2 {
            return 0.3;
        }

        let recent_contexts: Vec<&ContextEvent> = history.iter().rev().take(20).collect();
        let stabilities: Vec<f32> = recent_contexts.iter().map(|c| c.context_stability).collect();
        
        // Calculate range of context stabilities as diversity measure
        let min_stability = stabilities.iter().fold(f32::INFINITY, |a, &b| a.min(b));
        let max_stability = stabilities.iter().fold(f32::NEG_INFINITY, |a, &b| a.max(b));
        let diversity = (max_stability - min_stability).clamp(0.0, 1.0);
        
        diversity
    }

    /// Measure accuracy (IQ) based on threat prediction precision with temporal weighting
    pub fn measure_accuracy(&self, feedback: &FeedbackEvent) -> f32 {
        // Direct accuracy measurement from prediction vs reality
        let prediction_error = (feedback.predicted_threat - feedback.actual_threat).abs();
        let base_accuracy = 1.0 - prediction_error.min(1.0);
        
        // Enhance accuracy based on temporally weighted historical performance
        let historical_accuracy = if self.feedback_history.len() > 2 {
            self.calculate_weighted_accuracy()
        } else {
            base_accuracy
        };

        let iq = (base_accuracy * 0.6 + historical_accuracy * 0.4).clamp(0.0, 1.0);
        
        debug!("IQ measurement: prediction_error={:.3}, base_accuracy={:.3}, historical_accuracy={:.3}, iq={:.3}", 
               prediction_error, base_accuracy, historical_accuracy, iq);
        
        iq
    }

    /// Calculate stability trend from historical context with temporal weighting
    fn calculate_stability_trend(&self, history: &[ContextEvent]) -> f32 {
        if history.len() < 2 {
            return 0.5;
        }

        let recent_events: Vec<&ContextEvent> = history.iter().rev().take(10).collect();
        
        // Calculate weighted stability values with exponential decay
        let mut weighted_sum = 0.0;
        let mut weight_sum = 0.0;
        
        for (i, event) in recent_events.iter().enumerate() {
            let age_weight = self.temporal_decay.powi(i as i32);
            weighted_sum += event.context_stability * age_weight;
            weight_sum += age_weight;
        }
        
        let weighted_avg = if weight_sum > 0.0 { weighted_sum / weight_sum } else { 0.5 };
        
        // Calculate trend with temporal weighting
        let mut trend_sum = 0.0;
        let mut trend_weights = 0.0;
        
        for i in 1..recent_events.len().min(5) {
            let age_weight = self.temporal_decay.powi(i as i32);
            let trend_delta = recent_events[i-1].context_stability - recent_events[i].context_stability;
            trend_sum += trend_delta * age_weight;
            trend_weights += age_weight;
        }
        
        let weighted_trend = if trend_weights > 0.0 { trend_sum / trend_weights } else { 0.0 };
        
        // Combine weighted average with trend
        (weighted_avg + weighted_trend * 0.3).clamp(0.0, 1.0)
    }

    /// Calculate temporally weighted accuracy from feedback history
    fn calculate_weighted_accuracy(&self) -> f32 {
        if self.feedback_history.len() < 2 {
            return 0.5;
        }

        let recent_feedback: Vec<&FeedbackEvent> = self.feedback_history.iter().rev().take(10).collect();
        
        let mut weighted_sum = 0.0;
        let mut weight_sum = 0.0;
        
        for (i, feedback) in recent_feedback.iter().enumerate() {
            let age_weight = self.temporal_decay.powi(i as i32);
            weighted_sum += feedback.accuracy * age_weight;
            weight_sum += age_weight;
        }
        
        if weight_sum > 0.0 { weighted_sum / weight_sum } else { 0.5 }
    }

    /// Calculate non-linear EQ/IQ interaction for more sophisticated balance
    /// Combines multiplicative interaction, sigmoid gating, and adaptive weighting
    fn calculate_nonlinear_balance(&self, eq: f32, iq: f32, alpha: f32, beta: f32) -> f32 {
        // 1. Linear component (traditional α·EQ + β·IQ)
        let linear_component = alpha * eq + beta * iq;
        
        // 2. Multiplicative interaction (EQ and IQ reinforce each other)
        let multiplicative_component = eq * iq;
        
        // 3. Sigmoid gating based on confidence (high confidence amplifies, low confidence dampens)
        let confidence = (eq + iq) / 2.0;
        let sigmoid_gate = 1.0 / (1.0 + (-4.0 * (confidence - 0.5)).exp());
        
        // 4. Adaptive mixing based on threat level and balance
        let eq_iq_difference = (eq - iq).abs();
        let harmony_factor = 1.0 - eq_iq_difference; // Higher when EQ and IQ are aligned
        
        // Combine components with adaptive weighting
        let linear_weight = 0.6;
        let multiplicative_weight = 0.3 * harmony_factor; // More multiplicative when aligned
        let sigmoid_weight = 0.1;
        
        let balance = linear_weight * linear_component 
                    + multiplicative_weight * multiplicative_component 
                    + sigmoid_weight * sigmoid_gate;
        
        balance.clamp(0.0, 1.0)
    }

    /// Calculate uncertainty in EQ measurement based on context variability
    fn calculate_eq_uncertainty(&self) -> f32 {
        if self.context_history.len() < 3 {
            return 0.8; // High uncertainty with limited data
        }

        let recent_contexts: Vec<&ContextEvent> = self.context_history.iter().rev().take(10).collect();
        
        // Calculate variance in context stability
        let stabilities: Vec<f32> = recent_contexts.iter().map(|c| c.context_stability).collect();
        let mean_stability = stabilities.iter().sum::<f32>() / stabilities.len() as f32;
        let variance = stabilities.iter()
            .map(|s| (s - mean_stability).powi(2))
            .sum::<f32>() / stabilities.len() as f32;
        
        // Calculate variance in response appropriateness
        let appropriateness: Vec<f32> = recent_contexts.iter().map(|c| c.response_appropriateness).collect();
        let mean_appropriateness = appropriateness.iter().sum::<f32>() / appropriateness.len() as f32;
        let appropriateness_variance = appropriateness.iter()
            .map(|a| (a - mean_appropriateness).powi(2))
            .sum::<f32>() / appropriateness.len() as f32;
        
        // Higher variance = higher uncertainty
        let uncertainty = (variance + appropriateness_variance) / 2.0;
        uncertainty.clamp(0.0, 1.0)
    }

    /// Calculate uncertainty in IQ measurement based on prediction consistency
    fn calculate_iq_uncertainty(&self) -> f32 {
        if self.feedback_history.len() < 3 {
            return 0.8; // High uncertainty with limited data
        }

        let recent_feedback: Vec<&FeedbackEvent> = self.feedback_history.iter().rev().take(10).collect();
        
        // Calculate variance in prediction accuracy
        let accuracies: Vec<f32> = recent_feedback.iter().map(|f| f.accuracy).collect();
        let mean_accuracy = accuracies.iter().sum::<f32>() / accuracies.len() as f32;
        let accuracy_variance = accuracies.iter()
            .map(|a| (a - mean_accuracy).powi(2))
            .sum::<f32>() / accuracies.len() as f32;
        
        // Calculate variance in prediction errors
        let errors: Vec<f32> = recent_feedback.iter()
            .map(|f| (f.predicted_threat - f.actual_threat).abs())
            .collect();
        let mean_error = errors.iter().sum::<f32>() / errors.len() as f32;
        let error_variance = errors.iter()
            .map(|e| (e - mean_error).powi(2))
            .sum::<f32>() / errors.len() as f32;
        
        // Higher variance = higher uncertainty
        let uncertainty = (accuracy_variance + error_variance) / 2.0;
        uncertainty.clamp(0.0, 1.0)
    }

    /// Update cross-modal learning between EQ and IQ
    /// EQ and IQ should learn from each other's successes and failures
    fn update_cross_modal_learning(&mut self, eq: f32, iq: f32, feedback: &FeedbackEvent) {
        // Calculate correlation between EQ and IQ performance
        let eq_iq_correlation = self.calculate_eq_iq_correlation(eq, iq, feedback);
        
        // Add to correlation history
        self.eq_iq_correlation_history.push(eq_iq_correlation);
        if self.eq_iq_correlation_history.len() > 50 {
            self.eq_iq_correlation_history.remove(0);
        }

        // Adapt α/β based on cross-modal learning
        self.adapt_alpha_beta_from_correlation();
    }

    /// Calculate correlation between EQ and IQ performance
    fn calculate_eq_iq_correlation(&self, eq: f32, iq: f32, feedback: &FeedbackEvent) -> f32 {
        // When both EQ and IQ are high and accuracy is high, positive correlation
        // When EQ and IQ are misaligned but accuracy is still good, learn from the imbalance
        let performance = feedback.accuracy;
        let eq_iq_alignment = 1.0 - (eq - iq).abs(); // Higher when EQ and IQ are similar
        
        // Positive correlation when aligned and performing well
        // Negative correlation when misaligned but still performing well (indicates one is compensating)
        if performance > 0.7 {
            if eq_iq_alignment > 0.7 {
                1.0 // Strong positive correlation
            } else {
                -0.5 // One is compensating for the other
            }
        } else {
            if eq_iq_alignment > 0.7 {
                -1.0 // Both are aligned but performing poorly
            } else {
                0.0 // Misaligned and performing poorly - neutral
            }
        }
    }

    /// Adapt α/β parameters based on cross-modal learning history
    fn adapt_alpha_beta_from_correlation(&mut self) {
        if self.eq_iq_correlation_history.len() < 10 {
            return; // Need sufficient history
        }

        let recent_correlations: Vec<f32> = self.eq_iq_correlation_history.iter().rev().take(20).cloned().collect();
        let mean_correlation = recent_correlations.iter().sum::<f32>() / recent_correlations.len() as f32;

        // If EQ and IQ are positively correlated with good performance, maintain balance
        // If negatively correlated, one might be compensating - adjust accordingly
        let adaptation_strength = self.cross_modal_learning_rate;
        
        if mean_correlation > 0.3 {
            // Positive correlation - maintain current balance
            // No adjustment needed
        } else if mean_correlation < -0.3 {
            // Negative correlation - one is compensating for the other
            // Slightly increase the weight of the better performer
            let eq_performance = self.calculate_recent_eq_performance();
            let iq_performance = self.calculate_recent_iq_performance();
            
            if eq_performance > iq_performance {
                self.base_alpha = (self.base_alpha + adaptation_strength * 0.1).min(0.8);
                self.base_beta = (self.base_beta - adaptation_strength * 0.1).max(0.2);
            } else {
                self.base_beta = (self.base_beta + adaptation_strength * 0.1).min(0.8);
                self.base_alpha = (self.base_alpha - adaptation_strength * 0.1).max(0.2);
            }
        }
        // Neutral correlation (-0.3 to 0.3) - no adaptation needed
    }

    /// Calculate recent EQ performance trend
    fn calculate_recent_eq_performance(&self) -> f32 {
        if self.context_history.len() < 5 {
            return 0.5;
        }

        let recent_contexts: Vec<&ContextEvent> = self.context_history.iter().rev().take(10).collect();
        let appropriateness_scores: Vec<f32> = recent_contexts.iter()
            .map(|c| c.response_appropriateness).collect();
        
        appropriateness_scores.iter().sum::<f32>() / appropriateness_scores.len() as f32
    }

    /// Calculate recent IQ performance trend
    fn calculate_recent_iq_performance(&self) -> f32 {
        if self.feedback_history.len() < 5 {
            return 0.5;
        }

        let recent_feedback: Vec<&FeedbackEvent> = self.feedback_history.iter().rev().take(10).collect();
        let accuracy_scores: Vec<f32> = recent_feedback.iter()
            .map(|f| f.accuracy).collect();
        
        accuracy_scores.iter().sum::<f32>() / accuracy_scores.len() as f32
    }

    /// Core EQ/IQ balanced reward calculation
    pub fn calculate_eq_iq_balance(&mut self, context: &ContextEvent, feedback: &FeedbackEvent) -> EQIQBalance {
        // Add to history
        self.context_history.push(context.clone());
        self.feedback_history.push(feedback.clone());

        // Maintain history size
        if self.context_history.len() > self.max_history {
            self.context_history.remove(0);
        }
        if self.feedback_history.len() > self.max_history {
            self.feedback_history.remove(0);
        }

        // Calculate multi-dimensional EQ and scalar IQ
        let eq_vector = self.measure_multidimensional_empathy(context, &self.context_history);
        let eq = eq_vector.aggregate(); // Aggregate for backward compatibility
        let iq = self.measure_accuracy(feedback);

        // Calculate context-adaptive α/β parameters based on threat level
        let threat_level = feedback.actual_threat;
        let (adaptive_alpha, adaptive_beta) = self.adaptive_alpha_beta(threat_level);

        // Calculate uncertainty quantification
        let eq_uncertainty = self.calculate_eq_uncertainty();
        let iq_uncertainty = self.calculate_iq_uncertainty();
        let confidence = 1.0 - ((eq_uncertainty + iq_uncertainty) / 2.0);

        // Calculate balanced reward factor with non-linear EQ/IQ interaction
        let balance = self.calculate_nonlinear_balance(eq, iq, adaptive_alpha, adaptive_beta);

        // Update cross-modal learning between EQ and IQ
        self.update_cross_modal_learning(eq, iq, feedback);

        // Modulate balance by confidence (lower confidence = more conservative balance)
        let confidence_modulated_balance = balance * (0.5 + 0.5 * confidence);

        info!("EQ/IQ Balance: EQ={:.3}±{:.3}, IQ={:.3}±{:.3}, threat={:.3}, α={:.2}→{:.2}, β={:.2}→{:.2}, balance={:.3}, confidence={:.3}", 
              eq, eq_uncertainty, iq, iq_uncertainty, threat_level, self.base_alpha, adaptive_alpha, self.base_beta, adaptive_beta, confidence_modulated_balance, confidence);

        EQIQBalance { 
            eq, 
            eq_vector,
            iq, 
            balance: confidence_modulated_balance,
            eq_uncertainty,
            iq_uncertainty,
            confidence
        }
    }

    /// Bidirectional Hebbian update with EQ/IQ balance
    /// Implements: Δwij = η · (xi · yj) · (α · EQ + β · IQ)
    pub fn bidirectional_hebbian_update(
        &self,
        x_i: f32,
        y_j: f32,
        eq_weight: f32,
        iq_weight: f32,
    ) -> f32 {
        let eq_iq_balance = self.base_alpha * eq_weight + self.base_beta * iq_weight;
        let delta_w = self.learning_rate * (x_i * y_j) * eq_iq_balance;
        
        debug!("Hebbian update: xi={:.3}, yj={:.3}, eq_iq_balance={:.3}, Δw={:.3}", 
               x_i, y_j, eq_iq_balance, delta_w);
        
        delta_w
    }

    /// Update regulator parameters based on performance
    pub fn adapt_parameters(&mut self, performance_feedback: f32) {
        // Adaptive parameter adjustment based on overall system performance
        if performance_feedback > 0.8 {
            // High performance - maintain current balance
            return;
        } else if performance_feedback < 0.4 {
            // Poor performance - adjust balance toward accuracy
            self.base_beta = (self.base_beta * 1.1).min(1.0);
            self.base_alpha = (self.base_alpha * 0.95).max(0.1);
        } else {
            // Moderate performance - slight adjustment toward empathy
            self.base_alpha = (self.base_alpha * 1.05).min(1.0);
            self.base_beta = (self.base_beta * 0.98).max(0.1);
        }

        // Normalize to ensure α + β ≈ 1.0
        let total = self.base_alpha + self.base_beta;
        self.base_alpha /= total;
        self.base_beta /= total;

        info!("Adapted EQ/IQ parameters: α={:.3}, β={:.3}", self.base_alpha, self.base_beta);
    }

    /// Get current EQ/IQ statistics
    pub fn get_stats(&self) -> HashMap<String, f32> {
        let mut stats = HashMap::new();
        
        stats.insert("alpha".to_string(), self.base_alpha);
        stats.insert("beta".to_string(), self.base_beta);
        stats.insert("learning_rate".to_string(), self.learning_rate);
        stats.insert("context_history_size".to_string(), self.context_history.len() as f32);
        stats.insert("feedback_history_size".to_string(), self.feedback_history.len() as f32);

        if !self.context_history.is_empty() {
            let avg_stability: f32 = self.context_history.iter()
                .map(|c| c.context_stability)
                .sum::<f32>() / self.context_history.len() as f32;
            stats.insert("avg_context_stability".to_string(), avg_stability);
        }

        if !self.feedback_history.is_empty() {
            let avg_accuracy: f32 = self.feedback_history.iter()
                .map(|f| f.accuracy)
                .sum::<f32>() / self.feedback_history.len() as f32;
            stats.insert("avg_accuracy".to_string(), avg_accuracy);
        }

        stats
    }

    /// Process a context event for EQ/IQ regulation
    pub fn process_context_event(&mut self, context_event: ContextEvent) -> Result<(), Box<dyn std::error::Error>> {
        // Add to context history
        self.context_history.push(context_event.clone());
        
        // Maintain history size
        if self.context_history.len() > self.max_history {
            self.context_history.remove(0);
        }

        // Adapt EQ/IQ balance based on context
        let threat_level = context_event.threat_level;
        
        // Adjust alpha (EQ) and beta (IQ) based on context
        if threat_level > 0.5 {
            // High threat - increase IQ weight for accuracy
            self.base_beta = (self.base_beta * 1.1).min(1.0);
            self.base_alpha = (self.base_alpha * 0.9).max(0.1);
        } else {
            // Low threat - increase EQ weight for empathy
            self.base_alpha = (self.base_alpha * 1.05).min(1.0);
            self.base_beta = (self.base_beta * 0.95).max(0.1);
        }

        // Normalize
        let total = self.base_alpha + self.base_beta;
        self.base_alpha /= total;
        self.base_beta /= total;

        Ok(())
    }

    /// Apply feedback for learning
    pub fn apply_feedback(&mut self, feedback_event: FeedbackEvent) -> Result<(), Box<dyn std::error::Error>> {
        // Add to feedback history
        self.feedback_history.push(feedback_event.clone());
        
        // Maintain history size
        if self.feedback_history.len() > self.max_history {
            self.feedback_history.remove(0);
        }

        // Adapt learning rate based on feedback
        if feedback_event.accuracy > 0.8 {
            self.learning_rate = (self.learning_rate * 0.95).max(0.001);
        } else {
            self.learning_rate = (self.learning_rate * 1.05).min(0.1);
        }

        // Adjust EQ/IQ balance based on prediction error
        let prediction_error = (feedback_event.predicted_threat - feedback_event.actual_threat).abs();
        
        if prediction_error > 0.3 {
            // High error - adjust balance
            if feedback_event.predicted_threat > feedback_event.actual_threat {
                // False positive - increase EQ for empathy
                self.base_alpha = (self.base_alpha * 1.1).min(1.0);
                self.base_beta = (self.base_beta * 0.9).max(0.1);
            } else {
                // False negative - increase IQ for accuracy
                self.base_beta = (self.base_beta * 1.1).min(1.0);
                self.base_alpha = (self.base_alpha * 0.9).max(0.1);
            }
        }

        // Normalize
        let total = self.base_alpha + self.base_beta;
        self.base_alpha /= total;
        self.base_beta /= total;

        Ok(())
    }

    /// Get current EQ/IQ balance information
    pub fn get_balance_info(&self) -> crate::mesh_cognition::EqIqBalance {
        crate::mesh_cognition::EqIqBalance {
            eq_weight: self.base_alpha,
            iq_weight: self.base_beta,
        }
    }

    /// Get empathic accuracy score
    pub fn get_empathic_accuracy(&self) -> f32 {
        if self.feedback_history.is_empty() {
            return 0.5;
        }

        // Calculate empathic accuracy based on accuracy and false positive rate
        let avg_accuracy: f32 = self.feedback_history.iter()
            .map(|f| f.accuracy)
            .sum::<f32>() / self.feedback_history.len() as f32;

        let false_positive_rate = self.feedback_history.iter()
            .filter(|f| f.predicted_threat > f.actual_threat + 0.2)
            .count() as f32 / self.feedback_history.len() as f32;

        // Empathic accuracy is high accuracy with low false positives
        (avg_accuracy * (1.0 - false_positive_rate)).min(1.0).max(0.0)
    }

    pub fn get_analytical_precision(&self) -> f32 {
        if self.feedback_history.is_empty() {
            return 0.5;
        }

        // Calculate analytical precision based on prediction accuracy
        let precision: f32 = self.feedback_history.iter()
            .map(|f| 1.0 - (f.predicted_threat - f.actual_threat).abs())
            .sum::<f32>() / self.feedback_history.len() as f32;

        precision.min(1.0).max(0.0)
    }

    pub fn adapt_from_external_profile(
        &mut self, 
        external_eq_weight: f32, 
        external_iq_weight: f32, 
        external_empathic_accuracy: f32
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Adapt our EQ/IQ balance based on external profile
        let current_empathic_accuracy = self.get_empathic_accuracy();
        
        // If external profile has better empathic accuracy, adapt towards it
        if external_empathic_accuracy > current_empathic_accuracy {
            let adaptation_rate = 0.1; // Conservative adaptation
            self.base_alpha = self.base_alpha * (1.0 - adaptation_rate) + external_eq_weight * adaptation_rate;
            self.base_beta = self.base_beta * (1.0 - adaptation_rate) + external_iq_weight * adaptation_rate;
        }
        
        Ok(())
    }
}


