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
    /// EQ weight coefficient (α)
    alpha: f32,
    /// IQ weight coefficient (β) 
    beta: f32,
    /// Learning rate (η)
    learning_rate: f32,
    /// Maximum history size to maintain
    max_history: usize,
}

#[derive(Debug, Clone)]
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
pub struct EQIQBalance {
    pub eq: f32,  // Emotional Intelligence (contextual empathy/stability)
    pub iq: f32,  // Intelligence Quotient (threat precision/accuracy)
    pub balance: f32,  // Normalized balance factor
}

impl ExperientialBehavioralRegulator {
    pub fn new(alpha: f32, beta: f32, learning_rate: f32) -> Self {
        Self {
            context_history: Vec::new(),
            feedback_history: Vec::new(),
            alpha,
            beta,
            learning_rate,
            max_history: 1000,
        }
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

    /// Measure accuracy (IQ) based on threat prediction precision
    pub fn measure_accuracy(&self, feedback: &FeedbackEvent) -> f32 {
        // Direct accuracy measurement from prediction vs reality
        let prediction_error = (feedback.predicted_threat - feedback.actual_threat).abs();
        let base_accuracy = 1.0 - prediction_error.min(1.0);
        
        // Enhance accuracy based on historical performance
        let historical_accuracy = if self.feedback_history.len() > 5 {
            let recent_accuracies: Vec<f32> = self.feedback_history
                .iter()
                .rev()
                .take(10)
                .map(|f| f.accuracy)
                .collect();
            recent_accuracies.iter().sum::<f32>() / recent_accuracies.len() as f32
        } else {
            base_accuracy
        };

        let iq = (base_accuracy * 0.6 + historical_accuracy * 0.4).clamp(0.0, 1.0);
        
        debug!("IQ measurement: prediction_error={:.3}, base_accuracy={:.3}, historical_accuracy={:.3}, iq={:.3}", 
               prediction_error, base_accuracy, historical_accuracy, iq);
        
        iq
    }

    /// Calculate stability trend from historical context
    fn calculate_stability_trend(&self, history: &[ContextEvent]) -> f32 {
        if history.len() < 2 {
            return 0.5;
        }

        let recent_events: Vec<&ContextEvent> = history.iter().rev().take(5).collect();
        let stability_values: Vec<f32> = recent_events
            .iter()
            .map(|e| e.context_stability)
            .collect();

        // Calculate trend (positive = improving stability)
        let mut trend_sum = 0.0;
        for i in 1..stability_values.len() {
            trend_sum += stability_values[i] - stability_values[i-1];
        }
        
        let trend = trend_sum / (stability_values.len() - 1) as f32;
        (0.5 + trend).clamp(0.0, 1.0)
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

        // Calculate EQ and IQ
        let eq = self.measure_empathy(context, &self.context_history);
        let iq = self.measure_accuracy(feedback);

        // Calculate balanced reward factor: α · EQ + β · IQ
        let balance = self.alpha * eq + self.beta * iq;

        info!("EQ/IQ Balance: EQ={:.3} (α={:.2}), IQ={:.3} (β={:.2}), balance={:.3}", 
              eq, self.alpha, iq, self.beta, balance);

        EQIQBalance { eq, iq, balance }
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
        let eq_iq_balance = self.alpha * eq_weight + self.beta * iq_weight;
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
            self.beta = (self.beta * 1.1).min(1.0);
            self.alpha = (self.alpha * 0.95).max(0.1);
        } else {
            // Moderate performance - slight adjustment toward empathy
            self.alpha = (self.alpha * 1.05).min(1.0);
            self.beta = (self.beta * 0.98).max(0.1);
        }

        // Normalize to ensure α + β ≈ 1.0
        let total = self.alpha + self.beta;
        self.alpha /= total;
        self.beta /= total;

        info!("Adapted EQ/IQ parameters: α={:.3}, β={:.3}", self.alpha, self.beta);
    }

    /// Get current EQ/IQ statistics
    pub fn get_stats(&self) -> HashMap<String, f32> {
        let mut stats = HashMap::new();
        
        stats.insert("alpha".to_string(), self.alpha);
        stats.insert("beta".to_string(), self.beta);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eq_iq_regulator_creation() {
        let regulator = ExperientialBehavioralRegulator::new(0.6, 0.4, 0.01);
        assert_eq!(regulator.alpha, 0.6);
        assert_eq!(regulator.beta, 0.4);
        assert_eq!(regulator.learning_rate, 0.01);
    }

    #[test]
    fn test_empathy_measurement() {
        let mut regulator = ExperientialBehavioralRegulator::new(0.5, 0.5, 0.01);
        
        let context = ContextEvent {
            timestamp: 1.0,
            context_stability: 0.8,
            threat_level: 0.2,
            response_appropriateness: 0.9,
        };

        let eq = regulator.measure_empathy(&context, &[]);
        assert!(eq >= 0.0 && eq <= 1.0);
    }

    #[test]
    fn test_accuracy_measurement() {
        let regulator = ExperientialBehavioralRegulator::new(0.5, 0.5, 0.01);
        
        let feedback = FeedbackEvent {
            timestamp: 1.0,
            predicted_threat: 0.7,
            actual_threat: 0.8,
            accuracy: 0.9,
        };

        let iq = regulator.measure_accuracy(&feedback);
        assert!(iq >= 0.0 && iq <= 1.0);
    }

    #[test]
    fn test_bidirectional_hebbian_update() {
        let regulator = ExperientialBehavioralRegulator::new(0.6, 0.4, 0.01);
        
        let delta_w = regulator.bidirectional_hebbian_update(0.8, 0.7, 0.9, 0.8);
        
        // Expected: 0.01 * (0.8 * 0.7) * (0.6 * 0.9 + 0.4 * 0.8)
        // = 0.01 * 0.56 * (0.54 + 0.32) = 0.01 * 0.56 * 0.86 = 0.004816
        assert!((delta_w - 0.004816).abs() < 0.0001);
    }

    #[test]
    fn test_parameter_adaptation() {
        let mut regulator = ExperientialBehavioralRegulator::new(0.5, 0.5, 0.01);
        
        // Test poor performance adaptation
        regulator.adapt_parameters(0.3);
        assert!(regulator.beta > regulator.alpha); // Should favor accuracy
        
        // Reset and test good performance
        regulator.alpha = 0.5;
        regulator.beta = 0.5;
        regulator.adapt_parameters(0.9);
        // Should maintain balance for good performance
    }
}