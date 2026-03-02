/// Valence Controller for adaptive aggression management
/// 
/// BHSM Integration:
/// - SECURITY-FIRST: Detecting threats should INCREASE sensitivity (aggression)
/// - High-confidence misclassifications trigger stronger penalties
/// - The ValenceController penalizes high-confidence predictions that produce poor outcomes
/// 
/// The system should become MORE vigilant when threats are encountered, not less

#[derive(Debug)]
pub struct ValenceController {
    pub recent_rewards: Vec<f32>,
    pub aggression: f32, // 0.0 conservative -> 1.0 aggressive (more sensitive)
    pub threat_count: usize, // Track recent threat detections
    pub benign_count: usize, // Track recent benign classifications
    /// BHSM: Track high-confidence misclassifications
    high_conf_fn_count: usize, // High-confidence false negatives
    high_conf_fp_count: usize, // High-confidence false positives
    total_high_conf: usize,    // Total high-confidence predictions
    /// Confidence penalty based on high-confidence errors
    pub confidence_penalty: f32,
}

impl ValenceController {
    pub fn new(init_aggr: f32) -> Self { 
        Self { 
            recent_rewards: Vec::new(), 
            aggression: init_aggr,
            threat_count: 0,
            benign_count: 0,
            high_conf_fn_count: 0,
            high_conf_fp_count: 0,
            total_high_conf: 0,
            confidence_penalty: 0.0,
        } 
    }

    /// Record a reward/feedback signal
    /// Negative rewards indicate threat detection (should INCREASE aggression)
    /// Positive rewards indicate benign patterns (can slightly decrease aggression)
    pub fn record_reward(&mut self, r: f32) {
        self.recent_rewards.push(r);
        if self.recent_rewards.len() > 100 { self.recent_rewards.remove(0); }
        
        // Track threat vs benign counts for asymmetric adjustment
        if r < -0.3 {
            self.threat_count += 1;
        } else if r > 0.3 {
            self.benign_count += 1;
        }
        
        self.adjust();
    }
    
    /// BHSM: Record a high-confidence prediction outcome
    /// This penalizes high-confidence predictions that produce poor outcomes
    pub fn record_high_confidence_outcome(
        &mut self, 
        confidence: f32, 
        was_false_negative: bool, 
        was_false_positive: bool
    ) {
        // Only track if this was a high-confidence prediction
        if confidence < 0.7 {
            return;
        }
        
        self.total_high_conf += 1;
        
        if was_false_negative {
            self.high_conf_fn_count += 1;
            // FN with high confidence = very bad, boost aggression significantly
            self.aggression = (self.aggression + 0.15).min(0.95);
        } else if was_false_positive {
            self.high_conf_fp_count += 1;
            // FP with high confidence = bad but less critical
            // Small aggression reduction to avoid being too aggressive
            self.aggression = (self.aggression - 0.02).max(0.3);
        }
        
        // Update confidence penalty based on high-confidence error rate
        self.update_confidence_penalty();
    }
    
    /// Update the confidence penalty based on high-confidence error history
    fn update_confidence_penalty(&mut self) {
        if self.total_high_conf == 0 {
            self.confidence_penalty = 0.0;
            return;
        }
        
        // FN errors are weighted 3x more than FP errors
        let weighted_errors = (self.high_conf_fn_count as f32 * 3.0) 
                            + (self.high_conf_fp_count as f32);
        let error_rate = weighted_errors / (self.total_high_conf as f32 * 3.0);
        
        // Penalty scales with error rate (max 30%)
        self.confidence_penalty = (error_rate * 0.3).min(0.3);
    }
    
    /// Get adjusted confidence after applying penalty
    /// BHSM: High-confidence predictions are penalized if we've been wrong before
    pub fn adjust_confidence(&self, raw_confidence: f32) -> f32 {
        raw_confidence * (1.0 - self.confidence_penalty)
    }

    /// Adjust aggression based on recent experience
    /// SECURITY-FIRST: Threats INCREASE aggression, benign patterns slowly decrease it
    fn adjust(&mut self) {
        let sum: f32 = self.recent_rewards.iter().sum();
        let avg = if !self.recent_rewards.is_empty() { 
            sum / (self.recent_rewards.len() as f32) 
        } else { 
            0.0 
        };
        
        // Count recent negative (threat) signals
        let recent_threats = self.recent_rewards.iter().filter(|&&r| r < -0.2).count();
        let threat_ratio = recent_threats as f32 / self.recent_rewards.len().max(1) as f32;
        
        // SECURITY-FIRST: Inverted from original - threats INCREASE aggression
        if avg < 0.0 || threat_ratio > 0.1 {
            // Negative average (threats detected) -> INCREASE aggression (sensitivity)
            // The more threats, the more aggressive the increase
            let boost = 1.0 + (0.15 * (1.0 + threat_ratio));
            self.aggression = (self.aggression * boost).min(0.95);
        } else if avg > 0.3 && threat_ratio < 0.05 {
            // Strong positive average with very few threats -> slowly decrease aggression
            // But decay is much slower than the boost - security ratchet effect
            self.aggression = (self.aggression * 0.98).max(0.3); // Floor at 0.3 - never go too conservative
        }
        // Neutral/mixed signals: maintain current aggression level
    }
    
    /// Get current threat-to-benign ratio
    pub fn get_threat_ratio(&self) -> f32 {
        let total = self.threat_count + self.benign_count;
        if total == 0 { 0.5 } else { self.threat_count as f32 / total as f32 }
    }
    
    /// Get high-confidence error rate
    pub fn get_high_conf_error_rate(&self) -> f32 {
        if self.total_high_conf == 0 {
            0.0
        } else {
            (self.high_conf_fn_count + self.high_conf_fp_count) as f32 / self.total_high_conf as f32
        }
    }
    
    /// Force increase aggression (e.g., after confirmed false negative)
    pub fn boost_aggression(&mut self, amount: f32) {
        self.aggression = (self.aggression + amount).min(0.95);
    }
    
    /// Reset high-confidence tracking (e.g., after model update)
    pub fn reset_high_conf_tracking(&mut self) {
        self.high_conf_fn_count = 0;
        self.high_conf_fp_count = 0;
        self.total_high_conf = 0;
        self.confidence_penalty = 0.0;
    }
}
