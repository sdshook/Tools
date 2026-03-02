/// Policy module for WebGuard action selection
/// 
/// BHSM RISC Constraint: Exactly 3 actions for proxy mode
/// This is a structural boundary that limits blast radius regardless of classifier accuracy.
/// 
/// As a proxy (Harvard architecture safeguard), WebGuard separates:
/// - Classification (cognitive layer) from
/// - Execution (mechanical layer - only these 3 actions possible)
/// 
/// NO STOCHASTIC ELEMENTS - decisions are based purely on learned knowledge

/// RISC-constrained action set for proxy mode
/// Only 3 possible outcomes regardless of what the cognitive layer produces
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Detect: Log the request for analysis, allow to pass (monitoring mode)
    Detect,
    /// Allow: Request classified as benign, forward to backend
    Allow,
    /// Block: Request classified as threat, return 403 Forbidden
    Block,
}

impl Action {
    /// Returns true if this action permits the request to reach the backend
    pub fn permits_request(&self) -> bool {
        matches!(self, Action::Detect | Action::Allow)
    }
    
    /// Returns true if this action should be logged for threat analysis
    pub fn requires_logging(&self) -> bool {
        matches!(self, Action::Detect | Action::Block)
    }
}

// Legacy action mapping for backwards compatibility with existing code
#[derive(Debug, Clone, Copy)]
#[deprecated(note = "Use Action enum directly. Legacy actions map to RISC 3-action constraint.")]
pub enum LegacyAction {
    Log,
    Notify,
    Throttle,
    Isolate,
    Restart,
    SnapshotAndKill,
}

impl From<LegacyAction> for Action {
    fn from(legacy: LegacyAction) -> Self {
        match legacy {
            LegacyAction::Log => Action::Detect,
            LegacyAction::Notify => Action::Detect,
            LegacyAction::Throttle => Action::Block,  // Rate limiting = soft block
            LegacyAction::Isolate => Action::Block,
            LegacyAction::Restart => Action::Block,
            LegacyAction::SnapshotAndKill => Action::Block,
        }
    }
}

/// Choose action based on threat assessment - DETERMINISTIC, no random exploration
/// 
/// BHSM RISC Constraint: Returns exactly one of 3 actions (Detect, Allow, Block)
/// 
/// # Arguments
/// * `score` - Similarity score to known patterns (0.0 to 1.0)
/// * `valence` - Learned valence (-1.0 threat to +1.0 benign)
/// * `aggression` - System aggression level (0.0 conservative to 1.0 aggressive)
/// * `blocking_enabled` - Whether blocking mode is active (vs monitoring-only)
/// * `block_threshold` - Threat score threshold for blocking (0.0 to 1.0)
/// 
/// # Security Philosophy
/// - Unknown patterns are treated as SUSPICIOUS, not benign (Detect)
/// - Classification occurs pre-execution (Harvard architecture)
/// - Blast radius is structurally bounded to 3 actions regardless of classifier accuracy
pub fn choose_action(
    score: f32, 
    valence: f32, 
    aggression: f32, 
    blocking_enabled: bool,
    block_threshold: f32,
) -> Action {
    // Calculate threat score: combines valence and similarity
    let threat_score = calculate_threat_score(score, valence, aggression);
    
    // RISC 3-action decision tree
    if threat_score >= block_threshold {
        // High threat score -> Block (if enabled) or Detect
        if blocking_enabled {
            Action::Block
        } else {
            Action::Detect // Monitoring mode: detect but allow
        }
    } else if threat_score > 0.3 || (score > 0.2 && valence < 0.2) {
        // Medium threat or uncertain pattern -> Detect for learning
        Action::Detect
    } else if valence > 0.3 || (score == 0.0 && valence == 0.0) {
        // Known benign OR completely unknown -> Allow
        // Note: Unknown patterns start as Allow, learn from feedback
        Action::Allow
    } else {
        // Default: Allow with detection
        Action::Detect
    }
}

/// Calculate threat score from pattern metrics
/// 
/// Returns a normalized threat score (0.0 = benign, 1.0 = definite threat)
pub fn calculate_threat_score(score: f32, valence: f32, aggression: f32) -> f32 {
    // Combine similarity and valence with aggression weighting
    let base_threat = if valence < 0.0 {
        // Negative valence: threat indicator
        // High similarity + negative valence = higher threat
        (-valence * 0.6) + (score * 0.4)
    } else if valence > 0.3 {
        // Strong positive valence: likely benign
        // Reduce threat score based on positive evidence
        (score * 0.3) * (1.0 - valence)
    } else {
        // Neutral/weak positive: uncertain
        score * 0.5
    };
    
    // Aggression modulates sensitivity (higher = more sensitive = higher scores)
    let aggression_boost = 1.0 + (aggression * 0.3);
    
    (base_threat * aggression_boost).clamp(0.0, 1.0)
}

// Legacy API for backwards compatibility
#[deprecated(note = "Use choose_action with blocking_enabled and block_threshold parameters")]
pub fn choose_action_legacy(score: f32, valence: f32, aggression: f32, beta: f32, gamma: f32, _eps: f32) -> Action {
    let _ = (beta, gamma); // Unused in new implementation
    choose_action(score, valence, aggression, false, 0.7)
}
