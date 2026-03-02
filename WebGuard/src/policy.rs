/// Policy module for WebGuard action selection
/// SECURITY-FIRST: Deterministic policy based on learned threat assessments
/// NO STOCHASTIC ELEMENTS - decisions are based purely on learned knowledge

#[derive(Debug, Clone, Copy)]
pub enum Action {
    Log,
    Notify,
    Throttle,
    Isolate,
    Restart,
    SnapshotAndKill,
}

/// Choose action based on threat assessment - DETERMINISTIC, no random exploration
/// 
/// # Arguments
/// * `score` - Similarity score to known patterns (0.0 to 1.0)
/// * `valence` - Learned valence (-1.0 threat to +1.0 benign)
/// * `aggression` - System aggression level (0.0 conservative to 1.0 aggressive)
/// * `beta` - Valence weight coefficient
/// * `gamma` - Score weight coefficient
/// * `_eps` - IGNORED: epsilon parameter kept for API compatibility but not used
/// 
/// # Security Philosophy
/// - Unknown patterns (no memory) are treated as SUSPICIOUS, not benign
/// - Self-learning means the system should err on the side of caution until it learns
/// - False negatives are far more costly than false positives
pub fn choose_action(score: f32, valence: f32, aggression: f32, beta: f32, gamma: f32, _eps: f32) -> Action {
    // NO RANDOM EXPLORATION - security systems must be deterministic
    // The _eps parameter is kept for API compatibility but intentionally ignored
    
    // SECURITY-FIRST: Unknown patterns should trigger notification, not be logged silently
    // A truly self-learning system should be cautious about what it hasn't seen before
    if score == 0.0 && valence == 0.0 {
        return Action::Notify; // Unknown = potentially suspicious, not assumed benign
    }
    
    // Calculate threat score: emphasize negative valence and high similarity to known threats
    // SECURITY-FIRST: Treat absence of positive evidence as mildly negative
    let threat_score = if valence < 0.0 {
        beta * valence + gamma * score  // Negative valence with high similarity = threat
    } else if valence > 0.3 {
        beta * valence - gamma * score  // Strong positive valence = likely benign
    } else {
        // Weak positive or neutral valence - be cautious
        // Slight bias toward suspicion for security
        beta * (valence - 0.1) + gamma * score * 0.5
    };
    
    // Aggression-modulated thresholds (more aggressive = lower thresholds = more sensitive)
    // SECURITY-FIRST: Higher aggression impact for better threat detection
    let aggression_factor = 1.0 - (aggression * 0.5); // More aggressive threshold reduction
    
    // Critical threat: very negative valence with high similarity to known threats
    if threat_score < -0.5 * aggression_factor && score > 0.6 {
        if aggression > 0.7 && threat_score < -0.7 * aggression_factor {
            Action::SnapshotAndKill
        } else if aggression > 0.5 && threat_score < -0.6 * aggression_factor {
            Action::Restart
        } else {
            Action::Isolate
        }
    }
    // High threat: moderate negative valence with good similarity
    else if threat_score < -0.3 * aggression_factor && score > 0.4 {
        if aggression > 0.6 {
            Action::Isolate
        } else {
            Action::Throttle
        }
    }
    // Medium threat: slight negative valence with some similarity
    else if threat_score < -0.15 * aggression_factor && score > 0.25 {
        Action::Notify
    }
    // Low threat: borderline patterns - still notify for learning
    else if threat_score < -0.05 * aggression_factor || (score > 0.2 && valence < 0.2) {
        Action::Notify
    }
    // Benign: strong positive valence OR low similarity with neutral/positive valence
    else {
        Action::Log
    }
}
