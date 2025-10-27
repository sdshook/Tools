
use rand::Rng;

#[derive(Debug, Clone, Copy)]
pub enum Action {
    Log,
    Notify,
    Throttle,
    Isolate,
    Restart,
    SnapshotAndKill,
}

pub fn choose_action(score: f32, valence: f32, aggression: f32, beta: f32, gamma: f32, eps: f32) -> Action {
    let mut rng = rand::thread_rng();
    if rng.gen::<f32>() < eps { return Action::Notify; }
    
    // Handle the case where no memory traces exist yet (score = 0.0, valence = 0.0)
    // This should default to benign behavior, not suspicious
    if score == 0.0 && valence == 0.0 {
        return Action::Log; // Default to benign for unknown patterns
    }
    
    // Calculate threat score: emphasize negative valence and high similarity to known threats
    // Only high similarity to negative patterns should trigger alerts
    let threat_score = if valence < 0.0 {
        beta * valence + gamma * score  // Negative valence with high similarity = threat
    } else {
        beta * valence - gamma * score  // Positive valence with high similarity = benign
    };
    
    // Aggression-modulated thresholds (more aggressive = lower thresholds)
    let aggression_factor = 1.0 - (aggression * 0.3); // Less aggressive reduction
    
    // Critical threat: very negative valence with high similarity to known threats
    if threat_score < -0.6 * aggression_factor && score > 0.7 {
        if aggression > 0.8 && threat_score < -0.8 * aggression_factor {
            Action::SnapshotAndKill
        } else if aggression > 0.6 && threat_score < -0.7 * aggression_factor {
            Action::Restart
        } else {
            Action::Isolate
        }
    }
    // High threat: moderate negative valence with good similarity
    else if threat_score < -0.4 * aggression_factor && score > 0.5 {
        if aggression > 0.7 {
            Action::Isolate
        } else {
            Action::Throttle
        }
    }
    // Medium threat: slight negative valence with some similarity
    else if threat_score < -0.2 * aggression_factor && score > 0.3 {
        Action::Notify
    }
    // Low threat: very slight negative or unknown patterns
    else if threat_score < -0.1 * aggression_factor {
        Action::Notify
    }
    // Benign: positive valence, low similarity to threats, or neutral patterns
    else {
        Action::Log
    }
}
