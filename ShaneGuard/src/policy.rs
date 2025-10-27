
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
    
    // Calculate threat score: emphasize negative valence and high similarity
    let threat_score = beta * valence + gamma * score;
    
    // Aggression-modulated thresholds (more aggressive = lower thresholds)
    let aggression_factor = 1.0 - (aggression * 0.5); // Reduces thresholds as aggression increases
    
    // Critical threat: very negative valence or high similarity with negative valence
    if threat_score < -0.4 * aggression_factor {
        if aggression > 0.7 && threat_score < -0.6 * aggression_factor {
            Action::SnapshotAndKill
        } else if aggression > 0.5 && threat_score < -0.5 * aggression_factor {
            Action::Restart
        } else {
            Action::Isolate
        }
    }
    // High threat: moderate negative valence
    else if threat_score < -0.2 * aggression_factor {
        if aggression > 0.6 {
            Action::Isolate
        } else {
            Action::Throttle
        }
    }
    // Medium threat: slight negative valence or suspicious patterns
    else if threat_score < -0.05 * aggression_factor || (score > 0.7 && valence < -0.1) {
        Action::Throttle
    }
    // Low threat: borderline cases
    else if threat_score < 0.1 * aggression_factor || score > 0.5 {
        Action::Notify
    }
    // Benign: positive or neutral
    else {
        Action::Log
    }
}
