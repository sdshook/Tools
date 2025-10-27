
use rand::Rng;

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
    let s = beta * valence + gamma * score;
    if s < -0.6 * (1.0 + aggression) {
        if aggression > 0.7 { Action::SnapshotAndKill } else { Action::Isolate }
    } else if s < -0.3 {
        Action::Isolate
    } else if s < 0.0 {
        Action::Throttle
    } else {
        Action::Log
    }
}
