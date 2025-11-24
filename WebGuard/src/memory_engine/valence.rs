
#[derive(Debug)]
pub struct ValenceController {
    pub recent_rewards: Vec<f32>,
    pub aggression: f32, // 0.0 conservative -> 1.0 aggressive
}

impl ValenceController {
    pub fn new(init_aggr: f32) -> Self { Self { recent_rewards: Vec::new(), aggression: init_aggr } }

    pub fn record_reward(&mut self, r: f32) {
        self.recent_rewards.push(r);
        if self.recent_rewards.len() > 100 { self.recent_rewards.remove(0); }
        self.adjust();
    }

    fn adjust(&mut self) {
        let sum: f32 = self.recent_rewards.iter().sum();
        let avg = if self.recent_rewards.len()>0 { sum / (self.recent_rewards.len() as f32) } else { 0.0 };
        if avg < 0.0 {
            self.aggression = (self.aggression * 0.9).max(0.05);
        } else {
            self.aggression = (self.aggression * 1.05).min(0.95);
        }
    }
}
