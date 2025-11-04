
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub embed_dim: usize,
    pub window_seconds: u64,
    pub db_path: String,
    pub aggression_init: f32,
    pub eta: f32,
    pub tau_novel: f32,
    pub promote_threshold: f32,
    pub beta: f32,
    pub gamma: f32,
    pub eps_explore: f32,
    pub mesh_learning_rate: f32,
    pub cross_service_threshold: f32,
}

impl Config {
    pub fn load_default() -> Self {
        Self {
            embed_dim: 32,
            window_seconds: 30,
            db_path: "./data/webguard.db".into(),
            aggression_init: 0.2,
            eta: 0.3,             // Increased learning rate for faster adaptation
            tau_novel: 0.6,       // Lowered novelty threshold for better detection
            promote_threshold: 3.0,
            beta: 0.8,            // Increased valence weight for threat emphasis
            gamma: 0.6,           // Increased similarity weight for pattern recognition
            eps_explore: 0.05,    // Reduced exploration for more decisive actions
            mesh_learning_rate: 0.6,
            cross_service_threshold: 0.3,
        }
    }
}
