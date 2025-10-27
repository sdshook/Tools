
use serde::{Serialize, Deserialize};
use uuid::Uuid;

pub const EMBED_DIM: usize = 32;

#[derive(Serialize, Deserialize, Clone)]
pub struct MemoryTrace {
    pub id: String,
    pub vec: [f32; EMBED_DIM],
    pub valence: f32,
    pub uses: u32,
    pub cum_reward: f32,
}

pub struct BdhMemory {
    traces: Vec<MemoryTrace>,
}

impl BdhMemory {
    pub fn new() -> Self { Self { traces: Vec::new() } }

    pub fn add_trace(&mut self, vec: [f32; EMBED_DIM], valence: f32) -> String {
        let id = Uuid::new_v4().to_string();
        let trace = MemoryTrace { id: id.clone(), vec, valence, uses: 1, cum_reward: valence };
        self.traces.push(trace);
        id
    }

    pub fn retrieve_similar(&self, q: &[f32; EMBED_DIM], top_k: usize) -> Vec<(&MemoryTrace, f32)> {
        let mut out: Vec<(&MemoryTrace, f32)> = self.traces.iter()
            .map(|t| (t, cosine_sim(&t.vec, q)))
            .collect();
        out.sort_by(|a,b| b.1.partial_cmp(&a.1).unwrap());
        out.into_iter().take(top_k).collect()
    }

    pub fn reward_update(&mut self, id: &str, reward: f32, eta: f32) {
        if let Some(t) = self.traces.iter_mut().find(|x| x.id==id) {
            t.cum_reward += reward;
            t.valence = t.valence + eta * (reward - t.valence);
            t.uses += 1;
        }
    }

    pub fn promote_candidates(&self, threshold: f32) -> Vec<&MemoryTrace> {
        self.traces.iter().filter(|t| t.cum_reward.abs() >= threshold).collect()
    }

    pub fn max_similarity(&self, q: &[f32; EMBED_DIM]) -> f32 {
        self.traces.iter().map(|t| cosine_sim(&t.vec, q)).fold(0.0, |a,b| a.max(b))
    }
}

fn cosine_sim(a: &[f32; EMBED_DIM], b: &[f32; EMBED_DIM]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x,y)| x*y).sum();
    let an: f32 = a.iter().map(|x| x*x).sum::<f32>().sqrt();
    let bn: f32 = b.iter().map(|x| x*x).sum::<f32>().sqrt();
    if an==0.0 || bn==0.0 { return 0.0; }
    dot / (an*bn)
}
