
use serde::{Serialize, Deserialize};

pub const EMBED_DIM: usize = 32;

#[derive(Serialize, Deserialize, Clone)]
pub struct PsiEntry {
    pub id: String,
    pub vec: [f32; EMBED_DIM],
    pub valence: f32,
    pub uses: u32,
    pub tags: Vec<String>,
}

pub struct PsiIndex {
    entries: Vec<PsiEntry>,
}

impl PsiIndex {
    pub fn new() -> Self { Self { entries: Vec::new() } }

    pub fn add(&mut self, entry: PsiEntry) { self.entries.push(entry); }

    pub fn search(&self, q: &[f32; EMBED_DIM], top_k: usize) -> Vec<(&PsiEntry, f32)> {
        let mut out: Vec<(&PsiEntry, f32)> = self.entries.iter()
            .map(|e| (e, cosine_sim(&e.vec, q)))
            .collect();
        out.sort_by(|a,b| b.1.partial_cmp(&a.1).unwrap());
        out.into_iter().take(top_k).collect()
    }
}

fn cosine_sim(a: &[f32; EMBED_DIM], b: &[f32; EMBED_DIM]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x,y)| x*y).sum();
    let an: f32 = a.iter().map(|x| x*x).sum::<f32>().sqrt();
    let bn: f32 = b.iter().map(|x| x*x).sum::<f32>().sqrt();
    if an==0.0 || bn==0.0 { return 0.0; }
    dot / (an*bn)
}
