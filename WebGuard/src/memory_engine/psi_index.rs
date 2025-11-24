
/// PSI (Persistent Semantic Index) - Memory cache for BDH that avoids context window constraints
/// and enables experiential learning in RHLS (Reinforced Hebbian Learning System)
/// where CMNN provides synaptic signal inputs with behavioral reward adjustments.

use serde::{Serialize, Deserialize};

pub const EMBED_DIM: usize = 32;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PsiEntry {
    pub id: String,
    pub vec: [f32; EMBED_DIM],
    pub valence: f32,
    pub uses: u32,
    pub tags: Vec<String>,
}

/// PSI (Persistent Semantic Index) - Core memory cache structure
/// Provides persistent storage for BDH memory patterns to enable
/// experiential learning beyond context window limitations
#[derive(Debug)]
pub struct PsiIndex {
    entries: Vec<PsiEntry>,
    max_entries: usize,
    quality_threshold: f32,
    consolidation_interval: usize,
    last_consolidation: usize,
}

impl PsiIndex {
    pub fn new() -> Self { 
        Self { 
            entries: Vec::new(),
            max_entries: 500,
            quality_threshold: 0.1,
            consolidation_interval: 100,
            last_consolidation: 0,
        } 
    }

    pub fn add(&mut self, entry: PsiEntry) { 
        // Check if we need consolidation before adding
        if self.entries.len() >= self.max_entries {
            self.consolidate_entries();
        }
        
        self.entries.push(entry);
        
        // Periodic consolidation
        if self.entries.len() - self.last_consolidation >= self.consolidation_interval {
            self.consolidate_entries();
        }
    }

    pub fn search(&self, q: &[f32; EMBED_DIM], top_k: usize) -> Vec<(&PsiEntry, f32)> {
        let mut out: Vec<(&PsiEntry, f32)> = self.entries.iter()
            .map(|e| (e, cosine_sim(&e.vec, q)))
            .collect();
        out.sort_by(|a,b| b.1.partial_cmp(&a.1).unwrap());
        out.into_iter().take(top_k).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Export high-quality patterns for knowledge sharing
    pub fn export_high_quality_patterns(&self, min_valence_threshold: f32) -> Vec<PsiEntry> {
        self.entries.iter()
            .filter(|entry| entry.valence.abs() > min_valence_threshold && entry.uses > 1)
            .cloned()
            .collect()
    }
    
    /// PSI consolidation: merge similar entries and remove low-quality ones
    fn consolidate_entries(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        
        // Remove low-quality entries first
        self.entries.retain(|entry| entry.valence.abs() > self.quality_threshold);
        
        // Merge similar entries
        let mut consolidated = Vec::new();
        let mut processed = vec![false; self.entries.len()];
        
        for i in 0..self.entries.len() {
            if processed[i] {
                continue;
            }
            
            let mut cluster = vec![i];
            processed[i] = true;
            
            // Find similar entries to merge
            for j in (i + 1)..self.entries.len() {
                if processed[j] {
                    continue;
                }
                
                let similarity = cosine_sim(&self.entries[i].vec, &self.entries[j].vec);
                if similarity > 0.8 {
                    cluster.push(j);
                    processed[j] = true;
                }
            }
            
            // Create consolidated entry from cluster
            if cluster.len() == 1 {
                consolidated.push(self.entries[i].clone());
            } else {
                let merged_entry = self.merge_entries(&cluster);
                consolidated.push(merged_entry);
            }
        }
        
        self.entries = consolidated;
        self.last_consolidation = self.entries.len();
    }
    
    /// Merge multiple PSI entries into one
    fn merge_entries(&self, indices: &[usize]) -> PsiEntry {
        let mut merged_vec = [0.0; EMBED_DIM];
        let mut merged_valence = 0.0;
        let mut merged_uses = 0;
        let mut merged_tags = Vec::new();
        
        for &idx in indices {
            let entry = &self.entries[idx];
            
            // Average the vectors
            for i in 0..EMBED_DIM {
                merged_vec[i] += entry.vec[i];
            }
            
            // Weighted average of valence by usage
            merged_valence += entry.valence * entry.uses as f32;
            merged_uses += entry.uses;
            
            // Merge tags
            for tag in &entry.tags {
                if !merged_tags.contains(tag) {
                    merged_tags.push(tag.clone());
                }
            }
        }
        
        // Normalize vector
        for i in 0..EMBED_DIM {
            merged_vec[i] /= indices.len() as f32;
        }
        
        // Normalize valence
        if merged_uses > 0 {
            merged_valence /= merged_uses as f32;
        }
        
        PsiEntry {
            id: format!("merged_{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
            vec: merged_vec,
            valence: merged_valence,
            uses: merged_uses,
            tags: merged_tags,
        }
    }
    
    /// Get PSI statistics for monitoring
    pub fn get_stats(&self) -> PsiStats {
        let avg_valence = if self.entries.is_empty() {
            0.0
        } else {
            self.entries.iter().map(|e| e.valence).sum::<f32>() / self.entries.len() as f32
        };
        
        let avg_uses = if self.entries.is_empty() {
            0.0
        } else {
            self.entries.iter().map(|e| e.uses as f32).sum::<f32>() / self.entries.len() as f32
        };
        
        let memory_usage = self.entries.len() as f32 / self.max_entries as f32;
        
        PsiStats {
            entry_count: self.entries.len(),
            avg_valence,
            avg_uses,
            memory_usage,
            quality_threshold: self.quality_threshold,
        }
    }
    
    /// Promote high-quality entries to BDH memory
    pub fn promote_to_bdh(&self, quality_threshold: f32) -> Vec<PsiEntry> {
        self.entries.iter()
            .filter(|entry| entry.valence.abs() > quality_threshold && entry.uses > 2)
            .cloned()
            .collect()
    }

    /// Get the number of entries in the PSI index
    pub fn get_entry_count(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Debug)]
pub struct PsiStats {
    pub entry_count: usize,
    pub avg_valence: f32,
    pub avg_uses: f32,
    pub memory_usage: f32,
    pub quality_threshold: f32,
}

fn cosine_sim(a: &[f32; EMBED_DIM], b: &[f32; EMBED_DIM]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x,y)| x*y).sum();
    let an: f32 = a.iter().map(|x| x*x).sum::<f32>().sqrt();
    let bn: f32 = b.iter().map(|x| x*x).sum::<f32>().sqrt();
    if an==0.0 || bn==0.0 { return 0.0; }
    dot / (an*bn)
}
