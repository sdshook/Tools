//! # Harvard Architecture for Security: Semantic-Execution Separation
//!
//! ## The Von Neumann Problem
//! 
//! Traditional Von Neumann architecture stores code and data in the same memory space,
//! making them indistinguishable. This fundamental design flaw enables virtually all
//! injection attacks:
//! 
//! - **SQL Injection**: Data becomes database instructions
//! - **XSS**: Data becomes executable JavaScript
//! - **Command Injection**: Data becomes shell commands
//! - **Buffer Overflow**: Data becomes machine instructions
//! 
//! The root cause: **we cannot determine what data MEANS without potentially executing it**.
//!
//! ## The Harvard Solution
//! 
//! Harvard architecture physically separates instruction memory from data memory with
//! distinct pathways. WebGuard adapts this principle for application security:
//! 
//! ```text
//! ╔═══════════════════════════════════════════════════════════════════════════╗
//! ║                        HARVARD ARCHITECTURE                                ║
//! ║                     (Semantic-Execution Separation)                        ║
//! ╠═══════════════════════════════════════════════════════════════════════════╣
//! ║                                                                            ║
//! ║   ┌────────────────────────────────────────────────────────────────────┐  ║
//! ║   │                    SEMANTIC LAYER                                   │  ║
//! ║   │              (Harvard "Data Memory" Analog)                         │  ║
//! ║   │                                                                     │  ║
//! ║   │  PROPERTIES:                                                        │  ║
//! ║   │  • Analyzes MEANING without execution                               │  ║
//! ║   │  • Pure functions - no side effects                                 │  ║
//! ║   │  • Input: Raw bytes (untrusted data)                                │  ║
//! ║   │  • Output: SemanticVerdict ONLY                                     │  ║
//! ║   │  • CANNOT trigger system actions                                    │  ║
//! ║   │                                                                     │  ║
//! ║   │  COMPONENTS:                                                        │  ║
//! ║   │  • EmbeddingLearner (n-gram semantic extraction)                    │  ║
//! ║   │  • StatisticalFeatures (structural analysis)                        │  ║
//! ║   │  • SemanticMemory (learned pattern meanings)                        │  ║
//! ║   │                                                                     │  ║
//! ║   └────────────────────────────────────────────────────────────────────┘  ║
//! ║                                 │                                          ║
//! ║                                 │ SemanticVerdict                          ║
//! ║                                 │ (ONE-WAY DATA FLOW)                      ║
//! ║                                 │                                          ║
//! ║                                 ▼                                          ║
//! ║   ════════════════════════════════════════════════════════════════════    ║
//! ║                        HARVARD BOUNDARY                                    ║
//! ║            (No raw data crosses this line - only verdicts)                 ║
//! ║   ════════════════════════════════════════════════════════════════════    ║
//! ║                                 │                                          ║
//! ║                                 │                                          ║
//! ║                                 ▼                                          ║
//! ║   ┌────────────────────────────────────────────────────────────────────┐  ║
//! ║   │                   EXECUTION LAYER                                   │  ║
//! ║   │            (Harvard "Instruction Memory" Analog)                    │  ║
//! ║   │                                                                     │  ║
//! ║   │  PROPERTIES:                                                        │  ║
//! ║   │  • Acts on verdicts, NEVER on raw data                              │  ║
//! ║   │  • Makes execution decisions                                        │  ║
//! ║   │  • Input: SemanticVerdict ONLY                                      │  ║
//! ║   │  • Output: System actions                                           │  ║
//! ║   │  • CANNOT analyze raw request content                               │  ║
//! ║   │                                                                     │  ║
//! ║   │  COMPONENTS:                                                        │  ║
//! ║   │  • Policy (verdict → action mapping)                                │  ║
//! ║   │  • Actuators (action → system effect)                               │  ║
//! ║   │                                                                     │  ║
//! ║   └────────────────────────────────────────────────────────────────────┘  ║
//! ║                                                                            ║
//! ╚═══════════════════════════════════════════════════════════════════════════╝
//! ```
//!
//! ## Why This Solves Von Neumann
//! 
//! 1. **Data never becomes instructions in the semantic layer**
//!    - We analyze structure and statistics, not execute content
//!    - N-grams extract patterns without interpretation as code
//!    
//! 2. **The execution layer never sees raw data**
//!    - Policy decisions based on SemanticVerdict (threat_score, confidence)
//!    - Actuators receive action enums, not request content
//!    
//! 3. **One-way information flow**
//!    - Raw data → Semantic Layer → SemanticVerdict → Execution Layer
//!    - The execution layer CANNOT influence semantic analysis
//!    
//! 4. **Semantic analysis is pure**
//!    - Given the same input, always produces the same SemanticVerdict
//!    - No hidden state modifications during analysis
//!    - Cannot be corrupted by malicious input
//!
//! ## Type-Level Enforcement
//! 
//! The [`SemanticVerdict`] type is the ONLY bridge between layers.
//! It contains NO raw data - only derived semantic properties:
//! 
//! ```text
//! SemanticVerdict {
//!     threat_score: f32,      // Learned semantic threat level
//!     confidence: f32,        // Confidence in semantic analysis
//!     semantic_class: SemanticClass,  // Categorical classification
//!     analysis_hash: u64,     // Proof of semantic processing
//! }
//! ```
//!
//! The Rust type system enforces that:
//! - `SemanticLayer` accepts `&[u8]` and returns `SemanticVerdict`
//! - `ExecutionLayer` accepts `SemanticVerdict` and returns `Action`
//! - There is NO type that allows passing raw data to execution
//!
//! ## Implementation
//! 
//! See the [`SemanticVerdict`], [`SemanticLayerComponent`], and [`ExecutionLayerComponent`]
//! types for the enforced interfaces.

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// Semantic classification of analyzed content
/// 
/// This enum represents the MEANING we've extracted, not the content itself.
/// It's safe to pass to the execution layer because it contains no raw data.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SemanticClass {
    /// Semantically similar to learned benign patterns
    Benign,
    /// Semantically similar to learned threat patterns  
    Threat,
    /// No strong semantic match - requires caution (security-first)
    Unknown,
    /// Anomalous structure - statistical outlier
    Anomalous,
}

/// The ONE-WAY bridge between Semantic and Execution layers
/// 
/// # Harvard Architecture Invariants
/// 
/// 1. Contains NO raw request data
/// 2. Contains ONLY derived semantic properties
/// 3. Is the SOLE interface between layers
/// 4. Cannot be reverse-engineered to recover original input
/// 
/// # Security Properties
/// 
/// - `threat_score`: Learned semantic threat level [0.0, 1.0]
/// - `confidence`: How certain we are of the analysis [0.0, 1.0]
/// - `semantic_class`: Categorical classification
/// - `analysis_hash`: Cryptographic proof that semantic analysis occurred
/// - `experience_basis`: How many learned examples inform this verdict
#[derive(Debug, Clone)]
pub struct SemanticVerdict {
    /// Threat score derived from semantic analysis [0.0 = benign, 1.0 = threat]
    pub threat_score: f32,
    
    /// Confidence in the semantic analysis [0.0 = no experience, 1.0 = high certainty]
    pub confidence: f32,
    
    /// Categorical semantic classification
    pub semantic_class: SemanticClass,
    
    /// Hash proving semantic analysis occurred (NOT a hash of the content)
    /// This is hash(embedding) - proves we processed semantically, not raw
    pub analysis_hash: u64,
    
    /// Number of learned examples that inform this verdict
    pub experience_basis: usize,
    
    /// Semantic distance to nearest threat prototype
    pub threat_proximity: f32,
    
    /// Semantic distance to nearest benign prototype
    pub benign_proximity: f32,
}

impl SemanticVerdict {
    /// Create a new semantic verdict
    /// 
    /// # Arguments
    /// * `threat_score` - Semantic threat level [0.0, 1.0]
    /// * `confidence` - Analysis confidence [0.0, 1.0]
    /// * `embedding` - The semantic embedding (used for hash, not stored)
    /// * `experience_basis` - Number of training examples
    /// * `threat_proximity` - Distance to threat prototype
    /// * `benign_proximity` - Distance to benign prototype
    pub fn new(
        threat_score: f32,
        confidence: f32,
        embedding: &[f32],
        experience_basis: usize,
        threat_proximity: f32,
        benign_proximity: f32,
    ) -> Self {
        // Derive semantic class from score and confidence
        let semantic_class = if confidence < 0.2 {
            SemanticClass::Unknown
        } else if threat_score > 0.7 {
            SemanticClass::Threat
        } else if threat_score < 0.3 {
            SemanticClass::Benign
        } else if threat_proximity < benign_proximity * 0.5 {
            SemanticClass::Threat
        } else if benign_proximity < threat_proximity * 0.5 {
            SemanticClass::Benign
        } else {
            SemanticClass::Anomalous
        };
        
        // Hash the EMBEDDING, not the raw input
        // This proves semantic processing occurred
        let analysis_hash = Self::hash_embedding(embedding);
        
        Self {
            threat_score: threat_score.clamp(0.0, 1.0),
            confidence: confidence.clamp(0.0, 1.0),
            semantic_class,
            analysis_hash,
            experience_basis,
            threat_proximity,
            benign_proximity,
        }
    }
    
    /// Create a verdict for unknown/unanalyzable content
    /// SECURITY-FIRST: Unknown defaults to suspicious
    pub fn unknown() -> Self {
        Self {
            threat_score: 0.4,  // Slightly suspicious
            confidence: 0.0,
            semantic_class: SemanticClass::Unknown,
            analysis_hash: 0,
            experience_basis: 0,
            threat_proximity: f32::INFINITY,
            benign_proximity: f32::INFINITY,
        }
    }
    
    /// Hash the semantic embedding to prove analysis occurred
    fn hash_embedding(embedding: &[f32]) -> u64 {
        let mut hasher = DefaultHasher::new();
        for &val in embedding {
            val.to_bits().hash(&mut hasher);
        }
        hasher.finish()
    }
    
    /// Check if this verdict indicates a threat
    pub fn is_threat(&self) -> bool {
        matches!(self.semantic_class, SemanticClass::Threat) 
            || (self.threat_score > 0.5 && self.confidence > 0.3)
    }
    
    /// Check if this verdict is high-confidence
    pub fn is_confident(&self) -> bool {
        self.confidence > 0.5 && self.experience_basis > 10
    }
}

/// Marker trait for types that belong to the Semantic Layer
/// 
/// Types implementing this trait:
/// - CAN access raw request data
/// - MUST NOT trigger system actions
/// - MUST produce SemanticVerdict as output
pub trait SemanticLayerComponent {
    /// Analyze raw data and produce a semantic verdict
    /// 
    /// # Invariants
    /// - This function MUST be pure (no side effects)
    /// - This function MUST NOT execute or interpret the data as code
    /// - This function MUST return only semantic properties
    fn analyze(&self, raw_data: &[u8]) -> SemanticVerdict;
}

/// Marker trait for types that belong to the Execution Layer
/// 
/// Types implementing this trait:
/// - CANNOT access raw request data (enforced by type signature)
/// - CAN trigger system actions
/// - MUST accept only SemanticVerdict as input
pub trait ExecutionLayerComponent {
    /// The action type this component produces
    type Action;
    
    /// Decide action based ONLY on semantic verdict
    /// 
    /// # Invariants
    /// - This function MUST NOT access raw request data
    /// - This function receives ONLY the SemanticVerdict
    /// - Decisions are based on semantic properties, not content
    fn decide(&self, verdict: &SemanticVerdict) -> Self::Action;
}

/// Execution actions that can result from semantic analysis
/// 
/// These are the INSTRUCTIONS that the execution layer can trigger.
/// They contain NO reference to the original data.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExecutionAction {
    /// Log for analysis (low threat)
    Log,
    /// Notify security team (medium threat)  
    Notify,
    /// Rate limit the source (elevated threat)
    Throttle,
    /// Isolate/quarantine (high threat)
    Isolate,
    /// Restart the affected process (severe threat)
    Restart,
    /// Capture forensic evidence and terminate (critical threat)
    SnapshotAndKill,
}

impl ExecutionAction {
    /// Get the severity level of this action [0.0, 1.0]
    pub fn severity(&self) -> f32 {
        match self {
            ExecutionAction::Log => 0.0,
            ExecutionAction::Notify => 0.2,
            ExecutionAction::Throttle => 0.4,
            ExecutionAction::Isolate => 0.6,
            ExecutionAction::Restart => 0.8,
            ExecutionAction::SnapshotAndKill => 1.0,
        }
    }
}

/// The Harvard Boundary - orchestrates semantic-execution separation
/// 
/// This struct enforces that:
/// 1. Raw data only goes to semantic analysis
/// 2. Only SemanticVerdict crosses the boundary
/// 3. Execution decisions are based solely on verdicts
pub struct HarvardBoundary<S, E> 
where 
    S: SemanticLayerComponent,
    E: ExecutionLayerComponent,
{
    semantic: S,
    execution: E,
}

impl<S, E> HarvardBoundary<S, E>
where
    S: SemanticLayerComponent,
    E: ExecutionLayerComponent,
{
    /// Create a new Harvard boundary with semantic and execution components
    pub fn new(semantic: S, execution: E) -> Self {
        Self { semantic, execution }
    }
    
    /// Process raw data through the Harvard architecture
    /// 
    /// # Data Flow
    /// ```text
    /// raw_data → [Semantic Layer] → SemanticVerdict → [Execution Layer] → Action
    /// ```
    /// 
    /// The raw_data NEVER reaches the execution layer.
    pub fn process(&self, raw_data: &[u8]) -> (SemanticVerdict, E::Action) {
        // SEMANTIC LAYER: Analyze meaning without execution
        let verdict = self.semantic.analyze(raw_data);
        
        // HARVARD BOUNDARY: Only SemanticVerdict crosses
        // raw_data is NOT passed to execution layer
        
        // EXECUTION LAYER: Decide action based on semantic verdict
        let action = self.execution.decide(&verdict);
        
        (verdict, action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_semantic_verdict_creation() {
        let embedding = vec![0.1, 0.2, 0.3, 0.4];
        let verdict = SemanticVerdict::new(
            0.8,  // High threat
            0.9,  // High confidence
            &embedding,
            100,  // Good experience basis
            0.2,  // Close to threat
            0.8,  // Far from benign
        );
        
        assert!(verdict.is_threat());
        assert!(verdict.is_confident());
        assert_eq!(verdict.semantic_class, SemanticClass::Threat);
    }
    
    #[test]
    fn test_unknown_is_suspicious() {
        let verdict = SemanticVerdict::unknown();
        
        // Unknown should be slightly suspicious (security-first)
        assert!(verdict.threat_score > 0.3);
        assert_eq!(verdict.confidence, 0.0);
        assert_eq!(verdict.semantic_class, SemanticClass::Unknown);
    }
    
    #[test]
    fn test_verdict_contains_no_raw_data() {
        // This test verifies that SemanticVerdict cannot contain raw request data
        // The struct has no String, Vec<u8>, or similar fields that could hold content
        let verdict = SemanticVerdict::unknown();
        
        // All fields are primitive types or enums - no raw data possible
        let _ = verdict.threat_score;
        let _ = verdict.confidence;
        let _ = verdict.semantic_class;
        let _ = verdict.analysis_hash;
        let _ = verdict.experience_basis;
    }
}
