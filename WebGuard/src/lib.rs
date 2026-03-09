// Core architecture - Harvard semantic/execution separation
pub mod harvard_architecture;

// Configuration
pub mod config;
pub mod runtime_config;

// Semantic Layer (Harvard "Data Memory")
pub mod semantic_normalizer;  // Pre-processing: deterministic normalization
pub mod featurizer;
pub mod advanced_feature_extractor;
pub mod embedding_learner;
pub mod memory_engine;
pub mod experiential_anomaly;

// Cognitive Layer - BHSM
pub mod self_model;  // Metacognitive monitoring: coherence, confidence, arrogance

// Execution Layer (Harvard "Instruction Memory")  
pub mod policy;  // RISC 3-action constraint: Detect, Allow, Block
pub mod actuators;
pub mod adaptive_threshold;

// Learning Systems
pub mod eq_iq_regulator;
pub mod retrospective_learning;
pub mod threat_educator;  // Pedagogical knowledge transfer to PSI

// Infrastructure
pub mod mesh_cognition;
pub mod sensors;
pub mod evidence;

// Logging
pub mod detection_logger;

// Main System
pub mod webguard_system;
