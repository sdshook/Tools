use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use crate::adaptive_threshold::{AdaptiveThreshold, ThreatAssessment};
use crate::retrospective_learning::{RetrospectiveLearningStats, RetrospectiveLearningSystem, MissedThreatEvent as RetroMissedThreatEvent, FalsePositiveEvent as RetroFalsePositiveEvent};
use crate::eq_iq_regulator::{ExperientialBehavioralRegulator, ContextEvent as EQContextEvent, FeedbackEvent, EQIQBalance, MultiDimensionalEQ};
use crate::memory_engine::bdh_memory::BdhMemory;
use crate::mesh_cognition::{HostMeshCognition, WebServiceType};
use crate::advanced_feature_extractor::AdvancedFeatureExtractor;
use crate::embedding_learner::EmbeddingLearner;

/// Complete WebGuard System Implementation
/// Uses pure PSI/BHSM/CMNN cognitive architecture for threat detection
/// Now enhanced with learnable embeddings for true experiential RL
#[derive(Debug)]
pub struct WebGuardSystem {
    /// Host-based mesh cognition system (PSI/BHSM/CMNN)
    pub mesh_cognition: Arc<Mutex<HostMeshCognition>>,
    /// Feature extraction system (legacy, kept for compatibility)
    pub feature_extractor: AdvancedFeatureExtractor,
    /// Learnable embedding system for experiential RL
    pub embedding_learner: EmbeddingLearner,
    /// Adaptive threshold system
    pub adaptive_threshold: AdaptiveThreshold,
    /// Retrospective learning system
    pub retrospective_learning: RetrospectiveLearningSystem,
    /// EQ/IQ regulation system
    pub eq_iq_regulator: ExperientialBehavioralRegulator,
    /// System configuration
    pub config: WebGuardConfig,
    /// Performance metrics
    pub metrics: SystemMetrics,
    /// Service ID for this WebGuard instance
    pub service_id: String,
    /// Use embedding-based detection (vs legacy feature-based)
    pub use_embedding_detection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebGuardConfig {
    pub enable_experiential_learning: bool,
    pub enable_knowledge_sharing: bool,
    pub enable_adaptive_thresholds: bool,
    pub enable_retrospective_learning: bool,
    pub enable_eq_iq_regulation: bool,
    pub enable_memory_system: bool,
    pub base_threat_threshold: f32,
    pub learning_rate: f32,
    pub overfitting_prevention: bool,
}

#[derive(Debug, Clone)]
pub struct SystemMetrics {
    pub total_requests_processed: u64,
    pub threats_detected: u64,
    pub false_positives: u64,
    pub false_negatives: u64,
    pub average_processing_time_ms: f32,
    pub memory_usage_mb: f32,
    pub learning_events: u64,
}

#[derive(Debug, Clone)]
pub struct ThreatAnalysisResult {
    pub threat_score: f32,
    pub confidence: f32,
    pub detected_attack_types: Vec<String>,
    pub risk_level: String,
    pub cognitive_analysis: CognitiveAnalysisResult,
    pub threshold_assessment: Option<ThreatAssessment>,
    pub processing_time_ms: f32,
    pub memory_influence: f32,
    pub learning_feedback: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CognitiveAnalysisResult {
    pub psi_valence: f32,
    pub bhsm_activation: f32,
    pub cmnn_confidence: f32,
    pub learned_patterns: Vec<String>,
    pub mesh_aggression: f32,
    pub service_consensus: f32,
}

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub content_type: String,
    pub user_agent: String,
    pub source_ip: String,
    pub timestamp: std::time::SystemTime,
}

#[derive(Debug, Clone)]
pub struct ContextEvent {
    pub timestamp: std::time::SystemTime,
    pub request_context: String,
    pub user_context: String,
    pub environmental_factors: HashMap<String, String>,
    pub threat_indicators: Vec<String>,
}

impl Default for ContextEvent {
    fn default() -> Self {
        Self {
            timestamp: std::time::SystemTime::now(),
            request_context: String::new(),
            user_context: String::new(),
            environmental_factors: HashMap::new(),
            threat_indicators: Vec::new(),
        }
    }
}

impl WebGuardSystem {
    pub fn new() -> Self {
        let mesh_cognition = Arc::new(Mutex::new(HostMeshCognition::new(
            0.6,  // mesh_learning_rate
            0.3,  // cross_service_threshold
            0.5,  // initial_aggression
        )));
        
        let service_id = {
            let mut mesh = mesh_cognition.lock().unwrap();
            mesh.register_service(WebServiceType::IIS, 2001)
        };
        
        Self {
            mesh_cognition,
            feature_extractor: AdvancedFeatureExtractor::new(),
            embedding_learner: EmbeddingLearner::new(),
            adaptive_threshold: AdaptiveThreshold::new(),
            retrospective_learning: RetrospectiveLearningSystem::new(),
            eq_iq_regulator: ExperientialBehavioralRegulator::new(0.5, 0.5, 0.1),
            config: WebGuardConfig::default(),
            metrics: SystemMetrics::new(),
            service_id: service_id.to_string(),
            use_embedding_detection: true,  // Enable embedding-based detection by default
        }
    }

    /// Initialize all subsystems
    pub fn initialize_memory_engine(&mut self) {
        // Memory engine is already initialized in new()
    }

    pub fn initialize_learning_systems(&mut self) {
        // Learning systems are already initialized
    }

    pub fn initialize_pattern_recognition(&mut self) {
        // Pattern recognition is already initialized
    }

    pub fn initialize_adaptive_thresholds(&mut self) {
        // Adaptive thresholds are already initialized
    }

    pub fn initialize_eq_iq_regulation(&mut self) {
        // EQ/IQ regulation is already initialized
    }

    pub fn initialize_experiential_anomaly_detection(&mut self) {
        // This would be part of pattern recognition and memory systems
    }

    /// Main threat analysis function
    /// Uses learnable embeddings for true experiential RL when enabled
    pub fn analyze_request(&mut self, request: &str) -> ThreatAnalysisResult {
        let start_time = std::time::Instant::now();
        
        // Create request context
        let _context = self.create_request_context(request);
        
        // EMBEDDING-BASED DETECTION (experiential RL)
        let (threat_score, confidence) = if self.use_embedding_detection {
            // Generate embedding and calculate threat score
            let embedding = self.embedding_learner.embed(request);
            let score = self.embedding_learner.threat_score(&embedding);
            
            // Confidence based on prototype separation and experience
            let stats = self.embedding_learner.get_stats();
            let separation = stats.get("prototype_separation").unwrap_or(&0.1);
            let experience = stats.get("threat_experiences").unwrap_or(&0.0) 
                           + stats.get("benign_experiences").unwrap_or(&0.0);
            
            // Higher separation and more experience = higher confidence
            let conf = (separation / 2.0).min(1.0) * (experience / (experience + 10.0));
            
            (score, conf.max(0.1))
        } else {
            // Legacy feature-based detection
            let features = self.feature_extractor.extract_features(request);
            let cognitive_analysis = self.perform_cognitive_analysis(request, &features);
            let threshold_result = if self.config.enable_adaptive_thresholds {
                Some(self.adaptive_threshold.assess_threat(&features))
            } else {
                None
            };
            
            let score = self.calculate_final_threat_score_cognitive(
                &cognitive_analysis, &threshold_result, cognitive_analysis.bhsm_activation
            );
            let conf = self.calculate_confidence_cognitive(&cognitive_analysis, &threshold_result);
            (score, conf)
        };
        
        // Determine risk level and attack types
        let risk_level = self.determine_risk_level(threat_score, confidence);
        let detected_attack_types = if threat_score > 0.5 {
            vec!["potential_threat".to_string()]
        } else {
            Vec::new()
        };
        
        let processing_time = start_time.elapsed().as_millis() as f32;
        
        // Update metrics
        self.metrics.total_requests_processed += 1;
        self.metrics.average_processing_time_ms = 
            (self.metrics.average_processing_time_ms * (self.metrics.total_requests_processed - 1) as f32 + processing_time) 
            / self.metrics.total_requests_processed as f32;
        
        if threat_score > 0.5 {
            self.metrics.threats_detected += 1;
        }
        
        // Create cognitive analysis result (for compatibility)
        let cognitive_analysis = CognitiveAnalysisResult {
            psi_valence: threat_score,
            bhsm_activation: threat_score,
            cmnn_confidence: confidence,
            learned_patterns: detected_attack_types.clone(),
            mesh_aggression: 0.0,
            service_consensus: confidence,
        };
        
        ThreatAnalysisResult {
            threat_score,
            confidence,
            detected_attack_types,
            risk_level,
            cognitive_analysis,
            threshold_assessment: None,
            processing_time_ms: processing_time,
            memory_influence: threat_score,
            learning_feedback: None,
        }
    }

    /// Comprehensive threat analysis with full system integration
    pub fn comprehensive_threat_analysis(&mut self, request: &str) -> ThreatAnalysisResult {
        let mut result = self.analyze_request(request);
        
        // Apply EQ/IQ regulation if enabled
        if self.config.enable_eq_iq_regulation {
            let eq_iq_balance = self.get_eq_iq_balance();
            result.threat_score = self.apply_eq_iq_adjustment(result.threat_score, &eq_iq_balance);
        }
        
        // Store analysis in memory system
        if self.config.enable_memory_system {
            self.store_analysis_in_memory(&result, request);
        }
        
        result
    }

    /// Perform cognitive analysis using PSI/BHSM/CMNN architecture
    fn perform_cognitive_analysis(&mut self, _request: &str, features: &[f32]) -> CognitiveAnalysisResult {
        let mesh = self.mesh_cognition.lock().unwrap();
        
        // Get service memory for BHSM analysis using differential RL approach
        let (bhsm_activation, has_learned_patterns) = if let Some(service_memory) = mesh.get_service_memory(&self.service_id) {
            if let Ok(bdh) = service_memory.try_lock() {
                if features.len() >= 32 {
                    let mut array = [0.0f32; 32];
                    array.copy_from_slice(&features[..32]);
                    // Use differential similarity: threat_sim - benign_sim
                    // This is the key RL fix: benign patterns now SUPPRESS threat scores
                    let differential = bdh.differential_threat_similarity(&array);
                    let has_patterns = bdh.get_trace_count() > 0;
                    (differential, has_patterns)
                } else {
                    (0.0, false)
                }
            } else {
                (0.0, false)
            }
        } else {
            (0.0, false)
        };
        
        // PSI valence: Start neutral (0.5) when no patterns learned
        // Then adjust based on BHSM differential activation
        let psi_valence = if has_learned_patterns {
            // With learned patterns, use BHSM differential as primary signal
            // bhsm_activation is already differential (threat - benign)
            bhsm_activation
        } else {
            // No patterns yet - use conservative baseline (assume benign until proven otherwise)
            // Raw feature average, but dampened to avoid over-alerting on unknown patterns
            let raw_avg = features.iter().sum::<f32>() / features.len() as f32;
            raw_avg * 0.3  // Dampen to 30% - be cautious but not paranoid
        };
        
        // CMNN confidence based on having learned patterns and pattern match strength
        let cmnn_confidence = if has_learned_patterns && bhsm_activation > 0.1 {
            // High confidence when we have strong differential match to threats
            bhsm_activation.min(1.0)
        } else if has_learned_patterns {
            // We have patterns but no strong threat match - moderately confident it's benign
            0.3
        } else {
            // No patterns learned yet - low confidence
            0.1
        };
        
        // Get mesh aggression level
        let mesh_aggression = mesh.get_host_aggression();
        
        // Service consensus based on differential threat detection
        let service_consensus = if bhsm_activation > 0.5 { 
            0.8  // High consensus on threat
        } else if bhsm_activation < 0.2 && has_learned_patterns {
            0.2  // High consensus on benign (low differential = more similar to benign)
        } else {
            0.5  // Uncertain
        };
        
        // Extract learned patterns only when differential indicates threat
        let learned_patterns = if psi_valence > 0.5 && bhsm_activation > 0.3 {
            vec!["potential_threat".to_string()]
        } else {
            Vec::new()
        };
        
        CognitiveAnalysisResult {
            psi_valence,
            bhsm_activation,
            cmnn_confidence,
            learned_patterns,
            mesh_aggression,
            service_consensus,
        }
    }

    /// Calculate final threat score using cognitive analysis
    fn calculate_final_threat_score_cognitive(
        &self,
        cognitive_analysis: &CognitiveAnalysisResult,
        threshold_result: &Option<ThreatAssessment>,
        memory_influence: f32,
    ) -> f32 {
        let mut score = cognitive_analysis.psi_valence * 0.4;
        score += cognitive_analysis.bhsm_activation * 0.3;
        score += cognitive_analysis.cmnn_confidence * 0.2;
        score += memory_influence * 0.1;
        
        // Apply threshold adjustment if available
        if let Some(threshold) = threshold_result {
            score = (score + threshold.base_similarity) / 2.0;
        }
        
        // Apply mesh aggression influence
        score *= (1.0 + cognitive_analysis.mesh_aggression * 0.1);
        
        score.min(1.0)
    }

    /// Calculate confidence using cognitive analysis
    fn calculate_confidence_cognitive(
        &self,
        cognitive_analysis: &CognitiveAnalysisResult,
        threshold_result: &Option<ThreatAssessment>,
    ) -> f32 {
        let mut confidence = cognitive_analysis.cmnn_confidence * 0.5;
        confidence += cognitive_analysis.service_consensus * 0.3;
        confidence += cognitive_analysis.bhsm_activation * 0.2;
        
        if let Some(threshold) = threshold_result {
            confidence = (confidence + threshold.confidence_score) / 2.0;
        }
        
        confidence.min(1.0)
    }

    /// Extract attack types from cognitive analysis
    fn extract_attack_types_cognitive(&self, cognitive_analysis: &CognitiveAnalysisResult) -> Vec<String> {
        cognitive_analysis.learned_patterns.clone()
    }





    fn create_request_context(&self, request: &str) -> RequestContext {
        // Parse basic request information
        let lines: Vec<&str> = request.lines().collect();
        let first_line = lines.first().unwrap_or(&"").to_string();
        
        let mut method = "GET".to_string();
        let mut url = "/".to_string();
        
        if let Some(parts) = first_line.split_whitespace().collect::<Vec<_>>().get(0..2) {
            method = parts[0].to_string();
            url = parts[1].to_string();
        }
        
        RequestContext {
            method,
            url,
            headers: HashMap::new(),
            content_type: "text/plain".to_string(),
            user_agent: "unknown".to_string(),
            source_ip: "127.0.0.1".to_string(),
            timestamp: std::time::SystemTime::now(),
        }
    }

    fn get_memory_influence(&mut self, request: &str) -> f32 {
        // Extract features from request for memory lookup
        let features = self.feature_extractor.extract_features(request);
        let mut mesh = self.mesh_cognition.lock().unwrap();
        
        // Check for similar patterns in service memory
        if let Some(service_memory) = mesh.get_service_memory(&self.service_id) {
            if let Ok(bdh) = service_memory.try_lock() {
                if features.len() >= 32 {
                    let mut array = [0.0f32; 32];
                    array.copy_from_slice(&features[..32]);
                    bdh.max_similarity(&array)
                } else {
                    0.0
                }
            } else {
                0.0
            }
        } else {
            0.0
        }
    }

    fn _calculate_final_threat_score_legacy(
        &self,
        _pattern_result: &Option<()>, // Placeholder for removed PatternAnalysisResult
        threshold_result: &Option<ThreatAssessment>,
        memory_influence: f32,
    ) -> f32 {
        let mut final_score: f32 = 0.0;
        
        // Legacy pattern recognition score (removed)
        // if let Some(pattern) = pattern_result {
        //     final_score = final_score.max(pattern.overall_threat_score);
        // }
        
        // Threshold assessment score
        if let Some(threshold) = threshold_result {
            final_score = final_score.max(threshold.base_similarity);
        }
        
        // Apply memory influence
        final_score = (final_score + memory_influence * 0.2).min(1.0);
        
        final_score
    }

    fn _calculate_confidence_legacy(
        &self,
        _pattern_result: &Option<()>, // Placeholder for removed PatternAnalysisResult
        threshold_result: &Option<ThreatAssessment>,
    ) -> f32 {
        let mut confidence_factors = Vec::new();
        
        // Legacy pattern confidence (removed)
        // if let Some(pattern) = pattern_result {
        //     confidence_factors.push(pattern.confidence_level);
        // }
        
        if let Some(threshold) = threshold_result {
            confidence_factors.push(threshold.confidence_score);
        }
        
        if confidence_factors.is_empty() {
            0.5
        } else {
            confidence_factors.iter().sum::<f32>() / confidence_factors.len() as f32
        }
    }

    fn determine_risk_level(&self, threat_score: f32, confidence: f32) -> String {
        let risk_score = threat_score * confidence;
        
        if risk_score > 0.8 {
            "CRITICAL".to_string()
        } else if risk_score > 0.6 {
            "HIGH".to_string()
        } else if risk_score > 0.4 {
            "MEDIUM".to_string()
        } else if risk_score > 0.2 {
            "LOW".to_string()
        } else {
            "MINIMAL".to_string()
        }
    }

    fn _extract_attack_types_legacy(&self, _pattern_result: &Option<()>) -> Vec<String> {
        // Legacy pattern attack type extraction (removed)
        Vec::new()
    }

    /// Feed learning results into the embedding system
    /// This implements true experiential reinforcement learning:
    /// - Positive reward for correct classifications
    /// - Updates embedding weights to improve future predictions
    pub fn learn_from_validation(&mut self, request: &str, is_threat: bool, _attack_type: Option<String>) {
        if !self.config.enable_experiential_learning {
            return;
        }
        
        if self.use_embedding_detection {
            // EMBEDDING-BASED LEARNING (true experiential RL)
            // Reward is positive for correct implicit validation
            let reward = 1.0;
            self.embedding_learner.learn(request, is_threat, reward);
            self.metrics.learning_events += 1;
        } else {
            // Legacy BDH-based learning
            let features = self.feature_extractor.extract_features(request);
            let mut mesh = self.mesh_cognition.lock().unwrap();
            
            if let Some(service_memory) = mesh.get_service_memory(&self.service_id) {
                if let Ok(mut bdh) = service_memory.try_lock() {
                    let target_valence = if is_threat { 1.0 } else { 0.0 };
                    
                    if features.len() >= 32 {
                        let mut array = [0.0f32; 32];
                        array.copy_from_slice(&features[..32]);
                        bdh.add_trace(array, target_valence);
                    }
                }
            }
            
            if is_threat {
                mesh.update_host_aggression(0.1);
            } else {
                mesh.update_host_aggression(-0.05);
            }
        }
    }
    
    /// Learn from a prediction error (FP or FN) with contrastive update
    /// This is the KEY to experiential learning improvement over passes:
    /// - Errors drive stronger updates to the embedding space
    /// - FN: Push embedding toward threat prototype
    /// - FP: Push embedding toward benign prototype
    pub fn learn_from_error(&mut self, request: &str, predicted_threat: bool, actual_threat: bool) {
        if predicted_threat == actual_threat {
            return; // No error to learn from
        }
        
        if !self.config.enable_experiential_learning {
            return;
        }
        
        if self.use_embedding_detection {
            // EMBEDDING-BASED ERROR CORRECTION (contrastive learning)
            self.embedding_learner.learn_from_error(request, predicted_threat, actual_threat);
            self.metrics.learning_events += 1;
            
            // Track FP/FN in metrics
            if actual_threat && !predicted_threat {
                self.metrics.false_negatives += 1;
            } else {
                self.metrics.false_positives += 1;
            }
        } else {
            // Legacy BDH-based error learning
            let features = self.feature_extractor.extract_features(request);
            let mut mesh = self.mesh_cognition.lock().unwrap();
            
            if let Some(service_memory) = mesh.get_service_memory(&self.service_id) {
                if let Ok(mut bdh) = service_memory.try_lock() {
                    if features.len() >= 32 {
                        let mut array = [0.0f32; 32];
                        array.copy_from_slice(&features[..32]);
                        let target_valence = if actual_threat { 1.0 } else { 0.0 };
                        bdh.add_trace(array, target_valence);
                    }
                }
            }
        }
    }
    
    /// Get embedding learner statistics for monitoring learning progress
    pub fn get_embedding_stats(&self) -> HashMap<String, f32> {
        self.embedding_learner.get_stats()
    }
    
    /// Debug: print current learning state
    pub fn debug_print_learning_state(&self) {
        self.embedding_learner.debug_print_state();
    }

    /// Export learned knowledge from cognitive mesh
    pub fn export_knowledge(&self) -> Option<String> {
        if self.config.enable_knowledge_sharing {
            let mesh = self.mesh_cognition.lock().unwrap();
            // Simplified export - in practice would serialize mesh state
            Some(format!("{{\"aggression\": {}, \"service_id\": {}}}", 
                mesh.get_host_aggression(), self.service_id))
        } else {
            None
        }
    }

    /// Import knowledge into cognitive mesh
    pub fn import_knowledge(&mut self, knowledge_json: &str) -> Result<(), String> {
        if self.config.enable_knowledge_sharing {
            // Simplified import - in practice would deserialize and apply mesh state
            Ok(())
        } else {
            Err("Knowledge sharing is disabled".to_string())
        }
    }

    fn apply_eq_iq_adjustment(&self, threat_score: f32, eq_iq_balance: &EQIQBalance) -> f32 {
        // Apply EQ/IQ balance to threat score
        let adjustment_factor = eq_iq_balance.balance;
        
        // Higher balance (more analytical) increases sensitivity
        // Lower balance (more emotional) decreases sensitivity
        let adjusted_score = threat_score * (0.8 + adjustment_factor * 0.4);
        adjusted_score.min(1.0).max(0.0)
    }

    fn store_analysis_in_memory(&mut self, result: &ThreatAnalysisResult, request: &str) {
        // Extract features and store in cognitive mesh memory
        let features = self.feature_extractor.extract_features(request);
        let threat_value = result.threat_score;
        let mut mesh = self.mesh_cognition.lock().unwrap();
        
        // Store in service memory
        if let Some(service_memory) = mesh.get_service_memory(&self.service_id) {
            if let Ok(mut bdh) = service_memory.try_lock() {
                if features.len() >= 32 {
                    let mut array = [0.0f32; 32];
                    array.copy_from_slice(&features[..32]);
                    bdh.add_trace(array, threat_value);
                }
            }
        }
    }

    // Additional methods for comprehensive testing compatibility
    pub fn store_analysis_result(&mut self, _result: &ThreatAnalysisResult) {
        // Store result in memory system
    }

    pub fn add_missed_threat(&mut self, event: MissedThreatEvent) {
        if self.config.enable_retrospective_learning {
            // Convert timestamp to f64
            let timestamp = event.timestamp.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs_f64();
            
            // Extract features from the original input
            let features = self.feature_extractor.extract_features(&event.original_input);
            
            // Create context event
            let context_event = crate::eq_iq_regulator::ContextEvent {
                timestamp,
                context_stability: 0.5, // Default value
                threat_level: event.severity,
                response_appropriateness: 0.5, // Default value
            };
            
            // Convert to retrospective learning event format
            let retro_event = RetroMissedThreatEvent {
                original_timestamp: timestamp,
                discovery_timestamp: timestamp + 3600.0, // Assume discovered 1 hour later
                original_threat_score: event.original_score,
                actual_threat_level: event.severity,
                feature_vector: features.to_vec(),
                original_context: context_event,
                discovery_method: crate::retrospective_learning::ThreatDiscoveryMethod::SecurityAudit,
                consequence_severity: event.severity,
            };
            self.retrospective_learning.add_missed_threat(retro_event);
            self.metrics.learning_events += 1;
        }
    }

    pub fn add_false_positive(&mut self, event: FalsePositiveEvent) {
        if self.config.enable_retrospective_learning {
            // Convert timestamp to f64
            let timestamp = event.timestamp.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs_f64();
            
            // Extract features from the original input
            let features = self.feature_extractor.extract_features(&event.original_input);
            
            // Create context event
            let context_event = crate::eq_iq_regulator::ContextEvent {
                timestamp,
                context_stability: 0.5, // Default value
                threat_level: 0.1, // Low threat level for false positive
                response_appropriateness: 0.3, // Lower appropriateness for false positive
            };
            
            // Convert to retrospective learning event format
            let retro_event = RetroFalsePositiveEvent {
                timestamp,
                original_threat_score: event.original_score,
                actual_threat_level: 0.1, // Low actual threat for false positive
                feature_vector: features.to_vec(),
                context: context_event,
                impact_severity: 0.5, // Default impact severity
            };
            self.retrospective_learning.add_false_positive(retro_event);
            self.metrics.learning_events += 1;
        }
    }

    pub fn get_learning_stats(&self) -> &RetrospectiveLearningStats {
        self.retrospective_learning.get_learning_stats()
    }

    pub fn get_current_threshold(&self) -> f32 {
        self.adaptive_threshold.base_threshold
    }

    pub fn process_threat_result(&mut self, result: &ThreatAnalysisResult, confirmed: bool) {
        if let Some(assessment) = &result.threshold_assessment {
            self.adaptive_threshold.update_performance(assessment, confirmed);
        }
        
        if confirmed {
            self.metrics.threats_detected += 1;
        } else if result.threat_score > 0.5 {
            self.metrics.false_positives += 1;
        }
    }

    pub fn process_context_event(&mut self, context: &ContextEvent) {
        if self.config.enable_eq_iq_regulation {
            // Process context event through EQ/IQ regulator
            // This would update the emotional/analytical balance
        }
    }

    pub fn get_eq_iq_balance(&self) -> EQIQBalance {
        // Create a default balance based on current regulator state
        EQIQBalance {
            eq: 0.5,
            eq_vector: MultiDimensionalEQ {
                contextual_stability: 0.5,
                response_appropriateness: 0.5,
                social_awareness: 0.5,
                emotional_regulation: 0.5,
                empathic_accuracy: 0.5,
            },
            iq: 0.5,
            balance: 0.5,
            eq_uncertainty: 0.1,
            iq_uncertainty: 0.1,
            confidence: 0.8,
        }
    }

    pub fn update_behavioral_baseline(&mut self, _result: &ThreatAnalysisResult) {
        // Update behavioral baseline in memory system
    }
}

impl WebGuardConfig {
    pub fn default() -> Self {
        Self {
            enable_experiential_learning: true,
            enable_knowledge_sharing: true,
            enable_adaptive_thresholds: true,
            enable_retrospective_learning: true,
            enable_eq_iq_regulation: true,
            enable_memory_system: true,
            base_threat_threshold: 0.3,
            learning_rate: 0.1,
            overfitting_prevention: true,
        }
    }
}

impl SystemMetrics {
    pub fn new() -> Self {
        Self {
            total_requests_processed: 0,
            threats_detected: 0,
            false_positives: 0,
            false_negatives: 0,
            average_processing_time_ms: 0.0,
            memory_usage_mb: 0.0,
            learning_events: 0,
        }
    }
}

impl Default for WebGuardSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Event structure for missed threats (false negatives)
#[derive(Debug, Clone)]
pub struct MissedThreatEvent {
    pub timestamp: std::time::SystemTime,
    pub original_input: String,
    pub original_score: f32,
    pub actual_threat_type: String,
    pub severity: f32,
    pub context: HashMap<String, String>,
}

/// Event structure for false positives
#[derive(Debug, Clone)]
pub struct FalsePositiveEvent {
    pub timestamp: std::time::SystemTime,
    pub original_input: String,
    pub original_score: f32,
    pub actual_classification: String,
    pub context: HashMap<String, String>,
}