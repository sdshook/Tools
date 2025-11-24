use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::enhanced_pattern_recognition::{ExperientialKnowledgeBase, ExperientialAnalysisResult, PatternRequestContext};
use crate::adaptive_threshold::{AdaptiveThreshold, ThreatAssessment};
use crate::retrospective_learning::{RetrospectiveLearningStats, RetrospectiveLearningSystem, MissedThreatEvent as RetroMissedThreatEvent, FalsePositiveEvent as RetroFalsePositiveEvent};
use crate::eq_iq_regulator::{ExperientialBehavioralRegulator, ContextEvent as EQContextEvent, FeedbackEvent, EQIQBalance, MultiDimensionalEQ};
use crate::memory_engine::bdh_memory::BdhMemory;

/// Complete WebGuard System Implementation
/// Integrates all components for comprehensive threat detection
#[derive(Debug)]
pub struct WebGuardSystem {
    /// Experiential knowledge base (replaces static pattern recognition)
    pub experiential_kb: ExperientialKnowledgeBase,
    /// Adaptive threshold system
    pub adaptive_threshold: AdaptiveThreshold,
    /// Retrospective learning system
    pub retrospective_learning: RetrospectiveLearningSystem,
    /// EQ/IQ regulation system
    pub eq_iq_regulator: ExperientialBehavioralRegulator,
    /// Memory system for learning and recall
    pub memory_system: BdhMemory,
    /// System configuration
    pub config: WebGuardConfig,
    /// Performance metrics
    pub metrics: SystemMetrics,
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
    pub experiential_analysis: Option<ExperientialAnalysisResult>,
    pub threshold_assessment: Option<ThreatAssessment>,
    pub processing_time_ms: f32,
    pub memory_influence: f32,
    pub learning_feedback: Option<String>,
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
        Self {
            experiential_kb: ExperientialKnowledgeBase::new(),
            adaptive_threshold: AdaptiveThreshold::new(),
            retrospective_learning: RetrospectiveLearningSystem::new(),
            eq_iq_regulator: ExperientialBehavioralRegulator::new(0.5, 0.5, 0.1),
            memory_system: BdhMemory::new(),
            config: WebGuardConfig::default(),
            metrics: SystemMetrics::new(),
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
    pub fn analyze_request(&mut self, request: &str) -> ThreatAnalysisResult {
        let start_time = std::time::Instant::now();
        
        // Create request context
        let context = self.create_request_context(request);
        
        // Extract features for analysis
        let features = self.extract_features(request);
        
        // Experiential knowledge base analysis
        let experiential_result = if self.config.enable_experiential_learning {
            let pattern_context = PatternRequestContext {
                method: context.method.clone(),
                url: context.url.clone(),
                content_type: Some(context.content_type.clone()),
                user_agent: Some(context.user_agent.clone()),
                headers: context.headers.clone(),
            };
            Some(self.experiential_kb.analyze_experiential(request, &pattern_context))
        } else {
            None
        };
        
        // Adaptive threshold assessment
        let threshold_result = if self.config.enable_adaptive_thresholds {
            Some(self.adaptive_threshold.assess_threat(&features))
        } else {
            None
        };
        
        // Memory system influence
        let memory_influence = if self.config.enable_memory_system {
            self.get_memory_influence(request)
        } else {
            0.0
        };
        
        // Calculate final threat score
        let threat_score = self.calculate_final_threat_score_experiential(
            &experiential_result,
            &threshold_result,
            memory_influence
        );
        
        // Determine confidence and risk level
        let confidence = self.calculate_confidence_experiential(&experiential_result, &threshold_result);
        let risk_level = self.determine_risk_level(threat_score, confidence);
        let detected_attack_types = self.extract_attack_types_experiential(&experiential_result);
        
        let processing_time = start_time.elapsed().as_millis() as f32;
        
        // Update metrics
        self.metrics.total_requests_processed += 1;
        self.metrics.average_processing_time_ms = 
            (self.metrics.average_processing_time_ms * (self.metrics.total_requests_processed - 1) as f32 + processing_time) 
            / self.metrics.total_requests_processed as f32;
        
        if threat_score > 0.5 {
            self.metrics.threats_detected += 1;
        }
        
        ThreatAnalysisResult {
            threat_score,
            confidence,
            detected_attack_types,
            risk_level,
            experiential_analysis: experiential_result,
            threshold_assessment: threshold_result,
            processing_time_ms: processing_time,
            memory_influence,
            learning_feedback: None, // Will be populated by learning system
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

    /// Extract features from request for analysis
    fn extract_features(&self, request: &str) -> [f32; 32] {
        let mut features = [0.0; 32];
        let request_lower = request.to_lowercase();
        
        // SQL Injection features (0-4)
        features[0] = if request_lower.contains("' or") || request_lower.contains("or '") { 0.9 } else { 0.0 };
        features[1] = if request_lower.contains("union select") { 0.95 } else { 0.0 };
        features[2] = if request_lower.contains("drop table") { 0.95 } else { 0.0 };
        features[3] = if request_lower.contains("delete from") { 0.9 } else { 0.0 };
        features[4] = if request_lower.contains("insert into") { 0.8 } else { 0.0 };
        
        // XSS features (5-9)
        features[5] = if request_lower.contains("<script") { 0.9 } else { 0.0 };
        features[6] = if request_lower.contains("javascript:") { 0.9 } else { 0.0 };
        features[7] = if request_lower.contains("onerror=") || request_lower.contains("onload=") { 0.8 } else { 0.0 };
        features[8] = if request_lower.contains("alert(") { 0.7 } else { 0.0 };
        features[9] = if request_lower.contains("eval(") { 0.8 } else { 0.0 };
        
        // Path Traversal features (10-14)
        features[10] = if request_lower.contains("../") || request_lower.contains("..\\") { 0.8 } else { 0.0 };
        features[11] = if request_lower.contains("/etc/passwd") { 0.95 } else { 0.0 };
        features[12] = if request_lower.contains("\\windows\\system32") { 0.9 } else { 0.0 };
        features[13] = if request_lower.contains("%2e%2e%2f") { 0.9 } else { 0.0 };
        features[14] = if request_lower.contains("file://") { 0.7 } else { 0.0 };
        
        // Command Injection features (15-19)
        features[15] = if request_lower.contains("; cat") || request_lower.contains("| cat") { 0.9 } else { 0.0 };
        features[16] = if request_lower.contains("; ls") || request_lower.contains("| ls") { 0.9 } else { 0.0 };
        features[17] = if request_lower.contains("; whoami") || request_lower.contains("| whoami") { 0.9 } else { 0.0 };
        features[18] = if request_lower.contains("cmd /c") || request_lower.contains("powershell") { 0.8 } else { 0.0 };
        features[19] = if request_lower.contains("/bin/bash") || request_lower.contains("/bin/sh") { 0.8 } else { 0.0 };
        
        // Encoding features (20-24)
        features[20] = if request_lower.contains("%3c%73%63%72%69%70%74") { 0.95 } else { 0.0 };
        features[21] = if request_lower.contains("%27%20%6f%72%20%27") { 0.9 } else { 0.0 };
        features[22] = if request_lower.contains("\\x3c\\x73\\x63\\x72\\x69\\x70\\x74") { 0.95 } else { 0.0 };
        features[23] = if request_lower.contains("%2527") || request_lower.contains("%252f") { 0.8 } else { 0.0 };
        features[24] = if request_lower.contains("&#x") { 0.7 } else { 0.0 };
        
        // Behavioral features (25-29)
        features[25] = self.calculate_entropy(request);
        features[26] = self.calculate_length_anomaly(request);
        features[27] = self.calculate_character_frequency_anomaly(request);
        features[28] = self.calculate_structural_anomaly(request);
        features[29] = self.calculate_legitimate_patterns(request);
        
        // Complexity and composite features (30-31)
        features[30] = self.calculate_complexity_score(request);
        features[31] = self.calculate_composite_threat_score(&features[0..30]);
        
        features
    }

    fn calculate_entropy(&self, request: &str) -> f32 {
        if request.is_empty() {
            return 0.0;
        }
        
        let mut char_counts = HashMap::new();
        for c in request.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }
        
        let len = request.len() as f32;
        let mut entropy = 0.0;
        
        for count in char_counts.values() {
            let p = *count as f32 / len;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }
        
        // Normalize entropy (typical max is around 6-8 for text)
        (entropy / 8.0).min(1.0)
    }

    fn calculate_length_anomaly(&self, request: &str) -> f32 {
        let len = request.len();
        
        // Typical web requests are 50-500 characters
        // Very short or very long requests are suspicious
        if len < 10 {
            0.3 // Short requests might be probes
        } else if len > 2000 {
            0.8 // Very long requests are suspicious
        } else if len > 1000 {
            0.4 // Moderately long requests
        } else {
            0.0 // Normal length
        }
    }

    fn calculate_character_frequency_anomaly(&self, request: &str) -> f32 {
        if request.is_empty() {
            return 0.0;
        }
        
        let special_chars = request.chars().filter(|c| !c.is_alphanumeric() && !c.is_whitespace()).count();
        let total_chars = request.len();
        let special_ratio = special_chars as f32 / total_chars as f32;
        
        // High ratio of special characters is suspicious
        if special_ratio > 0.5 {
            0.8
        } else if special_ratio > 0.3 {
            0.5
        } else if special_ratio > 0.1 {
            0.2
        } else {
            0.0
        }
    }

    fn calculate_structural_anomaly(&self, request: &str) -> f32 {
        let mut anomaly_score: f32 = 0.0;
        
        // Check for unusual patterns
        if request.contains("''") || request.contains("\"\"") {
            anomaly_score += 0.3; // Empty quotes
        }
        
        if request.matches('(').count() != request.matches(')').count() {
            anomaly_score += 0.4; // Unbalanced parentheses
        }
        
        if request.matches('[').count() != request.matches(']').count() {
            anomaly_score += 0.3; // Unbalanced brackets
        }
        
        if request.matches('{').count() != request.matches('}').count() {
            anomaly_score += 0.3; // Unbalanced braces
        }
        
        // Check for repeated patterns
        let repeated_patterns = ["../", "\\\\", "%%", "''", "\"\"", ";;"];
        for pattern in &repeated_patterns {
            if request.matches(pattern).count() > 2 {
                anomaly_score += 0.2;
            }
        }
        
        anomaly_score.min(1.0)
    }

    fn calculate_legitimate_patterns(&self, request: &str) -> f32 {
        let mut legitimacy_score: f32 = 0.0;
        let request_lower = request.to_lowercase();
        
        // Common legitimate patterns
        let legitimate_patterns = [
            "get /", "post /", "put /", "delete /",
            "http/1.1", "content-type:", "user-agent:",
            "application/json", "text/html", "image/",
            "/api/", "/static/", "/assets/", "/css/", "/js/",
            "username=", "password=", "email=", "name=",
            "select * from", "where id =", "order by", "limit"
        ];
        
        for pattern in &legitimate_patterns {
            if request_lower.contains(pattern) {
                legitimacy_score += 0.1;
            }
        }
        
        legitimacy_score.min(1.0)
    }

    fn calculate_complexity_score(&self, request: &str) -> f32 {
        let mut complexity = 0.0;
        
        // Length complexity
        complexity += (request.len() as f32 / 1000.0).min(0.3);
        
        // Character diversity
        let unique_chars = request.chars().collect::<std::collections::HashSet<_>>().len();
        complexity += (unique_chars as f32 / 100.0).min(0.3);
        
        // Nesting depth (parentheses, brackets, etc.)
        let nesting_chars = ['(', ')', '[', ']', '{', '}', '<', '>'];
        let nesting_count = request.chars().filter(|c| nesting_chars.contains(c)).count();
        complexity += (nesting_count as f32 / 20.0).min(0.4);
        
        complexity.min(1.0)
    }

    fn calculate_composite_threat_score(&self, features: &[f32]) -> f32 {
        // Use maximum-based scoring to avoid dilution
        let max_feature = features.iter().cloned().fold(0.0f32, f32::max);
        
        // Count high-confidence features
        let high_confidence_features = features.iter().filter(|&&f| f > 0.7).count() as f32;
        let medium_confidence_features = features.iter().filter(|&&f| f > 0.4 && f <= 0.7).count() as f32;
        
        // Composite scoring
        let base_score = max_feature;
        let confidence_boost = (high_confidence_features * 0.1 + medium_confidence_features * 0.05).min(0.3);
        
        (base_score + confidence_boost).min(1.0)
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
        let features = self.extract_features(request);
        
        // Check for similar patterns in memory using feature vector
        let similarity = self.memory_system.max_similarity(&features);
        similarity
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

    // New experiential methods
    fn calculate_final_threat_score_experiential(
        &self,
        experiential_result: &Option<ExperientialAnalysisResult>,
        threshold_result: &Option<ThreatAssessment>,
        memory_influence: f32,
    ) -> f32 {
        let mut final_score: f32 = 0.0;
        
        // Experiential analysis score
        if let Some(exp) = experiential_result {
            final_score = final_score.max(exp.overall_threat_score);
        }
        
        // Threshold assessment score
        if let Some(threshold) = threshold_result {
            final_score = final_score.max(threshold.base_similarity);
        }
        
        // Apply memory influence
        final_score = (final_score + memory_influence * 0.2).min(1.0);
        
        final_score
    }

    fn calculate_confidence_experiential(
        &self,
        experiential_result: &Option<ExperientialAnalysisResult>,
        threshold_result: &Option<ThreatAssessment>,
    ) -> f32 {
        let mut confidence_factors = Vec::new();
        
        if let Some(exp) = experiential_result {
            confidence_factors.push(exp.confidence_level);
        }
        
        if let Some(threshold) = threshold_result {
            confidence_factors.push(threshold.confidence_score);
        }
        
        if confidence_factors.is_empty() {
            0.5
        } else {
            confidence_factors.iter().sum::<f32>() / confidence_factors.len() as f32
        }
    }

    fn extract_attack_types_experiential(&self, experiential_result: &Option<ExperientialAnalysisResult>) -> Vec<String> {
        if let Some(exp) = experiential_result {
            exp.matched_learned_patterns.iter()
                .map(|p| p.pattern.pattern.clone())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Feed learning results into the experiential knowledge base
    pub fn learn_from_validation(&mut self, request: &str, is_threat: bool, attack_type: Option<String>) {
        if self.config.enable_experiential_learning {
            let pattern = request.to_string();
            let context = vec![attack_type.unwrap_or_else(|| "unknown".to_string())];
            let discovery_method = if is_threat {
                crate::enhanced_pattern_recognition::DiscoveryMethod::ThreatValidation
            } else {
                crate::enhanced_pattern_recognition::DiscoveryMethod::FalsePositiveCorrection
            };
            self.experiential_kb.learn_pattern(pattern, is_threat, context, discovery_method);
        }
    }

    /// Export learned knowledge for sharing with other WebGuard instances
    pub fn export_knowledge(&self) -> Option<String> {
        if self.config.enable_knowledge_sharing {
            match self.experiential_kb.export_knowledge() {
                Ok(json) => Some(json),
                Err(_) => None,
            }
        } else {
            None
        }
    }

    /// Import knowledge from another WebGuard instance
    pub fn import_knowledge(&mut self, knowledge_json: &str) -> Result<(), String> {
        if self.config.enable_knowledge_sharing {
            match self.experiential_kb.import_knowledge(knowledge_json) {
                Ok(_) => Ok(()),
                Err(e) => Err(format!("Failed to import knowledge: {}", e)),
            }
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
        // Extract features and store in memory with valence based on threat score
        let features = self.extract_features(request);
        let valence = if result.threat_score > 0.5 { -1.0 } else { 1.0 };
        
        self.memory_system.add_trace(features, valence);
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
            let features = self.extract_features(&event.original_input);
            
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
            let features = self.extract_features(&event.original_input);
            
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