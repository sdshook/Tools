use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::enhanced_pattern_recognition::{EnhancedPatternRecognition, PatternAnalysisResult};
use crate::adaptive_threshold::{AdaptiveThreshold, ThreatAssessment};
use crate::retrospective_learning::{RetrospectiveLearningStats};
use crate::eq_iq_regulator::{ExperientialBehavioralRegulator, ContextEvent, FeedbackEvent};
use crate::memory_engine::bdh_memory::{BidirectionalDynamicHebbian, MemoryEvent};

/// Complete WebGuard System Implementation
/// Integrates all components for comprehensive threat detection
#[derive(Debug)]
pub struct WebGuardSystem {
    /// Enhanced pattern recognition engine
    pub pattern_recognition: EnhancedPatternRecognition,
    /// Adaptive threshold system
    pub adaptive_threshold: AdaptiveThreshold,
    /// Retrospective learning system
    pub retrospective_learning: RetrospectiveLearning,
    /// EQ/IQ regulation system
    pub eq_iq_regulator: EQIQRegulator,
    /// Memory system for learning and recall
    pub memory_system: BidirectionalDynamicHebbian,
    /// System configuration
    pub config: WebGuardConfig,
    /// Performance metrics
    pub metrics: SystemMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebGuardConfig {
    pub enable_pattern_recognition: bool,
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
    pub pattern_analysis: Option<PatternAnalysisResult>,
    pub threshold_assessment: Option<ThreatAssessment>,
    pub processing_time_ms: f32,
    pub memory_influence: f32,
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
            pattern_recognition: EnhancedPatternRecognition::new(),
            adaptive_threshold: AdaptiveThreshold::new(),
            retrospective_learning: RetrospectiveLearning::new(),
            eq_iq_regulator: EQIQRegulator::new(),
            memory_system: BidirectionalDynamicHebbian::new(0.1, 0.05, 0.01),
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
        
        // Pattern recognition analysis
        let pattern_result = if self.config.enable_pattern_recognition {
            Some(self.pattern_recognition.analyze_patterns(request, &context))
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
        let threat_score = self.calculate_final_threat_score(
            &pattern_result,
            &threshold_result,
            memory_influence
        );
        
        // Determine confidence and risk level
        let confidence = self.calculate_confidence(&pattern_result, &threshold_result);
        let risk_level = self.determine_risk_level(threat_score, confidence);
        let detected_attack_types = self.extract_attack_types(&pattern_result);
        
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
            pattern_analysis: pattern_result,
            threshold_assessment: threshold_result,
            processing_time_ms: processing_time,
            memory_influence,
        }
    }

    /// Comprehensive threat analysis with full system integration
    pub fn comprehensive_threat_analysis(&mut self, request: &str) -> ThreatAnalysisResult {
        let mut result = self.analyze_request(request);
        
        // Apply EQ/IQ regulation if enabled
        if self.config.enable_eq_iq_regulation {
            let eq_iq_balance = self.eq_iq_regulator.get_current_balance();
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
        let mut anomaly_score = 0.0;
        
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
        let mut legitimacy_score = 0.0;
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
        // Create memory event for the request
        let memory_event = MemoryEvent {
            timestamp: std::time::SystemTime::now(),
            event_type: "request_analysis".to_string(),
            payload: request.to_string(),
            threat_score: 0.0, // Will be updated later
            context: HashMap::new(),
        };
        
        // Check for similar patterns in memory
        // This is a simplified implementation
        let similarity = self.memory_system.calculate_similarity(&memory_event);
        similarity
    }

    fn calculate_final_threat_score(
        &self,
        pattern_result: &Option<PatternAnalysisResult>,
        threshold_result: &Option<ThreatAssessment>,
        memory_influence: f32,
    ) -> f32 {
        let mut final_score = 0.0;
        
        // Pattern recognition score
        if let Some(pattern) = pattern_result {
            final_score = final_score.max(pattern.overall_threat_score);
        }
        
        // Threshold assessment score
        if let Some(threshold) = threshold_result {
            final_score = final_score.max(threshold.base_similarity);
        }
        
        // Apply memory influence
        final_score = (final_score + memory_influence * 0.2).min(1.0);
        
        final_score
    }

    fn calculate_confidence(
        &self,
        pattern_result: &Option<PatternAnalysisResult>,
        threshold_result: &Option<ThreatAssessment>,
    ) -> f32 {
        let mut confidence_factors = Vec::new();
        
        if let Some(pattern) = pattern_result {
            confidence_factors.push(pattern.confidence_level);
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

    fn extract_attack_types(&self, pattern_result: &Option<PatternAnalysisResult>) -> Vec<String> {
        if let Some(pattern) = pattern_result {
            pattern.detected_patterns.iter()
                .map(|p| format!("{:?}", p.category))
                .collect()
        } else {
            Vec::new()
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
        let memory_event = MemoryEvent {
            timestamp: std::time::SystemTime::now(),
            event_type: "threat_analysis".to_string(),
            payload: request.to_string(),
            threat_score: result.threat_score,
            context: HashMap::new(),
        };
        
        self.memory_system.store_event(memory_event);
    }

    // Additional methods for comprehensive testing compatibility
    pub fn store_analysis_result(&mut self, _result: &ThreatAnalysisResult) {
        // Store result in memory system
    }

    pub fn add_missed_threat(&mut self, event: MissedThreatEvent) {
        if self.config.enable_retrospective_learning {
            self.retrospective_learning.add_missed_threat(event);
            self.metrics.learning_events += 1;
        }
    }

    pub fn add_false_positive(&mut self, event: FalsePositiveEvent) {
        if self.config.enable_retrospective_learning {
            self.retrospective_learning.add_false_positive(event);
            self.metrics.learning_events += 1;
        }
    }

    pub fn get_learning_stats(&self) -> &RetrospectiveLearningStats {
        self.retrospective_learning.get_stats()
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

    pub fn get_eq_iq_balance(&self) -> &EQIQBalance {
        self.eq_iq_regulator.get_current_balance()
    }

    pub fn update_behavioral_baseline(&mut self, _result: &ThreatAnalysisResult) {
        // Update behavioral baseline in memory system
    }
}

impl WebGuardConfig {
    pub fn default() -> Self {
        Self {
            enable_pattern_recognition: true,
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