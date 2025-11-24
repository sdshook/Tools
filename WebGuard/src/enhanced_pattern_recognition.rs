use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use crate::memory_engine::psi_index::{PsiIndex, PsiEntry, EMBED_DIM};
use crate::mesh_cognition::HostMeshCognition;

/// Experiential Knowledge Base - Learns patterns through experience and shares knowledge
/// Replaces static pattern matching with dynamic experiential learning
#[derive(Debug, Clone)]
pub struct ExperientialKnowledgeBase {
    /// Learned patterns from actual experience (not static)
    pub learned_patterns: HashMap<String, LearnedPattern>,
    /// Learned behavioral indicators
    pub behavioral_indicators: HashMap<String, BehavioralIndicator>,
    /// PSI connector for persistent memory
    pub psi_connector: Option<Arc<Mutex<PsiIndex>>>,
    /// Knowledge transfer interface
    pub knowledge_transfer: KnowledgeTransfer,
    /// Learning statistics
    pub learning_stats: LearningStatistics,
    /// Configuration for experiential learning
    pub config: ExperientialConfig,
}

/// Learned pattern from experiential learning (not static/hard-coded)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedPattern {
    /// The pattern learned from experience
    pub pattern: String,
    /// Threat weight learned from validation results
    pub threat_weight: f32,
    /// Benign weight learned from validation results  
    pub benign_weight: f32,
    /// Confidence based on validation count and success rate
    pub confidence: f32,
    /// Which WebGuard instance originally learned this pattern
    pub learning_source: String,
    /// How many times this pattern has been validated
    pub validation_count: u32,
    /// Success rate in actual threat detection
    pub success_rate: f32,
    /// False positive rate observed
    pub false_positive_rate: f32,
    /// Context tags where this pattern applies
    pub context_tags: Vec<String>,
    /// When this pattern was first learned
    pub learned_timestamp: u64,
    /// Last time this pattern was updated
    pub last_updated: u64,
    /// Learning method that discovered this pattern
    pub discovery_method: DiscoveryMethod,
}

/// How a pattern was discovered through experiential learning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// Learned from successful threat detection
    ThreatValidation,
    /// Learned from false positive correction
    FalsePositiveCorrection,
    /// Learned from behavioral analysis
    BehavioralLearning,
    /// Imported from another WebGuard instance
    KnowledgeTransfer,
    /// Learned from retrospective analysis
    RetrospectiveLearning,
}

/// Behavioral indicator learned from experience
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralIndicator {
    /// Name of the behavioral indicator
    pub name: String,
    /// Type of behavioral pattern
    pub indicator_type: BehavioralType,
    /// Weight learned from experience
    pub weight: f32,
    /// Threshold learned from experience
    pub threshold: f32,
    /// Confidence in this indicator
    pub confidence: f32,
    /// Validation statistics
    pub validation_stats: ValidationStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BehavioralType {
    /// Learned character frequency patterns
    CharacterFrequency,
    /// Learned length anomaly patterns
    LengthAnomaly,
    /// Learned encoding anomaly patterns
    EncodingAnomaly,
    /// Learned structural anomaly patterns
    StructuralAnomaly,
    /// Learned timing patterns
    TimingPattern,
    /// Learned obfuscation patterns
    ObfuscationPattern,
}

/// Statistics for pattern validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationStats {
    pub true_positives: u32,
    pub false_positives: u32,
    pub true_negatives: u32,
    pub false_negatives: u32,
    pub total_validations: u32,
}

/// Knowledge transfer interface for sharing learned patterns
#[derive(Debug, Clone)]
pub struct KnowledgeTransfer {
    /// Export format version
    pub version: String,
    /// Minimum confidence threshold for export
    pub export_threshold: f32,
    /// Maximum age for patterns to export (in seconds)
    pub max_export_age: u64,
}

/// Learning statistics for the knowledge base
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningStatistics {
    /// Total patterns learned
    pub total_patterns_learned: u32,
    /// Patterns learned from threats
    pub threat_patterns_learned: u32,
    /// Patterns learned from benign traffic
    pub benign_patterns_learned: u32,
    /// Patterns imported from other instances
    pub imported_patterns: u32,
    /// Patterns exported to other instances
    pub exported_patterns: u32,
    /// Average confidence of learned patterns
    pub average_confidence: f32,
    /// Learning start time
    pub learning_start_time: u64,
}

/// Configuration for experiential learning
#[derive(Debug, Clone)]
pub struct ExperientialConfig {
    /// Minimum validation count before pattern is trusted
    pub min_validation_count: u32,
    /// Minimum confidence threshold for pattern use
    pub min_confidence_threshold: f32,
    /// Maximum false positive rate allowed
    pub max_false_positive_rate: f32,
    /// Learning rate for pattern weight updates
    pub learning_rate: f32,
    /// Enable knowledge sharing with other instances
    pub enable_knowledge_sharing: bool,
    /// Enable PSI integration for persistent memory
    pub enable_psi_integration: bool,
}

/// Result of experiential pattern analysis
#[derive(Debug, Clone)]
pub struct ExperientialAnalysisResult {
    /// Overall threat score based on learned patterns
    pub overall_threat_score: f32,
    /// Confidence in the analysis based on pattern validation history
    pub confidence_level: f32,
    /// Patterns that matched from learned knowledge
    pub matched_learned_patterns: Vec<MatchedLearnedPattern>,
    /// Behavioral indicators that triggered
    pub triggered_indicators: Vec<TriggeredIndicator>,
    /// New patterns discovered during analysis
    pub discovered_patterns: Vec<String>,
    /// Learning feedback for pattern weight updates
    pub learning_feedback: LearningFeedback,
}

/// A learned pattern that matched during analysis
#[derive(Debug, Clone)]
pub struct MatchedLearnedPattern {
    /// The learned pattern that matched
    pub pattern: LearnedPattern,
    /// Match strength (0.0 to 1.0)
    pub match_strength: f32,
    /// Positions where pattern was found
    pub positions: Vec<usize>,
    /// Context of the match
    pub context: String,
}

/// A behavioral indicator that was triggered
#[derive(Debug, Clone)]
pub struct TriggeredIndicator {
    /// The behavioral indicator that triggered
    pub indicator: BehavioralIndicator,
    /// Trigger strength (0.0 to 1.0)
    pub trigger_strength: f32,
    /// Evidence that caused the trigger
    pub evidence: String,
    /// Description of what was detected
    pub description: String,
}

/// Feedback for updating learned patterns
#[derive(Debug, Clone)]
pub struct LearningFeedback {
    /// Patterns that should have their weights increased
    pub reinforce_patterns: Vec<String>,
    /// Patterns that should have their weights decreased
    pub weaken_patterns: Vec<String>,
    /// New patterns to learn from this analysis
    pub new_patterns_to_learn: Vec<String>,
    /// Context information for learning
    pub learning_context: HashMap<String, String>,
}

impl ExperientialKnowledgeBase {
    /// Create a new experiential knowledge base
    pub fn new() -> Self {
        Self {
            learned_patterns: HashMap::new(),
            behavioral_indicators: HashMap::new(),
            psi_connector: None,
            knowledge_transfer: KnowledgeTransfer {
                version: "1.0".to_string(),
                export_threshold: 0.7,
                max_export_age: 86400 * 30, // 30 days
            },
            learning_stats: LearningStatistics {
                total_patterns_learned: 0,
                threat_patterns_learned: 0,
                benign_patterns_learned: 0,
                imported_patterns: 0,
                exported_patterns: 0,
                average_confidence: 0.0,
                learning_start_time: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            config: ExperientialConfig {
                min_validation_count: 3,
                min_confidence_threshold: 0.6,
                max_false_positive_rate: 0.1,
                learning_rate: 0.1,
                enable_knowledge_sharing: true,
                enable_psi_integration: true,
            },
        }
    }

    /// Connect to PSI for persistent memory
    pub fn connect_psi(&mut self, psi: Arc<Mutex<PsiIndex>>) {
        self.psi_connector = Some(psi);
    }

    /// Analyze request using learned patterns (not static patterns)
    pub fn analyze_experiential(&self, request: &str, context: &PatternRequestContext) -> ExperientialAnalysisResult {
        let mut matched_patterns = Vec::new();
        let mut triggered_indicators = Vec::new();
        let mut discovered_patterns = Vec::new();
        let mut overall_score = 0.0;
        let mut total_confidence = 0.0;
        let mut pattern_count = 0;

        // Analyze using learned patterns only
        for (pattern_key, learned_pattern) in &self.learned_patterns {
            if learned_pattern.confidence >= self.config.min_confidence_threshold
                && learned_pattern.validation_count >= self.config.min_validation_count
                && learned_pattern.false_positive_rate <= self.config.max_false_positive_rate
            {
                if let Some(match_result) = self.match_learned_pattern(request, learned_pattern) {
                    matched_patterns.push(match_result);
                    overall_score += learned_pattern.threat_weight * learned_pattern.confidence;
                    total_confidence += learned_pattern.confidence;
                    pattern_count += 1;
                }
            }
        }

        // Analyze using learned behavioral indicators
        for (indicator_key, indicator) in &self.behavioral_indicators {
            if indicator.confidence >= self.config.min_confidence_threshold {
                if let Some(trigger_result) = self.check_behavioral_indicator(request, indicator) {
                    triggered_indicators.push(trigger_result);
                    overall_score += indicator.weight * indicator.confidence;
                    total_confidence += indicator.confidence;
                    pattern_count += 1;
                }
            }
        }

        // Discover new patterns for learning
        discovered_patterns = self.discover_new_patterns(request);

        // Calculate final scores
        let final_score = if pattern_count > 0 {
            overall_score / pattern_count as f32
        } else {
            0.0
        };

        let confidence = if pattern_count > 0 {
            total_confidence / pattern_count as f32
        } else {
            0.0
        };

        ExperientialAnalysisResult {
            overall_threat_score: final_score.min(1.0),
            confidence_level: confidence,
            matched_learned_patterns: matched_patterns,
            triggered_indicators,
            discovered_patterns,
            learning_feedback: self.generate_learning_feedback(request, final_score),
        }
    }

    /// Match a learned pattern against the request
    fn match_learned_pattern(&self, request: &str, pattern: &LearnedPattern) -> Option<MatchedLearnedPattern> {
        let request_lower = request.to_lowercase();
        let pattern_lower = pattern.pattern.to_lowercase();
        
        if request_lower.contains(&pattern_lower) {
            let positions = self.find_pattern_positions(&request_lower, &pattern_lower);
            let match_strength = self.calculate_match_strength(request, &pattern.pattern);
            
            Some(MatchedLearnedPattern {
                pattern: pattern.clone(),
                match_strength,
                positions,
                context: format!("Pattern '{}' found in request", pattern.pattern),
            })
        } else {
            None
        }
    }

    /// Check if a behavioral indicator is triggered
    fn check_behavioral_indicator(&self, request: &str, indicator: &BehavioralIndicator) -> Option<TriggeredIndicator> {
        match indicator.indicator_type {
            BehavioralType::CharacterFrequency => {
                let anomaly_score = self.analyze_character_frequency(request);
                if anomaly_score > indicator.threshold {
                    Some(TriggeredIndicator {
                        indicator: indicator.clone(),
                        trigger_strength: anomaly_score,
                        evidence: format!("Character frequency anomaly: {:.2}", anomaly_score),
                        description: "Unusual character distribution detected".to_string(),
                    })
                } else {
                    None
                }
            }
            BehavioralType::LengthAnomaly => {
                let length_score = self.analyze_length_anomaly(request);
                if length_score > indicator.threshold {
                    Some(TriggeredIndicator {
                        indicator: indicator.clone(),
                        trigger_strength: length_score,
                        evidence: format!("Length anomaly: {:.2}", length_score),
                        description: "Unusual request length detected".to_string(),
                    })
                } else {
                    None
                }
            }
            _ => None, // Other behavioral types can be implemented as needed
        }
    }

    /// URL decode a string, handling common URL encoding patterns
    fn url_decode(input: &str) -> String {
        let mut result = String::new();
        let mut chars = input.chars().peekable();
        
        while let Some(ch) = chars.next() {
            if ch == '%' {
                // Try to decode the next two characters as hex
                let hex1 = chars.next();
                let hex2 = chars.next();
                
                if let (Some(h1), Some(h2)) = (hex1, hex2) {
                    let hex_str = format!("{}{}", h1, h2);
                    if let Ok(byte_val) = u8::from_str_radix(&hex_str, 16) {
                        // Convert byte to char if it's valid ASCII
                        if byte_val < 128 {
                            result.push(byte_val as char);
                        } else {
                            // If not valid ASCII, keep the original percent encoding
                            result.push('%');
                            result.push(h1);
                            result.push(h2);
                        }
                    } else {
                        // If hex parsing failed, keep the original characters
                        result.push('%');
                        result.push(h1);
                        result.push(h2);
                    }
                } else {
                    // If we don't have two more characters, just keep the %
                    result.push(ch);
                }
            } else if ch == '+' {
                // Convert + to space (common in URL encoding)
                result.push(' ');
            } else {
                result.push(ch);
            }
        }
        
        result
    }
    
    /// Preprocess input by applying URL decoding and other normalizations
    fn preprocess_input(input: &str) -> Vec<String> {
        let mut variants = Vec::new();
        
        // Original input
        variants.push(input.to_string());
        
        // URL decoded version
        let decoded = Self::url_decode(input);
        if decoded != input {
            variants.push(decoded.clone());
            
            // Double URL decode (for double-encoded attacks)
            let double_decoded = Self::url_decode(&decoded);
            if double_decoded != decoded {
                variants.push(double_decoded);
            }
        }
        
        // Lowercase versions for case-insensitive matching
        let lower_original = input.to_lowercase();
        if lower_original != input {
            variants.push(lower_original);
        }
        
        let lower_decoded = Self::url_decode(&input.to_lowercase());
        if lower_decoded != input.to_lowercase() && !variants.contains(&lower_decoded) {
            variants.push(lower_decoded);
        }
        
        variants
    }

    /// Learn a new pattern from experiential feedback
    pub fn learn_pattern(&mut self, pattern: String, is_threat: bool, context: Vec<String>, discovery_method: DiscoveryMethod) {
        let pattern_key = pattern.clone();
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(existing_pattern) = self.learned_patterns.get_mut(&pattern_key) {
            // Update existing pattern
            existing_pattern.validation_count += 1;
            existing_pattern.last_updated = current_time;
            
            if is_threat {
                existing_pattern.threat_weight = (existing_pattern.threat_weight + self.config.learning_rate).min(1.0);
                existing_pattern.benign_weight = (existing_pattern.benign_weight - self.config.learning_rate * 0.5).max(0.0);
            } else {
                existing_pattern.benign_weight = (existing_pattern.benign_weight + self.config.learning_rate).min(1.0);
                existing_pattern.threat_weight = (existing_pattern.threat_weight - self.config.learning_rate * 0.5).max(0.0);
            }
            
            // Recalculate confidence and success rate
            self.update_pattern_confidence(&pattern_key);
        } else {
            // Create new learned pattern
            let new_pattern = LearnedPattern {
                pattern: pattern.clone(),
                threat_weight: if is_threat { 0.5 } else { 0.1 },
                benign_weight: if is_threat { 0.1 } else { 0.5 },
                confidence: 0.3, // Start with low confidence
                learning_source: "local".to_string(), // TODO: Get actual instance ID
                validation_count: 1,
                success_rate: 1.0, // Start optimistic
                false_positive_rate: 0.0,
                context_tags: context,
                learned_timestamp: current_time,
                last_updated: current_time,
                discovery_method,
            };
            
            self.learned_patterns.insert(pattern_key, new_pattern);
            self.learning_stats.total_patterns_learned += 1;
            
            if is_threat {
                self.learning_stats.threat_patterns_learned += 1;
            } else {
                self.learning_stats.benign_patterns_learned += 1;
            }
        }

        // Store in PSI if connected
        if self.config.enable_psi_integration {
            self.store_pattern_in_psi(&pattern, is_threat);
        }
    }

    /// Update pattern confidence based on validation history
    fn update_pattern_confidence(&mut self, pattern_key: &str) {
        if let Some(pattern) = self.learned_patterns.get_mut(pattern_key) {
            // Confidence increases with validation count and success rate
            let validation_factor = (pattern.validation_count as f32 / 10.0).min(1.0);
            let success_factor = pattern.success_rate;
            let fp_penalty = 1.0 - pattern.false_positive_rate;
            
            pattern.confidence = (validation_factor * success_factor * fp_penalty).min(1.0);
        }
    }

    /// Store learned pattern in PSI for persistent memory
    fn store_pattern_in_psi(&self, pattern: &str, is_threat: bool) {
        if let Some(psi) = &self.psi_connector {
            if let Ok(mut psi_lock) = psi.lock() {
                // Create embedding for the pattern (simplified)
                let mut embedding = [0.0f32; EMBED_DIM];
                let pattern_bytes = pattern.as_bytes();
                for (i, &byte) in pattern_bytes.iter().enumerate() {
                    if i < EMBED_DIM {
                        embedding[i] = (byte as f32) / 255.0;
                    }
                }
                
                let entry = PsiEntry {
                    id: format!("pattern_{}", pattern),
                    vec: embedding,
                    valence: if is_threat { -0.8 } else { 0.8 }, // Negative valence for threats
                    uses: 1,
                    tags: vec!["learned_pattern".to_string(), if is_threat { "threat" } else { "benign" }.to_string()],
                };
                
                psi_lock.add(entry);
            }
        }
    }

    /// Export learned knowledge for sharing with other WebGuard instances
    pub fn export_knowledge(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut exportable_patterns = HashMap::new();
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Only export high-confidence, validated patterns
        for (key, pattern) in &self.learned_patterns {
            if pattern.confidence >= self.knowledge_transfer.export_threshold
                && pattern.validation_count >= self.config.min_validation_count
                && (current_time - pattern.learned_timestamp) <= self.knowledge_transfer.max_export_age
            {
                exportable_patterns.insert(key.clone(), pattern.clone());
            }
        }

        let export_data = ExportedKnowledge {
            version: self.knowledge_transfer.version.clone(),
            export_timestamp: current_time,
            source_instance: "local".to_string(), // TODO: Get actual instance ID
            patterns: exportable_patterns,
            behavioral_indicators: self.behavioral_indicators.clone(),
            learning_stats: self.learning_stats.clone(),
        };

        Ok(serde_json::to_string(&export_data)?)
    }

    /// Import learned knowledge from another WebGuard instance
    pub fn import_knowledge(&mut self, knowledge_json: &str) -> Result<u32, Box<dyn std::error::Error>> {
        let imported: ExportedKnowledge = serde_json::from_str(knowledge_json)?;
        let mut imported_count = 0;

        // Import patterns with validation
        for (key, imported_pattern) in imported.patterns {
            // Only import high-quality patterns
            if imported_pattern.confidence >= self.config.min_confidence_threshold
                && imported_pattern.validation_count >= self.config.min_validation_count
            {
                // Mark as imported knowledge
                let mut pattern = imported_pattern;
                pattern.discovery_method = DiscoveryMethod::KnowledgeTransfer;
                pattern.learning_source = imported.source_instance.clone();
                
                self.learned_patterns.insert(key, pattern);
                imported_count += 1;
            }
        }

        // Import behavioral indicators
        for (key, indicator) in imported.behavioral_indicators {
            if indicator.confidence >= self.config.min_confidence_threshold {
                self.behavioral_indicators.insert(key, indicator);
            }
        }

        self.learning_stats.imported_patterns += imported_count;
        Ok(imported_count)
    }

    /// Generate learning feedback for pattern weight updates
    fn generate_learning_feedback(&self, request: &str, threat_score: f32) -> LearningFeedback {
        let mut reinforce_patterns = Vec::new();
        let mut weaken_patterns = Vec::new();
        let mut new_patterns = Vec::new();
        let mut context = HashMap::new();

        // If high threat score, reinforce matching patterns
        if threat_score > 0.7 {
            for (key, pattern) in &self.learned_patterns {
                if request.to_lowercase().contains(&pattern.pattern.to_lowercase()) {
                    reinforce_patterns.push(pattern.pattern.clone());
                }
            }
        }

        // Discover potential new patterns
        new_patterns = self.discover_new_patterns(request);

        context.insert("request_length".to_string(), request.len().to_string());
        context.insert("threat_score".to_string(), threat_score.to_string());

        LearningFeedback {
            reinforce_patterns,
            weaken_patterns,
            new_patterns_to_learn: new_patterns,
            learning_context: context,
        }
    }

    /// Discover new patterns from request for learning
    fn discover_new_patterns(&self, request: &str) -> Vec<String> {
        let mut patterns = Vec::new();
        let request_lower = request.to_lowercase();

        // Extract potential patterns (simplified approach)
        // Look for suspicious character sequences
        let suspicious_chars = ['<', '>', '\'', '"', '&', '|', ';', '(', ')', '{', '}'];
        for &ch in &suspicious_chars {
            if request_lower.contains(ch) {
                // Extract context around suspicious character
                if let Some(pos) = request_lower.find(ch) {
                    let start = pos.saturating_sub(5);
                    let end = (pos + 6).min(request_lower.len());
                    let pattern = request_lower[start..end].to_string();
                    if !patterns.contains(&pattern) {
                        patterns.push(pattern);
                    }
                }
            }
        }

        patterns
    }

    /// Helper methods for pattern matching
    fn find_pattern_positions(&self, text: &str, pattern: &str) -> Vec<usize> {
        let mut positions = Vec::new();
        let mut start = 0;
        
        while let Some(pos) = text[start..].find(pattern) {
            positions.push(start + pos);
            start += pos + 1;
        }
        
        positions
    }

    fn calculate_match_strength(&self, request: &str, pattern: &str) -> f32 {
        // Simple match strength calculation
        let pattern_len = pattern.len() as f32;
        let request_len = request.len() as f32;
        
        // Longer patterns in shorter requests have higher strength
        (pattern_len / request_len).min(1.0)
    }

    fn analyze_character_frequency(&self, request: &str) -> f32 {
        // Simplified character frequency analysis
        let mut char_counts = HashMap::new();
        for ch in request.chars() {
            *char_counts.entry(ch).or_insert(0) += 1;
        }
        
        // Calculate entropy-like measure
        let total_chars = request.len() as f32;
        let mut entropy = 0.0;
        for count in char_counts.values() {
            let freq = *count as f32 / total_chars;
            entropy -= freq * freq.log2();
        }
        
        // Normalize to 0-1 range (higher = more anomalous)
        (entropy / 8.0).min(1.0)
    }

    fn analyze_length_anomaly(&self, request: &str) -> f32 {
        // Simple length anomaly detection
        let len = request.len();
        
        // Typical web requests are 50-500 characters
        if len < 50 {
            0.2 // Slightly suspicious
        } else if len > 1000 {
            0.8 // Very suspicious
        } else if len > 500 {
            0.4 // Moderately suspicious
        } else {
            0.0 // Normal
        }
    }

    /// Legacy compatibility method - now uses experiential analysis
    pub fn analyze_patterns(&self, request: &str, context: &PatternRequestContext) -> ExperientialAnalysisResult {
        self.analyze_experiential(request, context)
    }
}

/// Structure for exporting/importing learned knowledge between WebGuard instances
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedKnowledge {
    pub version: String,
    pub export_timestamp: u64,
    pub source_instance: String,
    pub patterns: HashMap<String, LearnedPattern>,
    pub behavioral_indicators: HashMap<String, BehavioralIndicator>,
    pub learning_stats: LearningStatistics,
}

/// Request context for pattern analysis
#[derive(Debug, Clone)]
pub struct PatternRequestContext {
    pub method: String,
    pub url: String,
    pub content_type: Option<String>,
    pub user_agent: Option<String>,
    pub headers: HashMap<String, String>,
}
