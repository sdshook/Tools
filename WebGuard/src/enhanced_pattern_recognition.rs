use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Enhanced pattern recognition system for complex attack detection
#[derive(Debug, Clone)]
pub struct EnhancedPatternRecognition {
    /// N-gram analyzers for different attack types
    pub ngram_analyzers: HashMap<AttackCategory, NgramAnalyzer>,
    /// Behavioral pattern detectors
    pub behavioral_detectors: Vec<BehavioralDetector>,
    /// Context-aware pattern weights
    pub context_weights: ContextWeights,
    /// Attack signature database
    pub signature_db: AttackSignatureDatabase,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum AttackCategory {
    SqlInjection,
    XssAttack,
    PathTraversal,
    CommandInjection,
    FileInclusion,
    EncodingAttack,
}

#[derive(Debug, Clone)]
pub struct NgramAnalyzer {
    /// N-gram size (2, 3, 4, etc.)
    pub n: usize,
    /// Known malicious n-grams with their threat scores
    pub malicious_ngrams: HashMap<String, f32>,
    /// Known benign n-grams with their legitimacy scores
    pub benign_ngrams: HashMap<String, f32>,
    /// Minimum frequency threshold for n-gram consideration
    pub min_frequency: usize,
}

#[derive(Debug, Clone)]
pub struct BehavioralDetector {
    pub name: String,
    pub detector_type: BehavioralType,
    pub weight: f32,
    pub threshold: f32,
}

#[derive(Debug, Clone)]
pub enum BehavioralType {
    /// Detects unusual character frequency patterns
    CharacterFrequency,
    /// Detects suspicious length patterns
    LengthAnomaly,
    /// Detects encoding inconsistencies
    EncodingAnomaly,
    /// Detects structural anomalies in requests
    StructuralAnomaly,
    /// Detects timing-based attack patterns
    TimingPattern,
    /// Detects payload obfuscation attempts
    ObfuscationPattern,
}

#[derive(Debug, Clone)]
pub struct ContextWeights {
    /// Weights based on request context (GET, POST, headers, etc.)
    pub request_context: HashMap<String, f32>,
    /// Weights based on URL patterns
    pub url_patterns: HashMap<String, f32>,
    /// Weights based on parameter names
    pub parameter_patterns: HashMap<String, f32>,
    /// Weights based on content type
    pub content_type_weights: HashMap<String, f32>,
}

#[derive(Debug, Clone)]
pub struct AttackSignatureDatabase {
    /// Known attack signatures with metadata
    pub signatures: Vec<AttackSignature>,
    /// Signature matching cache for performance
    pub match_cache: HashMap<String, Vec<usize>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSignature {
    pub id: String,
    pub name: String,
    pub category: String,
    pub pattern: String,
    pub severity: f32,
    pub confidence: f32,
    pub description: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PatternAnalysisResult {
    pub overall_threat_score: f32,
    pub category_scores: HashMap<AttackCategory, f32>,
    pub detected_patterns: Vec<DetectedPattern>,
    pub behavioral_anomalies: Vec<BehavioralAnomaly>,
    pub context_adjustments: f32,
    pub confidence_level: f32,
}

#[derive(Debug, Clone)]
pub struct DetectedPattern {
    pub pattern: String,
    pub category: AttackCategory,
    pub score: f32,
    pub positions: Vec<usize>,
    pub context: String,
}

#[derive(Debug, Clone)]
pub struct BehavioralAnomaly {
    pub anomaly_type: BehavioralType,
    pub score: f32,
    pub description: String,
    pub evidence: String,
}

impl EnhancedPatternRecognition {
    pub fn new() -> Self {
        let mut ngram_analyzers = HashMap::new();
        
        // Initialize N-gram analyzers for each attack category
        ngram_analyzers.insert(AttackCategory::SqlInjection, Self::create_sql_ngram_analyzer());
        ngram_analyzers.insert(AttackCategory::XssAttack, Self::create_xss_ngram_analyzer());
        ngram_analyzers.insert(AttackCategory::PathTraversal, Self::create_path_ngram_analyzer());
        ngram_analyzers.insert(AttackCategory::CommandInjection, Self::create_cmd_ngram_analyzer());
        ngram_analyzers.insert(AttackCategory::FileInclusion, Self::create_file_ngram_analyzer());
        ngram_analyzers.insert(AttackCategory::EncodingAttack, Self::create_encoding_ngram_analyzer());
        
        Self {
            ngram_analyzers,
            behavioral_detectors: Self::create_behavioral_detectors(),
            context_weights: ContextWeights::new(),
            signature_db: AttackSignatureDatabase::new(),
        }
    }

    /// Perform comprehensive pattern analysis on input
    pub fn analyze_patterns(&self, input: &str, context: &RequestContext) -> PatternAnalysisResult {
        let mut category_scores = HashMap::new();
        let mut detected_patterns = Vec::new();
        let mut behavioral_anomalies = Vec::new();
        
        // N-gram analysis for each category
        for (category, analyzer) in &self.ngram_analyzers {
            let (score, patterns) = self.analyze_ngrams(input, analyzer, category);
            category_scores.insert(category.clone(), score);
            detected_patterns.extend(patterns);
        }
        
        // Behavioral analysis
        for detector in &self.behavioral_detectors {
            if let Some(anomaly) = self.detect_behavioral_anomaly(input, detector) {
                behavioral_anomalies.push(anomaly);
            }
        }
        
        // Context-aware adjustments
        let context_adjustments = self.calculate_context_adjustments(input, context);
        
        // Signature matching
        let signature_matches = self.match_signatures(input);
        detected_patterns.extend(signature_matches);
        
        // Calculate overall threat score using maximum-based scoring to avoid dilution
        let base_score = category_scores.values().cloned().fold(0.0f32, f32::max);
        let behavioral_score = behavioral_anomalies.iter().map(|a| a.score).fold(0.0f32, f32::max);
        let overall_threat_score = (base_score.max(behavioral_score) + context_adjustments).min(1.0).max(0.0);
        
        // Calculate confidence level
        let confidence_level = self.calculate_confidence_level(&category_scores, &behavioral_anomalies, &detected_patterns);
        
        PatternAnalysisResult {
            overall_threat_score,
            category_scores,
            detected_patterns,
            behavioral_anomalies,
            context_adjustments,
            confidence_level,
        }
    }

    fn create_sql_ngram_analyzer() -> NgramAnalyzer {
        let mut malicious_ngrams = HashMap::new();
        let mut benign_ngrams = HashMap::new();
        
        // SQL injection 2-grams
        malicious_ngrams.insert("' or".to_string(), 0.9);
        malicious_ngrams.insert("or '".to_string(), 0.9);
        malicious_ngrams.insert("' and".to_string(), 0.8);
        malicious_ngrams.insert("and '".to_string(), 0.8);
        malicious_ngrams.insert("union select".to_string(), 0.95);
        malicious_ngrams.insert("select *".to_string(), 0.7);
        malicious_ngrams.insert("drop table".to_string(), 0.95);
        malicious_ngrams.insert("delete from".to_string(), 0.9);
        malicious_ngrams.insert("insert into".to_string(), 0.8);
        malicious_ngrams.insert("update set".to_string(), 0.8);
        malicious_ngrams.insert("-- ".to_string(), 0.6);
        malicious_ngrams.insert("/*".to_string(), 0.5);
        malicious_ngrams.insert("*/".to_string(), 0.5);
        malicious_ngrams.insert("waitfor delay".to_string(), 0.9);
        malicious_ngrams.insert("sleep(".to_string(), 0.9);
        malicious_ngrams.insert("benchmark(".to_string(), 0.9);
        
        // SQL injection 3-grams
        malicious_ngrams.insert("' or '1'='1".to_string(), 0.95);
        malicious_ngrams.insert("' or 1=1".to_string(), 0.95);
        malicious_ngrams.insert("union all select".to_string(), 0.95);
        malicious_ngrams.insert("information_schema.tables".to_string(), 0.9);
        malicious_ngrams.insert("information_schema.columns".to_string(), 0.9);
        
        // Benign SQL-like patterns
        benign_ngrams.insert("select option".to_string(), 0.8);
        benign_ngrams.insert("order by".to_string(), 0.7);
        benign_ngrams.insert("group by".to_string(), 0.7);
        
        NgramAnalyzer {
            n: 2,
            malicious_ngrams,
            benign_ngrams,
            min_frequency: 1,
        }
    }

    fn create_xss_ngram_analyzer() -> NgramAnalyzer {
        let mut malicious_ngrams = HashMap::new();
        let mut benign_ngrams = HashMap::new();
        
        // XSS 2-grams
        malicious_ngrams.insert("<script".to_string(), 0.9);
        malicious_ngrams.insert("script>".to_string(), 0.9);
        malicious_ngrams.insert("javascript:".to_string(), 0.9);
        malicious_ngrams.insert("vbscript:".to_string(), 0.9);
        malicious_ngrams.insert("onload=".to_string(), 0.8);
        malicious_ngrams.insert("onclick=".to_string(), 0.8);
        malicious_ngrams.insert("onmouseover=".to_string(), 0.8);
        malicious_ngrams.insert("onerror=".to_string(), 0.8);
        malicious_ngrams.insert("<iframe".to_string(), 0.7);
        malicious_ngrams.insert("<object".to_string(), 0.7);
        malicious_ngrams.insert("<embed".to_string(), 0.7);
        malicious_ngrams.insert("expression(".to_string(), 0.8);
        malicious_ngrams.insert("document.write".to_string(), 0.8);
        malicious_ngrams.insert("document.cookie".to_string(), 0.8);
        malicious_ngrams.insert("alert(".to_string(), 0.7);
        malicious_ngrams.insert("eval(".to_string(), 0.8);
        
        // XSS 3-grams
        malicious_ngrams.insert("<script>alert".to_string(), 0.95);
        malicious_ngrams.insert("javascript:alert(".to_string(), 0.95);
        malicious_ngrams.insert("<img src=x".to_string(), 0.8);
        malicious_ngrams.insert("onerror=alert".to_string(), 0.9);
        
        // Benign HTML patterns
        benign_ngrams.insert("<div class".to_string(), 0.9);
        benign_ngrams.insert("<span id".to_string(), 0.8);
        benign_ngrams.insert("<a href".to_string(), 0.8);
        
        NgramAnalyzer {
            n: 2,
            malicious_ngrams,
            benign_ngrams,
            min_frequency: 1,
        }
    }

    fn create_path_ngram_analyzer() -> NgramAnalyzer {
        let mut malicious_ngrams = HashMap::new();
        let mut benign_ngrams = HashMap::new();
        
        // Path traversal patterns
        malicious_ngrams.insert("../".to_string(), 0.8);
        malicious_ngrams.insert("..\\".to_string(), 0.8);
        malicious_ngrams.insert("/etc/passwd".to_string(), 0.95);
        malicious_ngrams.insert("/etc/shadow".to_string(), 0.95);
        malicious_ngrams.insert("\\windows\\system32".to_string(), 0.9);
        malicious_ngrams.insert("\\boot.ini".to_string(), 0.9);
        malicious_ngrams.insert("%2e%2e%2f".to_string(), 0.9);
        malicious_ngrams.insert("file://".to_string(), 0.7);
        malicious_ngrams.insert("..%2f".to_string(), 0.8);
        malicious_ngrams.insert("..%5c".to_string(), 0.8);
        
        // Benign path patterns
        benign_ngrams.insert("/api/".to_string(), 0.9);
        benign_ngrams.insert("/static/".to_string(), 0.9);
        benign_ngrams.insert("/assets/".to_string(), 0.9);
        
        NgramAnalyzer {
            n: 2,
            malicious_ngrams,
            benign_ngrams,
            min_frequency: 1,
        }
    }

    fn create_cmd_ngram_analyzer() -> NgramAnalyzer {
        let mut malicious_ngrams = HashMap::new();
        let mut benign_ngrams = HashMap::new();
        
        // Command injection patterns
        malicious_ngrams.insert("; cat".to_string(), 0.9);
        malicious_ngrams.insert("| cat".to_string(), 0.9);
        malicious_ngrams.insert("&& cat".to_string(), 0.9);
        malicious_ngrams.insert("; ls".to_string(), 0.9);
        malicious_ngrams.insert("| ls".to_string(), 0.9);
        malicious_ngrams.insert("; dir".to_string(), 0.9);
        malicious_ngrams.insert("| dir".to_string(), 0.9);
        malicious_ngrams.insert("; whoami".to_string(), 0.9);
        malicious_ngrams.insert("| whoami".to_string(), 0.9);
        malicious_ngrams.insert("; id".to_string(), 0.9);
        malicious_ngrams.insert("| id".to_string(), 0.9);
        malicious_ngrams.insert("`cat".to_string(), 0.9);
        malicious_ngrams.insert("$(cat".to_string(), 0.9);
        malicious_ngrams.insert("powershell -".to_string(), 0.8);
        malicious_ngrams.insert("cmd /c".to_string(), 0.8);
        malicious_ngrams.insert("/bin/bash".to_string(), 0.8);
        malicious_ngrams.insert("/bin/sh".to_string(), 0.8);
        
        NgramAnalyzer {
            n: 2,
            malicious_ngrams,
            benign_ngrams,
            min_frequency: 1,
        }
    }

    fn create_file_ngram_analyzer() -> NgramAnalyzer {
        let mut malicious_ngrams = HashMap::new();
        let mut benign_ngrams = HashMap::new();
        
        // File inclusion patterns
        malicious_ngrams.insert("include(\"".to_string(), 0.7);
        malicious_ngrams.insert("require(\"".to_string(), 0.7);
        malicious_ngrams.insert("include('".to_string(), 0.7);
        malicious_ngrams.insert("require('".to_string(), 0.7);
        malicious_ngrams.insert("http://".to_string(), 0.6);
        malicious_ngrams.insert("https://".to_string(), 0.5);
        malicious_ngrams.insert("ftp://".to_string(), 0.7);
        malicious_ngrams.insert("php://".to_string(), 0.8);
        malicious_ngrams.insert("data://".to_string(), 0.8);
        malicious_ngrams.insert("expect://".to_string(), 0.9);
        malicious_ngrams.insert("zip://".to_string(), 0.8);
        
        NgramAnalyzer {
            n: 2,
            malicious_ngrams,
            benign_ngrams,
            min_frequency: 1,
        }
    }

    fn create_encoding_ngram_analyzer() -> NgramAnalyzer {
        let mut malicious_ngrams = HashMap::new();
        let mut benign_ngrams = HashMap::new();
        
        // Encoding attack patterns
        malicious_ngrams.insert("%3c%73%63%72%69%70%74".to_string(), 0.95); // <script
        malicious_ngrams.insert("%27%20%6f%72%20%27".to_string(), 0.9); // ' or '
        malicious_ngrams.insert("\\x3c\\x73\\x63\\x72\\x69\\x70\\x74".to_string(), 0.95);
        malicious_ngrams.insert("\\u003c\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074".to_string(), 0.95);
        malicious_ngrams.insert("&#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;".to_string(), 0.95);
        malicious_ngrams.insert("%2527".to_string(), 0.8); // Double-encoded '
        malicious_ngrams.insert("%252f".to_string(), 0.8); // Double-encoded /
        
        NgramAnalyzer {
            n: 3,
            malicious_ngrams,
            benign_ngrams,
            min_frequency: 1,
        }
    }

    fn create_behavioral_detectors() -> Vec<BehavioralDetector> {
        vec![
            BehavioralDetector {
                name: "Character Frequency Anomaly".to_string(),
                detector_type: BehavioralType::CharacterFrequency,
                weight: 0.3,
                threshold: 0.7,
            },
            BehavioralDetector {
                name: "Length Anomaly".to_string(),
                detector_type: BehavioralType::LengthAnomaly,
                weight: 0.2,
                threshold: 0.8,
            },
            BehavioralDetector {
                name: "Encoding Inconsistency".to_string(),
                detector_type: BehavioralType::EncodingAnomaly,
                weight: 0.4,
                threshold: 0.6,
            },
            BehavioralDetector {
                name: "Structural Anomaly".to_string(),
                detector_type: BehavioralType::StructuralAnomaly,
                weight: 0.3,
                threshold: 0.7,
            },
            BehavioralDetector {
                name: "Obfuscation Pattern".to_string(),
                detector_type: BehavioralType::ObfuscationPattern,
                weight: 0.5,
                threshold: 0.5,
            },
        ]
    }

    fn analyze_ngrams(&self, input: &str, analyzer: &NgramAnalyzer, category: &AttackCategory) -> (f32, Vec<DetectedPattern>) {
        let ngrams = self.extract_ngrams(input, analyzer.n);
        let mut total_score = 0.0;
        let mut detected_patterns = Vec::new();
        let mut ngram_count = 0;
        
        for (ngram, positions) in ngrams {
            let mut pattern_score = 0.0;
            
            // Check against malicious patterns
            if let Some(&malicious_score) = analyzer.malicious_ngrams.get(&ngram) {
                pattern_score += malicious_score;
                detected_patterns.push(DetectedPattern {
                    pattern: ngram.clone(),
                    category: category.clone(),
                    score: malicious_score,
                    positions: positions.clone(),
                    context: format!("Malicious {}-gram detected", analyzer.n),
                });
            }
            
            // Check against benign patterns (reduces score)
            if let Some(&benign_score) = analyzer.benign_ngrams.get(&ngram) {
                pattern_score -= benign_score * 0.5; // Reduce impact of benign patterns
            }
            
            total_score += pattern_score.max(0.0);
            ngram_count += 1;
        }
        
        let average_score = if ngram_count > 0 {
            total_score / ngram_count as f32
        } else {
            0.0
        };
        
        (average_score.min(1.0), detected_patterns)
    }

    fn extract_ngrams(&self, input: &str, n: usize) -> HashMap<String, Vec<usize>> {
        let mut ngrams = HashMap::new();
        let input_lower = input.to_lowercase();
        
        // Extract both character-level and word-level n-grams
        // Character-level n-grams for fine-grained analysis
        let chars: Vec<char> = input_lower.chars().collect();
        for i in 0..=chars.len().saturating_sub(n) {
            let ngram: String = chars[i..i + n].iter().collect();
            ngrams.entry(ngram).or_insert_with(Vec::new).push(i);
        }
        
        // Word-level n-grams for semantic analysis
        let words: Vec<&str> = input_lower.split_whitespace().collect();
        if words.len() >= n {
            for i in 0..=words.len() - n {
                let ngram = words[i..i + n].join(" ");
                ngrams.entry(ngram).or_insert_with(Vec::new).push(i);
            }
        }
        
        // Also extract substring patterns for attack detection
        // SQL injection patterns
        if input_lower.contains("' or") {
            ngrams.entry("' or".to_string()).or_insert_with(Vec::new).push(0);
        }
        if input_lower.contains("or '") {
            ngrams.entry("or '".to_string()).or_insert_with(Vec::new).push(0);
        }
        if input_lower.contains("union select") {
            ngrams.entry("union select".to_string()).or_insert_with(Vec::new).push(0);
        }
        if input_lower.contains("' and") {
            ngrams.entry("' and".to_string()).or_insert_with(Vec::new).push(0);
        }
        if input_lower.contains("and '") {
            ngrams.entry("and '".to_string()).or_insert_with(Vec::new).push(0);
        }
        if input_lower.contains("--") {
            ngrams.entry("-- ".to_string()).or_insert_with(Vec::new).push(0);
        }
        
        // XSS patterns
        if input_lower.contains("<script") {
            ngrams.entry("<script".to_string()).or_insert_with(Vec::new).push(0);
        }
        if input_lower.contains("script>") {
            ngrams.entry("script>".to_string()).or_insert_with(Vec::new).push(0);
        }
        if input_lower.contains("javascript:") {
            ngrams.entry("javascript:".to_string()).or_insert_with(Vec::new).push(0);
        }
        if input_lower.contains("onload=") {
            ngrams.entry("onload=".to_string()).or_insert_with(Vec::new).push(0);
        }
        if input_lower.contains("onclick=") {
            ngrams.entry("onclick=".to_string()).or_insert_with(Vec::new).push(0);
        }
        if input_lower.contains("onerror=") {
            ngrams.entry("onerror=".to_string()).or_insert_with(Vec::new).push(0);
        }
        
        ngrams
    }

    fn detect_behavioral_anomaly(&self, input: &str, detector: &BehavioralDetector) -> Option<BehavioralAnomaly> {
        let score = match detector.detector_type {
            BehavioralType::CharacterFrequency => self.analyze_character_frequency(input),
            BehavioralType::LengthAnomaly => self.analyze_length_anomaly(input),
            BehavioralType::EncodingAnomaly => self.analyze_encoding_anomaly(input),
            BehavioralType::StructuralAnomaly => self.analyze_structural_anomaly(input),
            BehavioralType::TimingPattern => 0.0, // Would require timing data
            BehavioralType::ObfuscationPattern => self.analyze_obfuscation_pattern(input),
        };
        
        if score > detector.threshold {
            Some(BehavioralAnomaly {
                anomaly_type: detector.detector_type.clone(),
                score,
                description: detector.name.clone(),
                evidence: format!("Score: {:.3}, Threshold: {:.3}", score, detector.threshold),
            })
        } else {
            None
        }
    }

    fn analyze_character_frequency(&self, input: &str) -> f32 {
        let mut char_counts = HashMap::new();
        let total_chars = input.len() as f32;
        
        for c in input.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }
        
        // Calculate entropy and unusual character frequency
        let mut entropy = 0.0;
        let mut suspicious_chars = 0;
        
        for (&_char, &count) in &char_counts {
            let frequency = count as f32 / total_chars;
            entropy -= frequency * frequency.log2();
            
            // Count suspicious characters
            if "';\"<>&|`$(){}[]".contains(_char) {
                suspicious_chars += count;
            }
        }
        
        let suspicious_ratio = suspicious_chars as f32 / total_chars;
        let normalized_entropy = entropy / 8.0; // Normalize to 0-1
        
        (suspicious_ratio + normalized_entropy) / 2.0
    }

    fn analyze_length_anomaly(&self, input: &str) -> f32 {
        let length = input.len();
        
        // Typical web request lengths
        if length < 50 {
            0.0 // Very short, likely normal
        } else if length < 200 {
            0.1 // Normal range
        } else if length < 500 {
            0.3 // Getting longer
        } else if length < 1000 {
            0.6 // Quite long
        } else if length < 2000 {
            0.8 // Very long
        } else {
            1.0 // Extremely long, suspicious
        }
    }

    fn analyze_encoding_anomaly(&self, input: &str) -> f32 {
        let mut encoding_score = 0.0;
        
        // URL encoding density
        let url_encoded = input.matches('%').count();
        let url_encoding_ratio = url_encoded as f32 / input.len() as f32;
        encoding_score += url_encoding_ratio * 2.0;
        
        // Hex encoding
        let hex_encoded = input.matches("\\x").count();
        let hex_encoding_ratio = hex_encoded as f32 / input.len() as f32;
        encoding_score += hex_encoding_ratio * 3.0;
        
        // Unicode encoding
        let unicode_encoded = input.matches("\\u").count() + input.matches("&#").count();
        let unicode_encoding_ratio = unicode_encoded as f32 / input.len() as f32;
        encoding_score += unicode_encoding_ratio * 2.5;
        
        // Double encoding (suspicious)
        if input.contains("%25") {
            encoding_score += 0.5;
        }
        
        encoding_score.min(1.0)
    }

    fn analyze_structural_anomaly(&self, input: &str) -> f32 {
        let mut anomaly_score = 0.0;
        
        // Unbalanced brackets/quotes
        let open_parens = input.matches('(').count();
        let close_parens = input.matches(')').count();
        let paren_imbalance = (open_parens as i32 - close_parens as i32).abs() as f32 / (open_parens + close_parens).max(1) as f32;
        anomaly_score += paren_imbalance * 0.3;
        
        let single_quotes = input.matches('\'').count();
        let double_quotes = input.matches('"').count();
        if single_quotes % 2 != 0 || double_quotes % 2 != 0 {
            anomaly_score += 0.4;
        }
        
        // Unusual character sequences
        if input.contains("''") || input.contains("\"\"") || input.contains(";;") {
            anomaly_score += 0.3;
        }
        
        // Multiple encoding schemes in one request
        let encoding_types = [
            input.contains('%'),
            input.contains("\\x"),
            input.contains("\\u"),
            input.contains("&#"),
        ].iter().filter(|&&x| x).count();
        
        if encoding_types > 2 {
            anomaly_score += 0.4;
        }
        
        anomaly_score.min(1.0)
    }

    fn analyze_obfuscation_pattern(&self, input: &str) -> f32 {
        let mut obfuscation_score: f32 = 0.0;
        
        // Multiple encoding layers
        if input.contains("%25") { // Double URL encoding
            obfuscation_score += 0.4;
        }
        
        // Mixed case in keywords (common obfuscation)
        let keywords = ["script", "union", "select", "alert", "eval"];
        for keyword in &keywords {
            let variations = [
                keyword.to_uppercase(),
                keyword.chars().enumerate().map(|(i, c)| {
                    if i % 2 == 0 { c.to_uppercase().collect::<String>() } else { c.to_lowercase().collect::<String>() }
                }).collect::<String>(),
            ];
            
            for variation in &variations {
                if input.contains(variation) {
                    obfuscation_score += 0.2;
                }
            }
        }
        
        // Excessive whitespace or comments
        if input.matches("/*").count() > 2 || input.matches("--").count() > 1 {
            obfuscation_score += 0.3;
        }
        
        // Character substitution patterns
        if input.contains("0x") || input.contains("char(") || input.contains("chr(") {
            obfuscation_score += 0.3;
        }
        
        obfuscation_score.min(1.0)
    }

    fn calculate_context_adjustments(&self, _input: &str, context: &RequestContext) -> f32 {
        let mut adjustment = 0.0;
        
        // Adjust based on HTTP method
        match context.method.as_str() {
            "GET" => adjustment -= 0.1, // GET requests slightly less suspicious
            "POST" => adjustment += 0.0, // Neutral
            "PUT" | "DELETE" => adjustment += 0.1, // Slightly more suspicious
            _ => adjustment += 0.2, // Unusual methods more suspicious
        }
        
        // Adjust based on content type
        if let Some(content_type) = &context.content_type {
            match content_type.as_str() {
                "application/json" => adjustment -= 0.05,
                "application/x-www-form-urlencoded" => adjustment += 0.0,
                "multipart/form-data" => adjustment += 0.05,
                _ => adjustment += 0.1,
            }
        }
        
        // Adjust based on URL patterns
        if context.url.contains("/api/") {
            adjustment -= 0.1; // API endpoints less suspicious
        } else if context.url.contains("/admin/") {
            adjustment += 0.2; // Admin endpoints more critical
        }
        
        adjustment
    }

    fn match_signatures(&self, input: &str) -> Vec<DetectedPattern> {
        let mut matches = Vec::new();
        
        for signature in &self.signature_db.signatures {
            if input.contains(&signature.pattern) {
                matches.push(DetectedPattern {
                    pattern: signature.pattern.clone(),
                    category: self.string_to_category(&signature.category),
                    score: signature.severity,
                    positions: vec![0], // Would need proper position tracking
                    context: signature.description.clone(),
                });
            }
        }
        
        matches
    }

    fn string_to_category(&self, category: &str) -> AttackCategory {
        match category.to_lowercase().as_str() {
            "sql" | "sqli" | "sql_injection" => AttackCategory::SqlInjection,
            "xss" | "cross_site_scripting" => AttackCategory::XssAttack,
            "path" | "path_traversal" => AttackCategory::PathTraversal,
            "cmd" | "command_injection" => AttackCategory::CommandInjection,
            "file" | "file_inclusion" => AttackCategory::FileInclusion,
            "encoding" | "encoding_attack" => AttackCategory::EncodingAttack,
            _ => AttackCategory::SqlInjection, // Default
        }
    }

    fn calculate_confidence_level(&self, category_scores: &HashMap<AttackCategory, f32>, 
                                 behavioral_anomalies: &[BehavioralAnomaly], 
                                 detected_patterns: &[DetectedPattern]) -> f32 {
        let max_category_score = category_scores.values().fold(0.0f32, |a, &b| a.max(b));
        let avg_behavioral_score = if behavioral_anomalies.is_empty() {
            0.0
        } else {
            behavioral_anomalies.iter().map(|a| a.score).sum::<f32>() / behavioral_anomalies.len() as f32
        };
        let pattern_confidence = if detected_patterns.is_empty() {
            0.0
        } else {
            detected_patterns.iter().map(|p| p.score).sum::<f32>() / detected_patterns.len() as f32
        };
        
        (max_category_score + avg_behavioral_score + pattern_confidence) / 3.0
    }
}

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub method: String,
    pub url: String,
    pub content_type: Option<String>,
    pub user_agent: Option<String>,
    pub headers: HashMap<String, String>,
}

impl ContextWeights {
    pub fn new() -> Self {
        let mut request_context = HashMap::new();
        request_context.insert("GET".to_string(), 0.9);
        request_context.insert("POST".to_string(), 1.0);
        request_context.insert("PUT".to_string(), 1.1);
        request_context.insert("DELETE".to_string(), 1.1);
        
        let mut content_type_weights = HashMap::new();
        content_type_weights.insert("application/json".to_string(), 0.9);
        content_type_weights.insert("application/x-www-form-urlencoded".to_string(), 1.0);
        content_type_weights.insert("multipart/form-data".to_string(), 1.1);
        
        Self {
            request_context,
            url_patterns: HashMap::new(),
            parameter_patterns: HashMap::new(),
            content_type_weights,
        }
    }
}

impl AttackSignatureDatabase {
    pub fn new() -> Self {
        let signatures = vec![
            AttackSignature {
                id: "SQL001".to_string(),
                name: "Classic SQL Injection".to_string(),
                category: "sql_injection".to_string(),
                pattern: "' or '1'='1".to_string(),
                severity: 0.95,
                confidence: 0.9,
                description: "Classic SQL injection bypass attempt".to_string(),
                references: vec!["OWASP-A03".to_string()],
            },
            AttackSignature {
                id: "XSS001".to_string(),
                name: "Basic XSS Script Tag".to_string(),
                category: "xss".to_string(),
                pattern: "<script>alert(".to_string(),
                severity: 0.9,
                confidence: 0.95,
                description: "Basic XSS attempt using script tag".to_string(),
                references: vec!["OWASP-A07".to_string()],
            },
            // Add more signatures as needed
        ];
        
        Self {
            signatures,
            match_cache: HashMap::new(),
        }
    }
}

impl Default for EnhancedPatternRecognition {
    fn default() -> Self {
        Self::new()
    }
}