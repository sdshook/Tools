//! Threat Educator Module - Structured Knowledge Transfer for BHSM/PSI
//!
//! The ThreatEducator enables pedagogical knowledge transfer to PSI (Persistent Semantic Index)
//! without requiring operational experience or individual examples. It provides:
//!
//! 1. **Declarative Curricula**: Describe threat categories with feature profiles
//! 2. **Synthetic Generation**: Generate training examples from templates/mutations
//! 3. **Semantic Injection**: Create PSI entries with proper Hebbian connections
//! 4. **N-gram Teaching**: Teach characteristic patterns to EmbeddingLearner
//!
//! ## Design Philosophy
//!
//! The educator maintains the "learned, not coded" principle by:
//! - Injecting learnable content (not detection rules)
//! - Using existing PSI one-shot learning infrastructure
//! - Creating Hebbian associations that evolve with experience
//! - Generating traceable knowledge (tagged as "educated")
//!
//! ## Learning Pathway Comparison
//!
//! | Pathway | Source | Learning Type | Speed |
//! |---------|--------|---------------|-------|
//! | Zero-shot | Environment/Logs | Passive statistical | Slow (needs volume) |
//! | One-shot (Mentor) | Individual examples | Experiential | Medium (per-example) |
//! | Educator | Curriculum definitions | Pedagogical | Fast (batch injection) |

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use rand::Rng;

use crate::memory_engine::psi_index::{PsiIndex, PsiEntry, EMBED_DIM};
use crate::advanced_feature_extractor::AdvancedFeatureExtractor;
use crate::embedding_learner::EmbeddingLearner;

/// Attack category taxonomy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttackCategory {
    #[serde(rename = "injection.sql")]
    SqlInjection,
    #[serde(rename = "injection.sql.boolean")]
    SqlInjectionBoolean,
    #[serde(rename = "injection.sql.union")]
    SqlInjectionUnion,
    #[serde(rename = "injection.sql.time")]
    SqlInjectionTime,
    #[serde(rename = "injection.command")]
    CommandInjection,
    #[serde(rename = "xss.reflected")]
    XssReflected,
    #[serde(rename = "xss.stored")]
    XssStored,
    #[serde(rename = "xss.dom")]
    XssDom,
    #[serde(rename = "traversal.path")]
    PathTraversal,
    #[serde(rename = "traversal.lfi")]
    LocalFileInclusion,
    #[serde(rename = "traversal.rfi")]
    RemoteFileInclusion,
    #[serde(rename = "ssrf")]
    Ssrf,
    #[serde(rename = "xxe")]
    XxeInjection,
    #[serde(rename = "deserialization")]
    InsecureDeserialization,
    #[serde(rename = "custom")]
    Custom(String),
}

impl Default for AttackCategory {
    fn default() -> Self {
        AttackCategory::Custom("unknown".to_string())
    }
}

/// Severity level for threat curricula
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Medium
    }
}

impl Severity {
    /// Convert severity to valence modifier (higher severity = higher valence)
    pub fn to_valence(&self) -> f32 {
        match self {
            Severity::Low => 0.6,
            Severity::Medium => 0.75,
            Severity::High => 0.85,
            Severity::Critical => 0.95,
        }
    }
}

/// Feature profile describing statistical characteristics of a threat
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeatureProfile {
    /// Expected entropy range (min, max) - normalized 0-1
    #[serde(default)]
    pub entropy_range: Option<(f32, f32)>,
    
    /// Expected special character ratio range (min, max)
    #[serde(default)]
    pub special_char_ratio: Option<(f32, f32)>,
    
    /// Expected punctuation ratio range
    #[serde(default)]
    pub punctuation_ratio: Option<(f32, f32)>,
    
    /// Whether quotes are typically unbalanced
    #[serde(default)]
    pub quote_unbalanced: bool,
    
    /// Whether brackets are typically unbalanced
    #[serde(default)]
    pub bracket_unbalanced: bool,
    
    /// Expected nesting depth range
    #[serde(default)]
    pub nesting_depth: Option<(f32, f32)>,
    
    /// Structural markers to expect
    #[serde(default)]
    pub markers: Vec<String>,
}

/// Signature pattern with threat weight
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePattern {
    /// The n-gram or pattern string
    pub ngram: String,
    /// Weight for this pattern (0.0-1.0)
    pub weight: f32,
}

/// Mutation rules for generating variations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationRule {
    /// Type of mutation
    #[serde(rename = "type")]
    pub mutation_type: MutationType,
    /// Targets or variants for the mutation
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub variants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MutationType {
    CaseVariation,
    Whitespace,
    Encoding,
    CommentInsertion,
    CharSubstitution,
}

/// A threat curriculum - structured description of an attack pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCurriculum {
    /// Unique identifier for this curriculum
    pub name: String,
    
    /// Attack category from taxonomy
    #[serde(default)]
    pub category: AttackCategory,
    
    /// Human-readable description
    #[serde(default)]
    pub description: String,
    
    /// Severity level
    #[serde(default)]
    pub severity: Severity,
    
    /// Statistical feature profile
    #[serde(default)]
    pub feature_profile: FeatureProfile,
    
    /// Characteristic n-gram patterns
    #[serde(default)]
    pub signature_patterns: Vec<SignaturePattern>,
    
    /// Template strings for generating examples
    /// Use {placeholder} for variable parts
    #[serde(default)]
    pub templates: Vec<String>,
    
    /// Mutation rules for generating variations
    #[serde(default)]
    pub mutations: Vec<MutationRule>,
}

/// Result of an education session
#[derive(Debug, Clone)]
pub struct EducationResult {
    /// Curriculum that was taught
    pub curriculum_name: String,
    /// Number of PSI entries created
    pub entries_created: usize,
    /// Number of n-gram associations taught
    pub ngram_associations: usize,
    /// Whether a prototype was injected
    pub prototype_injected: bool,
    /// Generated examples (for verification)
    pub examples_generated: Vec<String>,
}

/// Statistics for the ThreatEducator
#[derive(Debug, Clone, Default)]
pub struct EducatorStats {
    pub curricula_taught: usize,
    pub total_entries_created: usize,
    pub total_ngram_associations: usize,
    pub total_examples_generated: usize,
}

/// The ThreatEducator - structured knowledge transfer to PSI
pub struct ThreatEducator {
    /// Feature extractor for creating embeddings
    feature_extractor: AdvancedFeatureExtractor,
    /// Configuration
    examples_per_curriculum: usize,
    prototype_valence: f32,
    example_valence_base: f32,
    /// Statistics
    stats: EducatorStats,
    /// Taught curricula (for tracking)
    taught_curricula: HashMap<String, ThreatCurriculum>,
}

impl ThreatEducator {
    /// Create a new ThreatEducator
    pub fn new() -> Self {
        Self {
            feature_extractor: AdvancedFeatureExtractor::new(),
            examples_per_curriculum: 10,
            prototype_valence: 0.95,
            example_valence_base: 0.8,
            stats: EducatorStats::default(),
            taught_curricula: HashMap::new(),
        }
    }

    /// Configure the number of examples to generate per curriculum
    pub fn with_examples_per_curriculum(mut self, count: usize) -> Self {
        self.examples_per_curriculum = count;
        self
    }

    /// Teach a curriculum to PSI
    ///
    /// This is the main entry point for education. It:
    /// 1. Generates synthetic examples from templates
    /// 2. Creates PSI entries with appropriate valence
    /// 3. Uses one-shot learning to establish Hebbian connections
    /// 4. Optionally injects a semantic prototype
    pub fn teach(&mut self, curriculum: &ThreatCurriculum, psi: &mut PsiIndex) -> EducationResult {
        let mut result = EducationResult {
            curriculum_name: curriculum.name.clone(),
            entries_created: 0,
            ngram_associations: 0,
            prototype_injected: false,
            examples_generated: Vec::new(),
        };

        // 1. Generate synthetic examples from templates
        let examples = self.generate_examples(curriculum);
        result.examples_generated = examples.clone();

        // 2. Inject prototype first (serves as anchor for Hebbian connections)
        if !curriculum.feature_profile.markers.is_empty() || curriculum.feature_profile.entropy_range.is_some() {
            self.inject_prototype(curriculum, psi);
            result.prototype_injected = true;
            result.entries_created += 1;
        }

        // 3. Create PSI entries from generated examples
        let base_valence = curriculum.severity.to_valence();
        
        for (i, example) in examples.iter().enumerate() {
            let embedding = self.create_embedding(example);
            
            // Vary valence slightly to avoid exact duplicates
            let valence_variation = (i as f32 * 0.01).min(0.05);
            let valence = (base_valence + valence_variation).min(0.99);
            
            let entry = PsiEntry {
                id: format!("edu_{}_{}", curriculum.name.replace(' ', "_"), i),
                vec: embedding,
                valence,
                uses: 0,
                tags: vec![
                    curriculum.name.clone(),
                    "educated".to_string(),
                    format!("{:?}", curriculum.category),
                ],
                last_activation: current_timestamp(),
                cumulative_reward: 0.0,
            };

            // Use one-shot learning to create Hebbian connections
            psi.one_shot_learn(entry, 1.0);
            result.entries_created += 1;
        }

        // 4. Track statistics
        self.stats.curricula_taught += 1;
        self.stats.total_entries_created += result.entries_created;
        self.stats.total_examples_generated += result.examples_generated.len();
        self.taught_curricula.insert(curriculum.name.clone(), curriculum.clone());

        result
    }

    /// Teach n-gram associations to the EmbeddingLearner
    ///
    /// This supplements PSI learning by directly teaching characteristic
    /// n-gram patterns to the embedding learner.
    pub fn teach_ngram_associations(
        &mut self,
        curriculum: &ThreatCurriculum,
        embedding_learner: &mut EmbeddingLearner,
    ) -> usize {
        let examples = self.generate_examples(curriculum);
        let mut associations_taught = 0;

        for example in &examples {
            // Teach as threat pattern with high confidence
            embedding_learner.learn(example, true, 1.0);
            associations_taught += 1;
        }

        // Also teach signature patterns directly if provided
        for pattern in &curriculum.signature_patterns {
            embedding_learner.learn(&pattern.ngram, true, pattern.weight);
            associations_taught += 1;
        }

        self.stats.total_ngram_associations += associations_taught;
        associations_taught
    }

    /// Full education: teach to both PSI and EmbeddingLearner
    pub fn teach_full(
        &mut self,
        curriculum: &ThreatCurriculum,
        psi: &mut PsiIndex,
        embedding_learner: &mut EmbeddingLearner,
    ) -> EducationResult {
        let mut result = self.teach(curriculum, psi);
        result.ngram_associations = self.teach_ngram_associations(curriculum, embedding_learner);
        result
    }

    /// Teach multiple curricula as a course
    pub fn teach_course(
        &mut self,
        curricula: &[ThreatCurriculum],
        psi: &mut PsiIndex,
    ) -> Vec<EducationResult> {
        curricula.iter()
            .map(|c| self.teach(c, psi))
            .collect()
    }

    /// Generate synthetic examples from a curriculum
    fn generate_examples(&self, curriculum: &ThreatCurriculum) -> Vec<String> {
        let mut examples = Vec::new();
        let mut rng = rand::thread_rng();

        // Generate from templates
        for template in &curriculum.templates {
            // Generate base example from template
            let base = self.expand_template(template);
            examples.push(base.clone());

            // Generate mutations if configured
            for mutation in &curriculum.mutations {
                if examples.len() >= self.examples_per_curriculum {
                    break;
                }
                if let Some(mutated) = self.apply_mutation(&base, mutation, &mut rng) {
                    examples.push(mutated);
                }
            }
        }

        // If we still need more examples, generate from signature patterns
        while examples.len() < self.examples_per_curriculum && !curriculum.signature_patterns.is_empty() {
            let idx = rng.gen_range(0..curriculum.signature_patterns.len());
            let pattern = &curriculum.signature_patterns[idx];
            
            // Wrap pattern in realistic context
            let example = self.contextualize_pattern(&pattern.ngram, &mut rng);
            examples.push(example);
        }

        // Limit to configured count
        examples.truncate(self.examples_per_curriculum);
        examples
    }

    /// Expand template placeholders
    fn expand_template(&self, template: &str) -> String {
        let mut result = template.to_string();
        let mut rng = rand::thread_rng();

        // Replace common placeholders
        let replacements = [
            ("{bool_expr}", vec!["1=1", "'a'='a'", "1", "true"]),
            ("{condition}", vec!["1=1", "'x'='x'", "1>0", "2=2"]),
            ("{char}", vec!["a", "x", "1", "z"]),
            ("{table}", vec!["users", "admin", "accounts", "data"]),
            ("{column}", vec!["password", "id", "username", "email"]),
            ("{cmd}", vec!["id", "whoami", "cat /etc/passwd", "ls -la"]),
            ("{file}", vec!["/etc/passwd", "/etc/shadow", "../../etc/passwd"]),
            ("{url}", vec!["http://evil.com", "http://localhost", "file://"]),
            ("{script}", vec!["alert(1)", "alert('xss')", "document.cookie"]),
        ];

        for (placeholder, options) in &replacements {
            while result.contains(placeholder) {
                let replacement = options[rng.gen_range(0..options.len())];
                result = result.replacen(placeholder, replacement, 1);
            }
        }

        result
    }

    /// Apply a mutation to generate a variant
    fn apply_mutation(&self, input: &str, mutation: &MutationRule, rng: &mut impl Rng) -> Option<String> {
        match mutation.mutation_type {
            MutationType::CaseVariation => {
                // Randomly change case of keywords
                let mut result = input.to_string();
                for target in &mutation.targets {
                    if result.contains(target) {
                        let variants = [
                            target.to_uppercase(),
                            target.to_lowercase(),
                            Self::mixed_case(target),
                        ];
                        let variant = &variants[rng.gen_range(0..variants.len())];
                        result = result.replace(target, variant);
                    }
                }
                Some(result)
            }
            MutationType::Whitespace => {
                // Insert whitespace variants
                let mut result = input.to_string();
                if !mutation.variants.is_empty() {
                    let variant = &mutation.variants[rng.gen_range(0..mutation.variants.len())];
                    // Insert between tokens
                    result = result.replace(" ", variant);
                }
                Some(result)
            }
            MutationType::Encoding => {
                // Apply encoding variant
                if !mutation.variants.is_empty() {
                    let variant_type = &mutation.variants[rng.gen_range(0..mutation.variants.len())];
                    match variant_type.as_str() {
                        "url" => Some(Self::url_encode_partial(input, rng)),
                        "unicode" => Some(Self::unicode_encode_partial(input, rng)),
                        "hex" => Some(Self::hex_encode_partial(input, rng)),
                        _ => Some(input.to_string()),
                    }
                } else {
                    Some(input.to_string())
                }
            }
            MutationType::CommentInsertion => {
                // Insert SQL/HTML comments
                let comments = ["/**/", "<!---->", "-- ", "#"];
                let comment = comments[rng.gen_range(0..comments.len())];
                let pos = rng.gen_range(1..input.len().max(2));
                let mut result = input.to_string();
                result.insert_str(pos.min(result.len()), comment);
                Some(result)
            }
            MutationType::CharSubstitution => {
                // Substitute characters with lookalikes
                let mut result = input.to_string();
                let subs = [('a', 'α'), ('e', 'е'), ('o', 'о'), ('i', 'і')];
                for (from, to) in &subs {
                    if rng.gen_bool(0.3) {
                        result = result.replacen(*from, &to.to_string(), 1);
                    }
                }
                Some(result)
            }
        }
    }

    /// Create mixed case version of a string
    fn mixed_case(s: &str) -> String {
        s.chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_uppercase().next().unwrap_or(c)
                } else {
                    c.to_lowercase().next().unwrap_or(c)
                }
            })
            .collect()
    }

    /// Partially URL encode a string
    fn url_encode_partial(s: &str, rng: &mut impl Rng) -> String {
        s.chars()
            .map(|c| {
                if !c.is_alphanumeric() && rng.gen_bool(0.5) {
                    format!("%{:02X}", c as u8)
                } else {
                    c.to_string()
                }
            })
            .collect()
    }

    /// Partially unicode encode a string
    fn unicode_encode_partial(s: &str, rng: &mut impl Rng) -> String {
        s.chars()
            .map(|c| {
                if !c.is_alphanumeric() && rng.gen_bool(0.3) {
                    format!("\\u{:04X}", c as u32)
                } else {
                    c.to_string()
                }
            })
            .collect()
    }

    /// Partially hex encode a string
    fn hex_encode_partial(s: &str, rng: &mut impl Rng) -> String {
        s.chars()
            .map(|c| {
                if !c.is_alphanumeric() && rng.gen_bool(0.3) {
                    format!("0x{:02X}", c as u8)
                } else {
                    c.to_string()
                }
            })
            .collect()
    }

    /// Wrap a pattern in realistic request context
    fn contextualize_pattern(&self, pattern: &str, rng: &mut impl Rng) -> String {
        let contexts = [
            format!("GET /search?q={} HTTP/1.1", pattern),
            format!("POST /api/data\n\nid={}", pattern),
            format!("/page?input={}", pattern),
            format!("user={}&action=view", pattern),
            pattern.to_string(),
        ];
        contexts[rng.gen_range(0..contexts.len())].clone()
    }

    /// Inject a semantic prototype into PSI
    fn inject_prototype(&self, curriculum: &ThreatCurriculum, psi: &mut PsiIndex) {
        let embedding = self.profile_to_embedding(&curriculum.feature_profile);
        
        let prototype = PsiEntry {
            id: format!("prototype_{}", curriculum.name.replace(' ', "_")),
            vec: embedding,
            valence: self.prototype_valence,
            uses: 0,
            tags: vec![
                curriculum.name.clone(),
                "prototype".to_string(),
                "educated".to_string(),
                format!("{:?}", curriculum.category),
            ],
            last_activation: current_timestamp(),
            cumulative_reward: 0.0,
        };

        psi.add(prototype);
    }

    /// Convert a feature profile to an embedding vector
    fn profile_to_embedding(&self, profile: &FeatureProfile) -> [f32; EMBED_DIM] {
        let mut embedding = [0.0f32; EMBED_DIM];
        
        // Map feature profile to embedding dimensions
        // Based on AdvancedFeatureExtractor's feature layout
        
        // Entropy (dim 4)
        if let Some((min, max)) = profile.entropy_range {
            embedding[4] = (min + max) / 2.0;
        }
        
        // Special char ratio (dim 10)
        if let Some((min, max)) = profile.special_char_ratio {
            embedding[10] = (min + max) / 2.0;
        }
        
        // Punctuation ratio (dim 14)
        if let Some((min, max)) = profile.punctuation_ratio {
            embedding[14] = (min + max) / 2.0;
        }
        
        // Quote balance (dim 20) - 0.0 means unbalanced
        embedding[20] = if profile.quote_unbalanced { 0.0 } else { 1.0 };
        
        // Bracket balance (dim 21) - 0.0 means unbalanced
        embedding[21] = if profile.bracket_unbalanced { 0.0 } else { 1.0 };
        
        // Nesting depth (dim 16)
        if let Some((min, max)) = profile.nesting_depth {
            embedding[16] = (min + max) / 2.0;
        }
        
        // Structural anomaly (dim 30) - set high for threat profiles
        embedding[30] = 0.7;
        
        // Statistical complexity (dim 31)
        embedding[31] = 0.6;
        
        // Add some noise to make it realistic
        let mut rng = rand::thread_rng();
        for i in 0..EMBED_DIM {
            if embedding[i] == 0.0 && rng.gen_bool(0.3) {
                embedding[i] = rng.gen_range(0.1..0.4);
            }
        }
        
        // Normalize
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in &mut embedding {
                *x /= norm;
            }
        }
        
        embedding
    }

    /// Create an embedding from a request string
    fn create_embedding(&self, request: &str) -> [f32; EMBED_DIM] {
        self.feature_extractor.extract_features(request)
    }

    /// Get educator statistics
    pub fn get_stats(&self) -> &EducatorStats {
        &self.stats
    }

    /// Get list of taught curricula names
    pub fn get_taught_curricula(&self) -> Vec<String> {
        self.taught_curricula.keys().cloned().collect()
    }

    /// Check if a curriculum has been taught
    pub fn is_taught(&self, name: &str) -> bool {
        self.taught_curricula.contains_key(name)
    }

    /// Load curricula from JSON
    pub fn load_curricula_from_json(json: &str) -> Result<Vec<ThreatCurriculum>, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Create built-in SQL injection curriculum
    pub fn builtin_sqli_curriculum() -> ThreatCurriculum {
        ThreatCurriculum {
            name: "SQL Injection".to_string(),
            category: AttackCategory::SqlInjection,
            description: "SQL injection attacks that manipulate database queries through user input".to_string(),
            severity: Severity::Critical,
            feature_profile: FeatureProfile {
                entropy_range: Some((0.55, 0.75)),
                special_char_ratio: Some((0.15, 0.35)),
                punctuation_ratio: Some((0.1, 0.3)),
                quote_unbalanced: true,
                bracket_unbalanced: false,
                nesting_depth: Some((0.0, 0.2)),
                markers: vec!["unbalanced_quotes".to_string(), "consecutive_special".to_string()],
            },
            signature_patterns: vec![
                SignaturePattern { ngram: "' OR".to_string(), weight: 0.9 },
                SignaturePattern { ngram: "1=1".to_string(), weight: 0.85 },
                SignaturePattern { ngram: "' AND".to_string(), weight: 0.8 },
                SignaturePattern { ngram: "--".to_string(), weight: 0.7 },
                SignaturePattern { ngram: "UNION".to_string(), weight: 0.85 },
                SignaturePattern { ngram: "SELECT".to_string(), weight: 0.6 },
            ],
            templates: vec![
                "' OR {bool_expr} --".to_string(),
                "' AND {bool_expr} --".to_string(),
                "1' OR '{char}'='{char}".to_string(),
                "admin'--".to_string(),
                "' UNION SELECT * FROM {table}--".to_string(),
                "1; DROP TABLE {table}--".to_string(),
            ],
            mutations: vec![
                MutationRule {
                    mutation_type: MutationType::CaseVariation,
                    targets: vec!["OR".to_string(), "AND".to_string(), "SELECT".to_string(), "UNION".to_string()],
                    variants: vec![],
                },
                MutationRule {
                    mutation_type: MutationType::Whitespace,
                    targets: vec![],
                    variants: vec!["/**/".to_string(), "+".to_string(), "%20".to_string()],
                },
                MutationRule {
                    mutation_type: MutationType::CommentInsertion,
                    targets: vec![],
                    variants: vec![],
                },
            ],
        }
    }

    /// Create built-in XSS curriculum
    pub fn builtin_xss_curriculum() -> ThreatCurriculum {
        ThreatCurriculum {
            name: "Cross-Site Scripting".to_string(),
            category: AttackCategory::XssReflected,
            description: "XSS attacks that inject malicious scripts into web pages".to_string(),
            severity: Severity::High,
            feature_profile: FeatureProfile {
                entropy_range: Some((0.5, 0.7)),
                special_char_ratio: Some((0.2, 0.4)),
                punctuation_ratio: Some((0.15, 0.35)),
                quote_unbalanced: false,
                bracket_unbalanced: true,
                nesting_depth: Some((0.1, 0.4)),
                markers: vec!["high_nesting".to_string(), "angle_brackets".to_string()],
            },
            signature_patterns: vec![
                SignaturePattern { ngram: "<script".to_string(), weight: 0.95 },
                SignaturePattern { ngram: "javascript:".to_string(), weight: 0.9 },
                SignaturePattern { ngram: "onerror=".to_string(), weight: 0.85 },
                SignaturePattern { ngram: "onload=".to_string(), weight: 0.8 },
                SignaturePattern { ngram: "alert(".to_string(), weight: 0.75 },
                SignaturePattern { ngram: "document.cookie".to_string(), weight: 0.85 },
            ],
            templates: vec![
                "<script>{script}</script>".to_string(),
                "<img src=x onerror={script}>".to_string(),
                "javascript:{script}".to_string(),
                "<svg onload={script}>".to_string(),
                "'\"><script>{script}</script>".to_string(),
            ],
            mutations: vec![
                MutationRule {
                    mutation_type: MutationType::CaseVariation,
                    targets: vec!["script".to_string(), "onerror".to_string(), "onload".to_string()],
                    variants: vec![],
                },
                MutationRule {
                    mutation_type: MutationType::Encoding,
                    targets: vec![],
                    variants: vec!["url".to_string(), "unicode".to_string()],
                },
            ],
        }
    }

    /// Create built-in path traversal curriculum
    pub fn builtin_path_traversal_curriculum() -> ThreatCurriculum {
        ThreatCurriculum {
            name: "Path Traversal".to_string(),
            category: AttackCategory::PathTraversal,
            description: "Path traversal attacks that access files outside the intended directory".to_string(),
            severity: Severity::High,
            feature_profile: FeatureProfile {
                entropy_range: Some((0.4, 0.6)),
                special_char_ratio: Some((0.2, 0.35)),
                punctuation_ratio: Some((0.15, 0.3)),
                quote_unbalanced: false,
                bracket_unbalanced: false,
                nesting_depth: Some((0.0, 0.1)),
                markers: vec!["repetition".to_string(), "path_separators".to_string()],
            },
            signature_patterns: vec![
                SignaturePattern { ngram: "../".to_string(), weight: 0.9 },
                SignaturePattern { ngram: "..\\".to_string(), weight: 0.9 },
                SignaturePattern { ngram: "/etc/passwd".to_string(), weight: 0.85 },
                SignaturePattern { ngram: "....//".to_string(), weight: 0.8 },
                SignaturePattern { ngram: "%2e%2e".to_string(), weight: 0.85 },
            ],
            templates: vec![
                "../../../{file}".to_string(),
                "....//....//....//etc/passwd".to_string(),
                "..\\..\\..\\windows\\system32\\config\\sam".to_string(),
                "/var/www/../../{file}".to_string(),
            ],
            mutations: vec![
                MutationRule {
                    mutation_type: MutationType::Encoding,
                    targets: vec![],
                    variants: vec!["url".to_string()],
                },
            ],
        }
    }

    /// Create built-in command injection curriculum
    pub fn builtin_command_injection_curriculum() -> ThreatCurriculum {
        ThreatCurriculum {
            name: "Command Injection".to_string(),
            category: AttackCategory::CommandInjection,
            description: "Command injection attacks that execute system commands through user input".to_string(),
            severity: Severity::Critical,
            feature_profile: FeatureProfile {
                entropy_range: Some((0.5, 0.7)),
                special_char_ratio: Some((0.15, 0.3)),
                punctuation_ratio: Some((0.1, 0.25)),
                quote_unbalanced: false,
                bracket_unbalanced: false,
                nesting_depth: Some((0.0, 0.2)),
                markers: vec!["pipe_char".to_string(), "semicolon".to_string()],
            },
            signature_patterns: vec![
                SignaturePattern { ngram: "; cat".to_string(), weight: 0.9 },
                SignaturePattern { ngram: "| ls".to_string(), weight: 0.85 },
                SignaturePattern { ngram: "`id`".to_string(), weight: 0.9 },
                SignaturePattern { ngram: "$(".to_string(), weight: 0.75 },
                SignaturePattern { ngram: "&&".to_string(), weight: 0.6 },
                SignaturePattern { ngram: "||".to_string(), weight: 0.6 },
            ],
            templates: vec![
                "; {cmd}".to_string(),
                "| {cmd}".to_string(),
                "`{cmd}`".to_string(),
                "$({cmd})".to_string(),
                "&& {cmd}".to_string(),
                "|| {cmd}".to_string(),
            ],
            mutations: vec![
                MutationRule {
                    mutation_type: MutationType::Whitespace,
                    targets: vec![],
                    variants: vec!["${IFS}".to_string(), "\t".to_string()],
                },
                MutationRule {
                    mutation_type: MutationType::Encoding,
                    targets: vec![],
                    variants: vec!["url".to_string(), "hex".to_string()],
                },
            ],
        }
    }

    /// Get all built-in curricula
    pub fn builtin_curricula() -> Vec<ThreatCurriculum> {
        vec![
            Self::builtin_sqli_curriculum(),
            Self::builtin_xss_curriculum(),
            Self::builtin_path_traversal_curriculum(),
            Self::builtin_command_injection_curriculum(),
        ]
    }
}

impl Default for ThreatEducator {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current timestamp as f64 seconds since UNIX epoch
fn current_timestamp() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curriculum_serialization() {
        let curriculum = ThreatEducator::builtin_sqli_curriculum();
        let json = serde_json::to_string_pretty(&curriculum).unwrap();
        println!("Curriculum JSON:\n{}", json);
        
        let parsed: ThreatCurriculum = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, curriculum.name);
    }

    #[test]
    fn test_example_generation() {
        let educator = ThreatEducator::new().with_examples_per_curriculum(5);
        let curriculum = ThreatEducator::builtin_sqli_curriculum();
        let examples = educator.generate_examples(&curriculum);
        
        println!("Generated {} examples:", examples.len());
        for (i, ex) in examples.iter().enumerate() {
            println!("  {}: {}", i, ex);
        }
        
        assert!(!examples.is_empty());
        assert!(examples.len() <= 5);
    }

    #[test]
    fn test_teach_to_psi() {
        let mut educator = ThreatEducator::new().with_examples_per_curriculum(3);
        let mut psi = PsiIndex::new();
        
        let curriculum = ThreatEducator::builtin_sqli_curriculum();
        let result = educator.teach(&curriculum, &mut psi);
        
        println!("Education result: {:?}", result);
        
        assert!(result.entries_created > 0);
        assert_eq!(result.curriculum_name, "SQL Injection");
        assert!(psi.len() > 0);
    }

    #[test]
    fn test_multiple_curricula() {
        let mut educator = ThreatEducator::new().with_examples_per_curriculum(3);
        let mut psi = PsiIndex::new();
        
        let curricula = ThreatEducator::builtin_curricula();
        let results = educator.teach_course(&curricula, &mut psi);
        
        println!("Taught {} curricula:", results.len());
        for result in &results {
            println!("  {} - {} entries", result.curriculum_name, result.entries_created);
        }
        
        assert_eq!(results.len(), 4);
        assert!(psi.len() > 10);
    }

    #[test]
    fn test_mutations() {
        let educator = ThreatEducator::new();
        let mut rng = rand::thread_rng();
        
        let mutation = MutationRule {
            mutation_type: MutationType::CaseVariation,
            targets: vec!["SELECT".to_string(), "UNION".to_string()],
            variants: vec![],
        };
        
        let input = "' UNION SELECT * FROM users";
        let result = educator.apply_mutation(input, &mutation, &mut rng);
        
        println!("Original: {}", input);
        println!("Mutated: {:?}", result);
        
        assert!(result.is_some());
    }

    #[test]
    fn test_profile_to_embedding() {
        let educator = ThreatEducator::new();
        let curriculum = ThreatEducator::builtin_sqli_curriculum();
        
        let embedding = educator.profile_to_embedding(&curriculum.feature_profile);
        
        // Should be normalized
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 0.01, "Embedding should be normalized, got norm={}", norm);
        
        // Should have some non-zero values
        let non_zero = embedding.iter().filter(|&&x| x.abs() > 0.01).count();
        assert!(non_zero > 5, "Embedding should have multiple non-zero values");
    }

    #[test]
    fn test_load_custom_curriculum() {
        // Test with a known category (custom requires newtype syntax)
        let json = r#"[{
            "name": "Custom Test Attack",
            "category": "injection.sql",
            "description": "A test curriculum",
            "severity": "high",
            "templates": ["test{placeholder}payload"],
            "signature_patterns": [
                {"ngram": "test", "weight": 0.8}
            ]
        }]"#;
        
        let curricula = ThreatEducator::load_curricula_from_json(json).unwrap();
        assert_eq!(curricula.len(), 1);
        assert_eq!(curricula[0].name, "Custom Test Attack");
        
        // Test with custom category (newtype syntax)
        let json_custom = r#"[{
            "name": "Custom Attack Type",
            "category": {"custom": "my_custom_attack"},
            "description": "A custom curriculum",
            "severity": "medium",
            "templates": ["payload"]
        }]"#;
        
        let custom_curricula = ThreatEducator::load_curricula_from_json(json_custom).unwrap();
        assert_eq!(custom_curricula.len(), 1);
        assert_eq!(custom_curricula[0].name, "Custom Attack Type");
        assert!(matches!(custom_curricula[0].category, AttackCategory::Custom(_)));
    }
}
