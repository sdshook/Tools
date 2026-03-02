#![allow(dead_code)]

//! Pure Statistical Feature Extractor for Self-Learning WebGuard
//! 
//! DESIGN PRINCIPLE: NO hard-coded attack patterns, signatures, whitelists, or blacklists.
//! This extractor produces ONLY raw statistical features that the learning system
//! uses to develop its own understanding of threats through reinforcement.

use std::collections::{HashMap, HashSet};

/// Character class distribution for statistical analysis
#[derive(Debug, Clone, Default)]
pub struct CharacterDistribution {
    pub alpha_ratio: f32,
    pub digit_ratio: f32,
    pub special_ratio: f32,
    pub whitespace_ratio: f32,
    pub uppercase_ratio: f32,
    pub printable_ratio: f32,
    pub punctuation_ratio: f32,
    pub unique_char_ratio: f32,
}

/// Pure statistical feature extractor - NO predefined attack patterns
#[derive(Debug, Clone)]
pub struct AdvancedFeatureExtractor {
    _placeholder: (),
}

impl AdvancedFeatureExtractor {
    pub fn new() -> Self {
        Self { _placeholder: () }
    }

    /// Extract PURE STATISTICAL features - NO attack pattern matching
    pub fn extract_features(&self, request_data: &str) -> [f32; 32] {
        let mut features = [0.0; 32];
        let bytes = request_data.as_bytes();
        
        // SIZE/LENGTH METRICS (0-3)
        features[0] = (request_data.len() as f32 / 2000.0).min(1.0);
        features[1] = (request_data.lines().count() as f32 / 50.0).min(1.0);
        features[2] = self.avg_line_length(request_data);
        features[3] = self.max_line_length(request_data);
        
        // ENTROPY MEASUREMENTS (4-7)
        features[4] = self.calculate_entropy(bytes);
        features[5] = self.calculate_bigram_entropy(request_data);
        features[6] = self.calculate_positional_entropy(request_data);
        features[7] = self.calculate_entropy_variance(request_data);
        
        // CHARACTER CLASS DISTRIBUTIONS (8-15)
        let char_dist = self.character_class_distribution(request_data);
        features[8] = char_dist.alpha_ratio;
        features[9] = char_dist.digit_ratio;
        features[10] = char_dist.special_ratio;
        features[11] = char_dist.whitespace_ratio;
        features[12] = char_dist.uppercase_ratio;
        features[13] = char_dist.printable_ratio;
        features[14] = char_dist.punctuation_ratio;
        features[15] = char_dist.unique_char_ratio;
        
        // STRUCTURAL METRICS (16-23)
        features[16] = self.nesting_depth(request_data);
        features[17] = self.repetition_score(request_data);
        features[18] = self.token_diversity(request_data);
        features[19] = self.delimiter_density(request_data);
        features[20] = self.quote_balance(request_data);
        features[21] = self.bracket_balance(request_data);
        features[22] = self.consecutive_special_ratio(request_data);
        features[23] = self.word_length_variance(request_data);
        
        // ENCODING STATISTICS (24-27)
        features[24] = self.percent_encoding_density(request_data);
        features[25] = self.hex_sequence_density(request_data);
        features[26] = self.base64_likelihood(request_data);
        features[27] = self.non_ascii_ratio(bytes);
        
        // DERIVED FEATURES (28-31)
        features[28] = (features[4] * features[10]).min(1.0);
        features[29] = (features[0] * features[16]).min(1.0);
        features[30] = self.structural_anomaly_score(&features);
        features[31] = self.statistical_complexity(&features);
        
        features
    }

    fn avg_line_length(&self, s: &str) -> f32 {
        let lines: Vec<&str> = s.lines().collect();
        if lines.is_empty() { return 0.0; }
        let total: usize = lines.iter().map(|l| l.len()).sum();
        ((total as f32 / lines.len() as f32) / 200.0).min(1.0)
    }
    
    fn max_line_length(&self, s: &str) -> f32 {
        let max = s.lines().map(|l| l.len()).max().unwrap_or(0);
        (max as f32 / 500.0).min(1.0)
    }

    fn calculate_entropy(&self, bytes: &[u8]) -> f32 {
        if bytes.is_empty() { return 0.0; }
        let mut counts = [0u32; 256];
        for &b in bytes { counts[b as usize] += 1; }
        
        let len = bytes.len() as f32;
        let mut entropy = 0.0f32;
        for &count in &counts {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }
        (entropy / 8.0).min(1.0)
    }
    
    fn calculate_bigram_entropy(&self, s: &str) -> f32 {
        if s.len() < 2 { return 0.0; }
        let bytes = s.as_bytes();
        let mut bigram_counts: HashMap<(u8, u8), u32> = HashMap::new();
        
        for i in 0..bytes.len()-1 {
            *bigram_counts.entry((bytes[i], bytes[i+1])).or_insert(0) += 1;
        }
        
        let total = (bytes.len() - 1) as f32;
        let mut entropy = 0.0f32;
        for &count in bigram_counts.values() {
            let p = count as f32 / total;
            entropy -= p * p.log2();
        }
        (entropy / 16.0).min(1.0)
    }
    
    fn calculate_positional_entropy(&self, s: &str) -> f32 {
        if s.len() < 4 { return 0.0; }
        let chunk_size = s.len() / 4;
        let mut entropies = Vec::new();
        
        for i in 0..4 {
            let start = i * chunk_size;
            let end = if i == 3 { s.len() } else { (i + 1) * chunk_size };
            let chunk = &s.as_bytes()[start..end];
            entropies.push(self.calculate_entropy(chunk));
        }
        
        entropies.iter().sum::<f32>() / 4.0
    }
    
    fn calculate_entropy_variance(&self, s: &str) -> f32 {
        if s.len() < 20 { return 0.0; }
        let chunk_size = s.len() / 5;
        let mut entropies = Vec::new();
        
        for i in 0..5 {
            let start = i * chunk_size;
            let end = if i == 4 { s.len() } else { (i + 1) * chunk_size };
            let chunk = &s.as_bytes()[start..end];
            entropies.push(self.calculate_entropy(chunk));
        }
        
        let mean = entropies.iter().sum::<f32>() / 5.0;
        let variance = entropies.iter().map(|e| (e - mean).powi(2)).sum::<f32>() / 5.0;
        (variance * 10.0).min(1.0)
    }

    fn character_class_distribution(&self, s: &str) -> CharacterDistribution {
        if s.is_empty() { return CharacterDistribution::default(); }
        
        let len = s.len() as f32;
        let mut alpha = 0u32;
        let mut digit = 0u32;
        let mut special = 0u32;
        let mut whitespace = 0u32;
        let mut uppercase = 0u32;
        let mut printable = 0u32;
        let mut punctuation = 0u32;
        let mut unique_chars: HashSet<char> = HashSet::new();
        
        for c in s.chars() {
            unique_chars.insert(c);
            if c.is_alphabetic() { alpha += 1; }
            if c.is_numeric() { digit += 1; }
            if c.is_whitespace() { whitespace += 1; }
            if c.is_uppercase() { uppercase += 1; }
            if c.is_ascii_punctuation() { punctuation += 1; }
            if c.is_ascii_graphic() || c.is_whitespace() { printable += 1; }
            if !c.is_alphanumeric() && !c.is_whitespace() { special += 1; }
        }
        
        CharacterDistribution {
            alpha_ratio: alpha as f32 / len,
            digit_ratio: digit as f32 / len,
            special_ratio: special as f32 / len,
            whitespace_ratio: whitespace as f32 / len,
            uppercase_ratio: if alpha > 0 { uppercase as f32 / alpha as f32 } else { 0.0 },
            printable_ratio: printable as f32 / len,
            punctuation_ratio: punctuation as f32 / len,
            unique_char_ratio: (unique_chars.len() as f32 / len).min(1.0),
        }
    }

    fn nesting_depth(&self, s: &str) -> f32 {
        let mut max_depth = 0i32;
        let mut current_depth = 0i32;
        
        for c in s.chars() {
            match c {
                '(' | '[' | '{' | '<' => {
                    current_depth += 1;
                    max_depth = max_depth.max(current_depth);
                }
                ')' | ']' | '}' | '>' => {
                    current_depth = (current_depth - 1).max(0);
                }
                _ => {}
            }
        }
        (max_depth as f32 / 10.0).min(1.0)
    }
    
    fn repetition_score(&self, s: &str) -> f32 {
        if s.len() < 6 { return 0.0; }
        let mut repeat_count = 0;
        let bytes = s.as_bytes();
        
        for i in 0..bytes.len().saturating_sub(5) {
            let pattern = &bytes[i..i+3];
            if bytes[i+3..].windows(3).any(|w| w == pattern) {
                repeat_count += 1;
            }
        }
        (repeat_count as f32 / (s.len() as f32 / 3.0)).min(1.0)
    }
    
    fn token_diversity(&self, s: &str) -> f32 {
        let tokens: Vec<&str> = s.split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty()).collect();
        if tokens.is_empty() { return 0.0; }
        
        let unique: HashSet<&str> = tokens.iter().cloned().collect();
        unique.len() as f32 / tokens.len() as f32
    }
    
    fn delimiter_density(&self, s: &str) -> f32 {
        if s.is_empty() { return 0.0; }
        let delimiters = s.chars().filter(|&c| 
            c == '&' || c == '=' || c == '?' || c == ';' || c == ',' || c == '/'
        ).count();
        (delimiters as f32 / s.len() as f32 * 10.0).min(1.0)
    }
    
    fn quote_balance(&self, s: &str) -> f32 {
        let single = s.chars().filter(|&c| c == '\'').count();
        let double = s.chars().filter(|&c| c == '"').count();
        let single_balanced = single % 2 == 0;
        let double_balanced = double % 2 == 0;
        
        if single_balanced && double_balanced { 1.0 }
        else if single_balanced || double_balanced { 0.5 }
        else { 0.0 }
    }
    
    fn bracket_balance(&self, s: &str) -> f32 {
        let mut paren = 0i32;
        let mut square = 0i32;
        let mut curly = 0i32;
        
        for c in s.chars() {
            match c {
                '(' => paren += 1, ')' => paren -= 1,
                '[' => square += 1, ']' => square -= 1,
                '{' => curly += 1, '}' => curly -= 1,
                _ => {}
            }
        }
        
        let imbalance = paren.abs() + square.abs() + curly.abs();
        (1.0 - (imbalance as f32 / 10.0)).max(0.0)
    }
    
    fn consecutive_special_ratio(&self, s: &str) -> f32 {
        if s.len() < 2 { return 0.0; }
        let mut consecutive = 0;
        let mut prev_special = false;
        
        for c in s.chars() {
            let is_special = !c.is_alphanumeric() && !c.is_whitespace();
            if is_special && prev_special { consecutive += 1; }
            prev_special = is_special;
        }
        (consecutive as f32 / s.len() as f32 * 5.0).min(1.0)
    }
    
    fn word_length_variance(&self, s: &str) -> f32 {
        let words: Vec<&str> = s.split_whitespace().collect();
        if words.len() < 2 { return 0.0; }
        
        let lengths: Vec<f32> = words.iter().map(|w| w.len() as f32).collect();
        let mean = lengths.iter().sum::<f32>() / lengths.len() as f32;
        let variance = lengths.iter().map(|l| (l - mean).powi(2)).sum::<f32>() / lengths.len() as f32;
        (variance / 50.0).min(1.0)
    }

    fn percent_encoding_density(&self, s: &str) -> f32 {
        let percent_count = s.matches('%').count();
        (percent_count as f32 / (s.len() as f32 + 1.0) * 10.0).min(1.0)
    }
    
    fn hex_sequence_density(&self, s: &str) -> f32 {
        let hex_patterns = s.matches("0x").count() + s.matches("\\x").count();
        (hex_patterns as f32 / (s.len() as f32 / 10.0 + 1.0)).min(1.0)
    }
    
    fn base64_likelihood(&self, s: &str) -> f32 {
        if s.len() < 8 { return 0.0; }
        
        let base64_chars = s.chars().filter(|c| 
            c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '='
        ).count();
        
        let ratio = base64_chars as f32 / s.len() as f32;
        let has_padding = s.ends_with('=') || s.ends_with("==");
        let proper_length = s.len() % 4 == 0;
        
        let mut score = ratio * 0.5;
        if has_padding { score += 0.25; }
        if proper_length { score += 0.25; }
        score.min(1.0)
    }
    
    fn non_ascii_ratio(&self, bytes: &[u8]) -> f32 {
        if bytes.is_empty() { return 0.0; }
        let non_ascii = bytes.iter().filter(|&&b| b > 127).count();
        (non_ascii as f32 / bytes.len() as f32).min(1.0)
    }

    fn structural_anomaly_score(&self, features: &[f32]) -> f32 {
        let nesting = features[16];
        let imbalance = 1.0 - features[21];
        let consecutive_special = features[22];
        ((nesting + imbalance + consecutive_special) / 3.0).min(1.0)
    }
    
    fn statistical_complexity(&self, features: &[f32]) -> f32 {
        let entropy_complexity = features[4] * 0.3;
        let structural_complexity = features[16] * 0.2;
        let char_diversity = features[15] * 0.2;
        let encoding_density = (features[24] + features[25]) * 0.15;
        let length_factor = features[0] * 0.15;
        (entropy_complexity + structural_complexity + char_diversity + encoding_density + length_factor).min(1.0)
    }
}

impl Default for AdvancedFeatureExtractor {
    fn default() -> Self { Self::new() }
}
