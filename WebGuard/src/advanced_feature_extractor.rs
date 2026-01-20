#![allow(dead_code)]

use regex::Regex;

/// Advanced feature extraction for sophisticated threat detection
#[derive(Debug)]
pub struct AdvancedFeatureExtractor {
    sql_patterns: Vec<Regex>,
    xss_patterns: Vec<Regex>,
    path_traversal_patterns: Vec<Regex>,
    command_injection_patterns: Vec<Regex>,
}

impl AdvancedFeatureExtractor {
    pub fn new() -> Self {
        Self {
            sql_patterns: Self::build_sql_patterns(),
            xss_patterns: Self::build_xss_patterns(),
            path_traversal_patterns: Self::build_path_traversal_patterns(),
            command_injection_patterns: Self::build_command_injection_patterns(),
        }
    }

    /// Extract comprehensive features for threat detection
    pub fn extract_features(&self, request_data: &str) -> [f32; 32] {
        let mut features = [0.0; 32];
        
        // Normalize input for analysis
        let normalized = request_data.to_lowercase();
        let decoded = self.decode_common_encodings(request_data);
        
        // Feature 0: Request length (normalized)
        features[0] = (request_data.len() as f32 / 1000.0).min(1.0);
        
        // Features 1-5: SQL Injection Detection
        features[1] = self.detect_sql_injection_basic(&normalized);
        features[2] = self.detect_sql_injection_advanced(&decoded);
        features[3] = self.detect_sql_union_attacks(&normalized);
        features[4] = self.detect_sql_blind_injection(&normalized);
        features[5] = self.detect_sql_time_based(&normalized);
        
        // Features 6-10: XSS Detection
        features[6] = self.detect_xss_basic(&normalized);
        features[7] = self.detect_xss_advanced(&decoded);
        features[8] = self.detect_xss_event_handlers(&normalized);
        features[9] = self.detect_xss_encoded(&request_data);
        features[10] = self.detect_dom_xss(&normalized);
        
        // Features 11-15: Path Traversal & File Inclusion
        features[11] = self.detect_path_traversal(&normalized);
        features[12] = self.detect_file_inclusion(&normalized);
        features[13] = self.detect_directory_listing(&normalized);
        features[14] = self.detect_file_upload_bypass(&normalized);
        features[15] = self.detect_null_byte_injection(&request_data);
        
        // Features 16-20: Command Injection
        features[16] = self.detect_command_injection(&normalized);
        features[17] = self.detect_shell_metacharacters(&request_data);
        features[18] = self.detect_system_commands(&normalized);
        features[19] = self.detect_powershell_commands(&normalized);
        features[20] = self.detect_bash_commands(&normalized);
        
        // Features 21-25: Encoding & Obfuscation
        features[21] = self.detect_url_encoding(&request_data);
        features[22] = self.detect_hex_encoding(&request_data);
        features[23] = self.detect_base64_encoding(&request_data);
        features[24] = self.detect_unicode_encoding(&request_data);
        features[25] = self.detect_double_encoding(&request_data);
        
        // Features 26-30: Statistical Analysis
        features[26] = self.calculate_entropy(&request_data.as_bytes());
        features[27] = self.calculate_character_diversity(request_data);
        features[28] = self.calculate_suspicious_ratio(request_data);
        features[29] = self.detect_legitimate_patterns(request_data);
        features[30] = self.calculate_payload_complexity(request_data);
        
        // Feature 31: Overall threat score
        features[31] = self.calculate_composite_threat_score(&features[0..31]);
        
        features
    }

    fn build_sql_patterns() -> Vec<Regex> {
        vec![
            Regex::new(r"(?i)\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b").unwrap(),
            Regex::new(r"(?i)\b(or|and)\s+\d+\s*=\s*\d+").unwrap(),
            Regex::new(r"(?i)'.*?(\bor\b|\band\b).*?'").unwrap(),
            Regex::new(r"(?i)\b(waitfor|delay|sleep|benchmark)\b").unwrap(),
            Regex::new(r"(?i)\b(information_schema|sysobjects|syscolumns)\b").unwrap(),
            Regex::new(r"(?i)(\bxp_|\bsp_)").unwrap(),
            Regex::new(r"(?i)\b(load_file|into\s+outfile|into\s+dumpfile)\b").unwrap(),
        ]
    }

    fn build_xss_patterns() -> Vec<Regex> {
        vec![
            Regex::new(r"(?i)<script[^>]*>").unwrap(),
            Regex::new(r"(?i)javascript:").unwrap(),
            Regex::new(r"(?i)on\w+\s*=").unwrap(),
            Regex::new(r"(?i)<iframe[^>]*>").unwrap(),
            Regex::new(r"(?i)<object[^>]*>").unwrap(),
            Regex::new(r"(?i)<embed[^>]*>").unwrap(),
            Regex::new(r"(?i)expression\s*\(").unwrap(),
            Regex::new(r"(?i)vbscript:").unwrap(),
        ]
    }

    fn build_path_traversal_patterns() -> Vec<Regex> {
        vec![
            Regex::new(r"\.\.[\\/]").unwrap(),
            Regex::new(r"(?i)[\\/]etc[\\/]passwd").unwrap(),
            Regex::new(r"(?i)[\\/]windows[\\/]system32").unwrap(),
            Regex::new(r"(?i)[\\/]boot\.ini").unwrap(),
            Regex::new(r"%2e%2e%2f").unwrap(),
            Regex::new(r"(?i)file://").unwrap(),
        ]
    }

    fn build_command_injection_patterns() -> Vec<Regex> {
        vec![
            Regex::new(r"[;&|`$()]").unwrap(),
            Regex::new(r"(?i)\b(cat|ls|dir|type|echo|whoami|id|pwd|uname)\b").unwrap(),
            Regex::new(r"(?i)\b(wget|curl|nc|netcat|telnet|ssh)\b").unwrap(),
            Regex::new(r"(?i)\b(powershell|cmd|bash|sh|zsh)\b").unwrap(),
        ]
    }

    // SQL Injection Detection Methods
    fn detect_sql_injection_basic(&self, input: &str) -> f32 {
        let mut score: f32 = 0.0;
        
        // Check for basic SQL injection patterns
        if input.contains("' or '1'='1") || input.contains("\" or \"1\"=\"1") {
            score += 0.9;
        }
        
        if input.contains("' or 1=1") || input.contains("\" or 1=1") {
            score += 0.8;
        }
        
        // Check for SQL keywords with quotes
        for pattern in &self.sql_patterns[0..3] {
            if pattern.is_match(input) {
                score += 0.3;
            }
        }
        
        score.min(1.0)
    }

    fn detect_sql_injection_advanced(&self, input: &str) -> f32 {
        let mut score: f32 = 0.0;
        
        // Advanced SQL injection patterns
        for pattern in &self.sql_patterns {
            if pattern.is_match(input) {
                score += 0.2;
            }
        }
        
        // Check for SQL functions and system tables
        if input.contains("information_schema") || input.contains("sysobjects") {
            score += 0.4;
        }
        
        // Check for SQL comments
        if input.contains("--") || input.contains("/*") || input.contains("#") {
            score += 0.2;
        }
        
        score.min(1.0)
    }

    fn detect_sql_union_attacks(&self, input: &str) -> f32 {
        if input.contains("union") && (input.contains("select") || input.contains("all")) {
            0.9
        } else {
            0.0
        }
    }

    fn detect_sql_blind_injection(&self, input: &str) -> f32 {
        let mut score: f32 = 0.0;
        
        // Blind SQL injection patterns
        if input.contains("and") && input.contains("substring") {
            score += 0.6;
        }
        
        if input.contains("ascii") && input.contains("substr") {
            score += 0.7;
        }
        
        if input.contains("length") && input.contains("database") {
            score += 0.5;
        }
        
        score.min(1.0)
    }

    fn detect_sql_time_based(&self, input: &str) -> f32 {
        if input.contains("waitfor") || input.contains("delay") || 
           input.contains("sleep") || input.contains("benchmark") {
            0.8
        } else {
            0.0
        }
    }

    // XSS Detection Methods
    fn detect_xss_basic(&self, input: &str) -> f32 {
        let mut score: f32 = 0.0;
        
        for pattern in &self.xss_patterns {
            if pattern.is_match(input) {
                score += 0.3;
            }
        }
        
        score.min(1.0)
    }

    fn detect_xss_advanced(&self, input: &str) -> f32 {
        let mut score: f32 = 0.0;
        
        // Check for advanced XSS patterns
        if input.contains("javascript:") || input.contains("vbscript:") {
            score += 0.8;
        }
        
        if input.contains("expression(") {
            score += 0.7;
        }
        
        // Check for data URIs
        if input.contains("data:") && (input.contains("javascript") || input.contains("base64")) {
            score += 0.6;
        }
        
        score.min(1.0)
    }

    fn detect_xss_event_handlers(&self, input: &str) -> f32 {
        let events = ["onload", "onclick", "onmouseover", "onerror", "onsubmit", "onfocus"];
        let mut score: f32 = 0.0;
        
        for event in &events {
            if input.contains(event) {
                score += 0.2;
            }
        }
        
        score.min(1.0)
    }

    fn detect_xss_encoded(&self, input: &str) -> f32 {
        // Check for encoded XSS attempts
        if input.contains("%3Cscript") || input.contains("&lt;script") {
            0.8
        } else if input.contains("&#x") && input.contains("script") {
            0.7
        } else {
            0.0
        }
    }

    fn detect_dom_xss(&self, input: &str) -> f32 {
        let dom_sinks = ["innerHTML", "outerHTML", "document.write", "eval", "setTimeout"];
        let mut score: f32 = 0.0;
        
        for sink in &dom_sinks {
            if input.contains(sink) {
                score += 0.3;
            }
        }
        
        score.min(1.0)
    }

    // Path Traversal Detection Methods
    fn detect_path_traversal(&self, input: &str) -> f32 {
        let mut score: f32 = 0.0;
        
        for pattern in &self.path_traversal_patterns {
            if pattern.is_match(input) {
                score += 0.3;
            }
        }
        
        score.min(1.0)
    }

    fn detect_file_inclusion(&self, input: &str) -> f32 {
        if input.contains("include") || input.contains("require") {
            if input.contains("http://") || input.contains("https://") || input.contains("ftp://") {
                0.9
            } else {
                0.4
            }
        } else {
            0.0
        }
    }

    fn detect_directory_listing(&self, input: &str) -> f32 {
        if input.contains("/etc/") || input.contains("/var/") || input.contains("/usr/") ||
           input.contains("c:\\") || input.contains("\\windows\\") {
            0.6
        } else {
            0.0
        }
    }

    fn detect_file_upload_bypass(&self, input: &str) -> f32 {
        if input.contains(".php") || input.contains(".asp") || input.contains(".jsp") {
            if input.contains("null") || input.contains("%00") {
                0.8
            } else {
                0.3
            }
        } else {
            0.0
        }
    }

    fn detect_null_byte_injection(&self, input: &str) -> f32 {
        if input.contains("%00") || input.contains("\\0") || input.contains("\0") {
            0.9
        } else {
            0.0
        }
    }

    // Command Injection Detection Methods
    fn detect_command_injection(&self, input: &str) -> f32 {
        let mut score: f32 = 0.0;
        
        for pattern in &self.command_injection_patterns {
            if pattern.is_match(input) {
                score += 0.2;
            }
        }
        
        score.min(1.0)
    }

    fn detect_shell_metacharacters(&self, input: &str) -> f32 {
        let metacharacters = [';', '|', '&', '`', '$', '(', ')', '{', '}'];
        let count = metacharacters.iter().filter(|&&c| input.contains(c)).count();
        (count as f32 / metacharacters.len() as f32).min(1.0)
    }

    fn detect_system_commands(&self, input: &str) -> f32 {
        let commands = ["cat", "ls", "dir", "type", "echo", "whoami", "id", "pwd", "uname"];
        let mut score: f32 = 0.0;
        
        for cmd in &commands {
            if input.contains(cmd) {
                score += 0.1;
            }
        }
        
        score.min(1.0)
    }

    fn detect_powershell_commands(&self, input: &str) -> f32 {
        if input.contains("powershell") || input.contains("invoke-expression") || 
           input.contains("iex") || input.contains("get-process") {
            0.8
        } else {
            0.0
        }
    }

    fn detect_bash_commands(&self, input: &str) -> f32 {
        if input.contains("/bin/bash") || input.contains("/bin/sh") || 
           input.contains("bash -c") || input.contains("sh -c") {
            0.8
        } else {
            0.0
        }
    }

    // Encoding Detection Methods
    fn detect_url_encoding(&self, input: &str) -> f32 {
        let url_encoded_count = input.matches('%').count();
        (url_encoded_count as f32 / 10.0).min(1.0)
    }

    fn detect_hex_encoding(&self, input: &str) -> f32 {
        let hex_count = input.matches("\\x").count();
        (hex_count as f32 / 5.0).min(1.0)
    }

    fn detect_base64_encoding(&self, input: &str) -> f32 {
        // Simple base64 detection heuristic
        let base64_chars = input.chars().filter(|c| c.is_alphanumeric() || *c == '+' || *c == '/' || *c == '=').count();
        if base64_chars > input.len() * 3 / 4 && input.len() > 10 {
            0.7
        } else {
            0.0
        }
    }

    fn detect_unicode_encoding(&self, input: &str) -> f32 {
        let unicode_count = input.matches("\\u").count() + input.matches("&#").count();
        (unicode_count as f32 / 5.0).min(1.0)
    }

    fn detect_double_encoding(&self, input: &str) -> f32 {
        if input.contains("%25") {
            0.8
        } else {
            0.0
        }
    }

    // Statistical Analysis Methods
    fn calculate_entropy(&self, data: &[u8]) -> f32 {
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        let len = data.len() as f32;
        let mut entropy = 0.0;
        
        for &count in &counts {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }
        
        (entropy / 8.0).min(1.0)
    }

    fn calculate_character_diversity(&self, input: &str) -> f32 {
        let unique_chars: std::collections::HashSet<char> = input.chars().collect();
        (unique_chars.len() as f32 / input.len() as f32).min(1.0)
    }

    fn calculate_suspicious_ratio(&self, input: &str) -> f32 {
        let suspicious_chars = ['<', '>', '\'', '"', ';', '|', '&', '`', '$'];
        let suspicious_count = input.chars().filter(|c| suspicious_chars.contains(c)).count();
        (suspicious_count as f32 / input.len() as f32).min(1.0)
    }

    fn detect_legitimate_patterns(&self, input: &str) -> f32 {
        let mut score: f32 = 0.0;
        
        // HTTP methods
        if input.contains("GET") || input.contains("POST") || input.contains("PUT") || input.contains("DELETE") {
            score += 0.3;
        }
        
        // HTTP headers
        if input.contains("HTTP/1.1") || input.contains("Content-Type") || input.contains("User-Agent") {
            score += 0.2;
        }
        
        // Common legitimate paths
        if input.contains("/api/") || input.contains("/static/") || input.contains("/assets/") {
            score += 0.2;
        }
        
        // JSON/XML patterns
        if (input.contains("{") && input.contains("}")) || (input.contains("<") && input.contains(">") && !input.contains("script")) {
            score += 0.1;
        }
        
        score.min(1.0)
    }

    fn calculate_payload_complexity(&self, input: &str) -> f32 {
        let mut complexity = 0.0;
        
        // Length factor
        complexity += (input.len() as f32 / 1000.0).min(0.3);
        
        // Special character density
        let special_chars = input.chars().filter(|c| !c.is_alphanumeric() && !c.is_whitespace()).count();
        complexity += (special_chars as f32 / input.len() as f32).min(0.4);
        
        // Nested structures
        let nesting_score = (input.matches('(').count() + input.matches('[').count() + input.matches('{').count()) as f32;
        complexity += (nesting_score / 10.0).min(0.3);
        
        complexity.min(1.0)
    }

    fn calculate_composite_threat_score(&self, features: &[f32]) -> f32 {
        // Use maximum-based scoring to avoid diluting strong signals
        let sql_score = features[1..6].iter().fold(0.0f32, |acc, &x| acc.max(x));
        let xss_score = features[6..11].iter().fold(0.0f32, |acc, &x| acc.max(x));
        let path_score = features[11..16].iter().fold(0.0f32, |acc, &x| acc.max(x));
        let cmd_score = features[16..21].iter().fold(0.0f32, |acc, &x| acc.max(x));
        let encoding_score = features[21..26].iter().fold(0.0f32, |acc, &x| acc.max(x));
        
        // Take the maximum threat score across categories, with slight boost for multiple categories
        let max_category_score = sql_score.max(xss_score).max(path_score).max(cmd_score).max(encoding_score);
        
        // Add small bonus for multiple threat types detected
        let category_count = [sql_score, xss_score, path_score, cmd_score, encoding_score]
            .iter()
            .filter(|&&score| score > 0.1)
            .count() as f32;
        
        let multi_threat_bonus = if category_count > 1.0 { 0.1 * (category_count - 1.0) } else { 0.0 };
        
        (max_category_score + multi_threat_bonus).min(1.0)
    }

    fn decode_common_encodings(&self, input: &str) -> String {
        let mut decoded = input.to_string();
        
        // URL decode
        decoded = urlencoding::decode(&decoded).unwrap_or_else(|_| std::borrow::Cow::Borrowed(&decoded)).to_string();
        
        // HTML entity decode (basic)
        decoded = decoded.replace("&lt;", "<")
                        .replace("&gt;", ">")
                        .replace("&amp;", "&")
                        .replace("&quot;", "\"")
                        .replace("&#x27;", "'")
                        .replace("&#x2F;", "/");
        
        decoded
    }
}

impl Default for AdvancedFeatureExtractor {
    fn default() -> Self {
        Self::new()
    }
}