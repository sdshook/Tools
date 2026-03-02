//! # Semantic Normalizer: Deterministic Pre-Processing for Harvard Architecture
//!
//! This module provides **deterministic semantic normalization** as a pre-processing
//! stage before N-gram embedding. It solves the obfuscation problem without violating
//! Harvard architecture principles.
//!
//! ## The Obfuscation Problem
//!
//! Attackers use encoding and syntax variations to evade pattern detection:
//!
//! ```text
//! All of these are semantically identical:
//!   ' OR 1=1--
//!   %27%20OR%201%3D1--
//!   &#x27; OR 1=1--
//!   '/**/OR/**/1=1--
//!   ' oR 1=1--
//! ```
//!
//! Without normalization, each variant appears as a completely different pattern
//! to the N-gram embedding system.
//!
//! ## The Solution: Deterministic Normalization
//!
//! Unlike a GPT (which would introduce stochasticity and pre-trained knowledge),
//! this normalizer is:
//!
//! - **100% Deterministic**: Same input → same output, always
//! - **Pure Function**: No side effects, no hidden state
//! - **No Pre-trained Attack Knowledge**: Just decoding rules, not attack signatures
//! - **Harvard Compliant**: Operates purely in the semantic layer
//!
//! ## Processing Pipeline
//!
//! ```text
//! Raw Bytes
//!     │
//!     ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │  LAYER 1: Multi-Encoding Decode                             │
//! │  • URL decode (%XX → char)                                  │
//! │  • HTML entity decode (&lt; → <, &#x27; → ')                │
//! │  • Unicode escape decode (\uXXXX → char)                    │
//! │  • Hex decode (\xXX → char)                                 │
//! │  • Iterative until stable (handles double-encoding)         │
//! └─────────────────────────────────────────────────────────────┘
//!     │
//!     ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │  LAYER 2: Syntax Normalization                              │
//! │  • Collapse whitespace (multiple spaces → single)           │
//! │  • Normalize line endings                                   │
//! │  • Remove null bytes                                        │
//! │  • Normalize quotes (" ' ` → canonical forms)               │
//! └─────────────────────────────────────────────────────────────┘
//!     │
//!     ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │  LAYER 3: Case Normalization (Context-Aware)                │
//! │  • SQL keywords → lowercase                                 │
//! │  • HTML tags → lowercase                                    │
//! │  • Preserve case in string literals                         │
//! └─────────────────────────────────────────────────────────────┘
//!     │
//!     ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │  LAYER 4: Canonical Tokenization                            │
//! │  • Split on semantic boundaries                             │
//! │  • Produce CanonicalToken stream                            │
//! │  • Ready for N-gram embedding                               │
//! └─────────────────────────────────────────────────────────────┘
//!     │
//!     ▼
//! Canonical Tokens → N-gram Embedding → SemanticVerdict
//! ```
//!
//! ## Harvard Architecture Compliance
//!
//! This normalizer operates **entirely within the Semantic Layer**:
//!
//! - **Input**: Raw bytes (untrusted)
//! - **Output**: Canonical tokens (semantic representation)
//! - **Cannot**: Trigger any system actions
//! - **Cannot**: Execute or interpret as code
//! - **Is**: A pure transformation function

use std::collections::HashMap;

/// Maximum iterations for decode loops (prevents infinite loops on malformed input)
const MAX_DECODE_ITERATIONS: usize = 10;

/// Maximum input size to process (prevents DoS)
const MAX_INPUT_SIZE: usize = 1_000_000;

/// A canonical token representing normalized semantic content
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CanonicalToken {
    /// Alphanumeric word (lowercase normalized)
    Word(String),
    /// Numeric literal
    Number(String),
    /// String literal (content preserved)
    StringLiteral(String),
    /// Operator or punctuation
    Operator(char),
    /// Whitespace (normalized to single space)
    Space,
    /// Unknown/binary content (hex encoded)
    Binary(Vec<u8>),
}

/// Deterministic Semantic Normalizer
/// 
/// # Harvard Architecture Invariants
/// 
/// 1. **Pure Function**: `normalize()` has no side effects
/// 2. **Deterministic**: Same input always produces same output
/// 3. **No Execution**: Transforms syntax, never interprets as code
/// 4. **No Pre-trained Knowledge**: Uses decoding rules, not attack signatures
#[derive(Debug, Clone)]
pub struct SemanticNormalizer {
    /// HTML entity mappings
    html_entities: HashMap<String, char>,
    /// Common SQL keywords for case normalization
    sql_keywords: Vec<&'static str>,
    /// Common HTML tags for case normalization
    html_tags: Vec<&'static str>,
}

impl SemanticNormalizer {
    /// Create a new semantic normalizer
    pub fn new() -> Self {
        Self {
            html_entities: Self::build_html_entities(),
            sql_keywords: Self::build_sql_keywords(),
            html_tags: Self::build_html_tags(),
        }
    }

    /// Normalize raw input to canonical form
    /// 
    /// # Invariants
    /// - Deterministic: same input → same output
    /// - Pure: no side effects
    /// - Bounded: O(n) time complexity with iteration limits
    /// 
    /// # Returns
    /// Canonical byte string ready for N-gram embedding
    pub fn normalize(&self, raw: &[u8]) -> Vec<u8> {
        // Enforce size limit
        let input = if raw.len() > MAX_INPUT_SIZE {
            &raw[..MAX_INPUT_SIZE]
        } else {
            raw
        };

        // Convert to string (lossy for binary)
        let mut text = String::from_utf8_lossy(input).into_owned();

        // Layer 1: Multi-encoding decode (iterative until stable)
        text = self.decode_all_encodings(&text);

        // Layer 2: Syntax normalization
        text = self.normalize_syntax(&text);

        // Layer 3: Case normalization
        text = self.normalize_case(&text);

        text.into_bytes()
    }

    /// Normalize and tokenize for detailed analysis
    pub fn normalize_to_tokens(&self, raw: &[u8]) -> Vec<CanonicalToken> {
        let normalized = self.normalize(raw);
        self.tokenize(&normalized)
    }

    /// Decode all encoding layers iteratively until stable
    fn decode_all_encodings(&self, input: &str) -> String {
        let mut current = input.to_string();
        
        for _ in 0..MAX_DECODE_ITERATIONS {
            let decoded = self.decode_single_pass(&current);
            if decoded == current {
                break; // Stable - no more decoding needed
            }
            current = decoded;
        }
        
        current
    }

    /// Single pass of all decodings
    fn decode_single_pass(&self, input: &str) -> String {
        let mut result = input.to_string();
        
        // URL decode
        result = self.url_decode(&result);
        
        // HTML entity decode
        result = self.html_decode(&result);
        
        // Unicode escape decode
        result = self.unicode_decode(&result);
        
        // Hex escape decode
        result = self.hex_decode(&result);
        
        result
    }

    /// URL decode (%XX → char)
    fn url_decode(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();
        
        while let Some(c) = chars.next() {
            if c == '%' {
                // Try to read two hex digits
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() == 2 {
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        if byte.is_ascii() && !byte.is_ascii_control() {
                            result.push(byte as char);
                            continue;
                        }
                    }
                }
                // Failed to decode - keep original
                result.push('%');
                result.push_str(&hex);
            } else if c == '+' {
                // Plus sign often means space in URL encoding
                result.push(' ');
            } else {
                result.push(c);
            }
        }
        
        result
    }

    /// HTML entity decode (&name; or &#num; or &#xhex;)
    fn html_decode(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();
        
        while let Some(c) = chars.next() {
            if c == '&' {
                let mut entity = String::new();
                let mut found_semicolon = false;
                
                // Collect until semicolon or max length
                for _ in 0..10 {
                    if let Some(&next) = chars.peek() {
                        if next == ';' {
                            chars.next();
                            found_semicolon = true;
                            break;
                        } else if next.is_alphanumeric() || next == '#' {
                            entity.push(chars.next().unwrap());
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                
                if found_semicolon {
                    if let Some(decoded) = self.decode_html_entity(&entity) {
                        result.push(decoded);
                        continue;
                    }
                }
                
                // Failed to decode - keep original
                result.push('&');
                result.push_str(&entity);
                if found_semicolon {
                    result.push(';');
                }
            } else {
                result.push(c);
            }
        }
        
        result
    }

    /// Decode a single HTML entity
    fn decode_html_entity(&self, entity: &str) -> Option<char> {
        // Numeric entity
        if entity.starts_with('#') {
            let num_str = &entity[1..];
            let value = if num_str.starts_with('x') || num_str.starts_with('X') {
                u32::from_str_radix(&num_str[1..], 16).ok()?
            } else {
                num_str.parse::<u32>().ok()?
            };
            return char::from_u32(value);
        }
        
        // Named entity
        self.html_entities.get(entity).copied()
    }

    /// Unicode escape decode (\uXXXX)
    fn unicode_decode(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();
        
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    if next == 'u' || next == 'U' {
                        chars.next();
                        let hex: String = chars.by_ref().take(4).collect();
                        if hex.len() == 4 {
                            if let Ok(value) = u32::from_str_radix(&hex, 16) {
                                if let Some(decoded) = char::from_u32(value) {
                                    result.push(decoded);
                                    continue;
                                }
                            }
                        }
                        // Failed - keep original
                        result.push('\\');
                        result.push(next);
                        result.push_str(&hex);
                        continue;
                    }
                }
            }
            result.push(c);
        }
        
        result
    }

    /// Hex escape decode (\xXX)
    fn hex_decode(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();
        
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    if next == 'x' || next == 'X' {
                        chars.next();
                        let hex: String = chars.by_ref().take(2).collect();
                        if hex.len() == 2 {
                            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                                if byte.is_ascii() && !byte.is_ascii_control() {
                                    result.push(byte as char);
                                    continue;
                                }
                            }
                        }
                        // Failed - keep original
                        result.push('\\');
                        result.push(next);
                        result.push_str(&hex);
                        continue;
                    }
                }
            }
            result.push(c);
        }
        
        result
    }

    /// Normalize syntax (whitespace, quotes, control chars)
    fn normalize_syntax(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut last_was_space = false;
        
        for c in input.chars() {
            // Skip null bytes and most control characters
            if c == '\0' || (c.is_control() && c != '\n' && c != '\t') {
                continue;
            }
            
            // Normalize whitespace
            if c.is_whitespace() {
                if !last_was_space {
                    result.push(' ');
                    last_was_space = true;
                }
                continue;
            }
            
            last_was_space = false;
            
            // Normalize quotes to canonical forms
            // Unicode curly quotes: U+2018, U+2019, U+201B, U+201C, U+201D, U+201F
            // Dashes: U+2013 (en-dash), U+2014 (em-dash)
            match c {
                '\'' | '`' | '\u{2018}' | '\u{2019}' | '\u{201B}' => result.push('\''),
                '"' | '\u{201C}' | '\u{201D}' | '\u{201F}' => result.push('"'),
                '\u{2013}' | '\u{2014}' => result.push('-'),
                _ => result.push(c),
            }
        }
        
        result.trim().to_string()
    }

    /// Context-aware case normalization
    fn normalize_case(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let lower = input.to_lowercase();
        let mut i = 0;
        let chars: Vec<char> = input.chars().collect();
        let lower_chars: Vec<char> = lower.chars().collect();
        
        while i < chars.len() {
            // Check for SQL keywords
            let mut matched_keyword = false;
            for keyword in &self.sql_keywords {
                if self.matches_word_at(&lower, i, keyword) {
                    result.push_str(keyword);
                    i += keyword.len();
                    matched_keyword = true;
                    break;
                }
            }
            if matched_keyword {
                continue;
            }
            
            // Check for HTML tags
            if chars[i] == '<' {
                for tag in &self.html_tags {
                    if self.matches_tag_at(&lower, i, tag) {
                        // Normalize the tag
                        result.push('<');
                        i += 1;
                        if i < chars.len() && chars[i] == '/' {
                            result.push('/');
                            i += 1;
                        }
                        result.push_str(tag);
                        i += tag.len();
                        matched_keyword = true;
                        break;
                    }
                }
                if matched_keyword {
                    continue;
                }
            }
            
            // Default: preserve original case
            result.push(chars[i]);
            i += 1;
        }
        
        result
    }

    /// Check if a word matches at position (word boundary aware)
    fn matches_word_at(&self, text: &str, pos: usize, word: &str) -> bool {
        if pos + word.len() > text.len() {
            return false;
        }
        
        // Check word matches
        if &text[pos..pos + word.len()] != word {
            return false;
        }
        
        // Check word boundaries
        let before_ok = pos == 0 || !text.chars().nth(pos - 1).unwrap().is_alphanumeric();
        let after_ok = pos + word.len() == text.len() 
            || !text.chars().nth(pos + word.len()).unwrap().is_alphanumeric();
        
        before_ok && after_ok
    }

    /// Check if an HTML tag matches at position
    fn matches_tag_at(&self, text: &str, pos: usize, tag: &str) -> bool {
        if pos >= text.len() || text.chars().nth(pos) != Some('<') {
            return false;
        }
        
        let rest = &text[pos + 1..];
        let rest = rest.trim_start_matches('/');
        
        rest.starts_with(tag) && 
            (rest.len() == tag.len() || 
             !rest.chars().nth(tag.len()).unwrap().is_alphanumeric())
    }

    /// Tokenize normalized content
    fn tokenize(&self, normalized: &[u8]) -> Vec<CanonicalToken> {
        let text = String::from_utf8_lossy(normalized);
        let mut tokens = Vec::new();
        let mut current_word = String::new();
        let mut in_string = false;
        let mut string_char = '"';
        let mut string_content = String::new();
        
        for c in text.chars() {
            if in_string {
                if c == string_char {
                    tokens.push(CanonicalToken::StringLiteral(string_content.clone()));
                    string_content.clear();
                    in_string = false;
                } else {
                    string_content.push(c);
                }
                continue;
            }
            
            if c == '"' || c == '\'' {
                // Flush current word
                if !current_word.is_empty() {
                    tokens.push(self.classify_word(&current_word));
                    current_word.clear();
                }
                in_string = true;
                string_char = c;
                continue;
            }
            
            if c.is_alphanumeric() || c == '_' {
                current_word.push(c);
            } else {
                // Flush current word
                if !current_word.is_empty() {
                    tokens.push(self.classify_word(&current_word));
                    current_word.clear();
                }
                
                if c.is_whitespace() {
                    if tokens.last() != Some(&CanonicalToken::Space) {
                        tokens.push(CanonicalToken::Space);
                    }
                } else {
                    tokens.push(CanonicalToken::Operator(c));
                }
            }
        }
        
        // Flush remaining
        if !current_word.is_empty() {
            tokens.push(self.classify_word(&current_word));
        }
        if in_string && !string_content.is_empty() {
            tokens.push(CanonicalToken::StringLiteral(string_content));
        }
        
        tokens
    }

    /// Classify a word token
    fn classify_word(&self, word: &str) -> CanonicalToken {
        if word.chars().all(|c| c.is_numeric() || c == '.') {
            CanonicalToken::Number(word.to_string())
        } else {
            CanonicalToken::Word(word.to_lowercase())
        }
    }

    /// Build HTML entity map
    fn build_html_entities() -> HashMap<String, char> {
        let mut map = HashMap::new();
        // Common HTML entities
        map.insert("lt".to_string(), '<');
        map.insert("gt".to_string(), '>');
        map.insert("amp".to_string(), '&');
        map.insert("quot".to_string(), '"');
        map.insert("apos".to_string(), '\'');
        map.insert("nbsp".to_string(), ' ');
        map.insert("tab".to_string(), '\t');
        map.insert("newline".to_string(), '\n');
        // Extended entities
        map.insert("copy".to_string(), '©');
        map.insert("reg".to_string(), '®');
        map.insert("trade".to_string(), '™');
        map.insert("ndash".to_string(), '–');
        map.insert("mdash".to_string(), '—');
        map.insert("lsquo".to_string(), '\'');
        map.insert("rsquo".to_string(), '\'');
        map.insert("ldquo".to_string(), '"');
        map.insert("rdquo".to_string(), '"');
        map
    }

    /// Build SQL keyword list for case normalization
    fn build_sql_keywords() -> Vec<&'static str> {
        vec![
            "select", "from", "where", "and", "or", "not", "in", "like",
            "insert", "into", "values", "update", "set", "delete",
            "drop", "create", "alter", "table", "database", "index",
            "union", "all", "join", "left", "right", "inner", "outer",
            "order", "by", "group", "having", "limit", "offset",
            "null", "true", "false", "is", "as", "on", "between",
            "exists", "case", "when", "then", "else", "end",
            "exec", "execute", "declare", "cast", "convert",
            "waitfor", "delay", "sleep", "benchmark",
        ]
    }

    /// Build HTML tag list for case normalization
    fn build_html_tags() -> Vec<&'static str> {
        vec![
            "script", "style", "iframe", "object", "embed", "form",
            "input", "button", "a", "img", "link", "meta", "base",
            "body", "head", "html", "div", "span", "p", "br", "hr",
            "table", "tr", "td", "th", "thead", "tbody",
            "svg", "math", "video", "audio", "canvas",
            "onload", "onerror", "onclick", "onmouseover",
        ]
    }
}

impl Default for SemanticNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode() {
        let normalizer = SemanticNormalizer::new();
        
        // Basic URL decoding
        let input = b"%27%20OR%201%3D1--";
        let output = normalizer.normalize(input);
        assert_eq!(String::from_utf8_lossy(&output), "' or 1=1--");
    }

    #[test]
    fn test_html_decode() {
        let normalizer = SemanticNormalizer::new();
        
        // HTML entity decoding
        let input = b"&lt;script&gt;alert(1)&lt;/script&gt;";
        let output = normalizer.normalize(input);
        assert_eq!(String::from_utf8_lossy(&output), "<script>alert(1)</script>");
    }

    #[test]
    fn test_numeric_html_entity() {
        let normalizer = SemanticNormalizer::new();
        
        // Numeric HTML entity
        let input = b"&#x27; or &#39;";
        let output = normalizer.normalize(input);
        assert_eq!(String::from_utf8_lossy(&output), "' or '");
    }

    #[test]
    fn test_double_encoding() {
        let normalizer = SemanticNormalizer::new();
        
        // Double URL encoding
        let input = b"%2527"; // %25 = %, then %27 = '
        let output = normalizer.normalize(input);
        assert_eq!(String::from_utf8_lossy(&output), "'");
    }

    #[test]
    fn test_mixed_encoding() {
        let normalizer = SemanticNormalizer::new();
        
        // Mixed URL and HTML encoding
        let input = b"%3Cscript%3Ealert(&quot;xss&quot;)%3C/script%3E";
        let output = normalizer.normalize(input);
        assert_eq!(String::from_utf8_lossy(&output), "<script>alert(\"xss\")</script>");
    }

    #[test]
    fn test_case_normalization_sql() {
        let normalizer = SemanticNormalizer::new();
        
        // SQL keyword case normalization
        let input = b"SELECT * FROM users WHERE id=1";
        let output = normalizer.normalize(input);
        assert_eq!(String::from_utf8_lossy(&output), "select * from users where id=1");
    }

    #[test]
    fn test_whitespace_normalization() {
        let normalizer = SemanticNormalizer::new();
        
        // Multiple spaces collapsed
        let input = b"SELECT   *    FROM     users";
        let output = normalizer.normalize(input);
        assert_eq!(String::from_utf8_lossy(&output), "select * from users");
    }

    #[test]
    fn test_determinism() {
        let normalizer = SemanticNormalizer::new();
        
        // Same input must produce same output (deterministic)
        let input = b"%27%20OR%201%3D1--";
        let output1 = normalizer.normalize(input);
        let output2 = normalizer.normalize(input);
        let output3 = normalizer.normalize(input);
        
        assert_eq!(output1, output2);
        assert_eq!(output2, output3);
    }

    #[test]
    fn test_obfuscation_equivalence() {
        let normalizer = SemanticNormalizer::new();
        
        // All these obfuscated variants should normalize to the same output
        let variants = [
            b"' OR 1=1--".to_vec(),
            b"%27%20OR%201%3D1--".to_vec(),
            b"&#x27; OR 1=1--".to_vec(),
            b"'  OR  1=1--".to_vec(),  // Extra spaces
        ];
        
        let normalized: Vec<_> = variants.iter()
            .map(|v| String::from_utf8_lossy(&normalizer.normalize(v)).to_string())
            .collect();
        
        // All should be equivalent after normalization
        assert_eq!(normalized[0], normalized[1]);
        assert_eq!(normalized[1], normalized[2]);
        assert_eq!(normalized[2], normalized[3]);
    }

    #[test]
    fn test_tokenization() {
        let normalizer = SemanticNormalizer::new();
        
        let input = b"SELECT * FROM users WHERE name='admin'";
        let tokens = normalizer.normalize_to_tokens(input);
        
        // Should have: select, *, from, users, where, name, =, 'admin'
        assert!(tokens.iter().any(|t| matches!(t, CanonicalToken::Word(w) if w == "select")));
        assert!(tokens.iter().any(|t| matches!(t, CanonicalToken::StringLiteral(s) if s == "admin")));
    }
}
