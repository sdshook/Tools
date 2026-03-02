//! Log Parser Module for WebGuard
//!
//! Parses various web server log formats into a unified structure for analysis.
//! Supports:
//! - nginx combined/custom formats
//! - Apache combined/common formats
//! - JSON logs
//! - Auto-detection

use chrono::{DateTime, Utc, NaiveDateTime};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use lazy_static::lazy_static;

use webguard::runtime_config::LogFormat;

/// Parsed log entry - unified structure for all log formats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedLogEntry {
    /// Source IP address
    pub remote_addr: String,
    /// Remote user (if authenticated)
    pub remote_user: Option<String>,
    /// Timestamp of the request
    pub timestamp: DateTime<Utc>,
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Request URI/path
    pub uri: String,
    /// Query string (if any)
    pub query_string: Option<String>,
    /// HTTP protocol version
    pub protocol: String,
    /// HTTP status code
    pub status: u16,
    /// Response body size in bytes
    pub body_bytes: u64,
    /// Referer header
    pub referer: Option<String>,
    /// User-Agent header
    pub user_agent: Option<String>,
    /// Request body (if available in logs)
    pub request_body: Option<String>,
    /// Full request line for analysis
    pub request_line: String,
    /// Additional fields from JSON logs
    pub extra_fields: HashMap<String, String>,
    /// Raw log line
    pub raw_line: String,
}

impl ParsedLogEntry {
    /// Get the full request string for semantic analysis
    pub fn to_analysis_string(&self) -> String {
        let mut parts = vec![
            format!("{} {}", self.method, self.uri),
        ];
        
        if let Some(ref qs) = self.query_string {
            if !qs.is_empty() {
                parts.push(format!("?{}", qs));
            }
        }
        
        if let Some(ref ua) = self.user_agent {
            parts.push(format!(" UA:{}", ua));
        }
        
        if let Some(ref body) = self.request_body {
            parts.push(format!(" BODY:{}", body));
        }
        
        parts.join("")
    }
}

lazy_static! {
    // nginx combined: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"'
    static ref NGINX_COMBINED_RE: Regex = Regex::new(
        r#"^(\S+) - (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)""#
    ).unwrap();
    
    // Apache combined: same as nginx combined
    static ref APACHE_COMBINED_RE: Regex = Regex::new(
        r#"^(\S+) - (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)""#
    ).unwrap();
    
    // Apache common: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent'
    static ref APACHE_COMMON_RE: Regex = Regex::new(
        r#"^(\S+) - (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+)"#
    ).unwrap();
    
    // Request line parser: "METHOD /path?query HTTP/1.1"
    // Query string can contain spaces (URL-encoded or raw)
    static ref REQUEST_LINE_RE: Regex = Regex::new(
        r#"^(\w+)\s+([^\s?]+)(?:\?(.+?))?\s+(HTTP/\S+)?$"#
    ).unwrap();
}

/// Log parser with format detection and parsing
pub struct LogParser {
    format: LogFormat,
    custom_regex: Option<Regex>,
}

impl LogParser {
    /// Create a new log parser with specified format
    pub fn new(format: LogFormat) -> Self {
        Self {
            format,
            custom_regex: None,
        }
    }
    
    /// Create a parser with a custom regex pattern
    pub fn with_custom_regex(pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            format: LogFormat::NginxCustom,
            custom_regex: Some(Regex::new(pattern)?),
        })
    }
    
    /// Parse a single log line
    pub fn parse_line(&self, line: &str) -> Result<ParsedLogEntry, ParseError> {
        let line = line.trim();
        if line.is_empty() {
            return Err(ParseError::EmptyLine);
        }
        
        match self.format {
            LogFormat::NginxCombined => self.parse_nginx_combined(line),
            LogFormat::NginxCustom => {
                if let Some(ref re) = self.custom_regex {
                    self.parse_with_regex(line, re)
                } else {
                    self.parse_nginx_combined(line)
                }
            }
            LogFormat::ApacheCombined => self.parse_apache_combined(line),
            LogFormat::ApacheCommon => self.parse_apache_common(line),
            LogFormat::Json => self.parse_json(line),
            LogFormat::Auto => self.parse_auto(line),
        }
    }
    
    /// Parse multiple lines, returning successful parses and skipping errors
    pub fn parse_lines<'a>(&self, lines: impl Iterator<Item = &'a str>) -> Vec<ParsedLogEntry> {
        lines
            .filter_map(|line| self.parse_line(line).ok())
            .collect()
    }
    
    /// Parse nginx combined format
    fn parse_nginx_combined(&self, line: &str) -> Result<ParsedLogEntry, ParseError> {
        let caps = NGINX_COMBINED_RE.captures(line)
            .ok_or(ParseError::FormatMismatch)?;
        
        let remote_addr = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        let remote_user = caps.get(2).map(|m| {
            let u = m.as_str();
            if u == "-" { None } else { Some(u.to_string()) }
        }).flatten();
        let time_str = caps.get(3).map(|m| m.as_str()).unwrap_or("");
        let request_line = caps.get(4).map(|m| m.as_str().to_string()).unwrap_or_default();
        let status: u16 = caps.get(5).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
        let body_bytes: u64 = caps.get(6).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
        let referer = caps.get(7).map(|m| {
            let r = m.as_str();
            if r == "-" { None } else { Some(r.to_string()) }
        }).flatten();
        let user_agent = caps.get(8).map(|m| {
            let ua = m.as_str();
            if ua == "-" { None } else { Some(ua.to_string()) }
        }).flatten();
        
        let timestamp = self.parse_nginx_timestamp(time_str)?;
        let (method, uri, query_string, protocol) = self.parse_request_line(&request_line)?;
        
        Ok(ParsedLogEntry {
            remote_addr,
            remote_user,
            timestamp,
            method,
            uri,
            query_string,
            protocol,
            status,
            body_bytes,
            referer,
            user_agent,
            request_body: None,
            request_line,
            extra_fields: HashMap::new(),
            raw_line: line.to_string(),
        })
    }
    
    /// Parse Apache combined format (same as nginx combined)
    fn parse_apache_combined(&self, line: &str) -> Result<ParsedLogEntry, ParseError> {
        self.parse_nginx_combined(line)
    }
    
    /// Parse Apache common format
    fn parse_apache_common(&self, line: &str) -> Result<ParsedLogEntry, ParseError> {
        let caps = APACHE_COMMON_RE.captures(line)
            .ok_or(ParseError::FormatMismatch)?;
        
        let remote_addr = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        let remote_user = caps.get(2).map(|m| {
            let u = m.as_str();
            if u == "-" { None } else { Some(u.to_string()) }
        }).flatten();
        let time_str = caps.get(3).map(|m| m.as_str()).unwrap_or("");
        let request_line = caps.get(4).map(|m| m.as_str().to_string()).unwrap_or_default();
        let status: u16 = caps.get(5).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
        let body_bytes: u64 = caps.get(6).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
        
        let timestamp = self.parse_nginx_timestamp(time_str)?;
        let (method, uri, query_string, protocol) = self.parse_request_line(&request_line)?;
        
        Ok(ParsedLogEntry {
            remote_addr,
            remote_user,
            timestamp,
            method,
            uri,
            query_string,
            protocol,
            status,
            body_bytes,
            referer: None,
            user_agent: None,
            request_body: None,
            request_line,
            extra_fields: HashMap::new(),
            raw_line: line.to_string(),
        })
    }
    
    /// Parse JSON format log line
    fn parse_json(&self, line: &str) -> Result<ParsedLogEntry, ParseError> {
        let json: serde_json::Value = serde_json::from_str(line)
            .map_err(|_| ParseError::InvalidJson)?;
        
        let obj = json.as_object().ok_or(ParseError::InvalidJson)?;
        
        // Try common field names
        let remote_addr = self.extract_json_string(obj, &["remote_addr", "client_ip", "ip", "source_ip"])
            .unwrap_or_else(|| "unknown".to_string());
        
        let method = self.extract_json_string(obj, &["method", "request_method", "http_method"])
            .unwrap_or_else(|| "GET".to_string());
        
        let uri = self.extract_json_string(obj, &["uri", "path", "request_uri", "url"])
            .unwrap_or_else(|| "/".to_string());
        
        let query_string = self.extract_json_string(obj, &["query", "query_string", "args"]);
        
        let status: u16 = obj.get("status")
            .or_else(|| obj.get("status_code"))
            .or_else(|| obj.get("http_status"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u16)
            .unwrap_or(0);
        
        let body_bytes: u64 = obj.get("body_bytes_sent")
            .or_else(|| obj.get("bytes"))
            .or_else(|| obj.get("response_size"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        
        let user_agent = self.extract_json_string(obj, &["user_agent", "http_user_agent", "ua"]);
        let referer = self.extract_json_string(obj, &["referer", "http_referer", "referrer"]);
        let request_body = self.extract_json_string(obj, &["body", "request_body", "post_data"]);
        
        let timestamp = self.extract_json_timestamp(obj)?;
        
        let request_line = format!("{} {}{}", method, uri, 
            query_string.as_ref().map(|q| format!("?{}", q)).unwrap_or_default());
        
        // Collect extra fields
        let mut extra_fields = HashMap::new();
        for (key, value) in obj {
            if let Some(s) = value.as_str() {
                extra_fields.insert(key.clone(), s.to_string());
            }
        }
        
        Ok(ParsedLogEntry {
            remote_addr,
            remote_user: self.extract_json_string(obj, &["remote_user", "user"]),
            timestamp,
            method,
            uri,
            query_string,
            protocol: "HTTP/1.1".to_string(),
            status,
            body_bytes,
            referer,
            user_agent,
            request_body,
            request_line,
            extra_fields,
            raw_line: line.to_string(),
        })
    }
    
    /// Auto-detect format and parse
    fn parse_auto(&self, line: &str) -> Result<ParsedLogEntry, ParseError> {
        // Try JSON first (starts with '{')
        if line.trim_start().starts_with('{') {
            if let Ok(entry) = self.parse_json(line) {
                return Ok(entry);
            }
        }
        
        // Try nginx/apache combined
        if let Ok(entry) = self.parse_nginx_combined(line) {
            return Ok(entry);
        }
        
        // Try apache common
        if let Ok(entry) = self.parse_apache_common(line) {
            return Ok(entry);
        }
        
        Err(ParseError::FormatMismatch)
    }
    
    /// Parse with custom regex
    fn parse_with_regex(&self, line: &str, regex: &Regex) -> Result<ParsedLogEntry, ParseError> {
        let caps = regex.captures(line).ok_or(ParseError::FormatMismatch)?;
        
        // Try to extract named groups, fall back to positional
        let remote_addr = caps.name("remote_addr")
            .or_else(|| caps.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        
        let request_line = caps.name("request")
            .or_else(|| caps.get(4))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        
        let (method, uri, query_string, protocol) = self.parse_request_line(&request_line)?;
        
        Ok(ParsedLogEntry {
            remote_addr,
            remote_user: None,
            timestamp: Utc::now(), // Would need timestamp parsing
            method,
            uri,
            query_string,
            protocol,
            status: caps.name("status").or_else(|| caps.get(5))
                .and_then(|m| m.as_str().parse().ok()).unwrap_or(0),
            body_bytes: caps.name("bytes").or_else(|| caps.get(6))
                .and_then(|m| m.as_str().parse().ok()).unwrap_or(0),
            referer: None,
            user_agent: None,
            request_body: None,
            request_line,
            extra_fields: HashMap::new(),
            raw_line: line.to_string(),
        })
    }
    
    /// Parse nginx timestamp format: "10/Oct/2023:13:55:36 +0000"
    fn parse_nginx_timestamp(&self, time_str: &str) -> Result<DateTime<Utc>, ParseError> {
        let formats = [
            "%d/%b/%Y:%H:%M:%S %z",
            "%d/%b/%Y:%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
        ];
        
        for fmt in &formats {
            if let Ok(dt) = DateTime::parse_from_str(time_str, fmt) {
                return Ok(dt.with_timezone(&Utc));
            }
            if let Ok(ndt) = NaiveDateTime::parse_from_str(time_str, fmt) {
                return Ok(DateTime::from_naive_utc_and_offset(ndt, Utc));
            }
        }
        
        // Fall back to current time if parsing fails
        Ok(Utc::now())
    }
    
    /// Parse request line: "GET /path?query HTTP/1.1"
    fn parse_request_line(&self, request_line: &str) -> Result<(String, String, Option<String>, String), ParseError> {
        if let Some(caps) = REQUEST_LINE_RE.captures(request_line) {
            let method = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_else(|| "GET".to_string());
            let uri = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_else(|| "/".to_string());
            let query_string = caps.get(3).map(|m| m.as_str().to_string()).filter(|s| !s.is_empty());
            let protocol = caps.get(4).map(|m| m.as_str().to_string()).unwrap_or_else(|| "HTTP/1.1".to_string());
            Ok((method, uri, query_string, protocol))
        } else {
            // Fallback for malformed request lines
            Ok(("GET".to_string(), request_line.to_string(), None, "HTTP/1.1".to_string()))
        }
    }
    
    /// Extract string from JSON with multiple possible field names
    fn extract_json_string(&self, obj: &serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> Option<String> {
        for key in keys {
            if let Some(value) = obj.get(*key) {
                if let Some(s) = value.as_str() {
                    return Some(s.to_string());
                }
            }
        }
        None
    }
    
    /// Extract timestamp from JSON
    fn extract_json_timestamp(&self, obj: &serde_json::Map<String, serde_json::Value>) -> Result<DateTime<Utc>, ParseError> {
        let timestamp_keys = ["timestamp", "time", "@timestamp", "datetime", "date"];
        
        for key in &timestamp_keys {
            if let Some(value) = obj.get(*key) {
                // Try string format
                if let Some(s) = value.as_str() {
                    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
                        return Ok(dt.with_timezone(&Utc));
                    }
                    if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%z") {
                        return Ok(dt.with_timezone(&Utc));
                    }
                }
                // Try unix timestamp
                if let Some(ts) = value.as_i64() {
                    if let Some(dt) = DateTime::from_timestamp(ts, 0) {
                        return Ok(dt);
                    }
                }
                if let Some(ts) = value.as_f64() {
                    if let Some(dt) = DateTime::from_timestamp(ts as i64, ((ts.fract()) * 1_000_000_000.0) as u32) {
                        return Ok(dt);
                    }
                }
            }
        }
        
        Ok(Utc::now())
    }
}

/// Parse error types
#[derive(Debug)]
pub enum ParseError {
    EmptyLine,
    FormatMismatch,
    InvalidJson,
    InvalidTimestamp,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::EmptyLine => write!(f, "Empty line"),
            ParseError::FormatMismatch => write!(f, "Log format mismatch"),
            ParseError::InvalidJson => write!(f, "Invalid JSON"),
            ParseError::InvalidTimestamp => write!(f, "Invalid timestamp"),
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_nginx_combined() {
        let parser = LogParser::new(LogFormat::NginxCombined);
        let line = r#"192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /api/users?id=1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0""#;
        
        let entry = parser.parse_line(line).unwrap();
        assert_eq!(entry.remote_addr, "192.168.1.1");
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.uri, "/api/users");
        assert_eq!(entry.query_string, Some("id=1".to_string()));
        assert_eq!(entry.status, 200);
    }
    
    #[test]
    fn test_parse_suspicious_request() {
        let parser = LogParser::new(LogFormat::NginxCombined);
        let line = r#"10.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /search?q=' OR 1=1-- HTTP/1.1" 200 500 "-" "sqlmap/1.0""#;
        
        let entry = parser.parse_line(line).unwrap();
        assert_eq!(entry.query_string, Some("q=' OR 1=1--".to_string()));
        assert!(entry.user_agent.as_ref().unwrap().contains("sqlmap"));
    }
    
    #[test]
    fn test_parse_json() {
        let parser = LogParser::new(LogFormat::Json);
        let line = r#"{"remote_addr": "192.168.1.1", "method": "POST", "uri": "/login", "status": 401, "user_agent": "curl/7.0"}"#;
        
        let entry = parser.parse_line(line).unwrap();
        assert_eq!(entry.remote_addr, "192.168.1.1");
        assert_eq!(entry.method, "POST");
        assert_eq!(entry.uri, "/login");
        assert_eq!(entry.status, 401);
    }
    
    #[test]
    fn test_auto_detect() {
        let parser = LogParser::new(LogFormat::Auto);
        
        // Should detect nginx format
        let nginx_line = r#"192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0""#;
        assert!(parser.parse_line(nginx_line).is_ok());
        
        // Should detect JSON format
        let json_line = r#"{"remote_addr": "192.168.1.1", "method": "GET", "uri": "/"}"#;
        assert!(parser.parse_line(json_line).is_ok());
    }
    
    #[test]
    fn test_analysis_string() {
        let parser = LogParser::new(LogFormat::NginxCombined);
        let line = r#"192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /api?id=1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0""#;
        
        let entry = parser.parse_line(line).unwrap();
        let analysis_str = entry.to_analysis_string();
        
        assert!(analysis_str.contains("GET /api"));
        assert!(analysis_str.contains("?id=1"));
        assert!(analysis_str.contains("Mozilla"));
    }
}
