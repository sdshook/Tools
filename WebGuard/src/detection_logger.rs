//! Detection and Access Logging for WebGuard
//!
//! Provides structured logging of threat detections and all access requests
//! with support for multiple output formats:
//! - Plain text (human readable)
//! - JSON (SIEM integration)
//! - Syslog (RFC 5424)

use crate::runtime_config::{LoggingConfig, OutputLogFormat};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Severity level for detections
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational - normal request
    Info,
    /// Low - slightly suspicious
    Low,
    /// Medium - suspicious activity
    Medium,
    /// High - likely threat
    High,
    /// Critical - definite threat, blocked
    Critical,
}

impl Severity {
    pub fn from_score(score: f32, blocked: bool) -> Self {
        if blocked {
            Severity::Critical
        } else if score > 0.8 {
            Severity::High
        } else if score > 0.6 {
            Severity::Medium
        } else if score > 0.4 {
            Severity::Low
        } else {
            Severity::Info
        }
    }
    
    /// Syslog severity number (RFC 5424)
    pub fn syslog_severity(&self) -> u8 {
        match self {
            Severity::Critical => 2, // Critical
            Severity::High => 3,     // Error
            Severity::Medium => 4,   // Warning
            Severity::Low => 5,      // Notice
            Severity::Info => 6,     // Informational
        }
    }
}

/// A single log entry for detection/access logging
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    /// Timestamp in ISO 8601 format
    pub timestamp: String,
    /// Event type: "detection" or "access"
    pub event_type: String,
    /// Severity level
    pub severity: Severity,
    /// Service/proxy name
    pub service: String,
    /// Client IP address
    pub client_ip: String,
    /// HTTP method
    pub method: String,
    /// Request URI
    pub uri: String,
    /// Threat score (0.0 - 1.0)
    pub threat_score: f32,
    /// Whether request was blocked
    pub blocked: bool,
    /// Detection reason/category (if threat)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_reason: Option<String>,
    /// Similar threat pattern (if matched)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_pattern: Option<String>,
    /// Request body snippet (if enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_snippet: Option<String>,
    /// User agent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Response status code (if proxied)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_status: Option<u16>,
}

impl LogEntry {
    /// Format as plain text
    pub fn to_plain(&self) -> String {
        let severity_str = match self.severity {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        };
        
        let blocked_str = if self.blocked { " [BLOCKED]" } else { "" };
        let reason = self.detection_reason.as_deref().unwrap_or("");
        
        format!(
            "{} [{}] {} {}{} {} {} score={:.3}{}{}",
            self.timestamp,
            severity_str,
            self.service,
            self.client_ip,
            blocked_str,
            self.method,
            self.uri,
            self.threat_score,
            if !reason.is_empty() { format!(" reason={}", reason) } else { String::new() },
            self.response_status.map(|s| format!(" status={}", s)).unwrap_or_default()
        )
    }
    
    /// Format as JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| self.to_plain())
    }
    
    /// Format as syslog (RFC 5424)
    pub fn to_syslog(&self, facility: &str, app_name: &str) -> String {
        // RFC 5424 format:
        // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        
        // Facility 16 = local0, 17 = local1, etc.
        let facility_num: u8 = match facility {
            "local0" => 16,
            "local1" => 17,
            "local2" => 18,
            "local3" => 19,
            "local4" => 20,
            "local5" => 21,
            "local6" => 22,
            "local7" => 23,
            _ => 16, // default to local0
        };
        
        // PRI = facility * 8 + severity
        let pri = facility_num * 8 + self.severity.syslog_severity();
        
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "-".to_string());
        
        let pid = std::process::id();
        let msg_id = if self.blocked { "BLOCKED" } else { "ACCESS" };
        
        // Structured data
        let sd = format!(
            "[webguard@0 service=\"{}\" score=\"{:.3}\" blocked=\"{}\" method=\"{}\" uri=\"{}\"]",
            self.service,
            self.threat_score,
            self.blocked,
            self.method,
            self.uri.replace('"', "\\\"")
        );
        
        // Message
        let msg = format!(
            "{} {} {} score={:.3}",
            self.client_ip, self.method, self.uri, self.threat_score
        );
        
        format!(
            "<{}>1 {} {} {} {} {} {} {}",
            pri,
            self.timestamp,
            hostname,
            app_name,
            pid,
            msg_id,
            sd,
            msg
        )
    }
}

/// Detection logger that writes to configured files
pub struct DetectionLogger {
    config: LoggingConfig,
    detection_writer: Option<Arc<Mutex<BufWriter<File>>>>,
    access_writer: Option<Arc<Mutex<BufWriter<File>>>>,
}

impl DetectionLogger {
    /// Create a new detection logger from config
    pub fn new(config: LoggingConfig) -> std::io::Result<Self> {
        let detection_writer = if let Some(ref path) = config.detection_log {
            Some(Arc::new(Mutex::new(Self::open_log_file(path)?)))
        } else {
            None
        };
        
        let access_writer = if let Some(ref path) = config.access_log {
            Some(Arc::new(Mutex::new(Self::open_log_file(path)?)))
        } else {
            None
        };
        
        Ok(Self {
            config,
            detection_writer,
            access_writer,
        })
    }
    
    /// Open a log file for appending
    fn open_log_file(path: &PathBuf) -> std::io::Result<BufWriter<File>> {
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        
        Ok(BufWriter::new(file))
    }
    
    /// Format an entry according to configured format
    fn format_entry(&self, entry: &LogEntry) -> String {
        match self.config.output_format {
            OutputLogFormat::Plain => entry.to_plain(),
            OutputLogFormat::Json => entry.to_json(),
            OutputLogFormat::Syslog => entry.to_syslog(
                &self.config.syslog_facility,
                &self.config.syslog_app_name
            ),
        }
    }
    
    /// Log a detection (threat/suspicious request)
    pub fn log_detection(&self, entry: &LogEntry) {
        let formatted = self.format_entry(entry);
        
        // Write to detection log file
        if let Some(ref writer) = self.detection_writer {
            if let Ok(mut w) = writer.lock() {
                let _ = writeln!(w, "{}", formatted);
                let _ = w.flush();
            }
        }
        
        // Also write to stdout if enabled
        if self.config.log_to_stdout {
            eprintln!("{}", formatted);
        }
    }
    
    /// Log an access (all requests)
    pub fn log_access(&self, entry: &LogEntry) {
        let formatted = self.format_entry(entry);
        
        // Write to access log file
        if let Some(ref writer) = self.access_writer {
            if let Ok(mut w) = writer.lock() {
                let _ = writeln!(w, "{}", formatted);
                let _ = w.flush();
            }
        }
        
        // If this is also a detection, log it there too
        if entry.severity != Severity::Info {
            self.log_detection(entry);
        }
    }
    
    /// Create a log entry from request data
    pub fn create_entry(
        service: &str,
        client_ip: &str,
        method: &str,
        uri: &str,
        threat_score: f32,
        blocked: bool,
        detection_reason: Option<String>,
        user_agent: Option<String>,
        response_status: Option<u16>,
    ) -> LogEntry {
        LogEntry {
            timestamp: Utc::now().to_rfc3339(),
            event_type: if blocked || threat_score > 0.4 { "detection".to_string() } else { "access".to_string() },
            severity: Severity::from_score(threat_score, blocked),
            service: service.to_string(),
            client_ip: client_ip.to_string(),
            method: method.to_string(),
            uri: uri.to_string(),
            threat_score,
            blocked,
            detection_reason,
            matched_pattern: None,
            body_snippet: None,
            user_agent,
            response_status,
        }
    }
    
    /// Check if any logging is enabled
    pub fn is_enabled(&self) -> bool {
        self.detection_writer.is_some() || self.access_writer.is_some() || self.config.log_to_stdout
    }
    
    /// Check if detection logging is enabled
    pub fn detection_logging_enabled(&self) -> bool {
        self.detection_writer.is_some()
    }
    
    /// Check if access logging is enabled
    pub fn access_logging_enabled(&self) -> bool {
        self.access_writer.is_some()
    }
}

impl Clone for DetectionLogger {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            detection_writer: self.detection_writer.clone(),
            access_writer: self.access_writer.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_severity_from_score() {
        assert_eq!(Severity::from_score(0.2, false), Severity::Info);
        assert_eq!(Severity::from_score(0.5, false), Severity::Low);
        assert_eq!(Severity::from_score(0.7, false), Severity::Medium);
        assert_eq!(Severity::from_score(0.9, false), Severity::High);
        assert_eq!(Severity::from_score(0.5, true), Severity::Critical);
    }
    
    #[test]
    fn test_log_entry_plain_format() {
        let entry = LogEntry {
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            event_type: "detection".to_string(),
            severity: Severity::High,
            service: "nginx".to_string(),
            client_ip: "192.168.1.100".to_string(),
            method: "GET".to_string(),
            uri: "/admin?id=1' OR '1'='1".to_string(),
            threat_score: 0.85,
            blocked: false,
            detection_reason: Some("sqli".to_string()),
            matched_pattern: None,
            body_snippet: None,
            user_agent: None,
            response_status: Some(200),
        };
        
        let plain = entry.to_plain();
        assert!(plain.contains("[HIGH]"));
        assert!(plain.contains("nginx"));
        assert!(plain.contains("192.168.1.100"));
        assert!(plain.contains("score=0.850"));
        assert!(plain.contains("reason=sqli"));
    }
    
    #[test]
    fn test_log_entry_json_format() {
        let entry = LogEntry {
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            event_type: "detection".to_string(),
            severity: Severity::Critical,
            service: "api".to_string(),
            client_ip: "10.0.0.50".to_string(),
            method: "POST".to_string(),
            uri: "/login".to_string(),
            threat_score: 0.95,
            blocked: true,
            detection_reason: Some("brute_force".to_string()),
            matched_pattern: None,
            body_snippet: None,
            user_agent: Some("curl/7.68.0".to_string()),
            response_status: None,
        };
        
        let json = entry.to_json();
        assert!(json.contains("\"severity\":\"critical\""));
        assert!(json.contains("\"blocked\":true"));
        assert!(json.contains("\"threat_score\":0.95"));
    }
    
    #[test]
    fn test_log_entry_syslog_format() {
        let entry = LogEntry {
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            event_type: "detection".to_string(),
            severity: Severity::High,
            service: "web".to_string(),
            client_ip: "172.16.0.1".to_string(),
            method: "GET".to_string(),
            uri: "/etc/passwd".to_string(),
            threat_score: 0.9,
            blocked: false,
            detection_reason: None,
            matched_pattern: None,
            body_snippet: None,
            user_agent: None,
            response_status: None,
        };
        
        let syslog = entry.to_syslog("local0", "webguard");
        // PRI = 16*8 + 3 = 131 for local0.error
        assert!(syslog.starts_with("<131>1"));
        assert!(syslog.contains("webguard"));
        assert!(syslog.contains("[webguard@0"));
    }
}
