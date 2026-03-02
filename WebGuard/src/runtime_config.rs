//! Runtime Configuration for WebGuard Operational Modes
//!
//! WebGuard supports multiple operational modes:
//! - **Proxy**: HTTP reverse proxy with inline request analysis (PRODUCTION)
//! - **Tail**: Real-time log file monitoring (PRODUCTION)
//! - **Audit**: Batch log analysis for forensic investigation (PRODUCTION)
//! - **Demo**: Simulated telemetry for testing/demonstration (NOT FOR PRODUCTION)
//!
//! Configuration can be provided via:
//! - Command-line arguments
//! - Configuration file (TOML)
//! - Environment variables

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Operational mode for WebGuard
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperationalMode {
    /// HTTP reverse proxy - inline analysis of live traffic (PRODUCTION)
    Proxy,
    /// Log tail - real-time monitoring of log files (PRODUCTION)
    Tail,
    /// Log audit - batch analysis of historical logs (PRODUCTION)
    Audit,
    /// Demo mode - simulated telemetry for testing/demonstration ONLY
    /// WARNING: This mode generates fake data and should NEVER be used in production
    Demo,
}

impl Default for OperationalMode {
    fn default() -> Self {
        // Default to proxy mode for production readiness
        // Users must explicitly choose demo mode
        OperationalMode::Proxy
    }
}

impl std::str::FromStr for OperationalMode {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "proxy" => Ok(OperationalMode::Proxy),
            "tail" => Ok(OperationalMode::Tail),
            "audit" => Ok(OperationalMode::Audit),
            "demo" | "simulate" | "sim" | "test" => Ok(OperationalMode::Demo),
            _ => Err(format!("Unknown mode: {}. Valid modes: proxy, tail, audit, demo", s)),
        }
    }
}

/// Log format for parsing
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// nginx combined format (default)
    NginxCombined,
    /// nginx custom format
    NginxCustom,
    /// Apache combined format
    ApacheCombined,
    /// Apache common format
    ApacheCommon,
    /// JSON format (one JSON object per line)
    Json,
    /// Auto-detect format
    Auto,
}

impl Default for LogFormat {
    fn default() -> Self {
        LogFormat::Auto
    }
}

impl std::str::FromStr for LogFormat {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "nginx" | "nginx_combined" | "nginx-combined" => Ok(LogFormat::NginxCombined),
            "nginx_custom" | "nginx-custom" => Ok(LogFormat::NginxCustom),
            "apache" | "apache_combined" | "apache-combined" => Ok(LogFormat::ApacheCombined),
            "apache_common" | "apache-common" => Ok(LogFormat::ApacheCommon),
            "json" => Ok(LogFormat::Json),
            "auto" => Ok(LogFormat::Auto),
            _ => Err(format!("Unknown log format: {}. Valid formats: nginx, apache, json, auto", s)),
        }
    }
}

/// Single proxy mapping (listen -> backend)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyMapping {
    /// Name/identifier for this proxy (e.g., "nginx_main", "api_server")
    pub name: String,
    /// Address to listen on (e.g., "0.0.0.0:8080")
    pub listen_addr: String,
    /// Backend server to forward requests to (e.g., "127.0.0.1:80")
    pub backend_addr: String,
    /// Web server type for this backend
    pub server_type: String,
    /// Whether to use TLS for incoming connections
    #[serde(default)]
    pub tls_enabled: bool,
    /// Path to TLS certificate (if tls_enabled)
    #[serde(default)]
    pub tls_cert_path: Option<PathBuf>,
    /// Path to TLS key (if tls_enabled)
    #[serde(default)]
    pub tls_key_path: Option<PathBuf>,
}

impl Default for ProxyMapping {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            listen_addr: "0.0.0.0:8080".to_string(),
            backend_addr: "127.0.0.1:80".to_string(),
            server_type: "nginx".to_string(),
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

/// Proxy mode configuration - supports multiple port mappings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Multiple proxy mappings (listen_port -> backend)
    /// For collective immunity, all proxies share the same PSI
    pub mappings: Vec<ProxyMapping>,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Whether to block detected threats (vs just log)
    pub blocking_mode: bool,
    /// Threat score threshold for blocking (0.0 - 1.0)
    pub block_threshold: f32,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            mappings: vec![ProxyMapping::default()],
            timeout_secs: 30,
            blocking_mode: false,
            block_threshold: 0.7,
        }
    }
}

impl ProxyConfig {
    /// Create config from simple listen/backend pair (CLI compatibility)
    pub fn from_single(listen_addr: String, backend_addr: String) -> Self {
        Self {
            mappings: vec![ProxyMapping {
                name: "cli".to_string(),
                listen_addr,
                backend_addr,
                server_type: "generic".to_string(),
                tls_enabled: false,
                tls_cert_path: None,
                tls_key_path: None,
            }],
            timeout_secs: 30,
            blocking_mode: false,
            block_threshold: 0.7,
        }
    }
    
    /// Add a proxy mapping
    pub fn add_mapping(&mut self, name: &str, listen: &str, backend: &str, server_type: &str) {
        self.mappings.push(ProxyMapping {
            name: name.to_string(),
            listen_addr: listen.to_string(),
            backend_addr: backend.to_string(),
            server_type: server_type.to_string(),
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
        });
    }
}

/// Log tail mode configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailConfig {
    /// Log file paths to monitor
    pub log_paths: Vec<PathBuf>,
    /// Log format
    pub format: LogFormat,
    /// Whether to follow log rotation
    pub follow_rotation: bool,
    /// Poll interval in milliseconds (for systems without inotify)
    pub poll_interval_ms: u64,
}

impl Default for TailConfig {
    fn default() -> Self {
        Self {
            log_paths: vec![PathBuf::from("/var/log/nginx/access.log")],
            format: LogFormat::Auto,
            follow_rotation: true,
            poll_interval_ms: 100,
        }
    }
}

/// Log audit mode configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Log file paths to analyze (supports glob patterns)
    pub log_paths: Vec<PathBuf>,
    /// Log format
    pub format: LogFormat,
    /// Output report path
    pub report_path: PathBuf,
    /// Output format for report
    pub report_format: ReportFormat,
    /// Time range filter - start (ISO 8601)
    pub time_start: Option<String>,
    /// Time range filter - end (ISO 8601)
    pub time_end: Option<String>,
    /// Minimum threat score to include in report
    pub min_threat_score: f32,
    /// Maximum entries to analyze (0 = unlimited)
    pub max_entries: usize,
    /// Whether to learn from the audit (update PSI)
    pub learn_from_audit: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_paths: vec![],
            format: LogFormat::Auto,
            report_path: PathBuf::from("./webguard_audit_report.json"),
            report_format: ReportFormat::Json,
            time_start: None,
            time_end: None,
            min_threat_score: 0.3,
            max_entries: 0,
            learn_from_audit: false,
        }
    }
}

/// Report output format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Json,
    Csv,
    Html,
    Markdown,
}

impl Default for ReportFormat {
    fn default() -> Self {
        ReportFormat::Json
    }
}

/// Output log format for detection and access logs
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputLogFormat {
    /// Plain text format (human readable)
    Plain,
    /// JSON format (machine readable, SIEM-friendly)
    Json,
    /// Syslog format (RFC 5424)
    Syslog,
}

impl Default for OutputLogFormat {
    fn default() -> Self {
        OutputLogFormat::Plain
    }
}

impl std::str::FromStr for OutputLogFormat {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "plain" | "text" | "txt" => Ok(OutputLogFormat::Plain),
            "json" => Ok(OutputLogFormat::Json),
            "syslog" | "rfc5424" => Ok(OutputLogFormat::Syslog),
            _ => Err(format!("Unknown output log format: {}. Valid formats: plain, json, syslog", s)),
        }
    }
}

/// Logging configuration for WebGuard output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Path to detection log file (threats only) - None = disabled
    pub detection_log: Option<PathBuf>,
    /// Path to access log file (all requests) - None = disabled
    pub access_log: Option<PathBuf>,
    /// Output format for log files
    pub output_format: OutputLogFormat,
    /// Also log to stdout (in addition to files)
    pub log_to_stdout: bool,
    /// Include request body snippet in logs (up to N bytes, 0 = disabled)
    pub include_body_bytes: usize,
    /// Syslog facility (when using syslog format)
    pub syslog_facility: String,
    /// Syslog app name
    pub syslog_app_name: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            detection_log: None,
            access_log: None,
            output_format: OutputLogFormat::Plain,
            log_to_stdout: true,
            include_body_bytes: 0,
            syslog_facility: "local0".to_string(),
            syslog_app_name: "webguard".to_string(),
        }
    }
}

/// Persistence configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceConfig {
    /// Enable persistence
    pub enabled: bool,
    /// Path to persistence directory
    pub data_dir: PathBuf,
    /// Auto-save interval in seconds (0 = disabled)
    pub auto_save_interval_secs: u64,
    /// Load state on startup
    pub load_on_startup: bool,
    /// Compress saved state
    pub compress: bool,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            data_dir: PathBuf::from("./webguard_data"),
            auto_save_interval_secs: 300, // 5 minutes
            load_on_startup: true,
            compress: true,
        }
    }
}

/// Complete runtime configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Operational mode
    pub mode: OperationalMode,
    /// Proxy mode settings
    pub proxy: ProxyConfig,
    /// Tail mode settings
    pub tail: TailConfig,
    /// Audit mode settings
    pub audit: AuditConfig,
    /// Persistence settings
    pub persistence: PersistenceConfig,
    /// Logging/output settings
    pub logging: LoggingConfig,
    /// Web server types to register (for multi-server environments)
    pub server_types: Vec<String>,
    /// Logging level
    pub log_level: String,
    /// Enable metrics endpoint
    pub metrics_enabled: bool,
    /// Metrics endpoint address
    pub metrics_addr: String,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            mode: OperationalMode::Proxy, // Production-ready default
            proxy: ProxyConfig::default(),
            tail: TailConfig::default(),
            audit: AuditConfig::default(),
            persistence: PersistenceConfig::default(),
            logging: LoggingConfig::default(),
            server_types: vec!["nginx".to_string()],
            log_level: "info".to_string(),
            metrics_enabled: false,
            metrics_addr: "127.0.0.1:9090".to_string(),
        }
    }
}

impl RuntimeConfig {
    /// Load configuration from file
    pub fn load_from_file(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: RuntimeConfig = toml::from_str(&content)?;
        Ok(config)
    }
    
    /// Save configuration to file
    pub fn save_to_file(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
    
    /// Create default config file if it doesn't exist
    pub fn ensure_default_config(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        if path.exists() {
            Self::load_from_file(path)
        } else {
            let config = Self::default();
            config.save_to_file(path)?;
            Ok(config)
        }
    }
    
    /// Parse from command line arguments
    pub fn from_args() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let mut config = RuntimeConfig::default();
        let mut cli_listen: Option<String> = None;
        let mut cli_backend: Option<String> = None;
        let mut additional_mappings: Vec<(String, String, String)> = Vec::new(); // (listen, backend, name)
        
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--mode" | "-m" => {
                    if i + 1 < args.len() {
                        config.mode = args[i + 1].parse().unwrap_or_default();
                        i += 1;
                    }
                }
                "--config" | "-c" => {
                    if i + 1 < args.len() {
                        if let Ok(loaded) = Self::load_from_file(&PathBuf::from(&args[i + 1])) {
                            config = loaded;
                        }
                        i += 1;
                    }
                }
                "--log" | "-l" => {
                    if i + 1 < args.len() {
                        config.tail.log_paths.push(PathBuf::from(&args[i + 1]));
                        config.audit.log_paths.push(PathBuf::from(&args[i + 1]));
                        i += 1;
                    }
                }
                "--listen" => {
                    if i + 1 < args.len() {
                        cli_listen = Some(args[i + 1].clone());
                        i += 1;
                    }
                }
                "--backend" => {
                    if i + 1 < args.len() {
                        cli_backend = Some(args[i + 1].clone());
                        i += 1;
                    }
                }
                // Multi-port: --proxy name:listen:backend (can be repeated)
                "--proxy" | "-p" => {
                    if i + 1 < args.len() {
                        let parts: Vec<&str> = args[i + 1].split(':').collect();
                        if parts.len() >= 3 {
                            // Format: name:listen_port:backend_host:backend_port
                            // e.g., nginx:8080:127.0.0.1:80 or nginx:8080:localhost:80
                            let name = parts[0].to_string();
                            let listen = format!("0.0.0.0:{}", parts[1]);
                            let backend = if parts.len() == 4 {
                                format!("{}:{}", parts[2], parts[3])
                            } else {
                                format!("127.0.0.1:{}", parts[2])
                            };
                            additional_mappings.push((listen, backend, name));
                        }
                        i += 1;
                    }
                }
                "--report" | "-r" => {
                    if i + 1 < args.len() {
                        config.audit.report_path = PathBuf::from(&args[i + 1]);
                        i += 1;
                    }
                }
                "--format" | "-f" => {
                    if i + 1 < args.len() {
                        config.tail.format = args[i + 1].parse().unwrap_or_default();
                        config.audit.format = args[i + 1].parse().unwrap_or_default();
                        i += 1;
                    }
                }
                "--blocking" => {
                    config.proxy.blocking_mode = true;
                }
                "--learn" => {
                    config.audit.learn_from_audit = true;
                }
                "--no-persist" => {
                    config.persistence.enabled = false;
                }
                "--data-dir" => {
                    if i + 1 < args.len() {
                        config.persistence.data_dir = PathBuf::from(&args[i + 1]);
                        i += 1;
                    }
                }
                // Logging options
                "--detection-log" => {
                    if i + 1 < args.len() {
                        config.logging.detection_log = Some(PathBuf::from(&args[i + 1]));
                        i += 1;
                    }
                }
                "--access-log" => {
                    if i + 1 < args.len() {
                        config.logging.access_log = Some(PathBuf::from(&args[i + 1]));
                        i += 1;
                    }
                }
                "--log-format" => {
                    if i + 1 < args.len() {
                        config.logging.output_format = args[i + 1].parse().unwrap_or_default();
                        i += 1;
                    }
                }
                "--no-stdout" => {
                    config.logging.log_to_stdout = false;
                }
                "--help" | "-h" => {
                    Self::print_help();
                    std::process::exit(0);
                }
                _ => {}
            }
            i += 1;
        }
        
        // Build proxy mappings from CLI arguments
        if !additional_mappings.is_empty() {
            config.proxy.mappings.clear();
            for (listen, backend, name) in additional_mappings {
                config.proxy.mappings.push(ProxyMapping {
                    name,
                    listen_addr: listen,
                    backend_addr: backend,
                    server_type: "generic".to_string(),
                    tls_enabled: false,
                    tls_cert_path: None,
                    tls_key_path: None,
                });
            }
        } else if let (Some(listen), Some(backend)) = (cli_listen, cli_backend) {
            // Single --listen/--backend pair
            config.proxy.mappings = vec![ProxyMapping {
                name: "cli".to_string(),
                listen_addr: listen,
                backend_addr: backend,
                server_type: "generic".to_string(),
                tls_enabled: false,
                tls_cert_path: None,
                tls_key_path: None,
            }];
        }
        
        // Clean up default paths if user specified custom ones
        let tail_len = config.tail.log_paths.len();
        if tail_len > 1 {
            let default_path = "/var/log/nginx/access.log";
            config.tail.log_paths.retain(|p| p.to_string_lossy() != default_path);
        }
        if config.audit.log_paths.len() > 1 {
            config.audit.log_paths.retain(|p| !p.to_string_lossy().is_empty());
        }
        
        config
    }
    
    /// Print help message
    pub fn print_help() {
        println!(r#"
WebGuard - Self-Learning Web Server EDR
Neuromorphic Defense with Biological Immunity Architecture

USAGE:
    webguard [OPTIONS]

MODES (Production):
    --mode, -m proxy      HTTP reverse proxy with inline analysis (default)
    --mode, -m tail       Real-time log file monitoring
    --mode, -m audit      Batch log analysis for forensics

MODES (Testing Only):
    --mode, -m demo       Simulated telemetry for testing (NOT FOR PRODUCTION)

PROXY MODE OPTIONS (Single Port):
    --listen <ADDR>       Listen address (e.g., 0.0.0.0:8080)
    --backend <ADDR>      Backend server address (e.g., 127.0.0.1:80)
    --blocking            Enable blocking mode (block detected threats)

PROXY MODE OPTIONS (Multiple Ports - Collective Immunity):
    --proxy, -p <SPEC>    Add proxy mapping (can be repeated)
                          Format: name:listen_port:backend_host:backend_port
                          
                          All proxies share the same PSI for collective immunity:
                          Threat detected on any port protects ALL other ports!

TAIL MODE OPTIONS:
    --log, -l <PATH>      Log file path to monitor (can be repeated)
    --format, -f <FMT>    Log format: nginx, apache, json, auto

AUDIT MODE OPTIONS:
    --log, -l <PATH>      Log file path(s) to analyze (supports globs)
    --report, -r <PATH>   Output report path
    --format, -f <FMT>    Log format: nginx, apache, json, auto
    --learn               Learn from audit (update threat knowledge)

LOGGING OPTIONS:
    --detection-log <PATH>  Log file for threats/detections only
    --access-log <PATH>     Log file for all requests with scores
    --log-format <FMT>      Output format: plain, json, syslog (default: plain)
    --no-stdout             Disable console output (log to files only)

GENERAL OPTIONS:
    --config, -c <PATH>   Load configuration from TOML file
    --data-dir <PATH>     Persistence data directory
    --no-persist          Disable persistence
    --help, -h            Show this help message

EXAMPLES:
    # Single proxy
    webguard --mode proxy --listen 0.0.0.0:8080 --backend 127.0.0.1:80

    # Multiple proxies with collective immunity
    webguard --mode proxy \
        -p nginx:8080:127.0.0.1:80 \
        -p apache:8081:127.0.0.1:81 \
        -p api:3000:127.0.0.1:3001 \
        -p admin:9000:127.0.0.1:9001 \
        --blocking

    # Monitor multiple log files
    webguard --mode tail \
        -l /var/log/nginx/access.log \
        -l /var/log/apache2/access.log

    # Audit historical logs
    webguard --mode audit \
        --log "/var/log/nginx/access.log*" \
        --report audit.html --format html \
        --learn

    # Run with config file
    webguard --config /etc/webguard/config.toml

    # Log detections to file in JSON format (SIEM integration)
    webguard --mode proxy -p web:8080:127.0.0.1:80 \
        --detection-log /var/log/webguard/detections.log \
        --log-format json

    # Full access logging with syslog format
    webguard --mode proxy -p web:8080:127.0.0.1:80 \
        --detection-log /var/log/webguard/threats.log \
        --access-log /var/log/webguard/access.log \
        --log-format syslog \
        --no-stdout

COLLECTIVE IMMUNITY:
    When running multiple proxy mappings, all share the same learning:
    
      nginx:8080 ─┐
      apache:8081─┼──► Shared PSI ──► Threat on ANY port protects ALL
      api:3000   ─┤
      admin:9000 ─┘
    
    Example: SQL injection detected on nginx:8080 immediately protects
    apache:8081, api:3000, and admin:9000 without any additional training!
"#);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mode_parsing() {
        assert_eq!("proxy".parse::<OperationalMode>().unwrap(), OperationalMode::Proxy);
        assert_eq!("tail".parse::<OperationalMode>().unwrap(), OperationalMode::Tail);
        assert_eq!("audit".parse::<OperationalMode>().unwrap(), OperationalMode::Audit);
        // Demo mode accepts multiple aliases for backwards compatibility
        assert_eq!("demo".parse::<OperationalMode>().unwrap(), OperationalMode::Demo);
        assert_eq!("simulate".parse::<OperationalMode>().unwrap(), OperationalMode::Demo);
        assert_eq!("sim".parse::<OperationalMode>().unwrap(), OperationalMode::Demo);
        assert_eq!("test".parse::<OperationalMode>().unwrap(), OperationalMode::Demo);
    }
    
    #[test]
    fn test_log_format_parsing() {
        assert_eq!("nginx".parse::<LogFormat>().unwrap(), LogFormat::NginxCombined);
        assert_eq!("apache".parse::<LogFormat>().unwrap(), LogFormat::ApacheCombined);
        assert_eq!("json".parse::<LogFormat>().unwrap(), LogFormat::Json);
    }
    
    #[test]
    fn test_default_config() {
        let config = RuntimeConfig::default();
        // Default should be production-ready proxy mode
        assert_eq!(config.mode, OperationalMode::Proxy);
        assert!(config.persistence.enabled);
    }
}
