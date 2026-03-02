//! Audit Mode - Batch Log Analysis for Forensic Investigation
//!
//! Analyzes historical log files to identify anomalies, threats, and suspicious patterns.
//! Generates comprehensive reports suitable for security audits and incident investigation.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

use webguard::runtime_config::{AuditConfig, ReportFormat};
use crate::log_parser::{LogParser, ParsedLogEntry};
use crate::semantic_normalizer::SemanticNormalizer;
use crate::embedding_learner::EmbeddingLearner;
use crate::mesh_cognition::HostMeshCognition;
use crate::memory_engine::psi_index::PsiIndex;

/// Analysis result for a single log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Original log entry
    pub entry: ParsedLogEntry,
    /// Threat score (0.0 = benign, 1.0 = definite threat)
    pub threat_score: f32,
    /// Confidence in the assessment
    pub confidence: f32,
    /// Classification
    pub classification: ThreatClassification,
    /// Matched threat patterns (if any)
    pub matched_patterns: Vec<String>,
    /// Anomaly indicators
    pub anomaly_indicators: Vec<String>,
    /// Recommended action
    pub recommended_action: String,
}

/// Threat classification levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatClassification {
    Benign,
    Suspicious,
    LikelyThreat,
    ConfirmedThreat,
    Unknown,
}

impl ThreatClassification {
    fn from_score(score: f32, confidence: f32) -> Self {
        if confidence < 0.3 {
            ThreatClassification::Unknown
        } else if score < 0.3 {
            ThreatClassification::Benign
        } else if score < 0.5 {
            ThreatClassification::Suspicious
        } else if score < 0.7 {
            ThreatClassification::LikelyThreat
        } else {
            ThreatClassification::ConfirmedThreat
        }
    }
}

/// Audit report summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    /// Report metadata
    pub metadata: ReportMetadata,
    /// Summary statistics
    pub summary: AuditSummary,
    /// Top threats by severity
    pub top_threats: Vec<AnalysisResult>,
    /// Suspicious IPs
    pub suspicious_ips: Vec<IpSummary>,
    /// Attack patterns detected
    pub attack_patterns: Vec<PatternSummary>,
    /// Timeline of threats
    pub threat_timeline: Vec<TimelineEntry>,
    /// Recommendations
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub generated_at: DateTime<Utc>,
    pub webguard_version: String,
    pub log_files_analyzed: Vec<String>,
    pub time_range_start: Option<DateTime<Utc>>,
    pub time_range_end: Option<DateTime<Utc>>,
    pub total_entries_analyzed: usize,
    pub analysis_duration_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub total_requests: usize,
    pub benign_count: usize,
    pub suspicious_count: usize,
    pub likely_threat_count: usize,
    pub confirmed_threat_count: usize,
    pub unknown_count: usize,
    pub unique_ips: usize,
    pub unique_user_agents: usize,
    pub error_rate_4xx: f32,
    pub error_rate_5xx: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpSummary {
    pub ip: String,
    pub request_count: usize,
    pub threat_count: usize,
    pub avg_threat_score: f32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub targeted_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternSummary {
    pub pattern_type: String,
    pub occurrence_count: usize,
    pub example_requests: Vec<String>,
    pub source_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub threat_count: usize,
    pub avg_threat_score: f32,
}

/// Audit engine for batch log analysis
pub struct AuditEngine {
    config: AuditConfig,
    parser: LogParser,
    normalizer: SemanticNormalizer,
    embedding_learner: EmbeddingLearner,
    psi: Arc<Mutex<PsiIndex>>,
    results: Vec<AnalysisResult>,
    ip_stats: HashMap<String, IpStats>,
    pattern_stats: HashMap<String, PatternStats>,
}

struct IpStats {
    request_count: usize,
    threat_count: usize,
    threat_scores: Vec<f32>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    paths: Vec<String>,
}

struct PatternStats {
    count: usize,
    examples: Vec<String>,
    ips: Vec<String>,
}

impl AuditEngine {
    /// Create a new audit engine
    pub fn new(config: AuditConfig, psi: Arc<Mutex<PsiIndex>>) -> Self {
        Self {
            parser: LogParser::new(config.format.clone()),
            normalizer: SemanticNormalizer::new(),
            embedding_learner: EmbeddingLearner::new(),
            psi,
            results: Vec::new(),
            ip_stats: HashMap::new(),
            pattern_stats: HashMap::new(),
            config,
        }
    }
    
    /// Analyze a single log entry
    pub fn analyze_entry(&mut self, entry: ParsedLogEntry) -> AnalysisResult {
        // Get the request string for analysis
        let request_str = entry.to_analysis_string();
        
        // Normalize the request
        let normalized = self.normalizer.normalize(request_str.as_bytes());
        let normalized_str = String::from_utf8_lossy(&normalized);
        
        // Get embedding and threat score
        let embedding = self.embedding_learner.embed(&normalized_str);
        let threat_score = self.embedding_learner.threat_score(&embedding);
        
        // Query PSI for similar known patterns
        let psi_results = if let Ok(psi) = self.psi.try_lock() {
            let mut arr = [0.0f32; 32];
            for i in 0..embedding.len().min(32) {
                arr[i] = embedding[i];
            }
            psi.search(&arr, 3)
                .iter()
                .map(|(e, s)| (e.id.clone(), e.valence, *s))
                .collect::<Vec<_>>()
        } else {
            vec![]
        };
        
        // Calculate confidence based on PSI matches
        let confidence = if psi_results.is_empty() {
            0.3 // Low confidence without training data
        } else {
            let max_sim = psi_results.iter().map(|(_, _, s)| *s).fold(0.0f32, |a, b| a.max(b));
            (max_sim * 0.7 + 0.3).min(1.0)
        };
        
        // Determine classification
        let classification = ThreatClassification::from_score(threat_score, confidence);
        
        // Identify anomaly indicators
        let mut anomaly_indicators = Vec::new();
        
        // Check for common attack indicators
        if request_str.contains("'") || request_str.contains("\"") {
            anomaly_indicators.push("Quote characters in request".to_string());
        }
        if request_str.contains("..") {
            anomaly_indicators.push("Path traversal pattern".to_string());
        }
        if request_str.contains("<") || request_str.contains(">") {
            anomaly_indicators.push("HTML/script tags in request".to_string());
        }
        if request_str.to_lowercase().contains("select") && request_str.to_lowercase().contains("from") {
            anomaly_indicators.push("SQL keyword patterns".to_string());
        }
        if entry.status >= 400 && entry.status < 500 {
            anomaly_indicators.push(format!("Client error status: {}", entry.status));
        }
        if entry.status >= 500 {
            anomaly_indicators.push(format!("Server error status: {}", entry.status));
        }
        
        // Matched patterns from PSI
        let matched_patterns: Vec<String> = psi_results.iter()
            .filter(|(_, valence, sim)| *valence > 0.5 && *sim > 0.5)
            .map(|(id, _, _)| id.clone())
            .collect();
        
        // Recommended action
        let recommended_action = match classification {
            ThreatClassification::ConfirmedThreat => "BLOCK - Add IP to blocklist, investigate further".to_string(),
            ThreatClassification::LikelyThreat => "THROTTLE - Rate limit source IP, monitor closely".to_string(),
            ThreatClassification::Suspicious => "MONITOR - Flag for review, increase logging".to_string(),
            ThreatClassification::Benign => "ALLOW - Normal traffic".to_string(),
            ThreatClassification::Unknown => "REVIEW - Manual inspection recommended".to_string(),
        };
        
        // Update IP statistics
        let ip = entry.remote_addr.clone();
        let ip_stat = self.ip_stats.entry(ip).or_insert_with(|| IpStats {
            request_count: 0,
            threat_count: 0,
            threat_scores: Vec::new(),
            first_seen: entry.timestamp,
            last_seen: entry.timestamp,
            paths: Vec::new(),
        });
        ip_stat.request_count += 1;
        ip_stat.threat_scores.push(threat_score);
        if threat_score > 0.5 {
            ip_stat.threat_count += 1;
        }
        if entry.timestamp < ip_stat.first_seen {
            ip_stat.first_seen = entry.timestamp;
        }
        if entry.timestamp > ip_stat.last_seen {
            ip_stat.last_seen = entry.timestamp;
        }
        if !ip_stat.paths.contains(&entry.uri) {
            ip_stat.paths.push(entry.uri.clone());
        }
        
        AnalysisResult {
            entry,
            threat_score,
            confidence,
            classification,
            matched_patterns,
            anomaly_indicators,
            recommended_action,
        }
    }
    
    /// Analyze a log file
    pub fn analyze_file(&mut self, path: &PathBuf) -> Result<usize, Box<dyn std::error::Error>> {
        info!("Analyzing log file: {:?}", path);
        
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0;
        let mut error_count = 0;
        
        for line in reader.lines() {
            let line = line?;
            
            match self.parser.parse_line(&line) {
                Ok(entry) => {
                    // Apply time filter if configured
                    if let Some(ref start) = self.config.time_start {
                        if let Ok(start_dt) = DateTime::parse_from_rfc3339(start) {
                            if entry.timestamp < start_dt.with_timezone(&Utc) {
                                continue;
                            }
                        }
                    }
                    if let Some(ref end) = self.config.time_end {
                        if let Ok(end_dt) = DateTime::parse_from_rfc3339(end) {
                            if entry.timestamp > end_dt.with_timezone(&Utc) {
                                continue;
                            }
                        }
                    }
                    
                    let result = self.analyze_entry(entry);
                    
                    // Only store results above threshold
                    if result.threat_score >= self.config.min_threat_score {
                        self.results.push(result);
                    }
                    
                    count += 1;
                    
                    // Check max entries limit
                    if self.config.max_entries > 0 && count >= self.config.max_entries {
                        break;
                    }
                    
                    // Progress logging
                    if count % 10000 == 0 {
                        info!("Processed {} entries, {} threats found", count, self.results.len());
                    }
                }
                Err(_) => {
                    error_count += 1;
                }
            }
        }
        
        if error_count > 0 {
            warn!("Failed to parse {} lines", error_count);
        }
        
        info!("Completed analysis of {:?}: {} entries, {} threats", path, count, self.results.len());
        Ok(count)
    }
    
    /// Generate the audit report
    pub fn generate_report(&self, duration_secs: f64) -> AuditReport {
        // Summary statistics
        let mut summary = AuditSummary {
            total_requests: self.results.len(),
            benign_count: 0,
            suspicious_count: 0,
            likely_threat_count: 0,
            confirmed_threat_count: 0,
            unknown_count: 0,
            unique_ips: self.ip_stats.len(),
            unique_user_agents: 0,
            error_rate_4xx: 0.0,
            error_rate_5xx: 0.0,
        };
        
        let mut user_agents = std::collections::HashSet::new();
        let mut count_4xx = 0;
        let mut count_5xx = 0;
        
        for result in &self.results {
            match result.classification {
                ThreatClassification::Benign => summary.benign_count += 1,
                ThreatClassification::Suspicious => summary.suspicious_count += 1,
                ThreatClassification::LikelyThreat => summary.likely_threat_count += 1,
                ThreatClassification::ConfirmedThreat => summary.confirmed_threat_count += 1,
                ThreatClassification::Unknown => summary.unknown_count += 1,
            }
            
            if let Some(ref ua) = result.entry.user_agent {
                user_agents.insert(ua.clone());
            }
            
            if result.entry.status >= 400 && result.entry.status < 500 {
                count_4xx += 1;
            }
            if result.entry.status >= 500 {
                count_5xx += 1;
            }
        }
        
        summary.unique_user_agents = user_agents.len();
        if !self.results.is_empty() {
            summary.error_rate_4xx = count_4xx as f32 / self.results.len() as f32;
            summary.error_rate_5xx = count_5xx as f32 / self.results.len() as f32;
        }
        
        // Top threats
        let mut top_threats: Vec<_> = self.results.iter()
            .filter(|r| r.classification == ThreatClassification::ConfirmedThreat 
                     || r.classification == ThreatClassification::LikelyThreat)
            .cloned()
            .collect();
        top_threats.sort_by(|a, b| b.threat_score.partial_cmp(&a.threat_score).unwrap());
        top_threats.truncate(100);
        
        // Suspicious IPs
        let mut suspicious_ips: Vec<IpSummary> = self.ip_stats.iter()
            .filter(|(_, stats)| stats.threat_count > 0)
            .map(|(ip, stats)| {
                let avg_score = if stats.threat_scores.is_empty() {
                    0.0
                } else {
                    stats.threat_scores.iter().sum::<f32>() / stats.threat_scores.len() as f32
                };
                IpSummary {
                    ip: ip.clone(),
                    request_count: stats.request_count,
                    threat_count: stats.threat_count,
                    avg_threat_score: avg_score,
                    first_seen: stats.first_seen,
                    last_seen: stats.last_seen,
                    targeted_paths: stats.paths.clone(),
                }
            })
            .collect();
        suspicious_ips.sort_by(|a, b| b.threat_count.cmp(&a.threat_count));
        suspicious_ips.truncate(50);
        
        // Recommendations
        let mut recommendations = Vec::new();
        
        if summary.confirmed_threat_count > 0 {
            recommendations.push(format!(
                "CRITICAL: {} confirmed threats detected. Immediate investigation required.",
                summary.confirmed_threat_count
            ));
        }
        
        if !suspicious_ips.is_empty() {
            let top_ip = &suspicious_ips[0];
            recommendations.push(format!(
                "Consider blocking IP {} ({} threats, {} total requests)",
                top_ip.ip, top_ip.threat_count, top_ip.request_count
            ));
        }
        
        if summary.error_rate_5xx > 0.05 {
            recommendations.push(format!(
                "High 5xx error rate ({:.1}%). Check server health.",
                summary.error_rate_5xx * 100.0
            ));
        }
        
        AuditReport {
            metadata: ReportMetadata {
                generated_at: Utc::now(),
                webguard_version: env!("CARGO_PKG_VERSION").to_string(),
                log_files_analyzed: self.config.log_paths.iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect(),
                time_range_start: self.results.first().map(|r| r.entry.timestamp),
                time_range_end: self.results.last().map(|r| r.entry.timestamp),
                total_entries_analyzed: summary.total_requests,
                analysis_duration_secs: duration_secs,
            },
            summary,
            top_threats,
            suspicious_ips,
            attack_patterns: vec![], // TODO: Pattern clustering
            threat_timeline: vec![], // TODO: Timeline aggregation
            recommendations,
        }
    }
    
    /// Export report to file
    pub fn export_report(&self, report: &AuditReport, path: &PathBuf, format: &ReportFormat) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = File::create(path)?;
        
        match format {
            ReportFormat::Json => {
                let json = serde_json::to_string_pretty(report)?;
                file.write_all(json.as_bytes())?;
            }
            ReportFormat::Csv => {
                // CSV format - just top threats
                writeln!(file, "timestamp,ip,method,uri,status,threat_score,classification,indicators")?;
                for result in &report.top_threats {
                    writeln!(file, "{},{},{},{},{},{:.3},{:?},\"{}\"",
                        result.entry.timestamp.to_rfc3339(),
                        result.entry.remote_addr,
                        result.entry.method,
                        result.entry.uri,
                        result.entry.status,
                        result.threat_score,
                        result.classification,
                        result.anomaly_indicators.join("; ")
                    )?;
                }
            }
            ReportFormat::Markdown => {
                self.write_markdown_report(&mut file, report)?;
            }
            ReportFormat::Html => {
                self.write_html_report(&mut file, report)?;
            }
        }
        
        Ok(())
    }
    
    fn write_markdown_report(&self, file: &mut File, report: &AuditReport) -> Result<(), Box<dyn std::error::Error>> {
        writeln!(file, "# WebGuard Audit Report\n")?;
        writeln!(file, "Generated: {}\n", report.metadata.generated_at.to_rfc3339())?;
        
        writeln!(file, "## Summary\n")?;
        writeln!(file, "| Metric | Value |")?;
        writeln!(file, "|--------|-------|")?;
        writeln!(file, "| Total Requests | {} |", report.summary.total_requests)?;
        writeln!(file, "| Confirmed Threats | {} |", report.summary.confirmed_threat_count)?;
        writeln!(file, "| Likely Threats | {} |", report.summary.likely_threat_count)?;
        writeln!(file, "| Suspicious | {} |", report.summary.suspicious_count)?;
        writeln!(file, "| Unique IPs | {} |", report.summary.unique_ips)?;
        
        writeln!(file, "\n## Top Threats\n")?;
        writeln!(file, "| Time | IP | Request | Score |")?;
        writeln!(file, "|------|----|---------| ------|")?;
        for threat in report.top_threats.iter().take(20) {
            writeln!(file, "| {} | {} | {} {} | {:.2} |",
                threat.entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                threat.entry.remote_addr,
                threat.entry.method,
                threat.entry.uri,
                threat.threat_score
            )?;
        }
        
        writeln!(file, "\n## Recommendations\n")?;
        for rec in &report.recommendations {
            writeln!(file, "- {}", rec)?;
        }
        
        Ok(())
    }
    
    fn write_html_report(&self, file: &mut File, report: &AuditReport) -> Result<(), Box<dyn std::error::Error>> {
        writeln!(file, r#"<!DOCTYPE html>
<html>
<head>
    <title>WebGuard Audit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .threat {{ background-color: #ffcccc; }}
        .suspicious {{ background-color: #ffffcc; }}
        .summary-box {{ background: #f0f0f0; padding: 20px; border-radius: 8px; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>WebGuard Audit Report</h1>
    <p>Generated: {}</p>
    
    <div class="summary-box">
        <h2>Summary</h2>
        <p><strong>Total Requests:</strong> {}</p>
        <p><strong>Confirmed Threats:</strong> {}</p>
        <p><strong>Likely Threats:</strong> {}</p>
        <p><strong>Suspicious:</strong> {}</p>
    </div>
    
    <h2>Top Threats</h2>
    <table>
        <tr>
            <th>Time</th>
            <th>IP</th>
            <th>Method</th>
            <th>URI</th>
            <th>Score</th>
            <th>Classification</th>
        </tr>"#,
            report.metadata.generated_at.to_rfc3339(),
            report.summary.total_requests,
            report.summary.confirmed_threat_count,
            report.summary.likely_threat_count,
            report.summary.suspicious_count
        )?;
        
        for threat in report.top_threats.iter().take(50) {
            let class = match threat.classification {
                ThreatClassification::ConfirmedThreat | ThreatClassification::LikelyThreat => "threat",
                ThreatClassification::Suspicious => "suspicious",
                _ => "",
            };
            writeln!(file, r#"        <tr class="{}">
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{:.2}</td>
            <td>{:?}</td>
        </tr>"#,
                class,
                threat.entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                threat.entry.remote_addr,
                threat.entry.method,
                threat.entry.uri,
                threat.threat_score,
                threat.classification
            )?;
        }
        
        writeln!(file, r#"    </table>
</body>
</html>"#)?;
        
        Ok(())
    }
}

/// Run audit mode
pub async fn run_audit_mode(
    config: AuditConfig,
    mesh: Arc<Mutex<HostMeshCognition>>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting WebGuard Audit Mode");
    info!("Log files to analyze: {:?}", config.log_paths);
    
    let psi = mesh.lock().unwrap().get_shared_psi();
    let mut engine = AuditEngine::new(config.clone(), psi);
    
    let start_time = std::time::Instant::now();
    let mut total_entries = 0;
    
    // Analyze each log file
    for path in &config.log_paths {
        // Support glob patterns
        if path.to_string_lossy().contains('*') {
            for entry in glob::glob(&path.to_string_lossy())? {
                if let Ok(p) = entry {
                    total_entries += engine.analyze_file(&p)?;
                }
            }
        } else {
            total_entries += engine.analyze_file(path)?;
        }
    }
    
    let duration = start_time.elapsed().as_secs_f64();
    
    info!("Analysis complete: {} entries in {:.2}s ({:.0} entries/sec)",
        total_entries, duration, total_entries as f64 / duration);
    
    // Generate and export report
    let report = engine.generate_report(duration);
    
    info!("Report Summary:");
    info!("  - Total Requests: {}", report.summary.total_requests);
    info!("  - Confirmed Threats: {}", report.summary.confirmed_threat_count);
    info!("  - Likely Threats: {}", report.summary.likely_threat_count);
    info!("  - Suspicious: {}", report.summary.suspicious_count);
    info!("  - Suspicious IPs: {}", report.suspicious_ips.len());
    
    engine.export_report(&report, &config.report_path, &config.report_format)?;
    info!("Report saved to: {:?}", config.report_path);
    
    // Optionally learn from audit
    if config.learn_from_audit {
        info!("Learning from audit results...");
        // TODO: Feed high-confidence results back to PSI
    }
    
    Ok(())
}
