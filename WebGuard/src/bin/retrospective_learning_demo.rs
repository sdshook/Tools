/// Demonstration of WebGuard's Retrospective Learning System
/// 
/// This demo shows how the system learns from false negatives - missed threats
/// that are discovered later. This mimics how humans learn more from mistakes
/// than from successes.

use std::time::{SystemTime, UNIX_EPOCH};
use webguard::{
    mesh_cognition::{HostMeshCognition, WebServiceType},
    retrospective_learning::ThreatDiscoveryMethod,
    featurizer,
    config::Config,
};

fn main() {
    env_logger::init();
    
    println!("🧠 WebGuard Retrospective Learning System Demo");
    println!("===============================================");
    println!("Demonstrating how the system learns from missed threats (false negatives)");
    println!();

    // Initialize the mesh cognition system
    let mut mesh = HostMeshCognition::new(0.1, 0.7, 0.5);
    
    // Register some web services
    let apache_service = mesh.register_service(WebServiceType::Apache, 1234);
    let nginx_service = mesh.register_service(WebServiceType::Nginx, 5678);
    
    println!("📊 Registered services: {} and {}", apache_service, nginx_service);
    println!();

    // Simulate some normal traffic that was correctly classified
    println!("🔍 Phase 1: Processing normal traffic (correctly classified)");
    simulate_normal_traffic(&mesh);
    
    // Simulate missed threats that were discovered later
    println!("⚠️  Phase 2: Reporting missed threats discovered through various methods");
    simulate_missed_threats(&mesh);
    
    // Show learning statistics
    println!("📈 Phase 3: Retrospective learning statistics");
    show_learning_statistics(&mesh);
    
    // Apply retrospective learning
    println!("🎓 Phase 4: Applying retrospective learning");
    apply_retrospective_learning(&mesh);
    
    // Test threat score adjustments
    println!("🔧 Phase 5: Testing threat score adjustments");
    test_threat_score_adjustments(&mesh);
    
    // Export patterns for analysis
    println!("📋 Phase 6: Exporting missed threat patterns");
    export_threat_patterns(&mesh);
    
    println!();
    println!("✅ Demo completed! The system has learned from past mistakes.");
    println!("   Future similar patterns will be scored higher based on retrospective learning.");
}

fn simulate_normal_traffic(mesh: &HostMeshCognition) {
    let config = Config::default();
    
    // Simulate some benign requests that were correctly classified
    let benign_requests = vec![
        "GET /index.html HTTP/1.1",
        "POST /api/login HTTP/1.1",
        "GET /static/style.css HTTP/1.1",
        "GET /favicon.ico HTTP/1.1",
    ];
    
    for request in benign_requests {
        let features = featurizer::extract_features(request, &config);
        println!("  ✓ Processed benign request: {} (features extracted)", request);
    }
    
    println!("  → {} benign requests processed correctly", 4);
    println!();
}

fn simulate_missed_threats(mesh: &HostMeshCognition) {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    
    // Simulate missed threats discovered through different methods
    let missed_threats = vec![
        MissedThreatScenario {
            description: "SQL injection attempt missed during initial scan",
            original_request: "GET /search?q='; DROP TABLE users; -- HTTP/1.1",
            original_timestamp: current_time - 86400.0 * 7.0, // 7 days ago
            discovery_timestamp: current_time - 86400.0 * 1.0, // 1 day ago
            original_score: 0.15, // Originally scored as low threat
            actual_threat: 0.95,  // Actually very high threat
            discovery_method: ThreatDiscoveryMethod::SecurityAudit,
            consequence_severity: 0.9, // High severity - could have compromised database
        },
        MissedThreatScenario {
            description: "XSS payload in user comment overlooked",
            original_request: "POST /comment HTTP/1.1\r\nContent: <script>alert('xss')</script>",
            original_timestamp: current_time - 86400.0 * 3.0, // 3 days ago
            discovery_timestamp: current_time - 86400.0 * 0.5, // 12 hours ago
            original_score: 0.25,
            actual_threat: 0.8,
            discovery_method: ThreatDiscoveryMethod::UserReport,
            consequence_severity: 0.6, // Medium severity
        },
        MissedThreatScenario {
            description: "Directory traversal attempt not detected",
            original_request: "GET /../../etc/passwd HTTP/1.1",
            original_timestamp: current_time - 86400.0 * 5.0, // 5 days ago
            discovery_timestamp: current_time - 86400.0 * 2.0, // 2 days ago
            original_score: 0.1,
            actual_threat: 0.85,
            discovery_method: ThreatDiscoveryMethod::IncidentResponse,
            consequence_severity: 0.8, // High severity - file system access
        },
        MissedThreatScenario {
            description: "Command injection in API parameter",
            original_request: "POST /api/process HTTP/1.1\r\nContent: {\"cmd\": \"ls; rm -rf /\"}",
            original_timestamp: current_time - 86400.0 * 2.0, // 2 days ago
            discovery_timestamp: current_time - 3600.0, // 1 hour ago
            original_score: 0.2,
            actual_threat: 1.0, // Maximum threat level
            discovery_method: ThreatDiscoveryMethod::ForensicAnalysis,
            consequence_severity: 1.0, // Maximum severity - system compromise
        },
    ];
    
    for (i, scenario) in missed_threats.iter().enumerate() {
        println!("  🚨 Missed Threat #{}: {}", i + 1, scenario.description);
        println!("     Original request: {}", scenario.original_request);
        println!("     Original score: {:.2} → Actual threat: {:.2}", 
                 scenario.original_score, scenario.actual_threat);
        println!("     Discovery method: {:?}", scenario.discovery_method);
        println!("     Consequence severity: {:.2}", scenario.consequence_severity);
        
        // Extract features from the missed threat
        let config = Config::default();
        let features = featurizer::extract_features(&scenario.original_request, &config);
        let feature_vector: Vec<f32> = features.iter().map(|&f| f as f32).collect();
        
        // Report the missed threat to the system
        mesh.report_missed_threat(
            scenario.original_timestamp,
            scenario.discovery_timestamp,
            scenario.original_score,
            scenario.actual_threat,
            feature_vector,
            scenario.discovery_method.clone(),
            scenario.consequence_severity,
        );
        
        println!("     ✓ Added to retrospective learning system");
        println!();
    }
}

fn show_learning_statistics(mesh: &HostMeshCognition) {
    if let Some(stats) = mesh.get_retrospective_learning_stats() {
        println!("  📊 Learning Statistics:");
        println!("     Total missed threats processed: {}", stats.total_missed_threats_processed);
        println!("     Average discovery delay: {:.1} hours", stats.avg_discovery_delay / 3600.0);
        println!("     Average consequence severity: {:.2}", stats.avg_consequence_severity);
        println!("     EQ/IQ adjustments made: {}", stats.eq_iq_adjustments_made);
        println!("     Memory corrections applied: {}", stats.memory_corrections_applied);
        println!("     Patterns reinforced: {}", stats.patterns_reinforced);
    } else {
        println!("  ❌ Could not retrieve learning statistics");
    }
    println!();
}

fn apply_retrospective_learning(mesh: &HostMeshCognition) {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    
    println!("  🎓 Applying retrospective learning to EQ/IQ regulator and memory systems...");
    mesh.apply_retrospective_learning(current_time);
    
    // Show updated statistics
    if let Some(stats) = mesh.get_retrospective_learning_stats() {
        println!("     ✓ EQ/IQ adjustments applied: {}", stats.eq_iq_adjustments_made);
        println!("     ✓ Memory corrections applied: {}", stats.memory_corrections_applied);
    }
    println!();
}

fn test_threat_score_adjustments(mesh: &HostMeshCognition) {
    let config = Config::default();
    
    // Test patterns similar to missed threats
    let test_requests = vec![
        ("SQL injection variant", "GET /search?q=1' OR '1'='1 HTTP/1.1"),
        ("XSS variant", "POST /comment HTTP/1.1\r\nContent: <img src=x onerror=alert(1)>"),
        ("Directory traversal variant", "GET /../../../windows/system32/config/sam HTTP/1.1"),
        ("Command injection variant", "POST /api/exec HTTP/1.1\r\nContent: {\"cmd\": \"cat /etc/shadow\"}"),
        ("Benign request", "GET /about.html HTTP/1.1"),
    ];
    
    println!("  🔧 Testing threat score adjustments based on retrospective learning:");
    
    for (description, request) in test_requests {
        let features = featurizer::extract_features(request, &config);
        let feature_vector: Vec<f32> = features.iter().map(|&f| f as f32).collect();
        
        let base_score = 0.3; // Simulated base threat score
        let adjusted_score = mesh.get_retrospective_threat_adjustment(&feature_vector, base_score);
        
        let adjustment = adjusted_score - base_score;
        let adjustment_str = if adjustment > 0.1 {
            format!("📈 +{:.2}", adjustment)
        } else if adjustment > 0.01 {
            format!("📊 +{:.2}", adjustment)
        } else {
            "➡️  No change".to_string()
        };
        
        println!("     {}: {:.2} → {:.2} {}", 
                 description, base_score, adjusted_score, adjustment_str);
    }
    println!();
}

fn export_threat_patterns(mesh: &HostMeshCognition) {
    let patterns = mesh.export_missed_threat_patterns();
    
    println!("  📋 Exported {} missed threat patterns for analysis:", patterns.len());
    
    for (i, pattern) in patterns.iter().enumerate() {
        println!("     Pattern #{}: ", i + 1);
        if let Some(discovery_delay) = pattern.get("discovery_delay_hours") {
            println!("       Discovery delay: {} hours", discovery_delay);
        }
        if let Some(severity) = pattern.get("consequence_severity") {
            println!("       Consequence severity: {}", severity);
        }
        if let Some(method) = pattern.get("discovery_method") {
            println!("       Discovery method: {}", method);
        }
    }
    
    println!("     💾 These patterns can be exported to JSON/CSV for further analysis");
    println!();
}

#[derive(Debug)]
struct MissedThreatScenario {
    description: String,
    original_request: String,
    original_timestamp: f64,
    discovery_timestamp: f64,
    original_score: f32,
    actual_threat: f32,
    discovery_method: ThreatDiscoveryMethod,
    consequence_severity: f32,
}