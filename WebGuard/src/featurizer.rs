
use crate::config::Config;
use anyhow::Result;
use serde_json::Value;

// Estimate Shannon entropy of bytes (normalized)
fn estimate_entropy(bytes: &[u8]) -> f32 {
    if bytes.len() == 0 { return 0.0; }
    let mut counts = [0usize; 256];
    for &b in bytes { counts[b as usize] += 1; }
    let len = bytes.len() as f32;
    let mut ent = 0.0f32;
    for c in counts.iter() {
        if *c == 0 { continue; }
        let p = (*c as f32) / len;
        ent -= p * p.max(1e-12).ln() / std::f32::consts::LN_2; // bits
    }
    let norm = (ent / 8.0).max(0.0).min(1.0);
    norm
}

// Heuristic detection of long base64 runs and known serialized markers
fn serialized_blob_score_from_text(s: &str) -> f32 {
    let mut max_run = 0usize;
    let mut cur = 0usize;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=' {
            cur += 1;
            if cur > max_run { max_run = cur; }
        } else {
            cur = 0;
        }
    }
    if max_run >= 300 { return 0.98; }
    if max_run >= 200 { return 0.9; }
    if max_run >= 120 { return 0.7; }
    let s_low = s.to_lowercase();
    if s_low.contains("binaryformatter") || s_low.contains("<binary>") || s_low.contains("0xaced") || s_low.contains("javaserialized") {
        return 0.85;
    }
    let ent = estimate_entropy(s.as_bytes());
    if ent > 0.85 { return 0.6; }
    if ent > 0.7 { return 0.4; }
    0.0
}

pub fn featurize_from_telemetry(telemetry: &Value, cfg: &Config) -> Result<Vec<f32>> {
    featurize_from_telemetry_enhanced(telemetry, cfg, None)
}

pub fn featurize_from_telemetry_enhanced(telemetry: &Value, cfg: &Config, temporal_context: Option<&[Value]>) -> Result<Vec<f32>> {
    let mut v = vec![0.0f32; cfg.embed_dim];
    
    // Legacy system-level features (for backward compatibility)
    let wrc = telemetry.get("write_remote").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let mpr = telemetry.get("mprotect_rwx").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let nth = telemetry.get("new_threads_unexpected").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let addr_entropy = telemetry.get("addr_entropy").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
    let endpoints = telemetry.get("unique_endpoints").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let mod_unusual = telemetry.get("module_loads_unusual").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let op_vm_write = telemetry.get("open_proc_vmwrite").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let ptrace = telemetry.get("ptrace_attempts").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let pvwrite = telemetry.get("process_vm_writev").and_then(|x| x.as_i64()).unwrap_or(0) as f32;

    // New comprehensive telemetry features
    let pid = telemetry.get("pid").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let network_connections = telemetry.get("network_connections").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let file_operations = telemetry.get("file_operations").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let memory_usage = telemetry.get("memory_usage").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
    let cpu_usage = telemetry.get("cpu_usage").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
    let payload_size = telemetry.get("payload_size").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let entropy = telemetry.get("entropy").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;

    // Process suspicious patterns
    let suspicious_patterns = telemetry.get("suspicious_patterns")
        .and_then(|x| x.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0) as f32;

    // Process name analysis
    let process_name = telemetry.get("process_name").and_then(|x| x.as_str()).unwrap_or("");
    let process_risk_score = match process_name {
        "java" | "python" | "php" | "node" => 0.3,
        "apache" | "nginx" | "iis" => 0.2,
        "vulnerable_app" | "browser" | "media_player" => 0.8,
        _ => 0.1,
    };

    // Application-layer payload fields (legacy)
    let payload = telemetry.get("request_body").and_then(|x| x.as_str()).unwrap_or("");
    let payload_bytes = payload.as_bytes();
    let legacy_payload_size = payload_bytes.len() as f32;
    let payload_entropy = estimate_entropy(payload_bytes);
    let serialized_score = serialized_blob_score_from_text(payload);

    // Admin endpoint and endpoint rarity (if present)
    let admin_flag = telemetry.get("admin_api_flag").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let endpoint_rarity = telemetry.get("endpoint_rarity").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;

    // Additional threat indicators
    let stack_violations = telemetry.get("stack_canary_violations").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let heap_allocations = telemetry.get("heap_allocations").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let memory_violations = telemetry.get("memory_violations").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let system_calls = telemetry.get("system_calls").and_then(|x| x.as_i64()).unwrap_or(0) as f32;

    // Populate feature vector
    v[0] = wrc.min(50.0) / 50.0;
    v[1] = mpr.min(10.0) / 10.0;
    v[2] = nth.min(10.0) / 10.0;
    v[3] = addr_entropy;
    v[4] = endpoints.min(20.0) / 20.0;
    v[5] = mod_unusual.min(20.0) / 20.0;
    v[6] = op_vm_write.min(20.0) / 20.0;
    v[7] = ptrace.min(10.0) / 10.0;
    v[8] = pvwrite.min(20.0) / 20.0;
    v[9] = serialized_score;
    v[10] = payload_entropy;
    v[11] = legacy_payload_size.min(200000.0) / 200000.0;
    v[12] = admin_flag;
    v[13] = endpoint_rarity;

    // New comprehensive features
    v[14] = network_connections.min(50.0) / 50.0;
    v[15] = file_operations.min(100.0) / 100.0;
    v[16] = memory_usage.min(100.0) / 100.0;
    v[17] = cpu_usage.min(100.0) / 100.0;
    v[18] = payload_size.min(10000.0) / 10000.0;
    v[19] = entropy.min(10.0) / 10.0;
    v[20] = suspicious_patterns.min(20.0) / 20.0;
    v[21] = process_risk_score;
    v[22] = stack_violations.min(10.0) / 10.0;
    v[23] = heap_allocations.min(2000.0) / 2000.0;
    v[24] = memory_violations.min(10.0) / 10.0;
    v[25] = system_calls.min(50.0) / 50.0;

    // PID-based features (normalized)
    v[26] = (pid % 1000.0) / 1000.0;
    v[27] = if pid > 2000.0 { 1.0 } else { 0.0 }; // High PID indicator

    // Enhanced temporal and behavioral features
    let temporal_features = extract_temporal_features(temporal_context);
    let behavioral_features = extract_behavioral_features(telemetry);
    
    // Fill remaining dimensions with enhanced features
    let mut feature_idx = 28;
    
    // Add temporal features (if available)
    for (_i, &temp_feat) in temporal_features.iter().enumerate() {
        if feature_idx < cfg.embed_dim {
            v[feature_idx] = temp_feat;
            feature_idx += 1;
        }
    }
    
    // Add behavioral features
    for (_i, &behav_feat) in behavioral_features.iter().enumerate() {
        if feature_idx < cfg.embed_dim {
            v[feature_idx] = behav_feat;
            feature_idx += 1;
        }
    }
    
    // Fill remaining dimensions with derived features
    for i in feature_idx..cfg.embed_dim {
        let idx = i - feature_idx;
        match idx % 6 {
            0 => v[i] = (v[14] * v[15]).min(1.0), // Network * File operations
            1 => v[i] = (v[16] * v[17]).min(1.0), // Memory * CPU usage
            2 => v[i] = (v[18] * v[19]).min(1.0), // Payload size * Entropy
            3 => v[i] = (v[20] * v[21]).min(1.0), // Suspicious patterns * Process risk
            4 => v[i] = (v[0] + v[1] + v[2]).min(1.0), // Combined system threats
            5 => v[i] = (v[22] + v[24]).min(1.0), // Combined memory violations
            _ => v[i] = 0.0,
        }
    }

    // L2-normalize
    let norm: f32 = v.iter().map(|x| x*x).sum::<f32>().sqrt().max(1e-6);
    for i in 0..v.len() { v[i] = v[i] / norm; }
    Ok(v)
}

/// Extract temporal features from historical context
fn extract_temporal_features(temporal_context: Option<&[Value]>) -> Vec<f32> {
    let mut features = Vec::new();
    
    if let Some(context) = temporal_context {
        if context.len() >= 2 {
            // Temporal trend analysis
            let recent_activity = calculate_activity_trend(context);
            features.push(recent_activity);
            
            // Frequency analysis
            let frequency_score = calculate_frequency_patterns(context);
            features.push(frequency_score);
            
            // Anomaly detection in temporal sequence
            let anomaly_score = calculate_temporal_anomaly(context);
            features.push(anomaly_score);
            
            // Burst detection
            let burst_score = calculate_burst_activity(context);
            features.push(burst_score);
            
            // Periodicity detection
            let periodicity_score = calculate_periodicity(context);
            features.push(periodicity_score);
        }
    }
    
    // Pad with zeros if no temporal context
    while features.len() < 5 {
        features.push(0.0);
    }
    
    features
}

/// Extract behavioral features from current telemetry
fn extract_behavioral_features(telemetry: &Value) -> Vec<f32> {
    let mut features = Vec::new();
    
    // Multi-vector attack pattern detection
    let multi_vector_score = detect_multi_vector_attack(telemetry);
    features.push(multi_vector_score);
    
    // Privilege escalation indicators
    let privilege_escalation_score = detect_privilege_escalation(telemetry);
    features.push(privilege_escalation_score);
    
    // Data exfiltration patterns
    let exfiltration_score = detect_data_exfiltration(telemetry);
    features.push(exfiltration_score);
    
    // Lateral movement indicators
    let lateral_movement_score = detect_lateral_movement(telemetry);
    features.push(lateral_movement_score);
    
    // Persistence mechanism detection
    let persistence_score = detect_persistence_mechanisms(telemetry);
    features.push(persistence_score);
    
    // Evasion technique detection
    let evasion_score = detect_evasion_techniques(telemetry);
    features.push(evasion_score);
    
    features
}

/// Calculate activity trend from temporal context
fn calculate_activity_trend(context: &[Value]) -> f32 {
    if context.len() < 3 {
        return 0.0;
    }
    
    let mut activity_levels = Vec::new();
    for event in context {
        let activity = calculate_event_activity_level(event);
        activity_levels.push(activity);
    }
    
    // Calculate trend using simple linear regression
    let n = activity_levels.len() as f32;
    let sum_x: f32 = (0..activity_levels.len()).map(|i| i as f32).sum();
    let sum_y: f32 = activity_levels.iter().sum();
    let sum_xy: f32 = activity_levels.iter().enumerate()
        .map(|(i, &y)| i as f32 * y).sum();
    let sum_x2: f32 = (0..activity_levels.len()).map(|i| (i as f32).powi(2)).sum();
    
    let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x.powi(2));
    slope.max(-1.0).min(1.0) // Normalize slope
}

/// Calculate frequency patterns in temporal context
fn calculate_frequency_patterns(context: &[Value]) -> f32 {
    if context.len() < 5 {
        return 0.0;
    }
    
    let mut intervals = Vec::new();
    let mut last_timestamp = 0.0;
    
    for event in context {
        let timestamp = event.get("timestamp").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
        if last_timestamp > 0.0 {
            intervals.push(timestamp - last_timestamp);
        }
        last_timestamp = timestamp;
    }
    
    if intervals.is_empty() {
        return 0.0;
    }
    
    // Calculate coefficient of variation for intervals
    let mean = intervals.iter().sum::<f32>() / intervals.len() as f32;
    let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f32>() / intervals.len() as f32;
    let std_dev = variance.sqrt();
    
    if mean > 0.0 {
        (std_dev / mean).min(1.0) // High variation = suspicious
    } else {
        0.0
    }
}

/// Calculate temporal anomaly score
fn calculate_temporal_anomaly(context: &[Value]) -> f32 {
    if context.len() < 3 {
        return 0.0;
    }
    
    let current_event = &context[context.len() - 1];
    let current_activity = calculate_event_activity_level(current_event);
    
    // Calculate baseline from previous events
    let baseline_activity: f32 = context[..context.len()-1].iter()
        .map(|event| calculate_event_activity_level(event))
        .sum::<f32>() / (context.len() - 1) as f32;
    
    if baseline_activity > 0.0 {
        ((current_activity - baseline_activity) / baseline_activity).abs().min(1.0)
    } else {
        current_activity.min(1.0)
    }
}

/// Calculate burst activity score
fn calculate_burst_activity(context: &[Value]) -> f32 {
    if context.len() < 4 {
        return 0.0;
    }
    
    let window_size = 3;
    let mut max_burst: f32 = 0.0;
    
    for i in 0..=(context.len() - window_size) {
        let window_activity: f32 = context[i..i+window_size].iter()
            .map(|event| calculate_event_activity_level(event))
            .sum();
        max_burst = max_burst.max(window_activity);
    }
    
    (max_burst / window_size as f32).min(1.0)
}

/// Calculate periodicity score
fn calculate_periodicity(context: &[Value]) -> f32 {
    if context.len() < 6 {
        return 0.0;
    }
    
    let activity_levels: Vec<f32> = context.iter()
        .map(|event| calculate_event_activity_level(event))
        .collect();
    
    // Simple autocorrelation for period detection
    let mut max_correlation: f32 = 0.0;
    for lag in 1..=(activity_levels.len() / 2) {
        let correlation = calculate_autocorrelation(&activity_levels, lag);
        max_correlation = max_correlation.max(correlation);
    }
    
    max_correlation
}

/// Calculate activity level for a single event
fn calculate_event_activity_level(event: &Value) -> f32 {
    let network = event.get("network_connections").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let file_ops = event.get("file_operations").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let memory = event.get("memory_usage").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
    let cpu = event.get("cpu_usage").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
    
    ((network / 10.0) + (file_ops / 20.0) + (memory / 100.0) + (cpu / 100.0)).min(1.0)
}

/// Calculate autocorrelation for periodicity detection
fn calculate_autocorrelation(data: &[f32], lag: usize) -> f32 {
    if lag >= data.len() {
        return 0.0;
    }
    
    let n = data.len() - lag;
    let mean = data.iter().sum::<f32>() / data.len() as f32;
    
    let mut numerator = 0.0;
    let mut denominator = 0.0;
    
    for i in 0..n {
        numerator += (data[i] - mean) * (data[i + lag] - mean);
    }
    
    for &value in data {
        denominator += (value - mean).powi(2);
    }
    
    if denominator > 0.0 {
        numerator / denominator
    } else {
        0.0
    }
}

/// Detect multi-vector attack patterns
fn detect_multi_vector_attack(telemetry: &Value) -> f32 {
    let mut attack_vectors = 0;
    
    // Network-based attacks
    let network_connections = telemetry.get("network_connections").and_then(|x| x.as_i64()).unwrap_or(0);
    if network_connections > 10 {
        attack_vectors += 1;
    }
    
    // Memory-based attacks
    let memory_violations = telemetry.get("memory_violations").and_then(|x| x.as_i64()).unwrap_or(0);
    if memory_violations > 0 {
        attack_vectors += 1;
    }
    
    // File system attacks
    let file_operations = telemetry.get("file_operations").and_then(|x| x.as_i64()).unwrap_or(0);
    if file_operations > 50 {
        attack_vectors += 1;
    }
    
    // Process manipulation
    let system_calls = telemetry.get("system_calls").and_then(|x| x.as_i64()).unwrap_or(0);
    if system_calls > 20 {
        attack_vectors += 1;
    }
    
    (attack_vectors as f32 / 4.0).min(1.0)
}

/// Detect privilege escalation indicators
fn detect_privilege_escalation(telemetry: &Value) -> f32 {
    let mut escalation_score = 0.0;
    
    // Process spawning with elevated privileges
    let new_threads = telemetry.get("new_threads_unexpected").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    escalation_score += (new_threads / 5.0).min(0.3);
    
    // Memory protection changes
    let mprotect = telemetry.get("mprotect_rwx").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    escalation_score += (mprotect / 3.0).min(0.4);
    
    // System call anomalies
    let system_calls = telemetry.get("system_calls").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    escalation_score += (system_calls / 30.0).min(0.3);
    
    escalation_score.min(1.0)
}

/// Detect data exfiltration patterns
fn detect_data_exfiltration(telemetry: &Value) -> f32 {
    let mut exfiltration_score = 0.0;
    
    // High network activity
    let network_connections = telemetry.get("network_connections").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    exfiltration_score += (network_connections / 20.0).min(0.4);
    
    // Large payload sizes
    let payload_size = telemetry.get("payload_size").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    exfiltration_score += (payload_size / 5000.0).min(0.3);
    
    // High entropy data (encrypted/compressed)
    let entropy = telemetry.get("entropy").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
    exfiltration_score += (entropy / 8.0).min(0.3);
    
    exfiltration_score.min(1.0)
}

/// Detect lateral movement indicators
fn detect_lateral_movement(telemetry: &Value) -> f32 {
    let mut movement_score = 0.0;
    
    // Multiple unique endpoints
    let endpoints = telemetry.get("unique_endpoints").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    movement_score += (endpoints / 10.0).min(0.5);
    
    // Remote write operations
    let write_remote = telemetry.get("write_remote").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    movement_score += (write_remote / 5.0).min(0.3);
    
    // Process injection attempts
    let ptrace = telemetry.get("ptrace_attempts").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    movement_score += (ptrace / 3.0).min(0.2);
    
    movement_score.min(1.0)
}

/// Detect persistence mechanisms
fn detect_persistence_mechanisms(telemetry: &Value) -> f32 {
    let mut persistence_score = 0.0;
    
    // Unusual module loads
    let module_loads = telemetry.get("module_loads_unusual").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    persistence_score += (module_loads / 5.0).min(0.4);
    
    // File system modifications
    let file_operations = telemetry.get("file_operations").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    persistence_score += (file_operations / 100.0).min(0.3);
    
    // Process spawning
    let new_threads = telemetry.get("new_threads_unexpected").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    persistence_score += (new_threads / 8.0).min(0.3);
    
    persistence_score.min(1.0)
}

/// Detect evasion techniques
fn detect_evasion_techniques(telemetry: &Value) -> f32 {
    let mut evasion_score = 0.0;
    
    // Process VM manipulation
    let vm_write = telemetry.get("process_vm_writev").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    evasion_score += (vm_write / 5.0).min(0.3);
    
    // Memory protection manipulation
    let open_vm_write = telemetry.get("open_proc_vmwrite").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    evasion_score += (open_vm_write / 3.0).min(0.3);
    
    // High entropy payloads (obfuscation)
    let payload = telemetry.get("request_body").and_then(|x| x.as_str()).unwrap_or("");
    let payload_entropy = estimate_entropy(payload.as_bytes());
    evasion_score += (payload_entropy * 0.4).min(0.4);
    
    evasion_score.min(1.0)
}
