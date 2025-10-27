
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
    v[0] = (wrc.min(50.0) / 50.0);
    v[1] = (mpr.min(10.0) / 10.0);
    v[2] = (nth.min(10.0) / 10.0);
    v[3] = addr_entropy;
    v[4] = (endpoints.min(20.0) / 20.0);
    v[5] = (mod_unusual.min(20.0) / 20.0);
    v[6] = (op_vm_write.min(20.0) / 20.0);
    v[7] = (ptrace.min(10.0) / 10.0);
    v[8] = (pvwrite.min(20.0) / 20.0);
    v[9] = serialized_score;
    v[10] = payload_entropy;
    v[11] = (legacy_payload_size.min(200000.0) / 200000.0);
    v[12] = admin_flag;
    v[13] = endpoint_rarity;

    // New comprehensive features
    v[14] = (network_connections.min(50.0) / 50.0);
    v[15] = (file_operations.min(100.0) / 100.0);
    v[16] = (memory_usage.min(100.0) / 100.0);
    v[17] = (cpu_usage.min(100.0) / 100.0);
    v[18] = (payload_size.min(10000.0) / 10000.0);
    v[19] = (entropy.min(10.0) / 10.0);
    v[20] = (suspicious_patterns.min(20.0) / 20.0);
    v[21] = process_risk_score;
    v[22] = (stack_violations.min(10.0) / 10.0);
    v[23] = (heap_allocations.min(2000.0) / 2000.0);
    v[24] = (memory_violations.min(10.0) / 10.0);
    v[25] = (system_calls.min(50.0) / 50.0);

    // PID-based features (normalized)
    v[26] = ((pid % 1000.0) / 1000.0);
    v[27] = if pid > 2000.0 { 1.0 } else { 0.0 }; // High PID indicator

    // Fill remaining dimensions with derived features
    for i in 28..cfg.embed_dim {
        let idx = i - 28;
        match idx % 4 {
            0 => v[i] = (v[14] * v[15]).min(1.0), // Network * File operations
            1 => v[i] = (v[16] * v[17]).min(1.0), // Memory * CPU usage
            2 => v[i] = (v[18] * v[19]).min(1.0), // Payload size * Entropy
            3 => v[i] = (v[20] * v[21]).min(1.0), // Suspicious patterns * Process risk
            _ => v[i] = 0.0,
        }
    }

    // L2-normalize
    let norm: f32 = v.iter().map(|x| x*x).sum::<f32>().sqrt().max(1e-6);
    for i in 0..v.len() { v[i] = v[i] / norm; }
    Ok(v)
}
