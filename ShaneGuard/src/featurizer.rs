
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
    let wrc = telemetry.get("write_remote").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let mpr = telemetry.get("mprotect_rwx").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let nth = telemetry.get("new_threads_unexpected").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let entropy = telemetry.get("addr_entropy").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
    let endpoints = telemetry.get("unique_endpoints").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let mod_unusual = telemetry.get("module_loads_unusual").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let op_vm_write = telemetry.get("open_proc_vmwrite").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let ptrace = telemetry.get("ptrace_attempts").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let pvwrite = telemetry.get("process_vm_writev").and_then(|x| x.as_i64()).unwrap_or(0) as f32;

    // application-layer payload fields
    let payload = telemetry.get("request_body").and_then(|x| x.as_str()).unwrap_or("");
    let payload_bytes = payload.as_bytes();
    let payload_size = payload_bytes.len() as f32;
    let payload_entropy = estimate_entropy(payload_bytes);
    let serialized_score = serialized_blob_score_from_text(payload);

    // admin endpoint and endpoint rarity (if present)
    let admin_flag = telemetry.get("admin_api_flag").and_then(|x| x.as_i64()).unwrap_or(0) as f32;
    let endpoint_rarity = telemetry.get("endpoint_rarity").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;

    v[0] = (wrc.min(50.0) / 50.0) as f32;
    v[1] = (mpr.min(10.0) / 10.0) as f32;
    v[2] = (nth.min(10.0) / 10.0) as f32;
    v[3] = entropy;
    v[4] = (endpoints.min(20.0) / 20.0) as f32;
    v[5] = (mod_unusual.min(20.0) / 20.0) as f32;
    v[6] = (op_vm_write.min(20.0) / 20.0) as f32;
    v[7] = (ptrace.min(10.0) / 10.0) as f32;
    v[8] = (pvwrite.min(20.0) / 20.0) as f32;

    v[9] = serialized_score;
    v[10] = payload_entropy;
    v[11] = (payload_size.min(200000.0) / 200000.0) as f32;
    v[12] = admin_flag;
    v[13] = endpoint_rarity;

    for i in 14..cfg.embed_dim {
        v[i] = 0.0;
    }

    // L2-normalize
    let norm: f32 = v.iter().map(|x| x*x).sum::<f32>().sqrt().max(1e-6);
    for i in 0..v.len() { v[i] = v[i] / norm; }
    Ok(v)
}
