//! Proxy Mode - HTTP Reverse Proxy with Inline Analysis
//!
//! Operates as a reverse proxy, analyzing all HTTP requests before forwarding
//! to the backend server. Can optionally block detected threats.
//!
//! Supports multiple port mappings for collective immunity across different
//! web servers on the same host.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use hyper::{Body, Client, Request, Response, Server, StatusCode};
use hyper::client::HttpConnector;
use hyper::service::{make_service_fn, service_fn};
use tracing::{info, warn, error, debug};

use webguard::runtime_config::{ProxyConfig, ProxyMapping, LoggingConfig};
use crate::semantic_normalizer::SemanticNormalizer;
use crate::embedding_learner::EmbeddingLearner;
use crate::mesh_cognition::{HostMeshCognition, WebServiceType};
use crate::config::Config;
use webguard::detection_logger::{DetectionLogger, LogEntry, Severity};

/// Proxy state shared across request handlers
struct ProxyState {
    /// Global config (timeout, blocking mode, threshold)
    config: ProxyConfig,
    /// This specific mapping (listen -> backend)
    mapping: ProxyMapping,
    app_config: Config,
    normalizer: SemanticNormalizer,
    embedding_learner: EmbeddingLearner,
    mesh: Arc<Mutex<HostMeshCognition>>,
    client: Client<HttpConnector>,
    stats: Mutex<ProxyStats>,
    /// Service ID for this proxy mapping (for collective immunity)
    service_id: String,
    /// Detection logger for file output
    logger: Option<DetectionLogger>,
}

/// Proxy statistics
#[derive(Debug, Default)]
struct ProxyStats {
    total_requests: u64,
    blocked_requests: u64,
    suspicious_requests: u64,
    total_latency_ms: u64,
}

impl ProxyState {
    fn new(
        config: ProxyConfig,
        mapping: ProxyMapping,
        mesh: Arc<Mutex<HostMeshCognition>>,
        service_id: String,
        logger: Option<DetectionLogger>,
    ) -> Self {
        Self {
            app_config: Config::load_default(),
            normalizer: SemanticNormalizer::new(),
            embedding_learner: EmbeddingLearner::new(),
            mesh,
            client: Client::new(),
            stats: Mutex::new(ProxyStats::default()),
            config,
            mapping,
            service_id,
            logger,
        }
    }
    
    /// Analyze a request and return threat assessment
    fn analyze_request(&self, req: &Request<Body>) -> (f32, f32, bool) {
        // Build analysis string from request
        let method = req.method().as_str();
        let uri = req.uri().to_string();
        let user_agent = req.headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        
        let analysis_str = format!("{} {} UA:{}", method, uri, user_agent);
        
        // Normalize
        let normalized = self.normalizer.normalize(analysis_str.as_bytes());
        let normalized_str = String::from_utf8_lossy(&normalized);
        
        // Get embedding and threat score
        let embedding = self.embedding_learner.embed(&normalized_str);
        let threat_score = self.embedding_learner.threat_score(&embedding);
        
        // Convert to fixed array
        let mut feature_arr = [0.0f32; 32];
        for i in 0..embedding.len().min(32) {
            feature_arr[i] = embedding[i];
        }
        
        // Query mesh cognition
        let (similarity, valence) = if let Ok(m) = self.mesh.try_lock() {
            let service_id = m.get_active_services().first()
                .map(|s| s.0.clone())
                .unwrap_or_else(|| "proxy".to_string());
            
            if let Some(service_memory) = m.get_service_memory(&service_id) {
                let bdh = service_memory.lock().unwrap();
                let sims = bdh.retrieve_similar(&feature_arr, 5);
                if !sims.is_empty() {
                    let top_sim = sims[0].1;
                    let sum_val: f32 = sims.iter().map(|(t, s)| t.valence * s).sum();
                    let sum_s: f32 = sims.iter().map(|(_, s)| *s).sum();
                    let avg_val = if sum_s > 0.0 { sum_val / (sum_s + 1e-6) } else { threat_score };
                    (top_sim, avg_val)
                } else {
                    (0.0, threat_score)
                }
            } else {
                (0.0, threat_score)
            }
        } else {
            (0.0, threat_score)
        };
        
        // Combined threat score
        let combined_score = (threat_score + valence.max(0.0)) / 2.0;
        let should_block = self.config.blocking_mode && combined_score >= self.config.block_threshold;
        
        (combined_score, similarity, should_block)
    }
    
    /// Learn from a request (after seeing the response)
    fn learn_from_request(&self, uri: &str, features: &[f32; 32], threat_score: f32, was_blocked: bool, status: u16) {
        if let Ok(m) = self.mesh.try_lock() {
            let service_id = m.get_active_services().first()
                .map(|s| s.0.clone())
                .unwrap_or_else(|| "proxy".to_string());
            
            if let Some(service_memory) = m.get_service_memory(&service_id) {
                let mut bdh = service_memory.lock().unwrap();
                
                // Determine reward based on outcome
                let reward = if was_blocked {
                    // We blocked it - assume we were right (positive for high threat score)
                    if threat_score > 0.5 { 0.5 } else { -0.2 }
                } else if status >= 400 && status < 500 {
                    // Client error - might indicate attack attempt
                    0.3
                } else if status >= 500 {
                    // Server error - might indicate successful attack
                    0.5
                } else {
                    // Normal response
                    -0.1
                };
                
                let max_sim = bdh.max_similarity(features);
                if max_sim < self.app_config.tau_novel {
                    // Novel pattern
                    let valence = if threat_score > 0.5 { threat_score } else { -0.1 };
                    bdh.add_trace(*features, valence);
                } else {
                    // Update existing
                    let similar: Vec<(String, f32)> = bdh.retrieve_similar(features, 3)
                        .into_iter()
                        .map(|(t, s)| (t.id.clone(), s))
                        .collect();
                    
                    for (trace_id, similarity) in similar {
                        bdh.reward_update(&trace_id, reward * similarity, self.app_config.eta);
                    }
                }
            }
            
            // Cross-service learning for high threats
            if threat_score > 0.6 {
                let service_id = m.get_active_services().first()
                    .map(|s| s.0.clone())
                    .unwrap_or_else(|| "proxy".to_string());
                m.cross_service_learning(&service_id, features, threat_score, 1.0);
            }
        }
    }
}

/// Handle a single request
async fn handle_request(
    req: Request<Body>,
    state: Arc<ProxyState>,
    client_addr: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    let start_time = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let uri_string = uri.to_string();
    
    // Analyze the request
    let (threat_score, similarity, should_block) = state.analyze_request(&req);
    
    // Update stats
    {
        let mut stats = state.stats.lock().unwrap();
        stats.total_requests += 1;
        if should_block {
            stats.blocked_requests += 1;
        } else if threat_score > 0.4 {
            stats.suspicious_requests += 1;
        }
    }
    
    // Extract user agent for logging
    let user_agent = req.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    
    // Block if threshold exceeded
    if should_block {
        warn!(
            "BLOCKED: {} {} {} - threat_score={:.3}, similarity={:.3}",
            client_addr, method, uri, threat_score, similarity
        );
        
        // Log to detection file
        if let Some(ref logger) = state.logger {
            let entry = DetectionLogger::create_entry(
                &state.mapping.name,
                &client_addr.ip().to_string(),
                method.as_str(),
                uri.path(),
                threat_score,
                true,
                Some("threshold_exceeded".to_string()),
                user_agent.clone(),
                Some(403),
            );
            logger.log_detection(&entry);
        }
        
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("X-WebGuard-Blocked", "true")
            .header("X-WebGuard-Score", format!("{:.3}", threat_score))
            .body(Body::from("Request blocked by WebGuard security analysis"))
            .unwrap());
    }
    
    // Log suspicious but allowed requests
    if threat_score > 0.4 {
        warn!(
            "SUSPICIOUS (allowed): {} {} {} - threat_score={:.3}",
            client_addr, method, uri, threat_score
        );
        
        // Log to detection file (suspicious)
        if let Some(ref logger) = state.logger {
            let entry = DetectionLogger::create_entry(
                &state.mapping.name,
                &client_addr.ip().to_string(),
                method.as_str(),
                uri.path(),
                threat_score,
                false,
                Some("suspicious".to_string()),
                user_agent.clone(),
                None, // response status not known yet
            );
            logger.log_detection(&entry);
        }
    } else {
        debug!(
            "ALLOWED: {} {} {} - threat_score={:.3}",
            client_addr, method, uri, threat_score
        );
    }
    
    // Forward to backend (use mapping's backend_addr)
    let backend_uri = format!("http://{}{}", state.mapping.backend_addr, uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"));
    
    let mut backend_req = Request::builder()
        .method(req.method())
        .uri(&backend_uri);
    
    // Copy headers
    for (name, value) in req.headers() {
        if name != "host" {
            backend_req = backend_req.header(name, value);
        }
    }
    
    // Add WebGuard headers
    backend_req = backend_req
        .header("X-WebGuard-Score", format!("{:.3}", threat_score))
        .header("X-Forwarded-For", client_addr.ip().to_string());
    
    let backend_req = match backend_req.body(req.into_body()) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to build backend request: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Failed to forward request"))
                .unwrap());
        }
    };
    
    // Forward request
    let response = match state.client.request(backend_req).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Backend request failed: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("Backend error: {}", e)))
                .unwrap());
        }
    };
    
    let status = response.status().as_u16();
    let latency = start_time.elapsed().as_millis() as u64;
    
    // Update latency stats
    {
        let mut stats = state.stats.lock().unwrap();
        stats.total_latency_ms += latency;
    }
    
    // Log to access file (all requests)
    if let Some(ref logger) = state.logger {
        if logger.access_logging_enabled() {
            let entry = DetectionLogger::create_entry(
                &state.mapping.name,
                &client_addr.ip().to_string(),
                method.as_str(),
                uri.path(),
                threat_score,
                false,
                None,
                user_agent,
                Some(status),
            );
            logger.log_access(&entry);
        }
    }
    
    // Learn from the request/response
    let mut feature_arr = [0.0f32; 32];
    let normalized = state.normalizer.normalize(uri_string.as_bytes());
    let embedding = state.embedding_learner.embed(&String::from_utf8_lossy(&normalized));
    for i in 0..embedding.len().min(32) {
        feature_arr[i] = embedding[i];
    }
    state.learn_from_request(&uri_string, &feature_arr, threat_score, false, status);
    
    // Add response headers
    let (parts, body) = response.into_parts();
    let mut response = Response::from_parts(parts, body);
    
    response.headers_mut().insert(
        "X-WebGuard-Latency",
        format!("{}ms", latency).parse().unwrap(),
    );
    
    Ok(response)
}

/// Parse server type string to WebServiceType
fn parse_server_type(s: &str) -> WebServiceType {
    match s.to_lowercase().as_str() {
        "nginx" => WebServiceType::Nginx,
        "apache" => WebServiceType::Apache,
        "iis" => WebServiceType::IIS,
        "nodejs" | "node" => WebServiceType::NodeJS,
        _ => WebServiceType::Generic,
    }
}

/// Run a single proxy server for one mapping
async fn run_single_proxy(
    config: ProxyConfig,
    mapping: ProxyMapping,
    mesh: Arc<Mutex<HostMeshCognition>>,
    service_id: String,
    logger: Option<DetectionLogger>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = mapping.listen_addr.parse()?;
    
    let state = Arc::new(ProxyState::new(
        config.clone(),
        mapping.clone(),
        mesh,
        service_id.clone(),
        logger,
    ));
    
    // Stats reporting task for this proxy
    let stats_state = state.clone();
    let proxy_name = mapping.name.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let stats = stats_state.stats.lock().unwrap();
            let avg_latency = if stats.total_requests > 0 {
                stats.total_latency_ms as f64 / stats.total_requests as f64
            } else {
                0.0
            };
            info!(
                "[{}] Stats: {} requests, {} blocked, {} suspicious, avg latency {:.1}ms",
                proxy_name,
                stats.total_requests,
                stats.blocked_requests,
                stats.suspicious_requests,
                avg_latency
            );
        }
    });
    
    let make_svc = make_service_fn(move |conn: &hyper::server::conn::AddrStream| {
        let state = state.clone();
        let client_addr = conn.remote_addr();
        
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle_request(req, state.clone(), client_addr)
            }))
        }
    });
    
    let server = Server::bind(&addr).serve(make_svc);
    
    info!("[{}] Proxy listening on http://{} -> {}", 
          mapping.name, addr, mapping.backend_addr);
    
    server.await?;
    
    Ok(())
}

/// Run proxy mode with multiple port mappings
/// 
/// All proxies share the same mesh cognition (PSI) for collective immunity:
/// - Threat detected on port 80 → protects ports 8080, 443, etc.
/// - Learning is shared across all web servers
pub async fn run_proxy_mode(
    config: ProxyConfig,
    mesh: Arc<Mutex<HostMeshCognition>>,
    logging_config: LoggingConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting WebGuard Multi-Port Proxy Mode");
    info!("Blocking mode: {}", config.blocking_mode);
    if config.blocking_mode {
        info!("Block threshold: {}", config.block_threshold);
    }
    
    // Initialize detection logger
    let logger = match DetectionLogger::new(logging_config.clone()) {
        Ok(l) => {
            if l.detection_logging_enabled() {
                info!("Detection logging enabled: {:?}", logging_config.detection_log);
            }
            if l.access_logging_enabled() {
                info!("Access logging enabled: {:?}", logging_config.access_log);
            }
            info!("Log format: {:?}", logging_config.output_format);
            Some(l)
        }
        Err(e) => {
            error!("Failed to initialize detection logger: {}", e);
            None
        }
    };
    
    // Register a service for each proxy mapping
    let service_ids: Vec<String> = {
        let mut m = mesh.lock().unwrap();
        config.mappings.iter().enumerate().map(|(idx, mapping)| {
            let server_type = parse_server_type(&mapping.server_type);
            let pid = std::process::id() as i32 + idx as i32;
            let service_id = m.register_service(server_type, pid);
            info!("[{}] Registered service {} ({} -> {})", 
                  mapping.name, service_id, mapping.listen_addr, mapping.backend_addr);
            service_id
        }).collect()
    };
    
    info!("");
    info!("╔═══════════════════════════════════════════════════════════════════╗");
    info!("║                 COLLECTIVE IMMUNITY ENABLED                        ║");
    info!("║  All {} proxy mappings share the same PSI for cross-protection   ║", config.mappings.len());
    info!("╚═══════════════════════════════════════════════════════════════════╝");
    info!("");
    
    // Spawn a proxy server for each mapping
    let mut handles = Vec::new();
    
    for (mapping, service_id) in config.mappings.iter().zip(service_ids.into_iter()) {
        let config_clone = config.clone();
        let mapping_clone = mapping.clone();
        let mesh_clone = mesh.clone();
        let logger_clone = logger.clone();
        
        let handle = tokio::spawn(async move {
            if let Err(e) = run_single_proxy(config_clone, mapping_clone, mesh_clone, service_id, logger_clone).await {
                error!("Proxy error: {}", e);
            }
        });
        
        handles.push(handle);
    }
    
    // Wait for all proxies (they run forever unless there's an error)
    for handle in handles {
        let _ = handle.await;
    }
    
    Ok(())
}


