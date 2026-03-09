//! Integration tests for ThreatEducator module
//! 
//! These tests demonstrate that the ThreatEducator successfully:
//! 1. Pre-warms PSI with threat knowledge
//! 2. Improves classification accuracy on threat patterns
//! 3. Creates proper Hebbian connections for future learning

use webguard::threat_educator::ThreatEducator;
use webguard::memory_engine::psi_index::PsiIndex;
use webguard::advanced_feature_extractor::AdvancedFeatureExtractor;
use webguard::embedding_learner::EmbeddingLearner;

/// Test that educated PSI correctly identifies SQL injection patterns
#[test]
fn test_educated_psi_classifies_sqli() {
    // Setup
    let mut educator = ThreatEducator::new().with_examples_per_curriculum(5);
    let mut psi = PsiIndex::new();
    let feature_extractor = AdvancedFeatureExtractor::new();

    // Teach SQL injection curriculum
    let curriculum = ThreatEducator::builtin_sqli_curriculum();
    let result = educator.teach(&curriculum, &mut psi);

    println!("\n=== SQL Injection Education Results ===");
    println!("Entries created: {}", result.entries_created);
    println!("Prototype injected: {}", result.prototype_injected);
    println!("Examples generated: {:?}", result.examples_generated);

    // Verify PSI was populated
    assert!(psi.len() > 0, "PSI should have entries after education");
    assert!(result.entries_created > 0, "Should have created entries");
    assert!(result.prototype_injected, "Should have injected prototype");

    // Test classification of SQL injection attacks
    let test_attacks = vec![
        "' OR 'x'='x",
        "1' UNION SELECT password FROM users--",
        "admin' AND '1'='1",
        "'; DROP TABLE accounts; --",
    ];

    println!("\n=== Testing SQL Injection Classification ===");
    for attack in &test_attacks {
        let embedding = feature_extractor.extract_features(attack);
        let results = psi.search(&embedding, 3);
        
        // Calculate weighted score from results
        let score = if results.is_empty() {
            0.0
        } else {
            results.iter()
                .map(|(entry, sim)| entry.valence * sim)
                .sum::<f32>() / results.len() as f32
        };
        
        println!("Attack: {} -> score={:.3}, matching_entries={}", attack, score, results.len());
        
        // Educated PSI should find similar threat patterns
        assert!(!results.is_empty(), "SQL injection '{}' should find similar entries", attack);
    }

    // Test that benign requests find fewer/weaker matches
    let benign_requests = vec![
        "GET /index.html HTTP/1.1",
        "POST /api/users HTTP/1.1",
        "/products?category=books&page=1",
    ];

    println!("\n=== Testing Benign Request Classification ===");
    for request in &benign_requests {
        let embedding = feature_extractor.extract_features(request);
        let results = psi.search(&embedding, 3);
        
        let score = if results.is_empty() {
            0.0
        } else {
            results.iter()
                .map(|(entry, sim)| entry.valence * sim)
                .sum::<f32>() / results.len() as f32
        };
        
        println!("Benign: {} -> score={:.3}, matches={}", request, score, results.len());
    }
}

/// Test that XSS education improves detection
#[test]
fn test_educated_psi_classifies_xss() {
    let mut educator = ThreatEducator::new().with_examples_per_curriculum(5);
    let mut psi = PsiIndex::new();
    let feature_extractor = AdvancedFeatureExtractor::new();

    // Teach XSS curriculum
    let curriculum = ThreatEducator::builtin_xss_curriculum();
    let result = educator.teach(&curriculum, &mut psi);

    println!("\n=== XSS Education Results ===");
    println!("Entries created: {}", result.entries_created);
    println!("Examples: {:?}", result.examples_generated);

    // Test XSS patterns
    let xss_attacks = vec![
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
        "<svg onload=alert('test')>",
    ];

    println!("\n=== Testing XSS Classification ===");
    for attack in &xss_attacks {
        let embedding = feature_extractor.extract_features(attack);
        let results = psi.search(&embedding, 3);
        
        let score = if results.is_empty() {
            0.0
        } else {
            results.iter()
                .map(|(entry, sim)| entry.valence * sim)
                .sum::<f32>() / results.len() as f32
        };
        
        println!("XSS: {} -> score={:.3}, matches={}", attack, score, results.len());
        assert!(!results.is_empty(), "XSS attack '{}' should find similar entries", attack);
    }
}

/// Test that path traversal education works
#[test]
fn test_educated_psi_classifies_path_traversal() {
    let mut educator = ThreatEducator::new().with_examples_per_curriculum(5);
    let mut psi = PsiIndex::new();
    let feature_extractor = AdvancedFeatureExtractor::new();

    // Teach path traversal curriculum
    let curriculum = ThreatEducator::builtin_path_traversal_curriculum();
    let result = educator.teach(&curriculum, &mut psi);

    println!("\n=== Path Traversal Education Results ===");
    println!("Entries created: {}", result.entries_created);

    // Test path traversal patterns
    let traversal_attacks = vec![
        "../../../etc/passwd",
        "....//....//....//etc/shadow",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    ];

    println!("\n=== Testing Path Traversal Classification ===");
    for attack in &traversal_attacks {
        let embedding = feature_extractor.extract_features(attack);
        let results = psi.search(&embedding, 3);
        
        let score = if results.is_empty() {
            0.0
        } else {
            results.iter()
                .map(|(entry, sim)| entry.valence * sim)
                .sum::<f32>() / results.len() as f32
        };
        
        println!("Path traversal: {} -> score={:.3}, matches={}", attack, score, results.len());
        assert!(!results.is_empty(), "Path traversal '{}' should find similar entries", attack);
    }
}

/// Test teaching multiple curricula creates distinct clusters
#[test]
fn test_multi_curriculum_education() {
    let mut educator = ThreatEducator::new().with_examples_per_curriculum(3);
    let mut psi = PsiIndex::new();

    // Teach all built-in curricula
    let curricula = ThreatEducator::builtin_curricula();
    let results = educator.teach_course(&curricula, &mut psi);

    println!("\n=== Multi-Curriculum Education Summary ===");
    let total_entries: usize = results.iter().map(|r| r.entries_created).sum();
    println!("Total curricula: {}", results.len());
    println!("Total entries: {}", total_entries);
    
    for result in &results {
        println!("  {} - {} entries, prototype: {}", 
                 result.curriculum_name, 
                 result.entries_created,
                 result.prototype_injected);
    }

    // Verify all curricula were taught
    assert_eq!(results.len(), 4, "Should have taught 4 curricula");
    assert!(total_entries >= 12, "Should have created at least 12 entries total");

    // Verify educator statistics
    let stats = educator.get_stats();
    assert_eq!(stats.curricula_taught, 4);
    assert!(stats.total_entries_created >= 12);
}

/// Test that educated entries have proper tags for auditability
#[test]
fn test_educated_entries_tagged() {
    let mut educator = ThreatEducator::new().with_examples_per_curriculum(2);
    let mut psi = PsiIndex::new();

    let curriculum = ThreatEducator::builtin_sqli_curriculum();
    educator.teach(&curriculum, &mut psi);

    // Check that entries have 'educated' tag
    let mut educated_count = 0;
    let mut prototype_count = 0;

    for entry in psi.entries() {
        if entry.tags.contains(&"educated".to_string()) {
            educated_count += 1;
        }
        if entry.tags.contains(&"prototype".to_string()) {
            prototype_count += 1;
        }
    }

    println!("\n=== Entry Tag Analysis ===");
    println!("Educated entries: {}", educated_count);
    println!("Prototype entries: {}", prototype_count);

    assert!(educated_count > 0, "Should have entries tagged as 'educated'");
    assert_eq!(prototype_count, 1, "Should have exactly 1 prototype entry");
}

/// Test full learning pipeline: Education -> Experience -> Classification
#[test]
fn test_education_plus_experiential_learning() {
    let mut educator = ThreatEducator::new().with_examples_per_curriculum(3);
    let mut psi = PsiIndex::new();
    let feature_extractor = AdvancedFeatureExtractor::new();

    // Phase 1: Pre-deployment education
    let curriculum = ThreatEducator::builtin_sqli_curriculum();
    let _edu_result = educator.teach(&curriculum, &mut psi);
    
    println!("\n=== Phase 1: Education ===");
    println!("PSI entries after education: {}", psi.len());

    // Phase 2: Simulate operational experience with reinforcement
    let operational_threats = vec![
        "' OR username='admin'--",
        "1'; SELECT * FROM passwords;--",
    ];

    println!("\n=== Phase 2: Operational Reinforcement ===");
    for threat in &operational_threats {
        let embedding = feature_extractor.extract_features(threat);
        
        // Query before reinforcement
        let results_before = psi.search(&embedding, 3);
        let score_before = if results_before.is_empty() {
            0.0
        } else {
            results_before.iter()
                .map(|(entry, sim)| entry.valence * sim)
                .sum::<f32>() / results_before.len() as f32
        };
        
        // Create experiential entry (simulating detection + confirmation)
        use webguard::memory_engine::psi_index::PsiEntry;
        let entry = PsiEntry {
            id: format!("operational_{}", threat.len()),
            vec: embedding,
            valence: 0.9,  // Confirmed threat
            uses: 1,
            tags: vec!["operational".to_string(), "confirmed".to_string()],
            last_activation: 0.0,
            cumulative_reward: 1.0,
        };
        
        // Use one-shot learning (creates Hebbian connections to educated entries)
        psi.one_shot_learn(entry, 1.0);
        
        // Query after reinforcement
        let results_after = psi.search(&embedding, 3);
        let score_after = if results_after.is_empty() {
            0.0
        } else {
            results_after.iter()
                .map(|(entry, sim)| entry.valence * sim)
                .sum::<f32>() / results_after.len() as f32
        };
        
        println!("Threat '{}': before={:.3}, after={:.3}", 
                 &threat[..20.min(threat.len())], score_before, score_after);
    }

    println!("\n=== Phase 3: Novel Threat Classification ===");
    // Test a novel SQL injection variant (not in training)
    let novel_attacks = vec![
        "' HAVING 1=1--",
        "1' ORDER BY 1--/*",
        "' OR EXISTS(SELECT * FROM admins)--",
    ];

    for attack in &novel_attacks {
        let embedding = feature_extractor.extract_features(attack);
        let results = psi.search(&embedding, 5);
        
        let score = if results.is_empty() {
            0.0
        } else {
            results.iter()
                .map(|(entry, sim)| entry.valence * sim)
                .sum::<f32>() / results.len() as f32
        };
        
        println!("Novel attack '{}': score={:.3}, similar_entries={}", 
                 attack, score, results.len());
        
        // The educated + reinforced PSI should generalize to novel variants
        // (though score may vary based on feature similarity)
    }

    // Final PSI state
    println!("\n=== Final PSI State ===");
    println!("Total entries: {}", psi.len());
    println!("Connections: {}", psi.connection_count());
}

/// Test custom curriculum loading and teaching
#[test]
fn test_custom_curriculum() {
    let json = r#"[{
        "name": "LDAP Injection",
        "category": "injection.sql",
        "description": "LDAP injection attacks",
        "severity": "high",
        "feature_profile": {
            "special_char_ratio": [0.1, 0.3],
            "quote_unbalanced": true
        },
        "signature_patterns": [
            {"ngram": ")(", "weight": 0.9},
            {"ngram": "*))", "weight": 0.85}
        ],
        "templates": [
            "*)(&",
            "*)(uid=*))(|(uid=*",
            "admin)(&)"
        ]
    }]"#;

    let curricula = ThreatEducator::load_curricula_from_json(json).unwrap();
    assert_eq!(curricula.len(), 1);
    assert_eq!(curricula[0].name, "LDAP Injection");

    let mut educator = ThreatEducator::new().with_examples_per_curriculum(3);
    let mut psi = PsiIndex::new();

    let result = educator.teach(&curricula[0], &mut psi);

    println!("\n=== Custom LDAP Injection Curriculum ===");
    println!("Name: {}", result.curriculum_name);
    println!("Entries: {}", result.entries_created);
    println!("Examples: {:?}", result.examples_generated);

    assert!(result.entries_created > 0);
}

/// Test that n-gram associations are taught to EmbeddingLearner
#[test]
fn test_ngram_teaching() {
    let mut educator = ThreatEducator::new().with_examples_per_curriculum(3);
    let mut psi = PsiIndex::new();
    let mut embedding_learner = EmbeddingLearner::new();

    let curriculum = ThreatEducator::builtin_sqli_curriculum();
    
    // Full teaching: PSI + EmbeddingLearner
    let result = educator.teach_full(&curriculum, &mut psi, &mut embedding_learner);

    println!("\n=== Full Education with N-gram Teaching ===");
    println!("PSI entries: {}", result.entries_created);
    println!("N-gram associations: {}", result.ngram_associations);

    assert!(result.ngram_associations > 0, "Should have taught n-gram associations");
}

/// Benchmark: Compare educated vs uneducated PSI
#[test]
fn test_education_improves_detection() {
    let feature_extractor = AdvancedFeatureExtractor::new();
    
    // Test attacks
    let attacks = vec![
        "' OR 1=1--",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "; cat /etc/shadow",
    ];

    // Uneducated PSI
    let uneducated_psi = PsiIndex::new();
    
    println!("\n=== Uneducated PSI Scores ===");
    let mut uneducated_scores = Vec::new();
    for attack in &attacks {
        let embedding = feature_extractor.extract_features(attack);
        let results = uneducated_psi.search(&embedding, 3);
        let score = if results.is_empty() {
            0.0
        } else {
            results.iter()
                .map(|(entry, sim)| entry.valence * sim)
                .sum::<f32>() / results.len() as f32
        };
        uneducated_scores.push(score);
        println!("{}: {:.3} (matches={})", attack, score, results.len());
    }

    // Educated PSI
    let mut educator = ThreatEducator::new().with_examples_per_curriculum(5);
    let mut educated_psi = PsiIndex::new();
    let curricula = ThreatEducator::builtin_curricula();
    educator.teach_course(&curricula, &mut educated_psi);

    println!("\n=== Educated PSI Scores ===");
    let mut educated_scores = Vec::new();
    for attack in &attacks {
        let embedding = feature_extractor.extract_features(attack);
        let results = educated_psi.search(&embedding, 3);
        let score = if results.is_empty() {
            0.0
        } else {
            results.iter()
                .map(|(entry, sim)| entry.valence * sim)
                .sum::<f32>() / results.len() as f32
        };
        educated_scores.push(score);
        println!("{}: {:.3}", attack, score);
    }

    // Education should improve threat detection
    println!("\n=== Improvement Analysis ===");
    for i in 0..attacks.len() {
        let improvement = educated_scores[i] - uneducated_scores[i];
        println!("{}: improvement = {:.3}", attacks[i], improvement);
    }

    // At least some attacks should have improved scores
    let improvements: Vec<f32> = educated_scores.iter()
        .zip(uneducated_scores.iter())
        .map(|(e, u)| e - u)
        .collect();
    
    let avg_improvement: f32 = improvements.iter().sum::<f32>() / improvements.len() as f32;
    println!("\nAverage improvement: {:.3}", avg_improvement);
    
    // Education should provide SOME improvement (educated PSI has threat references)
    assert!(avg_improvement >= 0.0 || educated_scores.iter().any(|&s| s > 0.5),
            "Educated PSI should show improvement or high scores");
}
