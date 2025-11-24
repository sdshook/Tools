use std::fs;
use webguard::enhanced_pattern_recognition::{ExperientialKnowledgeBase, DiscoveryMethod};

/// Demonstrates how to export learned knowledge from WebGuard
/// for use in other security systems
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧠 WebGuard Knowledge Export Demo");
    println!("==================================");
    
    // Create a knowledge base and simulate some learning
    let mut knowledge_base = ExperientialKnowledgeBase::new();
    
    // Simulate learning some threat patterns
    println!("\n📚 Simulating pattern learning...");
    
    let threat_patterns = vec![
        ("' OR 1=1 --", vec!["sql".to_string(), "injection".to_string()]),
        ("<script>alert('xss')</script>", vec!["xss".to_string(), "javascript".to_string()]),
        ("../../../etc/passwd", vec!["lfi".to_string(), "traversal".to_string()]),
        ("UNION SELECT * FROM users", vec!["sql".to_string(), "union".to_string()]),
        ("javascript:alert(1)", vec!["xss".to_string(), "javascript".to_string()]),
    ];
    
    let benign_patterns = vec![
        ("SELECT * FROM products WHERE id = ?", vec!["sql".to_string(), "legitimate".to_string()]),
        ("<div>Welcome to our site</div>", vec!["html".to_string(), "content".to_string()]),
        ("user/profile/settings", vec!["navigation".to_string(), "legitimate".to_string()]),
    ];
    
    // Learn threat patterns
    for (pattern, context) in threat_patterns {
        knowledge_base.learn_pattern(
            pattern.to_string(),
            true, // is_threat
            context,
            DiscoveryMethod::ThreatValidation
        );
        println!("  ✅ Learned threat pattern: {}", pattern);
    }
    
    // Learn benign patterns
    for (pattern, context) in benign_patterns {
        knowledge_base.learn_pattern(
            pattern.to_string(),
            false, // is_threat
            context,
            DiscoveryMethod::FalsePositiveCorrection
        );
        println!("  ✅ Learned benign pattern: {}", pattern);
    }
    
    // Simulate multiple validations to increase confidence
    println!("\n🔄 Simulating pattern validation...");
    
    // Learn each threat pattern multiple times to increase confidence
    let validation_patterns = vec![
        ("' OR 1=1 --", "SQL injection"),
        ("<script>alert('xss')</script>", "XSS"),
        ("../../../etc/passwd", "Path traversal"),
        ("UNION SELECT * FROM users", "SQL union"),
        ("javascript:alert(1)", "JavaScript XSS"),
    ];
    
    for (pattern, description) in validation_patterns {
        for _ in 0..10 {  // Learn each pattern 10 times to build confidence
            knowledge_base.learn_pattern(
                pattern.to_string(),
                true,
                vec!["threat".to_string(), "validated".to_string()],
                DiscoveryMethod::ThreatValidation
            );
        }
        println!("  ✅ Increased confidence for {} pattern", description);
    }
    
    // Export the learned knowledge
    println!("\n📤 Exporting learned knowledge...");
    match knowledge_base.export_knowledge() {
        Ok(exported_json) => {
            println!("  ✅ Successfully exported {} bytes of knowledge", exported_json.len());
            
            // Save to file
            let export_path = "examples/exported_knowledge.json";
            fs::write(export_path, &exported_json)?;
            println!("  💾 Saved to: {}", export_path);
            
            // Parse and display summary
            let parsed: serde_json::Value = serde_json::from_str(&exported_json)?;
            if let Some(patterns) = parsed["patterns"].as_object() {
                println!("\n📊 Export Summary:");
                println!("  • Total patterns exported: {}", patterns.len());
                
                let mut threat_count = 0;
                let mut benign_count = 0;
                let mut total_confidence = 0.0;
                
                for (pattern_id, pattern_data) in patterns {
                    if let Some(threat_weight) = pattern_data["threat_weight"].as_f64() {
                        if threat_weight > 0.5 {
                            threat_count += 1;
                        } else {
                            benign_count += 1;
                        }
                    }
                    
                    if let Some(confidence) = pattern_data["confidence"].as_f64() {
                        total_confidence += confidence;
                    }
                    
                    println!("    - {}: confidence {:.2}", 
                        pattern_id,
                        pattern_data["confidence"].as_f64().unwrap_or(0.0)
                    );
                }
                
                println!("  • Threat patterns: {}", threat_count);
                println!("  • Benign patterns: {}", benign_count);
                println!("  • Average confidence: {:.2}", total_confidence / patterns.len() as f64);
            }
            
            // Demonstrate import functionality
            println!("\n🔄 Demonstrating knowledge import...");
            let mut new_knowledge_base = ExperientialKnowledgeBase::new();
            match new_knowledge_base.import_knowledge(&exported_json) {
                Ok(imported_count) => {
                    println!("  ✅ Successfully imported {} patterns", imported_count);
                }
                Err(e) => {
                    println!("  ❌ Import failed: {}", e);
                }
            }
            
            // Show integration examples
            println!("\n🔧 Integration Examples:");
            println!("  • ModSecurity: Convert patterns to SecRule format");
            println!("  • Snort: Generate alert rules with pattern matching");
            println!("  • YARA: Create detection rules for malware analysis");
            println!("  • SIEM: Import as threat intelligence indicators");
            println!("  • ML Pipeline: Use as training data for custom models");
            
            println!("\n📖 For detailed integration examples, see:");
            println!("  KNOWLEDGE_EXPORT_GUIDE.md");
            
        }
        Err(e) => {
            println!("  ❌ Export failed: {}", e);
        }
    }
    
    println!("\n🎉 Knowledge export demo completed!");
    println!("Check examples/exported_knowledge.json for the exported data.");
    
    Ok(())
}