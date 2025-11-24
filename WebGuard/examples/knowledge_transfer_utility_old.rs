use std::fs;
use std::path::Path;
use std::env;
use webguard::mesh_cognition::HostMeshCognition;

/// Simple utility for WebGuard knowledge transfer operations
/// Usage:
///   cargo run --bin knowledge_transfer_utility export <output_file>
///   cargo run --bin knowledge_transfer_utility import <input_file>
///   cargo run --bin knowledge_transfer_utility info <knowledge_file>
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }
    
    match args[1].as_str() {
        "export" => {
            if args.len() != 3 {
                eprintln!("Usage: {} export <output_file>", args[0]);
                return Ok(());
            }
            export_knowledge(&args[2])?;
        }
        "import" => {
            if args.len() != 3 {
                eprintln!("Usage: {} import <input_file>", args[0]);
                return Ok(());
            }
            import_knowledge(&args[2])?;
        }
        "info" => {
            if args.len() != 3 {
                eprintln!("Usage: {} info <knowledge_file>", args[0]);
                return Ok(());
            }
            show_knowledge_info(&args[2])?;
        }
        "merge" => {
            if args.len() != 4 {
                eprintln!("Usage: {} merge <file1> <file2>", args[0]);
                return Ok(());
            }
            merge_knowledge(&args[2], &args[3])?;
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
        }
    }
    
    Ok(())
}

fn print_usage() {
    println!("WebGuard Knowledge Transfer Utility");
    println!("===================================");
    println!();
    println!("Commands:");
    println!("  export <output_file>     Export knowledge from current WebGuard instance");
    println!("  import <input_file>      Import knowledge into current WebGuard instance");
    println!("  info <knowledge_file>    Display information about a knowledge file");
    println!("  merge <file1> <file2>    Merge two knowledge files");
    println!();
    println!("Examples:");
    println!("  cargo run --bin knowledge_transfer_utility export production_knowledge.json");
    println!("  cargo run --bin knowledge_transfer_utility import staging_knowledge.json");
    println!("  cargo run --bin knowledge_transfer_utility info production_knowledge.json");
    println!("  cargo run --bin knowledge_transfer_utility merge prod.json staging.json");
}

fn export_knowledge(output_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔄 Exporting WebGuard Knowledge");
    println!("==============================");
    
    // Create a WebGuard instance and simulate some learning for demo
    let mut webguard = ExperientialKnowledgeBase::new();
    
    // Add some sample patterns for demonstration
    let sample_threats = vec![
        ("' OR 1=1 --", vec!["sql".to_string(), "injection".to_string()]),
        ("<script>alert('xss')</script>", vec!["xss".to_string(), "script_injection".to_string()]),
        ("../../../etc/passwd", vec!["lfi".to_string(), "traversal".to_string()]),
        ("UNION SELECT * FROM users", vec!["sql".to_string(), "union".to_string()]),
    ];
    
    println!("📚 Learning sample patterns for export...");
    for (pattern, context) in &sample_threats {
        // Learn each pattern multiple times to build confidence
        for _ in 0..5 {
            webguard.learn_pattern(
                pattern.to_string(),
                true,
                context.clone(),
                webguard::enhanced_pattern_recognition::DiscoveryMethod::ThreatValidation
            );
        }
        println!("  ✅ Learned: {}", pattern);
    }
    
    // Export the knowledge
    println!("\n📤 Exporting knowledge...");
    let knowledge_json = webguard.export_knowledge()?;
    
    // Save to file
    fs::write(output_file, &knowledge_json)?;
    
    println!("✅ Knowledge exported successfully!");
    println!("📁 File: {}", output_file);
    println!("📊 Size: {} bytes", knowledge_json.len());
    
    // Parse and show statistics
    let parsed: serde_json::Value = serde_json::from_str(&knowledge_json)?;
    let patterns = parsed["patterns"].as_object().unwrap();
    println!("🎯 Patterns exported: {}", patterns.len());
    
    Ok(())
}

fn import_knowledge(input_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔄 Importing WebGuard Knowledge");
    println!("===============================");
    
    if !Path::new(input_file).exists() {
        eprintln!("❌ File not found: {}", input_file);
        return Ok(());
    }
    
    // Create a new WebGuard instance
    let mut webguard = ExperientialKnowledgeBase::new();
    
    // Read the knowledge file
    println!("📖 Reading knowledge file: {}", input_file);
    let knowledge_json = fs::read_to_string(input_file)?;
    
    // Import the knowledge
    println!("📥 Importing knowledge...");
    match webguard.import_knowledge(&knowledge_json) {
        Ok(imported_count) => {
            println!("✅ Knowledge imported successfully!");
            println!("🎯 Patterns imported: {}", imported_count);
            
            // Test the imported knowledge
            println!("\n🧪 Testing imported patterns...");
            let test_inputs = vec![
                "' OR 1=1 --",
                "<script>alert('test')</script>",
                "../../../etc/passwd",
                "SELECT * FROM users",
            ];
            
            for test_input in &test_inputs {
                // Simple pattern matching test
                let mut detected = false;
                for (_, pattern) in &webguard.learned_patterns {
                    if test_input.to_lowercase().contains(&pattern.pattern.to_lowercase()) ||
                       pattern.pattern.to_lowercase().contains(&test_input.to_lowercase()) {
                        detected = true;
                        break;
                    }
                }
                
                if detected {
                    println!("  ✅ Can detect: {}", test_input);
                } else {
                    println!("  ❌ Cannot detect: {}", test_input);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Import failed: {}", e);
        }
    }
    
    Ok(())
}

fn show_knowledge_info(knowledge_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("📋 WebGuard Knowledge File Information");
    println!("=====================================");
    
    if !Path::new(knowledge_file).exists() {
        eprintln!("❌ File not found: {}", knowledge_file);
        return Ok(());
    }
    
    // Read and parse the knowledge file
    let knowledge_json = fs::read_to_string(knowledge_file)?;
    let parsed: serde_json::Value = serde_json::from_str(&knowledge_json)?;
    
    // Display file information
    println!("📁 File: {}", knowledge_file);
    println!("📊 Size: {} bytes ({:.1} KB)", knowledge_json.len(), knowledge_json.len() as f64 / 1024.0);
    
    // Display export metadata
    if let Some(version) = parsed["version"].as_str() {
        println!("🏷️  Version: {}", version);
    }
    
    if let Some(timestamp) = parsed["export_timestamp"].as_u64() {
        let datetime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
        println!("📅 Export Date: {:?}", datetime);
    }
    
    if let Some(source) = parsed["source_instance"].as_str() {
        println!("🏭 Source Instance: {}", source);
    }
    
    // Display pattern statistics
    if let Some(patterns) = parsed["patterns"].as_object() {
        println!("\n🎯 Pattern Statistics:");
        println!("   Total Patterns: {}", patterns.len());
        
        let mut threat_count = 0;
        let mut benign_count = 0;
        let mut total_confidence = 0.0;
        let mut total_validations = 0;
        
        for (pattern_id, pattern_data) in patterns {
            let threat_weight = pattern_data["threat_weight"].as_f64().unwrap_or(0.0);
            let confidence = pattern_data["confidence"].as_f64().unwrap_or(0.0);
            let validations = pattern_data["validation_count"].as_u64().unwrap_or(0);
            
            if threat_weight > 0.5 {
                threat_count += 1;
            } else {
                benign_count += 1;
            }
            
            total_confidence += confidence;
            total_validations += validations;
        }
        
        println!("   Threat Patterns: {}", threat_count);
        println!("   Benign Patterns: {}", benign_count);
        println!("   Average Confidence: {:.2}", total_confidence / patterns.len() as f64);
        println!("   Average Validations: {:.1}", total_validations as f64 / patterns.len() as f64);
        
        // Show top patterns by confidence
        println!("\n🏆 Top Patterns by Confidence:");
        let mut pattern_list: Vec<_> = patterns.iter().collect();
        pattern_list.sort_by(|a, b| {
            let conf_a = a.1["confidence"].as_f64().unwrap_or(0.0);
            let conf_b = b.1["confidence"].as_f64().unwrap_or(0.0);
            conf_b.partial_cmp(&conf_a).unwrap()
        });
        
        for (pattern_id, pattern_data) in pattern_list.iter().take(5) {
            let confidence = pattern_data["confidence"].as_f64().unwrap_or(0.0);
            let validations = pattern_data["validation_count"].as_u64().unwrap_or(0);
            let display_pattern = if pattern_id.len() > 50 {
                format!("{}...", &pattern_id[..47])
            } else {
                pattern_id.to_string()
            };
            println!("   • {} (confidence: {:.2}, validations: {})", display_pattern, confidence, validations);
        }
    }
    
    // Display learning statistics
    if let Some(stats) = parsed["learning_stats"].as_object() {
        println!("\n📈 Learning Statistics:");
        for (key, value) in stats {
            match value {
                serde_json::Value::Number(n) => println!("   {}: {}", key, n),
                serde_json::Value::String(s) => println!("   {}: {}", key, s),
                _ => {}
            }
        }
    }
    
    Ok(())
}

fn merge_knowledge(file1: &str, file2: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔄 Merging WebGuard Knowledge Files");
    println!("===================================");
    
    if !Path::new(file1).exists() {
        eprintln!("❌ File not found: {}", file1);
        return Ok(());
    }
    
    if !Path::new(file2).exists() {
        eprintln!("❌ File not found: {}", file2);
        return Ok(());
    }
    
    // Create a WebGuard instance for merging
    let mut webguard = ExperientialKnowledgeBase::new();
    
    // Import from first file
    println!("📥 Importing from: {}", file1);
    let knowledge1 = fs::read_to_string(file1)?;
    let imported1 = webguard.import_knowledge(&knowledge1)?;
    println!("  ✅ Imported {} patterns", imported1);
    
    // Import from second file
    println!("📥 Importing from: {}", file2);
    let knowledge2 = fs::read_to_string(file2)?;
    let imported2 = webguard.import_knowledge(&knowledge2)?;
    println!("  ✅ Imported {} additional patterns", imported2);
    
    // Export merged knowledge
    let merged_knowledge = webguard.export_knowledge()?;
    let output_file = "merged_knowledge.json";
    fs::write(output_file, &merged_knowledge)?;
    
    println!("\n✅ Knowledge files merged successfully!");
    println!("📁 Output file: {}", output_file);
    println!("📊 Total patterns: {}", imported1 + imported2);
    println!("📊 File size: {} bytes", merged_knowledge.len());
    
    Ok(())
}