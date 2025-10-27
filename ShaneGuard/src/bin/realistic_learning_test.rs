use shaneguard::{mesh_cognition::MeshCognition, config::Config, policy::Action};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{info, warn};

#[derive(Debug)]
struct RealisticTestResult {
    iteration: usize,
    benign_accuracy: f32,
    attack_accuracy: f32,
    overall_accuracy: f32,
    false_positive_rate: f32,
    hebbian_connections: usize,
    avg_connection_weight: f32,
    memory_traces: usize,
    host_aggression: f32,
}

struct RealisticLearningTest {
    mesh: MeshCognition,
    config: Config,
    benign_scenarios: Vec<Value>,
    attack_scenarios: Vec<Value>,
    results: Vec<RealisticTestResult>,
}

impl RealisticLearningTest {
    fn new() -> Self {
        let config = Config::load_default();
        let mesh = MeshCognition::new(config.clone());
        
        Self {
            mesh,
            config,
            benign_scenarios: Self::generate_diverse_benign_scenarios(),
            attack_scenarios: Self::load_attack_scenarios(),
            results: Vec::new(),
        }
    }

    fn generate_diverse_benign_scenarios() -> Vec<Value> {
        let mut scenarios = Vec::new();
        
        // Web browsing patterns
        for i in 0..200 {
            scenarios.push(json!({
                "scenario": format!("Web Browsing {}", i),
                "pid": 1000 + (i % 100),
                "process_name": "chrome",
                "network_connections": 2 + (i % 5),
                "file_operations": 5 + (i % 10),
                "memory_usage": 30.0 + (i as f64 % 40.0),
                "cpu_usage": 10.0 + (i as f64 % 20.0),
                "payload_size": 500 + (i % 1000),
                "entropy": 2.0 + (i as f64 % 3.0),
                "suspicious_patterns": [],
                "session_duration": 1800 + (i % 3600),
                "expected": "none"
            }));
        }

        // API calls
        for i in 0..150 {
            scenarios.push(json!({
                "scenario": format!("API Call {}", i),
                "pid": 2000 + (i % 50),
                "process_name": "node",
                "network_connections": 1 + (i % 3),
                "file_operations": 2 + (i % 5),
                "memory_usage": 25.0 + (i as f64 % 30.0),
                "cpu_usage": 5.0 + (i as f64 % 15.0),
                "payload_size": 100 + (i % 500),
                "entropy": 1.5 + (i as f64 % 2.0),
                "suspicious_patterns": [],
                "response_code": 200,
                "expected": "none"
            }));
        }

        // File operations
        for i in 0..100 {
            scenarios.push(json!({
                "scenario": format!("File Operation {}", i),
                "pid": 3000 + (i % 30),
                "process_name": "explorer",
                "network_connections": 0,
                "file_operations": 10 + (i % 20),
                "memory_usage": 15.0 + (i as f64 % 25.0),
                "cpu_usage": 3.0 + (i as f64 % 10.0),
                "payload_size": 0,
                "entropy": 0.5 + (i as f64 % 1.0),
                "suspicious_patterns": [],
                "file_type": "document",
                "expected": "none"
            }));
        }

        // Database queries
        for i in 0..75 {
            scenarios.push(json!({
                "scenario": format!("Database Query {}", i),
                "pid": 4000 + (i % 20),
                "process_name": "mysql",
                "network_connections": 1,
                "file_operations": 3 + (i % 8),
                "memory_usage": 40.0 + (i as f64 % 35.0),
                "cpu_usage": 8.0 + (i as f64 % 18.0),
                "payload_size": 200 + (i % 800),
                "entropy": 1.8 + (i as f64 % 2.5),
                "suspicious_patterns": [],
                "query_type": "SELECT",
                "expected": "none"
            }));
        }

        // System maintenance
        for i in 0..75 {
            scenarios.push(json!({
                "scenario": format!("System Maintenance {}", i),
                "pid": 5000 + (i % 15),
                "process_name": "system",
                "network_connections": 0 + (i % 2),
                "file_operations": 15 + (i % 25),
                "memory_usage": 20.0 + (i as f64 % 30.0),
                "cpu_usage": 12.0 + (i as f64 % 20.0),
                "payload_size": 0,
                "entropy": 0.3 + (i as f64 % 0.8),
                "suspicious_patterns": [],
                "maintenance_type": "cleanup",
                "expected": "none"
            }));
        }

        scenarios
    }

    fn load_attack_scenarios() -> Vec<Value> {
        // Load existing attack scenarios but with more variations
        vec![
            json!({
                "scenario": "Buffer Overflow Variant A",
                "pid": 6001,
                "process_name": "vulnerable_app",
                "network_connections": 1,
                "file_operations": 2,
                "memory_usage": 95.8,
                "cpu_usage": 78.4,
                "payload_size": 4096,
                "entropy": 8.2,
                "suspicious_patterns": ["strcpy", "gets", "sprintf"],
                "stack_canary_violations": 3,
                "expected": "critical"
            }),
            json!({
                "scenario": "SQL Injection Variant A",
                "pid": 6002,
                "process_name": "apache",
                "network_connections": 2,
                "file_operations": 5,
                "memory_usage": 45.2,
                "cpu_usage": 35.1,
                "payload_size": 1024,
                "entropy": 6.8,
                "suspicious_patterns": ["UNION", "SELECT", "--", "OR 1=1"],
                "expected": "high"
            }),
            // Add more attack variations...
        ]
    }

    async fn run_realistic_learning(&mut self, iterations: usize) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting Realistic Learning Test with {} iterations", iterations);
        info!("Dataset: {} benign scenarios, {} attack scenarios", 
              self.benign_scenarios.len(), self.attack_scenarios.len());

        // Register services
        self.register_services().await?;

        for iteration in 1..=iterations {
            info!("=== Realistic Learning Iteration {} ===", iteration);
            
            let start_time = Instant::now();
            let mut correct_predictions = 0;
            let mut total_predictions = 0;
            let mut benign_correct = 0;
            let mut benign_total = 0;
            let mut attack_correct = 0;
            let mut attack_total = 0;
            let mut false_positives = 0;

            // Phase-based learning strategy
            let (benign_ratio, attack_ratio) = self.get_phase_ratios(iteration, iterations);
            
            // Sample scenarios based on phase
            let benign_sample_size = (self.benign_scenarios.len() as f32 * benign_ratio) as usize;
            let attack_sample_size = (self.attack_scenarios.len() as f32 * attack_ratio) as usize;

            info!("Phase ratios - Benign: {:.1}%, Attack: {:.1}%", 
                  benign_ratio * 100.0, attack_ratio * 100.0);

            // Process benign scenarios
            for scenario in self.benign_scenarios.iter().take(benign_sample_size) {
                let result = self.process_scenario(scenario, iteration).await?;
                benign_total += 1;
                total_predictions += 1;

                // Benign traffic should be logged (not escalated)
                if matches!(result.action, Action::Log) {
                    benign_correct += 1;
                    correct_predictions += 1;
                } else {
                    false_positives += 1;
                }

                // Add reward feedback
                let reward = if matches!(result.action, Action::Log) { 1.0 } else { -0.5 };
                self.add_reward_feedback(&result.service_id, &result.features, reward).await;
            }

            // Process attack scenarios
            for scenario in self.attack_scenarios.iter().take(attack_sample_size) {
                let result = self.process_scenario(scenario, iteration).await?;
                attack_total += 1;
                total_predictions += 1;

                let expected_threat = scenario.get("expected").and_then(|v| v.as_str()).unwrap_or("none");
                let is_correct = self.evaluate_attack_response(&result.action, expected_threat);
                
                if is_correct {
                    attack_correct += 1;
                    correct_predictions += 1;
                }

                // Add reward feedback
                let reward = if is_correct { 1.0 } else { -1.0 };
                self.add_reward_feedback(&result.service_id, &result.features, reward).await;
            }

            // Calculate metrics
            let iteration_result = self.calculate_iteration_metrics(
                iteration,
                correct_predictions,
                total_predictions,
                benign_correct,
                benign_total,
                attack_correct,
                attack_total,
                false_positives,
            ).await;

            self.results.push(iteration_result);
            
            let elapsed = start_time.elapsed();
            info!("Iteration {} complete in {:?} - Overall: {:.1}%, Benign: {:.1}%, Attack: {:.1}%",
                  iteration, elapsed,
                  self.results.last().unwrap().overall_accuracy * 100.0,
                  self.results.last().unwrap().benign_accuracy * 100.0,
                  self.results.last().unwrap().attack_accuracy * 100.0);

            // Brief pause between iterations
            sleep(Duration::from_millis(100)).await;
        }

        self.generate_final_report()?;
        Ok(())
    }

    fn get_phase_ratios(&self, iteration: usize, total_iterations: usize) -> (f32, f32) {
        let progress = iteration as f32 / total_iterations as f32;
        
        if progress <= 0.3 {
            // Phase 1: Establish benign baseline (95% benign, 5% attack)
            (0.95, 0.05)
        } else if progress <= 0.7 {
            // Phase 2: Gradual attack introduction (90% benign, 10% attack)
            (0.90, 0.10)
        } else {
            // Phase 3: Realistic mixed traffic (85% benign, 15% attack)
            (0.85, 0.15)
        }
    }

    async fn register_services(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Register diverse service types
        let services = vec![
            ("apache", vec![1001, 1002, 1003]),
            ("nginx", vec![2001, 2002]),
            ("iis", vec![3001]),
            ("mysql", vec![4001, 4002]),
            ("postgres", vec![5001]),
        ];

        for (service_type, pids) in services {
            for pid in pids {
                self.mesh.register_service(service_type, pid).await?;
            }
        }

        Ok(())
    }

    // ... (implement remaining methods similar to comprehensive_test_suite.rs)

    fn generate_final_report(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n# Realistic Learning Test Results\n");
        println!("## Learning Progression\n");
        
        for result in &self.results {
            println!("Iteration {}: Overall {:.1}%, Benign {:.1}%, Attack {:.1}%, Connections: {}, FP Rate: {:.2}%",
                     result.iteration,
                     result.overall_accuracy * 100.0,
                     result.benign_accuracy * 100.0,
                     result.attack_accuracy * 100.0,
                     result.hebbian_connections,
                     result.false_positive_rate * 100.0);
        }

        if let Some(final_result) = self.results.last() {
            println!("\n## Final Performance");
            println!("- Overall Accuracy: {:.1}%", final_result.overall_accuracy * 100.0);
            println!("- Benign Accuracy: {:.1}%", final_result.benign_accuracy * 100.0);
            println!("- Attack Accuracy: {:.1}%", final_result.attack_accuracy * 100.0);
            println!("- False Positive Rate: {:.2}%", final_result.false_positive_rate * 100.0);
            println!("- Hebbian Connections: {}", final_result.hebbian_connections);
            println!("- Memory Traces: {}", final_result.memory_traces);
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let iterations = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);

    let mut test = RealisticLearningTest::new();
    test.run_realistic_learning(iterations).await?;

    Ok(())
}