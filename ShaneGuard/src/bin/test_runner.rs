use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use serde_json::{Value, from_str};
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

use shaneguard::mesh_cognition::{HostMeshCognition, WebServiceType};
use shaneguard::featurizer;
use shaneguard::policy;
use shaneguard::config::Config;

#[derive(Debug, Clone)]
pub struct TestResult {
    pub scenario_name: String,
    pub attack_vector: String,
    pub expected_threat_level: String,
    pub detected_action: String,
    pub similarity_score: f32,
    pub valence: f32,
    pub host_aggression: f32,
    pub response_time_ms: u64,
    pub learning_iteration: usize,
}

#[derive(Debug)]
pub struct TestSuite {
    pub name: String,
    pub scenarios: Vec<Value>,
    pub results: Vec<TestResult>,
}

pub struct VulnerabilityTestRunner {
    mesh: Arc<Mutex<HostMeshCognition>>,
    config: Config,
    test_suites: Vec<TestSuite>,
}

impl VulnerabilityTestRunner {
    pub fn new(mesh: Arc<Mutex<HostMeshCognition>>, config: Config) -> Self {
        Self {
            mesh,
            config,
            test_suites: Vec::new(),
        }
    }

    pub fn load_test_scenarios(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let test_files = vec![
            ("Deserialization Attacks", "tests/scenarios/deserialization_attacks.json"),
            ("Memory Corruption Attacks", "tests/scenarios/memory_corruption_attacks.json"),
            ("Web Application Attacks", "tests/scenarios/webapp_attacks.json"),
            ("Benign Traffic", "tests/scenarios/benign_traffic.json"),
        ];

        for (suite_name, file_path) in test_files {
            if Path::new(file_path).exists() {
                let content = fs::read_to_string(file_path)?;
                let scenarios: Vec<Value> = from_str(&content)?;
                
                self.test_suites.push(TestSuite {
                    name: suite_name.to_string(),
                    scenarios,
                    results: Vec::new(),
                });
                
                info!("Loaded {} scenarios from {}", self.test_suites.last().unwrap().scenarios.len(), file_path);
            } else {
                warn!("Test file not found: {}", file_path);
            }
        }

        Ok(())
    }

    pub async fn run_learning_simulation(&mut self, server_type: WebServiceType, iterations: usize) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting vulnerability simulation with {:?} server type for {} iterations", server_type, iterations);

        // Register multiple processes of the same server type
        let service_ids = {
            let mut mesh = self.mesh.lock().unwrap();
            let mut ids = Vec::new();
            for i in 1001..1007 {
                let id = mesh.register_service(server_type.clone(), i);
                ids.push(id);
            }
            ids
        };

        info!("Registered {} processes: {:?}", service_ids.len(), service_ids);

        // Run multiple learning iterations
        for iteration in 0..iterations {
            info!("=== Learning Iteration {} ===", iteration + 1);
            
            // Mix benign and malicious traffic
            let mut all_scenarios = Vec::new();
            
            // Add benign traffic (70% of requests)
            for suite in &self.test_suites {
                if suite.name == "Benign Traffic" {
                    for _ in 0..7 {
                        all_scenarios.extend(suite.scenarios.clone());
                    }
                }
            }
            
            // Add attack scenarios (30% of requests)
            for suite in &self.test_suites {
                if suite.name != "Benign Traffic" {
                    all_scenarios.extend(suite.scenarios.clone());
                }
            }

            // Randomize order
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            all_scenarios.shuffle(&mut rng);

            // Process each scenario
            for (scenario_idx, scenario) in all_scenarios.iter().enumerate() {
                let result = self.process_scenario(scenario, iteration, scenario_idx).await?;
                
                // Find the appropriate test suite and add result
                let attack_vector = scenario["attack_vector"].as_str().unwrap_or("unknown");
                for suite in &mut self.test_suites {
                    if (attack_vector == "benign" && suite.name == "Benign Traffic") ||
                       (attack_vector != "benign" && suite.name != "Benign Traffic") {
                        suite.results.push(result);
                        break;
                    }
                }

                // Small delay between requests
                sleep(Duration::from_millis(50)).await;
            }

            // Log learning progress
            let mesh = self.mesh.lock().unwrap();
            let aggression = mesh.get_host_aggression();
            let stats = mesh.get_service_stats();
            info!("Iteration {} complete - Host Aggression: {:.3}, Service Stats: {:?}", 
                  iteration + 1, aggression, stats);
            drop(mesh);

            // Delay between iterations
            sleep(Duration::from_millis(500)).await;
        }

        Ok(())
    }

    async fn process_scenario(&self, scenario: &Value, iteration: usize, _scenario_idx: usize) -> Result<TestResult, Box<dyn std::error::Error>> {
        let start_time = std::time::Instant::now();
        
        let name = scenario["name"].as_str().unwrap_or("Unknown").to_string();
        let attack_vector = scenario["attack_vector"].as_str().unwrap_or("unknown").to_string();
        let expected_threat_level = scenario["expected_threat_level"].as_str().unwrap_or("none").to_string();
        let telemetry = &scenario["telemetry"];

        // Convert telemetry to the format expected by featurizer
        let mut telemetry_map = HashMap::new();
        if let Value::Object(obj) = telemetry {
            for (key, value) in obj {
                telemetry_map.insert(key.clone(), value.clone());
            }
        }

        // Featurize the telemetry
        let vec = featurizer::featurize_from_telemetry(&Value::Object(telemetry_map.clone().into_iter().collect()), &self.config)
            .unwrap_or(vec![0.0_f32; self.config.embed_dim]);
        let mut qarr = [0.0_f32; 32];
        for i in 0..vec.len().min(32) {
            qarr[i] = vec[i];
        }

        let pid = telemetry["pid"].as_i64().unwrap_or(1001) as i32;

        // Get the service memory for this PID
        let (similarity_score, valence, action, host_aggression) = {
            let mesh = self.mesh.lock().unwrap();
            let service_id = format!("apache_{}", pid); // Use the actual service type
            
            if let Some(service_memory) = mesh.get_service_memory(&service_id) {
                let (top_sim, avg_valence) = {
                    let bdh = service_memory.lock().unwrap();
                    let sims = bdh.retrieve_similar(&qarr, 5);
                    if !sims.is_empty() {
                        let top = sims[0].1;
                        let sum_val: f32 = sims.iter().map(|(t, s)| t.valence * s).sum();
                        let sum_s: f32 = sims.iter().map(|(_t, s)| *s).sum();
                        let avg = if sum_s > 0.0 { sum_val / (sum_s + 1e-6) } else { 0.0 };
                        (top, avg)
                    } else {
                        (0.0, 0.0)
                    }
                };

                let aggression = mesh.get_host_aggression();
                let action = policy::choose_action(top_sim, avg_valence, aggression, self.config.beta, self.config.gamma, self.config.eps_explore);
                
                // Simulate learning update
                drop(mesh); // Release mesh lock before acquiring service memory lock
                
                // Update memory based on attack success/failure
                let reward = self.calculate_reward(&attack_vector, &action, &expected_threat_level);
                {
                    let mut bdh = service_memory.lock().unwrap();
                    let maxsim = bdh.max_similarity(&qarr);
                    if maxsim < self.config.tau_novel {
                        let init_val = reward.max(-1.0).min(1.0);
                        let _id = bdh.add_trace(qarr, init_val);
                    } else {
                        let similar_traces: Vec<(String, f32)> = {
                            let sims = bdh.retrieve_similar(&qarr, 5);
                            sims.into_iter()
                                .take(5)
                                .map(|(trace, similarity)| (trace.id.clone(), similarity))
                                .collect()
                        };
                        
                        for (trace_id, similarity) in similar_traces {
                            let scaled = reward * similarity;
                            bdh.reward_update(&trace_id, scaled, self.config.eta);
                        }
                    }
                }

                let mesh = self.mesh.lock().unwrap();
                let final_aggression = mesh.get_host_aggression();
                
                (top_sim, avg_valence, action, final_aggression)
            } else {
                (0.0, 0.0, policy::Action::Log, 0.0)
            }
        };

        let response_time = start_time.elapsed().as_millis() as u64;
        let action_str = match action {
            policy::Action::Log => "log",
            policy::Action::Notify => "notify",
            policy::Action::Throttle => "throttle",
            policy::Action::Isolate => "isolate",
            policy::Action::Restart => "restart",
            policy::Action::SnapshotAndKill => "snapshot",
        };

        Ok(TestResult {
            scenario_name: name,
            attack_vector,
            expected_threat_level,
            detected_action: action_str.to_string(),
            similarity_score,
            valence,
            host_aggression,
            response_time_ms: response_time,
            learning_iteration: iteration,
        })
    }

    fn calculate_reward(&self, attack_vector: &str, action: &policy::Action, expected_threat_level: &str) -> f32 {
        // Reward function based on appropriate response to threat level
        let action_severity: f32 = match action {
            policy::Action::Log => 0.0,
            policy::Action::Notify => 0.2,
            policy::Action::Throttle => 0.4,
            policy::Action::Isolate => 0.7,
            policy::Action::Restart => 0.8,
            policy::Action::SnapshotAndKill => 1.0,
        };

        let expected_severity: f32 = match expected_threat_level {
            "none" => 0.0,
            "low" => 0.2,
            "medium" => 0.5,
            "high" => 0.8,
            "critical" => 1.0,
            _ => 0.0,
        };

        if attack_vector == "benign" {
            // For benign traffic, reward low-severity responses
            if action_severity <= 0.2 { 1.0 } else { -0.5 }
        } else {
            // For attacks, reward appropriate response severity
            let diff = (action_severity - expected_severity).abs();
            if diff < 0.2 { 1.0 } else if diff < 0.4 { 0.5 } else { -0.5 }
        }
    }

    pub fn generate_results_summary(&self) -> String {
        let mut summary = String::new();
        summary.push_str("# Vulnerability Test Results Summary\n\n");

        for suite in &self.test_suites {
            if suite.results.is_empty() { continue; }

            summary.push_str(&format!("## {}\n\n", suite.name));
            
            // Calculate metrics
            let total_tests = suite.results.len();
            let mut correct_responses = 0;
            let mut avg_response_time = 0.0;
            let mut final_aggression = 0.0;

            for result in &suite.results {
                // Check if response was appropriate
                let appropriate = match result.expected_threat_level.as_str() {
                    "none" => matches!(result.detected_action.as_str(), "log" | "notify"),
                    "low" | "medium" => matches!(result.detected_action.as_str(), "notify" | "throttle"),
                    "high" => matches!(result.detected_action.as_str(), "throttle" | "isolate"),
                    "critical" => matches!(result.detected_action.as_str(), "isolate" | "restart" | "snapshot"),
                    _ => false,
                };
                
                if appropriate { correct_responses += 1; }
                avg_response_time += result.response_time_ms as f32;
                final_aggression = result.host_aggression; // Use latest value
            }

            avg_response_time /= total_tests as f32;
            let accuracy = (correct_responses as f32 / total_tests as f32) * 100.0;

            summary.push_str(&format!("- **Total Tests**: {}\n", total_tests));
            summary.push_str(&format!("- **Accuracy**: {:.1}% ({}/{})\n", accuracy, correct_responses, total_tests));
            summary.push_str(&format!("- **Average Response Time**: {:.1}ms\n", avg_response_time));
            summary.push_str(&format!("- **Final Host Aggression**: {:.3}\n\n", final_aggression));

            // Show some example results
            summary.push_str("### Sample Results:\n\n");
            summary.push_str("| Scenario | Expected | Detected | Similarity | Valence | Iteration |\n");
            summary.push_str("|----------|----------|----------|------------|---------|----------|\n");
            
            for (i, result) in suite.results.iter().enumerate() {
                if i >= 10 { break; } // Show first 10 results
                summary.push_str(&format!("| {} | {} | {} | {:.3} | {:.3} | {} |\n",
                    result.scenario_name,
                    result.expected_threat_level,
                    result.detected_action,
                    result.similarity_score,
                    result.valence,
                    result.learning_iteration + 1
                ));
            }
            summary.push_str("\n");
        }

        summary
    }

    pub fn export_results_csv(&self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut csv_content = String::new();
        csv_content.push_str("suite,scenario,attack_vector,expected_threat,detected_action,similarity,valence,aggression,response_time_ms,iteration\n");

        for suite in &self.test_suites {
            for result in &suite.results {
                csv_content.push_str(&format!("{},{},{},{},{},{:.3},{:.3},{:.3},{},{}\n",
                    suite.name,
                    result.scenario_name,
                    result.attack_vector,
                    result.expected_threat_level,
                    result.detected_action,
                    result.similarity_score,
                    result.valence,
                    result.host_aggression,
                    result.response_time_ms,
                    result.learning_iteration + 1
                ));
            }
        }

        fs::write(filename, csv_content)?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    let args: Vec<String> = std::env::args().collect();
    let mut iterations = 100;
    let mut scenarios = 20;
    
    // Parse command line arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iterations" => {
                if i + 1 < args.len() {
                    iterations = args[i + 1].parse().unwrap_or(100);
                    i += 2;
                } else {
                    i += 1;
                }
            },
            "--scenarios" => {
                if i + 1 < args.len() {
                    scenarios = args[i + 1].parse().unwrap_or(20);
                    i += 2;
                } else {
                    i += 1;
                }
            },
            _ => i += 1,
        }
    }
    
    println!("ShaneGuard Test Runner");
    println!("Iterations: {}, Scenarios: {}", iterations, scenarios);
    
    let config = Config::load_default();
    let mesh = Arc::new(Mutex::new(HostMeshCognition::new(0.1, 0.3, 0.2)));
    let mut test_runner = VulnerabilityTestRunner::new(mesh, config);
    
    // Load test scenarios
    test_runner.load_test_scenarios()?;
    
    // Run learning simulation
    test_runner.run_learning_simulation(WebServiceType::Apache, iterations).await?;
    
    // Generate reports
    let summary = test_runner.generate_results_summary();
    println!("{}", summary);
    test_runner.export_results_csv("test_results.csv")?;
    
    println!("Test results exported to test_results.csv");
    
    Ok(())
}