use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use serde_json;

use webguard::webguard_system::{WebGuardSystem, WebGuardConfig, ThreatAnalysisResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestRequest {
    id: String,
    timestamp: String,
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
    source_ip: String,
    label: String,
    threat_type: Option<String>,
    confidence: f64,
    injection_point: Option<String>,
    pattern: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TestResults {
    total_samples: usize,
    benign_samples: usize,
    threat_samples: usize,
    true_positives: usize,
    false_positives: usize,
    true_negatives: usize,
    false_negatives: usize,
    accuracy: f64,
    precision: f64,
    recall: f64,
    f1_score: f64,
    processing_time_ms: u128,
    learning_progression: Vec<LearningMetrics>,
    threat_type_performance: HashMap<String, ThreatTypeMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LearningMetrics {
    batch_number: usize,
    samples_processed: usize,
    current_accuracy: f64,
    current_precision: f64,
    current_recall: f64,
    false_positive_rate: f64,
    learning_rate: f64,
    confidence_threshold: f64,
    processing_time_ms: u128,
}

#[derive(Debug, Serialize, Deserialize)]
struct ThreatTypeMetrics {
    total_samples: usize,
    detected: usize,
    missed: usize,
    detection_rate: f64,
    avg_confidence: f64,
}

struct ExperientialLearningTester {
    webguard: WebGuardSystem,
    test_data: Vec<TestRequest>,
    results: TestResults,
    batch_size: usize,
}

impl ExperientialLearningTester {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Load test data
        let data_path = Path::new("tests/data/comprehensive_test_data.json");
        let data_content = fs::read_to_string(data_path)?;
        let test_data: Vec<TestRequest> = serde_json::from_str(&data_content)?;
        
        // Initialize WebGuard with default config
        let mut webguard = WebGuardSystem::new();
        
        let benign_count = test_data.iter().filter(|r| r.label == "benign").count();
        let threat_count = test_data.iter().filter(|r| r.label == "threat").count();
        
        let results = TestResults {
            total_samples: test_data.len(),
            benign_samples: benign_count,
            threat_samples: threat_count,
            true_positives: 0,
            false_positives: 0,
            true_negatives: 0,
            false_negatives: 0,
            accuracy: 0.0,
            precision: 0.0,
            recall: 0.0,
            f1_score: 0.0,
            processing_time_ms: 0,
            learning_progression: Vec::new(),
            threat_type_performance: HashMap::new(),
        };
        
        Ok(ExperientialLearningTester {
            webguard,
            test_data,
            results,
            batch_size: 50, // Process in batches to show learning progression
        })
    }
    
    fn convert_to_http_request(&self, test_req: &TestRequest) -> HttpRequest {
        HttpRequest {
            method: test_req.method.clone(),
            path: test_req.path.clone(),
            headers: test_req.headers.clone(),
            body: test_req.body.clone(),
            source_ip: test_req.source_ip.clone(),
            timestamp: chrono::Utc::now(),
        }
    }
    
    fn run_comprehensive_test(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting comprehensive experiential learning test...");
        println!("Dataset: {} samples ({} benign, {} threats)", 
                 self.results.total_samples, 
                 self.results.benign_samples, 
                 self.results.threat_samples);
        
        let start_time = Instant::now();
        let total_batches = (self.test_data.len() + self.batch_size - 1) / self.batch_size;
        
        // Process data in batches to demonstrate learning progression
        for batch_num in 0..total_batches {
            let batch_start = batch_num * self.batch_size;
            let batch_end = std::cmp::min(batch_start + self.batch_size, self.test_data.len());
            let batch = &self.test_data[batch_start..batch_end];
            
            let batch_start_time = Instant::now();
            let batch_metrics = self.process_batch(batch, batch_num + 1)?;
            let batch_time = batch_start_time.elapsed().as_millis();
            
            // Update learning metrics
            let mut learning_metrics = batch_metrics;
            learning_metrics.processing_time_ms = batch_time;
            self.results.learning_progression.push(learning_metrics.clone());
            
            println!("Batch {}/{}: Processed {} samples, Accuracy: {:.2}%, Precision: {:.2}%, Recall: {:.2}%",
                     batch_num + 1, total_batches, batch.len(),
                     learning_metrics.current_accuracy * 100.0,
                     learning_metrics.current_precision * 100.0,
                     learning_metrics.current_recall * 100.0);
            
            // Allow the system to learn from this batch
            self.webguard.trigger_learning_cycle()?;
        }
        
        self.results.processing_time_ms = start_time.elapsed().as_millis();
        self.calculate_final_metrics();
        self.calculate_threat_type_performance();
        
        println!("\nTest completed in {:.2}s", self.results.processing_time_ms as f64 / 1000.0);
        self.print_results();
        
        Ok(())
    }
    
    fn process_batch(&mut self, batch: &[TestRequest], batch_num: usize) -> Result<LearningMetrics, Box<dyn std::error::Error>> {
        let mut batch_tp = 0;
        let mut batch_fp = 0;
        let mut batch_tn = 0;
        let mut batch_fn = 0;
        
        for test_req in batch {
            let http_req = self.convert_to_http_request(test_req);
            
            // Process request through WebGuard
            let evidence = self.webguard.process_request(&http_req)?;
            let is_threat_detected = evidence.threat_score > self.webguard.get_config().confidence_threshold;
            let is_actual_threat = test_req.label == "threat";
            
            // Update confusion matrix
            match (is_actual_threat, is_threat_detected) {
                (true, true) => {
                    batch_tp += 1;
                    self.results.true_positives += 1;
                },
                (false, true) => {
                    batch_fp += 1;
                    self.results.false_positives += 1;
                },
                (false, false) => {
                    batch_tn += 1;
                    self.results.true_negatives += 1;
                },
                (true, false) => {
                    batch_fn += 1;
                    self.results.false_negatives += 1;
                },
            }
            
            // Provide feedback for learning (simulate ground truth feedback)
            if is_actual_threat != is_threat_detected {
                self.provide_learning_feedback(&http_req, is_actual_threat, &evidence)?;
            }
        }
        
        // Calculate batch metrics
        let samples_processed = batch_num * self.batch_size.min(self.test_data.len() - (batch_num - 1) * self.batch_size);
        let accuracy = (self.results.true_positives + self.results.true_negatives) as f64 / samples_processed as f64;
        let precision = if self.results.true_positives + self.results.false_positives > 0 {
            self.results.true_positives as f64 / (self.results.true_positives + self.results.false_positives) as f64
        } else { 0.0 };
        let recall = if self.results.true_positives + self.results.false_negatives > 0 {
            self.results.true_positives as f64 / (self.results.true_positives + self.results.false_negatives) as f64
        } else { 0.0 };
        let fpr = if self.results.false_positives + self.results.true_negatives > 0 {
            self.results.false_positives as f64 / (self.results.false_positives + self.results.true_negatives) as f64
        } else { 0.0 };
        
        Ok(LearningMetrics {
            batch_number: batch_num,
            samples_processed,
            current_accuracy: accuracy,
            current_precision: precision,
            current_recall: recall,
            false_positive_rate: fpr,
            learning_rate: self.webguard.get_config().learning_rate,
            confidence_threshold: self.webguard.get_config().confidence_threshold,
            processing_time_ms: 0, // Will be set by caller
        })
    }
    
    fn provide_learning_feedback(&mut self, request: &HttpRequest, is_threat: bool, evidence: &Evidence) -> Result<(), Box<dyn std::error::Error>> {
        // Simulate providing ground truth feedback to the learning system
        if is_threat {
            // This was a threat that was missed or incorrectly classified
            self.webguard.learn_from_threat(request, evidence)?;
        } else {
            // This was benign traffic that was incorrectly flagged
            self.webguard.learn_from_false_positive(request, evidence)?;
        }
        Ok(())
    }
    
    fn calculate_final_metrics(&mut self) {
        let total = self.results.total_samples as f64;
        self.results.accuracy = (self.results.true_positives + self.results.true_negatives) as f64 / total;
        
        if self.results.true_positives + self.results.false_positives > 0 {
            self.results.precision = self.results.true_positives as f64 / 
                (self.results.true_positives + self.results.false_positives) as f64;
        }
        
        if self.results.true_positives + self.results.false_negatives > 0 {
            self.results.recall = self.results.true_positives as f64 / 
                (self.results.true_positives + self.results.false_negatives) as f64;
        }
        
        if self.results.precision + self.results.recall > 0.0 {
            self.results.f1_score = 2.0 * (self.results.precision * self.results.recall) / 
                (self.results.precision + self.results.recall);
        }
    }
    
    fn calculate_threat_type_performance(&mut self) {
        let mut threat_stats: HashMap<String, (usize, usize, f64)> = HashMap::new();
        
        for test_req in &self.test_data {
            if test_req.label == "threat" {
                if let Some(threat_type) = &test_req.threat_type {
                    let entry = threat_stats.entry(threat_type.clone()).or_insert((0, 0, 0.0));
                    entry.0 += 1; // total
                    
                    // Simulate detection check (in real implementation, this would be stored during processing)
                    let http_req = self.convert_to_http_request(test_req);
                    if let Ok(evidence) = self.webguard.process_request(&http_req) {
                        if evidence.threat_score > self.webguard.get_config().confidence_threshold {
                            entry.1 += 1; // detected
                        }
                        entry.2 += evidence.threat_score; // sum confidence
                    }
                }
            }
        }
        
        for (threat_type, (total, detected, sum_confidence)) in threat_stats {
            let detection_rate = detected as f64 / total as f64;
            let avg_confidence = sum_confidence / total as f64;
            
            self.results.threat_type_performance.insert(threat_type, ThreatTypeMetrics {
                total_samples: total,
                detected,
                missed: total - detected,
                detection_rate,
                avg_confidence,
            });
        }
    }
    
    fn print_results(&self) {
        println!("\n" + "=".repeat(60).as_str());
        println!("EXPERIENTIAL LEARNING TEST RESULTS");
        println!("=".repeat(60));
        
        println!("\nOverall Performance:");
        println!("  Accuracy:  {:.2}%", self.results.accuracy * 100.0);
        println!("  Precision: {:.2}%", self.results.precision * 100.0);
        println!("  Recall:    {:.2}%", self.results.recall * 100.0);
        println!("  F1-Score:  {:.2}%", self.results.f1_score * 100.0);
        
        println!("\nConfusion Matrix:");
        println!("  True Positives:  {}", self.results.true_positives);
        println!("  False Positives: {}", self.results.false_positives);
        println!("  True Negatives:  {}", self.results.true_negatives);
        println!("  False Negatives: {}", self.results.false_negatives);
        
        println!("\nThreat Type Performance:");
        for (threat_type, metrics) in &self.results.threat_type_performance {
            println!("  {}: {}/{} detected ({:.1}%), avg confidence: {:.3}",
                     threat_type, metrics.detected, metrics.total_samples,
                     metrics.detection_rate * 100.0, metrics.avg_confidence);
        }
        
        println!("\nLearning Progression:");
        let progression_samples = [1, 5, 10, 15, 20]; // Show specific batch numbers
        for &batch_num in &progression_samples {
            if let Some(metrics) = self.results.learning_progression.get(batch_num - 1) {
                println!("  Batch {}: Accuracy {:.1}%, Precision {:.1}%, Recall {:.1}%, FPR {:.1}%",
                         batch_num, metrics.current_accuracy * 100.0,
                         metrics.current_precision * 100.0, metrics.current_recall * 100.0,
                         metrics.false_positive_rate * 100.0);
            }
        }
        
        println!("\nProcessing Performance:");
        println!("  Total time: {:.2}s", self.results.processing_time_ms as f64 / 1000.0);
        println!("  Avg per sample: {:.2}ms", self.results.processing_time_ms as f64 / self.results.total_samples as f64);
    }
    
    fn save_results(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Save detailed results
        let results_path = Path::new("tests/results/experiential_learning_results.json");
        fs::create_dir_all(results_path.parent().unwrap())?;
        let results_json = serde_json::to_string_pretty(&self.results)?;
        fs::write(results_path, results_json)?;
        
        // Save learning progression CSV for visualization
        let progression_path = Path::new("tests/results/learning_progression.csv");
        let mut csv_content = String::from("batch,samples_processed,accuracy,precision,recall,false_positive_rate,processing_time_ms\n");
        for metrics in &self.results.learning_progression {
            csv_content.push_str(&format!("{},{},{:.4},{:.4},{:.4},{:.4},{}\n",
                metrics.batch_number, metrics.samples_processed,
                metrics.current_accuracy, metrics.current_precision,
                metrics.current_recall, metrics.false_positive_rate,
                metrics.processing_time_ms));
        }
        fs::write(progression_path, csv_content)?;
        
        println!("\nResults saved to:");
        println!("  {}", results_path.display());
        println!("  {}", progression_path.display());
        
        Ok(())
    }
}

#[tokio::test]
async fn test_experiential_learning_comprehensive() -> Result<(), Box<dyn std::error::Error>> {
    println!("WebGuard Comprehensive Experiential Learning Test");
    println!("Testing with 1000 samples (95% benign, 5% threats)");
    
    let mut tester = ExperientialLearningTester::new()?;
    tester.run_comprehensive_test()?;
    tester.save_results()?;
    
    // Verify minimum performance thresholds
    assert!(tester.results.accuracy > 0.80, "Accuracy should be > 80%");
    assert!(tester.results.precision > 0.70, "Precision should be > 70%");
    assert!(tester.results.recall > 0.60, "Recall should be > 60%");
    
    // Verify learning progression (accuracy should improve over time)
    if tester.results.learning_progression.len() >= 2 {
        let first_batch = &tester.results.learning_progression[0];
        let last_batch = &tester.results.learning_progression[tester.results.learning_progression.len() - 1];
        assert!(last_batch.current_accuracy >= first_batch.current_accuracy,
                "Learning should show improvement or maintain performance");
    }
    
    println!("\n✅ All test assertions passed!");
    println!("🧠 Experiential learning demonstrated successfully!");
    
    Ok(())
}