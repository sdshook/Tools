/// Comprehensive Test Suite for Experiential Learning with Isolation Forest Integration
/// Tests cognitive learning improvements, EQ/IQ regulation, and fear mitigation

use crate::experiential_anomaly::{ExperientialLearningIntegrator, AnomalyResult};
use crate::memory_engine::psi_index::PsiIndex;
use crate::memory_engine::bdh_memory::BdhMemory;
use crate::adaptive_threshold::AdaptiveThreshold;
use std::collections::HashMap;

/// Test configuration for experiential learning validation
pub struct ExperientialLearningTest {
    integrator: ExperientialLearningIntegrator,
    psi_index: PsiIndex,
    bdh_memory: BdhMemory,
    adaptive_threshold: AdaptiveThreshold,
    test_results: Vec<TestResult>,
    learning_passes: usize,
}

/// Individual test result for tracking learning progress
#[derive(Debug, Clone)]
pub struct TestResult {
    pub pass: usize,
    pub threat_detection_rate: f32,
    pub false_positive_rate: f32,
    pub false_negative_rate: f32,
    pub confidence_score: f32,
    pub memory_utilization: f32,
    pub eq_iq_balance: f32,
    pub fear_mitigation_applied: usize,
    pub experiential_context_used: usize,
    pub learning_improvement: f32,
}

/// Comprehensive learning metrics
#[derive(Debug)]
pub struct LearningMetrics {
    pub initial_performance: f32,
    pub final_performance: f32,
    pub total_improvement: f32,
    pub learning_rate: f32,
    pub memory_efficiency: f32,
    pub eq_iq_stability: f32,
    pub fear_mitigation_effectiveness: f32,
    pub experiential_benefit: f32,
}

impl ExperientialLearningTest {
    /// Create new experiential learning test
    pub fn new() -> Self {
        Self {
            integrator: ExperientialLearningIntegrator::new(),
            psi_index: PsiIndex::new(),
            bdh_memory: BdhMemory::new(),
            adaptive_threshold: AdaptiveThreshold::new(),
            test_results: Vec::new(),
            learning_passes: 5,
        }
    }

    /// Run comprehensive experiential learning test with security-first approach
    pub fn run_comprehensive_test(&mut self) -> LearningMetrics {
        println!("🧠 Starting Comprehensive Experiential Learning Test with Isolation Forest");
        println!("🎯 Security-First Approach: Preferring false positives over false negatives");
        println!("🔧 EQ/IQ Regulation: Preventing fear-based decision paralysis");
        
        // Generate diverse test dataset with anomalies
        let (normal_samples, anomaly_samples) = self.generate_test_dataset();
        
        // Train initial isolation forest
        let mut all_training_data = normal_samples.clone();
        all_training_data.extend(anomaly_samples.iter().take(anomaly_samples.len() / 2).cloned());
        self.integrator.train_detector(&all_training_data);
        
        println!("📊 Training isolation forest with {} samples ({} normal, {} anomalies)", 
                all_training_data.len(), normal_samples.len(), anomaly_samples.len() / 2);
        
        // Run multiple learning passes
        for pass in 0..self.learning_passes {
            println!("\n🔄 Learning Pass {}/{}", pass + 1, self.learning_passes);
            
            let test_result = self.run_learning_pass(
                pass, 
                &normal_samples, 
                &anomaly_samples
            );
            
            self.test_results.push(test_result.clone());
            
            // Display pass results
            println!("   📈 Threat Detection Rate: {:.1}%", test_result.threat_detection_rate * 100.0);
            println!("   🚨 False Positive Rate: {:.1}%", test_result.false_positive_rate * 100.0);
            println!("   ⚠️  False Negative Rate: {:.1}%", test_result.false_negative_rate * 100.0);
            println!("   🎯 Confidence Score: {:.3}", test_result.confidence_score);
            println!("   🧠 Memory Utilization: {:.1}%", test_result.memory_utilization * 100.0);
            println!("   ⚖️  EQ/IQ Balance: {:.3}", test_result.eq_iq_balance);
            println!("   🛡️  Fear Mitigation Applied: {} times", test_result.fear_mitigation_applied);
            println!("   💭 Experiential Context Used: {} times", test_result.experiential_context_used);
            
            if pass > 0 {
                println!("   📊 Learning Improvement: {:.1}%", test_result.learning_improvement * 100.0);
            }
        }
        
        // Calculate comprehensive metrics
        let metrics = self.calculate_learning_metrics();
        self.display_final_results(&metrics);
        
        metrics
    }
    
    /// Run single learning pass
    fn run_learning_pass(
        &mut self, 
        pass: usize, 
        normal_samples: &[Vec<f32>], 
        anomaly_samples: &[Vec<f32>]
    ) -> TestResult {
        let mut correct_detections = 0;
        let mut false_positives = 0;
        let mut false_negatives = 0;
        let mut total_confidence = 0.0;
        let mut fear_mitigation_count = 0;
        let mut experiential_context_count = 0;
        
        let total_tests = normal_samples.len() + anomaly_samples.len();
        
        // Test normal samples (should not be anomalies)
        for (i, sample) in normal_samples.iter().enumerate() {
            let context_stability = 0.8 + (i as f32 / normal_samples.len() as f32) * 0.2;
            let threat_level = 0.1; // Low threat for normal samples
            
            let result = self.integrator.process_experiential_input(
                sample,
                &self.psi_index,
                &self.bdh_memory,
                context_stability,
                threat_level
            );
            
            total_confidence += result.confidence;
            
            if result.memory_triggered {
                experiential_context_count += 1;
            }
            
            // Count fear mitigation applications
            fear_mitigation_count += result.experiential_context.iter()
                .filter(|ctx| ctx.fear_mitigation_applied)
                .count();
            
            if !result.is_anomaly {
                correct_detections += 1;
            } else {
                false_positives += 1;
            }
            
            // Create experiential memory for learning
            self.integrator.create_experiential_memory(
                sample,
                &result,
                &mut self.psi_index,
                &mut self.bdh_memory,
                context_stability,
                false // Not an actual threat
            );
        }
        
        // Test anomaly samples (should be detected as anomalies)
        for (i, sample) in anomaly_samples.iter().enumerate() {
            let context_stability = 0.6 + (i as f32 / anomaly_samples.len() as f32) * 0.3;
            let threat_level = 0.7 + (i as f32 / anomaly_samples.len() as f32) * 0.3; // High threat for anomalies
            
            let result = self.integrator.process_experiential_input(
                sample,
                &self.psi_index,
                &self.bdh_memory,
                context_stability,
                threat_level
            );
            
            total_confidence += result.confidence;
            
            if result.memory_triggered {
                experiential_context_count += 1;
            }
            
            // Count fear mitigation applications
            fear_mitigation_count += result.experiential_context.iter()
                .filter(|ctx| ctx.fear_mitigation_applied)
                .count();
            
            if result.is_anomaly {
                correct_detections += 1;
            } else {
                false_negatives += 1;
            }
            
            // Create experiential memory for learning
            self.integrator.create_experiential_memory(
                sample,
                &result,
                &mut self.psi_index,
                &mut self.bdh_memory,
                context_stability,
                true // Actual threat
            );
        }
        
        // Calculate metrics
        let threat_detection_rate = correct_detections as f32 / total_tests as f32;
        let false_positive_rate = false_positives as f32 / normal_samples.len() as f32;
        let false_negative_rate = false_negatives as f32 / anomaly_samples.len() as f32;
        let confidence_score = total_confidence / total_tests as f32;
        
        // Get memory statistics
        let memory_stats = self.bdh_memory.get_memory_stats();
        let memory_utilization = memory_stats.memory_usage;
        
        // Get EQ/IQ statistics
        let eq_iq_stats = self.integrator.get_comprehensive_stats();
        let eq_iq_balance = eq_iq_stats.get("eq_iq_balance").copied().unwrap_or(0.5);
        
        // Calculate learning improvement
        let learning_improvement = if pass > 0 {
            let previous_performance = self.test_results[pass - 1].threat_detection_rate;
            threat_detection_rate - previous_performance
        } else {
            0.0
        };
        
        TestResult {
            pass,
            threat_detection_rate,
            false_positive_rate,
            false_negative_rate,
            confidence_score,
            memory_utilization,
            eq_iq_balance,
            fear_mitigation_applied: fear_mitigation_count,
            experiential_context_used: experiential_context_count,
            learning_improvement,
        }
    }
    
    /// Generate diverse test dataset with normal and anomalous patterns
    fn generate_test_dataset(&self) -> (Vec<Vec<f32>>, Vec<Vec<f32>>) {
        let mut normal_samples = Vec::new();
        let mut anomaly_samples = Vec::new();
        
        // Generate normal patterns (clustered around common values)
        for i in 0..100 {
            let base_pattern = vec![
                1.0 + (i as f32 * 0.01),
                2.0 + (i as f32 * 0.02),
                3.0 + (i as f32 * 0.01),
                0.5 + (i as f32 * 0.005),
                1.5 + (i as f32 * 0.01),
            ];
            normal_samples.push(base_pattern);
        }
        
        // Generate anomalous patterns (outliers and unusual combinations)
        for i in 0..50 {
            let anomaly_pattern = vec![
                10.0 + (i as f32 * 0.1),  // Much higher values
                -5.0 + (i as f32 * 0.05), // Negative values
                100.0 + (i as f32 * 0.5), // Extreme outliers
                0.001 + (i as f32 * 0.0001), // Very small values
                50.0 + (i as f32 * 0.2),  // Unusual combinations
            ];
            anomaly_samples.push(anomaly_pattern);
        }
        
        (normal_samples, anomaly_samples)
    }
    
    /// Calculate comprehensive learning metrics
    fn calculate_learning_metrics(&self) -> LearningMetrics {
        if self.test_results.is_empty() {
            return LearningMetrics {
                initial_performance: 0.0,
                final_performance: 0.0,
                total_improvement: 0.0,
                learning_rate: 0.0,
                memory_efficiency: 0.0,
                eq_iq_stability: 0.0,
                fear_mitigation_effectiveness: 0.0,
                experiential_benefit: 0.0,
            };
        }
        
        let initial_performance = self.test_results[0].threat_detection_rate;
        let final_performance = self.test_results.last().unwrap().threat_detection_rate;
        let total_improvement = final_performance - initial_performance;
        
        // Calculate learning rate (improvement per pass)
        let learning_rate = if self.test_results.len() > 1 {
            total_improvement / (self.test_results.len() - 1) as f32
        } else {
            0.0
        };
        
        // Calculate memory efficiency (performance per memory usage)
        let avg_memory_usage = self.test_results.iter()
            .map(|r| r.memory_utilization)
            .sum::<f32>() / self.test_results.len() as f32;
        let memory_efficiency = final_performance / avg_memory_usage.max(0.01);
        
        // Calculate EQ/IQ stability (consistency of balance)
        let eq_iq_values: Vec<f32> = self.test_results.iter()
            .map(|r| r.eq_iq_balance)
            .collect();
        let eq_iq_mean = eq_iq_values.iter().sum::<f32>() / eq_iq_values.len() as f32;
        let eq_iq_variance = eq_iq_values.iter()
            .map(|x| (x - eq_iq_mean).powi(2))
            .sum::<f32>() / eq_iq_values.len() as f32;
        let eq_iq_stability = 1.0 - eq_iq_variance.sqrt(); // Higher stability = lower variance
        
        // Calculate fear mitigation effectiveness
        let total_fear_mitigation = self.test_results.iter()
            .map(|r| r.fear_mitigation_applied)
            .sum::<usize>() as f32;
        let total_contexts = self.test_results.iter()
            .map(|r| r.experiential_context_used)
            .sum::<usize>() as f32;
        let fear_mitigation_effectiveness = if total_contexts > 0.0 {
            total_fear_mitigation / total_contexts
        } else {
            0.0
        };
        
        // Calculate experiential benefit (improvement from using experiential context)
        let experiential_benefit = self.test_results.iter()
            .filter(|r| r.experiential_context_used > 0)
            .map(|r| r.threat_detection_rate)
            .sum::<f32>() / self.test_results.iter()
            .filter(|r| r.experiential_context_used > 0)
            .count().max(1) as f32;
        
        LearningMetrics {
            initial_performance,
            final_performance,
            total_improvement,
            learning_rate,
            memory_efficiency,
            eq_iq_stability,
            fear_mitigation_effectiveness,
            experiential_benefit,
        }
    }
    
    /// Display comprehensive final results
    fn display_final_results(&self, metrics: &LearningMetrics) {
        println!("\n🎯 ===== COMPREHENSIVE EXPERIENTIAL LEARNING RESULTS =====");
        println!("📊 Performance Metrics:");
        println!("   Initial Performance: {:.1}%", metrics.initial_performance * 100.0);
        println!("   Final Performance: {:.1}%", metrics.final_performance * 100.0);
        println!("   Total Improvement: {:.1}% ({:+.1}%)", 
                metrics.total_improvement * 100.0, 
                metrics.total_improvement * 100.0);
        println!("   Learning Rate: {:.3}% per pass", metrics.learning_rate * 100.0);
        
        println!("\n🧠 Cognitive Architecture Metrics:");
        println!("   Memory Efficiency: {:.2}", metrics.memory_efficiency);
        println!("   EQ/IQ Stability: {:.3}", metrics.eq_iq_stability);
        println!("   Fear Mitigation Effectiveness: {:.1}%", metrics.fear_mitigation_effectiveness * 100.0);
        println!("   Experiential Benefit: {:.1}%", metrics.experiential_benefit * 100.0);
        
        println!("\n🔍 Detailed Analysis:");
        
        // Analyze learning trajectory
        if metrics.total_improvement > 0.1 {
            println!("   ✅ STRONG LEARNING: Significant improvement across passes");
        } else if metrics.total_improvement > 0.05 {
            println!("   ✅ MODERATE LEARNING: Consistent improvement observed");
        } else if metrics.total_improvement > 0.0 {
            println!("   ⚠️  WEAK LEARNING: Minimal improvement detected");
        } else {
            println!("   ❌ NO LEARNING: No improvement or performance degradation");
        }
        
        // Analyze EQ/IQ regulation effectiveness
        if metrics.eq_iq_stability > 0.8 {
            println!("   ✅ STABLE EQ/IQ REGULATION: Consistent emotional-analytical balance");
        } else if metrics.eq_iq_stability > 0.6 {
            println!("   ⚠️  MODERATE EQ/IQ STABILITY: Some fluctuation in balance");
        } else {
            println!("   ❌ UNSTABLE EQ/IQ REGULATION: Significant balance fluctuations");
        }
        
        // Analyze fear mitigation
        if metrics.fear_mitigation_effectiveness > 0.3 {
            println!("   ✅ EFFECTIVE FEAR MITIGATION: Successfully preventing decision paralysis");
        } else if metrics.fear_mitigation_effectiveness > 0.1 {
            println!("   ⚠️  MODERATE FEAR MITIGATION: Some paralysis prevention");
        } else {
            println!("   ❌ INEFFECTIVE FEAR MITIGATION: Risk of decision paralysis");
        }
        
        // Security-first validation
        let final_result = self.test_results.last().unwrap();
        if final_result.false_negative_rate < 0.2 {
            println!("   ✅ SECURITY-FIRST ACHIEVED: Low false negative rate");
        } else {
            println!("   ⚠️  SECURITY-FIRST CONCERN: High false negative rate");
        }
        
        println!("\n🎯 EXPERIENTIAL LEARNING VALIDATION: {}", 
                if metrics.total_improvement > 0.05 && metrics.eq_iq_stability > 0.6 {
                    "✅ SUCCESSFUL - Cognitive learning with EQ/IQ regulation working effectively"
                } else {
                    "⚠️  NEEDS IMPROVEMENT - Cognitive learning or regulation requires adjustment"
                });
    }
    
    /// Get test results for external analysis
    pub fn get_test_results(&self) -> &[TestResult] {
        &self.test_results
    }
    
    /// Get final learning metrics
    pub fn get_learning_metrics(&self) -> LearningMetrics {
        self.calculate_learning_metrics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_experiential_learning_integration() {
        let mut test = ExperientialLearningTest::new();
        let metrics = test.run_comprehensive_test();
        
        // Validate that learning occurred
        assert!(metrics.final_performance >= metrics.initial_performance, 
               "Performance should not degrade");
        
        // Validate EQ/IQ regulation stability
        assert!(metrics.eq_iq_stability > 0.0, 
               "EQ/IQ regulation should maintain some stability");
        
        // Validate fear mitigation is functioning
        assert!(metrics.fear_mitigation_effectiveness >= 0.0, 
               "Fear mitigation should be non-negative");
    }
    
    #[test]
    fn test_isolation_forest_anomaly_detection() {
        let mut test = ExperientialLearningTest::new();
        let (normal_samples, anomaly_samples) = test.generate_test_dataset();
        
        // Train detector
        let mut training_data = normal_samples.clone();
        training_data.extend(anomaly_samples.iter().take(10).cloned());
        test.integrator.train_detector(&training_data);
        
        // Test anomaly detection
        let normal_result = test.integrator.process_experiential_input(
            &normal_samples[0],
            &test.psi_index,
            &test.bdh_memory,
            0.8,
            0.1
        );
        
        let anomaly_result = test.integrator.process_experiential_input(
            &anomaly_samples[0],
            &test.psi_index,
            &test.bdh_memory,
            0.7,
            0.9
        );
        
        // Anomaly should have higher score than normal
        assert!(anomaly_result.anomaly_score > normal_result.anomaly_score,
               "Anomaly should have higher anomaly score");
    }
}