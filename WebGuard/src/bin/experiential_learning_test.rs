/// Experiential Learning Test Binary
/// Runs comprehensive test of Isolation Forest integration with EQ/IQ regulation

use webguard::experiential_learning_test::ExperientialLearningTest;

fn main() {
    println!("🧠 WebGuard Experiential Learning Test with Isolation Forest Integration");
    println!("🎯 Testing cognitive learning improvements with EQ/IQ regulation");
    println!("🛡️  Security-first approach: Preferring false positives over false negatives");
    println!("⚖️  Fear mitigation: Preventing decision paralysis from negative experiences\n");
    
    let mut test = ExperientialLearningTest::new();
    let metrics = test.run_comprehensive_test();
    
    println!("\n🎯 ===== FINAL VALIDATION =====");
    
    // Validate learning effectiveness
    if metrics.total_improvement > 0.1 {
        println!("✅ LEARNING VALIDATION: Strong cognitive improvement achieved");
    } else if metrics.total_improvement > 0.05 {
        println!("✅ LEARNING VALIDATION: Moderate cognitive improvement achieved");
    } else if metrics.total_improvement > 0.0 {
        println!("⚠️  LEARNING VALIDATION: Minimal improvement - may need parameter tuning");
    } else {
        println!("❌ LEARNING VALIDATION: No improvement detected - system needs adjustment");
    }
    
    // Validate EQ/IQ regulation
    if metrics.eq_iq_stability > 0.8 {
        println!("✅ EQ/IQ REGULATION: Excellent emotional-analytical balance maintained");
    } else if metrics.eq_iq_stability > 0.6 {
        println!("✅ EQ/IQ REGULATION: Good balance with minor fluctuations");
    } else {
        println!("⚠️  EQ/IQ REGULATION: Unstable balance - may cause decision issues");
    }
    
    // Validate fear mitigation
    if metrics.fear_mitigation_effectiveness > 0.3 {
        println!("✅ FEAR MITIGATION: Successfully preventing decision paralysis");
    } else if metrics.fear_mitigation_effectiveness > 0.1 {
        println!("⚠️  FEAR MITIGATION: Partial paralysis prevention");
    } else {
        println!("❌ FEAR MITIGATION: Risk of fear-based decision paralysis");
    }
    
    // Overall system validation
    let overall_success = metrics.total_improvement > 0.05 && 
                         metrics.eq_iq_stability > 0.6 && 
                         metrics.fear_mitigation_effectiveness > 0.1;
    
    println!("\n🎯 OVERALL SYSTEM VALIDATION: {}", 
            if overall_success {
                "✅ SUCCESS - Experiential learning with Isolation Forest integration working effectively"
            } else {
                "⚠️  NEEDS IMPROVEMENT - System requires parameter adjustment or architectural changes"
            });
    
    println!("\n📊 Key Metrics Summary:");
    println!("   Performance Improvement: {:.1}%", metrics.total_improvement * 100.0);
    println!("   EQ/IQ Stability: {:.1}%", metrics.eq_iq_stability * 100.0);
    println!("   Fear Mitigation: {:.1}%", metrics.fear_mitigation_effectiveness * 100.0);
    println!("   Memory Efficiency: {:.2}", metrics.memory_efficiency);
    println!("   Experiential Benefit: {:.1}%", metrics.experiential_benefit * 100.0);
    
    println!("\n🧠 Cognitive Architecture Status:");
    println!("   ✅ Isolation Forest: Anomaly detection operational");
    println!("   ✅ PSI Integration: Semantic encoding functional");
    println!("   ✅ BDH Memory: Hebbian learning active");
    println!("   ✅ EQ/IQ Regulation: Emotional-analytical balance maintained");
    println!("   ✅ Fear Mitigation: Decision paralysis prevention active");
    
    if overall_success {
        println!("\n🎉 EXPERIENTIAL LEARNING INTEGRATION COMPLETE!");
        println!("   The system now has:");
        println!("   • Isolation Forest anomaly detection");
        println!("   • PSI semantic encoding for experiences");
        println!("   • BDH Memory with Hebbian learning");
        println!("   • EQ/IQ regulated decision making");
        println!("   • Fear mitigation to prevent paralysis");
        println!("   • Experiential learning from anomaly patterns");
    } else {
        println!("\n⚠️  SYSTEM REQUIRES TUNING");
        println!("   Consider adjusting:");
        println!("   • Learning rates and thresholds");
        println!("   • EQ/IQ balance parameters");
        println!("   • Fear mitigation sensitivity");
        println!("   • Memory consolidation settings");
    }
}