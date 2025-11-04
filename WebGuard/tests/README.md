# WebGuard Test Suite

This directory contains all test-related files for the WebGuard cybersecurity system.

## Directory Structure

### `/scripts/`
Contains executable test scripts and programs:
- `comprehensive_multipass_test.rs` - Main comprehensive multipass learning test framework
- `generate_visualizations.py` - Python script for generating test result visualizations

### `/results/`
Contains test execution results and data:
- `webguard_test_metrics.json` - Raw test metrics in JSON format
- `webguard_test_metrics.csv` - Test metrics formatted for visualization

### `/documentation/`
Contains test documentation and analysis reports:
- `webguard_comprehensive_test_report.md` - Comprehensive test results summary
- `COMPREHENSIVE_TESTING_SUMMARY.md` - Historical testing summary
- `CRITICAL_ISSUES_ANALYSIS.md` - Analysis of critical issues and resolutions

### `/visualizations/`
Contains generated charts and visual analysis:
- `webguard_comprehensive_analysis.png` - Comprehensive test results visualization

## Running Tests

### Comprehensive Multipass Learning Test
```bash
# Build the test
cargo build --bin comprehensive_multipass_test

# Run the test
./target/debug/comprehensive_multipass_test
```

### Generate Visualizations
```bash
# Run the Python visualization script
python tests/scripts/generate_visualizations.py
```

## Test Results Summary

The latest comprehensive test demonstrates:
- **Detection Rate Improvement**: 30.4% → 80.8% (+50.3%)
- **Average Learning Efficiency**: 188.5%
- **Final False Negative Rate**: 19.2% (Security-First Achieved)
- **Final System Confidence**: 0.727
- **EQ/IQ Balance Stability**: 0.700

## Key Validations

✅ **Multipass Learning**: System shows consistent improvement across learning passes  
✅ **Experiential Integration**: Isolation Forest anomaly detection contributes to cognitive model  
✅ **Memory Consolidation**: PSI-BDH memory synergy enables effective long-term learning  
✅ **EQ/IQ Regulation**: Emotional-analytical balance prevents decision paralysis  
✅ **Security-First Approach**: System prioritizes threat detection over precision  
✅ **Fear Mitigation**: Negative experiences don't prevent necessary security actions  

For detailed results, see the documentation in `/documentation/`.