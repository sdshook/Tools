# WebGuard Test Visualizations

This directory contains visualizations generated from WebGuard testing and experiential learning processes.

## Structure

- `learning_progress/` - Charts showing learning progression over time
- `performance_metrics/` - Performance analysis charts and graphs
- `threat_detection/` - Threat detection accuracy and false positive analysis
- `experiential_data/` - Visualizations of experiential learning patterns
- `comparative_analysis/` - Before/after comparisons and trend analysis

## Generated Files

All visualization files are automatically generated during test runs and include:
- PNG images for quick viewing
- SVG files for scalable graphics
- Interactive HTML plots where applicable
- Raw data CSV files for further analysis

## Usage

Run the comprehensive test suite to generate fresh visualizations:
```bash
cargo test --test experiential_learning_comprehensive
```

Or use the Python visualization scripts:
```bash
python scripts/generate_comprehensive_visualizations.py
```