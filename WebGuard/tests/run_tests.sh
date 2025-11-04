#!/bin/bash

# WebGuard Test Runner Script
# This script runs the comprehensive test suite and generates visualizations

set -e

echo "🚀 WebGuard Test Suite Runner"
echo "=============================="

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "❌ Error: Please run this script from the WebGuard root directory"
    exit 1
fi

# Build the test binary
echo "🔨 Building comprehensive multipass test..."
cargo build --bin comprehensive_multipass_test

# Run the comprehensive test
echo "🧪 Running comprehensive multipass learning test..."
./target/debug/comprehensive_multipass_test

# Generate visualizations
echo "📊 Generating visualizations..."
if command -v python3 &> /dev/null; then
    python3 tests/scripts/generate_visualizations.py
elif command -v python &> /dev/null; then
    python tests/scripts/generate_visualizations.py
else
    echo "⚠️  Warning: Python not found. Skipping visualization generation."
fi

echo ""
echo "✅ Test suite completed successfully!"
echo ""
echo "📁 Results available in:"
echo "   - tests/results/ (raw data)"
echo "   - tests/documentation/ (reports)"
echo "   - tests/visualizations/ (charts)"
echo ""
echo "📖 See tests/README.md for detailed information"