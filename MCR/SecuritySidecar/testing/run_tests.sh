#!/bin/bash
#
# Run all SecuritySidecar tests
#
# Usage:
#   ./testing/run_tests.sh          # Run all tests
#   ./testing/run_tests.sh -v       # Verbose output
#   ./testing/run_tests.sh -k scan  # Run only tests matching "scan"
#

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Set PYTHONPATH to include the project directory
export PYTHONPATH="$PROJECT_DIR:$PYTHONPATH"

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    echo "pytest not found. Installing test dependencies..."
    pip install pytest pytest-asyncio pytest-cov
fi

echo "Running SecuritySidecar tests..."
echo "================================"

# Run pytest with coverage
python -m pytest testing/ \
    --tb=short \
    --cov=. \
    --cov-report=term-missing \
    --cov-report=html:testing/coverage_html \
    "$@"

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "All tests passed!"
    echo "Coverage report: testing/coverage_html/index.html"
else
    echo ""
    echo "Some tests failed. Exit code: $EXIT_CODE"
fi

exit $EXIT_CODE
