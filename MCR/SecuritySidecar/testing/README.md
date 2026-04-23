# SecuritySidecar Testing

## Standalone Tests (No NATS/MCR Required)

Run the standalone integration tests to verify all components work correctly:

```bash
cd MCR/SecuritySidecar
python testing/test_standalone.py
```

This tests:
- Scanner (injection detection, Unicode detection, trust classification)
- Redactor (credentials, PII, topology redaction)
- Sequence Analyzer (toxic flow pattern detection)
- Policy Engine (allowlist, denylist, approval gates)
- End-to-end pipeline (scan to redact flow)

## Full Integration with MCR

To test with actual MCR, you would need to:

### 1. Start NATS with JetStream

```bash
docker run -d --name nats -p 4222:4222 nats:2.10-alpine -js
```

### 2. Modify MCR core files per INTEGRATION.md

- Add scanner call in `context_plane.py:publish_event()`
- Add redactor call in `context_plane.py:reconstruct()`
- Add policy check in `mcr_orchestrator.py:handle_tool_call()`

### 3. Run the security sidecar

```bash
cd MCR
python -m SecuritySidecar.sidecar
```

### 4. Run MCR with a workflow that triggers security events

Execute a workflow that includes:
- Content with injection patterns (to test scanner)
- Tool results containing sensitive data (to test redactor)
- Tool call sequences that match toxic flow patterns (to test sequence analyzer)
- Calls to denylisted or approval-required tools (to test policy engine)

## Test Files

| File | Description |
|------|-------------|
| `test_standalone.py` | Comprehensive integration tests without external dependencies |
| `test_scanner.py` | Unit tests for scanner module |
| `test_redactor.py` | Unit tests for redactor module |
| `test_policy_engine.py` | Unit tests for policy engine (async) |
| `test_sequence_analyzer.py` | Unit tests for sequence analyzer |
| `test_integration.py` | Integration tests for module interactions |
| `conftest.py` | Pytest fixtures |
| `run_tests.sh` | Test runner script with coverage |

## Running pytest

```bash
# Run all tests
cd MCR/SecuritySidecar
./testing/run_tests.sh

# Run specific test file
python -m pytest testing/test_scanner.py -v

# Run with coverage
python -m pytest testing/ --cov=. --cov-report=html
```
