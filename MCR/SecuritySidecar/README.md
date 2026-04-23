# SecuritySidecar

**Model Context Routing: Supporting an Enterprise AI Security Plane**

*Shane D. Shook, PhD, April 18, 2026*

## Overview

Enterprise AI workflows introduce security risks that conventional application security tooling cannot address. Prompt injection, malicious tool call sequences, and data leakage via model context are runtime threats that exist inside the AI execution layer, below the network perimeter and above the application logic, in a gap that neither firewalls nor API gateways reach.

Model Context Routing (MCR) closes this gap. Because MCR interposes a persistent, event-driven context plane between all ingress sources and every model invocation, it occupies the exact architectural position required to enforce security policy universally. Every MCP tool call, REST webhook, CLI invocation, and agent output passes through the MCR context plane before reaching the model. That single chokepoint, reinforced by MCR's durable JetStream event log and declarative routing policy engine, is the foundation of a comprehensive AI security plane.

## The Security Problem

Standard AI invocation protocols (MCP, REST APIs, CLI tools) define how a model receives context and returns a response within a single call. They do not define what happens to that context across calls, who is permitted to inject content into it, or how to detect when tool results have been weaponized to redirect model behavior.

Three threat classes exploit this gap:

**Prompt injection via tool results.** When an AI agent reads external content (a GitHub issue, a document, a web page, a database record), that content becomes part of the model's context. Adversaries embed instructions in this content that override system prompts or redirect tool use. In a stateless architecture there is no layer positioned to scan tool results before they reach the model.

**Toxic tool call sequences.** A single tool call may be benign in isolation but malicious in sequence. Reading credentials from a secrets store followed immediately by an outbound network call is a data exfiltration pattern regardless of whether each individual call is permitted. Stateless architectures have no memory of prior tool calls within a workflow, making sequence-based detection impossible.

**Context-borne data leakage.** PII, API keys, internal network topology, and other sensitive material routinely appear in tool results. Without a reconstruction layer that can scan and redact before model injection, this material enters the model's context window and may subsequently appear in model outputs, logs, or downstream tool calls.

API gateways operate on HTTP request and response envelopes. They see the fact of a tool call but not the semantic sequence of tool calls within a workflow. SIEM systems receive logs after execution and can detect but not prevent. MCR operates before execution, with full knowledge of the workflow's event history, making it the only layer positioned to enforce both content and sequence policies simultaneously.

## Architecture

MCR's architecture defines four functional layers, each of which becomes a natural enforcement point when extended with security controls. No new infrastructure is required.

### Ingress Normalization: Injection Detection

All events enter the MCR context plane through the ingress normalization layer, where they are converted to a consistent event schema before publication to JetStream. This is the correct location to scan for injection content, because it occurs before any event is persisted and before any context is reconstructed for model delivery.

The scan examines every inbound payload for:
- Invisible Unicode characters used to conceal instructions
- HTML comment blocks and hidden markdown fragments
- Known injection phrase patterns (directives to ignore prior instructions, assume a new identity)
- Base64-encoded payloads that may carry obfuscated instruction content

Each event is annotated with a trust level derived from its source type. Content originating from external tool results is tagged as low-trust, and that tag persists through the entire workflow lifecycle.

### Context Persistence: Immutable Audit Log

JetStream's immutable event log, which MCR already uses for context reconstruction, is simultaneously the most capable forensic resource available in an enterprise AI deployment. Every event (the exact content the model had access to at each decision point, the tool calls made, and the model outputs returned) is retained with configurable retention periods and is replayable on demand.

This enables:
- **Post-incident investigation**: Reconstruct the exact context that preceded an anomalous model output
- **Compliance verification**: Demonstrate to auditors that a model-assisted decision was made using only approved data within defined policy constraints

### Context Reconstruction: Trust-Aware Redaction

The reconstruction service assembles the context window delivered to the model at each workflow step. MCR's existing relevance-ratio filtering already limits what prior context is reconstructed. Trust-aware redaction means that low-trust events undergo content scanning before their payloads are included.

Redaction targets:
- Credentials and API keys matching known token formats
- Personally identifiable information (national identifiers, contact data, financial account numbers)
- Internal network topology (private IP ranges, internal hostnames)
- Any content flagged during ingress scanning

The original event is retained unmodified in JetStream for forensic purposes. Only the reconstructed context delivered to the model is sanitized.

### Routing and Dispatch: Sequence Policy Enforcement

The routing layer has visibility into the full event history of a workflow instance through JetStream. Before any tool call is dispatched, the routing engine queries the workflow's prior event stream and evaluates the proposed call against declared sequence policies.

Sequence policies can express constraints such as:
- Deny any outbound network tool call in a workflow where a credential-read tool call has occurred within the prior five steps
- Require human confirmation before executing any destructive operation
- Limit the number of external egress calls per workflow instance
- Deny any tool call to a destination not on the approved domain list

## Security Control Mapping

| Threat | Component | Mechanism |
|--------|-----------|-----------|
| Prompt injection via tool results | Ingress normalization | Unicode and pattern scanning before JetStream persist; trust-level tagging |
| Hidden instruction injection | Ingress normalization | Content sanitization on low-trust source types |
| Toxic tool call sequences | Routing and dispatch | JetStream history query; sequence policy evaluation |
| Credential exfiltration | Context reconstruction | Regex-based redaction before context assembly |
| PII leakage into model context | Context reconstruction | Entity recognition and placeholder substitution |
| Unapproved egress destinations | Routing and dispatch | Domain allowlist enforcement |
| Post-incident investigation | Context persistence | Replay of exact event stream by workflow_id |
| Compliance audit | Context persistence | Tamper-evident, time-retained event log |
| Anomaly detection and alerting | All layers | Security events to dedicated NATS subject; wildcard consumer feeds SIEM |

## Why a Sidecar Architecture

The security sidecar rides alongside the MCR context plane without modifying the core architecture. MCR's job stays what it is: attention management, context persistence, and routing. The sidecar observes the same event stream, enforces policy at two synchronous points (ingress scan before publish, policy check before dispatch), and otherwise operates independently.

**Failure isolation.** If the scanner crashes or a redaction pattern causes an exception, it should not take down context routing. The sidecar failing degrades security posture but does not stop the workflow plane from functioning. You can configure synchronous checks to fail-open or fail-closed per environment.

**Independent deployment.** The audit consumer, investigator, and SIEM forwarder have no reason to run in the same process or container as the MCR orchestrator. They just need NATS access. You can scale, update, and restart them independently.

**Independent policy updates.** policy.yaml and patterns.yaml can be reloaded without restarting MCR. New toxic flow patterns, updated redaction rules, and revised allowlists are sidecar concerns that never touch routing or persistence configuration.

**Clean repo structure.** MCR core stays in src/. The sidecar lives entirely in SecuritySidecar/ with its own requirements, config, and entry points.

The only coupling is intentional and minimal: two call sites in existing MCR files (context_plane.py and mcr_orchestrator.py) where the sidecar must be synchronous. Everything else is the sidecar listening on NATS just like any other consumer.

## Installation

### Prerequisites

- Python 3.10+
- MCR core installed and running
- NATS server with JetStream enabled
- Access to MCR's NATS account

### Install Dependencies

```bash
cd SecuritySidecar
pip install -r requirements.txt
```

For the full feature set including PII detection with presidio-analyzer (which includes spaCy models):

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

### Quick Start

```bash
# Copy sample configuration
cp policy.yaml.example policy.yaml
cp patterns.yaml.example patterns.yaml

# Edit configuration for your environment
vim policy.yaml

# Run the audit consumer
python -m sidecar
```

## Configuration

### policy.yaml

The primary configuration file governing security behavior:

```yaml
tools:
  allowlist: [read_file, search_code, run_tests, query_db]
  denylist: [execute_shell]
  require_approval: [delete_*, publish_*, send_*]

sequences:
  patterns_file: patterns.yaml

egress:
  max_calls_per_workflow: 3
  approved_domains: [api.internal.com, docs.company.com]

redaction:
  credentials: true
  pii: true
  internal_topology: true

retention:
  security_events_days: 90
  audit_records_days: 365

siem:
  endpoint: https://siem.internal/ingest
  format: json
```

### patterns.yaml

Defines toxic flow patterns for sequence detection:

```yaml
toxic_flows:
  - name: credential_exfiltration
    description: Read credentials then make network call
    sequence:
      - category: credential_read
        tools: [read_secrets, get_env, read_config]
      - category: network_egress
        tools: [http_request, curl, wget]
    window: 5
    severity: critical
```

### Hot Reload

Configuration can be reloaded without restarting:

```bash
# Send SIGHUP to reload configuration
kill -HUP $(cat /var/run/security_sidecar.pid)
```

Or programmatically:

```python
from config import reload
reload()
```

## Building and Packaging

### Development Install

```bash
pip install -e .
```

### Build Distribution

```bash
pip install build
python -m build
```

This creates:
- `dist/security_sidecar-*.whl` (wheel package)
- `dist/security_sidecar-*.tar.gz` (source distribution)

### Docker Build

```bash
docker build -t mcr-security-sidecar:latest .
```

## Deployment

### Standalone Process

```bash
# Run audit consumer as a daemon
python -m sidecar --config /etc/mcr/policy.yaml &
```

### Docker Compose

Add to your existing MCR docker-compose.yaml:

```yaml
services:
  security-sidecar:
    image: mcr-security-sidecar:latest
    environment:
      - NATS_URL=nats://nats:4222
      - CONFIG_PATH=/config/policy.yaml
    volumes:
      - ./config:/config:ro
      - ./audit_logs:/var/log/security
    depends_on:
      - nats
    restart: unless-stopped
```

### Kubernetes

See INTEGRATION.md for Kubernetes deployment manifests including:
- ConfigMap for policy.yaml and patterns.yaml
- Deployment for audit consumer
- Service for internal communication
- PodDisruptionBudget for high availability

### Integration Points

The sidecar requires two touch points in MCR core:

```
context_plane.py      calls  scanner.py          (before publish_event)
context_plane.py      calls  redactor.py         (inside reconstruct)
mcr_orchestrator.py   calls  policy_engine.py    (before handle_tool_call dispatch)
```

See INTEGRATION.md for exact code snippets.

## Testing

### Run All Tests

```bash
cd SecuritySidecar
./testing/run_tests.sh
```

### Run Specific Test Modules

```bash
pytest testing/test_scanner.py -v
pytest testing/test_redactor.py -v
pytest testing/test_policy_engine.py -v
pytest testing/test_sequence_analyzer.py -v
pytest testing/test_integration.py -v
```

### Run with Coverage

```bash
pytest testing/ --cov=. --cov-report=html
# View report at testing/coverage_html/index.html
```

### Test Categories

- **test_scanner.py**: Invisible Unicode detection, injection pattern matching, hidden markup detection, trust classification
- **test_redactor.py**: Credential redaction, PII redaction, topology redaction, placeholder generation
- **test_policy_engine.py**: Allowlist/denylist checks, argument validation, sequence enforcement, egress limits
- **test_sequence_analyzer.py**: Pattern loading, call graph building, toxic flow matching
- **test_integration.py**: End-to-end workflow simulations

## File Reference

### Foundation
- **models.py**: Shared dataclasses (ScanResult, RedactionResult, PolicyDecision, SecurityEvent) and enums for trust levels and severity
- **config.py**: Loads policy.yaml and patterns.yaml; exposes reload() for hot-reload

### Defense (synchronous, in the hot path)
- **scanner.py**: Called in context_plane.publish_event() before JetStream persist; checks Unicode, injection phrases, hidden markup, base64 blobs; annotates events with trust level
- **redactor.py**: Called in context_plane.reconstruct() before model delivery; removes credentials, PII, and topology from LOW/UNTRUSTED events

### Detection (pre-dispatch)
- **sequence_analyzer.py**: Matches proposed tool calls against patterns.yaml using workflow call history; graph-style pattern matching
- **policy_engine.py**: Called in mcr_orchestrator.handle_tool_call() before execution; runs denylist, allowlist, arg validation, sequence check, egress check, approval gate

### Event Bus
- **sidecar.py**: SecurityPublisher class for emitting findings to NATS; standalone entry point for audit consumer

### Investigation (async, off the hot path)
- **audit_consumer.py**: Separate process; wildcard subscriber on *.*.*.*.security_event; writes audit log, forwards to SIEM, escalates on CRITICAL
- **investigator.py**: Forensic replay from JetStream; replay_workflow(), build_timeline(), diff_context(), summarize_redactions(), export_for_siem()

### Configuration
- **policy.yaml**: Allowlist, denylist, egress limits, redaction toggles, SIEM endpoint
- **patterns.yaml**: Toxic flow category definitions and named patterns

### Integration
- **INTEGRATION.md**: Code snippets for MCR touch points, CLI extensions, Docker Compose additions
- **requirements.txt**: Dependencies organized by function

## Dependencies

### Ingress Scanning
- **detect-secrets** (Yelp): Credential and API key pattern detection across 30+ token formats
- **presidio-analyzer** (Microsoft): PII entity recognition; runs locally with no data egress
- **regex**: Drop-in re replacement with better Unicode property support

### Sequence Analysis
- **nats-py**: Async subscriber for audit consumer and sequence queries
- **networkx**: Model tool sequences as directed graphs for subgraph pattern matching
- **pydantic**: Schema validation for tool call arguments

### Trust Scoring
- **langdetect**: Detect language switches mid-payload (injection signal)
- **scikit-learn**: Anomaly detection using IsolationForest
- **tiktoken**: Token counting for context budget verification

### Forensic Replay
- **duckdb**: Query JetStream exports without loading into memory
- **pandas**: Timeline reconstruction from event streams
- **rich**: CLI rendering for analyst investigation

### SIEM Integration
- **python-json-logger**: Structured JSON log output
- **aiohttp**: Async HTTP for SIEM webhook forwarding

### Dependency Notes

**presidio-analyzer** ships with spaCy models and should run in its own worker process rather than inline in publish_event(). The pattern is to publish raw events to JetStream immediately, then have a dedicated scanning consumer process them asynchronously.

**networkx** shifts sequence detection from hand-coded rules to a graph problem. Define toxic flow patterns as small directed graphs, then check each new tool call to see whether it completes a known pattern. This scales better as attack patterns grow.

**duckdb** handles large JetStream exports without loading everything into memory, which matters for 90-day retention windows in finance and healthcare scenarios.
