# SecuritySidecar

It rides alongside the MCR context plane without modifying the core architecture. MCR's job stays what it is: attention management, context persistence, and routing. The security sidecar observes the same event stream, enforces policy at the two points where it must be synchronous (ingress scan before publish, policy check before dispatch), and otherwise operates independently on its own consumers.

The separation matters for a few reasons:

**Failure isolation.** If the scanner crashes or a redaction pattern causes an exception, it shouldn't take down context routing. The sidecar failing degrades security posture but doesn't stop the workflow plane from functioning. You can make the synchronous checks fail-open or fail-closed per environment without touching MCR core.

**Independent deployment.** The audit consumer, investigator, and SIEM forwarder have no reason to run in the same process or even the same container as the MCR orchestrator. They just need NATS access. You can scale them, update them, and restart them independently.

**Independent policy updates.** policy.yaml and patterns.yaml can be reloaded without restarting MCR. New toxic flow patterns, updated redaction rules, and revised allowlists are sidecar concerns that never touch the routing or persistence configuration.

**Clean repo structure.** MCR core stays in src/. The sidecar lives entirely in security/ with its own requirements, its own config, and its own entry points. Someone working on context reconstruction doesn't need to understand the sequence analyzer, and vice versa.

The only coupling is intentional and minimal: two call sites in existing MCR files (context_plane.py and mcr_orchestrator.py) where the sidecar must be synchronous. Everything else is the sidecar listening on NATS just like any other consumer.

It's a clean pattern and it fits naturally with how MCR is already structured around NATS as the coordination primitive.

---

Thirteen files. Here is what each does and how they relate:

## Foundation

- **models.py** — shared dataclasses used by every other module: ScanResult, RedactionResult, PolicyDecision, SecurityEvent, WorkflowTimeline, and the enums for trust levels and severity
- **config.py** — loads policy.yaml and patterns.yaml into typed dataclasses; exposes reload() for hot-reload without restart

## Defense (synchronous, in the hot path)

- **scanner.py** — called inside context_plane.publish_event() before JetStream persist; checks invisible Unicode, injection phrases, hidden markup, and base64 blobs; annotates every event with a trust level
- **redactor.py** — called inside context_plane.reconstruct() before model delivery; removes credentials, PII, and internal topology from LOW and UNTRUSTED events; leaves originals untouched in JetStream

## Detection (pre-dispatch)

- **sequence_analyzer.py** — matches the proposed tool call against patterns.yaml using the workflow's call history; graph-style pattern matching rather than brittle if-then rules; the only place you update to add new attack patterns
- **policy_engine.py** — called inside mcr_orchestrator.handle_tool_call() before execution; runs denylist, allowlist, arg validation, sequence check, egress domain check, and approval gate in order

## Event bus

- **sidecar.py** — SecurityPublisher class that MCR core imports to emit findings into NATS; also the standalone entry point that launches the audit consumer

## Investigation (async, off the hot path)

- **audit_consumer.py** — separate process; wildcard subscriber on *.*.*.*.security_event; writes audit log, forwards to SIEM, escalates and suspends workflows on CRITICAL events
- **investigator.py** — forensic replay from JetStream; replay_workflow(), build_timeline(), diff_context(), summarize_redactions(), export_for_siem()

## Configuration

- **policy.yaml** — allowlist, denylist, egress limits, redaction toggles, SIEM endpoint; no code change needed to update policy
- **patterns.yaml** — toxic flow category definitions and named patterns; add new attack sequences here without touching Python

## Integration

- **INTEGRATION.md** — the exact code snippets showing the two context_plane.py touch points and the one mcr_orchestrator.py touch point, plus the CLI extensions and Docker Compose addition
- **requirements.txt** — dependencies organized by function: ingress scanning, sequence analysis, trust scoring, forensic replay, and SIEM integration

---

## Module Details

### Ingress Layer: scanner.py

The core scanning module called inside `publish_event()` before anything hits JetStream. It needs to be synchronous and fast since it sits in the hot path.

- `scan_payload(content, source_type)` — runs all checks, returns a ScanResult dataclass with flags, trust level, and a sanitized copy of the content
- `detect_invisible_unicode(content)` — character-by-character category inspection
- `detect_injection_patterns(content)` — compiled regex set for instruction override phrases, role reassignment language, and delimiter smuggling
- `detect_hidden_markup(content)` — HTML comment stripping, zero-width character removal, hidden markdown fragment detection
- `classify_trust(source_type, flags)` — maps source origin plus scan flags to a trust level enum: HIGH / MEDIUM / LOW / UNTRUSTED

### Ingress Layer: redactor.py

Runs during context reconstruction on any LOW or UNTRUSTED event before it enters the assembled context window. Called from `context_plane.py` inside `reconstruct()`.

- `redact(content, trust_level)` — master entry point returning redacted content plus a RedactionRecord of what was removed and why
- `redact_credentials(content)` — token pattern matching for API keys, bearer tokens, private keys
- `redact_pii(content)` — structured patterns for SSNs, credit card numbers, email addresses, phone numbers
- `redact_internal_topology(content)` — private IP ranges, internal hostnames, subnet references
- `build_placeholder(category, original_hash)` — produces `[REDACTED:api_key:a3f2]` style replacements that are traceable in the audit log without exposing the original

### Routing Layer: policy_engine.py

Called from `mcr_orchestrator.py` in `handle_tool_call()` before any dispatch. Evaluates the proposed call against the workflow's declared policy and its JetStream event history.

- `evaluate(tool_name, args, workflow_id, step, policy)` — returns `PolicyDecision(permitted, violation_reason, requires_approval)`
- `check_allowlist(tool_name, policy)` — simple membership check
- `validate_args(tool_name, args, policy)` — schema validation against per-tool argument shapes defined in policy config
- `check_sequence(tool_name, workflow_id, prior_calls, policy)` — the important one; queries prior tool calls for the workflow and checks whether the proposed call completes a prohibited sequence
- `check_egress(tool_name, args, policy)` — domain allowlist enforcement for any network-class tool
- `requires_human_approval(tool_name, policy)` — returns true for destructive or high-risk tool classes

### Routing Layer: sequence_analyzer.py

Supporting module for `policy_engine.py`. Maintains the known toxic flow pattern library and does the actual sequence matching against the workflow's call history.

- `load_patterns(path)` — loads toxic flow definitions from `security/patterns.yaml`
- `match(call_history, proposed_call)` — checks whether proposed call completes any known pattern given the history
- `get_call_history(workflow_id)` — queries JetStream for all tool-call events in the current workflow
- `patterns.yaml` — the pattern definition file itself, expressed as named sequences of tool categories with optional conditions; this is what you update as new attack patterns are identified without touching code

### Persistence Layer: audit_consumer.py

A standalone NATS consumer that subscribes to the dedicated security subject wildcard across all tenants. Runs as a separate process from the main MCR services.

- `run()` — async main loop; connects to NATS and subscribes to `*.*.*.*.security_event`
- `handle_event(msg)` — deserializes the security event, routes to the appropriate handler based on severity
- `escalate(event)` — triggers workflow suspension and analyst notification for HIGH severity events
- `forward_to_siem(event)` — emits structured JSON to configured SIEM endpoint or log pipeline
- `write_audit_record(event)` — appends to the durable local audit log with full event payload

### Investigation Layer: investigator.py

Used by analysts via `mcr_cli.py` extensions or directly. Queries JetStream to reconstruct exactly what happened in a flagged workflow.

- `replay_workflow(workflow_id)` — fetches the complete ordered event stream for a workflow and returns a structured timeline
- `build_timeline(events)` — produces a step-by-step record of every tool call, model input, model output, scan flag, and redaction that occurred
- `diff_context(step_a, step_b, workflow_id)` — shows exactly what changed in the reconstructed context between two steps; useful for pinpointing where injected content entered
- `summarize_redactions(workflow_id)` — aggregates all RedactionRecord entries for a workflow into a report of what was removed and at which steps
- `export_for_siem(workflow_id, path)` — dumps the full forensic record as structured JSON for ingestion into external systems

### Config: policy.yaml

The declarative file that governs all of the above without code changes.

```yaml
tools:
  allowlist: [read_file, search_code, run_tests, query_db]
  denylist: [execute_shell]
  require_approval: [delete_*, publish_*, send_*]

sequences:
  patterns_file: security/patterns.yaml

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

---

## How It Wires Into Existing MCR Files

```
context_plane.py      calls  scanner.py          (before publish_event)
context_plane.py      calls  redactor.py         (inside reconstruct)
mcr_orchestrator.py   calls  policy_engine.py    (before handle_tool_call dispatch)
policy_engine.py      calls  sequence_analyzer.py
audit_consumer.py     runs independently, subscribes to *.*.*.*.security_event
investigator.py       called from mcr_cli.py extensions or directly by analysts
```

---

## Dependencies

### Ingress Scanning / Injection Detection

- **detect-secrets** (Yelp) — production-grade credential and API key pattern detection across 30+ token formats; better than hand-rolled regex
- **presidio-analyzer** (Microsoft) — PII entity recognition including SSNs, credit cards, emails, phone numbers, names; runs locally with no data leaving the environment
- **unicodedata** (stdlib) — invisible Unicode detection; category-based inspection of every character in an inbound payload
- **regex** — drop-in `re` replacement with better Unicode property support for injection pattern matching across scripts

### Sequence and Flow Analysis

- **nats-py** — already a dependency for MCR core; the async subscriber you need for the security audit consumer and sequence query against prior workflow events
- **networkx** — model tool call sequences as directed graphs; useful for detecting known toxic flow patterns (read-then-exfiltrate, escalate-then-delete) as subgraph matches rather than brittle if-then rules
- **pydantic** — schema validation for tool call arguments before dispatch; define strict models per tool and reject non-conforming calls at the routing layer

### Trust Scoring and Reconstruction

- **langdetect** or **lingua-py** — detect language switches mid-payload, a signal for injected content from a different source than the surrounding context
- **scikit-learn** — lightweight anomaly detection on token volume, call frequency, and sequence patterns using IsolationForest or similar; no heavy inference required
- **tiktoken** (OpenAI, but model-agnostic for counting) — accurate token counting for redacted vs. unredacted context, so you can verify the reconstruction stays within policy-defined budgets after redaction

### Forensic Replay and Investigation

- **duckdb** — query JetStream event exports as structured data without standing up a full database; fast enough for ad hoc forensic queries across millions of events by workflow_id, timestamp, or event_type
- **pandas** — timeline reconstruction from replayed event streams; pivot by correlation_id to produce a per-workflow decision audit trail
- **rich** — human-readable CLI rendering of replayed workflows for analyst investigation; pairs well with mcr_cli.py for interactive forensic sessions

### SIEM Integration

- **python-json-logger** — structured JSON log output from the security audit consumer in a format SIEM ingestion pipelines expect natively
- **aiohttp** — async HTTP for forwarding security events to SIEM webhook endpoints without blocking the NATS consumer loop

### Notes on Fit

**presidio-analyzer** is the heaviest dependency here and ships with spaCy models, so it warrants its own worker process rather than running inline in `publish_event()`. The pattern is to publish the raw event to JetStream immediately, then have a dedicated scanning consumer process it asynchronously and publish a `scan_result` event back. This keeps ingress latency clean while still ensuring no flagged content reaches reconstruction.

**networkx** is worth calling out specifically because it shifts sequence detection from a list of hand-coded rules to a graph problem. You define known toxic flow patterns as small directed graphs, then check each new tool call to see whether it completes a known pattern in the workflow's call history. This is significantly more maintainable as the number of tools and attack patterns grows.

**duckdb** is the right choice for forensic replay over a Pandas-only approach because JetStream event exports can be large and DuckDB handles them without loading everything into memory, which matters for 90-day retention windows in the finance and healthcare scenarios.
