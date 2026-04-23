# SecuritySidecar

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
- **requirements.txt** — only two new dependencies beyond MCR core: aiohttp for SIEM forwarding and pyyaml which MCR likely already has
