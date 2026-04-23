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
- **requirements.txt** — only two new dependencies beyond MCR core: aiohttp for SIEM forwarding and pyyaml which MCR likely already has
