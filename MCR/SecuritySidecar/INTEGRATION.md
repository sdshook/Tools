# MCR Security Sidecar: Integration Notes

Two files in MCR core require modification. Everything else is additive.

---

## context_plane.py: two additions

### 1. Import at top of file

```python
from security.scanner import scan_payload
from security.redactor import redact
from security.models import SourceType, TrustLevel
# SecurityPublisher is async; initialise once in ContextPlane.__init__
# or pass it in from the orchestrator.
```

### 2. Inside publish_event(), before js.publish()

```python
async def publish_event(self, workflow_id, step_index, role, content,
                        source_type=SourceType.USER, ...):

    # SECURITY: scan before persist
    scan_result = scan_payload(content, source_type, workflow_id, step_index)
    if not scan_result.clean:
        await self.security_publisher.emit_scan_result(
            scan_result, workflow_id, step_index, source_type
        )
        if scan_result.trust_level.value == "untrusted":
            raise SecurityViolation(f"Untrusted content blocked: {scan_result.flags[0].category}")

    # Use sanitized content (inert markup stripped) for storage
    content_to_store = scan_result.sanitized or content

    # Annotate event with trust metadata before publishing
    headers = {
        "MCR-Trust-Level": scan_result.trust_level.value,
        "MCR-Source-Type": source_type.value,
        "MCR-Scan-Clean":  str(scan_result.clean),
    }

    # ... existing publish logic using content_to_store and headers ...
```

### 3. Inside reconstruct(), before assembling context for model

```python
def reconstruct(self, workflow_id, current_step, current_task):
    events = self._fetch_events(workflow_id, current_step)
    selected = self._select_by_relevance(events, current_task)

    # SECURITY: redact low-trust events before model delivery
    clean_events = []
    for event in selected:
        trust = TrustLevel(event.headers.get("MCR-Trust-Level", "low"))
        redaction_result = redact(event.content, trust, workflow_id, event.step_index)
        if redaction_result.modified:
            await self.security_publisher.emit_redaction(
                workflow_id, event.step_index,
                len(redaction_result.records),
                [r.category for r in redaction_result.records],
            )
            event = replace(event, content=redaction_result.content)
        clean_events.append(event)

    return clean_events
```

---

## mcr_orchestrator.py: one addition

### Inside handle_tool_call(), before publish and dispatch

```python
from security.policy_engine import evaluate as policy_evaluate
from security.models import SourceType

async def handle_tool_call(self, tool_name, args, correlation_id, step):

    # SECURITY: fetch prior tool call history for this workflow
    call_history = await self._get_tool_call_history(correlation_id)

    # SECURITY: evaluate policy before any publish or execution
    decision = await policy_evaluate(
        tool_name=tool_name,
        args=args,
        workflow_id=correlation_id,
        step_index=step,
        call_history=call_history,
    )

    if not decision.permitted:
        await self.security_publisher.emit_policy_violation(
            decision, tool_name, correlation_id, step
        )
        raise PolicyViolation(decision.violation_reason)

    if decision.requires_approval:
        await self.security_publisher.emit_approval_required(
            tool_name, correlation_id, step
        )
        # Block until approval received or timeout
        await self._await_human_approval(tool_name, correlation_id, step)

    # ... existing publish and dispatch logic ...


async def _get_tool_call_history(self, workflow_id: str) -> list[str]:
    """
    Query JetStream for all tool-call events in this workflow instance.
    Returns ordered list of tool names, most recent last.
    """
    events = await self.context_plane.fetch_events_by_type(
        workflow_id=workflow_id,
        event_type="tool_call",
    )
    return [e.metadata.get("tool_name") for e in events if e.metadata.get("tool_name")]
```

---

## mcr_cli.py: investigator commands

```python
# Add to existing CLI command group

@cli.command()
@click.argument("workflow_id")
def investigate(workflow_id):
    """Replay and display the complete security timeline for a workflow."""
    import asyncio
    from security.investigator import replay_workflow, build_timeline
    from rich.table import Table
    from rich.console import Console

    timeline = asyncio.run(replay_workflow(workflow_id))
    if not timeline:
        click.echo(f"No events found for workflow {workflow_id}")
        return

    console = Console()
    table = Table(title=f"Workflow {workflow_id[:8]}...")
    for col in ["Step", "Role", "Trust", "Tool", "Flags", "Redactions", "Content"]:
        table.add_column(col)
    for row in build_timeline(timeline):
        table.add_row(
            str(row["step"]), row["role"], row["trust_level"],
            row["tool"] or "", ", ".join(row["scan_flags"]),
            str(row["redactions"]), row["content_excerpt"][:60],
        )
    console.print(table)


@cli.command()
@click.argument("workflow_id")
@click.argument("output_path")
def export_investigation(workflow_id, output_path):
    """Export full forensic record to NDJSON for SIEM ingestion."""
    import asyncio
    from pathlib import Path
    from security.investigator import replay_workflow, export_for_siem

    timeline = asyncio.run(replay_workflow(workflow_id))
    if not timeline:
        click.echo(f"No events found for workflow {workflow_id}")
        return
    export_for_siem(timeline, Path(output_path))
    click.echo(f"Exported to {output_path}")
```

---

## Deployment

Run the sidecar audit consumer as a separate process alongside MCR core:

```bash
# Start MCR core (existing)
python mcr_poc_runner.py

# Start security sidecar (new, separate process)
python -m security.sidecar
```

Or via Docker Compose alongside the existing MCR container:

```yaml
services:
  mcr:
    build: .
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - MCR_NATS_URL=nats://nats:4222

  mcr-security:
    build: .
    command: python -m security.sidecar
    environment:
      - MCR_NATS_URL=nats://nats:4222
      - MCR_SECURITY_POLICY=security/policy.yaml
      - MCR_SECURITY_PATTERNS=security/patterns.yaml
      - MCR_AUDIT_LOG=/var/log/mcr/audit.log
    volumes:
      - audit_logs:/var/log/mcr
    depends_on:
      - nats

  nats:
    image: nats:2.10-alpine
    command: ["-js", "-c", "/etc/nats/nats_config.conf"]
```
