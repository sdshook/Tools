"""
security/investigator.py

Forensic replay and investigation tooling. Used by analysts directly
or via mcr_cli.py extensions to reconstruct exactly what happened in
a flagged workflow.

All data comes from JetStream replay. No inference, no approximation.
"""

from __future__ import annotations
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import nats

from .models import (
    SecurityEvent, WorkflowEvent, WorkflowTimeline,
    TrustLevel, SourceType, Severity, RedactionRecord,
)
from .sequence_analyzer import describe_history

logger = logging.getLogger(__name__)

NATS_URL    = os.getenv("MCR_NATS_URL",    "nats://localhost:4222")
STREAM_NAME = os.getenv("MCR_STREAM_NAME", "MCR_CONTEXT")


# ---------------------------------------------------------------------------
# JetStream fetch helpers
# ---------------------------------------------------------------------------

async def _fetch_workflow_events(
    js,
    workflow_id: str,
    stream: str,
) -> list[dict]:
    """
    Fetch all JetStream messages for a given workflow_id by filtering
    on the correlation ID position in the subject hierarchy:
    {tenant}.{domain}.{workflow_type}.{workflow_id}.{event_type}
    """
    raw_events = []
    try:
        # Subscribe with an ephemeral consumer filtered to this workflow_id's subjects
        sub = await js.subscribe(
            f"*.*.*.{workflow_id}.*",
            stream=stream,
            deliver="all",
        )
        # Drain available messages with a short timeout
        try:
            async for msg in sub.messages:
                raw_events.append({
                    "seq":     msg.metadata.sequence.stream if msg.metadata else 0,
                    "subject": msg.subject,
                    "data":    json.loads(msg.data) if msg.data else {},
                    "timestamp": (
                        msg.metadata.timestamp.isoformat()
                        if msg.metadata and msg.metadata.timestamp
                        else datetime.now(timezone.utc).isoformat()
                    ),
                })
                await msg.ack()
        except nats.errors.TimeoutError:
            pass  # expected: stream exhausted
        finally:
            await sub.unsubscribe()
    except Exception as exc:
        logger.error("_fetch_workflow_events: %s workflow_id=%s", exc, workflow_id)

    # Sort by sequence number for chronological order
    return sorted(raw_events, key=lambda e: e["seq"])


def _parse_workflow_event(raw: dict) -> Optional[WorkflowEvent]:
    try:
        data = raw["data"]
        return WorkflowEvent(
            seq=raw["seq"],
            subject=raw["subject"],
            timestamp=datetime.fromisoformat(raw["timestamp"]),
            workflow_id=data.get("workflow_id", ""),
            step_index=data.get("step_index", -1),
            role=data.get("role", "unknown"),
            content=data.get("content", ""),
            source_type=SourceType(data.get("source_type", "external")),
            trust_level=TrustLevel(data.get("trust_level", "low")),
            scan_flags=data.get("scan_flags", []),
            redactions=[
                RedactionRecord(**r) for r in data.get("redactions", [])
            ],
            tool_name=data.get("tool_name"),
            tool_args=data.get("tool_args"),
            policy_outcome=data.get("policy_outcome"),
        )
    except Exception as exc:
        logger.warning("_parse_workflow_event failed: %s", exc)
        return None


def _parse_security_event(raw: dict) -> Optional[SecurityEvent]:
    try:
        data = raw["data"]
        return SecurityEvent(
            event_id=data.get("event_id", ""),
            workflow_id=data.get("workflow_id", ""),
            step_index=data.get("step_index", -1),
            timestamp=datetime.fromisoformat(
                data.get("timestamp", datetime.now(timezone.utc).isoformat())
            ),
            severity=Severity(data.get("severity", "info")),
            category=data.get("category", "unknown"),
            detail=data.get("detail", ""),
            source_type=SourceType(data.get("source_type", "external")),
            tenant=data.get("tenant", "default"),
            domain=data.get("domain", ""),
            raw_flags=data.get("flags", []),
            metadata=data.get("metadata", {}),
        )
    except Exception as exc:
        logger.warning("_parse_security_event failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

async def replay_workflow(workflow_id: str) -> Optional[WorkflowTimeline]:
    """
    Fetch and reconstruct the complete ordered event stream for a workflow.
    Returns a WorkflowTimeline with all events and security events annotated.
    """
    nc = await nats.connect(NATS_URL)
    js = nc.jetstream()

    try:
        raw_events = await _fetch_workflow_events(js, workflow_id, STREAM_NAME)
        if not raw_events:
            logger.warning("replay_workflow: no events found for workflow_id=%s", workflow_id)
            return None

        events: list[WorkflowEvent] = []
        security_events: list[SecurityEvent] = []
        tenant = ""
        domain = ""

        for raw in raw_events:
            parts = raw["subject"].split(".")
            if len(parts) >= 2:
                tenant = parts[0]
                domain = parts[1]

            # Route by event_type (last subject part)
            event_type = parts[-1] if parts else ""
            if event_type == "security_event":
                se = _parse_security_event(raw)
                if se:
                    security_events.append(se)
            else:
                we = _parse_workflow_event(raw)
                if we:
                    events.append(we)

        start = events[0].timestamp if events else datetime.now(timezone.utc)
        end   = events[-1].timestamp if len(events) > 1 else None

        return WorkflowTimeline(
            workflow_id=workflow_id,
            tenant=tenant,
            domain=domain,
            start_time=start,
            end_time=end,
            events=events,
            security_events=security_events,
        )
    finally:
        await nc.drain()


def build_timeline(timeline: WorkflowTimeline) -> list[dict]:
    """
    Produce a flat, step-by-step record of the workflow for analyst review.
    Each entry contains the role, content excerpt, trust level, tool info,
    scan flags, and redaction summary.
    """
    rows = []
    for event in timeline.events:
        rows.append({
            "seq":          event.seq,
            "step":         event.step_index,
            "timestamp":    event.timestamp.isoformat(),
            "role":         event.role,
            "source_type":  event.source_type.value,
            "trust_level":  event.trust_level.value,
            "tool":         event.tool_name,
            "tool_args":    event.tool_args,
            "policy":       event.policy_outcome,
            "scan_flags":   event.scan_flags,
            "redactions":   len(event.redactions),
            "content_excerpt": event.content[:200] + "..." if len(event.content) > 200 else event.content,
        })
    return rows


def diff_context(
    step_a: int,
    step_b: int,
    timeline: WorkflowTimeline,
) -> dict:
    """
    Show what changed in reconstructed context between two steps.
    Useful for pinpointing exactly where injected content entered.
    """
    events_a = [e for e in timeline.events if e.step_index == step_a]
    events_b = [e for e in timeline.events if e.step_index == step_b]

    content_a = set(e.content for e in events_a)
    content_b = set(e.content for e in events_b)

    flags_a = {f for e in events_a for f in e.scan_flags}
    flags_b = {f for e in events_b for f in e.scan_flags}

    return {
        "workflow_id":   timeline.workflow_id,
        "step_a":        step_a,
        "step_b":        step_b,
        "new_content":   list(content_b - content_a),
        "removed_content": list(content_a - content_b),
        "new_flags":     list(flags_b - flags_a),
        "cleared_flags": list(flags_a - flags_b),
        "trust_levels_a": [e.trust_level.value for e in events_a],
        "trust_levels_b": [e.trust_level.value for e in events_b],
    }


def summarize_redactions(timeline: WorkflowTimeline) -> list[dict]:
    """
    Aggregate all RedactionRecords across the workflow.
    Returns per-step summaries of what was removed and why.
    """
    summary = []
    for event in timeline.events:
        if event.redactions:
            summary.append({
                "step":       event.step_index,
                "timestamp":  event.timestamp.isoformat(),
                "tool":       event.tool_name,
                "redactions": [
                    {
                        "category":      r.category,
                        "placeholder":   r.placeholder,
                        "original_hash": r.original_hash,
                        "position":      r.position,
                        "length":        r.length,
                    }
                    for r in event.redactions
                ],
            })
    return summary


def annotate_call_history(timeline: WorkflowTimeline) -> list[dict]:
    """
    Return tool call history with toxic flow category annotations.
    Used to explain why a sequence policy triggered.
    """
    tool_calls = [
        e.tool_name for e in timeline.events
        if e.tool_name is not None
    ]
    return describe_history(tool_calls)


def export_for_siem(timeline: WorkflowTimeline, path: Path) -> None:
    """
    Dump the complete forensic record as structured NDJSON for SIEM ingestion.
    One JSON object per line: workflow metadata, each event, each security event.
    
    Each record includes a content_hash (SHA-256) for chain of custody verification.
    This enables:
    - Tamper detection: hash mismatch indicates modification
    - Deduplication: identical content produces identical hash
    - Audit trail: hashes can be independently verified
    """
    import hashlib
    
    def compute_hash(data: dict) -> str:
        """Compute SHA-256 hash of JSON-serialized record for chain of custody."""
        content = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()
    
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        # Header record
        header = {
            "record_type":  "workflow_summary",
            "workflow_id":  timeline.workflow_id,
            "tenant":       timeline.tenant,
            "domain":       timeline.domain,
            "start_time":   timeline.start_time.isoformat(),
            "end_time":     timeline.end_time.isoformat() if timeline.end_time else None,
            "duration_s":   timeline.duration_seconds,
            "total_events": len(timeline.events),
            "flagged_steps": timeline.flagged_steps,
            "redacted_steps": timeline.redacted_steps,
        }
        header["content_hash"] = compute_hash(header)
        f.write(json.dumps(header) + "\n")

        # Workflow events with content hashes
        for event in timeline.events:
            record = {
                "record_type":    "workflow_event",
                "seq":            event.seq,
                "step":           event.step_index,
                "timestamp":      event.timestamp.isoformat(),
                "role":           event.role,
                "source_type":    event.source_type.value,
                "trust_level":    event.trust_level.value,
                "tool":           event.tool_name,
                "tool_args":      event.tool_args,
                "policy":         event.policy_outcome,
                "scan_flags":     event.scan_flags,
                "redactions":     len(event.redactions),
                "content_excerpt": event.content[:200] + "..." if len(event.content) > 200 else event.content,
                "content_hash":   hashlib.sha256(event.content.encode()).hexdigest(),
            }
            record["record_hash"] = compute_hash(record)
            f.write(json.dumps(record) + "\n")

        # Security events with content hashes
        for se in timeline.security_events:
            record = {
                "record_type": "security_event",
                "event_id":    se.event_id,
                "timestamp":   se.timestamp.isoformat(),
                "severity":    se.severity.value,
                "category":    se.category,
                "step_index":  se.step_index,
                "detail":      se.detail,
                "flags":       se.raw_flags,
            }
            record["record_hash"] = compute_hash(record)
            f.write(json.dumps(record) + "\n")

    logger.info("export_for_siem: wrote %s", path)
