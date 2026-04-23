"""
security/audit_consumer.py

Standalone NATS consumer. Subscribes to all security events across all tenants
and handles escalation, SIEM forwarding, and durable local audit logging.

Run as a separate process:
    python -m security.audit_consumer

Subject pattern: *.*.*.*.security_event
"""

from __future__ import annotations
import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import nats
from nats.js.api import ConsumerConfig, DeliverPolicy

from .models import SecurityEvent, Severity, SourceType
from .config import get_policy, reload as reload_config

logger = logging.getLogger(__name__)

NATS_URL     = os.getenv("MCR_NATS_URL",       "nats://localhost:4222")
AUDIT_LOG    = Path(os.getenv("MCR_AUDIT_LOG", "security/audit.log"))
STREAM_NAME  = os.getenv("MCR_STREAM_NAME",    "MCR_CONTEXT")


# ---------------------------------------------------------------------------
# Event deserialization
# ---------------------------------------------------------------------------

def _parse_event(raw: bytes) -> Optional[SecurityEvent]:
    try:
        data = json.loads(raw)
        return SecurityEvent(
            event_id=data.get("event_id", ""),
            workflow_id=data.get("workflow_id", ""),
            step_index=data.get("step_index", -1),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.now(timezone.utc).isoformat())),
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
        logger.error("Failed to parse security event: %s | raw=%s", exc, raw[:200])
        return None


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

async def _write_audit_record(event: SecurityEvent) -> None:
    """Append to durable local audit log in structured JSON."""
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "event_id":   event.event_id,
        "timestamp":  event.timestamp.isoformat(),
        "severity":   event.severity.value,
        "category":   event.category,
        "workflow_id": event.workflow_id,
        "step_index": event.step_index,
        "tenant":     event.tenant,
        "domain":     event.domain,
        "source_type": event.source_type.value,
        "detail":     event.detail,
        "flags":      event.raw_flags,
        "metadata":   event.metadata,
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")


async def _forward_to_siem(event: SecurityEvent) -> None:
    """POST security event to configured SIEM endpoint."""
    policy = get_policy()
    if not policy.siem.enabled or not policy.siem.endpoint:
        return
    try:
        import aiohttp
        payload = {
            "source":     "mcr_security_sidecar",
            "event_id":   event.event_id,
            "timestamp":  event.timestamp.isoformat(),
            "severity":   event.severity.value,
            "category":   event.category,
            "workflow_id": event.workflow_id,
            "tenant":     event.tenant,
            "detail":     event.detail,
            "flags":      event.raw_flags,
        }
        headers = {"Content-Type": "application/json", **policy.siem.headers}
        async with aiohttp.ClientSession() as session:
            async with session.post(policy.siem.endpoint, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status >= 400:
                    logger.warning("SIEM forward failed: status=%d event_id=%s", resp.status, event.event_id)
    except Exception as exc:
        logger.error("SIEM forward exception: %s event_id=%s", exc, event.event_id)


async def _escalate(event: SecurityEvent, nc: nats.aio.client.Client) -> None:
    """
    For HIGH and CRITICAL events: publish to a dedicated escalation subject
    so that downstream alerting consumers (PagerDuty bridge, Slack bot, etc.)
    can act immediately. Also suspends the workflow by publishing a
    suspend command to the MCR orchestrator subject.
    """
    escalation_subject = f"{event.tenant}.security.escalation.{event.severity.value}"
    suspend_subject    = f"{event.tenant}.{event.domain}.control.suspend"

    payload = json.dumps({
        "event_id":   event.event_id,
        "workflow_id": event.workflow_id,
        "severity":   event.severity.value,
        "category":   event.category,
        "detail":     event.detail,
        "timestamp":  event.timestamp.isoformat(),
    }).encode()

    try:
        await nc.publish(escalation_subject, payload)
        logger.warning(
            "ESCALATED: workflow=%s severity=%s category=%s",
            event.workflow_id, event.severity.value, event.category,
        )
        if event.severity == Severity.CRITICAL:
            await nc.publish(suspend_subject, json.dumps({"workflow_id": event.workflow_id, "reason": event.detail}).encode())
            logger.warning("WORKFLOW SUSPENDED: workflow=%s", event.workflow_id)
    except Exception as exc:
        logger.error("Escalation publish failed: %s", exc)


# ---------------------------------------------------------------------------
# Main consumer loop
# ---------------------------------------------------------------------------

async def _handle_msg(msg, nc: nats.aio.client.Client) -> None:
    event = _parse_event(msg.data)
    if event is None:
        await msg.ack()
        return

    # Always write audit record first
    await _write_audit_record(event)

    # Always forward to SIEM if configured
    await _forward_to_siem(event)

    # Escalate on HIGH and CRITICAL
    if event.severity in (Severity.HIGH, Severity.CRITICAL):
        await _escalate(event, nc)

    await msg.ack()
    logger.info("audit_consumer: processed event_id=%s severity=%s category=%s",
                event.event_id, event.severity.value, event.category)


async def run() -> None:
    reload_config()
    logger.info("audit_consumer: connecting to NATS at %s", NATS_URL)
    nc = await nats.connect(NATS_URL)
    js = nc.jetstream()

    # Durable consumer on the MCR_CONTEXT stream filtered to security_event subjects
    # Subject pattern: {tenant}.{domain}.{workflow_type}.{correlation_id}.security_event
    consumer_config = ConsumerConfig(
        durable_name="mcr_security_audit",
        filter_subject="*.*.*.*.security_event",
        deliver_policy=DeliverPolicy.NEW,
        ack_wait=30,
        max_deliver=3,
    )

    sub = await js.subscribe(
        "*.*.*.*.security_event",
        config=consumer_config,
        stream=STREAM_NAME,
    )

    logger.info("audit_consumer: listening on *.*.*.*.security_event")

    # Handle SIGTERM / SIGINT gracefully
    loop = asyncio.get_event_loop()
    stop = loop.create_future()

    def _shutdown(signum, frame):
        if not stop.done():
            stop.set_result(None)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    async def _consume():
        async for msg in sub.messages:
            await _handle_msg(msg, nc)
            if stop.done():
                break

    await asyncio.gather(_consume(), stop)
    await sub.unsubscribe()
    await nc.drain()
    logger.info("audit_consumer: shutdown complete")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
    asyncio.run(run())
