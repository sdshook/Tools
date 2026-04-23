"""
security/sidecar.py

Main entry point for the MCR security sidecar.

Responsibilities:
  1. Exposes publish_security_event() for MCR core modules to call
     when scanner or policy engine produce findings.
  2. Starts the audit consumer as a background task.
  3. Provides the SecurityPublisher class that mcr_orchestrator.py
     and context_plane.py import to emit security events into NATS.

Run standalone (starts audit consumer only):
    python -m security.sidecar

Import in MCR core:
    from security.sidecar import SecurityPublisher
"""

from __future__ import annotations
import asyncio
import json
import logging
import os
import signal
import sys
import uuid
from datetime import datetime, timezone
from typing import Optional

import nats

from .models import SecurityEvent, Severity, SourceType, ScanResult, PolicyDecision
from .config import get_policy, load as load_config
from . import audit_consumer

logger = logging.getLogger(__name__)

NATS_URL   = os.getenv("MCR_NATS_URL",  "nats://localhost:4222")
MCR_TENANT = os.getenv("MCR_TENANT",    "default")
MCR_DOMAIN = os.getenv("MCR_DOMAIN",    "workflows")


# ---------------------------------------------------------------------------
# Security event publisher
# ---------------------------------------------------------------------------

class SecurityPublisher:
    """
    Thin async wrapper used by context_plane.py and mcr_orchestrator.py
    to publish security findings into the NATS security event subject.

    Usage:
        publisher = await SecurityPublisher.connect()
        await publisher.emit_scan_result(scan_result, workflow_id, step, source_type)
        await publisher.emit_policy_violation(decision, tool_name, workflow_id, step)
        await publisher.close()
    """

    def __init__(self, nc: nats.aio.client.Client):
        self._nc = nc

    @classmethod
    async def connect(cls, url: str = NATS_URL) -> "SecurityPublisher":
        nc = await nats.connect(url)
        logger.info("SecurityPublisher connected to %s", url)
        return cls(nc)

    async def close(self):
        await self._nc.drain()

    def _make_subject(self, workflow_id: str, correlation_id: Optional[str] = None) -> str:
        wf_id = correlation_id or workflow_id
        return f"{MCR_TENANT}.{MCR_DOMAIN}.security.{wf_id}.security_event"

    async def _publish(self, event: SecurityEvent, workflow_id: str) -> None:
        subject = self._make_subject(workflow_id)
        payload = json.dumps({
            "event_id":    event.event_id,
            "workflow_id": event.workflow_id,
            "step_index":  event.step_index,
            "timestamp":   event.timestamp.isoformat(),
            "severity":    event.severity.value,
            "category":    event.category,
            "detail":      event.detail,
            "source_type": event.source_type.value,
            "tenant":      event.tenant,
            "domain":      event.domain,
            "flags":       event.raw_flags,
            "metadata":    event.metadata,
        }).encode()
        try:
            await self._nc.publish(subject, payload)
        except Exception as exc:
            logger.error("SecurityPublisher publish failed: %s", exc)

    async def emit_scan_result(
        self,
        result:      ScanResult,
        workflow_id: str,
        step_index:  int,
        source_type: SourceType,
    ) -> None:
        """Called after scanner.scan_payload() when flags are found."""
        if result.clean:
            return

        severity = (
            Severity.CRITICAL if result.trust_level.value == "untrusted"
            else Severity.HIGH
        )
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            workflow_id=workflow_id,
            step_index=step_index,
            timestamp=datetime.now(timezone.utc),
            severity=severity,
            category="injection_detected",
            detail=f"{len(result.flags)} flag(s): {', '.join(f.category for f in result.flags)}",
            source_type=source_type,
            tenant=MCR_TENANT,
            domain=MCR_DOMAIN,
            raw_flags=[f.category for f in result.flags],
            metadata={"trust_level": result.trust_level.value},
        )
        await self._publish(event, workflow_id)

    async def emit_policy_violation(
        self,
        decision:    PolicyDecision,
        tool_name:   str,
        workflow_id: str,
        step_index:  int,
    ) -> None:
        """Called after policy_engine.evaluate() when permitted=False."""
        severity = (
            Severity.CRITICAL if decision.matched_pattern
            else Severity.HIGH
        )
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            workflow_id=workflow_id,
            step_index=step_index,
            timestamp=datetime.now(timezone.utc),
            severity=severity,
            category="policy_violation",
            detail=decision.violation_reason or "Policy denied tool call",
            source_type=SourceType.USER,
            tenant=MCR_TENANT,
            domain=MCR_DOMAIN,
            raw_flags=[decision.matched_pattern] if decision.matched_pattern else [],
            metadata={"tool_name": tool_name},
        )
        await self._publish(event, workflow_id)

    async def emit_redaction(
        self,
        workflow_id: str,
        step_index:  int,
        redaction_count: int,
        categories:  list[str],
    ) -> None:
        """Called after redactor.redact() when content is modified."""
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            workflow_id=workflow_id,
            step_index=step_index,
            timestamp=datetime.now(timezone.utc),
            severity=Severity.MEDIUM,
            category="redaction_applied",
            detail=f"{redaction_count} item(s) redacted: {', '.join(set(categories))}",
            source_type=SourceType.TOOL_RESULT,
            tenant=MCR_TENANT,
            domain=MCR_DOMAIN,
            raw_flags=list(set(categories)),
            metadata={"count": redaction_count},
        )
        await self._publish(event, workflow_id)

    async def emit_approval_required(
        self,
        tool_name:   str,
        workflow_id: str,
        step_index:  int,
    ) -> None:
        """Called when policy_engine flags a tool as requiring human approval."""
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            workflow_id=workflow_id,
            step_index=step_index,
            timestamp=datetime.now(timezone.utc),
            severity=Severity.MEDIUM,
            category="approval_required",
            detail=f"Tool '{tool_name}' requires human approval before execution",
            source_type=SourceType.USER,
            tenant=MCR_TENANT,
            domain=MCR_DOMAIN,
            raw_flags=["approval_gate"],
            metadata={"tool_name": tool_name},
        )
        await self._publish(event, workflow_id)


# ---------------------------------------------------------------------------
# Standalone entry point (starts audit consumer)
# ---------------------------------------------------------------------------

async def _main():
    load_config()
    logger.info("MCR security sidecar starting")
    await audit_consumer.run()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
    asyncio.run(_main())
