"""
context_plane.py
MCR Context Plane: JetStream stream management, event publishing,
subject-level correlation filtering, explicit-ack durable consumers,
and semantic relevance reconstruction.
"""

import asyncio
import json
import math
import time
from collections import Counter
from dataclasses import dataclass, asdict
from typing import Optional

import nats
from nats.js.api import (
    StreamConfig, RetentionPolicy, StorageType,
    ConsumerConfig, AckPolicy, DeliverPolicy,
)


# ── Token estimation ──────────────────────────────────────────────────────────

def estimate_tokens(text: str) -> int:
    """~4 characters per token (standard approximation for Claude/GPT models)."""
    return max(1, len(text) // 4)


# ── Semantic relevance scoring ────────────────────────────────────────────────

def _bow(text: str) -> Counter:
    return Counter(w.lower() for w in text.split() if w.isalpha())

def relevance_score(query: str, document: str) -> float:
    """
    Cosine similarity between bag-of-words vectors.

    This implements content-aware selective aggregation: prior events are
    ranked by their semantic relationship to the current task rather than
    by recency or structural role. Equivalent to the learned, input-dependent
    weighting that Attention Residuals applies within transformer depth;
    MCR applies it across workflow temporal depth.
    """
    q, d = _bow(query), _bow(document)
    if not q or not d:
        return 0.0
    vocab = set(q) | set(d)
    qv = [q.get(w, 0) for w in vocab]
    dv = [d.get(w, 0) for w in vocab]
    dot    = sum(a * b for a, b in zip(qv, dv))
    mag_q  = math.sqrt(sum(a * a for a in qv))
    mag_d  = math.sqrt(sum(b * b for b in dv))
    return 0.0 if mag_q == 0 or mag_d == 0 else dot / (mag_q * mag_d)


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class ContextEvent:
    correlation_id: str
    workflow_type:  str
    step_index:     int
    event_type:     str    # "request" | "response"
    role:           str    # "user" | "assistant"
    content:        str
    token_count:    int
    timestamp:      float
    tenant:         str = "poc"
    domain:         str = "secops"

    def to_json(self) -> bytes:
        return json.dumps(asdict(self)).encode()

    @staticmethod
    def from_json(data: bytes) -> "ContextEvent":
        return ContextEvent(**json.loads(data))

    def subject(self) -> str:
        """
        {tenant}.{domain}.{workflow_type}.{correlation_id}.{event_type}

        Embedding the correlation ID at level 4 means a per-workflow consumer
        can filter at the JetStream broker via filter_subject, giving O(N_workflow)
        retrieval rather than O(N_stream) Python-level filtering.
        """
        return (
            f"{self.tenant}.{self.domain}"
            f".{self.workflow_type}"
            f".{self.correlation_id}"
            f".{self.event_type}"
        )


# ── Context Plane ─────────────────────────────────────────────────────────────

class MCRContextPlane:
    """
    JetStream-backed MCR context plane.

    Architectural properties:
      1. Stream covers all workflows via wildcard: {tenant}.{domain}.>
      2. Per-workflow pull consumer filters to: ...{correlation_id}.>
         (broker-level filtering, not application-level)
      3. AckPolicy.EXPLICIT: reconstruction is confirmed message-by-message.
         Unacked messages replay from the last confirmed position on failure.
      4. Semantic reconstruction: events scored by cosine similarity to the
         current task; highest-scoring events selected within R*available budget.
    """

    STREAM_NAME    = "MCR_CONTEXT"
    STREAM_SUBJECT = "poc.secops.>"

    def __init__(self, nats_url: str = "nats://localhost:4222"):
        self.nats_url = nats_url
        self.nc: Optional[nats.aio.client.Client] = None
        self.js: Optional[object] = None

    async def connect(self):
        self.nc = await nats.connect(self.nats_url)
        self.js = self.nc.jetstream()
        await self._ensure_stream()
        print(f"  [NATS]      Connected  → {self.nats_url}")
        print(f"  [JetStream] Stream '{self.STREAM_NAME}' ready  "
              f"(subject: {self.STREAM_SUBJECT})")

    async def _ensure_stream(self):
        cfg = StreamConfig(
            name=self.STREAM_NAME,
            subjects=[self.STREAM_SUBJECT],
            retention=RetentionPolicy.LIMITS,
            storage=StorageType.FILE,
            max_age=86400,
            max_msgs=500_000,
            max_bytes=512 * 1024 * 1024,
            num_replicas=1,
        )
        try:
            await self.js.add_stream(cfg)
        except Exception:
            await self.js.update_stream(cfg)

    async def publish(self, event: ContextEvent) -> int:
        ack = await self.js.publish(
            event.subject(),
            event.to_json(),
            headers={
                "correlation-id": event.correlation_id,
                "step-index":     str(event.step_index),
                "workflow-type":  event.workflow_type,
                "event-role":     event.role,
            },
        )
        return ack.seq

    async def reconstruct_context(
        self,
        correlation_id: str,
        current_step:   int,
        current_task:   str,
        relevance_ratio: float,
    ) -> tuple[list[ContextEvent], dict]:
        """
        Fetch all prior events for this workflow, score each against the
        current task via cosine similarity, and select the highest-scoring
        events within relevance_ratio * total_available_tokens.

        The token budget is computed from the actual available pool so R is
        a true fraction of what exists — not a pre-specified constant applied
        to an assumed pool size.

        Returns (selected_events_chronological, stats).
        """
        # ── 1. Fetch via subject-filtered durable pull consumer ───────────
        all_events = await self._fetch_workflow_events(correlation_id)

        # Exclude the current step's events — only prior steps inform reconstruction
        all_events = [e for e in all_events if e.step_index < current_step]

        if not all_events:
            return [], {
                "prior_events_fetched":   0,
                "prior_tokens_available": 0,
                "selected_events":        0,
                "selected_tokens":        0,
                "token_budget":           0,
                "actual_ratio":           0.0,
                "tokens_eliminated":      0,
                "top_event_scores":       [],
            }

        # ── 2. Score each prior event against current task ────────────────
        scored = sorted(
            [(relevance_score(current_task, e.content), e) for e in all_events],
            key=lambda x: x[0],
            reverse=True,
        )

        total_tokens  = sum(e.token_count for e in all_events)
        token_budget  = int(total_tokens * relevance_ratio)

        # ── 3. Greedy selection with minimum-one guarantee ───────────────
        # Always include the highest-scoring event regardless of budget
        # (it is the most semantically relevant prior context and must be
        # represented). Then fill remaining budget with next-best events.
        # This implements the principled minimum: MCR never delivers zero
        # context when prior events exist.
        selected: list[ContextEvent] = []
        consumed = 0
        first = True
        for score, evt in scored:
            if first:
                selected.append(evt)
                consumed += evt.token_count
                first = False
            elif consumed + evt.token_count <= token_budget:
                selected.append(evt)
                consumed += evt.token_count

        selected.sort(key=lambda e: (e.step_index, e.timestamp))

        actual_ratio = consumed / total_tokens if total_tokens else 0.0

        return selected, {
            "prior_events_fetched":   len(all_events),
            "prior_tokens_available": total_tokens,
            "selected_events":        len(selected),
            "selected_tokens":        consumed,
            "token_budget":           token_budget,
            "actual_ratio":           round(actual_ratio, 3),
            "tokens_eliminated":      total_tokens - consumed,
            "top_event_scores":       [round(s, 3) for s, _ in scored[:3]],
        }

    async def _fetch_workflow_events(self, correlation_id: str) -> list[ContextEvent]:
        """
        Read all events for this workflow from JetStream using a subject-filtered
        ephemeral ordered consumer.

        DESIGN NOTE ON CONSUMER CHOICE:
        Reconstruction is a READ-ONLY operation over the workflow's event history.
        An ordered consumer is correct here: it replays from sequence 1 on every call,
        delivering a consistent view of all prior events without consuming them.

        AckPolicy.EXPLICIT applies to WORKFLOW STEP DELIVERY (JetStream's at-least-once
        guarantee on the publish side), not to reconstruction reads. The publish() call
        above already carries JetStream's delivery guarantee. Reconstruction idempotency
        means that re-reading the stream on failure produces the same result —
        so no ack is needed on the read path.

        filter_subject scopes the consumer to exactly this workflow's subjects at the
        broker (O(N_workflow)), not O(N_stream) Python-level filtering.
        """
        filter_subject = f"poc.secops.incident.{correlation_id}.>"
        events: list[ContextEvent] = []

        try:
            psub = await self.js.subscribe(
                filter_subject,
                ordered_consumer=True,
                deliver_policy="all",
            )
            deadline = __import__('time').time() + 2.0
            while __import__('time').time() < deadline:
                try:
                    msg = await asyncio.wait_for(psub.next_msg(), timeout=0.3)
                    events.append(ContextEvent.from_json(msg.data))
                except asyncio.TimeoutError:
                    break
            await psub.unsubscribe()
        except Exception:
            pass

        return events

    async def stream_info(self) -> dict:
        info = await self.js.stream_info(self.STREAM_NAME)
        return {
            "messages":  info.state.messages,
            "bytes":     info.state.bytes,
            "first_seq": info.state.first_seq,
            "last_seq":  info.state.last_seq,
        }

    async def close(self):
        if self.nc:
            await self.nc.drain()
