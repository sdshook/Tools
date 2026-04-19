"""
mcr_client.py
MCR Client Library for integration with existing applications.

This module provides a clean interface for integrating MCR into:
- Existing MCP servers
- CLI tools and CI/CD pipelines
- REST API services
- Any Python application

Usage:
    from mcr_client import MCRClient
    
    async with MCRClient() as mcr:
        # Start a workflow
        workflow_id = mcr.start_workflow("incident")
        
        # Publish an event
        await mcr.publish_event(
            workflow_id=workflow_id,
            step_index=0,
            role="user",
            content="Analyze this security alert...",
        )
        
        # Reconstruct context for next step
        context = await mcr.reconstruct(
            workflow_id=workflow_id,
            current_step=1,
            current_task="Correlate with threat intelligence...",
        )
        
        # Use context with your LLM
        messages = context["messages"]
"""

import asyncio
import json
import os
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Optional

import nats
from nats.js.api import StreamConfig, RetentionPolicy, StorageType


@dataclass
class MCRConfig:
    """MCR client configuration."""
    nats_url: str = "nats://localhost:4222"
    tenant: str = "default"
    domain: str = "workflows"
    stream_name: str = "MCR_CONTEXT"
    relevance_ratio: float = 0.35
    max_stream_age: int = 86400
    max_stream_msgs: int = 500000
    max_stream_bytes: int = 512 * 1024 * 1024
    
    @classmethod
    def from_env(cls) -> "MCRConfig":
        """Create configuration from environment variables."""
        return cls(
            nats_url=os.getenv("MCR_NATS_URL", "nats://localhost:4222"),
            tenant=os.getenv("MCR_TENANT", "default"),
            domain=os.getenv("MCR_DOMAIN", "workflows"),
            stream_name=os.getenv("MCR_STREAM_NAME", "MCR_CONTEXT"),
            relevance_ratio=float(os.getenv("MCR_RELEVANCE_RATIO", "0.35")),
            max_stream_age=int(os.getenv("MCR_MAX_STREAM_AGE", "86400")),
            max_stream_msgs=int(os.getenv("MCR_MAX_STREAM_MSGS", "500000")),
            max_stream_bytes=int(os.getenv("MCR_MAX_STREAM_BYTES", str(512 * 1024 * 1024))),
        )


@dataclass
class ContextEvent:
    """Event stored in the MCR context plane."""
    workflow_id: str
    workflow_type: str
    step_index: int
    event_type: str  # "request" | "response"
    role: str  # "user" | "assistant" | "system"
    content: str
    token_count: int
    timestamp: float
    tenant: str
    domain: str
    metadata: Optional[dict] = None
    
    def to_json(self) -> bytes:
        return json.dumps(asdict(self)).encode()
    
    @staticmethod
    def from_json(data: bytes) -> "ContextEvent":
        d = json.loads(data)
        return ContextEvent(**d)
    
    def subject(self) -> str:
        return f"{self.tenant}.{self.domain}.{self.workflow_type}.{self.workflow_id}.{self.event_type}"


def estimate_tokens(text: str) -> int:
    """Approximate token count (~4 chars per token)."""
    return max(1, len(text) // 4)


def relevance_score(query: str, document: str) -> float:
    """Cosine similarity between bag-of-words vectors."""
    from collections import Counter
    import math
    
    def bow(text):
        return Counter(w.lower() for w in text.split() if w.isalpha())
    
    q, d = bow(query), bow(document)
    if not q or not d:
        return 0.0
    vocab = set(q) | set(d)
    qv = [q.get(w, 0) for w in vocab]
    dv = [d.get(w, 0) for w in vocab]
    dot = sum(a * b for a, b in zip(qv, dv))
    mag_q = math.sqrt(sum(a * a for a in qv))
    mag_d = math.sqrt(sum(b * b for b in dv))
    return 0.0 if mag_q == 0 or mag_d == 0 else dot / (mag_q * mag_d)


class MCRClient:
    """
    MCR Client for integrating context persistence into any application.
    
    This client can be used standalone or integrated with existing
    MCP servers, CLI tools, REST APIs, or CI/CD pipelines.
    """
    
    def __init__(self, config: Optional[MCRConfig] = None):
        self.config = config or MCRConfig.from_env()
        self.nc: Optional[nats.aio.client.Client] = None
        self.js = None
        self._connected = False
    
    async def connect(self):
        """Connect to NATS and ensure JetStream stream exists."""
        if self._connected:
            return
        
        self.nc = await nats.connect(self.config.nats_url)
        self.js = self.nc.jetstream()
        
        # Ensure stream exists
        stream_subject = f"{self.config.tenant}.{self.config.domain}.>"
        cfg = StreamConfig(
            name=self.config.stream_name,
            subjects=[stream_subject],
            retention=RetentionPolicy.LIMITS,
            storage=StorageType.FILE,
            max_age=self.config.max_stream_age,
            max_msgs=self.config.max_stream_msgs,
            max_bytes=self.config.max_stream_bytes,
            num_replicas=1,
        )
        try:
            await self.js.add_stream(cfg)
        except Exception:
            await self.js.update_stream(cfg)
        
        self._connected = True
    
    async def close(self):
        """Close NATS connection."""
        if self.nc:
            await self.nc.drain()
            self._connected = False
    
    async def __aenter__(self):
        await self.connect()
        return self
    
    async def __aexit__(self, *args):
        await self.close()
    
    def start_workflow(self, workflow_type: str) -> str:
        """Generate a new workflow correlation ID."""
        return str(uuid.uuid4())
    
    async def publish_event(
        self,
        workflow_id: str,
        step_index: int,
        role: str,
        content: str,
        workflow_type: str = "workflow",
        event_type: str = "request",
        metadata: Optional[dict] = None,
    ) -> int:
        """
        Publish an event to the MCR context plane.
        
        Args:
            workflow_id: Correlation ID from start_workflow()
            step_index: Zero-based step index
            role: "user", "assistant", or "system"
            content: Event content
            workflow_type: Classification (e.g., "incident", "support", "ci")
            event_type: "request" or "response"
            metadata: Optional additional metadata
            
        Returns:
            JetStream sequence number
        """
        if not self._connected:
            await self.connect()
        
        event = ContextEvent(
            workflow_id=workflow_id,
            workflow_type=workflow_type,
            step_index=step_index,
            event_type=event_type,
            role=role,
            content=content,
            token_count=estimate_tokens(content),
            timestamp=time.time(),
            tenant=self.config.tenant,
            domain=self.config.domain,
            metadata=metadata,
        )
        
        ack = await self.js.publish(
            event.subject(),
            event.to_json(),
            headers={
                "workflow-id": workflow_id,
                "step-index": str(step_index),
                "workflow-type": workflow_type,
                "role": role,
            },
        )
        return ack.seq
    
    async def publish_turn(
        self,
        workflow_id: str,
        step_index: int,
        user_content: str,
        assistant_content: str,
        workflow_type: str = "workflow",
        metadata: Optional[dict] = None,
    ) -> tuple[int, int]:
        """
        Publish both user request and assistant response for a step.
        
        Convenience method for publishing a complete turn.
        
        Returns:
            Tuple of (request_seq, response_seq)
        """
        req_seq = await self.publish_event(
            workflow_id=workflow_id,
            step_index=step_index,
            role="user",
            content=user_content,
            workflow_type=workflow_type,
            event_type="request",
            metadata=metadata,
        )
        
        resp_seq = await self.publish_event(
            workflow_id=workflow_id,
            step_index=step_index,
            role="assistant",
            content=assistant_content,
            workflow_type=workflow_type,
            event_type="response",
            metadata=metadata,
        )
        
        return req_seq, resp_seq
    
    async def reconstruct(
        self,
        workflow_id: str,
        current_step: int,
        current_task: str,
        workflow_type: str = "workflow",
        relevance_ratio: Optional[float] = None,
    ) -> dict:
        """
        Reconstruct context for the current step using semantic relevance.
        
        Args:
            workflow_id: Correlation ID
            current_step: Current step index (reconstructs from prior steps)
            current_task: Current task description (used for relevance scoring)
            workflow_type: Workflow type for subject filtering
            relevance_ratio: Override default R value (0.0 to 1.0)
            
        Returns:
            Dictionary with:
            - messages: List of {"role": str, "content": str} for LLM
            - events: List of ContextEvent objects
            - stats: Reconstruction statistics
        """
        if not self._connected:
            await self.connect()
        
        R = relevance_ratio or self.config.relevance_ratio
        
        # Fetch all prior events for this workflow
        filter_subject = f"{self.config.tenant}.{self.config.domain}.{workflow_type}.{workflow_id}.>"
        events = []
        
        try:
            psub = await self.js.subscribe(
                filter_subject,
                ordered_consumer=True,
                deliver_policy="all",
            )
            deadline = time.time() + 2.0
            while time.time() < deadline:
                try:
                    msg = await asyncio.wait_for(psub.next_msg(), timeout=0.3)
                    events.append(ContextEvent.from_json(msg.data))
                except asyncio.TimeoutError:
                    break
            await psub.unsubscribe()
        except Exception:
            pass
        
        # Filter to prior steps only
        prior_events = [e for e in events if e.step_index < current_step]
        
        if not prior_events:
            return {
                "messages": [],
                "events": [],
                "stats": {
                    "prior_events": 0,
                    "prior_tokens": 0,
                    "selected_events": 0,
                    "selected_tokens": 0,
                    "tokens_eliminated": 0,
                    "relevance_ratio": R,
                },
            }
        
        # Score by relevance to current task
        scored = sorted(
            [(relevance_score(current_task, e.content), e) for e in prior_events],
            key=lambda x: x[0],
            reverse=True,
        )
        
        total_tokens = sum(e.token_count for e in prior_events)
        token_budget = int(total_tokens * R)
        
        # Greedy selection with minimum-one guarantee
        selected = []
        consumed = 0
        for i, (score, evt) in enumerate(scored):
            if i == 0 or consumed + evt.token_count <= token_budget:
                selected.append(evt)
                consumed += evt.token_count
        
        # Sort chronologically for conversation order
        selected.sort(key=lambda e: (e.step_index, e.timestamp))
        
        # Build messages list for LLM
        messages = [{"role": e.role, "content": e.content} for e in selected]
        
        return {
            "messages": messages,
            "events": selected,
            "stats": {
                "prior_events": len(prior_events),
                "prior_tokens": total_tokens,
                "selected_events": len(selected),
                "selected_tokens": consumed,
                "tokens_eliminated": total_tokens - consumed,
                "relevance_ratio": R,
                "actual_ratio": round(consumed / total_tokens, 3) if total_tokens else 0,
            },
        }
    
    async def get_workflow_history(
        self,
        workflow_id: str,
        workflow_type: str = "workflow",
    ) -> list[ContextEvent]:
        """
        Retrieve complete workflow history for audit/replay.
        
        Returns all events for a workflow in chronological order.
        """
        if not self._connected:
            await self.connect()
        
        filter_subject = f"{self.config.tenant}.{self.config.domain}.{workflow_type}.{workflow_id}.>"
        events = []
        
        try:
            psub = await self.js.subscribe(
                filter_subject,
                ordered_consumer=True,
                deliver_policy="all",
            )
            deadline = time.time() + 2.0
            while time.time() < deadline:
                try:
                    msg = await asyncio.wait_for(psub.next_msg(), timeout=0.3)
                    events.append(ContextEvent.from_json(msg.data))
                except asyncio.TimeoutError:
                    break
            await psub.unsubscribe()
        except Exception:
            pass
        
        events.sort(key=lambda e: (e.step_index, e.timestamp))
        return events
    
    async def stream_info(self) -> dict:
        """Get JetStream stream statistics."""
        if not self._connected:
            await self.connect()
        
        info = await self.js.stream_info(self.config.stream_name)
        return {
            "messages": info.state.messages,
            "bytes": info.state.bytes,
            "first_seq": info.state.first_seq,
            "last_seq": info.state.last_seq,
        }
