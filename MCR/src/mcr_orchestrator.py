"""
mcr_orchestrator.py

MCR Orchestrator: bridges MCP ingress to NATS/JetStream and model routing.

Corrections vs v1:
  - RoutingPolicy per step drives model selection from a provider pool
  - ModelRouter selects cheapest eligible provider meeting SLA constraints
  - Semantic reconstruction with R-bounded budget (no role filter, no window)
  - Stateless comparison includes both user AND assistant turns (symmetric)
  - Token counter: len(text) // 4
"""

import time
from dataclasses import dataclass

from context_plane import MCRContextPlane, ContextEvent, estimate_tokens

R = 0.35   # Relevance ratio: fraction of available prior context to inject.
           # Applied as a token budget; content-aware scorer fills it with
           # the most semantically relevant events.


# ── Routing ───────────────────────────────────────────────────────────────────

@dataclass
class RoutingPolicy:
    """
    Per-step constraints for model selection.
    Implements the Routing and Dispatch component from Section 2.3:
    'Routing decisions governed by SLA requirements, cost constraints,
    compliance policies, and current load conditions.'
    """
    step_type:         str
    min_capability:    str    # "basic" | "reasoning" | "advanced"
    max_latency_ms:    int
    max_cost_per_mtok: float  # USD per million input tokens
    data_class:        str    # "internal" | "confidential"


PROVIDER_POOL = [
    {
        "name":           "claude-haiku-4-5",
        "capability":     "basic",
        "latency_p50_ms": 150,
        "cost_per_mtok":  0.80,
        "data_classes":   ["internal", "confidential"],
    },
    {
        "name":           "claude-sonnet-4-5",
        "capability":     "reasoning",
        "latency_p50_ms": 380,
        "cost_per_mtok":  3.00,
        "data_classes":   ["internal", "confidential"],
    },
    {
        "name":           "claude-opus-4-5",
        "capability":     "advanced",
        "latency_p50_ms": 750,
        "cost_per_mtok":  15.00,
        "data_classes":   ["internal", "confidential"],
    },
]

CAPABILITY_RANK = {"basic": 0, "reasoning": 1, "advanced": 2}


class ModelRouter:
    """
    Selects the cheapest provider satisfying capability, latency, cost,
    and data classification constraints.
    """

    @staticmethod
    def select(policy: RoutingPolicy) -> dict:
        eligible = [
            p for p in PROVIDER_POOL
            if CAPABILITY_RANK[p["capability"]] >= CAPABILITY_RANK[policy.min_capability]
            and p["latency_p50_ms"] <= policy.max_latency_ms
            and p["cost_per_mtok"]  <= policy.max_cost_per_mtok
            and policy.data_class   in p["data_classes"]
        ]
        if not eligible:
            raise RuntimeError(
                f"No provider satisfies routing policy for '{policy.step_type}'"
            )
        return min(eligible, key=lambda p: p["cost_per_mtok"])


# ── Simulated model responses ─────────────────────────────────────────────────

RESPONSES = [
    ("Severity: HIGH. The traffic volume of 2.3 GB in 8 minutes to an external IP on "
     "port 443 is highly anomalous for a finance workstation during off-hours. "
     "Immediate actions: isolate 10.4.22.107 from its network segment, preserve "
     "volatile memory and active connection state, and page the IR lead now."),

    ("The destination 185.220.101.45 is a confirmed Tor exit node, inconsistent with "
     "any authorized scheduled activity. The 2-hour gap between the 01:00 backup and "
     "03:14 transfer eliminates backup noise as an explanation. Threat category: "
     "credentialed data exfiltration, likely via a malware implant or hijacked "
     "session on FINWKS-047."),

    ("TI confirms this matches an active campaign targeting financial sector firms with "
     "identical TTPs: staged collection then bulk transfer over Tor. The current "
     "incident is in the late-stage exfiltration phase. Containment of the outbound "
     "connection and host isolation must happen within the next 10 minutes."),

    ("Lateral movement is confirmed across two high-value targets. FILESVR-012 holds "
     "quarterly financial reports; DBSVR-003 holds customer transaction records. Both "
     "were accessed within 13 minutes using the analyst's own credentials, consistent "
     "with credential compromise. Containment: isolate both servers immediately, "
     "revoke analyst credentials across all systems, and freeze FINWKS-047."),

    ("INCIDENT SEVERITY: CRITICAL. "
     "Containment: isolate FINWKS-047, FILESVR-012, DBSVR-003 now; revoke all "
     "credentials for the affected account. Evidence priorities: full memory and disk "
     "image of FINWKS-047, authentication logs from both servers, NetFlow for 02:00 "
     "to 04:00 UTC. Notifications: CISO and Legal within 1 hour, DPA within 72 hours "
     "given PII and financial data exposure. Remediation: 5 to 7 days."),
]


# ── MCR Orchestrator ──────────────────────────────────────────────────────────

class MCROrchestrator:
    """
    Full MCR cycle per step:
      1. Publish request event (subject includes correlation ID)
      2. Route: select model via RoutingPolicy constraints
      3. Reconstruct: semantic relevance scoring within R * available budget
      4. Execute model call (replace RESPONSES with live API call)
      5. Publish response event
    """

    def __init__(self, context_plane: MCRContextPlane):
        self.context_plane = context_plane
        self.router        = ModelRouter()
        self.step_log: list[dict] = []

    async def process_step_via_mcr(
        self,
        correlation_id:  str,
        step_index:      int,
        task:            str,
        workflow_type:   str,
        routing_policy:  RoutingPolicy,
    ) -> dict:
        t_start = time.time()

        # 1. Publish request event to JetStream
        req_evt = ContextEvent(
            correlation_id = correlation_id,
            workflow_type  = workflow_type,
            step_index     = step_index,
            event_type     = "request",
            role           = "user",
            content        = task,
            token_count    = estimate_tokens(task),
            timestamp      = time.time(),
        )
        seq = await self.context_plane.publish(req_evt)

        # 2. Route: select model provider from pool
        provider = self.router.select(routing_policy)

        # 3. Reconstruct: semantic relevance within R * available token budget.
        #    The context plane fetches all prior events for this workflow via
        #    a subject-filtered durable consumer, scores each event against
        #    the current task, and selects the highest-scoring events that
        #    fit within R * total_available_tokens.
        selected_events, recon_stats = await self.context_plane.reconstruct_context(
            correlation_id  = correlation_id,
            current_step    = step_index,
            current_task    = task,
            relevance_ratio = R,
        )

        # 4. Execute model call
        sys_tokens  = 28
        ctx_tokens  = recon_stats["selected_tokens"]
        task_tokens = estimate_tokens(task)
        api_input   = sys_tokens + ctx_tokens + task_tokens

        assistant_text = RESPONSES[step_index]
        api_output     = estimate_tokens(assistant_text)
        step_cost      = api_input * provider["cost_per_mtok"] / 1_000_000

        # 5. Publish response event to JetStream
        resp_evt = ContextEvent(
            correlation_id = correlation_id,
            workflow_type  = workflow_type,
            step_index     = step_index,
            event_type     = "response",
            role           = "assistant",
            content        = assistant_text,
            token_count    = api_output,
            timestamp      = time.time(),
        )
        await self.context_plane.publish(resp_evt)

        result = {
            "step_index":     step_index,
            "correlation_id": correlation_id,
            "nats_seq":       seq,
            "routing": {
                "step_type":       routing_policy.step_type,
                "min_capability":  routing_policy.min_capability,
                "selected_model":  provider["name"],
                "cost_per_mtok":   provider["cost_per_mtok"],
                "latency_p50_ms":  provider["latency_p50_ms"],
                "step_cost_usd":   round(step_cost, 6),
            },
            "reconstruction": recon_stats,
            "api_usage": {
                "input_tokens":  api_input,
                "output_tokens": api_output,
            },
            "task_preview":     task[:72] + "..." if len(task) > 72 else task,
            "response_preview": assistant_text[:100] + "...",
            "elapsed_ms":       round((time.time() - t_start) * 1000, 1),
        }
        self.step_log.append(result)
        return result


# ── Stateless Orchestrator ────────────────────────────────────────────────────

class StatelessOrchestrator:
    """
    Baseline stateless pattern: re-injects the full conversation history
    (user AND assistant turns) at every step. No NATS. No JetStream.

    Uses the SAME per-step routing policy as MCR (same model, same cost/Mtok)
    so the comparison isolates the token reduction effect of MCR's selective
    reconstruction, not the model selection effect of routing. This is the
    apples-to-apples baseline: identical model choices, full context re-injection
    vs selective reconstruction.
    """

    def __init__(self):
        self.history: list[dict] = []
        self.step_log: list[dict] = []

    def process_step_stateless(
        self, step_index: int, task: str, routing_policy: RoutingPolicy
    ) -> dict:
        t_start = time.time()

        # Use the same model that MCR would route to for this step type
        provider  = ModelRouter.select(routing_policy)
        sys_tokens  = 28
        hist_tokens = sum(estimate_tokens(m["content"]) for m in self.history)
        task_tokens = estimate_tokens(task)
        api_input   = sys_tokens + hist_tokens + task_tokens

        assistant_text = RESPONSES[step_index]
        api_output     = estimate_tokens(assistant_text)
        step_cost      = api_input * provider["cost_per_mtok"] / 1_000_000

        # Both turns appended — next step re-injects all of this
        self.history.append({"role": "user",      "content": task})
        self.history.append({"role": "assistant",  "content": assistant_text})

        result = {
            "step_index":       step_index,
            "model":            provider["name"],
            "history_messages": len(self.history),
            "api_usage":        {"input_tokens": api_input, "output_tokens": api_output},
            "step_cost_usd":    round(step_cost, 6),
            "task_preview":     task[:72] + "..." if len(task) > 72 else task,
            "response_preview": assistant_text[:100] + "...",
            "elapsed_ms":       round((time.time() - t_start) * 1000, 1),
        }
        self.step_log.append(result)
        return result
