"""
security/policy_engine.py

Pre-dispatch tool call policy enforcement. Called from mcr_orchestrator.py
inside handle_tool_call() before any tool is executed or event is published.

Evaluation order:
  1. Denylist check         (immediate reject)
  2. Allowlist check        (reject if not listed)
  3. Argument schema check  (reject malformed args)
  4. Sequence analysis      (reject toxic flows)
  5. Egress check           (reject unapproved destinations)
  6. Approval check         (flag for human confirmation)
"""

from __future__ import annotations
import fnmatch
import logging
from typing import Optional

from .models import PolicyDecision, SourceType
from .config import get_policy, SecurityPolicy
from .sequence_analyzer import check_sequence

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool name glob matching
# ---------------------------------------------------------------------------

def _matches_any(tool_name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(tool_name.lower(), p.lower()) for p in patterns)


# ---------------------------------------------------------------------------
# Egress domain check
# ---------------------------------------------------------------------------

_EGRESS_ARG_KEYS = {"url", "endpoint", "destination", "host", "uri", "target"}


def _extract_destination(args: dict) -> Optional[str]:
    for key in _EGRESS_ARG_KEYS:
        if key in args:
            return str(args[key])
    return None


def _domain_approved(destination: str, approved: list[str]) -> bool:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(destination if "://" in destination else f"https://{destination}")
        hostname = parsed.hostname or ""
    except Exception:
        hostname = destination

    return any(
        fnmatch.fnmatch(hostname.lower(), approved_domain.lower())
        for approved_domain in approved
    )


# ---------------------------------------------------------------------------
# Argument schema validation
# ---------------------------------------------------------------------------

def _validate_args(tool_name: str, args: dict, policy: SecurityPolicy) -> Optional[str]:
    """
    Minimal structural validation. Extend with per-tool schemas via
    policy.tools.arg_schemas if needed. Currently enforces:
      - args must be a dict
      - no deeply nested callable-looking values (basic prompt injection via args)
    """
    if not isinstance(args, dict):
        return f"args for '{tool_name}' must be a dict, got {type(args).__name__}"

    # Check for injection-like values in args
    for key, value in args.items():
        if isinstance(value, str) and len(value) > 2000:
            logger.warning("policy_engine: oversized arg '%s' in tool '%s' (%d chars)", key, tool_name, len(value))
        # Detect obvious prompt injection in arg values
        suspicious = ["ignore previous", "disregard", "you are now", "new system prompt"]
        if isinstance(value, str) and any(s in value.lower() for s in suspicious):
            return f"arg '{key}' in tool '{tool_name}' contains injection-like content"

    return None


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

async def evaluate(
    tool_name:   str,
    args:        dict,
    workflow_id: str,
    step_index:  int,
    call_history: list[str],
    source_type: SourceType = SourceType.USER,
) -> PolicyDecision:
    """
    Main entry point. Returns PolicyDecision.

    call_history: ordered list of prior tool names in this workflow instance.
    Caller (mcr_orchestrator.py) is responsible for fetching this from JetStream
    and passing it in. See _get_call_history() in orchestrator integration notes.
    """
    policy = get_policy()

    # 1. Denylist
    if _matches_any(tool_name, policy.tools.denylist):
        logger.warning("policy_engine: DENY denylist hit: tool=%s workflow=%s", tool_name, workflow_id)
        return PolicyDecision(
            permitted=False,
            violation_reason=f"Tool '{tool_name}' is on the denylist",
        )

    # 2. Allowlist (if defined; empty allowlist means all non-denied tools permitted)
    if policy.tools.allowlist and not _matches_any(tool_name, policy.tools.allowlist):
        logger.warning("policy_engine: DENY not in allowlist: tool=%s workflow=%s", tool_name, workflow_id)
        return PolicyDecision(
            permitted=False,
            violation_reason=f"Tool '{tool_name}' is not in the allowlist",
        )

    # 3. Argument validation
    arg_error = _validate_args(tool_name, args, policy)
    if arg_error:
        logger.warning("policy_engine: DENY arg validation: %s workflow=%s", arg_error, workflow_id)
        return PolicyDecision(permitted=False, violation_reason=arg_error)

    # 4. Sequence analysis
    sequence_decision = check_sequence(tool_name, call_history)
    if sequence_decision is not None:
        logger.warning(
            "policy_engine: DENY sequence: pattern=%s tool=%s workflow=%s",
            sequence_decision.matched_pattern, tool_name, workflow_id,
        )
        return sequence_decision

    # 5. Egress check
    if _matches_any(tool_name, policy.egress.network_tool_classes):
        destination = _extract_destination(args)
        if destination:
            # Count prior egress calls in this workflow
            prior_egress = sum(
                1 for t in call_history
                if _matches_any(t, policy.egress.network_tool_classes)
            )
            if prior_egress >= policy.egress.max_calls_per_workflow:
                logger.warning(
                    "policy_engine: DENY egress limit reached: tool=%s workflow=%s prior=%d",
                    tool_name, workflow_id, prior_egress,
                )
                return PolicyDecision(
                    permitted=False,
                    violation_reason=(
                        f"Egress call limit ({policy.egress.max_calls_per_workflow}) "
                        f"reached for workflow {workflow_id}"
                    ),
                )
            if policy.egress.approved_domains and not _domain_approved(destination, policy.egress.approved_domains):
                logger.warning(
                    "policy_engine: DENY unapproved egress: destination=%s tool=%s workflow=%s",
                    destination, tool_name, workflow_id,
                )
                return PolicyDecision(
                    permitted=False,
                    violation_reason=f"Destination '{destination}' is not on the approved domain list",
                )

    # 6. Human approval gate
    requires_approval = _matches_any(tool_name, policy.tools.require_approval)
    if requires_approval:
        logger.info("policy_engine: APPROVAL REQUIRED: tool=%s workflow=%s", tool_name, workflow_id)

    return PolicyDecision(permitted=True, requires_approval=requires_approval)
