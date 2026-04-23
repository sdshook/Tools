"""
security/sequence_analyzer.py

Matches the current tool call against known toxic flow patterns defined
in security/patterns.yaml, using the workflow's JetStream event history
to evaluate multi-step sequences.

Called by policy_engine.check_sequence().
"""

from __future__ import annotations
import fnmatch
import logging
from typing import Optional

from .config import get_patterns, PatternLibrary, ToxicPattern, ToolCategory
from .models import PolicyDecision, Severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool category resolution
# ---------------------------------------------------------------------------

def _tool_matches_category(tool_name: str, category: ToolCategory) -> bool:
    """Return True if tool_name matches any pattern in the category's tool list."""
    for pattern in category.tools:
        if fnmatch.fnmatch(tool_name.lower(), pattern.lower()):
            return True
    return False


def _resolve_category(tool_name: str, library: PatternLibrary) -> list[str]:
    """Return all category names that the given tool belongs to."""
    return [
        cat.name
        for cat in library.categories
        if _tool_matches_category(tool_name, cat)
    ]


# ---------------------------------------------------------------------------
# Sequence matching
# ---------------------------------------------------------------------------

def _match_pattern(
    proposed_tool:   str,
    call_history:    list[str],          # ordered list of prior tool names
    pattern:         ToxicPattern,
    library:         PatternLibrary,
) -> bool:
    """
    Check whether proposed_tool completes the given toxic pattern given
    the call history.

    Algorithm:
      - The pattern defines an ordered sequence of tool categories.
      - We look for a subsequence in (call_history + proposed_tool) that
        satisfies the pattern order, within the pattern's window size.
    """
    sequence_cats = pattern.sequence   # e.g. ["credential_read", "network_egress"]
    if not sequence_cats:
        return False

    # The last category in the sequence must match the proposed tool
    last_cat_name = sequence_cats[-1]
    last_cat_tools = library.category_tools(last_cat_name)
    if not any(fnmatch.fnmatch(proposed_tool.lower(), t.lower()) for t in last_cat_tools):
        return False

    # If the pattern is length 1, we only need to check the proposed tool
    if len(sequence_cats) == 1:
        return True

    # For longer patterns, check that the preceding categories appear in
    # the call history within the window, in order
    preceding = sequence_cats[:-1]
    window_history = call_history[-(pattern.window - 1):]  # last N-1 calls

    # Walk through window_history looking for each preceding category in order
    cat_idx = 0
    for tool in window_history:
        if cat_idx >= len(preceding):
            break
        tools_in_cat = library.category_tools(preceding[cat_idx])
        if any(fnmatch.fnmatch(tool.lower(), t.lower()) for t in tools_in_cat):
            cat_idx += 1

    return cat_idx >= len(preceding)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def check_sequence(
    proposed_tool: str,
    call_history:  list[str],
) -> Optional[PolicyDecision]:
    """
    Evaluate proposed_tool against all toxic flow patterns given call_history.

    Returns a PolicyDecision with permitted=False if a pattern matches,
    or None if no pattern matches (caller should continue evaluation).

    call_history: ordered list of tool names called so far in this workflow,
                  most recent last. Obtained from policy_engine via JetStream query.
    """
    library = get_patterns()

    for pattern in library.patterns:
        if _match_pattern(proposed_tool, call_history, pattern, library):
            logger.warning(
                "sequence_analyzer: toxic pattern matched: %s (proposed=%s)",
                pattern.name, proposed_tool,
            )
            return PolicyDecision(
                permitted=False,
                violation_reason=(
                    f"Toxic flow pattern '{pattern.name}': {pattern.description}"
                ),
                matched_pattern=pattern.name,
            )

    return None


def describe_history(call_history: list[str]) -> list[dict]:
    """
    Annotate call history with category membership.
    Used by investigator.py to render readable timelines.
    """
    library = get_patterns()
    return [
        {"tool": tool, "categories": _resolve_category(tool, library)}
        for tool in call_history
    ]
