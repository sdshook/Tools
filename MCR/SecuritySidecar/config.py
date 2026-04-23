"""
security/config.py

Loads and validates security policy and toxic flow pattern definitions.
Supports hot-reload: call reload() without restarting the sidecar process.
"""

from __future__ import annotations
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

_POLICY_PATH   = Path(os.getenv("MCR_SECURITY_POLICY",   "security/policy.yaml"))
_PATTERNS_PATH = Path(os.getenv("MCR_SECURITY_PATTERNS", "security/patterns.yaml"))


# ---------------------------------------------------------------------------
# Policy schema
# ---------------------------------------------------------------------------

@dataclass
class ToolPolicy:
    allowlist:        list[str]  = field(default_factory=list)
    denylist:         list[str]  = field(default_factory=list)
    require_approval: list[str]  = field(default_factory=list)   # supports glob: "delete_*"


@dataclass
class EgressPolicy:
    max_calls_per_workflow: int        = 5
    approved_domains:       list[str]  = field(default_factory=list)
    network_tool_classes:   list[str]  = field(default_factory=list)


@dataclass
class RedactionPolicy:
    credentials:       bool = True
    pii:               bool = True
    internal_topology: bool = True
    custom_patterns:   list[str] = field(default_factory=list)   # additional regex strings


@dataclass
class RetentionPolicy:
    security_events_days: int = 90
    audit_records_days:   int = 365


@dataclass
class SIEMConfig:
    enabled:  bool         = False
    endpoint: Optional[str] = None
    format:   str          = "json"
    headers:  dict         = field(default_factory=dict)


@dataclass
class SecurityPolicy:
    tools:     ToolPolicy     = field(default_factory=ToolPolicy)
    egress:    EgressPolicy   = field(default_factory=EgressPolicy)
    redaction: RedactionPolicy = field(default_factory=RedactionPolicy)
    retention: RetentionPolicy = field(default_factory=RetentionPolicy)
    siem:      SIEMConfig     = field(default_factory=SIEMConfig)
    fail_open: bool           = False  # if True, scanner errors permit the event


# ---------------------------------------------------------------------------
# Toxic flow pattern schema
# ---------------------------------------------------------------------------

@dataclass
class ToolCategory:
    """Named group of tools sharing a risk profile."""
    name:  str
    tools: list[str]   # supports glob matching


@dataclass
class ToxicPattern:
    """
    A named sequence of tool categories that constitutes a prohibited flow.
    The sequence is ordered: each step must follow the previous within
    the same workflow instance to trigger a match.
    """
    name:        str
    description: str
    severity:    str          # maps to Severity enum values
    sequence:    list[str]    # list of ToolCategory names in order
    window:      int = 10     # max steps between first and last match


@dataclass
class PatternLibrary:
    categories: list[ToolCategory] = field(default_factory=list)
    patterns:   list[ToxicPattern] = field(default_factory=list)

    def category_tools(self, name: str) -> list[str]:
        for cat in self.categories:
            if cat.name == name:
                return cat.tools
        return []


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_policy:   Optional[SecurityPolicy]  = None
_patterns: Optional[PatternLibrary]  = None


def _load_policy(path: Path) -> SecurityPolicy:
    with open(path) as f:
        raw = yaml.safe_load(f)

    tools_raw = raw.get("tools", {})
    egress_raw = raw.get("egress", {})
    redaction_raw = raw.get("redaction", {})
    retention_raw = raw.get("retention", {})
    siem_raw = raw.get("siem", {})

    return SecurityPolicy(
        tools=ToolPolicy(
            allowlist=tools_raw.get("allowlist", []),
            denylist=tools_raw.get("denylist", []),
            require_approval=tools_raw.get("require_approval", []),
        ),
        egress=EgressPolicy(
            max_calls_per_workflow=egress_raw.get("max_calls_per_workflow", 5),
            approved_domains=egress_raw.get("approved_domains", []),
            network_tool_classes=egress_raw.get("network_tool_classes", []),
        ),
        redaction=RedactionPolicy(
            credentials=redaction_raw.get("credentials", True),
            pii=redaction_raw.get("pii", True),
            internal_topology=redaction_raw.get("internal_topology", True),
            custom_patterns=redaction_raw.get("custom_patterns", []),
        ),
        retention=RetentionPolicy(
            security_events_days=retention_raw.get("security_events_days", 90),
            audit_records_days=retention_raw.get("audit_records_days", 365),
        ),
        siem=SIEMConfig(
            enabled=siem_raw.get("enabled", False),
            endpoint=siem_raw.get("endpoint"),
            format=siem_raw.get("format", "json"),
            headers=siem_raw.get("headers", {}),
        ),
        fail_open=raw.get("fail_open", False),
    )


def _load_patterns(path: Path) -> PatternLibrary:
    with open(path) as f:
        raw = yaml.safe_load(f)

    categories = [
        ToolCategory(name=c["name"], tools=c.get("tools", []))
        for c in raw.get("categories", [])
    ]
    patterns = [
        ToxicPattern(
            name=p["name"],
            description=p.get("description", ""),
            severity=p.get("severity", "high"),
            sequence=p["sequence"],
            window=p.get("window", 10),
        )
        for p in raw.get("patterns", [])
    ]
    return PatternLibrary(categories=categories, patterns=patterns)


def load() -> tuple[SecurityPolicy, PatternLibrary]:
    global _policy, _patterns
    _policy   = _load_policy(_POLICY_PATH)
    _patterns = _load_patterns(_PATTERNS_PATH)
    logger.info("Security config loaded: %d patterns", len(_patterns.patterns))
    return _policy, _patterns


def reload() -> tuple[SecurityPolicy, PatternLibrary]:
    logger.info("Reloading security config")
    return load()


def get_policy() -> SecurityPolicy:
    global _policy
    if _policy is None:
        load()
    return _policy


def get_patterns() -> PatternLibrary:
    global _patterns
    if _patterns is None:
        load()
    return _patterns
