"""
security/models.py

Shared dataclasses for the MCR security sidecar.
All modules import from here to ensure consistent types across
the scanner, redactor, policy engine, audit consumer, and investigator.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class TrustLevel(str, Enum):
    HIGH      = "high"       # System-originated: MCR internals, system prompts
    MEDIUM    = "medium"     # User-originated: direct user input
    LOW       = "low"        # Tool-result-originated: external API, file reads
    UNTRUSTED = "untrusted"  # Flagged during scan: injection patterns detected


class Severity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class SourceType(str, Enum):
    USER         = "user"
    SYSTEM       = "system"
    TOOL_RESULT  = "tool_result"
    AGENT_OUTPUT = "agent_output"
    EXTERNAL     = "external"


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@dataclass
class ScanFlag:
    category: str          # e.g. "invisible_unicode", "injection_pattern"
    detail:   str          # specific match or character range
    position: Optional[int] = None  # character offset if applicable


@dataclass
class ScanResult:
    clean:       bool
    trust_level: TrustLevel
    flags:       list[ScanFlag]     = field(default_factory=list)
    sanitized:   Optional[str]      = None  # content with overt markup stripped


# ---------------------------------------------------------------------------
# Redactor
# ---------------------------------------------------------------------------

@dataclass
class RedactionRecord:
    category:      str   # "api_key", "pii_ssn", "internal_ip", etc.
    placeholder:   str   # e.g. "[REDACTED:api_key:a3f2]"
    original_hash: str   # SHA-256 of removed value for audit traceability
    position:      int   # character offset in original content
    length:        int   # length of removed span


@dataclass
class RedactionResult:
    content:  str                       # redacted content
    records:  list[RedactionRecord]     = field(default_factory=list)
    modified: bool                      = False


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------

@dataclass
class PolicyDecision:
    permitted:        bool
    requires_approval: bool             = False
    violation_reason: Optional[str]     = None
    matched_pattern:  Optional[str]     = None  # name of toxic flow pattern if applicable


# ---------------------------------------------------------------------------
# Security Events (published to NATS security subjects)
# ---------------------------------------------------------------------------

@dataclass
class SecurityEvent:
    event_id:    str
    workflow_id: str
    step_index:  int
    timestamp:   datetime
    severity:    Severity
    category:    str          # "injection_detected", "policy_violation", "redaction", etc.
    detail:      str
    source_type: SourceType
    tenant:      str
    domain:      str
    raw_flags:   list[str]    = field(default_factory=list)
    metadata:    dict         = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Investigation / Replay
# ---------------------------------------------------------------------------

@dataclass
class WorkflowEvent:
    """Reconstructed event from JetStream replay, annotated for investigation."""
    seq:            int
    subject:        str
    timestamp:      datetime
    workflow_id:    str
    step_index:     int
    role:           str
    content:        str
    source_type:    SourceType
    trust_level:    TrustLevel
    scan_flags:     list[str]           = field(default_factory=list)
    redactions:     list[RedactionRecord] = field(default_factory=list)
    tool_name:      Optional[str]       = None
    tool_args:      Optional[dict]      = None
    policy_outcome: Optional[str]       = None


@dataclass
class WorkflowTimeline:
    workflow_id: str
    tenant:      str
    domain:      str
    start_time:  datetime
    end_time:    Optional[datetime]
    events:      list[WorkflowEvent]    = field(default_factory=list)
    security_events: list[SecurityEvent] = field(default_factory=list)

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    @property
    def flagged_steps(self) -> list[int]:
        return sorted({e.step_index for e in self.security_events})

    @property
    def redacted_steps(self) -> list[int]:
        return sorted({e.step_index for e in self.events if e.redactions})
