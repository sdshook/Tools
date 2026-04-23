"""
MCR Security Sidecar

Enterprise AI security plane for Model Context Routing.
Provides ingress scanning, content redaction, policy enforcement,
sequence analysis, and forensic investigation.

Usage:
    # Import specific modules
    from SecuritySidecar.scanner import scan_payload
    from SecuritySidecar.redactor import redact
    from SecuritySidecar.policy_engine import evaluate
    from SecuritySidecar.sidecar import SecurityPublisher

    # Or import models/config
    from SecuritySidecar.models import TrustLevel, ScanResult, PolicyDecision
    from SecuritySidecar.config import get_policy, reload

Run standalone:
    python -m SecuritySidecar.sidecar
"""

__version__ = "0.1.0"

# Expose key classes and functions at package level
from .models import (
    TrustLevel,
    Severity,
    SourceType,
    ScanResult,
    ScanFlag,
    RedactionResult,
    RedactionRecord,
    PolicyDecision,
    SecurityEvent,
    WorkflowEvent,
    WorkflowTimeline,
)

from .config import (
    get_policy,
    get_patterns,
    reload,
    SecurityPolicy,
    PatternLibrary,
)

__all__ = [
    # Enums
    "TrustLevel",
    "Severity", 
    "SourceType",
    # Dataclasses
    "ScanResult",
    "ScanFlag",
    "RedactionResult",
    "RedactionRecord",
    "PolicyDecision",
    "SecurityEvent",
    "WorkflowEvent",
    "WorkflowTimeline",
    # Config
    "get_policy",
    "get_patterns",
    "reload",
    "SecurityPolicy",
    "PatternLibrary",
]
