"""
security/redactor.py

Content redactor. Called from context_plane.reconstruct() on LOW and UNTRUSTED
events before their content is included in the context window assembled for
model delivery.

The original event is never modified in JetStream. Only the reconstructed
context delivered to the model is sanitized.
"""

from __future__ import annotations
import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Optional

from .models import RedactionRecord, RedactionResult, TrustLevel
from .config import get_policy

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------------

# Credentials and API keys
_CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Anthropic / OpenAI style keys
    ("api_key_sk",      re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("api_key_ant",     re.compile(r"\bsk-ant-[A-Za-z0-9\-]{20,}\b")),
    # AWS access keys
    ("aws_access_key",  re.compile(r"\bAKIA[A-Z0-9]{16}\b")),
    ("aws_secret_key",  re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]")),
    # Google API keys
    ("google_api_key",  re.compile(r"\bAIza[A-Za-z0-9\-_]{35}\b")),
    # Generic bearer tokens
    ("bearer_token",    re.compile(r"(?i)bearer\s+([A-Za-z0-9\-._~+/]+=*)")),
    # Private key blocks
    ("private_key",     re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END.*?-----", re.DOTALL)),
    # GitHub tokens
    ("github_token",    re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    # Generic high-entropy token heuristic (40+ hex chars)
    ("hex_token",       re.compile(r"\b[0-9a-f]{40,}\b")),
]

# PII patterns
_PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ssn",             re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card",     re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")),
    ("email",           re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("phone_us",        re.compile(r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b")),
    ("passport",        re.compile(r"\b[A-Z]{1,2}[0-9]{6,9}\b")),  # simplified passport heuristic
]

# Internal network topology
_TOPOLOGY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private_ip_10",   re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")),
    ("private_ip_172",  re.compile(r"\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b")),
    ("private_ip_192",  re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b")),
    ("internal_host",   re.compile(r"\b[\w\-]+\.(internal|corp|local|lan|intranet)\b", re.IGNORECASE)),
    ("subnet_cidr",     re.compile(r"\b(10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b")),
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_placeholder(category: str, original: str) -> tuple[str, str]:
    """Return (placeholder_string, sha256_hash)."""
    digest = hashlib.sha256(original.encode()).hexdigest()[:8]
    return f"[REDACTED:{category}:{digest}]", hashlib.sha256(original.encode()).hexdigest()


def _apply_patterns(
    content:  str,
    patterns: list[tuple[str, re.Pattern]],
    records:  list[RedactionRecord],
) -> str:
    """Apply a list of (category, pattern) pairs against content, building records."""
    offset_shift = 0  # track how placeholder length differs from original

    # Collect all matches first so we can process left-to-right without overlap
    matches = []
    for category, pattern in patterns:
        for m in pattern.finditer(content):
            matches.append((m.start(), m.end(), category, m.group(0)))

    # Sort by start position, remove overlapping (keep first)
    matches.sort(key=lambda x: x[0])
    filtered = []
    last_end = -1
    for start, end, category, original in matches:
        if start >= last_end:
            filtered.append((start, end, category, original))
            last_end = end

    # Apply substitutions right-to-left to preserve offsets
    result = content
    for start, end, category, original in reversed(filtered):
        placeholder, digest = _make_placeholder(category, original)
        records.append(RedactionRecord(
            category=category,
            placeholder=placeholder,
            original_hash=hashlib.sha256(original.encode()).hexdigest(),
            position=start,
            length=len(original),
        ))
        result = result[:start] + placeholder + result[end:]

    return result


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def redact(
    content:     str,
    trust_level: TrustLevel,
    workflow_id: Optional[str] = None,
    step_index:  Optional[int] = None,
) -> RedactionResult:
    """
    Main entry point. Called from context_plane.reconstruct() before
    assembling the context window for model delivery.

    Only operates on LOW and UNTRUSTED events. HIGH and MEDIUM events
    are returned unmodified (scanner already classified them as clean).
    """
    if trust_level in (TrustLevel.HIGH, TrustLevel.MEDIUM):
        return RedactionResult(content=content, modified=False)

    try:
        policy = get_policy()
        records: list[RedactionRecord] = []
        result = content

        if policy.redaction.credentials:
            result = _apply_patterns(result, _CREDENTIAL_PATTERNS, records)

        if policy.redaction.pii:
            result = _apply_patterns(result, _PII_PATTERNS, records)

        if policy.redaction.internal_topology:
            result = _apply_patterns(result, _TOPOLOGY_PATTERNS, records)

        if policy.redaction.custom_patterns:
            custom = [
                (f"custom_{i}", re.compile(p))
                for i, p in enumerate(policy.redaction.custom_patterns)
            ]
            result = _apply_patterns(result, custom, records)

        modified = len(records) > 0
        if modified:
            logger.info(
                "redactor: %d redaction(s) on workflow=%s step=%s",
                len(records), workflow_id, step_index,
            )

        return RedactionResult(content=result, records=records, modified=modified)

    except Exception as exc:
        logger.error("redactor exception: %s", exc, exc_info=True)
        # Fail safe: return placeholder content rather than original
        placeholder = f"[REDACTION_ERROR: content withheld due to processing failure]"
        return RedactionResult(
            content=placeholder,
            records=[RedactionRecord(
                category="redaction_error",
                placeholder=placeholder,
                original_hash=hashlib.sha256(content.encode()).hexdigest(),
                position=0,
                length=len(content),
            )],
            modified=True,
        )
