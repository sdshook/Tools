"""
security/scanner.py

Ingress content scanner. Called synchronously inside context_plane.publish_event()
before any event is persisted to JetStream.

Design constraints:
  - Must be fast: no blocking I/O, no model inference
  - Must be safe: exceptions must not crash the calling MCR process
  - Returns ScanResult with trust classification and sanitized content
"""

from __future__ import annotations
import hashlib
import logging
import re
import unicodedata
from typing import Optional

from .models import ScanFlag, ScanResult, SourceType, TrustLevel
from .config import get_policy

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Invisible and confusable Unicode ranges
# ---------------------------------------------------------------------------

# Categories that are invisible or used for instruction hiding
_INVISIBLE_CATEGORIES = {
    "Cf",   # Format characters (zero-width joiners, directional marks, etc.)
    "Cc",   # Control characters
    "Zs",   # Space separators (non-standard spaces)
}

# Specific codepoints commonly exploited
_SUSPICIOUS_CODEPOINTS = {
    0x200B,  # Zero-width space
    0x200C,  # Zero-width non-joiner
    0x200D,  # Zero-width joiner
    0x2028,  # Line separator
    0x2029,  # Paragraph separator
    0xFEFF,  # BOM / zero-width no-break space
    0x00AD,  # Soft hyphen
}


# ---------------------------------------------------------------------------
# Injection phrase patterns
# ---------------------------------------------------------------------------
# Compiled once at import time for performance.

_INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("override_instruction",
     re.compile(
         r"(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|earlier|above)\s+"
         r"(instructions?|context|rules?|constraints?|prompts?)",
         re.IGNORECASE,
     )),
    ("role_reassignment",
     re.compile(
         r"(you are now|act as|pretend (you are|to be)|your new (role|persona|identity) is"
         r"|from now on you)",
         re.IGNORECASE,
     )),
    ("system_prompt_injection",
     re.compile(
         r"(new system prompt|updated system prompt|system:\s|<\|system\|>|\[SYSTEM\]"
         r"|\[INST\]|<<SYS>>)",
         re.IGNORECASE,
     )),
    ("jailbreak_marker",
     re.compile(
         r"(DAN mode|developer mode|jailbreak|unrestricted mode|no (restrictions|limits|guidelines))",
         re.IGNORECASE,
     )),
    ("exfiltration_instruction",
     re.compile(
         r"(send|transmit|post|upload|exfiltrate)\s+(all\s+)?(the\s+)?"
         r"(context|conversation|system prompt|instructions?|data|contents?)\s+(to|via|through)",
         re.IGNORECASE,
     )),
]


# ---------------------------------------------------------------------------
# Hidden markup patterns
# ---------------------------------------------------------------------------

_HIDDEN_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_HIDDEN_HTML_ATTR    = re.compile(r'(style|hidden|aria-hidden)\s*=\s*["\'].*?["\']', re.IGNORECASE)
_HIDDEN_MD_FRAGMENT  = re.compile(r"\[(?!\w+\])[^\]]{0,20}\]\(\s*\)")  # empty link targets

# Base64 blob heuristic: 40+ chars of pure base64 outside of known contexts
_BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])")


# ---------------------------------------------------------------------------
# Trust level derivation
# ---------------------------------------------------------------------------

def _base_trust(source_type: SourceType) -> TrustLevel:
    return {
        SourceType.SYSTEM:       TrustLevel.HIGH,
        SourceType.USER:         TrustLevel.MEDIUM,
        SourceType.AGENT_OUTPUT: TrustLevel.LOW,
        SourceType.TOOL_RESULT:  TrustLevel.LOW,
        SourceType.EXTERNAL:     TrustLevel.LOW,
    }.get(source_type, TrustLevel.MEDIUM)


def _derive_trust(base: TrustLevel, flags: list[ScanFlag]) -> TrustLevel:
    if not flags:
        return base
    # Any injection flag downgrades to UNTRUSTED regardless of source
    injection_categories = {
        "override_instruction", "role_reassignment",
        "system_prompt_injection", "jailbreak_marker", "exfiltration_instruction",
    }
    if any(f.category in injection_categories for f in flags):
        return TrustLevel.UNTRUSTED
    # Other flags (hidden markup, suspicious unicode) downgrade by one level
    level_order = [TrustLevel.HIGH, TrustLevel.MEDIUM, TrustLevel.LOW, TrustLevel.UNTRUSTED]
    idx = level_order.index(base)
    return level_order[min(idx + 1, len(level_order) - 1)]


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_invisible_unicode(content: str) -> list[ScanFlag]:
    flags = []
    for i, ch in enumerate(content):
        cp = ord(ch)
        cat = unicodedata.category(ch)
        if cat in _INVISIBLE_CATEGORIES or cp in _SUSPICIOUS_CODEPOINTS:
            flags.append(ScanFlag(
                category="invisible_unicode",
                detail=f"U+{cp:04X} ({unicodedata.name(ch, 'UNKNOWN')}) at offset {i}",
                position=i,
            ))
    return flags


def _check_injection_patterns(content: str) -> list[ScanFlag]:
    flags = []
    for name, pattern in _INJECTION_PATTERNS:
        for m in pattern.finditer(content):
            flags.append(ScanFlag(
                category=name,
                detail=f"matched: {m.group(0)!r}",
                position=m.start(),
            ))
    return flags


def _check_hidden_markup(content: str) -> list[ScanFlag]:
    flags = []
    for m in _HIDDEN_HTML_COMMENT.finditer(content):
        flags.append(ScanFlag(category="hidden_html_comment", detail=m.group(0)[:60], position=m.start()))
    for m in _HIDDEN_HTML_ATTR.finditer(content):
        flags.append(ScanFlag(category="hidden_html_attribute", detail=m.group(0)[:60], position=m.start()))
    for m in _HIDDEN_MD_FRAGMENT.finditer(content):
        flags.append(ScanFlag(category="hidden_markdown_fragment", detail=m.group(0), position=m.start()))
    return flags


def _check_base64_blobs(content: str) -> list[ScanFlag]:
    flags = []
    for m in _BASE64_BLOB.finditer(content):
        flags.append(ScanFlag(
            category="suspicious_base64",
            detail=f"blob of length {len(m.group(0))} at offset {m.start()}",
            position=m.start(),
        ))
    return flags


# ---------------------------------------------------------------------------
# Sanitization (strip overt markup without removing payload content)
# ---------------------------------------------------------------------------

def _sanitize(content: str) -> str:
    """Strip provably inert hidden markup. Does not remove payload text."""
    content = _HIDDEN_HTML_COMMENT.sub("", content)
    # Strip invisible Unicode characters
    cleaned = []
    for ch in content:
        cp = ord(ch)
        cat = unicodedata.category(ch)
        if cat not in _INVISIBLE_CATEGORIES and cp not in _SUSPICIOUS_CODEPOINTS:
            cleaned.append(ch)
    return "".join(cleaned)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def scan_payload(
    content:     str,
    source_type: SourceType,
    workflow_id: Optional[str] = None,
    step_index:  Optional[int] = None,
) -> ScanResult:
    """
    Main entry point. Called from context_plane.publish_event() before JetStream persist.

    Returns ScanResult with:
      - clean: bool (no flags found)
      - trust_level: derived from source + flags
      - flags: list of ScanFlag
      - sanitized: content with inert hidden markup stripped
    """
    try:
        policy = get_policy()
        flags: list[ScanFlag] = []

        flags += _check_invisible_unicode(content)
        flags += _check_injection_patterns(content)
        flags += _check_hidden_markup(content)
        flags += _check_base64_blobs(content)

        base_trust = _base_trust(source_type)
        trust_level = _derive_trust(base_trust, flags)
        sanitized = _sanitize(content)
        clean = len(flags) == 0

        if not clean:
            logger.warning(
                "scan_payload: %d flag(s) on workflow=%s step=%s trust=%s",
                len(flags), workflow_id, step_index, trust_level.value,
            )

        return ScanResult(
            clean=clean,
            trust_level=trust_level,
            flags=flags,
            sanitized=sanitized,
        )

    except Exception as exc:
        logger.error("scanner exception: %s", exc, exc_info=True)
        policy = get_policy()
        if policy.fail_open:
            return ScanResult(clean=True, trust_level=TrustLevel.LOW, flags=[])
        # Fail closed: treat scanner failure as untrusted
        return ScanResult(
            clean=False,
            trust_level=TrustLevel.UNTRUSTED,
            flags=[ScanFlag(category="scanner_error", detail=str(exc))],
        )
