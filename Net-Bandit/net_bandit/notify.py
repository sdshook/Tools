"""Notifications: risky observations and agent lifecycle events, sent to sinks.

Event IDs use the 7100-7199 range, which Windows' own Security auditing does not use
(it uses 1100-1108 and 4608-6424), so SIEM rules keyed on event ID alone won't misfire.

  7100  info     agent started
  7101  info     new compiled entry installed (pending or approved)
  7102  info     high-novelty observation (benign, but unlike anything seen before)
  7110  warning  suspicious observation
  7111  error    malicious observation
  7120  warning  entry revoked (runtime error or repeated disagreement)
  7121  warning  entry disagreed with Claude on a spot-check
  7122  error    entry failed its integrity (signature) check: possible tampering
  7123  warning  model produced an entry that failed validation (rejected)
  7130  warning  daily token budget reached (misses now go unanalysed)
  7131  warning  analysis call to Claude failed
  7132  error    isolated entry worker unavailable (cached checks not running)

Security log events are written as audit-success records. Severity is a field, not the
audit result, so "Audit Failure" keeps its usual meaning of a failed access attempt.
Insertion strings, in order (EventData Data[1..9]):
  1 message (summary + JSON details)   2 severity   3 verdict   4 event kind
  5 host   6 class key   7 entry id   8 novelty   9 confidence
"""
from __future__ import annotations

import json

INFO, WARNING, ERROR = "info", "warning", "error"

STARTED = 7100
ENTRY_NEW = 7101
NOVEL = 7102
SUSPICIOUS = 7110
MALICIOUS = 7111
ENTRY_REVOKED = 7120
ENTRY_DISAGREED = 7121
ENTRY_TAMPERED = 7122
ENTRY_REJECTED = 7123
BUDGET = 7130
ANALYSIS_FAILED = 7131
RUNNER_DOWN = 7132


def _message(record: dict) -> str:
    summary = record.get("summary", "")
    body = json.dumps({k: v for k, v in record.items() if k != "summary"}, default=str, indent=1)
    return f"{summary}\n\n{body}" if summary else body


def _fields(level: str, record: dict) -> list[str]:
    def v(k):
        x = record.get(k)
        return "-" if x is None or x == "" else str(x)
    return [_message(record), level, v("verdict"), v("kind"), v("host"), v("class_key"), v("entry_id"),
            v("novelty"), v("confidence")]


class MemorySink:
    """Collects notifications in a list (tests, debugging)."""

    def __init__(self):
        self.items: list[tuple[int, str, dict]] = []

    def __call__(self, event_id: int, level: str, record: dict) -> None:
        self.items.append((event_id, level, record))


class SecurityEventLogSink:
    """Writes to the Windows Security log as a registered third-party audit source (authz.dll)."""

    def __init__(self, source: str = "net-bandit", install: bool = True, log=print):
        from .win.seclog import SecurityLogWriter
        self.writer = SecurityLogWriter(source, install, log)

    def __call__(self, event_id: int, level: str, record: dict) -> None:
        if not self.writer.write(event_id, _fields(level, record)):
            import ctypes
            raise OSError(ctypes.get_last_error(), "AuthzReportSecurityEvent failed")

    def close(self) -> None:
        self.writer.close()


class ApplicationEventLogSink:
    """Writes to the Windows Application log (advapi32 ReportEventW). Optional alternative."""

    def __init__(self, source: str = "net-bandit", register: bool = True, log=print):
        from .win.winlog import EventLogWriter, register_source
        if register:
            ok, msg = register_source(source)
            log(f"[i] Application log source '{source}': {msg}")
        self.writer = EventLogWriter(source)

    def __call__(self, event_id: int, level: str, record: dict) -> None:
        self.writer.write(event_id, level, _message(record))

    def close(self) -> None:
        self.writer.close()


def build_sink(cfg: dict, log=print):
    """Build the configured sink. Returns (sink or None, description)."""
    target = cfg.get("target", "security")
    source = cfg.get("source", "net-bandit")
    if target == "none":
        return None, "event log output off"
    if target == "security":
        try:
            return SecurityEventLogSink(source, cfg.get("register_source", True), log), "Security log"
        except (OSError, RuntimeError) as e:
            if not cfg.get("fallback_to_application", False):
                return None, f"Security log unavailable: {e}"
            log(f"[!] Security log unavailable ({e}); falling back to the Application log")
    try:
        return ApplicationEventLogSink(source, cfg.get("register_source", True), log), "Application log"
    except (OSError, RuntimeError) as e:
        return None, f"Application log unavailable: {e}"
