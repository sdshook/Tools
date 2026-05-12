# (c) 2025 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture — Chain of Custody Logging

Provides forensic-grade audit logging for all ADVulture operations to satisfy
chain of custody requirements for security assessments and incident response.

Features:
- Cryptographic integrity via SHA-256 hash chaining
- JSON Lines format for forensic tool compatibility
- Automatic capture of actions, tool calls, data access, and downloads
- Session tracking with unique identifiers
- Tamper-evident log structure
- Support for both file and syslog output

Log Entry Categories:
- SESSION_START/END: Assessment session boundaries
- AUTH: Authentication events (LDAP bind, Entra token acquisition)
- COLLECTION: Data enumeration operations
- ANALYSIS: Posture analysis and finding generation
- DOWNLOAD: File and artifact retrieval
- EXPORT: Report generation and data export
- API_CALL: External API invocations
- CONFIG: Configuration changes
- ERROR: Error conditions with context
"""

from __future__ import annotations
import hashlib
import json
import logging
import os
import platform
import socket
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union
import getpass


class CustodyEventType(str, Enum):
    """Categories of auditable events."""
    SESSION_START = "SESSION_START"
    SESSION_END = "SESSION_END"
    AUTH = "AUTH"
    AUTH_FAILURE = "AUTH_FAILURE"
    COLLECTION = "COLLECTION"
    ANALYSIS = "ANALYSIS"
    DOWNLOAD = "DOWNLOAD"
    EXPORT = "EXPORT"
    API_CALL = "API_CALL"
    CONFIG = "CONFIG"
    ERROR = "ERROR"
    DATA_ACCESS = "DATA_ACCESS"
    FINDING = "FINDING"


class CustodyLogLevel(str, Enum):
    """Log severity levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class CustodyEntry:
    """
    A single chain of custody log entry with cryptographic linking.
    
    Each entry contains:
    - Unique entry ID
    - Session context
    - Timestamp in ISO 8601 format (UTC)
    - Event classification
    - Action details
    - Cryptographic hash of previous entry (for tamper detection)
    - Hash of current entry (for verification)
    """
    entry_id: str
    session_id: str
    timestamp: str
    event_type: CustodyEventType
    level: CustodyLogLevel
    action: str
    details: Dict[str, Any]
    
    # Execution context
    operator: str
    hostname: str
    platform: str
    working_dir: str
    
    # Integrity fields
    previous_hash: str
    entry_hash: str = ""
    
    # Optional metadata
    target: Optional[str] = None
    duration_ms: Optional[int] = None
    bytes_transferred: Optional[int] = None
    record_count: Optional[int] = None
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    
    def compute_hash(self) -> str:
        """Compute SHA-256 hash of entry contents (excluding entry_hash field)."""
        data = {
            "entry_id": self.entry_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value if isinstance(self.event_type, Enum) else self.event_type,
            "level": self.level.value if isinstance(self.level, Enum) else self.level,
            "action": self.action,
            "details": self.details,
            "operator": self.operator,
            "hostname": self.hostname,
            "platform": self.platform,
            "working_dir": self.working_dir,
            "previous_hash": self.previous_hash,
            "target": self.target,
            "duration_ms": self.duration_ms,
            "bytes_transferred": self.bytes_transferred,
            "record_count": self.record_count,
        }
        content = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        d = asdict(self)
        if isinstance(d.get("event_type"), Enum):
            d["event_type"] = d["event_type"].value
        if isinstance(d.get("level"), Enum):
            d["level"] = d["level"].value
        # Remove None values for cleaner output
        return {k: v for k, v in d.items() if v is not None}
    
    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class ChainOfCustodyLogger:
    """
    Singleton logger for chain of custody audit records.
    
    Maintains cryptographic hash chain for tamper detection.
    Supports multiple output destinations (file, syslog, callback).
    
    Usage:
        custody = ChainOfCustodyLogger.get_instance()
        custody.start_session(case_id="CASE-2025-001")
        
        custody.log_auth("ldap_bind", {"server": "dc01.corp.local", "user": "admin"})
        custody.log_collection("users", record_count=1523)
        custody.log_analysis("posture_assessment", {"regime": "CRITICAL"})
        
        custody.end_session()
    """
    
    _instance: Optional["ChainOfCustodyLogger"] = None
    _lock = threading.Lock()
    
    @classmethod
    def get_instance(cls) -> "ChainOfCustodyLogger":
        """Get or create singleton instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
    
    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton (for testing)."""
        with cls._lock:
            if cls._instance is not None:
                cls._instance.end_session()
            cls._instance = None
    
    def __init__(self):
        self.session_id: Optional[str] = None
        self.case_id: Optional[str] = None
        self.log_path: Optional[Path] = None
        self.entries: List[CustodyEntry] = []
        self.previous_hash: str = "GENESIS"
        self._file_handle = None
        self._callbacks: List[Callable[[CustodyEntry], None]] = []
        self._enabled = True
        
        # Execution context (captured once)
        self._operator = self._get_operator()
        self._hostname = socket.gethostname()
        self._platform = f"{platform.system()} {platform.release()}"
        
        # Standard logger for debug output
        self._log = logging.getLogger("advulture.custody")
    
    def _get_operator(self) -> str:
        """Get current operator identity."""
        try:
            return getpass.getuser()
        except Exception:
            return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
    
    def configure(
        self,
        log_dir: Optional[Path] = None,
        enabled: bool = True,
        callbacks: Optional[List[Callable[[CustodyEntry], None]]] = None,
    ) -> None:
        """
        Configure the custody logger.
        
        Args:
            log_dir: Directory for custody log files (default: ./custody_logs)
            enabled: Whether custody logging is active
            callbacks: Optional list of callbacks for each log entry
        """
        self._enabled = enabled
        if callbacks:
            self._callbacks = callbacks
        
        if log_dir:
            self.log_path = Path(log_dir)
            self.log_path.mkdir(parents=True, exist_ok=True)
    
    def start_session(
        self,
        case_id: Optional[str] = None,
        assessment_type: str = "security_posture",
        notes: Optional[str] = None,
    ) -> str:
        """
        Start a new custody session.
        
        Args:
            case_id: External case/ticket identifier
            assessment_type: Type of assessment being performed
            notes: Optional session notes
            
        Returns:
            Session ID (UUID)
        """
        if self.session_id is not None:
            self.end_session()
        
        self.session_id = str(uuid.uuid4())
        self.case_id = case_id
        self.entries = []
        self.previous_hash = "GENESIS"
        
        # Open log file
        if self.log_path is None:
            self.log_path = Path("custody_logs")
        self.log_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"custody_{self.session_id[:8]}_{timestamp}.jsonl"
        log_file = self.log_path / filename
        self._file_handle = open(log_file, "a", encoding="utf-8")
        
        # Log session start
        self._log_entry(
            event_type=CustodyEventType.SESSION_START,
            level=CustodyLogLevel.INFO,
            action="session_started",
            details={
                "case_id": case_id,
                "assessment_type": assessment_type,
                "notes": notes,
                "advulture_version": self._get_version(),
                "python_version": platform.python_version(),
                "log_file": str(log_file),
            },
        )
        
        self._log.info("Custody session started: %s (log: %s)", self.session_id[:8], log_file)
        return self.session_id
    
    def end_session(self, summary: Optional[Dict[str, Any]] = None) -> None:
        """
        End the current custody session.
        
        Args:
            summary: Optional session summary data
        """
        if self.session_id is None:
            return
        
        self._log_entry(
            event_type=CustodyEventType.SESSION_END,
            level=CustodyLogLevel.INFO,
            action="session_ended",
            details={
                "total_entries": len(self.entries),
                "final_hash": self.previous_hash,
                "summary": summary,
            },
        )
        
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None
        
        self._log.info("Custody session ended: %s (%d entries)", self.session_id[:8], len(self.entries))
        self.session_id = None
    
    def _log_entry(
        self,
        event_type: CustodyEventType,
        level: CustodyLogLevel,
        action: str,
        details: Dict[str, Any],
        target: Optional[str] = None,
        duration_ms: Optional[int] = None,
        bytes_transferred: Optional[int] = None,
        record_count: Optional[int] = None,
        error_message: Optional[str] = None,
        stack_trace: Optional[str] = None,
    ) -> Optional[CustodyEntry]:
        """Internal method to create and persist a log entry."""
        if not self._enabled:
            return None
        
        # Auto-start session if needed
        if self.session_id is None:
            self.start_session()
        
        entry = CustodyEntry(
            entry_id=str(uuid.uuid4()),
            session_id=self.session_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            level=level,
            action=action,
            details=details,
            operator=self._operator,
            hostname=self._hostname,
            platform=self._platform,
            working_dir=os.getcwd(),
            previous_hash=self.previous_hash,
            target=target,
            duration_ms=duration_ms,
            bytes_transferred=bytes_transferred,
            record_count=record_count,
            error_message=error_message,
            stack_trace=stack_trace,
        )
        
        # Compute and set entry hash
        entry.entry_hash = entry.compute_hash()
        self.previous_hash = entry.entry_hash
        
        # Store entry
        self.entries.append(entry)
        
        # Write to file
        if self._file_handle:
            self._file_handle.write(entry.to_json() + "\n")
            self._file_handle.flush()
        
        # Invoke callbacks
        for callback in self._callbacks:
            try:
                callback(entry)
            except Exception as e:
                self._log.warning("Custody callback error: %s", e)
        
        return entry
    
    def _get_version(self) -> str:
        """Get ADVulture version."""
        try:
            from advulture import __version__
            return __version__
        except (ImportError, AttributeError):
            return "unknown"
    
    # ─── Public Logging Methods ─────────────────────────────────────────────
    
    def log_auth(
        self,
        method: str,
        details: Dict[str, Any],
        success: bool = True,
        target: Optional[str] = None,
    ) -> Optional[CustodyEntry]:
        """
        Log an authentication event.
        
        Args:
            method: Authentication method (ldap_bind, device_code, kerberos, etc.)
            details: Authentication details (server, user, tenant, etc.)
            success: Whether authentication succeeded
            target: Target system/service
        """
        # Sanitize sensitive fields
        safe_details = {k: v for k, v in details.items() 
                       if k.lower() not in ("password", "secret", "token", "credential")}
        
        return self._log_entry(
            event_type=CustodyEventType.AUTH if success else CustodyEventType.AUTH_FAILURE,
            level=CustodyLogLevel.INFO if success else CustodyLogLevel.WARNING,
            action=f"auth_{method}",
            details={"method": method, "success": success, **safe_details},
            target=target,
        )
    
    def log_collection(
        self,
        source: str,
        details: Optional[Dict[str, Any]] = None,
        record_count: Optional[int] = None,
        duration_ms: Optional[int] = None,
        bytes_transferred: Optional[int] = None,
    ) -> Optional[CustodyEntry]:
        """
        Log a data collection operation.
        
        Args:
            source: Data source (users, groups, service_principals, evtx, etc.)
            details: Collection parameters and filters
            record_count: Number of records collected
            duration_ms: Operation duration in milliseconds
            bytes_transferred: Amount of data transferred
        """
        return self._log_entry(
            event_type=CustodyEventType.COLLECTION,
            level=CustodyLogLevel.INFO,
            action=f"collect_{source}",
            details=details or {},
            target=source,
            record_count=record_count,
            duration_ms=duration_ms,
            bytes_transferred=bytes_transferred,
        )
    
    def log_analysis(
        self,
        analysis_type: str,
        details: Dict[str, Any],
        duration_ms: Optional[int] = None,
    ) -> Optional[CustodyEntry]:
        """
        Log an analysis operation.
        
        Args:
            analysis_type: Type of analysis (posture, hmm_phase, markov, gradient)
            details: Analysis parameters and results summary
            duration_ms: Operation duration
        """
        return self._log_entry(
            event_type=CustodyEventType.ANALYSIS,
            level=CustodyLogLevel.INFO,
            action=f"analyze_{analysis_type}",
            details=details,
            duration_ms=duration_ms,
        )
    
    def log_finding(
        self,
        finding_id: str,
        title: str,
        severity: str,
        risk_class: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Optional[CustodyEntry]:
        """
        Log a security finding.
        
        Args:
            finding_id: Unique finding identifier
            title: Finding title
            severity: Finding severity level
            risk_class: Risk classification
            details: Additional finding details
        """
        return self._log_entry(
            event_type=CustodyEventType.FINDING,
            level=CustodyLogLevel.INFO,
            action="finding_generated",
            details={
                "finding_id": finding_id,
                "title": title,
                "severity": severity,
                "risk_class": risk_class,
                **(details or {}),
            },
        )
    
    def log_download(
        self,
        resource: str,
        destination: Optional[str] = None,
        file_hash: Optional[str] = None,
        bytes_transferred: Optional[int] = None,
    ) -> Optional[CustodyEntry]:
        """
        Log a file or artifact download.
        
        Args:
            resource: Resource identifier (URL, path, API endpoint)
            destination: Local destination path
            file_hash: SHA-256 hash of downloaded content
            bytes_transferred: File size in bytes
        """
        return self._log_entry(
            event_type=CustodyEventType.DOWNLOAD,
            level=CustodyLogLevel.INFO,
            action="download",
            details={
                "resource": resource,
                "destination": destination,
                "file_hash": file_hash,
            },
            target=resource,
            bytes_transferred=bytes_transferred,
        )
    
    def log_export(
        self,
        export_type: str,
        destination: str,
        format: str,
        record_count: Optional[int] = None,
        file_hash: Optional[str] = None,
    ) -> Optional[CustodyEntry]:
        """
        Log a report or data export.
        
        Args:
            export_type: Type of export (report, findings, raw_data)
            destination: Output file path
            format: Output format (html, json, csv)
            record_count: Number of records exported
            file_hash: SHA-256 hash of exported file
        """
        return self._log_entry(
            event_type=CustodyEventType.EXPORT,
            level=CustodyLogLevel.INFO,
            action=f"export_{export_type}",
            details={
                "format": format,
                "destination": destination,
                "file_hash": file_hash,
            },
            target=destination,
            record_count=record_count,
        )
    
    def log_api_call(
        self,
        service: str,
        endpoint: str,
        method: str = "GET",
        status_code: Optional[int] = None,
        duration_ms: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Optional[CustodyEntry]:
        """
        Log an external API call.
        
        Args:
            service: Service name (graph_api, ldap, splunk)
            endpoint: API endpoint
            method: HTTP method
            status_code: Response status code
            duration_ms: Request duration
            details: Request/response details
        """
        return self._log_entry(
            event_type=CustodyEventType.API_CALL,
            level=CustodyLogLevel.INFO,
            action=f"api_{service}",
            details={
                "endpoint": endpoint,
                "method": method,
                "status_code": status_code,
                **(details or {}),
            },
            target=f"{service}:{endpoint}",
            duration_ms=duration_ms,
        )
    
    def log_data_access(
        self,
        data_type: str,
        operation: str,
        record_count: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Optional[CustodyEntry]:
        """
        Log data access operation.
        
        Args:
            data_type: Type of data accessed (users, credentials, logs)
            operation: Operation type (read, query, enumerate)
            record_count: Number of records accessed
            details: Access parameters
        """
        return self._log_entry(
            event_type=CustodyEventType.DATA_ACCESS,
            level=CustodyLogLevel.INFO,
            action=f"access_{data_type}",
            details={"operation": operation, **(details or {})},
            target=data_type,
            record_count=record_count,
        )
    
    def log_config(
        self,
        action: str,
        details: Dict[str, Any],
    ) -> Optional[CustodyEntry]:
        """
        Log a configuration change.
        
        Args:
            action: Configuration action (load, modify, validate)
            details: Configuration details (sanitized)
        """
        # Sanitize sensitive config values
        safe_details = {}
        for k, v in details.items():
            if any(s in k.lower() for s in ("password", "secret", "token", "key", "credential")):
                safe_details[k] = "[REDACTED]"
            else:
                safe_details[k] = v
        
        return self._log_entry(
            event_type=CustodyEventType.CONFIG,
            level=CustodyLogLevel.INFO,
            action=f"config_{action}",
            details=safe_details,
        )
    
    def log_error(
        self,
        action: str,
        error_message: str,
        details: Optional[Dict[str, Any]] = None,
        stack_trace: Optional[str] = None,
    ) -> Optional[CustodyEntry]:
        """
        Log an error condition.
        
        Args:
            action: Action that failed
            error_message: Error description
            details: Error context
            stack_trace: Optional stack trace
        """
        return self._log_entry(
            event_type=CustodyEventType.ERROR,
            level=CustodyLogLevel.ERROR,
            action=action,
            details=details or {},
            error_message=error_message,
            stack_trace=stack_trace,
        )
    
    # ─── Verification Methods ───────────────────────────────────────────────
    
    def verify_chain(self) -> tuple[bool, List[str]]:
        """
        Verify the integrity of the log chain.
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        if not self.entries:
            return True, []
        
        # Check first entry links to GENESIS
        if self.entries[0].previous_hash != "GENESIS":
            errors.append(f"Entry 0: Expected GENESIS, got {self.entries[0].previous_hash}")
        
        # Verify hash chain
        for i, entry in enumerate(self.entries):
            computed = entry.compute_hash()
            if computed != entry.entry_hash:
                errors.append(f"Entry {i}: Hash mismatch (computed={computed[:16]}..., stored={entry.entry_hash[:16]}...)")
            
            if i > 0 and entry.previous_hash != self.entries[i-1].entry_hash:
                errors.append(f"Entry {i}: Previous hash doesn't match entry {i-1}")
        
        return len(errors) == 0, errors
    
    @classmethod
    def verify_log_file(cls, path: Path) -> tuple[bool, List[str]]:
        """
        Verify integrity of a custody log file.
        
        Args:
            path: Path to .jsonl custody log file
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        previous_hash = "GENESIS"
        
        with open(path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                try:
                    data = json.loads(line.strip())
                    entry = CustodyEntry(
                        entry_id=data["entry_id"],
                        session_id=data["session_id"],
                        timestamp=data["timestamp"],
                        event_type=CustodyEventType(data["event_type"]),
                        level=CustodyLogLevel(data["level"]),
                        action=data["action"],
                        details=data["details"],
                        operator=data["operator"],
                        hostname=data["hostname"],
                        platform=data["platform"],
                        working_dir=data["working_dir"],
                        previous_hash=data["previous_hash"],
                        entry_hash=data.get("entry_hash", ""),
                        target=data.get("target"),
                        duration_ms=data.get("duration_ms"),
                        bytes_transferred=data.get("bytes_transferred"),
                        record_count=data.get("record_count"),
                        error_message=data.get("error_message"),
                        stack_trace=data.get("stack_trace"),
                    )
                    
                    # Verify previous hash chain
                    if entry.previous_hash != previous_hash:
                        errors.append(f"Line {i+1}: Chain break (expected={previous_hash[:16]}..., got={entry.previous_hash[:16]}...)")
                    
                    # Verify entry hash
                    computed = entry.compute_hash()
                    if computed != entry.entry_hash:
                        errors.append(f"Line {i+1}: Hash mismatch")
                    
                    previous_hash = entry.entry_hash
                    
                except json.JSONDecodeError as e:
                    errors.append(f"Line {i+1}: Invalid JSON - {e}")
                except Exception as e:
                    errors.append(f"Line {i+1}: Parse error - {e}")
        
        return len(errors) == 0, errors


# ─── Decorator for Automatic Custody Logging ────────────────────────────────

F = TypeVar("F", bound=Callable[..., Any])


def custody_logged(
    event_type: CustodyEventType = CustodyEventType.DATA_ACCESS,
    action: Optional[str] = None,
) -> Callable[[F], F]:
    """
    Decorator to automatically log function calls to chain of custody.
    
    Usage:
        @custody_logged(CustodyEventType.COLLECTION, "enumerate_users")
        def get_users(self, domain: str):
            ...
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            custody = ChainOfCustodyLogger.get_instance()
            func_action = action or func.__name__
            start_time = datetime.now(timezone.utc)
            
            try:
                result = func(*args, **kwargs)
                duration = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
                
                # Try to extract record count from result
                record_count = None
                if hasattr(result, "__len__"):
                    record_count = len(result)
                elif isinstance(result, (list, tuple)):
                    record_count = len(result)
                
                custody._log_entry(
                    event_type=event_type,
                    level=CustodyLogLevel.INFO,
                    action=func_action,
                    details={"args_count": len(args), "kwargs_keys": list(kwargs.keys())},
                    duration_ms=duration,
                    record_count=record_count,
                )
                
                return result
                
            except Exception as e:
                duration = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
                custody.log_error(
                    action=func_action,
                    error_message=str(e),
                    details={"args_count": len(args), "kwargs_keys": list(kwargs.keys())},
                )
                raise
        
        return wrapper  # type: ignore
    return decorator


@contextmanager
def custody_session(
    case_id: Optional[str] = None,
    assessment_type: str = "security_posture",
    log_dir: Optional[Path] = None,
):
    """
    Context manager for custody-logged sessions.
    
    Usage:
        with custody_session(case_id="CASE-2025-001") as custody:
            custody.log_collection("users", record_count=1000)
            # ... perform assessment ...
    """
    custody = ChainOfCustodyLogger.get_instance()
    if log_dir:
        custody.configure(log_dir=log_dir)
    custody.start_session(case_id=case_id, assessment_type=assessment_type)
    
    try:
        yield custody
    finally:
        custody.end_session()


# ─── Utility Functions ──────────────────────────────────────────────────────

def compute_file_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_custody_logger() -> ChainOfCustodyLogger:
    """Convenience function to get the custody logger instance."""
    return ChainOfCustodyLogger.get_instance()
