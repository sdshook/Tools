# (c) 2025 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture — Evidence Preservation

Provides forensic-grade evidence preservation for collected data, ensuring
a tamper-evident "system of record" copy exists independent of analyzed data.

Features:
- Automatic compression (gzip) of raw collected data
- SHA-256 hashing for integrity verification
- Timestamped evidence archives with case ID tracking
- Manifest file documenting archive contents
- Integration with chain of custody logging
- Support for multiple data source types

Evidence Archive Structure:
    evidence/
    └── CASE-2025-001_20250513_184500/
        ├── manifest.json           # Archive metadata and hashes
        ├── ad_snapshot.json.gz     # Compressed AD enumeration data
        ├── entra_snapshot.json.gz  # Compressed Entra ID data
        ├── entra_events.json.gz    # Compressed Entra sign-in/audit logs
        ├── event_stream.json.gz    # Compressed Windows event log data
        └── source_hashes.json      # Original file hashes (EVTX, etc.)
"""

from __future__ import annotations
import gzip
import hashlib
import json
import logging
import os
import shutil
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable

log = logging.getLogger(__name__)


@dataclass
class EvidenceManifest:
    """Metadata manifest for an evidence archive."""
    archive_id: str
    case_id: Optional[str]
    created_at: str
    created_by: str
    hostname: str
    advulture_version: str
    
    # Collection metadata
    collection_started: str
    collection_completed: str
    collection_duration_ms: int
    
    # Content summary
    ad_snapshot_hash: Optional[str] = None
    ad_snapshot_records: int = 0
    entra_snapshot_hash: Optional[str] = None
    entra_snapshot_records: int = 0
    entra_events_hash: Optional[str] = None
    entra_events_records: int = 0
    event_stream_hash: Optional[str] = None
    event_stream_records: int = 0
    
    # Source file hashes (original EVTX, etc.)
    source_file_hashes: Dict[str, str] = field(default_factory=dict)
    
    # Archive integrity
    manifest_hash: str = ""
    
    def compute_manifest_hash(self) -> str:
        """Compute SHA-256 hash of manifest contents (excluding manifest_hash)."""
        data = asdict(self)
        data.pop("manifest_hash", None)
        content = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceManifest":
        return cls(**data)
    
    @classmethod
    def from_file(cls, path: Path) -> "EvidenceManifest":
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))


@dataclass
class PreservationResult:
    """Result of evidence preservation operation."""
    success: bool
    archive_path: Path
    manifest: EvidenceManifest
    errors: List[str] = field(default_factory=list)
    
    @property
    def archive_id(self) -> str:
        return self.manifest.archive_id


class EvidencePreserver:
    """
    Preserves collected data as a forensic "system of record" before analysis.
    
    Creates compressed, hashed archives of raw collected data that can be
    independently verified for chain of custody purposes.
    
    Usage:
        preserver = EvidencePreserver(evidence_dir=Path("evidence"))
        
        # Start preservation (call before collection begins)
        preserver.start_collection(case_id="CASE-2025-001")
        
        # After each collection phase, preserve the data
        preserver.preserve_ad_snapshot(ad_snapshot)
        preserver.preserve_entra_snapshot(entra_snapshot)
        preserver.preserve_event_stream(event_stream)
        
        # Finalize and get result
        result = preserver.finalize()
        print(f"Evidence archived: {result.archive_path}")
        print(f"Manifest hash: {result.manifest.manifest_hash}")
    """
    
    def __init__(
        self,
        evidence_dir: Path = Path("evidence"),
        compression_level: int = 6,
    ):
        """
        Initialize evidence preserver.
        
        Args:
            evidence_dir: Base directory for evidence archives
            compression_level: gzip compression level (1-9, default 6)
        """
        self.evidence_dir = Path(evidence_dir)
        self.compression_level = compression_level
        
        self._archive_path: Optional[Path] = None
        self._manifest: Optional[EvidenceManifest] = None
        self._collection_start: Optional[datetime] = None
        self._errors: List[str] = []
        
    def start_collection(
        self,
        case_id: Optional[str] = None,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Path:
        """
        Initialize a new evidence archive for the upcoming collection.
        
        Args:
            case_id: External case/ticket identifier
            progress_callback: Optional callback for progress updates
            
        Returns:
            Path to the archive directory
        """
        import getpass
        import platform
        import socket
        import uuid
        
        self._collection_start = datetime.now(timezone.utc)
        self._errors = []
        
        # Generate archive ID and path
        archive_id = str(uuid.uuid4())[:8]
        timestamp = self._collection_start.strftime("%Y%m%d_%H%M%S")
        case_prefix = f"{case_id}_" if case_id else ""
        archive_name = f"{case_prefix}{timestamp}_{archive_id}"
        
        self._archive_path = self.evidence_dir / archive_name
        self._archive_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize manifest
        self._manifest = EvidenceManifest(
            archive_id=archive_id,
            case_id=case_id,
            created_at=self._collection_start.isoformat(),
            created_by=self._get_operator(),
            hostname=socket.gethostname(),
            advulture_version=self._get_version(),
            collection_started=self._collection_start.isoformat(),
            collection_completed="",
            collection_duration_ms=0,
        )
        
        if progress_callback:
            progress_callback(f"Evidence archive initialized: {archive_name}")
        
        log.info("Evidence archive initialized: %s", self._archive_path)
        return self._archive_path
    
    def preserve_ad_snapshot(
        self,
        snapshot: Any,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Optional[str]:
        """
        Preserve AD snapshot data.
        
        Args:
            snapshot: ADSnapshot object from ldap_enumerator
            progress_callback: Optional callback for progress updates
            
        Returns:
            SHA-256 hash of compressed data, or None on failure
        """
        if self._archive_path is None:
            self._errors.append("Archive not initialized - call start_collection first")
            return None
        
        if snapshot is None:
            log.debug("No AD snapshot to preserve")
            return None
        
        try:
            # Serialize snapshot to dict
            data = self._snapshot_to_dict(snapshot)
            record_count = (
                len(snapshot.users) + 
                len(snapshot.computers) + 
                len(snapshot.groups) +
                len(snapshot.trusts) +
                len(snapshot.cert_templates)
            )
            
            # Compress and hash
            file_path = self._archive_path / "ad_snapshot.json.gz"
            file_hash = self._compress_and_hash(data, file_path)
            
            # Update manifest
            self._manifest.ad_snapshot_hash = file_hash
            self._manifest.ad_snapshot_records = record_count
            
            if progress_callback:
                progress_callback(f"AD snapshot preserved: {record_count} records")
            
            log.info("AD snapshot preserved: %d records, hash=%s", record_count, file_hash[:16])
            return file_hash
            
        except Exception as e:
            error_msg = f"Failed to preserve AD snapshot: {e}"
            self._errors.append(error_msg)
            log.error(error_msg)
            return None
    
    def preserve_entra_snapshot(
        self,
        snapshot: Any,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Optional[str]:
        """
        Preserve Entra ID snapshot data.
        
        Args:
            snapshot: EntraSnapshot object from entra_ingester
            progress_callback: Optional callback for progress updates
            
        Returns:
            SHA-256 hash of compressed data, or None on failure
        """
        if self._archive_path is None:
            self._errors.append("Archive not initialized - call start_collection first")
            return None
        
        if snapshot is None:
            log.debug("No Entra snapshot to preserve")
            return None
        
        try:
            # Serialize snapshot to dict
            data = self._entra_snapshot_to_dict(snapshot)
            record_count = (
                len(snapshot.users) + 
                len(snapshot.service_principals) +
                len(snapshot.critical_role_assignments) +
                len(snapshot.ca_policies) +
                len(snapshot.pim_assignments)
            )
            
            # Compress and hash
            file_path = self._archive_path / "entra_snapshot.json.gz"
            file_hash = self._compress_and_hash(data, file_path)
            
            # Update manifest
            self._manifest.entra_snapshot_hash = file_hash
            self._manifest.entra_snapshot_records = record_count
            
            if progress_callback:
                progress_callback(f"Entra snapshot preserved: {record_count} records")
            
            log.info("Entra snapshot preserved: %d records, hash=%s", record_count, file_hash[:16])
            return file_hash
            
        except Exception as e:
            error_msg = f"Failed to preserve Entra snapshot: {e}"
            self._errors.append(error_msg)
            log.error(error_msg)
            return None
    
    def preserve_entra_events(
        self,
        events: Any,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Optional[str]:
        """
        Preserve Entra ID event stream (sign-ins, audits, risk detections).
        
        Args:
            events: EntraEventStream object from entra_ingester
            progress_callback: Optional callback for progress updates
            
        Returns:
            SHA-256 hash of compressed data, or None on failure
        """
        if self._archive_path is None:
            self._errors.append("Archive not initialized - call start_collection first")
            return None
        
        if events is None:
            log.debug("No Entra events to preserve")
            return None
        
        try:
            # Serialize events to dict
            data = self._entra_events_to_dict(events)
            record_count = (
                len(events.signins) + 
                len(events.audits) +
                len(events.risk_detections)
            )
            
            # Compress and hash
            file_path = self._archive_path / "entra_events.json.gz"
            file_hash = self._compress_and_hash(data, file_path)
            
            # Update manifest
            self._manifest.entra_events_hash = file_hash
            self._manifest.entra_events_records = record_count
            
            if progress_callback:
                progress_callback(f"Entra events preserved: {record_count} records")
            
            log.info("Entra events preserved: %d records, hash=%s", record_count, file_hash[:16])
            return file_hash
            
        except Exception as e:
            error_msg = f"Failed to preserve Entra events: {e}"
            self._errors.append(error_msg)
            log.error(error_msg)
            return None
    
    def preserve_event_stream(
        self,
        event_stream: Any,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Optional[str]:
        """
        Preserve Windows event stream (from EVTX files).
        
        Args:
            event_stream: EventStream object from log_ingester
            progress_callback: Optional callback for progress updates
            
        Returns:
            SHA-256 hash of compressed data, or None on failure
        """
        if self._archive_path is None:
            self._errors.append("Archive not initialized - call start_collection first")
            return None
        
        if event_stream is None:
            log.debug("No event stream to preserve")
            return None
        
        try:
            # Serialize event stream to dict
            data = self._event_stream_to_dict(event_stream)
            record_count = len(event_stream.events) if hasattr(event_stream, 'events') else 0
            
            # Compress and hash
            file_path = self._archive_path / "event_stream.json.gz"
            file_hash = self._compress_and_hash(data, file_path)
            
            # Update manifest
            self._manifest.event_stream_hash = file_hash
            self._manifest.event_stream_records = record_count
            
            if progress_callback:
                progress_callback(f"Event stream preserved: {record_count} records")
            
            log.info("Event stream preserved: %d records, hash=%s", record_count, file_hash[:16])
            return file_hash
            
        except Exception as e:
            error_msg = f"Failed to preserve event stream: {e}"
            self._errors.append(error_msg)
            log.error(error_msg)
            return None
    
    def record_source_file_hash(
        self,
        file_path: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Optional[str]:
        """
        Record the hash of a source file (e.g., EVTX file).
        
        Args:
            file_path: Path to the source file
            progress_callback: Optional callback for progress updates
            
        Returns:
            SHA-256 hash of the file, or None on failure
        """
        if self._manifest is None:
            return None
        
        try:
            file_hash = self._compute_file_hash(file_path)
            self._manifest.source_file_hashes[str(file_path)] = file_hash
            
            if progress_callback:
                progress_callback(f"Source file hashed: {file_path.name}")
            
            log.debug("Source file hashed: %s -> %s", file_path.name, file_hash[:16])
            return file_hash
            
        except Exception as e:
            error_msg = f"Failed to hash source file {file_path}: {e}"
            self._errors.append(error_msg)
            log.warning(error_msg)
            return None
    
    def finalize(
        self,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> PreservationResult:
        """
        Finalize the evidence archive and write the manifest.
        
        Args:
            progress_callback: Optional callback for progress updates
            
        Returns:
            PreservationResult with archive details
        """
        if self._archive_path is None or self._manifest is None:
            return PreservationResult(
                success=False,
                archive_path=Path("."),
                manifest=EvidenceManifest(
                    archive_id="", case_id=None, created_at="", created_by="",
                    hostname="", advulture_version="", collection_started="",
                    collection_completed="", collection_duration_ms=0,
                ),
                errors=["Archive not initialized"],
            )
        
        # Calculate duration
        collection_end = datetime.now(timezone.utc)
        duration_ms = int((collection_end - self._collection_start).total_seconds() * 1000)
        
        self._manifest.collection_completed = collection_end.isoformat()
        self._manifest.collection_duration_ms = duration_ms
        
        # Compute manifest hash
        self._manifest.manifest_hash = self._manifest.compute_manifest_hash()
        
        # Write manifest
        manifest_path = self._archive_path / "manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write(self._manifest.to_json())
        
        # Write source hashes separately for easy reference
        if self._manifest.source_file_hashes:
            hashes_path = self._archive_path / "source_hashes.json"
            with open(hashes_path, "w", encoding="utf-8") as f:
                json.dump(self._manifest.source_file_hashes, f, indent=2)
        
        if progress_callback:
            progress_callback(f"Evidence archive finalized: {self._manifest.manifest_hash[:16]}...")
        
        log.info(
            "Evidence archive finalized: %s (hash=%s, duration=%dms)",
            self._archive_path.name,
            self._manifest.manifest_hash[:16],
            duration_ms,
        )
        
        return PreservationResult(
            success=len(self._errors) == 0,
            archive_path=self._archive_path,
            manifest=self._manifest,
            errors=self._errors.copy(),
        )
    
    # ─── Serialization Methods ───────────────────────────────────────────────
    
    def _snapshot_to_dict(self, snapshot: Any) -> Dict[str, Any]:
        """Serialize ADSnapshot to dictionary."""
        from dataclasses import asdict, is_dataclass
        
        def serialize_obj(obj):
            if is_dataclass(obj):
                d = asdict(obj)
                # Remove binary data (security descriptors) - too large and not JSON-friendly
                for key in list(d.keys()):
                    if isinstance(d[key], bytes):
                        d[key] = f"<binary:{len(d[key])}bytes>"
                return d
            elif isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, bytes):
                return f"<binary:{len(obj)}bytes>"
            return obj
        
        return {
            "domain": snapshot.domain,
            "domain_sid": snapshot.domain_sid,
            "base_dn": snapshot.base_dn,
            "timestamp": snapshot.timestamp.isoformat() if snapshot.timestamp else None,
            "users": [serialize_obj(u) for u in snapshot.users],
            "computers": [serialize_obj(c) for c in snapshot.computers],
            "groups": [serialize_obj(g) for g in snapshot.groups],
            "trusts": [serialize_obj(t) for t in snapshot.trusts],
            "cert_templates": [serialize_obj(ct) for ct in snapshot.cert_templates],
            "acl_edges": [serialize_obj(e) for e in snapshot.acl_edges],
            "gpo_links": snapshot.gpo_links,
            "ou_structure": snapshot.ou_structure,
        }
    
    def _entra_snapshot_to_dict(self, snapshot: Any) -> Dict[str, Any]:
        """Serialize EntraSnapshot to dictionary."""
        from dataclasses import asdict, is_dataclass
        
        def serialize_obj(obj):
            if is_dataclass(obj):
                return asdict(obj)
            elif isinstance(obj, datetime):
                return obj.isoformat()
            return obj
        
        return {
            "timestamp": snapshot.timestamp.isoformat() if snapshot.timestamp else None,
            "tenant_id": snapshot.tenant_id,
            "users": [serialize_obj(u) for u in snapshot.users],
            "service_principals": [serialize_obj(sp) for sp in snapshot.service_principals],
            "critical_role_assignments": snapshot.critical_role_assignments,
            "ca_policies": snapshot.ca_policies,
            "pim_assignments": snapshot.pim_assignments,
            "sync_enabled": snapshot.sync_enabled,
            "on_prem_sync_timestamp": snapshot.on_prem_sync_timestamp.isoformat() 
                if snapshot.on_prem_sync_timestamp else None,
            "federation_enabled": snapshot.federation_enabled,
        }
    
    def _entra_events_to_dict(self, events: Any) -> Dict[str, Any]:
        """Serialize EntraEventStream to dictionary."""
        from dataclasses import asdict, is_dataclass
        
        def serialize_obj(obj):
            if is_dataclass(obj):
                d = asdict(obj)
                # Handle nested datetime objects
                for key, val in d.items():
                    if isinstance(val, datetime):
                        d[key] = val.isoformat()
                return d
            elif isinstance(obj, datetime):
                return obj.isoformat()
            return obj
        
        return {
            "signins": [serialize_obj(s) for s in events.signins],
            "audits": [serialize_obj(a) for a in events.audits],
            "risk_detections": events.risk_detections,  # Already dict
        }
    
    def _event_stream_to_dict(self, event_stream: Any) -> Dict[str, Any]:
        """Serialize EventStream to dictionary."""
        from dataclasses import asdict, is_dataclass
        
        def serialize_event(evt):
            if is_dataclass(evt):
                d = asdict(evt)
                for key, val in d.items():
                    if isinstance(val, datetime):
                        d[key] = val.isoformat()
                return d
            elif hasattr(evt, '__dict__'):
                return {k: v.isoformat() if isinstance(v, datetime) else v 
                        for k, v in evt.__dict__.items()}
            return str(evt)
        
        events = event_stream.events if hasattr(event_stream, 'events') else []
        return {
            "events": [serialize_event(e) for e in events],
            "event_count": len(events),
        }
    
    # ─── Utility Methods ─────────────────────────────────────────────────────
    
    def _compress_and_hash(self, data: Dict[str, Any], output_path: Path) -> str:
        """Compress data to gzip and compute SHA-256 hash."""
        json_bytes = json.dumps(data, default=str, ensure_ascii=False).encode("utf-8")
        
        # Compute hash of uncompressed data (for verification)
        data_hash = hashlib.sha256(json_bytes).hexdigest()
        
        # Write compressed file
        with gzip.open(output_path, "wb", compresslevel=self.compression_level) as f:
            f.write(json_bytes)
        
        return data_hash
    
    def _compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _get_operator(self) -> str:
        """Get current operator identity."""
        import getpass
        try:
            return getpass.getuser()
        except Exception:
            return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
    
    def _get_version(self) -> str:
        """Get ADVulture version."""
        try:
            from advulture import __version__
            return __version__
        except (ImportError, AttributeError):
            return "unknown"
    
    # ─── Verification Methods ────────────────────────────────────────────────
    
    @classmethod
    def verify_archive(cls, archive_path: Path) -> tuple[bool, List[str]]:
        """
        Verify integrity of an evidence archive.
        
        Args:
            archive_path: Path to the evidence archive directory
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        manifest_path = archive_path / "manifest.json"
        if not manifest_path.exists():
            return False, ["Manifest file not found"]
        
        try:
            manifest = EvidenceManifest.from_file(manifest_path)
        except Exception as e:
            return False, [f"Failed to parse manifest: {e}"]
        
        # Verify manifest hash
        computed_hash = manifest.compute_manifest_hash()
        if computed_hash != manifest.manifest_hash:
            errors.append(
                f"Manifest hash mismatch (computed={computed_hash[:16]}..., "
                f"stored={manifest.manifest_hash[:16]}...)"
            )
        
        # Verify each data file
        file_checks = [
            ("ad_snapshot.json.gz", manifest.ad_snapshot_hash),
            ("entra_snapshot.json.gz", manifest.entra_snapshot_hash),
            ("entra_events.json.gz", manifest.entra_events_hash),
            ("event_stream.json.gz", manifest.event_stream_hash),
        ]
        
        for filename, expected_hash in file_checks:
            if expected_hash is None:
                continue
            
            file_path = archive_path / filename
            if not file_path.exists():
                errors.append(f"Missing file: {filename}")
                continue
            
            # Read and decompress to verify hash
            try:
                with gzip.open(file_path, "rb") as f:
                    data = f.read()
                computed = hashlib.sha256(data).hexdigest()
                if computed != expected_hash:
                    errors.append(
                        f"Hash mismatch for {filename} "
                        f"(computed={computed[:16]}..., expected={expected_hash[:16]}...)"
                    )
            except Exception as e:
                errors.append(f"Failed to verify {filename}: {e}")
        
        return len(errors) == 0, errors


# ─── Convenience Functions ───────────────────────────────────────────────────

def create_evidence_preserver(
    evidence_dir: Optional[Path] = None,
    case_id: Optional[str] = None,
) -> EvidencePreserver:
    """
    Create and initialize an evidence preserver.
    
    Args:
        evidence_dir: Directory for evidence archives (default: ./evidence)
        case_id: Optional case/ticket identifier
        
    Returns:
        Initialized EvidencePreserver with collection started
    """
    preserver = EvidencePreserver(
        evidence_dir=evidence_dir or Path("evidence"),
    )
    preserver.start_collection(case_id=case_id)
    return preserver
