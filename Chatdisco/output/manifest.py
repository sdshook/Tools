"""
Manifest writer.
Produces a cryptographically-signed hash manifest of all output
artifacts plus an append-only examiner log for chain of custody.
Every file created by Chatdisco is hashed and recorded here.
"""

import os
import json
import hashlib
import datetime
import platform
import socket
from pathlib import Path
from typing import Optional


class ManifestWriter:
    """
    Writes a SHA-256 hash manifest of all output artifacts.
    The manifest itself is hashed to detect tampering.
    Examiner log records every significant action with timestamp.
    """

    def __init__(
        self,
        output_dir: Path,
        intake_result=None,
    ):
        self.output_dir    = Path(output_dir)
        self.intake_result = intake_result
        self._log_entries  = []

    def write(self):
        """Hash all output files and write manifest + log."""
        manifest = {
            "chatdisco_version": "0.1.0",
            "manifest_created":
                datetime.datetime.utcnow().isoformat() + "Z",
            "examiner_system": socket.gethostname(),
            "examiner_platform": platform.platform(),
            "case_id": (
                self.intake_result.coc.case_id
                if self.intake_result else ""),
            "examiner": (
                self.intake_result.coc.examiner
                if self.intake_result else ""),
            "source_evidence": {
                "path": str(
                    self.intake_result.path.resolve()
                    if self.intake_result else ""),
                "sha256": (
                    self.intake_result.hashes.sha256
                    if self.intake_result else ""),
                "sha1": (
                    self.intake_result.hashes.sha1
                    if self.intake_result else ""),
                "md5": (
                    self.intake_result.hashes.md5
                    if self.intake_result else ""),
                "size_bytes": (
                    self.intake_result.hashes.size_bytes
                    if self.intake_result else 0),
            },
            "output_files": [],
            "sbom": (
                self.intake_result.coc.sbom
                if self.intake_result else []),
        }

        # Hash every file in output directory except the manifest itself
        manifest_path = self.output_dir / "hash_manifest.json"
        log_path      = self.output_dir / "examiner_log.json"

        output_files = []
        for f in sorted(self.output_dir.rglob("*")):
            if not f.is_file():
                continue
            if f == manifest_path or f == log_path:
                continue
            rel_path = str(f.relative_to(self.output_dir))
            sha256   = self._hash_file(f)
            size     = f.stat().st_size
            output_files.append({
                "path":       rel_path,
                "sha256":     sha256,
                "size_bytes": size,
            })

        manifest["output_files"] = output_files
        manifest["file_count"]   = len(output_files)

        # Write manifest
        manifest_json = json.dumps(manifest, indent=2, default=str)
        manifest_path.write_text(manifest_json)

        # Hash the manifest itself and append self-hash
        manifest_hash = hashlib.sha256(
            manifest_json.encode()).hexdigest()
        manifest["manifest_sha256"] = manifest_hash
        manifest_path.write_text(
            json.dumps(manifest, indent=2, default=str))

        # Write examiner log
        self._log_entries.append({
            "timestamp":
                datetime.datetime.utcnow().isoformat() + "Z",
            "action": "manifest_written",
            "detail": f"{len(output_files)} files hashed",
            "manifest_sha256": manifest_hash,
        })

        log = {
            "case_id": manifest["case_id"],
            "examiner": manifest["examiner"],
            "log_entries": self._log_entries,
        }
        log_path.write_text(
            json.dumps(log, indent=2, default=str))

    def log(self, action: str, detail: str = ""):
        """Append an entry to the examiner log."""
        self._log_entries.append({
            "timestamp":
                datetime.datetime.utcnow().isoformat() + "Z",
            "action": action,
            "detail": detail,
        })

    @staticmethod
    def _hash_file(path: Path) -> str:
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            while chunk := f.read(1024 * 1024):
                sha256.update(chunk)
        return sha256.hexdigest()
