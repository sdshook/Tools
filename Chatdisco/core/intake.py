"""
Intake module.
Handles input validation, type detection, SHA-256 hashing,
and creation of the initial chain of custody record.
All evidence hashing happens here before any analysis touches the input.
"""

import os
import hashlib
import platform
import socket
import datetime
import json
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()


class InputType(Enum):
    MEMORY_DUMP       = auto()  # Raw RAM: .raw, .mem, .img, .dump
    PROCESS_DUMP      = auto()  # Process dump: .dmp, .mdmp
    PCAP              = auto()  # Network capture: .pcap, .pcapng
    DISK_IMAGE        = auto()  # Disk image: .e01, .dd, .vmdk, .vhd
    HIBERFIL          = auto()  # hiberfil.sys
    PAGEFILE          = auto()  # pagefile.sys / swapfile.sys
    CRASH_DUMP        = auto()  # Windows MEMORY.DMP / minidump
    PREFETCH_FILE     = auto()  # .pf file
    PREFETCH_DIR      = auto()  # C:\Windows\Prefetch\ directory
    EVIDENCE_DIR      = auto()  # Chatdisco collection output directory
    DIRECTORY         = auto()  # Generic directory (mixed content)
    UNKNOWN           = auto()


# File signatures (magic bytes) for format detection
MAGIC_SIGNATURES = {
    InputType.MEMORY_DUMP: [
        b'LYME',                    # LiME format
        b'AVML',                    # AVML format
    ],
    InputType.PCAP: [
        b'\xd4\xc3\xb2\xa1',       # pcap little-endian
        b'\xa1\xb2\xc3\xd4',       # pcap big-endian
        b'\x0a\x0d\x0d\x0a',       # pcapng
    ],
    InputType.CRASH_DUMP: [
        b'PAGEDUMP',                # Windows crash dump
        b'PAGEDU64',                # Windows 64-bit crash dump
        b'KDUMPEDP',                # Kernel dump
    ],
    InputType.HIBERFIL: [
        b'hibr',                    # Hibernation file
        b'wake',                    # Resume from hibernation
    ],
    InputType.DISK_IMAGE: [
        b'EVF',                     # E01 (EnCase)
        b'EWF',                     # EWF variant
    ],
    InputType.PREFETCH_FILE: [
        b'\x11\x00\x00\x00SCCA',   # Prefetch v17 (XP)
        b'\x17\x00\x00\x00SCCA',   # Prefetch v23 (Vista/7)
        b'\x1a\x00\x00\x00SCCA',   # Prefetch v26 (Win8)
        b'\x1e\x00\x00\x00SCCA',   # Prefetch v30 (Win10)
        b'\x1f\x00\x00\x00SCCA',   # Prefetch v31 (Win11)
        b'\x4d\x41\x4d\x04',       # MAM compressed (Win10+)
    ],
}

EXTENSION_HINTS = {
    '.raw': InputType.MEMORY_DUMP,
    '.mem': InputType.MEMORY_DUMP,
    '.lime': InputType.MEMORY_DUMP,
    '.dmp': InputType.CRASH_DUMP,
    '.mdmp': InputType.PROCESS_DUMP,
    '.pcap': InputType.PCAP,
    '.pcapng': InputType.PCAP,
    '.cap': InputType.PCAP,
    '.e01': InputType.DISK_IMAGE,
    '.dd': InputType.DISK_IMAGE,
    '.img': InputType.DISK_IMAGE,
    '.vmdk': InputType.DISK_IMAGE,
    '.vhd': InputType.DISK_IMAGE,
    '.vhdx': InputType.DISK_IMAGE,
    '.pf': InputType.PREFETCH_FILE,
}

NAMED_FILE_HINTS = {
    'hiberfil.sys': InputType.HIBERFIL,
    'pagefile.sys': InputType.PAGEFILE,
    'swapfile.sys': InputType.PAGEFILE,
    'memory.dmp': InputType.CRASH_DUMP,
    'memory.raw': InputType.MEMORY_DUMP,
}


@dataclass
class ArtifactHash:
    sha256: str
    sha1: str
    md5: str
    size_bytes: int


@dataclass
class COCRecord:
    """Chain of custody record created at intake."""
    case_id: str
    examiner: str
    org: str
    tool_name: str = "Chatdisco"
    tool_version: str = "0.1.0"
    acquisition_timestamp: str = ""
    examiner_system: str = ""
    examiner_platform: str = ""
    input_path: str = ""
    input_type: str = ""
    input_hash: Optional[ArtifactHash] = None
    notes: str = ""
    sbom: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.input_hash:
            d['input_hash'] = asdict(self.input_hash)
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


@dataclass
class IntakeResult:
    path: Path
    input_type: InputType
    hashes: ArtifactHash
    coc: COCRecord
    paired_memory: Optional[Path] = None
    keylog_path: Optional[Path] = None


def detect_input_type(path: Path) -> InputType:
    """
    Detect input type by magic bytes first, then extension,
    then name, then directory contents.
    """
    if path.is_dir():
        # Check if it's a Chatdisco evidence directory
        if (path / "acquisition_manifest.json").exists():
            return InputType.EVIDENCE_DIR
        # Check if it looks like Windows Prefetch directory
        pf_files = list(path.glob("*.pf"))
        db_files = list(path.glob("Ag*.db"))
        if pf_files or db_files:
            return InputType.PREFETCH_DIR
        return InputType.DIRECTORY

    # Check named files
    name_lower = path.name.lower()
    if name_lower in NAMED_FILE_HINTS:
        return NAMED_FILE_HINTS[name_lower]

    # Read magic bytes
    try:
        with open(path, 'rb') as f:
            header = f.read(16)
        for itype, signatures in MAGIC_SIGNATURES.items():
            for sig in signatures:
                if header[:len(sig)] == sig:
                    return itype
    except (IOError, PermissionError):
        pass

    # Fall back to extension
    ext = path.suffix.lower()
    if ext in EXTENSION_HINTS:
        return EXTENSION_HINTS[ext]

    # Heuristic: large file with no extension or .bin/.img
    # could be a raw memory dump
    try:
        size = path.stat().st_size
        if size > 500_000_000 and ext in ('', '.bin', '.img', '.raw'):
            return InputType.MEMORY_DUMP
    except OSError:
        pass

    return InputType.UNKNOWN


def hash_file(path: Path, show_progress: bool = True) -> ArtifactHash:
    """
    Compute SHA-256, SHA-1, and MD5 of a file.
    Uses chunked reading for large files.
    For directories, hashes a manifest of all contained files.
    """
    BUF_SIZE = 1024 * 1024 * 4  # 4MB chunks

    sha256 = hashlib.sha256()
    sha1   = hashlib.sha1()
    md5    = hashlib.md5()
    size   = 0

    if path.is_dir():
        # Hash directory: sorted manifest of relative paths + file hashes
        manifest_data = b""
        for child in sorted(path.rglob("*")):
            if child.is_file():
                rel = str(child.relative_to(path)).encode()
                child_hash = hash_file(child, show_progress=False)
                manifest_data += rel + b":" + \
                                  child_hash.sha256.encode() + b"\n"
                size += child.stat().st_size
        sha256.update(manifest_data)
        sha1.update(manifest_data)
        md5.update(manifest_data)
    else:
        size = path.stat().st_size
        if show_progress and size > 10_000_000:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Hashing {task.description}"),
                BarColumn(),
                TextColumn("{task.percentage:>3.0f}%"),
                console=console,
            ) as progress:
                task = progress.add_task(path.name, total=size)
                with open(path, 'rb') as f:
                    while chunk := f.read(BUF_SIZE):
                        sha256.update(chunk)
                        sha1.update(chunk)
                        md5.update(chunk)
                        progress.advance(task, len(chunk))
        else:
            with open(path, 'rb') as f:
                while chunk := f.read(BUF_SIZE):
                    sha256.update(chunk)
                    sha1.update(chunk)
                    md5.update(chunk)

    return ArtifactHash(
        sha256=sha256.hexdigest(),
        sha1=sha1.hexdigest(),
        md5=md5.hexdigest(),
        size_bytes=size,
    )


class Intake:
    """
    Handles all input validation, type detection, hashing,
    and COC record creation. This is the first thing that runs
    before any analysis. Nothing touches the evidence before
    Intake has hashed it.
    """

    def __init__(
        self,
        input_path: str,
        examiner: str,
        case_id: str,
        org: str = "",
        keylog_path: Optional[str] = None,
        paired_memory: Optional[str] = None,
        notes: str = "",
    ):
        self.input_path    = Path(input_path)
        self.examiner      = examiner
        self.case_id       = case_id
        self.org           = org
        self.keylog_path   = Path(keylog_path) if keylog_path else None
        self.paired_memory = Path(paired_memory) if paired_memory else None
        self.notes         = notes
        self._result: Optional[IntakeResult] = None

    def process(self) -> IntakeResult:
        """
        Run intake: validate inputs, detect types, hash everything,
        create COC record. Returns IntakeResult.
        """
        if self._result:
            return self._result

        console.print(f"\n[bold]Intake:[/bold] {self.input_path}")

        # Validate
        if not self.input_path.exists():
            raise FileNotFoundError(
                f"Input not found: {self.input_path}")

        # Detect type
        input_type = detect_input_type(self.input_path)
        console.print(
            f"  Type detected: [bold cyan]{input_type.name}[/bold cyan]")

        # Hash primary input
        console.print("  Hashing primary input...")
        input_hash = hash_file(self.input_path)
        console.print(
            f"  SHA-256: [green]{input_hash.sha256}[/green]")
        console.print(
            f"  Size: {input_hash.size_bytes:,} bytes")

        # Hash paired memory if provided
        paired_mem_path = None
        if self.paired_memory:
            console.print(f"\n  Hashing paired memory: {self.paired_memory}")
            pm_hash = hash_file(self.paired_memory)
            console.print(
                f"  Paired memory SHA-256: [green]{pm_hash.sha256}[/green]")
            paired_mem_path = self.paired_memory

        # Hash keylog if provided
        if self.keylog_path:
            console.print(f"\n  Hashing keylog: {self.keylog_path}")
            kl_hash = hash_file(self.keylog_path)
            console.print(
                f"  Keylog SHA-256: [green]{kl_hash.sha256}[/green]")

        # Build COC record
        from chatdisco.core.dependency_check import check_dependencies
        deps = check_dependencies(require_collection=False)

        coc = COCRecord(
            case_id=self.case_id,
            examiner=self.examiner,
            org=self.org,
            acquisition_timestamp=datetime.datetime.utcnow().isoformat() + "Z",
            examiner_system=socket.gethostname(),
            examiner_platform=platform.platform(),
            input_path=str(self.input_path.resolve()),
            input_type=input_type.name,
            input_hash=input_hash,
            notes=self.notes,
            sbom=deps.as_sbom_entries(),
        )

        self._result = IntakeResult(
            path=self.input_path,
            input_type=input_type,
            hashes=input_hash,
            coc=coc,
            paired_memory=paired_mem_path,
            keylog_path=self.keylog_path,
        )

        return self._result

    @property
    def result(self) -> Optional[IntakeResult]:
        return self._result
