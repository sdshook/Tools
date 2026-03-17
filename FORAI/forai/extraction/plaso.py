"""
Plaso (log2timeline + psort) integration.
"""

import json
import subprocess
import sqlite3
from pathlib import Path
from typing import Iterator, Optional, List, Dict, Any
import time

from ..db.evidence import Evidence, EvidenceDB


def run_log2timeline(artifacts_dir: Path, output_file: Path, 
                    plaso_path: Optional[Path] = None,
                    parsers: Optional[List[str]] = None) -> bool:
    """
    Run log2timeline to create a Plaso storage file.
    
    Args:
        artifacts_dir: Directory containing forensic artifacts
        output_file: Output .plaso file path
        plaso_path: Path to Plaso installation (uses system PATH if None)
        parsers: List of parsers to use (uses defaults if None)
        
    Returns:
        True if successful
    """
    log2timeline = "log2timeline.py"
    if plaso_path:
        log2timeline = str(plaso_path / "log2timeline.py")
    
    cmd = [log2timeline, "--status_view", "none"]
    
    if parsers:
        cmd.extend(["--parsers", ",".join(parsers)])
    
    cmd.extend([str(output_file), str(artifacts_dir)])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        return result.returncode == 0
    except Exception as e:
        print(f"log2timeline error: {e}")
        return False


def run_psort(plaso_file: Path, output_file: Path,
             output_format: str = "json_line",
             plaso_path: Optional[Path] = None,
             time_slice: Optional[str] = None) -> bool:
    """
    Run psort to export Plaso data.
    
    Args:
        plaso_file: Input .plaso file
        output_file: Output file path
        output_format: Output format (json_line, dynamic, etc.)
        plaso_path: Path to Plaso installation
        time_slice: Optional time filter (e.g., "2024-01-01,2024-12-31")
        
    Returns:
        True if successful
    """
    psort = "psort.py"
    if plaso_path:
        psort = str(plaso_path / "psort.py")
    
    cmd = [psort, "-o", output_format, "-w", str(output_file)]
    
    if time_slice:
        cmd.extend(["--slice", time_slice])
    
    cmd.append(str(plaso_file))
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        return result.returncode == 0
    except Exception as e:
        print(f"psort error: {e}")
        return False


def parse_plaso_jsonl(jsonl_file: Path, case_id: str) -> Iterator[Evidence]:
    """
    Parse Plaso JSON Lines output into Evidence objects.
    
    Args:
        jsonl_file: Path to JSON Lines file from psort
        case_id: Case identifier
        
    Yields:
        Evidence objects
    """
    with open(jsonl_file, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            # Extract timestamp
            timestamp = event.get("timestamp", 0)
            if isinstance(timestamp, str):
                # Try to parse ISO format
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    timestamp = dt.timestamp()
                except:
                    timestamp = time.time()
            elif timestamp > 1e15:  # Microseconds
                timestamp = timestamp / 1e6
            elif timestamp > 1e12:  # Milliseconds  
                timestamp = timestamp / 1e3
            
            # Determine artifact type from parser/data_type
            parser = event.get("parser", "unknown")
            data_type = event.get("data_type", "")
            
            artifact_type = _classify_artifact(parser, data_type)
            
            # Build summary
            message = event.get("message", "")
            if not message:
                message = event.get("display_name", str(event)[:200])
            
            # Source file
            source = event.get("filename", "") or event.get("display_name", "") or parser
            
            # Build data dict (exclude very large fields)
            data = {}
            for key, value in event.items():
                if key in ("message", "timestamp", "__container_type__", "__type__"):
                    continue
                if isinstance(value, str) and len(value) > 1000:
                    value = value[:1000] + "..."
                data[key] = value
            
            yield Evidence(
                id=None,
                case_id=case_id,
                timestamp=timestamp,
                artifact_type=artifact_type,
                source_file=source,
                summary=message[:500],
                data=data
            )


def _classify_artifact(parser: str, data_type: str) -> str:
    """Classify artifact type from Plaso parser and data_type."""
    parser_lower = parser.lower()
    data_type_lower = data_type.lower()
    
    # Registry
    if "registry" in parser_lower or "winreg" in parser_lower:
        return "registry"
    
    # Prefetch
    if "prefetch" in parser_lower:
        return "prefetch"
    
    # Event logs
    if "evtx" in parser_lower or "winevt" in parser_lower:
        return "evtx"
    
    # MFT/NTFS
    if "mft" in parser_lower or "ntfs" in parser_lower:
        return "mft"
    
    # USN Journal
    if "usnjrnl" in parser_lower or "usn" in parser_lower:
        return "usnjrnl"
    
    # LNK files
    if "lnk" in parser_lower or "shell" in parser_lower:
        return "lnk"
    
    # Browser
    if any(b in parser_lower for b in ["chrome", "firefox", "edge", "safari", "browser"]):
        return "browser"
    
    # SAM/Security
    if "sam" in parser_lower or "security" in parser_lower:
        return "sam"
    
    # Amcache
    if "amcache" in parser_lower:
        return "amcache"
    
    # SetupAPI logs
    if "setupapi" in parser_lower:
        return "setupapi"
    
    # USB
    if "usbstor" in parser_lower or "usb" in data_type_lower:
        return "usbstor"
    
    # Default to parser name
    return parser_lower.split(":")[-1] if ":" in parser_lower else parser_lower


def import_plaso_to_db(plaso_file: Path, db: EvidenceDB, case_id: str,
                       plaso_path: Optional[Path] = None,
                       batch_size: int = 1000) -> int:
    """
    Import Plaso file into evidence database.
    
    Args:
        plaso_file: Path to .plaso file
        db: Evidence database
        case_id: Case identifier
        plaso_path: Path to Plaso installation
        batch_size: Batch size for database inserts
        
    Returns:
        Number of events imported
    """
    import tempfile
    
    # Export to JSON Lines
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        jsonl_path = Path(tmp.name)
    
    try:
        # Run psort
        if not run_psort(plaso_file, jsonl_path, plaso_path=plaso_path):
            raise RuntimeError("psort failed")
        
        # Parse and import
        count = 0
        batch = []
        
        for evidence in parse_plaso_jsonl(jsonl_path, case_id):
            batch.append(evidence)
            
            if len(batch) >= batch_size:
                db.add_evidence_batch(batch)
                count += len(batch)
                batch = []
        
        # Final batch
        if batch:
            db.add_evidence_batch(batch)
            count += len(batch)
        
        return count
        
    finally:
        # Cleanup
        if jsonl_path.exists():
            jsonl_path.unlink()


# Default parser sets for different analysis modes
FAST_PARSERS = [
    "prefetch",
    "winevtx",
    "winreg",
    "lnk",
    "amcache",
    "usnjrnl",
]

STANDARD_PARSERS = FAST_PARSERS + [
    "mft",
    "chrome_history",
    "firefox_history",
    "setupapi",
    "sam",
    "srum",
]

FULL_PARSERS = None  # All parsers
