#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
FORAI.py (c) 2025 All Rights Reserved Shane D. Shook
Automated collection and processing for essential forensic Q&A
Supported by TinyLLaMA 1.1b
Note: prototype utilizing KAPE and Eric Zimmerman's Tools
requirements (pip install pandas wmi pywin32 fpdf llama-cpp-python psutil)
dotNet 9 performs better than 6 also...

=============Order of Script Definition======================================
 IMPORTS - All external dependencies first
 CONSTANTS AND CONFIGURATION - All configuration in one place  
 GLOBAL VARIABLES AND CACHES - Performance optimization state
 DATABASE SCHEMA AND VIEWS - All database structure definitions
 UTILITY FUNCTIONS - Basic helper functions used throughout
 TIME PROCESSING FUNCTIONS - Optimized timestamp handling
 ARTIFACT DETECTION AND PROCESSING - Evidence classification
 DATABASE FUNCTIONS - All database operations grouped together
 ENHANCED FTS SEARCH FUNCTIONS - Accuracy-prioritized earch
 LLM GUARDRAILS AND SAFETY - Security and accuracy enforcement
 CSV INGESTION FUNCTIONS - Optimized parallel processing
 KAPE INTEGRATION FUNCTIONS - External tool orchestration
 FORENSIC ANALYSIS FUNCTIONS - Core question answering logic
 LLM FUNCTIONS - Enhanced accuracy-focused language model integration
 OUTPUT AND REPORTING FUNCTIONS - Report generation and archiving
 MAIN FUNCTION - Orchestrates the entire analysis workflow
=============================================================================
"""

# =============================================================================
# IMPORTS - All external dependencies first
# =============================================================================

import os, sys, argparse, hashlib, sqlite3, json, re, time, subprocess, shutil, zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Optional imports with graceful degradation
try:
    import pandas as pd
except Exception:
    print("[!] pandas not found. Install with: pip install pandas", file=sys.stderr)
    sys.exit(1)

try:
    from tqdm import tqdm
    TQDM = True
except Exception:
    TQDM = False

try:
    from fpdf import FPDF
    HAVE_PDF = True
except Exception:
    HAVE_PDF = False
    
try:
    from llama_cpp import Llama
    HAVE_LLAMA = True
except Exception:
    HAVE_LLAMA = False

try:
    import psutil
    HAVE_PSUTIL = True
except Exception:
    HAVE_PSUTIL = False

# =============================================================================
# CONSTANTS AND CONFIGURATION - All configuration in one place
# =============================================================================

# Directory structure
BASE = Path(r"D:\FORAI")
DIR_ARCHIVES = BASE / "archives"
DIR_ARTIFACTS = BASE / "artifacts"
DIR_EXTRACTS = BASE / "extracts"
DIR_LLM = BASE / "LLM"
DIR_REPORTS = BASE / "reports"
DIR_TOOLS = BASE / "tools"
DB_PATH = DIR_EXTRACTS / "forai.db"

# External tool paths
KAPE_EXE  = DIR_TOOLS / "kape" / "kape.exe"
SQLE_MAPS = DIR_TOOLS / "kape" / "Modules" / "bin" / "SQLECmd" / "Maps"

# LLM guardrails configuration
GUARDRAIL_SYSTEM_PROMPT = """You are a senior digital forensics analyst.
Follow these rules strictly:
1) Ground EVERY statement only in the provided evidence. Do NOT invent or assume facts.
2) If evidence is insufficient to answer, reply: "Insufficient evidence in scope."
3) Do NOT assert crimes, motives, or malicious intent (e.g., murder, homicide, extortion, blackmail, fraud)
   unless those exact terms appear in the evidence excerpt.
4) Use neutral, non-accusatory language. Do not speculate.
5) Prefer short, factual bullets; keep narrative brief and restrained.
"""

GUARDRAIL_BANNED_TERMS = [
    r"\bmurder\b", r"\bhomicide\b", r"\bmanslaughter\b",
    r"\bextortion\b", r"\bblackmail\b", r"\bfraud\b",
    r"\bterror(ism|ist)\b", r"\bassault\b", r"\bchild\s*abuse\b",
]

# Artifact detection patterns
ARTIFACT_HINTS = [
    (re.compile(r"systeminfo", re.I),        "systeminfo"),
    (re.compile(r"setupapi",   re.I),        "setupapi"),
    (re.compile(r"storage|disk|physicaldrive", re.I), "storage"),
    (re.compile(r"sam",        re.I),        "SAM"),
    (re.compile(r"ntuser",     re.I),        "NTUSER"),
    (re.compile(r"event.*logon|logon|4624|4647|4634", re.I), "EventLog_Logon"),
    (re.compile(r"usbstor",    re.I),        "USBSTOR"),
    (re.compile(r"mountpoints2", re.I),      "MountPoints2"),
    (re.compile(r"mfte?cmd.*\$(?:mft|j)|\$(?:mft)\b", re.I), "MFT"),
    (re.compile(r"usnjrnl|\$j", re.I),      "USNJRNL"),
    (re.compile(r"lecmd|jumplist", re.I),    "LECmd"),
    (re.compile(r"browser|history|edge|chrome|firefox", re.I), "BrowserHistory"),
    (re.compile(r"dns", re.I),                "DNSCache"),
    (re.compile(r"process|pslist|tasklist", re.I), "Process"),
    (re.compile(r"recentdocs|shellbags|filesystem", re.I), "FileSystem"),
    (re.compile(r"printservice|spool", re.I), "PrintService"),
    (re.compile(r"spool", re.I),              "Spooler"),
    (re.compile(r"amcache", re.I),            "Amcache"),
    (re.compile(r"services", re.I),           "Services"),
    (re.compile(r"event.*app|application", re.I), "EventLog_App"),
]

# Timestamp parsing configuration
KNOWN_TIME_COLS = [
    "TimeCreated","EventCreatedTime","Timestamp","TimeStamp",
    "Created","CreationTime","LastAccess","LastWrite","LastWriteTime","FirstRun","LastRun",
    "RecordCreateTime","FileCreated","FileModified","Modified","WriteTime","Accessed"
]

# Forensic questions template
QUESTIONS = [
    "What is the computername?",
    "What are the Computer make / model / serialnumber?",
    "What are the Internal hard drive make / model / Windows + adapter serialnumbers?",
    "What are the UserNames, SIDs, first/last use (include built-ins)?",
    "Who is the primary user of the computer?",
    "Is there any evidence of data destruction or forensic tampering on this computer and if so, when and by what user?",
    "Have any removable storage devices been used, if so what are their Make / Model / SerialNumber and when were they used?",
    "If any removable storage devices were used, what files were copied to or copied/accessed from the storage devices, by whom, and when?",
    "Have any files been transferred to cloud storage services, if so which, by whom, and when?",
    "Were any screenshots created, if so by whom and when?",
    "Have any documents been printed, if so by whom and when, and using what printer?",
    "Have any software been installed or services been modified, if so - which, by whom and when?",
]

# =============================================================================
# GLOBAL VARIABLES AND CACHES - Performance optimization state
# =============================================================================

# Compiled regex for performance
_GUARDRAIL_BANNED_RE = re.compile("|".join(GUARDRAIL_BANNED_TERMS), re.IGNORECASE)

# Timestamp format cache for optimization
_timestamp_format_cache = {}

# =============================================================================
# DATABASE SCHEMA AND VIEWS - All database structure definitions
# =============================================================================

# Enhanced schema with optimal indexing
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS evidence (
    row_id      TEXT PRIMARY KEY,
    case_id     TEXT,
    host        TEXT,
    user        TEXT,
    ts_utc      INTEGER,
    artifact    TEXT,
    src_file    TEXT,
    summary     TEXT,
    fields_json TEXT,
    src_sha256  TEXT,
    row_sha256  TEXT
);
CREATE TABLE IF NOT EXISTS sources (
    src_file     TEXT PRIMARY KEY,
    tool         TEXT,
    tool_version TEXT,
    src_sha256   TEXT,
    ingested_utc INTEGER
);
CREATE TABLE IF NOT EXISTS time_normalization_log (
    id INTEGER PRIMARY KEY,
    src_file         TEXT,
    original_ts      TEXT,
    normalized_epoch INTEGER,
    note             TEXT
);

-- Performance-optimized indexes for common query patterns
CREATE INDEX IF NOT EXISTS ix_evidence_ts       ON evidence(ts_utc);
CREATE INDEX IF NOT EXISTS ix_evidence_artifact ON evidence(artifact);
CREATE INDEX IF NOT EXISTS ix_evidence_user     ON evidence(user);
CREATE INDEX IF NOT EXISTS ix_evidence_host     ON evidence(host);
CREATE INDEX IF NOT EXISTS ix_evidence_user_ts  ON evidence(user, ts_utc);
CREATE INDEX IF NOT EXISTS ix_evidence_artifact_ts ON evidence(artifact, ts_utc);
CREATE INDEX IF NOT EXISTS ix_evidence_host_user ON evidence(host, user);
CREATE INDEX IF NOT EXISTS ix_evidence_case_ts  ON evidence(case_id, ts_utc);

-- Enhanced FTS with automatic synchronization
CREATE VIRTUAL TABLE IF NOT EXISTS evidence_fts USING fts5(
    summary, fields_json, 
    content='evidence', 
    content_rowid='rowid',
    tokenize='unicode61 remove_diacritics 1'
);

-- Automatic FTS synchronization triggers
CREATE TRIGGER IF NOT EXISTS evidence_ai AFTER INSERT ON evidence BEGIN
  INSERT INTO evidence_fts(rowid, summary, fields_json) VALUES (new.rowid, new.summary, new.fields_json);
END;

CREATE TRIGGER IF NOT EXISTS evidence_ad AFTER DELETE ON evidence BEGIN
  INSERT INTO evidence_fts(evidence_fts, rowid, summary, fields_json) VALUES('delete', old.rowid, old.summary, old.fields_json);
END;

CREATE TRIGGER IF NOT EXISTS evidence_au AFTER UPDATE ON evidence BEGIN
  INSERT INTO evidence_fts(evidence_fts, rowid, summary, fields_json) VALUES('delete', old.rowid, old.summary, old.fields_json);
  INSERT INTO evidence_fts(rowid, summary, fields_json) VALUES (new.rowid, new.summary, new.fields_json);
END;
"""

# Analytical views for forensic questions
VIEWS_SQL = {
    "evidence_norm": """
    CREATE TEMP VIEW evidence_norm AS
    SELECT
      ts_utc, host, user, artifact, src_file, summary, fields_json,

      /* normalized identities */
      COALESCE(
        user,
        json_extract(fields_json,'$.User'),
        json_extract(fields_json,'$.UserName'),
        json_extract(fields_json,'$.Username'),
        json_extract(fields_json,'$.AccountName'),
        json_extract(fields_json,'$.SubjectUserName'),
        json_extract(fields_json,'$.TargetUserName')
      ) AS n_user,

      COALESCE(
        json_extract(fields_json,'$.SID'),
        json_extract(fields_json,'$.Sid'),
        json_extract(fields_json,'$."User SID"'),
        json_extract(fields_json,'$.SecurityId'),
        json_extract(fields_json,'$.TargetSid')
      ) AS n_sid,

      /* system identity */
      COALESCE(
        json_extract(fields_json,'$.SystemManufacturer'),
        json_extract(fields_json,'$.System_Manufacturer'),
        json_extract(fields_json,'$."System Manufacturer"'),
        json_extract(fields_json,'$.Manufacturer')
      ) AS n_make,

      COALESCE(
        json_extract(fields_json,'$.SystemProductName'),
        json_extract(fields_json,'$.System_Product_Name'),
        json_extract(fields_json,'$."System Model"'),
        json_extract(fields_json,'$.Model')
      ) AS n_model,

      COALESCE(
        json_extract(fields_json,'$.SystemSerialNumber'),
        json_extract(fields_json,'$.System_Serial_Number'),
        json_extract(fields_json,'$."Serial Number"'),
        json_extract(fields_json,'$.SerialNumber'),
        json_extract(fields_json,'$."Chassis Serial Number"')
      ) AS n_serial,

      COALESCE(
        json_extract(fields_json,'$.DriveModel'),
        json_extract(fields_json,'$.DiskModel'),
        json_extract(fields_json,'$."Model"')
      ) AS n_drive_model,

      COALESCE(
        json_extract(fields_json,'$.DriveSerial'),
        json_extract(fields_json,'$.DiskSerial'),
        json_extract(fields_json,'$."SerialNumber"'),
        json_extract(fields_json,'$."Disk Serial Number"')
      ) AS n_drive_serial,

      /* unify path/action and usb hints */
      COALESCE(
        json_extract(fields_json,'$.FullPath'),
        json_extract(fields_json,'$.TargetPath'),
        json_extract(fields_json,'$.FileName'),
        json_extract(fields_json,'$.Path')
      ) AS n_file_path,

      lower(COALESCE(
        json_extract(fields_json,'$.Reason'),
        json_extract(fields_json,'$.UsnReason'),
        json_extract(fields_json,'$.Operation')
      )) AS n_action,

      json_extract(fields_json,'$.DriveType')  AS n_drive_type,
      json_extract(fields_json,'$.BusType')    AS n_bus_type,
      json_extract(fields_json,'$.DeviceType') AS n_device_type,

      /* lowercase once for keyword scans */
      lower(summary)     AS lsum,
      lower(fields_json) AS ljson
    FROM evidence_scope;
    """,

    "mv_computer_identity": """
    CREATE TEMP VIEW mv_computer_identity AS
    SELECT DISTINCT
      host AS computer_name,
      n_make   AS make,
      n_model  AS model,
      n_serial AS serial,
      n_drive_model  AS drive_model,
      n_drive_serial AS drive_serial,
      ts_utc,
      src_file
    FROM evidence_norm
    WHERE artifact IN ('systeminfo','setupapi','storage');
    """,

    "mv_accounts_activity": """
    CREATE TEMP VIEW mv_accounts_activity AS
    SELECT
      n_user AS user,
      n_sid  AS sid,
      MIN(ts_utc) AS first_activity,
      MAX(ts_utc) AS last_activity,
      COUNT(*)    AS evidence_count
    FROM evidence_norm
    GROUP BY n_user, n_sid;
    """,

    "mv_primary_user": """
    CREATE TEMP VIEW mv_primary_user AS
    SELECT
      a.user, a.sid, a.first_activity, a.last_activity, a.evidence_count
    FROM mv_accounts_activity a
    WHERE a.sid IS NOT NULL
      AND a.sid LIKE 'S-1-5-21-%'
    ORDER BY a.last_activity DESC, a.evidence_count DESC
    LIMIT 1;
    """,

    "mv_tamper": """
    CREATE TEMP VIEW mv_tamper AS
    SELECT ts_utc, n_user AS user, summary, src_file
    FROM evidence_norm
    WHERE lsum LIKE '%wevtutil cl%'
       OR lsum LIKE '%sdelete%'
       OR lsum LIKE '%timestomp%'
       OR lsum LIKE '%log cleared%';
    """,

    "mv_usb_devices": """
    CREATE TEMP VIEW mv_usb_devices AS
    SELECT
      ts_utc,
      n_user AS user,
      COALESCE(
        json_extract(fields_json,'$.DeviceMake'),
        json_extract(fields_json,'$.FriendlyName'),
        json_extract(fields_json,'$.DeviceDesc'),
        json_extract(fields_json,'$.Product'),
        json_extract(fields_json,'$.Model'),
        json_extract(fields_json,'$.ModelName')
      ) AS make,
      COALESCE(
        json_extract(fields_json,'$.DeviceModel'),
        json_extract(fields_json,'$.Model'),
        json_extract(fields_json,'$.Product')
      ) AS model,
      COALESCE(
        json_extract(fields_json,'$.SerialNumber'),
        json_extract(fields_json,'$.Serial'),
        json_extract(fields_json,'$.ContainerId'),
        json_extract(fields_json,'$.ParentIdPrefix')
      ) AS serial,
      src_file
    FROM evidence_norm
    WHERE artifact IN ('USBSTOR','setupapi','MountPoints2');
    """,

    "mv_usb_file_transfers": """
    CREATE TEMP VIEW mv_usb_file_transfers AS
    WITH base AS (
      SELECT
        ts_utc, n_user AS user, artifact, summary, src_file,
        n_file_path AS file_path,
        n_action    AS action,
        n_drive_type AS drive_type,
        n_bus_type   AS bus_type,
        n_device_type AS device_type,
        lsum, ljson
      FROM evidence_norm
      WHERE artifact IN ('MFT','USNJRNL','LECmd','JumpLists')
    )
    SELECT
      ts_utc,
      user,
      file_path AS file_name,
      action,
      src_file
    FROM base
    WHERE
      ( action LIKE '%create%' OR action LIKE '%rename%' OR action LIKE '%write%' OR lsum LIKE '%jumplist%' )
      AND (
           lower(bus_type) = 'usb'
        OR lower(device_type) = 'usb'
        OR lower(CAST(drive_type AS TEXT)) LIKE '%removable%'
        OR (CASE WHEN CAST(drive_type AS TEXT) GLOB '[0-9]*' THEN CAST(drive_type AS INTEGER) ELSE NULL END) = 2
        OR ljson LIKE '%\\usb%'
        OR ( file_path IS NOT NULL AND substr(file_path,2,1)=':' AND substr(upper(file_path),1,1) <> 'C' )
      );
    """,

    "mv_cloud_exfil": """
    CREATE TEMP VIEW mv_cloud_exfil AS
    SELECT
      ts_utc,
      n_user AS user,
      COALESCE(json_extract(fields_json,'$.FileName'),
               json_extract(fields_json,'$.URL'),
               json_extract(fields_json,'$.Url'),
               json_extract(fields_json,'$.Address')) AS file_name,
      CASE
        WHEN ljson LIKE '%onedrive%' OR ljson LIKE '%graph.microsoft.com%' THEN 'OneDrive/SharePoint'
        WHEN ljson LIKE '%dropbox%'  OR ljson LIKE '%content.dropboxapi.com%' THEN 'Dropbox'
        WHEN ljson LIKE '%box.com%'  THEN 'Box'
        WHEN ljson LIKE '%drive.google%' OR ljson LIKE '%www.googleapis.com/upload%' THEN 'Google Drive'
        WHEN ljson LIKE '%slack%' OR ljson LIKE '%slack-files.com%' THEN 'Slack'
        WHEN ljson LIKE '%icloud%' THEN 'iCloud'
        ELSE 'Other'
      END AS cloud_service,
      src_file
    FROM evidence_norm
    WHERE artifact IN ('BrowserHistory','EventLog_App','FileSystem');
    """,

    "mv_screenshots": """
    CREATE TEMP VIEW mv_screenshots AS
    SELECT
      ts_utc,
      n_user AS user,
      COALESCE(json_extract(fields_json,'$.FilePath'),
               json_extract(fields_json,'$.FullPath'),
               json_extract(fields_json,'$.TargetPath'),
               json_extract(fields_json,'$.FileName')) AS screenshot_file,
      src_file
    FROM evidence_norm
    WHERE artifact IN ('FileSystem')
      AND ( ljson LIKE '%.png%' OR ljson LIKE '%.jpg%' OR ljson LIKE '%screenshot%'
            OR lsum  LIKE '%.png%' OR lsum  LIKE '%.jpg%' OR lsum  LIKE '%screenshot%' );
    """,

    "mv_printing": """
    CREATE TEMP VIEW mv_printing AS
    SELECT
      ts_utc,
      n_user AS user,
      COALESCE(json_extract(fields_json,'$.DocumentName'),
               json_extract(fields_json,'$.FileName'),
               json_extract(fields_json,'$.DocName')) AS document,
      COALESCE(json_extract(fields_json,'$.PrinterName'),
               json_extract(fields_json,'$.Printer')) AS printer,
      src_file
    FROM evidence_norm
    WHERE artifact IN ('PrintService','Spooler','EventLog_App');
    """,

    "mv_installs_services": """
    CREATE TEMP VIEW mv_installs_services AS
    SELECT
      ts_utc,
      n_user AS user,
      COALESCE(json_extract(fields_json,'$.ProgramName'),
               json_extract(fields_json,'$.DisplayName'),
               json_extract(fields_json,'$.ProductName')) AS program,
      COALESCE(json_extract(fields_json,'$.ServiceName'),
               json_extract(fields_json,'$.Name'),
               json_extract(fields_json,'$.Service')) AS service,
      summary, src_file
    FROM evidence_norm
    WHERE artifact IN ('setupapi','Amcache','Services','EventLog_App');
    """,
}

# =============================================================================
# UTILITY FUNCTIONS - Basic helper functions used throughout
# =============================================================================

def sha256_file(path: Path) -> str:
    """Calculate SHA256 hash of a file."""
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()

def sha256_text(s: str) -> str:
    """Calculate SHA256 hash of text."""
    return hashlib.sha256(s.encode('utf-8', errors='ignore')).hexdigest()

def check_memory_usage() -> bool:
    """Monitor memory usage for large cases."""
    if not HAVE_PSUTIL:
        return False
    
    memory = psutil.virtual_memory()
    if memory.percent > 85:
        print(f"[WARN] High memory usage: {memory.percent}%")
        return True
    return False

def ensure_dirs():
    """Create required directory structure."""
    for d in [DIR_ARCHIVES, DIR_ARTIFACTS, DIR_EXTRACTS, DIR_LLM, DIR_REPORTS, DIR_TOOLS]:
        d.mkdir(parents=True, exist_ok=True)

def _run(cmd, cwd=None):
    """Execute external command with logging."""
    print(f"\n[RUN] {' '.join(map(str, cmd))}")
    proc = subprocess.run(list(map(str, cmd)), cwd=cwd, capture_output=True, text=True, shell=False)
    if proc.stdout:
        print(proc.stdout)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(map(str, cmd))}")

# =============================================================================
# TIME PROCESSING FUNCTIONS - Optimized timestamp handling
# =============================================================================

def parse_mmddyyyy(s: str) -> datetime:
    """Parse MMDDYYYY format to datetime."""
    return datetime.strptime(s, "%m%d%Y").replace(tzinfo=timezone.utc)

def pick_timestamp_optimized(row: Dict[str, object], src_file: str, con: sqlite3.Connection) -> Optional[int]:
    """Optimized timestamp parsing with format caching per source file."""
    global _timestamp_format_cache
    
    # Try cached format first for this source file
    if src_file in _timestamp_format_cache:
        cached_fmt = _timestamp_format_cache[src_file]
        for col in KNOWN_TIME_COLS:
            if col in row and str(row[col]).strip():
                val = str(row[col])
                try:
                    dt = datetime.strptime(val, cached_fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    else:
                        dt = dt.astimezone(timezone.utc)
                    return int(dt.timestamp())
                except Exception:
                    # Cache miss, continue to full parsing
                    break
    
    # Full parsing with caching on success
    for col in KNOWN_TIME_COLS:
        if col in row and str(row[col]).strip():
            val = str(row[col])
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
                try:
                    dt = datetime.strptime(val, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    else:
                        dt = dt.astimezone(timezone.utc)
                    # Cache successful format for this file
                    _timestamp_format_cache[src_file] = fmt
                    return int(dt.timestamp())
                except Exception:
                    pass
            
            # Try epoch formats
            if re.fullmatch(r"\d{13}", val):
                return int(int(val)//1000)
            if re.fullmatch(r"\d{10}", val):
                return int(val)
            if re.fullmatch(r"\d{16,19}", val):
                ticks = int(val)
                if ticks > 116444736000000000:
                    return int((ticks - 116444736000000000) / 10_000_000)
            
            # Try ISO format
            try:
                dt = datetime.fromisoformat(val.replace('Z','+00:00'))
                return int(dt.astimezone(timezone.utc).timestamp())
            except Exception:
                pass
            
            # Log unparsed timestamp
            con.execute("INSERT INTO time_normalization_log(src_file, original_ts, normalized_epoch, note) VALUES (?,?,?,?)",
                        (src_file, val, None, f"unparsed:{col}"))
    return None

def compute_range(mode: str, between: Optional[str], target: Optional[str], days: Optional[int], con: sqlite3.Connection) -> Tuple[int,int,str]:
    """Compute analysis time range based on mode and parameters."""
    cur = con.execute("SELECT MIN(ts_utc), MAX(ts_utc) FROM evidence")
    obs_min, obs_max = cur.fetchone() or (None, None)

    # EMPTY DB handling for ALL
    if mode == "ALL" and (obs_min is None or obs_max is None):
        now = int(datetime.now(timezone.utc).timestamp())
        return now, now, "(no evidence ingested yet – empty scope)"

    if mode == "ALL":
        start = int(obs_min)
        end   = int(obs_max)
        text  = (
            f"{datetime.fromtimestamp(start, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')} "
            f"to {datetime.fromtimestamp(end,   tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}"
        )
        return start, end, text

    if mode == "BETWEEN" and between:
        m = re.match(r"^(\d{8})-(\d{8})$", between)
        if not m:
            raise ValueError("--between must be MMDDYYYY-MMDDYYYY")
        s = datetime.strptime(m.group(1), "%m%d%Y").replace(tzinfo=timezone.utc)
        e = datetime.strptime(m.group(2), "%m%d%Y").replace(tzinfo=timezone.utc) + timedelta(hours=23, minutes=59, seconds=59)
        return int(s.timestamp()), int(e.timestamp()), f"{s.strftime('%Y-%m-%d')} to {e.strftime('%Y-%m-%d')}"

    if mode == "DAYS_BEFORE" and target and days is not None:
        t = datetime.strptime(target, "%m%d%Y").replace(tzinfo=timezone.utc)
        s = t - timedelta(days=int(days))
        e = t + timedelta(hours=23, minutes=59, seconds=59)
        return int(s.timestamp()), int(e.timestamp()), f"{days} days before {t.strftime('%Y-%m-%d')}"

    raise ValueError("Invalid date mode/arguments")

def _calculate_time_span(evidence_rows: List[Dict]) -> str:
    """Calculate time span of evidence for context statistics."""
    timestamps = [row.get('ts_utc') for row in evidence_rows if row.get('ts_utc')]
    if not timestamps:
        return "unknown"
    
    min_ts = min(timestamps)
    max_ts = max(timestamps)
    
    if min_ts == max_ts:
        return "single point in time"
    
    span = max_ts - min_ts
    if span < 3600:  # Less than 1 hour
        return f"{span // 60} minutes"
    elif span < 86400:  # Less than 1 day
        return f"{span // 3600} hours"
    else:  # Days
        return f"{span // 86400} days"

# =============================================================================
# ARTIFACT DETECTION AND PROCESSING - Evidence classification
# =============================================================================

def detect_artifact(filename: str) -> str:
    """Detect artifact type based on filename patterns."""
    for rx, name in ARTIFACT_HINTS:
        if rx.search(filename):
            return name
    return "Unknown"

def build_summary(artifact: str, row: Dict[str, object]) -> str:
    """Build human-readable summary for evidence row."""
    try:
        if artifact in ("EventLog_Logon",):
            eid = row.get("EventID") or row.get("Id")
            user = row.get("TargetUserName") or row.get("SubjectUserName") or row.get("User")
            comp = row.get("Computer") or row.get("Host")
            msg  = (row.get("Message") or "").replace("\n"," ")
            return f"[Logon {eid}] {user} @{comp} - {msg[:160]}"
        if artifact in ("MFT","USNJRNL"):
            op = row.get("Reason") or row.get("Operation")
            path = row.get("FullPath") or row.get("Path") or row.get("FileName")
            return f"FS {op}:{path}"
        if artifact in ("LECmd","JumpLists"):
            app = row.get("AppName") or row.get("AppId")
            tgt = row.get("TargetPath")
            return f"JumpList {app} -> {tgt}"
        if artifact in ("USBSTOR","setupapi","MountPoints2"):
            make = row.get("FriendlyName") or row.get("DeviceMake")
            serial = row.get("SerialNumber")
            return f"USB {make} {serial}"
        if artifact in ("PrintService","Spooler"):
            doc = row.get("DocumentName") or row.get("FileName")
            prn = row.get("PrinterName")
            return f"Print {doc} on {prn}"
    except Exception:
        pass
    path = row.get("Path") or row.get("TargetPath") or row.get("FullPath") or ""
    return (f"{artifact} {path}")[:200]

# =============================================================================
# DATABASE FUNCTIONS - All database operations grouped together
# =============================================================================

def db_connect() -> sqlite3.Connection:
    """Create optimized database connection."""
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA cache_size=-64000")  # 64MB cache
    con.execute("PRAGMA temp_store=MEMORY")
    con.executescript(SCHEMA_SQL)
    return con

def set_analysis_scope(con: sqlite3.Connection, start_epoch: int, end_epoch: int):
    """Set temporal scope for analysis with optimized views."""
    # Nuke any prior scope (view or table), then materialize the scoped rows
    con.executescript("""
        DROP VIEW IF EXISTS evidence_scope;
        DROP TABLE IF EXISTS evidence_scope;
    """)
    con.execute(
        """
        CREATE TEMP TABLE evidence_scope AS
        SELECT * FROM evidence
        WHERE ts_utc BETWEEN ? AND ?
        """,
        (start_epoch, end_epoch)
    )

    # Update query planner statistics
    con.execute("ANALYZE evidence_scope")

    # Rebuild the temp views that reference evidence_scope
    for name, sql in VIEWS_SQL.items():
        con.execute(f"DROP VIEW IF EXISTS {name}")
        con.executescript(sql)

# =============================================================================
# ENHANCED FTS SEARCH FUNCTIONS - Accuracy-prioritized search
# =============================================================================

def enhanced_fts_search(con: sqlite3.Connection, query: str, limit: int = 500) -> List[Dict]:
    """
    Enhanced FTS search with multiple strategies and relevance scoring.
    Sacrifices economy for accuracy as requested.
    """
    # Multiple search strategies to maximize recall
    search_strategies = []
    
    # Strategy 1: Exact query
    search_strategies.append(("exact", query))
    
    # Strategy 2: OR of all terms
    terms = [term.strip() for term in query.split() if len(term.strip()) > 1]
    if len(terms) > 1:
        or_query = " OR ".join(terms)
        search_strategies.append(("or_terms", or_query))
    
    # Strategy 3: Phrase matching for terms > 2 chars
    if len(terms) > 1:
        phrase_terms = [f'"{term}"' for term in terms if len(term) > 2]
        if phrase_terms:
            phrase_query = " AND ".join(phrase_terms)
            search_strategies.append(("phrases", phrase_query))
    
    # Strategy 4: Wildcard matching
    wildcard_terms = [f"{term}*" for term in terms if len(term) > 2]
    if wildcard_terms:
        wildcard_query = " OR ".join(wildcard_terms)
        search_strategies.append(("wildcards", wildcard_query))
    
    all_results = []
    seen_row_ids = set()
    
    for strategy_name, search_query in search_strategies:
        try:
            sql = """
            SELECT e.rowid, e.ts_utc, e.user, e.artifact, e.summary, 
                   e.src_file, e.fields_json, f.rank as relevance
            FROM evidence_fts f
            JOIN evidence e ON e.rowid = f.rowid
            WHERE f MATCH ?
            ORDER BY f.rank
            LIMIT ?
            """
            
            strategy_limit = limit // len(search_strategies) if len(search_strategies) > 1 else limit
            
            for r in con.execute(sql, (search_query, strategy_limit)):
                row_id = r[0]
                if row_id not in seen_row_ids:
                    seen_row_ids.add(row_id)
                    try:
                        fields = json.loads(r[6]) if r[6] else {}
                    except Exception:
                        fields = {"_raw_fields_json": r[6]}
                    
                    all_results.append({
                        'ts_utc': r[1], 
                        'user': r[2], 
                        'artifact': r[3], 
                        'summary': r[4], 
                        'src_file': r[5], 
                        'fields': fields,
                        'relevance': r[7],
                        'strategy': strategy_name
                    })
        except Exception as e:
            print(f"[WARN] FTS search failed for strategy '{strategy_name}' with query '{search_query}': {e}")
            continue
    
    # Sort by relevance then recency, prioritizing high-relevance matches
    return sorted(all_results, key=lambda x: (-x.get('relevance', 0), -x.get('ts_utc', 0)))[:limit]

def build_comprehensive_context(evidence_rows: List[Dict], max_context_size: int = 8000) -> str:
    """
    Build comprehensive context for LLM, prioritizing accuracy over economy.
    Uses smart deduplication and hierarchical importance scoring.
    """
    if not evidence_rows:
        return "No evidence found for this query."
    
    # Sort by recency and relevance
    sorted_evidence = sorted(evidence_rows, 
                           key=lambda x: (x.get('relevance', 0), x.get('ts_utc', 0)), 
                           reverse=True)
    
    context_lines = []
    seen_summaries = set()
    seen_files = set()
    char_count = 0
    
    # Artifact importance weights (higher = more important)
    artifact_weights = {
        'EventLog_Logon': 10, 'USBSTOR': 9, 'setupapi': 8, 'MountPoints2': 8,
        'BrowserHistory': 7, 'MFT': 7, 'USNJRNL': 7, 'LECmd': 6,
        'PrintService': 6, 'Spooler': 6, 'EventLog_App': 5, 'FileSystem': 5,
        'Process': 4, 'Services': 4, 'Amcache': 3, 'DNSCache': 3
    }
    
    for row in sorted_evidence:
        # Calculate importance score
        artifact = row.get('artifact', 'Unknown')
        base_weight = artifact_weights.get(artifact, 1)
        relevance = row.get('relevance', 0)
        importance_score = base_weight * (1 + relevance / 10.0)
        
        # Enhanced deduplication
        summary = row.get('summary', '')
        summary_key = summary[:80]  # Longer key for better dedup
        src_file = row.get('src_file', '')
        
        # Skip if we've seen very similar content from same file
        file_summary_key = f"{src_file}:{summary_key}"
        if file_summary_key in seen_summaries:
            continue
        seen_summaries.add(file_summary_key)
        
        # Format timestamp
        ts = row.get('ts_utc')
        when = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if ts else "unknown_time"
        
        # Enhanced evidence formatting with more context
        user = row.get('user', 'unknown_user')
        fields = row.get('fields', {})
        
        # Extract key additional context from fields
        extra_context = []
        if isinstance(fields, dict):
            for key in ['EventID', 'ProcessName', 'CommandLine', 'FileName', 'TargetPath', 'ServiceName']:
                if key in fields and fields[key]:
                    extra_context.append(f"{key}:{fields[key]}")
        
        # Build comprehensive evidence line
        context_parts = [
            f"[{when}]",
            f"[{artifact}]",
            f"[User:{user}]" if user and user != 'unknown_user' else "[User:system]",
            summary[:200],  # Allow longer summaries for accuracy
        ]
        
        if extra_context:
            context_parts.append(f"({'; '.join(extra_context[:3])})")  # Top 3 context items
        
        # Add source file for traceability
        if src_file not in seen_files:
            context_parts.append(f"(Source: {Path(src_file).name})")
            seen_files.add(src_file)
        
        line = " ".join(context_parts)
        
        # Check if adding this line would exceed context limit
        if char_count + len(line) > max_context_size:
            # If we're near the limit, add a truncation notice
            if len(context_lines) > 10:  # Only if we have substantial evidence
                context_lines.append(f"[... truncated after {len(context_lines)} evidence items due to context limit ...]")
            break
        
        context_lines.append(f"- {line}")
        char_count += len(line)
    
    # Add summary statistics
    stats = [
        f"Evidence items: {len(context_lines)}",
        f"Unique artifacts: {len(set(row.get('artifact', 'Unknown') for row in evidence_rows))}",
        f"Time span: {_calculate_time_span(evidence_rows)}",
        f"Unique users: {len(set(row.get('user', 'unknown') for row in evidence_rows if row.get('user')))}"
    ]
    
    header = f"COMPREHENSIVE EVIDENCE CONTEXT ({'; '.join(stats)}):\n"
    return header + "\n".join(context_lines)

# =============================================================================
# LLM GUARDRAILS AND SAFETY - Security and accuracy enforcement
# =============================================================================

def _sanitize_against_hallucinations(text: str, evidence_blob: str) -> str:
    """
    If the answer contains banned terms that are NOT present in the evidence,
    fail closed with a neutral message.
    """
    trigger = _GUARDRAIL_BANNED_RE.search(text) is not None
    justified = _GUARDRAIL_BANNED_RE.search(evidence_blob) is not None
    if trigger and not justified:
        return ("Guardrail: Potentially defamatory or crime-specific language detected without supporting evidence. "
                "Insufficient evidence in scope.")
    return text

# =============================================================================
# CSV INGESTION FUNCTIONS - Optimized parallel processing
# =============================================================================

def process_single_csv(case_id: str, csv_path: Path, con: sqlite3.Connection) -> int:
    """
    Process a single CSV file with optimized batch inserts.
    """
    try:
        src_hash = sha256_file(csv_path)
    except Exception:
        print(f"[!] Cannot hash {csv_path}")
        src_hash = None
    
    con.execute("INSERT OR REPLACE INTO sources(src_file, tool, tool_version, src_sha256, ingested_utc) VALUES (?,?,?,?,?)",
                (str(csv_path), None, None, src_hash, int(time.time())))

    artifact = detect_artifact(csv_path.name)
    
    try:
        reader_iter = pd.read_csv(csv_path, header=0, low_memory=False, encoding="utf-8-sig", chunksize=10000)
        if not hasattr(reader_iter, "__iter__"):
            reader_iter = [reader_iter]
    except Exception:
        reader_iter = pd.read_csv(csv_path, header=0, low_memory=False, engine="python", chunksize=10000)
        if not hasattr(reader_iter, "__iter__"):
            reader_iter = [reader_iter]

    cur = con.cursor()
    row_counter = 0
    batch_data = []
    batch_size = 5000
    
    for df in reader_iter:
        if df is None or df.empty:
            continue
        
        records = df.to_dict(orient="records")
        for row in records:
            row_counter += 1
            ts = pick_timestamp_optimized(row, str(csv_path), con)
            host = row.get("Computer") or row.get("Host") or None
            user = (row.get("User") or row.get("Username") or row.get("UserName") or
                    row.get("AccountName") or row.get("Account") or
                    row.get("SubjectUserName") or row.get("TargetUserName") or
                    row.get("SamAccountName") or row.get("LogonUser") or
                    row.get("Owner") or row.get("CreatedBy") or None)
            
            row_id = sha256_text(f"{csv_path}:{row_counter}")
            fields_json = json.dumps(row)[:150000]
            summary = build_summary(artifact, row)
            
            batch_data.append((
                row_id, case_id, host, user, ts, artifact, str(csv_path), summary, 
                fields_json, src_hash, 
                sha256_text(f"{case_id}|{host}|{user}|{ts}|{artifact}|{summary}|{fields_json}|{src_hash}")
            ))
            
            # Batch insert when we reach batch_size
            if len(batch_data) >= batch_size:
                cur.executemany(
                    """
                    INSERT OR REPLACE INTO evidence(row_id,case_id,host,user,ts_utc,artifact,src_file,summary,fields_json,src_sha256,row_sha256)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    batch_data
                )
                con.commit()
                batch_data = []
                
                # Check memory usage
                if check_memory_usage():
                    print(f"[INFO] High memory usage detected during processing of {csv_path}")
    
    # Insert remaining batch
    if batch_data:
        cur.executemany(
            """
            INSERT OR REPLACE INTO evidence(row_id,case_id,host,user,ts_utc,artifact,src_file,summary,fields_json,src_sha256,row_sha256)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            batch_data
        )
        con.commit()
    
    return row_counter

def ingest_extracts_parallel(con: sqlite3.Connection, case_id: str, extracts_dir: Path = DIR_EXTRACTS) -> int:
    """
    Enhanced ingestion with parallel processing and batch optimization.
    """
    csv_files = sorted(extracts_dir.rglob("*.csv"))
    if not csv_files:
        print(f"[!] No CSVs found under {extracts_dir}")
        return 0
    
    total = 0
    
    # For small numbers of files, process sequentially
    if len(csv_files) <= 4:
        for csv_path in (tqdm(csv_files, desc="Ingesting") if TQDM else csv_files):
            total += process_single_csv(case_id, csv_path, con)
    else:
        # Parallel processing for larger datasets
        print(f"[INFO] Processing {len(csv_files)} CSV files in parallel...")
        
        # Create separate connections for parallel processing
        def process_csv_worker(csv_path):
            worker_con = sqlite3.connect(DB_PATH)
            worker_con.execute("PRAGMA journal_mode=WAL")
            worker_con.execute("PRAGMA synchronous=NORMAL")
            try:
                count = process_single_csv(case_id, csv_path, worker_con)
                worker_con.close()
                return count
            except Exception as e:
                worker_con.close()
                print(f"[ERROR] Failed to process {csv_path}: {e}")
                return 0
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            if TQDM:
                futures = {executor.submit(process_csv_worker, csv_path): csv_path for csv_path in csv_files}
                for future in tqdm(as_completed(futures), total=len(csv_files), desc="Ingesting"):
                    total += future.result()
            else:
                futures = [executor.submit(process_csv_worker, csv_path) for csv_path in csv_files]
                for future in as_completed(futures):
                    total += future.result()
    
    # Rebuild FTS if we have new data
    if total > 0:
        print("[INFO] Rebuilding FTS index...")
        con.execute("INSERT INTO evidence_fts(evidence_fts) VALUES('rebuild')")
        con.commit()
    
    return total

def ingest_setupapi_text(con: sqlite3.Connection, case_id: str, root: Optional[Path] = None) -> int:
    """
    Ingest setupapi.* text logs from extracts\\Registry into the evidence table
    as artifact='setupapi'. Extracts coarse timestamps and useful context.
    """
    root = root or (DIR_EXTRACTS / "Registry")
    if not root.exists():
        return 0

    log_files = sorted(p for p in root.glob("setupapi*") if p.is_file())
    if not log_files:
        return 0

    # Regexes for time / sections in SetupAPI logs (e.g., "2025/08/18 17:41:17.363")
    rx_dt = re.compile(r'(?P<dt>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3})?)')
    rx_hdr = re.compile(r'^\>\>\>\s+\[(?P<header>.+?)\]\s*')   # >>>  [Device Install ...]
    rx_start = re.compile(r'Section start', re.IGNORECASE)
    rx_end   = re.compile(r'Section end',   re.IGNORECASE)

    cur = con.cursor()
    total = 0
    batch_data = []
    batch_size = 1000

    for path in log_files:
        try:
            src_hash = sha256_file(path)
        except Exception:
            src_hash = None

        con.execute(
            "INSERT OR REPLACE INTO sources(src_file, tool, tool_version, src_sha256, ingested_utc) VALUES (?,?,?,?,?)",
            (str(path), "SetupAPI", None, src_hash, int(time.time()))
        )

        header_ctx = None
        last_ts = None

        with path.open('r', encoding='utf-8', errors='ignore') as f:
            for lineno, line in enumerate(f, 1):
                line_s = line.strip()
                if not line_s:
                    continue

                # Timestamp (carry forward last seen)
                mdt = rx_dt.search(line_s)
                ts = None
                if mdt:
                    s = mdt.group('dt')
                    try:
                        fmt = "%Y/%m/%d %H:%M:%S.%f" if '.' in s else "%Y/%m/%d %H:%M:%S"
                        dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                        ts = int(dt.timestamp())
                        last_ts = ts
                    except Exception:
                        ts = last_ts
                else:
                    ts = last_ts

                event = None
                mh = rx_hdr.match(line_s)
                if mh:
                    header_ctx = mh.group('header')
                    event = "section"
                elif rx_start.search(line_s):
                    event = "section_start"
                elif rx_end.search(line_s):
                    event = "section_end"
                elif line_s.lower().startswith(("inf:", "dvi:", "ndi:", "ump:")):
                    event = line_s[:3].lower().rstrip(':')  # inf / dvi / ndi / ump
                else:
                    # Keep only higher-signal lines
                    continue

                fields = {
                    "Event": event,
                    "Header": header_ctx,
                    "Line": line_s,
                    "LogFile": str(path)
                }
                summary = f"setupapi {event}: {(header_ctx or '')} {line_s}"[:200]
                row_id = sha256_text(f"{path}:{lineno}")
                
                batch_data.append((
                    row_id, case_id, None, None, ts, "setupapi", str(path), summary,
                    json.dumps(fields)[:150000], src_hash,
                    sha256_text(f"{case_id}|{ts}|setupapi|{summary}|{fields}|{src_hash}")
                ))
                
                total += 1
                
                # Batch insert
                if len(batch_data) >= batch_size:
                    cur.executemany(
                        """
                        INSERT OR REPLACE INTO evidence
                        (row_id,case_id,host,user,ts_utc,artifact,src_file,summary,fields_json,src_sha256,row_sha256)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        batch_data
                    )
                    con.commit()
                    batch_data = []

    # Insert remaining batch
    if batch_data:
        cur.executemany(
            """
            INSERT OR REPLACE INTO evidence
            (row_id,case_id,host,user,ts_utc,artifact,src_file,summary,fields_json,src_sha256,row_sha256)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            batch_data
        )
        con.commit()

    print(f"[*] Ingested setupapi text rows: {total}")
    return total

# =============================================================================
# KAPE INTEGRATION FUNCTIONS - External tool orchestration
# =============================================================================

def check_kape_prereqs():
    """Verify KAPE installation and prerequisites."""
    if not KAPE_EXE.exists():
        raise FileNotFoundError(f"KAPE not found at {KAPE_EXE}")
    if not SQLE_MAPS.exists():
        print(f"[WARN] SQLECmd Maps not found at {SQLE_MAPS}. Ensure maps are present.")

def kape_collect(tsource: str):
    """Execute KAPE collection phase."""
    _run([KAPE_EXE, '--tsource', tsource, '--tdest', DIR_ARTIFACTS, '--target', '!SANS_Triage', '--tflush'])

def kape_parse():
    """Execute KAPE parsing phase."""
    _run([KAPE_EXE, '--msource', DIR_ARTIFACTS, '--mdest', DIR_EXTRACTS, '--module', '!EZParser', '--mflush'])

def run_live_only_supplements():
    """Execute live system supplemental commands."""
    stamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    reg_dir = DIR_EXTRACTS / 'Registry'
    reg_dir.mkdir(parents=True, exist_ok=True)

    commands = [
        (['cmd.exe','/c','netstat -anob'],        f'netstat_anob_{stamp}.txt'),
        (['cmd.exe','/c','ipconfig /displaydns'], f'displaydns_{stamp}.txt'),
        (['cmd.exe','/c','tasklist /m'],          f'tasklist_m_{stamp}.txt'),
        (['cmd.exe','/c','systeminfo /fo csv'],   f'systeminfo_{stamp}.csv'),
    ]

    for cmd, fname in commands:
        print(f"[LIVE] {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True, shell=False)

        # 1) Save to ARTIFACTS
        art_path = DIR_ARTIFACTS / fname
        with art_path.open('w', encoding='utf-8', errors='ignore') as f:
            if proc.stdout:
                f.write(proc.stdout)
            if proc.stderr:
                f.write('\n=== STDERR ===\n')
                f.write(proc.stderr)

        # 2) Copy to EXTRACTS\Registry
        dst_path = reg_dir / fname
        try:
            shutil.copy2(art_path, dst_path)
        except Exception:
            # Fallback: write content again if copy fails
            with dst_path.open('w', encoding='utf-8', errors='ignore') as f:
                if proc.stdout:
                    f.write(proc.stdout)
                if proc.stderr:
                    f.write('\n=== STDERR ===\n')
                    f.write(proc.stderr)

        print(f"[LIVE] saved: {art_path}  |  copied to: {dst_path}")

def copy_setupapi_logs():
    """
    Copy setupapi.* from artifacts\\*\\Windows\\INF\\ into extracts\\Registry.
    This runs regardless of live vs. mounted evidence.
    """
    reg_dir = DIR_EXTRACTS / "Registry"
    reg_dir.mkdir(parents=True, exist_ok=True)

    copied = 0
    for p in DIR_ARTIFACTS.rglob("setupapi*"):
        try:
            if not p.is_file():
                continue
            # only if the parent path contains \windows\inf\ (case-insensitive)
            parent_norm = str(p.parent).lower().replace("/", "\\")
            if "\\windows\\inf" not in parent_norm:
                continue

            dest = reg_dir / p.name
            # avoid collisions by adding a numeric suffix
            if dest.exists():
                stem, suf = p.stem, p.suffix
                i = 1
                while (reg_dir / f"{stem}_{i}{suf}").exists():
                    i += 1
                dest = reg_dir / f"{stem}_{i}{suf}"

            shutil.copy2(p, dest)
            print(f"[COPY] setupapi: {p} -> {dest}")
            copied += 1
        except Exception as e:
            print(f"[WARN] copy setupapi failed for {p}: {e}")

    print(f"[INFO] setupapi files copied: {copied}")

# =============================================================================
# FORENSIC ANALYSIS FUNCTIONS - Core question answering logic
# =============================================================================

def get_header_values(con: sqlite3.Connection, range_text: str) -> Dict[str, str]:
    """Extract case header information from evidence."""
    comp = None
    try:
        cur = con.execute("SELECT computer_name FROM mv_computer_identity WHERE computer_name IS NOT NULL LIMIT 1")
        row = cur.fetchone()
        if row:
            comp = row[0]
    except Exception:
        pass
    if not comp:
        cur = con.execute("SELECT host, COUNT(*) c FROM evidence_scope GROUP BY host ORDER BY c DESC LIMIT 1")
        r = cur.fetchone()
        comp = r[0] if r else None
    return {
        "ComputerName": comp or "(unknown)",
        "DateRange": range_text,
        "GeneratedUTC": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
    }

def answer_questions(con: sqlite3.Connection) -> List[Dict[str, object]]:
    """Execute all standard forensic questions against evidence views."""
    results = []
    
    # Questions 1-3: Computer identity
    cur = con.execute("SELECT computer_name, make, model, serial, drive_model, drive_serial, ts_utc, src_file FROM mv_computer_identity ORDER BY ts_utc ASC")
    rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
    results.append({"number": 1, "question": QUESTIONS[0], "evidence": rows})
    results.append({"number": 2, "question": QUESTIONS[1], "evidence": rows})
    results.append({"number": 3, "question": QUESTIONS[2], "evidence": rows})

    # Question 4: User accounts
    cur = con.execute("SELECT user, sid, first_activity, last_activity, evidence_count FROM mv_accounts_activity ORDER BY last_activity DESC")
    rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
    results.append({"number": 4, "question": QUESTIONS[3], "evidence": rows})

    # Question 5: Primary user
    cur = con.execute("SELECT user, sid, first_activity, last_activity, evidence_count FROM mv_primary_user")
    rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
    results.append({"number": 5, "question": QUESTIONS[4], "evidence": rows})

    # Question 7: USB devices
    cur = con.execute("SELECT ts_utc, user, make, model, serial, src_file FROM mv_usb_devices ORDER BY ts_utc ASC")
    rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
    results.append({"number": 7, "question": QUESTIONS[6], "evidence": rows})

    # Question 8: USB file transfers
    cur = con.execute("SELECT ts_utc, user, file_name, action, src_file FROM mv_usb_file_transfers ORDER BY ts_utc ASC")
    rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
    results.append({"number": 8, "question": QUESTIONS[7], "evidence": rows})

    # Question 9: Cloud exfiltration
    cur = con.execute("SELECT ts_utc, user, file_name, cloud_service, src_file FROM mv_cloud_exfil ORDER BY ts_utc ASC")
    rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
    results.append({"number": 9, "question": QUESTIONS[8], "evidence": rows})

    # Question 10: Screenshots
    cur = con.execute("SELECT ts_utc, user, screenshot_file, src_file FROM mv_screenshots ORDER BY ts_utc ASC")
    rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
    results.append({"number": 10, "question": QUESTIONS[9], "evidence": rows})

    # Question 11: Printing
    cur = con.execute("SELECT ts_utc, user, document, printer, src_file FROM mv_printing ORDER BY ts_utc ASC")
    rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
    results.append({"number": 11, "question": QUESTIONS[10], "evidence": rows})

    # Question 12: Software installations/services
    cur = con.execute("SELECT ts_utc, user, program, service, summary, src_file FROM mv_installs_services ORDER BY ts_utc ASC")
    rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
    results.append({"number": 12, "question": QUESTIONS[11], "evidence": rows})
    
    return results

# =============================================================================
# LLM FUNCTIONS - Enhanced accuracy-focused language model integration
# =============================================================================

def build_enhanced_llm_prompt(header: Dict[str, str], qa: List[Dict[str, object]]) -> str:
    """
    Enhanced LLM prompt building with comprehensive context.
    Prioritizes accuracy over token economy.
    """
    lines = []
    lines.append("You are analyzing digital forensics evidence. Provide a comprehensive, factual summary.")
    lines.append("CRITICAL: Only state facts directly supported by the evidence below. Do NOT speculate or infer beyond the evidence.")
    lines.append("")
    lines.append(f"CASE DETAILS:")
    lines.append(f"Computer: {header.get('ComputerName', 'unknown')}")
    lines.append(f"Analysis Period: {header.get('DateRange', 'unknown')}")
    lines.append(f"Generated: {header.get('GeneratedUTC', 'unknown')}")
    lines.append("")
    
    # Process each question with full evidence context
    for item in qa:
        lines.append(f"FORENSIC QUESTION {item['number']}: {item['question']}")
        ev = item.get('evidence', [])
        
        if not ev:
            lines.append("EVIDENCE: None found in analysis scope")
            lines.append("")
            continue
        
        lines.append(f"EVIDENCE ({len(ev)} items):")
        
        # Include more evidence per question for accuracy
        for i, row in enumerate(ev[:25]):  # Increased from 10 to 25
            ts = row.get('ts_utc')
            when = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if ts else "unknown_time"
            
            # Enhanced row formatting with more detail
            row_parts = []
            for key in ['computer_name', 'user', 'make', 'model', 'serial', 'file_name', 'action', 'cloud_service', 'program', 'service']:
                if key in row and row[key]:
                    row_parts.append(f"{key}={row[key]}")
            
            # Build comprehensive evidence line
            evidence_detail = f"{when} | {' | '.join(row_parts[:8])}"  # Top 8 details
            lines.append(f"  {i+1}. {evidence_detail}")
        
        if len(ev) > 25:
            lines.append(f"  ... and {len(ev) - 25} additional evidence items")
        
        lines.append("")
    
    # Enhanced analysis instructions
    lines.append("ANALYSIS INSTRUCTIONS:")
    lines.append("1. For each question, provide a direct factual answer based ONLY on the evidence above")
    lines.append("2. If evidence is insufficient, state: 'Insufficient evidence in analysis scope'")
    lines.append("3. Do NOT assert criminal activity, intent, or motives unless explicitly stated in evidence")
    lines.append("4. Use precise timestamps and quantities when available")
    lines.append("5. Distinguish between system/automatic activity vs. user-initiated activity when possible")
    lines.append("6. Provide a brief executive summary highlighting the most significant findings")
    lines.append("")
    lines.append("FORMAT: Provide answers as numbered responses matching the questions, followed by an executive summary.")
    
    return "\n".join(lines)

def llm_summarize_enhanced(header: Dict[str,str], qa: List[Dict[str,object]], model_path: str, max_tokens: int = 1200) -> str:
    """
    Enhanced LLM summarization prioritizing accuracy over brevity.
    """
    if not HAVE_LLAMA:
        raise RuntimeError("llama-cpp-python not installed. Install with: pip install llama-cpp-python")

    # Initialize with larger context window for accuracy
    llm = Llama(
        model_path=model_path, 
        n_ctx=8192,  # Larger context window
        chat_format="chatml",
        n_threads=4,  # Utilize more CPU threads
        verbose=False
    )
    
    prompt = build_enhanced_llm_prompt(header, qa)
    
    # Enhanced generation parameters for accuracy
    resp = llm.create_chat_completion(
        messages=[
            {"role": "system", "content": GUARDRAIL_SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        max_tokens=max_tokens,
        temperature=0.05,  # Very low temperature for accuracy
        top_p=0.85,        # Focused sampling
        repeat_penalty=1.1,
        stop=["</s>", "Human:", "Assistant:"]
    )
    
    text = resp["choices"][0]["message"]["content"].strip()
    
    # Enhanced guardrail check with full prompt context
    evidence_blob = prompt.lower()
    return _sanitize_against_hallucinations(text, evidence_blob)

def llm_answer_custom_enhanced(con: sqlite3.Connection, header: Dict[str,str], nl_question: str, model_path: str, max_tokens: int = 1000) -> str:
    """
    Enhanced ad-hoc question answering with comprehensive context gathering.
    """
    if not HAVE_LLAMA:
        raise RuntimeError("llama-cpp-python not installed. Install with: pip install llama-cpp-python")

    # Enhanced context gathering with multiple search strategies
    context_hits = enhanced_fts_search(con, nl_question, limit=200)
    
    # Build comprehensive context
    context_text = build_comprehensive_context(context_hits, max_context_size=6000)
    
    lines = []
    lines.append(f"FORENSIC ANALYSIS QUESTION: {nl_question}")
    lines.append("")
    lines.append(f"CASE CONTEXT:")
    lines.append(f"Computer: {header.get('ComputerName', 'unknown')}")
    lines.append(f"Analysis Period: {header.get('DateRange', 'unknown')}")
    lines.append("")
    lines.append(context_text)
    lines.append("")
    lines.append("ANALYSIS REQUIREMENTS:")
    lines.append("1. Answer the question using ONLY the evidence provided above")
    lines.append("2. If evidence is insufficient, state exactly: 'Insufficient evidence in scope'")
    lines.append("3. Provide specific timestamps, file names, and user accounts when available")
    lines.append("4. Do NOT speculate beyond the evidence or assert criminal intent")
    lines.append("5. Distinguish between correlation and causation")
    lines.append("6. Note any limitations in the available evidence")
    
    llm = Llama(
        model_path=model_path, 
        n_ctx=8192,
        chat_format="chatml",
        n_threads=4,
        verbose=False
    )
    
    resp = llm.create_chat_completion(
        messages=[
            {"role": "system", "content": GUARDRAIL_SYSTEM_PROMPT},
            {"role": "user",   "content": "\n".join(lines)},
        ],
        max_tokens=max_tokens,
        temperature=0.05,
        top_p=0.85,
        repeat_penalty=1.1,
        stop=["</s>", "Human:", "Assistant:"]
    )
    
    text = resp["choices"][0]["message"]["content"].strip()
    evidence_blob = "\n".join(lines).lower()
    return _sanitize_against_hallucinations(text, evidence_blob)

# =============================================================================
# OUTPUT AND REPORTING FUNCTIONS - Report generation and archiving
# =============================================================================

def write_outputs(case_id: str, header: Dict[str,str], qa: List[Dict[str,object]]) -> Dict[str, str]:
    """Generate standard output reports in multiple formats."""
    DIR_REPORTS.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    
    # JSON output
    json_path = DIR_REPORTS / f"FORAI_{case_id}_{ts}.json"
    with json_path.open('w', encoding='utf-8') as f:
        json.dump({"header": header, "qa": qa}, f, ensure_ascii=False, indent=2)
    
    # Text output
    txt_path = DIR_REPORTS / f"FORAI_{case_id}_{ts}.txt"
    with txt_path.open('w', encoding='utf-8', errors='ignore') as f:
        f.write(f"FORAI Report for {case_id}\n")
        for k, v in header.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")
        for item in qa:
            f.write(f"Q{item['number']}. {item['question']}\n")
            ev = item['evidence']
            if not ev:
                f.write("  (no evidence in scope)\n\n")
                continue
            for row in ev[:50]:
                f.write("  - ")
                try:
                    f.write(json.dumps(row, ensure_ascii=False))
                except Exception:
                    f.write(str(row))
                f.write("\n")
            f.write("\n")
    
    # PDF output (optional)
    pdf_path = ""
    if HAVE_PDF:
        try:
            pdf_path = DIR_REPORTS / f"FORAI_{case_id}_{ts}.pdf"
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.cell(0, 10, f"FORAI Report for {case_id}", ln=True)
            for k, v in header.items():
                pdf.cell(0, 8, f"{k}: {v}", ln=True)
            for item in qa:
                pdf.add_page()
                pdf.set_font("Arial", style='B', size=12)
                pdf.cell(0, 10, f"Q{item['number']}. {item['question']}", ln=True)
                pdf.set_font("Arial", size=10)
                ev = item['evidence']
                if not ev:
                    pdf.cell(0, 8, "(no evidence in scope)", ln=True)
                    continue
                for row in ev[:50]:
                    line = json.dumps(row, ensure_ascii=False)
                    pdf.multi_cell(0, 6, line)
            pdf.output(str(pdf_path))
        except Exception as e:
            print(f"[WARN] PDF generation failed: {e}")
            pdf_path = ""
    
    return {"json": str(json_path), "txt": str(txt_path), "pdf": str(pdf_path) if pdf_path else ""}

def write_chain_of_custody(case_id: str) -> Path:
    """Generate chain of custody log with file hashes."""
    DIR_REPORTS.mkdir(parents=True, exist_ok=True)
    date_stamp = datetime.now().strftime('%m%d%Y')  # file name per write date
    out_path = DIR_REPORTS / f"{date_stamp}_custody.txt"

    def _iter_files(root: Path):
        for r, _, files in os.walk(root):
            for name in files:
                p = Path(r) / name
                try:
                    st = p.stat()
                    size = st.st_size
                    mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
                    h = sha256_file(p)
                    rel = str(p.relative_to(BASE))
                    yield h, size, mtime, rel
                except Exception:
                    # If a file disappears mid-walk, still note it
                    yield "ERR", -1, "N/A", str(p)

    with out_path.open('w', encoding='utf-8') as f:
        f.write("FORAI Chain of Custody Log\n")
        f.write(f"Case: {case_id}\n")
        f.write(f"Generated UTC: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}\n")
        f.write(f"Artifacts root: {DIR_ARTIFACTS}\n")
        f.write(f"Extracts root: {DIR_EXTRACTS}\n\n")

        for label, root in (("ARTIFACTS", DIR_ARTIFACTS), ("EXTRACTS", DIR_EXTRACTS)):
            f.write(f"=== {label} ===\n")
            count = 0
            for h, size, mtime, rel in _iter_files(root):
                f.write(f"{mtime}  {size:>12}  {h}  {rel}\n")
                count += 1
            f.write(f"(total files: {count})\n\n")

    return out_path

def write_case_archive() -> Path:
    """
    Create archives\\MMDDYYYY.zip containing artifacts\\, extracts\\, and reports\\ trees.
    If a same-day archive already exists, append _HHMMSS to avoid overwriting.
    """
    DIR_ARCHIVES.mkdir(parents=True, exist_ok=True)
    date_stamp = datetime.now().strftime('%m%d%Y')
    out_zip = DIR_ARCHIVES / f"{date_stamp}.zip"
    if out_zip.exists():
        out_zip = DIR_ARCHIVES / f"{date_stamp}_{datetime.now().strftime('%H%M%S')}.zip"

    with zipfile.ZipFile(out_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root_dir in (DIR_ARTIFACTS, DIR_EXTRACTS, DIR_REPORTS):
            if not root_dir.exists():
                continue
            for r, _, files in os.walk(root_dir):
                for name in files:
                    p = Path(r) / name
                    # store paths relative to D:\FORAI (so top-level = artifacts/, extracts/, reports/)
                    arcname = str(p.relative_to(BASE))
                    try:
                        zf.write(p, arcname)
                    except Exception as e:
                        print(f"[WARN] Skipping {p}: {e}")

    return out_zip

# =============================================================================
# MAIN FUNCTION - Orchestrates the entire analysis workflow
# =============================================================================

def main():
    """
    Main orchestration function - optimally ordered for performance and clarity.
    All setup, validation, and cleanup happens in logical sequence.
    """
    global DIR_EXTRACTS, DB_PATH
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="FORAI end-to-end analysis with enhanced accuracy")
    parser.add_argument('--case-id', required=True, help='Case identifier')
    parser.add_argument('--mode', choices=['ALL','BETWEEN','DAYS_BEFORE'], default='ALL')
    parser.add_argument('--between', help='MMDDYYYY-MMDDYYYY (used with --mode BETWEEN)')
    parser.add_argument('--target', help='MMDDYYYY (used with --mode DAYS_BEFORE)')
    parser.add_argument('--days', type=int, help='Number of days before target (with --mode DAYS_BEFORE)')

    # Ingestion/processing controls
    parser.add_argument('--no-ingest', action='store_true', help='Skip CSV ingestion (reuse existing DB)')
    parser.add_argument('--extracts-dir', default=str(DIR_EXTRACTS), help='Path to existing extracts directory (default: D:\\FORAI\\extracts)')

    # KAPE controls
    parser.add_argument('--target-drive', default='C:', help='Drive letter of target (e.g., C:, E:, F:)')
    parser.add_argument('--skip-collect', action='store_true', help='Skip KAPE !SANS_Triage collection step')
    parser.add_argument('--skip-parse', action='store_true', help='Skip KAPE !EZParser parsing step')
    parser.add_argument('--skip-kape', action='store_true', help='Skip all KAPE steps (shorthand for --skip-collect --skip-parse)')
    
    # Enhanced LLM Support
    parser.add_argument('--use-llm', action='store_true',
                        help='Generate enhanced LLM executive summary with comprehensive context')
    parser.add_argument('--llm-model',
                        default=str(DIR_LLM / 'tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'),
                        help='Path to local GGUF model (default: D:\\FORAI\\LLM\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf)')
    parser.add_argument('--llm-max-tokens', type=int, default=1200,
                        help='Max tokens for LLM outputs (default: 1200, increased for accuracy)')
    parser.add_argument('--ask', default=None,
                        help='Optional ad-hoc natural-language question with enhanced context search')
    
    args = parser.parse_args()

    # Initialize environment
    ensure_dirs()

    # Handle custom extracts directory
    if args.extracts_dir and Path(args.extracts_dir) != DIR_EXTRACTS:
        DIR_EXTRACTS = Path(args.extracts_dir)
        DB_PATH = DIR_EXTRACTS / 'forai.db'
        print(f"[INFO] Using extracts dir: {DIR_EXTRACTS}")

    # KAPE collection and parsing phase
    try:
        if not (args.skip_kape or (args.skip_collect and args.skip_parse)):
            check_kape_prereqs()
            tdrive = args.target_drive.rstrip('\\/')
            if len(tdrive) >= 2 and tdrive[1] == ':':
                tsource = tdrive + '\\'
            else:
                raise ValueError('Invalid --target-drive (e.g., C: or E:)')
            is_live = tdrive.upper().startswith('C:')
            
            if not args.skip_collect:
                print(f"[INFO] Collecting with KAPE !SANS_Triage from {tsource} -> {DIR_ARTIFACTS}")
                kape_collect(tsource)
            if not args.skip_parse:
                print(f"[INFO] Parsing with KAPE !EZParser from {DIR_ARTIFACTS} -> {DIR_EXTRACTS}")
                kape_parse()
            if is_live and not args.skip_collect:
                print("[INFO] Live system detected (C:). Running live-only supplemental commands...")
                run_live_only_supplements()
            else:
                print("[INFO] Mounted evidence or KAPE skipped; not running live-only supplements.")
        else:
            print("[INFO] --skip-kape specified (or both --skip-collect and --skip-parse). Skipping all KAPE steps.")
    except Exception as e:
        print(f"[WARN] KAPE step skipped or failed: {e}")

    # Always copy setupapi.* from artifacts into extracts\Registry
    try:
        copy_setupapi_logs()
    except Exception as e:
        print(f"[WARN] setupapi copy failed: {e}")

    # Administrator privileges check for live systems
    if os.name == 'nt':
        try:
            import ctypes
            if not bool(ctypes.windll.shell32.IsUserAnAdmin()):
                print("[i] TIP: On live C: collections, run this script as Administrator for full access.")
        except Exception:
            pass

    # Database initialization and ingestion phase
    con = db_connect()
    
    # Ingest setupapi.* text logs staged in extracts\Registry
    try:
        ingest_setupapi_text(con, args.case_id)
    except Exception as e:
        print(f"[WARN] setupapi ingest failed: {e}")

    if not args.no_ingest:
        print(f"[*] Ingesting CSVs from {DIR_EXTRACTS} into {DB_PATH} (enhanced parallel processing)")
        total = ingest_extracts_parallel(con, args.case_id, DIR_EXTRACTS)
        print(f"[*] Ingested rows: {total}")
    else:
        print("[*] Skipping ingestion (using existing DB)")

    # Analysis scope and question answering phase
    start_epoch, end_epoch, range_text = compute_range(args.mode, args.between, args.target, args.days, con)
    set_analysis_scope(con, start_epoch, end_epoch)

    header = get_header_values(con, range_text)
    qa = answer_questions(con)
    
    # Standard report generation
    out = write_outputs(args.case_id, header, qa)

    # Chain-of-custody and archiving
    try:
        coc_path = write_chain_of_custody(args.case_id)
        print(f"    custody: {coc_path}")
    except Exception as e:
        print(f"[WARN] Chain-of-custody log failed: {e}")
    
    try:
        zip_path = write_case_archive()
        print(f"    archive: {zip_path}")
    except Exception as e:
        print(f"[WARN] Case archive creation failed: {e}")

    print("[*] Standard Outputs:")
    for k, v in out.items():
        if v:
            print(f"    {k}: {v}")

    # Enhanced LLM executive summary (12-question rollup)
    if args.use_llm:
        try:
            print("[INFO] Generating enhanced LLM summary with comprehensive context...")
            ts2 = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            summary = llm_summarize_enhanced(header, qa, args.llm_model, args.llm_max_tokens)
            llm_path = DIR_REPORTS / f"FORAI_{args.case_id}_{ts2}_enhanced_llm.txt"
            with llm_path.open('w', encoding='utf-8') as f:
                f.write("FORAI ENHANCED EXECUTIVE SUMMARY\n")
                f.write("=" * 50 + "\n\n")
                f.write(summary)
            print(f"    enhanced_llm: {llm_path}")
        except Exception as e:
            print(f"[WARN] Enhanced LLM summary failed: {e}")

    # Enhanced ad-hoc question with comprehensive context
    if args.ask:
        try:
            print(f"[INFO] Processing enhanced ad-hoc question: {args.ask}")
            ts3 = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            ans = llm_answer_custom_enhanced(con, header, args.ask, args.llm_model, max_tokens=max(800, args.llm_max_tokens))
            ask_path = DIR_REPORTS / f"FORAI_{args.case_id}_{ts3}_enhanced_ask.txt"
            with ask_path.open('w', encoding='utf-8') as f:
                f.write("FORAI ENHANCED AD-HOC ANALYSIS\n")
                f.write("=" * 50 + "\n\n")
                f.write("QUESTION: " + args.ask + "\n\n")
                f.write("ANALYSIS:\n")
                f.write(ans)
            print(f"    enhanced_ask: {ask_path}")
        except Exception as e:
            print(f"[WARN] Enhanced LLM ad-hoc answer failed: {e}")

    # Cleanup
    con.close()
    print("\n[*] Analysis complete. Enhanced accuracy prioritized over token economy.")

if __name__ == '__main__':
    main()
