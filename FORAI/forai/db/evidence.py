"""
Evidence database operations.
"""

import json
import sqlite3
import hashlib
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .schema import ALL_SCHEMAS


@dataclass
class Evidence:
    """A single piece of forensic evidence."""
    id: Optional[int]
    case_id: str
    timestamp: float
    artifact_type: str
    source_file: str
    summary: str
    data: Dict[str, Any]
    hash: str = ""
    confidence: float = 1.0
    
    def __post_init__(self):
        if not self.hash:
            content = f"{self.timestamp}:{self.artifact_type}:{self.source_file}:{json.dumps(self.data, sort_keys=True)}"
            self.hash = hashlib.sha256(content.encode()).hexdigest()[:16]


class EvidenceDB:
    """SQLite database for forensic evidence."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize database with all schemas."""
        with self._connect() as conn:
            for schema in ALL_SCHEMAS:
                conn.executescript(schema)
    
    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    
    def add_evidence(self, evidence: Evidence) -> int:
        """Add evidence to database. Returns ID."""
        with self._connect() as conn:
            cursor = conn.execute("""
                INSERT INTO evidence (case_id, timestamp, artifact_type, source_file, 
                                     summary, data, hash, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                evidence.case_id,
                evidence.timestamp,
                evidence.artifact_type,
                evidence.source_file,
                evidence.summary,
                json.dumps(evidence.data),
                evidence.hash,
                evidence.confidence
            ))
            return cursor.lastrowid
    
    def add_evidence_batch(self, evidence_list: List[Evidence]) -> int:
        """Add multiple evidence items. Returns count added."""
        with self._connect() as conn:
            conn.executemany("""
                INSERT INTO evidence (case_id, timestamp, artifact_type, source_file,
                                     summary, data, hash, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (e.case_id, e.timestamp, e.artifact_type, e.source_file,
                 e.summary, json.dumps(e.data), e.hash, e.confidence)
                for e in evidence_list
            ])
            return len(evidence_list)
    
    def get_evidence(self, case_id: str, artifact_type: Optional[str] = None,
                    time_start: Optional[float] = None,
                    time_end: Optional[float] = None,
                    limit: int = 1000) -> List[Evidence]:
        """Query evidence with filters."""
        query = "SELECT * FROM evidence WHERE case_id = ?"
        params: List[Any] = [case_id]
        
        if artifact_type:
            query += " AND artifact_type = ?"
            params.append(artifact_type)
        
        if time_start:
            query += " AND timestamp >= ?"
            params.append(time_start)
        
        if time_end:
            query += " AND timestamp <= ?"
            params.append(time_end)
        
        query += " ORDER BY timestamp LIMIT ?"
        params.append(limit)
        
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [
                Evidence(
                    id=row["id"],
                    case_id=row["case_id"],
                    timestamp=row["timestamp"],
                    artifact_type=row["artifact_type"],
                    source_file=row["source_file"],
                    summary=row["summary"],
                    data=json.loads(row["data"]) if row["data"] else {},
                    hash=row["hash"],
                    confidence=row["confidence"]
                )
                for row in rows
            ]
    
    def search_evidence(self, case_id: str, query: str, limit: int = 100) -> List[Evidence]:
        """Search evidence by text in summary."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT * FROM evidence 
                WHERE case_id = ? AND summary LIKE ?
                ORDER BY timestamp
                LIMIT ?
            """, (case_id, f"%{query}%", limit)).fetchall()
            
            return [
                Evidence(
                    id=row["id"],
                    case_id=row["case_id"],
                    timestamp=row["timestamp"],
                    artifact_type=row["artifact_type"],
                    source_file=row["source_file"],
                    summary=row["summary"],
                    data=json.loads(row["data"]) if row["data"] else {},
                    hash=row["hash"],
                    confidence=row["confidence"]
                )
                for row in rows
            ]
    
    def get_artifact_types(self, case_id: str) -> List[str]:
        """Get list of artifact types in case."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT DISTINCT artifact_type FROM evidence WHERE case_id = ?
            """, (case_id,)).fetchall()
            return [row[0] for row in rows]
    
    def get_case_stats(self, case_id: str) -> Dict[str, Any]:
        """Get statistics for a case."""
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM evidence WHERE case_id = ?", (case_id,)
            ).fetchone()[0]
            
            by_type = conn.execute("""
                SELECT artifact_type, COUNT(*) FROM evidence 
                WHERE case_id = ? GROUP BY artifact_type
            """, (case_id,)).fetchall()
            
            time_range = conn.execute("""
                SELECT MIN(timestamp), MAX(timestamp) FROM evidence WHERE case_id = ?
            """, (case_id,)).fetchone()
            
            return {
                "total_evidence": total,
                "by_type": {row[0]: row[1] for row in by_type},
                "time_start": time_range[0],
                "time_end": time_range[1]
            }
    
    def log_custody_event(self, case_id: str, event_type: str, description: str,
                         file_path: Optional[str] = None, file_hash: Optional[str] = None):
        """Log a chain of custody event."""
        import time
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO custody_log (case_id, timestamp, event_type, description, 
                                        file_path, file_hash, user)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (case_id, time.time(), event_type, description, file_path, file_hash, "forai"))
    
    def get_custody_log(self, case_id: str) -> List[Dict[str, Any]]:
        """Get chain of custody log for a case."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT * FROM custody_log WHERE case_id = ? ORDER BY timestamp
            """, (case_id,)).fetchall()
            return [dict(row) for row in rows]
