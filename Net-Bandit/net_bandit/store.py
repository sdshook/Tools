"""SQLite store for cache entries, analyses, decisions and LLM usage."""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time
from collections import OrderedDict
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries(
  id INTEGER PRIMARY KEY, class_key TEXT NOT NULL, version INTEGER NOT NULL,
  status TEXT NOT NULL, code TEXT NOT NULL, code_sha TEXT NOT NULL, sig TEXT NOT NULL,
  description TEXT, template TEXT, model TEXT, created_at REAL, approved_at REAL,
  hits INTEGER DEFAULT 0, diff_checks INTEGER DEFAULT 0, disagreements INTEGER DEFAULT 0,
  status_note TEXT, last_check_ts REAL);
CREATE INDEX IF NOT EXISTS ix_entries_class ON entries(class_key, status);
CREATE TABLE IF NOT EXISTS analyses(
  id INTEGER PRIMARY KEY, class_key TEXT, ts REAL, verdict TEXT, confidence REAL,
  reason TEXT, compiled INTEGER, compile_error TEXT, raw TEXT);
CREATE INDEX IF NOT EXISTS ix_analyses_class ON analyses(class_key, ts);
CREATE TABLE IF NOT EXISTS decisions(
  id INTEGER PRIMARY KEY, ts REAL, class_key TEXT, kind TEXT, source TEXT,
  entry_id INTEGER, verdict TEXT, confidence REAL, reason TEXT, event TEXT);
CREATE INDEX IF NOT EXISTS ix_decisions_class ON decisions(class_key, ts);
CREATE TABLE IF NOT EXISTS llm_calls(
  id INTEGER PRIMARY KEY, ts REAL, purpose TEXT, model TEXT, class_key TEXT,
  input_tokens INTEGER, output_tokens INTEGER, cache_read INTEGER, cache_write INTEGER);
CREATE TABLE IF NOT EXISTS classes(
  class_key TEXT PRIMARY KEY, kind TEXT, template TEXT, verdict TEXT, confidence REAL,
  reason TEXT, updated REAL);
"""

FRONT_CACHE_SIZE = 4096
_NONE = object()  # front-cache marker for "this class has no active entry"


class Store:
    def __init__(self, data_dir: str):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.dir / "net_bandit.db", timeout=15)
        self.db.row_factory = sqlite3.Row
        # Small, predictable footprint: WAL, relaxed fsync, a 2 MB page cache.
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA cache_size=-2048")
        self.db.executescript(SCHEMA)
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(entries)")}
        if "last_check_ts" not in cols:  # migrate databases created by earlier versions
            self.db.execute("ALTER TABLE entries ADD COLUMN last_check_ts REAL")
        self.key = self._load_key()
        self._pending = 0
        self._last_commit = time.time()
        self._front: OrderedDict = OrderedDict()
        self._data_version = self.db.execute("PRAGMA data_version").fetchone()[0]
        self._dv_checked = time.time()

    # Commits are batched (every 50 writes or 2 s) to avoid an fsync per event.
    def _commit(self, force: bool = False) -> None:
        self._pending += 1
        if force or self._pending >= 50 or time.time() - self._last_commit >= 2.0:
            self.flush()

    def flush(self) -> None:
        self.db.commit()
        self._pending = 0
        self._last_commit = time.time()

    def prune(self, retention_days: float) -> int:
        """Delete decisions and LLM-call records older than the retention window."""
        cutoff = time.time() - retention_days * 86400
        n = self.db.execute("DELETE FROM decisions WHERE ts < ?", (cutoff,)).rowcount
        self.db.execute("DELETE FROM llm_calls WHERE ts < ?", (cutoff,))
        self.flush()
        return n

    def _load_key(self) -> bytes:
        p = self.dir / "entry.key"
        if not p.exists():
            p.write_bytes(secrets.token_bytes(32))
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
        return p.read_bytes()

    # ---- in-memory front cache ------------------------------------------
    # Hot path: class key -> active entry row (or "none"), LRU-bounded. SQLite stays the
    # durable copy. Changes made by another process (e.g. `net-bandit approve`) bump SQLite's
    # data_version, which we check at most once a second and then drop the front cache.
    def _check_external_changes(self) -> None:
        now = time.time()
        if now - self._dv_checked < 1.0:
            return
        self._dv_checked = now
        dv = self.db.execute("PRAGMA data_version").fetchone()[0]
        if dv != self._data_version:
            self._data_version = dv
            self._front.clear()

    def _invalidate(self, class_key: str) -> None:
        self._front.pop(class_key, None)

    # ---- entries ---------------------------------------------------------
    def active_entry(self, class_key: str):
        self._check_external_changes()
        if class_key in self._front:
            self._front.move_to_end(class_key)
            row = self._front[class_key]
            return None if row is _NONE else row
        row = self.db.execute(
            "SELECT * FROM entries WHERE class_key=? AND status IN ('approved','pending') "
            "ORDER BY status='approved' DESC, version DESC LIMIT 1", (class_key,)).fetchone()
        self._front[class_key] = row if row is not None else _NONE
        if len(self._front) > FRONT_CACHE_SIZE:
            self._front.popitem(last=False)
        return row

    def add_entry(self, class_key, code, code_sha, sig, description, template, model, status) -> int:
        v = self.db.execute("SELECT COALESCE(MAX(version),0)+1 FROM entries WHERE class_key=?",
                            (class_key,)).fetchone()[0]
        now = time.time()
        cur = self.db.execute(
            "INSERT INTO entries(class_key,version,status,code,code_sha,sig,description,template,model,"
            "created_at,approved_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (class_key, v, status, code, code_sha, sig, description, json.dumps(template), model, now,
             now if status == "approved" else None))
        self._commit(force=True)
        self._invalidate(class_key)
        return cur.lastrowid

    # ---- known classes (for near-miss retrieval) ------------------------
    def upsert_class(self, class_key, kind, template, verdict, confidence, reason) -> None:
        self.db.execute(
            "INSERT INTO classes(class_key,kind,template,verdict,confidence,reason,updated) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(class_key) DO UPDATE SET verdict=excluded.verdict, confidence=excluded.confidence, "
            "reason=excluded.reason, updated=excluded.updated",
            (class_key, kind, json.dumps(template), verdict, confidence, reason, time.time()))
        self._commit()

    def class_verdict(self, class_key):
        r = self.db.execute("SELECT verdict FROM classes WHERE class_key=?", (class_key,)).fetchone()
        return r["verdict"] if r else None

    def all_classes(self):
        return self.db.execute("SELECT * FROM classes ORDER BY updated").fetchall()

    def get_entry(self, entry_id: int):
        return self.db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()

    def list_entries(self, status: str | None = None):
        q = "SELECT * FROM entries"
        args: tuple = ()
        if status:
            q += " WHERE status=?"
            args = (status,)
        return self.db.execute(q + " ORDER BY id", args).fetchall()

    def set_status(self, entry_id: int, status: str, note: str = "") -> None:
        self.db.execute(
            "UPDATE entries SET status=?, status_note=?, approved_at=CASE WHEN ?='approved' "
            "THEN ? ELSE approved_at END WHERE id=?", (status, note, status, time.time(), entry_id))
        self._commit(force=True)
        row = self.get_entry(entry_id)
        if row is not None:
            self._invalidate(row["class_key"])

    def bump(self, entry_id: int, hits=0, diff_checks=0, disagreements=0, checked=False) -> None:
        self.db.execute("UPDATE entries SET hits=hits+?, diff_checks=diff_checks+?, "
                        "disagreements=disagreements+?, last_check_ts=CASE WHEN ? THEN ? ELSE last_check_ts END "
                        "WHERE id=?",
                        (hits, diff_checks, disagreements, int(checked), time.time(), entry_id))
        self._commit()

    # ---- analyses / decisions -------------------------------------------
    def add_analysis(self, class_key, verdict, confidence, reason, compiled, compile_error, raw) -> None:
        self.db.execute(
            "INSERT INTO analyses(class_key,ts,verdict,confidence,reason,compiled,compile_error,raw) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (class_key, time.time(), verdict, confidence, reason, int(compiled), compile_error,
             json.dumps(raw, default=str)))
        self._commit()

    def last_analysis(self, class_key):
        return self.db.execute("SELECT * FROM analyses WHERE class_key=? ORDER BY ts DESC LIMIT 1",
                               (class_key,)).fetchone()

    def add_decision(self, class_key, kind, source, entry_id, verdict, confidence, reason, event_json) -> None:
        self.db.execute(
            "INSERT INTO decisions(ts,class_key,kind,source,entry_id,verdict,confidence,reason,event) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (time.time(), class_key, kind, source, entry_id, verdict, confidence, reason, event_json))
        self._commit()

    def recent_samples(self, class_key, n=3) -> list[dict]:
        rows = self.db.execute("SELECT event FROM decisions WHERE class_key=? ORDER BY ts DESC LIMIT ?",
                               (class_key, n)).fetchall()
        return [json.loads(r["event"]) for r in rows]

    # ---- LLM usage -------------------------------------------------------
    def add_llm_call(self, purpose, model, class_key, usage) -> None:
        self.db.execute(
            "INSERT INTO llm_calls(ts,purpose,model,class_key,input_tokens,output_tokens,cache_read,cache_write) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (time.time(), purpose, model, class_key, usage.input_tokens, usage.output_tokens,
             usage.cache_read, usage.cache_write))
        self._commit()

    def tokens_since(self, since: float) -> int:
        r = self.db.execute("SELECT COALESCE(SUM(input_tokens+output_tokens+cache_read+cache_write),0) "
                            "FROM llm_calls WHERE ts>=?", (since,)).fetchone()
        return int(r[0])

    def stats(self) -> dict:
        q = lambda sql: self.db.execute(sql).fetchone()[0]  # noqa: E731
        by_source = {r["source"]: r["n"] for r in self.db.execute(
            "SELECT source, COUNT(*) n FROM decisions GROUP BY source")}
        by_verdict = {r["verdict"]: r["n"] for r in self.db.execute(
            "SELECT verdict, COUNT(*) n FROM decisions GROUP BY verdict")}
        calls = {r["purpose"]: dict(r) for r in self.db.execute(
            "SELECT purpose, COUNT(*) calls, SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens, "
            "SUM(cache_read) cache_read, SUM(cache_write) cache_write FROM llm_calls GROUP BY purpose")}
        entries = {r["status"]: r["n"] for r in self.db.execute(
            "SELECT status, COUNT(*) n FROM entries GROUP BY status")}
        return {
            "decisions": q("SELECT COUNT(*) FROM decisions"),
            "classes": q("SELECT COUNT(DISTINCT class_key) FROM decisions"),
            "by_source": by_source,
            "by_verdict": by_verdict,
            "llm_calls": calls,
            "entries": entries,
        }
