"""
Browser-based AI service disk parsers.
Parses Chrome/Edge/Firefox profile artifacts for cloud AI services:
ChatGPT, Claude, Gemini, Copilot, Perplexity, Grok.

Sources: cookies, localStorage (LevelDB), IndexedDB, network cache,
browser history SQLite.
"""

import json
import sqlite3
import re
from pathlib import Path
from typing import Optional

from chatdisco.parsers.base import (
    ConversationRecord, Message, MessageRole, AIService,
    SourceType, Confidence, SessionIdentity,
    detect_service_from_url, detect_service_from_cookie,
    SESSION_COOKIE_PATTERNS,
)


class BrowserAPIParser:
    """
    Parses browser profile directories for AI service artifacts.
    Handles Chrome/Chromium/Edge profile structures.
    """

    def parse_chrome_profile(self, profile_dir: Path) -> dict:
        """
        Parse a Chrome profile directory.
        Returns dict with conversations, tokens, cookies, and history.
        """
        results = {
            "conversations": [],
            "session_tokens": [],
            "cookies": [],
            "ai_history": [],
        }

        profile_dir = Path(profile_dir)
        if not profile_dir.exists():
            return results

        # Cookies
        cookie_db = profile_dir / "Cookies"
        if not cookie_db.exists():
            cookie_db = profile_dir / "Network" / "Cookies"
        if cookie_db.exists():
            results["cookies"].extend(
                self._parse_cookies(cookie_db))
            results["session_tokens"].extend(
                self._extract_ai_tokens_from_cookies(
                    results["cookies"]))

        # History (visited AI service URLs)
        history_db = profile_dir / "History"
        if history_db.exists():
            results["ai_history"].extend(
                self._parse_history(history_db))

        # Local Storage (LevelDB) - contains conversation metadata
        ls_dir = profile_dir / "Local Storage" / "leveldb"
        if ls_dir.exists():
            results["conversations"].extend(
                self._parse_localstorage(ls_dir))

        # IndexedDB - contains full conversation data for some services
        idb_dir = profile_dir / "IndexedDB"
        if idb_dir.exists():
            results["conversations"].extend(
                self._parse_indexeddb(idb_dir))

        # Network cache - can contain API responses
        cache_dir = profile_dir / "Cache" / "Cache_Data"
        if cache_dir.exists():
            results["conversations"].extend(
                self._parse_network_cache(cache_dir))

        return results

    # ── Cookies ────────────────────────────────────────────────────────

    def _parse_cookies(self, cookie_db: Path) -> list:
        """
        Parse Chrome Cookies SQLite database.
        Returns list of cookie dicts for AI service domains.
        """
        AI_DOMAINS = {
            "openai.com", "chatgpt.com",
            "anthropic.com", "claude.ai",
            "google.com", "gemini.google.com",
            "microsoft.com", "copilot.microsoft.com", "bing.com",
            "perplexity.ai",
            "x.ai",
        }

        cookies = []
        try:
            # Chrome locks the DB; use a copy
            import tempfile, shutil
            with tempfile.NamedTemporaryFile(
                    suffix=".db", delete=False) as tmp:
                tmp_path = Path(tmp.name)
            shutil.copy2(cookie_db, tmp_path)

            conn = sqlite3.connect(str(tmp_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute(
                "SELECT host_key, name, value, encrypted_value, "
                "path, expires_utc, is_secure, is_httponly "
                "FROM cookies WHERE " +
                " OR ".join(
                    f"host_key LIKE '%{d}'"
                    for d in AI_DOMAINS)
            )
            for row in cur.fetchall():
                cookies.append({
                    "host":      row["host_key"],
                    "name":      row["name"],
                    "value":     row["value"],
                    # encrypted_value requires DPAPI decryption
                    "encrypted": len(row["encrypted_value"]) > 0,
                    "path":      row["path"],
                    "secure":    bool(row["is_secure"]),
                })
            conn.close()
            tmp_path.unlink(missing_ok=True)
        except (sqlite3.Error, IOError, OSError):
            pass
        return cookies

    def _extract_ai_tokens_from_cookies(self, cookies: list) -> list:
        """Extract session tokens relevant to AI services."""
        tokens = []
        for cookie in cookies:
            service = detect_service_from_cookie(cookie["name"])
            if service != AIService.UNKNOWN or \
                    cookie["name"] in (
                        "session", "auth_token", "sessionKey",
                        "__Secure-next-auth.session-token",
                        "SID", "HSID"):
                tokens.append({
                    "service": service.value,
                    "cookie_name": cookie["name"],
                    "host":    cookie["host"],
                    "value":   cookie["value"],
                    "encrypted": cookie["encrypted"],
                })
        return tokens

    # ── Browser history ────────────────────────────────────────────────

    def _parse_history(self, history_db: Path) -> list:
        """Extract AI service visits from Chrome History."""
        AI_PATTERNS = [
            "chatgpt.com", "chat.openai.com",
            "claude.ai",
            "gemini.google.com",
            "copilot.microsoft.com",
            "perplexity.ai",
            "grok.x.ai",
        ]
        visits = []
        try:
            import tempfile, shutil
            with tempfile.NamedTemporaryFile(
                    suffix=".db", delete=False) as tmp:
                tmp_path = Path(tmp.name)
            shutil.copy2(history_db, tmp_path)

            conn = sqlite3.connect(str(tmp_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            where = " OR ".join(
                f"url LIKE '%{p}%'" for p in AI_PATTERNS)
            cur.execute(
                f"SELECT url, title, visit_count, "
                f"last_visit_time FROM urls WHERE {where} "
                f"ORDER BY last_visit_time DESC")

            CHROME_EPOCH_OFFSET = 11644473600000000  # microseconds
            for row in cur.fetchall():
                ts = None
                try:
                    # Chrome timestamps are microseconds since
                    # 1601-01-01; convert to Unix epoch
                    unix_us = row["last_visit_time"] - CHROME_EPOCH_OFFSET
                    import datetime
                    ts = datetime.datetime.utcfromtimestamp(
                        unix_us / 1e6).isoformat() + "Z"
                except (ValueError, OSError):
                    pass
                visits.append({
                    "url":         row["url"],
                    "title":       row["title"],
                    "visit_count": row["visit_count"],
                    "last_visit":  ts,
                    "service":     detect_service_from_url(
                        row["url"]).value,
                })
            conn.close()
            tmp_path.unlink(missing_ok=True)
        except (sqlite3.Error, IOError, OSError):
            pass
        return visits

    # ── Local Storage (LevelDB) ────────────────────────────────────────

    def _parse_localstorage(self, ls_dir: Path) -> list:
        """
        Parse Chrome LevelDB Local Storage for AI conversation data.
        ChatGPT, Claude, and others cache conversation metadata here.
        Uses simple key scanning since full LevelDB parsing requires
        external library.
        """
        conversations = []

        # Scan .ldb and .log files for AI service JSON patterns
        for f in list(ls_dir.glob("*.ldb")) + \
                  list(ls_dir.glob("*.log")):
            try:
                raw = f.read_bytes()
                # Find JSON-like fragments
                self._extract_json_from_bytes(
                    raw, f, conversations)
            except IOError:
                pass

        return conversations

    def _extract_json_from_bytes(
        self,
        raw: bytes,
        source_file: Path,
        conversations: list,
    ):
        """
        Extract parseable JSON objects from raw binary content.
        Looks for AI service conversation patterns.
        """
        # Decode with replacement
        text = raw.decode('utf-8', errors='replace')

        # Look for conversation_id patterns
        CONV_ID_RE = re.compile(
            r'"conversation_id"\s*:\s*"([a-f0-9\-]{32,})"')
        MESSAGES_RE = re.compile(
            r'"messages"\s*:\s*(\[.{10,}\])', re.DOTALL)

        # Find conversation fragments
        for m in CONV_ID_RE.finditer(text):
            conv_id = m.group(1)
            # Look for message content nearby
            start = max(0, m.start() - 200)
            end   = min(len(text), m.end() + 5000)
            fragment = text[start:end]

            msg_match = MESSAGES_RE.search(fragment)
            if msg_match:
                try:
                    msgs_raw = msg_match.group(1)
                    # Try to parse
                    msgs = json.loads(msgs_raw)
                    if isinstance(msgs, list) and msgs:
                        conv = self._build_conv_from_messages(
                            msgs,
                            conv_id=conv_id,
                            source_file=str(source_file),
                            source_type=SourceType.BROWSER_INDEXEDDB,
                        )
                        if conv:
                            conversations.append(conv)
                except (json.JSONDecodeError, ValueError):
                    pass

    # ── IndexedDB ─────────────────────────────────────────────────────

    def _parse_indexeddb(self, idb_dir: Path) -> list:
        """
        Parse Chrome IndexedDB for AI service conversation data.
        Claude.ai and ChatGPT use IndexedDB for conversation storage.
        """
        conversations = []

        # IndexedDB is stored as LevelDB — same scanning approach
        for service_dir in idb_dir.iterdir():
            if not service_dir.is_dir():
                continue

            # Identify service from directory name
            # (e.g. "https_claude.ai_0.indexeddb.leveldb")
            dir_name = service_dir.name.lower()
            service = AIService.UNKNOWN
            if "claude" in dir_name or "anthropic" in dir_name:
                service = AIService.ANTHROPIC_CLAUDE
            elif "openai" in dir_name or "chatgpt" in dir_name:
                service = AIService.OPENAI_CHATGPT
            elif "gemini" in dir_name:
                service = AIService.GOOGLE_GEMINI
            elif "copilot" in dir_name or "bing" in dir_name:
                service = AIService.MICROSOFT_COPILOT
            elif "perplexity" in dir_name:
                service = AIService.PERPLEXITY

            if service == AIService.UNKNOWN:
                continue

            # Scan LevelDB files
            for f in list(service_dir.glob("*.ldb")) + \
                      list(service_dir.glob("*.log")):
                try:
                    raw = f.read_bytes()
                    self._scan_indexeddb_file(
                        raw, f, service, conversations)
                except IOError:
                    pass

        return conversations

    def _scan_indexeddb_file(
        self,
        raw: bytes,
        source_file: Path,
        service: AIService,
        conversations: list,
    ):
        """Scan a single IndexedDB LevelDB file for conversation data."""
        text = raw.decode('utf-8', errors='replace')

        # Service-specific patterns
        if service == AIService.OPENAI_CHATGPT:
            self._scan_openai_indexeddb(
                text, source_file, conversations)
        elif service == AIService.ANTHROPIC_CLAUDE:
            self._scan_claude_indexeddb(
                text, source_file, conversations)
        else:
            self._extract_json_from_bytes(
                raw, source_file, conversations)

    def _scan_openai_indexeddb(
        self, text: str, source_file: Path, conversations: list
    ):
        """Extract ChatGPT conversations from IndexedDB content."""
        # ChatGPT stores full conversation trees in IndexedDB
        TITLE_RE = re.compile(
            r'"title"\s*:\s*"([^"]{3,100})"')
        for m in TITLE_RE.finditer(text):
            start = max(0, m.start() - 100)
            end   = min(len(text), m.end() + 20000)
            fragment = text[start:end]

            # Try to find messages array
            msg_start = fragment.find('"messages"')
            if msg_start == -1:
                continue
            try:
                # Find the array start
                arr_start = fragment.index('[', msg_start)
                # Simple bracket matching
                depth = 0
                arr_end = arr_start
                for i, c in enumerate(
                        fragment[arr_start:], arr_start):
                    if c == '[':
                        depth += 1
                    elif c == ']':
                        depth -= 1
                        if depth == 0:
                            arr_end = i
                            break

                msgs_json = fragment[arr_start:arr_end + 1]
                msgs = json.loads(msgs_json)
                if msgs:
                    conv = self._build_conv_from_messages(
                        msgs,
                        service=AIService.OPENAI_CHATGPT,
                        source_file=str(source_file),
                        source_type=SourceType.BROWSER_INDEXEDDB,
                        title=m.group(1),
                    )
                    if conv:
                        conversations.append(conv)
            except (json.JSONDecodeError, ValueError, IndexError):
                pass

    def _scan_claude_indexeddb(
        self, text: str, source_file: Path, conversations: list
    ):
        """Extract Claude conversations from IndexedDB content."""
        # Claude.ai stores conversations with uuid keys
        UUID_RE = re.compile(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}'
            r'-[0-9a-f]{4}-[0-9a-f]{12}')

        seen_ids = set()
        for m in UUID_RE.finditer(text):
            conv_id = m.group(0)
            if conv_id in seen_ids:
                continue
            seen_ids.add(conv_id)

            start = max(0, m.start() - 50)
            end   = min(len(text), m.end() + 10000)
            fragment = text[start:end]

            if '"messages"' not in fragment:
                continue

            try:
                # Find surrounding JSON object
                obj_start = fragment.rfind('{', 0,
                                            fragment.find(conv_id))
                if obj_start == -1:
                    continue
                # Try to parse from here
                candidate = fragment[obj_start:]
                depth = 0
                obj_end = 0
                for i, c in enumerate(candidate):
                    if c == '{':
                        depth += 1
                    elif c == '}':
                        depth -= 1
                        if depth == 0:
                            obj_end = i
                            break
                obj_json = candidate[:obj_end + 1]
                obj = json.loads(obj_json)
                msgs = obj.get("messages", [])
                if msgs:
                    conv = self._build_conv_from_messages(
                        msgs,
                        service=AIService.ANTHROPIC_CLAUDE,
                        conv_id=conv_id,
                        source_file=str(source_file),
                        source_type=SourceType.BROWSER_INDEXEDDB,
                    )
                    if conv:
                        conversations.append(conv)
            except (json.JSONDecodeError, ValueError, IndexError):
                pass

    # ── Network cache ──────────────────────────────────────────────────

    def _parse_network_cache(self, cache_dir: Path) -> list:
        """
        Scan Chrome network cache for AI API responses.
        Cache files can contain SSE stream bodies and REST responses.
        """
        conversations = []
        for cache_file in cache_dir.iterdir():
            if not cache_file.is_file():
                continue
            try:
                raw = cache_file.read_bytes()
                # Look for SSE data or JSON API responses
                if (b"data:" in raw and
                        b"content" in raw and
                        (b"openai.com" in raw or
                         b"anthropic.com" in raw or
                         b"claude.ai" in raw)):
                    self._extract_json_from_bytes(
                        raw, cache_file, conversations)
            except IOError:
                pass
        return conversations

    # ── Shared helpers ─────────────────────────────────────────────────

    def _build_conv_from_messages(
        self,
        messages: list,
        service: AIService = AIService.UNKNOWN,
        conv_id: Optional[str] = None,
        source_file: str = "",
        source_type: SourceType = SourceType.BROWSER_INDEXEDDB,
        title: Optional[str] = None,
    ) -> Optional[ConversationRecord]:
        """Build a ConversationRecord from a list of message dicts."""
        if not messages:
            return None

        conv = ConversationRecord(
            service=service,
            source_type=source_type,
            source_file=source_file,
            confidence=Confidence.MEDIUM,
        )
        if conv_id:
            conv.identity.conversation_id = conv_id
        if title:
            conv.reconstruction_notes.append(f"Title: {title}")

        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role_str = msg.get("role", "")
            role = (MessageRole.USER if role_str == "user"
                    else MessageRole.ASSISTANT
                    if role_str == "assistant"
                    else MessageRole.SYSTEM
                    if role_str == "system"
                    else MessageRole.UNKNOWN)
            content = msg.get("content", "")
            if isinstance(content, list):
                # Anthropic content blocks or OpenAI multi-modal
                parts = []
                for part in content:
                    if isinstance(part, dict):
                        parts.append(part.get("text", "")
                                     or part.get("value", ""))
                content = " ".join(p for p in parts if p)
            if isinstance(content, str) and content.strip():
                conv.add_message(
                    role=role,
                    content=content,
                    timestamp=msg.get("create_time")
                              or msg.get("created_at"),
                    source_type=source_type,
                )

        return conv if conv.message_count > 0 else None
