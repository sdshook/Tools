"""
Local LLM disk parsers.
Parses on-disk conversation formats from Ollama, LM Studio, Jan,
llama.cpp, and Open WebUI. These services store conversations locally
and are often unencrypted — high-confidence recoveries from disk.
"""

import json
import sqlite3
from pathlib import Path
from typing import Optional

from chatdisco.parsers.base import (
    ConversationRecord, Message, MessageRole, AIService,
    SourceType, Confidence, SessionIdentity
)


class LocalLLMParser:
    """
    Parses conversation data from local LLM application directories.
    """

    # ── Ollama ─────────────────────────────────────────────────────────

    def parse_ollama_dir(self, ollama_dir: Path) -> list:
        """
        Parse Ollama data directory (~/.ollama).
        Ollama stores conversation history in JSON files under
        ~/.ollama/history/ (community builds) or as SQLite.
        """
        conversations = []
        history_dir = ollama_dir / "history"

        if history_dir.exists():
            for f in history_dir.glob("*.json"):
                conv = self._parse_ollama_json(f)
                if conv:
                    conversations.append(conv)

        # Also check for sqlite history (Open WebUI backend)
        db_path = ollama_dir / "ollama.db"
        if db_path.exists():
            conversations.extend(self._parse_ollama_sqlite(db_path))

        return conversations

    def _parse_ollama_json(self, path: Path) -> Optional[ConversationRecord]:
        """Parse a single Ollama conversation JSON file."""
        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            return None

        messages = data.get("messages", [])
        if not messages:
            return None

        conv = ConversationRecord(
            service=AIService.OLLAMA,
            model=data.get("model"),
            source_type=SourceType.DISK_FILE,
            source_file=str(path),
            confidence=Confidence.HIGH,
        )
        conv.identity.conversation_id = (
            data.get("id") or path.stem)

        for msg in messages:
            role_str = msg.get("role", "")
            role = (MessageRole.USER if role_str == "user"
                    else MessageRole.ASSISTANT
                    if role_str == "assistant"
                    else MessageRole.SYSTEM
                    if role_str == "system"
                    else MessageRole.UNKNOWN)
            content = msg.get("content", "")
            if content:
                conv.add_message(
                    role=role,
                    content=content,
                    timestamp=msg.get("created_at"),
                    model=msg.get("model") or data.get("model"),
                    source_type=SourceType.DISK_FILE,
                )

        return conv if conv.message_count > 0 else None

    def _parse_ollama_sqlite(self, db_path: Path) -> list:
        """Parse Ollama SQLite database."""
        conversations = []
        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # Try common table schemas
            tables = [r[0] for r in
                      cur.execute(
                          "SELECT name FROM sqlite_master "
                          "WHERE type='table'").fetchall()]

            if "messages" in tables:
                conversations.extend(
                    self._parse_openwebui_messages(cur))
            elif "chat" in tables:
                conversations.extend(
                    self._parse_ollama_chat_table(cur))

            conn.close()
        except sqlite3.Error:
            pass
        return conversations

    def _parse_openwebui_messages(self, cur) -> list:
        """Parse Open WebUI message schema."""
        conversations = []
        try:
            chats = cur.execute(
                "SELECT id, title, created_at FROM chat").fetchall()
            for chat in chats:
                msgs = cur.execute(
                    "SELECT role, content, created_at "
                    "FROM messages WHERE chat_id=? "
                    "ORDER BY created_at",
                    (chat["id"],)
                ).fetchall()

                if not msgs:
                    continue

                conv = ConversationRecord(
                    service=AIService.OPEN_WEBUI,
                    source_type=SourceType.BROWSER_SQLITE,
                    confidence=Confidence.HIGH,
                )
                conv.identity.conversation_id = str(chat["id"])

                for msg in msgs:
                    role_str = msg["role"]
                    role = (MessageRole.USER if role_str == "user"
                            else MessageRole.ASSISTANT)
                    content = msg["content"]
                    if isinstance(content, str):
                        try:
                            content_obj = json.loads(content)
                            if isinstance(content_obj, list):
                                content = " ".join(
                                    p.get("text", "")
                                    for p in content_obj
                                    if isinstance(p, dict))
                        except (json.JSONDecodeError, TypeError):
                            pass
                    if content:
                        conv.add_message(
                            role=role,
                            content=str(content),
                            source_type=SourceType.BROWSER_SQLITE,
                        )

                if conv.message_count > 0:
                    conversations.append(conv)
        except sqlite3.Error:
            pass
        return conversations

    def _parse_ollama_chat_table(self, cur) -> list:
        """Fallback for alternate Ollama schema."""
        return []

    # ── LM Studio ─────────────────────────────────────────────────────

    def parse_lmstudio_dir(self, lms_dir: Path) -> list:
        """
        Parse LM Studio data directory (~/.lmstudio).
        LM Studio stores conversations as JSON in
        ~/.lmstudio/conversations/ or similar.
        """
        conversations = []
        search_dirs = [
            lms_dir / "conversations",
            lms_dir / "history",
            lms_dir / "chats",
        ]

        for d in search_dirs:
            if d.exists():
                for f in d.glob("**/*.json"):
                    conv = self.parse_lmstudio_json_file(f)
                    if conv:
                        conversations.append(conv)

        return conversations

    def parse_lmstudio_json_file(
        self, path: Path
    ) -> Optional[ConversationRecord]:
        """Parse a single LM Studio conversation JSON file."""
        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            return None
        return self.parse_lmstudio_json(data, str(path))

    def parse_lmstudio_json(
        self, data: dict, source_path: str = ""
    ) -> Optional[ConversationRecord]:
        """
        Parse LM Studio JSON conversation object.
        Handles OpenAI-compatible message format.
        """
        messages = data.get("messages", [])
        if not messages:
            return None

        conv = ConversationRecord(
            service=AIService.LM_STUDIO,
            model=data.get("model") or data.get("modelId"),
            source_type=SourceType.DISK_FILE,
            source_file=source_path,
            confidence=Confidence.HIGH,
        )
        conv.identity.conversation_id = data.get("id")

        for msg in messages:
            role_str = msg.get("role", "")
            role = (MessageRole.USER if role_str == "user"
                    else MessageRole.ASSISTANT
                    if role_str == "assistant"
                    else MessageRole.SYSTEM
                    if role_str == "system"
                    else MessageRole.UNKNOWN)
            content = msg.get("content", "")
            # Content can be string or list of content blocks
            if isinstance(content, list):
                content = " ".join(
                    p.get("text", "")
                    for p in content
                    if isinstance(p, dict))
            if content:
                conv.add_message(
                    role=role,
                    content=str(content),
                    source_type=SourceType.DISK_FILE,
                )

        return conv if conv.message_count > 0 else None

    # ── Jan ────────────────────────────────────────────────────────────

    def parse_jan_dir(self, jan_dir: Path) -> list:
        """
        Parse Jan app data directory (~/jan).
        Jan stores threads as JSON files under
        ~/jan/threads/<thread_id>/messages.jsonl
        """
        conversations = []
        threads_dir = jan_dir / "threads"

        if not threads_dir.exists():
            return conversations

        for thread_dir in threads_dir.iterdir():
            if not thread_dir.is_dir():
                continue

            messages_file = thread_dir / "messages.jsonl"
            if not messages_file.exists():
                continue

            conv = self._parse_jan_thread(
                thread_dir, messages_file)
            if conv:
                conversations.append(conv)

        return conversations

    def _parse_jan_thread(
        self, thread_dir: Path, messages_file: Path
    ) -> Optional[ConversationRecord]:
        """Parse a single Jan thread directory."""
        # Load thread metadata
        metadata = {}
        meta_file = thread_dir / "thread.json"
        if meta_file.exists():
            try:
                with open(meta_file) as f:
                    metadata = json.load(f)
            except (json.JSONDecodeError, IOError):
                pass

        conv = ConversationRecord(
            service=AIService.JAN,
            model=metadata.get("assistants", [{}])[0].get(
                "model", {}).get("id") if metadata.get(
                "assistants") else None,
            source_type=SourceType.DISK_FILE,
            source_file=str(messages_file),
            confidence=Confidence.HIGH,
        )
        conv.identity.conversation_id = thread_dir.name

        # Parse JSONL messages file
        try:
            with open(messages_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                        role_str = msg.get("role", "")
                        role = (MessageRole.USER if role_str == "user"
                                else MessageRole.ASSISTANT)
                        content = msg.get("content", "")
                        if isinstance(content, list):
                            content = " ".join(
                                p.get("text", "")
                                for p in content
                                if isinstance(p, dict))
                        if content:
                            conv.add_message(
                                role=role,
                                content=str(content),
                                timestamp=msg.get("created_at"),
                                source_type=SourceType.DISK_FILE,
                            )
                    except json.JSONDecodeError:
                        pass
        except IOError:
            return None

        return conv if conv.message_count > 0 else None

    # ── llama.cpp ─────────────────────────────────────────────────────

    def parse_llamacpp_log(self, log_path: Path) -> list:
        """
        Parse llama.cpp server log for conversation fragments.
        llama.cpp server logs requests/responses to stdout/file.
        This is best-effort extraction from log format.
        """
        conversations = []
        if not log_path.exists():
            return conversations

        current_messages = []
        current_model = None

        try:
            with open(log_path, errors='replace') as f:
                for line in f:
                    line = line.strip()
                    # Look for JSON request/response lines
                    if '"messages"' in line:
                        try:
                            obj = json.loads(line)
                            if "messages" in obj:
                                msgs = obj["messages"]
                                conv = ConversationRecord(
                                    service=AIService.LLAMA_CPP,
                                    model=obj.get("model"),
                                    source_type=SourceType.DISK_FILE,
                                    source_file=str(log_path),
                                    confidence=Confidence.MEDIUM,
                                )
                                for msg in msgs:
                                    role_str = msg.get("role", "")
                                    role = (MessageRole.USER
                                            if role_str == "user"
                                            else MessageRole.ASSISTANT)
                                    content = msg.get("content", "")
                                    if content:
                                        conv.add_message(
                                            role=role,
                                            content=content,
                                            source_type=SourceType.DISK_FILE,
                                        )
                                if conv.message_count > 0:
                                    conversations.append(conv)
                        except json.JSONDecodeError:
                            pass
        except IOError:
            pass

        return conversations
