"""
Base ConversationRecord schema.

Every AI chat artifact extracted by Chatdisco, regardless of source
(memory heap, PCAP stream, disk file, prefetch residue), is normalised
into this schema before output. This is Chatdisco's central data model.
"""

import json
import uuid
import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class AIService(Enum):
    """Known AI services. UNKNOWN for unrecognised or unattributed."""
    OPENAI_CHATGPT    = "openai_chatgpt"
    ANTHROPIC_CLAUDE  = "anthropic_claude"
    GOOGLE_GEMINI     = "google_gemini"
    MICROSOFT_COPILOT = "microsoft_copilot"
    PERPLEXITY        = "perplexity"
    XGROK             = "xai_grok"
    META_LLAMA        = "meta_llama"
    OLLAMA            = "ollama"
    LM_STUDIO         = "lm_studio"
    JAN               = "jan"
    LLAMA_CPP         = "llama_cpp"
    OPEN_WEBUI        = "open_webui"
    COPILOT_RECALL    = "copilot_recall"
    COPILOT_WINDOWS   = "copilot_windows"
    COPILOT_M365      = "copilot_m365"
    GITHUB_COPILOT    = "github_copilot"
    CURSOR            = "cursor_ai"
    UNKNOWN           = "unknown"


class MessageRole(Enum):
    USER      = "user"
    ASSISTANT = "assistant"
    SYSTEM    = "system"
    TOOL      = "tool"
    UNKNOWN   = "unknown"


class SourceType(Enum):
    """Where this artifact was recovered from."""
    LIVE_RAM          = "live_ram"
    PROCESS_DUMP      = "process_dump"
    HEAP_CARVE        = "heap_carve"          # bulk_extractor JSON carve
    PCAP_STREAM       = "pcap_stream"         # tshark SSE reconstruction
    PCAP_ENCRYPTED    = "pcap_encrypted"      # PCAP, no keys available
    DISK_FILE         = "disk_file"           # On-disk app data
    BROWSER_CACHE     = "browser_cache"       # Chrome/Firefox cache
    BROWSER_INDEXEDDB = "browser_indexeddb"
    BROWSER_SQLITE    = "browser_sqlite"
    MEMORY_MAPPED     = "memory_mapped"       # From pagefile/hiberfil/pf
    PAGEFILE          = "pagefile"
    HIBERFIL          = "hiberfil"
    PREFETCH          = "prefetch"
    CRASH_DUMP        = "crash_dump"
    REGISTRY          = "registry"
    UNKNOWN           = "unknown"


class Confidence(Enum):
    """Confidence in reconstruction completeness/accuracy."""
    HIGH   = "high"    # Complete, ordered, verified
    MEDIUM = "medium"  # Mostly complete, minor gaps
    LOW    = "low"     # Partial, fragments, uncertain order
    TRACE  = "trace"   # Only fragments, significant gaps


@dataclass
class Message:
    """A single turn in a conversation."""
    role: MessageRole
    content: str
    timestamp: Optional[str]      = None   # ISO 8601 UTC if known
    message_id: Optional[str]     = None   # Service-assigned ID if present
    model: Optional[str]          = None   # Model used for this turn
    token_count: Optional[int]    = None
    source_offset: Optional[int]  = None   # Byte offset in source file
    source_type: Optional[SourceType] = None
    partial: bool                 = False  # True if content is incomplete
    encoding: Optional[str]       = None   # utf-8, utf-16le, etc.


@dataclass
class SessionIdentity:
    """All identity and session attribution artifacts."""
    # Session / conversation identifiers
    conversation_id: Optional[str]   = None
    thread_id: Optional[str]         = None
    session_id: Optional[str]        = None
    request_id: Optional[str]        = None

    # User identity
    username: Optional[str]          = None
    email: Optional[str]             = None
    user_id: Optional[str]           = None
    display_name: Optional[str]      = None

    # Authentication tokens (partial or full)
    session_token: Optional[str]     = None   # __Secure-next-auth etc.
    bearer_token: Optional[str]      = None   # JWT
    api_key: Optional[str]           = None   # sk-... etc.
    access_token: Optional[str]      = None
    refresh_token: Optional[str]     = None

    # Device / network
    client_ip: Optional[str]         = None
    user_agent: Optional[str]        = None
    device_id: Optional[str]         = None


@dataclass
class TLSInfo:
    """TLS session metadata."""
    server_name: Optional[str]       = None   # SNI
    tls_version: Optional[str]       = None
    cipher_suite: Optional[str]      = None
    cert_subject: Optional[str]      = None
    cert_issuer: Optional[str]       = None
    cert_fingerprint: Optional[str]  = None
    cert_valid_from: Optional[str]   = None
    cert_valid_to: Optional[str]     = None
    key_recovered: bool              = False
    key_source: Optional[str]        = None   # How keys were obtained


@dataclass
class NetworkContext:
    """Network context for PCAP-sourced conversations."""
    src_ip: Optional[str]            = None
    src_port: Optional[int]          = None
    dst_ip: Optional[str]            = None
    dst_port: Optional[int]          = None
    protocol: Optional[str]          = None   # HTTP/1.1, HTTP/2, WS
    stream_id: Optional[int]         = None   # TCP/HTTP2 stream ID
    first_packet_ts: Optional[str]   = None
    last_packet_ts: Optional[str]    = None
    bytes_client: Optional[int]      = None
    bytes_server: Optional[int]      = None
    tls: Optional[TLSInfo]           = None


@dataclass
class ConversationRecord:
    """
    Normalised AI chat conversation record.
    Single output schema regardless of source surface or AI service.
    """
    # Unique ID for this record within the case
    record_id: str                        = field(
        default_factory=lambda: str(uuid.uuid4()))

    # Service and session
    service: AIService                    = AIService.UNKNOWN
    service_version: Optional[str]        = None
    model: Optional[str]                  = None
    identity: SessionIdentity             = field(
        default_factory=SessionIdentity)

    # The conversation itself
    messages: list                        = field(default_factory=list)
    message_count: int                    = 0
    system_prompt: Optional[str]          = None

    # Temporal
    first_message_ts: Optional[str]       = None
    last_message_ts: Optional[str]        = None
    duration_seconds: Optional[float]     = None

    # Provenance
    source_type: SourceType               = SourceType.UNKNOWN
    source_file: Optional[str]            = None
    source_offset_start: Optional[int]    = None
    source_offset_end: Optional[int]      = None
    extraction_method: Optional[str]      = None

    # Network context (PCAP-sourced only)
    network: Optional[NetworkContext]     = None

    # Quality
    confidence: Confidence                = Confidence.LOW
    partial: bool                         = False
    reconstruction_notes: list            = field(default_factory=list)

    # Raw artifacts preserved for COC
    raw_json_fragments: list              = field(default_factory=list)

    def add_message(self, role: MessageRole, content: str,
                    **kwargs) -> Message:
        msg = Message(role=role, content=content, **kwargs)
        self.messages.append(msg)
        self.message_count = len(self.messages)
        # Update timestamps
        if msg.timestamp:
            if not self.first_message_ts:
                self.first_message_ts = msg.timestamp
            self.last_message_ts = msg.timestamp
        return msg

    def to_dict(self) -> dict:
        d = asdict(self)
        # Convert enums to values
        d['service'] = self.service.value
        d['source_type'] = self.source_type.value
        d['confidence'] = self.confidence.value
        d['messages'] = [
            {**m, 'role': m['role'].value if hasattr(m['role'], 'value')
             else m['role'],
             'source_type': m['source_type'].value
             if m.get('source_type') and hasattr(m['source_type'], 'value')
             else m.get('source_type')}
            for m in d['messages']
        ]
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def summary(self) -> str:
        """One-line summary for logging."""
        turns = self.message_count
        svc = self.service.value
        user = self.identity.email or self.identity.username or "unknown user"
        conf = self.confidence.value
        src = self.source_type.value
        return (f"[{svc}] {turns} messages | {user} | "
                f"confidence={conf} | source={src}")


# ── Service detection helpers ─────────────────────────────────────────

# Known API endpoint patterns mapped to services
API_ENDPOINT_PATTERNS = {
    AIService.OPENAI_CHATGPT: [
        "api.openai.com",
        "chatgpt.com",
        "chat.openai.com",
        "backend-api",
    ],
    AIService.ANTHROPIC_CLAUDE: [
        "api.anthropic.com",
        "claude.ai",
    ],
    AIService.GOOGLE_GEMINI: [
        "generativelanguage.googleapis.com",
        "gemini.google.com",
        "bard.google.com",
        "aistudio.google.com",
    ],
    AIService.MICROSOFT_COPILOT: [
        "copilot.microsoft.com",
        "sydney.bing.com",
        "api.bing.microsoft.com",
        "copilot.cloud.microsoft",
    ],
    AIService.PERPLEXITY: [
        "api.perplexity.ai",
        "perplexity.ai",
    ],
    AIService.XGROK: [
        "api.x.ai",
        "grok.x.ai",
    ],
    AIService.OLLAMA: [
        "localhost:11434",
        "127.0.0.1:11434",
        "/api/generate",
        "/api/chat",
    ],
    AIService.LM_STUDIO: [
        "localhost:1234",
        "127.0.0.1:1234",
        "localhost:1234/v1",
    ],
}

# Known session token cookie names per service
SESSION_COOKIE_PATTERNS = {
    AIService.OPENAI_CHATGPT: [
        "__Secure-next-auth.session-token",
        "__Secure-next-auth.callback-url",
        "_puid",
    ],
    AIService.ANTHROPIC_CLAUDE: [
        "sessionKey",
        "activitySessionId",
    ],
    AIService.GOOGLE_GEMINI: [
        "SID",
        "HSID",
        "SSID",
        "__Secure-1PSID",
    ],
    AIService.MICROSOFT_COPILOT: [
        "MUID",
        "SRCHUID",
        "BCP",
    ],
}

# Known API key prefixes
API_KEY_PATTERNS = {
    AIService.OPENAI_CHATGPT:    r"sk-[A-Za-z0-9]{48,}",
    AIService.ANTHROPIC_CLAUDE:  r"sk-ant-[A-Za-z0-9\-_]{90,}",
    AIService.GOOGLE_GEMINI:     r"AIza[A-Za-z0-9\-_]{35}",
    AIService.PERPLEXITY:        r"pplx-[A-Za-z0-9]{48}",
    AIService.XGROK:             r"xai-[A-Za-z0-9]{48,}",
}


def detect_service_from_url(url: str) -> AIService:
    """Infer AI service from a URL or hostname string."""
    url_lower = url.lower()
    for service, patterns in API_ENDPOINT_PATTERNS.items():
        for pattern in patterns:
            if pattern in url_lower:
                return service
    return AIService.UNKNOWN


def detect_service_from_cookie(cookie_name: str) -> AIService:
    """Infer AI service from a cookie name."""
    for service, patterns in SESSION_COOKIE_PATTERNS.items():
        if cookie_name in patterns:
            return service
    return AIService.UNKNOWN
