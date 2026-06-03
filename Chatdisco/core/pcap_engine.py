"""
PCAP engine.
tshark subprocess wrapper for protocol-aware stream reconstruction.
Handles HTTP/2 frame dissection, SSE stream reassembly, TLS metadata
extraction, DNS history, and conversation timing.
"""

import json
import re
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from chatdisco.parsers.base import (
    AIService, detect_service_from_url, ConversationRecord,
    Message, MessageRole, SessionIdentity, NetworkContext,
    TLSInfo, SourceType, Confidence
)

console = Console()


@dataclass
class RawStream:
    """A reassembled TCP/HTTP2 stream from tshark."""
    stream_id: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str           # HTTP/1.1, HTTP/2, WebSocket
    sni: Optional[str]
    host: Optional[str]
    request_method: Optional[str]
    request_uri: Optional[str]
    response_status: Optional[int]
    content_type: Optional[str]
    request_body: Optional[str]
    response_body: Optional[str]
    first_ts: Optional[str]
    last_ts: Optional[str]
    bytes_client: int = 0
    bytes_server: int = 0
    tls_info: Optional[TLSInfo] = None
    is_sse: bool = False
    sse_events: list = field(default_factory=list)


@dataclass
class PCAPResult:
    """Results from tshark PCAP analysis."""
    streams: list = field(default_factory=list)         # RawStream list
    ai_streams: list = field(default_factory=list)      # AI service streams
    dns_queries: list = field(default_factory=list)
    tls_handshakes: list = field(default_factory=list)
    certificates: list = field(default_factory=list)
    conversations: list = field(default_factory=list)   # ConversationRecord
    encrypted_unresolved: list = field(default_factory=list)
    decryption_applied: bool = False


class PCAPEngine:
    """
    Wraps tshark for AI chat PCAP analysis.
    """

    def __init__(self, tshark_binary: str = "tshark"):
        self.tshark = tshark_binary

    def run(
        self,
        pcap_path: Path,
        keylog_path: Optional[Path] = None,
        work_dir: Optional[Path] = None,
    ) -> PCAPResult:
        """
        Full analysis of a PCAP file.

        Args:
            pcap_path:   Input PCAP or pcapng file
            keylog_path: Optional TLS key log for decryption
            work_dir:    Working directory for temp files

        Returns:
            PCAPResult with reconstructed streams and conversations
        """
        result = PCAPResult()

        # Check tshark available
        if not self._check_tshark():
            console.print("[red]tshark not found[/red]")
            return result

        console.print(
            f"\n[bold blue]tshark[/bold blue] analysing {pcap_path.name}")

        # Classify streams - get all TCP connections with SNI/host
        self._classify_streams(pcap_path, keylog_path, result)

        # Extract DNS history
        self._extract_dns(pcap_path, result)

        # Extract TLS certificates (available even without decryption)
        self._extract_certificates(pcap_path, result)

        # Reconstruct HTTP streams for AI service endpoints
        self._reconstruct_ai_streams(
            pcap_path, keylog_path, result)

        # Build ConversationRecords from AI streams
        for stream in result.ai_streams:
            conv = self._stream_to_conversation(stream)
            if conv:
                result.conversations.append(conv)

        console.print(
            f"  [green]tshark complete:[/green] "
            f"{len(result.ai_streams)} AI streams, "
            f"{len(result.conversations)} conversations, "
            f"{len(result.encrypted_unresolved)} encrypted/unresolved")

        return result

    # ── Stream classification ──────────────────────────────────────────

    def _classify_streams(
        self,
        pcap_path: Path,
        keylog_path: Optional[Path],
        result: PCAPResult,
    ):
        """
        Use tshark to get all TCP connections with metadata.
        Identifies AI service connections by SNI and host headers.
        """
        cmd = self._base_cmd(pcap_path, keylog_path) + [
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "tcp.srcport",
            "-e", "ip.dst",
            "-e", "tcp.dstport",
            "-e", "tls.handshake.extensions_server_name",  # SNI
            "-e", "http.host",
            "-e", "http2.headers.authority",
            "-E", "header=n",
            "-E", "separator=|",
            "-Y", "tcp.flags.syn == 1 or tls.handshake.type == 1 "
                  "or http.host or http2.headers.authority",
        ]

        output = self._run_tshark(cmd, timeout=120)
        if not output:
            return

        seen_streams = set()
        for line in output.splitlines():
            parts = line.split("|")
            if len(parts) < 5:
                continue
            ts, src_ip, src_port, dst_ip, dst_port = parts[:5]
            sni = parts[5].strip() if len(parts) > 5 else ""
            host = parts[6].strip() if len(parts) > 6 else ""
            h2_auth = parts[7].strip() if len(parts) > 7 else ""

            hostname = sni or host or h2_auth or ""
            service = detect_service_from_url(hostname)

            stream_key = (src_ip, dst_ip, dst_port)
            if stream_key in seen_streams:
                continue
            seen_streams.add(stream_key)

            entry = {
                "src_ip":   src_ip.strip(),
                "src_port": src_port.strip(),
                "dst_ip":   dst_ip.strip(),
                "dst_port": dst_port.strip(),
                "sni":      sni,
                "host":     hostname,
                "service":  service.value,
                "ts":       ts.strip(),
            }

            if service != AIService.UNKNOWN:
                result.ai_streams.append(entry)
            elif hostname and "443" in dst_port:
                # HTTPS to unknown host - note as potentially relevant
                result.encrypted_unresolved.append(entry)

        result.decryption_applied = keylog_path is not None

    def _extract_dns(self, pcap_path: Path, result: PCAPResult):
        """Extract DNS query history."""
        cmd = self._base_cmd(pcap_path) + [
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "dns.qry.name",
            "-e", "dns.a",
            "-E", "header=n",
            "-E", "separator=|",
            "-Y", "dns.qry.name",
        ]
        output = self._run_tshark(cmd, timeout=60)
        if not output:
            return

        ai_domains = set()
        for svc, patterns in {
            "openai": ["openai.com", "chatgpt.com"],
            "anthropic": ["anthropic.com", "claude.ai"],
            "google_ai": ["gemini.google.com", "generativelanguage"],
            "copilot": ["copilot.microsoft.com", "sydney.bing.com"],
            "perplexity": ["perplexity.ai"],
            "xai": ["x.ai", "grok.x.ai"],
            "ollama_local": ["localhost"],
        }.items():
            ai_domains.update(patterns)

        for line in output.splitlines():
            parts = line.split("|")
            if len(parts) < 2:
                continue
            ts = parts[0].strip()
            name = parts[1].strip()
            addr = parts[2].strip() if len(parts) > 2 else ""
            if any(d in name for d in ai_domains):
                result.dns_queries.append({
                    "timestamp": ts,
                    "query": name,
                    "response_ip": addr,
                })

    def _extract_certificates(self, pcap_path: Path, result: PCAPResult):
        """Extract TLS certificate metadata from handshakes."""
        cmd = self._base_cmd(pcap_path) + [
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tls.handshake.extensions_server_name",
            "-e", "x509sat.uTF8String",
            "-e", "tls.handshake.certificate",
            "-E", "header=n",
            "-E", "separator=|",
            "-Y", "tls.handshake.type == 11",  # Certificate message
        ]
        output = self._run_tshark(cmd, timeout=60)
        if not output:
            return

        for line in output.splitlines():
            parts = line.split("|")
            if len(parts) < 3:
                continue
            result.certificates.append({
                "timestamp": parts[0].strip(),
                "src": parts[1].strip(),
                "dst": parts[2].strip(),
                "sni": parts[3].strip() if len(parts) > 3 else "",
                "subject": parts[4].strip() if len(parts) > 4 else "",
            })

    # ── Stream reconstruction ──────────────────────────────────────────

    def _reconstruct_ai_streams(
        self,
        pcap_path: Path,
        keylog_path: Optional[Path],
        result: PCAPResult,
    ):
        """
        For each identified AI service connection, follow the stream
        and reconstruct the HTTP exchange including SSE responses.
        """
        if not result.ai_streams:
            return

        # Get all HTTP/2 streams in JSON format
        cmd = self._base_cmd(pcap_path, keylog_path) + [
            "-T", "json",
            "-Y", "http2 or http",
            "--no-duplicate-keys",
        ]

        output = self._run_tshark(cmd, timeout=300)
        if not output:
            return

        try:
            packets = json.loads(output)
        except json.JSONDecodeError:
            # tshark can output multiple JSON objects; try line-by-line
            packets = []
            for line in output.splitlines():
                try:
                    packets.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        # Group packets by stream and reconstruct
        streams_by_id = {}
        for pkt in packets:
            layers = pkt.get("_source", {}).get("layers", {})
            stream_id = (
                layers.get("tcp", {}).get("tcp.stream") or
                layers.get("http2", {}).get("http2.streamid", "0")
            )
            if stream_id not in streams_by_id:
                streams_by_id[stream_id] = []
            streams_by_id[stream_id].append(layers)

        for stream_id, layers_list in streams_by_id.items():
            stream = self._reconstruct_stream(stream_id, layers_list)
            if stream and stream.host:
                svc = detect_service_from_url(stream.host)
                if svc != AIService.UNKNOWN:
                    result.ai_streams.append(stream)

    def _reconstruct_stream(
        self, stream_id, layers_list: list
    ) -> Optional[RawStream]:
        """Reconstruct a single HTTP stream from packet layers."""
        stream = None
        request_body_parts = []
        response_body_parts = []

        for layers in layers_list:
            ip = layers.get("ip", {})
            tcp = layers.get("tcp", {})
            http = layers.get("http", {})
            http2 = layers.get("http2", {})

            if not stream:
                stream = RawStream(
                    stream_id=int(stream_id) if stream_id else 0,
                    src_ip=ip.get("ip.src", ""),
                    src_port=int(tcp.get("tcp.srcport", 0) or 0),
                    dst_ip=ip.get("ip.dst", ""),
                    dst_port=int(tcp.get("tcp.dstport", 0) or 0),
                    protocol="HTTP/2" if http2 else "HTTP/1.1",
                    sni=None,
                    host=None,
                    request_method=None,
                    request_uri=None,
                    response_status=None,
                    content_type=None,
                    request_body=None,
                    response_body=None,
                    first_ts=layers.get(
                        "frame", {}).get("frame.time_epoch"),
                    last_ts=None,
                )

            # HTTP/1.1 fields
            if http:
                stream.host = (http.get("http.host") or
                               stream.host)
                stream.request_method = (
                    http.get("http.request.method") or
                    stream.request_method)
                stream.request_uri = (
                    http.get("http.request.full_uri") or
                    stream.request_uri)
                status = http.get("http.response.code")
                if status:
                    stream.response_status = int(status)
                ct = http.get("http.content_type", "")
                if ct:
                    stream.content_type = ct
                    if "event-stream" in ct:
                        stream.is_sse = True
                body = http.get("http.file_data", "")
                if body:
                    response_body_parts.append(body)

            # HTTP/2 fields
            if http2:
                headers = http2.get("http2.header", {})
                if isinstance(headers, list):
                    for h in headers:
                        name = h.get("http2.header.name", "")
                        value = h.get("http2.header.value", "")
                        if name == ":authority":
                            stream.host = value
                        elif name == ":method":
                            stream.request_method = value
                        elif name == ":path":
                            stream.request_uri = value
                        elif name == ":status":
                            try:
                                stream.response_status = int(value)
                            except (ValueError, TypeError):
                                pass
                        elif name == "content-type":
                            stream.content_type = value
                            if "event-stream" in value:
                                stream.is_sse = True
                data = http2.get("http2.data.data", "")
                if data:
                    response_body_parts.append(data)

        if stream and response_body_parts:
            stream.response_body = "\n".join(response_body_parts)
            if stream.is_sse:
                stream.sse_events = self._parse_sse(stream.response_body)

        return stream

    def _parse_sse(self, raw_body: str) -> list:
        """
        Parse Server-Sent Events stream into individual events.
        Handles the 'data: {...}' format used by all major AI APIs.
        """
        events = []
        for line in raw_body.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                data_str = line[5:].strip()
                if data_str == "[DONE]":
                    break
                try:
                    obj = json.loads(data_str)
                    events.append(obj)
                except json.JSONDecodeError:
                    if data_str:
                        events.append({"raw": data_str})
        return events

    # ── Conversation building ──────────────────────────────────────────

    def _stream_to_conversation(
        self, stream
    ) -> Optional[ConversationRecord]:
        """
        Convert a RawStream into a ConversationRecord.
        Handles both REST response bodies and SSE streams.
        """
        if isinstance(stream, dict):
            # Entry from classification phase (not yet reconstructed)
            return None

        host = stream.host or ""
        service = detect_service_from_url(host)

        conv = ConversationRecord(
            service=service,
            source_type=SourceType.PCAP_STREAM,
            network=NetworkContext(
                src_ip=stream.src_ip,
                src_port=stream.src_port,
                dst_ip=stream.dst_ip,
                dst_port=stream.dst_port,
                protocol=stream.protocol,
                stream_id=stream.stream_id,
                first_packet_ts=stream.first_ts,
                last_packet_ts=stream.last_ts,
                tls=stream.tls_info,
            ),
        )

        # Try to extract conversation from SSE events
        if stream.is_sse and stream.sse_events:
            self._reconstruct_from_sse(conv, stream)
        elif stream.response_body:
            self._reconstruct_from_body(conv, stream)

        if conv.message_count == 0:
            return None

        conv.confidence = (Confidence.HIGH if stream.is_sse
                           and not stream.partial
                           else Confidence.MEDIUM)
        return conv

    def _reconstruct_from_sse(
        self,
        conv: ConversationRecord,
        stream: RawStream,
    ):
        """
        Reconstruct conversation turns from SSE event stream.
        Handles OpenAI, Anthropic, Gemini, Perplexity SSE schemas.
        """
        # Extract user message from request body if available
        if stream.request_body:
            try:
                req = json.loads(stream.request_body)
                messages = req.get("messages", [])
                for msg in messages:
                    role_str = msg.get("role", "unknown")
                    role = MessageRole.USER if role_str == "user" \
                        else MessageRole.SYSTEM if role_str == "system" \
                        else MessageRole.ASSISTANT
                    content = msg.get("content", "")
                    if isinstance(content, list):
                        # Anthropic content blocks
                        content = " ".join(
                            b.get("text", "") for b in content
                            if isinstance(b, dict))
                    if content:
                        conv.add_message(
                            role=role,
                            content=content,
                            source_type=SourceType.PCAP_STREAM,
                        )
                        # Extract identity from request
                        if "user" in req:
                            conv.identity.user_id = req["user"]
                        if "conversation_id" in req:
                            conv.identity.conversation_id = \
                                req["conversation_id"]
            except (json.JSONDecodeError, AttributeError):
                pass

        # Reconstruct assistant response from SSE delta chunks
        assistant_content = []
        model = None

        for event in stream.sse_events:
            if not isinstance(event, dict):
                continue

            # OpenAI format: choices[0].delta.content
            choices = event.get("choices", [])
            if choices:
                delta = choices[0].get("delta", {})
                content = delta.get("content", "")
                if content:
                    assistant_content.append(content)
                if not model:
                    model = event.get("model")
                # Extract IDs
                if not conv.identity.conversation_id:
                    conv.identity.conversation_id = event.get("id")

            # Anthropic format: delta.text
            elif event.get("type") == "content_block_delta":
                delta = event.get("delta", {})
                text = delta.get("text", "")
                if text:
                    assistant_content.append(text)

            # Gemini format: candidates[0].content.parts[0].text
            elif "candidates" in event:
                for candidate in event.get("candidates", []):
                    for part in candidate.get("content", {}).get(
                            "parts", []):
                        text = part.get("text", "")
                        if text:
                            assistant_content.append(text)

        if assistant_content:
            full_content = "".join(assistant_content)
            conv.add_message(
                role=MessageRole.ASSISTANT,
                content=full_content,
                model=model,
                source_type=SourceType.PCAP_STREAM,
            )
            if model:
                conv.model = model

    def _reconstruct_from_body(
        self,
        conv: ConversationRecord,
        stream: RawStream,
    ):
        """
        Extract conversation from non-streaming REST response body.
        Used for local LLM APIs (Ollama, LM Studio) and batch endpoints.
        """
        if not stream.response_body:
            return
        try:
            body = json.loads(stream.response_body)
        except json.JSONDecodeError:
            return

        # Ollama /api/chat response
        if "message" in body:
            msg = body["message"]
            role_str = msg.get("role", "assistant")
            content = msg.get("content", "")
            if content:
                conv.add_message(
                    role=MessageRole.ASSISTANT
                         if role_str == "assistant"
                         else MessageRole.USER,
                    content=content,
                    model=body.get("model"),
                    source_type=SourceType.PCAP_STREAM,
                )
                conv.model = body.get("model")

        # OpenAI-compatible /v1/chat/completions (non-streaming)
        elif "choices" in body:
            for choice in body.get("choices", []):
                msg = choice.get("message", {})
                content = msg.get("content", "")
                if content:
                    conv.add_message(
                        role=MessageRole.ASSISTANT,
                        content=content,
                        model=body.get("model"),
                        source_type=SourceType.PCAP_STREAM,
                    )
            conv.model = body.get("model")

    # ── Utilities ──────────────────────────────────────────────────────

    def _base_cmd(
        self,
        pcap_path: Path,
        keylog_path: Optional[Path] = None,
    ) -> list:
        """Build base tshark command with optional TLS decryption."""
        cmd = [self.tshark, "-r", str(pcap_path), "-q"]
        if keylog_path and keylog_path.exists():
            cmd += ["-o", f"tls.keylog_file:{keylog_path}"]
        return cmd

    def _run_tshark(
        self,
        cmd: list,
        timeout: int = 300,
    ) -> Optional[str]:
        """Run a tshark command and return stdout."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode not in (0, 1):
                # tshark returns 1 for some warnings
                console.print(
                    f"[dim]tshark warning: {result.stderr[:200]}[/dim]")
            return result.stdout
        except subprocess.TimeoutExpired:
            console.print("[yellow]tshark timed out[/yellow]")
            return None
        except FileNotFoundError:
            console.print("[red]tshark not found[/red]")
            return None

    def _check_tshark(self) -> bool:
        """Verify tshark is available."""
        try:
            subprocess.run(
                [self.tshark, "--version"],
                capture_output=True,
                timeout=10,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
