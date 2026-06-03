"""
bulk_extractor engine wrapper.

Manages bulk_extractor subprocess execution, scanner selection,
output parsing, and feature file ingestion. Used for byte-stream
carving of JSON fragments, URLs, base64, x509 certificates,
network packets, and cookie material from any input type.
"""

import os
import re
import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@dataclass
class BEFeature:
    """A single feature extracted by bulk_extractor."""
    offset: str           # Forensic path (offset or compound path)
    feature: str          # Extracted feature value
    context: str          # Surrounding context bytes
    scanner: str          # Which scanner found this
    source_file: str      # Which feature file it came from


@dataclass
class BEResult:
    """Results from a bulk_extractor run."""
    output_dir: str
    feature_files: dict = field(default_factory=dict)  # name -> Path
    packets_pcap: Optional[Path] = None
    json_fragments: list = field(default_factory=list)
    urls: list = field(default_factory=list)
    base64_items: list = field(default_factory=list)
    x509_certs: list = field(default_factory=list)
    cookies: list = field(default_factory=list)
    email_addresses: list = field(default_factory=list)
    ip_addresses: list = field(default_factory=list)
    tls_key_candidates: list = field(default_factory=list)
    ai_service_hits: list = field(default_factory=list)


# Scanners relevant to AI chat forensics
# Format: (scanner_name, flag, purpose)
FORENSIC_SCANNERS = [
    ("json",       "-e json",       "JSON fragments (API responses, config)"),
    ("url",        "-e url",        "URLs and HTTP references"),
    ("base64",     "-e base64",     "Base64-encoded data (JWTs, tokens)"),
    ("email",      "-e email",      "Email addresses (user identity)"),
    ("net",        "-e net",        "Network packets → packets.pcap"),
    ("httplogs",   "-e httplogs",   "HTTP request/response logs"),
    ("cookiefile", "-e cookiefile", "Browser cookies"),
    ("x509",       "-e x509",       "TLS certificates"),
    ("aes_keys",   "-e aes_keys",   "AES key material"),
    ("find",       None,            "Configurable pattern search"),
]

# TLS key log label patterns for -find scanner
TLS_KEY_LABELS = [
    "CLIENT_RANDOM",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
]

# AI service URL patterns for bulk_extractor find scanner
AI_URL_PATTERNS = [
    "api.openai.com",
    "chatgpt.com",
    "chat.openai.com",
    "api.anthropic.com",
    "claude.ai",
    "generativelanguage.googleapis.com",
    "gemini.google.com",
    "copilot.microsoft.com",
    "sydney.bing.com",
    "perplexity.ai",
    "api.perplexity.ai",
    "api.x.ai",
    "grok.x.ai",
    "conversation_id",
    "session-token",
    "CLIENT_RANDOM",
    "sk-ant-",
    "AIza",
    "pplx-",
]


class BEEngine:
    """
    Wraps bulk_extractor for AI chat forensics.

    Selects appropriate scanners based on input type, runs
    bulk_extractor, parses feature files, and returns structured
    results for downstream AI chat parsers.
    """

    def __init__(
        self,
        be_binary: str = "bulk_extractor",
        threads: int = 0,          # 0 = auto-detect
        page_size: int = 16777216, # 16MB pages
    ):
        self.be_binary  = be_binary
        self.threads    = threads
        self.page_size  = page_size

    def run(
        self,
        input_path: Path,
        output_dir: Path,
        input_type: str = "generic",
        extra_patterns: Optional[list] = None,
    ) -> BEResult:
        """
        Run bulk_extractor on input_path, write features to output_dir.

        Args:
            input_path:      File or directory to scan
            output_dir:      Where to write feature files
            input_type:      Hint for scanner selection
            extra_patterns:  Additional regex patterns for find scanner

        Returns:
            BEResult with all extracted features parsed and categorised
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = self._build_command(
            input_path, output_dir, input_type, extra_patterns)

        console.print(
            f"\n[bold blue]bulk_extractor[/bold blue] scanning "
            f"{input_path.name}...")
        console.print(f"  Command: {' '.join(cmd[:6])}...")

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task(
                    f"Scanning {input_path.name}", total=None)

                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=7200,  # 2 hour timeout for large dumps
                )

                progress.update(task, completed=True)

            if proc.returncode != 0:
                console.print(
                    f"[yellow]bulk_extractor returned "
                    f"{proc.returncode}[/yellow]")
                if proc.stderr:
                    console.print(f"[dim]{proc.stderr[:500]}[/dim]")

        except subprocess.TimeoutExpired:
            console.print("[red]bulk_extractor timed out[/red]")
            return BEResult(output_dir=str(output_dir))
        except FileNotFoundError:
            console.print(
                "[red]bulk_extractor not found. "
                "Check installation.[/red]")
            return BEResult(output_dir=str(output_dir))

        # Parse results
        result = self._parse_output(output_dir)
        self._classify_ai_hits(result)

        console.print(
            f"  [green]bulk_extractor complete:[/green] "
            f"{len(result.json_fragments)} JSON fragments, "
            f"{len(result.urls)} URLs, "
            f"{len(result.tls_key_candidates)} TLS key candidates")

        return result

    def _build_command(
        self,
        input_path: Path,
        output_dir: Path,
        input_type: str,
        extra_patterns: Optional[list],
    ) -> list:
        """Build the bulk_extractor command line."""
        cmd = [self.be_binary]

        # Disable all scanners first, then enable what we need
        cmd += ["-x", "all"]

        # Always enable these
        cmd += ["-e", "json"]
        cmd += ["-e", "url"]
        cmd += ["-e", "base64"]
        cmd += ["-e", "email"]
        cmd += ["-e", "x509"]
        cmd += ["-e", "aes_keys"]

        # Enable net scanner for memory/disk inputs (not PCAP)
        if input_type not in ("pcap",):
            cmd += ["-e", "net"]

        # Enable httplogs and cookiefile always
        cmd += ["-e", "httplogs"]
        cmd += ["-e", "cookiefile"]

        # Build find patterns
        patterns = TLS_KEY_LABELS + AI_URL_PATTERNS
        if extra_patterns:
            patterns += extra_patterns

        for pattern in patterns:
            cmd += ["-F", pattern]

        # Threading
        if self.threads > 0:
            cmd += ["-j", str(self.threads)]

        # Page size
        cmd += ["-G", str(self.page_size)]

        # Output and input
        cmd += ["-o", str(output_dir)]
        cmd += [str(input_path)]

        return cmd

    def _parse_output(self, output_dir: Path) -> BEResult:
        """Parse all feature files in output_dir into BEResult."""
        result = BEResult(output_dir=str(output_dir))

        # Index feature files
        for f in output_dir.glob("*.txt"):
            result.feature_files[f.stem] = f

        # Check for carved PCAP
        pcap_path = output_dir / "packets.pcap"
        if pcap_path.exists():
            result.packets_pcap = pcap_path

        # Parse each feature file
        parsers = {
            "json":       self._parse_json_file,
            "url":        self._parse_url_file,
            "base64":     self._parse_base64_file,
            "x509":       self._parse_x509_file,
            "cookiefile": self._parse_cookie_file,
            "email":      self._parse_email_file,
            "ip":         self._parse_ip_file,
            "find":       self._parse_find_file,
        }

        for name, parser in parsers.items():
            # bulk_extractor uses various naming conventions
            for variant in [name, f"{name}_histogram",
                            f"ether_histogram", f"url_searches"]:
                fpath = result.feature_files.get(variant)
                if fpath and fpath.exists():
                    try:
                        parser(fpath, result)
                    except Exception as e:
                        console.print(
                            f"[dim]Warning: failed to parse "
                            f"{fpath.name}: {e}[/dim]")

        return result

    def _read_feature_file(self, path: Path) -> list:
        """
        Read a bulk_extractor feature file.
        Format: offset<TAB>feature<TAB>context
        Lines starting with # are comments.
        """
        features = []
        try:
            with open(path, 'r', errors='replace',
                      encoding='utf-8') as f:
                for line in f:
                    line = line.rstrip('\n\r')
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split('\t', 2)
                    if len(parts) >= 2:
                        features.append(BEFeature(
                            offset=parts[0],
                            feature=parts[1],
                            context=parts[2] if len(parts) > 2 else "",
                            scanner=path.stem,
                            source_file=str(path),
                        ))
        except (IOError, UnicodeDecodeError):
            pass
        return features

    def _parse_json_file(self, path: Path, result: BEResult):
        """Parse json.txt - attempt to reconstruct valid JSON objects."""
        for feat in self._read_feature_file(path):
            raw = feat.feature.strip()
            if not raw:
                continue
            # Attempt JSON parse
            try:
                obj = json.loads(raw)
                result.json_fragments.append({
                    "offset": feat.offset,
                    "parsed": obj,
                    "raw": raw,
                })
            except json.JSONDecodeError:
                # Store as raw fragment even if not fully parseable
                if len(raw) > 20:
                    result.json_fragments.append({
                        "offset": feat.offset,
                        "parsed": None,
                        "raw": raw,
                    })

    def _parse_url_file(self, path: Path, result: BEResult):
        for feat in self._read_feature_file(path):
            if feat.feature.startswith(('http://', 'https://', 'ftp://')):
                result.urls.append({
                    "offset": feat.offset,
                    "url": feat.feature,
                    "context": feat.context[:200],
                })

    def _parse_base64_file(self, path: Path, result: BEResult):
        JWT_PATTERN = re.compile(r'^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.'
                                  r'[A-Za-z0-9_\-]*$')
        for feat in self._read_feature_file(path):
            entry = {
                "offset": feat.offset,
                "data": feat.feature,
                "is_jwt": bool(JWT_PATTERN.match(feat.feature)),
            }
            result.base64_items.append(entry)

    def _parse_x509_file(self, path: Path, result: BEResult):
        for feat in self._read_feature_file(path):
            result.x509_certs.append({
                "offset": feat.offset,
                "cert_data": feat.feature,
            })

    def _parse_cookie_file(self, path: Path, result: BEResult):
        for feat in self._read_feature_file(path):
            result.cookies.append({
                "offset": feat.offset,
                "cookie": feat.feature,
                "context": feat.context[:300],
            })

    def _parse_email_file(self, path: Path, result: BEResult):
        for feat in self._read_feature_file(path):
            if '@' in feat.feature:
                result.email_addresses.append({
                    "offset": feat.offset,
                    "email": feat.feature,
                })

    def _parse_ip_file(self, path: Path, result: BEResult):
        for feat in self._read_feature_file(path):
            result.ip_addresses.append({
                "offset": feat.offset,
                "ip": feat.feature,
            })

    def _parse_find_file(self, path: Path, result: BEResult):
        """Parse find.txt for TLS key labels and AI URL patterns."""
        TLS_RE = re.compile(
            r'(CLIENT_RANDOM|CLIENT_EARLY_TRAFFIC_SECRET|'
            r'CLIENT_HANDSHAKE_TRAFFIC_SECRET|'
            r'SERVER_HANDSHAKE_TRAFFIC_SECRET|'
            r'CLIENT_TRAFFIC_SECRET_0|SERVER_TRAFFIC_SECRET_0|'
            r'EXPORTER_SECRET)'
            r'\s+([0-9a-fA-F]{64})\s+([0-9a-fA-F]+)'
        )
        for feat in self._read_feature_file(path):
            combined = feat.feature + " " + feat.context
            m = TLS_RE.search(combined)
            if m:
                result.tls_key_candidates.append({
                    "offset":  feat.offset,
                    "label":   m.group(1),
                    "client_random": m.group(2),
                    "secret":  m.group(3),
                    "raw_line": f"{m.group(1)} {m.group(2)} {m.group(3)}",
                })

    def _classify_ai_hits(self, result: BEResult):
        """
        Post-process results to tag AI service hits across all
        feature types and populate result.ai_service_hits.
        """
        from chatdisco.parsers.base import detect_service_from_url

        seen = set()

        for url_entry in result.urls:
            url = url_entry.get("url", "")
            svc = detect_service_from_url(url)
            if svc.value != "unknown" and url not in seen:
                seen.add(url)
                result.ai_service_hits.append({
                    "type":    "url",
                    "service": svc.value,
                    "value":   url,
                    "offset":  url_entry.get("offset"),
                })

        # Check JSON fragments for known API response structures
        for frag in result.json_fragments:
            if not frag.get("parsed"):
                continue
            obj = frag["parsed"]
            if isinstance(obj, dict):
                # OpenAI conversation_id
                if "conversation_id" in obj:
                    result.ai_service_hits.append({
                        "type":    "json_field",
                        "service": "openai_chatgpt",
                        "value":   obj.get("conversation_id"),
                        "offset":  frag.get("offset"),
                        "field":   "conversation_id",
                    })
                # Anthropic message structure
                if obj.get("type") == "message" and "content" in obj:
                    result.ai_service_hits.append({
                        "type":    "json_field",
                        "service": "anthropic_claude",
                        "value":   str(obj.get("id", "")),
                        "offset":  frag.get("offset"),
                        "field":   "message",
                    })

        # JWT / Bearer tokens
        for b64 in result.base64_items:
            if b64.get("is_jwt"):
                result.ai_service_hits.append({
                    "type":    "jwt_token",
                    "service": "unknown",
                    "value":   b64["data"][:64] + "...",
                    "offset":  b64.get("offset"),
                })

    def carve_tls_keylog(self, result: BEResult) -> Optional[str]:
        """
        Attempt to reconstruct a valid SSLKEYLOGFILE from
        bulk_extractor find results.

        Returns keylog file content string if any keys found,
        else None.
        """
        if not result.tls_key_candidates:
            return None

        lines = ["# Chatdisco: TLS keys carved from memory/disk artifact"]
        seen = set()

        for candidate in result.tls_key_candidates:
            line = candidate.get("raw_line", "").strip()
            if line and line not in seen:
                # Basic validation: label + 64 hex + hex
                parts = line.split()
                if (len(parts) == 3
                        and len(parts[1]) == 64
                        and all(c in '0123456789abcdefABCDEF'
                                for c in parts[1])):
                    lines.append(line)
                    seen.add(line)

        if len(lines) <= 1:
            return None

        console.print(
            f"  [green]Carved {len(lines)-1} TLS key entries "
            f"from bulk_extractor output[/green]")
        return "\n".join(lines) + "\n"
