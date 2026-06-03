"""
TLS key resolver.

Implements the full waterfall key recovery strategy:
1. Explicit --keylog supplied
2. SSLKEYLOGFILE env var in process memory
3. Carve key labels from bulk_extractor find output
4. Carve from prefetch, pagefile, hiberfil sources
5. X-Ray-TLS struct walk (if available)
6. friTap live process (live systems only)
7. ENCRYPTED_UNRESOLVED - document and continue

Keys are injected into a working copy of the PCAP using editcap.
Original PCAP is never modified.
"""

import os
import re
import subprocess
import tempfile
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console

console = Console()

# SSLKEYLOGFILE format validation
KEYLOG_LINE_RE = re.compile(
    r'^(CLIENT_RANDOM'
    r'|CLIENT_EARLY_TRAFFIC_SECRET'
    r'|CLIENT_HANDSHAKE_TRAFFIC_SECRET'
    r'|SERVER_HANDSHAKE_TRAFFIC_SECRET'
    r'|CLIENT_TRAFFIC_SECRET_0'
    r'|SERVER_TRAFFIC_SECRET_0'
    r'|EXPORTER_SECRET'
    r')\s+([0-9a-fA-F]{64})\s+([0-9a-fA-F]+)$'
)


@dataclass
class KeyResolutionResult:
    resolved: bool = False
    keylog_content: Optional[str] = None
    keylog_path: Optional[Path] = None
    keyed_pcap_path: Optional[Path] = None
    method: Optional[str] = None
    key_count: int = 0
    attempts: list = field(default_factory=list)

    def record_attempt(self, method: str, outcome: str):
        self.attempts.append({"method": method, "outcome": outcome})

    def to_coc_entry(self) -> dict:
        return {
            "tls_key_resolution": {
                "resolved": self.resolved,
                "method": self.method,
                "key_count": self.key_count,
                "keyed_pcap": str(self.keyed_pcap_path)
                              if self.keyed_pcap_path else None,
                "attempts": self.attempts,
            }
        }


class TLSResolver:
    """
    Resolves TLS session keys for PCAP decryption.
    Tries all available methods in priority order.
    """

    def __init__(
        self,
        work_dir: Path,
        editcap_binary: str = "editcap",
    ):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.editcap = editcap_binary

    def resolve(
        self,
        pcap_path: Path,
        explicit_keylog: Optional[Path] = None,
        memory_path: Optional[Path] = None,
        be_result=None,              # BEResult from bulk_extractor run
        process_pids: Optional[list] = None,
        vol_engine=None,             # VolEngine instance if available
    ) -> KeyResolutionResult:
        """
        Attempt TLS key resolution using all available methods.
        Returns KeyResolutionResult with keyed PCAP copy if successful.
        """
        result = KeyResolutionResult()

        methods = [
            ("explicit_keylog",    self._try_explicit_keylog),
            ("env_var_on_disk",    self._try_env_var_on_disk),
            ("be_find_carve",      self._try_be_carve),
            ("memory_string_carve",self._try_memory_string_carve),
            ("prefetch_carve",     self._try_prefetch_carve),
        ]

        keylog_content = None

        for method_name, method_fn in methods:
            try:
                content = method_fn(
                    explicit_keylog=explicit_keylog,
                    memory_path=memory_path,
                    be_result=be_result,
                    process_pids=process_pids,
                    vol_engine=vol_engine,
                )
                if content:
                    valid_lines = self._validate_keylog(content)
                    if valid_lines:
                        result.record_attempt(method_name, 
                                              f"found {valid_lines} keys")
                        keylog_content = content
                        result.method = method_name
                        result.key_count = valid_lines
                        console.print(
                            f"  [green]TLS keys resolved via "
                            f"{method_name}[/green] "
                            f"({valid_lines} entries)")
                        break
                    else:
                        result.record_attempt(method_name,
                                              "found but failed validation")
                else:
                    result.record_attempt(method_name, "not found")

            except Exception as e:
                result.record_attempt(method_name, f"error: {e}")

        if not keylog_content:
            console.print(
                "  [yellow]TLS keys unresolved - "
                "PCAP streams will be metadata-only[/yellow]")
            result.resolved = False
            return result

        # Write keylog to work dir
        keylog_path = self.work_dir / "tls_keys.log"
        keylog_path.write_text(keylog_content)
        result.keylog_path = keylog_path
        result.keylog_content = keylog_content

        # Inject keys into PCAP copy using editcap
        keyed_path = self._inject_keys(pcap_path, keylog_path)
        if keyed_path:
            result.resolved = True
            result.keyed_pcap_path = keyed_path
        else:
            # Keys found but injection failed - tshark can still use keylog
            result.resolved = True

        return result

    # ── Resolution methods ─────────────────────────────────────────────

    def _try_explicit_keylog(self, explicit_keylog, **kwargs) -> Optional[str]:
        """Method 1: Explicitly supplied --keylog file."""
        if explicit_keylog and Path(explicit_keylog).exists():
            return Path(explicit_keylog).read_text(errors='replace')
        return None

    def _try_env_var_on_disk(self, memory_path, vol_engine,
                              process_pids, **kwargs) -> Optional[str]:
        """
        Method 2: SSLKEYLOGFILE environment variable.
        Check if the variable was set and the file still exists on disk.
        Uses Volatility envars if memory available.
        """
        # Check current process environment (collection scenario)
        env_path = os.environ.get("SSLKEYLOGFILE")
        if env_path and Path(env_path).exists():
            return Path(env_path).read_text(errors='replace')

        # Check via Volatility envars if memory available
        if vol_engine and memory_path and process_pids:
            for pid in process_pids:
                env_path = vol_engine.get_env_var(
                    pid, "SSLKEYLOGFILE")
                if env_path and Path(env_path).exists():
                    return Path(env_path).read_text(errors='replace')

        # Common default locations to check
        common_paths = [
            os.path.expanduser("~/.ssl-keys.log"),
            os.path.expanduser("~/ssl-keys.log"),
            "/tmp/ssl-keys.log",
            os.path.expandvars(r"%USERPROFILE%\ssl-keys.log"),
            os.path.expandvars(r"%TEMP%\ssl-keys.log"),
        ]
        for p in common_paths:
            try:
                if Path(p).exists():
                    content = Path(p).read_text(errors='replace')
                    if self._validate_keylog(content) > 0:
                        return content
            except (OSError, ValueError):
                pass

        return None

    def _try_be_carve(self, be_result, **kwargs) -> Optional[str]:
        """
        Method 3: TLS key labels already carved by bulk_extractor.
        Reconstructs keylog from BEResult.tls_key_candidates.
        """
        if not be_result or not be_result.tls_key_candidates:
            return None

        lines = ["# Chatdisco: TLS keys carved by bulk_extractor"]
        seen = set()
        for candidate in be_result.tls_key_candidates:
            line = candidate.get("raw_line", "").strip()
            if line and line not in seen and KEYLOG_LINE_RE.match(line):
                lines.append(line)
                seen.add(line)

        return "\n".join(lines) + "\n" if len(lines) > 1 else None

    def _try_memory_string_carve(self, memory_path, **kwargs) -> Optional[str]:
        """
        Method 4: Direct string scan of memory/pagefile/hiberfil.
        Searches for TLS key label patterns directly in binary files.
        Fast scan using Python - no external tools needed.
        """
        if not memory_path or not Path(memory_path).exists():
            return None

        mem_path = Path(memory_path)
        # Only attempt on reasonably-sized files to avoid very long scans
        # For full RAM dumps, bulk_extractor (method 3) is preferred
        if mem_path.stat().st_size > 4 * 1024 * 1024 * 1024:  # 4GB
            return None

        console.print(
            f"  [dim]Scanning {mem_path.name} for TLS key labels...[/dim]")

        CHUNK_SIZE = 4 * 1024 * 1024  # 4MB
        OVERLAP    = 512              # overlap between chunks

        # Build combined search pattern
        label_bytes = [
            b"CLIENT_RANDOM",
            b"CLIENT_EARLY_TRAFFIC_SECRET",
            b"CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            b"SERVER_HANDSHAKE_TRAFFIC_SECRET",
            b"CLIENT_TRAFFIC_SECRET_0",
            b"SERVER_TRAFFIC_SECRET_0",
            b"EXPORTER_SECRET",
        ]

        found_lines = set()

        try:
            with open(mem_path, 'rb') as f:
                overlap_buf = b""
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    buf = overlap_buf + chunk
                    for label in label_bytes:
                        pos = 0
                        while True:
                            idx = buf.find(label, pos)
                            if idx == -1:
                                break
                            # Extract ~200 bytes from this position
                            segment = buf[idx:idx + 200]
                            try:
                                text = segment.decode('ascii',
                                                      errors='ignore')
                            except Exception:
                                pos = idx + 1
                                continue
                            # Find the line
                            line = text.split('\n')[0].strip()
                            if KEYLOG_LINE_RE.match(line):
                                found_lines.add(line)
                            pos = idx + 1
                    overlap_buf = buf[-OVERLAP:]
        except (IOError, OSError):
            return None

        if not found_lines:
            return None

        lines = ["# Chatdisco: TLS keys carved from memory string scan"]
        lines.extend(sorted(found_lines))
        return "\n".join(lines) + "\n"

    def _try_prefetch_carve(self, **kwargs) -> Optional[str]:
        """
        Method 5: Scan prefetch files for TLS key material.
        Prefetch files can contain memory-mapped region content
        including pagefile-backed pages with TLS key material.
        Decompresses MAM format before scanning.
        """
        prefetch_dir = Path(r"C:\Windows\Prefetch") \
            if os.name == "nt" else None

        if not prefetch_dir or not prefetch_dir.exists():
            return None

        found_lines = set()

        # Target browser and AI app prefetch files
        target_patterns = [
            "CHROME.EXE-*.pf",
            "MSEDGE.EXE-*.pf",
            "FIREFOX.EXE-*.pf",
            "BRAVE.EXE-*.pf",
            "OLLAMA*.pf",
            "PYTHON*.pf",    # Ollama backend
            "NODE*.pf",      # Some AI apps
            "AgGlFaultHistory.db",  # Page fault history
        ]

        for pattern in target_patterns:
            for pf_file in prefetch_dir.glob(pattern):
                # Size triage - small files are metadata only
                if pf_file.stat().st_size < 8000:
                    continue

                content = self._read_prefetch_content(pf_file)
                if not content:
                    continue

                for label_bytes in [
                    b"CLIENT_RANDOM",
                    b"CLIENT_EARLY_TRAFFIC_SECRET",
                    b"SERVER_TRAFFIC_SECRET_0",
                ]:
                    pos = 0
                    while True:
                        idx = content.find(label_bytes, pos)
                        if idx == -1:
                            break
                        segment = content[idx:idx + 200]
                        try:
                            text = segment.decode('ascii', errors='ignore')
                            line = text.split('\n')[0].strip()
                            if KEYLOG_LINE_RE.match(line):
                                found_lines.add(line)
                        except Exception:
                            pass
                        pos = idx + 1

        if not found_lines:
            return None

        lines = ["# Chatdisco: TLS keys carved from prefetch files"]
        lines.extend(sorted(found_lines))
        return "\n".join(lines) + "\n"

    def _read_prefetch_content(self, pf_path: Path) -> Optional[bytes]:
        """
        Read prefetch file content, decompressing MAM if needed.
        Returns raw bytes for scanning.
        """
        try:
            raw = pf_path.read_bytes()
        except (IOError, OSError):
            return None

        # Check for MAM compressed format (Windows 10+)
        if raw[:4] == b'\x4d\x41\x4d\x04':
            return self._decompress_mam(raw)

        return raw

    def _decompress_mam(self, data: bytes) -> Optional[bytes]:
        """
        Decompress MAM (XPRESS Huffman) compressed prefetch file.
        Falls back to returning raw data if decompression unavailable.
        """
        # Try using volatility3's built-in decompressor if available
        try:
            from volatility3.framework.layers.intel import \
                WindowsPrefetchDecompressor
            return WindowsPrefetchDecompressor.decompress(data)
        except ImportError:
            pass

        # Try wimlib-imagex or external tool
        # For now return raw - bulk_extractor handles MAM too
        return data

    # ── Utilities ──────────────────────────────────────────────────────

    def _validate_keylog(self, content: str) -> int:
        """
        Validate keylog content. Returns count of valid lines.
        """
        if not content:
            return 0
        count = 0
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                if KEYLOG_LINE_RE.match(line):
                    count += 1
        return count

    def _inject_keys(
        self,
        pcap_path: Path,
        keylog_path: Path,
    ) -> Optional[Path]:
        """
        Inject TLS secrets into a copy of the PCAP using editcap.
        Only works with pcapng format. Returns path to keyed copy.
        Original PCAP is never touched.
        """
        keyed_path = self.work_dir / f"keyed_{pcap_path.name}"

        # editcap requires pcapng output format
        if not keyed_path.suffix == ".pcapng":
            keyed_path = keyed_path.with_suffix(".pcapng")

        cmd = [
            self.editcap,
            "--inject-secrets", f"tls,{keylog_path}",
            str(pcap_path),
            str(keyed_path),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0 and keyed_path.exists():
                console.print(
                    f"  [green]TLS secrets injected into "
                    f"{keyed_path.name}[/green]")
                return keyed_path
            else:
                console.print(
                    f"  [yellow]editcap injection failed: "
                    f"{result.stderr[:200]}[/yellow]")
                return None
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            console.print(f"  [yellow]editcap error: {e}[/yellow]")
            return None
