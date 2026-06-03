"""
Analysis pipeline.
Orchestrates all engines for offline analysis of collected artifacts.
Determines which engines to run based on input type, sequences
execution, correlates results across sources, and hands off to output.
"""

import os
import json
import datetime
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from chatdisco.core.intake import Intake, InputType, IntakeResult
from chatdisco.core.be_engine import BEEngine
from chatdisco.core.pcap_engine import PCAPEngine
from chatdisco.core.tls_resolver import TLSResolver
from chatdisco.parsers.base import ConversationRecord

console = Console()


class AnalysisPipeline:
    """
    Main analysis orchestrator.

    Given an IntakeResult, determines what to run, runs it,
    correlates results, and produces final output.
    """

    def __init__(
        self,
        intake: Intake,
        output_dir: str,
        target_services: Optional[list] = None,
        report_format: str = "all",
        verbose: bool = False,
    ):
        self.intake           = intake
        self.output_dir       = Path(output_dir)
        self.target_services  = target_services
        self.report_format    = report_format
        self.verbose          = verbose

        self.work_dir         = self.output_dir / "work"
        self.evidence_dir     = self.output_dir / "evidence"
        self.reports_dir      = self.output_dir / "reports"

        self._all_conversations: list = []
        self._all_be_results: list    = []
        self._tls_result              = None
        self._intake_result: Optional[IntakeResult] = None

    def run(self):
        """Execute full analysis pipeline."""
        for d in [self.output_dir, self.work_dir,
                  self.evidence_dir, self.reports_dir]:
            d.mkdir(parents=True, exist_ok=True)

        # ── Intake ─────────────────────────────────────────────────────
        console.print("\n[bold]Step 1/6:[/bold] Intake and hashing")
        self._intake_result = self.intake.process()

        # Write initial COC record
        coc_path = self.output_dir / "chain_of_custody.json"
        coc_path.write_text(self._intake_result.coc.to_json())
        console.print(f"  COC record: {coc_path.name}")

        # ── Route to engines based on input type ───────────────────────
        itype = self._intake_result.input_type

        if itype == InputType.EVIDENCE_DIR:
            self._process_evidence_dir()
        elif itype in (InputType.MEMORY_DUMP,
                       InputType.PROCESS_DUMP,
                       InputType.HIBERFIL):
            self._process_memory_input()
        elif itype == InputType.PCAP:
            self._process_pcap_input()
        elif itype in (InputType.PAGEFILE, InputType.CRASH_DUMP):
            self._process_virtual_memory_input()
        elif itype in (InputType.PREFETCH_FILE,
                       InputType.PREFETCH_DIR):
            self._process_prefetch_input()
        elif itype == InputType.DIRECTORY:
            self._process_directory()
        else:
            # Unknown type - try bulk_extractor anyway
            console.print(
                f"  [yellow]Unknown input type, "
                f"attempting bulk_extractor scan[/yellow]")
            self._run_bulk_extractor(self._intake_result.path)

        # ── Correlation ────────────────────────────────────────────────
        console.print("\n[bold]Step 5/6:[/bold] Correlation")
        self._correlate()

        # ── Output ─────────────────────────────────────────────────────
        console.print("\n[bold]Step 6/6:[/bold] Output")
        self._write_output()

        self._print_summary()

    # ── Input type handlers ────────────────────────────────────────────

    def _process_evidence_dir(self):
        """Process a Chatdisco collection evidence directory."""
        evidence_dir = self._intake_result.path
        console.print(
            "\n[bold]Processing evidence directory:[/bold] "
            f"{evidence_dir.name}")

        # Load acquisition manifest
        manifest_path = evidence_dir / "acquisition_manifest.json"
        if manifest_path.exists():
            with open(manifest_path) as f:
                manifest = json.load(f)
            console.print(
                f"  Acquisition manifest: {len(manifest.get('artifacts',[]))} "
                f"artifacts")

        # Process each subdirectory
        subdir_handlers = {
            "memory":         self._process_memory_dir,
            "network":        self._process_network_dir,
            "prefetch":       self._process_prefetch_dir,
            "virtual_memory": self._process_vm_dir,
            "ai_apps":        self._process_ai_apps_dir,
        }

        for subdir, handler in subdir_handlers.items():
            path = evidence_dir / subdir
            if path.exists():
                handler(path)

    def _process_memory_input(self):
        """Process a memory dump or hibernation file."""
        path = self._intake_result.path
        itype = self._intake_result.input_type

        console.print(
            f"\n[bold]Step 2/6:[/bold] Memory analysis "
            f"({itype.name})")

        # Decompress hiberfil if needed
        if itype == InputType.HIBERFIL:
            path = self._decompress_hiberfil(path)

        # Run bulk_extractor
        console.print("\n[bold]Step 3/6:[/bold] bulk_extractor scan")
        be_result = self._run_bulk_extractor(path)
        if be_result:
            self._all_be_results.append(be_result)

        # Run Volatility for OS structures
        console.print(
            "\n[bold]Step 4/6:[/bold] Volatility analysis")
        self._run_volatility(path)

        # If a paired PCAP was provided, process it too
        if self._intake_result.paired_memory or \
                self._intake_result.keylog_path:
            # Check if there's a PCAP to process
            pass

    def _process_pcap_input(self):
        """Process a PCAP file."""
        path = self._intake_result.path

        console.print("\n[bold]Step 2/6:[/bold] PCAP analysis")

        # Resolve TLS keys
        console.print("\n[bold]Step 3/6:[/bold] TLS key resolution")
        resolver = TLSResolver(work_dir=self.work_dir / "tls")

        # Run bulk_extractor on PCAP for feature extraction
        console.print("\n[bold]Step 4/6:[/bold] bulk_extractor scan")
        be_result = self._run_bulk_extractor(path, input_type="pcap")
        if be_result:
            self._all_be_results.append(be_result)

        self._tls_result = resolver.resolve(
            pcap_path=path,
            explicit_keylog=self._intake_result.keylog_path,
            memory_path=self._intake_result.paired_memory,
            be_result=be_result,
        )

        # Run tshark on (potentially keyed) PCAP
        pcap_engine = PCAPEngine()
        keyed_pcap = (self._tls_result.keyed_pcap_path
                      if self._tls_result.resolved
                      else path)
        keylog = self._tls_result.keylog_path

        pcap_result = pcap_engine.run(
            pcap_path=keyed_pcap or path,
            keylog_path=keylog,
            work_dir=self.work_dir / "pcap",
        )

        self._all_conversations.extend(pcap_result.conversations)

    def _process_virtual_memory_input(self):
        """Process pagefile, swapfile, or crash dump."""
        path = self._intake_result.path
        itype = self._intake_result.input_type

        console.print(
            f"\n[bold]Step 2/6:[/bold] Virtual memory analysis "
            f"({itype.name})")
        console.print(
            "  Virtual memory files contain paged-out process memory\n"
            "  including potential TLS key material and heap content.")

        # bulk_extractor is the primary tool here
        console.print("\n[bold]Step 3/6:[/bold] bulk_extractor scan")
        be_result = self._run_bulk_extractor(path)
        if be_result:
            self._all_be_results.append(be_result)

        # Volatility can work on crash dumps
        if self._intake_result.input_type == InputType.CRASH_DUMP:
            console.print("\n[bold]Step 4/6:[/bold] Volatility analysis")
            self._run_volatility(path)
        else:
            console.print(
                "\n[bold]Step 4/6:[/bold] "
                "[dim]Skipping Volatility (pagefile)[/dim]")

    def _process_prefetch_input(self):
        """
        Process prefetch files or directory.
        Treats as memory residue source - full bulk_extractor scan.
        Size-based triage to identify files with substantive content.
        """
        path = self._intake_result.path
        itype = self._intake_result.input_type

        console.print(
            f"\n[bold]Step 2/6:[/bold] Prefetch analysis "
            f"({itype.name})")
        console.print(
            "  Prefetch files contain memory-mapped region content\n"
            "  including pagefile-backed pages. Size triage applied.")

        if itype == InputType.PREFETCH_FILE:
            files_to_scan = [path]
        else:
            # Directory - triage by size
            all_files = (list(path.glob("*.pf")) +
                         list(path.glob("*.db")))
            files_to_scan = [
                f for f in all_files
                if f.stat().st_size > 8000  # Size threshold
            ]
            console.print(
                f"  {len(all_files)} total files, "
                f"{len(files_to_scan)} pass size triage (>8KB)")

        # Process each file
        console.print(
            f"\n[bold]Step 3/6:[/bold] "
            f"bulk_extractor on {len(files_to_scan)} prefetch files")

        for pf_file in files_to_scan:
            size_kb = pf_file.stat().st_size / 1024
            be_out = self.work_dir / "be_prefetch" / pf_file.stem

            if self.verbose:
                console.print(
                    f"  Scanning {pf_file.name} "
                    f"({size_kb:.0f} KB)")

            be_result = self._run_bulk_extractor(
                pf_file,
                output_dir=be_out,
            )
            if be_result:
                self._all_be_results.append(be_result)

        console.print(
            "\n[bold]Step 4/6:[/bold] "
            "[dim]Volatility N/A for prefetch[/dim]")

    def _process_directory(self):
        """Process a generic directory - scan everything found."""
        path = self._intake_result.path
        console.print(
            f"\n[bold]Step 2/6:[/bold] Directory scan: {path}")

        # Find all processable files
        memory_exts = {'.raw', '.mem', '.dmp', '.lime', '.img'}
        pcap_exts   = {'.pcap', '.pcapng', '.cap'}
        pf_exts     = {'.pf', '.db'}

        for f in path.rglob("*"):
            if not f.is_file():
                continue
            ext = f.suffix.lower()
            name = f.name.lower()

            if ext in memory_exts or name in (
                    'hiberfil.sys', 'pagefile.sys', 'swapfile.sys',
                    'memory.dmp'):
                self._run_bulk_extractor(f)
            elif ext in pcap_exts:
                # Queue for PCAP processing
                pass
            elif ext in pf_exts and f.stat().st_size > 8000:
                self._run_bulk_extractor(f)

    def _process_memory_dir(self, mem_dir: Path):
        """Process memory subdirectory of evidence collection."""
        for f in mem_dir.iterdir():
            if f.is_file() and f.stat().st_size > 1000:
                be_result = self._run_bulk_extractor(f)
                if be_result:
                    self._all_be_results.append(be_result)

    def _process_network_dir(self, net_dir: Path):
        """Process network captures in evidence directory."""
        for pcap in list(net_dir.glob("*.pcap")) + \
                    list(net_dir.glob("*.pcapng")):
            self._process_pcap_file(pcap)

    def _process_prefetch_dir(self, pf_dir: Path):
        """Process prefetch subdirectory of evidence collection."""
        files = [f for f in pf_dir.rglob("*")
                 if f.is_file() and f.stat().st_size > 8000
                 and f.suffix.lower() in ('.pf', '.db')]
        for f in files:
            be_result = self._run_bulk_extractor(f)
            if be_result:
                self._all_be_results.append(be_result)

    def _process_vm_dir(self, vm_dir: Path):
        """Process virtual memory files in evidence collection."""
        for f in vm_dir.iterdir():
            if f.is_file() and f.stat().st_size > 1000:
                be_result = self._run_bulk_extractor(f)
                if be_result:
                    self._all_be_results.append(be_result)

    def _process_ai_apps_dir(self, apps_dir: Path):
        """Process AI app data directories."""
        # SQLite DBs, JSON files, cache files
        for f in apps_dir.rglob("*.json"):
            if f.stat().st_size > 100:
                self._parse_json_artifact(f)
        for f in apps_dir.rglob("*.sqlite"):
            self._parse_sqlite_artifact(f)
        for f in apps_dir.rglob("*.db"):
            if f.stat().st_size > 100:
                self._parse_sqlite_artifact(f)

    def _process_pcap_file(self, pcap_path: Path):
        """Process a single PCAP file."""
        resolver = TLSResolver(work_dir=self.work_dir / "tls")
        be_result = (self._all_be_results[-1]
                     if self._all_be_results else None)

        tls_result = resolver.resolve(
            pcap_path=pcap_path,
            explicit_keylog=self._intake_result.keylog_path
                            if self._intake_result else None,
            be_result=be_result,
        )

        pcap_engine = PCAPEngine()
        pcap_result = pcap_engine.run(
            pcap_path=tls_result.keyed_pcap_path or pcap_path,
            keylog_path=tls_result.keylog_path,
            work_dir=self.work_dir / "pcap",
        )
        self._all_conversations.extend(pcap_result.conversations)

    # ── Engine runners ─────────────────────────────────────────────────

    def _run_bulk_extractor(
        self,
        path: Path,
        input_type: str = "generic",
        output_dir: Optional[Path] = None,
    ):
        """Run bulk_extractor on a path, return BEResult."""
        if not output_dir:
            safe_name = path.name.replace("/", "_").replace("\\", "_")
            output_dir = self.work_dir / "be" / safe_name

        be = BEEngine()
        return be.run(
            input_path=path,
            output_dir=output_dir,
            input_type=input_type,
        )

    def _run_volatility(self, path: Path):
        """Run Volatility 3 analysis on a memory image."""
        from chatdisco.core.vol_engine import VolEngine
        vol = VolEngine()
        vol_result = vol.run(path, self.work_dir / "volatility")
        if vol_result:
            # Extract any conversations from Volatility results
            pass

    def _decompress_hiberfil(self, path: Path) -> Path:
        """Decompress hiberfil.sys to a raw memory image."""
        out_path = self.work_dir / "hiberfil_decompressed.raw"
        if out_path.exists():
            return out_path

        console.print(
            "  Decompressing hiberfil.sys...")

        # Try Volatility imagecopy
        try:
            import subprocess
            result = subprocess.run(
                ["vol", "-f", str(path),
                 "windows.imagecopy",
                 "-O", str(out_path)],
                capture_output=True, text=True, timeout=3600,
            )
            if out_path.exists():
                console.print(
                    f"  [green]Decompressed:[/green] {out_path.name}")
                return out_path
        except Exception:
            pass

        console.print(
            "  [yellow]Could not decompress hiberfil.sys - "
            "scanning raw[/yellow]")
        return path  # Fall back to raw scan

    # ── Parsers for disk artifacts ─────────────────────────────────────

    def _parse_json_artifact(self, path: Path):
        """Parse a JSON file for AI chat content."""
        try:
            with open(path) as f:
                data = json.load(f)
            # LM Studio conversation format
            if isinstance(data, dict) and "messages" in data:
                from chatdisco.parsers.local_llm import LocalLLMParser
                parser = LocalLLMParser()
                conv = parser.parse_lmstudio_json(data, str(path))
                if conv:
                    self._all_conversations.append(conv)
        except (json.JSONDecodeError, IOError):
            pass

    def _parse_sqlite_artifact(self, path: Path):
        """Parse a SQLite database for AI chat artifacts."""
        # Browser history, cookies, IndexedDB
        # Deferred to browser_api parser
        pass

    # ── Correlation ────────────────────────────────────────────────────

    def _correlate(self):
        """
        Cross-source correlation:
        - Match session tokens from BE output to conversations
        - Deduplicate conversations found in multiple sources
        - Build unified timeline
        """
        # Extract identity artifacts from all BE results
        all_tokens = []
        all_emails = []
        all_conv_ids = []

        for be_result in self._all_be_results:
            # JWTs
            for b64 in be_result.base64_items:
                if b64.get("is_jwt"):
                    all_tokens.append(b64["data"])

            # Email addresses
            for email in be_result.email_addresses:
                all_emails.append(email["email"])

            # Conversation IDs from JSON
            for frag in be_result.json_fragments:
                if frag.get("parsed") and isinstance(
                        frag["parsed"], dict):
                    cid = frag["parsed"].get("conversation_id")
                    if cid:
                        all_conv_ids.append(cid)

            # TLS key candidates → try to build keylog
            if be_result.tls_key_candidates and \
                    not self._tls_result:
                keylog_content = be_result.carve_tls_keylog(
                    be_result)
                if keylog_content:
                    keylog_path = (
                        self.work_dir / "tls" / "carved_keys.log")
                    keylog_path.parent.mkdir(
                        parents=True, exist_ok=True)
                    keylog_path.write_text(keylog_content)

        # Apply known identities to conversations without them
        for conv in self._all_conversations:
            if not conv.identity.email and all_emails:
                # Heuristic: apply most common email
                # Real implementation would use session correlation
                pass

        console.print(
            f"  Tokens: {len(all_tokens)}, "
            f"Emails: {len(set(all_emails))}, "
            f"Conversation IDs: {len(set(all_conv_ids))}, "
            f"Conversations: {len(self._all_conversations)}")

    # ── Output ─────────────────────────────────────────────────────────

    def _write_output(self):
        """Write all output files."""
        from chatdisco.output.case_bundle import CASEBundleWriter
        from chatdisco.output.report import ReportWriter
        from chatdisco.output.manifest import ManifestWriter

        # Write conversations as JSON
        conv_path = self.evidence_dir / "conversations.json"
        conv_path.write_text(
            json.dumps(
                [c.to_dict() for c in self._all_conversations],
                indent=2, default=str,
            )
        )
        console.print(
            f"  Conversations: {conv_path.name} "
            f"({len(self._all_conversations)} records)")

        # Write CASE/UCO bundle
        case_writer = CASEBundleWriter(
            intake_result=self._intake_result,
            conversations=self._all_conversations,
            be_results=self._all_be_results,
            tls_result=self._tls_result,
        )
        case_path = self.output_dir / "case_bundle.jsonld"
        case_writer.write(case_path)
        console.print(f"  CASE bundle: {case_path.name}")

        # Write hash manifest
        manifest_writer = ManifestWriter(
            output_dir=self.output_dir,
            intake_result=self._intake_result,
        )
        manifest_writer.write()

        # Write HTML report
        if self.report_format in ("html", "all"):
            report_writer = ReportWriter(
                conversations=self._all_conversations,
                intake_result=self._intake_result,
                be_results=self._all_be_results,
                tls_result=self._tls_result,
            )
            report_path = self.reports_dir / "report.html"
            report_writer.write_html(report_path)
            console.print(f"  HTML report: {report_path.name}")

    def _print_summary(self):
        """Print analysis summary table."""
        table = Table(
            title="Analysis Summary", show_lines=True)
        table.add_column("Metric", style="bold")
        table.add_column("Value")

        table.add_row(
            "Conversations found",
            str(len(self._all_conversations)))
        table.add_row(
            "AI services identified",
            str(len(set(
                c.service.value
                for c in self._all_conversations))))
        table.add_row(
            "bulk_extractor runs",
            str(len(self._all_be_results)))

        total_json = sum(
            len(r.json_fragments)
            for r in self._all_be_results)
        table.add_row("JSON fragments carved", str(total_json))

        tls_status = (
            f"Resolved ({self._tls_result.method})"
            if self._tls_result and self._tls_result.resolved
            else "Unresolved" if self._tls_result
            else "N/A")
        table.add_row("TLS decryption", tls_status)

        table.add_row("Output directory", str(self.output_dir))

        console.print(table)
