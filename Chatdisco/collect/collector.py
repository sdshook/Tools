"""
Live collector orchestrator.

Sequences all acquisition tasks following the order of volatility.
PCAP starts first and runs throughout. TLS keys extracted early
from process memory. Full RAM dump runs concurrently. Disk artifacts
collected after RAM is secure.

All acquired artifacts are hashed immediately on capture.
Acquisition manifest written in real-time for COC integrity.
"""

import os
import sys
import json
import time
import signal
import hashlib
import platform
import datetime
import subprocess
import threading
import shutil
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
)

from chatdisco.core.dependency_check import check_dependencies
from chatdisco.core.intake import hash_file

console = Console()

SYSTEM = platform.system()  # Windows, Linux, Darwin


@dataclass
class AcquiredArtifact:
    """Record of a single acquired artifact."""
    artifact_id: str
    artifact_type: str          # memory, pcap, registry, prefetch, etc.
    filename: str
    path: str
    captured_at: str            # ISO 8601 UTC
    sha256: str
    sha1: str
    md5: str
    size_bytes: int
    method: str                 # How it was acquired
    notes: str = ""
    # TLS-specific
    tls_keys_carved: bool = False
    tls_key_count: int = 0
    # Process-specific
    pid: Optional[int] = None
    process_name: Optional[str] = None


@dataclass
class AcquisitionManifest:
    """Real-time acquisition manifest written during collection."""
    case_id: str
    examiner: str
    org: str
    collection_start: str
    collection_end: str = ""
    target_hostname: str = ""
    target_os: str = ""
    target_timezone: str = ""
    collection_mode: str = ""
    artifacts: list = field(default_factory=list)
    ai_surfaces_detected: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    sbom: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


class Collector:
    """
    Live forensic collection orchestrator.

    Sequences acquisition following strict order of volatility:
    1. Snapshot volatile state (processes, network, env vars)
    2. Start PCAP capture (runs throughout)
    3. TLS key capture (friTap if available, then env var check)
    4. Targeted process memory dumps (AI processes first)
    5. Carve TLS keys from process dumps immediately
    6. Full RAM acquisition (runs concurrently with above)
    7. Registry hives and AI app directories
    8. Prefetch directory (memory residue)
    9. Pagefile/hiberfil/crash dumps
    10. Event logs, execution artifacts
    11. Finalise PCAP, hash everything, write manifest
    """

    def __init__(
        self,
        output_dir: str,
        mode: str = "triage",
        target_pids: Optional[list] = None,
        pcap_duration: int = 300,
        collect_disk: bool = True,
        examiner: str = "",
        case_id: str = "",
        org: str = "",
        notes: str = "",
    ):
        self.output_dir     = Path(output_dir)
        self.mode           = mode
        self.target_pids    = target_pids
        self.pcap_duration  = pcap_duration
        self.collect_disk   = collect_disk
        self.examiner       = examiner
        self.case_id        = case_id
        self.org            = org
        self.notes          = notes

        # Internal state
        self._manifest: Optional[AcquisitionManifest] = None
        self._artifact_counter = 0
        self._pcap_proc: Optional[subprocess.Popen] = None
        self._fritap_proc: Optional[subprocess.Popen] = None
        self._stop_event = threading.Event()

        # Sub-directories
        self.mem_dir        = self.output_dir / "memory"
        self.net_dir        = self.output_dir / "network"
        self.reg_dir        = self.output_dir / "registry"
        self.app_dir        = self.output_dir / "ai_apps"
        self.prefetch_dir   = self.output_dir / "prefetch"
        self.pagefile_dir   = self.output_dir / "virtual_memory"
        self.logs_dir       = self.output_dir / "event_logs"
        self.keys_dir       = self.output_dir / "tls_keys"
        self.snap_dir       = self.output_dir / "snapshots"

    def run(self):
        """Execute full collection sequence."""
        self._setup()

        console.print(Panel(
            "[bold green]Collection sequence starting[/bold green]\n"
            "Following order of volatility.\n"
            "Do NOT power off or close the target application.",
            border_style="green"
        ))

        try:
            # ── PHASE 1: Volatile state snapshot (seconds) ────────────
            self._phase_snapshot()

            # ── PHASE 2: Start PCAP capture immediately ───────────────
            self._phase_start_pcap()

            # ── PHASE 3: TLS key capture ──────────────────────────────
            self._phase_tls_keys()

            # ── PHASE 4: Targeted process dumps (AI processes) ────────
            self._phase_process_dumps()

            # ── PHASE 5: Full RAM acquisition ─────────────────────────
            # Runs in background while disk collection proceeds
            ram_thread = threading.Thread(
                target=self._phase_full_ram, daemon=True)
            ram_thread.start()

            # ── PHASE 6: Registry hives ───────────────────────────────
            if self.collect_disk and SYSTEM == "Windows":
                self._phase_registry()

            # ── PHASE 7: AI app data directories ─────────────────────
            if self.collect_disk:
                self._phase_ai_app_dirs()

            # ── PHASE 8: Prefetch directory ───────────────────────────
            if self.collect_disk and SYSTEM == "Windows":
                self._phase_prefetch()

            # ── PHASE 9: Virtual memory files ─────────────────────────
            if self.collect_disk and SYSTEM == "Windows":
                self._phase_virtual_memory()

            # ── PHASE 10: Event logs and execution artifacts ──────────
            if self.collect_disk and self.mode == "full":
                self._phase_event_logs()

            # Wait for RAM dump to complete
            console.print("\n[bold]Waiting for RAM acquisition "
                          "to complete...[/bold]")
            ram_thread.join(timeout=3600)

        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted[/yellow]")
        finally:
            self.finalise()

    def finalise(self):
        """Stop all background processes and write final manifest."""
        # Stop PCAP capture
        if self._pcap_proc and self._pcap_proc.poll() is None:
            console.print("\n[bold]Stopping PCAP capture...[/bold]")
            self._pcap_proc.send_signal(signal.SIGINT
                                        if SYSTEM != "Windows"
                                        else signal.CTRL_C_EVENT)
            try:
                self._pcap_proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self._pcap_proc.kill()

            # Hash the PCAP
            pcap_path = self.net_dir / "capture.pcapng"
            if pcap_path.exists():
                self._record_artifact(
                    artifact_type="network_capture",
                    path=pcap_path,
                    method="tshark live capture",
                )

        # Stop friTap
        if self._fritap_proc and self._fritap_proc.poll() is None:
            self._fritap_proc.terminate()

        # Write final manifest
        if self._manifest:
            self._manifest.collection_end = \
                datetime.datetime.utcnow().isoformat() + "Z"
            manifest_path = self.output_dir / "acquisition_manifest.json"
            manifest_path.write_text(self._manifest.to_json())
            console.print(
                f"\n[bold green]Acquisition manifest written:[/bold green] "
                f"{manifest_path}")

        # Print summary
        if self._manifest:
            n = len(self._manifest.artifacts)
            console.print(Panel(
                f"[bold]Collection complete[/bold]\n"
                f"Artifacts: {n}\n"
                f"Output: {self.output_dir}\n"
                f"Manifest: acquisition_manifest.json",
                border_style="green"
            ))

    # ── Phase implementations ──────────────────────────────────────────

    def _phase_snapshot(self):
        """Capture volatile system state before anything else."""
        console.print("\n[bold cyan]Phase 1:[/bold cyan] "
                      "Volatile state snapshot")
        snap = {}

        # Timestamp and system info
        snap["captured_at"] = datetime.datetime.utcnow().isoformat() + "Z"
        snap["hostname"]    = platform.node()
        snap["os"]          = platform.platform()
        snap["architecture"]= platform.machine()

        try:
            import time as _time
            snap["uptime_seconds"] = _time.time()
        except Exception:
            pass

        # Running processes
        if SYSTEM == "Windows":
            snap["processes"] = self._snapshot_processes_windows()
            snap["network_connections"] = self._snapshot_netstat_windows()
            snap["environment"] = dict(os.environ)
        else:
            snap["processes"] = self._snapshot_processes_unix()
            snap["network_connections"] = self._snapshot_netstat_unix()
            snap["environment"] = dict(os.environ)

        # Detect AI surfaces
        ai_surfaces = self._detect_ai_surfaces(
            snap.get("processes", []))
        snap["ai_surfaces"] = ai_surfaces
        self._manifest.ai_surfaces_detected = ai_surfaces

        # Update target PIDs from AI surface detection if not specified
        if not self.target_pids and ai_surfaces:
            self.target_pids = [
                s["pid"] for s in ai_surfaces if s.get("pid")]

        snap_path = self.snap_dir / "volatile_state.json"
        snap_path.write_text(
            json.dumps(snap, indent=2, default=str))
        self._record_artifact(
            artifact_type="volatile_snapshot",
            path=snap_path,
            method="os_api_snapshot",
        )

        console.print(
            f"  Detected AI surfaces: "
            f"{len(ai_surfaces)}: "
            f"{[s.get('name','?') for s in ai_surfaces]}")

    def _phase_start_pcap(self):
        """Start network capture immediately. Runs throughout collection."""
        console.print("\n[bold cyan]Phase 2:[/bold cyan] "
                      "Starting PCAP capture")
        self.net_dir.mkdir(parents=True, exist_ok=True)
        pcap_out = self.net_dir / "capture.pcapng"

        # Get primary network interface
        iface = self._get_primary_interface()

        cmd = [
            "tshark",
            "-i", iface,
            "-w", str(pcap_out),
            "-F", "pcapng",
            # Capture all traffic - filter in analysis
            # Don't filter here - we might miss key material
        ]

        if self.pcap_duration > 0:
            cmd += ["-a", f"duration:{self.pcap_duration}"]

        try:
            self._pcap_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            console.print(
                f"  [green]PCAP capture started[/green] "
                f"on {iface} → {pcap_out.name}")
        except FileNotFoundError:
            console.print(
                "  [yellow]tshark not found, "
                "trying tcpdump...[/yellow]")
            self._start_tcpdump_fallback(pcap_out)

    def _phase_tls_keys(self):
        """Capture TLS keys: env var check, then friTap if available."""
        console.print("\n[bold cyan]Phase 3:[/bold cyan] "
                      "TLS key capture")
        self.keys_dir.mkdir(parents=True, exist_ok=True)

        # Check SSLKEYLOGFILE environment variable
        keylog_env = os.environ.get("SSLKEYLOGFILE")
        if keylog_env and Path(keylog_env).exists():
            dst = self.keys_dir / "sslkeylogfile_env.log"
            shutil.copy2(keylog_env, dst)
            self._record_artifact(
                artifact_type="tls_keylog",
                path=dst,
                method="SSLKEYLOGFILE_env_var",
                notes=f"Source: {keylog_env}",
            )
            console.print(
                f"  [green]SSLKEYLOGFILE found:[/green] {keylog_env}")
            return

        # Try friTap if available and we have target PIDs
        if self.target_pids:
            try:
                import fritap  # noqa: F401
                self._start_fritap()
                return
            except ImportError:
                pass

        console.print(
            "  [dim]No live TLS key source available. "
            "Keys will be carved from memory artifacts.[/dim]")

    def _phase_process_dumps(self):
        """Dump memory of AI-related processes."""
        console.print("\n[bold cyan]Phase 4:[/bold cyan] "
                      "Process memory dumps")
        self.mem_dir.mkdir(parents=True, exist_ok=True)

        if not self.target_pids:
            console.print(
                "  [dim]No target PIDs identified[/dim]")
            return

        for pid in self.target_pids:
            self._dump_process(pid)

    def _phase_full_ram(self):
        """Full physical memory acquisition. Runs concurrently."""
        console.print("\n[bold cyan]Phase 5:[/bold cyan] "
                      "Full RAM acquisition")
        self.mem_dir.mkdir(parents=True, exist_ok=True)
        out_path = self.mem_dir / "memory.raw"

        if SYSTEM == "Windows":
            success = self._acquire_ram_windows(out_path)
        elif SYSTEM == "Linux":
            success = self._acquire_ram_linux(out_path)
        elif SYSTEM == "Darwin":
            success = self._acquire_ram_macos(out_path)
        else:
            console.print(
                f"  [red]Unsupported OS: {SYSTEM}[/red]")
            return

        if success and out_path.exists():
            self._record_artifact(
                artifact_type="full_memory",
                path=out_path,
                method=f"{'winpmem' if SYSTEM=='Windows' else 'avml/lime'}",
            )
            console.print(
                f"  [green]RAM acquisition complete:[/green] "
                f"{out_path.stat().st_size:,} bytes")

    def _phase_registry(self):
        """Export Windows registry hives."""
        console.print("\n[bold cyan]Phase 6:[/bold cyan] "
                      "Registry hives")
        self.reg_dir.mkdir(parents=True, exist_ok=True)

        hives = {
            "SYSTEM":   r"HKLM\SYSTEM",
            "SAM":      r"HKLM\SAM",
            "SECURITY": r"HKLM\SECURITY",
            "SOFTWARE": r"HKLM\SOFTWARE",
        }

        for name, key in hives.items():
            out = self.reg_dir / f"{name}.hiv"
            try:
                result = subprocess.run(
                    ["reg", "save", key, str(out), "/y"],
                    capture_output=True, text=True, timeout=120,
                )
                if result.returncode == 0 and out.exists():
                    self._record_artifact(
                        artifact_type="registry_hive",
                        path=out,
                        method="reg_save",
                        notes=f"Key: {key}",
                    )
                    console.print(f"  [green]Saved:[/green] {name}")
                else:
                    self._manifest.warnings.append(
                        f"Registry {name}: {result.stderr[:100]}")
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                self._manifest.warnings.append(
                    f"Registry {name} failed: {e}")

        # NTUSER.DAT and UsrClass.dat
        ntuser = Path(os.environ.get("USERPROFILE", "")) / "NTUSER.DAT"
        if ntuser.exists():
            dst = self.reg_dir / "NTUSER.DAT"
            try:
                shutil.copy2(ntuser, dst)
                self._record_artifact(
                    artifact_type="registry_hive",
                    path=dst, method="file_copy",
                    notes="NTUSER.DAT")
            except (IOError, OSError) as e:
                self._manifest.warnings.append(
                    f"NTUSER.DAT copy failed: {e}")

        # AI-relevant registry keys as plaintext snapshot
        self._snapshot_ai_registry_keys()

    def _phase_ai_app_dirs(self):
        """Copy AI app data directories."""
        console.print("\n[bold cyan]Phase 7:[/bold cyan] "
                      "AI app data directories")
        self.app_dir.mkdir(parents=True, exist_ok=True)

        targets = self._get_ai_app_paths()
        for name, path in targets.items():
            src = Path(path)
            if not src.exists():
                continue
            dst = self.app_dir / name
            try:
                if src.is_dir():
                    shutil.copytree(
                        src, dst, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns(
                            "*.tmp", "GPUCache", "ShaderCache"))
                else:
                    shutil.copy2(src, dst)
                self._record_artifact(
                    artifact_type="ai_app_data",
                    path=dst,
                    method="directory_copy",
                    notes=f"Source: {src}",
                )
                console.print(f"  [green]Collected:[/green] {name}")
            except (IOError, OSError, shutil.Error) as e:
                self._manifest.warnings.append(
                    f"AI app dir {name}: {e}")

    def _phase_prefetch(self):
        """Copy Windows Prefetch directory - includes memory residue."""
        console.print("\n[bold cyan]Phase 8:[/bold cyan] "
                      "Prefetch directory")
        prefetch_src = Path(r"C:\Windows\Prefetch")
        if not prefetch_src.exists():
            console.print("  [dim]Prefetch directory not found[/dim]")
            return

        self.prefetch_dir.mkdir(parents=True, exist_ok=True)

        # Count and size before copying
        pf_files = list(prefetch_src.glob("*.pf"))
        db_files = list(prefetch_src.glob("*.db"))
        total = len(pf_files) + len(db_files)

        console.print(
            f"  Found {len(pf_files)} .pf files, "
            f"{len(db_files)} .db files")

        try:
            shutil.copytree(
                prefetch_src, self.prefetch_dir,
                dirs_exist_ok=True,
            )
            self._record_artifact(
                artifact_type="prefetch_directory",
                path=self.prefetch_dir,
                method="directory_copy",
                notes=f"{total} files including memory-mapped "
                      f"region content and page fault history",
            )
            console.print(
                f"  [green]Prefetch collected:[/green] "
                f"{total} files")
        except (IOError, shutil.Error) as e:
            self._manifest.warnings.append(f"Prefetch copy: {e}")

    def _phase_virtual_memory(self):
        """Note and optionally copy pagefile/hiberfil."""
        console.print("\n[bold cyan]Phase 9:[/bold cyan] "
                      "Virtual memory files")
        self.pagefile_dir.mkdir(parents=True, exist_ok=True)

        vm_files = {
            "pagefile.sys":  Path(r"C:\pagefile.sys"),
            "swapfile.sys":  Path(r"C:\swapfile.sys"),
            "hiberfil.sys":  Path(r"C:\hiberfil.sys"),
        }

        for name, path in vm_files.items():
            if not path.exists():
                continue
            size = path.stat().st_size
            size_gb = size / (1024**3)
            console.print(
                f"  Found {name}: {size_gb:.1f} GB")

            # Always record existence with hash
            # Copying pagefile/hiberfil requires VSS or offline access
            # Note location for offline acquisition
            self._manifest.warnings.append(
                f"{name} found at {path} ({size_gb:.1f} GB) - "
                f"requires offline/VSS acquisition for full copy. "
                f"Run bulk_extractor against this file offline "
                f"for memory residue analysis."
            )

        # Crash dumps
        crash_locs = [
            Path(r"C:\Windows\MEMORY.DMP"),
            Path(r"C:\Windows\Minidump"),
        ]
        for loc in crash_locs:
            if loc.exists():
                if loc.is_file():
                    dst = self.pagefile_dir / loc.name
                    try:
                        shutil.copy2(loc, dst)
                        self._record_artifact(
                            artifact_type="crash_dump",
                            path=dst,
                            method="file_copy",
                        )
                        console.print(
                            f"  [green]Copied crash dump:[/green] "
                            f"{loc.name}")
                    except (IOError, OSError) as e:
                        self._manifest.warnings.append(
                            f"Crash dump copy {loc}: {e}")
                elif loc.is_dir():
                    dst = self.pagefile_dir / "Minidump"
                    try:
                        shutil.copytree(loc, dst, dirs_exist_ok=True)
                        self._record_artifact(
                            artifact_type="minidump_directory",
                            path=dst,
                            method="directory_copy",
                        )
                        console.print(
                            f"  [green]Copied minidumps[/green]")
                    except (IOError, shutil.Error) as e:
                        self._manifest.warnings.append(
                            f"Minidump copy: {e}")

        # Chrome CrashPad reports
        crashpad_paths = [
            Path(os.environ.get("LOCALAPPDATA", "")) /
            "Google/Chrome/User Data/Crashpad/reports",
            Path(os.environ.get("LOCALAPPDATA", "")) /
            "Microsoft/Edge/User Data/Crashpad/reports",
        ]
        for cp_path in crashpad_paths:
            if cp_path.exists():
                name = cp_path.parent.parent.parent.name
                dst = self.pagefile_dir / f"crashpad_{name}"
                try:
                    shutil.copytree(cp_path, dst, dirs_exist_ok=True)
                    self._record_artifact(
                        artifact_type="crashpad_reports",
                        path=dst,
                        method="directory_copy",
                        notes=f"Browser: {name}",
                    )
                    console.print(
                        f"  [green]Copied CrashPad reports:[/green] "
                        f"{name}")
                except (IOError, shutil.Error):
                    pass

    def _phase_event_logs(self):
        """Export Windows event logs."""
        console.print("\n[bold cyan]Phase 10:[/bold cyan] "
                      "Event logs")
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        logs = [
            ("Security",     "Security.evtx"),
            ("Application",  "Application.evtx"),
            ("System",       "System.evtx"),
            ("PowerShell",
             "Microsoft-Windows-PowerShell%4Operational.evtx"),
        ]

        for log_name, evtx_name in logs:
            out = self.logs_dir / evtx_name
            try:
                result = subprocess.run(
                    ["wevtutil", "epl", log_name, str(out)],
                    capture_output=True, text=True, timeout=120,
                )
                if result.returncode == 0 and out.exists():
                    self._record_artifact(
                        artifact_type="event_log",
                        path=out,
                        method="wevtutil",
                        notes=f"Log: {log_name}",
                    )
                    console.print(
                        f"  [green]Exported:[/green] {log_name}")
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                self._manifest.warnings.append(
                    f"Event log {log_name}: {e}")

    # ── Platform-specific memory acquisition ──────────────────────────

    def _acquire_ram_windows(self, out_path: Path) -> bool:
        """Acquire RAM using WinPmem."""
        winpmem = (shutil.which("winpmem_mini_x64") or
                   shutil.which("winpmem_mini_x86") or
                   shutil.which("winpmem"))
        if not winpmem:
            self._manifest.warnings.append(
                "WinPmem not found - RAM not acquired")
            console.print("  [red]WinPmem not found[/red]")
            return False

        try:
            result = subprocess.run(
                [winpmem, str(out_path)],
                capture_output=True, text=True,
                timeout=7200,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self._manifest.warnings.append(f"WinPmem failed: {e}")
            return False

    def _acquire_ram_linux(self, out_path: Path) -> bool:
        """Acquire RAM using AVML (preferred) or LiME."""
        avml = shutil.which("avml")
        if avml:
            try:
                result = subprocess.run(
                    [avml, str(out_path)],
                    capture_output=True, text=True,
                    timeout=7200,
                )
                return result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # Fallback: /proc/kcore (limited but no kernel module)
        kcore = Path("/proc/kcore")
        if kcore.exists():
            self._manifest.warnings.append(
                "Using /proc/kcore - may not capture all memory. "
                "AVML or LiME recommended.")
            try:
                subprocess.run(
                    ["dd", f"if={kcore}", f"of={out_path}",
                     "bs=4M", "status=progress"],
                    timeout=7200,
                )
                return out_path.exists()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        self._manifest.warnings.append("RAM acquisition failed on Linux")
        return False

    def _acquire_ram_macos(self, out_path: Path) -> bool:
        """Acquire RAM using osxpmem."""
        osxpmem = shutil.which("osxpmem")
        if not osxpmem:
            self._manifest.warnings.append(
                "osxpmem not found - RAM not acquired")
            return False
        try:
            result = subprocess.run(
                [osxpmem, str(out_path)],
                capture_output=True, text=True,
                timeout=7200,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self._manifest.warnings.append(f"osxpmem failed: {e}")
            return False

    # ── Process dump ──────────────────────────────────────────────────

    def _dump_process(self, pid: int):
        """Dump memory of a specific process."""
        proc_name = self._get_process_name(pid)
        out_path = self.mem_dir / f"pid_{pid}_{proc_name}.dmp"

        console.print(
            f"  Dumping PID {pid} ({proc_name})...")

        success = False

        if SYSTEM == "Windows":
            # Use MiniDumpWriteDump via ctypes
            success = self._dump_process_windows(pid, out_path)
        elif SYSTEM == "Linux":
            success = self._dump_process_linux(pid, out_path)
        elif SYSTEM == "Darwin":
            success = self._dump_process_macos(pid, out_path)

        if success and out_path.exists():
            art = self._record_artifact(
                artifact_type="process_memory",
                path=out_path,
                method="process_dump",
                notes=f"PID: {pid}, Process: {proc_name}",
            )
            art.pid = pid
            art.process_name = proc_name
            console.print(
                f"  [green]Dumped:[/green] {out_path.name} "
                f"({out_path.stat().st_size:,} bytes)")
        else:
            self._manifest.warnings.append(
                f"Process dump failed for PID {pid} ({proc_name})")

    def _dump_process_windows(self, pid: int, out_path: Path) -> bool:
        """Windows process dump using DbgHelp MiniDumpWriteDump."""
        try:
            import ctypes
            import ctypes.wintypes

            PROCESS_ALL_ACCESS = 0x1F0FFF
            MiniDumpWithFullMemory = 2

            kernel32 = ctypes.windll.kernel32
            dbghelp  = ctypes.windll.dbghelp

            h_process = kernel32.OpenProcess(
                PROCESS_ALL_ACCESS, False, pid)
            if not h_process:
                return False

            with open(out_path, 'wb') as f:
                result = dbghelp.MiniDumpWriteDump(
                    h_process, pid,
                    ctypes.wintypes.HANDLE(
                        ctypes.cast(f.fileno(),
                                    ctypes.wintypes.HANDLE)),
                    MiniDumpWithFullMemory,
                    None, None, None,
                )
            kernel32.CloseHandle(h_process)
            return bool(result)
        except Exception as e:
            self._manifest.warnings.append(
                f"Windows process dump PID {pid}: {e}")
            return False

    def _dump_process_linux(self, pid: int, out_path: Path) -> bool:
        """Linux process dump by reading /proc/PID/mem."""
        try:
            maps_file = Path(f"/proc/{pid}/maps")
            mem_file  = Path(f"/proc/{pid}/mem")

            if not maps_file.exists() or not mem_file.exists():
                return False

            with open(out_path, 'wb') as out_f:
                with open(maps_file, 'r') as maps:
                    for line in maps:
                        parts = line.split()
                        if not parts:
                            continue
                        addr_range = parts[0]
                        perms = parts[1] if len(parts) > 1 else ""
                        if 'r' not in perms:
                            continue
                        try:
                            start, end = [
                                int(x, 16)
                                for x in addr_range.split('-')]
                        except ValueError:
                            continue
                        try:
                            with open(mem_file, 'rb') as mem:
                                mem.seek(start)
                                chunk = mem.read(end - start)
                                out_f.write(chunk)
                        except (IOError, OSError, OverflowError):
                            pass
            return out_path.exists()
        except (IOError, OSError) as e:
            self._manifest.warnings.append(
                f"Linux process dump PID {pid}: {e}")
            return False

    def _dump_process_macos(self, pid: int, out_path: Path) -> bool:
        """macOS process dump using gcore."""
        gcore = shutil.which("gcore")
        if not gcore:
            return False
        try:
            result = subprocess.run(
                [gcore, "-o", str(out_path), str(pid)],
                capture_output=True, timeout=300,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    # ── Utilities ──────────────────────────────────────────────────────

    def _setup(self):
        """Create output directories and initialise manifest."""
        for d in [self.output_dir, self.mem_dir, self.net_dir,
                  self.reg_dir, self.app_dir, self.prefetch_dir,
                  self.pagefile_dir, self.logs_dir, self.keys_dir,
                  self.snap_dir]:
            d.mkdir(parents=True, exist_ok=True)

        deps = check_dependencies(require_collection=True)

        self._manifest = AcquisitionManifest(
            case_id=self.case_id,
            examiner=self.examiner,
            org=self.org,
            collection_start=datetime.datetime.utcnow().isoformat() + "Z",
            target_hostname=platform.node(),
            target_os=platform.platform(),
            collection_mode=self.mode,
            sbom=deps.as_sbom_entries(),
        )

        try:
            import tzlocal
            self._manifest.target_timezone = str(
                tzlocal.get_localzone())
        except ImportError:
            self._manifest.target_timezone = \
                datetime.datetime.now().astimezone().tzname() or "unknown"

        # Write initial manifest immediately
        manifest_path = self.output_dir / "acquisition_manifest.json"
        manifest_path.write_text(self._manifest.to_json())

    def _record_artifact(
        self,
        artifact_type: str,
        path: Path,
        method: str,
        notes: str = "",
    ) -> AcquiredArtifact:
        """Hash an artifact and add to manifest. Returns AcquiredArtifact."""
        self._artifact_counter += 1
        artifact_id = f"ACQ-{self._artifact_counter:04d}"

        hashes = hash_file(path, show_progress=False)

        artifact = AcquiredArtifact(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            filename=path.name,
            path=str(path.resolve()),
            captured_at=datetime.datetime.utcnow().isoformat() + "Z",
            sha256=hashes.sha256,
            sha1=hashes.sha1,
            md5=hashes.md5,
            size_bytes=hashes.size_bytes,
            method=method,
            notes=notes,
        )

        self._manifest.artifacts.append(asdict(artifact))

        # Write manifest update immediately (real-time COC)
        manifest_path = self.output_dir / "acquisition_manifest.json"
        manifest_path.write_text(self._manifest.to_json())

        return artifact

    def _detect_ai_surfaces(self, processes: list) -> list:
        """Identify AI-related processes from process list."""
        AI_PROCESS_NAMES = {
            "chrome.exe":       "Google Chrome",
            "msedge.exe":       "Microsoft Edge",
            "firefox.exe":      "Mozilla Firefox",
            "brave.exe":        "Brave Browser",
            "ollama.exe":       "Ollama",
            "ollama":           "Ollama",
            "lmstudio.exe":     "LM Studio",
            "lm studio.exe":    "LM Studio",
            "jan.exe":          "Jan",
            "python.exe":       "Python (possible Ollama/LLM backend)",
            "python3":          "Python3 (possible LLM backend)",
            "node.exe":         "Node.js (possible AI app)",
            "copilot.exe":      "Microsoft Copilot",
            "cursor.exe":       "Cursor AI",
            "code.exe":         "VS Code (GitHub Copilot)",
            "perplexity.exe":   "Perplexity",
        }

        surfaces = []
        for proc in processes:
            name = (proc.get("name") or proc.get("Name") or "").lower()
            pid  = proc.get("pid") or proc.get("PID") or proc.get("Id")
            for key, friendly in AI_PROCESS_NAMES.items():
                if key.lower() in name:
                    surfaces.append({
                        "name":     friendly,
                        "process":  name,
                        "pid":      int(pid) if pid else None,
                    })
                    break
        return surfaces

    def _snapshot_processes_windows(self) -> list:
        """Get running processes on Windows."""
        try:
            result = subprocess.run(
                ["tasklist", "/fo", "csv", "/v"],
                capture_output=True, text=True, timeout=30,
            )
            procs = []
            for line in result.stdout.splitlines()[1:]:
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2:
                    procs.append({
                        "name": parts[0],
                        "pid":  parts[1] if len(parts) > 1 else "",
                    })
            return procs
        except Exception:
            return []

    def _snapshot_processes_unix(self) -> list:
        """Get running processes on Linux/macOS."""
        try:
            result = subprocess.run(
                ["ps", "axo", "pid,comm,args"],
                capture_output=True, text=True, timeout=30,
            )
            procs = []
            for line in result.stdout.splitlines()[1:]:
                parts = line.strip().split(None, 2)
                if parts:
                    procs.append({
                        "pid":  parts[0],
                        "name": parts[1] if len(parts) > 1 else "",
                        "cmd":  parts[2] if len(parts) > 2 else "",
                    })
            return procs
        except Exception:
            return []

    def _snapshot_netstat_windows(self) -> list:
        try:
            result = subprocess.run(
                ["netstat", "-nao"],
                capture_output=True, text=True, timeout=30,
            )
            return result.stdout.splitlines()
        except Exception:
            return []

    def _snapshot_netstat_unix(self) -> list:
        try:
            result = subprocess.run(
                ["ss", "-tunap"],
                capture_output=True, text=True, timeout=30,
            )
            return result.stdout.splitlines()
        except Exception:
            try:
                result = subprocess.run(
                    ["netstat", "-tunap"],
                    capture_output=True, text=True, timeout=30,
                )
                return result.stdout.splitlines()
            except Exception:
                return []

    def _snapshot_ai_registry_keys(self):
        """Export AI-relevant registry keys as JSON snapshot."""
        if SYSTEM != "Windows":
            return
        import winreg
        keys_of_interest = [
            (winreg.HKEY_CURRENT_USER,
             r"Environment"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"),
        ]
        snap = {}
        for hive, key_path in keys_of_interest:
            try:
                key = winreg.OpenKey(hive, key_path)
                values = {}
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        values[name] = str(data)
                        i += 1
                    except OSError:
                        break
                snap[key_path] = values
                winreg.CloseKey(key)
            except OSError:
                pass

        snap_path = self.snap_dir / "registry_ai_keys.json"
        snap_path.write_text(json.dumps(snap, indent=2))
        self._record_artifact(
            artifact_type="registry_snapshot",
            path=snap_path,
            method="winreg_api",
            notes="AI-relevant registry key snapshot",
        )

    def _get_ai_app_paths(self) -> dict:
        """Return known AI app data directory paths for this platform."""
        appdata = os.environ.get("APPDATA", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")
        home = str(Path.home())

        paths = {}

        if SYSTEM == "Windows":
            paths.update({
                "chrome_profile": os.path.join(
                    localappdata,
                    "Google/Chrome/User Data/Default"),
                "edge_profile": os.path.join(
                    localappdata,
                    "Microsoft/Edge/User Data/Default"),
                "ollama_data": os.path.join(home, ".ollama"),
                "lmstudio_data": os.path.join(home, ".lmstudio"),
                "jan_data": os.path.join(home, "jan"),
                "copilot_webview": os.path.join(
                    localappdata,
                    "Packages/Microsoft.Windows.Copilot_8wekyb3d8bbwe"),
            })
        elif SYSTEM == "Linux":
            paths.update({
                "chrome_profile": os.path.join(
                    home, ".config/google-chrome/Default"),
                "firefox_profile": os.path.join(
                    home, ".mozilla/firefox"),
                "ollama_data": os.path.join(home, ".ollama"),
                "lmstudio_data": os.path.join(home, ".lmstudio"),
                "jan_data": os.path.join(home, "jan"),
            })
        elif SYSTEM == "Darwin":
            lib = os.path.join(home, "Library")
            paths.update({
                "chrome_profile": os.path.join(
                    lib,
                    "Application Support/Google/Chrome/Default"),
                "safari_data": os.path.join(
                    lib, "Safari"),
                "ollama_data": os.path.join(home, ".ollama"),
                "lmstudio_data": os.path.join(home, ".lmstudio"),
                "jan_data": os.path.join(home, "jan"),
            })

        return paths

    def _get_primary_interface(self) -> str:
        """Get the primary network interface name."""
        if SYSTEM == "Windows":
            return "Ethernet"    # tshark accepts interface name
        else:
            # Try to find default route interface
            try:
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True, text=True, timeout=10,
                )
                parts = result.stdout.split()
                if "dev" in parts:
                    return parts[parts.index("dev") + 1]
            except Exception:
                pass
            return "any"

    def _start_tcpdump_fallback(self, out_path: Path):
        """Start tcpdump as fallback if tshark unavailable."""
        tcpdump = shutil.which("tcpdump")
        if not tcpdump:
            self._manifest.warnings.append(
                "Neither tshark nor tcpdump available - "
                "no network capture")
            return
        cmd = [tcpdump, "-i", "any", "-w", str(out_path)]
        if self.pcap_duration > 0:
            # tcpdump doesn't have built-in duration;
            # use timeout wrapper
            cmd = ["timeout", str(self.pcap_duration)] + cmd
        try:
            self._pcap_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            console.print(
                f"  [yellow]tcpdump capture started "
                f"(tshark fallback)[/yellow]")
        except FileNotFoundError:
            self._manifest.warnings.append(
                "tcpdump fallback also failed")

    def _start_fritap(self):
        """Start friTap for live TLS key capture."""
        if not self.target_pids:
            return
        keylog_path = self.keys_dir / "fritap_keys.log"
        pid = self.target_pids[0]  # Attach to first AI process
        try:
            cmd = ["fritap", "--pcap",
                   str(self.net_dir / "fritap_decrypted.pcap"),
                   "-k", str(keylog_path),
                   str(pid)]
            self._fritap_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            console.print(
                f"  [green]friTap started[/green] on PID {pid}")
        except FileNotFoundError:
            pass

    def _get_process_name(self, pid: int) -> str:
        """Get process name for a PID."""
        try:
            if SYSTEM == "Windows":
                result = subprocess.run(
                    ["tasklist", "/fi", f"PID eq {pid}",
                     "/fo", "csv", "/nh"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.stdout:
                    parts = result.stdout.strip().split('","')
                    if parts:
                        return parts[0].strip('"').replace(
                            ".exe", "").lower()
            else:
                comm = Path(f"/proc/{pid}/comm")
                if comm.exists():
                    return comm.read_text().strip()
        except Exception:
            pass
        return "unknown"
