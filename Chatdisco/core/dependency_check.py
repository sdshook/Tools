"""
Dependency checker.
Verifies all required third-party binaries and Python packages
are present, captures exact versions for SBOM inclusion in COC.
"""

import subprocess
import shutil
import importlib
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class ToolVersion:
    name: str
    required: bool
    present: bool
    version: Optional[str] = None
    path: Optional[str] = None
    purpose: str = ""
    sbom_id: Optional[str] = None  # CPE or PURL if known


@dataclass
class DependencyReport:
    tools: list = field(default_factory=list)

    @property
    def all_required_present(self) -> bool:
        return all(t.present for t in self.tools if t.required)

    def format_missing(self) -> str:
        missing = [t for t in self.tools if t.required and not t.present]
        lines = ["[bold red]Missing required dependencies:[/bold red]"]
        for t in missing:
            lines.append(f"  • {t.name}: {t.purpose}")
        lines.append("\nSee docs/INSTALL.md for installation instructions.")
        return "\n".join(lines)

    def as_sbom_entries(self) -> list:
        """Return SBOM-formatted entries for COC inclusion."""
        entries = []
        for t in self.tools:
            if not t.present:
                continue
            entries.append({
                "name": t.name,
                "version": t.version or "unknown",
                "path": t.path,
                "required": t.required,
                "purpose": t.purpose,
                "sbom_id": t.sbom_id,
                "type": "binary" if t.path else "python-package",
            })
        return entries


def _run_version(cmd: list) -> Optional[str]:
    """Run a command and return first line of stdout, or None on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        output = (result.stdout or result.stderr or "").strip()
        return output.split("\n")[0] if output else None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _python_package_version(package: str) -> Optional[str]:
    """Return installed version of a Python package, or None."""
    try:
        mod = importlib.import_module(package.replace("-", "_"))
        return getattr(mod, "__version__", None) or \
               _run_version(["pip", "show", package])
    except ImportError:
        return None


def check_dependencies(require_collection: bool = False) -> DependencyReport:
    """
    Check all required and optional dependencies.

    Args:
        require_collection: If True, also check collection-only
                            tools (WinPmem, LiME, etc.)

    Returns:
        DependencyReport with full version info for SBOM.
    """
    report = DependencyReport()

    # ── Binary tools ──────────────────────────────────────────────────

    # bulk_extractor
    be_path = shutil.which("bulk_extractor")
    be_ver = _run_version(["bulk_extractor", "--version"]) if be_path else None
    report.tools.append(ToolVersion(
        name="bulk_extractor",
        required=True,
        present=be_path is not None,
        version=be_ver,
        path=be_path,
        purpose="Byte-stream carving: JSON, URLs, base64, x509, "
                "cookies, network packets from memory/disk/PCAP",
        sbom_id="pkg:generic/bulk_extractor",
    ))

    # tshark
    ts_path = shutil.which("tshark")
    ts_ver = _run_version(["tshark", "--version"]) if ts_path else None
    report.tools.append(ToolVersion(
        name="tshark",
        required=True,
        present=ts_path is not None,
        version=ts_ver,
        path=ts_path,
        purpose="Network protocol dissection: HTTP/2, SSE stream "
                "reconstruction, TLS decryption with keylog",
        sbom_id="pkg:generic/wireshark",
    ))

    # editcap (ships with Wireshark/tshark)
    ec_path = shutil.which("editcap")
    ec_ver = _run_version(["editcap", "--version"]) if ec_path else None
    report.tools.append(ToolVersion(
        name="editcap",
        required=True,
        present=ec_path is not None,
        version=ec_ver,
        path=ec_path,
        purpose="Inject TLS secrets into pcapng for decryption",
        sbom_id="pkg:generic/wireshark",
    ))

    # ── Platform-specific collection tools ───────────────────────────

    if require_collection:
        import platform
        system = platform.system()

        if system == "Windows":
            wp_path = shutil.which("winpmem") or \
                      shutil.which("winpmem_mini_x64") or \
                      shutil.which("winpmem_mini_x86")
            wp_ver = _run_version([wp_path, "-h"]) if wp_path else None
            report.tools.append(ToolVersion(
                name="winpmem",
                required=True,
                present=wp_path is not None,
                version=wp_ver,
                path=wp_path,
                purpose="Windows physical memory acquisition",
                sbom_id="pkg:github/Velocidex/WinPmem",
            ))

        elif system == "Linux":
            # AVML - preferred (no kernel module needed)
            avml_path = shutil.which("avml")
            avml_ver = _run_version(
                ["avml", "--version"]) if avml_path else None
            report.tools.append(ToolVersion(
                name="avml",
                required=False,  # LiME is alternative
                present=avml_path is not None,
                version=avml_ver,
                path=avml_path,
                purpose="Linux memory acquisition (userland, "
                        "no kernel module)",
                sbom_id="pkg:github/microsoft/avml",
            ))

            # LiME (kernel module path)
            lime_path = shutil.which("lime-forensics") or \
                        _find_lime_module()
            report.tools.append(ToolVersion(
                name="lime",
                required=False,  # AVML is alternative
                present=lime_path is not None,
                version=None,
                path=lime_path,
                purpose="Linux memory acquisition via kernel module",
                sbom_id="pkg:github/504ensicsLabs/LiME",
            ))

        elif system == "Darwin":
            opm_path = shutil.which("osxpmem")
            report.tools.append(ToolVersion(
                name="osxpmem",
                required=True,
                present=opm_path is not None,
                version=None,
                path=opm_path,
                purpose="macOS memory acquisition",
                sbom_id="pkg:generic/osxpmem",
            ))

        # tcpdump as fallback for network capture
        td_path = shutil.which("tcpdump")
        td_ver = _run_version(["tcpdump", "--version"]) if td_path else None
        report.tools.append(ToolVersion(
            name="tcpdump",
            required=False,
            present=td_path is not None,
            version=td_ver,
            path=td_path,
            purpose="Network capture fallback if tshark unavailable",
            sbom_id="pkg:generic/tcpdump",
        ))

        # friTap (optional live key capture)
        ft_ver = _python_package_version("fritap")
        report.tools.append(ToolVersion(
            name="friTap",
            required=False,
            present=ft_ver is not None,
            version=ft_ver,
            path=None,
            purpose="Live TLS key extraction via Frida instrumentation",
            sbom_id="pkg:pypi/friTap",
        ))

    # ── Python packages ───────────────────────────────────────────────

    python_deps = [
        ("volatility3", True,
         "Memory structure analysis: processes, network, registry",
         "pkg:pypi/volatility3"),
        ("dpkt", True,
         "Low-level packet parsing for PCAP supplemental processing",
         "pkg:pypi/dpkt"),
        ("yara", True,
         "Pattern matching for AI service identification",
         "pkg:pypi/yara-python"),
        ("click", True,
         "CLI framework",
         "pkg:pypi/click"),
        ("rich", True,
         "Terminal output formatting",
         "pkg:pypi/rich"),
        ("jinja2", True,
         "HTML report templating",
         "pkg:pypi/jinja2"),
        ("scapy", False,
         "Supplemental packet parsing",
         "pkg:pypi/scapy"),
        ("Crypto", False,
         "Cryptographic operations for key handling",
         "pkg:pypi/pycryptodome"),
        ("orjson", False,
         "High-performance JSON parsing for large API responses",
         "pkg:pypi/orjson"),
    ]

    for pkg, required, purpose, sbom_id in python_deps:
        ver = _python_package_version(pkg)
        report.tools.append(ToolVersion(
            name=pkg,
            required=required,
            present=ver is not None,
            version=ver,
            path=None,
            purpose=purpose,
            sbom_id=sbom_id,
        ))

    return report


def print_dependency_table(report: DependencyReport):
    """Print a formatted dependency status table."""
    table = Table(title="Chatdisco Dependency Status", show_lines=True)
    table.add_column("Tool", style="bold")
    table.add_column("Required")
    table.add_column("Status")
    table.add_column("Version")
    table.add_column("Purpose")

    for t in report.tools:
        status = "[green]✓ Present[/green]" if t.present \
            else ("[red]✗ Missing[/red]" if t.required
                  else "[yellow]○ Optional[/yellow]")
        required = "[bold]Yes[/bold]" if t.required else "No"
        version = t.version or "—"
        # Truncate long version strings
        if len(version) > 40:
            version = version[:37] + "..."

        table.add_row(t.name, required, status, version, t.purpose)

    console.print(table)
    if report.all_required_present:
        console.print("[bold green]All required dependencies present.[/bold green]")
    else:
        console.print(report.format_missing())


def _find_lime_module() -> Optional[str]:
    """Search common LiME kernel module locations."""
    import os
    search_paths = [
        "/lib/modules",
        "/usr/local/lib",
        "/opt/lime",
    ]
    for base in search_paths:
        if not os.path.exists(base):
            continue
        for root, dirs, files in os.walk(base):
            for f in files:
                if f == "lime.ko" or f.startswith("lime-"):
                    return os.path.join(root, f)
    return None
