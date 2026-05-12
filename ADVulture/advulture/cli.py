# (c) 2025 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture — CLI Entry Point
"""

from __future__ import annotations
import logging
from pathlib import Path
from typing import Optional
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from advulture.custody import (
    ChainOfCustodyLogger, 
    CustodyEventType,
    compute_file_hash,
)

console = Console()
log = logging.getLogger("advulture")

# Suppress verbose Azure SDK logging
logging.getLogger("azure").setLevel(logging.WARNING)
logging.getLogger("azure.core").setLevel(logging.WARNING)
logging.getLogger("azure.identity").setLevel(logging.WARNING)


@click.group()
@click.option("--config", "-c", type=Path, default=Path("config.yaml"),
              help="Path to config.yaml")
@click.option("--log-level", default="INFO",
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]))
@click.option("--case-id", envvar="ADVULTURE_CASE_ID",
              help="Case/ticket ID for chain of custody logging")
@click.option("--custody-dir", type=Path, default=Path("custody_logs"),
              help="Directory for chain of custody logs")
@click.option("--no-custody", is_flag=True, default=False,
              help="Disable chain of custody logging")
@click.pass_context
def main(ctx, config: Path, log_level: str, case_id: Optional[str], 
         custody_dir: Path, no_custody: bool):
    """🦅 ADVulture — Active Directory Vulnerability Intelligence"""
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["case_id"] = case_id
    ctx.obj["custody_dir"] = custody_dir
    ctx.obj["no_custody"] = no_custody
    
    # Initialize chain of custody logging
    if not no_custody:
        custody = ChainOfCustodyLogger.get_instance()
        custody.configure(log_dir=custody_dir, enabled=True)
        custody.start_session(case_id=case_id, assessment_type="advulture_analysis")
        ctx.obj["custody"] = custody
        
        # Log config load
        if config.exists():
            custody.log_config("load", {"path": str(config), "exists": True})


# Default EVTX paths on Windows DCs
DEFAULT_EVTX_PATHS = [
    Path(r"C:/Windows/System32/winevt/Logs/Security.evtx"),
    Path(r"C:/Windows/System32/winevt/Logs/System.evtx"),
    Path(r"C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx"),
]


def _discover_evtx_files() -> list:
    """Auto-discover EVTX files in default Windows locations or current directory."""
    found = []
    
    # Check default Windows paths
    for path in DEFAULT_EVTX_PATHS:
        if path.exists():
            found.append(path)
            log.info("Found EVTX: %s", path)
    
    # Check current directory for .evtx files
    for evtx_file in Path(".").glob("*.evtx"):
        if evtx_file not in found:
            found.append(evtx_file)
            log.info("Found EVTX: %s", evtx_file)
    
    return found


@main.command()
@click.option("--output", "-o", type=Path, default=Path("reports"),
              help="Output directory for reports")
@click.option("--evtx", "-e", type=Path, multiple=True,
              help="EVTX files (auto-discovered if not specified)")
@click.option("--format", "fmt", default="both",
              type=click.Choice(["html", "json", "both"]))
# On-prem AD options
@click.option("--ad-auth", type=click.Choice(["prompt", "kerberos", "ntlm", "simple"]),
              help="On-prem AD auth mode (default: prompt for creds)")
@click.option("--domain", help="AD domain (auto-discovered if not specified)")
@click.option("--server", help="DC hostname (auto-discovered if not specified)")
# Entra ID options
@click.option("--entra-auth", type=click.Choice([
              "device_code", "interactive", "client_secret", 
              "certificate", "managed_identity"]),
              help="Enable Entra ID analysis with specified auth mode")
@click.option("--entra-only", is_flag=True, default=False,
              help="Run Entra ID analysis only (no on-prem AD)")
@click.option("--ad-only", is_flag=True, default=False,
              help="Run on-prem AD analysis only (no Entra)")
@click.option("--tenant-id", envvar="AZURE_TENANT_ID",
              help="Entra ID tenant ID (optional for interactive auth)")
@click.option("--client-id", envvar="AZURE_CLIENT_ID",
              help="Entra ID client/app ID (optional for interactive auth)")
@click.pass_context
def analyze(ctx, output: Path, evtx, fmt: str, 
            ad_auth: Optional[str], domain: Optional[str], server: Optional[str],
            entra_auth: Optional[str], entra_only: bool, ad_only: bool,
            tenant_id: Optional[str], client_id: Optional[str]):
    """
    Run posture analysis and generate reports.
    
    \b
    SIMPLEST USAGE:
      advulture analyze --entra-only     # Cloud-only (Entra ID)
      advulture analyze --ad-only        # On-prem AD (auto-discovers logs)
      advulture analyze                  # Hybrid (prompts for both)
    
    EVTX files are auto-discovered from current directory or Windows default
    locations. Use --evtx to specify files explicitly.
    """
    from datetime import datetime, timezone
    from advulture.config import Config, EntraAuthMode, LDAPAuthMode
    from advulture.analysis.posture import PostureAnalyzer
    from advulture.reporting.report import ReportGenerator

    # Get custody logger
    custody = ctx.obj.get("custody")

    config_path: Path = ctx.obj["config_path"]
    if config_path.exists():
        cfg = Config.from_file(config_path)
        if custody:
            custody.log_config("load", {
                "path": str(config_path),
                "entra_enabled": cfg.entra.enabled,
                "ldap_server": cfg.ldap.server or "auto-discover",
            })
    else:
        console.print("[dim]No config.yaml — using auto-discovery[/dim]")
        cfg = Config()
        if custody:
            custody.log_config("default", {"reason": "no config.yaml found"})

    # Handle EVTX files: use provided, or auto-discover
    if evtx:
        cfg.logs.evtx_paths = list(evtx)
    elif not entra_only:
        # Auto-discover EVTX files for on-prem/hybrid modes
        discovered = _discover_evtx_files()
        if discovered:
            cfg.logs.evtx_paths = discovered
            console.print(f"[dim]Auto-discovered {len(discovered)} EVTX file(s)[/dim]")

    # Handle environment type flags
    if entra_only and ad_only:
        console.print("[red]Error:[/red] Cannot specify both --entra-only and --ad-only")
        raise SystemExit(1)

    if entra_only:
        # Entra-only: disable on-prem AD
        cfg.entra.enabled = True
        cfg.entra.auth_mode = EntraAuthMode(entra_auth or "device_code")
        cfg.ldap.server = ""
        cfg.ldap.username = ""
        console.print("[dim]Mode: Entra ID only (cloud)[/dim]")
        
    elif ad_only:
        # AD-only: disable Entra
        cfg.entra.enabled = False
        cfg.ldap.auth_mode = LDAPAuthMode(ad_auth or "prompt")
        if domain:
            cfg.ldap.domain = domain
        if server:
            cfg.ldap.server = server
        console.print("[dim]Mode: On-prem AD only[/dim]")
        
    else:
        # Hybrid or default
        if entra_auth:
            cfg.entra.enabled = True
            cfg.entra.auth_mode = EntraAuthMode(entra_auth)
        if ad_auth:
            cfg.ldap.auth_mode = LDAPAuthMode(ad_auth)
        if domain:
            cfg.ldap.domain = domain
        if server:
            cfg.ldap.server = server
        if tenant_id:
            cfg.entra.tenant_id = tenant_id
        if client_id:
            cfg.entra.client_id = client_id
            
        mode_parts = []
        if cfg.ldap.server or cfg.ldap.domain or ad_auth:
            mode_parts.append("on-prem AD")
        if cfg.entra.enabled:
            mode_parts.append("Entra ID")
        if mode_parts:
            console.print(f"[dim]Mode: {' + '.join(mode_parts)}[/dim]")

    console.print(Panel.fit(
        "[bold cyan]🦅 ADVulture[/bold cyan] — Starting analysis",
        border_style="cyan",
    ))

    # Log analysis start
    analysis_mode = "entra_only" if entra_only else ("ad_only" if ad_only else "hybrid")
    if custody:
        custody.log_analysis("posture_start", {
            "mode": analysis_mode,
            "entra_enabled": cfg.entra.enabled,
            "entra_auth_mode": cfg.entra.auth_mode.value if cfg.entra.enabled else None,
            "ldap_domain": cfg.ldap.domain or "auto-discover",
            "evtx_count": len(cfg.logs.evtx_paths),
        })

    analysis_start = datetime.now(timezone.utc)
    analyzer = PostureAnalyzer(cfg)
    report = analyzer.analyze()
    analysis_duration = int((datetime.now(timezone.utc) - analysis_start).total_seconds() * 1000)

    # Log analysis completion
    if custody:
        custody.log_analysis("posture_complete", {
            "regime": report.regime,
            "tier0_probability": round(report.tier0_steady_state_probability, 4),
            "mean_steps_to_tier0": round(report.mean_steps_to_tier0, 2),
            "total_findings": len(report.findings),
            "finding_counts": report.finding_counts,
            "attacker_phase": report.attacker_phase.most_likely.name if report.attacker_phase else "UNKNOWN",
            "phase_confidence": round(report.attacker_phase.confidence, 3) if report.attacker_phase else 0,
        }, duration_ms=analysis_duration)
        
        # Log individual findings for audit trail
        for finding in report.findings[:50]:  # Log top 50 findings
            custody.log_finding(
                finding_id=finding.id,
                title=finding.title,
                severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                risk_class=finding.risk_class.value if hasattr(finding.risk_class, 'value') else str(finding.risk_class),
                details={
                    "gradient": round(finding.gradient_contribution, 4),
                    "tier0_paths": finding.tier0_reachable_paths,
                    "active_signal": finding.active_signal,
                },
            )

    # Print summary
    regime_color = {"ORDERED": "green", "CRITICAL": "yellow", "CHAOTIC": "red"}
    color = regime_color.get(report.regime, "white")

    console.print(f"\n[bold {color}]REGIME: {report.regime}[/bold {color}]")
    console.print(f"π_tier0: {report.tier0_steady_state_probability:.1%}  |  "
                  f"Mean steps to DA: {report.mean_steps_to_tier0:.1f}")
    if report.attacker_phase:
        console.print(f"Phase: {report.attacker_phase.most_likely.name}  |  "
                      f"Confidence: {report.attacker_phase.confidence:.0%}")

    # Print remediation table
    table = Table(title="Top Remediation Actions", box=box.ROUNDED, show_lines=True)
    table.add_column("#", width=4)
    table.add_column("Control", style="cyan")
    table.add_column("Gradient", justify="right")
    table.add_column("Classes")
    table.add_column("Explanation", max_width=50)

    for i, item in enumerate(report.remediation_ranking[:10], 1):
        table.add_row(
            str(i),
            item.control,
            f"{item.gradient:.3f}",
            " ".join(item.risk_classes_affected),
            item.explanation[:60] + "...",
        )
    console.print(table)

    # Print finding summary
    counts_str = "  ".join(f"[{k}] {v}" for k, v in report.finding_counts.items())
    console.print(f"\nFindings: {counts_str}  |  Total: {len(report.findings)}")

    if report.active_signals:
        console.print(f"\n[bold yellow]Active Signals:[/bold yellow]")
        for sig in report.active_signals[:5]:
            console.print(f"  ⚠ {sig}")

    # Generate reports
    gen = ReportGenerator()
    output.mkdir(parents=True, exist_ok=True)
    
    if fmt in ("html", "both"):
        html_path = output / f"advulture_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"
        gen.generate_html(report, html_path)
        console.print(f"\n[green]HTML report:[/green] {html_path}")
        if custody:
            file_hash = compute_file_hash(html_path)
            custody.log_export("report", str(html_path), "html", 
                             record_count=len(report.findings), file_hash=file_hash)
    
    if fmt in ("json", "both"):
        json_path = output / f"advulture_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        gen.generate_json(report, json_path)
        console.print(f"[green]JSON report:[/green] {json_path}")
        if custody:
            file_hash = compute_file_hash(json_path)
            custody.log_export("report", str(json_path), "json",
                             record_count=len(report.findings), file_hash=file_hash)
    
    # End custody session with summary
    if custody:
        custody.end_session(summary={
            "domain": report.domain,
            "regime": report.regime,
            "total_findings": len(report.findings),
            "reports_generated": [str(p) for p in [html_path if fmt in ("html", "both") else None,
                                                    json_path if fmt in ("json", "both") else None] if p],
        })


@main.command()
@click.option("--host", default="0.0.0.0")
@click.option("--port", default=8000, type=int)
@click.pass_context
def serve(ctx, host: str, port: int):
    """Start the ADVulture API server."""
    import uvicorn
    from advulture.api.main import create_app
    config_path: Path = ctx.obj["config_path"]
    app = create_app(config_path if config_path.exists() else None)
    console.print(f"[bold cyan]🦅 ADVulture API[/bold cyan] → http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


@main.command()
@click.option("--ntds", "-n", type=Path, required=True,
              help="Path to NTDS.dit file")
@click.option("--system", "-s", type=Path,
              help="Path to SYSTEM registry hive (for hash extraction)")
@click.option("--evtx", "-e", type=Path, multiple=True,
              help="EVTX log files to analyze (can specify multiple)")
@click.option("--output", "-o", type=Path, default=Path("reports"),
              help="Output directory for reports")
@click.option("--format", "fmt", default="both",
              type=click.Choice(["html", "json", "both"]))
@click.option("--extract-hashes", is_flag=True, default=False,
              help="Attempt to extract password hashes (requires SYSTEM hive)")
@click.pass_context
def audit(ctx, ntds: Path, system: Optional[Path], evtx, output: Path, 
          fmt: str, extract_hashes: bool):
    """
    Run offline audit on NTDS.dit and DC logs.
    
    Analyzes extracted AD artifacts without live network access:
    
    \b
    - NTDS.dit: AD database containing users, groups, computers, trusts
    - SYSTEM hive: Required for hash extraction (optional)
    - EVTX logs: Security/System event logs from domain controllers
    
    \b
    Example:
      advulture audit --ntds ./ntds.dit --system ./SYSTEM --evtx ./Security.evtx
    """
    from advulture.audit import OfflineAuditor
    
    console.print(Panel.fit(
        "[bold cyan]🦅 ADVulture[/bold cyan] — Offline Audit Mode",
        border_style="cyan",
    ))
    
    # Validate inputs
    if not ntds.exists():
        console.print(f"[red]Error:[/red] NTDS.dit not found: {ntds}")
        raise SystemExit(1)
    
    if system and not system.exists():
        console.print(f"[yellow]Warning:[/yellow] SYSTEM hive not found: {system}")
        system = None
    
    if extract_hashes and not system:
        console.print("[yellow]Warning:[/yellow] Hash extraction requires SYSTEM hive")
        extract_hashes = False
    
    evtx_paths = [p for p in evtx if p.exists()]
    missing_evtx = [p for p in evtx if not p.exists()]
    for p in missing_evtx:
        console.print(f"[yellow]Warning:[/yellow] EVTX file not found: {p}")
    
    console.print(f"NTDS.dit: {ntds}")
    if system:
        console.print(f"SYSTEM hive: {system}")
    if evtx_paths:
        console.print(f"EVTX files: {len(evtx_paths)}")
    
    # Run audit
    auditor = OfflineAuditor(
        ntds_path=ntds,
        system_hive_path=system,
        evtx_paths=evtx_paths,
        extract_hashes=extract_hashes,
    )
    
    with console.status("[bold green]Analyzing artifacts..."):
        report = auditor.audit()
    
    # Print summary
    report.compute_counts()
    
    console.print(f"\n[bold]Domain:[/bold] {report.snapshot.domain}")
    console.print(
        f"[bold]Objects:[/bold] "
        f"{len(report.snapshot.users)} users, "
        f"{len(report.snapshot.computers)} computers, "
        f"{len(report.snapshot.groups)} groups"
    )
    
    # Findings summary table
    table = Table(title="Findings Summary", box=box.ROUNDED)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    
    table.add_row("[red]CRITICAL[/red]", str(report.critical_count))
    table.add_row("[orange1]HIGH[/orange1]", str(report.high_count))
    table.add_row("[yellow]MEDIUM[/yellow]", str(report.medium_count))
    table.add_row("[green]LOW[/green]", str(report.low_count))
    table.add_row("[bold]Total[/bold]", str(len(report.findings)))
    
    console.print(table)
    
    # Top findings
    if report.findings:
        console.print("\n[bold]Top Findings:[/bold]")
        for i, finding in enumerate(report.findings[:5], 1):
            sev_colors = {
                "CRITICAL": "red", "HIGH": "orange1", 
                "MEDIUM": "yellow", "LOW": "green", "INFO": "blue"
            }
            color = sev_colors.get(finding.severity, "white")
            console.print(
                f"  {i}. [{color}]{finding.severity}[/{color}] {finding.title}"
            )
    
    # Generate reports
    output.mkdir(parents=True, exist_ok=True)
    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    
    if fmt in ("json", "both"):
        import json
        json_path = output / f"audit_{timestamp}.json"
        with open(json_path, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        console.print(f"\n[green]JSON report:[/green] {json_path}")
    
    if fmt in ("html", "both"):
        from advulture.audit import _write_html_report
        html_path = output / f"audit_{timestamp}.html"
        _write_html_report(report, html_path)
        console.print(f"[green]HTML report:[/green] {html_path}")


@main.command()
def configure():
    """Generate example config.yaml for automation scenarios."""
    example = Path("config.example.yaml")
    content = """# ADVulture Configuration
# (c) 2025 Shane D. Shook, PhD - All Rights Reserved
#
# This config file is OPTIONAL. For interactive use, just run:
#   advulture analyze --ad-only          # On-prem AD
#   advulture analyze --entra-only       # Cloud (Entra ID)
#   advulture analyze --entra-auth device_code  # Hybrid
#
# Use this config file for automation scenarios with stored credentials.

# ── On-Premises Active Directory ──────────────────────────────────────
ldap:
  # Leave empty for auto-discovery, or specify explicitly
  server: ""                    # e.g., "ldaps://dc01.corp.local"
  domain: ""                    # e.g., "corp.local" (auto-discovered)
  base_dn: ""                   # e.g., "DC=corp,DC=local" (derived from domain)
  # Authentication: prompt, kerberos, ntlm, simple
  auth_mode: "prompt"
  # Only needed for auth_mode: simple (automation)
  username: ""
  password: ""

# ── Event Log Collection ──────────────────────────────────────────────
logs:
  evtx_paths: []                # List of EVTX files for offline analysis
  authn_window_days: 30
  authz_window_days: 90

# ── Entra ID / Azure AD ───────────────────────────────────────────────
# For interactive use, no config needed - just use --entra-auth device_code
entra:
  enabled: false
  # Authentication: device_code, interactive, client_secret, certificate, managed_identity
  auth_mode: "device_code"
  # Only needed for automation (client_secret, certificate, managed_identity)
  tenant_id: ""
  client_id: ""
  client_secret: ""
  certificate_path: ""

# ── Output ────────────────────────────────────────────────────────────
db_path: "advulture.duckdb"
report_dir: "reports"
log_level: "INFO"
"""
    example.write_text(content)
    console.print(f"[green]Written:[/green] {example}")
    console.print("This config is optional — for interactive use, just run: advulture analyze --ad-only")


@main.command()
@click.argument("log_file", type=Path)
def verify_custody(log_file: Path):
    """
    Verify integrity of a chain of custody log file.
    
    Checks cryptographic hash chain to detect any tampering or corruption.
    
    \b
    Example:
      advulture verify-custody custody_logs/custody_abc12345_20250512_183000.jsonl
    """
    from advulture.custody import ChainOfCustodyLogger
    
    if not log_file.exists():
        console.print(f"[red]Error:[/red] File not found: {log_file}")
        raise SystemExit(1)
    
    console.print(f"[cyan]Verifying:[/cyan] {log_file}")
    
    is_valid, errors = ChainOfCustodyLogger.verify_log_file(log_file)
    
    if is_valid:
        console.print("[bold green]✓ Chain of custody log is VALID[/bold green]")
        console.print("  Hash chain integrity verified — no tampering detected.")
        
        # Count entries
        with open(log_file, "r") as f:
            entry_count = sum(1 for _ in f)
        console.print(f"  Total entries: {entry_count}")
    else:
        console.print("[bold red]✗ Chain of custody log is INVALID[/bold red]")
        console.print("  The following integrity errors were detected:")
        for error in errors:
            console.print(f"    [red]•[/red] {error}")
        raise SystemExit(1)


@main.command()
@click.option("--dir", "-d", "log_dir", type=Path, default=Path("custody_logs"),
              help="Directory containing custody logs")
@click.option("--session", "-s", help="Filter by session ID prefix")
@click.option("--case", "-c", help="Filter by case ID")
def list_custody(log_dir: Path, session: Optional[str], case: Optional[str]):
    """
    List chain of custody log files.
    
    \b
    Example:
      advulture list-custody
      advulture list-custody --dir /path/to/logs --case CASE-2025-001
    """
    import json
    
    if not log_dir.exists():
        console.print(f"[yellow]No custody logs directory found:[/yellow] {log_dir}")
        return
    
    log_files = sorted(log_dir.glob("custody_*.jsonl"), reverse=True)
    
    if not log_files:
        console.print(f"[yellow]No custody logs found in:[/yellow] {log_dir}")
        return
    
    table = Table(title="Chain of Custody Logs", box=box.ROUNDED)
    table.add_column("File", style="cyan")
    table.add_column("Session")
    table.add_column("Case ID")
    table.add_column("Entries", justify="right")
    table.add_column("Started")
    table.add_column("Status")
    
    for log_file in log_files:
        try:
            with open(log_file, "r") as f:
                first_line = f.readline()
                first_entry = json.loads(first_line) if first_line else {}
                
                # Count entries
                entry_count = 1 + sum(1 for _ in f)
            
            session_id = first_entry.get("session_id", "")[:8]
            case_id = first_entry.get("details", {}).get("case_id", "-")
            timestamp = first_entry.get("timestamp", "")[:19]
            
            # Apply filters
            if session and not session_id.startswith(session):
                continue
            if case and case_id != case:
                continue
            
            # Verify integrity
            is_valid, _ = ChainOfCustodyLogger.verify_log_file(log_file)
            status = "[green]✓ Valid[/green]" if is_valid else "[red]✗ Invalid[/red]"
            
            table.add_row(
                log_file.name,
                session_id,
                case_id or "-",
                str(entry_count),
                timestamp,
                status,
            )
        except Exception as e:
            table.add_row(log_file.name, "?", "?", "?", "?", f"[red]Error: {e}[/red]")
    
    console.print(table)


if __name__ == "__main__":
    main()
