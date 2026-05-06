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

console = Console()
log = logging.getLogger("advulture")


@click.group()
@click.option("--config", "-c", type=Path, default=Path("config.yaml"),
              help="Path to config.yaml")
@click.option("--log-level", default="INFO",
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]))
@click.pass_context
def main(ctx, config: Path, log_level: str):
    """🦅 ADVulture — Active Directory Vulnerability Intelligence"""
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config


@main.command()
@click.option("--output", "-o", type=Path, default=Path("reports"),
              help="Output directory for reports")
@click.option("--evtx", "-e", type=Path, multiple=True,
              help="EVTX files to analyse (can specify multiple)")
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
    SIMPLEST USAGE - just run and authenticate:
    
      # Cloud-only (Entra ID)
      advulture analyze --entra-only
    
      # On-prem only (prompts for AD creds, auto-discovers domain)
      advulture analyze --ad-only
    
      # Hybrid (both on-prem AD and Entra)
      advulture analyze --entra-auth device_code
    
    \b
    On a domain-joined Windows machine with Kerberos ticket:
      advulture analyze --ad-auth kerberos --entra-auth device_code
    """
    from advulture.config import Config, EntraAuthMode, LDAPAuthMode
    from advulture.analysis.posture import PostureAnalyzer
    from advulture.reporting.report import ReportGenerator

    config_path: Path = ctx.obj["config_path"]
    if config_path.exists():
        cfg = Config.from_file(config_path)
    else:
        console.print("[yellow]config.yaml not found — using defaults[/yellow]")
        cfg = Config()

    if evtx:
        cfg.logs.evtx_paths = list(evtx)

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

    analyzer = PostureAnalyzer(cfg)
    report = analyzer.analyze()

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
        from datetime import datetime
        html_path = output / f"advulture_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
        gen.generate_html(report, html_path)
        console.print(f"\n[green]HTML report:[/green] {html_path}")
    if fmt in ("json", "both"):
        from datetime import datetime
        json_path = output / f"advulture_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        gen.generate_json(report, json_path)
        console.print(f"[green]JSON report:[/green] {json_path}")


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
    from datetime import datetime
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    
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


if __name__ == "__main__":
    main()
