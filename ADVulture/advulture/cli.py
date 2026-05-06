# (c) 2025 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture — CLI Entry Point
"""

from __future__ import annotations
import logging
import sys
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
@click.pass_context
def analyze(ctx, output: Path, evtx, fmt: str):
    """Run posture analysis and generate reports."""
    from advulture.config import Config
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
    """Generate example config.yaml."""
    example = Path("config.example.yaml")
    content = """# ADVulture Configuration
# (c) 2025 Shane D. Shook, PhD - All Rights Reserved

ldap:
  server: "ldaps://dc01.corp.local"
  port: 636
  use_ssl: true
  username: "CORP\\advulture_svc"
  password: "CHANGE_ME"
  domain: "corp.local"
  base_dn: "DC=corp,DC=local"

logs:
  evtx_paths: []
  winrm_hosts: []
  authn_window_days: 30
  authz_window_days: 90

entra:
  enabled: false
  tenant_id: ""
  client_id: ""
  client_secret: ""

adfs:
  enabled: false
  server_hosts: []

db_path: "advulture.duckdb"
report_dir: "reports"
log_level: "INFO"
"""
    example.write_text(content)
    console.print(f"[green]Written:[/green] {example}")
    console.print("Edit config.example.yaml then rename to config.yaml")


@main.command()
@click.option("--output", "-o", type=Path, default=Path("reports"),
              help="Output directory for reports")
@click.pass_context
def collect(ctx, output: Path):
    """Enumerate AD objects only (no ML analysis)."""
    from advulture.config import Config
    from advulture.collection.ldap_enumerator import LDAPEnumerator
    import json
    
    config_path: Path = ctx.obj["config_path"]
    if not config_path.exists():
        console.print("[red]Error:[/red] config.yaml not found")
        raise SystemExit(1)
    
    cfg = Config.from_file(config_path)
    
    console.print(Panel.fit(
        "[bold cyan]🦅 ADVulture[/bold cyan] — Collection Mode",
        border_style="cyan",
    ))
    
    with console.status("[bold green]Enumerating AD objects..."):
        enum = LDAPEnumerator(
            cfg.ldap.server,
            cfg.ldap.username,
            cfg.ldap.password,
            cfg.ldap.base_dn,
        )
        snapshot = enum.enumerate_all()
    
    console.print(
        f"[bold]Collected:[/bold] "
        f"{len(snapshot.users)} users, "
        f"{len(snapshot.computers)} computers, "
        f"{len(snapshot.groups)} groups"
    )
    
    output.mkdir(parents=True, exist_ok=True)
    from datetime import datetime
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_path = output / f"collection_{timestamp}.json"
    
    with open(json_path, "w") as f:
        json.dump(snapshot.to_dict(), f, indent=2)
    
    console.print(f"[green]Collection saved:[/green] {json_path}")


if __name__ == "__main__":
    main()
