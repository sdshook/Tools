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
def configure():
    """Generate example config.yaml."""
    example = Path("config.example.yaml")
    content = """# ADVulture Configuration
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


if __name__ == "__main__":
    main()
