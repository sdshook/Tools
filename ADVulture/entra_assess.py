#!/usr/bin/env python3
"""
ADVulture Entra-Only Security Assessment
Standalone script for Entra ID / M365 security posture analysis.
Does not require ML components.

Usage:
    python entra_assess.py [--days 7] [--output report.md]
"""

import asyncio
import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("advulture")

# Suppress verbose Azure SDK logging
logging.getLogger("azure").setLevel(logging.WARNING)
logging.getLogger("azure.core").setLevel(logging.WARNING)
logging.getLogger("azure.identity").setLevel(logging.WARNING)


async def run_assessment(days: int = 7, output_path: str = None):
    """Run Entra ID security assessment."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.table import Table
    
    from advulture.collection.entra_ingester import EntraEnumerator, EntraLogIngester
    from advulture.analysis.entra_report import EntraReportGenerator
    
    console = Console()
    
    console.print(Panel.fit(
        "[bold blue]🦅 ADVulture Entra ID Security Assessment[/bold blue]\n"
        "Comprehensive identity and permissions analysis",
        border_style="blue"
    ))
    
    # Phase 1: Authentication
    console.print("\n[cyan]Phase 1: Authentication[/cyan]")
    console.print("Using device code flow — check below for login instructions\n")
    
    enumerator = EntraEnumerator(auth_mode="device_code")
    
    # This will trigger device code prompt
    try:
        client = enumerator._get_client()
    except Exception as e:
        console.print(f"[red]Authentication failed:[/red] {e}")
        return
    
    console.print("\n[green]✓ Authentication successful[/green]\n")
    
    # Phase 2: Collection
    console.print("[cyan]Phase 2: Data Collection[/cyan]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        
        # Enumerate tenant
        task1 = progress.add_task("[cyan]Enumerating tenant configuration...", total=1)
        snapshot = await enumerator.enumerate_all()
        progress.update(task1, completed=1, description="[green]✓ Tenant enumeration complete")
        
        # Collect logs
        task2 = progress.add_task(f"[cyan]Collecting logs ({days} days)...", total=1)
        log_ingester = EntraLogIngester.from_enumerator(enumerator)
        events = await log_ingester.collect_window(days=days, include_security=True)
        progress.update(task2, completed=1, description="[green]✓ Log collection complete")
    
    # Collection summary
    console.print()
    table = Table(title="Collection Summary", show_header=True)
    table.add_column("Data Type", style="cyan")
    table.add_column("Count", justify="right", style="green")
    
    table.add_row("Users", str(len(snapshot.users)))
    table.add_row("Service Principals", str(len(snapshot.service_principals)))
    table.add_row("Role Definitions", str(len(snapshot.role_definitions)))
    table.add_row("Role Assignments", str(len(snapshot.all_role_assignments)))
    table.add_row("OAuth Grants", str(len(snapshot.oauth_grants)))
    table.add_row("Sign-in Events", str(len(events.signins)))
    table.add_row("Audit Events", str(len(events.audits)))
    table.add_row("Risk Detections", str(len(events.risk_detections)))
    table.add_row("Security Alerts", str(len(events.security_alerts)))
    table.add_row("App Permission Grants", str(len(events.app_permission_grants)))
    table.add_row("Mailbox Rules", str(len(events.mailbox_rules)))
    
    console.print(table)
    
    # Phase 3: Analysis
    console.print("\n[cyan]Phase 3: Security Analysis[/cyan]")
    
    generator = EntraReportGenerator(snapshot, events)
    report = generator.generate()
    
    # Findings summary
    console.print()
    findings_table = Table(title="Findings Summary", show_header=True)
    findings_table.add_column("Severity", style="bold")
    findings_table.add_column("Count", justify="right")
    
    severity_counts = {
        "CRITICAL": len([f for f in report.findings if f.severity.value == "CRITICAL"]),
        "HIGH": len([f for f in report.findings if f.severity.value == "HIGH"]),
        "MEDIUM": len([f for f in report.findings if f.severity.value == "MEDIUM"]),
        "LOW": len([f for f in report.findings if f.severity.value == "LOW"]),
        "INFO": len([f for f in report.findings if f.severity.value == "INFO"]),
    }
    
    findings_table.add_row("[red]CRITICAL[/red]", str(severity_counts["CRITICAL"]))
    findings_table.add_row("[orange1]HIGH[/orange1]", str(severity_counts["HIGH"]))
    findings_table.add_row("[yellow]MEDIUM[/yellow]", str(severity_counts["MEDIUM"]))
    findings_table.add_row("[blue]LOW[/blue]", str(severity_counts["LOW"]))
    findings_table.add_row("[dim]INFO[/dim]", str(severity_counts["INFO"]))
    findings_table.add_row("[bold]TOTAL[/bold]", f"[bold]{len(report.findings)}[/bold]")
    
    console.print(findings_table)
    
    # Print critical and high findings
    critical_high = [f for f in report.findings if f.severity.value in ("CRITICAL", "HIGH")]
    if critical_high:
        console.print("\n[bold red]Critical & High Severity Findings:[/bold red]")
        for i, finding in enumerate(critical_high, 1):
            sev_color = "red" if finding.severity.value == "CRITICAL" else "orange1"
            console.print(f"\n  [{sev_color}]{i}. [{finding.severity.value}] {finding.title}[/{sev_color}]")
            console.print(f"     [dim]{finding.description[:200]}...[/dim]" if len(finding.description) > 200 else f"     [dim]{finding.description}[/dim]")
            if finding.affected_objects:
                console.print(f"     [cyan]Affected:[/cyan] {', '.join(finding.affected_objects[:3])}")
    
    # Generate markdown report
    markdown = report.to_markdown()
    
    # Save report
    if output_path:
        output_file = Path(output_path)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = Path(f"entra_assessment_{timestamp}.md")
    
    output_file.write_text(markdown)
    console.print(f"\n[green]✓ Report saved to:[/green] {output_file}")
    
    # Also save JSON
    import json
    json_file = output_file.with_suffix(".json")
    json_file.write_text(json.dumps(report.to_dict(), indent=2, default=str))
    console.print(f"[green]✓ JSON data saved to:[/green] {json_file}")
    
    console.print(Panel.fit(
        f"[bold green]Assessment Complete[/bold green]\n"
        f"Total findings: {len(report.findings)} | "
        f"Critical: {severity_counts['CRITICAL']} | "
        f"High: {severity_counts['HIGH']}",
        border_style="green"
    ))
    
    return report


def main():
    parser = argparse.ArgumentParser(
        description="ADVulture Entra ID Security Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python entra_assess.py                     # 7-day analysis
    python entra_assess.py --days 30           # 30-day analysis
    python entra_assess.py --output report.md  # Custom output file
        """
    )
    parser.add_argument("--days", type=int, default=7, help="Days of logs to analyze (default: 7)")
    parser.add_argument("--output", "-o", type=str, help="Output file path (default: entra_assessment_TIMESTAMP.md)")
    
    args = parser.parse_args()
    
    # Run the async assessment
    asyncio.run(run_assessment(days=args.days, output_path=args.output))


if __name__ == "__main__":
    main()
