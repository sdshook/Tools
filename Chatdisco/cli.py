"""
Chatdisco - AI Chat Forensics Tool
CLI entry point providing 'collect' and 'analyze' subcommands.
"""

import sys
import click
from rich.console import Console
from rich.panel import Panel

from chatdisco.core.dependency_check import check_dependencies
from chatdisco.core.intake import InputType

console = Console()

BANNER = """
 ██████╗██╗  ██╗ █████╗ ████████╗██████╗ ██╗███████╗ ██████╗ ██████╗
██╔════╝██║  ██║██╔══██╗╚══██╔══╝██╔══██╗██║██╔════╝██╔════╝██╔═══██╗
██║     ███████║███████║   ██║   ██║  ██║██║███████╗██║     ██║   ██║
██║     ██╔══██║██╔══██║   ██║   ██║  ██║██║╚════██║██║     ██║   ██║
╚██████╗██║  ██║██║  ██║   ██║   ██████╔╝██║███████║╚██████╗╚██████╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═════╝

AI Chat Forensics Tool v0.1.0
"""


@click.group()
@click.version_option(version="0.1.0")
def main():
    """Chatdisco - AI Chat Activity Forensics.

    Extracts and reconstructs AI chat sessions from memory dumps,
    process dumps, PCAP files, and disk artifacts. Supports all
    major AI services (ChatGPT, Claude, Copilot, Perplexity, Gemini,
    Grok, Ollama, LM Studio, and more).

    Produces CASE/UCO-format evidence bundles with full chain of
    custody documentation including SBOM.
    """
    console.print(BANNER, style="bold cyan")


@main.command()
@click.option("--output", "-o", required=True,
              type=click.Path(), help="Output directory for collected artifacts")
@click.option("--mode", "-m",
              type=click.Choice(["full", "triage", "targeted"]),
              default="triage", show_default=True,
              help="Collection mode: full|triage|targeted")
@click.option("--target-pids", "-p", default=None,
              help="Comma-separated PIDs to target (targeted mode)")
@click.option("--pcap-duration", "-d", default=300, show_default=True,
              help="PCAP capture duration in seconds (0=until stopped)")
@click.option("--no-disk", is_flag=True, default=False,
              help="Skip disk artifact collection (RAM + network only)")
@click.option("--examiner", "-e", required=True,
              help="Examiner name for chain of custody")
@click.option("--case-id", "-c", required=True,
              help="Case identifier for chain of custody")
@click.option("--org", default="",
              help="Examiner organisation")
@click.option("--notes", default="",
              help="Free-text acquisition notes")
def collect(output, mode, target_pids, pcap_duration, no_disk,
            examiner, case_id, org, notes):
    """Live collection: captures memory, network, keys, and disk artifacts.

    Must be run with administrator/root privileges on the target system.
    Produces a self-contained evidence directory consumable by 'analyze'.

    Example:
        chatdisco collect -o /mnt/usb/CASE-001 -e "J.Smith" -c "2025-042"
    """
    from chatdisco.collect.collector import Collector

    console.print(Panel(
        f"[bold]Case:[/bold] {case_id}\n"
        f"[bold]Examiner:[/bold] {examiner}\n"
        f"[bold]Mode:[/bold] {mode}\n"
        f"[bold]Output:[/bold] {output}",
        title="[bold green]Live Collection Starting[/bold green]",
        border_style="green"
    ))

    # Verify privileges
    import os
    if os.name == "nt":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            console.print("[bold red]ERROR:[/bold red] Administrator "
                          "privileges required for live collection.")
            sys.exit(1)
    elif os.getuid() != 0:
        console.print("[bold red]ERROR:[/bold red] Root privileges "
                      "required for live collection.")
        sys.exit(1)

    deps = check_dependencies(require_collection=True)
    if not deps.all_required_present:
        console.print(deps.format_missing())
        sys.exit(1)

    pids = None
    if target_pids:
        try:
            pids = [int(p.strip()) for p in target_pids.split(",")]
        except ValueError:
            console.print("[bold red]ERROR:[/bold red] "
                          "Invalid PID list format.")
            sys.exit(1)

    collector = Collector(
        output_dir=output,
        mode=mode,
        target_pids=pids,
        pcap_duration=pcap_duration,
        collect_disk=not no_disk,
        examiner=examiner,
        case_id=case_id,
        org=org,
        notes=notes,
    )

    try:
        collector.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Collection interrupted by user. "
                      "Finalising manifest...[/yellow]")
        collector.finalise()


@main.command()
@click.option("--input", "-i", "input_path", required=True,
              type=click.Path(exists=True),
              help="Input: memory dump, process dump, PCAP, "
                   "disk image, or collected evidence directory")
@click.option("--output", "-o", required=True,
              type=click.Path(), help="Output directory for analysis results")
@click.option("--keylog", "-k", default=None,
              type=click.Path(exists=True),
              help="TLS key log file (NSS/SSLKEYLOGFILE format)")
@click.option("--memory", "-m", default=None,
              type=click.Path(exists=True),
              help="Memory dump to pair with PCAP for key extraction")
@click.option("--examiner", "-e", required=True,
              help="Examiner name for chain of custody")
@click.option("--case-id", "-c", required=True,
              help="Case identifier")
@click.option("--org", default="",
              help="Examiner organisation")
@click.option("--services", "-s", default=None,
              help="Comma-separated services to target "
                   "(default: all). e.g. openai,anthropic,ollama")
@click.option("--report-format", "-r",
              type=click.Choice(["html", "pdf", "json", "all"]),
              default="all", show_default=True,
              help="Report output format")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Verbose output")
def analyze(input_path, output, keylog, memory, examiner, case_id,
            org, services, report_format, verbose):
    """Analyze collected artifacts and reconstruct AI chat activity.

    Accepts a collected evidence directory (from 'collect'), a raw
    memory dump, process dump, PCAP file, or disk image.

    Example:
        chatdisco analyze -i /mnt/usb/CASE-001 -o ./results
            -e "J.Smith" -c "2025-042"

        chatdisco analyze -i memory.raw -o ./results
            -e "J.Smith" -c "2025-042" --keylog tls-keys.log
    """
    from chatdisco.core.intake import Intake
    from chatdisco.core.pipeline import AnalysisPipeline

    deps = check_dependencies(require_collection=False)
    if not deps.all_required_present:
        console.print(deps.format_missing())
        sys.exit(1)

    console.print(Panel(
        f"[bold]Case:[/bold] {case_id}\n"
        f"[bold]Examiner:[/bold] {examiner}\n"
        f"[bold]Input:[/bold] {input_path}\n"
        f"[bold]Output:[/bold] {output}",
        title="[bold blue]Analysis Starting[/bold blue]",
        border_style="blue"
    ))

    target_services = None
    if services:
        target_services = [s.strip().lower() for s in services.split(",")]

    intake = Intake(
        input_path=input_path,
        examiner=examiner,
        case_id=case_id,
        org=org,
        keylog_path=keylog,
        paired_memory=memory,
    )

    pipeline = AnalysisPipeline(
        intake=intake,
        output_dir=output,
        target_services=target_services,
        report_format=report_format,
        verbose=verbose,
    )

    pipeline.run()


if __name__ == "__main__":
    main()
