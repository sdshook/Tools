"""
Volatility 3 engine wrapper.

Uses Volatility as a Python library (not subprocess) for OS structure
analysis: process trees, network connections, environment variables,
handles, command lines, and process memory dumps.

Volatility docs: https://volatility3.readthedocs.io/en/stable/using-as-a-library.html
"""

import os
import json
import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field
from rich.console import Console

console = Console()
logging.getLogger("volatility3").setLevel(logging.WARNING)


@dataclass
class VolResult:
    """Results from Volatility analysis."""
    processes: list = field(default_factory=list)
    network_connections: list = field(default_factory=list)
    env_vars: dict = field(default_factory=dict)     # pid -> {var: val}
    cmdlines: dict = field(default_factory=dict)     # pid -> cmdline
    handles: dict = field(default_factory=dict)      # pid -> [handles]
    dumped_files: list = field(default_factory=list) # paths to dumped process memory
    errors: list = field(default_factory=list)


class VolEngine:
    """
    Wraps Volatility 3 library API for memory structure analysis.
    """

    def __init__(self, symbols_path: Optional[str] = None):
        self.symbols_path = symbols_path
        self._ctx = None

    def run(self, memory_path: Path, work_dir: Path) -> Optional[VolResult]:
        """
        Run full Volatility analysis suite on a memory image.
        Returns VolResult, or None if Volatility unavailable.
        """
        try:
            import volatility3
            from volatility3 import framework
            from volatility3.framework import contexts, automagic
        except ImportError:
            console.print(
                "  [yellow]volatility3 not installed — "
                "skipping OS structure analysis[/yellow]")
            return None

        work_dir = Path(work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)

        result = VolResult()

        console.print(
            f"  [bold blue]Volatility 3[/bold blue] "
            f"analysing {memory_path.name}")

        try:
            ctx = self._build_context(memory_path, framework, contexts)
        except Exception as e:
            result.errors.append(f"Context build failed: {e}")
            console.print(f"  [red]Volatility context error: {e}[/red]")
            return result

        plugins_to_run = [
            ("pstree",   self._run_pstree),
            ("netscan",  self._run_netscan),
            ("envars",   self._run_envars),
            ("cmdline",  self._run_cmdline),
        ]

        for name, fn in plugins_to_run:
            try:
                fn(ctx, result, work_dir)
                console.print(f"    [green]✓[/green] {name}")
            except Exception as e:
                result.errors.append(f"{name}: {e}")
                console.print(f"    [yellow]✗ {name}: {e}[/yellow]")

        # Write results to disk
        out_path = work_dir / "volatility_results.json"
        out_path.write_text(json.dumps({
            "processes":     result.processes,
            "network":       result.network_connections,
            "env_vars":      result.env_vars,
            "cmdlines":      result.cmdlines,
            "errors":        result.errors,
        }, indent=2, default=str))

        console.print(
            f"  Volatility: {len(result.processes)} processes, "
            f"{len(result.network_connections)} connections")

        return result

    def get_env_var(
        self, pid: int, var_name: str
    ) -> Optional[str]:
        """Get a specific environment variable for a PID."""
        if self._ctx is None:
            return None
        pid_env = self._vol_result_env.get(str(pid), {})
        return pid_env.get(var_name) or pid_env.get(var_name.upper())

    # ── Plugin runners ─────────────────────────────────────────────────

    def _build_context(self, memory_path, framework, contexts):
        """Build a Volatility context for the memory image."""
        from volatility3.framework import constants
        from volatility3.framework.configuration import requirements

        ctx = contexts.Context()
        ctx.config["automagic.LayerStacker.single_location"] = \
            memory_path.as_uri() if hasattr(memory_path, 'as_uri') \
            else f"file://{memory_path.resolve()}"

        if self.symbols_path:
            ctx.config[constants.SYMBOL_PATH] = self.symbols_path

        self._ctx = ctx
        return ctx

    def _run_pstree(self, ctx, result: VolResult, work_dir: Path):
        """Extract process tree."""
        from volatility3.plugins.windows import pstree as vol_pstree
        from volatility3.framework import automagic, interfaces

        automagics = automagic.available(ctx)
        plugin = vol_pstree.PsTree(ctx, config_path="plugins.PsTree",
                                   progress_callback=None)
        try:
            tree = plugin.run()
            for row in tree:
                result.processes.append({
                    "pid":    int(row[0]),
                    "ppid":   int(row[1]),
                    "name":   str(row[2]),
                    "offset": str(row[3]),
                })
        except Exception:
            # Try pslist as fallback
            from volatility3.plugins.windows import pslist as vol_pslist
            plugin = vol_pslist.PsList(ctx, config_path="plugins.PsList",
                                       progress_callback=None)
            tree = plugin.run()
            for row in tree:
                result.processes.append({
                    "pid":  int(row[0]),
                    "ppid": int(row[1]),
                    "name": str(row[2]),
                })

    def _run_netscan(self, ctx, result: VolResult, work_dir: Path):
        """Extract network connections."""
        from volatility3.plugins.windows import netstat as vol_netscan
        plugin = vol_netscan.NetStat(ctx, config_path="plugins.NetStat",
                                     progress_callback=None)
        for row in plugin.run():
            result.network_connections.append({
                "offset":   str(row[0]),
                "proto":    str(row[1]),
                "local_ip": str(row[2]),
                "local_port": int(row[3] or 0),
                "remote_ip":  str(row[4]),
                "remote_port": int(row[5] or 0),
                "state":    str(row[6]),
                "pid":      int(row[7] or 0),
                "owner":    str(row[8]),
            })

    def _run_envars(self, ctx, result: VolResult, work_dir: Path):
        """Extract process environment variables."""
        from volatility3.plugins.windows import envars as vol_envars
        plugin = vol_envars.Envars(ctx, config_path="plugins.Envars",
                                   progress_callback=None)
        self._vol_result_env = {}
        for row in plugin.run():
            pid = str(int(row[0]))
            var = str(row[2])
            val = str(row[3])
            if pid not in self._vol_result_env:
                self._vol_result_env[pid] = {}
                result.env_vars[pid] = {}
            self._vol_result_env[pid][var] = val
            result.env_vars[pid][var] = val

    def _run_cmdline(self, ctx, result: VolResult, work_dir: Path):
        """Extract process command lines."""
        from volatility3.plugins.windows import cmdline as vol_cmdline
        plugin = vol_cmdline.CmdLine(ctx, config_path="plugins.CmdLine",
                                     progress_callback=None)
        for row in plugin.run():
            pid = str(int(row[0]))
            result.cmdlines[pid] = str(row[2])

    def dump_process(
        self,
        ctx,
        pid: int,
        work_dir: Path,
    ) -> Optional[Path]:
        """
        Dump process memory for a specific PID using Volatility.
        Returns path to dump file, or None on failure.
        """
        try:
            from volatility3.plugins.windows import dumpfiles as vol_dump
            plugin = vol_dump.DumpFiles(
                ctx,
                config_path="plugins.DumpFiles",
                progress_callback=None,
            )
            ctx.config["plugins.DumpFiles.pid"] = [pid]
            ctx.config["plugins.DumpFiles.dump-dir"] = str(work_dir)
            plugin.run()

            # Find dumped file
            for f in work_dir.glob(f"pid.{pid}*.dmp"):
                return f
        except Exception as e:
            console.print(
                f"  [yellow]Volatility dump PID {pid}: {e}[/yellow]")
        return None
