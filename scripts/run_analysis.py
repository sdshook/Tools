#!/usr/bin/env python3
"""
ADVulture — Quick Start Analysis Script
Run: python scripts/run_analysis.py --config config.yaml

For full CLI options: advulture --help
"""

import sys
import argparse
from pathlib import Path

# Allow running from project root without installation
sys.path.insert(0, str(Path(__file__).parent.parent))


def main():
    parser = argparse.ArgumentParser(description="ADVulture — Quick Analysis")
    parser.add_argument("--config", "-c", type=Path, default=Path("config.yaml"))
    parser.add_argument("--evtx", "-e", type=Path, nargs="*", help="EVTX files")
    parser.add_argument("--output", "-o", type=Path, default=Path("reports"))
    parser.add_argument("--format", choices=["html", "json", "both"], default="both")
    args = parser.parse_args()

    from advulture.config import Config
    from advulture.analysis.posture import PostureAnalyzer
    from advulture.reporting.report import ReportGenerator

    if args.config.exists():
        cfg = Config.from_file(args.config)
        print(f"Loaded config: {args.config}")
    else:
        cfg = Config()
        print("Warning: config.yaml not found — using defaults")

    if args.evtx:
        cfg.logs.evtx_paths = args.evtx

    print("Running analysis...")
    analyzer = PostureAnalyzer(cfg)
    report = analyzer.analyze()

    print(f"\n{report.summary()}")

    gen = ReportGenerator()
    args.output.mkdir(parents=True, exist_ok=True)
    results = gen.generate_all(report, args.output)
    print(f"\nReports written to {args.output}/")

    if report.active_signals:
        print(f"\n⚠  Active signals detected:")
        for sig in report.active_signals:
            print(f"   • {sig}")

    return 0 if report.regime != "CHAOTIC" else 1


if __name__ == "__main__":
    sys.exit(main())
