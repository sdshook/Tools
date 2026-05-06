# (c) 2025 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture — Report Generator
Produces HTML and JSON reports from PostureReport.
"""

from __future__ import annotations
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape

from advulture.analysis.posture import PostureReport

log = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportGenerator:

    def __init__(self):
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )

    def generate_html(
        self,
        report: PostureReport,
        output_path: Optional[Path] = None,
    ) -> str:
        template = self.env.get_template("report.html.j2")
        html = template.render(report=report, version="0.1.0")
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(html, encoding="utf-8")
            log.info("HTML report written to %s", output_path)
        return html

    def generate_json(
        self,
        report: PostureReport,
        output_path: Optional[Path] = None,
    ) -> str:
        data = report.to_dict()
        content = json.dumps(data, indent=2, default=str)
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(content, encoding="utf-8")
            log.info("JSON report written to %s", output_path)
        return content

    def generate_all(self, report: PostureReport, output_dir: Path) -> dict:
        ts = report.timestamp.strftime("%Y%m%d_%H%M%S")
        domain = report.domain.replace(".", "_").replace(" ", "_")
        base = output_dir / f"advulture_{domain}_{ts}"
        return {
            "html": self.generate_html(report, base.with_suffix(".html")),
            "json": self.generate_json(report, base.with_suffix(".json")),
        }
