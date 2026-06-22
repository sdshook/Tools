"""
Reporting layer: roll up search + triage + (optional) fingerprint/deepcrawl
data into a single record per URL, sorted by risk, exportable as CSV/JSON
for attaching to abuse reports (Google Ads, Microsoft DCU, Cloudflare,
registrar abuse contacts).
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


REPORT_FIELDS = [
    "query",
    "rank",
    "result_type",
    "title",
    "original_url",
    "final_url",
    "final_domain",
    "redirect_count",
    "domain_age_days",
    "registrar",
    "typosquat_target",
    "typosquat_score",
    "safe_browsing_flagged",
    "safe_browsing_threats",
    "urlhaus_flagged",
    "urlhaus_tags",
    # Fingerprint fields
    "tls_version",
    "cert_issuer",
    "is_likely_aitm",
    "is_likely_static_phish",
    "signature_matches",
    "fingerprint_risk_score",
    "fingerprint_risk_reasons",
    # Combined scoring
    "risk_score",
    "risk_reasons",
    # Deep crawl artifacts
    "screenshot_path",
    "har_path",
]


def _as_dict(obj: Any) -> dict:
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, dict):
        return obj
    raise TypeError(f"Cannot convert {type(obj)} to dict for reporting")


def merge_record(
    serp_result: Any,
    triage_result: Any,
    deepcrawl_result: Any | None = None,
) -> dict:
    """Combine one SerpResult + one TriageResult + optional DeepCrawlResult into a flat record."""
    merged: dict = {}
    merged.update(_as_dict(serp_result))
    merged.update(_as_dict(triage_result))
    if deepcrawl_result is not None:
        dc = _as_dict(deepcrawl_result)
        merged["screenshot_path"] = dc.get("screenshot_path", "")
        merged["har_path"] = dc.get("har_path", "")
    return merged


def write_json_report(records: list[dict], out_path: str) -> None:
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    records_sorted = sorted(records, key=lambda r: r.get("risk_score", 0), reverse=True)
    path.write_text(json.dumps(records_sorted, indent=2, default=str))


def write_csv_report(records: list[dict], out_path: str) -> None:
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    records_sorted = sorted(records, key=lambda r: r.get("risk_score", 0), reverse=True)

    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=REPORT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for rec in records_sorted:
            row = dict(rec)
            # Flatten list fields to semicolon-separated strings
            for key in ("safe_browsing_threats", "urlhaus_tags", "risk_reasons", "fingerprint_risk_reasons"):
                if isinstance(row.get(key), list):
                    row[key] = "; ".join(str(v) for v in row[key])
            # Handle signature_matches specially (list of dicts)
            if isinstance(row.get("signature_matches"), list):
                matches = row["signature_matches"]
                row["signature_matches"] = "; ".join(
                    f"{m.get('type', '')}:{m.get('kit', '')}" if isinstance(m, dict) else str(m)
                    for m in matches
                )
            writer.writerow(row)


def summarize(records: list[dict], threshold: int = 50) -> str:
    """Quick human-readable summary for terminal output."""
    high_risk = [r for r in records if r.get("risk_score", 0) >= threshold]
    lines = [
        f"Total URLs triaged: {len(records)}",
        f"High risk (score >= {threshold}): {len(high_risk)}",
        "",
    ]
    for r in sorted(high_risk, key=lambda r: r.get("risk_score", 0), reverse=True):
        lines.append(
            f"  [{r.get('risk_score')}] {r.get('final_domain', r.get('original_url'))} "
            f"-- {', '.join(r.get('risk_reasons', []))}"
        )
    return "\n".join(lines)
