"""
Search-result discovery layer.

Prefers a paid SERP API (SerpApi here, but the pattern generalizes to
Bright Data SERP, Oxylabs, etc.) over raw Google scraping. Reasons, per the
research notes: Google blocks/cloaks bot traffic aggressively on ad-heavy
queries, many malvertising kits show benign content to obvious scrapers,
and scraping Google directly carries ToS risk that a paid API sidesteps.

If you don't have a SERP API key, use `load_manual_results()` to import
results you collected by hand (e.g. copy-pasted ad URLs, or exported from
a browser extension) as JSON/CSV in the same shape this module produces.
"""

from __future__ import annotations

import csv
import json
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable

import requests

SERPAPI_ENDPOINT = "https://serpapi.com/search"


@dataclass
class SerpResult:
    query: str
    rank: int
    result_type: str  # "ad" | "organic"
    title: str
    displayed_url: str
    actual_url: str  # the href, before any redirect following
    position_block: str = ""  # e.g. "top_ads", "organic", "bottom_ads"

    def to_dict(self) -> dict:
        return asdict(self)


def search_serpapi(query: str, api_key: str | None = None, num_results: int = 20) -> list[SerpResult]:
    """
    Query Google SERPs via SerpApi and return structured ad + organic results.

    SerpApi (or similar) is recommended specifically because it returns
    sponsored/ad blocks as structured fields rather than requiring you to
    parse rendered HTML and guess which divs are ads.
    """
    api_key = api_key or os.environ.get("SERPAPI_KEY")
    if not api_key:
        raise RuntimeError(
            "No SerpApi key found. Set SERPAPI_KEY env var, or use "
            "load_manual_results() instead of search_serpapi()."
        )

    params = {
        "engine": "google",
        "q": query,
        "num": num_results,
        "api_key": api_key,
    }
    resp = requests.get(SERPAPI_ENDPOINT, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    results: list[SerpResult] = []

    for i, ad in enumerate(data.get("ads", []), start=1):
        results.append(
            SerpResult(
                query=query,
                rank=i,
                result_type="ad",
                title=ad.get("title", ""),
                displayed_url=ad.get("displayed_link", ""),
                actual_url=ad.get("link", ""),
                position_block="ads",
            )
        )

    for i, org in enumerate(data.get("organic_results", []), start=1):
        results.append(
            SerpResult(
                query=query,
                rank=i,
                result_type="organic",
                title=org.get("title", ""),
                displayed_url=org.get("displayed_link", ""),
                actual_url=org.get("link", ""),
                position_block="organic",
            )
        )

    return results


def load_manual_results(path: str | Path) -> list[SerpResult]:
    """
    Load results from a CSV or JSON file you collected manually.

    Expected CSV columns: query,rank,result_type,title,displayed_url,actual_url,position_block
    Expected JSON: a list of objects with the same fields.
    """
    path = Path(path)
    if path.suffix.lower() == ".json":
        raw = json.loads(path.read_text())
        return [SerpResult(**row) for row in raw]

    if path.suffix.lower() == ".csv":
        out = []
        with path.open(newline="") as f:
            for row in csv.DictReader(f):
                row["rank"] = int(row.get("rank", 0) or 0)
                out.append(SerpResult(**row))
        return out

    raise ValueError(f"Unsupported file type for manual results: {path.suffix}")


def run_searches(
    queries: Iterable[str],
    api_key: str | None = None,
    num_results: int = 20,
    delay_seconds: float = 1.0,
) -> list[SerpResult]:
    """Run multiple queries with a small delay between calls (rate-limit courtesy)."""
    all_results: list[SerpResult] = []
    for q in queries:
        all_results.extend(search_serpapi(q, api_key=api_key, num_results=num_results))
        time.sleep(delay_seconds)
    return all_results
