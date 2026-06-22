"""
Deep-crawl layer. Read SAFETY.md before using this module.

This is the ONLY part of the pipeline that renders a real page in a real
browser, which means it's the only part that can actually phish you (as
happened when you clicked the live #1 result manually). Everything here is
deliberately built to:

  - require an explicit acknowledgement flag before it will run at all
  - never fill in or submit any form field, under any circumstance
  - never click anything on the page (no "continue", no "next", nothing)
  - capture observational artifacts only: screenshot, DOM snapshot, HAR

If you want more interactive analysis (e.g. seeing what happens after
"submitting"), that's a deliberate design choice this module does NOT make
for you, because of exactly what happened to your inbox. Do that kind of
testing only inside a fully disposable sandbox built for malware analysis,
not via this script.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from playwright.sync_api import sync_playwright


@dataclass
class DeepCrawlResult:
    url: str
    final_url: str = ""
    title: str = ""
    screenshot_path: str = ""
    har_path: str = ""
    dom_snapshot_path: str = ""
    console_messages: list[str] = field(default_factory=list)
    network_requests: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def deep_crawl_url(
    url: str,
    output_dir: str,
    i_have_read_safety_md: bool = False,
    timeout_ms: int = 20000,
) -> DeepCrawlResult:
    """
    Render `url` in an isolated headless browser and capture observational
    artifacts only. Will not fill forms, click links, or submit anything.

    Set `i_have_read_safety_md=True` explicitly to confirm you're running
    this from a disposable, network-isolated host per SAFETY.md. This is
    a deliberate friction point, not a real technical control -- the real
    control is YOUR environment, not this flag. The flag just makes sure
    you don't run this by accident from your laptop.
    """
    if not i_have_read_safety_md:
        raise RuntimeError(
            "Refusing to run. This stage renders live, potentially-malicious "
            "pages in a real browser. Read SAFETY.md, run this from a "
            "disposable/isolated host, then call again with "
            "i_have_read_safety_md=True."
        )

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(c if c.isalnum() else "_" for c in url)[:120]

    result = DeepCrawlResult(url=url)
    har_path = out_dir / f"{safe_name}.har"
    screenshot_path = out_dir / f"{safe_name}.png"
    dom_path = out_dir / f"{safe_name}.dom.html"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                record_har_path=str(har_path),
                ignore_https_errors=True,  # we want to see what's there even with cert issues
            )
            page = context.new_page()

            page.on("console", lambda msg: result.console_messages.append(f"{msg.type}: {msg.text}"))
            page.on(
                "request",
                lambda req: result.network_requests.append(f"{req.method} {req.url}"),
            )

            try:
                page.goto(url, timeout=timeout_ms, wait_until="networkidle")
            except Exception as nav_error:
                result.error = f"navigation error (page may have partially loaded): {nav_error}"

            result.final_url = page.url
            try:
                result.title = page.title()
            except Exception:
                pass

            # Observation only -- no .click(), no .fill(), no .press() on
            # anything. We deliberately stop here.
            page.screenshot(path=str(screenshot_path), full_page=True)
            result.screenshot_path = str(screenshot_path)

            dom_path.write_text(page.content())
            result.dom_snapshot_path = str(dom_path)

            context.close()
            browser.close()

        result.har_path = str(har_path)

    except Exception as e:
        result.error = (result.error + " | " if result.error else "") + str(e)

    return result


def deep_crawl_batch(
    urls: list[str],
    output_dir: str,
    i_have_read_safety_md: bool = False,
    delay_seconds: float = 2.0,
) -> list[DeepCrawlResult]:
    """Run deep_crawl_url across multiple URLs with a courteous delay between each."""
    results = []
    for url in urls:
        results.append(
            deep_crawl_url(url, output_dir, i_have_read_safety_md=i_have_read_safety_md)
        )
        time.sleep(delay_seconds)
    return results
