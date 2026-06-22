"""
URLScan.io Integration Module

Submits suspicious URLs to URLScan.io for analysis and retrieves:
- Rendered screenshots
- Verdict (malicious/suspicious/benign)
- DOM content and requests
- Detected technologies
- Brand impersonation indicators

This provides behavioral validation - we can see what the page actually does.

API docs: https://urlscan.io/docs/api/
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

import requests


URLSCAN_API = "https://urlscan.io/api/v1"
DEFAULT_TIMEOUT = 30


@dataclass
class URLScanResult:
    """Result from URLScan.io analysis."""
    url: str
    scan_id: str | None = None
    result_url: str | None = None
    screenshot_url: str | None = None
    
    # Verdicts
    is_malicious: bool = False
    malicious_score: int = 0
    verdicts: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    brands_detected: list[str] = field(default_factory=list)
    
    # Page analysis
    final_url: str | None = None
    page_title: str | None = None
    page_domain: str | None = None
    server: str | None = None
    ip_address: str | None = None
    asn: str | None = None
    country: str | None = None
    
    # Requests/resources
    requests_count: int = 0
    domains_contacted: list[str] = field(default_factory=list)
    
    # Detection indicators
    has_login_form: bool = False
    has_password_field: bool = False
    mimics_brand: str | None = None
    
    # Status
    status: str = "pending"  # pending, done, error
    error: str | None = None
    
    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "scan_id": self.scan_id,
            "result_url": self.result_url,
            "screenshot_url": self.screenshot_url,
            "is_malicious": self.is_malicious,
            "malicious_score": self.malicious_score,
            "verdicts": self.verdicts,
            "categories": self.categories,
            "brands_detected": self.brands_detected,
            "final_url": self.final_url,
            "page_title": self.page_title,
            "page_domain": self.page_domain,
            "server": self.server,
            "ip_address": self.ip_address,
            "asn": self.asn,
            "country": self.country,
            "requests_count": self.requests_count,
            "domains_contacted": self.domains_contacted,
            "has_login_form": self.has_login_form,
            "has_password_field": self.has_password_field,
            "mimics_brand": self.mimics_brand,
            "status": self.status,
            "error": self.error,
        }


def get_api_key() -> str | None:
    """Get URLScan.io API key from environment."""
    return os.environ.get("URLSCAN_API_KEY")


def submit_scan(
    url: str,
    api_key: str | None = None,
    visibility: str = "unlisted",
    tags: list[str] | None = None,
) -> URLScanResult:
    """
    Submit a URL to URLScan.io for scanning.
    
    Args:
        url: URL to scan
        api_key: URLScan.io API key (or from URLSCAN_API_KEY env var)
        visibility: public, unlisted, or private
        tags: Optional tags for the scan
    
    Returns:
        URLScanResult with scan_id (poll with get_result)
    """
    result = URLScanResult(url=url)
    api_key = api_key or get_api_key()
    
    if not api_key:
        result.status = "error"
        result.error = "No API key provided (set URLSCAN_API_KEY)"
        return result
    
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json",
    }
    
    payload = {
        "url": url,
        "visibility": visibility,
    }
    
    if tags:
        payload["tags"] = tags
    
    try:
        resp = requests.post(
            f"{URLSCAN_API}/scan/",
            headers=headers,
            json=payload,
            timeout=DEFAULT_TIMEOUT,
        )
        
        if resp.status_code == 429:
            result.status = "error"
            result.error = "Rate limited - too many requests"
            return result
        
        if resp.status_code == 401:
            result.status = "error"
            result.error = "Invalid API key"
            return result
            
        resp.raise_for_status()
        data = resp.json()
        
        result.scan_id = data.get("uuid")
        result.result_url = data.get("result")
        result.status = "pending"
        
    except requests.RequestException as e:
        result.status = "error"
        result.error = str(e)
    
    return result


def get_result(
    scan_id: str,
    api_key: str | None = None,
    wait: bool = True,
    max_wait: int = 60,
) -> URLScanResult:
    """
    Get results for a completed scan.
    
    Args:
        scan_id: UUID from submit_scan
        api_key: URLScan.io API key
        wait: If True, poll until scan completes
        max_wait: Maximum seconds to wait
    
    Returns:
        URLScanResult with full analysis
    """
    result = URLScanResult(url="", scan_id=scan_id)
    api_key = api_key or get_api_key()
    
    headers = {}
    if api_key:
        headers["API-Key"] = api_key
    
    start_time = time.time()
    
    while True:
        try:
            resp = requests.get(
                f"{URLSCAN_API}/result/{scan_id}/",
                headers=headers,
                timeout=DEFAULT_TIMEOUT,
            )
            
            if resp.status_code == 404:
                # Scan not ready yet
                if wait and (time.time() - start_time) < max_wait:
                    time.sleep(5)
                    continue
                else:
                    result.status = "pending"
                    return result
            
            resp.raise_for_status()
            data = resp.json()
            
            # Parse the result
            result = _parse_urlscan_result(data)
            result.scan_id = scan_id
            result.status = "done"
            return result
            
        except requests.RequestException as e:
            if wait and (time.time() - start_time) < max_wait:
                time.sleep(5)
                continue
            result.status = "error"
            result.error = str(e)
            return result


def _parse_urlscan_result(data: dict) -> URLScanResult:
    """Parse URLScan.io API response into URLScanResult."""
    result = URLScanResult(url=data.get("task", {}).get("url", ""))
    
    # Basic info
    task = data.get("task", {})
    page = data.get("page", {})
    
    result.result_url = f"https://urlscan.io/result/{task.get('uuid', '')}/"
    result.screenshot_url = f"https://urlscan.io/screenshots/{task.get('uuid', '')}.png"
    result.final_url = page.get("url")
    result.page_title = page.get("title")
    result.page_domain = page.get("domain")
    result.server = page.get("server")
    result.ip_address = page.get("ip")
    result.asn = page.get("asn")
    result.country = page.get("country")
    
    # Verdicts
    verdicts = data.get("verdicts", {})
    
    # Overall verdict
    overall = verdicts.get("overall", {})
    result.is_malicious = overall.get("malicious", False)
    result.malicious_score = overall.get("score", 0)
    result.categories = overall.get("categories", [])
    result.brands_detected = overall.get("brands", [])
    
    # Collect all verdict tags
    verdict_tags = []
    if overall.get("malicious"):
        verdict_tags.append("malicious")
    for tag in overall.get("tags", []):
        verdict_tags.append(tag)
    
    # URLScan community verdicts
    urlscan_verdicts = verdicts.get("urlscan", {})
    if urlscan_verdicts.get("malicious"):
        verdict_tags.append("urlscan:malicious")
    for tag in urlscan_verdicts.get("tags", []):
        verdict_tags.append(f"urlscan:{tag}")
    
    # Engine verdicts
    engines = verdicts.get("engines", {})
    if engines.get("malicious"):
        verdict_tags.append(f"engines:malicious ({engines.get('maliciousTotal', 0)} detections)")
    
    result.verdicts = verdict_tags
    
    # Requests analysis
    lists = data.get("lists", {})
    result.domains_contacted = lists.get("domains", [])[:20]  # Limit to 20
    
    stats = data.get("stats", {})
    result.requests_count = stats.get("requests", 0)
    
    # Check for login indicators in DOM
    dom = data.get("data", {}).get("dom", [])
    result.has_login_form = _check_for_login_form(data)
    result.has_password_field = _check_for_password_field(data)
    
    # Brand detection
    if result.brands_detected:
        result.mimics_brand = result.brands_detected[0]
    
    return result


def _check_for_login_form(data: dict) -> bool:
    """Check if page contains login form indicators."""
    # Check cookies for session indicators
    cookies = data.get("data", {}).get("cookies", [])
    
    # Check requests for auth endpoints
    requests_list = data.get("data", {}).get("requests", [])
    for req in requests_list[:100]:  # Check first 100 requests
        url = req.get("request", {}).get("url", "").lower()
        if any(x in url for x in ["login", "signin", "auth", "oauth", "token"]):
            return True
    
    # Check page content indicators (from console messages or globals)
    console = data.get("data", {}).get("console", [])
    for msg in console:
        if any(x in str(msg).lower() for x in ["password", "login", "credential"]):
            return True
    
    return False


def _check_for_password_field(data: dict) -> bool:
    """Check if page has password input field."""
    # This would require DOM analysis which isn't always available
    # URLScan doesn't expose raw DOM, but we can check globals
    globals_data = data.get("data", {}).get("globals", [])
    
    # Check if page loaded password-related resources
    requests_list = data.get("data", {}).get("requests", [])
    for req in requests_list[:100]:
        url = req.get("request", {}).get("url", "").lower()
        if "password" in url or "credential" in url:
            return True
    
    return False


def scan_and_wait(
    url: str,
    api_key: str | None = None,
    max_wait: int = 90,
    visibility: str = "unlisted",
) -> URLScanResult:
    """
    Submit a URL and wait for results.
    
    Convenience function that combines submit_scan and get_result.
    """
    # Submit
    submit_result = submit_scan(url, api_key=api_key, visibility=visibility)
    
    if submit_result.status == "error":
        return submit_result
    
    if not submit_result.scan_id:
        submit_result.status = "error"
        submit_result.error = "No scan ID returned"
        return submit_result
    
    # Wait a bit for scan to start
    time.sleep(10)
    
    # Get result
    return get_result(submit_result.scan_id, api_key=api_key, wait=True, max_wait=max_wait)


def search_urlscan(
    query: str,
    api_key: str | None = None,
    size: int = 100,
) -> list[dict]:
    """
    Search URLScan.io for existing scans.
    
    Useful for checking if a domain has been scanned before.
    
    Args:
        query: Search query (e.g., "domain:example.com" or "page.domain:microsoft*")
        api_key: Optional API key (public searches don't require key)
        size: Number of results to return
    
    Returns:
        List of scan result summaries
    """
    headers = {}
    if api_key:
        headers["API-Key"] = api_key
    
    try:
        resp = requests.get(
            f"{URLSCAN_API}/search/",
            params={"q": query, "size": size},
            headers=headers,
            timeout=DEFAULT_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("results", [])
    except requests.RequestException:
        return []


def check_domain_history(domain: str, api_key: str | None = None) -> list[dict]:
    """
    Check if a domain has been scanned before and what the verdicts were.
    
    Returns list of previous scan summaries.
    """
    results = search_urlscan(f"domain:{domain}", api_key=api_key, size=10)
    
    summaries = []
    for r in results:
        task = r.get("task", {})
        verdicts = r.get("verdicts", {})
        
        summaries.append({
            "scan_id": task.get("uuid"),
            "url": task.get("url"),
            "time": task.get("time"),
            "malicious": verdicts.get("overall", {}).get("malicious", False),
            "score": verdicts.get("overall", {}).get("score", 0),
            "categories": verdicts.get("overall", {}).get("categories", []),
        })
    
    return summaries


# CLI interface
if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python -m aitm_hunter.urlscan <url>")
        print("       python -m aitm_hunter.urlscan --search <query>")
        sys.exit(1)
    
    if sys.argv[1] == "--search":
        query = sys.argv[2] if len(sys.argv) > 2 else "domain:microsoft*"
        results = search_urlscan(query, size=5)
        for r in results:
            task = r.get("task", {})
            print(f"  {task.get('url')} - {task.get('time')}")
    else:
        url = sys.argv[1]
        print(f"Submitting {url} to URLScan.io...")
        
        result = scan_and_wait(url)
        
        if result.status == "done":
            print(f"\n✅ Scan complete: {result.result_url}")
            print(f"Screenshot: {result.screenshot_url}")
            print(f"Final URL: {result.final_url}")
            print(f"Title: {result.page_title}")
            print(f"Malicious: {result.is_malicious} (score: {result.malicious_score})")
            print(f"Verdicts: {result.verdicts}")
            print(f"Brands detected: {result.brands_detected}")
        else:
            print(f"\n❌ Error: {result.error}")
