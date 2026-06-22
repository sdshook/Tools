"""
Triage layer: cheap, safe-at-scale checks that don't render JS or execute
anything on the target page. Just HTTP HEAD/GET for redirect-chain
resolution, WHOIS, string-similarity typosquat scoring, and reputation
API lookups (Google Safe Browsing, URLhaus).

Nothing here opens a real browser. This is intentionally the stage you can
run against hundreds of URLs without the isolation concerns described in
SAFETY.md.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

try:
    import tldextract
    # Use the bundled snapshot instead of fetching the public suffix list
    # over the network on every cold start -- avoids failures in
    # network-restricted environments and avoids a slow first call.
    _tldextract_instance = tldextract.TLDExtract(suffix_list_urls=())
except ImportError:  # pragma: no cover
    tldextract = None
    _tldextract_instance = None

try:
    import whois as whois_lib  # python-whois
except ImportError:  # pragma: no cover
    whois_lib = None

try:
    from rapidfuzz import fuzz
except ImportError:  # pragma: no cover
    fuzz = None


SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"

# Brands commonly targeted by AiTM kits, for typosquat comparison.
# Extend this with your customer's actual domains.
DEFAULT_BRAND_DOMAINS = {
    "microsoft": ["microsoft.com", "office.com", "login.microsoftonline.com", "microsoftonline.com"],
    "google": ["google.com", "accounts.google.com"],
    "okta": ["okta.com"],

}


@dataclass
class TriageResult:
    original_url: str
    final_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    redirect_count: int = 0
    final_domain: str = ""
    domain_age_days: int | None = None
    registrar: str = ""
    typosquat_target: str = ""
    typosquat_score: float = 0.0
    safe_browsing_flagged: bool = False
    safe_browsing_threats: list[str] = field(default_factory=list)
    urlhaus_flagged: bool = False
    urlhaus_tags: list[str] = field(default_factory=list)
    http_error: str = ""
    risk_score: int = 0
    risk_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def resolve_redirect_chain(url: str, timeout: int = 10, max_hops: int = 10) -> tuple[list[str], str, str]:
    """
    Follow redirects manually (rather than trusting requests' built-in
    history blindly) so we get a clean ordered chain. Returns
    (chain, final_url, error_message).
    """
    chain: list[str] = []
    current = url
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )
    }
    try:
        for _ in range(max_hops):
            chain.append(current)
            resp = requests.get(
                current, headers=headers, timeout=timeout, allow_redirects=False, stream=True
            )
            resp.close()
            if resp.is_redirect or resp.is_permanent_redirect or resp.status_code in (301, 302, 303, 307, 308):
                next_url = resp.headers.get("Location")
                if not next_url:
                    break
                if next_url.startswith("/"):
                    parsed = urlparse(current)
                    next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"
                current = next_url
                continue
            break
        return chain, current, ""
    except requests.RequestException as e:
        return chain, current, str(e)


def get_domain(url: str) -> str:
    if _tldextract_instance:
        ext = _tldextract_instance(url)
        return ".".join(part for part in [ext.domain, ext.suffix] if part)
    return urlparse(url).netloc


def check_domain_age(domain: str) -> tuple[int | None, str]:
    """Return (age_in_days, registrar). Newly-registered domains are a strong
    AiTM/malvertising signal — most kits burn domains within days to weeks."""
    if not whois_lib:
        return None, ""
    try:
        w = whois_lib.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not creation:
            return None, str(w.registrar or "")
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation).days
        return age_days, str(w.registrar or "")
    except Exception:
        return None, ""


def _is_legitimate_domain_or_subdomain(domain: str, brand_domains: dict[str, list[str]]) -> bool:
    """True if `domain` IS one of the known-good domains, or a subdomain of one
    (e.g. login.microsoftonline.com is a legitimate subdomain of microsoftonline.com).
    Distinct from typosquatting, where the domain merely LOOKS similar."""
    for known_list in brand_domains.values():
        for known in known_list:
            if domain == known or domain.endswith("." + known):
                return True
    return False


def typosquat_score(domain: str, brand_domains: dict[str, list[str]] = DEFAULT_BRAND_DOMAINS) -> tuple[str, float]:
    """
    Fuzzy-match the candidate domain against known brand domains.
    Returns (best_matching_brand, similarity_score 0-100).
    A high score on a domain that ISN'T actually the real brand domain (or a
    legitimate subdomain of it) is suspicious -- a high score on the real
    domain itself is just... the real domain, so we explicitly exclude that
    case rather than relying on fuzzy-match math alone.
    """
    if not fuzz:
        return "", 0.0

    if _is_legitimate_domain_or_subdomain(domain, brand_domains):
        return "", 0.0

    best_brand, best_score = "", 0.0
    for brand, known_domains in brand_domains.items():
        for known in known_domains:
            score = fuzz.ratio(domain, known)
            if score > best_score:
                best_brand, best_score = brand, score
    return best_brand, best_score


def check_safe_browsing(url: str, api_key: str | None = None) -> tuple[bool, list[str]]:
    api_key = api_key or os.environ.get("GOOGLE_SAFE_BROWSING_KEY")
    if not api_key:
        return False, []
    body = {
        "client": {"clientId": "aitm-hunter", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(SAFE_BROWSING_ENDPOINT, params={"key": api_key}, json=body, timeout=10)
        resp.raise_for_status()
        matches = resp.json().get("matches", [])
        threats = [m.get("threatType", "") for m in matches]
        return bool(matches), threats
    except requests.RequestException:
        return False, []


def check_urlhaus(domain: str) -> tuple[bool, list[str]]:
    try:
        resp = requests.post(URLHAUS_ENDPOINT, data={"host": domain}, timeout=10)
        if resp.status_code != 200:
            return False, []
        data = resp.json()
        if data.get("query_status") != "ok":
            return False, []
        tags: list[str] = []
        for url_entry in data.get("urls", []):
            tags.extend(url_entry.get("tags", []) or [])
        return True, list(set(tags))
    except requests.RequestException:
        return False, []


def score_risk(result: TriageResult) -> tuple[int, list[str]]:
    """Roll the individual signals up into a single 0-100 risk score."""
    score = 0
    reasons = []

    if result.urlhaus_flagged:
        score += 50
        reasons.append("URLhaus: known malicious host")
    if result.safe_browsing_flagged:
        score += 50
        reasons.append(f"Google Safe Browsing: {', '.join(result.safe_browsing_threats)}")
    if result.typosquat_score >= 85 and result.typosquat_target:
        score += 30
        reasons.append(f"High similarity ({result.typosquat_score:.0f}) to {result.typosquat_target} domain")
    if result.domain_age_days is not None and result.domain_age_days < 30:
        score += 25
        reasons.append(f"Domain registered {result.domain_age_days} days ago")
    if result.redirect_count >= 3:
        score += 10
        reasons.append(f"{result.redirect_count} redirect hops before landing")
    if result.http_error:
        reasons.append(f"HTTP error during resolution: {result.http_error}")

    return min(score, 100), reasons


def triage_url(
    url: str,
    brand_domains: dict[str, list[str]] = DEFAULT_BRAND_DOMAINS,
    safe_browsing_key: str | None = None,
) -> TriageResult:
    result = TriageResult(original_url=url)

    chain, final_url, error = resolve_redirect_chain(url)
    result.redirect_chain = chain
    result.final_url = final_url
    result.redirect_count = max(len(chain) - 1, 0)
    result.http_error = error

    result.final_domain = get_domain(final_url or url)

    age_days, registrar = check_domain_age(result.final_domain)
    result.domain_age_days = age_days
    result.registrar = registrar

    brand, score = typosquat_score(result.final_domain, brand_domains)
    result.typosquat_target = brand
    result.typosquat_score = score

    flagged, threats = check_safe_browsing(final_url or url, api_key=safe_browsing_key)
    result.safe_browsing_flagged = flagged
    result.safe_browsing_threats = threats

    uh_flagged, uh_tags = check_urlhaus(result.final_domain)
    result.urlhaus_flagged = uh_flagged
    result.urlhaus_tags = uh_tags

    result.risk_score, result.risk_reasons = score_risk(result)
    return result
