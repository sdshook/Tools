"""
Fingerprinting layer.

Two independent signals, both drawn from published AiTM-detection research
rather than guesswork:

1. JA3/JA4 TLS client/server fingerprinting. AiTM reverse-proxy toolkits
   (Evilginx, Modlishka, Muraena) are built on specific TLS libraries/stacks,
   which gives them a recognizable JA4S (server-side) fingerprint distinct
   from the real IdP they're proxying. This is the "toolkit-agnostic"
   approach from the academic AiTM-detection literature: it doesn't rely on
   HTML/JS content (which is trivially changed) but on lower-level network
   behavior that's expensive for an attacker to fake.

2. The "dynamic proxy" behavioral probe from Deepwatch's Evilginx research:
   static phishing kits serve a fixed page where things like "Forgot
   password" don't actually work and arbitrary credentials get accepted.
   AiTM reverse proxies, by contrast, continuously fetch live content from
   the real IdP, so interactive elements behave like the real site. We test
   this passively (no credentials submitted) by checking whether
   non-credential page resources (logos, CSS, well-known IdP API endpoints)
   are being live-proxied vs. served from the candidate's own origin.

JA4+ ATTRIBUTION:
-----------------
JA4+ is a network fingerprinting methodology created by John Althouse at FoxIO.
https://github.com/FoxIO-LLC/ja4

Licensing:
- JA4 (TLS Client): BSD 3-Clause
- JA4S, JA4H, JA4X (JA4+): FoxIO License 1.1 (permissive for security use)

Signature database is maintained in signatures.py with 90+ known-bad
fingerprints from multiple sources.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

import requests

# Import signatures from the dedicated signatures module
from aitm_hunter.signatures import (
    KNOWN_MALWARE_JA4_CLIENT,
    KNOWN_AITM_JA4S_SIGNATURES,
    KNOWN_MALWARE_JA4X,
    KNOWN_MALWARE_JA4H,
    KNOWN_MALWARE_JA3,
)

# Import JA4S computation
from aitm_hunter.ja4 import get_ja4s, JA4SResult

# Resources that, if NOT being proxied (i.e. served from the candidate's own
# domain instead of redirecting to/fetching from the real IdP), suggest a
# static phishing kit rather than a live AiTM reverse proxy. Conversely, if
# they ARE being actively fetched from the real IdP at request time, that's
# consistent with a reverse-proxy AiTM setup. Either way it's a useful signal
# -- we're not asserting one implies "safe."
IDP_LIVE_RESOURCE_PROBES = {
    "microsoft": [
        "https://aadcdn.msftauth.net/shared/1.0/content/images/favicon_a_eupayfgghqiai7k9wsj1sg2.ico",
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "https://logincdn.msauth.net/shared/1.0/content/js/ConvergedLogin_PCore.js",
    ],
    "google": [
        "https://accounts.google.com/favicon.ico",
        "https://www.gstatic.com/accounts/ui/avatar_2x.png",
        "https://ssl.gstatic.com/accounts/ui/logo_2x.png",
    ],
    "okta": [
        "https://ok1static.oktacdn.com/assets/img/logos/okta-logo.png",
        "https://ok1static.oktacdn.com/assets/js/sdk/okta-signin-widget/current/js/okta-sign-in.min.js",
    ],
}


@dataclass
class FingerprintResult:
    domain: str
    ip_address: str = ""
    tls_version: str = ""
    cipher_suite: str = ""
    cert_issuer: str = ""
    cert_subject: str = ""
    cert_not_before: str = ""
    cert_not_after: str = ""
    ja4s_hash: str = ""  # JA4S fingerprint (computed via ja4.py)
    ja4s_raw: str = ""   # Raw JA4S for debugging
    matched_kit_signature: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def get_tls_certificate_info(domain: str, port: int = 443, timeout: int = 10) -> FingerprintResult:
    """
    Pull TLS/cert metadata and compute JA4S fingerprint.
    
    This function:
    1. Resolves the domain to IP
    2. Computes JA4S fingerprint (server TLS fingerprint)
    3. Captures certificate metadata (issuer, validity dates)
    
    JA4S fingerprinting is based on the methodology by John Althouse at FoxIO:
    https://github.com/FoxIO-LLC/ja4
    
    This is a "triage-safe" operation - no rendering, no JS execution.
    """
    result = FingerprintResult(domain=domain)
    
    try:
        # Resolve IP
        result.ip_address = socket.gethostbyname(domain)
        
        # Compute JA4S fingerprint
        ja4s_result = get_ja4s(domain, port, timeout)
        if ja4s_result.ja4s:
            result.ja4s_hash = ja4s_result.ja4s
            result.ja4s_raw = ja4s_result.ja4s_raw
            result.tls_version = f"TLSv1.{ja4s_result.version}" if ja4s_result.version.isdigit() else ja4s_result.version
            
            # Check for signature match
            if ja4s_result.ja4s in KNOWN_AITM_JA4S_SIGNATURES:
                result.matched_kit_signature = KNOWN_AITM_JA4S_SIGNATURES[ja4s_result.ja4s]
        
        if ja4s_result.error and "partial" not in ja4s_result.error:
            result.error = ja4s_result.error
        
        # Get cipher suite name via standard SSL (more readable than hex)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    if not result.tls_version:
                        result.tls_version = ssock.version() or ""
                    cipher = ssock.cipher()
                    result.cipher_suite = cipher[0] if cipher else ""
        except (socket.error, ssl.SSLError):
            pass

        # Parse certificate fields
        try:
            ctx2 = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        result.cert_issuer = str(dict(x[0] for x in cert.get("issuer", [])))
                        result.cert_subject = str(dict(x[0] for x in cert.get("subject", [])))
                        result.cert_not_before = cert.get("notBefore", "")
                        result.cert_not_after = cert.get("notAfter", "")
        except ssl.SSLError:
            pass  # self-signed or otherwise unverifiable; non-fatal

    except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError) as e:
        result.error = str(e)

    return result


def check_known_kit_signature(ja4s_hash: str) -> str:
    """Look up a JA4S hash against the known-bad list. Returns kit name or ''."""
    return KNOWN_AITM_JA4S_SIGNATURES.get(ja4s_hash, "")


def check_all_signatures(
    ja4_hash: str = "",
    ja4s_hash: str = "",
    ja4x_hash: str = "",
    ja4h_hash: str = "",
) -> list[tuple[str, str, str]]:
    """
    Check all provided hashes against all known-bad signature databases.
    Returns list of (hash_type, hash_value, kit_name) for any matches.
    """
    matches = []
    if ja4_hash and ja4_hash in KNOWN_MALWARE_JA4_CLIENT:
        matches.append(("JA4", ja4_hash, KNOWN_MALWARE_JA4_CLIENT[ja4_hash]))
    if ja4s_hash and ja4s_hash in KNOWN_AITM_JA4S_SIGNATURES:
        matches.append(("JA4S", ja4s_hash, KNOWN_AITM_JA4S_SIGNATURES[ja4s_hash]))
    if ja4x_hash and ja4x_hash in KNOWN_MALWARE_JA4X:
        matches.append(("JA4X", ja4x_hash, KNOWN_MALWARE_JA4X[ja4x_hash]))
    if ja4h_hash and ja4h_hash in KNOWN_MALWARE_JA4H:
        matches.append(("JA4H", ja4h_hash, KNOWN_MALWARE_JA4H[ja4h_hash]))
    return matches


def probe_live_proxy_behavior(candidate_domain: str, brand: str, timeout: int = 10) -> dict:
    """
    Passive behavioral probe: request a known IdP-hosted static resource
    (e.g. Microsoft's auth CDN favicon) and compare against the same path
    requested on the candidate domain.

    This never submits credentials or interacts with login forms -- it's
    just comparing static asset delivery, which is enough to distinguish
    "static cloned HTML" kits from "live reverse-proxy" kits per the
    Deepwatch research referenced in the module docstring.

    Returns a dict of observations; interpretation is left to the caller
    since a mismatch isn't inherently proof of maliciousness on its own --
    it's one signal among several.
    """
    observations = {"candidate_domain": candidate_domain, "brand": brand, "checked_resources": []}

    probes = IDP_LIVE_RESOURCE_PROBES.get(brand, [])
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )
    }

    for resource_url in probes:
        entry = {"resource": resource_url}
        try:
            direct = requests.get(resource_url, headers=headers, timeout=timeout)
            entry["direct_status"] = direct.status_code
            entry["direct_content_length"] = len(direct.content)
        except requests.RequestException as e:
            entry["direct_error"] = str(e)

        parsed = urlparse(resource_url)
        candidate_url = f"https://{candidate_domain}{parsed.path}"
        try:
            via_candidate = requests.get(candidate_url, headers=headers, timeout=timeout)
            entry["candidate_status"] = via_candidate.status_code
            entry["candidate_content_length"] = len(via_candidate.content)
        except requests.RequestException as e:
            entry["candidate_error"] = str(e)

        observations["checked_resources"].append(entry)

    return observations


@dataclass
class FullFingerprintResult:
    """Combined result of all fingerprinting checks for a URL."""
    url: str
    domain: str = ""
    tls_info: FingerprintResult | None = None
    proxy_behavior: dict = field(default_factory=dict)
    signature_matches: list[tuple[str, str, str]] = field(default_factory=list)
    is_likely_aitm: bool = False
    is_likely_static_phish: bool = False
    fingerprint_risk_score: int = 0
    fingerprint_risk_reasons: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.tls_info:
            d["tls_info"] = self.tls_info.to_dict()
        return d


def fingerprint_url(
    url: str,
    brand: str = "",
    check_tls: bool = True,
    check_proxy_behavior: bool = True,
) -> FullFingerprintResult:
    """
    Run all fingerprinting checks on a URL.
    
    This is the main entry point for fingerprint analysis. It combines:
    - TLS certificate inspection
    - Signature matching against known-bad JA4+ hashes
    - Live proxy behavior probing (if brand is specified)
    
    Returns a FullFingerprintResult with risk scoring.
    """
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    
    result = FullFingerprintResult(url=url, domain=domain)
    risk_score = 0
    risk_reasons = []
    
    # TLS fingerprinting with JA4S computation
    if check_tls:
        try:
            tls_result = get_tls_certificate_info(domain)
            result.tls_info = tls_result
            
            if tls_result.error and "partial" not in tls_result.error:
                result.error = tls_result.error
            
            # Check for Let's Encrypt (common for throwaway phishing domains)
            if tls_result.cert_issuer and "Let's Encrypt" in tls_result.cert_issuer:
                # Not inherently bad, but combined with other signals is notable
                pass
            
            # Check JA4S signature if available
            if tls_result.ja4s_hash:
                kit_match = check_known_kit_signature(tls_result.ja4s_hash)
                if kit_match:
                    result.signature_matches.append(("JA4S", tls_result.ja4s_hash, kit_match))
                    risk_score += 50
                    risk_reasons.append(f"JA4S signature matches known kit: {kit_match}")
            
            # Also check if matched_kit_signature was set during fingerprinting
            if tls_result.matched_kit_signature and not any(m[0] == "JA4S" for m in result.signature_matches):
                result.signature_matches.append(("JA4S", tls_result.ja4s_hash, tls_result.matched_kit_signature))
                risk_score += 50
                risk_reasons.append(f"JA4S signature matches known kit: {tls_result.matched_kit_signature}")
                    
        except Exception as e:
            result.error = f"TLS check failed: {e}"
    
    # Proxy behavior check (only if brand specified)
    if check_proxy_behavior and brand:
        try:
            proxy_obs = probe_live_proxy_behavior(domain, brand)
            result.proxy_behavior = proxy_obs
            
            # Analyze proxy behavior
            resources = proxy_obs.get("checked_resources", [])
            proxied_count = 0
            static_count = 0
            
            for res in resources:
                direct_len = res.get("direct_content_length", 0)
                candidate_len = res.get("candidate_content_length", 0)
                candidate_status = res.get("candidate_status", 0)
                
                if candidate_status == 200 and direct_len > 0:
                    # Check if content length is similar (suggests proxying)
                    if candidate_len > 0 and abs(candidate_len - direct_len) < 1000:
                        proxied_count += 1
                    elif candidate_len > 0:
                        static_count += 1
            
            if proxied_count > 0:
                result.is_likely_aitm = True
                risk_score += 30
                risk_reasons.append(f"Behavior consistent with AiTM reverse proxy ({proxied_count} resources proxied)")
            elif static_count > 0:
                result.is_likely_static_phish = True
                risk_score += 20
                risk_reasons.append("Behavior consistent with static phishing kit")
                
        except Exception as e:
            if not result.error:
                result.error = f"Proxy behavior check failed: {e}"
    
    result.fingerprint_risk_score = min(risk_score, 100)
    result.fingerprint_risk_reasons = risk_reasons
    
    return result
