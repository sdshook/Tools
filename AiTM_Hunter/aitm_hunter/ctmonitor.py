"""
Certificate Transparency Monitoring Module

Monitors Certificate Transparency logs for suspicious certificate issuance:
- Typosquat domains (micr0soft.com, g00gle.com)
- Brand keyword domains (microsoft-login.com)
- Wildcard certs (*.example.com - common for Evilginx)
- Bulk issuance (campaign indicator)

Data sources:
- crt.sh (Comodo CT log search) - Free, no API key required
- Certstream (real-time CT feed) - For continuous monitoring

This provides EARLY WARNING - catch phishing infrastructure before it's used.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterator
from urllib.parse import quote

import requests

# Import typosquat detection for checking if cert domains are suspicious
try:
    from aitm_hunter import typosquat as typosquat_mod
except ImportError:
    typosquat_mod = None


CRT_SH_API = "https://crt.sh"
DEFAULT_TIMEOUT = 30


@dataclass  
class CertificateInfo:
    """Information about a certificate from CT logs."""
    id: int | None = None
    issuer_name: str = ""
    common_name: str = ""
    name_value: str = ""  # All SANs
    domains: list[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    issuer_ca_id: int | None = None
    
    # Analysis
    is_wildcard: bool = False
    is_typosquat: bool = False
    typosquat_target: str | None = None
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "issuer_name": self.issuer_name,
            "common_name": self.common_name,
            "domains": self.domains,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "is_wildcard": self.is_wildcard,
            "is_typosquat": self.is_typosquat,
            "typosquat_target": self.typosquat_target,
            "is_suspicious": self.is_suspicious,
            "suspicion_reasons": self.suspicion_reasons,
        }


# =============================================================================
# Brand Monitoring Patterns
# =============================================================================

# Patterns to monitor in CT logs (regex)
BRAND_MONITOR_PATTERNS = [
    # Microsoft variants
    (r'micro.?soft', 'microsoft'),
    (r'm[i1]cr[o0]s[o0]ft', 'microsoft'),
    (r'msft', 'microsoft'),
    (r'office.?365', 'microsoft'),
    (r'0ffice', 'microsoft'),
    (r'outlook', 'microsoft'),
    (r'0utlook', 'microsoft'),
    (r'azure', 'microsoft'),
    (r'sharepoint', 'microsoft'),
    (r'onedrive', 'microsoft'),
    (r'teams', 'microsoft'),
    
    # Google variants
    (r'g[o0][o0]gle', 'google'),
    (r'gmail', 'google'),
    (r'gma[i1]l', 'google'),
    
    # Okta
    (r'[o0]kta', 'okta'),
    
    # Amazon
    (r'amaz[o0]n', 'amazon'),
    (r'aws', 'amazon'),
    
    # Apple
    (r'app[l1]e', 'apple'),
    (r'[i1]cloud', 'apple'),
]

# Keywords that indicate phishing when combined with brand
PHISHING_KEYWORDS = [
    'login', 'signin', 'sign-in', 'logon',
    'verify', 'verification', 'validate',
    'secure', 'security', 'protection',
    'account', 'password', 'credential',
    'update', 'confirm', 'alert',
    'portal', 'auth', 'oauth',
    'support', 'help', 'service',
]

# Legitimate domains to exclude (exact match)
LEGITIMATE_DOMAINS = {
    'microsoft.com', 'office.com', 'office365.com', 'microsoftonline.com',
    'outlook.com', 'azure.com', 'sharepoint.com', 'onedrive.com',
    'google.com', 'gmail.com', 'googleapis.com',
    'okta.com', 'oktacdn.com',
    'amazon.com', 'amazonaws.com', 'aws.amazon.com',
    'apple.com', 'icloud.com',
}


# =============================================================================
# crt.sh API Functions
# =============================================================================

def search_crtsh(
    query: str,
    wildcard: bool = True,
    deduplicate: bool = True,
    limit: int = 100,
) -> list[CertificateInfo]:
    """
    Search crt.sh for certificates matching a pattern.
    
    Args:
        query: Domain or pattern to search (e.g., "%.microsoft%" for wildcards)
        wildcard: If True, wrap query in % wildcards
        deduplicate: If True, group by (pre)certificate
        limit: Max results to return
    
    Returns:
        List of CertificateInfo objects
    """
    if wildcard and '%' not in query:
        query = f"%{query}%"
    
    params = {
        "q": query,
        "output": "json",
    }
    
    if deduplicate:
        params["deduplicate"] = "Y"
    
    try:
        resp = requests.get(
            CRT_SH_API,
            params=params,
            timeout=DEFAULT_TIMEOUT,
        )
        
        if resp.status_code == 404:
            return []
        
        resp.raise_for_status()
        
        # crt.sh returns empty response for no results
        if not resp.text or resp.text.strip() == "":
            return []
        
        data = resp.json()
        
        results = []
        for entry in data[:limit]:
            cert = CertificateInfo(
                id=entry.get("id"),
                issuer_name=entry.get("issuer_name", ""),
                common_name=entry.get("common_name", ""),
                name_value=entry.get("name_value", ""),
                not_before=entry.get("not_before", ""),
                not_after=entry.get("not_after", ""),
                issuer_ca_id=entry.get("issuer_ca_id"),
            )
            
            # Parse domains from name_value (newline-separated SANs)
            if cert.name_value:
                cert.domains = [d.strip().lower() for d in cert.name_value.split('\n') if d.strip()]
            
            # Check for wildcard
            cert.is_wildcard = any(d.startswith('*.') for d in cert.domains)
            
            results.append(cert)
        
        return results
        
    except requests.RequestException as e:
        print(f"crt.sh error: {e}")
        return []
    except ValueError:
        # JSON decode error - likely no results
        return []


def search_recent_certs(
    query: str,
    days: int = 7,
) -> list[CertificateInfo]:
    """
    Search for certificates issued in the last N days.
    
    Note: crt.sh doesn't have a date filter, so we filter client-side.
    """
    certs = search_crtsh(query, limit=500)
    
    cutoff = datetime.now() - timedelta(days=days)
    
    recent = []
    for cert in certs:
        try:
            # Parse not_before date (format: "2024-01-15T00:00:00")
            if cert.not_before:
                cert_date = datetime.fromisoformat(cert.not_before.replace('Z', '+00:00').split('+')[0])
                if cert_date >= cutoff:
                    recent.append(cert)
        except (ValueError, TypeError):
            # Include if we can't parse date
            recent.append(cert)
    
    return recent


def get_cert_details(cert_id: int) -> dict | None:
    """Get detailed certificate information by ID."""
    try:
        resp = requests.get(
            f"{CRT_SH_API}/?id={cert_id}&output=json",
            timeout=DEFAULT_TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException:
        pass
    return None


# =============================================================================
# Analysis Functions
# =============================================================================

def analyze_certificate(cert: CertificateInfo) -> CertificateInfo:
    """
    Analyze a certificate for suspicious indicators.
    
    Checks for:
    - Typosquat domains
    - Brand impersonation with phishing keywords
    - Wildcard certs (common for Evilginx)
    - Suspicious issuers
    """
    # Skip known legitimate domains
    if cert.common_name.lower() in LEGITIMATE_DOMAINS:
        return cert
    
    for domain in cert.domains:
        domain_lower = domain.lower().lstrip('*.')
        
        if domain_lower in LEGITIMATE_DOMAINS:
            continue
        
        # Check 1: Typosquat detection
        if typosquat_mod:
            typo_result = typosquat_mod.detect_typosquat(domain_lower)
            if typo_result.is_typosquat:
                cert.is_typosquat = True
                cert.typosquat_target = typo_result.target_brand
                cert.is_suspicious = True
                cert.suspicion_reasons.append(
                    f"Typosquat of {typo_result.target_brand}: {domain_lower} ({typo_result.technique})"
                )
        
        # Check 2: Brand pattern + phishing keyword
        for pattern, brand in BRAND_MONITOR_PATTERNS:
            if re.search(pattern, domain_lower, re.IGNORECASE):
                # Has brand pattern - check for phishing keywords
                for keyword in PHISHING_KEYWORDS:
                    if keyword in domain_lower:
                        cert.is_suspicious = True
                        cert.suspicion_reasons.append(
                            f"Brand+keyword: {domain_lower} ({brand}+{keyword})"
                        )
                        break
    
    # Check 3: Wildcard cert (suspicious if combined with other indicators)
    if cert.is_wildcard:
        # Wildcard alone isn't suspicious, but note it
        if cert.is_suspicious:
            cert.suspicion_reasons.append("Wildcard certificate (Evilginx indicator)")
    
    # Check 4: Suspicious issuer (free/rapid issuance)
    suspicious_issuers = ["Let's Encrypt", "ZeroSSL", "Buypass"]
    for issuer in suspicious_issuers:
        if issuer.lower() in cert.issuer_name.lower():
            if cert.is_suspicious:
                cert.suspicion_reasons.append(f"Rapid-issue CA: {issuer}")
            break
    
    return cert


def monitor_brand_certs(
    brand: str,
    days: int = 7,
    analyze: bool = True,
) -> list[CertificateInfo]:
    """
    Monitor CT logs for certificates related to a brand.
    
    Args:
        brand: Brand name to monitor (microsoft, google, okta, etc.)
        days: Look back N days
        analyze: If True, analyze each cert for suspicious indicators
    
    Returns:
        List of potentially suspicious certificates
    """
    # Build search patterns for the brand
    patterns = []
    for pattern, pattern_brand in BRAND_MONITOR_PATTERNS:
        if pattern_brand == brand.lower():
            # Convert regex to SQL LIKE pattern (simplified)
            sql_pattern = pattern.replace('.?', '%').replace('[o0]', '%').replace('[i1]', '%')
            patterns.append(sql_pattern)
    
    if not patterns:
        patterns = [brand]
    
    all_certs = []
    seen_ids = set()
    
    for pattern in patterns[:3]:  # Limit to avoid too many queries
        certs = search_recent_certs(pattern, days=days)
        for cert in certs:
            if cert.id not in seen_ids:
                seen_ids.add(cert.id)
                if analyze:
                    cert = analyze_certificate(cert)
                all_certs.append(cert)
    
    return all_certs


def find_suspicious_certs(
    brands: list[str] | None = None,
    days: int = 7,
) -> list[CertificateInfo]:
    """
    Find suspicious certificates for multiple brands.
    
    Args:
        brands: List of brands to monitor (default: microsoft, google, okta)
        days: Look back N days
    
    Returns:
        List of suspicious certificates (filtered)
    """
    if brands is None:
        brands = ["microsoft", "google", "okta"]
    
    suspicious = []
    
    for brand in brands:
        print(f"  Checking CT logs for {brand}...")
        certs = monitor_brand_certs(brand, days=days, analyze=True)
        
        for cert in certs:
            if cert.is_suspicious:
                suspicious.append(cert)
    
    return suspicious


# =============================================================================
# Alerting Functions
# =============================================================================

def format_cert_alert(cert: CertificateInfo) -> str:
    """Format a suspicious certificate as an alert string."""
    lines = [
        f"🚨 Suspicious Certificate Detected",
        f"   Domain: {cert.common_name}",
        f"   SANs: {', '.join(cert.domains[:5])}{'...' if len(cert.domains) > 5 else ''}",
        f"   Issuer: {cert.issuer_name}",
        f"   Issued: {cert.not_before}",
        f"   Reasons:",
    ]
    
    for reason in cert.suspicion_reasons:
        lines.append(f"     - {reason}")
    
    lines.append(f"   crt.sh: https://crt.sh/?id={cert.id}")
    
    return '\n'.join(lines)


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    import sys
    
    print("Certificate Transparency Monitor")
    print("=" * 60)
    
    # Default: monitor for Microsoft, Google, Okta
    brands = sys.argv[1:] if len(sys.argv) > 1 else ["microsoft", "google", "okta"]
    days = 7
    
    print(f"Searching CT logs for: {', '.join(brands)}")
    print(f"Looking back: {days} days")
    print()
    
    suspicious = find_suspicious_certs(brands=brands, days=days)
    
    if suspicious:
        print(f"\n⚠️  Found {len(suspicious)} suspicious certificates:\n")
        for cert in suspicious[:10]:  # Limit output
            print(format_cert_alert(cert))
            print()
    else:
        print("\n✅ No suspicious certificates found.")
