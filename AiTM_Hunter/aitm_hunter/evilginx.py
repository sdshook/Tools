"""
Evilginx Detection Module

Specialized detection for Evilginx-style AiTM (Adversary-in-the-Middle) phishing.
Identifies behavioral and infrastructure markers specific to Evilginx deployments.

Key Evilginx indicators:
- rid= parameter in URLs (session tracking)
- openresty or nginx server headers
- Wildcard DNS configuration
- Let's Encrypt or self-signed certificates
- Proxying of IdP login resources
- Bulletproof hosting ASNs
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import requests

from . import signatures


@dataclass
class EvilginxDetectionResult:
    """Results from Evilginx-specific detection checks."""
    domain: str
    is_evilginx: bool = False
    confidence: str = "none"  # none, low, medium, high, confirmed
    risk_score: int = 0
    markers_found: list[str] = field(default_factory=list)
    infrastructure: dict = field(default_factory=dict)
    ioc_match: dict | None = None
    reasons: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "is_evilginx": self.is_evilginx,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "markers_found": self.markers_found,
            "infrastructure": self.infrastructure,
            "ioc_match": self.ioc_match,
            "reasons": self.reasons,
        }


# Evilginx-specific URL patterns
EVILGINX_URL_PATTERNS = [
    (r'[?&]rid=[a-zA-Z0-9]+', "Evilginx session ID (rid=)"),
    (r'/lure/', "Evilginx lure path"),
    (r'/phishlet/', "Evilginx phishlet path"),
]

# Evilginx-specific HTTP response patterns
EVILGINX_RESPONSE_PATTERNS = [
    (r'rid=[a-zA-Z0-9]+', "rid= parameter in response"),
    (r'evilginx', "Direct Evilginx reference"),
    (r'phishlet', "Phishlet reference"),
]

# Server headers commonly used by Evilginx
EVILGINX_SERVER_HEADERS = [
    "openresty",
    "nginx",  # nginx alone is not conclusive but combined with other markers
]

# Certificate issuers commonly used for rapid Evilginx deployment
SUSPICIOUS_CERT_ISSUERS = [
    "Let's Encrypt",
    "ZeroSSL",
    "Buypass",
]

# Lure content patterns (Storm-2755 style phishing lures)
LURE_CONTENT_PATTERNS = [
    (r'device\s*activation', "Device Activation lure (Storm-2755)"),
    (r'security\s*verification', "Security Verification lure"),
    (r'account\s*verification\s*required', "Account Verification lure"),
    (r'verify\s*your\s*identity', "Identity Verification lure"),
    (r'session\s*expired', "Session Expired lure"),
    (r're-?authenticate', "Re-authentication lure"),
    (r'your\s*session\s*has\s*timed?\s*out', "Session Timeout lure"),
    (r'please\s*sign\s*in\s*again', "Re-sign-in lure"),
    (r'additional\s*verification', "Additional Verification lure"),
]

# Brand impersonation patterns (Storm-2755 naming conventions)
BRAND_IMPERSONATION_PATTERNS = [
    (r'armor\w*', "Armor* brand pattern (Storm-2755)"),
    (r'security\w*\d+', "Security*N pattern (Storm-2755)"),
    (r'protect\w*shield', "Protect*Shield pattern"),
    (r'secure\w*guard', "Secure*Guard pattern"),
    (r'safe\w*defense', "Safe*Defense pattern"),
    (r'auth\w*secure', "Auth*Secure pattern"),
    (r'login\w*verify', "Login*Verify pattern"),
]

# Known CDN providers used for fronting
CDN_PROVIDERS = {
    "cloudflare": ["cloudflare", "cf-ray"],
    "aws_cloudfront": ["cloudfront", "x-amz-cf"],
    "akamai": ["akamai"],
    "fastly": ["fastly"],
}


def check_url_markers(url: str) -> list[str]:
    """Check URL for Evilginx-specific markers."""
    markers = []
    for pattern, description in EVILGINX_URL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            markers.append(description)
    return markers


def check_response_markers(content: str, headers: dict) -> list[str]:
    """Check HTTP response for Evilginx markers."""
    markers = []
    
    # Check content
    for pattern, description in EVILGINX_RESPONSE_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            markers.append(description)
    
    # Check server header
    server = headers.get('Server', '').lower()
    if 'openresty' in server:
        markers.append("openresty server (common Evilginx)")
    
    return markers


def check_lure_content(content: str) -> list[str]:
    """Check page content for phishing lure patterns (Storm-2755 style)."""
    markers = []
    content_lower = content.lower()
    
    for pattern, description in LURE_CONTENT_PATTERNS:
        if re.search(pattern, content_lower, re.IGNORECASE):
            markers.append(description)
    
    return markers


def check_brand_impersonation(domain: str) -> list[str]:
    """Check domain for brand impersonation patterns."""
    markers = []
    domain_lower = domain.lower()
    
    for pattern, description in BRAND_IMPERSONATION_PATTERNS:
        if re.search(pattern, domain_lower, re.IGNORECASE):
            markers.append(description)
    
    return markers


def detect_cdn_fronting(headers: dict) -> dict:
    """
    Detect CDN fronting from response headers.
    
    Storm-2755 uses Cloudflare-fronted landing pages with AWS backend proxies.
    """
    result = {
        "is_cdn_fronted": False,
        "cdn_provider": None,
        "cdn_indicators": [],
    }
    
    headers_lower = {k.lower(): v for k, v in headers.items()}
    all_headers_str = str(headers_lower).lower()
    
    for provider, indicators in CDN_PROVIDERS.items():
        for indicator in indicators:
            if indicator in all_headers_str:
                result["is_cdn_fronted"] = True
                result["cdn_provider"] = provider
                result["cdn_indicators"].append(indicator)
    
    # Check for specific Cloudflare headers
    if 'cf-ray' in headers_lower:
        result["is_cdn_fronted"] = True
        result["cdn_provider"] = "cloudflare"
        result["cdn_indicators"].append(f"cf-ray: {headers_lower.get('cf-ray', '')}")
    
    return result


def trace_backend_infrastructure(domain: str, follow_redirects: bool = True) -> dict:
    """
    Attempt to trace backend infrastructure behind CDN fronting.
    
    For two-tier AiTM setups (landing page -> backend proxy), this follows
    redirects and identifies the actual credential-stealing infrastructure.
    """
    result = {
        "landing_domain": domain,
        "backend_domain": None,
        "redirect_chain": [],
        "final_ip": None,
        "cdn_detected": None,
        "backend_hosting": None,
    }
    
    try:
        session = requests.Session()
        session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        
        resp = session.get(
            f'https://{domain}/',
            timeout=15,
            verify=False,
            allow_redirects=follow_redirects
        )
        
        # Record redirect chain
        for r in resp.history:
            result["redirect_chain"].append({
                "url": r.url,
                "status": r.status_code,
            })
        
        # Final destination
        final_parsed = urlparse(resp.url)
        if final_parsed.netloc != domain:
            result["backend_domain"] = final_parsed.netloc
        
        # Check CDN on final response
        cdn_info = detect_cdn_fronting(dict(resp.headers))
        result["cdn_detected"] = cdn_info.get("cdn_provider")
        
        # Try to resolve final domain IP
        try:
            final_domain = final_parsed.netloc or domain
            result["final_ip"] = socket.gethostbyname(final_domain)
        except socket.gaierror:
            pass
            
    except Exception as e:
        result["error"] = str(e)
    
    return result


def check_wildcard_dns(domain: str) -> bool:
    """Check if domain has wildcard DNS (all subdomains resolve to same IP)."""
    try:
        # Get IP for base domain
        base_ip = socket.gethostbyname(domain)
        
        # Test random subdomain
        random_sub = f"xyzrandomtest{hash(domain) % 10000}.{domain}"
        try:
            random_ip = socket.gethostbyname(random_sub)
            return random_ip == base_ip
        except socket.gaierror:
            return False
    except socket.gaierror:
        return False


def check_certificate(domain: str) -> dict:
    """Analyze TLS certificate for Evilginx indicators."""
    result = {
        "issuer": None,
        "is_self_signed": False,
        "is_suspicious_issuer": False,
        "error": None,
    }
    
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                
                issuer_org = issuer.get('organizationName', '')
                result['issuer'] = issuer_org
                
                # Check for self-signed
                if issuer == subject:
                    result['is_self_signed'] = True
                
                # Check for suspicious issuers
                for suspicious in SUSPICIOUS_CERT_ISSUERS:
                    if suspicious.lower() in issuer_org.lower():
                        result['is_suspicious_issuer'] = True
                        break
                        
    except ssl.SSLCertVerificationError as e:
        if 'self-signed' in str(e).lower():
            result['is_self_signed'] = True
        result['error'] = str(e)
    except Exception as e:
        result['error'] = str(e)
    
    return result


def get_ip_info(domain: str) -> dict:
    """Get IP and ASN information for domain."""
    result = {
        "ip": None,
        "asn": None,
        "org": None,
        "is_suspicious_asn": False,
        "asn_reason": None,
    }
    
    try:
        ip = socket.gethostbyname(domain)
        result['ip'] = ip
        
        # Try to get ASN info
        try:
            resp = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5)
            if resp.status_code == 200:
                info = resp.json()
                org = info.get('org', '')
                result['org'] = org
                
                # Extract ASN
                if org:
                    asn_match = re.match(r'(AS\d+)', org)
                    if asn_match:
                        asn = asn_match.group(1)
                        result['asn'] = asn
                        
                        # Check if suspicious
                        asn_reason = signatures.check_asn_reputation(asn)
                        if asn_reason:
                            result['is_suspicious_asn'] = True
                            result['asn_reason'] = asn_reason
        except Exception:
            pass
            
    except socket.gaierror:
        pass
    
    return result


def check_proxies_idp(domain: str, idp_type: str = "microsoft") -> dict:
    """Check if domain proxies identity provider resources."""
    result = {
        "proxies_idp": False,
        "idp_type": idp_type,
        "proxied_paths": [],
    }
    
    # Microsoft Entra/Azure AD paths
    ms_paths = [
        '/common/oauth2/v2.0/authorize',
        '/.well-known/openid-configuration',
        '/common/discovery/keys',
    ]
    
    try:
        session = requests.Session()
        session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        
        for path in ms_paths:
            try:
                resp = session.get(f'https://{domain}{path}', timeout=10, verify=False)
                if resp.status_code == 200:
                    content = resp.text.lower()
                    # Check if it returns actual Microsoft content
                    if 'microsoft' in content or 'azure' in content or 'issuer' in content:
                        result['proxies_idp'] = True
                        result['proxied_paths'].append(path)
            except Exception:
                pass
                
    except Exception:
        pass
    
    return result


def detect_evilginx(url: str, deep_check: bool = True) -> EvilginxDetectionResult:
    """
    Comprehensive Evilginx detection for a URL.
    
    Args:
        url: URL to analyze
        deep_check: If True, perform network-based checks (slower but more thorough)
    
    Returns:
        EvilginxDetectionResult with detection findings
    """
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    
    result = EvilginxDetectionResult(domain=domain)
    
    # 1. Check against known IOCs first
    ioc_match = signatures.check_domain_ioc(domain)
    if ioc_match:
        result.ioc_match = ioc_match
        result.is_evilginx = True
        result.confidence = "confirmed"
        result.risk_score = 100
        result.reasons.append(f"Matches known Evilginx IOC: {ioc_match.get('notes', domain)}")
        result.markers_found.append("Known malicious domain")
        # Include threat actor attribution if available
        if ioc_match.get('threat_actor'):
            result.reasons.append(f"Threat Actor: {ioc_match.get('threat_actor')}")
        return result
    
    # 2. Check URL for markers
    url_markers = check_url_markers(url)
    result.markers_found.extend(url_markers)
    if url_markers:
        result.risk_score += 30
        result.reasons.extend([f"URL marker: {m}" for m in url_markers])
    
    # 3. Check for brand impersonation patterns (Storm-2755 style)
    brand_markers = check_brand_impersonation(domain)
    if brand_markers:
        result.markers_found.extend(brand_markers)
        result.risk_score += 25
        result.reasons.extend([f"Brand impersonation: {m}" for m in brand_markers])
    
    if not deep_check:
        # Calculate confidence based on URL markers alone
        if result.risk_score >= 30:
            result.confidence = "medium"
            result.is_evilginx = True
        return result
    
    # 4. Deep checks (network-based)
    
    # Check wildcard DNS
    if check_wildcard_dns(domain):
        result.markers_found.append("Wildcard DNS")
        result.infrastructure['wildcard_dns'] = True
        result.risk_score += 20
        result.reasons.append("Wildcard DNS detected (all subdomains resolve to same IP)")
    
    # Check certificate
    cert_info = check_certificate(domain)
    result.infrastructure['certificate'] = cert_info
    
    if cert_info.get('is_self_signed'):
        result.markers_found.append("Self-signed certificate")
        result.risk_score += 25
        result.reasons.append("Self-signed certificate (common for Evilginx)")
    elif cert_info.get('is_suspicious_issuer'):
        result.markers_found.append(f"Suspicious cert issuer: {cert_info.get('issuer')}")
        result.risk_score += 10
        result.reasons.append(f"Auto-provisioned cert from {cert_info.get('issuer')}")
    
    # Check IP/ASN
    ip_info = get_ip_info(domain)
    result.infrastructure['ip_info'] = ip_info
    
    # Check against known malicious IPs
    if ip_info.get('ip'):
        ip_ioc = signatures.check_ip_ioc(ip_info['ip'])
        if ip_ioc:
            result.markers_found.append("Known malicious IP")
            result.risk_score += 50
            result.reasons.append(f"IP matches known Evilginx infrastructure: {ip_info['ip']}")
    
    if ip_info.get('is_suspicious_asn'):
        result.markers_found.append(f"Suspicious ASN: {ip_info.get('asn')}")
        result.risk_score += 20
        result.reasons.append(f"Hosted on suspicious ASN: {ip_info.get('asn_reason')}")
    
    # Check HTTP response for markers and lure content
    try:
        resp = requests.get(f'https://{domain}/', timeout=10, verify=False,
                          headers={'User-Agent': 'Mozilla/5.0'})
        response_markers = check_response_markers(resp.text, dict(resp.headers))
        result.markers_found.extend(response_markers)
        
        if response_markers:
            result.risk_score += 20 * len(response_markers)
            result.reasons.extend([f"Response marker: {m}" for m in response_markers])
        
        # Check for lure content patterns (Storm-2755 style)
        lure_markers = check_lure_content(resp.text)
        if lure_markers:
            result.markers_found.extend(lure_markers)
            result.risk_score += 30
            result.reasons.extend([f"Lure content: {m}" for m in lure_markers])
        
        # Detect CDN fronting (Storm-2755 uses Cloudflare -> AWS pattern)
        cdn_info = detect_cdn_fronting(dict(resp.headers))
        result.infrastructure['cdn'] = cdn_info
        if cdn_info.get('is_cdn_fronted'):
            result.infrastructure['cdn_provider'] = cdn_info.get('cdn_provider')
            # CDN fronting alone isn't suspicious, but combined with other markers it is
            if result.risk_score >= 20:
                result.reasons.append(f"CDN fronted ({cdn_info.get('cdn_provider')}) - potential two-tier AiTM")
            
        result.infrastructure['server'] = resp.headers.get('Server', 'Unknown')
        
    except Exception:
        pass
    
    # Trace backend infrastructure (for two-tier setups)
    backend_info = trace_backend_infrastructure(domain)
    result.infrastructure['backend_trace'] = backend_info
    
    if backend_info.get('backend_domain'):
        # Check if backend is a known IOC
        backend_ioc = signatures.check_domain_ioc(backend_info['backend_domain'])
        if backend_ioc:
            result.markers_found.append(f"Backend is known IOC: {backend_info['backend_domain']}")
            result.risk_score += 50
            result.reasons.append(f"Redirects to known malicious backend: {backend_info['backend_domain']}")
        else:
            result.reasons.append(f"Two-tier architecture: redirects to {backend_info['backend_domain']}")
    
    # Check if proxies IdP
    proxy_check = check_proxies_idp(domain)
    result.infrastructure['proxy_check'] = proxy_check
    
    if proxy_check.get('proxies_idp'):
        result.markers_found.append("Proxies IdP resources")
        result.risk_score += 40
        result.reasons.append(f"Proxies Microsoft identity resources: {proxy_check.get('proxied_paths')}")
    
    # Calculate final confidence
    if result.risk_score >= 80:
        result.confidence = "high"
        result.is_evilginx = True
    elif result.risk_score >= 50:
        result.confidence = "medium"
        result.is_evilginx = True
    elif result.risk_score >= 30:
        result.confidence = "low"
        result.is_evilginx = True
    
    return result


def batch_detect(urls: list[str], deep_check: bool = True) -> list[EvilginxDetectionResult]:
    """Run Evilginx detection on multiple URLs."""
    results = []
    for url in urls:
        try:
            result = detect_evilginx(url, deep_check=deep_check)
            results.append(result)
        except Exception as e:
            result = EvilginxDetectionResult(domain=url)
            result.reasons.append(f"Error during detection: {e}")
            results.append(result)
    return results


if __name__ == "__main__":
    # Test with known domains
    test_domains = [
        "https://armorprotect.com",
        "https://vlm.armorprotect.com",
        "https://login.microsoftonline.com",
        "https://www.office.com",
    ]
    
    print("Evilginx Detection Test")
    print("=" * 60)
    
    for url in test_domains:
        print(f"\nTesting: {url}")
        result = detect_evilginx(url, deep_check=True)
        print(f"  Is Evilginx: {result.is_evilginx}")
        print(f"  Confidence: {result.confidence}")
        print(f"  Risk Score: {result.risk_score}")
        print(f"  Markers: {result.markers_found}")
        if result.reasons:
            print(f"  Reasons: {result.reasons[:3]}...")
