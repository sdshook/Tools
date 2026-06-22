"""
Allowlist Module - Known-Good Domains

Reduces false positives by identifying legitimate domains that should
not be flagged as suspicious, even if they have login forms or tracking
parameters.

Categories:
1. Identity Providers (Microsoft, Google, Okta, etc.)
2. Major Cloud Services (AWS, Azure, GCP)
3. Popular SaaS (Salesforce, Workday, etc.)
4. CDN/Infrastructure (Cloudflare, Akamai, etc.)
5. Security Services (that might look suspicious)
"""

from __future__ import annotations

import re
from urllib.parse import urlparse


# =============================================================================
# Known-Good Domains by Category
# =============================================================================

IDENTITY_PROVIDERS: set[str] = {
    # Microsoft
    "login.microsoftonline.com",
    "login.microsoft.com",
    "login.live.com",
    "login.windows.net",
    "microsoftonline.com",
    "microsoft.com",
    "office.com",
    "office365.com",
    "sharepoint.com",
    "outlook.com",
    "outlook.office.com",
    "outlook.office365.com",
    "portal.azure.com",
    "azure.com",
    "azure.microsoft.com",
    "onedrive.com",
    "onedrive.live.com",
    
    # Google
    "accounts.google.com",
    "google.com",
    "gmail.com",
    "googleusercontent.com",
    "googleapis.com",
    "gstatic.com",
    "workspace.google.com",
    
    # Okta
    "okta.com",
    "oktacdn.com",
    "oktapreview.com",
    
    # Other IdPs
    "auth0.com",
    "onelogin.com",
    "duosecurity.com",
    "duo.com",
    "pingidentity.com",
    "forgerock.com",
    "keycloak.org",
}

CLOUD_SERVICES: set[str] = {
    # AWS
    "aws.amazon.com",
    "amazonaws.com",
    "console.aws.amazon.com",
    "signin.aws.amazon.com",
    
    # Azure (additional)
    "portal.azure.com",
    "management.azure.com",
    "blob.core.windows.net",
    
    # GCP
    "cloud.google.com",
    "console.cloud.google.com",
    
    # Other
    "digitalocean.com",
    "heroku.com",
    "vercel.com",
    "netlify.com",
    "render.com",
}

SAAS_SERVICES: set[str] = {
    # CRM/Business
    "salesforce.com",
    "force.com",
    "lightning.force.com",
    "hubspot.com",
    "zendesk.com",
    "freshdesk.com",
    "intercom.com",
    
    # HR/Finance
    "workday.com",
    "adp.com",
    "paylocity.com",
    "bamboohr.com",
    "gusto.com",
    "rippling.com",
    
    # Productivity
    "slack.com",
    "zoom.us",
    "zoom.com",
    "webex.com",
    "teams.microsoft.com",
    "notion.so",
    "notion.com",
    "asana.com",
    "monday.com",
    "trello.com",
    "atlassian.com",
    "atlassian.net",
    "jira.com",
    "confluence.com",
    
    # Dev Tools
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "npmjs.com",
    "pypi.org",
    
    # Storage
    "dropbox.com",
    "box.com",
    "egnyte.com",
}

CDN_AND_INFRASTRUCTURE: set[str] = {
    # CDNs
    "cloudflare.com",
    "cloudflare-dns.com",
    "cloudflareinsights.com",
    "akamai.com",
    "akamaized.net",
    "fastly.net",
    "edgecastcdn.net",
    "cloudfront.net",
    "azureedge.net",
    
    # Analytics (not malicious, just tracking)
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "facebook.com",
    "facebook.net",
    "fbcdn.net",
    "twitter.com",
    "linkedin.com",
    
    # Font/Resource CDNs
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "jsdelivr.net",
}

SECURITY_SERVICES: set[str] = {
    # These might look suspicious but are legitimate
    "urlscan.io",
    "virustotal.com",
    "hybrid-analysis.com",
    "any.run",
    "joesandbox.com",
    "browserling.com",
    "shodan.io",
    "censys.io",
    "securitytrails.com",
    "riskiq.com",
    "domaintools.com",
    "threatcrowd.org",
}

# Combine all categories
ALL_ALLOWLISTED_DOMAINS: set[str] = (
    IDENTITY_PROVIDERS |
    CLOUD_SERVICES |
    SAAS_SERVICES |
    CDN_AND_INFRASTRUCTURE |
    SECURITY_SERVICES
)


# =============================================================================
# Allowlist Functions
# =============================================================================

def extract_domain(url_or_domain: str) -> str:
    """Extract the domain from a URL or return as-is if already a domain."""
    if '://' in url_or_domain:
        parsed = urlparse(url_or_domain)
        domain = parsed.netloc
    else:
        domain = url_or_domain.split('/')[0]
    
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    
    # Remove www prefix
    if domain.startswith('www.'):
        domain = domain[4:]
    
    return domain.lower()


def is_allowlisted(url_or_domain: str) -> bool:
    """
    Check if a URL or domain is on the allowlist.
    
    Matches exact domains and subdomains of allowlisted domains.
    """
    domain = extract_domain(url_or_domain)
    
    # Exact match
    if domain in ALL_ALLOWLISTED_DOMAINS:
        return True
    
    # Subdomain match (e.g., login.microsoft.com matches microsoft.com)
    for allowed in ALL_ALLOWLISTED_DOMAINS:
        if domain.endswith('.' + allowed):
            return True
    
    return False


def get_allowlist_category(url_or_domain: str) -> str | None:
    """
    Get the category of an allowlisted domain.
    
    Returns None if not allowlisted.
    """
    domain = extract_domain(url_or_domain)
    
    def check_category(domain: str, category_set: set[str]) -> bool:
        if domain in category_set:
            return True
        for allowed in category_set:
            if domain.endswith('.' + allowed):
                return True
        return False
    
    if check_category(domain, IDENTITY_PROVIDERS):
        return "identity_provider"
    if check_category(domain, CLOUD_SERVICES):
        return "cloud_service"
    if check_category(domain, SAAS_SERVICES):
        return "saas_service"
    if check_category(domain, CDN_AND_INFRASTRUCTURE):
        return "cdn_infrastructure"
    if check_category(domain, SECURITY_SERVICES):
        return "security_service"
    
    return None


def is_identity_provider(url_or_domain: str) -> bool:
    """Check if domain is a known identity provider (Microsoft, Google, Okta, etc.)."""
    domain = extract_domain(url_or_domain)
    
    if domain in IDENTITY_PROVIDERS:
        return True
    
    for allowed in IDENTITY_PROVIDERS:
        if domain.endswith('.' + allowed):
            return True
    
    return False


def filter_allowlisted(urls: list[str]) -> tuple[list[str], list[str]]:
    """
    Separate URLs into allowlisted and non-allowlisted.
    
    Returns (suspicious_urls, allowlisted_urls)
    """
    suspicious = []
    allowed = []
    
    for url in urls:
        if is_allowlisted(url):
            allowed.append(url)
        else:
            suspicious.append(url)
    
    return suspicious, allowed


# =============================================================================
# Custom Allowlist Support
# =============================================================================

_custom_allowlist: set[str] = set()


def add_to_allowlist(domain: str) -> None:
    """Add a domain to the custom allowlist."""
    _custom_allowlist.add(domain.lower())


def remove_from_allowlist(domain: str) -> None:
    """Remove a domain from the custom allowlist."""
    _custom_allowlist.discard(domain.lower())


def load_custom_allowlist(filepath: str) -> int:
    """
    Load custom allowlist from a file (one domain per line).
    
    Returns number of domains loaded.
    """
    count = 0
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    _custom_allowlist.add(line.lower())
                    count += 1
    except FileNotFoundError:
        pass
    return count


def is_custom_allowlisted(url_or_domain: str) -> bool:
    """Check if domain is in the custom allowlist."""
    domain = extract_domain(url_or_domain)
    
    if domain in _custom_allowlist:
        return True
    
    for allowed in _custom_allowlist:
        if domain.endswith('.' + allowed):
            return True
    
    return False


# Override is_allowlisted to include custom
_original_is_allowlisted = is_allowlisted

def is_allowlisted(url_or_domain: str) -> bool:
    """Check if URL/domain is on built-in or custom allowlist."""
    return _original_is_allowlisted(url_or_domain) or is_custom_allowlisted(url_or_domain)


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    import sys
    
    test_domains = [
        "https://login.microsoftonline.com/oauth2/authorize",
        "microsoft.com",
        "login.microsoft.com",
        "portal.azure.com",
        "accounts.google.com",
        "evil-microsoft.com",
        "micr0soft.com",
        "armorprotect.com",
        "colinandresw.com",
        "totally-legit-login.com",
        "okta.com",
        "mycompany.okta.com",
        "github.com",
        "slack.com",
    ]
    
    print("Allowlist Check")
    print("=" * 60)
    
    for domain in test_domains:
        allowed = is_allowlisted(domain)
        category = get_allowlist_category(domain) or "not allowlisted"
        status = "✓ ALLOWED" if allowed else "⚠ CHECK"
        print(f"{status:12s} | {domain:40s} | {category}")
