"""
Malvertising Detection Module

Captures and analyzes sponsored ads from search engines to detect
malvertising campaigns leading to AiTM/phishing sites.

Supports:
- Bing Ads API integration (requires BING_ADS_API_KEY)
- Browser-based ad scraping via Playwright
- Google Ads detection via search results
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests


@dataclass
class AdResult:
    """Represents a sponsored ad from search results."""
    query: str
    ad_position: int
    title: str
    displayed_url: str
    actual_url: str
    description: str = ""
    source: str = "unknown"  # google, bing, browser_scrape
    ad_extensions: list[str] = field(default_factory=list)
    tracking_params: dict = field(default_factory=dict)
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "ad_position": self.ad_position,
            "title": self.title,
            "displayed_url": self.displayed_url,
            "actual_url": self.actual_url,
            "description": self.description,
            "source": self.source,
            "ad_extensions": self.ad_extensions,
            "tracking_params": self.tracking_params,
            "is_suspicious": self.is_suspicious,
            "suspicion_reasons": self.suspicion_reasons,
        }


# Suspicious patterns in ad URLs
SUSPICIOUS_URL_PATTERNS = [
    (r'rid=[a-zA-Z0-9]+', "Evilginx session ID"),
    (r'login|signin|auth', "Login-related URL"),
    (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "Raw IP address"),
]

# Brand keywords often targeted by malvertising
TARGET_BRAND_KEYWORDS = [
    "microsoft", "office", "365", "o365", "outlook", "azure",
    "google", "gmail", "workspace",
    "okta", "duo", "onelogin",
    "salesforce", "workday", "servicenow",
    "aws", "amazon",
]

# Malvertising indicators for both Bing/Microsoft Ads AND Google Ads
MALVERTISING_AD_PARAMS = {
    "high_risk_params": {
        # Microsoft/Bing Ads
        "msclkid": 30,  # Microsoft Advertising click ID - strong indicator
        "subid": 20,    # Sub-affiliate tracking
        # Google Ads - these alone aren't suspicious, but with domain mismatch they are
        "gclid": 15,    # Google Ads click ID
        "gad_campaignid": 10,  # Google Ads campaign ID
        "gad_source": 10,  # Google Ads source
    },
    "high_risk_values": {
        "utm_source": {"bing": 15, "microsoft": 15, "google": 5},
        "utm_medium": {"display": 10, "cpc": 5, "ppc": 5},
        "subid": {"microsoft.resp.1": 40},  # Specific Storm-2755 indicator
    },
    # Combination scoring - if these appear together, significantly elevate risk
    "combo_indicators": [
        (["msclkid", "utm_source"], 20),  # msclkid + utm_source together
        (["msclkid", "utm_medium"], 15),  # msclkid + utm_medium together
        (["gclid", "gad_campaignid"], 15),  # Google Ads combo
    ],
}

# Known malicious Google Ads campaign IDs (supplementary IOC, not primary detection)
# These are stored for reference/correlation but fingerprinting should detect the attack pattern
KNOWN_MALICIOUS_CAMPAIGN_IDS = {
    "23869465194": "colinandresw.com AiTM (June 2026)",
}

# Lure content patterns (Storm-2755 style)
LURE_CONTENT_PATTERNS = [
    (r'device\s*activation', "Device Activation lure"),
    (r'security\s*verification', "Security Verification lure"),
    (r'account\s*verification\s*required', "Account Verification lure"),
    (r'verify\s*your\s*identity', "Identity Verification lure"),
    (r'session\s*expired', "Session Expired lure"),
    (r're-?authenticate', "Re-authentication lure"),
]

# Brand impersonation patterns (Storm-2755 naming conventions)
BRAND_IMPERSONATION_PATTERNS = [
    (r'armor\w*', "Armor* brand pattern (Storm-2755)"),
    (r'security\w*\d+', "Security*N pattern (Storm-2755)"),
    (r'protect\w*shield', "Protect*Shield pattern"),
    (r'secure\w*guard', "Secure*Guard pattern"),
    (r'safe\w*defense', "Safe*Defense pattern"),
]


def extract_tracking_params(url: str) -> dict:
    """Extract tracking parameters from URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    tracking = {}
    tracking_prefixes = ['utm_', 'gclid', 'msclkid', 'fbclid', 'ref', 'src', 'rid']
    
    for key, values in params.items():
        for prefix in tracking_prefixes:
            if key.lower().startswith(prefix) or key.lower() == prefix:
                tracking[key] = values[0] if len(values) == 1 else values
                break
    
    return tracking


def score_ad_parameters(params: dict) -> tuple[int, list[str]]:
    """
    Score ad tracking parameters for malvertising fingerprinting.
    Returns (score, list of reasons).
    
    This is BEHAVIORAL fingerprinting - scoring based on parameter patterns
    that indicate malvertising campaigns, not blacklist matching.
    
    Key patterns:
    - msclkid + utm_source=bing = Bing Ads malvertising (Storm-2755 style)
    - gclid + gad_campaignid = Google Ads campaign
    - subid=microsoft.resp.1 = Known Storm-2755 affiliate tracking
    """
    score = 0
    reasons = []
    
    # Check for high-risk parameters (fingerprint patterns)
    for param, points in MALVERTISING_AD_PARAMS["high_risk_params"].items():
        if param in params:
            score += points
            reasons.append(f"{param} (+{points})")
    
    # Check for high-risk parameter values
    for param, value_scores in MALVERTISING_AD_PARAMS["high_risk_values"].items():
        if param in params:
            param_value = params[param]
            if isinstance(param_value, list):
                param_value = param_value[0]
            param_value = str(param_value).lower()
            
            for value, points in value_scores.items():
                if value.lower() in param_value:
                    score += points
                    reasons.append(f"{param}={value} (+{points})")
    
    # Check for high-risk combinations (fingerprint: these together = campaign)
    param_keys = set(params.keys())
    for combo_params, points in MALVERTISING_AD_PARAMS["combo_indicators"]:
        if all(p in param_keys for p in combo_params):
            score += points
            reasons.append(f"Combo: {'+'.join(combo_params)} (+{points})")
    
    # Supplementary: note if campaign ID is in known malicious list (for correlation)
    gad_campaignid = params.get('gad_campaignid', '')
    if isinstance(gad_campaignid, list):
        gad_campaignid = gad_campaignid[0]
    if str(gad_campaignid) in KNOWN_MALICIOUS_CAMPAIGN_IDS:
        reasons.append(f"[IOC] Campaign ID in known list: {KNOWN_MALICIOUS_CAMPAIGN_IDS[str(gad_campaignid)]}")
    
    return score, reasons


def check_brand_impersonation(domain: str) -> tuple[bool, str | None]:
    """Check if domain matches known brand impersonation patterns."""
    domain_lower = domain.lower()
    for pattern, description in BRAND_IMPERSONATION_PATTERNS:
        if re.search(pattern, domain_lower, re.IGNORECASE):
            return True, description
    return False, None


# High-value brands commonly spoofed in ad malvertising
SPOOFED_BRANDS = {
    "microsoft": ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com"],
    "google": ["google.com", "gmail.com", "accounts.google.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "okta": ["okta.com"],
}


def check_brand_spoofing_in_ad(displayed_url: str, actual_url: str) -> tuple[bool, str | None]:
    """
    Check if an ad is spoofing a trusted brand.
    
    This catches scenarios where the displayed URL shows "microsoft.com" 
    but the actual URL goes to "colinandresw.com" (malicious).
    """
    if not displayed_url or not actual_url:
        return False, None
    
    displayed_lower = displayed_url.lower()
    actual_parsed = urlparse(actual_url if actual_url.startswith('http') else f'https://{actual_url}')
    actual_domain = actual_parsed.netloc.lower().replace('www.', '')
    
    for brand, legitimate_domains in SPOOFED_BRANDS.items():
        # Check if displayed URL contains a legitimate brand domain
        for legit_domain in legitimate_domains:
            if legit_domain in displayed_lower:
                # Check if actual URL goes to a different domain
                if actual_domain and legit_domain not in actual_domain:
                    # It's spoofing the brand!
                    return True, f"Ad spoofs {brand} (shows '{legit_domain}' but goes to '{actual_domain}')"
    
    return False, None


def analyze_ad_url(ad: AdResult) -> AdResult:
    """
    Analyze an ad URL for AiTM/phishing indicators using behavioral fingerprinting.
    
    Detection priority:
    1. BEHAVIORAL FINGERPRINTING (primary) - detect attack patterns regardless of domain
    2. IOC MATCHING (supplementary) - known malicious infrastructure
    
    Key fingerprints for ad-based AiTM:
    - Brand spoofing: displayed URL shows trusted brand, actual URL is different
    - Ad tracking params: gclid/msclkid with brand mismatch = malvertising
    - Evilginx markers: rid= parameter
    - Domain naming patterns: Armor*, Security*N, etc.
    """
    url = ad.actual_url.lower()
    displayed = ad.displayed_url.lower()
    actual_parsed = urlparse(ad.actual_url)
    actual_domain = actual_parsed.netloc.replace('www.', '')
    
    # Extract tracking params first - needed for fingerprinting
    ad.tracking_params = extract_tracking_params(ad.actual_url)
    
    # =========================================================================
    # BEHAVIORAL FINGERPRINTING (Primary Detection)
    # =========================================================================
    
    # FINGERPRINT 1: Brand spoofing in ad display
    # Critical detection - ad shows "microsoft.com" but goes to "colinandresw.com"
    is_spoofing, spoof_desc = check_brand_spoofing_in_ad(ad.displayed_url, ad.actual_url)
    if is_spoofing:
        ad.is_suspicious = True
        ad.suspicion_reasons.append(f"🚨 BRAND SPOOFING: {spoof_desc}")
        
        # If brand spoofing + ad tracking params = high confidence malvertising AiTM
        if 'gclid' in ad.tracking_params or 'msclkid' in ad.tracking_params:
            ad.suspicion_reasons.append("AD-BASED AiTM: Brand spoof + ad click tracking")
    
    # FINGERPRINT 2: Display/actual URL mismatch (general)
    # Extract domain from displayed URL properly
    if displayed and ad.actual_url:
        # Parse displayed URL to get domain
        displayed_parsed = urlparse(displayed if displayed.startswith('http') else f'https://{displayed}')
        displayed_domain = displayed_parsed.netloc.replace('www.', '') if displayed_parsed.netloc else displayed.split('/')[0].replace('www.', '')
        
        if displayed_domain and actual_domain and displayed_domain != 'https:':
            # Check if domains are genuinely different (not just subdomain variations)
            if displayed_domain not in actual_domain and actual_domain not in displayed_domain:
                ad.is_suspicious = True
                ad.suspicion_reasons.append(
                    f"Display URL mismatch: shows '{displayed_domain}' but goes to '{actual_domain}'"
                )
    
    # FINGERPRINT 3: Evilginx session tracking (rid=)
    if 'rid' in ad.tracking_params:
        ad.is_suspicious = True
        ad.suspicion_reasons.append("Evilginx marker: rid= parameter")
    
    # FINGERPRINT 4: URL patterns indicating phishing
    for pattern, description in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            ad.is_suspicious = True
            ad.suspicion_reasons.append(f"URL pattern: {description}")
    
    # FINGERPRINT 5: Domain naming patterns (Storm-2755 style)
    is_impersonation, impersonation_desc = check_brand_impersonation(actual_domain)
    if is_impersonation:
        ad.is_suspicious = True
        ad.suspicion_reasons.append(f"Domain pattern: {impersonation_desc}")
    
    # FINGERPRINT 6: Ad parameter combinations indicating malvertising campaign
    # (gclid + brand spoof, msclkid + utm_source=bing, etc.)
    param_score, param_reasons = score_ad_parameters(ad.tracking_params)
    if param_score >= 30:
        ad.is_suspicious = True
        ad.suspicion_reasons.append(f"Malvertising fingerprint ({param_score}): {', '.join(param_reasons)}")
    elif param_score >= 15:
        ad.suspicion_reasons.append(f"Ad tracking indicators ({param_score}): {', '.join(param_reasons)}")
    
    # =========================================================================
    # IOC MATCHING (Supplementary - confirms known threats)
    # =========================================================================
    from . import signatures
    domain_ioc = signatures.check_domain_ioc(actual_domain)
    if domain_ioc:
        # IOC match confirms but doesn't replace fingerprint detection
        ad.suspicion_reasons.append(f"[IOC MATCH] {domain_ioc.get('notes', actual_domain)}")
        if not ad.is_suspicious:
            ad.is_suspicious = True  # Only set if fingerprinting didn't already catch it
    
    return ad


# =============================================================================
# Bing Ads API Integration
# =============================================================================

def search_bing_ads_api(query: str, api_key: str | None = None) -> list[AdResult]:
    """
    Search for ads using Bing Ads API.
    
    Requires BING_ADS_API_KEY environment variable or api_key parameter.
    
    Note: This uses the Bing Web Search API which includes ads in results.
    For production, consider the Microsoft Advertising API for more detailed ad data.
    """
    api_key = api_key or os.environ.get('BING_ADS_API_KEY') or os.environ.get('BING_SEARCH_API_KEY')
    
    if not api_key:
        raise RuntimeError(
            "No Bing API key found. Set BING_ADS_API_KEY or BING_SEARCH_API_KEY env var."
        )
    
    endpoint = "https://api.bing.microsoft.com/v7.0/search"
    
    headers = {
        "Ocp-Apim-Subscription-Key": api_key,
    }
    
    params = {
        "q": query,
        "count": 50,
        "responseFilter": "Webpages,Ads",
        "mkt": "en-US",
    }
    
    try:
        resp = requests.get(endpoint, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Bing API request failed: {e}")
    
    ads = []
    
    # Parse ads from response
    # Note: Bing Web Search API may return ads in different formats
    if 'ads' in data:
        for idx, ad_data in enumerate(data['ads'].get('value', [])):
            ad = AdResult(
                query=query,
                ad_position=idx + 1,
                title=ad_data.get('name', ''),
                displayed_url=ad_data.get('displayUrl', ''),
                actual_url=ad_data.get('url', ''),
                description=ad_data.get('description', ''),
                source='bing_api',
            )
            ad = analyze_ad_url(ad)
            ads.append(ad)
    
    # Also check webpages that might be sponsored
    if 'webPages' in data:
        for idx, page in enumerate(data['webPages'].get('value', [])):
            # Look for sponsored markers
            if page.get('isSponsored') or 'ad' in str(page.get('contractualRules', [])).lower():
                ad = AdResult(
                    query=query,
                    ad_position=idx + 1,
                    title=page.get('name', ''),
                    displayed_url=page.get('displayUrl', ''),
                    actual_url=page.get('url', ''),
                    description=page.get('snippet', ''),
                    source='bing_api_sponsored',
                )
                ad = analyze_ad_url(ad)
                ads.append(ad)
    
    return ads


# =============================================================================
# Browser-based Ad Scraping (Playwright)
# =============================================================================

def scrape_google_ads_browser(query: str, headless: bool = True) -> list[AdResult]:
    """
    Scrape Google search ads using Playwright browser automation.
    
    This captures sponsored results that may not appear in API results.
    Requires playwright to be installed: pip install playwright && playwright install
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise RuntimeError(
            "Playwright not installed. Run: pip install playwright && playwright install chromium"
        )
    
    ads = []
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080},
        )
        page = context.new_page()
        
        try:
            # Navigate to Google
            search_url = f"https://www.google.com/search?q={requests.utils.quote(query)}"
            page.goto(search_url, wait_until="networkidle", timeout=30000)
            
            # Wait for results
            time.sleep(2)
            
            # Find sponsored results
            # Google ads typically have "Sponsored" or "Ad" labels
            ad_selectors = [
                'div[data-text-ad="1"]',
                'div[data-hveid] span:has-text("Sponsored")',
                'div[data-hveid] span:has-text("Ad")',
                '.commercial-unit-desktop-top',
                'div[data-sokoban-container]',
            ]
            
            ad_position = 0
            
            for selector in ad_selectors:
                try:
                    elements = page.query_selector_all(selector)
                    for elem in elements:
                        ad_position += 1
                        
                        # Try to extract ad info
                        try:
                            # Find the link
                            link = elem.query_selector('a[href]')
                            if not link:
                                continue
                            
                            href = link.get_attribute('href') or ''
                            title = link.inner_text().strip()
                            
                            # Find displayed URL
                            displayed_url = ""
                            cite = elem.query_selector('cite')
                            if cite:
                                displayed_url = cite.inner_text().strip()
                            
                            # Find description
                            description = ""
                            desc_elem = elem.query_selector('div[role="text"]')
                            if desc_elem:
                                description = desc_elem.inner_text().strip()
                            
                            if href and title:
                                ad = AdResult(
                                    query=query,
                                    ad_position=ad_position,
                                    title=title[:200],
                                    displayed_url=displayed_url,
                                    actual_url=href,
                                    description=description[:500],
                                    source='google_browser',
                                )
                                ad = analyze_ad_url(ad)
                                ads.append(ad)
                                
                        except Exception:
                            continue
                            
                except Exception:
                    continue
            
        except Exception as e:
            print(f"Browser scraping error: {e}")
        finally:
            browser.close()
    
    return ads


def scrape_bing_ads_browser(query: str, headless: bool = True) -> list[AdResult]:
    """
    Scrape Bing search ads using Playwright browser automation.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise RuntimeError(
            "Playwright not installed. Run: pip install playwright && playwright install chromium"
        )
    
    ads = []
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            viewport={"width": 1920, "height": 1080},
        )
        page = context.new_page()
        
        try:
            search_url = f"https://www.bing.com/search?q={requests.utils.quote(query)}"
            page.goto(search_url, wait_until="networkidle", timeout=30000)
            
            time.sleep(2)
            
            # Bing ad selectors
            ad_selectors = [
                'li.b_ad',
                'div.b_adSlug',
                'ol#b_results li.b_ad',
            ]
            
            ad_position = 0
            
            for selector in ad_selectors:
                try:
                    elements = page.query_selector_all(selector)
                    for elem in elements:
                        ad_position += 1
                        
                        try:
                            link = elem.query_selector('a[href]')
                            if not link:
                                continue
                            
                            href = link.get_attribute('href') or ''
                            title = link.inner_text().strip()
                            
                            displayed_url = ""
                            cite = elem.query_selector('cite')
                            if cite:
                                displayed_url = cite.inner_text().strip()
                            
                            description = ""
                            desc = elem.query_selector('p')
                            if desc:
                                description = desc.inner_text().strip()
                            
                            if href and title:
                                ad = AdResult(
                                    query=query,
                                    ad_position=ad_position,
                                    title=title[:200],
                                    displayed_url=displayed_url,
                                    actual_url=href,
                                    description=description[:500],
                                    source='bing_browser',
                                )
                                ad = analyze_ad_url(ad)
                                ads.append(ad)
                                
                        except Exception:
                            continue
                            
                except Exception:
                    continue
            
        except Exception as e:
            print(f"Browser scraping error: {e}")
        finally:
            browser.close()
    
    return ads


def scrape_ads_all_sources(query: str, use_bing_api: bool = False, 
                           headless: bool = True) -> list[AdResult]:
    """
    Scrape ads from all available sources.
    
    Args:
        query: Search query
        use_bing_api: Try Bing Ads API (requires key)
        headless: Run browser in headless mode
    
    Returns:
        Combined list of AdResults from all sources
    """
    all_ads = []
    
    # Try Bing API if requested and key available
    if use_bing_api:
        try:
            bing_ads = search_bing_ads_api(query)
            all_ads.extend(bing_ads)
            print(f"  Bing API: {len(bing_ads)} ads")
        except Exception as e:
            print(f"  Bing API failed: {e}")
    
    # Browser scraping
    try:
        google_ads = scrape_google_ads_browser(query, headless=headless)
        all_ads.extend(google_ads)
        print(f"  Google browser: {len(google_ads)} ads")
    except Exception as e:
        print(f"  Google browser failed: {e}")
    
    try:
        bing_ads = scrape_bing_ads_browser(query, headless=headless)
        all_ads.extend(bing_ads)
        print(f"  Bing browser: {len(bing_ads)} ads")
    except Exception as e:
        print(f"  Bing browser failed: {e}")
    
    # Deduplicate by URL
    seen_urls = set()
    unique_ads = []
    for ad in all_ads:
        if ad.actual_url not in seen_urls:
            seen_urls.add(ad.actual_url)
            unique_ads.append(ad)
    
    return unique_ads


def find_suspicious_ads(query: str, use_bing_api: bool = False,
                       headless: bool = True) -> list[AdResult]:
    """
    Search for ads and return only suspicious ones.
    
    This is the main entry point for malvertising detection.
    """
    all_ads = scrape_ads_all_sources(query, use_bing_api=use_bing_api, headless=headless)
    
    suspicious = [ad for ad in all_ads if ad.is_suspicious]
    
    return suspicious


if __name__ == "__main__":
    import sys
    
    query = sys.argv[1] if len(sys.argv) > 1 else "o365 login"
    
    print(f"Searching for malvertising: '{query}'")
    print("=" * 60)
    
    ads = scrape_ads_all_sources(query, use_bing_api=False, headless=True)
    
    print(f"\nTotal ads found: {len(ads)}")
    suspicious = [a for a in ads if a.is_suspicious]
    print(f"Suspicious ads: {len(suspicious)}")
    
    for ad in ads:
        status = "🚨 SUSPICIOUS" if ad.is_suspicious else "  "
        print(f"\n{status} [{ad.source}] {ad.title[:50]}")
        print(f"   Display: {ad.displayed_url}")
        print(f"   Actual:  {ad.actual_url[:80]}")
        if ad.suspicion_reasons:
            print(f"   Reasons: {ad.suspicion_reasons}")
