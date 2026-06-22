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


def analyze_ad_url(ad: AdResult) -> AdResult:
    """Analyze an ad URL for suspicious patterns."""
    url = ad.actual_url.lower()
    displayed = ad.displayed_url.lower()
    
    # Check for URL pattern mismatches
    if displayed and ad.actual_url:
        displayed_domain = displayed.split('/')[0].replace('www.', '')
        actual_parsed = urlparse(ad.actual_url)
        actual_domain = actual_parsed.netloc.replace('www.', '')
        
        if displayed_domain and actual_domain:
            if displayed_domain not in actual_domain and actual_domain not in displayed_domain:
                ad.is_suspicious = True
                ad.suspicion_reasons.append(
                    f"Display URL mismatch: shows '{displayed_domain}' but goes to '{actual_domain}'"
                )
    
    # Check for suspicious patterns
    for pattern, description in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            ad.is_suspicious = True
            ad.suspicion_reasons.append(f"Suspicious pattern: {description}")
    
    # Extract tracking params
    ad.tracking_params = extract_tracking_params(ad.actual_url)
    
    # Check for rid= (Evilginx marker)
    if 'rid' in ad.tracking_params:
        ad.is_suspicious = True
        ad.suspicion_reasons.append("Contains rid= parameter (Evilginx marker)")
    
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
