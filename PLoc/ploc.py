#!/usr/bin/env python3
# (c) 2026, Shane D. Shook, PhD
"""
PLoc - Physical Location to Shodan Scanner

Converts a physical address to lat/long coordinates and queries Shodan
for devices in that geographic area. Includes optional filtering for
Building Automation Systems (BAS) and Building Management Systems (BMS).
Supports WHOIS cross-referencing for property management/tenant identification.
"""

import json
import socket
import ssl
import sys
from datetime import datetime
from getpass import getpass
from collections import defaultdict
from urllib.parse import quote

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from ipwhois import IPWhois
    from ipwhois.exceptions import IPDefinedError, ASNRegistryError
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False

# BAS/BMS Shodan fingerprints - common building automation protocols and products
BAS_BMS_FILTERS = [
    'port:47808',           # BACnet
    'port:502',             # Modbus
    'port:1911',            # Niagara Fox
    'port:4911',            # Niagara Fox SSL
    '"BACnet"',
    '"Modbus"',
    '"Niagara"',
    '"Tridium"',
    '"Johnson Controls"',
    '"Honeywell"',
    '"Siemens" "building"',
    '"Schneider Electric"',
    '"LonWorks"',
    '"KNX"',
    '"HVAC"',
    '"Building Automation"',
    '"EnergyPlus"',
    '"Carrier"',
    '"Automated Logic"',
    '"Delta Controls"',
    '"Distech"',
    '"Crestron"',
    '"Lutron"',
    '"Metasys"',
]

try:
    import shodan
except ImportError:
    print("Error: shodan module not found. Install with: pip install shodan")
    sys.exit(1)

try:
    from geopy.geocoders import Nominatim
    from geopy.exc import GeocoderTimedOut, GeocoderServiceError
except ImportError:
    print("Error: geopy module not found. Install with: pip install geopy")
    sys.exit(1)


def get_coordinates(address: str) -> tuple[float, float, str] | None:
    """
    Convert a physical address to latitude/longitude coordinates.
    
    Args:
        address: Physical address string
        
    Returns:
        Tuple of (latitude, longitude, display_name) or None if not found
    """
    geolocator = Nominatim(user_agent="ploc_scanner")
    
    try:
        location = geolocator.geocode(address, timeout=10)
        if location:
            return (location.latitude, location.longitude, location.address)
        return None
    except GeocoderTimedOut:
        print("Error: Geocoding request timed out. Please try again.")
        return None
    except GeocoderServiceError as e:
        print(f"Error: Geocoding service error: {e}")
        return None


def search_shodan_by_geo(api_key: str, lat: float, lon: float, radius_km: int = 10, 
                         bas_bms_only: bool = False) -> dict:
    """
    Search Shodan for devices near given coordinates.
    
    Args:
        api_key: Shodan API key
        lat: Latitude coordinate
        lon: Longitude coordinate
        radius_km: Search radius in kilometers
        bas_bms_only: If True, filter results to BAS/BMS devices only
        
    Returns:
        Dictionary containing search results
    """
    api = shodan.Shodan(api_key)
    
    # Shodan geo search query format: geo:lat,lon,radius_km
    geo_query = f"geo:{lat},{lon},{radius_km}"
    
    if bas_bms_only:
        # Combine geo filter with BAS/BMS fingerprints using OR
        bas_filter = " OR ".join(BAS_BMS_FILTERS)
        query = f"{geo_query} ({bas_filter})"
    else:
        query = geo_query
    
    try:
        results = api.search(query)
        return {
            "success": True,
            "query": query,
            "total": results.get("total", 0),
            "matches": results.get("matches", [])
        }
    except shodan.APIError as e:
        return {
            "success": False,
            "query": query,
            "error": str(e),
            "total": 0,
            "matches": []
        }


def lookup_rdap(ip: str) -> dict | None:
    """
    Perform RDAP lookup for an IP address.
    
    Args:
        ip: IP address to lookup
        
    Returns:
        Dictionary containing RDAP data or None if lookup fails
    """
    if not IPWHOIS_AVAILABLE:
        return None
    
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        
        # Extract relevant fields
        return {
            "source": "RDAP",
            "asn": results.get("asn"),
            "asn_description": results.get("asn_description"),
            "asn_country_code": results.get("asn_country_code"),
            "network_name": results.get("network", {}).get("name"),
            "network_cidr": results.get("asn_cidr"),
            "registrant": extract_entity(results, "registrant"),
            "admin": extract_entity(results, "administrative"),
            "tech": extract_entity(results, "technical"),
            "abuse": extract_entity(results, "abuse"),
        }
    except (IPDefinedError, ASNRegistryError):
        return None
    except Exception:
        return None


def lookup_whois_legacy(ip: str) -> dict | None:
    """
    Perform legacy WHOIS lookup for an IP address.
    
    Args:
        ip: IP address to lookup
        
    Returns:
        Dictionary containing WHOIS data or None if lookup fails
    """
    if not IPWHOIS_AVAILABLE:
        return None
    
    try:
        obj = IPWhois(ip)
        results = obj.lookup_whois()
        
        # Extract relevant fields from legacy WHOIS format
        nets = results.get("nets", [{}])
        primary_net = nets[0] if nets else {}
        
        return {
            "source": "WHOIS",
            "asn": results.get("asn"),
            "asn_description": results.get("asn_description"),
            "asn_country_code": results.get("asn_country_code"),
            "network_name": primary_net.get("name"),
            "network_cidr": results.get("asn_cidr"),
            "registrant": {
                "name": primary_net.get("name"),
                "organization": primary_net.get("description"),
                "address": primary_net.get("address"),
                "email": primary_net.get("emails", [None])[0] if primary_net.get("emails") else None,
            },
            "admin": None,
            "tech": None,
            "abuse": {
                "email": primary_net.get("abuse_emails", [None])[0] if primary_net.get("abuse_emails") else None,
            } if primary_net.get("abuse_emails") else None,
        }
    except (IPDefinedError, ASNRegistryError):
        return None
    except Exception:
        return None


def lookup_ip_registration(ip: str) -> dict | None:
    """
    Perform IP registration lookup using RDAP first, falling back to legacy WHOIS.
    
    Args:
        ip: IP address to lookup
        
    Returns:
        Dictionary containing registration data or None if all lookups fail
    """
    # Try RDAP first (modern, structured format)
    result = lookup_rdap(ip)
    if result:
        return result
    
    # Fall back to legacy WHOIS
    return lookup_whois_legacy(ip)


def reverse_dns_lookup(ip: str, timeout: float = 2.0) -> dict:
    """
    Perform reverse DNS lookup for an IP address.
    
    Args:
        ip: IP address to lookup
        timeout: Socket timeout in seconds
        
    Returns:
        Dictionary containing hostname and aliases, or error info
    """
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        return {
            "success": True,
            "hostname": hostname,
            "aliases": aliases if aliases else []
        }
    except socket.herror as e:
        # Host not found or no PTR record
        return {
            "success": False,
            "hostname": None,
            "aliases": [],
            "error": "No PTR record"
        }
    except socket.gaierror as e:
        return {
            "success": False,
            "hostname": None,
            "aliases": [],
            "error": str(e)
        }
    except socket.timeout:
        return {
            "success": False,
            "hostname": None,
            "aliases": [],
            "error": "Timeout"
        }
    except Exception as e:
        return {
            "success": False,
            "hostname": None,
            "aliases": [],
            "error": str(e)
        }
    finally:
        socket.setdefaulttimeout(old_timeout)


def get_tls_certificate(ip: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    Retrieve and parse TLS certificate from a host.
    
    Args:
        ip: IP address or hostname
        port: Port number (default 443)
        timeout: Connection timeout in seconds
        
    Returns:
        Dictionary containing certificate details
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Accept self-signed certs
        
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_binary = ssock.getpeercert(binary_form=True)
                
                # If cert is empty (happens with CERT_NONE), try to get basic info
                if not cert and cert_binary:
                    # Parse binary cert for basic info
                    import hashlib
                    cert_hash = hashlib.sha256(cert_binary).hexdigest()
                    return {
                        "success": True,
                        "fingerprint_sha256": cert_hash,
                        "raw_available": True,
                        "parse_error": "Certificate details require verification mode"
                    }
                
                if not cert:
                    return {"success": False, "error": "No certificate returned"}
                
                # Extract subject details
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                
                # Extract SANs
                sans = []
                for ext_type, ext_value in cert.get('subjectAltName', []):
                    sans.append({"type": ext_type, "value": ext_value})
                
                return {
                    "success": True,
                    "subject": {
                        "common_name": subject.get('commonName'),
                        "organization": subject.get('organizationName'),
                        "organizational_unit": subject.get('organizationalUnitName'),
                        "locality": subject.get('localityName'),
                        "state": subject.get('stateOrProvinceName'),
                        "country": subject.get('countryName'),
                        "email": subject.get('emailAddress'),
                    },
                    "issuer": {
                        "common_name": issuer.get('commonName'),
                        "organization": issuer.get('organizationName'),
                        "country": issuer.get('countryName'),
                    },
                    "sans": sans,
                    "san_dns_names": [s["value"] for s in sans if s["type"] == "DNS"],
                    "san_emails": [s["value"] for s in sans if s["type"] == "email"],
                    "serial_number": cert.get('serialNumber'),
                    "not_before": cert.get('notBefore'),
                    "not_after": cert.get('notAfter'),
                    "version": cert.get('version'),
                }
    
    except ssl.SSLError as e:
        return {"success": False, "error": f"SSL error: {str(e)}"}
    except socket.timeout:
        return {"success": False, "error": "Connection timeout"}
    except ConnectionRefusedError:
        return {"success": False, "error": "Connection refused"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def query_crtsh(domain: str, timeout: float = 10.0) -> dict:
    """
    Query crt.sh certificate transparency logs for a domain.
    
    Args:
        domain: Domain name to search
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary containing crt.sh results
    """
    if not REQUESTS_AVAILABLE:
        return {"success": False, "error": "requests module not available"}
    
    try:
        # crt.sh JSON API
        url = f"https://crt.sh/?q={quote(domain)}&output=json"
        response = requests.get(url, timeout=timeout)
        
        if response.status_code != 200:
            return {"success": False, "error": f"HTTP {response.status_code}"}
        
        certs = response.json()
        
        if not certs:
            return {"success": True, "certificates": [], "total": 0}
        
        # Deduplicate and extract relevant info
        seen_ids = set()
        unique_certs = []
        
        for cert in certs:
            cert_id = cert.get('id')
            if cert_id not in seen_ids:
                seen_ids.add(cert_id)
                unique_certs.append({
                    "id": cert_id,
                    "logged_at": cert.get('entry_timestamp'),
                    "not_before": cert.get('not_before'),
                    "not_after": cert.get('not_after'),
                    "common_name": cert.get('common_name'),
                    "name_value": cert.get('name_value'),  # All names in cert
                    "issuer_name": cert.get('issuer_name'),
                    "issuer_ca_id": cert.get('issuer_ca_id'),
                })
        
        # Sort by logged date, most recent first
        unique_certs.sort(key=lambda x: x.get('logged_at', ''), reverse=True)
        
        return {
            "success": True,
            "total": len(unique_certs),
            "certificates": unique_certs[:50],  # Limit to 50 most recent
        }
    
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Request timeout"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": str(e)}
    except json.JSONDecodeError:
        return {"success": False, "error": "Invalid JSON response"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def query_securitytrails(domain: str, api_key: str, timeout: float = 10.0) -> dict:
    """
    Query SecurityTrails API for domain information.
    
    Args:
        domain: Domain name to search
        api_key: SecurityTrails API key
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary containing SecurityTrails results
    """
    if not REQUESTS_AVAILABLE:
        return {"success": False, "error": "requests module not available"}
    
    if not api_key:
        return {"success": False, "error": "No API key provided"}
    
    try:
        headers = {
            "APIKEY": api_key,
            "Accept": "application/json"
        }
        
        # Get domain details
        url = f"https://api.securitytrails.com/v1/domain/{quote(domain)}"
        response = requests.get(url, headers=headers, timeout=timeout)
        
        if response.status_code == 401:
            return {"success": False, "error": "Invalid API key"}
        if response.status_code == 429:
            return {"success": False, "error": "Rate limit exceeded"}
        if response.status_code != 200:
            return {"success": False, "error": f"HTTP {response.status_code}"}
        
        data = response.json()
        
        return {
            "success": True,
            "hostname": data.get('hostname'),
            "alexa_rank": data.get('alexa_rank'),
            "current_dns": data.get('current_dns', {}),
            "subdomains_count": data.get('subdomain_count'),
        }
    
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def analyze_tls_for_matches(matches: list, do_crtsh: bool = True, 
                            securitytrails_key: str = None,
                            progress_callback=None) -> tuple[list, dict]:
    """
    Analyze TLS certificates for HTTPS services in Shodan matches.
    
    Args:
        matches: List of Shodan match results
        do_crtsh: Whether to query crt.sh for certificate transparency
        securitytrails_key: Optional SecurityTrails API key
        progress_callback: Optional progress callback function
        
    Returns:
        Tuple of (enriched matches, certificate summary)
    """
    # Find matches with HTTPS/TLS services
    tls_ports = {443, 8443, 8080, 4443, 9443}  # Common HTTPS ports
    tls_matches = []
    
    for match in matches:
        port = match.get('port')
        ssl_info = match.get('ssl')
        
        # Check if it's a TLS service
        if port in tls_ports or ssl_info:
            tls_matches.append(match)
    
    if not tls_matches:
        return matches, {}
    
    # Track domains for crt.sh lookups (deduplicated)
    domains_seen = set()
    cert_summary = {
        "total_tls_services": len(tls_matches),
        "certificates_retrieved": 0,
        "unique_domains": [],
        "organizations": defaultdict(int),
        "issuers": defaultdict(int),
        "crtsh_results": {},
        "securitytrails_results": {},
    }
    
    total = len(tls_matches)
    for idx, match in enumerate(tls_matches):
        ip = match.get('ip_str')
        port = match.get('port', 443)
        
        if progress_callback:
            progress_callback(idx + 1, total, f"{ip}:{port}")
        
        # Get TLS certificate
        cert_data = get_tls_certificate(ip, port)
        match['tls_certificate'] = cert_data
        
        if cert_data.get('success'):
            cert_summary["certificates_retrieved"] += 1
            
            # Track organization
            org = cert_data.get('subject', {}).get('organization')
            if org:
                cert_summary["organizations"][org] += 1
            
            # Track issuer
            issuer = cert_data.get('issuer', {}).get('organization')
            if issuer:
                cert_summary["issuers"][issuer] += 1
            
            # Collect domains for crt.sh lookup
            cn = cert_data.get('subject', {}).get('common_name')
            if cn and not cn.startswith('*') and '.' in cn:
                domains_seen.add(cn)
            
            for dns_name in cert_data.get('san_dns_names', []):
                if not dns_name.startswith('*') and '.' in dns_name:
                    # Extract base domain
                    parts = dns_name.split('.')
                    if len(parts) >= 2:
                        base_domain = '.'.join(parts[-2:])
                        domains_seen.add(base_domain)
    
    cert_summary["unique_domains"] = list(domains_seen)
    
    # Query crt.sh for discovered domains
    if do_crtsh and domains_seen:
        print(f"\n    Querying crt.sh for {len(domains_seen)} domains...")
        for domain in list(domains_seen)[:10]:  # Limit to 10 domains
            crtsh_data = query_crtsh(domain)
            cert_summary["crtsh_results"][domain] = crtsh_data
    
    # Query SecurityTrails if API key provided
    if securitytrails_key and domains_seen:
        print(f"\n    Querying SecurityTrails for {len(domains_seen)} domains...")
        for domain in list(domains_seen)[:5]:  # Limit to 5 (API rate limits)
            st_data = query_securitytrails(domain, securitytrails_key)
            cert_summary["securitytrails_results"][domain] = st_data
    
    # Convert defaultdicts to regular dicts
    cert_summary["organizations"] = dict(cert_summary["organizations"])
    cert_summary["issuers"] = dict(cert_summary["issuers"])
    
    return matches, cert_summary


def search_property_management(address: str, timeout: float = 15.0) -> dict:
    """
    Search for property/building management companies for a given address.
    
    Args:
        address: Physical address to search
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary containing property management info
    """
    if not REQUESTS_AVAILABLE:
        return {"success": False, "error": "requests module not available"}
    
    property_managers = []
    
    try:
        # Search for property management info via DuckDuckGo
        # Extract street address for searching
        addr_parts = address.replace("\n", " ").split(",")
        street_addr = addr_parts[0].strip() if addr_parts else address[:50]
        
        search_queries = [
            f'"{street_addr}" property management',
            f'"{street_addr}" building owner landlord',
            f'"{street_addr}" building management company',
        ]
        
        for query in search_queries[:2]:  # Limit queries
            search_url = f"https://api.duckduckgo.com/?q={quote(query)}&format=json&no_html=1"
            response = requests.get(search_url, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                # Check related topics for company names
                for topic in data.get("RelatedTopics", [])[:5]:
                    text = topic.get("Text", "")
                    if text and any(kw in text.lower() for kw in 
                                   ["management", "property", "realty", "commercial", "landlord"]):
                        property_managers.append({
                            "name": text[:100],
                            "source": "Web Search",
                            "raw": True
                        })
    except Exception:
        pass
    
    return {
        "success": True,
        "address": address,
        "property_managers": property_managers
    }


def search_shodan_by_org(api_key: str, org_name: str, city: str = None) -> dict:
    """
    Search Shodan for hosts by organization name.
    
    Args:
        api_key: Shodan API key
        org_name: Organization name to search
        city: Optional city to filter results
        
    Returns:
        Dictionary containing search results
    """
    try:
        api = shodan.Shodan(api_key)
        
        # Build query
        query = f'org:"{org_name}"'
        if city:
            query += f' city:"{city}"'
        
        results = api.search(query)
        
        return {
            "success": True,
            "query": query,
            "total": results.get("total", 0),
            "matches": results.get("matches", [])
        }
    except shodan.APIError as e:
        return {
            "success": False,
            "query": query if 'query' in dir() else org_name,
            "error": str(e),
            "total": 0,
            "matches": []
        }


def extract_addresses_from_webpage(url: str, timeout: float = 15.0) -> list:
    """
    Extract potential office addresses from a webpage.
    
    Args:
        url: URL to scrape
        timeout: Request timeout
        
    Returns:
        List of potential address strings found
    """
    if not REQUESTS_AVAILABLE:
        return []
    
    import re
    
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=timeout)
        
        if response.status_code != 200:
            return []
        
        content = response.text
        
        # First, strip HTML tags and normalize whitespace for cleaner extraction
        text_content = re.sub(r'<[^>]+>', ' ', content)
        text_content = re.sub(r'\s+', ' ', text_content)
        
        addresses = []
        
        # Pattern for US addresses with zip codes
        # Match: number + street + city + state + zip
        us_patterns = [
            # Full address with Suite
            r'(\d+\s+[A-Za-z\.\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Way|Lane|Ln|Place|Pl|Real|Grove)[,\s]+(?:Suite|Ste|#)?\s*\d*[,\s]+[A-Za-z\s]+[,\s]+[A-Z]{2}[,\s]+\d{5}(?:-\d{4})?)',
            # Simpler: number + street + city, state zip
            r'(\d+\s+[A-Za-z\.\s]{5,40}[,\s]+[A-Za-z\s]{3,30}[,\s]+[A-Z]{2}\s+\d{5})',
        ]
        
        for pattern in us_patterns:
            matches = re.findall(pattern, text_content)
            for match in matches:
                clean = match.strip()
                if len(clean) > 15 and len(clean) < 150:
                    addresses.append(clean)
        
        # Pattern for UK addresses with postcodes
        # Format: number + street, city postcode country
        uk_pattern = r'(\d+\s+[A-Za-z\s]+(?:Grove|Street|Road|Lane|Avenue|Way|Place|Square|Court|Gardens)[,\s]+(?:Suite|Floor|Unit)?\s*\d*[,\s]*[A-Za-z\s]*[A-Z]{1,2}\d{1,2}[A-Z]?\s*\d[A-Z]{2}(?:\s+United Kingdom|\s+UK)?)'
        uk_matches = re.findall(uk_pattern, text_content)
        for match in uk_matches:
            clean = match.strip()
            if len(clean) > 15 and len(clean) < 150:
                addresses.append(clean)
        
        # Fallback: find UK postcodes and get surrounding context
        uk_postcode_pattern = r'([A-Z]{1,2}\d{1,2}[A-Z]?\s*\d[A-Z]{2})'
        uk_postcodes = re.findall(uk_postcode_pattern, text_content)
        
        for postcode in uk_postcodes:
            # Find the postcode in text and get context
            idx = text_content.find(postcode)
            if idx > 0:
                # Get text before and after postcode
                start = max(0, idx - 80)
                end = min(len(text_content), idx + len(postcode) + 20)
                context = text_content[start:end]
                # Clean up
                context = context.strip()
                # Try to find where the address starts (look for a number)
                addr_start = re.search(r'\d+\s+[A-Za-z]', context)
                if addr_start:
                    clean_addr = context[addr_start.start():].strip()
                    # Clean up trailing text
                    clean_addr = re.sub(r'\s+(Signatories|Companies|About|Contact).*$', '', clean_addr, flags=re.IGNORECASE)
                    if len(clean_addr) > 15 and len(clean_addr) < 150:
                        addresses.append(clean_addr)
        
        # Look for address-related HTML elements
        address_tag_pattern = r'<address[^>]*>(.*?)</address>'
        address_tags = re.findall(address_tag_pattern, content, re.DOTALL | re.IGNORECASE)
        for addr in address_tags:
            clean = re.sub(r'<[^>]+>', ' ', addr)
            clean = re.sub(r'\s+', ' ', clean).strip()
            if len(clean) > 10 and len(clean) < 200:
                addresses.append(clean)
        
        # Deduplicate and filter out garbage
        seen = set()
        unique = []
        for addr in addresses:
            # Skip if looks like code/HTML
            if '<' in addr or '>' in addr or '{' in addr or '}' in addr:
                continue
            if 'http' in addr.lower() or 'www.' in addr.lower():
                continue
            if 'svg' in addr.lower() or 'viewbox' in addr.lower():
                continue
                
            key = addr[:30].lower()
            if key not in seen:
                seen.add(key)
                unique.append(addr)
        
        return unique[:10]  # Limit results
        
    except Exception as e:
        return []


def search_company_website_for_locations(company_name: str, timeout: float = 15.0) -> dict:
    """
    Search the web for a company's office locations by finding and scraping
    their website contact/about pages.
    
    Args:
        company_name: Company name to search
        timeout: Request timeout
        
    Returns:
        Dictionary containing found locations
    """
    if not REQUESTS_AVAILABLE:
        return {"success": False, "error": "requests module not available"}
    
    import re
    
    locations = []
    urls_checked = []
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    try:
        # Generate likely company website URLs
        company_words = company_name.lower().replace(',', '').replace('.', '').split()
        
        # Create potential domain names
        potential_domains = []
        
        # Try common patterns: companyname.com, company-name.com
        if len(company_words) >= 1:
            # First word only
            potential_domains.append(f"https://{company_words[0]}.com")
            potential_domains.append(f"https://www.{company_words[0]}.com")
            
            # First two words combined
            if len(company_words) >= 2:
                combined = ''.join(company_words[:2])
                potential_domains.append(f"https://{combined}.com")
                potential_domains.append(f"https://www.{combined}.com")
                
                # With hyphen
                hyphenated = '-'.join(company_words[:2])
                potential_domains.append(f"https://{hyphenated}.com")
                
            # Common suffixes: cap, capital, hq, etc.
            if 'capital' in company_words:
                base = company_words[0]
                potential_domains.append(f"https://{base}cap.com")
                potential_domains.append(f"https://www.{base}cap.com")
        
        # Step 1: Try direct company website URLs
        for base_url in potential_domains[:6]:
            if base_url in urls_checked:
                continue
                
            try:
                urls_checked.append(base_url)
                addresses = extract_addresses_from_webpage(base_url, timeout=5)
                
                for addr in addresses:
                    locations.append({
                        "address": addr,
                        "source": f"Website: {base_url}",
                        "company_name": company_name,
                        "type": "web_scraped"
                    })
                
                if locations:
                    # Found addresses, also try contact page
                    contact_url = base_url.rstrip('/') + '/contact'
                    urls_checked.append(contact_url)
                    contact_addrs = extract_addresses_from_webpage(contact_url, timeout=5)
                    for addr in contact_addrs:
                        locations.append({
                            "address": addr,
                            "source": f"Website: {contact_url}",
                            "company_name": company_name,
                            "type": "web_scraped"
                        })
                    break
                    
            except Exception:
                continue
        
        # Step 2: If no locations found, try web search
        if not locations:
            search_url = f"https://html.duckduckgo.com/html/?q={quote(company_name + ' office address')}"
            
            try:
                response = requests.get(search_url, headers=headers, timeout=timeout)
                
                if response.status_code == 200:
                    # Extract URLs that might be the company website
                    url_pattern = r'href="(https?://[^"]+)"'
                    urls = re.findall(url_pattern, response.text)
                    
                    # Filter to likely company websites
                    for url in urls[:10]:
                        url_lower = url.lower()
                        if any(word in url_lower for word in company_words[:2] if len(word) > 3):
                            if 'duckduckgo' not in url_lower and 'google' not in url_lower:
                                if url not in urls_checked:
                                    urls_checked.append(url)
                                    addresses = extract_addresses_from_webpage(url, timeout=5)
                                    for addr in addresses:
                                        locations.append({
                                            "address": addr,
                                            "source": f"Website: {url[:50]}",
                                            "company_name": company_name,
                                            "type": "web_scraped"
                                        })
                                    if locations:
                                        break
            except Exception:
                pass
        
        # Deduplicate by first 30 chars of address
        seen = set()
        unique_locations = []
        for loc in locations:
            key = loc["address"][:30].lower()
            if key not in seen:
                seen.add(key)
                unique_locations.append(loc)
        
        return {
            "success": True,
            "locations": unique_locations,
            "urls_checked": urls_checked
        }
        
    except Exception as e:
        return {"success": False, "error": str(e), "locations": []}


def search_uk_companies_house(company_name: str, timeout: float = 15.0) -> dict:
    """
    Search UK Companies House for company registrations.
    
    Args:
        company_name: Company name to search
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary containing search results
    """
    if not REQUESTS_AVAILABLE:
        return {"success": False, "error": "requests module not available"}
    
    try:
        # UK Companies House free search API
        url = "https://api.company-information.service.gov.uk/search/companies"
        params = {"q": company_name}
        
        response = requests.get(url, params=params, timeout=timeout)
        
        if response.status_code == 401:
            # API key required - try alternative approach
            return {"success": False, "error": "API key required"}
        
        if response.status_code != 200:
            return {"success": False, "error": f"HTTP {response.status_code}"}
        
        data = response.json()
        items = data.get("items", [])
        
        companies = []
        for item in items[:10]:
            addr = item.get("address", {})
            addr_str = ", ".join(filter(None, [
                addr.get("address_line_1"),
                addr.get("address_line_2"),
                addr.get("locality"),
                addr.get("region"),
                addr.get("postal_code"),
                addr.get("country")
            ]))
            
            companies.append({
                "name": item.get("title"),
                "company_number": item.get("company_number"),
                "status": item.get("company_status"),
                "registered_address": addr_str if addr_str else None,
            })
        
        return {
            "success": True,
            "total": data.get("total_results", 0),
            "companies": companies
        }
    
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def search_sec_edgar(company_name: str, timeout: float = 15.0) -> dict:
    """
    Search SEC EDGAR for company filings and addresses.
    
    Args:
        company_name: Company name to search
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary containing search results
    """
    if not REQUESTS_AVAILABLE:
        return {"success": False, "error": "requests module not available"}
    
    try:
        # SEC EDGAR full-text search
        url = "https://efts.sec.gov/LATEST/search-index"
        params = {
            "q": company_name,
            "dateRange": "custom",
            "startdt": "2020-01-01",
            "enddt": "2026-12-31",
        }
        
        headers = {
            "User-Agent": "PLoc/1.0 (Security Research Tool)"
        }
        
        # Try company search endpoint
        search_url = f"https://www.sec.gov/cgi-bin/browse-edgar?company={quote(company_name)}&CIK=&type=&owner=include&count=10&action=getcompany&output=atom"
        
        response = requests.get(search_url, headers=headers, timeout=timeout)
        
        if response.status_code != 200:
            return {"success": False, "error": f"HTTP {response.status_code}"}
        
        # Parse the Atom feed for company info
        # This is a simplified parser - in production would use proper XML parsing
        addresses = []
        
        # Look for company info in the response
        content = response.text
        
        # Extract CIK numbers and company names from the feed
        import re
        cik_matches = re.findall(r'CIK=(\d+)', content)
        name_matches = re.findall(r'<title[^>]*>([^<]+)</title>', content)
        
        # For each CIK, we could fetch detailed company info
        # But for now, just indicate we found matches
        if cik_matches:
            return {
                "success": True,
                "addresses": [],  # Would need additional API calls to get addresses
                "ciks_found": cik_matches[:5],
                "note": "SEC filings found - addresses require additional lookup"
            }
        
        return {"success": True, "addresses": []}
    
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def search_company_locations(company_name: str, api_key: str = None, 
                             include_property_mgmt: bool = True,
                             manual_addresses: list = None,
                             timeout: float = 15.0) -> dict:
    """
    Search for a company's physical operating locations using multiple sources.
    Optionally includes property management company lookups and their Shodan results.
    
    Args:
        company_name: Company name to search
        api_key: Optional Shodan API key for property management searches
        include_property_mgmt: Whether to search for property management companies
        manual_addresses: Optional list of known addresses to include
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary containing found locations
    """
    if not REQUESTS_AVAILABLE:
        return {"success": False, "error": "requests module not available"}
    
    locations = []
    sources_checked = []
    
    # Source 0: Manual/known addresses if provided
    if manual_addresses:
        print(f"    [*] Adding {len(manual_addresses)} known addresses...")
        sources_checked.append("Manual/Known Addresses")
        for addr_info in manual_addresses:
            if isinstance(addr_info, str):
                addr_info = {"address": addr_info}
            locations.append({
                "address": addr_info.get("address", ""),
                "source": addr_info.get("source", "Manual Entry"),
                "company_name": addr_info.get("company_name", company_name),
                "type": "known_address",
                "property_managers": [],
                "property_manager_shodan": []
            })
    
    # Source 1: Company Website Scraping (PRIMARY - works globally)
    print(f"    [*] Searching company website for office locations...")
    sources_checked.append("Company Website")
    web_results = search_company_website_for_locations(company_name, timeout)
    
    if web_results.get("success") and web_results.get("locations"):
        print(f"    [+] Found {len(web_results['locations'])} addresses from web")
        for loc in web_results["locations"]:
            locations.append({
                "address": loc.get("address", ""),
                "source": loc.get("source", "Website"),
                "company_name": loc.get("company_name", company_name),
                "type": loc.get("type", "web_scraped"),
                "property_managers": [],
                "property_manager_shodan": []
            })
    
    # Source 2: OpenCorporates (backup - may require API key)
    print(f"    [*] Searching OpenCorporates...")
    sources_checked.append("OpenCorporates")
    oc_results = query_opencorporates(company_name)
    
    if oc_results.get("success") and oc_results.get("companies"):
        for company in oc_results["companies"]:
            if company.get("registered_address"):
                locations.append({
                    "address": company["registered_address"],
                    "source": "OpenCorporates",
                    "company_name": company.get("name"),
                    "status": company.get("status"),
                    "jurisdiction": company.get("jurisdiction"),
                    "type": "registered_address",
                    "property_managers": [],
                    "property_manager_shodan": []
                })
    elif oc_results.get("error"):
        print(f"    [!] OpenCorporates: {oc_results.get('error')}")
    
    # Source 3: DuckDuckGo/Web search for "{company} office address" or "headquarters"
    print(f"    [*] Searching web for additional locations...")
    sources_checked.append("Web Search")
    
    try:
        search_queries = [
            f"{company_name} headquarters address",
            f"{company_name} office locations",
        ]
        
        for query in search_queries:
            search_url = f"https://api.duckduckgo.com/?q={quote(query)}&format=json&no_html=1"
            response = requests.get(search_url, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                abstract = data.get("Abstract", "")
                if abstract and any(term in abstract.lower() for term in ["address", "located", "headquarter"]):
                    locations.append({
                        "address": abstract[:200],
                        "source": "Web Search (Abstract)",
                        "company_name": company_name,
                        "type": "extracted_reference",
                        "raw": True,
                        "property_managers": [],
                        "property_manager_shodan": []
                    })
    except Exception:
        pass
    
    # Deduplicate locations by address similarity
    unique_locations = []
    seen_addresses = set()
    
    for loc in locations:
        addr_key = loc["address"].lower()[:50] if loc.get("address") else ""
        if addr_key and addr_key not in seen_addresses:
            seen_addresses.add(addr_key)
            unique_locations.append(loc)
    
    # Search for property management companies at each location
    if include_property_mgmt and unique_locations:
        print(f"    [*] Searching for property management companies...")
        sources_checked.append("Property Management Search")
        
        for loc in unique_locations:
            pm_results = search_property_management(loc["address"])
            if pm_results.get("success") and pm_results.get("property_managers"):
                loc["property_managers"] = pm_results["property_managers"]
                
                # Search Shodan for each property manager if API key provided
                if api_key:
                    for pm in loc["property_managers"][:3]:  # Limit to 3
                        pm_name = pm.get("name", "")
                        if pm_name and len(pm_name) > 5:
                            # Extract company name (first few words)
                            pm_search_name = " ".join(pm_name.split()[:3])
                            shodan_results = search_shodan_by_org(api_key, pm_search_name)
                            if shodan_results.get("total", 0) > 0:
                                loc["property_manager_shodan"].append({
                                    "property_manager": pm_search_name,
                                    "shodan_total": shodan_results["total"],
                                    "shodan_matches": shodan_results["matches"][:10]
                                })
    
    # Also search Shodan directly for the company name
    company_shodan_results = None
    if api_key:
        print(f"    [*] Searching Shodan for {company_name}...")
        sources_checked.append("Shodan Org Search")
        company_shodan = search_shodan_by_org(api_key, company_name)
        if company_shodan.get("total", 0) > 0:
            company_shodan_results = {
                "total": company_shodan["total"],
                "matches": company_shodan["matches"][:20]
            }
            print(f"    [+] Found {company_shodan['total']} Shodan results for {company_name}")
    
    return {
        "success": True,
        "company_name": company_name,
        "locations_found": len(unique_locations),
        "locations": unique_locations,
        "company_shodan_results": company_shodan_results,
        "sources_checked": sources_checked
    }


def query_opencorporates(company_name: str, jurisdiction: str = None, 
                          timeout: float = 10.0) -> dict:
    """
    Query OpenCorporates API for business registration information.
    
    Args:
        company_name: Company name to search
        jurisdiction: Optional jurisdiction code (e.g., 'us_ca' for California)
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary containing company registration results
    """
    if not REQUESTS_AVAILABLE:
        return {"success": False, "error": "requests module not available"}
    
    try:
        # OpenCorporates API (free tier, no key required for basic searches)
        base_url = "https://api.opencorporates.com/v0.4/companies/search"
        params = {
            "q": company_name,
            "format": "json",
        }
        if jurisdiction:
            params["jurisdiction_code"] = jurisdiction
        
        response = requests.get(base_url, params=params, timeout=timeout)
        
        if response.status_code != 200:
            return {"success": False, "error": f"HTTP {response.status_code}"}
        
        data = response.json()
        results = data.get("results", {})
        companies = results.get("companies", [])
        
        # Extract relevant info from top matches
        matches = []
        for company_data in companies[:10]:
            company = company_data.get("company", {})
            matches.append({
                "name": company.get("name"),
                "company_number": company.get("company_number"),
                "jurisdiction": company.get("jurisdiction_code"),
                "status": company.get("current_status"),
                "incorporation_date": company.get("incorporation_date"),
                "company_type": company.get("company_type"),
                "registered_address": company.get("registered_address_in_full"),
                "opencorporates_url": company.get("opencorporates_url"),
            })
        
        return {
            "success": True,
            "total_results": results.get("total_count", 0),
            "companies": matches,
        }
    
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def calculate_address_similarity(addr1: str, addr2: str) -> float:
    """
    Calculate similarity score between two addresses.
    
    Args:
        addr1: First address string
        addr2: Second address string
        
    Returns:
        Similarity score between 0.0 and 1.0
    """
    if not addr1 or not addr2:
        return 0.0
    
    # Normalize addresses
    addr1 = addr1.lower().strip()
    addr2 = addr2.lower().strip()
    
    # Remove common abbreviations and normalize
    replacements = [
        ("street", "st"), ("avenue", "ave"), ("boulevard", "blvd"),
        ("drive", "dr"), ("road", "rd"), ("lane", "ln"),
        ("court", "ct"), ("place", "pl"), ("suite", "ste"),
        ("floor", "fl"), ("building", "bldg"), (",", " "),
        (".", " "), ("  ", " ")
    ]
    
    for old, new in replacements:
        addr1 = addr1.replace(old, new)
        addr2 = addr2.replace(old, new)
    
    # Extract components
    words1 = set(addr1.split())
    words2 = set(addr2.split())
    
    if not words1 or not words2:
        return 0.0
    
    # Calculate Jaccard similarity
    intersection = words1 & words2
    union = words1 | words2
    
    return len(intersection) / len(union)


def analyze_and_correlate(query_address: str, resolved_address: str,
                          matches: list, org_summary: dict, cert_summary: dict,
                          do_business_lookup: bool = True,
                          progress_callback=None) -> dict:
    """
    Analyze collected results and create confidence-scored associations.
    
    Args:
        query_address: Original query address
        resolved_address: Geocoded/resolved address
        matches: Enriched Shodan match results
        org_summary: Organization summary from WHOIS
        cert_summary: Certificate summary from TLS analysis
        do_business_lookup: Whether to perform business registration lookups
        progress_callback: Optional progress callback
        
    Returns:
        Dictionary containing analysis results with confidence scores
    """
    analysis = {
        "location": {
            "query_address": query_address,
            "resolved_address": resolved_address,
        },
        "ip_inventory": [],
        "organizations_identified": {},
        "potential_building_management": [],
        "potential_tenants": [],
        "business_registrations": {},
        "confidence_matrix": [],
        "summary_statistics": {},
    }
    
    # Build comprehensive IP inventory
    ip_details = {}
    org_indicators = defaultdict(lambda: {
        "sources": [],
        "ips": set(),
        "hostnames": set(),
        "addresses": set(),
        "emails": set(),
        "cert_domains": set(),
        "evidence_count": 0,
    })
    
    for match in matches:
        ip = match.get("ip_str")
        port = match.get("port")
        
        ip_entry = {
            "ip": ip,
            "port": port,
            "organization_shodan": match.get("org"),
            "isp": match.get("isp"),
            "asn": match.get("asn"),
            "hostnames": match.get("hostnames", []),
            "domains": match.get("domains", []),
        }
        
        # Add reverse DNS
        rdns = match.get("reverse_dns", {})
        if rdns.get("success"):
            ip_entry["reverse_dns"] = rdns.get("hostname")
            ip_entry["dns_aliases"] = rdns.get("aliases", [])
        
        # Add WHOIS/RDAP registration
        reg = match.get("registration", {})
        if reg:
            registrant = reg.get("registrant", {}) or {}
            ip_entry["registration"] = {
                "asn": reg.get("asn"),
                "asn_description": reg.get("asn_description"),
                "network_name": reg.get("network_name"),
                "network_cidr": reg.get("network_cidr"),
                "registrant_org": registrant.get("organization"),
                "registrant_address": registrant.get("address"),
                "registrant_email": registrant.get("email"),
                "source": reg.get("source"),
            }
            
            # Track organization indicators
            org_name = registrant.get("organization") or reg.get("asn_description") or reg.get("network_name")
            if org_name:
                org_indicators[org_name]["sources"].append("RDAP/WHOIS")
                org_indicators[org_name]["ips"].add(ip)
                org_indicators[org_name]["evidence_count"] += 1
                if registrant.get("address"):
                    org_indicators[org_name]["addresses"].add(registrant["address"])
                if registrant.get("email"):
                    org_indicators[org_name]["emails"].add(registrant["email"])
        
        # Add TLS certificate info
        cert = match.get("tls_certificate", {})
        if cert.get("success"):
            subject = cert.get("subject", {})
            ip_entry["tls_certificate"] = {
                "common_name": subject.get("common_name"),
                "organization": subject.get("organization"),
                "email": subject.get("email"),
                "san_dns_names": cert.get("san_dns_names", []),
                "issuer": cert.get("issuer", {}).get("organization"),
                "valid_until": cert.get("not_after"),
            }
            
            # Track organization from certificate
            cert_org = subject.get("organization")
            if cert_org:
                org_indicators[cert_org]["sources"].append("TLS Certificate")
                org_indicators[cert_org]["ips"].add(ip)
                org_indicators[cert_org]["evidence_count"] += 1
                if subject.get("email"):
                    org_indicators[cert_org]["emails"].add(subject["email"])
                for dns in cert.get("san_dns_names", []):
                    org_indicators[cert_org]["cert_domains"].add(dns)
        
        # Track Shodan org
        shodan_org = match.get("org")
        if shodan_org:
            org_indicators[shodan_org]["sources"].append("Shodan")
            org_indicators[shodan_org]["ips"].add(ip)
            org_indicators[shodan_org]["evidence_count"] += 1
        
        # Add hostnames
        for hostname in match.get("hostnames", []):
            if hostname:
                for org_name in org_indicators:
                    if org_name.lower().replace(" ", "") in hostname.lower().replace(".", ""):
                        org_indicators[org_name]["hostnames"].add(hostname)
        
        ip_details[f"{ip}:{port}"] = ip_entry
    
    analysis["ip_inventory"] = list(ip_details.values())
    
    # Process organizations and calculate confidence scores
    all_orgs = []
    
    for org_name, indicators in org_indicators.items():
        # Calculate confidence score
        confidence = 0.0
        confidence_factors = []
        
        # Factor 1: Number of evidence sources (max 30%)
        source_types = set(indicators["sources"])
        source_score = min(len(source_types) * 10, 30)
        confidence += source_score
        confidence_factors.append(f"Data sources ({len(source_types)}): +{source_score}%")
        
        # Factor 2: Number of IPs associated (max 20%)
        ip_count = len(indicators["ips"])
        ip_score = min(ip_count * 5, 20)
        confidence += ip_score
        confidence_factors.append(f"Associated IPs ({ip_count}): +{ip_score}%")
        
        # Factor 3: Address match with query location (max 30%)
        address_score = 0
        best_addr_match = 0
        for addr in indicators["addresses"]:
            similarity = calculate_address_similarity(resolved_address, addr)
            if similarity > best_addr_match:
                best_addr_match = similarity
        address_score = int(best_addr_match * 30)
        confidence += address_score
        if address_score > 0:
            confidence_factors.append(f"Address match ({best_addr_match:.0%}): +{address_score}%")
        
        # Factor 4: Has contact information (max 10%)
        if indicators["emails"]:
            confidence += 10
            confidence_factors.append("Has email contacts: +10%")
        
        # Factor 5: Domain/hostname presence (max 10%)
        if indicators["cert_domains"] or indicators["hostnames"]:
            confidence += 10
            confidence_factors.append("Has domains/hostnames: +10%")
        
        org_entry = {
            "name": org_name,
            "confidence_score": min(confidence, 100),
            "confidence_factors": confidence_factors,
            "ip_count": ip_count,
            "ips": list(indicators["ips"]),
            "data_sources": list(source_types),
            "hostnames": list(indicators["hostnames"]),
            "domains": list(indicators["cert_domains"]),
            "addresses": list(indicators["addresses"]),
            "emails": list(indicators["emails"]),
            "evidence_count": indicators["evidence_count"],
        }
        
        all_orgs.append(org_entry)
    
    # Sort by confidence score
    all_orgs.sort(key=lambda x: x["confidence_score"], reverse=True)
    analysis["organizations_identified"] = {org["name"]: org for org in all_orgs}
    
    # Perform business registration lookups for top organizations
    if do_business_lookup and all_orgs:
        if progress_callback:
            progress_callback(0, len(all_orgs[:5]), "Starting business lookups...")
        
        for idx, org in enumerate(all_orgs[:5]):  # Top 5 orgs
            org_name = org["name"]
            if progress_callback:
                progress_callback(idx + 1, min(5, len(all_orgs)), org_name)
            
            biz_results = query_opencorporates(org_name)
            analysis["business_registrations"][org_name] = biz_results
            
            # Update confidence if business registration found with matching address
            if biz_results.get("success") and biz_results.get("companies"):
                for company in biz_results["companies"]:
                    reg_addr = company.get("registered_address")
                    if reg_addr:
                        addr_sim = calculate_address_similarity(resolved_address, reg_addr)
                        if addr_sim > 0.3:
                            # Boost confidence
                            org["confidence_score"] = min(org["confidence_score"] + 15, 100)
                            org["confidence_factors"].append(
                                f"Business registration match ({addr_sim:.0%}): +15%"
                            )
                            org["business_registration"] = {
                                "name": company.get("name"),
                                "address": reg_addr,
                                "status": company.get("status"),
                                "jurisdiction": company.get("jurisdiction"),
                            }
                            break
    
    # Categorize as building management vs tenants
    # Building management indicators: "management", "property", "realty", "building", "facilities"
    bldg_mgmt_keywords = ["management", "property", "realty", "building", "facilities", 
                          "maintenance", "estate", "bms", "hvac", "controls"]
    
    for org in all_orgs:
        org_lower = org["name"].lower()
        is_bldg_mgmt = any(kw in org_lower for kw in bldg_mgmt_keywords)
        
        # Also check if they have BAS/BMS-related ports
        bas_ports = {47808, 502, 1911, 4911}
        has_bas_ports = False
        for ip_entry in analysis["ip_inventory"]:
            if ip_entry["ip"] in org["ips"] and ip_entry.get("port") in bas_ports:
                has_bas_ports = True
                break
        
        if is_bldg_mgmt or has_bas_ports:
            analysis["potential_building_management"].append({
                "organization": org["name"],
                "confidence": org["confidence_score"],
                "indicators": ["BAS/BMS ports detected"] if has_bas_ports else ["Name suggests building management"],
            })
        else:
            analysis["potential_tenants"].append({
                "organization": org["name"],
                "confidence": org["confidence_score"],
            })
    
    # Generate confidence matrix
    for org in all_orgs[:10]:
        analysis["confidence_matrix"].append({
            "organization": org["name"],
            "confidence_score": org["confidence_score"],
            "ip_count": org["ip_count"],
            "data_sources": len(org["data_sources"]),
            "has_address_match": any(
                calculate_address_similarity(resolved_address, addr) > 0.2 
                for addr in org["addresses"]
            ),
            "has_business_registration": org["name"] in analysis["business_registrations"],
        })
    
    # Summary statistics
    analysis["summary_statistics"] = {
        "total_ips_discovered": len(ip_details),
        "unique_organizations": len(all_orgs),
        "high_confidence_orgs": len([o for o in all_orgs if o["confidence_score"] >= 70]),
        "medium_confidence_orgs": len([o for o in all_orgs if 40 <= o["confidence_score"] < 70]),
        "low_confidence_orgs": len([o for o in all_orgs if o["confidence_score"] < 40]),
        "potential_building_managers": len(analysis["potential_building_management"]),
        "potential_tenants": len(analysis["potential_tenants"]),
        "business_registrations_found": sum(
            1 for r in analysis["business_registrations"].values() 
            if r.get("success") and r.get("companies")
        ),
    }
    
    return analysis


def extract_entity(whois_data: dict, role: str) -> dict | None:
    """
    Extract entity information from WHOIS data by role.
    
    Args:
        whois_data: Full WHOIS lookup results
        role: Entity role to extract (registrant, administrative, technical, abuse)
        
    Returns:
        Dictionary with entity details or None
    """
    objects = whois_data.get("objects", {})
    
    for obj_key, obj_data in objects.items():
        roles = obj_data.get("roles", [])
        if role in roles:
            contact = obj_data.get("contact", {})
            return {
                "name": contact.get("name"),
                "email": contact.get("email", [{}])[0].get("value") if contact.get("email") else None,
                "phone": contact.get("phone", [{}])[0].get("value") if contact.get("phone") else None,
                "address": contact.get("address", [{}])[0].get("value") if contact.get("address") else None,
                "organization": obj_data.get("name"),
            }
    return None


def enrich_results(matches: list, do_whois: bool = True, do_rdns: bool = True, 
                   progress_callback=None) -> tuple[list, dict]:
    """
    Enrich Shodan results with RDAP/WHOIS data and reverse DNS.
    
    Args:
        matches: List of Shodan match results
        do_whois: Whether to perform RDAP/WHOIS lookups
        do_rdns: Whether to perform reverse DNS lookups
        progress_callback: Optional callback function for progress updates
        
    Returns:
        Tuple of (enriched matches list, organization summary dict)
    """
    # Cache lookups to avoid duplicate queries
    reg_cache = {}
    rdns_cache = {}
    org_summary = defaultdict(lambda: {"count": 0, "ips": [], "hostnames": [], "details": None})
    rdap_count = 0
    whois_count = 0
    rdns_success = 0
    
    total = len(matches)
    for idx, match in enumerate(matches):
        ip = match.get("ip_str")
        
        if progress_callback:
            progress_callback(idx + 1, total, ip)
        
        # Reverse DNS lookup
        if do_rdns:
            if ip in rdns_cache:
                match["reverse_dns"] = rdns_cache[ip]
            else:
                rdns_data = reverse_dns_lookup(ip)
                rdns_cache[ip] = rdns_data
                match["reverse_dns"] = rdns_data
                if rdns_data.get("success"):
                    rdns_success += 1
        
        # RDAP/WHOIS lookup
        if do_whois and IPWHOIS_AVAILABLE:
            if ip in reg_cache:
                match["registration"] = reg_cache[ip]
            else:
                reg_data = lookup_ip_registration(ip)
                reg_cache[ip] = reg_data
                match["registration"] = reg_data
                
                # Track lookup source
                if reg_data:
                    if reg_data.get("source") == "RDAP":
                        rdap_count += 1
                    else:
                        whois_count += 1
        
        # Build organization summary
        reg = match.get("registration")
        if reg:
            org_name = (reg.get("registrant", {}) or {}).get("organization") or \
                       reg.get("asn_description") or \
                       reg.get("network_name") or "Unknown"
            
            org_summary[org_name]["count"] += 1
            org_summary[org_name]["ips"].append(ip)
            
            # Add hostname to org summary
            rdns = match.get("reverse_dns", {})
            if rdns.get("hostname"):
                org_summary[org_name]["hostnames"].append(rdns["hostname"])
            
            if not org_summary[org_name]["details"]:
                org_summary[org_name]["details"] = reg
    
    # Report lookup stats
    if do_rdns:
        print(f"    Reverse DNS: {rdns_success}/{len(rdns_cache)} resolved")
    if do_whois and IPWHOIS_AVAILABLE:
        print(f"    RDAP lookups: {rdap_count}, WHOIS fallbacks: {whois_count}")
    elif do_whois and not IPWHOIS_AVAILABLE:
        print("    Warning: ipwhois module not available. Install with: pip install ipwhois")
    
    return matches, dict(org_summary)


def save_results(data: dict, filename: str) -> str:
    """
    Save results to a JSON file.
    
    Args:
        data: Results dictionary to save
        filename: Output filename
        
    Returns:
        Path to saved file
    """
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)
    return filename


def run_location_scan(api_key: str, address: str, display_name: str, lat: float, lon: float,
                      radius_km: int, bas_bms_only: bool, do_rdns: bool, do_whois: bool,
                      do_tls: bool, do_crtsh: bool, securitytrails_key: str,
                      do_analysis: bool, do_business_lookup: bool,
                      property_managers: list = None, 
                      property_manager_shodan: list = None) -> dict:
    """
    Run a full PLoc scan for a single location.
    
    Returns:
        Dictionary containing all scan results
    """
    results_data = {
        "address": address,
        "resolved_address": display_name,
        "latitude": lat,
        "longitude": lon,
        "radius_km": radius_km,
        "property_managers": property_managers or [],
        "property_manager_shodan": property_manager_shodan or [],
    }
    
    # Show property manager info if available
    if property_managers:
        print(f"[*] Property managers identified: {len(property_managers)}")
        for pm in property_managers[:3]:
            print(f"    • {pm.get('name', 'Unknown')[:50]}...")
    
    if property_manager_shodan:
        print(f"[*] Property manager Shodan results included: {len(property_manager_shodan)} orgs")
        total_pm_hosts = sum(pm.get("shodan_total", 0) for pm in property_manager_shodan)
        print(f"    Total hosts from property managers: {total_pm_hosts}")
    
    # Search Shodan
    filter_msg = " for BAS/BMS devices" if bas_bms_only else ""
    print(f"[*] Searching Shodan within {radius_km}km radius{filter_msg}...")
    results = search_shodan_by_geo(api_key, lat, lon, radius_km, bas_bms_only)
    
    if not results["success"]:
        print(f"Error: Shodan search failed - {results.get('error', 'Unknown error')}")
        results_data["error"] = results.get("error")
        results_data["total_results"] = 0
        return results_data
    
    print(f"[+] Found {results['total']} results")
    results_data["total_results"] = results["total"]
    results_data["matches_returned"] = len(results["matches"])
    
    if not results["matches"]:
        return results_data
    
    # Perform enrichment lookups if requested
    org_summary = {}
    if (do_whois or do_rdns) and results["matches"]:
        print()
        lookups = []
        if do_rdns:
            lookups.append("reverse DNS")
        if do_whois:
            lookups.append("RDAP/WHOIS")
        print(f"[*] Performing {' and '.join(lookups)} lookups...")
        
        def progress(current, total, ip):
            print(f"    [{current}/{total}] Looking up {ip}...".ljust(60), end='\r')
        
        results["matches"], org_summary = enrich_results(
            results["matches"], 
            do_whois=do_whois, 
            do_rdns=do_rdns, 
            progress_callback=progress
        )
        print()
        if org_summary:
            print(f"[+] Enrichment complete - identified {len(org_summary)} organizations")
    
    results_data["organization_summary"] = org_summary
    
    # Perform TLS certificate analysis if requested
    cert_summary = {}
    if do_tls and results["matches"]:
        print()
        print("[*] Analyzing TLS certificates...")
        
        def tls_progress(current, total, target):
            print(f"    [{current}/{total}] Analyzing {target}...".ljust(60), end='\r')
        
        results["matches"], cert_summary = analyze_tls_for_matches(
            results["matches"],
            do_crtsh=do_crtsh,
            securitytrails_key=securitytrails_key,
            progress_callback=tls_progress
        )
        print()
        print(f"[+] TLS analysis complete - {cert_summary.get('certificates_retrieved', 0)}/{cert_summary.get('total_tls_services', 0)} certificates retrieved")
    
    results_data["certificate_summary"] = cert_summary
    
    # Perform correlation analysis if requested
    correlation_analysis = {}
    if do_analysis and results["matches"]:
        print()
        print("[*] Performing correlation analysis...")
        
        def analysis_progress(current, total, item):
            print(f"    [{current}/{total}] Analyzing {item}...".ljust(60), end='\r')
        
        correlation_analysis = analyze_and_correlate(
            query_address=address,
            resolved_address=display_name,
            matches=results["matches"],
            org_summary=org_summary,
            cert_summary=cert_summary,
            do_business_lookup=do_business_lookup,
            progress_callback=analysis_progress if do_business_lookup else None
        )
        print()
        stats = correlation_analysis.get("summary_statistics", {})
        print(f"[+] Analysis complete - {stats.get('unique_organizations', 0)} organizations identified")
    
    results_data["correlation_analysis"] = correlation_analysis
    results_data["results"] = results["matches"]
    
    return results_data


def main():
    """Main entry point for PLoc scanner."""
    print("=" * 60)
    print("PLoc - Physical Location to Shodan Scanner")
    print("=" * 60)
    print()
    
    # Prompt for Shodan API key (hidden input)
    api_key = getpass("Enter your Shodan API key: ").strip()
    if not api_key:
        print("Error: Shodan API key is required.")
        sys.exit(1)
    
    # Validate API key
    try:
        api = shodan.Shodan(api_key)
        api_info = api.info()
        print(f"[+] API key validated. Query credits remaining: {api_info.get('query_credits', 'N/A')}")
    except shodan.APIError as e:
        print(f"Error: Invalid Shodan API key - {e}")
        sys.exit(1)
    
    print()
    
    # Ask for search mode
    print("Search modes:")
    print("  1. Single address")
    print("  2. Company name (lookup all locations)")
    mode = input("Select mode [1]: ").strip() or "1"
    
    addresses_to_scan = []
    company_name = None
    
    if mode == "2":
        # Company lookup mode
        company_name = input("Enter company name: ").strip()
        if not company_name:
            print("Error: Company name is required.")
            sys.exit(1)
        
        # Ask about property management lookups
        pm_input = input("Search for building/property management companies? (Y/n): ").strip().lower()
        include_property_mgmt = pm_input not in ('n', 'no')
        
        print()
        print(f"[*] Searching for {company_name} locations...")
        
        location_results = search_company_locations(
            company_name, 
            api_key=api_key,
            include_property_mgmt=include_property_mgmt
        )
        
        if not location_results.get("success"):
            print(f"Error: {location_results.get('error', 'Failed to search for company')}")
            sys.exit(1)
        
        locations = location_results.get("locations", [])
        
        # Show direct Shodan results for the company
        company_shodan = location_results.get("company_shodan_results")
        if company_shodan:
            print(f"\n[+] Direct Shodan results for '{company_name}': {company_shodan['total']} hosts")
            for m in company_shodan.get("matches", [])[:5]:
                ip = m.get("ip_str")
                port = m.get("port")
                org = m.get("org", "")
                city = m.get("location", {}).get("city", "")
                print(f"    • {ip}:{port} | {org} | {city}")
        
        if not locations:
            print(f"[!] No registered locations found in business registries.")
            # Allow manual entry of multiple addresses
            manual = input("Enter addresses manually? (y/N): ").strip().lower()
            if manual in ('y', 'yes'):
                print("Enter addresses one per line (blank line to finish):")
                while True:
                    address = input("  Address: ").strip()
                    if not address:
                        break
                    addresses_to_scan.append({
                        "address": address,
                        "source": "Manual Entry",
                        "company_name": company_name
                    })
                    print(f"    Added: {address[:50]}...")
        else:
            print(f"\n[+] Found {len(locations)} location(s) for {company_name}:")
            for i, loc in enumerate(locations):
                addr = loc.get("address", "").replace("\n", ", ")[:70]
                source = loc.get("source", "Unknown")
                print(f"    {i+1}. {addr}... [{source}]")
                
                # Show property managers if found
                pm_list = loc.get("property_managers", [])
                pm_shodan = loc.get("property_manager_shodan", [])
                
                if pm_list:
                    print(f"       Property Managers Found: {len(pm_list)}")
                    for pm in pm_list[:2]:
                        pm_name = pm.get("name", "")[:50]
                        print(f"         • {pm_name}...")
                
                if pm_shodan:
                    print(f"       Property Manager Shodan Results:")
                    for pm_s in pm_shodan:
                        pm_name = pm_s.get("property_manager", "Unknown")
                        pm_total = pm_s.get("shodan_total", 0)
                        print(f"         • {pm_name}: {pm_total} hosts found")
            
            print()
            selection = input(f"Scan all locations? (Y/n) or enter numbers (e.g., 1,3): ").strip()
            
            if selection.lower() == 'n':
                print("Scan cancelled.")
                sys.exit(0)
            elif selection and selection[0].isdigit():
                # Parse selected indices
                indices = [int(x.strip()) - 1 for x in selection.split(",") if x.strip().isdigit()]
                for idx in indices:
                    if 0 <= idx < len(locations):
                        addresses_to_scan.append(locations[idx])
            else:
                # Scan all
                addresses_to_scan = locations
        
        if not addresses_to_scan:
            print("No locations to scan.")
            sys.exit(0)
            
        print(f"\n[+] Will scan {len(addresses_to_scan)} location(s)")
    else:
        # Single address mode
        address = input("Enter physical address to search: ").strip()
        if not address:
            print("Error: Address is required.")
            sys.exit(1)
        addresses_to_scan.append({"address": address, "source": "Direct Input"})
    
    # Prompt for search radius
    radius_input = input("Enter search radius in km (default: 10): ").strip()
    try:
        radius_km = int(radius_input) if radius_input else 10
        if radius_km <= 0 or radius_km > 1000:
            print("Warning: Radius should be between 1-1000km. Using default of 10km.")
            radius_km = 10
    except ValueError:
        print("Warning: Invalid radius. Using default of 10km.")
        radius_km = 10
    
    # Prompt for BAS/BMS filter option
    bas_input = input("Filter for BAS/BMS devices only? (y/N): ").strip().lower()
    bas_bms_only = bas_input in ('y', 'yes')
    
    if bas_bms_only:
        print("[*] BAS/BMS filter enabled - searching for building automation systems")
    
    # Prompt for reverse DNS lookups
    rdns_input = input("Perform reverse DNS lookups? (y/N): ").strip().lower()
    do_rdns = rdns_input in ('y', 'yes')
    
    # Prompt for WHOIS enrichment
    if IPWHOIS_AVAILABLE:
        whois_input = input("Perform RDAP/WHOIS lookups for registrant/tenant info? (y/N): ").strip().lower()
        do_whois = whois_input in ('y', 'yes')
    else:
        print("[!] RDAP/WHOIS lookups unavailable - install ipwhois: pip install ipwhois")
        do_whois = False
    
    # Prompt for TLS certificate analysis
    tls_input = input("Analyze TLS certificates for HTTPS services? (y/N): ").strip().lower()
    do_tls = tls_input in ('y', 'yes')
    
    do_crtsh = False
    securitytrails_key = None
    
    if do_tls:
        crtsh_input = input("Query crt.sh certificate transparency logs? (y/N): ").strip().lower()
        do_crtsh = crtsh_input in ('y', 'yes')
        
        st_input = input("Query SecurityTrails? (requires API key) (y/N): ").strip().lower()
        if st_input in ('y', 'yes'):
            securitytrails_key = getpass("Enter SecurityTrails API key: ").strip()
            if not securitytrails_key:
                print("[!] No API key provided, skipping SecurityTrails")
                securitytrails_key = None
    
    # Prompt for correlation analysis
    analysis_input = input("Perform correlation analysis with confidence scoring? (y/N): ").strip().lower()
    do_analysis = analysis_input in ('y', 'yes')
    
    do_business_lookup = False
    if do_analysis:
        biz_input = input("Include business registration lookups (OpenCorporates)? (y/N): ").strip().lower()
        do_business_lookup = biz_input in ('y', 'yes')
    
    # Process each location
    all_location_results = []
    
    for loc_idx, loc_info in enumerate(addresses_to_scan):
        address = loc_info.get("address", "")
        loc_source = loc_info.get("source", "Unknown")
        loc_company = loc_info.get("company_name", company_name or "")
        
        if len(addresses_to_scan) > 1:
            print()
            print("=" * 60)
            print(f"LOCATION {loc_idx + 1} of {len(addresses_to_scan)}")
            print("=" * 60)
        
        print()
        print(f"[*] Geocoding address: {address[:60]}...")
        
        # Convert address to coordinates
        coords = get_coordinates(address)
        if not coords:
            print(f"[!] Could not geocode address - skipping")
            all_location_results.append({
                "address": address,
                "source": loc_source,
                "company": loc_company,
                "error": "Could not geocode address"
            })
            continue
        
        lat, lon, display_name = coords
        print(f"[+] Resolved to: {display_name}")
        print(f"[+] Coordinates: {lat}, {lon}")
        print()
        
        # Run the full scan for this location
        location_result = run_location_scan(
            api_key=api_key,
            address=address,
            display_name=display_name,
            lat=lat,
            lon=lon,
            radius_km=radius_km,
            bas_bms_only=bas_bms_only,
            do_rdns=do_rdns,
            do_whois=do_whois,
            do_tls=do_tls,
            do_crtsh=do_crtsh,
            securitytrails_key=securitytrails_key,
            do_analysis=do_analysis,
            do_business_lookup=do_business_lookup,
            property_managers=loc_info.get("property_managers"),
            property_manager_shodan=loc_info.get("property_manager_shodan")
        )
        
        location_result["source"] = loc_source
        location_result["company"] = loc_company
        all_location_results.append(location_result)
    
    # Use the last location's data for backward compatibility with single-address output
    # Or aggregate for multi-location
    if len(all_location_results) == 1:
        results = {"matches": all_location_results[0].get("results", [])}
        org_summary = all_location_results[0].get("organization_summary", {})
        cert_summary = all_location_results[0].get("certificate_summary", {})
        correlation_analysis = all_location_results[0].get("correlation_analysis", {})
        address = all_location_results[0].get("address", "")
        display_name = all_location_results[0].get("resolved_address", "")
        lat = all_location_results[0].get("latitude", 0)
        lon = all_location_results[0].get("longitude", 0)
    else:
        # Multi-location mode - aggregate results
        results = {"matches": []}
        org_summary = {}
        cert_summary = {}
        correlation_analysis = {}
        
        for loc_result in all_location_results:
            results["matches"].extend(loc_result.get("results", []))
        
        # Use first valid location for display
        for loc_result in all_location_results:
            if loc_result.get("resolved_address"):
                address = loc_result.get("address", "")
                display_name = loc_result.get("resolved_address", "")
                lat = loc_result.get("latitude", 0)
                lon = loc_result.get("longitude", 0)
                break
        print()  # Clear progress line
        stats = correlation_analysis.get("summary_statistics", {})
        print(f"[+] Analysis complete - {stats.get('unique_organizations', 0)} organizations identified")
        print(f"    High confidence: {stats.get('high_confidence_orgs', 0)}, " +
              f"Medium: {stats.get('medium_confidence_orgs', 0)}, " +
              f"Low: {stats.get('low_confidence_orgs', 0)}")
    
    # Prepare output data
    timestamp = datetime.now().isoformat()
    output_data = {
        "query": {
            "address": address,
            "resolved_address": display_name,
            "latitude": lat,
            "longitude": lon,
            "radius_km": radius_km,
            "bas_bms_filter": bas_bms_only,
            "reverse_dns_lookup": do_rdns,
            "rdap_whois_lookup": do_whois,
            "tls_analysis": do_tls,
            "crtsh_lookup": do_crtsh,
            "securitytrails_lookup": bool(securitytrails_key),
            "correlation_analysis": do_analysis,
            "business_lookup": do_business_lookup,
            "shodan_query": results.get("query", "")
        },
        "timestamp": timestamp,
        "total_results": results["total"],
        "organization_summary": org_summary,
        "certificate_summary": cert_summary,
        "correlation_analysis": correlation_analysis,
        "results": results["matches"]
    }
    
    # Generate output filename
    safe_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"shodan_results_{safe_timestamp}.json"
    
    # Save results
    saved_path = save_results(output_data, output_file)
    print(f"[+] Results saved to: {saved_path}")
    
    # Print summary of findings
    if results["matches"]:
        print()
        print("=" * 60)
        print("SUMMARY OF FINDINGS")
        print("=" * 60)
        
        # Count by Shodan organization field
        orgs = {}
        ports = {}
        
        for match in results["matches"]:
            org = match.get("org", "Unknown")
            orgs[org] = orgs.get(org, 0) + 1
            
            port = match.get("port", "Unknown")
            ports[port] = ports.get(port, 0) + 1
        
        print("\nTop Organizations (Shodan):")
        for org, count in sorted(orgs.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  - {org}: {count}")
        
        print("\nTop Ports:")
        for port, count in sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  - {port}: {count}")
        
        # Print RDAP/WHOIS organization summary if available
        if org_summary:
            print("\n" + "=" * 60)
            print("REGISTRANT/TENANT SUMMARY")
            print("=" * 60)
            
            sorted_orgs = sorted(org_summary.items(), key=lambda x: x[1]["count"], reverse=True)
            
            for org_name, data in sorted_orgs[:15]:
                print(f"\n  {org_name}")
                print(f"    Devices: {data['count']}")
                
                # Show hostnames if available
                hostnames = data.get("hostnames", [])
                if hostnames:
                    unique_hostnames = list(set(hostnames))[:5]
                    print(f"    Hostnames: {', '.join(unique_hostnames)}")
                    if len(set(hostnames)) > 5:
                        print(f"               ... and {len(set(hostnames)) - 5} more")
                
                if data["details"]:
                    details = data["details"]
                    source = details.get("source", "Unknown")
                    if details.get("asn"):
                        print(f"    ASN: {details['asn']} ({details.get('asn_country_code', 'N/A')}) [{source}]")
                    if details.get("network_cidr"):
                        print(f"    Network: {details['network_cidr']}")
                    
                    registrant = details.get("registrant") or {}
                    if registrant.get("address"):
                        addr = registrant["address"].replace('\n', ', ')[:80]
                        print(f"    Address: {addr}")
                    if registrant.get("email"):
                        print(f"    Contact: {registrant['email']}")
        
        # Print TLS certificate summary if available
        if cert_summary:
            print("\n" + "=" * 60)
            print("TLS CERTIFICATE SUMMARY")
            print("=" * 60)
            
            print(f"\n  TLS Services Found: {cert_summary.get('total_tls_services', 0)}")
            print(f"  Certificates Retrieved: {cert_summary.get('certificates_retrieved', 0)}")
            
            if cert_summary.get('unique_domains'):
                print(f"\n  Unique Domains in Certificates:")
                for domain in cert_summary['unique_domains'][:10]:
                    print(f"    - {domain}")
                if len(cert_summary['unique_domains']) > 10:
                    print(f"    ... and {len(cert_summary['unique_domains']) - 10} more")
            
            if cert_summary.get('organizations'):
                print(f"\n  Certificate Organizations:")
                sorted_orgs = sorted(cert_summary['organizations'].items(), 
                                    key=lambda x: x[1], reverse=True)
                for org, count in sorted_orgs[:10]:
                    print(f"    - {org}: {count}")
            
            if cert_summary.get('issuers'):
                print(f"\n  Certificate Issuers:")
                sorted_issuers = sorted(cert_summary['issuers'].items(), 
                                       key=lambda x: x[1], reverse=True)
                for issuer, count in sorted_issuers[:10]:
                    print(f"    - {issuer}: {count}")
            
            # Show crt.sh highlights
            if cert_summary.get('crtsh_results'):
                print(f"\n  Certificate Transparency (crt.sh):")
                for domain, crtsh_data in cert_summary['crtsh_results'].items():
                    if crtsh_data.get('success'):
                        total = crtsh_data.get('total', 0)
                        print(f"    - {domain}: {total} certificates logged")
                    else:
                        print(f"    - {domain}: {crtsh_data.get('error', 'Error')}")
            
            # Show SecurityTrails highlights
            if cert_summary.get('securitytrails_results'):
                print(f"\n  SecurityTrails:")
                for domain, st_data in cert_summary['securitytrails_results'].items():
                    if st_data.get('success'):
                        subs = st_data.get('subdomains_count', 'N/A')
                        print(f"    - {domain}: {subs} subdomains")
                    else:
                        print(f"    - {domain}: {st_data.get('error', 'Error')}")
        
        # Print correlation analysis if available
        if correlation_analysis:
            print("\n" + "=" * 60)
            print("CORRELATION ANALYSIS & CONFIDENCE SCORING")
            print("=" * 60)
            
            stats = correlation_analysis.get("summary_statistics", {})
            print(f"\n  Location: {correlation_analysis.get('location', {}).get('resolved_address', 'N/A')}")
            print(f"  Total IPs Discovered: {stats.get('total_ips_discovered', 0)}")
            print(f"  Unique Organizations: {stats.get('unique_organizations', 0)}")
            
            # Confidence breakdown
            print(f"\n  Confidence Distribution:")
            print(f"    High (≥70%):    {stats.get('high_confidence_orgs', 0)}")
            print(f"    Medium (40-69%): {stats.get('medium_confidence_orgs', 0)}")
            print(f"    Low (<40%):      {stats.get('low_confidence_orgs', 0)}")
            
            # Building management
            bldg_mgmt = correlation_analysis.get("potential_building_management", [])
            if bldg_mgmt:
                print(f"\n  Potential Building Management ({len(bldg_mgmt)}):")
                for mgmt in bldg_mgmt[:5]:
                    print(f"    ★ {mgmt['organization']} [{mgmt['confidence']:.0f}% confidence]")
                    for indicator in mgmt.get('indicators', []):
                        print(f"      └─ {indicator}")
            
            # Top tenants
            tenants = correlation_analysis.get("potential_tenants", [])
            if tenants:
                print(f"\n  Potential Tenants ({len(tenants)}):")
                for tenant in tenants[:10]:
                    conf = tenant['confidence']
                    conf_bar = "█" * int(conf / 10) + "░" * (10 - int(conf / 10))
                    print(f"    • {tenant['organization']}")
                    print(f"      [{conf_bar}] {conf:.0f}%")
            
            # Top organizations with details
            orgs = correlation_analysis.get("organizations_identified", {})
            if orgs:
                print(f"\n  Top Organizations by Confidence:")
                sorted_orgs = sorted(orgs.values(), key=lambda x: x.get('confidence_score', 0), reverse=True)
                for org in sorted_orgs[:5]:
                    print(f"\n    {org['name']}")
                    print(f"      Confidence: {org.get('confidence_score', 0):.0f}%")
                    print(f"      IPs: {org.get('ip_count', 0)} | Sources: {', '.join(org.get('data_sources', []))}")
                    
                    if org.get('addresses'):
                        addr = list(org['addresses'])[0][:60]
                        print(f"      Address: {addr}...")
                    
                    if org.get('emails'):
                        print(f"      Contact: {', '.join(list(org['emails'])[:2])}")
                    
                    if org.get('business_registration'):
                        biz = org['business_registration']
                        print(f"      Business Reg: {biz.get('name')} ({biz.get('status', 'N/A')})")
                    
                    # Show confidence factors
                    factors = org.get('confidence_factors', [])
                    if factors:
                        print(f"      Factors: {'; '.join(factors[:3])}")
            
            # Business registrations found
            biz_regs = correlation_analysis.get("business_registrations", {})
            if biz_regs:
                found = [k for k, v in biz_regs.items() if v.get('success') and v.get('companies')]
                if found:
                    print(f"\n  Business Registrations Found ({len(found)}):")
                    for org_name in found[:5]:
                        companies = biz_regs[org_name].get('companies', [])
                        if companies:
                            co = companies[0]
                            print(f"    • {co.get('name', org_name)}")
                            if co.get('registered_address'):
                                print(f"      Address: {co['registered_address'][:60]}...")
                            print(f"      Status: {co.get('status', 'N/A')} | Jurisdiction: {co.get('jurisdiction', 'N/A')}")
            
            # IP inventory summary
            ip_inv = correlation_analysis.get("ip_inventory", [])
            if ip_inv:
                print(f"\n  IP Address Inventory ({len(ip_inv)} entries):")
                for ip_entry in ip_inv[:10]:
                    ip = ip_entry.get('ip')
                    port = ip_entry.get('port')
                    org = ip_entry.get('organization_shodan', 'Unknown')
                    rdns = ip_entry.get('reverse_dns', '')
                    
                    print(f"    {ip}:{port}")
                    print(f"      Org: {org}")
                    if rdns:
                        print(f"      rDNS: {rdns}")
                    
                    reg = ip_entry.get('registration', {})
                    if reg.get('registrant_org'):
                        print(f"      Registrant: {reg['registrant_org']}")
                    
                    cert = ip_entry.get('tls_certificate', {})
                    if cert.get('common_name'):
                        print(f"      TLS CN: {cert['common_name']}")
                
                if len(ip_inv) > 10:
                    print(f"\n    ... and {len(ip_inv) - 10} more (see JSON output)")
    
    print()
    print("[+] Scan complete!")


if __name__ == "__main__":
    main()
