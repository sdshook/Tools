# PLoc - Physical Location to Shodan Scanner
### (c) 2026, Shane D. Shook, PhD

PLoc is a reconnaissance tool that converts a physical address to geographic coordinates and queries the Shodan API to find internet-connected devices near that location.

## Features

- **Address Geocoding**: Converts a physical address to latitude/longitude coordinates using the Nominatim (OpenStreetMap) geocoding service
- **Shodan Integration**: Queries Shodan's API using geographic coordinates to discover nearby devices
- **BAS/BMS Filtering**: Optional filter to search specifically for Building Automation Systems and Building Management Systems
- **Reverse DNS Lookup**: Optional PTR record lookups to resolve IP addresses to hostnames
- **RDAP/WHOIS Cross-Reference**: Optional lookup of IP registrant details to identify property management companies, tenants, and network owners
- **TLS Certificate Analysis**: Extract certificate details (CN, SANs, Organization, emails) from HTTPS services
- **Certificate Transparency**: Query crt.sh for historical certificate issuance
- **SecurityTrails Integration**: Optional domain intelligence lookup (requires API key)
- **Correlation Analysis**: Confidence-scored associations between physical address and organizations
- **Business Registration Lookup**: Query OpenCorporates for company registration details
- **Building Management Detection**: Identify potential building management vs tenant companies
- **JSON Export**: Saves all results to a timestamped JSON file for further analysis

## Requirements

- Python 3.7+
- Shodan API key (get one at https://account.shodan.io/)

## Installation

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install shodan geopy requests ipwhois
```

## Usage

Run the tool and follow the prompts:

```bash
python ploc.py
```

### Search Modes

**Mode 1: Single Address**
- Enter a physical address directly
- Tool geocodes and searches Shodan for that location

**Mode 2: Company Name Lookup**
- Enter a company name (e.g., "Acme Corporation")
- Tool searches OpenCorporates and web for registered addresses
- Identifies building/property management companies at each location
- Searches Shodan for property management company infrastructure
- Scans all discovered locations for exposed systems

### Prompts

1. **Shodan API Key**: Your Shodan API key
2. **Search Mode**: Single address (1) or Company lookup (2)
3. **Company Name** (Mode 2): Company name to search
4. **Property Management Search** (Mode 2): Search for building managers (Y/n)
5. **Physical Address** (Mode 1): The address to search
6. **Search Radius**: Search radius in kilometers (default: 10km)
7. **BAS/BMS Filter**: Filter for building automation systems only
8. **Reverse DNS**: Lookup IP addresses to hostnames
9. **RDAP/WHOIS Lookup**: Cross-reference IPs with registrant data
10. **TLS Analysis**: Certificate analysis for HTTPS services
11. **crt.sh Lookup**: Certificate transparency log queries
12. **SecurityTrails**: Domain intelligence (requires API key)
13. **Correlation Analysis**: Confidence scoring and association analysis
14. **Business Lookup**: OpenCorporates business registration queries

### Company Lookup Example

```
Search modes:
  1. Single address
  2. Company name (lookup all locations)
Select mode [1]: 2

Enter company name: Acme Corporation
Search for building/property management companies? (Y/n): y

[*] Searching for Acme Corporation locations...
    [*] Searching OpenCorporates...
    [*] Searching web for office locations...
    [*] Searching for property management companies...

[+] Found 2 location(s) for Acme Corporation:
    1. 100 Main Street, Suite 500, Anytown, CA... [OpenCorporates]
       Property Managers Found: 1
         • Example Property Management Inc...
       Property Manager Shodan Results:
         • Example Property Management: 1 hosts found
    2. 25 Business Park Road, Suite 200, London... [OpenCorporates]

Scan all locations? (Y/n): y
```

## BAS/BMS Filter

When enabled, the BAS/BMS filter searches for devices matching common building automation fingerprints including:

- **Protocols**: BACnet (port 47808), Modbus (port 502), Niagara Fox (port 1911/4911), LonWorks, KNX
- **Vendors**: Johnson Controls, Honeywell, Siemens, Schneider Electric, Tridium, Carrier, Automated Logic, Delta Controls, Distech, Crestron, Lutron
- **Systems**: HVAC controllers, Building Automation Systems, Metasys, EnergyPlus

## Reverse DNS Lookup

When enabled, performs PTR record lookups to resolve IP addresses to their associated hostnames. This can reveal:

- Server naming conventions (e.g., `hvac-controller-1.building.example.com`)
- Organization domain names
- Service identifiers
- Geographic or functional naming patterns

Hostnames are included in both the per-device results and the organization summary.

## RDAP/WHOIS Cross-Reference

When enabled, the tool performs IP registration lookups to identify organizations associated with discovered devices:

1. **RDAP (Registration Data Access Protocol)** - Tried first; modern RESTful protocol with structured JSON responses
2. **Legacy WHOIS** - Fallback if RDAP fails; traditional text-based protocol

### Information Retrieved

- **Network Registrants**: Organizations that own the IP address blocks
- **Property Management**: Companies managing building network infrastructure  
- **Tenants**: Businesses operating from the location
- **Contact Details**: Administrative, technical, and abuse contact information

### Output Includes

- ASN (Autonomous System Number) and country code
- Network CIDR ranges
- Registrant organization name and address
- Contact email addresses
- Data source indicator (RDAP or WHOIS)

**Note**: Lookups add processing time. Results are cached to avoid duplicate queries for IPs in the same network block.

## TLS Certificate Analysis

When enabled, the tool connects to HTTPS services and extracts certificate information:

### Certificate Details Extracted

- **Subject**: Common Name (CN), Organization, Organizational Unit, Location, Country, Email
- **Issuer**: CA name, Organization, Country
- **SANs**: All Subject Alternative Names (DNS names, email addresses)
- **Validity**: Not Before / Not After dates
- **Serial Number**: Certificate serial number

### crt.sh Integration

Queries Certificate Transparency logs to discover:
- Historical certificates issued for discovered domains
- All subdomains that have had certificates issued
- Certificate issuance timeline
- Issuing Certificate Authorities

### SecurityTrails Integration

Requires a SecurityTrails API key (get one at https://securitytrails.com/). Provides:
- Current DNS records
- Subdomain count
- Historical domain data
- Alexa ranking

## Correlation Analysis & Confidence Scoring

When enabled, the tool performs comprehensive analysis to associate discovered entities with the physical location:

### Confidence Score Calculation

Each organization receives a confidence score (0-100%) based on:

| Factor | Max Points | Description |
|--------|-----------|-------------|
| Data Sources | 30% | Number of sources confirming the org (Shodan, WHOIS, TLS) |
| IP Count | 20% | Number of IPs associated with the organization |
| Address Match | 30% | Similarity between WHOIS address and query location |
| Contact Info | 10% | Presence of email contacts |
| Domains/Hostnames | 10% | Associated domain names or hostnames |
| Business Registration | 15% (bonus) | Matching business registration found |

### Organization Classification

Organizations are classified as:

- **Building Management**: Companies with names containing management/property/facilities keywords, or those operating BAS/BMS protocols
- **Tenants**: Other organizations identified at the location

### Business Registration Lookup

Queries OpenCorporates (free API) for:
- Company registration status
- Registered address (compared against query location)
- Incorporation date
- Jurisdiction

### IP Inventory

Creates a comprehensive inventory of each discovered IP including:
- Shodan organization and ISP
- Reverse DNS hostname
- WHOIS registrant details
- TLS certificate information
- Associated ports and services

## Output

Results are saved to a JSON file named `shodan_results_<timestamp>.json` containing:

- Original query address
- Resolved coordinates (latitude/longitude)
- Search radius used
- Timestamp of the query
- Full Shodan results including discovered hosts

## Example Output Structure

```json
{
    "query": {
        "address": "1600 Pennsylvania Ave, Washington DC",
        "latitude": 38.8976763,
        "longitude": -77.0365298,
        "radius_km": 10
    },
    "timestamp": "2024-01-15T10:30:00",
    "total_results": 150,
    "results": [...]
}
```

## Legal Disclaimer

This tool is intended for authorized security assessments and research purposes only. Users are responsible for ensuring they have proper authorization before scanning any networks or systems. Unauthorized access to computer systems is illegal.

## License

MIT License
