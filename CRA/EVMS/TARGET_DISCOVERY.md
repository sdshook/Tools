# Target Discovery Implementation

## Overview

EVMS now supports comprehensive target discovery for all input types:
- **Domains**: Subfinder → DNS resolution → IPs
- **ASNs**: BGP data → CIDR ranges → IP sampling
- **CIDRs**: Intelligent IP sampling based on network size
- **IPs**: Direct scanning

## ASN Discovery

### Supported ASN Formats
```bash
python evms.py --target AS1234    # Standard format
python evms.py --target as1234    # Lowercase
python evms.py --target 1234      # Plain number (validated as ASN)
```

### ASN → IP Discovery Process

1. **BGP Data Sources** (Multiple fallbacks):
   - **BGPView API**: `https://api.bgpview.io/asn/{asn}/prefixes`
   - **RIPE API**: `https://stat.ripe.net/data/announced-prefixes/data.json`
   - **Whois Command**: Local whois lookup for route/inetnum entries

2. **CIDR Range Extraction**:
   ```
   ASN 1234 → [10.0.0.0/16, 192.168.1.0/24, 203.0.113.0/24]
   ```

3. **Intelligent IP Sampling**:
   - **Small networks** (<1000 IPs): Scan all hosts
   - **Medium networks** (1000-10000 IPs): Sample 500 IPs
   - **Large networks** (>10000 IPs): Sample 1000 IPs

### Example ASN Discovery Flow
```
Input: AS7922 (Comcast)
↓
BGPView API Query
↓
Found Prefixes: [
  "96.120.0.0/16",
  "68.80.0.0/15", 
  "173.160.0.0/11",
  "50.128.0.0/9"
]
↓
IP Sampling (large networks detected)
↓
Sampled IPs: [
  "96.120.0.1", "96.120.0.10", "96.120.255.254",  # Boundaries
  "96.120.1.1", "96.120.10.1", "96.120.100.1",   # Common endings
  "96.120.45.123", "96.120.178.67", ...           # Random samples
]
↓
Port Scanning → Service Discovery → Vulnerability Scanning
```

## CIDR Discovery

### Intelligent Network Handling

```python
# Small networks (/24 and smaller)
192.168.1.0/24 → Scan all 254 hosts

# Medium networks (/22 to /18)  
10.0.0.0/22 → Sample 500 IPs intelligently

# Large networks (/18 and larger)
172.16.0.0/16 → Sample 1000 IPs intelligently
```

### Smart IP Sampling Strategy

1. **Network Boundaries**: Always include first/last IPs
   ```
   10.0.0.1, 10.0.0.2, ..., 10.0.255.253, 10.0.255.254
   ```

2. **Common Server IPs**: Target typical server addresses
   ```
   10.0.0.1    # Gateway
   10.0.0.10   # DNS/DHCP
   10.0.0.100  # Common server range
   10.0.1.1    # Subnet gateways
   10.0.10.1   # VLAN gateways
   ```

3. **Random Sampling**: Fill remaining slots with random IPs

### Example CIDR Discovery Flow
```
Input: 10.0.0.0/16 (65,536 addresses)
↓
Large network detected → Sample 1000 IPs
↓
Sampling Strategy:
- Boundaries: 10.0.0.1, 10.0.0.2, ..., 10.0.255.253, 10.0.255.254
- Common: 10.0.0.1, 10.0.0.10, 10.0.1.1, 10.0.10.1, 10.0.100.1
- Random: 10.0.45.123, 10.0.178.67, 10.0.234.89, ...
↓
Final Sample: 1000 unique IPs
↓
Port Scanning → Service Discovery → Vulnerability Scanning
```

## Domain Discovery

### Subdomain Enumeration
```
Input: example.com
↓
Subfinder Discovery: [
  "www.example.com",
  "api.example.com", 
  "mail.example.com",
  "dev.example.com"
]
↓
DNS Resolution:
  example.com → 192.168.1.1
  www.example.com → 192.168.1.1 (same IP)
  api.example.com → 192.168.1.2
  mail.example.com → 192.168.1.3
  dev.example.com → 192.168.1.4
↓
Unique IPs: [192.168.1.1, 192.168.1.2, 192.168.1.3, 192.168.1.4]
↓
Port Scanning → Service Discovery → Vulnerability Scanning
```

## Complete Scanning Flow

### Universal Flow (All Target Types)
```
1. Target Input → Target Type Detection
2. Target Discovery → IP List
3. Port Scanning (masscan) → Open Ports
4. Service URL Building → Service URLs  
5. Service Fingerprinting (httpx) → Web Technologies
6. Vulnerability Scanning (nuclei) → Vulnerabilities
7. Risk Assessment → Prioritized Results
```

### Target Type Detection
```python
def detect_target_type(target):
    if is_ip_address(target):     return 'ip'
    if is_cidr_range(target):     return 'cidr'  
    if is_asn_format(target):     return 'asn'
    else:                         return 'domain'
```

## Performance Considerations

### ASN Scanning
- **API Rate Limits**: Multiple fallback sources
- **Large ASNs**: Intelligent sampling prevents overwhelming scans
- **Timeout Handling**: 30-second timeouts for API calls

### CIDR Scanning  
- **Memory Usage**: Streaming IP generation for large networks
- **Scan Time**: Sampling reduces scan time from hours to minutes
- **Coverage**: Smart sampling ensures good coverage of likely targets

### Domain Scanning
- **DNS Resolution**: Parallel resolution with error handling
- **Duplicate Removal**: Multiple domains may resolve to same IP
- **Subdomain Limits**: Subfinder naturally limits results

## Usage Examples

### ASN Scanning
```bash
# Scan Cloudflare's ASN
python evms.py --target AS13335

# Scan Google's ASN  
python evms.py --target 15169

# Scan Amazon's ASN
python evms.py --target as16509
```

### CIDR Scanning
```bash
# Small network - scan all
python evms.py --target 192.168.1.0/24

# Medium network - sample 500
python evms.py --target 10.0.0.0/22

# Large network - sample 1000  
python evms.py --target 172.16.0.0/16
```

### Domain Scanning
```bash
# Single domain with subdomain discovery
python evms.py --target example.com

# Will discover and scan:
# - example.com
# - www.example.com  
# - api.example.com
# - All other subdomains found by subfinder
```

## Error Handling

### ASN Discovery Failures
- **API Unavailable**: Falls back to whois command
- **No Ranges Found**: Logs error and skips target
- **Invalid CIDRs**: Validates and skips malformed ranges

### CIDR Processing Failures  
- **Invalid CIDR**: Validates format before processing
- **Memory Limits**: Streaming generation for large networks
- **Sampling Errors**: Graceful fallback to simple random sampling

### Domain Resolution Failures
- **DNS Failures**: Logs warning and continues with other domains
- **Timeout Handling**: 10-second DNS resolution timeout
- **Invalid Domains**: Skips malformed domain names

This comprehensive target discovery ensures EVMS can effectively scan any input type and discover the complete attack surface.