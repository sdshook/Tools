# BAI Analyzer

> Offline analysis tool for BAI (Browser Audit Inventory) packages.

Mission-focused analyzer that processes BAI evidence packages to detect **Adversary-in-the-Middle (AiTM) attacks** and **Infostealer malware** indicators, while correlating browser-side evidence with enterprise logs.

## Design Philosophy

**Detection-First Prioritization:**
Rather than analyzing all artifacts equally, this analyzer prioritizes artifacts by their actual value for AiTM/infostealer detection:

| Priority | Artifacts | Detection Value |
|----------|-----------|-----------------|
| **HIGH** | webstorage/indexeddb, extensions, proxy, performance/serviceworkers | Direct AiTM and token theft indicators |
| **MEDIUM** | privacy, searchengines, sessions, webauthn | Tampering and context/triage |
| **LOW** | bookmarks, topsites, mediadevices | Attribution only |

## Features

### Findings Layer (Severity-Ranked Output)
Instead of raw tables, the analyzer produces a **verdict-shaped output** with findings ranked by severity:
- **CRITICAL**: Immediate compromise indicators
- **HIGH**: Strong AiTM/infostealer signals requiring investigation
- **MEDIUM**: Potential tampering or suspicious configuration
- **LOW/INFO**: Context and enrichment

### Cross-Artifact AiTM View
Joins three critical data sources for AiTM detection:
1. **Redirect chains** from visitdetails
2. **Performance timing** (redirect duration, DNS/connect latency)
3. **Proxy configuration**

### Token Decoder (localStorage/IndexedDB)
Modern SPAs store JWTs and refresh tokens in web storage, not cookies. The analyzer:
- Scans localStorage/sessionStorage for token patterns
- Decodes IndexedDB records for embedded JWTs
- Extracts identity claims (same as cookie analysis)
- Flags XSS-vulnerable token exposure

### Extension Analysis (Infostealer Vector #1)
Flags high-risk extensions:
- **Sideloaded** (not from Web Store)
- **Broad host permissions** (`<all_urls>`)
- **Dangerous permissions**: `cookies`, `webRequest`, `debugger`, `scripting`

## Usage

```bash
# Basic analysis
python3 bai_analyze.py /path/to/BAI_package

# With timezone and output directory
python3 bai_analyze.py pkg.zip --out ./analysis --tz America/Los_Angeles

# Filter by date range
python3 bai_analyze.py pkg/ --since 2026-06-01 --until 2026-06-11

# Include raw token values (DANGEROUS - treat output as live credentials)
python3 bai_analyze.py pkg/ --include-token-values

# Quiet mode (just write files)
python3 bai_analyze.py pkg/ -q
```

## Output Files

| File | Contents |
|------|----------|
| `findings.json` | Severity-ranked findings with AiTM view |
| `auth_sessions.json` | Cookie/storage token inventory with decoded claims |
| `timeline.csv` | Chronological event timeline |

### findings.json Structure
```json
{
  "findings": [
    {
      "category": "AiTM Indicator",
      "severity": "HIGH",
      "title": "PAC script proxy detected",
      "details": { "mode": "pac_script", "pac_url": "..." },
      "recommendation": "PAC scripts can redirect traffic..."
    }
  ],
  "aitm_view": {
    "proxy_status": "system",
    "redirect_chains": [...],
    "timing_anomalies": [...],
    "overall_risk": "MEDIUM",
    "summary": "AiTM risk factors: 15 redirect transitions"
  },
  "summary": {
    "total_findings": 5,
    "by_severity": { "HIGH": 2, "MEDIUM": 2, "INFO": 1 },
    "by_category": { "AiTM Indicator": 2, "Infostealer Indicator": 1, ... }
  }
}
```

## Finding Categories

| Category | Description |
|----------|-------------|
| `AiTM Indicator` | Proxy/redirect anomalies suggesting adversary-in-the-middle |
| `Infostealer Indicator` | Extension/permission patterns matching credential theft |
| `Token/Session Exposure` | Auth tokens in XSS-vulnerable storage |
| `Tampering/Hijack` | Search engine hijacking, browser tampering |
| `Persistence Mechanism` | Service workers on sensitive origins |
| `Insecure Configuration` | Safe Browsing disabled, etc. |
| `SEO Poisoning Indicator` | Search → suspicious domain → download patterns |
| `Malvertising Indicator` | Ad-triggered downloads, ad-injector extensions |
| `Suspicious Download` | High-risk file types from untrusted sources |
| `Delivery Vector` | How malware/extensions were delivered to the user |

## Delivery Vector Detection

### SEO Poisoning Analysis
Detects the classic infostealer delivery pattern:
1. User searches for risky terms (cracks, keygens, drivers, free software)
2. Clicks on poisoned search result
3. Visits suspicious TLDs (`.xyz`, `.top`, `.club`, etc.) or typosquatting domains
4. Downloads executable within 5-minute window

**What's detected:**
- Search queries containing bait terms (crack, keygen, driver, adobe, office, etc.)
- Suspicious TLDs commonly used in SEO poisoning
- Typosquatting domains (mircosoft, gooogle, amaz0n, etc.)
- Homograph/IDN attacks (non-ASCII characters in domains)
- High-risk file downloads (`.exe`, `.msi`, `.iso`, `.dll`, etc.)

### Malvertising Analysis
Detects malicious advertising indicators:
- **Ad-triggered downloads**: Executable downloads within 60 seconds of ad network activity
- **Ad-injector extensions**: Sideloaded extensions with ad/shopping keywords + broad permissions
- **Ad network service workers**: Persistence mechanisms from advertising domains

### Extension Timeline Correlation
Attempts to correlate sideloaded extension installations with browsing history to understand the delivery vector (social engineering, malicious download site, etc.).

## Domain Intelligence

The analyzer includes comprehensive domain reputation analysis combining offline heuristics (always available) with optional online lookups.

### Offline Heuristics (Default)

| Check | Description |
|-------|-------------|
| **Suspicious TLDs** | `.xyz`, `.top`, `.club`, `.click`, `.download`, `.tk`, `.ml`, `.cf`, `.ga`, `.gq`, `.zip`, `.mov` |
| **Typosquatting** | Common misspellings of brands (mircosoft, gooogle, amaz0n, faceb00k) |
| **Brand Similarity** | Levenshtein distance to 35+ popular brands (Google, Microsoft, PayPal, etc.) |
| **DGA Detection** | High entropy, unusual consonant/vowel ratios, long consonant runs |
| **Homograph Attacks** | Non-ASCII characters in domain names (IDN/punycode abuse) |
| **Phishing Keywords** | `secure`, `login`, `verify`, `update` + suspicious TLD |

### Online Lookups (`--online` flag)

When enabled, performs WHOIS/RDAP queries to determine domain registration age:

```bash
python3 bai_analyze.py pkg/ --online
```

| Check | Description |
|-------|-------------|
| **Newly Registered** | Domain registered within 30 days (+50 risk score) |
| **Recently Registered** | Domain registered within 90 days (+25 risk score) |

**Lookup Methods:**
1. **RDAP** (preferred) - JSON-based, standardized via rdap.org bootstrap
2. **WHOIS** (fallback) - Direct socket queries to TLD-specific servers

**Supported TLDs for WHOIS:** `.com`, `.net`, `.org`, `.info`, `.io`, `.co`, `.xyz`, `.top`, `.club`, `.online`, `.site`, `.tech`, `.app`, `.dev`

### Risk Scoring

Domains receive a cumulative risk score:
- **50+**: Newly registered domain (online mode)
- **50**: Typosquatting detected
- **40**: Brand similarity (Levenshtein ≤ 2)
- **40**: Phishing keywords + suspicious TLD
- **35**: DGA-like pattern
- **30**: Suspicious TLD
- **25**: Recently registered (online mode)
- **15**: High entropy

Domains with risk score > 20 are flagged in findings.

## Correlation with Enterprise Logs

### Microsoft Entra Sign-in Logs
Join on: `tenant_id` + `object_id` + `upn` + time window

**Hunt pattern:** Same user/session reused from a different IP/ASN/device than the original MFA sign-in.

**Note:** Cookie blobs do NOT contain Entra `correlationId`/`sessionId`/`UTI` - those are server-side only.

### Purview / Unified Audit Log
Join on: `SessionId` in audit records

### Storage Tokens
localStorage/IndexedDB tokens may have **longer validity windows** than cookies (refresh tokens). Check for:
- Token reuse after cookie expiry
- Refresh token theft enabling persistent access

## Requirements

- Python 3.8+ (standard library only)
- No pip installs required
- Runs fully offline

## Security

**SECRET-SAFE BY DEFAULT**: Raw token values are never written unless you explicitly pass `--include-token-values`.

The analyzer extracts correlatable metadata (tenant ID, object ID, UPN, token type, validity window) without exposing the actual bearer tokens.

## License

© 2026 Shane Shook. All Rights Reserved.
Provided as analysis support for BAI. Standard-library only.
