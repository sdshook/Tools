# BAI Analyzer

> © 2026, Shane Shook, All Rights Reserved. This tool is for testing and analysis.

Offline analysis tool for BAI (Browser Audit Inventory) packages.

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

### Session Theft Timeline - Causal Chain Reconstruction
The analyzer builds a **causal chain** for token theft investigations:

**Key insight:** BAI cannot timestamp exfiltration itself, but it CAN date:
- When the stealable session was born
- The causal action that delivered the victim to the IdP

**The assembled chain:**
1. `visitdetails` referrer-chain → dates the lure and auth (causal action → session birth)
2. ESTS cookie → proves replayable session existed, whose it is, and validity window
3. `auth_time` claim (when available) → precise session birth from cleartext tokens
4. Entra sign-in logs (external) → date the first replay from TA infrastructure

**Theft window = [session_birth, first_TA_replay]**

**What's extracted:**
- **Stealable sessions**: ESTSAUTH/ESTSAUTHPERSISTENT with tenant_id, object_id, estimated birth
- **IdP authentication flows**: Visits to login.microsoftonline.com with full referrer chains
- **Delivery vector detection**: link (phishing email), typed (pharming), search (SEO poisoning)
- **Session birth anchors**: `auth_time` claims from cleartext tokens (more precise than `iat`)
- **Theft windows**: Estimated brackets for Entra sign-in log correlation
- **Correlation guidance**: Query templates for Entra sign-in logs

### Entra / Purview Log Correlation (Optional)
When provided with Entra sign-in logs, audit logs, and Purview/UAL exports, the analyzer **completes the theft window** by finding the first TA replay:

```bash
python3 bai_analyze.py pkg.zip --entra-logs /path/to/logs/
```

**Auto-detected log files (CSV or JSON):**
| Log Type | Filename Patterns |
|----------|-------------------|
| Interactive Sign-ins | `interactive*.json/csv` |
| Non-Interactive Sign-ins | `noninteractive*.json/csv` |
| Service Principal Sign-ins | `serviceprincipal*.json/csv`, `application*.json/csv` |
| Managed Identity Sign-ins | `managedidentity*.json/csv`, `msi*.json/csv` |
| Audit Logs | `audit*.json/csv` |
| Purview/UAL | `unified*.json/csv`, `ual*.json/csv`, `purview*.json/csv` |

**What's correlated:**
- **Token replays**: Non-interactive sign-ins from unusual IPs after session birth (HIGH confidence)
- **Completed theft windows**: `[session_birth_from_BAI, first_TA_replay_from_Entra]`
- **Anomalous sign-ins**: Sign-ins from IPs not in the user's baseline
- **Post-compromise activity**: Suspicious audit log actions (role changes, app consent, MFA changes)
- **Session correlations**: Purview/UAL activity matching BAI sessions

### Identity Inventory (UPN-Centric)
The analyzer discovers user accounts by scanning cookies, localStorage, and IndexedDB for authentication evidence, then presents a theft-risk-focused table:

| Column | Description |
|--------|-------------|
| **UPN (User)** | User Principal Name (email format) |
| **Service** | Domain where token is valid |
| **Type** | JWT, Cookie, localStorage, or IndexedDB |
| **Protection** | HttpOnly (protected from JS) or JS-accessible |
| **Theft Risk** | How the token can be stolen |

**Theft Risk Assessment:**
- **JS-accessible**: "Stealable via XSS or malicious extension" (HIGH risk)
- **HttpOnly**: "Requires malware/browser exploit to steal" (MEDIUM risk)

**Microsoft Entra Sessions** are shown separately with:
- UPN associated via `login_hint` correlation from Microsoft login URLs
- Tenant ID and Object ID for log correlation
- Cookie name (ESTSAUTH/ESTSAUTHPERSISTENT)

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
python3 bai_analyze.py <package> [options]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `package` | Yes | Path to BAI package folder or .zip file |

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--out DIR` | `./bai_analysis` | Output directory for analysis results |
| `--format {txt,html}` | `txt` | Report output format |
| `--tz TIMEZONE` | System default | Display timezone (e.g., `America/Los_Angeles`, `UTC`) |
| `--since YYYY-MM-DD` | None | Filter events on/after this date |
| `--until YYYY-MM-DD` | None | Filter events on/before this date |
| `--entra-logs FOLDER` | None | Folder containing Entra sign-in logs, audit logs, and Purview/UAL for correlation (CSV or JSON) |
| `--include-token-values` | Off | **DANGEROUS**: Write raw token values into output JSON. Treat output as live credentials! |
| `--online` | Off | Enable online lookups (WHOIS/RDAP) for domain age analysis |
| `--quiet`, `-q` | Off | Minimal console output (just write files) |

### Examples

```bash
# Basic BAI-only analysis (default)
python3 bai_analyze.py /path/to/BAI_package

# Specify output directory and timezone
python3 bai_analyze.py pkg.zip --out ./analysis --tz America/Los_Angeles

# Filter timeline to specific date range
python3 bai_analyze.py pkg/ --since 2026-06-01 --until 2026-06-11

# With Entra/Purview log correlation (completes theft windows)
python3 bai_analyze.py pkg.zip --entra-logs /path/to/entra_logs/

# Enable domain age lookups (requires internet)
python3 bai_analyze.py pkg.zip --online

# Include raw token values (DANGEROUS - treat output as live credentials)
python3 bai_analyze.py pkg/ --include-token-values

# Quiet mode (just write files, no console report)
python3 bai_analyze.py pkg/ -q

# Full analysis with all options
python3 bai_analyze.py pkg.zip \
    --out ./case_001 \
    --tz America/New_York \
    --since 2026-06-01 \
    --until 2026-06-10 \
    --entra-logs ./entra_exports/ \
    --online
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean - no critical/high findings |
| `1` | Critical or High severity findings detected |
| `2` | Token replay detected (likely active compromise) |

## Output Files

| File | Format | Contents |
|------|--------|----------|
| `report.txt` or `report.html` | TXT/HTML | Full forensic report (format selected by `--format`) |
| `identity_inventory.csv` | CSV | All accounts with IdP, MFA status, token types, validity |
| `findings.json` | JSON | Severity-ranked findings with AiTM view |
| `auth_sessions.json` | JSON | Cookie/storage token inventory with decoded claims |
| `timeline.csv` | CSV | Chronological event timeline |
| `entra_correlation.json` | JSON | Entra log correlation results (only with `--entra-logs`) |

### Report Structure

The generated report includes:
1. **Evidence Provenance** - Collection metadata, case info, chain of custody, integrity verification
2. **System Context** - Computer info, browser details, collection statistics
3. **Identity Inventory** - UPN-centric account inventory with token theft risk assessment
4. **Risk Assessment Summary** - Executive summary, severity counts, key threats, recommended actions
5. **Detailed Findings** - Full finding details by severity (HTML tables with evidence)
6. **Timeline Analysis** - Session theft timeline, authentication flows, Entra correlation
7. **Chain of Custody** - Evidence handling documentation

### Generating DOCX/PDF Reports

Use the AI prompt in `REPORT_PROMPT.md` to convert report files into professionally formatted Word/PDF documents with:
- "Privileged and Confidential - DRAFT Work Product" headers
- Page X of Y footers
- US English spelling/grammar corrections
- Professional table formatting

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
