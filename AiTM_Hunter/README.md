# AiTM Hunter

© 2026, Shane Shook. All Rights Reserved.

A defensive threat-intelligence toolkit for identifying AiTM (Adversary-in-the-Middle)
phishing infrastructure and malvertising surfaced via search-engine results
(e.g., sponsored ads targeting "o365 login" queries).

Built for incident responders and threat-intel analysts doing takedown work
(Google Ads abuse, Microsoft DCU, Cloudflare abuse, registrar abuse contacts).

## Features

- **Search Integration** — Query SerpApi or import manual results (JSON/CSV)
- **Multi-Signal Triage** — Domain age, typosquat detection, redirect chains, URLhaus, Google Safe Browsing
- **Typosquat Detection** — dnstwist-style detection (homoglyphs, omissions, keyword additions)
- **JA4S Fingerprinting** — Real-time TLS server fingerprinting with 93+ malware signatures
- **Evilginx Detection** — rid= markers, openresty, wildcard DNS, CDN fronting, two-tier architecture
- **Malvertising Analysis** — Ad parameter scoring (gclid/msclkid), brand spoofing detection
- **Behavioral Analysis** — Detect AiTM reverse proxies vs. static phishing kits
- **URLScan.io Integration** — Behavioral validation with rendered screenshots and verdicts
- **CT Log Monitoring** — Certificate Transparency for early warning on typosquat domains
- **Allowlist** — 100+ known-good domains to reduce false positives
- **Safe Deep Crawl** — Isolated Playwright capture (screenshot, DOM, HAR) with no credential submission
- **Takedown Reports** — CSV/JSON output ready for abuse reports

## What This Tool Does NOT Do

- **Mass scrape Google** — Uses SerpApi or manual imports (ToS-compliant)
- **Run from your daily machine** — Deep crawl stage must run in isolated/disposable environment (see `SAFETY.md`)
- **Submit credentials** — Never enters credentials, real or fake; observation only

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AiTM Hunter Pipeline                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  search.py ──────► triage.py ──────► fingerprint.py ──────► deepcrawl.py   │
│      │                 │                   │                     │          │
│      ▼                 ▼                   ▼                     ▼          │
│  SerpApi or       Domain age          JA4S TLS            Playwright        │
│  manual import    WHOIS lookup        fingerprint         screenshot        │
│                   Typosquats          Signature match     DOM snapshot      │
│                   Allowlist check     Proxy behavior      HAR capture       │
│                   URLhaus             Cert inspection                       │
│                   Safe Browsing       Evilginx markers                      │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Supplementary Tools (can run independently)                          │   │
│  ├──────────────────────────────────────────────────────────────────────┤   │
│  │  urlscan.py      Submit URLs for behavioral analysis (screenshots)   │   │
│  │  ctmonitor.py    Monitor CT logs for suspicious certificates         │   │
│  │  evilginx.py     Deep Evilginx detection (rid=, CDN fronting, etc.)  │   │
│  │  malvertising.py Ad scraping and brand spoof detection               │   │
│  │  typosquat.py    dnstwist-style domain analysis                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│                              ▼                                              │
│                         report.py                                           │
│                              │                                              │
│                              ▼                                              │
│                    CSV/JSON for abuse reports                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Installation

```bash
# Clone and setup
git clone <repository>
cd AiTM_Hunter

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Only on isolated deep-crawl host (see SAFETY.md)
playwright install chromium
```

### Environment Variables

```bash
export SERPAPI_KEY="..."                # https://serpapi.com (recommended)
export GOOGLE_SAFE_BROWSING_KEY="..."   # Optional, improves triage accuracy
export URLSCAN_API_KEY="..."            # Optional, for URLScan.io integration
```

## Usage

### Quick Start

```bash
# 1. Search + Triage (safe to run anywhere)
python -m aitm_hunter.main search \
    --query "o365 login" \
    --brand microsoft \
    --out results/o365.json

# 2. Fingerprint suspicious URLs (safe, no JS execution)
python -m aitm_hunter.main fingerprint \
    --input results/o365.json \
    --out results/o365_fp.json

# 3. Deep crawl high-risk survivors (ISOLATED HOST ONLY - see SAFETY.md)
python -m aitm_hunter.main deepcrawl \
    --input results/o365_fp.json \
    --out results/o365_deep.json \
    --i-have-read-safety-md

# 4. Generate takedown report
python -m aitm_hunter.main report \
    --input results/o365_deep.json \
    --out results/o365_report.csv
```

### Command Reference

#### `search` — Discover and triage URLs

```bash
python -m aitm_hunter.main search --query "okta login" --out results.json

# Options:
#   --query           Search query (required unless --manual-input)
#   --manual-input    Path to JSON/CSV file with URLs to analyze
#   --brand           Brand to check typosquats against (repeatable)
#   --num-results     Number of search results (default: 20)
#   --out             Output JSON file (required)
```

#### `fingerprint` — TLS/behavioral fingerprinting

```bash
python -m aitm_hunter.main fingerprint --input results.json --out results_fp.json

# Options:
#   --input           JSON from search step (required)
#   --risk-threshold  Only fingerprint URLs with risk >= N (default: 30)
#   --skip-tls        Skip TLS certificate fingerprinting
#   --skip-proxy-check Skip live proxy behavior probing
#   --out             Output JSON file (required)
```

#### `deepcrawl` — Isolated browser capture

```bash
python -m aitm_hunter.main deepcrawl --input results_fp.json --out results_deep.json --i-have-read-safety-md

# Options:
#   --input           JSON from fingerprint step (required)
#   --risk-threshold  Only crawl URLs with risk >= N (default: 50)
#   --artifact-dir    Directory for screenshots/HARs (default: results/artifacts)
#   --i-have-read-safety-md  REQUIRED safety acknowledgment
#   --out             Output JSON file (required)
```

#### `report` — Generate takedown report

```bash
python -m aitm_hunter.main report --input results_deep.json --out report.csv

# Options:
#   --input           JSON from any previous step (required)
#   --risk-threshold  Filter for summary (default: 50)
#   --out             Output file (.csv or .json) (required)
```

#### `evilginx` — Evilginx-specific detection

```bash
python -m aitm_hunter.main evilginx --url "https://suspicious.com" --out results.json

# Checks for:
#   - rid= parameter (Evilginx session ID)
#   - openresty server header
#   - Wildcard DNS
#   - Self-signed or Let's Encrypt certificates
#   - CDN fronting (Cloudflare → backend)
#   - Two-tier architecture detection
```

#### `urlscan` — URLScan.io behavioral analysis

```bash
# Search for existing scans of a domain
python -m aitm_hunter.main urlscan --url "suspicious.com" --search

# Submit URL for full analysis (requires URLSCAN_API_KEY)
python -m aitm_hunter.main urlscan --url "https://suspicious.com" --out results.json

# Returns: screenshot URL, verdicts, brand detection, login form indicators
```

#### `ctmonitor` — Certificate Transparency monitoring

```bash
python -m aitm_hunter.main ctmonitor --brands microsoft google okta --days 7

# Monitors CT logs for:
#   - Typosquat domain certificates (micr0soft.com, g00gle.com)
#   - Brand+keyword certificates (microsoft-login.com)
#   - Wildcard certificates (Evilginx indicator)
```

#### `allowlist` — Check/manage known-good domains

```bash
# Check if domains are allowlisted
python -m aitm_hunter.main allowlist --check microsoft.com evil-microsoft.com

# List all 100+ allowlisted domains
python -m aitm_hunter.main allowlist --list
```

#### `signatures` — View signature database

```bash
python -m aitm_hunter.main signatures --list-domains

# Shows: 93+ fingerprints, 48+ malware families, known Evilginx IOCs
```

---

## JA4+ Fingerprinting

### Attribution

**JA4+ is a network fingerprinting methodology created by:**
- **John Althouse** at FoxIO, LLC
- With contributions from Josh Atkins, Jeff Atkinson, and the security community

**Reference:** https://github.com/FoxIO-LLC/ja4

### JA4S Format

JA4S fingerprints the TLS ServerHello to identify malicious server infrastructure:

```
JA4S: t1302h2_c030_5e2616a54c73
      ├─┬─┬─┬─┤    │    └── Extension hash (12 chars, truncated SHA256)
      │ │ │ │ │    └─────── Cipher suite (4 chars, hex)
      │ │ │ │ └──────────── ALPN (2 chars, first/last of server's ALPN response)
      │ │ │ └────────────── Extension count (2 digits)
      │ │ └──────────────── TLS version (2 chars: 13=1.3, 12=1.2, etc.)
      │ └────────────────── Protocol (t=TLS, q=QUIC, d=DTLS)
      └──────────────────── 7 characters before first underscore
```

### How It Works

1. **Initiates TLS handshake** with target server
2. **Captures ServerHello** — version, cipher, extensions, ALPN
3. **Computes JA4S fingerprint** per FoxIO specification
4. **Matches against 93+ signatures** from known-malicious infrastructure

### Licensing

- **JA4** (TLS Client): BSD 3-Clause License
- **JA4S, JA4H, JA4X** (JA4+): FoxIO License 1.1
  - Permissive for internal security and academic use
  - Commercial/monetized use requires OEM licensing from FoxIO
  - Contact: john@foxio.io

---

## Signature Database

**93+ known-malicious fingerprints** covering **48+ malware families**:

| Type | Count | Description |
|------|-------|-------------|
| JA4 Client | 37 | TLS client fingerprints (C2 agents, trojans) |
| JA4S Server | 7 | TLS server fingerprints (C2 infrastructure) |
| JA4X Cert | 7 | X.509 certificate fingerprints |
| JA4H HTTP | 35 | HTTP client behavior fingerprints |
| JA3 Legacy | 7 | Legacy JA3 fingerprints |

### Malware/Tools Covered

| Category | Families |
|----------|----------|
| **C2 Frameworks** | Cobalt Strike, Sliver, Havoc, Covenant, Mythic, PoshC2 |
| **AiTM Kits** | Evilginx, Modlishka, Muraena, GoLang net package proxies |
| **Banking Trojans** | Zeus, IcedID, Qakbot, Pikabot |
| **Botnets** | FastFlux, Neris, HTBot |
| **Infostealers** | LummaC2, Darkgate, PhantomSteal, SmartAPeSG |
| **Red Team Tools** | AADInternals, AzureHound, GraphRunner, GraphSpy, TokenTactics |
| **RATs** | AsyncRAT, Remcos, njRAT |

### Signature Sources

1. **[FoxIO ja4plus-mapping.csv](https://github.com/FoxIO-LLC/ja4)** — Official JA4+ mappings
2. **[ostweg/malicious-ja4-fingerprints](https://github.com/ostweg/malicious-ja4-fingerprints)** — PCAP-derived malware signatures
3. **[r3m0s/malicious-ja4-database](https://github.com/r3m0s/malicious-ja4-database)** — C2 framework signatures (AGPL-3.0)

### Updating Signatures

```bash
# View current signature stats
python -c "from aitm_hunter.signatures import *; print(f'JA4: {len(KNOWN_MALWARE_JA4_CLIENT)}, JA4S: {len(KNOWN_AITM_JA4S_SIGNATURES)}, JA4H: {len(KNOWN_MALWARE_JA4H)}, JA4X: {len(KNOWN_MALWARE_JA4X)}, JA3: {len(KNOWN_MALWARE_JA3)}')"

# Manually edit aitm_hunter/signatures.py to add new fingerprints
```

---

## Risk Scoring

URLs are scored 0-100 based on multiple signals:

| Signal | Points | Description |
|--------|--------|-------------|
| URLhaus flagged | +50 | Known malicious host |
| Safe Browsing flagged | +50 | Google-flagged threat |
| JA4S signature match | +50 | Known malware TLS fingerprint |
| High typosquat score | +30 | Domain resembles target brand (≥85% similarity) |
| New domain | +25 | Registered within last 30 days |
| AiTM proxy behavior | +30 | Live-proxies IdP resources |
| Static phish behavior | +20 | Serves static copied content |
| Many redirects | +10 | 3+ redirect hops |

**Thresholds:**
- `≥30` — Fingerprinting recommended
- `≥50` — High risk, deep crawl recommended
- `≥70` — Very high risk, likely malicious

---

## Project Structure

```
AiTM_Hunter/
├── aitm_hunter/
│   ├── __init__.py
│   ├── main.py          # CLI orchestrator
│   ├── search.py        # SerpApi integration + manual import
│   ├── triage.py        # Domain analysis, reputation checks
│   ├── typosquat.py     # dnstwist-style typosquat detection
│   ├── fingerprint.py   # TLS/behavioral fingerprinting
│   ├── ja4.py           # JA4S computation (FoxIO spec)
│   ├── signatures.py    # Malware signature database (93+ fingerprints)
│   ├── evilginx.py      # Evilginx-specific detection
│   ├── malvertising.py  # Ad scraping and brand spoof detection
│   ├── urlscan.py       # URLScan.io API integration
│   ├── ctmonitor.py     # Certificate Transparency monitoring
│   ├── allowlist.py     # Known-good domain allowlist (100+ domains)
│   ├── deepcrawl.py     # Playwright-based capture
│   └── report.py        # CSV/JSON report generation
├── tests/
│   ├── test_fingerprint.py
│   ├── test_ja4.py
│   ├── test_triage.py
│   ├── test_search.py
│   └── test_report.py
├── requirements.txt
├── README.md
├── SAFETY.md            # MUST READ before deep crawling
├── IMPROVEMENTS.md      # Roadmap for future enhancements
└── pytest.ini
```

---

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test module
python -m pytest tests/test_ja4.py -v

# Current: 65 tests passing
```

---

## Known Limitations

1. **Fallback Mode** — Raw ServerHello capture may fail on some servers; falls back to Python's ssl module which cannot capture extension list (hash shows as `000000000000`)

2. **Extension Count in Fallback** — When extensions can't be captured, count defaults to `00` which may not match signatures with specific extension counts

3. **TLS 1.3 Version Field** — In TLS 1.3, ServerHello version is always 0x0303 for compatibility; actual version is detected via `ssock.version()`

4. **WHOIS Rate Limiting** — Running against many domains may trigger WHOIS rate limits

---

## Safety Warning

⚠️ **READ `SAFETY.md` BEFORE USING `deepcrawl`** ⚠️

The deep-crawl stage renders live, potentially-malicious pages in a real browser.
It **must** run from a disposable, network-isolated environment.

---

## License

© 2026, Shane Shook. All Rights Reserved.

This tool is for authorized security testing and threat intelligence analysis only.

**Third-party components:**
- JA4/JA4+ methodology: FoxIO License 1.1 / BSD 3-Clause
- Signature sources: See individual repository licenses
