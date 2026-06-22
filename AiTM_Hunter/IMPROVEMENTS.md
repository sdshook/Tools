# AiTM_Hunter Critical Review & Improvement Roadmap

## Current State Summary

**12 modules, ~4,300 lines of code**

| Module | Purpose | Status |
|--------|---------|--------|
| search.py | SerpApi SERP collection | ✅ Working |
| triage.py | URL analysis, reputation | ✅ Working |
| typosquat.py | dnstwist-style detection | ✅ Working |
| fingerprint.py | TLS/JA4+ signatures | ✅ Working |
| evilginx.py | Evilginx-specific markers | ✅ Working |
| malvertising.py | Ad scraping/analysis | ⚠️ Untested in production |
| signatures.py | IOC database | ✅ Working |
| deepcrawl.py | Browser artifact collection | ⚠️ Requires isolation |
| report.py | CSV/JSON output | ✅ Working |

---

## Critical Gaps

### 1. **Ad Capture is Unreliable**

**Problem:** The malvertising module uses Playwright to scrape ads, but:
- Google/Bing dynamically load ads with JS
- Ad targeting means different users see different ads
- Geo-targeting affects ad visibility
- Many sponsored results are in iframes or shadow DOM

**Impact:** The Storm-2755 and colinandresw.com attacks were delivered via ads, but we can't reliably capture them.

**Recommendation:**
```
Priority: HIGH
- Integrate Google Ads Transparency Center API
- Use multiple geo-located proxies for ad scraping
- Add headless browser with longer wait times for JS
- Consider commercial ad intelligence services (SpyFu, SEMrush APIs)
```

### 2. **No Behavioral Validation of AiTM**

**Problem:** We detect *indicators* but don't verify if a site actually performs AiTM:
- Does it serve a real login page?
- Does it proxy authentication requests?
- Does it capture session tokens?

**Impact:** High false positive rate. Legitimate sites with login forms get flagged.

**Recommendation:**
```
Priority: HIGH
- Add safe credential submission test (use honeypot creds)
- Check if authentication traffic is proxied to real IdP
- Verify if Set-Cookie headers capture session tokens
- Analyze if page requests Microsoft/Okta resources
```

### 3. **No Certificate Transparency Monitoring**

**Problem:** We only analyze certs on-demand. CT logs could reveal:
- Newly issued certs for typosquat domains
- Bulk cert issuance (campaign indicator)
- Wildcard certs (Evilginx pattern)

**Impact:** Missing early warning capability.

**Recommendation:**
```
Priority: MEDIUM
- Integrate crt.sh or Certstream API
- Monitor for certs issued to typosquat patterns
- Alert on wildcard certs for suspicious domains
- Track Let's Encrypt issuance velocity
```

### 4. **Limited Infrastructure Correlation**

**Problem:** We analyze domains individually but don't correlate:
- Same IP hosting multiple lures
- Same registrar/creation date (bulk registration)
- Same nameservers
- Same cert issuer/subject pattern

**Impact:** Miss campaign-level detection and attribution.

**Recommendation:**
```
Priority: MEDIUM
- Add infrastructure clustering (group by IP, ASN, registrar)
- Integrate passive DNS (SecurityTrails, VirusTotal, Farsight)
- Track domain registration patterns
- Build relationship graphs
```

### 5. **No JavaScript Analysis**

**Problem:** AiTM kits inject JS for:
- Keylogging
- Form hijacking
- Session token extraction
- Anti-analysis evasion

**Impact:** Missing detection of credential-stealing code.

**Recommendation:**
```
Priority: MEDIUM
- Extract and hash inline scripts
- Detect known malicious JS patterns
- Identify obfuscated code (entropy analysis)
- Compare JS to legitimate site baselines
```

### 6. **Missing Data Sources**

| Source | Value | Integration Effort |
|--------|-------|-------------------|
| URLScan.io | See rendered pages, detect phishing | Low (API) |
| PhishTank | Crowdsourced phishing DB | Low (API) |
| VirusTotal | Multi-engine scanning, passive DNS | Low (API) |
| Shodan/Censys | Infrastructure fingerprinting | Medium |
| Farsight DNSDB | Historical DNS | Medium (paid) |
| WHOIS History | Registration changes | Medium |

### 7. **False Positive Issues**

**Current problems:**
- Legitimate login pages flagged as "static phish"
- React SPAs with catch-all routing trigger "proxies resources"
- Any site with gclid flagged with moderate score

**Recommendation:**
```
Priority: HIGH
- Add allowlist for known-good domains
- Require multiple signals before flagging
- Weight signals by reliability
- Add "likely legitimate" classification
```

---

## Architecture Improvements

### 1. **Confidence Score Aggregation**

Current: Each module produces independent scores.
Needed: Weighted combination with thresholds.

```python
# Proposed scoring model
confidence = (
    typosquat_score * 0.25 +
    evilginx_markers * 0.30 +
    brand_spoof_in_ad * 0.25 +
    infra_reputation * 0.10 +
    behavioral_verification * 0.10
)

if confidence >= 80: return "HIGH - Likely AiTM"
if confidence >= 50: return "MEDIUM - Investigate"
if confidence >= 30: return "LOW - Monitor"
```

### 2. **Pipeline Orchestration**

Current: Manual CLI execution of each stage.
Needed: Automated pipeline with dependencies.

```
search → triage → [parallel: typosquat, fingerprint, evilginx] → correlate → report
```

### 3. **Caching Layer**

Current: Every run re-fetches everything.
Needed: Cache DNS, WHOIS, cert data with TTL.

```python
# Redis/SQLite cache
cache.set(f"dns:{domain}", ip_address, ttl=3600)
cache.set(f"whois:{domain}", registration_data, ttl=86400)
```

### 4. **API Mode**

Current: CLI only.
Needed: REST API for integration.

```
POST /api/scan {"url": "https://suspicious.com"}
GET /api/results/{scan_id}
POST /api/monitor {"query": "o365 login", "interval": "hourly"}
```

---

## Operational Improvements

### 1. **Continuous Monitoring**

```
- Schedule recurring searches for high-risk queries
- Monitor CT logs for new typosquat certs
- Track changes to known-malicious infrastructure
- Alert on new findings
```

### 2. **SIEM/SOAR Integration**

```
- Splunk HEC output
- Sentinel/Log Analytics webhook
- XSOAR playbook triggers
- Slack/Teams alerting
```

### 3. **Reporting Enhancements**

Current: Raw CSV/JSON.
Needed:
- Executive summary with risk levels
- IOC export (STIX/TAXII format)
- Timeline visualization
- Campaign attribution

---

## Quick Wins (Low Effort, High Value)

1. **Add URLScan.io integration** - Single API call gives rendered screenshots and detection
2. **Add allowlist** - Reduce false positives on known-good domains
3. **Add PhishTank/OpenPhish lookup** - Free threat intel
4. **Improve ad wait times** - Longer Playwright waits may capture more ads
5. **Add VirusTotal lookup** - Multi-engine scanning

---

## Testing Gaps

### Missing Test Coverage:
- No integration tests with live APIs
- No tests for malvertising browser scraping
- No tests for deepcrawl module
- No performance/load tests

### Recommended:
```
- Add integration test suite (with mocked APIs)
- Add end-to-end test with known-malicious samples
- Add regression tests for false positive cases
- Add performance benchmarks
```

---

## Summary: Priority Roadmap

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| P0 | Fix ad capture reliability | High | Critical |
| P0 | Add behavioral AiTM validation | High | Critical |
| P0 | Reduce false positives | Medium | High |
| P1 | Add URLScan.io integration | Low | High |
| P1 | Add confidence score aggregation | Medium | High |
| P1 | Add CT log monitoring | Medium | Medium |
| P2 | Infrastructure clustering | High | Medium |
| P2 | Add API mode | Medium | Medium |
| P2 | JavaScript analysis | High | Medium |
| P3 | SIEM integration | Medium | Low |
| P3 | Continuous monitoring | High | Medium |

---

## Conclusion

**Strengths:**
- Good fingerprint-first architecture
- Solid typosquat detection
- Comprehensive Evilginx marker detection
- Clean separation of concerns

**Weaknesses:**
- Ad capture is the weakest link (critical for this threat vector)
- No behavioral validation = high false positives
- Point-in-time scanning vs. continuous monitoring
- Limited external data source integration

**The fundamental gap:** The tool can identify *potential* AiTM infrastructure but cannot definitively confirm AiTM behavior without:
1. Reliable ad capture (to catch malvertising delivery)
2. Behavioral validation (to confirm credential proxying)
3. Lower false positive rate (to be operationally useful)

Focus on these three areas first.
