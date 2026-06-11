# AiTM_analyzer

**Unified adversary-in-the-middle (AiTM) / token-theft analyzer — host evidence, log evidence, or both, in one consistent report.**

© 2026 Shane D. Shook. All rights reserved.

---

## Overview

`AiTM_analyzer.py` reconstructs an AiTM / session-token-theft intrusion from whatever evidence you have at the time:

- **host** — a BAI (Browser Audit Inventory) package from the victim endpoint, or
- **logs** — exported Microsoft Entra sign-in logs + Purview Unified Audit Log, or
- **both** — host *and* logs together, correlated.

It is a **single Python file with no third-party dependencies** (standard library only) and runs fully offline. Raw token values are never written unless you explicitly pass `--include-token-values`.

The two evidence sides answer different questions, which is why the tool unifies them:

- The **host** side recovers token-grade ground truth the logs don't contain: the actual stolen token's linkable identifiers (`uti` / `sid`), the precise `auth_time` session birth, the ESTS cookie, and the browser-side AiTM artifacts (proxy config, redirect chains, malicious extensions).
- The **logs** side shows what the host can't see: where the token was replayed from, the threat-actor infrastructure and ASN, the mailbox exfiltration, BEC inbox rules, containment, and persistence.
- In **both** mode the host-extracted `uti` / `sid` are pivoted into the logs for **token-grade replay confirmation** — the stolen session identified by token identity, not by a heuristic IP/baseline inference — and the host `auth_time` brackets the exact theft window.

---

## Requirements

- **Python 3.8+** (Python **3.9+** only if you use `--tz`, which relies on `zoneinfo`).
- No external packages. No installation step.

```bash
python3 AiTM_analyzer.py --help
```

---

## Quick start

```bash
# Host evidence only (BAI package or .zip)
python3 AiTM_analyzer.py --host pkg.zip --out ./case

# Log evidence only (folder of Entra/Purview exports)
python3 AiTM_analyzer.py --logs ./logs --asn-intel hosting.json --out ./case

# Both, correlated
python3 AiTM_analyzer.py --host pkg.zip --logs ./logs --out ./case

# A single evidence path, auto-classified as host or logs
python3 AiTM_analyzer.py ./evidence_path
```

---

## Usage

```text
usage: AiTM_analyzer.py [-h] [--host PATH] [--logs FOLDER] [--out OUT]
                        [--format {txt,html}] [--tz TZ] [--since SINCE]
                        [--until UNTIL] [--asn-intel FILE]
                        [--spray-min-users SPRAY_MIN_USERS]
                        [--travel-kmh TRAVEL_KMH] [--include-token-values]
                        [--online] [--quiet]
                        [evidence]
```

| Flag | Default | Applies to | Purpose |
|---|---|---|---|
| `evidence` *(positional)* | — | any | a single evidence path, auto-classified as host or logs |
| `--host` | — | host/both | BAI package folder or `.zip` |
| `--logs` | — | logs/both | folder of exported Entra/Purview logs (JSON or CSV) |
| `--out` | `./aitm_analysis` | all | output directory |
| `--format` | `txt` | host | also emit the rich host **HTML** report when set to `html` |
| `--tz` | UTC | all | display timezone, IANA name (e.g. `America/Los_Angeles`) |
| `--since` / `--until` | none | all | bound the window, `YYYY-MM-DD` |
| `--asn-intel` | built-in list | logs/both | JSON hosting/VPS ASN file to merge with the built-in defaults |
| `--spray-min-users` | `5` | logs/both | distinct users failing from one IP to call it a password spray |
| `--travel-kmh` | `900` | logs/both | implied speed over which travel is "impossible" |
| `--include-token-values` | off | host/both | **DANGEROUS:** write raw token values into host output JSON |
| `--online` | off | host/both | enable WHOIS/RDAP lookups for domain-age analysis |
| `--quiet`, `-q` | off | all | minimal console output |

### Mode is the evidence you supply

There is no mode switch — what you pass determines what runs:

- `--host` and `--logs` both supplied → **both** (correlated).
- only `--host` → **host**; only `--logs` → **logs**.
- a single positional path → auto-classified (`.zip` or a directory containing `cookies.json` / `history.json` / web-storage / extensions → host; a directory of sign-in / audit / UAL files → logs).
- if neither is supplied (and no positional), the tool exits with a clear message.

### Exit codes

| Code | Meaning |
|---|---|
| `2` | **Token-grade confirmed replay** — a host-extracted `uti`/`sid` was seen in the logs |
| `1` | HIGH or CRITICAL findings present (host or logs) |
| `0` | Ran successfully; nothing HIGH/CRITICAL and no token-grade confirmation |

---

## Input data

### Host evidence (`--host`)

A BAI package **folder** or **`.zip`**. It must contain at least `cookies.json` or `history.json`. Recognized artifacts include: `history.json`, `visitdetails.json`, `downloads.json`, `cookies.json`, `webstorage.json`, `indexeddb.json`, `extensions.json`, `permissions.json`, `proxy.json`, `performance.json`, `serviceworkers.json`, `sessions.json`, `webauthn.json`, and others. More artifacts mean richer detection (web-storage/IndexedDB carry the MSAL tokens; proxy/serviceworkers carry AiTM indicators).

### Log evidence (`--logs`)

A **folder** of exported Entra sign-in logs and the Purview Unified Audit Log. Supported formats: `.json` (array, `{"value":[...]}`, or JSONL), `.jsonl`, and `.csv`. Microsoft Graph, Azure portal, and PowerShell field shapes are handled, including Purview `AuditData` JSON-string envelopes.

Files are routed by **case-insensitive substring** in the filename:

| Bucket | Filename keywords |
|---|---|
| Purview / UAL | `unifiedauditlog`, `unified`, `purview`, `ual` |
| Non-interactive sign-ins | `noninteractive`, `non-interactive` |
| Service principal sign-ins | `serviceprincipal`, `service-principal`, `appsignin` |
| Managed identity sign-ins | `managedidentity`, `managed-identity`, `msi` |
| Interactive sign-ins | `interactive`, `signin`, `sign-in`, `logon` |
| Entra audit | `audit`, `directoryaudit` |

Suggested names: `InteractiveSignIns.json`, `NonInteractiveSignIns.json`, `ServicePrincipalSignIns.json`, `ManagedIdentitySignIns.json`, `AuditLogs.json`, `UnifiedAuditLog.csv`. At minimum supply interactive + non-interactive sign-ins; add the UAL for post-compromise actions, the mail-exfil inventory, the phishing lure, and BEC inbox-rule details.

---

## What it detects

### Host side (BAI artifacts)

- MSAL access/ID/refresh tokens in `localStorage` / `sessionStorage` / IndexedDB, decoded to claims (`oid`, `tid`, `upn`, `uti`, `sid`, `auth_time`).
- ESTS authentication cookies (`ESTSAUTH*`) — the replayable session "loaded gun."
- A **session-theft timeline** with precise `auth_time` session-birth anchors and estimated theft windows.
- **SID / UTI pivots**: `sid` = `AADSessionId` (session sweep, catches tokens minted from a replayed cookie); `uti` = `UniqueTokenId` (traces a single token) — the linkable identifiers to hunt in the logs.
- Malicious extensions, proxy configuration, service workers, and redirect chains (AiTM and infostealer vectors).

### Log side (Entra + Purview)

- **AiTM relay chains** — `AADSTS50132` / `50199` from an outside network followed by a success from that same network (robust to device/UA spoofing).
- **Session / token replay** — an `AADSessionId` or `UniqueTokenId` exercised from outside the user's footprint.
- **MFA-wall** (`50074/50076/50079`) and the "MFA wall then success" bypass.
- **Impossible travel**, **password spray / brute force / MFA fatigue**.
- **Post-compromise actions** — inbox rules (with parsed parameters), forwarding, OAuth consent, app secret/credential additions, privilege changes, MFA tampering.
- **Mail exfiltration inventory** — `MailItemsAccessed` resolved to InternetMessageIds, folders, sizes, times.
- **Phishing lure** and **lure propagation / outbound mail**.
- **Containment** (`AADSTS50057` account-disable) and **TA persistence** (post-containment retries from attacker infrastructure).

### Both (correlation)

- **Token-grade replay confirmation** — host-extracted `uti` / `sid` matched in the logs' sign-ins and UAL events; reported with the network, ASN, IP, and time of use.
- **Identity unification** — host `oid` / `upn` matched to the log users.
- **Precise theft window** — host `auth_time` (true session birth) bracketing the first outside-footprint use.

---

## How log-side attribution works

Everything is **learned per user from the supplied logs** — there are no incident-specific values hard-coded. For each user the tool builds a legitimate footprint (trusted device fleet, baseline networks collapsed to **/24** and **/64**, baseline ASNs / user-agents / apps / countries), then isolates the threat actor with three guards that stop an AiTM relay from poisoning that baseline:

1. **Taint** — any network/ASN that ever carried an AiTM error code (`50199/50132/50074/50076`) or an Entra risk flag is excluded from the baseline.
2. **Hosting-ASN exclusion** — sign-ins from hosting/VPS ASNs never seed the baseline.
3. **Replayed-device handling** — a fleet `deviceId` confers trust only off hosting/tainted infrastructure; the same `deviceId` from a datacenter ASN is treated as a **replayed claim** (the attacker spoofing the victim's device).

> This build does **not** suppress Microsoft first-party / Azure ranges. Every network is evaluated on its merits, so a threat actor operating from Microsoft/Azure infrastructure is not auto-cleared. The trade-off is that Microsoft service ranges may appear as findings; recognize and dismiss them, or add their ASNs to `--asn-intel` to keep them out of the baseline.

---

## Hosting-ASN intelligence (`--asn-intel`)

The analyzer ships with a built-in list of hosting/VPS/colo/proxy ASNs (TA infrastructure lives here; users do not). Extend or override it at runtime with a JSON file that **merges** with the defaults:

```json
{ "hosting_asns": { "64500": "SomeVPS", "64501": "AnotherHost" } }
```

A bare list of ASN numbers is also accepted: `[64500, 64501]`. A ready-to-use `hosting.json` (~700 ASNs, built from the open-source `brianhama/bad-asn-list` plus the built-in defaults) can be supplied alongside the tool.

> **Pruning note:** the supplied list includes hyperscaler ASNs (AWS, Google, Cloudflare). If your organization legitimately egresses through cloud (Azure Virtual Desktop, AWS WorkSpaces, a cloud-hosted SASE/proxy), remove those ASN lines so genuine user traffic isn't kept out of the baseline.

---

## Output

A single combined human-readable report plus the native machine-readable artifacts for each side, all in `--out`:

| File | Written in mode | Contents |
|---|---|---|
| `AiTM_report.txt` | all | combined report: banner + verdict, then correlation (both), host section, log section |
| `findings.json`, `timeline.csv`, `auth_sessions.json` | host, both | host findings, event timeline, decoded auth sessions |
| `report.html` | host/both with `--format html` | rich host HTML report |
| `ms_findings.json` | logs, both | log findings + summary (attacker IPs, suspect sessions, compromised accounts) |
| `correlation.json` | both | token-grade confirmations, matched identities, birth anchors |

The combined `AiTM_report.txt` is ordered for triage: the banner gives the mode and a one-line verdict; in **both** mode the **HOST ↔ LOG CORRELATION** section comes first (highest-value), followed by the full **HOST EVIDENCE** section and the full **LOG EVIDENCE** section (which ends with the IOC handoff block: TA infrastructure + ASN, stolen sessions, TA fingerprint, lure, propagation, persistence/BEC with inbox-rule parameters and BEC addresses, containment, TA persistence, and the mailbox-items-accessed exfil inventory).

### Severity

`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO`. Routine, non-session-bound mailbox reads are emitted at `INFO` so they do not crowd out genuine findings.

---

## AADSTS error codes surfaced (log side)

| Code | Meaning (DFIR context) |
|---|---|
| `50126` | Invalid username or password |
| `50053` | Smart lockout (too many failed attempts) |
| `50074/50076/50079` | Strong auth (MFA) required but **not satisfied** — stolen token at the MFA wall |
| `50132` | Session/token invalid — often an AiTM proxy warming a relay |
| `50199` | CMSI interrupt — anti-spoofing challenge; a burst signals a proxied auth context |
| `50173` | Fresh auth required — session/token revoked or password changed |
| `50057` | Account disabled — containment; a `50057` from attacker infra confirms a post-disable retry |
| `500121` | MFA failed/timed out (possible MFA fatigue) |
| `53003 / 530032` | Blocked by Conditional Access |

**Linkable identifiers.** Replay detection and the host↔log pivot rely on the Entra linkable identifiers `AADSessionId` (session) and `UniqueTokenId` (per-token). Confirm they are populated for your window; availability and field names vary by export and licensing.

---

## Limitations & assumptions

- **Timestamps are assumed UTC.** Confirm every log source is in UTC before correlating.
- **ASN-dependent logic degrades gracefully.** If an export lacks `autonomousSystemNumber`, the tool falls back to /24–/64 network grouping and the device fleet; hosting-ASN and replayed-device-on-hosting detection are reduced.
- **Field-name coverage** spans Graph / portal / PowerShell shapes but is not exhaustive.
- **Heuristic windows** (AiTM chain 30 min, phishing-lure lookback 20 min, "concurrent" 60 min, impossible-travel ≥100 km) are reasonable defaults; tune for unusually slow or fast intrusions.
- **Subjects/senders for accessed mail** are not present in `MailItemsAccessed`; the tool outputs InternetMessageIds for resolution via eDiscovery / `Get-MessageTrace`.
- **Host correlation requires recoverable linkable identifiers.** If the ESTS cookie is opaque (no `uti`/`sid`) or the logs lack them, the bridge cannot make a token-grade match — the independent host and log findings still apply.
- **`--include-token-values` writes live credentials.** Treat any such output as sensitive and handle accordingly.

---

## Analyst validation checklist

- Linkable identifiers (`AADSessionId` / `UniqueTokenId`) are confirmed populated for the window.
- Interactive baseline sign-ins are confirmed to be the genuine user.
- Every impossible-travel and outside-footprint hit is cleared against corporate VPN / egress / known travel.
- Risk fields (`riskState` / `riskLevelDuringSignIn`) require Entra ID P2; absence is not evidence of safety.
- All log sources are confirmed to be in UTC.
- O365 actions are attributed by actor **and** by `AADSessionId`; an action under a flagged session/IP is attacker activity until proven otherwise.
- In `both` mode, a token-grade confirmation (host `uti`/`sid` seen in logs) is treated as definitive; the absence of one is not exculpatory.

---

## Disclaimer

This tool is provided for authorized incident-response and security-analysis use only. Findings are investigative leads, not adjudications; corroborate before acting. The software is provided "as is", without warranty of any kind. ASN intelligence is sourced from third-party open data and should be reviewed for the target environment.

---

© 2026 Shane D. Shook. All rights reserved.
