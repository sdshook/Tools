#!/usr/bin/env python3
# © 2026, Shane Shook, All Rights Reserved - this tool is for testing and analysis.
"""
bai_analyze.py - Offline analyzer for BAI (Browser Audit Inventory) packages.

Builds a unified event timeline from history/visits/downloads/cookies and decodes
identity-provider session cookies into the anchors needed to correlate browser-side
evidence with Microsoft Entra sign-in logs and Purview/Unified Audit Log records.

**Mission-Focused Design:**
  * AiTM Detection: Cross-artifact correlation of redirects, proxy config, timing
  * Infostealer Detection: Extension analysis, token theft from storage, session hijack
  * Pure standard library. No pip installs. Runs fully offline.
  * SECRET-SAFE BY DEFAULT: raw token values are NEVER written unless --include-token-values.

**Artifact Priority (based on detection value):**
  HIGH: webstorage/indexeddb (token theft), extensions (infostealer vectors),
        proxy (AiTM), performance/serviceworkers (redirects/persistence)
  MED:  privacy/searchengines (tampering), sessions/webauthn (context/triage)
  LOW:  bookmarks, topsites, mediadevices (attribution only)

Usage:
    python3 bai_analyze.py /path/to/BAI_package_or_zip
    python3 bai_analyze.py pkg.zip --out ./analysis --tz America/Los_Angeles
    python3 bai_analyze.py pkg/  --since 2026-06-01 --until 2026-06-11
    python3 bai_analyze.py pkg/  --include-token-values        # opt-in, dangerous

(c) Provided as analysis support for BAI by Shane Shook. Standard-library only.
"""

import argparse
import base64
import csv
import json
import os
import re
import struct
import sys
import zipfile
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Severity and Finding types
# --------------------------------------------------------------------------- #

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other):
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        return order.index(self) < order.index(other)


class FindingCategory(Enum):
    AITM = "AiTM Indicator"
    INFOSTEALER = "Infostealer Indicator"
    TAMPERING = "Tampering/Hijack"
    PERSISTENCE = "Persistence Mechanism"
    TOKEN_EXPOSURE = "Token/Session Exposure"
    CONFIG_DRIFT = "Insecure Configuration"
    SEO_POISONING = "SEO Poisoning Indicator"
    MALVERTISING = "Malvertising Indicator"
    SUSPICIOUS_DOWNLOAD = "Suspicious Download"
    DELIVERY_VECTOR = "Delivery Vector"


# --------------------------------------------------------------------------- #
# Time helpers
# --------------------------------------------------------------------------- #

def _try_zoneinfo(tzname):
    if not tzname:
        return timezone.utc
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(tzname)
    except Exception:
        sys.stderr.write(f"[warn] timezone {tzname!r} unavailable; using UTC\n")
        return timezone.utc


def from_chrome_micros(v):
    """Chrome history/visit time = ms since epoch (BAI emits ms as float)."""
    if v is None:
        return None
    try:
        return datetime.fromtimestamp(float(v) / 1000.0, timezone.utc)
    except Exception:
        return None


def from_epoch_seconds(v):
    """Cookie expirationDate and download start/end are epoch seconds (float)."""
    if v is None:
        return None
    try:
        return datetime.fromtimestamp(float(v), timezone.utc)
    except Exception:
        return None


def parse_iso(v):
    if not v:
        return None
    try:
        s = v.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def fmt(dt, tz):
    if dt is None:
        return ""
    return dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + dt.astimezone(tz).strftime(" %z")


# --------------------------------------------------------------------------- #
# Package loading - expanded artifact list
# --------------------------------------------------------------------------- #

ARTIFACT_FILES = [
    # Core
    "history.json", "visitdetails.json", "downloads.json", "cookies.json",
    "MANIFEST.json", "session_log.json", "chain_of_custody.json",
    # High priority
    "webstorage.json", "indexeddb.json", "indexeddbfull.json",
    "extensions.json", "permissions.json",
    "proxy.json",
    "performance.json", "serviceworkers.json",
    # Medium priority
    "privacy.json", "searchengines.json",
    "sessions.json", "webauthn.json",
    "tabsdetailed.json", "windows.json",
    # Low priority (loaded but not prioritized in findings)
    "bookmarks.json", "topsites.json", "mediadevices.json",
    "storageestimates.json", "contentsettings.json", "readinglist.json",
    "systeminfo.json", "account.json",
]


def load_package(path: str) -> Dict[str, Any]:
    """Return dict {basename: parsed_json} for all available artifacts."""
    data = {}
    if os.path.isdir(path):
        root = path
        names = os.listdir(path)
        if "MANIFEST.json" not in names:
            subs = [os.path.join(path, n) for n in names
                    if os.path.isdir(os.path.join(path, n))]
            for s in subs:
                if os.path.exists(os.path.join(s, "MANIFEST.json")):
                    root = s
                    break
        for fn in ARTIFACT_FILES:
            fp = os.path.join(root, fn)
            if os.path.exists(fp):
                try:
                    with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                        data[fn] = json.load(fh)
                except json.JSONDecodeError as e:
                    sys.stderr.write(f"[warn] failed to parse {fn}: {e}\n")
        # Also check for snapshots directory
        snap_dir = os.path.join(root, "snapshots")
        if os.path.isdir(snap_dir):
            data["_snapshots_dir"] = snap_dir
            data["_snapshot_files"] = os.listdir(snap_dir)
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            members = z.namelist()
            for fn in ARTIFACT_FILES:
                hit = next((m for m in members if m.endswith("/" + fn) or m == fn), None)
                if hit:
                    try:
                        with z.open(hit) as fh:
                            data[fn] = json.loads(fh.read().decode("utf-8", "replace"))
                    except json.JSONDecodeError as e:
                        sys.stderr.write(f"[warn] failed to parse {fn}: {e}\n")
            # Check for snapshots
            snap_files = [m for m in members if "/snapshots/" in m and m.endswith(".mhtml")]
            if snap_files:
                data["_snapshot_files"] = [os.path.basename(m) for m in snap_files]
    else:
        raise SystemExit(f"[fatal] {path} is neither a directory nor a zip")
    return data


def records(blob) -> List[Dict]:
    if not blob:
        return []
    return blob.get("records") or []


# --------------------------------------------------------------------------- #
# Base64 / JWT / GUID decoders
# --------------------------------------------------------------------------- #

def _b64u(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _guid_le(b: bytes) -> Optional[str]:
    """Decode a 16-byte .NET little-endian GUID."""
    if len(b) < 16:
        return None
    a = struct.unpack("<I", b[0:4])[0]
    c = struct.unpack("<H", b[4:6])[0]
    d = struct.unpack("<H", b[6:8])[0]
    rest = b[8:16]
    return "%08x-%04x-%04x-%02x%02x-%s" % (a, c, d, rest[0], rest[1], rest[2:8].hex())


def _printable_strings(b: bytes, minlen: int = 4) -> List[str]:
    out, cur = [], []
    for ch in b:
        if 32 <= ch < 127:
            cur.append(chr(ch))
        else:
            if len(cur) >= minlen:
                out.append("".join(cur))
            cur = []
    if len(cur) >= minlen:
        out.append("".join(cur))
    return out


def decode_jwt_noverify(value: str) -> Dict[str, Any]:
    """Extract claims from a JWT without signature verification."""
    out = {}
    try:
        segs = value.split(".")
        if len(segs) >= 2:
            payload = json.loads(_b64u(segs[1]))
            # Include auth_time - critical for session birth timing
            # auth_time = interactive authentication instant (MFA moment)
            # iat = token issuance (can be silent refresh, less useful)
            for k in ("tid", "oid", "upn", "preferred_username", "unique_name",
                      "email", "sub", "iss", "aud", "iat", "exp", "nbf", "sid",
                      "name", "given_name", "family_name", "azp", "appid", "scp",
                      "auth_time", "amr", "acr", "nonce"):
                if k in payload:
                    out[k] = payload[k]
    except Exception:
        pass
    return out


def decode_entra_home_account(value: str) -> Dict[str, Any]:
    """Extract tenant/object IDs from ESTSAUTH cookies."""
    out = {}
    try:
        parts = value.split(".")
        if len(parts) >= 2 and parts[0] in ("1", "2"):
            raw = _b64u(parts[1])
            if len(raw) >= 35:
                out["tenant_id"] = _guid_le(raw[3:19])
                out["object_id"] = _guid_le(raw[19:35])
    except Exception:
        pass
    return out


def decode_entra_ccstate(value: str) -> Dict[str, Any]:
    """Extract UPN from CCState cookie."""
    out = {}
    try:
        raw = _b64(value)
        for s in _printable_strings(raw, 6):
            if "@" in s and "." in s.split("@")[-1]:
                out["upn"] = s.strip()
                break
    except Exception:
        pass
    return out


# --------------------------------------------------------------------------- #
# Token patterns for web storage analysis
# --------------------------------------------------------------------------- #

JWT_PATTERN = re.compile(r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
BEARER_TOKEN_KEYS = {
    # Common OAuth/OIDC token storage keys
    "access_token", "accesstoken", "id_token", "idtoken", "refresh_token",
    "refreshtoken", "auth_token", "authtoken", "bearer", "jwt",
    # MSAL patterns
    "msal.", "oidc.", "oauth",
    # Provider-specific
    "msalaccount", "msalaccesstoken", "msalrefreshtoken", "msalidtoken",
    "__session", "session_token", "user_token",
}


def looks_like_token(key: str, value: str) -> Tuple[bool, str]:
    """Check if a storage key/value looks like an auth token."""
    kl = key.lower()
    
    # Check key name patterns
    for pattern in BEARER_TOKEN_KEYS:
        if pattern in kl:
            return True, f"key matches '{pattern}'"
    
    # Check if value is a JWT
    if isinstance(value, str) and JWT_PATTERN.match(value):
        return True, "value is JWT format"
    
    # Check if value is JSON with token-like structure
    if isinstance(value, str) and value.startswith("{"):
        try:
            obj = json.loads(value)
            if isinstance(obj, dict):
                obj_keys = {k.lower() for k in obj.keys()}
                token_keys = {"access_token", "accesstoken", "id_token", "refresh_token", "expiresIn", "expires_in"}
                if obj_keys & token_keys:
                    return True, "JSON contains token fields"
        except (json.JSONDecodeError, TypeError):
            pass
    
    return False, ""


# --------------------------------------------------------------------------- #
# IdP classification
# --------------------------------------------------------------------------- #

def classify_idp(domain: str) -> Optional[str]:
    d = domain.lower().lstrip(".")
    table = [
        ("login.microsoftonline.com", "Microsoft Entra ID (Azure AD)"),
        ("login.microsoftonline.us", "Microsoft Entra ID (US Gov)"),
        ("login.microsoft.com",      "Microsoft Entra ID"),
        ("login.live.com",           "Microsoft consumer (MSA)"),
        ("sts.",                     "AD FS / STS"),
        ("adfs",                     "AD FS"),
        ("accounts.google.com",      "Google"),
        ("okta.com",                 "Okta"),
        ("auth0.com",                "Auth0"),
        ("keycloak",                 "Keycloak"),
        ("github.com",               "GitHub"),
        ("chatgpt.com",              "OpenAI"),
        ("openai.com",               "OpenAI"),
        ("sharepoint.com",           "SharePoint Online"),
        ("cognito",                  "AWS Cognito"),
        ("firebase",                 "Firebase Auth"),
    ]
    for needle, label in table:
        if needle in d:
            return label
    return None


STRONG_AUTH_NAMES = {
    "estsauth", "estsauthpersistent", "estsauthlight", "buid", "ccstate",
    "msisauth", "msisauthenticated", "fedauth", "rtfa", "fpc",
    "sapisid", "__secure-1psid", "__host-1psid", "__secure-3psid",
    "auth_session_id", "keycloak_session", "keycloak_auth",
    "kc-access", "user_session", "_gh_sess", "dotcom_user",
    "oai-client-auth-info", "unified_session_manifest", "x-ms-cpim-sso",
}

STRONG_AUTH_PREFIXES = (
    "estsauth", "__secure-next-auth.session-token", "__host-next-auth",
    "msal.", "msisauth",
)


def is_auth_cookie(name: str) -> bool:
    n = name.lower()
    if n in STRONG_AUTH_NAMES:
        return True
    return any(n.startswith(p) for p in STRONG_AUTH_PREFIXES)


# --------------------------------------------------------------------------- #
# HIGH PRIORITY: Extension analysis (infostealer vector #1)
# --------------------------------------------------------------------------- #

HIGH_RISK_PERMISSIONS = {
    "cookies": "Can read all cookies including auth tokens",
    "webRequest": "Can intercept/modify all network traffic",
    "webRequestBlocking": "Can block/modify requests synchronously",
    "debugger": "Can attach debugger to any tab (full control)",
    "scripting": "Can inject scripts into any page",
    "tabs": "Can access tab URLs and content",
    "history": "Can read/modify browsing history",
    "storage": "Can access extension storage",
    "nativeMessaging": "Can communicate with native applications",
    "management": "Can manage other extensions",
    "proxy": "Can configure proxy settings",
    "downloads": "Can initiate/access downloads",
    "clipboardRead": "Can read clipboard content",
    "clipboardWrite": "Can write to clipboard",
}

BROAD_HOST_PATTERNS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}


def analyze_extensions(pkg: Dict) -> List[Dict]:
    """Analyze extensions for infostealer indicators."""
    findings = []
    ext_blob = pkg.get("extensions.json")
    perm_blob = pkg.get("permissions.json")
    
    for ext in records(ext_blob):
        ext_id = ext.get("id", "unknown")
        name = ext.get("name", "Unknown Extension")
        install_type = ext.get("installType", "")
        enabled = ext.get("enabled", False)
        permissions = ext.get("permissions", []) or []
        host_permissions = ext.get("hostPermissions", []) or []
        
        issues = []
        severity = Severity.INFO
        
        # Check for sideloaded extensions (not from store)
        if install_type == "sideload":
            issues.append("SIDELOADED (not from Chrome Web Store)")
            severity = Severity.HIGH
        elif install_type == "development":
            issues.append("DEVELOPMENT mode extension")
            severity = max(severity, Severity.MEDIUM)
        
        # Check for high-risk permissions
        risky_perms = []
        for perm in permissions:
            if perm in HIGH_RISK_PERMISSIONS:
                risky_perms.append(f"{perm}: {HIGH_RISK_PERMISSIONS[perm]}")
        
        if risky_perms:
            if any(p in permissions for p in ["cookies", "webRequest", "debugger"]):
                severity = max(severity, Severity.HIGH)
            else:
                severity = max(severity, Severity.MEDIUM)
            issues.append(f"High-risk permissions: {', '.join(risky_perms)}")
        
        # Check for broad host access
        broad_hosts = [h for h in host_permissions if h in BROAD_HOST_PATTERNS]
        if broad_hosts:
            issues.append(f"Broad host access: {', '.join(broad_hosts)}")
            severity = max(severity, Severity.HIGH)
        
        # Only report if there are actual issues (not just INFO level) and extension is enabled
        if issues and enabled and severity != Severity.INFO:
            findings.append({
                "category": FindingCategory.INFOSTEALER.value,
                "severity": severity.value,
                "title": f"Suspicious extension: {name}",
                "details": {
                    "extension_id": ext_id,
                    "name": name,
                    "install_type": install_type,
                    "issues": issues,
                    "permissions": permissions,
                    "host_permissions": host_permissions,
                },
                "recommendation": "Review extension legitimacy and permissions. Sideloaded extensions with broad permissions are a primary infostealer vector."
            })
    
    return findings


# --------------------------------------------------------------------------- #
# HIGH PRIORITY: Proxy analysis (AiTM critical)
# --------------------------------------------------------------------------- #

def analyze_proxy(pkg: Dict) -> List[Dict]:
    """Analyze proxy configuration for AiTM indicators."""
    findings = []
    proxy_blob = pkg.get("proxy.json")
    
    if not proxy_blob:
        findings.append({
            "category": FindingCategory.AITM.value,
            "severity": Severity.INFO.value,
            "title": "Proxy configuration not collected",
            "details": {"status": "artifact_missing"},
            "recommendation": "Re-run collection to capture proxy settings."
        })
        return findings
    
    settings = proxy_blob.get("settings") or proxy_blob.get("records", [{}])[0] if proxy_blob else {}
    mode = settings.get("mode", "")
    pac_script = settings.get("pacScript", {})
    rules = settings.get("rules", {})
    
    if mode in ("system", "direct"):
        # Clean configuration
        findings.append({
            "category": FindingCategory.AITM.value,
            "severity": Severity.INFO.value,
            "title": f"Proxy mode is '{mode}' (normal)",
            "details": {"mode": mode, "status": "clean"},
            "recommendation": None
        })
    elif mode == "pac_script":
        # PAC script - potential AiTM
        pac_url = pac_script.get("url", "")
        findings.append({
            "category": FindingCategory.AITM.value,
            "severity": Severity.HIGH.value,
            "title": "PAC script proxy detected",
            "details": {
                "mode": mode,
                "pac_url": pac_url,
                "pac_data_present": bool(pac_script.get("data")),
            },
            "recommendation": "PAC scripts can redirect traffic through attacker infrastructure. Verify the PAC URL is legitimate and authorized."
        })
    elif mode == "fixed_servers":
        # Fixed proxy - check if expected
        proxy_rules = rules.get("singleProxy") or rules.get("proxyForHttp") or {}
        findings.append({
            "category": FindingCategory.AITM.value,
            "severity": Severity.MEDIUM.value,
            "title": "Fixed proxy server configured",
            "details": {
                "mode": mode,
                "proxy_host": proxy_rules.get("host"),
                "proxy_port": proxy_rules.get("port"),
                "proxy_scheme": proxy_rules.get("scheme"),
            },
            "recommendation": "Verify this proxy is authorized. Unexpected proxy configurations may indicate AiTM attack setup."
        })
    elif mode:
        # Unknown mode
        findings.append({
            "category": FindingCategory.AITM.value,
            "severity": Severity.MEDIUM.value,
            "title": f"Unusual proxy mode: {mode}",
            "details": {"mode": mode, "full_settings": settings},
            "recommendation": "Investigate this proxy configuration."
        })
    
    return findings


# --------------------------------------------------------------------------- #
# HIGH PRIORITY: Web storage / IndexedDB token analysis
# --------------------------------------------------------------------------- #

def analyze_webstorage(pkg: Dict, include_values: bool = False) -> Tuple[List[Dict], List[Dict]]:
    """Analyze localStorage/sessionStorage for auth tokens."""
    findings = []
    token_inventory = []
    
    ws_blob = pkg.get("webstorage.json")
    if not ws_blob:
        findings.append({
            "category": FindingCategory.TOKEN_EXPOSURE.value,
            "severity": Severity.INFO.value,
            "title": "Web storage not collected",
            "details": {"status": "artifact_missing"},
            "recommendation": "Re-run collection with content script enabled to capture web storage."
        })
        return findings, token_inventory
    
    for item in records(ws_blob):
        origin = item.get("origin", item.get("url", ""))
        storage_type = item.get("type", "localStorage")
        storage_data = item.get("data", {}) or item.get("localStorage", {}) or item.get("sessionStorage", {})
        
        for key, value in storage_data.items():
            is_token, reason = looks_like_token(key, str(value) if value else "")
            if is_token:
                # Decode if JWT
                decoded = {}
                val_str = str(value) if value else ""
                if JWT_PATTERN.match(val_str):
                    decoded = decode_jwt_noverify(val_str)
                
                token_entry = {
                    "origin": origin,
                    "storage_type": storage_type,
                    "key": key,
                    "detection_reason": reason,
                    "value_length": len(val_str),
                    "decoded": decoded if decoded else None,
                }
                if include_values:
                    token_entry["value"] = val_str
                token_inventory.append(token_entry)
    
    if token_inventory:
        # Group by origin for reporting
        by_origin = defaultdict(list)
        for t in token_inventory:
            by_origin[t["origin"]].append(t)
        
        findings.append({
            "category": FindingCategory.TOKEN_EXPOSURE.value,
            "severity": Severity.HIGH.value,
            "title": f"Auth tokens found in web storage ({len(token_inventory)} tokens across {len(by_origin)} origins)",
            "details": {
                "total_tokens": len(token_inventory),
                "origins": list(by_origin.keys()),
                "tokens_by_origin": {k: [{"key": t["key"], "type": t["storage_type"]} for t in v] 
                                     for k, v in by_origin.items()}
            },
            "recommendation": "Tokens stored in localStorage/sessionStorage are vulnerable to XSS-based theft. These should be cross-referenced with authentication logs."
        })
    
    return findings, token_inventory


def analyze_indexeddb(pkg: Dict, include_values: bool = False) -> Tuple[List[Dict], List[Dict]]:
    """Analyze IndexedDB for auth tokens and sensitive data."""
    findings = []
    token_inventory = []
    
    idb_blob = pkg.get("indexeddbfull.json") or pkg.get("indexeddb.json")
    if not idb_blob:
        findings.append({
            "category": FindingCategory.TOKEN_EXPOSURE.value,
            "severity": Severity.INFO.value,
            "title": "IndexedDB not collected",
            "details": {"status": "artifact_missing"},
            "recommendation": "Re-run collection with content script enabled to capture IndexedDB."
        })
        return findings, token_inventory
    
    for item in records(idb_blob):
        origin = item.get("origin", "")
        databases = item.get("databases", [])
        
        for db in databases:
            db_name = db.get("name", "")
            stores = db.get("objectStores", [])
            
            for store in stores:
                store_name = store.get("name", "")
                store_records = store.get("records", [])
                
                for rec in store_records:
                    # Check both key and value for tokens
                    rec_str = json.dumps(rec) if isinstance(rec, (dict, list)) else str(rec)
                    
                    # Check for JWT patterns in values
                    jwt_matches = JWT_PATTERN.findall(rec_str) if isinstance(rec_str, str) else []
                    
                    # Check for token-like keys
                    is_token = False
                    reason = ""
                    
                    if jwt_matches:
                        is_token = True
                        reason = f"Contains {len(jwt_matches)} JWT(s)"
                    elif isinstance(rec, dict):
                        for k in rec.keys():
                            t, r = looks_like_token(str(k), str(rec.get(k, "")))
                            if t:
                                is_token = True
                                reason = r
                                break
                    
                    if is_token:
                        decoded = {}
                        if jwt_matches:
                            decoded = decode_jwt_noverify(jwt_matches[0])
                        
                        token_entry = {
                            "origin": origin,
                            "database": db_name,
                            "store": store_name,
                            "detection_reason": reason,
                            "decoded": decoded if decoded else None,
                        }
                        if include_values:
                            token_entry["record"] = rec
                        token_inventory.append(token_entry)
    
    if token_inventory:
        findings.append({
            "category": FindingCategory.TOKEN_EXPOSURE.value,
            "severity": Severity.HIGH.value,
            "title": f"Auth tokens found in IndexedDB ({len(token_inventory)} records)",
            "details": {
                "total_records": len(token_inventory),
                "summary": [{"origin": t["origin"], "db": t["database"], "store": t["store"]} 
                           for t in token_inventory[:10]],  # First 10 for summary
            },
            "recommendation": "IndexedDB tokens are as vulnerable to XSS theft as localStorage. Modern SPAs often store JWTs and refresh tokens here."
        })
    
    return findings, token_inventory


# --------------------------------------------------------------------------- #
# HIGH PRIORITY: Performance / Service Workers (AiTM & persistence)
# --------------------------------------------------------------------------- #

def analyze_performance(pkg: Dict) -> List[Dict]:
    """Analyze performance timing for redirect anomalies (AiTM indicator)."""
    findings = []
    perf_blob = pkg.get("performance.json")
    
    if not perf_blob:
        findings.append({
            "category": FindingCategory.AITM.value,
            "severity": Severity.INFO.value,
            "title": "Performance timing not collected",
            "details": {"status": "artifact_missing"},
            "recommendation": "Re-run collection to capture performance timing data."
        })
        return findings
    
    redirect_anomalies = []
    
    for item in records(perf_blob):
        url = item.get("url", item.get("name", ""))
        timing = item.get("timing", item)
        
        # Check for redirects
        redirect_count = timing.get("redirectCount", 0)
        redirect_start = timing.get("redirectStart", 0)
        redirect_end = timing.get("redirectEnd", 0)
        redirect_time = redirect_end - redirect_start if redirect_end and redirect_start else 0
        
        # Check navigation type
        nav_type = timing.get("type", "")
        
        if redirect_count > 0 or redirect_time > 0:
            # Check if redirect went through suspicious domains
            redirect_anomalies.append({
                "url": url,
                "redirect_count": redirect_count,
                "redirect_time_ms": redirect_time,
                "navigation_type": nav_type,
                "dns_time_ms": timing.get("domainLookupEnd", 0) - timing.get("domainLookupStart", 0),
                "connect_time_ms": timing.get("connectEnd", 0) - timing.get("connectStart", 0),
            })
    
    if redirect_anomalies:
        findings.append({
            "category": FindingCategory.AITM.value,
            "severity": Severity.MEDIUM.value,
            "title": f"Redirect chains detected ({len(redirect_anomalies)} pages with redirects)",
            "details": {
                "redirect_anomalies": redirect_anomalies[:20],  # Cap at 20 for report
            },
            "recommendation": "Cross-reference redirect chains with visitdetails to identify AiTM proxy hops."
        })
    
    return findings


def analyze_serviceworkers(pkg: Dict) -> List[Dict]:
    """Analyze service workers for persistence mechanisms."""
    findings = []
    sw_blob = pkg.get("serviceworkers.json")
    
    if not sw_blob:
        return findings  # SW collection failure is common, don't over-report
    
    suspicious_workers = []
    
    for item in records(sw_blob):
        scope = item.get("scope", "")
        script_url = item.get("scriptURL", item.get("active", {}).get("scriptURL", ""))
        state = item.get("state", item.get("active", {}).get("state", ""))
        
        # Flag workers on sensitive origins
        is_suspicious = False
        reason = ""
        
        if any(idp in scope.lower() for idp in ["login.", "auth.", "sso.", "accounts."]):
            is_suspicious = True
            reason = "Service worker on authentication-related origin"
        
        if is_suspicious:
            suspicious_workers.append({
                "scope": scope,
                "script_url": script_url,
                "state": state,
                "reason": reason,
            })
    
    if suspicious_workers:
        findings.append({
            "category": FindingCategory.PERSISTENCE.value,
            "severity": Severity.MEDIUM.value,
            "title": f"Service workers on sensitive origins ({len(suspicious_workers)} found)",
            "details": {"workers": suspicious_workers},
            "recommendation": "Service workers can persist malicious code and intercept requests. Verify these are legitimate."
        })
    
    return findings


# --------------------------------------------------------------------------- #
# MEDIUM PRIORITY: Privacy / Search engines (tampering indicators)
# --------------------------------------------------------------------------- #

def analyze_privacy(pkg: Dict) -> List[Dict]:
    """Analyze privacy settings for security deviations."""
    findings = []
    priv_blob = pkg.get("privacy.json")
    
    if not priv_blob:
        return findings
    
    # Handle both list and dict formats for records
    raw_records = priv_blob.get("settings") or priv_blob.get("records", {})
    if isinstance(raw_records, list):
        settings = raw_records[0] if raw_records else {}
    elif isinstance(raw_records, dict):
        settings = raw_records
    else:
        settings = {}
    
    issues = []
    
    # Check Safe Browsing
    safe_browsing = settings.get("safeBrowsingEnabled", {}).get("value", True)
    if not safe_browsing:
        issues.append({
            "setting": "safeBrowsingEnabled",
            "value": False,
            "expected": True,
            "risk": "Phishing and malware protection disabled"
        })
    
    # Check Do Not Track
    dnt = settings.get("doNotTrackEnabled", {}).get("value")
    
    # Check third-party cookies
    third_party = settings.get("thirdPartyCookiesAllowed", {}).get("value")
    
    # Check hyperlink auditing
    hyperlink_audit = settings.get("hyperlinkAuditingEnabled", {}).get("value", True)
    
    if issues:
        findings.append({
            "category": FindingCategory.CONFIG_DRIFT.value,
            "severity": Severity.MEDIUM.value,
            "title": "Security settings deviate from secure defaults",
            "details": {"issues": issues},
            "recommendation": "Safe Browsing disabled significantly increases phishing risk. This may indicate intentional tampering."
        })
    
    return findings


def analyze_search_engines(pkg: Dict) -> List[Dict]:
    """Analyze search engine settings for hijacking."""
    findings = []
    se_blob = pkg.get("searchengines.json")
    
    if not se_blob:
        return findings
    
    # Known legitimate default search engines
    LEGITIMATE_ENGINES = {
        "google.com", "bing.com", "duckduckgo.com", "yahoo.com",
        "ecosia.org", "brave.com", "startpage.com", "qwant.com"
    }
    
    for item in records(se_blob):
        is_default = item.get("isDefault", False)
        name = item.get("name", "")
        url = item.get("url", "") or item.get("searchUrl", "")
        
        if is_default and url:
            # Extract domain from search URL
            import urllib.parse
            try:
                parsed = urllib.parse.urlparse(url)
                domain = parsed.netloc.lower()
                base_domain = ".".join(domain.split(".")[-2:]) if domain.count(".") > 1 else domain
                
                if base_domain not in LEGITIMATE_ENGINES:
                    findings.append({
                        "category": FindingCategory.TAMPERING.value,
                        "severity": Severity.MEDIUM.value,
                        "title": f"Non-standard default search engine: {name}",
                        "details": {
                            "engine_name": name,
                            "search_url": url,
                            "domain": domain,
                        },
                        "recommendation": "Non-standard search engines may indicate adware/browser hijacking or could be used for data collection."
                    })
            except Exception:
                pass
    
    return findings


# --------------------------------------------------------------------------- #
# MEDIUM PRIORITY: Sessions / WebAuthn (context & triage)
# --------------------------------------------------------------------------- #

def analyze_sessions(pkg: Dict) -> List[Dict]:
    """Analyze recently closed sessions for timeline context."""
    findings = []
    sess_blob = pkg.get("sessions.json")
    
    if not sess_blob:
        return findings
    
    # Extract recently closed tabs for timeline enrichment
    recently_closed = []
    for item in records(sess_blob):
        tab = item.get("tab", {})
        window = item.get("window", {})
        
        if tab:
            recently_closed.append({
                "type": "tab",
                "url": tab.get("url", ""),
                "title": tab.get("title", ""),
                "lastModified": item.get("lastModified"),
            })
        elif window:
            tabs = window.get("tabs", [])
            for t in tabs:
                recently_closed.append({
                    "type": "window_tab",
                    "url": t.get("url", ""),
                    "title": t.get("title", ""),
                    "lastModified": item.get("lastModified"),
                })
    
    # Check for auth-related URLs in recently closed
    auth_urls = [rc for rc in recently_closed 
                 if any(x in rc.get("url", "").lower() 
                       for x in ["login", "auth", "signin", "oauth", "sso"])]
    
    if auth_urls:
        findings.append({
            "category": FindingCategory.TOKEN_EXPOSURE.value,
            "severity": Severity.INFO.value,
            "title": f"Auth-related pages in recently closed ({len(auth_urls)} tabs)",
            "details": {
                "auth_urls": [{"url": u["url"], "title": u["title"]} for u in auth_urls[:10]],
            },
            "recommendation": "Review recently closed auth pages for context on user's authentication activity."
        })
    
    return findings


def analyze_webauthn(pkg: Dict) -> List[Dict]:
    """Analyze WebAuthn/FIDO support for AiTM triage."""
    findings = []
    wa_blob = pkg.get("webauthn.json")
    
    if not wa_blob:
        findings.append({
            "category": FindingCategory.AITM.value,
            "severity": Severity.INFO.value,
            "title": "WebAuthn capabilities not collected",
            "details": {"status": "artifact_missing"},
            "recommendation": "WebAuthn/FIDO2 support indicates whether passkeys could have defeated an AiTM attack."
        })
        return findings
    
    settings = wa_blob.get("settings") or wa_blob.get("records", [{}])[0] if wa_blob else {}
    
    platform_auth = settings.get("isUserVerifyingPlatformAuthenticatorAvailable", False)
    conditional_ui = settings.get("isConditionalMediationAvailable", False)
    
    if platform_auth or conditional_ui:
        findings.append({
            "category": FindingCategory.AITM.value,
            "severity": Severity.INFO.value,
            "title": "WebAuthn/FIDO2 support available",
            "details": {
                "platform_authenticator": platform_auth,
                "conditional_ui": conditional_ui,
            },
            "recommendation": "If targeted services supported FIDO2/passkeys and user had them configured, AiTM token theft should have been defeated. Verify if passkeys were in use."
        })
    
    return findings


# --------------------------------------------------------------------------- #
# Domain Intelligence (Online + Offline Heuristics)
# --------------------------------------------------------------------------- #

import socket
import math

# Cache for WHOIS results to avoid repeated lookups
_whois_cache: Dict[str, Dict] = {}

# WHOIS servers by TLD
WHOIS_SERVERS = {
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'info': 'whois.afilias.net',
    'io': 'whois.nic.io',
    'co': 'whois.nic.co',
    'xyz': 'whois.nic.xyz',
    'top': 'whois.nic.top',
    'club': 'whois.nic.club',
    'online': 'whois.nic.online',
    'site': 'whois.nic.site',
    'tech': 'whois.nic.tech',
    'app': 'whois.nic.google',
    'dev': 'whois.nic.google',
}

# RDAP bootstrap servers
RDAP_BOOTSTRAP = "https://rdap.org/domain/"


def query_whois(domain: str, timeout: int = 5) -> Optional[Dict]:
    """Query WHOIS for domain registration info. Returns creation date if found."""
    if domain in _whois_cache:
        return _whois_cache[domain]
    
    # Extract TLD
    parts = domain.lower().split('.')
    if len(parts) < 2:
        return None
    tld = parts[-1]
    
    whois_server = WHOIS_SERVERS.get(tld)
    if not whois_server:
        # Try generic lookup
        whois_server = f"whois.nic.{tld}"
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((whois_server, 43))
        sock.send(f"{domain}\r\n".encode())
        
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        
        response_text = response.decode('utf-8', errors='replace')
        
        # Parse creation date (various formats)
        creation_date = None
        creation_patterns = [
            r'Creation Date:\s*(\d{4}-\d{2}-\d{2})',
            r'Created Date:\s*(\d{4}-\d{2}-\d{2})',
            r'Registration Time:\s*(\d{4}-\d{2}-\d{2})',
            r'created:\s*(\d{4}-\d{2}-\d{2})',
            r'Creation Date:\s*(\d{4}\.\d{2}\.\d{2})',
            r'Registered on:\s*(\d{2}-\w{3}-\d{4})',  # UK format
        ]
        
        for pattern in creation_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                date_str = match.group(1)
                # Try parsing various formats
                for fmt in ['%Y-%m-%d', '%Y.%m.%d', '%d-%b-%Y']:
                    try:
                        creation_date = datetime.strptime(date_str, fmt)
                        break
                    except ValueError:
                        continue
                if creation_date:
                    break
        
        result = {
            "creation_date": creation_date,
            "raw_length": len(response_text),
            "whois_server": whois_server,
        }
        _whois_cache[domain] = result
        return result
        
    except (socket.timeout, socket.error, ConnectionRefusedError) as e:
        _whois_cache[domain] = {"error": str(e)}
        return None


def query_rdap(domain: str, timeout: int = 5) -> Optional[Dict]:
    """Query RDAP for domain info (JSON-based, more reliable than WHOIS)."""
    if domain in _whois_cache:
        return _whois_cache[domain]
    
    try:
        import urllib.request
        import ssl
        
        url = f"{RDAP_BOOTSTRAP}{domain}"
        ctx = ssl.create_default_context()
        
        req = urllib.request.Request(url, headers={'Accept': 'application/rdap+json'})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        
        # Extract registration date from events
        creation_date = None
        for event in data.get('events', []):
            if event.get('eventAction') == 'registration':
                date_str = event.get('eventDate', '')
                try:
                    # RDAP uses ISO format
                    creation_date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                except ValueError:
                    pass
        
        result = {
            "creation_date": creation_date,
            "registrar": data.get('entities', [{}])[0].get('vcardArray', [[],[]])[1] if data.get('entities') else None,
            "status": data.get('status', []),
        }
        _whois_cache[domain] = result
        return result
        
    except Exception as e:
        _whois_cache[domain] = {"error": str(e)}
        return None


def calculate_domain_entropy(domain: str) -> float:
    """Calculate Shannon entropy of domain name (high entropy = possibly DGA)."""
    # Remove TLD for analysis
    parts = domain.lower().split('.')
    if len(parts) > 1:
        name = '.'.join(parts[:-1])
    else:
        name = domain
    
    if not name:
        return 0.0
    
    # Calculate character frequency
    freq = {}
    for char in name:
        freq[char] = freq.get(char, 0) + 1
    
    # Shannon entropy
    entropy = 0.0
    length = len(name)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy


def calculate_levenshtein(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return calculate_levenshtein(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


# Popular brands for typosquatting detection
POPULAR_BRANDS = [
    'google', 'microsoft', 'apple', 'amazon', 'facebook', 'netflix', 'paypal',
    'instagram', 'twitter', 'linkedin', 'dropbox', 'github', 'zoom', 'slack',
    'adobe', 'oracle', 'salesforce', 'shopify', 'stripe', 'coinbase', 'binance',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'usbank',
    'outlook', 'office365', 'onedrive', 'sharepoint', 'teams',
    'gmail', 'youtube', 'drive', 'docs', 'sheets',
]


def check_brand_similarity(domain: str) -> Optional[Tuple[str, int]]:
    """Check if domain is similar to a popular brand (typosquatting)."""
    # Remove TLD
    parts = domain.lower().split('.')
    if len(parts) > 1:
        name = parts[0]  # Just the main part
    else:
        name = domain
    
    # Remove common prefixes/suffixes
    for prefix in ['www', 'login', 'secure', 'account', 'my', 'get', 'go']:
        if name.startswith(prefix) and len(name) > len(prefix) + 3:
            name = name[len(prefix):]
    
    for suffix in ['login', 'secure', 'account', 'online', 'verify', 'update', 'help']:
        if name.endswith(suffix) and len(name) > len(suffix) + 3:
            name = name[:-len(suffix)]
    
    best_match = None
    best_distance = float('inf')
    
    for brand in POPULAR_BRANDS:
        distance = calculate_levenshtein(name, brand)
        # Flag if very close but not exact
        if 0 < distance <= 2 and len(name) >= 4:
            if distance < best_distance:
                best_distance = distance
                best_match = brand
    
    if best_match:
        return (best_match, best_distance)
    return None


def is_dga_like(domain: str) -> Tuple[bool, str]:
    """Check if domain looks like it was generated by a DGA."""
    parts = domain.lower().split('.')
    if len(parts) > 1:
        name = parts[0]
    else:
        name = domain
    
    if len(name) < 6:
        return False, ""
    
    # High entropy (random-looking)
    entropy = calculate_domain_entropy(domain)
    if entropy > 4.0 and len(name) > 10:
        return True, f"High entropy ({entropy:.2f})"
    
    # Consonant/vowel ratio analysis
    vowels = set('aeiou')
    consonants = set('bcdfghjklmnpqrstvwxyz')
    
    v_count = sum(1 for c in name if c in vowels)
    c_count = sum(1 for c in name if c in consonants)
    
    if c_count > 0 and v_count > 0:
        ratio = c_count / v_count
        # Normal English has ratio around 1.5-2.5
        if ratio > 5.0 or ratio < 0.3:
            return True, f"Unusual consonant/vowel ratio ({ratio:.2f})"
    
    # Long strings of consonants
    consonant_runs = re.findall(r'[bcdfghjklmnpqrstvwxyz]{5,}', name)
    if consonant_runs:
        return True, f"Long consonant sequences: {consonant_runs}"
    
    # Numeric patterns mixed with letters
    if re.search(r'[a-z]+\d+[a-z]+\d+', name) or re.search(r'\d+[a-z]+\d+[a-z]+', name):
        return True, "Mixed letter/number pattern"
    
    return False, ""


def analyze_domain_reputation(domain: str, online: bool = False) -> Dict:
    """Comprehensive domain analysis combining online and offline heuristics."""
    result = {
        "domain": domain,
        "issues": [],
        "risk_score": 0,
        "creation_date": None,
        "age_days": None,
    }
    
    tld = _get_tld(domain)
    
    # Offline heuristics (always run)
    
    # 1. Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        result["issues"].append(f"Suspicious TLD: {tld}")
        result["risk_score"] += 30
    
    # 2. Typosquatting check
    typo = _check_typosquatting(domain)
    if typo:
        result["issues"].append(typo)
        result["risk_score"] += 50
    
    # 3. Brand similarity (Levenshtein)
    brand_match = check_brand_similarity(domain)
    if brand_match:
        result["issues"].append(f"Similar to '{brand_match[0]}' (distance: {brand_match[1]})")
        result["risk_score"] += 40
    
    # 4. DGA-like pattern
    is_dga, dga_reason = is_dga_like(domain)
    if is_dga:
        result["issues"].append(f"DGA-like pattern: {dga_reason}")
        result["risk_score"] += 35
    
    # 5. Entropy check
    entropy = calculate_domain_entropy(domain)
    if entropy > 3.8:
        result["issues"].append(f"High domain entropy ({entropy:.2f})")
        result["risk_score"] += 15
    
    # 6. Suspicious keywords in domain
    suspicious_keywords = ['secure', 'login', 'verify', 'update', 'account', 'signin', 
                          'confirm', 'authenticate', 'validate', 'banking', 'wallet']
    domain_lower = domain.lower()
    found_keywords = [kw for kw in suspicious_keywords if kw in domain_lower]
    if found_keywords and tld in SUSPICIOUS_TLDS:
        result["issues"].append(f"Phishing keywords + suspicious TLD: {found_keywords}")
        result["risk_score"] += 40
    
    # Online heuristics (only if enabled)
    if online:
        # Try RDAP first (more reliable), fall back to WHOIS
        whois_data = query_rdap(domain) or query_whois(domain)
        
        if whois_data and whois_data.get("creation_date"):
            creation = whois_data["creation_date"]
            result["creation_date"] = creation.isoformat() if creation else None
            
            # Calculate age
            now = datetime.now(timezone.utc) if creation.tzinfo else datetime.now()
            age = now - creation
            result["age_days"] = age.days
            
            # Flag newly registered domains
            if age.days < 30:
                result["issues"].append(f"Newly registered domain ({age.days} days old)")
                result["risk_score"] += 50
            elif age.days < 90:
                result["issues"].append(f"Recently registered domain ({age.days} days old)")
                result["risk_score"] += 25
    
    return result


# --------------------------------------------------------------------------- #
# SEO Poisoning Detection
# --------------------------------------------------------------------------- #

# Search engine patterns
SEARCH_ENGINE_PATTERNS = [
    r'google\.[a-z]+/search',
    r'bing\.com/search',
    r'duckduckgo\.com/',
    r'yahoo\.com/search',
    r'yandex\.[a-z]+/search',
    r'baidu\.com/s\?',
    r'ecosia\.org/search',
]

# Suspicious TLDs often used in SEO poisoning
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.work', '.click', '.link', '.download',
    '.gq', '.ml', '.cf', '.ga', '.tk',  # Free TLDs abused for phishing
    '.zip', '.mov',  # New confusable TLDs
    '.buzz', '.surf', '.monster', '.cam', '.rest',
}

# High-risk download extensions
HIGH_RISK_EXTENSIONS = {
    '.exe', '.msi', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs',
    '.js', '.jse', '.wsf', '.wsh', '.hta', '.jar', '.com', '.pif',
    '.application', '.gadget', '.msp', '.msc', '.cpl',
    '.iso', '.img', '.dmg',  # Disk images often used for malware delivery
}

# Software terms commonly targeted by SEO poisoning
SEO_POISON_BAIT_TERMS = [
    'crack', 'keygen', 'serial', 'patch', 'activator', 'loader',
    'free download', 'full version', 'portable', 'nulled', 'warez',
    'driver', 'update', 'installer', 'setup',
    'zoom', 'teams', 'slack', 'discord',  # Popular app names
    'adobe', 'office', 'windows', 'antivirus',
    'vpn', 'password manager', 'recovery tool',
]


def _extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""


def _get_tld(domain: str) -> str:
    """Extract TLD from domain."""
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.' + parts[-1]
    return ''


def _is_search_url(url: str) -> Tuple[bool, Optional[str]]:
    """Check if URL is a search engine results page, return (is_search, query)."""
    url_lower = url.lower()
    for pattern in SEARCH_ENGINE_PATTERNS:
        if re.search(pattern, url_lower):
            # Try to extract query
            try:
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                query = params.get('q', params.get('query', params.get('wd', [None])))[0]
                return True, query
            except Exception:
                return True, None
    return False, None


def _check_typosquatting(domain: str) -> Optional[str]:
    """Check for common typosquatting patterns."""
    legitimate_domains = {
        'google': ['gooogle', 'googel', 'g00gle', 'gogle', 'googlle'],
        'microsoft': ['mircosoft', 'microsft', 'micros0ft', 'micosoft'],
        'amazon': ['amaz0n', 'amazn', 'amazonn', 'arnazon'],
        'facebook': ['faceb00k', 'facebok', 'faceboook'],
        'apple': ['appel', 'aple', 'app1e'],
        'paypal': ['paypa1', 'paypai', 'paypall'],
        'netflix': ['netfiix', 'netfl1x', 'netfllx'],
        'zoom': ['z00m', 'zooom', 'zom'],
        'dropbox': ['dr0pbox', 'dropb0x', 'dropboxs'],
        'github': ['githud', 'g1thub', 'glthub'],
    }
    
    domain_lower = domain.lower()
    for legit, typos in legitimate_domains.items():
        for typo in typos:
            if typo in domain_lower:
                return f"Possible typosquat of '{legit}'"
    
    # Check for homograph attacks (mixed scripts) - simplified check
    if any(ord(c) > 127 for c in domain):
        return "Contains non-ASCII characters (possible homograph attack)"
    
    return None


def analyze_seo_poisoning(pkg: Dict, online: bool = False) -> List[Dict]:
    """Detect SEO poisoning attack patterns.
    
    Args:
        pkg: BAI package data
        online: If True, perform WHOIS/RDAP lookups for domain age analysis
    """
    findings = []
    
    history = records(pkg.get("history.json"))
    visits = records(pkg.get("visitdetails.json"))
    downloads = records(pkg.get("downloads.json"))
    
    if not history:
        return findings
    
    # Build timeline of events
    events = []
    
    for h in history:
        ts = from_chrome_micros(h.get("lastVisitTime"))
        url = h.get("url", "")
        is_search, query = _is_search_url(url)
        events.append({
            "ts": ts,
            "type": "search" if is_search else "visit",
            "url": url,
            "query": query,
            "title": h.get("title", ""),
        })
    
    for d in downloads:
        ts = parse_iso(d.get("startTime")) or from_epoch_seconds(d.get("startTime"))
        events.append({
            "ts": ts,
            "type": "download",
            "url": d.get("finalUrl") or d.get("url", ""),
            "filename": d.get("filename", ""),
            "danger": d.get("danger", ""),
            "mime": d.get("mime", ""),
        })
    
    # Sort by timestamp
    events = [e for e in events if e["ts"]]
    events.sort(key=lambda e: e["ts"])
    
    # Pattern 1: Search → Suspicious domain visit → Download within short window
    seo_chains = []
    for i, event in enumerate(events):
        if event["type"] != "search":
            continue
        
        query = event.get("query", "") or ""
        # Check if search query contains bait terms
        is_bait_query = any(term in query.lower() for term in SEO_POISON_BAIT_TERMS)
        
        # Look for suspicious activity within 5 minutes of search
        window_end = event["ts"] + timedelta(minutes=5) if event["ts"] else None
        
        chain = {"search": event, "visits": [], "downloads": []}
        
        for j in range(i + 1, len(events)):
            next_event = events[j]
            if window_end and next_event["ts"] and next_event["ts"] > window_end:
                break
            
            if next_event["type"] == "visit":
                domain = _extract_domain(next_event["url"])
                
                # Use enhanced domain reputation analysis
                domain_analysis = analyze_domain_reputation(domain, online=online)
                
                if domain_analysis["risk_score"] > 20 or domain_analysis["issues"]:
                    chain["visits"].append({
                        **next_event,
                        "domain": domain,
                        "domain_analysis": domain_analysis,
                    })
            
            elif next_event["type"] == "download":
                filename = next_event.get("filename", "").lower()
                ext = os.path.splitext(filename)[1] if filename else ""
                
                if ext in HIGH_RISK_EXTENSIONS:
                    chain["downloads"].append({
                        **next_event,
                        "high_risk_extension": ext,
                    })
        
        # Report if we found suspicious activity after search
        if chain["visits"] or chain["downloads"]:
            severity = Severity.HIGH if (is_bait_query and chain["downloads"]) else Severity.MEDIUM
            seo_chains.append({
                "chain": chain,
                "bait_query": is_bait_query,
                "severity": severity,
            })
    
    if seo_chains:
        # Deduplicate and report most severe
        high_severity = [c for c in seo_chains if c["severity"] == Severity.HIGH]
        
        if high_severity:
            findings.append({
                "category": FindingCategory.SEO_POISONING.value,
                "severity": Severity.HIGH.value,
                "title": f"SEO poisoning pattern detected ({len(high_severity)} high-risk chains)",
                "details": {
                    "chains": [{
                        "search_query": c["chain"]["search"].get("query"),
                        "search_url": c["chain"]["search"].get("url"),
                        "suspicious_visits": len(c["chain"]["visits"]),
                        "downloads": [d.get("filename") for d in c["chain"]["downloads"]],
                    } for c in high_severity[:5]],  # Top 5
                },
                "recommendation": "User searched for potentially risky terms (cracks, keygens, drivers), "
                                  "visited suspicious domains, and downloaded executables. Classic SEO "
                                  "poisoning infostealer delivery pattern. Investigate downloaded files."
            })
        
        med_severity = [c for c in seo_chains if c["severity"] == Severity.MEDIUM]
        if med_severity and not high_severity:
            findings.append({
                "category": FindingCategory.SEO_POISONING.value,
                "severity": Severity.MEDIUM.value,
                "title": f"Potential SEO poisoning activity ({len(med_severity)} suspicious chains)",
                "details": {
                    "chains": [{
                        "search_query": c["chain"]["search"].get("query"),
                        "suspicious_domains": [v.get("domain") for v in c["chain"]["visits"]],
                    } for c in med_severity[:5]],
                },
                "recommendation": "Search activity followed by visits to suspicious TLDs or typosquatting "
                                  "domains. May indicate SEO poisoning attempt."
            })
    
    # Pattern 2: Check all downloads for suspicious characteristics
    suspicious_downloads = []
    for d in downloads:
        url = d.get("finalUrl") or d.get("url", "")
        domain = _extract_domain(url)
        filename = d.get("filename", "").lower()
        ext = os.path.splitext(filename)[1] if filename else ""
        danger = d.get("danger", "")
        
        issues = []
        severity = Severity.INFO
        
        # Check file extension
        if ext in HIGH_RISK_EXTENSIONS:
            issues.append(f"High-risk file type: {ext}")
            severity = Severity.MEDIUM
        
        # Check domain TLD
        tld = _get_tld(domain)
        if tld in SUSPICIOUS_TLDS:
            issues.append(f"Download from suspicious TLD: {tld}")
            severity = Severity.HIGH
        
        # Check for typosquatting
        typo = _check_typosquatting(domain)
        if typo:
            issues.append(typo)
            severity = Severity.HIGH
        
        # Check Chrome's danger assessment
        if danger and danger not in ("safe", "accepted"):
            issues.append(f"Chrome flagged as: {danger}")
            if danger in ("dangerous", "uncommon", "potentially_unwanted"):
                severity = Severity.HIGH
        
        if issues:
            suspicious_downloads.append({
                "filename": d.get("filename"),
                "url": url,
                "domain": domain,
                "issues": issues,
                "severity": severity.value,
                "danger": danger,
                "timestamp": d.get("startTime"),
            })
    
    if suspicious_downloads:
        high_risk = [d for d in suspicious_downloads if d["severity"] == "HIGH"]
        if high_risk:
            findings.append({
                "category": FindingCategory.SUSPICIOUS_DOWNLOAD.value,
                "severity": Severity.HIGH.value,
                "title": f"High-risk downloads detected ({len(high_risk)} files)",
                "details": {
                    "downloads": high_risk[:10],
                },
                "recommendation": "Downloads from suspicious sources with high-risk file types. "
                                  "Likely infostealer or malware delivery. Verify file hashes against "
                                  "threat intel and check for execution evidence."
            })
    
    return findings


# --------------------------------------------------------------------------- #
# Malvertising Detection
# --------------------------------------------------------------------------- #

# Ad network and tracking domains
AD_NETWORK_PATTERNS = [
    r'doubleclick\.net', r'googlesyndication\.com', r'googleadservices\.com',
    r'adsense', r'adnxs\.com', r'advertising\.com', r'taboola\.com',
    r'outbrain\.com', r'criteo\.', r'amazon-adsystem\.com', r'fbcdn\.net',
    r'ad\.', r'ads\.', r'adserver\.', r'tracking\.', r'pixel\.',
    r'analytics\.', r'telemetry\.', r'beacon\.',
]


def _is_ad_domain(domain: str) -> bool:
    """Check if domain appears to be an ad/tracking domain."""
    domain_lower = domain.lower()
    for pattern in AD_NETWORK_PATTERNS:
        if re.search(pattern, domain_lower):
            return True
    return False


def analyze_malvertising(pkg: Dict) -> List[Dict]:
    """Detect malvertising indicators."""
    findings = []
    
    # Check for service workers registered by ad domains
    sw_blob = pkg.get("serviceworkers.json")
    ad_serviceworkers = []
    
    for item in records(sw_blob):
        scope = item.get("scope", "")
        script_url = item.get("scriptURL", item.get("active", {}).get("scriptURL", ""))
        
        scope_domain = _extract_domain(scope)
        script_domain = _extract_domain(script_url)
        
        if _is_ad_domain(scope_domain) or _is_ad_domain(script_domain):
            ad_serviceworkers.append({
                "scope": scope,
                "script_url": script_url,
                "scope_domain": scope_domain,
            })
    
    if ad_serviceworkers:
        findings.append({
            "category": FindingCategory.MALVERTISING.value,
            "severity": Severity.MEDIUM.value,
            "title": f"Service workers from ad/tracking domains ({len(ad_serviceworkers)} found)",
            "details": {"workers": ad_serviceworkers},
            "recommendation": "Ad network service workers can persist malicious code. While some are "
                              "legitimate for ad functionality, they can also be abused for malvertising. "
                              "Review if unexpected or if user experienced suspicious ad behavior."
        })
    
    # Check for downloads initiated shortly after ad domain visits
    history = records(pkg.get("history.json"))
    downloads = records(pkg.get("downloads.json"))
    
    # Build ad visit timeline
    ad_visits = []
    for h in history:
        url = h.get("url", "")
        domain = _extract_domain(url)
        if _is_ad_domain(domain):
            ts = from_chrome_micros(h.get("lastVisitTime"))
            ad_visits.append({"ts": ts, "url": url, "domain": domain})
    
    # Check for downloads within 60 seconds of ad domain activity
    ad_triggered_downloads = []
    for d in downloads:
        dl_ts = parse_iso(d.get("startTime")) or from_epoch_seconds(d.get("startTime"))
        if not dl_ts:
            continue
        
        for av in ad_visits:
            if av["ts"] and abs((dl_ts - av["ts"]).total_seconds()) < 60:
                filename = d.get("filename", "").lower()
                ext = os.path.splitext(filename)[1] if filename else ""
                
                if ext in HIGH_RISK_EXTENSIONS:
                    ad_triggered_downloads.append({
                        "download": d.get("filename"),
                        "download_url": d.get("finalUrl") or d.get("url"),
                        "ad_domain": av["domain"],
                        "time_delta_seconds": abs((dl_ts - av["ts"]).total_seconds()),
                    })
    
    if ad_triggered_downloads:
        findings.append({
            "category": FindingCategory.MALVERTISING.value,
            "severity": Severity.HIGH.value,
            "title": f"Downloads triggered near ad activity ({len(ad_triggered_downloads)} instances)",
            "details": {"downloads": ad_triggered_downloads[:10]},
            "recommendation": "Executable downloads occurred within seconds of ad network activity. "
                              "This is a strong indicator of malvertising-based malware delivery. "
                              "Investigate the downloaded files for infostealer payloads."
        })
    
    # Check for extensions that might be ad-injectors
    ext_blob = pkg.get("extensions.json")
    ad_injector_indicators = []
    
    for ext in records(ext_blob):
        if not ext.get("enabled"):
            continue
        
        name = ext.get("name", "").lower()
        desc = ext.get("description", "").lower()
        permissions = ext.get("permissions", []) or []
        host_perms = ext.get("hostPermissions", []) or []
        
        # Check for ad-injector patterns
        issues = []
        
        # Extensions that modify web requests and have broad access
        if "webRequest" in permissions and ("<all_urls>" in host_perms or "*://*/*" in host_perms):
            if any(term in name + desc for term in ["ad", "shop", "deal", "coupon", "price", "save"]):
                issues.append("Ad/shopping extension with network interception capability")
        
        # Check for scripting + broad access (can inject content)
        if "scripting" in permissions and ("<all_urls>" in host_perms or "*://*/*" in host_perms):
            issues.append("Can inject scripts into any page")
        
        if issues and ext.get("installType") in ("sideload", "development"):
            ad_injector_indicators.append({
                "name": ext.get("name"),
                "id": ext.get("id"),
                "install_type": ext.get("installType"),
                "issues": issues,
            })
    
    if ad_injector_indicators:
        findings.append({
            "category": FindingCategory.MALVERTISING.value,
            "severity": Severity.HIGH.value,
            "title": f"Potential ad-injector extensions ({len(ad_injector_indicators)} found)",
            "details": {"extensions": ad_injector_indicators},
            "recommendation": "Sideloaded extensions with ad/shopping functionality and broad permissions "
                              "are commonly used for malvertising. They can inject malicious ads, redirect "
                              "traffic, or steal data. Verify legitimacy and consider removal."
        })
    
    return findings


# --------------------------------------------------------------------------- #
# Extension Timeline Correlation (install time vs visit history)
# --------------------------------------------------------------------------- #

def analyze_extension_timeline(pkg: Dict) -> List[Dict]:
    """Correlate extension installations with browsing history."""
    findings = []
    
    ext_blob = pkg.get("extensions.json")
    history = records(pkg.get("history.json"))
    
    if not ext_blob or not history:
        return findings
    
    # Check for sideloaded extensions and try to find related history
    suspicious_correlations = []
    
    for ext in records(ext_blob):
        if ext.get("installType") not in ("sideload", "development"):
            continue
        if not ext.get("enabled"):
            continue
        
        name = ext.get("name", "")
        ext_id = ext.get("id", "")
        
        # Look for history entries that might relate to this extension
        # (download pages, install prompts, etc.)
        related_history = []
        
        for h in history:
            url = h.get("url", "").lower()
            title = h.get("title", "").lower()
            
            # Check if history entry might be related to extension install
            if any(term in url + title for term in [
                ext_id.lower()[:10] if ext_id else "",
                name.lower().split()[0] if name else "",
                "extension", "addon", "chrome-extension", "crx",
                "install", "download",
            ]) and ext_id.lower()[:10]:  # Only if we have a meaningful ext_id
                ts = from_chrome_micros(h.get("lastVisitTime"))
                related_history.append({
                    "url": h.get("url"),
                    "title": h.get("title"),
                    "timestamp": ts.isoformat() if ts else None,
                })
        
        # Also check for suspicious domains visited around the same time
        # (This is heuristic - we don't have exact install time from BAI)
        
        if related_history:
            suspicious_correlations.append({
                "extension_name": name,
                "extension_id": ext_id,
                "install_type": ext.get("installType"),
                "possibly_related_history": related_history[:5],
            })
    
    if suspicious_correlations:
        findings.append({
            "category": FindingCategory.DELIVERY_VECTOR.value,
            "severity": Severity.MEDIUM.value,
            "title": f"Sideloaded extensions with possible install history ({len(suspicious_correlations)} found)",
            "details": {"correlations": suspicious_correlations},
            "recommendation": "Review the browsing history around extension installation to understand "
                              "how the user was led to install these sideloaded extensions. May indicate "
                              "social engineering or malicious download site."
        })
    
    return findings


# --------------------------------------------------------------------------- #
# Cookie analysis (existing functionality enhanced)
# --------------------------------------------------------------------------- #

def analyze_cookies(cookie_blob: Dict, include_values: bool = False) -> Tuple[List[Dict], List[Dict]]:
    """Return (auth_sessions, all_idp_cookies)."""
    sessions = {}
    idp_cookies = []
    
    for c in records(cookie_blob):
        dom = c.get("domain", "")
        idp = classify_idp(dom)
        name = c.get("name", "")
        if idp is None and not is_auth_cookie(name):
            continue
        
        val = c.get("value", "") or ""
        exp = from_epoch_seconds(c.get("expirationDate"))
        row = {
            "idp": idp or "(generic auth cookie)",
            "domain": dom,
            "cookie": name,
            "httpOnly": c.get("httpOnly"),
            "secure": c.get("secure"),
            "sameSite": c.get("sameSite"),
            "session_cookie": c.get("session"),
            "expires_utc": exp.isoformat() if exp else "session",
            "value_len": len(val),
        }
        if include_values:
            row["value"] = val
        
        decoded = {}
        nl = name.lower()
        if nl in ("estsauth", "estsauthpersistent"):
            decoded.update(decode_entra_home_account(val))
            decoded["token_type"] = ("persistent" if "persistent" in nl else "session")
        elif nl == "ccstate":
            decoded.update(decode_entra_ccstate(val))
        elif val.count(".") == 2 and len(val) > 40:
            decoded.update(decode_jwt_noverify(val))
        if decoded:
            row["decoded"] = decoded
        idp_cookies.append(row)
        
        # Aggregate identity per (idp, registrable-ish domain)
        key = (idp or "generic", dom.lstrip("."))
        s = sessions.setdefault(key, {
            "idp": idp or "(generic auth cookie)",
            "domain": dom.lstrip("."),
            "tenant_id": None, "object_id": None, "upn": None,
            "token_types": set(), "cookie_names": set(),
            "earliest_expiry": None, "latest_expiry": None,
            "any_persistent": False, "any_httponly": False,
        })
        s["cookie_names"].add(name)
        if c.get("httpOnly"):
            s["any_httponly"] = True
        for k in ("tenant_id", "object_id", "upn", "tid", "oid"):
            if k in decoded and decoded[k]:
                tgt = {"tid": "tenant_id", "oid": "object_id"}.get(k, k)
                s[tgt] = s[tgt] or decoded[k]
        if "upn" not in decoded:
            for k in ("preferred_username", "unique_name", "email"):
                if k in decoded and decoded[k] and not s["upn"]:
                    s["upn"] = decoded[k]
        if decoded.get("token_type") == "persistent" or "persistent" in nl:
            s["any_persistent"] = True
            s["token_types"].add("persistent")
        elif nl.startswith("estsauth"):
            s["token_types"].add("session")
        if exp:
            s["earliest_expiry"] = min(s["earliest_expiry"] or exp, exp)
            s["latest_expiry"] = max(s["latest_expiry"] or exp, exp)
    
    final = []
    for s in sessions.values():
        s["token_types"] = sorted(s["token_types"])
        s["cookie_names"] = sorted(s["cookie_names"])
        s["earliest_expiry"] = s["earliest_expiry"].isoformat() if s["earliest_expiry"] else None
        s["latest_expiry"] = s["latest_expiry"].isoformat() if s["latest_expiry"] else None
        final.append(s)
    final.sort(key=lambda x: (x["idp"], x["domain"]))
    return final, idp_cookies


# --------------------------------------------------------------------------- #
# UPN-Centric Identity Discovery
# --------------------------------------------------------------------------- #

def discover_upn_accounts(pkg: Dict) -> List[Dict]:
    """
    Discover user accounts by scanning for UPNs (name@domain.suffix) in:
    1. JWT cookies (decoded claims)
    2. Cookie values (raw and URL-encoded)
    3. Cookie names (underscore-encoded patterns like shane_shook_aus_com)
    4. localStorage/IndexedDB
    5. Page titles in history/visitdetails
    
    Returns list of account dicts with services and their stealable tokens.
    """
    import re
    from urllib.parse import unquote, urlparse
    
    upn_pattern = re.compile(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b')
    # Pattern for underscore-encoded UPNs: firstname_lastname_domain_tld
    underscore_pattern = re.compile(r'\b([a-z]{2,})_([a-z]{2,})_([a-z]{2,})_([a-z]{2,3})\b', re.IGNORECASE)
    
    # Skip patterns that look like UPNs but aren't user accounts
    skip_patterns = ['example.com', 'namprd', 'prod.outlook', 'mail.gmail.com',
                     'cookie', 'tracking', 'consent', 'adobe', 'analytics']
    valid_tlds = {'com', 'net', 'org', 'gov', 'edu', 'us', 'io', 'ai', 'co', 'dev'}
    
    # accounts[upn_lower] = {upn, services: {domain: {tokens: []}}}
    accounts = {}
    
    def add_token(upn: str, service: str, token_info: Dict):
        """Add a token/cookie that evidences this UPN at this service."""
        upn = upn.strip()
        if not upn or '@' not in upn:
            return
        if any(p in upn.lower() for p in skip_patterns):
            return
        local_part = upn.split('@')[0]
        if len(local_part) > 40 or len(local_part) < 2:
            return
            
        upn_lower = upn.lower()
        if upn_lower not in accounts:
            accounts[upn_lower] = {'upn': upn, 'services': {}}
        if service not in accounts[upn_lower]['services']:
            accounts[upn_lower]['services'][service] = {'tokens': []}
        
        # Avoid duplicate tokens
        existing = accounts[upn_lower]['services'][service]['tokens']
        if not any(t.get('cookie_name') == token_info.get('cookie_name') for t in existing):
            accounts[upn_lower]['services'][service]['tokens'].append(token_info)
    
    # 1. COOKIES - Most important source
    for c in records(pkg.get("cookies.json")):
        value = c.get('value', '') or ''
        domain = (c.get('domain', '') or '').lstrip('.')
        cookie_name = c.get('name', '') or ''
        httponly = c.get('httpOnly', False)
        
        # Determine if it's a JWT
        is_jwt = value.count('.') == 2 and len(value) > 50
        
        # 1a. Decode JWT cookies for UPN
        if is_jwt:
            decoded = decode_jwt_noverify(value)
            if decoded:
                for claim in ('upn', 'preferred_username', 'email', 'unique_name', 'sub'):
                    if claim in decoded and '@' in str(decoded[claim]):
                        add_token(decoded[claim], domain, {
                            'cookie_name': cookie_name,
                            'is_jwt': True,
                            'httponly': httponly,
                            'source': 'JWT cookie claim'
                        })
                        break
        
        # 1b. URL-decoded cookie name + value
        combined = unquote(cookie_name + ' ' + value)
        
        # Direct UPN patterns
        for match in upn_pattern.findall(combined):
            add_token(match, domain, {
                'cookie_name': cookie_name,
                'is_jwt': is_jwt,
                'httponly': httponly,
                'source': 'cookie value'
            })
        
        # 1c. Underscore-encoded UPNs (SharePoint style)
        for match in underscore_pattern.findall(combined):
            first, last, dom, tld = match
            if tld.lower() in valid_tlds:
                potential_upn = f'{first}.{last}@{dom}.{tld}'
                add_token(potential_upn, domain, {
                    'cookie_name': cookie_name,
                    'is_jwt': is_jwt,
                    'httponly': httponly,
                    'source': 'URL-encoded in cookie'
                })
    
    # 2. HISTORY/VISITDETAILS - Only extract UPNs from page titles
    for fname in ('history.json', 'visitdetails.json'):
        for r in records(pkg.get(fname)):
            title = r.get('title', '') or ''
            url = r.get('url', '') or ''
            
            try:
                service = urlparse(url).netloc
            except:
                service = 'unknown'
            
            if any(x in url.lower() for x in ['search', 'query=', 'investigate', 'audit']):
                continue
            
            # UPNs in page titles (strong evidence of authenticated session)
            for match in upn_pattern.findall(title):
                if ' - ' in title and (match.lower() in title.lower()):
                    add_token(match, service, {
                        'cookie_name': None,
                        'is_jwt': False,
                        'httponly': None,
                        'source': 'page title (logged in)'
                    })
            
            # Underscore-encoded UPNs in SharePoint personal site URLs
            if '/personal/' in url.lower():
                decoded_url = unquote(url)
                for match in underscore_pattern.findall(decoded_url):
                    first, last, dom, tld = match
                    if tld.lower() in valid_tlds:
                        potential_upn = f'{first}.{last}@{dom}.{tld}'
                        add_token(potential_upn, service, {
                            'cookie_name': None,
                            'is_jwt': False,
                            'httponly': None,
                            'source': 'SharePoint personal site URL'
                        })
    
    # 3. WEBSTORAGE - localStorage
    for ws in records(pkg.get("webstorage.json")):
        try:
            origin = ws.get('origin', '').replace('https://', '').replace('http://', '').split('/')[0]
        except:
            origin = 'unknown'
        
        local_storage = ws.get('localStorage', {}) or {}
        for key, value in local_storage.items():
            value_str = str(value)[:2000]
            
            jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
            for jwt_match in jwt_pattern.findall(value_str):
                decoded = decode_jwt_noverify(jwt_match)
                if decoded:
                    for claim in ('upn', 'preferred_username', 'email', 'sub'):
                        if claim in decoded and '@' in str(decoded[claim]):
                            add_token(decoded[claim], origin, {
                                'cookie_name': f'localStorage[{key}]',
                                'is_jwt': True,
                                'httponly': False,  # localStorage is always JS-accessible
                                'source': 'localStorage JWT'
                            })
                            break
            
            for match in upn_pattern.findall(value_str):
                add_token(match, origin, {
                    'cookie_name': f'localStorage[{key}]',
                    'is_jwt': False,
                    'httponly': False,
                    'source': 'localStorage value'
                })
    
    # 4. INDEXEDDB
    for idb in records(pkg.get("indexeddbfull.json")):
        try:
            origin = idb.get('origin', '').replace('https://', '').replace('http://', '').split('/')[0]
        except:
            origin = 'unknown'
        
        for db in idb.get('databases', []) or []:
            for store in db.get('objectStores', []) or []:
                store_name = store.get('name', '')
                for item in store.get('items', []) or []:
                    value_str = str(item.get('value', ''))[:2000]
                    
                    jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
                    for jwt_match in jwt_pattern.findall(value_str):
                        decoded = decode_jwt_noverify(jwt_match)
                        if decoded:
                            for claim in ('upn', 'preferred_username', 'email', 'sub'):
                                if claim in decoded and '@' in str(decoded[claim]):
                                    add_token(decoded[claim], origin, {
                                        'cookie_name': f'IndexedDB[{store_name}]',
                                        'is_jwt': True,
                                        'httponly': False,
                                        'source': 'IndexedDB JWT'
                                    })
                                    break
    
    # Convert to list format
    result = []
    for upn_lower, info in sorted(accounts.items()):
        has_strong_evidence = False
        services = {}
        
        for svc, details in info['services'].items():
            tokens = details['tokens']
            # Has strong evidence if any token has a cookie_name
            if any(t.get('cookie_name') for t in tokens):
                has_strong_evidence = True
            services[svc] = {'tokens': tokens}
        
        result.append({
            'upn': info['upn'],
            'services': services,
            'has_strong_evidence': has_strong_evidence
        })
    
    result.sort(key=lambda x: (not x['has_strong_evidence'], x['upn'].lower()))
    return result


def discover_tenant_upn_mapping(pkg: Dict) -> Dict[str, str]:
    """
    Build a mapping of Entra tenant IDs to UPNs by analyzing login URLs.
    The login_hint parameter in Microsoft login URLs contains the UPN.
    """
    import re
    from urllib.parse import unquote, urlparse, parse_qs
    
    tenant_to_upn = {}
    upn_pattern = re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
    tenant_pattern = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
    
    # Scan history for Microsoft login URLs with both tenant and login_hint
    for fname in ('history.json', 'visitdetails.json'):
        for r in records(pkg.get(fname)):
            url = r.get('url', '') or ''
            
            # Must be a Microsoft auth URL
            if not any(d in url.lower() for d in ['microsoftonline.com', 'microsoft.com/signin', 
                                                    'login.microsoft', 'security.microsoft']):
                continue
            
            decoded = unquote(url)
            
            # Extract tenant ID from URL
            tenants = tenant_pattern.findall(decoded)
            if not tenants:
                continue
            
            # Look for login_hint or username parameter
            upns = []
            if 'login_hint=' in decoded or 'username=' in decoded:
                upns = upn_pattern.findall(decoded)
            
            # Associate tenant with UPN
            for tenant in tenants:
                tenant_lower = tenant.lower()
                for upn in upns:
                    # Skip investigation subjects (usually in query params for audit searches)
                    if 'audit' in url.lower() and 'searchresults' in url.lower():
                        continue
                    # Prefer UPNs from login_hint
                    if 'login_hint=' in decoded and upn in decoded.split('login_hint=')[-1][:100]:
                        tenant_to_upn[tenant_lower] = upn
                        break
                    elif tenant_lower not in tenant_to_upn:
                        tenant_to_upn[tenant_lower] = upn
    
    return tenant_to_upn


def discover_entra_sessions(pkg: Dict, tenant_upn_map: Dict[str, str] = None) -> List[Dict]:
    """
    Extract Microsoft Entra sessions from ESTSAUTH/ESTSAUTHPERSISTENT cookies.
    These contain tenant_id and object_id even when UPN is encrypted.
    
    If tenant_upn_map is provided, associates UPNs with sessions based on tenant ID.
    """
    sessions = []
    tenant_upn_map = tenant_upn_map or {}
    
    for c in records(pkg.get("cookies.json")):
        cookie_name = (c.get('name', '') or '').lower()
        if cookie_name not in ('estsauth', 'estsauthpersistent'):
            continue
        
        value = c.get('value', '') or ''
        domain = (c.get('domain', '') or '').lstrip('.')
        httponly = c.get('httpOnly', False)
        expiry = c.get('expirationDate')
        
        decoded = decode_entra_home_account(value)
        if decoded and decoded.get('tenant_id'):
            tenant_id = decoded.get('tenant_id', '').lower()
            
            # Look up UPN for this tenant
            upn = tenant_upn_map.get(tenant_id, None)
            
            sessions.append({
                'tenant_id': decoded.get('tenant_id'),
                'object_id': decoded.get('object_id'),
                'upn': upn,  # Associated UPN from login URLs
                'domain': domain,
                'type': 'PERSISTENT' if 'persistent' in cookie_name else 'SESSION',
                'httponly': httponly,
                'cookie_name': c.get('name', ''),
                'expiry': expiry
            })
    
    return sessions


# --------------------------------------------------------------------------- #
# Cross-artifact AiTM view
# --------------------------------------------------------------------------- #

def build_aitm_view(pkg: Dict, findings: List[Dict]) -> Dict:
    """Build a cross-artifact AiTM analysis joining redirect chains + timing + proxy."""
    aitm_view = {
        "proxy_status": "unknown",
        "redirect_chains": [],
        "timing_anomalies": [],
        "overall_risk": Severity.INFO.value,
        "summary": "",
    }
    
    # Extract proxy status from findings
    proxy_findings = [f for f in findings if "proxy" in f.get("title", "").lower()]
    if proxy_findings:
        pf = proxy_findings[0]
        mode = pf.get("details", {}).get("mode", "unknown")
        aitm_view["proxy_status"] = mode
        if mode not in ("system", "direct", ""):
            aitm_view["overall_risk"] = Severity.HIGH.value
    
    # Extract redirect data from visitdetails
    visit_blob = pkg.get("visitdetails.json")
    if visit_blob:
        redirect_chains = []
        for visit in records(visit_blob):
            url = visit.get("url", "")
            transitions = visit.get("visits", [])
            
            for v in transitions:
                transition = v.get("transition", "")
                referring = v.get("referringVisitId", 0)
                
                if "redirect" in transition.lower() or referring:
                    redirect_chains.append({
                        "url": url,
                        "transition": transition,
                        "referring_visit": referring,
                        "visit_time": v.get("visitTime"),
                    })
        
        if redirect_chains:
            aitm_view["redirect_chains"] = redirect_chains[:50]  # Cap for report size
            if len(redirect_chains) > 10:
                aitm_view["overall_risk"] = max(
                    Severity[aitm_view["overall_risk"]], 
                    Severity.MEDIUM
                ).value
    
    # Extract performance anomalies from findings
    perf_findings = [f for f in findings if "redirect" in f.get("title", "").lower()]
    if perf_findings:
        aitm_view["timing_anomalies"] = perf_findings[0].get("details", {}).get("redirect_anomalies", [])
    
    # Build summary
    risk_factors = []
    if aitm_view["proxy_status"] not in ("system", "direct", "unknown", ""):
        risk_factors.append(f"Non-standard proxy ({aitm_view['proxy_status']})")
    if aitm_view["redirect_chains"]:
        risk_factors.append(f"{len(aitm_view['redirect_chains'])} redirect transitions")
    if aitm_view["timing_anomalies"]:
        risk_factors.append(f"{len(aitm_view['timing_anomalies'])} pages with timing anomalies")
    
    if risk_factors:
        aitm_view["summary"] = "AiTM risk factors: " + "; ".join(risk_factors)
    else:
        aitm_view["summary"] = "No significant AiTM indicators detected"
    
    return aitm_view


# --------------------------------------------------------------------------- #
# Session Theft Timeline - Causal Chain Reconstruction
# --------------------------------------------------------------------------- #

# Known IdP authentication domains
IDP_DOMAINS = {
    "login.microsoftonline.com": "Entra ID",
    "login.live.com": "Microsoft Account",
    "accounts.google.com": "Google",
    "auth0.com": "Auth0",
    "okta.com": "Okta",
    "login.okta.com": "Okta",
    "sso.": "SSO Provider",
    "idp.": "IdP Provider",
    "auth.": "Auth Provider",
    "saml.": "SAML IdP",
}

# ESTS persistent cookie default lifetime (days)
ESTS_PERSISTENT_LIFETIME_DAYS = 90


def build_session_theft_timeline(pkg: Dict, auth_sessions: List[Dict]) -> Dict:
    """
    Build a Session Theft Timeline reconstructing the causal chain for token theft.
    
    The assembled chain:
    1. visitdetails referrer-chain dates the lure and auth (causal action → session birth)
    2. ESTS cookie proves the resulting replayable session existed, whose it is, and validity
    3. Cleartext token auth_time (when available) provides precise session birth
    4. Entra sign-in logs (external) date the first replay from TA infrastructure
    
    The theft lives in the gap between session-birth and first-replay.
    BAI uniquely contributes the visitdetails navigation record for causality timing.
    """
    timeline = {
        "stealable_sessions": [],      # ESTS sessions with identity and validity window
        "authentication_flows": [],     # Reconstructed IdP auth flows from visitdetails
        "session_birth_anchors": [],    # auth_time from cleartext tokens
        "causal_events": [],            # Lure/phishing referrer chains
        "dropper_downloads": [],        # Infostealer delivery timestamps
        "theft_windows": [],            # Estimated theft brackets
        "correlation_anchors": [],      # For Entra sign-in log correlation
    }
    
    # -------------------------------------------------------------------------
    # 1. Extract Stealable Sessions (ESTS cookies)
    # -------------------------------------------------------------------------
    for session in auth_sessions:
        if session.get("type") in ("ESTSAUTH", "ESTSAUTHPERSISTENT"):
            stealable = {
                "cookie_name": session.get("name"),
                "domain": session.get("domain"),
                "tenant_id": session.get("identity", {}).get("tenant_id"),
                "object_id": session.get("identity", {}).get("object_id"),
                "upn": session.get("identity", {}).get("upn"),
                "expiration": session.get("expiration"),
                "is_persistent": session.get("type") == "ESTSAUTHPERSISTENT",
                "estimated_birth": None,
                "theft_note": None,
            }
            
            # Estimate session birth from expiration (exp - 90 days for persistent)
            if stealable["is_persistent"] and stealable["expiration"]:
                try:
                    exp_dt = datetime.fromisoformat(stealable["expiration"].replace("Z", "+00:00"))
                    birth_estimate = exp_dt - timedelta(days=ESTS_PERSISTENT_LIFETIME_DAYS)
                    stealable["estimated_birth"] = birth_estimate.isoformat()
                    stealable["theft_note"] = (
                        f"Session birth estimated as {birth_estimate.strftime('%Y-%m-%d')} "
                        f"(expiration - {ESTS_PERSISTENT_LIFETIME_DAYS} days). "
                        "Note: Conditional Access sign-in-frequency may alter this. "
                        "This is the 'loaded gun' - correlate with Entra sign-in logs for first TA replay."
                    )
                except Exception:
                    pass
            
            # Add correlation anchor for Entra
            if stealable["tenant_id"] and stealable["object_id"]:
                timeline["correlation_anchors"].append({
                    "type": "Entra",
                    "tenant_id": stealable["tenant_id"],
                    "object_id": stealable["object_id"],
                    "upn": stealable.get("upn"),
                    "query_guidance": (
                        "In Entra Sign-in Logs, filter by: "
                        f"userId eq '{stealable['object_id']}' or "
                        f"userPrincipalName eq '{stealable.get('upn', 'UNKNOWN')}'. "
                        "Look for: (1) SessionId match, (2) MFA inherited without prompt, "
                        "(3) Location/IP inconsistent with user."
                    ),
                })
            
            timeline["stealable_sessions"].append(stealable)
    
    # -------------------------------------------------------------------------
    # 2. Extract auth_time from cleartext tokens (best session birth anchor)
    # -------------------------------------------------------------------------
    for session in auth_sessions:
        claims = session.get("identity", {})
        if "auth_time" in claims:
            auth_time = claims["auth_time"]
            try:
                if isinstance(auth_time, (int, float)):
                    auth_dt = datetime.utcfromtimestamp(auth_time)
                    auth_time_iso = auth_dt.isoformat() + "Z"
                else:
                    auth_time_iso = str(auth_time)
                
                timeline["session_birth_anchors"].append({
                    "source": session.get("name", "unknown"),
                    "domain": session.get("domain"),
                    "auth_time": auth_time_iso,
                    "auth_time_epoch": auth_time if isinstance(auth_time, (int, float)) else None,
                    "iat": claims.get("iat"),
                    "amr": claims.get("amr"),  # Authentication methods (mfa, pwd, etc.)
                    "note": (
                        "auth_time is the interactive authentication instant (MFA moment). "
                        "This is more precise than iat (which can be a silent refresh). "
                        f"Authentication methods: {claims.get('amr', 'unknown')}"
                    ),
                })
            except Exception:
                pass
    
    # -------------------------------------------------------------------------
    # 3. Reconstruct IdP Authentication Flows from visitdetails
    # -------------------------------------------------------------------------
    visit_blob = pkg.get("visitdetails.json")
    visit_index = {}  # Map visitId to visit for chain reconstruction
    
    if visit_blob:
        for visit in records(visit_blob):
            url = visit.get("url", "")
            visit_list = visit.get("visits", [])
            
            for v in visit_list:
                vid = v.get("visitId")
                if vid:
                    visit_index[vid] = {
                        "url": url,
                        "visit_time": v.get("visitTime"),
                        "transition": v.get("transition", ""),
                        "referring_visit_id": v.get("referringVisitId", 0),
                    }
        
        # Find visits to IdP domains and trace their referrer chains
        for visit in records(visit_blob):
            url = visit.get("url", "")
            
            # Check if this is an IdP authentication URL
            idp_type = None
            for idp_domain, idp_name in IDP_DOMAINS.items():
                if idp_domain in url.lower():
                    idp_type = idp_name
                    break
            
            if not idp_type:
                continue
            
            visit_list = visit.get("visits", [])
            for v in visit_list:
                visit_time = v.get("visitTime")
                transition = v.get("transition", "")
                referring_id = v.get("referringVisitId", 0)
                
                # Build the referrer chain
                chain = []
                chain.append({
                    "url": url,
                    "transition": transition,
                    "visit_time": visit_time,
                    "role": "IdP authentication"
                })
                
                # Walk back the referrer chain
                current_ref = referring_id
                depth = 0
                while current_ref and current_ref in visit_index and depth < 10:
                    ref_visit = visit_index[current_ref]
                    
                    # Determine role based on transition type
                    ref_transition = ref_visit.get("transition", "")
                    role = "referrer"
                    if "link" in ref_transition.lower():
                        role = "link click (possible phishing email/page)"
                    elif "typed" in ref_transition.lower():
                        role = "typed URL (possible pharming/direct)"
                    elif "reload" in ref_transition.lower():
                        role = "page reload"
                    elif "form_submit" in ref_transition.lower():
                        role = "form submission"
                    
                    chain.append({
                        "url": ref_visit.get("url"),
                        "transition": ref_transition,
                        "visit_time": ref_visit.get("visit_time"),
                        "role": role,
                    })
                    
                    current_ref = ref_visit.get("referring_visit_id", 0)
                    depth += 1
                
                # Analyze the delivery vector
                delivery_vector = "unknown"
                if len(chain) > 1:
                    first_hop = chain[-1]
                    first_transition = first_hop.get("transition", "").lower()
                    first_url = first_hop.get("url", "").lower()
                    
                    if "link" in first_transition:
                        if any(mail in first_url for mail in ["mail.", "outlook.", "gmail.", "webmail"]):
                            delivery_vector = "phishing email (link from webmail)"
                        else:
                            delivery_vector = "link click (possible phishing page)"
                    elif "typed" in first_transition:
                        delivery_vector = "direct navigation (possible pharming/typosquatting)"
                    elif any(search in first_url for search in ["google.", "bing.", "search."]):
                        delivery_vector = "search result (possible SEO poisoning)"
                
                auth_flow = {
                    "idp_type": idp_type,
                    "idp_url": url,
                    "visit_time": visit_time,
                    "transition": transition,
                    "delivery_vector": delivery_vector,
                    "referrer_chain": list(reversed(chain)),  # Chronological order
                    "chain_depth": len(chain),
                    "note": (
                        f"Authentication to {idp_type} at {visit_time}. "
                        f"This visit_time is the best proxy for AiTM capture moment. "
                        f"Delivery: {delivery_vector}."
                    ),
                }
                
                timeline["authentication_flows"].append(auth_flow)
                
                # Add to causal events if there's a meaningful chain
                if len(chain) > 1:
                    timeline["causal_events"].append({
                        "type": "authentication_chain",
                        "idp": idp_type,
                        "auth_time": visit_time,
                        "delivery_vector": delivery_vector,
                        "lure_url": chain[-1].get("url") if len(chain) > 1 else None,
                        "chain_summary": " → ".join([c.get("url", "?")[:50] for c in reversed(chain)]),
                    })
    
    # -------------------------------------------------------------------------
    # 4. Extract Dropper Downloads (Infostealer delivery anchor)
    # -------------------------------------------------------------------------
    dl_blob = pkg.get("downloads.json")
    if dl_blob:
        suspicious_exts = {".exe", ".msi", ".dll", ".bat", ".cmd", ".ps1", ".vbs", 
                          ".js", ".hta", ".scr", ".zip", ".rar", ".7z", ".iso"}
        
        for dl in records(dl_blob):
            filename = dl.get("filename", "")
            url = dl.get("url", "")
            start_time = dl.get("startTime")
            
            # Check for suspicious file types
            ext = ""
            if "." in filename:
                ext = "." + filename.rsplit(".", 1)[-1].lower()
            
            if ext in suspicious_exts or any(x in filename.lower() for x in ["crack", "keygen", "patch", "loader"]):
                timeline["dropper_downloads"].append({
                    "filename": filename,
                    "url": url,
                    "download_time": start_time,
                    "extension": ext,
                    "referrer": dl.get("referrer"),
                    "note": (
                        f"Potential dropper download at {start_time}. "
                        "This is the causal anchor for infostealer delivery vector. "
                        "Correlate with any infostealer execution artifacts."
                    ),
                })
    
    # -------------------------------------------------------------------------
    # 5. Build Theft Windows
    # -------------------------------------------------------------------------
    for session in timeline["stealable_sessions"]:
        theft_window = {
            "identity": {
                "tenant_id": session.get("tenant_id"),
                "object_id": session.get("object_id"),
                "upn": session.get("upn"),
            },
            "session_birth_lower": None,  # Earliest possible birth
            "session_birth_upper": None,  # Latest possible birth
            "validity_end": session.get("expiration"),
            "birth_source": None,
            "investigation_guidance": [],
        }
        
        # Use auth_time if available for this identity
        for anchor in timeline["session_birth_anchors"]:
            # Try to match by domain/tenant
            if anchor.get("auth_time"):
                theft_window["session_birth_lower"] = anchor.get("auth_time")
                theft_window["session_birth_upper"] = anchor.get("auth_time")
                theft_window["birth_source"] = "auth_time claim (precise)"
                break
        
        # Fallback to ESTS expiration estimate
        if not theft_window["session_birth_lower"] and session.get("estimated_birth"):
            theft_window["session_birth_lower"] = session.get("estimated_birth")
            theft_window["session_birth_upper"] = session.get("expiration")
            theft_window["birth_source"] = "ESTS expiration estimate (coarse, ±sign-in-frequency)"
        
        # Use visitdetails auth flows
        for flow in timeline["authentication_flows"]:
            if flow.get("idp_type") == "Entra ID":
                if flow.get("visit_time"):
                    theft_window["session_birth_upper"] = flow.get("visit_time")
                    if not theft_window["birth_source"] or "estimate" in theft_window["birth_source"]:
                        theft_window["birth_source"] = "visitdetails IdP navigation"
                    break
        
        # Add investigation guidance
        guidance = []
        guidance.append(
            "1. The ESTS cookie is the 'loaded gun on the table' - proof the replayable session existed."
        )
        guidance.append(
            f"2. Session birth bracketed by: {theft_window['birth_source'] or 'unknown source'}"
        )
        if theft_window["session_birth_lower"]:
            guidance.append(
                f"3. Theft occurred AFTER {theft_window['session_birth_lower']} (session birth)"
            )
        guidance.append(
            "4. Query Entra sign-in logs for this object_id - look for first replay from TA IP "
            "(same SessionId, MFA inherited without prompt, anomalous location)"
        )
        guidance.append(
            "5. The theft window is: [session_birth, first_TA_replay]"
        )
        
        theft_window["investigation_guidance"] = guidance
        timeline["theft_windows"].append(theft_window)
    
    return timeline


# --------------------------------------------------------------------------- #
# Entra / Purview Log Correlation
# --------------------------------------------------------------------------- #

# Log file name patterns for auto-detection
ENTRA_LOG_PATTERNS = {
    "interactive": ["interactive", "interactivesignin"],
    "noninteractive": ["noninteractive", "non-interactive", "noninteractivesignin"],
    "serviceprincipal": ["serviceprincipal", "service-principal", "application", "appsignin"],
    "managedidentity": ["managedidentity", "managed-identity", "msi"],
    "audit": ["audit", "auditlog"],
    "purview": ["unified", "ual", "purview", "unifiedauditlog"],
}


def load_log_file(path: str) -> List[Dict]:
    """Load a log file (JSON or CSV) and return list of records."""
    records = []
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            content = f.read().strip()
        
        # Try JSON first
        if content.startswith("[") or content.startswith("{"):
            data = json.loads(content)
            if isinstance(data, list):
                records = data
            elif isinstance(data, dict):
                # Some exports wrap records in a "value" key
                records = data.get("value", [data])
        else:
            # Parse as CSV
            import csv
            from io import StringIO
            reader = csv.DictReader(StringIO(content))
            records = list(reader)
    except Exception as e:
        print(f"[!] Warning: Could not load {path}: {e}")
    
    return records


def discover_entra_logs(folder: str) -> Dict[str, List[Dict]]:
    """Auto-discover and load Entra/Purview log files from a folder."""
    logs = {
        "interactive_signins": [],
        "noninteractive_signins": [],
        "serviceprincipal_signins": [],
        "managedidentity_signins": [],
        "audit_logs": [],
        "purview_ual": [],
    }
    
    if not os.path.isdir(folder):
        print(f"[!] Warning: Entra logs folder not found: {folder}")
        return logs
    
    for filename in os.listdir(folder):
        filepath = os.path.join(folder, filename)
        if not os.path.isfile(filepath):
            continue
        
        lower = filename.lower()
        
        # Skip non-data files
        if not (lower.endswith(".json") or lower.endswith(".csv")):
            continue
        
        # Match against patterns
        matched = False
        for log_type, patterns in ENTRA_LOG_PATTERNS.items():
            if any(p in lower for p in patterns):
                records = load_log_file(filepath)
                if records:
                    if log_type == "interactive":
                        logs["interactive_signins"].extend(records)
                    elif log_type == "noninteractive":
                        logs["noninteractive_signins"].extend(records)
                    elif log_type == "serviceprincipal":
                        logs["serviceprincipal_signins"].extend(records)
                    elif log_type == "managedidentity":
                        logs["managedidentity_signins"].extend(records)
                    elif log_type == "audit":
                        logs["audit_logs"].extend(records)
                    elif log_type == "purview":
                        logs["purview_ual"].extend(records)
                    print(f"[+] Loaded {len(records)} records from {filename} ({log_type})")
                    matched = True
                    break
        
        if not matched and (lower.endswith(".json") or lower.endswith(".csv")):
            print(f"[*] Skipped unrecognized file: {filename}")
    
    return logs


def normalize_signin_record(rec: Dict, log_type: str) -> Dict:
    """Normalize sign-in record fields across different export formats."""
    # Handle various field name conventions (Azure portal vs Graph API vs PowerShell)
    normalized = {
        "log_type": log_type,
        "timestamp": None,
        "user_id": None,
        "user_principal_name": None,
        "app_id": None,
        "app_display_name": None,
        "ip_address": None,
        "location": None,
        "device_detail": None,
        "status": None,
        "error_code": None,
        "mfa_detail": None,
        "session_id": None,
        "correlation_id": None,
        "resource_id": None,
        "resource_display_name": None,
        "conditional_access": None,
        "risk_level": None,
        "original": rec,
    }
    
    # Timestamp
    for k in ["createdDateTime", "CreatedDateTime", "timestamp", "Timestamp", 
              "activityDateTime", "ActivityDateTime"]:
        if k in rec and rec[k]:
            normalized["timestamp"] = rec[k]
            break
    
    # User ID
    for k in ["userId", "UserId", "user_id", "id"]:
        if k in rec and rec[k]:
            normalized["user_id"] = rec[k]
            break
    
    # UPN
    for k in ["userPrincipalName", "UserPrincipalName", "upn", "UPN", 
              "userDisplayName", "UserDisplayName"]:
        if k in rec and rec[k]:
            normalized["user_principal_name"] = rec[k]
            break
    
    # App ID
    for k in ["appId", "AppId", "applicationId", "ApplicationId", "clientAppUsed"]:
        if k in rec and rec[k]:
            normalized["app_id"] = rec[k]
            break
    
    # App name
    for k in ["appDisplayName", "AppDisplayName", "applicationDisplayName", "resourceDisplayName"]:
        if k in rec and rec[k]:
            normalized["app_display_name"] = rec[k]
            break
    
    # IP address
    for k in ["ipAddress", "IpAddress", "ip", "IP", "clientIP", "ClientIP"]:
        if k in rec and rec[k]:
            normalized["ip_address"] = rec[k]
            break
    
    # Location
    for k in ["location", "Location"]:
        if k in rec and rec[k]:
            loc = rec[k]
            if isinstance(loc, dict):
                city = loc.get("city", "")
                state = loc.get("state", "")
                country = loc.get("countryOrRegion", "")
                normalized["location"] = f"{city}, {state}, {country}".strip(", ")
            else:
                normalized["location"] = str(loc)
            break
    
    # Device
    for k in ["deviceDetail", "DeviceDetail"]:
        if k in rec and rec[k]:
            dev = rec[k]
            if isinstance(dev, dict):
                normalized["device_detail"] = {
                    "device_id": dev.get("deviceId"),
                    "display_name": dev.get("displayName"),
                    "os": dev.get("operatingSystem"),
                    "browser": dev.get("browser"),
                    "trust_type": dev.get("trustType"),
                }
            else:
                normalized["device_detail"] = str(dev)
            break
    
    # Status
    for k in ["status", "Status"]:
        if k in rec and rec[k]:
            st = rec[k]
            if isinstance(st, dict):
                normalized["status"] = st.get("errorCode", 0) == 0
                normalized["error_code"] = st.get("errorCode")
            else:
                normalized["status"] = str(st).lower() in ("success", "0", "true")
            break
    
    # MFA
    for k in ["mfaDetail", "MfaDetail", "authenticationDetails"]:
        if k in rec and rec[k]:
            normalized["mfa_detail"] = rec[k]
            break
    
    # Session ID
    for k in ["sessionId", "SessionId", "correlationId", "CorrelationId"]:
        if k in rec and rec[k]:
            normalized["session_id"] = rec[k]
            break
    
    # Correlation ID
    for k in ["correlationId", "CorrelationId"]:
        if k in rec and rec[k]:
            normalized["correlation_id"] = rec[k]
            break
    
    # Resource
    for k in ["resourceId", "ResourceId"]:
        if k in rec and rec[k]:
            normalized["resource_id"] = rec[k]
            break
    
    for k in ["resourceDisplayName", "ResourceDisplayName"]:
        if k in rec and rec[k]:
            normalized["resource_display_name"] = rec[k]
            break
    
    # Risk
    for k in ["riskLevelDuringSignIn", "riskLevelAggregated", "riskLevel"]:
        if k in rec and rec[k]:
            normalized["risk_level"] = rec[k]
            break
    
    return normalized


def correlate_entra_logs(theft_timeline: Dict, entra_logs: Dict) -> Dict:
    """
    Correlate BAI theft timeline with Entra sign-in/audit logs.
    
    Finds:
    - First TA replay (anomalous sign-in for same identity)
    - Complete theft windows
    - Post-compromise activity
    """
    correlation = {
        "identities_matched": 0,
        "signins_analyzed": 0,
        "anomalous_signins": [],
        "first_ta_replays": [],
        "completed_theft_windows": [],
        "post_compromise_activity": [],
        "session_correlations": [],
        "summary": "",
    }
    
    # Collect all sign-ins and normalize
    all_signins = []
    for log_type, log_records in [
        ("interactive", entra_logs.get("interactive_signins", [])),
        ("noninteractive", entra_logs.get("noninteractive_signins", [])),
        ("serviceprincipal", entra_logs.get("serviceprincipal_signins", [])),
        ("managedidentity", entra_logs.get("managedidentity_signins", [])),
    ]:
        for rec in log_records:
            normalized = normalize_signin_record(rec, log_type)
            all_signins.append(normalized)
    
    correlation["signins_analyzed"] = len(all_signins)
    
    # Get stealable sessions from theft timeline
    stealable = theft_timeline.get("stealable_sessions", [])
    theft_windows = theft_timeline.get("theft_windows", [])
    
    # Build lookup of identities from BAI
    bai_identities = {}
    for session in stealable:
        obj_id = session.get("object_id")
        upn = session.get("upn")
        tenant = session.get("tenant_id")
        
        if obj_id:
            bai_identities[obj_id.lower()] = {
                "object_id": obj_id,
                "upn": upn,
                "tenant_id": tenant,
                "session_birth": session.get("estimated_birth"),
                "expiration": session.get("expiration"),
                "signins": [],
            }
        if upn:
            bai_identities[upn.lower()] = bai_identities.get(obj_id.lower(), {
                "object_id": obj_id,
                "upn": upn,
                "tenant_id": tenant,
                "session_birth": session.get("estimated_birth"),
                "expiration": session.get("expiration"),
                "signins": [],
            })
    
    # Match sign-ins to BAI identities
    for signin in all_signins:
        user_id = (signin.get("user_id") or "").lower()
        upn = (signin.get("user_principal_name") or "").lower()
        
        matched_identity = None
        if user_id in bai_identities:
            matched_identity = bai_identities[user_id]
        elif upn in bai_identities:
            matched_identity = bai_identities[upn]
        
        if matched_identity:
            matched_identity["signins"].append(signin)
    
    # Count matched identities
    matched_count = sum(1 for i in bai_identities.values() if i.get("signins"))
    correlation["identities_matched"] = matched_count
    
    # Analyze each identity for anomalous sign-ins
    for identity_key, identity in bai_identities.items():
        if not identity.get("signins"):
            continue
        
        signins = identity["signins"]
        session_birth = identity.get("session_birth")
        
        # Sort by timestamp
        signins.sort(key=lambda x: x.get("timestamp") or "")
        
        # Group by IP to find baseline
        ip_counts = {}
        for s in signins:
            ip = s.get("ip_address")
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        # Find most common IPs (likely legitimate)
        if ip_counts:
            baseline_ips = set(ip for ip, count in ip_counts.items() 
                              if count >= max(1, len(signins) * 0.1))
        else:
            baseline_ips = set()
        
        # Find anomalous sign-ins (different IP after session birth)
        for signin in signins:
            signin_time = signin.get("timestamp")
            signin_ip = signin.get("ip_address")
            
            # Check if after session birth and from unusual IP
            is_after_birth = True
            if session_birth and signin_time:
                try:
                    birth_dt = datetime.fromisoformat(session_birth.replace("Z", "+00:00"))
                    signin_dt = datetime.fromisoformat(signin_time.replace("Z", "+00:00"))
                    is_after_birth = signin_dt >= birth_dt
                except:
                    pass
            
            is_anomalous_ip = signin_ip and signin_ip not in baseline_ips
            
            # Flag non-interactive sign-ins from unusual IPs (token replay signature)
            is_token_replay = (signin.get("log_type") == "noninteractive" and 
                              is_anomalous_ip and is_after_birth)
            
            if is_anomalous_ip and is_after_birth:
                anomaly = {
                    "identity": identity.get("upn") or identity.get("object_id"),
                    "timestamp": signin_time,
                    "ip_address": signin_ip,
                    "location": signin.get("location"),
                    "log_type": signin.get("log_type"),
                    "app": signin.get("app_display_name"),
                    "resource": signin.get("resource_display_name"),
                    "is_token_replay_signature": is_token_replay,
                    "baseline_ips": list(baseline_ips)[:5],
                    "risk_level": signin.get("risk_level"),
                    "note": (
                        "Non-interactive sign-in from unusual IP after session birth - "
                        "HIGH confidence token replay" if is_token_replay else
                        "Sign-in from unusual IP after session birth"
                    ),
                }
                correlation["anomalous_signins"].append(anomaly)
                
                # Track first TA replay per identity
                if is_token_replay:
                    existing = [r for r in correlation["first_ta_replays"] 
                               if r.get("identity") == anomaly["identity"]]
                    if not existing:
                        correlation["first_ta_replays"].append({
                            "identity": anomaly["identity"],
                            "first_replay_time": signin_time,
                            "ip_address": signin_ip,
                            "location": signin.get("location"),
                            "session_birth": session_birth,
                            "theft_window": f"[{session_birth}, {signin_time}]",
                        })
                        
                        # Add completed theft window
                        correlation["completed_theft_windows"].append({
                            "identity": anomaly["identity"],
                            "session_birth": session_birth,
                            "first_ta_replay": signin_time,
                            "theft_ip": signin_ip,
                            "theft_location": signin.get("location"),
                        })
    
    # Analyze audit logs for post-compromise activity
    audit_logs = entra_logs.get("audit_logs", [])
    suspicious_operations = [
        "add member to role", "add app role assignment", "consent to application",
        "add service principal", "update application", "add delegated permission",
        "add owner", "update user", "reset password", "update authentication method",
        "register security info", "delete security info", "add member to group",
    ]
    
    for audit in audit_logs:
        activity = (audit.get("activityDisplayName") or 
                   audit.get("Activity") or 
                   audit.get("operationName") or "").lower()
        
        if any(op in activity for op in suspicious_operations):
            # Check if actor matches BAI identity
            actor = (audit.get("initiatedBy", {}).get("user", {}).get("userPrincipalName") or
                    audit.get("UserId") or audit.get("userPrincipalName") or "").lower()
            
            if actor in bai_identities or any(actor in k for k in bai_identities.keys()):
                correlation["post_compromise_activity"].append({
                    "timestamp": audit.get("activityDateTime") or audit.get("CreationTime"),
                    "activity": activity,
                    "actor": actor,
                    "target": (audit.get("targetResources", [{}])[0].get("displayName") 
                              if audit.get("targetResources") else None),
                    "details": audit.get("additionalDetails"),
                })
    
    # Analyze Purview/UAL for session correlation
    purview_logs = entra_logs.get("purview_ual", [])
    for ual in purview_logs[:1000]:  # Limit for performance
        session_id = ual.get("SessionId") or ual.get("sessionId")
        user_id = (ual.get("UserId") or ual.get("userId") or "").lower()
        
        if session_id and user_id in bai_identities:
            correlation["session_correlations"].append({
                "timestamp": ual.get("CreationTime") or ual.get("creationTime"),
                "operation": ual.get("Operation") or ual.get("operation"),
                "workload": ual.get("Workload") or ual.get("workload"),
                "session_id": session_id,
                "user_id": user_id,
                "client_ip": ual.get("ClientIP") or ual.get("clientIP"),
            })
    
    # Build summary
    summary_parts = []
    if correlation["identities_matched"]:
        summary_parts.append(f"{correlation['identities_matched']} BAI identities matched in Entra logs")
    if correlation["anomalous_signins"]:
        summary_parts.append(f"{len(correlation['anomalous_signins'])} anomalous sign-ins detected")
    if correlation["first_ta_replays"]:
        summary_parts.append(f"{len(correlation['first_ta_replays'])} potential token replays identified")
    if correlation["completed_theft_windows"]:
        summary_parts.append(f"{len(correlation['completed_theft_windows'])} theft windows completed")
    if correlation["post_compromise_activity"]:
        summary_parts.append(f"{len(correlation['post_compromise_activity'])} suspicious post-compromise actions")
    
    correlation["summary"] = "; ".join(summary_parts) if summary_parts else "No correlations found"
    
    return correlation


# --------------------------------------------------------------------------- #
# Timeline builder
# --------------------------------------------------------------------------- #

def build_timeline(pkg: Dict, since: datetime = None, until: datetime = None) -> List[Dict]:
    events = []
    
    # History entries
    for h in records(pkg.get("history.json")):
        ts = from_chrome_micros(h.get("lastVisitTime"))
        events.append({
            "ts": ts, "kind": "history",
            "detail": h.get("url", ""),
            "title": h.get("title", ""),
            "extra": f"visits={h.get('visitCount')} typed={h.get('typedCount')}",
        })
    
    # Visit details (more granular)
    for v in records(pkg.get("visitdetails.json")):
        url = v.get("url", "")
        for visit in v.get("visits", []):
            ts = from_chrome_micros(visit.get("visitTime"))
            events.append({
                "ts": ts, "kind": "visit",
                "detail": url,
                "title": v.get("title", ""),
                "extra": f"transition={visit.get('transition')} referring={visit.get('referringVisitId')}",
            })
    
    # Downloads
    for d in records(pkg.get("downloads.json")):
        st = parse_iso(d.get("startTime")) or from_epoch_seconds(d.get("startTime"))
        en = parse_iso(d.get("endTime")) or from_epoch_seconds(d.get("endTime"))
        danger = d.get("danger")
        base = (f"{d.get('filename','')} <- {d.get('finalUrl') or d.get('url','')} "
                f"[{d.get('mime','')}] danger={danger} state={d.get('state')}")
        if st:
            events.append({"ts": st, "kind": "download_start", "detail": base,
                           "title": "", "extra": f"bytes={d.get('totalBytes')}"})
        if en:
            events.append({"ts": en, "kind": "download_end", "detail": base,
                           "title": "", "extra": f"received={d.get('bytesReceived')}"})
    
    # Cookie expiry anchors
    for c in records(pkg.get("cookies.json")):
        if not (classify_idp(c.get("domain", "")) or is_auth_cookie(c.get("name", ""))):
            continue
        exp = from_epoch_seconds(c.get("expirationDate"))
        if exp:
            events.append({
                "ts": exp, "kind": "cookie_expiry",
                "detail": f"{c.get('domain','')} {c.get('name','')}",
                "title": "", "extra": f"httpOnly={c.get('httpOnly')} secure={c.get('secure')}",
            })
    
    # Chain of custody
    coc = pkg.get("chain_of_custody.json") or {}
    for ev in coc.get("events", []) or []:
        t = parse_iso(ev.get("timestamp_utc"))
        events.append({
            "ts": t, "kind": "acquisition",
            "detail": ev.get("action", ""), "title": "",
            "extra": f"operator={ev.get('operator','')}",
        })
    
    # Filter
    def keep(e):
        if e["ts"] is None:
            return False
        if since and e["ts"] < since:
            return False
        if until and e["ts"] > until:
            return False
        return True
    
    events = [e for e in events if keep(e)]
    events.sort(key=lambda e: e["ts"])
    return events


# --------------------------------------------------------------------------- #
# Findings aggregation
# --------------------------------------------------------------------------- #

def aggregate_findings(pkg: Dict, include_values: bool = False, online: bool = False) -> Tuple[List[Dict], Dict]:
    """Run all analyzers and aggregate findings.
    
    Args:
        pkg: BAI package data
        include_values: If True, include raw token values in output
        online: If True, perform WHOIS/RDAP lookups for domain age analysis
    """
    all_findings = []
    supplementary_data = {
        "storage_tokens": [],
        "indexeddb_tokens": [],
    }
    
    # HIGH PRIORITY - Direct AiTM/Infostealer indicators
    all_findings.extend(analyze_extensions(pkg))
    all_findings.extend(analyze_proxy(pkg))
    
    ws_findings, ws_tokens = analyze_webstorage(pkg, include_values)
    all_findings.extend(ws_findings)
    supplementary_data["storage_tokens"].extend(ws_tokens)
    
    idb_findings, idb_tokens = analyze_indexeddb(pkg, include_values)
    all_findings.extend(idb_findings)
    supplementary_data["indexeddb_tokens"].extend(idb_tokens)
    
    all_findings.extend(analyze_performance(pkg))
    all_findings.extend(analyze_serviceworkers(pkg))
    
    # HIGH PRIORITY - Delivery vector detection (SEO poisoning, malvertising)
    all_findings.extend(analyze_seo_poisoning(pkg, online=online))
    all_findings.extend(analyze_malvertising(pkg))
    all_findings.extend(analyze_extension_timeline(pkg))
    
    # MEDIUM PRIORITY - Tampering and context
    all_findings.extend(analyze_privacy(pkg))
    all_findings.extend(analyze_search_engines(pkg))
    all_findings.extend(analyze_sessions(pkg))
    all_findings.extend(analyze_webauthn(pkg))
    
    # Sort by severity
    severity_order = {s.value: i for i, s in enumerate(Severity)}
    all_findings.sort(key=lambda f: severity_order.get(f["severity"], 99))
    
    return all_findings, supplementary_data


# --------------------------------------------------------------------------- #
# Output writers
# --------------------------------------------------------------------------- #

def write_timeline_csv(events: List[Dict], tz, path: str):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp_local", "timestamp_utc", "kind", "detail", "title", "extra"])
        for e in events:
            w.writerow([
                fmt(e["ts"], tz),
                e["ts"].astimezone(timezone.utc).isoformat(),
                e["kind"], e["detail"], e["title"], e["extra"],
            ])


def write_findings_json(findings: List[Dict], aitm_view: Dict, 
                        theft_timeline: Dict, path: str, 
                        entra_correlation: Dict = None):
    output = {
        "findings": findings,
        "aitm_view": aitm_view,
        "session_theft_timeline": theft_timeline,
        "summary": {
            "total_findings": len(findings),
            "by_severity": {s.value: len([f for f in findings if f["severity"] == s.value]) 
                           for s in Severity},
            "by_category": {c.value: len([f for f in findings if f["category"] == c.value])
                           for c in FindingCategory},
            "stealable_sessions": len(theft_timeline.get("stealable_sessions", [])),
            "authentication_flows": len(theft_timeline.get("authentication_flows", [])),
            "dropper_downloads": len(theft_timeline.get("dropper_downloads", [])),
        },
    }
    
    # Add Entra correlation summary if available
    if entra_correlation:
        output["entra_correlation_summary"] = {
            "identities_matched": entra_correlation.get("identities_matched", 0),
            "signins_analyzed": entra_correlation.get("signins_analyzed", 0),
            "anomalous_signins": len(entra_correlation.get("anomalous_signins", [])),
            "token_replays_detected": len(entra_correlation.get("first_ta_replays", [])),
            "completed_theft_windows": len(entra_correlation.get("completed_theft_windows", [])),
            "post_compromise_actions": len(entra_correlation.get("post_compromise_activity", [])),
            "summary": entra_correlation.get("summary", ""),
        }
        # Include completed theft windows in main output for easy access
        if entra_correlation.get("completed_theft_windows"):
            output["completed_theft_windows"] = entra_correlation["completed_theft_windows"]
    
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2)


def write_auth_json(sessions: List[Dict], idp_cookies: List[Dict], 
                    storage_tokens: List[Dict], path: str):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({
            "auth_sessions": sessions,
            "idp_cookies": idp_cookies,
            "storage_tokens": storage_tokens,
            "correlation_guidance": {
                "entra_join_keys": ["tenant_id", "object_id", "upn", "time_window"],
                "entra_missing_from_cookie": ["correlationId", "sessionId", "uniqueTokenIdentifier(UTI)"],
                "entra_hunt": "Same user/session reused from a new IP/ASN/device/UA than the "
                              "original interactive MFA sign-in within the token validity window.",
                "purview_join_key": "SessionId in Unified Audit Log / Exchange & SharePoint audit records",
                "storage_note": "localStorage/IndexedDB tokens are XSS-vulnerable and may contain "
                               "refresh tokens with extended validity windows.",
            },
        }, fh, indent=2)


# --------------------------------------------------------------------------- #
# Structured Report Generator (HTML/TXT)
# --------------------------------------------------------------------------- #

class ReportGenerator:
    """Generate structured forensic reports in HTML or TXT format."""
    
    def __init__(self, pkg: Dict, findings: List[Dict], aitm_view: Dict,
                 sessions: List[Dict], storage_tokens: List[Dict],
                 events: List[Dict], theft_timeline: Dict,
                 entra_correlation: Dict = None, 
                 upn_accounts: List[Dict] = None,
                 entra_sessions: List[Dict] = None,
                 tz=None):
        self.pkg = pkg
        self.findings = findings
        self.aitm_view = aitm_view
        self.sessions = sessions
        self.storage_tokens = storage_tokens
        self.events = events
        self.theft_timeline = theft_timeline
        self.entra_correlation = entra_correlation
        self.upn_accounts = upn_accounts or []
        self.entra_sessions = entra_sessions or []
        self.tz = tz
        
        # Extract common data
        self.manifest = pkg.get("MANIFEST.json") or {}
        self.chain = pkg.get("chain_of_custody.json") or {}
        self.sysinfo = pkg.get("systeminfo.json") or {}
        self.session_log = pkg.get("session_log.json") or {}
        self.identity_json = pkg.get("identity.json") or {}
    
    def _fmt_ts(self, ts) -> str:
        """Format timestamp for display."""
        if ts is None:
            return "Unknown"
        if isinstance(ts, str):
            return ts
        return fmt(ts, self.tz) if self.tz else str(ts)
    
    def _fmt_epoch_dual(self, epoch_ms) -> str:
        """Format epoch milliseconds as both local timezone and UTC."""
        if epoch_ms is None:
            return "Unknown"
        
        try:
            # Handle both ms and seconds
            if isinstance(epoch_ms, str):
                epoch_ms = float(epoch_ms)
            
            # If it's in milliseconds (> year 2100 in seconds), convert to seconds
            if epoch_ms > 4102444800:  # Jan 1, 2100 in seconds
                epoch_s = epoch_ms / 1000.0
            else:
                epoch_s = epoch_ms
            
            dt_utc = datetime.fromtimestamp(epoch_s, tz=timezone.utc)
            utc_str = dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
            
            if self.tz:
                dt_local = dt_utc.astimezone(self.tz)
                local_str = dt_local.strftime("%Y-%m-%d %H:%M:%S %Z")
                return f"{local_str} ({utc_str})"
            else:
                return utc_str
        except (ValueError, TypeError, OSError):
            return str(epoch_ms)
    
    def _get_mfa_status(self, session: Dict) -> str:
        """Determine MFA status from session claims."""
        # Check decoded token claims
        identity = session.get("identity", {})
        amr = identity.get("amr", [])
        
        if isinstance(amr, list):
            if "mfa" in amr:
                return "MFA verified"
            if "ngcmfa" in amr:
                return "MFA (NGC)"
            if "otp" in amr:
                return "OTP"
            if "hwk" in amr or "fido" in amr:
                return "FIDO/Hardware key"
            if "pwd" in amr and len(amr) == 1:
                return "Password only"
        
        # Check for MFA-related cookies
        cookie_names = session.get("cookie_names", [])
        if any("mfa" in c.lower() for c in cookie_names):
            return "MFA (cookie indicator)"
        
        # Check token types for persistent (usually requires MFA)
        token_types = session.get("token_types", [])
        if "persistent" in token_types:
            return "Likely MFA (persistent)"
        
        return "Unknown"
    
    def _get_token_types(self, session: Dict) -> str:
        """Get token types as display string."""
        types = []
        token_types = session.get("token_types", [])
        
        if "persistent" in token_types:
            types.append("Persistent")
        if session.get("any_httponly"):
            types.append("Bearer (HttpOnly)")
        else:
            types.append("Bearer")
        
        # Check for refresh tokens in identity
        identity = session.get("identity", {})
        if identity.get("refresh_token") or identity.get("rt"):
            types.append("Refresh")
        
        return ", ".join(types) if types else "Session"
    
    def build_identity_inventory(self) -> List[Dict]:
        """Build comprehensive identity inventory from all sources."""
        inventory = []
        
        for session in self.sessions:
            idp = session.get("idp", "Unknown")
            domain = session.get("domain", "Unknown")
            identity = session.get("identity", {})
            
            entry = {
                "identity": identity.get("upn") or identity.get("preferred_username") or 
                           identity.get("email") or identity.get("name") or 
                           f"[{domain}]",
                "idp": idp,
                "domain": domain,
                "tenant_id": session.get("tenant_id") or identity.get("tid"),
                "object_id": session.get("object_id") or identity.get("oid"),
                "mfa_status": self._get_mfa_status(session),
                "token_types": self._get_token_types(session),
                "valid_until": session.get("latest_expiry") or session.get("earliest_expiry"),
                "cookie_count": len(session.get("cookie_names", [])),
                "httponly": "Yes" if session.get("any_httponly") else "No",
            }
            inventory.append(entry)
        
        # Add storage tokens
        for token in self.storage_tokens:
            identity = token.get("identity", {})
            entry = {
                "identity": identity.get("upn") or identity.get("preferred_username") or 
                           identity.get("email") or token.get("key", "Unknown"),
                "idp": token.get("idp", "Web Storage"),
                "domain": token.get("origin", "Unknown"),
                "tenant_id": identity.get("tid"),
                "object_id": identity.get("oid"),
                "mfa_status": self._get_mfa_status({"identity": identity}),
                "token_types": "Storage Token" + (" (Refresh)" if token.get("is_refresh") else ""),
                "valid_until": token.get("expiration"),
                "cookie_count": 0,
                "httponly": "N/A (XSS vulnerable)",
            }
            inventory.append(entry)
        
        return inventory
    
    def _section_evidence_provenance(self) -> str:
        """Generate Evidence Provenance section."""
        lines = []
        lines.append("=" * 78)
        lines.append("1. EVIDENCE PROVENANCE")
        lines.append("=" * 78)
        lines.append("")
        
        # Collection metadata - handle both old and new manifest formats
        tool = self.manifest.get("tool", {})
        env = self.manifest.get("environment", {})
        acq = self.manifest.get("acquisition", {})
        root_hash = self.manifest.get("root_hash", {})
        
        lines.append("COLLECTION METADATA")
        lines.append("-" * 40)
        lines.append(f"  Collection ID:   {self.manifest.get('collection_id', 'Unknown')}")
        lines.append(f"  Started:         {acq.get('started_utc', self.manifest.get('timestamp', 'Unknown'))}")
        lines.append(f"  Completed:       {acq.get('collection_completed_utc', 'Unknown')}")
        lines.append(f"  Extension:       {tool.get('name', 'BAI')} v{tool.get('version', env.get('extension_version', '?'))}")
        
        pkg_hash = root_hash.get('value', self.manifest.get('package_sha256', 'Not computed'))
        lines.append(f"  Root Hash:       {pkg_hash}")
        lines.append("")
        
        # Case information
        case = self.manifest.get("case", {})
        lines.append("CASE INFORMATION")
        lines.append("-" * 40)
        lines.append(f"  Case ID:         {case.get('case_id', 'Not specified')}")
        lines.append(f"  Examiner:        {case.get('examiner', 'Not specified')}")
        lines.append(f"  Notes:           {case.get('notes', 'None')}")
        lines.append("")
        
        # Chain of custody summary (full details at end of report)
        coc_entries = self.chain.get("events", self.chain.get("entries", []))
        lines.append("CHAIN OF CUSTODY SUMMARY")
        lines.append("-" * 40)
        if coc_entries:
            lines.append(f"  Total Events:    {len(coc_entries)}")
            lines.append(f"  Workflow:        {self.chain.get('workflow', 'Unknown')}")
            # Find start and end times
            if coc_entries:
                first_ts = coc_entries[0].get('timestamp_utc', coc_entries[0].get('timestamp', '?'))
                last_ts = coc_entries[-1].get('timestamp_utc', coc_entries[-1].get('timestamp', '?'))
                lines.append(f"  First Event:     {first_ts}")
                lines.append(f"  Last Event:      {last_ts}")
            lines.append(f"  (See Section 8 for full chain of custody details)")
        else:
            lines.append("  No chain of custody entries recorded.")
        lines.append("")
        
        # Signature verification - check both SIGNATURE.json and manifest.signing
        sig = self.pkg.get("SIGNATURE.json") or {}
        signing = self.manifest.get("signing", {})
        
        lines.append("INTEGRITY VERIFICATION")
        lines.append("-" * 40)
        
        if signing.get("signed") or sig.get("signature"):
            lines.append(f"  Signed:          Yes")
            lines.append(f"  Algorithm:       {signing.get('algorithm', sig.get('algorithm', 'Unknown'))}")
            lines.append(f"  Signer:          {signing.get('signer_label', sig.get('signer_label', 'Unknown'))}")
            
            key_fp = signing.get('public_key_fingerprint_sha256', sig.get('key_id', ''))
            if key_fp:
                lines.append(f"  Key Fingerprint: {key_fp}")
            
            if sig.get("signature"):
                lines.append(f"  Signature File:  SIGNATURE.json (present)")
            else:
                lines.append(f"  Signature File:  {signing.get('signature_file', 'Unknown')}")
        else:
            lines.append("  Signed:          No")
        lines.append("")
        
        return "\n".join(lines)
    
    def _section_system_context(self) -> str:
        """Generate System Context section."""
        lines = []
        lines.append("=" * 78)
        lines.append("2. SYSTEM CONTEXT")
        lines.append("=" * 78)
        lines.append("")
        
        env = self.manifest.get("environment", {})
        totals = self.manifest.get("totals", {})
        
        # Get systeminfo - it has platform, cpu, memory, storage at top level
        platform_info = self.sysinfo.get("platform", {})
        cpu_info = self.sysinfo.get("cpu", {})
        memory_info = self.sysinfo.get("memory", {})
        storage_info = self.sysinfo.get("storage", [])
        
        # Computer information
        lines.append("COMPUTER INFORMATION")
        lines.append("-" * 40)
        
        # Platform
        os_name = platform_info.get("os", env.get("platform", "Unknown"))
        if os_name == "win":
            os_name = "Windows"
        elif os_name == "mac":
            os_name = "macOS"
        elif os_name == "linux":
            os_name = "Linux"
        elif os_name == "cros":
            os_name = "Chrome OS"
        
        arch = platform_info.get("arch", "Unknown")
        lines.append(f"  Operating System: {os_name}")
        lines.append(f"  Architecture:     {arch}")
        
        # CPU
        cpu_model = cpu_info.get("modelName", "Unknown")
        cpu_cores = cpu_info.get("numOfProcessors", "Unknown")
        lines.append(f"  CPU Model:        {cpu_model}")
        lines.append(f"  CPU Cores:        {cpu_cores}")
        
        # Memory
        if memory_info:
            total_mem = memory_info.get("capacity", 0)
            avail_mem = memory_info.get("availableCapacity", 0)
            if total_mem:
                total_gb = total_mem / (1024**3)
                avail_gb = avail_mem / (1024**3)
                lines.append(f"  Total Memory:     {total_gb:.1f} GB")
                lines.append(f"  Available Memory: {avail_gb:.1f} GB")
        
        # Storage
        if storage_info:
            for i, disk in enumerate(storage_info[:2]):
                name = disk.get("name", "").strip("\x00").strip() or f"Disk {i}"
                capacity = disk.get("capacity", 0)
                if capacity:
                    cap_gb = capacity / (1024**3)
                    lines.append(f"  Storage ({name}):  {cap_gb:.0f} GB")
        
        # User Agent - full, no truncation
        ua = env.get('user_agent', 'Unknown')
        lines.append(f"  User Agent:       {ua}")
        
        # Languages
        langs = env.get('languages', [])
        if isinstance(langs, list):
            langs = ", ".join(langs)
        lines.append(f"  Locale:           {env.get('locale', 'Unknown')}")
        lines.append(f"  Languages:        {langs}")
        lines.append(f"  Timezone:         {env.get('timezone', 'Unknown')}")
        lines.append("")
        
        # Browser information
        lines.append("BROWSER INFORMATION")
        lines.append("-" * 40)
        lines.append(f"  Browser:          Chrome {env.get('chrome_version', 'Unknown')}")
        lines.append(f"  Extension ID:     {env.get('extension_id', 'Unknown')}")
        lines.append(f"  Extension Ver:    {env.get('extension_version', 'Unknown')}")
        lines.append(f"  Clock Source:     {env.get('clock_source', 'Unknown')}")
        lines.append("")
        
        # Collection statistics
        log = self.session_log
        lines.append("COLLECTION STATISTICS")
        lines.append("-" * 40)
        lines.append(f"  Artifacts:        {totals.get('artifact_count', self.manifest.get('artifact_count', '?'))}")
        lines.append(f"  Total Size:       {totals.get('total_bytes', 0):,} bytes")
        lines.append(f"  Partial:          {totals.get('partial_artifacts', 0)} artifact(s)")
        lines.append(f"  Log Entries:      {log.get('entry_count', '?')}")
        lines.append(f"  Errors:           {log.get('error_count', 0)}")
        lines.append(f"  Warnings:         {log.get('warning_count', 0)}")
        lines.append("")
        
        # List any errors/warnings
        if log.get('error_count', 0) > 0 or log.get('warning_count', 0) > 0:
            lines.append("COLLECTION ISSUES")
            lines.append("-" * 40)
            for entry in log.get('entries', []):
                if entry.get('level') in ('error', 'warning'):
                    lines.append(f"  [{entry['level'].upper()}] {entry.get('message', '?')}")
            lines.append("")
        
        return "\n".join(lines)
    
    def _section_identity_inventory(self) -> str:
        """Generate Identity Inventory section."""
        lines = []
        lines.append("=" * 78)
        lines.append("3. IDENTITY INVENTORY")
        lines.append("=" * 78)
        lines.append("")
        
        # Split accounts by evidence strength
        primary_accounts = [a for a in self.upn_accounts if a.get('has_strong_evidence')]
        
        # Show PRIMARY accounts (with cookie/token evidence)
        if primary_accounts or self.entra_sessions:
            lines.append("PRIMARY USER ACCOUNTS (Cookie/Token Evidence)")
            lines.append("-" * 78)
            lines.append("  These accounts have session cookies or tokens that could be stolen/replayed.")
            lines.append("")
            lines.append("TABLE:identity_accounts")  # Marker for HTML table
            
            # Display Microsoft Entra sessions (tenant/object ID based)
            if self.entra_sessions:
                lines.append("")
                lines.append("MICROSOFT ENTRA SESSIONS")
                lines.append("-" * 78)
                lines.append("")
                lines.append("TABLE:entra_sessions")  # Marker for HTML table
        
        if not primary_accounts and not self.entra_sessions:
            lines.append("  No authenticated accounts discovered in cookies or storage.")
            lines.append("")
        
        # Summary counts
        lines.append("")
        lines.append(f"  Total Authenticated Accounts: {len(primary_accounts)}")
        lines.append(f"  Entra Sessions: {len(self.entra_sessions)}")
        lines.append("")
        
        return "\n".join(lines)
    
    def _generate_identity_table_html(self) -> str:
        """Generate HTML table for identity accounts with stealable tokens."""
        import html as html_mod
        
        primary_accounts = [a for a in self.upn_accounts if a.get('has_strong_evidence')]
        
        if not primary_accounts:
            return "<p>No authenticated accounts discovered.</p>"
        
        rows = []
        for acct in primary_accounts:
            upn = acct.get('upn', 'Unknown')
            services = acct.get('services', {})
            
            # Flatten to one row per token (more informative)
            token_rows = []
            for domain, svc_info in sorted(services.items()):
                for token in svc_info.get('tokens', []):
                    cookie_name = token.get('cookie_name')
                    is_jwt = token.get('is_jwt', False)
                    httponly = token.get('httponly')
                    source = token.get('source', '')
                    
                    # Skip non-cookie evidence for this table
                    if not cookie_name:
                        continue
                    
                    # Format token type
                    if is_jwt:
                        token_type = "JWT"
                    elif 'localStorage' in (cookie_name or ''):
                        token_type = "localStorage"
                    elif 'IndexedDB' in (cookie_name or ''):
                        token_type = "IndexedDB"
                    else:
                        token_type = "Cookie"
                    
                    # Format protection and theft risk
                    if httponly is True:
                        protection = "HttpOnly"
                        theft_risk = "Requires malware/browser exploit to steal"
                        risk_class = 'low-risk'
                    elif httponly is False:
                        protection = "JS-accessible"
                        theft_risk = "Stealable via XSS or malicious extension"
                        risk_class = 'high-risk'
                    else:
                        protection = "N/A"
                        theft_risk = "Session evidence only"
                        risk_class = ''
                    
                    token_rows.append({
                        'domain': domain,
                        'cookie_name': cookie_name,
                        'token_type': token_type,
                        'protection': protection,
                        'theft_risk': theft_risk,
                        'risk_class': risk_class,
                    })
            
            if not token_rows:
                continue
            
            # Generate rows with rowspan for UPN
            for i, tr in enumerate(token_rows):
                if i == 0:
                    rows.append(f"<tr><td rowspan='{len(token_rows)}' class='upn-cell'>{html_mod.escape(upn)}</td>"
                               f"<td>{html_mod.escape(tr['domain'])}</td>"
                               f"<td>{tr['token_type']}</td>"
                               f"<td>{tr['protection']}</td>"
                               f"<td class='{tr['risk_class']}'>{tr['theft_risk']}</td></tr>")
                else:
                    rows.append(f"<tr><td>{html_mod.escape(tr['domain'])}</td>"
                               f"<td>{tr['token_type']}</td>"
                               f"<td>{tr['protection']}</td>"
                               f"<td class='{tr['risk_class']}'>{tr['theft_risk']}</td></tr>")
        
        return f"""<table class='data-table identity-table'>
<thead>
<tr><th>UPN (User)</th><th>Service</th><th>Type</th><th>Protection</th><th>Theft Risk</th></tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>"""
    
    def _generate_entra_table_html(self) -> str:
        """Generate HTML table for Entra sessions."""
        import html as html_mod
        
        if not self.entra_sessions:
            return "<p>No Entra sessions discovered.</p>"
        
        rows = []
        for sess in self.entra_sessions:
            upn = sess.get('upn') or '<em>Unknown</em>'
            tenant_id = sess.get('tenant_id', 'Unknown')
            object_id = sess.get('object_id', 'Unknown')
            sess_type = sess.get('type', 'SESSION')
            httponly = sess.get('httponly', False)
            cookie_name = sess.get('cookie_name', 'Unknown')
            
            # Token type with replayability info
            if httponly:
                token_desc = f"{sess_type} Cookie (HttpOnly) - Replayable if exfiltrated"
                risk_class = 'low-risk'
            else:
                token_desc = f"{sess_type} Cookie (JS-accessible) - Easily stolen & replayable"
                risk_class = 'high-risk'
            
            upn_html = html_mod.escape(upn) if upn and upn != '<em>Unknown</em>' else upn
            
            rows.append(f"<tr><td><strong>{upn_html}</strong></td>"
                       f"<td><code style='font-size:9px;'>{html_mod.escape(tenant_id)}</code></td>"
                       f"<td><code style='font-size:9px;'>{html_mod.escape(object_id)}</code></td>"
                       f"<td>{html_mod.escape(cookie_name)}</td>"
                       f"<td class='{risk_class}'>{token_desc}</td></tr>")
        
        return f"""<table class='data-table entra-table'>
<thead>
<tr><th>UPN (User)</th><th>Tenant ID</th><th>Object ID</th><th>Cookie</th><th>Token Type &amp; Risk</th></tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>"""
    
    def _section_risk_assessment(self) -> str:
        """Generate Risk Assessment Summary section."""
        lines = []
        lines.append("=" * 78)
        lines.append("4. RISK ASSESSMENT SUMMARY")
        lines.append("=" * 78)
        lines.append("")
        
        # Calculate overall risk
        severity_counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        if severity_counts.get("CRITICAL", 0) > 0:
            risk_level = "CRITICAL"
            risk_color = "CRITICAL security issues require immediate attention"
        elif severity_counts.get("HIGH", 0) > 0:
            risk_level = "HIGH"
            risk_color = "High-risk findings detected - investigation recommended"
        elif severity_counts.get("MEDIUM", 0) > 0:
            risk_level = "MEDIUM"
            risk_color = "Medium-risk findings present - review recommended"
        elif severity_counts.get("LOW", 0) > 0:
            risk_level = "LOW"
            risk_color = "Minor issues detected"
        else:
            risk_level = "CLEAN"
            risk_color = "No significant security findings"
        
        # Check for token replays
        if self.entra_correlation and self.entra_correlation.get("first_ta_replays"):
            risk_level = "CRITICAL"
            risk_color = "TOKEN REPLAY DETECTED - Active compromise likely"
        
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 40)
        lines.append(f"  Overall Risk:    [{risk_level}]")
        lines.append(f"  Assessment:      {risk_color}")
        lines.append("")
        
        # Findings by severity
        lines.append("FINDINGS BY SEVERITY")
        lines.append("-" * 40)
        lines.append(f"  CRITICAL:        {severity_counts.get('CRITICAL', 0)}")
        lines.append(f"  HIGH:            {severity_counts.get('HIGH', 0)}")
        lines.append(f"  MEDIUM:          {severity_counts.get('MEDIUM', 0)}")
        lines.append(f"  LOW:             {severity_counts.get('LOW', 0)}")
        lines.append(f"  INFO:            {severity_counts.get('INFO', 0)}")
        lines.append(f"  Total:           {len(self.findings)}")
        lines.append("")
        
        # Key threats
        lines.append("KEY THREATS IDENTIFIED")
        lines.append("-" * 40)
        if self.findings:
            for f in self.findings:
                if f.get("severity") in ("CRITICAL", "HIGH"):
                    lines.append(f"  • [{f['severity']}] {f['title']}")
            if not any(f.get("severity") in ("CRITICAL", "HIGH") for f in self.findings):
                lines.append("  No critical or high-severity threats identified.")
        else:
            lines.append("  No threats identified.")
        lines.append("")
        
        # AiTM risk
        lines.append("AiTM RISK ASSESSMENT")
        lines.append("-" * 40)
        aitm_risk = self.aitm_view.get("overall_risk", "Unknown")
        lines.append(f"  AiTM Risk:       {aitm_risk}")
        lines.append(f"  Proxy Status:    {self.aitm_view.get('proxy_status', 'Unknown')}")
        lines.append(f"  Redirect Chains: {len(self.aitm_view.get('redirect_chains', []))} transitions")
        lines.append(f"  Summary:         {self.aitm_view.get('summary', 'No summary')}")
        lines.append("")
        
        # Recommended actions
        lines.append("RECOMMENDED ACTIONS")
        lines.append("-" * 40)
        if risk_level == "CRITICAL":
            lines.append("  1. IMMEDIATE: Revoke all active sessions for affected identities")
            lines.append("  2. IMMEDIATE: Reset credentials for compromised accounts")
            lines.append("  3. Investigate Entra sign-in logs for unauthorized access")
            lines.append("  4. Review audit logs for post-compromise activity")
            lines.append("  5. Preserve this evidence package for incident response")
        elif risk_level == "HIGH":
            lines.append("  1. Review identified high-risk findings in detail")
            lines.append("  2. Correlate with Entra sign-in logs using provided anchors")
            lines.append("  3. Consider session revocation if token theft is suspected")
            lines.append("  4. Investigate flagged extensions and downloads")
        elif risk_level == "MEDIUM":
            lines.append("  1. Review medium-risk findings")
            lines.append("  2. Verify extension legitimacy")
            lines.append("  3. Check for signs of user deception (SEO poisoning, phishing)")
        else:
            lines.append("  1. No immediate action required")
            lines.append("  2. Retain evidence package for baseline comparison")
        lines.append("")
        
        return "\n".join(lines)
    
    def _section_detailed_findings(self) -> str:
        """Generate Detailed Findings section."""
        lines = []
        lines.append("=" * 78)
        lines.append("5. DETAILED FINDINGS")
        lines.append("=" * 78)
        lines.append("")
        
        if not self.findings:
            lines.append("  No findings to report.")
            lines.append("")
            return "\n".join(lines)
        
        lines.append("TABLE:findings")  # Marker for HTML table
        lines.append("")
        
        return "\n".join(lines)
    
    def _generate_findings_table_html(self) -> str:
        """Generate HTML table for findings."""
        import html as html_mod
        
        if not self.findings:
            return "<p>No findings to report.</p>"
        
        rows = []
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        severity_colors = {
            "CRITICAL": "#8b0000",
            "HIGH": "#cc0000",
            "MEDIUM": "#ff8c00",
            "LOW": "#b8860b",
            "INFO": "#0066cc"
        }
        
        # Group by severity
        by_severity = {}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(f)
        
        for sev in severity_order:
            if sev not in by_severity:
                continue
            
            color = severity_colors.get(sev, "#333")
            
            for f in by_severity[sev]:
                title = html_mod.escape(f.get('title', 'Unknown'))
                category = html_mod.escape(f.get('category', 'Unknown'))
                
                # Format evidence
                evidence_html = self._format_evidence_html(f.get('details', {}))
                
                # Format recommendation
                rec = f.get('recommendation', '')
                rec_html = html_mod.escape(rec) if rec else '<em>None</em>'
                
                rows.append(f"""<tr>
<td style="color: {color}; font-weight: bold; text-align: center; white-space: nowrap;">[{sev}]</td>
<td><strong>{title}</strong><br><small style="color: #666;">{category}</small></td>
<td>{evidence_html}</td>
<td>{rec_html}</td>
</tr>""")
        
        return f"""<table class='data-table findings-table'>
<thead>
<tr><th style="width: 80px;">Severity</th><th style="width: 25%;">Finding</th><th style="width: 35%;">Evidence</th><th style="width: 30%;">Recommended Action</th></tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>"""
    
    def _format_evidence_html(self, details: Dict) -> str:
        """Format finding evidence as HTML."""
        import html as html_mod
        
        if not details:
            return "<em>No specific evidence</em>"
        
        parts = []
        
        # SEO poisoning chains
        if 'chains' in details:
            for i, chain in enumerate(details['chains'][:3], 1):
                chain_parts = []
                if chain.get('search_query'):
                    chain_parts.append(f"Searched: <code>{html_mod.escape(chain['search_query'])}</code>")
                if chain.get('suspicious_visits'):
                    chain_parts.append(f"Visited {chain['suspicious_visits']} suspicious domains")
                if chain.get('suspicious_domains'):
                    domains = [str(d) for d in chain['suspicious_domains'][:3] if d]
                    if domains:
                        chain_parts.append(f"Domains: {', '.join(html_mod.escape(d) for d in domains)}")
                if chain.get('downloads'):
                    files = [str(d) for d in chain['downloads'] if d][:2]
                    if files:
                        chain_parts.append(f"Downloaded: <code>{html_mod.escape(', '.join(files))}</code>")
                if chain_parts:
                    parts.append(f"<strong>Chain {i}:</strong> " + "; ".join(chain_parts))
        
        # Extensions - format consistently with full details
        if 'extensions' in details:
            for ext in details['extensions'][:3]:
                if isinstance(ext, dict):
                    name = ext.get('name', 'Unknown')
                    ext_id = ext.get('id', '')
                    install_type = ext.get('install_type') or ext.get('installType', '')
                    issues = ext.get('issues', [])
                    
                    ext_parts = []
                    ext_parts.append(f"<strong>{html_mod.escape(name)}</strong>")
                    if ext_id:
                        ext_parts.append(f"ID: <code>{html_mod.escape(ext_id)}</code>")
                    if install_type:
                        ext_parts.append(f"Install: {html_mod.escape(install_type)}")
                    if issues:
                        ext_parts.append(f"Issues: {', '.join(html_mod.escape(str(i)) for i in issues[:3])}")
                    
                    parts.append("Extension: " + "<br>&nbsp;&nbsp;&nbsp;&nbsp;".join(ext_parts))
                else:
                    parts.append(f"Extension: {html_mod.escape(str(ext))}")
        
        # Extension correlations (sideloaded with install history)
        if 'correlations' in details:
            for corr in details['correlations'][:3]:
                if isinstance(corr, dict):
                    name = corr.get('extension_name', 'Unknown')
                    ext_id = corr.get('extension_id', '')
                    install_type = corr.get('install_type', '')
                    history = corr.get('possibly_related_history', [])
                    
                    corr_parts = [f"<strong>{html_mod.escape(name)}</strong>"]
                    if ext_id:
                        corr_parts.append(f"ID: <code>{html_mod.escape(ext_id)}</code>")
                    if install_type:
                        corr_parts.append(f"Install: {html_mod.escape(install_type)}")
                    if history:
                        urls = [h.get('url', '')[:50] for h in history[:2] if isinstance(h, dict)]
                        if urls:
                            corr_parts.append(f"Related URLs: {', '.join(urls)}")
                    
                    parts.append("Extension: " + "<br>&nbsp;&nbsp;&nbsp;&nbsp;".join(corr_parts))
        
        # Auth URLs (recently closed tabs)
        if 'auth_urls' in details:
            for auth in details['auth_urls'][:5]:
                if isinstance(auth, dict):
                    title = auth.get('title', 'Untitled')[:40]
                    url = auth.get('url', '')[:60]
                    parts.append(f"Tab: <strong>{html_mod.escape(title)}</strong><br>&nbsp;&nbsp;&nbsp;&nbsp;<code style='font-size:10px;'>{html_mod.escape(url)}</code>")
        
        # Permissions
        if 'permissions' in details and isinstance(details['permissions'], list):
            perms = details['permissions'][:6]
            if perms:
                parts.append(f"Permissions: <code>{', '.join(html_mod.escape(str(p)) for p in perms)}</code>")
        
        # Downloads (not in chains)
        if 'downloads' in details and 'chains' not in details:
            for dl in details['downloads'][:3]:
                if isinstance(dl, dict):
                    filename = dl.get('filename', 'Unknown')
                    parts.append(f"File: <code>{html_mod.escape(filename)}</code>")
        
        # URLs
        if 'urls' in details:
            for url in details['urls'][:3]:
                parts.append(f"URL: <code style='word-break:break-all;'>{html_mod.escape(url[:60])}</code>")
        
        # Domains
        if 'domains' in details:
            domains = [str(d) for d in details['domains'][:5] if d]
            if domains:
                parts.append(f"Domains: {', '.join(html_mod.escape(d) for d in domains)}")
        
        # Tabs (generic)
        if 'tabs' in details:
            for tab in details['tabs'][:3]:
                if isinstance(tab, dict):
                    title = tab.get('title', 'Untitled')[:40]
                    url = tab.get('url', '')[:50]
                    parts.append(f"Tab: <strong>{html_mod.escape(title)}</strong>" + 
                               (f" <code style='font-size:10px;'>{html_mod.escape(url)}</code>" if url else ""))
        
        # Other key-value pairs (skip already handled)
        skip_keys = {'chains', 'extensions', 'correlations', 'auth_urls', 'downloads', 
                     'urls', 'domains', 'tabs', 'permissions'}
        for key, value in details.items():
            if key in skip_keys:
                continue
            if isinstance(value, (str, int, float, bool)) and value:
                parts.append(f"{html_mod.escape(key)}: <code>{html_mod.escape(str(value))}</code>")
        
        if not parts:
            return "<em>No specific evidence</em>"
        
        return "<br>".join(parts)
    
    def _section_timelines(self) -> str:
        """Generate Timelines section."""
        lines = []
        lines.append("=" * 78)
        lines.append("6. TIMELINE ANALYSIS")
        lines.append("=" * 78)
        lines.append("")
        
        # Session Theft Timeline
        lines.append("SESSION THEFT TIMELINE")
        lines.append("-" * 40)
        
        tl = self.theft_timeline or {}
        stealable = tl.get("stealable_sessions", [])
        auth_flows = tl.get("authentication_flows", [])
        theft_windows = tl.get("theft_windows", [])
        
        lines.append(f"  Stealable Sessions (ESTS): {len(stealable)}")
        lines.append(f"  IdP Authentication Flows:  {len(auth_flows)}")
        lines.append(f"  Theft Windows:             {len(theft_windows)}")
        lines.append("")
        
        # Show theft windows if any
        if theft_windows:
            lines.append("  THEFT WINDOWS:")
            for i, tw in enumerate(theft_windows[:5], 1):
                lines.append(f"    [{i}] {tw.get('identity', 'Unknown')}")
                birth_lower = self._fmt_epoch_dual(tw.get('session_birth_lower'))
                birth_upper = self._fmt_epoch_dual(tw.get('session_birth_upper'))
                lines.append(f"        Session Birth Lower: {birth_lower}")
                lines.append(f"        Session Birth Upper: {birth_upper}")
                lines.append(f"        Birth Source:        {tw.get('birth_source', 'Unknown')}")
            lines.append("")
        
        # Show recent auth flows
        if auth_flows:
            lines.append("  RECENT AUTHENTICATION FLOWS (last 10):")
            for i, flow in enumerate(auth_flows[-10:], 1):
                visit_time = self._fmt_epoch_dual(flow.get('visit_time'))
                idp = flow.get('idp') or flow.get('idp_type') or '?'
                lines.append(f"    [{i}] {idp}")
                lines.append(f"        Time:     {visit_time}")
                lines.append(f"        Delivery: {flow.get('delivery_vector', 'Unknown')}")
                if flow.get('url'):
                    lines.append(f"        URL:      {flow['url']}")
            lines.append("")
        
        # Entra correlation results
        if self.entra_correlation:
            lines.append("ENTRA LOG CORRELATION")
            lines.append("-" * 40)
            ec = self.entra_correlation
            lines.append(f"  Identities Matched:    {ec.get('identities_matched', 0)}")
            lines.append(f"  Sign-ins Analyzed:     {ec.get('signins_analyzed', 0)}")
            lines.append(f"  Anomalous Sign-ins:    {len(ec.get('anomalous_signins', []))}")
            lines.append(f"  Token Replays:         {len(ec.get('first_ta_replays', []))}")
            lines.append("")
            
            replays = ec.get("first_ta_replays", [])
            if replays:
                lines.append("  🚨 TOKEN REPLAYS DETECTED:")
                for r in replays[:5]:
                    lines.append(f"    • {r.get('identity', '?')}")
                    lines.append(f"      Replay Time: {r.get('first_replay_time', '?')}")
                    lines.append(f"      Theft IP:    {r.get('ip_address', '?')}")
                    lines.append(f"      Window:      {r.get('theft_window', '?')}")
                lines.append("")
        
        # Event summary
        lines.append("EVENT TIMELINE SUMMARY")
        lines.append("-" * 40)
        lines.append(f"  Total Events:    {len(self.events)}")
        if self.events:
            lines.append(f"  First Event:     {self._fmt_ts(self.events[0].get('ts'))}")
            lines.append(f"  Last Event:      {self._fmt_ts(self.events[-1].get('ts'))}")
            
            # Count by type
            by_kind = {}
            for e in self.events:
                kind = e.get("kind", "unknown")
                by_kind[kind] = by_kind.get(kind, 0) + 1
            
            lines.append("  By Type:")
            for kind, count in sorted(by_kind.items(), key=lambda x: -x[1])[:8]:
                lines.append(f"    {kind}: {count}")
        lines.append("")
        
        return "\n".join(lines)
    
    def _section_correlation_guidance(self) -> str:
        """Generate Correlation Guidance section."""
        lines = []
        lines.append("=" * 78)
        lines.append("7. CORRELATION GUIDANCE")
        lines.append("=" * 78)
        lines.append("")
        
        lines.append("KEY CORRELATION ANCHORS")
        lines.append("-" * 40)
        lines.append("  • ESTS cookie = 'loaded gun on the table' — proves replayable session existed")
        lines.append("  • visitdetails = best causal anchor — dates lure + auth (AiTM capture moment)")
        lines.append("  • auth_time claim = precise session birth (when available in cleartext tokens)")
        lines.append("  • Theft window = [session_birth, first_TA_replay_in_Entra_logs]")
        lines.append("")
        
        lines.append("ENTRA SIGN-IN LOG QUERIES")
        lines.append("-" * 40)
        
        # Extract correlation anchors
        anchors = self.theft_timeline.get("correlation_anchors", []) if self.theft_timeline else []
        if anchors:
            for a in anchors[:3]:
                lines.append(f"  Identity: {a.get('upn', a.get('object_id', 'Unknown'))}")
                lines.append(f"  Tenant:   {a.get('tenant_id', 'Unknown')}")
                lines.append(f"  Query:    Filter by userId eq '{a.get('object_id', '?')}'")
                lines.append(f"            within {a.get('validity_start', '?')} to {a.get('validity_end', '?')}")
                lines.append("")
        else:
            lines.append("  No specific correlation anchors extracted.")
            lines.append("  Use tenant_id and object_id from Identity Inventory section.")
        lines.append("")
        
        lines.append("PURVIEW/UAL GUIDANCE")
        lines.append("-" * 40)
        lines.append("  • Pivot on SessionId in audit records")
        lines.append("  • Look for same SessionId used from different ClientIP")
        lines.append("  • Storage tokens (localStorage/IndexedDB) may have longer validity than cookies")
        lines.append("  • Check for refresh token reuse patterns")
        lines.append("")
        
        return "\n".join(lines)
    
    def _section_chain_of_custody(self) -> str:
        """Generate full Chain of Custody section."""
        lines = []
        lines.append("=" * 78)
        lines.append("8. CHAIN OF CUSTODY")
        lines.append("=" * 78)
        lines.append("")
        
        coc_entries = self.chain.get("events", self.chain.get("entries", []))
        
        if not coc_entries:
            lines.append("  No chain of custody entries recorded.")
            lines.append("")
            return "\n".join(lines)
        
        lines.append(f"  Collection ID: {self.chain.get('collection_id', 'Unknown')}")
        lines.append(f"  Workflow:      {self.chain.get('workflow', 'Unknown')}")
        lines.append(f"  Total Events:  {len(coc_entries)}")
        lines.append("")
        lines.append("-" * 78)
        lines.append("")
        
        # Show ALL events with full details
        for i, entry in enumerate(coc_entries, 1):
            ts = entry.get('timestamp_utc', entry.get('timestamp', '?'))
            operator = entry.get('operator', entry.get('actor', '?'))
            action = entry.get('action', '?')
            detail = entry.get('detail', {})
            
            # Format based on action type
            if action == 'session_started':
                lines.append(f"  [{i}] SESSION STARTED")
                lines.append(f"      Timestamp:      {ts}")
                lines.append(f"      Operator:       {operator}")
                if isinstance(detail, dict):
                    lines.append(f"      Collection ID:  {detail.get('collection_id', '?')}")
                    lines.append(f"      Container:      {detail.get('container', '?')}")
                    scope = detail.get('scope', [])
                    if scope:
                        lines.append(f"      Scope ({len(scope)} artifact types):")
                        for s in scope:
                            lines.append(f"        - {s}")
                lines.append("")
                
            elif action == 'artifact_collected':
                if isinstance(detail, dict):
                    path = detail.get('path', '?')
                    records = detail.get('record_count', '?')
                    sha256 = detail.get('sha256', '')
                    lines.append(f"  [{i}] ARTIFACT COLLECTED: {path}")
                    lines.append(f"      Timestamp:      {ts}")
                    lines.append(f"      Record Count:   {records}")
                    if sha256:
                        lines.append(f"      SHA-256:        {sha256}")
                lines.append("")
                
            elif action == 'collection_complete':
                lines.append(f"  [{i}] COLLECTION COMPLETE")
                lines.append(f"      Timestamp:      {ts}")
                lines.append(f"      Operator:       {operator}")
                lines.append("")
                
            else:
                lines.append(f"  [{i}] {action.upper()}")
                lines.append(f"      Timestamp:      {ts}")
                lines.append(f"      Operator:       {operator}")
                if detail:
                    lines.append(f"      Detail:         {str(detail)}")
                lines.append("")
        
        return "\n".join(lines)
    
    def generate_txt(self) -> str:
        """Generate complete TXT report."""
        sections = []
        
        # Header
        sections.append("=" * 78)
        sections.append("BAI OFFLINE ANALYSIS - FORENSIC REPORT")
        sections.append("=" * 78)
        
        now_utc = datetime.now(timezone.utc)
        if self.tz:
            now_local = now_utc.astimezone(self.tz)
            sections.append(f"Generated: {now_local.strftime('%Y-%m-%d %H:%M:%S %Z')} ({now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')})")
            sections.append(f"Display Timezone: {self.tz}")
        else:
            sections.append(f"Generated: {now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        sections.append("")
        
        # All sections
        sections.append(self._section_evidence_provenance())
        sections.append(self._section_system_context())
        sections.append(self._section_identity_inventory())
        sections.append(self._section_risk_assessment())
        sections.append(self._section_detailed_findings())
        sections.append(self._section_timelines())
        sections.append(self._section_chain_of_custody())
        
        # Footer
        sections.append("=" * 78)
        sections.append("END OF REPORT")
        sections.append("=" * 78)
        
        return "\n".join(sections)
    
    def generate_html(self) -> str:
        """Generate complete HTML report."""
        # Convert TXT sections to HTML with styling
        txt_content = self.generate_txt()
        
        # Escape HTML and convert structure
        import html as html_mod
        escaped = html_mod.escape(txt_content)
        
        # Convert section headers to styled divs
        lines = escaped.split("\n")
        html_lines = []
        in_section = False
        
        for line in lines:
            # Handle table markers (not escaped)
            if "TABLE:identity_accounts" in line:
                html_lines.append(self._generate_identity_table_html())
                continue
            elif "TABLE:entra_sessions" in line:
                html_lines.append(self._generate_entra_table_html())
                continue
            elif "TABLE:findings" in line:
                html_lines.append(self._generate_findings_table_html())
                continue
            
            if line.startswith("=" * 20):
                if in_section:
                    html_lines.append("</div>")
                html_lines.append("<hr class='section-break'>")
                in_section = False
            elif line.startswith("-" * 20):
                html_lines.append("<hr class='subsection-break'>")
            elif line.startswith("[CRITICAL]") or line.startswith("[HIGH]") or \
                 line.startswith("[MEDIUM]") or line.startswith("[LOW]") or line.startswith("[INFO]"):
                sev = line.strip("[]")
                html_lines.append(f"<h3 class='severity-{sev.lower()}'>{line}</h3>")
            elif any(line.startswith(f"{i}. ") for i in range(1, 10)):
                html_lines.append(f"<h2>{line}</h2>")
                html_lines.append("<div class='section'>")
                in_section = True
            elif line.strip().isupper() and len(line.strip()) > 5 and ":" not in line:
                html_lines.append(f"<h3>{line}</h3>")
            else:
                html_lines.append(f"<pre>{line}</pre>")
        
        if in_section:
            html_lines.append("</div>")
        
        body = "\n".join(html_lines)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BAI Forensic Analysis Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }}
        .header {{
            text-align: center;
            padding: 10px;
            background: #cc0000;
            color: white;
            margin-bottom: 20px;
            font-style: italic;
        }}
        h1 {{
            color: #1a1a2e;
            border-bottom: 3px solid #1a1a2e;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #16213e;
            background: #e8e8e8;
            padding: 10px;
            margin-top: 30px;
        }}
        h3 {{
            color: #0f3460;
            margin-top: 20px;
        }}
        pre {{
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 12px;
            margin: 2px 0;
            white-space: pre-wrap;
        }}
        .section {{
            background: white;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .section-break {{
            border: none;
            border-top: 3px solid #1a1a2e;
            margin: 30px 0;
        }}
        .subsection-break {{
            border: none;
            border-top: 1px solid #ccc;
            margin: 15px 0;
        }}
        .severity-critical {{ color: #8b0000; font-weight: bold; }}
        .severity-high {{ color: #cc0000; font-weight: bold; }}
        .severity-medium {{ color: #ff8c00; font-weight: bold; }}
        .severity-low {{ color: #b8860b; }}
        .severity-info {{ color: #0066cc; }}
        /* Data tables */
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            font-size: 12px;
        }}
        .data-table th, .data-table td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
            vertical-align: top;
        }}
        .data-table th {{
            background: #1a1a2e;
            color: white;
            font-weight: bold;
        }}
        .data-table tr:nth-child(even) {{
            background: #f9f9f9;
        }}
        .data-table tr:hover {{
            background: #f0f0f0;
        }}
        .upn-cell {{
            font-weight: bold;
            background: #e8f4e8;
            font-family: monospace;
        }}
        .high-risk {{
            color: #cc0000;
            font-weight: bold;
        }}
        .low-risk {{
            color: #228b22;
        }}
        .identity-table td:first-child {{
            white-space: nowrap;
        }}
        .entra-table code {{
            font-size: 10px;
            background: #f0f0f0;
            padding: 2px 4px;
            border-radius: 3px;
        }}
        .findings-table td {{
            font-size: 11px;
        }}
        .findings-table code {{
            font-size: 10px;
            background: #f5f5f5;
            padding: 1px 4px;
            border-radius: 3px;
            word-break: break-all;
        }}
        .findings-table td:first-child {{
            vertical-align: middle;
        }}
        .footer {{
            text-align: center;
            padding: 10px;
            margin-top: 30px;
            font-size: 11px;
            color: #666;
        }}
        @media print {{
            body {{ background: white; }}
            .section {{ box-shadow: none; border: 1px solid #ccc; }}
            .header {{ background: #333; -webkit-print-color-adjust: exact; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        Privileged and Confidential - DRAFT Work Product
    </div>
    <h1>BAI Forensic Analysis Report</h1>
    {body}
    <div class="footer">
        Generated by BAI Analyzer | © 2026, Shane Shook, All Rights Reserved
    </div>
</body>
</html>"""
        
        return html
    
    def write_identity_csv(self, path: str):
        """Write identity inventory to CSV."""
        inventory = self.build_identity_inventory()
        
        with open(path, "w", encoding="utf-8", newline="") as f:
            import csv
            writer = csv.DictWriter(f, fieldnames=[
                "identity", "idp", "domain", "tenant_id", "object_id",
                "mfa_status", "token_types", "valid_until", "cookie_count", "httponly"
            ])
            writer.writeheader()
            for entry in inventory:
                writer.writerow(entry)


# --------------------------------------------------------------------------- #
# Console report (legacy, kept for backward compatibility)
# --------------------------------------------------------------------------- #

def print_findings_report(findings: List[Dict], aitm_view: Dict):
    print()
    print("=" * 78)
    print("FINDINGS (Severity-Ranked)")
    print("=" * 78)
    
    if not findings:
        print("  No findings to report.")
        return
    
    # Group by severity for display
    for severity in Severity:
        sev_findings = [f for f in findings if f["severity"] == severity.value]
        if not sev_findings:
            continue
        
        print()
        print(f"[{severity.value}]")
        print("-" * 40)
        
        for f in sev_findings:
            print(f"  • {f['title']}")
            print(f"    Category: {f['category']}")
            if f.get("recommendation"):
                rec = f["recommendation"]
                # Wrap long recommendations
                if len(rec) > 70:
                    words = rec.split()
                    lines = []
                    current = "    → "
                    for w in words:
                        if len(current) + len(w) > 76:
                            lines.append(current)
                            current = "      " + w + " "
                        else:
                            current += w + " "
                    lines.append(current)
                    print("\n".join(lines))
                else:
                    print(f"    → {rec}")
            print()


def print_aitm_summary(aitm_view: Dict):
    print()
    print("=" * 78)
    print("CROSS-ARTIFACT AiTM VIEW")
    print("=" * 78)
    print(f"  Overall Risk: {aitm_view['overall_risk']}")
    print(f"  Proxy Status: {aitm_view['proxy_status']}")
    print(f"  Redirect Chains: {len(aitm_view['redirect_chains'])} transitions")
    print(f"  Timing Anomalies: {len(aitm_view['timing_anomalies'])} pages")
    print()
    print(f"  Summary: {aitm_view['summary']}")


def print_auth_report(sessions: List[Dict], storage_tokens: List[Dict], tz):
    print()
    print("=" * 78)
    print("AUTH SESSIONS / IdP IDENTITY ANCHORS")
    print("=" * 78)
    
    idp_sessions = [s for s in sessions if not s["idp"].startswith("(generic")]
    generic = [s for s in sessions if s["idp"].startswith("(generic")]
    
    if not idp_sessions and not storage_tokens:
        print("  (no IdP-classified cookies or storage tokens found)")
        return
    
    for s in idp_sessions:
        print(f"* {s['idp']}  [{s['domain']}]")
        if s.get("upn"):
            print(f"    UPN        : {s['upn']}")
        if s.get("tenant_id"):
            print(f"    Tenant ID  : {s['tenant_id']}")
        if s.get("object_id"):
            print(f"    Object ID  : {s['object_id']}")
        if s.get("token_types"):
            print(f"    Token types: {', '.join(s['token_types'])}"
                  f"{'  (PERSISTENT/stay-signed-in)' if s['any_persistent'] else ''}")
        if s.get("latest_expiry"):
            print(f"    Valid until: {s['latest_expiry']}  (replay window upper bound)")
        print(f"    Cookies    : {len(s['cookie_names'])} "
              f"({'has HttpOnly session bearer' if s['any_httponly'] else 'no HttpOnly'})")
        print()
    
    if generic:
        print(f"  + {len(generic)} other domain(s) carry a recognized strong bearer cookie.")
    
    if storage_tokens:
        print()
        print(f"  + {len(storage_tokens)} token(s) found in localStorage/IndexedDB")
        # Group by origin
        by_origin = defaultdict(list)
        for t in storage_tokens:
            by_origin[t.get("origin", "unknown")].append(t)
        for origin, tokens in list(by_origin.items())[:5]:
            print(f"    - {origin}: {len(tokens)} token(s)")


def print_theft_timeline(theft_timeline: Dict, tz):
    """Print Session Theft Timeline summary."""
    print()
    print("=" * 78)
    print("SESSION THEFT TIMELINE - CAUSAL CHAIN")
    print("=" * 78)
    
    stealable = theft_timeline.get("stealable_sessions", [])
    auth_flows = theft_timeline.get("authentication_flows", [])
    birth_anchors = theft_timeline.get("session_birth_anchors", [])
    droppers = theft_timeline.get("dropper_downloads", [])
    theft_windows = theft_timeline.get("theft_windows", [])
    correlation = theft_timeline.get("correlation_anchors", [])
    
    print(f"\n  Stealable Sessions (ESTS): {len(stealable)}")
    print(f"  IdP Authentication Flows:  {len(auth_flows)}")
    print(f"  Session Birth Anchors:     {len(birth_anchors)}")
    print(f"  Potential Droppers:        {len(droppers)}")
    
    # Show stealable sessions
    if stealable:
        print()
        print("-" * 40)
        print("STEALABLE SESSIONS (ESTS Cookies)")
        print("-" * 40)
        for i, s in enumerate(stealable[:5], 1):
            print(f"  [{i}] {s.get('cookie_name', '?')} @ {s.get('domain', '?')}")
            print(f"      Tenant: {s.get('tenant_id', '?')}")
            print(f"      Object: {s.get('object_id', '?')}")
            print(f"      UPN:    {s.get('upn', '?')}")
            print(f"      Exp:    {s.get('expiration', '?')}")
            if s.get("estimated_birth"):
                print(f"      Est Birth: {s.get('estimated_birth', '?')}")
    
    # Show authentication flows
    if auth_flows:
        print()
        print("-" * 40)
        print("IdP AUTHENTICATION FLOWS (visitdetails)")
        print("-" * 40)
        print("  These are the causal anchors - the visit_time approximates")
        print("  when the session was born (and when AiTM could capture it).")
        print()
        for i, flow in enumerate(auth_flows[:5], 1):
            print(f"  [{i}] {flow.get('idp_type', '?')} auth at {flow.get('visit_time', '?')}")
            print(f"      URL: {flow.get('idp_url', '?')[:70]}...")
            print(f"      Delivery Vector: {flow.get('delivery_vector', '?')}")
            if flow.get("referrer_chain"):
                print(f"      Chain depth: {flow.get('chain_depth', 0)} hops")
                if len(flow["referrer_chain"]) > 1:
                    print(f"      Lure: {flow['referrer_chain'][0].get('url', '?')[:60]}...")
    
    # Show session birth anchors (auth_time)
    if birth_anchors:
        print()
        print("-" * 40)
        print("SESSION BIRTH ANCHORS (auth_time claims)")
        print("-" * 40)
        print("  auth_time is the interactive authentication instant (MFA moment).")
        print("  More precise than iat (which can be silent refresh).")
        print()
        for anchor in birth_anchors[:3]:
            print(f"  • {anchor.get('source', '?')}: {anchor.get('auth_time', '?')}")
            if anchor.get("amr"):
                print(f"    Auth methods: {anchor.get('amr')}")
    
    # Show theft windows
    if theft_windows:
        print()
        print("-" * 40)
        print("THEFT WINDOWS")
        print("-" * 40)
        for i, tw in enumerate(theft_windows[:3], 1):
            identity = tw.get("identity", {})
            print(f"  [{i}] {identity.get('upn', identity.get('object_id', '?'))}")
            print(f"      Birth: {tw.get('session_birth_lower', '?')}")
            print(f"      Expires: {tw.get('validity_end', '?')}")
            print(f"      Source: {tw.get('birth_source', '?')}")
            print("      → Theft window = [session_birth, first_TA_replay_in_Entra_logs]")
    
    # Show correlation guidance
    if correlation:
        print()
        print("-" * 40)
        print("ENTRA SIGN-IN LOG CORRELATION")
        print("-" * 40)
        for anchor in correlation[:2]:
            print(f"  Tenant: {anchor.get('tenant_id', '?')}")
            print(f"  Object: {anchor.get('object_id', '?')}")
            print(f"  UPN:    {anchor.get('upn', '?')}")
            print()
            print("  Query Guidance:")
            guidance = anchor.get("query_guidance", "")
            for line in guidance.split(". "):
                if line.strip():
                    print(f"    • {line.strip()}.")


def print_entra_correlation(correlation: Dict):
    """Print Entra/Purview log correlation results."""
    print()
    print("=" * 78)
    print("ENTRA/PURVIEW LOG CORRELATION")
    print("=" * 78)
    
    print(f"\n  Identities Matched:    {correlation.get('identities_matched', 0)}")
    print(f"  Sign-ins Analyzed:     {correlation.get('signins_analyzed', 0)}")
    print(f"  Anomalous Sign-ins:    {len(correlation.get('anomalous_signins', []))}")
    print(f"  Token Replays:         {len(correlation.get('first_ta_replays', []))}")
    print(f"  Post-Compromise Acts:  {len(correlation.get('post_compromise_activity', []))}")
    
    # Token replays (most critical)
    replays = correlation.get("first_ta_replays", [])
    if replays:
        print()
        print("-" * 40)
        print("🚨 TOKEN REPLAYS DETECTED (HIGH CONFIDENCE)")
        print("-" * 40)
        for i, replay in enumerate(replays[:5], 1):
            print(f"  [{i}] {replay.get('identity', '?')}")
            print(f"      First Replay: {replay.get('first_replay_time', '?')}")
            print(f"      Theft IP:     {replay.get('ip_address', '?')}")
            print(f"      Location:     {replay.get('location', '?')}")
            print(f"      Session Birth: {replay.get('session_birth', '?')}")
            print(f"      THEFT WINDOW: {replay.get('theft_window', '?')}")
    
    # Completed theft windows
    completed = correlation.get("completed_theft_windows", [])
    if completed:
        print()
        print("-" * 40)
        print("COMPLETED THEFT WINDOWS")
        print("-" * 40)
        for tw in completed[:5]:
            print(f"  • {tw.get('identity', '?')}")
            print(f"    Birth → Replay: {tw.get('session_birth', '?')} → {tw.get('first_ta_replay', '?')}")
            print(f"    Theft from: {tw.get('theft_ip', '?')} ({tw.get('theft_location', '?')})")
    
    # Anomalous sign-ins
    anomalies = correlation.get("anomalous_signins", [])
    if anomalies:
        print()
        print("-" * 40)
        print(f"ANOMALOUS SIGN-INS ({len(anomalies)} detected)")
        print("-" * 40)
        for i, a in enumerate(anomalies[:10], 1):
            replay_tag = " [TOKEN REPLAY]" if a.get("is_token_replay_signature") else ""
            print(f"  [{i}] {a.get('identity', '?')} @ {a.get('timestamp', '?')}{replay_tag}")
            print(f"      IP: {a.get('ip_address', '?')} | {a.get('location', '?')}")
            print(f"      Type: {a.get('log_type', '?')} | App: {a.get('app', '?')}")
            if a.get("baseline_ips"):
                print(f"      Baseline IPs: {', '.join(a['baseline_ips'][:3])}")
    
    # Post-compromise activity
    post_comp = correlation.get("post_compromise_activity", [])
    if post_comp:
        print()
        print("-" * 40)
        print(f"POST-COMPROMISE ACTIVITY ({len(post_comp)} suspicious actions)")
        print("-" * 40)
        for i, act in enumerate(post_comp[:10], 1):
            print(f"  [{i}] {act.get('timestamp', '?')}: {act.get('activity', '?')}")
            print(f"      Actor: {act.get('actor', '?')}")
            if act.get("target"):
                print(f"      Target: {act.get('target')}")


def print_report(pkg: Dict, findings: List[Dict], aitm_view: Dict, 
                 sessions: List[Dict], storage_tokens: List[Dict], 
                 events: List[Dict], tz, theft_timeline: Dict = None,
                 entra_correlation: Dict = None):
    man = pkg.get("MANIFEST.json") or {}
    env = man.get("environment", {})
    case = man.get("case", {})
    
    print("=" * 78)
    print("BAI OFFLINE ANALYSIS - MISSION-FOCUSED REPORT")
    print("=" * 78)
    print(f"Case        : {case.get('case_id','?')}   Examiner: {case.get('examiner','?')}")
    print(f"Browser     : {env.get('platform','?')} / Chrome {env.get('chrome_version','?')}  "
          f"tz={env.get('timezone','?')}")
    print(f"Collection  : {man.get('collection_id','?')}")
    print(f"Events      : {len(events)}")
    if events:
        print(f"Window      : {fmt(events[0]['ts'], tz)}  ->  {fmt(events[-1]['ts'], tz)}")
    
    # Summary stats
    print()
    print("ARTIFACT SUMMARY")
    print("-" * 40)
    artifact_counts = {
        "cookies": len(records(pkg.get("cookies.json"))),
        "history": len(records(pkg.get("history.json"))),
        "downloads": len(records(pkg.get("downloads.json"))),
        "extensions": len(records(pkg.get("extensions.json"))),
        "webstorage_origins": len(records(pkg.get("webstorage.json"))),
        "indexeddb_origins": len(records(pkg.get("indexeddb.json") or pkg.get("indexeddbfull.json"))),
    }
    for name, count in artifact_counts.items():
        print(f"  {name}: {count}")
    
    # Findings section
    print_findings_report(findings, aitm_view)
    
    # AiTM view
    print_aitm_summary(aitm_view)
    
    # Auth sessions
    print_auth_report(sessions, storage_tokens, tz)
    
    # Session Theft Timeline
    if theft_timeline:
        print_theft_timeline(theft_timeline, tz)
    
    # Entra/Purview correlation (if available)
    if entra_correlation:
        print_entra_correlation(entra_correlation)
    
    print()
    print("=" * 78)
    print("CORRELATION GUIDANCE")
    print("=" * 78)
    print("• ESTS cookie = 'loaded gun on the table' — proves replayable session existed")
    print("• visitdetails = best causal anchor — dates lure + auth (AiTM capture moment)")
    print("• auth_time claim = precise session birth (when available in cleartext tokens)")
    print("• Theft window = [session_birth, first_TA_replay_in_Entra_logs]")
    print()
    print("• Entra Sign-in Logs: Join on tenant_id + object_id + UPN within token")
    print("  validity window. Hunt for same session reused from new IP/ASN/device.")
    print("• Purview/UAL: Pivot on SessionId in audit records.")
    print("• Storage Tokens: localStorage/IndexedDB tokens may have longer validity")
    print("  than cookies. Check for refresh token reuse.")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(
        description="Mission-focused offline analyzer for BAI packages. "
                    "Prioritizes AiTM and infostealer detection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic BAI-only analysis
    python3 bai_analyze.py /path/to/BAI_package_or_zip
    python3 bai_analyze.py pkg.zip --out ./analysis --tz America/Los_Angeles
    python3 bai_analyze.py pkg/  --since 2026-06-01 --until 2026-06-11
    
    # With Entra/Purview log correlation (complete theft window analysis)
    python3 bai_analyze.py pkg.zip --entra-logs /path/to/logs/
    
    # Entra logs folder should contain (CSV or JSON, auto-detected by filename):
    #   - InteractiveSignIns.csv/json
    #   - NonInteractiveSignIns.csv/json  
    #   - ServicePrincipalSignIns.csv/json (optional)
    #   - ManagedIdentitySignIns.csv/json (optional)
    #   - AuditLogs.csv/json
    #   - UnifiedAuditLog.csv/json (Purview/UAL)
    
    python3 bai_analyze.py pkg/  --include-token-values  # DANGEROUS: writes raw tokens
    python3 bai_analyze.py pkg/  --online  # Enable WHOIS/RDAP lookups for domain age
        """
    )
    ap.add_argument("package", help="BAI package folder or .zip")
    ap.add_argument("--out", default="./bai_analysis", help="output directory")
    ap.add_argument("--format", choices=["txt", "html"], default="txt",
                    help="Report output format (default: txt)")
    ap.add_argument("--tz", default=None, help="display timezone, e.g. America/Los_Angeles")
    ap.add_argument("--since", default=None, help="filter events on/after YYYY-MM-DD")
    ap.add_argument("--until", default=None, help="filter events on/before YYYY-MM-DD")
    ap.add_argument("--entra-logs", default=None, metavar="FOLDER",
                    help="Folder containing Entra sign-in logs, audit logs, and Purview UAL "
                         "(CSV or JSON). Auto-detects: Interactive, NonInteractive, "
                         "ServicePrincipal, ManagedIdentity, Audit, UnifiedAuditLog")
    ap.add_argument("--include-token-values", action="store_true",
                    help="DANGEROUS: write raw token values into output JSON")
    ap.add_argument("--online", action="store_true",
                    help="Enable online lookups (WHOIS/RDAP) for domain age analysis")
    ap.add_argument("--quiet", "-q", action="store_true",
                    help="minimal console output (just write files)")
    args = ap.parse_args()
    
    tz = _try_zoneinfo(args.tz)
    since = parse_iso(args.since + "T00:00:00+00:00") if args.since else None
    until = parse_iso(args.until + "T23:59:59+00:00") if args.until else None
    
    pkg = load_package(args.package)
    if "cookies.json" not in pkg and "history.json" not in pkg:
        raise SystemExit("[fatal] no cookies.json or history.json found in package")
    
    if args.online:
        print("[*] Online mode enabled - will perform WHOIS/RDAP lookups for domain analysis")
    
    # Load Entra/Purview logs if provided
    entra_logs = None
    if args.entra_logs:
        print(f"[*] Loading Entra/Purview logs from: {args.entra_logs}")
        entra_logs = discover_entra_logs(args.entra_logs)
        total_logs = sum(len(v) for v in entra_logs.values())
        print(f"[+] Loaded {total_logs} total log records for correlation")
    
    # Run all analyzers
    sessions, idp_cookies = analyze_cookies(pkg.get("cookies.json"), 
                                            include_values=args.include_token_values)
    findings, supplementary = aggregate_findings(pkg, include_values=args.include_token_values,
                                                 online=args.online)
    aitm_view = build_aitm_view(pkg, findings)
    events = build_timeline(pkg, since=since, until=until)
    
    # Combine storage tokens
    all_storage_tokens = supplementary["storage_tokens"] + supplementary["indexeddb_tokens"]
    
    # Build Session Theft Timeline for causal chain reconstruction
    # Combines auth_sessions with visitdetails to date the lure/auth and bracket the theft
    all_auth_sessions = sessions + all_storage_tokens
    theft_timeline = build_session_theft_timeline(pkg, all_auth_sessions)
    
    # Correlate with Entra logs if provided
    entra_correlation = None
    if entra_logs:
        print("[*] Correlating BAI identities with Entra/Purview logs...")
        entra_correlation = correlate_entra_logs(theft_timeline, entra_logs)
        print(f"[+] Correlation: {entra_correlation.get('summary', 'complete')}")
    
    # Discover user accounts using UPN-centric approach
    upn_accounts = discover_upn_accounts(pkg)
    
    # Build tenant-to-UPN mapping from login URLs, then discover Entra sessions
    tenant_upn_map = discover_tenant_upn_mapping(pkg)
    entra_sessions = discover_entra_sessions(pkg, tenant_upn_map)
    
    if not args.quiet:
        if upn_accounts:
            print(f"[+] Discovered {len(upn_accounts)} UPN accounts from cookies/storage")
        if entra_sessions:
            print(f"[+] Discovered {len(entra_sessions)} Microsoft Entra sessions")
    
    # Write outputs
    os.makedirs(args.out, exist_ok=True)
    
    tl_csv = os.path.join(args.out, "timeline.csv")
    findings_json = os.path.join(args.out, "findings.json")
    auth_json = os.path.join(args.out, "auth_sessions.json")
    identity_csv = os.path.join(args.out, "identity_inventory.csv")
    
    write_timeline_csv(events, tz, tl_csv)
    write_findings_json(findings, aitm_view, theft_timeline, findings_json, entra_correlation)
    write_auth_json(sessions, idp_cookies, all_storage_tokens, auth_json)
    
    # Generate structured report
    report_gen = ReportGenerator(
        pkg=pkg,
        findings=findings,
        aitm_view=aitm_view,
        sessions=sessions,
        storage_tokens=all_storage_tokens,
        events=events,
        theft_timeline=theft_timeline,
        entra_correlation=entra_correlation,
        upn_accounts=upn_accounts,
        entra_sessions=entra_sessions,
        tz=tz
    )
    
    # Write report in requested format
    if args.format == "html":
        report_path = os.path.join(args.out, "report.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_gen.generate_html())
    else:
        report_path = os.path.join(args.out, "report.txt")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_gen.generate_txt())
    
    # Write identity inventory CSV
    report_gen.write_identity_csv(identity_csv)
    
    # Write Entra correlation if available
    if entra_correlation:
        correlation_json = os.path.join(args.out, "entra_correlation.json")
        with open(correlation_json, "w", encoding="utf-8") as f:
            json.dump(entra_correlation, f, indent=2, default=str)
    
    # Console report (legacy format for terminal viewing)
    if not args.quiet:
        print_report(pkg, findings, aitm_view, sessions, all_storage_tokens, events, tz, 
                     theft_timeline, entra_correlation)
    
    print()
    print(f"[+] report written        : {report_path}")
    print(f"[+] identity inventory    : {identity_csv}  ({len(sessions) + len(all_storage_tokens)} identities)")
    print(f"[+] timeline written      : {tl_csv}  ({len(events)} events)")
    print(f"[+] findings written      : {findings_json}  ({len(findings)} findings)")
    print(f"[+] auth sessions written : {auth_json}  ({len(sessions)} sessions, "
          f"{len(all_storage_tokens)} storage tokens)")
    if entra_correlation:
        print(f"[+] entra correlation     : {os.path.join(args.out, 'entra_correlation.json')}")
    
    if args.include_token_values:
        print("[!] WARNING: raw token values were written - treat output as live credentials.")
    
    # Exit with non-zero if critical/high findings or token replays detected
    critical_high = [f for f in findings 
                     if f["severity"] in (Severity.CRITICAL.value, Severity.HIGH.value)]
    token_replays = entra_correlation.get("first_ta_replays", []) if entra_correlation else []
    
    if token_replays:
        print(f"\n[!!!] {len(token_replays)} TOKEN REPLAY(S) DETECTED - likely active compromise!")
        return 2
    if critical_high:
        print(f"\n[!] {len(critical_high)} CRITICAL/HIGH severity finding(s) detected!")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
