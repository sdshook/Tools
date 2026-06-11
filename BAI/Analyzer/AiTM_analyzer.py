#!/usr/bin/env python3
# (c) 2026 Shane D. Shook. All rights reserved - for authorized testing and analysis.
"""
AiTM_analyzer.py - Unified adversary-in-the-middle (AiTM) / token-theft analyzer.

ONE tool, THREE evidence modes:

  * host  : a BAI (Browser Audit Inventory) package - decodes browser web-storage
            MSAL tokens, ESTS cookies, IndexedDB, extensions and proxy config, and
            reconstructs the session-theft timeline with precise auth_time session
            birth anchors and the linkable identifiers (uti/sid) from the stolen token.

  * logs  : a folder of exported Microsoft Entra sign-in logs + Purview Unified Audit
            Log - footprint-aware attribution that isolates the threat actor from the
            user's own activity (network /24-/64 collapsing, hosting-ASN and taint
            guards, replayed-device handling, AiTM error-chain, MFA-wall, mail-exfil
            inventory, BEC inbox-rule parameters, containment and TA persistence).

  * both  : host AND logs together - the host-extracted uti/sid are pivoted into the
            logs for TOKEN-GRADE replay confirmation, and the host auth_time provides
            the precise session birth that brackets the exact theft window.

Mode is determined by the evidence you supply (--host, --logs, or both). Pure standard library,
fully offline (no pip installs). Raw token values are never written unless
--include-token-values is set.

Usage:
    python3 AiTM_analyzer.py --host pkg.zip
    python3 AiTM_analyzer.py --logs ./logs --asn-intel hosting.json
    python3 AiTM_analyzer.py --host pkg.zip --logs ./logs --out ./case
    python3 AiTM_analyzer.py ./some_evidence            # single path, auto-classified

(c) 2026 Shane D. Shook. Standard-library only.
"""

import argparse
import base64
import csv
import json
import math
import os
import re
import struct
import sys
import textwrap
import zipfile
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other):
        # Order ascending by severity so that max() returns the MORE severe level
        # (previously reversed, which made max(sev, MEDIUM) silently downgrade).
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
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
                      "email", "sub", "iss", "aud", "iat", "exp", "nbf", "sid", "uti",
                      "name", "given_name", "family_name", "azp", "appid", "scp",
                      "auth_time", "amr", "acr", "nonce"):
                if k in payload:
                    out[k] = payload[k]
    except Exception:
        pass
    return out


def _looks_guidish(g: Optional[str]) -> bool:
    """Reject obvious garbage from the heuristic GUID decode. NOTE: any 16 bytes
    form a syntactically valid GUID, so this only filters all-zero / single-nibble
    runs - it is NOT validation. Real trust requires corroboration with a token claim."""
    if not g:
        return False
    h = g.replace("-", "")
    if len(h) != 32:
        return False
    if len(set(h)) <= 2:  # all-zero or single repeated nibble -> not a real GUID
        return False
    return True


def decode_entra_home_account(value: str) -> Dict[str, Any]:
    """HEURISTIC byte-offset decode of an ESTSAUTH/ESTSAUTHPERSISTENT cookie.

    WARNING: reads tenant/object GUIDs from fixed offsets of an opaque, largely
    encrypted cookie. It is unvalidated and can emit fabricated GUIDs, so output
    is tagged confidence='heuristic'. Do NOT attribute on it alone - corroborate
    against a token claim (oid/tid) before relying on it.
    """
    out = {}
    try:
        parts = value.split(".")
        if len(parts) >= 2 and parts[0] in ("1", "2"):
            raw = _b64u(parts[1])
            if len(raw) >= 35:
                tid = _guid_le(raw[3:19])
                oid = _guid_le(raw[19:35])
                if _looks_guidish(tid) and _looks_guidish(oid):
                    out["tenant_id"] = tid
                    out["object_id"] = oid
                    out["confidence"] = "heuristic"
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


def confidence_label(conf: Optional[str]) -> str:
    """Human-readable label for an identity-attribution confidence tag."""
    return {
        "token_claim": "Token claim (high)",
        "cookie_plaintext": "Cookie plaintext",
        "ests_heuristic": "ESTS heuristic (unverified)",
        "url_login_hint": "URL login_hint (attacker-influenceable)",
    }.get(conf, "Unknown")


# --------------------------------------------------------------------------- #
# Token patterns for web storage analysis
# --------------------------------------------------------------------------- #

JWT_PATTERN = re.compile(r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
# Unanchored variant: finds JWTs embedded inside JSON envelopes (e.g. MSAL stores
# the token in a ".secret" field), where the anchored pattern above never matches.
JWT_FINDALL = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
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
        # BAI's content.js wraps each store as {itemCount, items:{k:v}, totalSize}.
        # Read BOTH localStorage and sessionStorage, descending into ".items".
        for storage_type in ("localStorage", "sessionStorage"):
            container = item.get(storage_type)
            if not isinstance(container, dict):
                continue
            storage_data = container.get("items")
            if not isinstance(storage_data, dict):
                # tolerate a flat {k:v} map from other versions
                storage_data = {k: v for k, v in container.items()
                                if k not in ("itemCount", "totalSize", "error")
                                and isinstance(v, str)}

            for key, value in storage_data.items():
                val_str = str(value) if value else ""
                is_token, reason = looks_like_token(key, val_str)
                # Find JWTs embedded anywhere in the value (covers MSAL's JSON
                # envelope where the token lives in a ".secret" field).
                jwt_list = JWT_FINDALL.findall(val_str)
                if not is_token and not jwt_list:
                    continue

                decoded = {}
                if jwt_list:
                    decoded = decode_jwt_noverify(jwt_list[0])
                    if not reason:
                        reason = f"embedded JWT ({len(jwt_list)})"

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
                    
                    # Check for JWT patterns in values (unanchored: rec_str is a
                    # JSON dump, so the anchored pattern would never match).
                    jwt_matches = JWT_FINDALL.findall(rec_str) if isinstance(rec_str, str) else []
                    
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
        identity_source = None
        if nl in ("estsauth", "estsauthpersistent"):
            home = decode_entra_home_account(val)
            decoded.update(home)
            decoded["token_type"] = ("persistent" if "persistent" in nl else "session")
            if home.get("tenant_id") or home.get("object_id"):
                identity_source = "ests_heuristic"
        elif nl == "ccstate":
            decoded.update(decode_entra_ccstate(val))
            if decoded.get("upn"):
                identity_source = "cookie_plaintext"
        elif val.count(".") == 2 and len(val) > 40:
            decoded.update(decode_jwt_noverify(val))
            if any(decoded.get(k) for k in ("tid", "oid", "upn", "preferred_username", "email")):
                identity_source = "token_claim"
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
            "identity_confidence": None,
        })
        # Track the strongest identity-attribution source seen for this session
        if identity_source:
            _rank = {"ests_heuristic": 0, "cookie_plaintext": 1, "token_claim": 2}
            cur = s.get("identity_confidence")
            if cur is None or _rank.get(identity_source, -1) > _rank.get(cur, -1):
                s["identity_confidence"] = identity_source
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
    
    # 3. WEBSTORAGE - localStorage AND sessionStorage (entries live under <store>.items)
    for ws in records(pkg.get("webstorage.json")):
        try:
            origin = ws.get('origin', '').replace('https://', '').replace('http://', '').split('/')[0]
        except:
            origin = 'unknown'

        for stype in ('localStorage', 'sessionStorage'):
            container = ws.get(stype)
            if not isinstance(container, dict):
                continue
            store = container.get('items')
            if not isinstance(store, dict):
                store = {k: v for k, v in container.items()
                         if k not in ('itemCount', 'totalSize', 'error') and isinstance(v, str)}

            for key, value in store.items():
                value_str = str(value)[:4000]

                for jwt_match in JWT_FINDALL.findall(value_str):
                    decoded = decode_jwt_noverify(jwt_match)
                    if decoded:
                        for claim in ('upn', 'preferred_username', 'email', 'sub'):
                            if claim in decoded and '@' in str(decoded[claim]):
                                add_token(decoded[claim], origin, {
                                    'cookie_name': f'{stype}[{key}]',
                                    'is_jwt': True,
                                    'httponly': False,  # web storage is JS-accessible
                                    'source': f'{stype} JWT'
                                })
                                break

                for match in upn_pattern.findall(value_str):
                    add_token(match, origin, {
                        'cookie_name': f'{stype}[{key}]',
                        'is_jwt': False,
                        'httponly': False,
                        'source': f'{stype} value'
                    })
    
    # 4. INDEXEDDB (content.js emits objectStores[].records = [{key, value}])
    for idb in records(pkg.get("indexeddbfull.json")):
        try:
            origin = idb.get('origin', '').replace('https://', '').replace('http://', '').split('/')[0]
        except:
            origin = 'unknown'
        
        for db in idb.get('databases', []) or []:
            for store in db.get('objectStores', []) or []:
                store_name = store.get('name', '')
                for item in (store.get('records') or store.get('items') or []):
                    value_str = (json.dumps(item) if isinstance(item, (dict, list)) else str(item))[:4000]
                    
                    for jwt_match in JWT_FINDALL.findall(value_str):
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
            
            # Look up UPN for this tenant. NOTE: this UPN comes from a login_hint
            # in a URL, which is attacker-influenceable in an AiTM lure - it is not
            # token-grade attribution.
            upn = tenant_upn_map.get(tenant_id, None)
            
            sessions.append({
                'tenant_id': decoded.get('tenant_id'),
                'object_id': decoded.get('object_id'),
                'upn': upn,  # Associated UPN from login URLs (url_login_hint)
                'upn_source': 'url_login_hint' if upn else None,
                'identity_confidence': 'ests_heuristic',  # tenant/object are byte-offset heuristic
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
    # 0. Normalize heterogeneous inputs into one identity shape.
    #    auth_sessions mixes cookie sessions (analyze_cookies: flat tenant_id/
    #    object_id/upn/cookie_names/token_types) with storage tokens
    #    (analyze_webstorage/indexeddb: origin/key/decoded claims). The previous
    #    code read session["type"]/session["identity"], which NEITHER producer
    #    emits, so stealable_sessions and correlation_anchors were always empty.
    # -------------------------------------------------------------------------
    def _norm(session):
        claims = session.get("decoded") or session.get("identity") or {}
        cookie_names = session.get("cookie_names") or (
            [session.get("key")] if session.get("key") else [])
        token_types = session.get("token_types") or []
        is_ests = any("estsauth" in (c or "").lower() for c in cookie_names)
        is_persistent = bool(session.get("any_persistent")) or ("persistent" in token_types) \
            or any("persistent" in (c or "").lower() for c in cookie_names)
        # Identity-attribution confidence: a decoded JWT (storage token / JWT cookie)
        # is a token_claim; otherwise fall back to the cookie session's tracked source
        # (ests_heuristic / cookie_plaintext / token_claim). ESTS-derived tenant/object
        # GUIDs are heuristic and must not be presented as hard attribution.
        if claims and any(claims.get(k) for k in
                          ("oid", "tid", "upn", "preferred_username", "email", "uti", "auth_time")):
            identity_confidence = "token_claim"
        else:
            identity_confidence = session.get("identity_confidence")
        return {
            "tenant_id": session.get("tenant_id") or claims.get("tid") or claims.get("tenant_id"),
            "object_id": session.get("object_id") or claims.get("oid") or claims.get("object_id"),
            "upn": (session.get("upn") or claims.get("upn") or claims.get("preferred_username")
                    or claims.get("unique_name") or claims.get("email")),
            "uti": claims.get("uti"),
            "sid": claims.get("sid"),
            "auth_time": claims.get("auth_time"),
            "iat": claims.get("iat"),
            "amr": claims.get("amr"),
            "is_ests": is_ests,
            "is_persistent": is_persistent,
            "identity_confidence": identity_confidence,
            "domain": session.get("domain") or session.get("origin"),
            "source": (cookie_names[0] if cookie_names else session.get("storage_type") or "storage"),
            "expiration": session.get("latest_expiry") or session.get("expiration"),
        }

    normalized = [_norm(s) for s in auth_sessions]

    # -------------------------------------------------------------------------
    # 1. Stealable sessions: any artifact carrying a recoverable identity or an
    #    ESTS cookie (the replayable session "loaded gun").
    # -------------------------------------------------------------------------
    for n in normalized:
        if not (n["is_ests"] or n["object_id"] or n["upn"]):
            continue
        stealable = {
            "cookie_name": n["source"],
            "domain": n["domain"],
            "tenant_id": n["tenant_id"],
            "object_id": n["object_id"],
            "upn": n["upn"],
            "uti": n["uti"],
            "sid": n["sid"],
            "expiration": n["expiration"],
            "is_persistent": n["is_persistent"],
            "identity_confidence": n["identity_confidence"],
            "estimated_birth": None,
            "theft_note": None,
        }

        # Estimate session birth from expiration (exp - lifetime for persistent)
        if n["is_persistent"] and n["expiration"]:
            try:
                exp_dt = datetime.fromisoformat(str(n["expiration"]).replace("Z", "+00:00"))
                birth_estimate = exp_dt - timedelta(days=ESTS_PERSISTENT_LIFETIME_DAYS)
                stealable["estimated_birth"] = birth_estimate.isoformat()
                stealable["theft_note"] = (
                    f"Session birth estimated as {birth_estimate.strftime('%Y-%m-%d')} "
                    f"(expiration - {ESTS_PERSISTENT_LIFETIME_DAYS} days; approximates the LAST "
                    "refresh of a rolling persistent session, not original sign-in). "
                    "Conditional Access sign-in-frequency may alter this. Correlate with Entra "
                    "sign-in logs for first TA replay."
                )
            except Exception:
                pass

        # Add correlation anchor for Entra. Thread BOTH linkable identifiers and
        # frame them as DISTINCT pivots:
        #   uti -> traces this one specific token's actions (UniqueTokenId)
        #   sid -> enumerates the whole session, INCLUDING tokens the attacker
        #          mints from a replayed cookie, which inherit the session's SID
        #          (AADSessionId). For replay hunting, sid is the broader sweep.
        if stealable["tenant_id"] and stealable["object_id"]:
            pivots = []
            if n["sid"]:
                pivots.append(
                    f"SID PIVOT (session sweep): linkable Session ID '{n['sid']}' "
                    "= AADSessionId in Unified Audit Log / Exchange / Graph activity logs. "
                    "Tokens minted from a replayed cookie inherit this SID, so this enumerates "
                    "the FULL session including attacker activity."
                )
            if n["uti"]:
                pivots.append(
                    f"UTI PIVOT (single token): unique token id '{n['uti']}' "
                    "= UniqueTokenId in those same logs. Traces only THIS token's actions; "
                    "a replay mints new tokens with different UTIs, so use UTI to confirm the "
                    "recovered token, not to catch the replay."
                )
            if not pivots:
                pivots.append(
                    "No uti/sid recovered from host artifacts (ESTS cookie is opaque). "
                    "Pivot on userId/SessionId from the sign-in logs directly."
                )
            conf = n["identity_confidence"]
            conf_hint = ("" if conf == "token_claim" else
                         " NOTE: tenant/object derived from an UNVALIDATED ESTS byte-offset "
                         "heuristic - corroborate against a token claim before attributing."
                         if conf == "ests_heuristic" else "")
            timeline["correlation_anchors"].append({
                "type": "Entra",
                "tenant_id": stealable["tenant_id"],
                "object_id": stealable["object_id"],
                "upn": stealable.get("upn"),
                "uti": n["uti"],
                "sid": n["sid"],
                "identity_confidence": conf,
                "pivots": pivots,
                "query_guidance": (
                    "In Entra Sign-in Logs, filter by: "
                    f"userId eq '{stealable['object_id']}' or "
                    f"userPrincipalName eq '{stealable.get('upn') or 'UNKNOWN'}'. "
                    + " ".join(pivots)
                    + f"{conf_hint}"
                ),
            })

        timeline["stealable_sessions"].append(stealable)

    # -------------------------------------------------------------------------
    # 1b. Cross-artifact identity merge for correlation anchors.
    #     The same identity (object_id) often appears in MULTIPLE artifacts - e.g.
    #     an ESTS cookie (ests_heuristic, no UPN/uti) AND a storage token
    #     (token_claim, with UPN + uti). Collapse those into one anchor per oid,
    #     keeping the highest-confidence attribution and the richest fields, so the
    #     report shows one corroborated identity instead of two partial rows.
    # -------------------------------------------------------------------------
    def _conf_rank(c):
        return {"token_claim": 3, "cookie_plaintext": 2,
                "ests_heuristic": 1, "url_login_hint": 1}.get(c, 0)

    _merged, _order = {}, []
    for a in timeline["correlation_anchors"]:
        oid = (a.get("object_id") or "").lower()
        key = oid or f"_nooid_{len(_order)}"  # anchors without an oid stay distinct
        if key not in _merged:
            rec = dict(a)
            rec["merged_from"] = [a["identity_confidence"]] if a.get("identity_confidence") else []
            _merged[key] = rec
            _order.append(key)
            continue
        rec = _merged[key]
        if a.get("identity_confidence"):
            rec["merged_from"].append(a["identity_confidence"])
        # enrich any missing fields from this duplicate
        rec["upn"] = rec.get("upn") or a.get("upn")
        rec["uti"] = rec.get("uti") or a.get("uti")
        rec["sid"] = rec.get("sid") or a.get("sid")
        rec["tenant_id"] = rec.get("tenant_id") or a.get("tenant_id")
        # if this duplicate is higher-confidence, promote its attribution +
        # token-grade identifiers + caveat-free guidance/pivots
        if _conf_rank(a.get("identity_confidence")) > _conf_rank(rec.get("identity_confidence")):
            rec["identity_confidence"] = a.get("identity_confidence")
            rec["tenant_id"] = a.get("tenant_id") or rec.get("tenant_id")
            rec["query_guidance"] = a.get("query_guidance")
            rec["pivots"] = a.get("pivots") or rec.get("pivots")
            if a.get("upn"):
                rec["upn"] = a["upn"]
            if a.get("uti"):
                rec["uti"] = a["uti"]
            if a.get("sid"):
                rec["sid"] = a["sid"]
    for rec in _merged.values():
        # de-duplicate provenance, strongest first
        rec["merged_from"] = sorted(set(rec.get("merged_from", [])),
                                    key=_conf_rank, reverse=True)
    timeline["correlation_anchors"] = [_merged[k] for k in _order]

    # -------------------------------------------------------------------------
    # 2. Extract auth_time from cleartext tokens (best session birth anchor)
    # -------------------------------------------------------------------------
    for n in normalized:
        auth_time = n["auth_time"]
        if auth_time is None:
            continue
        try:
            if isinstance(auth_time, (int, float)):
                auth_time_iso = datetime.fromtimestamp(auth_time, timezone.utc).isoformat()
            else:
                auth_time_iso = str(auth_time)

            timeline["session_birth_anchors"].append({
                "source": n["source"],
                "domain": n["domain"],
                "object_id": n["object_id"],   # for per-identity matching in step 5
                "tenant_id": n["tenant_id"],
                "auth_time": auth_time_iso,
                "auth_time_epoch": auth_time if isinstance(auth_time, (int, float)) else None,
                "iat": n["iat"],
                "amr": n["amr"],  # Authentication methods (mfa, pwd, etc.)
                "note": (
                    "auth_time is the interactive authentication instant (MFA moment). "
                    "This is more precise than iat (which can be a silent refresh). "
                    f"Authentication methods: {n['amr'] if n['amr'] is not None else 'unknown'}"
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
        
        # Use auth_time if available for THIS identity (match by object_id, not
        # "first anchor wins" which stamped every window with one identity's time).
        sess_oid = session.get("object_id")
        for anchor in timeline["session_birth_anchors"]:
            if anchor.get("auth_time") and anchor.get("object_id") \
                    and anchor.get("object_id") == sess_oid:
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

# Log file name patterns for auto-detection.
# ORDER MATTERS: more-specific names must be tested first because of substring
# collisions - "interactive" is a substring of "noninteractive", and "audit" is a
# substring of "unifiedauditlog". Dict iteration order is insertion order and the
# matcher breaks on first hit, so purview/noninteractive precede audit/interactive.
ENTRA_LOG_PATTERNS = {
    "purview": ["unifiedauditlog", "unified", "purview", "ual"],
    "noninteractive": ["noninteractive", "non-interactive", "noninteractivesignin"],
    "serviceprincipal": ["serviceprincipal", "service-principal", "appsignin", "application"],
    "managedidentity": ["managedidentity", "managed-identity", "msi"],
    "interactive": ["interactive", "interactivesignin"],
    "audit": ["audit", "auditlog"],
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
        "user_display_name": None,
        "app_id": None,
        "app_display_name": None,
        "client_app_used": None,
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
    
    # UPN - a real userPrincipalName only. Display name is NOT a UPN and would
    # never match BAI identities; capture it separately instead.
    for k in ["userPrincipalName", "UserPrincipalName", "upn", "UPN"]:
        if k in rec and rec[k]:
            normalized["user_principal_name"] = rec[k]
            break
    
    # Display name (distinct from UPN)
    for k in ["userDisplayName", "UserDisplayName"]:
        if k in rec and rec[k]:
            normalized["user_display_name"] = rec[k]
            break
    
    # App ID - an application identifier only. clientAppUsed is a transport
    # CATEGORY (e.g. "Browser", "Mobile Apps and Desktop clients"), not an app id.
    for k in ["appId", "AppId", "applicationId", "ApplicationId"]:
        if k in rec and rec[k]:
            normalized["app_id"] = rec[k]
            break
    
    # Client app category (transport), kept separate from app_id
    for k in ["clientAppUsed", "ClientAppUsed"]:
        if k in rec and rec[k]:
            normalized["client_app_used"] = rec[k]
            break
    
    # App name - the application's display name. Do NOT fall back to
    # resourceDisplayName (the resource/audience is a different field, mapped below).
    for k in ["appDisplayName", "AppDisplayName", "applicationDisplayName"]:
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
    
    # Session ID. Do NOT fall back to correlationId: SessionId and CorrelationId
    # are distinct Entra concepts, and the Purview/UAL pivot relies on a real
    # SessionId. Conflating them produces join keys that silently never match.
    for k in ["sessionId", "SessionId"]:
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
    
    # Build lookup of identities from BAI. An identity may be keyed by BOTH
    # object_id and upn, but both keys must alias the SAME record so we don't
    # process (and count) it twice. Guard against object_id being None (a
    # storage token / JWT cookie may carry a UPN but no oid) - the previous
    # obj_id.lower() unconditionally crashed in that case.
    # Precise session-birth anchors (auth_time) keyed by object_id, preferred over
    # the coarse exp-minus-lifetime estimate when reconstructing the theft window.
    birth_by_oid = {}
    for a in theft_timeline.get("session_birth_anchors", []):
        oid = (a.get("object_id") or "").lower()
        if oid and a.get("auth_time") and oid not in birth_by_oid:
            birth_by_oid[oid] = a["auth_time"]

    bai_identities = {}
    identity_objs = []  # unique identity records (iterate these, not aliased keys)
    for session in stealable:
        obj_id = session.get("object_id")
        upn = session.get("upn")
        tenant = session.get("tenant_id")
        if not (obj_id or upn):
            continue

        precise_birth = birth_by_oid.get((obj_id or "").lower())
        birth = precise_birth or session.get("estimated_birth")
        birth_source = ("auth_time" if precise_birth
                        else ("estimated" if session.get("estimated_birth") else None))

        rec = None
        if obj_id and obj_id.lower() in bai_identities:
            rec = bai_identities[obj_id.lower()]
        elif upn and upn.lower() in bai_identities:
            rec = bai_identities[upn.lower()]
        if rec is None:
            rec = {
                "object_id": obj_id,
                "upn": upn,
                "tenant_id": tenant,
                "session_birth": birth,
                "birth_source": birth_source,
                "expiration": session.get("expiration"),
                "signins": [],
            }
            identity_objs.append(rec)
        else:
            # enrich an existing record with any newly-seen identifiers
            rec["object_id"] = rec.get("object_id") or obj_id
            rec["upn"] = rec.get("upn") or upn
            rec["tenant_id"] = rec.get("tenant_id") or tenant
            # upgrade to a precise birth if one became available
            if precise_birth and rec.get("birth_source") != "auth_time":
                rec["session_birth"] = precise_birth
                rec["birth_source"] = "auth_time"
            elif rec.get("session_birth") is None and birth:
                rec["session_birth"] = birth
                rec["birth_source"] = birth_source

        if obj_id:
            bai_identities[obj_id.lower()] = rec
        if upn:
            bai_identities[upn.lower()] = rec
    
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
    
    # Count matched identities (unique records, not aliased keys)
    matched_count = sum(1 for i in identity_objs if i.get("signins"))
    correlation["identities_matched"] = matched_count
    
    # Analyze each identity for anomalous sign-ins
    for identity in identity_objs:
        if not identity.get("signins"):
            continue
        
        signins = identity["signins"]
        session_birth = identity.get("session_birth")
        
        # Sort by timestamp
        signins.sort(key=lambda x: x.get("timestamp") or "")
        
        # Establish a baseline of "known-good" IPs. The old rule (an IP is baseline
        # if it appears in >=10% of all sign-ins) treated a single attacker IP as
        # baseline whenever volume was low - in a handful of sign-ins, every IP
        # appears once and so every IP cleared the bar, hiding the replay entirely.
        # Instead, baseline = IPs the user genuinely signed in from INTERACTIVELY
        # (real, MFA-backed logins) plus any IP seen BEFORE session birth. A
        # non-interactive sign-in from an IP outside that set is the replay signature.
        birth_dt = None
        if session_birth:
            try:
                birth_dt = datetime.fromisoformat(session_birth.replace("Z", "+00:00"))
            except Exception:
                birth_dt = None

        ip_counts = {}
        baseline_ips = set()
        for s in signins:
            ip = s.get("ip_address")
            if not ip:
                continue
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            if s.get("log_type") == "interactive":
                baseline_ips.add(ip)
            elif birth_dt and s.get("timestamp"):
                try:
                    if datetime.fromisoformat(s["timestamp"].replace("Z", "+00:00")) < birth_dt:
                        baseline_ips.add(ip)
                except Exception:
                    pass

        # Fallback only when we have no interactive/pre-birth context at all:
        # treat the single most frequent IP as baseline (best-effort), so we still
        # flag clearly anomalous outliers rather than nothing.
        if not baseline_ips and ip_counts:
            top = max(ip_counts.values())
            baseline_ips = {ip for ip, c in ip_counts.items() if c == top}
        
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
                            "session_birth_source": identity.get("birth_source"),
                            "theft_window": f"[{session_birth}, {signin_time}]",
                        })
                        
                        # Add completed theft window
                        correlation["completed_theft_windows"].append({
                            "identity": anomaly["identity"],
                            "session_birth": session_birth,
                            "session_birth_source": identity.get("birth_source"),
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
            
            if actor and actor in bai_identities:
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
            identity = session.get("identity") or {}
            
            entry = {
                "identity": (session.get("upn") or identity.get("upn")
                           or identity.get("preferred_username")
                           or identity.get("email") or identity.get("name")
                           or f"[{domain}]"),
                "idp": idp,
                "domain": domain,
                "tenant_id": session.get("tenant_id") or identity.get("tid"),
                "object_id": session.get("object_id") or identity.get("oid"),
                "attribution": confidence_label(session.get("identity_confidence")),
                "mfa_status": self._get_mfa_status(session),
                "token_types": self._get_token_types(session),
                "valid_until": session.get("latest_expiry") or session.get("earliest_expiry"),
                "cookie_count": len(session.get("cookie_names", [])),
                "httponly": "Yes" if session.get("any_httponly") else "No",
            }
            inventory.append(entry)
        
        # Add storage tokens
        for token in self.storage_tokens:
            identity = token.get("decoded") or token.get("identity") or {}
            entry = {
                "identity": identity.get("upn") or identity.get("preferred_username") or 
                           identity.get("email") or token.get("key", "Unknown"),
                "idp": token.get("idp", "Web Storage"),
                "domain": token.get("origin", "Unknown"),
                "tenant_id": identity.get("tid"),
                "object_id": identity.get("oid"),
                "attribution": confidence_label("token_claim") if identity else "Unknown",
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
            conf = sess.get('identity_confidence')
            conf_text = confidence_label(conf)
            conf_class = 'low-risk' if conf == 'token_claim' else 'high-risk'
            
            # Token type with replayability info
            if httponly:
                token_desc = f"{sess_type} Cookie (HttpOnly) - Replayable if exfiltrated"
                risk_class = 'low-risk'
            else:
                token_desc = f"{sess_type} Cookie (JS-accessible) - Easily stolen & replayable"
                risk_class = 'high-risk'
            
            upn_html = html_mod.escape(upn) if upn and upn != '<em>Unknown</em>' else upn
            if sess.get('upn_source') == 'url_login_hint' and upn != '<em>Unknown</em>':
                upn_html += " <span style='font-size:8px;color:#cc0000;'>(from URL login_hint)</span>"
            
            rows.append(f"<tr><td><strong>{upn_html}</strong></td>"
                       f"<td><code style='font-size:9px;'>{html_mod.escape(tenant_id)}</code></td>"
                       f"<td><code style='font-size:9px;'>{html_mod.escape(object_id)}</code></td>"
                       f"<td class='{conf_class}'>{html_mod.escape(conf_text)}</td>"
                       f"<td>{html_mod.escape(cookie_name)}</td>"
                       f"<td class='{risk_class}'>{token_desc}</td></tr>")
        
        return f"""<table class='data-table entra-table'>
<thead>
<tr><th>UPN (User)</th><th>Tenant ID</th><th>Object ID</th><th>Attribution</th><th>Cookie</th><th>Token Type &amp; Risk</th></tr>
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
                lines.append(f"  Identity:    {a.get('upn') or a.get('object_id') or 'Unknown'}")
                lines.append(f"  Tenant:      {a.get('tenant_id', 'Unknown')}")
                lines.append(f"  Attribution: {confidence_label(a.get('identity_confidence'))}")
                mf = a.get('merged_from') or []
                if len(mf) > 1:
                    lines.append("  Corroboration: "
                                 + ", ".join(confidence_label(m) for m in mf)
                                 + " (same object_id across artifacts)")
                if a.get('uti'):
                    lines.append(f"  Token uti:   {a.get('uti')}  (single-token pivot -> UniqueTokenId)")
                if a.get('sid'):
                    lines.append(f"  Session sid: {a.get('sid')}  (session-sweep pivot -> AADSessionId)")
                lines.append(f"  Query:       Filter by userId eq '{a.get('object_id', '?')}'")
                lines.append(f"               within {a.get('validity_start', '?')} to {a.get('validity_end', '?')}")
                for p in (a.get('pivots') or []):
                    wrapped = textwrap.wrap(p, 72) or [p]
                    for i, ln in enumerate(wrapped):
                        lines.append(f"    • {ln}" if i == 0 else f"      {ln}")
                if a.get('identity_confidence') == 'ests_heuristic':
                    lines.append("  ⚠ tenant/object from UNVALIDATED ESTS heuristic — corroborate")
                    lines.append("    against a token claim before attributing.")
                lines.append("")
        else:
            lines.append("  No specific correlation anchors extracted.")
            lines.append("  Use tenant_id and object_id from Identity Inventory section.")
        lines.append("")
        
        lines.append("PURVIEW/UAL GUIDANCE")
        lines.append("-" * 40)
        lines.append("  • Linkable identifiers (Entra preview, 2025+) appear in the Unified Audit")
        lines.append("    Log export as: UniqueTokenId (= uti) and AADSessionId (= sid).")
        lines.append("  • sid / AADSessionId = SESSION SWEEP: links every token issued in the")
        lines.append("    login session, including tokens minted from a replayed cookie. Best")
        lines.append("    pivot to enumerate the full scope of attacker activity.")
        lines.append("  • uti / UniqueTokenId = SINGLE TOKEN: traces only the one recovered")
        lines.append("    token's actions; a replay mints new tokens with different uti values.")
        lines.append("  • Look for the same sid/AADSessionId used from a different ClientIP.")
        lines.append("  • Coverage is preview-era and varies by workload + retention window —")
        lines.append("    confirm these fields are populated for your incident window before relying on them.")
        lines.append("  • Storage tokens (localStorage/IndexedDB) may have longer validity than cookies.")
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
    
    def _section_validation_checklist(self) -> str:
        """Standing list of the assumptions this analyzer makes, so an examiner has
        a per-case prompt to confirm each before relying on it. Items are tagged
        [IN USE] when the current package/logs actually exercise that assumption."""
        tl = self.theft_timeline or {}
        anchors = tl.get("correlation_anchors", [])
        stealables = tl.get("stealable_sessions", [])
        ec = self.entra_correlation or {}

        def _any(seq, pred):
            return any(pred(x) for x in seq)

        ests_used = (_any(stealables, lambda s: s.get("identity_confidence") == "ests_heuristic")
                     or _any(anchors, lambda a: "ests_heuristic" in (a.get("merged_from") or []))
                     or _any(self.entra_sessions, lambda s: s.get("identity_confidence") == "ests_heuristic"))
        sid_used = _any(anchors, lambda a: a.get("sid")) or _any(stealables, lambda s: s.get("sid"))
        uti_used = _any(anchors, lambda a: a.get("uti")) or _any(stealables, lambda s: s.get("uti"))
        persistent_est = _any(stealables, lambda s: s.get("estimated_birth"))
        authtime_used = bool(tl.get("session_birth_anchors")) or _any(
            ec.get("first_ta_replays", []), lambda r: r.get("session_birth_source") == "auth_time")
        corr_ran = bool(self.entra_correlation)
        host_collection = bool(self.upn_accounts or stealables or self.storage_tokens)

        def tag(flag):
            return "[IN USE]   " if flag else "[ n/a  ]   "

        lines = []
        lines.append("=" * 78)
        lines.append("9. ANALYST VALIDATION CHECKLIST")
        lines.append("=" * 78)
        lines.append("")
        lines.append("  These are the analyzer's assumptions. Confirm each before relying on the")
        lines.append("  conclusions above. [IN USE] = this package/log set exercises the assumption.")
        lines.append("")

        items = [
            (ests_used,
             "ESTS tenant/object GUIDs are HEURISTIC",
             ["decode_entra_home_account reads tenant_id/object_id from fixed byte",
              "offsets of the opaque ESTS cookie; any 16 bytes form a valid-looking GUID.",
              "VERIFY: corroborate each ESTS-derived GUID against a token claim (oid/tid)",
              "or the tenant's known IDs. Do not attribute on the heuristic alone."]),
            (sid_used,
             "sid claim == AADSessionId (linkable identifier)",
             ["The analyzer treats the token's sid as the AADSessionId used in the logs.",
              "VERIFY: confirm against one known-good sign-in in THIS tenant that the",
              "recovered sid matches the logged AADSessionId before using it to sweep."]),
            (uti_used,
             "uti claim == UniqueTokenId (linkable identifier)",
             ["The analyzer treats the token's uti as the UniqueTokenId used in the logs.",
              "VERIFY: confirm the recovered uti matches a logged UniqueTokenId; remember",
              "a replay mints NEW tokens with different utis (uti confirms, sid sweeps)."]),
            (corr_ran or sid_used or uti_used,
             "Linkable-identifier coverage is preview-era",
             ["uti/sid surfaced in logs (Entra, 2025+) is preview and rolling out;",
              "coverage varies by workload and retention window.",
              "VERIFY: confirm UniqueTokenId/AADSessionId are actually populated for your",
              "incident window in the specific log sources you queried."]),
            (persistent_est and not authtime_used,
             "Persistent session-birth is ESTIMATED (exp - 90d)",
             ["estimated_birth approximates the LAST refresh of a rolling persistent",
              "cookie, NOT the original interactive sign-in. Conditional Access sign-in",
              "frequency changes the lifetime.",
              "VERIFY: prefer the precise auth_time anchor where present; treat the",
              "estimate as an approximate upper bound on the window."]),
            (corr_ran,
             "Replay baseline = interactive / pre-birth IPs",
             ["Replay detection treats interactive (and pre-birth) sign-in IPs as the",
              "user baseline and flags non-interactive sign-ins from other IPs after birth.",
              "VERIFY: confirm the baseline interactive sign-ins are genuinely the user and",
              "not attacker-interactive; clear flagged IPs against known VPN/egress/travel."]),
            (corr_ran,
             "Timestamps are reconciled to UTC",
             ["All correlation is timestamp-based across host artifacts and log sources.",
              "VERIFY: host clock integrity and that every log source's times are in (or",
              "converted to) UTC; a skewed clock distorts the theft window."]),
            (host_collection,
             "Web storage = OPEN tabs at collection time only",
             ["localStorage/sessionStorage tokens are captured only from tabs open during",
              "collection. Absence of a token is NOT evidence the session never existed.",
              "VERIFY: note which origins had open tabs; corroborate identity from the",
              "Cookies store and the server-side sign-in logs."]),
        ]

        n = 1
        for flag, title, body in items:
            lines.append(f"  {tag(flag)}{n}. {title}")
            for b in body:
                lines.append(f"             {b}")
            lines.append("")
            n += 1

        return "\n".join(lines)
    
    def _text_grid(self, headers: List[str], rows: List[List[str]],
                   widths: List[int]) -> str:
        """Render an ASCII grid table with per-column wrapping (TXT parity with HTML)."""
        def cell_lines(text, w):
            text = "" if text is None else str(text)
            out = []
            for para in text.split("\n"):
                out.extend(textwrap.wrap(para, w) or [""])
            return out

        sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

        def fmt(cells):
            cols = [cell_lines(c, w) for c, w in zip(cells, widths)]
            h = max((len(c) for c in cols), default=1)
            for c in cols:
                c += [""] * (h - len(c))
            out = []
            for r in range(h):
                out.append("| " + " | ".join(cols[i][r].ljust(widths[i])
                                              for i in range(len(widths))) + " |")
            return out

        out = [sep] + fmt(headers) + [sep]
        for row in rows:
            out += fmt(row)
        out.append(sep)
        return "\n".join(out)

    def _generate_identity_table_txt(self) -> str:
        """TXT version of the identity-accounts table (mirrors the HTML columns)."""
        primary_accounts = [a for a in self.upn_accounts if a.get('has_strong_evidence')]
        if not primary_accounts:
            return "  No authenticated accounts discovered."
        rows = []
        for acct in primary_accounts:
            upn = acct.get('upn', 'Unknown')
            first = True
            for domain, svc_info in sorted(acct.get('services', {}).items()):
                for token in svc_info.get('tokens', []):
                    cookie_name = token.get('cookie_name')
                    if not cookie_name:
                        continue
                    is_jwt = token.get('is_jwt', False)
                    httponly = token.get('httponly')
                    if is_jwt:
                        ttype = "JWT"
                    elif 'localStorage' in (cookie_name or ''):
                        ttype = "localStorage"
                    elif 'IndexedDB' in (cookie_name or ''):
                        ttype = "IndexedDB"
                    else:
                        ttype = "Cookie"
                    if httponly is True:
                        prot, risk = "HttpOnly", "Requires malware/browser exploit to steal"
                    elif httponly is False:
                        prot, risk = "JS-accessible", "Stealable via XSS or malicious extension"
                    else:
                        prot, risk = "N/A", "Session evidence only"
                    rows.append([upn if first else "", domain, ttype, prot, risk])
                    first = False
        if not rows:
            return "  No authenticated accounts with cookie/token evidence."
        return self._text_grid(
            ["UPN (User)", "Service", "Type", "Protection", "Theft Risk"],
            rows, [22, 22, 11, 13, 30])

    def _generate_entra_table_txt(self) -> str:
        """TXT version of the Entra sessions table. Block-per-session because the
        two 36-char GUIDs make a single-row grid wider than a terminal."""
        if not self.entra_sessions:
            return "  No Entra sessions discovered."
        lines = []
        for i, sess in enumerate(self.entra_sessions, 1):
            upn = sess.get('upn') or 'Unknown'
            if sess.get('upn_source') == 'url_login_hint' and upn != 'Unknown':
                upn += " (from URL login_hint)"
            httponly = sess.get('httponly', False)
            sess_type = sess.get('type', 'SESSION')
            risk = (f"{sess_type} Cookie (HttpOnly) - Replayable if exfiltrated" if httponly
                    else f"{sess_type} Cookie (JS-accessible) - Easily stolen & replayable")
            lines.append(f"  [{i}] {upn}")
            lines.append(f"      Tenant ID:   {sess.get('tenant_id', 'Unknown')}")
            lines.append(f"      Object ID:   {sess.get('object_id', 'Unknown')}")
            lines.append(f"      Attribution: {confidence_label(sess.get('identity_confidence'))}")
            lines.append(f"      Cookie:      {sess.get('cookie_name', 'Unknown')}")
            lines.append(f"      Token/Risk:  {risk}")
            lines.append("")
        return "\n".join(lines).rstrip()

    def _generate_findings_table_txt(self) -> str:
        """TXT version of the findings table. Block-per-finding for readability."""
        if not self.findings:
            return "  No findings to report."
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        by_sev = {}
        for f in self.findings:
            by_sev.setdefault(f.get("severity", "INFO"), []).append(f)
        lines = []
        for sev in severity_order:
            for f in by_sev.get(sev, []):
                lines.append(f"  [{sev}] {f.get('title', 'Unknown')}")
                lines.append(f"         Category: {f.get('category', 'Unknown')}")
                ev = self._format_evidence_text(f.get('details', {}))
                if ev:
                    first = True
                    for ln in ev:
                        label = "Evidence: " if first else "          "
                        lines.append(f"         {label}{ln}")
                        first = False
                rec = f.get('recommendation', '')
                if rec:
                    wrapped = textwrap.wrap(rec, 64) or [""]
                    first = True
                    for ln in wrapped:
                        label = "Action:   " if first else "          "
                        lines.append(f"         {label}{ln}")
                        first = False
                lines.append("")
        return "\n".join(lines).rstrip()

    def _format_evidence_text(self, details: Dict) -> List[str]:
        """Flatten a finding's details dict into readable text lines."""
        if not details or not isinstance(details, dict):
            return []
        out = []
        for k, v in details.items():
            if isinstance(v, (list, tuple)):
                v = ", ".join(str(x) for x in v[:5]) + (" ..." if len(v) > 5 else "")
            elif isinstance(v, dict):
                v = "; ".join(f"{ik}={iv}" for ik, iv in list(v.items())[:5])
            line = f"{k}: {v}"
            out.extend(textwrap.wrap(line, 64) or [line])
        return out[:12]

    def generate_txt(self, render_tables: bool = True) -> str:
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
        sections.append(self._section_correlation_guidance())
        sections.append(self._section_chain_of_custody())
        sections.append(self._section_validation_checklist())
        
        # Footer
        sections.append("=" * 78)
        sections.append("END OF REPORT")
        sections.append("=" * 78)
        
        # Replace table markers with rendered text tables (parity with HTML).
        # The HTML generator calls this with render_tables=False so it can swap in
        # real <table> elements instead.
        text = "\n".join(sections)
        if not render_tables:
            return text
        out_lines = []
        for line in text.split("\n"):
            stripped = line.strip()
            if stripped == "TABLE:identity_accounts":
                out_lines.append(self._generate_identity_table_txt())
            elif stripped == "TABLE:entra_sessions":
                out_lines.append(self._generate_entra_table_txt())
            elif stripped == "TABLE:findings":
                out_lines.append(self._generate_findings_table_txt())
            else:
                out_lines.append(line)
        return "\n".join(out_lines)
    
    def generate_html(self) -> str:
        """Generate complete HTML report."""
        # Convert TXT sections to HTML with styling
        txt_content = self.generate_txt(render_tables=False)
        
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
                "attribution", "mfa_status", "token_types", "valid_until",
                "cookie_count", "httponly"
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
            print(f"      Attribution: {confidence_label(s.get('identity_confidence'))}")
            if s.get("uti"):
                print(f"      uti:    {s.get('uti')}  (single-token pivot)")
            if s.get("sid"):
                print(f"      sid:    {s.get('sid')}  (session-sweep pivot)")
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
            print(f"  Attribution: {confidence_label(anchor.get('identity_confidence'))}")
            _mf = anchor.get('merged_from') or []
            if len(_mf) > 1:
                print("  Corroboration: " + ", ".join(confidence_label(m) for m in _mf))
            if anchor.get('uti'):
                print(f"  uti:    {anchor.get('uti')}  (single-token pivot -> UniqueTokenId)")
            if anchor.get('sid'):
                print(f"  sid:    {anchor.get('sid')}  (session-sweep pivot -> AADSessionId)")
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


def parse_time(v):
    """Tolerant timestamp parser -> aware UTC datetime, or None."""
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        try:
            return datetime.fromtimestamp(v / (1000.0 if v > 1e12 else 1.0), tz=timezone.utc)
        except Exception:
            return None
    s = str(v).strip().strip('"')
    if not s:
        return None
    # normalize Z and space-separated forms
    iso = s.replace("Z", "+00:00")
    for candidate in (iso, iso.replace(" ", "T")):
        try:
            dt = datetime.fromisoformat(candidate)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%Y-%m-%d %H:%M:%S",
                "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return None


def fmt_dt(dt, tz=None):
    if dt is None:
        return "?"
    if tz is not None:
        try:
            return dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S %Z")
        except Exception:
            pass
    return dt.strftime("%Y-%m-%d %H:%M:%SZ")


def _load_tz(name):
    if not name:
        return None
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Log discovery + loading
# --------------------------------------------------------------------------- #

# Order matters: specific names must beat substrings ("interactive" is inside
# "noninteractive"; "audit" is inside "unifiedauditlog").
LOG_PATTERNS = [
    ("purview",         ["unifiedauditlog", "unified", "purview", "ual"]),
    ("noninteractive",  ["noninteractive", "non-interactive"]),
    ("serviceprincipal",["serviceprincipal", "service-principal", "appsignin"]),
    ("managedidentity", ["managedidentity", "managed-identity", "msi"]),
    ("interactive",     ["interactive", "signin", "sign-in", "logon"]),
    ("audit",           ["audit", "directoryaudit"]),
]

BUCKETS = ("interactive", "noninteractive", "serviceprincipal",
           "managedidentity", "audit", "purview")


def load_records(path):
    """Load one log file (JSON array, JSON {value:[]}, JSONL, or CSV)."""
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            content = f.read().strip()
    except Exception as e:
        print(f"[!] cannot read {path}: {e}")
        return []
    if not content:
        return []
    if content[0] in "[{":
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("value", [data])
        except Exception:
            # try JSON Lines
            rows = []
            for line in content.splitlines():
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        pass
            if rows:
                return rows
    # CSV
    try:
        from io import StringIO
        return list(csv.DictReader(StringIO(content)))
    except Exception as e:
        print(f"[!] cannot parse {path}: {e}")
        return []


def discover_logs(folder):
    logs = {b: [] for b in BUCKETS}
    if not os.path.isdir(folder):
        print(f"[!] not a folder: {folder}")
        return logs
    for fn in sorted(os.listdir(folder)):
        fp = os.path.join(folder, fn)
        if not os.path.isfile(fp):
            continue
        low = fn.lower()
        if not (low.endswith(".json") or low.endswith(".csv") or low.endswith(".jsonl")):
            continue
        bucket = None
        for name, pats in LOG_PATTERNS:
            if any(p in low for p in pats):
                bucket = name
                break
        if bucket is None:
            print(f"[*] skipped unrecognized file: {fn}")
            continue
        recs = load_records(fp)
        logs[bucket].extend(recs)
        if recs:
            print(f"[+] {len(recs):>6} records  <-  {fn}  ({bucket})")
    return logs


# --------------------------------------------------------------------------- #
# Field extraction helpers (handle Graph / portal / PowerShell shapes)
# --------------------------------------------------------------------------- #

def _first(rec, keys, default=None):
    for k in keys:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
    return default


def _maybe_json(v):
    """UAL AuditData is often a JSON string; parse if so."""
    if isinstance(v, dict):
        return v
    if isinstance(v, str) and v.strip().startswith("{"):
        try:
            return json.loads(v)
        except Exception:
            return {}
    return {}


def _loc_parts(loc):
    if isinstance(loc, dict):
        country = loc.get("countryOrRegion") or loc.get("country") or ""
        city = loc.get("city") or ""
        geo = loc.get("geoCoordinates") or {}
        lat = geo.get("latitude")
        lon = geo.get("longitude")
        return country, city, lat, lon
    if isinstance(loc, str):
        return loc, "", None, None
    return "", "", None, None


def normalize_signin(rec, log_type):
    """Normalize an Entra sign-in record. UPN, app, session, uti kept DISTINCT
    (no display-name / clientAppUsed / resource conflation)."""
    loc = _first(rec, ["location", "Location"], {})
    country, city, lat, lon = _loc_parts(loc)
    status = _first(rec, ["status", "Status"], {})
    if isinstance(status, dict):
        err = status.get("errorCode", 0)
        success = (str(err) in ("0", "None") or err == 0)
    else:
        success = str(status).lower() in ("success", "0", "true")
        err = None if success else status
    dev = _first(rec, ["deviceDetail", "DeviceDetail"], {})
    dev = dev if isinstance(dev, dict) else {}

    # MFA / "satisfied by claim in token" tell
    auth_req = _first(rec, ["authenticationRequirement", "AuthenticationRequirement"], "")
    auth_details = _first(rec, ["authenticationDetails", "AuthenticationDetails"], []) or []
    satisfied_by_token = False
    if isinstance(auth_details, list):
        for d in auth_details:
            if isinstance(d, dict):
                blob = (str(d.get("authenticationStepResultDetail", "")) + " " +
                        str(d.get("authenticationStepRequirement", ""))).lower()
                if ("claim in the token" in blob or "previously satisfied" in blob
                        or "satisfied by token" in blob):
                    satisfied_by_token = True

    return {
        "log_type": log_type,
        "time": parse_time(_first(rec, ["createdDateTime", "CreatedDateTime",
                                        "timestamp", "Timestamp", "ActivityDateTime"])),
        "user_id": (_first(rec, ["userId", "UserId", "userKey"], "") or "").lower(),
        "upn": (_first(rec, ["userPrincipalName", "UserPrincipalName", "upn"], "") or "").lower(),
        "user_display": _first(rec, ["userDisplayName", "UserDisplayName"], ""),
        "ip": _first(rec, ["ipAddress", "IpAddress", "ip", "clientIP", "ClientIP"], ""),
        "asn": _first(rec, ["autonomousSystemNumber", "AutonomousSystemNumber"], None),
        "country": country, "city": city, "lat": lat, "lon": lon,
        "app_id": _first(rec, ["appId", "AppId", "applicationId"], ""),
        "app": _first(rec, ["appDisplayName", "AppDisplayName"], ""),
        "resource": _first(rec, ["resourceDisplayName", "ResourceDisplayName"], ""),
        "client_app": _first(rec, ["clientAppUsed", "ClientAppUsed"], ""),
        "user_agent": _first(rec, ["userAgent", "UserAgent"], ""),
        "success": success,
        "error_code": err,
        "auth_requirement": auth_req,
        "satisfied_by_token": satisfied_by_token,
        # linkable identifiers (preview): names vary by export
        "session_id": _first(rec, ["sessionId", "SessionId", "AADSessionId", "aadSessionId"], ""),
        "uti": _first(rec, ["uniqueTokenIdentifier", "UniqueTokenId", "uniqueTokenId", "uti"], ""),
        "correlation_id": _first(rec, ["correlationId", "CorrelationId"], ""),
        "incoming_token_type": _first(rec, ["incomingTokenType", "IncomingTokenType"], ""),
        "device_id": dev.get("deviceId", ""),
        "device_trust": dev.get("trustType", ""),
        "device_managed": bool(dev.get("isManaged")) if "isManaged" in dev else None,
        "risk_level": _first(rec, ["riskLevelDuringSignIn", "riskLevelAggregated", "RiskLevelDuringSignIn"], ""),
        "risk_state": _first(rec, ["riskState", "RiskState"], ""),
        "ca_status": _first(rec, ["conditionalAccessStatus", "ConditionalAccessStatus"], ""),
        "raw": rec,
    }


def normalize_audit(rec):
    """Entra directory audit record (role/app/consent/secret changes)."""
    init = _first(rec, ["initiatedBy", "InitiatedBy"], {})
    actor = ""
    if isinstance(init, dict):
        u = init.get("user") or {}
        actor = (u.get("userPrincipalName") or u.get("id") or "")
    actor = (actor or _first(rec, ["userPrincipalName", "UserId"], "") or "").lower()
    targets = _first(rec, ["targetResources", "TargetResources"], []) or []
    tname = ""
    if isinstance(targets, list) and targets:
        tname = (targets[0] or {}).get("displayName", "") if isinstance(targets[0], dict) else ""
    return {
        "source": "EntraAudit",
        "time": parse_time(_first(rec, ["activityDateTime", "ActivityDateTime",
                                        "createdDateTime", "CreationTime"])),
        "operation": (_first(rec, ["activityDisplayName", "ActivityDisplayName",
                                   "operationName", "Operation"], "") or ""),
        "actor": actor,
        "target": tname,
        "ip": _first(rec, ["ipAddress", "IpAddress"], ""),
        "session_id": _first(rec, ["sessionId", "AADSessionId"], ""),
        "result": _first(rec, ["result", "Result"], ""),
        "raw": rec,
    }


def _params_to_dict(p):
    """Exchange UAL Parameters / ModifiedProperties come as a list of {Name,Value}
    (or {Name,NewValue}); flatten to a plain dict."""
    out = {}
    if isinstance(p, list):
        for it in p:
            if isinstance(it, dict) and "Name" in it:
                out[str(it["Name"])] = it.get("Value", it.get("NewValue", ""))
    elif isinstance(p, dict):
        out = dict(p)
    return out


def normalize_ual(rec):
    """Purview / Unified Audit Log record (Exchange / SharePoint / AAD ops).
    Also extracts the mail-item evidence (InternetMessageId / folder / size) and
    subject / client info that the analyst needs to build an exfil inventory."""
    ad = _maybe_json(_first(rec, ["AuditData", "auditData"], {}))
    if not isinstance(ad, dict):
        ad = {}
    def g(*keys):
        return _first(rec, list(keys), None) or _first(ad, list(keys), None)

    # MailItemsAccessed / sync ops carry Folders[].FolderItems[].InternetMessageId
    mail_items = []
    folders = ad.get("Folders") or ad.get("AffectedItems")
    if isinstance(folders, list):
        for fol in folders:
            if not isinstance(fol, dict):
                continue
            path = fol.get("Path") or fol.get("FolderPath") or ""
            for it in (fol.get("FolderItems") or []):
                if isinstance(it, dict):
                    mail_items.append({
                        "message_id": it.get("InternetMessageId") or it.get("Id") or "",
                        "folder": path,
                        "size": it.get("SizeInBytes") or it.get("Size"),
                    })
    # Send / Create / Update ops carry the item directly (subject available here)
    item = ad.get("Item") if isinstance(ad.get("Item"), dict) else {}
    subject = item.get("Subject") or ad.get("Subject") or ""
    if item.get("InternetMessageId"):
        pf = item.get("ParentFolder") or {}
        mail_items.append({"message_id": item.get("InternetMessageId"),
                           "folder": pf.get("Path", "") if isinstance(pf, dict) else "",
                           "size": item.get("SizeInBytes"), "subject": subject})

    return {
        "source": "UAL",
        "time": parse_time(g("CreationTime", "creationTime", "CreationDate")),
        "operation": (g("Operation", "operation") or ""),
        "workload": (g("Workload", "workload") or ""),
        "actor": (g("UserId", "userId", "UserKey") or "").lower(),
        "ip": (g("ClientIP", "clientIP", "ClientIPAddress", "ActorIpAddress") or ""),
        "session_id": (g("AADSessionId", "SessionId", "sessionId") or ""),
        "uti": (g("UniqueTokenId", "uniqueTokenId") or ""),
        "object": (g("ObjectId", "ObjectID") or ""),
        "app_id": (g("AppId", "ClientAppId", "ApplicationId") or ""),
        "client_info": (g("ClientInfoString", "ClientProcessName", "ClientProcess") or ""),
        "subject": subject,
        "mail_items": mail_items,
        "params": ad.get("Parameters") or ad.get("ModifiedProperties") or "",
        "parameters": _params_to_dict(ad.get("Parameters") or ad.get("ModifiedProperties")),
        "raw": rec,
    }


# --------------------------------------------------------------------------- #
# Reference data
# --------------------------------------------------------------------------- #

# Entra sign-in error codes worth surfacing
ERROR_CODES = {
    "50126": "Invalid username or password (credential failure)",
    "50053": "Account locked / too many failed attempts (smart lockout)",
    "50055": "Expired password",
    "50056": "Invalid or null password",
    "50074": "Strong auth (MFA) required but NOT satisfied - frequently a TA replaying "
             "a stolen token/cookie that carries no MFA claim and cannot clear a fresh "
             "MFA challenge (the attacker hitting the MFA wall)",
    "50132": "Session/token invalid - fresh token needed (often the AiTM proxy 'warming "
             "up' a relay, or a session invalidated by password change / revocation)",
    "50076": "MFA required by Conditional Access - not completed",
    "50079": "User must enroll for MFA",
    "500121": "MFA failed or timed out (possible MFA fatigue)",
    "530032": "Blocked by Conditional Access policy",
    "53003": "Blocked by Conditional Access policy",
    "50158": "External security challenge not satisfied",
    "50199": "CMSI interrupt - anti-spoofing 'confirm this app' challenge. Benign on "
             "mobile webviews / chrome-extension redirects, but a burst signals an "
             "EMBEDDED or PROXIED auth context (AiTM kits, webviews) worth examining",
    "50173": "Fresh auth token required - session/token revoked or password changed "
             "(seen after a revocation, or when an old stolen token is re-presented)",
    "65001": "Application consent not granted",
    "650052": "App needs admin consent",
    "50097": "Device authentication required",
    "50057": "User account is disabled - after containment this blocks both the victim "
             "and the TA; a 50057 from attacker infra confirms a post-disable retry",
}

# Post-compromise operation -> (category, severity weight, note)
RISKY_OPS = {
    # mail rules / forwarding / exfil (BEC after AiTM)
    "new-inboxrule":        ("mail_rule",  "HIGH",   "Inbox rule created (forward/hide - BEC signature)"),
    "set-inboxrule":        ("mail_rule",  "HIGH",   "Inbox rule modified"),
    "updateinboxrules":     ("mail_rule",  "HIGH",   "Inbox rules updated via OWA"),
    "set-mailbox":          ("forwarding", "HIGH",   "Mailbox setting changed (check forwarding)"),
    "set-mailboxautoreplyconfiguration": ("forwarding", "MEDIUM", "Auto-reply changed"),
    "new-transportrule":    ("forwarding", "HIGH",   "Org-wide transport rule created"),
    "add-mailboxpermission":("mail_access","HIGH",   "Mailbox delegate permission granted"),
    "add-recipientpermission":("mail_access","HIGH", "SendAs permission granted"),
    "mailitemsaccessed":    ("mail_access","MEDIUM", "Mail items accessed (possible data access)"),
    # illicit OAuth consent / app abuse
    "consent to application":("oauth_consent","HIGH","Application consent granted (illicit consent grant?)"),
    "add oauth2permissiongrant":("oauth_consent","HIGH","Delegated permission grant added"),
    "add delegated permission grant":("oauth_consent","HIGH","Delegated permission grant added"),
    "add app role assignment grant to user.":("oauth_consent","HIGH","App role assignment granted"),
    "add app role assignment to service principal":("oauth_consent","HIGH","App role assigned to SP"),
    "add service principal":("app_persist","HIGH","Service principal added"),
    "add service principal credentials":("app_persist","CRITICAL","Credential/secret added to app (persistence)"),
    "update application - certificates and secrets management":("app_persist","CRITICAL","App secret/cert added (persistence)"),
    "update application – certificates and secrets management":("app_persist","CRITICAL","App secret/cert added (persistence)"),
    "add owner to application":("app_persist","HIGH","Owner added to application"),
    "add owner to service principal":("app_persist","HIGH","Owner added to service principal"),
    # privilege escalation
    "add member to role":   ("privilege",  "HIGH",   "Member added to directory role"),
    "add eligible member to role (pim)":("privilege","HIGH","PIM eligible role added"),
    "add member to group":  ("privilege",  "MEDIUM", "Member added to group (check if privileged)"),
    # MFA / auth method tampering
    "disable strong authentication":("mfa_tamper","CRITICAL","MFA disabled for user"),
    "user registered security info":("mfa_tamper","HIGH","Security info (MFA method) registered - attacker may add method"),
    "admin registered security info":("mfa_tamper","HIGH","Admin registered security info for user"),
    "user deleted security info":("mfa_tamper","HIGH","Security info deleted"),
    "update authentication phone":("mfa_tamper","HIGH","Auth phone changed"),
    "reset user password":  ("password",   "HIGH",   "Password reset"),
    "change user password": ("password",   "MEDIUM", "Password changed"),
    # SharePoint / OneDrive exfil
    "filedownloaded":       ("file_exfil", "MEDIUM", "File downloaded"),
    "filesyncdownloadedfull":("file_exfil","MEDIUM", "Full file sync download"),
    "anonymouslinkcreated": ("file_share", "HIGH",   "Anonymous sharing link created"),
    "sharinginvitationcreated":("file_share","MEDIUM","External sharing invitation"),
    "addedtosecurelink":    ("file_share", "MEDIUM", "User added to secure link"),
    "companylinkcreated":   ("file_share", "MEDIUM", "Org-wide sharing link created"),
}

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# --------------------------------------------------------------------------- #
# Geo
# --------------------------------------------------------------------------- #

def haversine_km(lat1, lon1, lat2, lon2):
    try:
        r = 6371.0
        p1, p2 = math.radians(lat1), math.radians(lat2)
        dp = math.radians(lat2 - lat1)
        dl = math.radians(lon2 - lon1)
        a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
        return 2 * r * math.asin(min(1.0, math.sqrt(a)))
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #

def strip_port(ip):
    """UAL ClientIP often carries a :port (and IPv6 may be bracketed). Drop it."""
    if not ip:
        return ip
    ip = str(ip).strip()
    if ip.startswith("["):                      # [v6]:port
        return ip[1:].split("]")[0]
    if ip.count(":") == 1 and "." in ip:        # v4:port
        return ip.split(":")[0]
    return ip


def net_key(ip):
    """Collapse an IP to a stable NETWORK identity so one user's churn doesn't look
    like many hosts: IPv4 -> /24, IPv6 -> /64. This is what makes 12.160.226.0/24
    (a corporate egress block) and rotating IPv6 privacy addresses read as ONE
    network instead of dozens."""
    ip = strip_port(ip)
    if not ip:
        return ip
    try:
        if ":" in ip:                            # IPv6 -> /64 (first 4 hextets)
            full = ip.split("%")[0]
            parts = full.split(":")
            # crude but dependency-free /64
            head = [p for p in parts if p != ""][:4]
            return ":".join(head) + "::/64"
        octs = ip.split(".")
        if len(octs) == 4:
            return ".".join(octs[:3]) + ".0/24"
    except Exception:
        pass
    return ip


# Built-in defaults for hosting / VPS / proxy ASNs (TA infra tends to live here,
# users do not). Kept OUT of the trusted baseline and used to spot replayed device
# claims on datacenter infra. Extend/override at runtime with --asn-intel <file.json>:
#   {"hosting_asns": {"64500": "SomeVPS", "64501": "AnotherHost"}}
# (a JSON list of ASN numbers is also accepted). File entries merge with these.
DEFAULT_HOSTING_ASNS = {
    14061: "DigitalOcean", 16276: "OVH", 20473: "Vultr/Choopa", 24940: "Hetzner",
    63949: "Akamai/Linode", 14618: "AWS", 16509: "AWS", 15169: "Google",
    396982: "Google Cloud", 13335: "Cloudflare", 9009: "M247", 51852: "Private Layer",
    53667: "FranTech/BuyVM", 62240: "Clouvider", 36352: "ColoCrossing",
    55286: "B2 Net Solutions/ServerMania", 22612: "Namecheap/Nocix",
    40021: "NL/Contabo", 51167: "Contabo", 29802: "HVC/Hudson Valley",
    46844: "ReliableSite", 8100: "QuadraNet", 25820: "IT7", 19318: "Interserver",
}


def load_hosting_asns(path):
    """Load hosting-ASN intel from a JSON file and merge with the built-in defaults.
    Accepts either {"hosting_asns": {"<asn>": "name", ...}} / {"<asn>": "name"} or a
    bare list [asn, asn, ...]. Returns a dict {int_asn: name}."""
    merged = dict(DEFAULT_HOSTING_ASNS)
    if not path:
        return merged
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("hosting_asns", data)
    if isinstance(data, dict):
        for k, v in data.items():
            try:
                merged[int(k)] = v or "(custom)"
            except (TypeError, ValueError):
                continue
    elif isinstance(data, list):
        for k in data:
            try:
                merged[int(k)] = "(custom)"
            except (TypeError, ValueError):
                continue
    return merged


class Analyzer:
    def __init__(self, logs, since=None, until=None, spray_min_users=5,
                 travel_kmh=900.0, hosting_asns=None):
        self.hosting_asns = hosting_asns if hosting_asns is not None else dict(DEFAULT_HOSTING_ASNS)
        self.signins = []
        for lt in ("interactive", "noninteractive", "serviceprincipal", "managedidentity"):
            for r in logs.get(lt, []):
                s = normalize_signin(r, lt)
                if self._in_window(s["time"], since, until):
                    self.signins.append(s)
        self.audits = [a for a in (normalize_audit(r) for r in logs.get("audit", []))
                       if self._in_window(a["time"], since, until)]
        self.ual = [u for u in (normalize_ual(r) for r in logs.get("purview", []))
                    if self._in_window(u["time"], since, until)]
        self.spray_min_users = spray_min_users
        self.travel_kmh = travel_kmh
        self.findings = []
        self.users = {}          # upn/userid -> user record
        self.attacker_ips = {}   # ip -> reasons
        self.suspect_sessions = {}

    @staticmethod
    def _in_window(t, since, until):
        if t is None:
            return True
        if since and t < since:
            return False
        if until and t > until:
            return False
        return True

    def add(self, sev, category, title, evidence, recommendation, entity=""):
        self.findings.append({
            "severity": sev, "category": category, "title": title,
            "evidence": evidence, "recommendation": recommendation, "entity": entity,
        })

    # -- identity index ----------------------------------------------------- #
    def build_users(self):
        for s in self.signins:
            s["ip"] = strip_port(s["ip"])          # normalize once
            s["net"] = net_key(s["ip"])
            key = s["upn"] or s["user_id"]
            if not key:
                continue
            u = self.users.setdefault(key, {
                "key": key, "upn": s["upn"], "user_id": s["user_id"],
                "display": s["user_display"], "signins": [],
                "interactive_ips": set(), "all_ips": set(),
                "countries": set(), "ual": [], "audits": [], "ta_observations": [],
            })
            u["upn"] = u["upn"] or s["upn"]
            u["display"] = u["display"] or s["user_display"]
            u["signins"].append(s)
            if s["ip"]:
                u["all_ips"].add(s["ip"])
                if s["log_type"] == "interactive" and s["success"]:
                    u["interactive_ips"].add(s["ip"])
            if s["country"]:
                u["countries"].add(s["country"])
        for u in self.ual:
            u["ip"] = strip_port(u["ip"])
            u["net"] = net_key(u["ip"])
            rec = self.users.get(u["actor"])
            if rec is not None:
                rec["ual"].append(u)
        for a in self.audits:
            a["ip"] = strip_port(a.get("ip"))
            rec = self.users.get(a["actor"])
            if rec is not None:
                rec["audits"].append(a)

        # Build the user's LEGITIMATE footprint. Two anti-contamination rules are
        # critical because an AiTM relay produces a SUCCESSFUL sign-in for the attacker
        # (often with the victim's deviceId replayed and UA spoofed):
        #   * any network/ASN that EVER carried an AiTM error code (50199/50132/50074)
        #     or an Entra risk flag is TAINTED and cannot seed the baseline;
        #   * hosting/VPS ASNs never seed the baseline (users don't log in from VPS).
        # Without this, the proxy's own /24 becomes "the user's network" and the TA
        # stops being flagged.
        AITM_CODES = {"50199", "50132", "50074", "50076"}
        for u in self.users.values():
            tainted_nets, tainted_asns = set(), set()
            for s in u["signins"]:
                risky = (str(s["error_code"]) in AITM_CODES
                         or str(s["risk_level"]).lower() in ("high", "medium")
                         or str(s["risk_state"]).lower() in ("atrisk", "confirmedcompromised"))
                if risky:
                    if s["net"]:
                        tainted_nets.add(s["net"])
                    if s["asn"]:
                        tainted_asns.add(s["asn"])
            u["tainted_nets"], u["tainted_asns"] = tainted_nets, tainted_asns

            succ = [s for s in u["signins"] if s["success"]]
            # device fleet: only from CLEAN sign-ins (a deviceId first seen on hosting/
            # tainted infra is a replayed claim, not a real enrolment)
            u["device_fleet"] = {s["device_id"] for s in succ if s["device_id"]
                                 and s["net"] not in tainted_nets
                                 and s["asn"] not in tainted_asns
                                 and (s["asn"] not in self.hosting_asns)}
            u["baseline_devices"] = set(u["device_fleet"])
            trusted = [s for s in succ
                       if ((s["device_id"] and s["device_id"] in u["device_fleet"])
                           or s["log_type"] == "interactive")
                       and s["net"] not in tainted_nets
                       and s["asn"] not in tainted_asns
                       and s["asn"] not in self.hosting_asns]
            if not trusted:
                trusted = [s for s in succ if s["asn"] not in self.hosting_asns][:1]
            u["baseline_nets"] = {s["net"] for s in trusted if s["net"]}
            u["baseline_asns"] = {s["asn"] for s in trusted if s["asn"]}
            u["baseline_uas"] = {s["user_agent"] for s in trusted if s["user_agent"]}
            u["baseline_countries"] = {s["country"] for s in trusted if s["country"]}
            u["baseline_apps"] = {s["app"] for s in trusted if s.get("app")}
            u["baseline_app_ids"] = {s["app_id"] for s in trusted if s.get("app_id")}
            u["baseline_client_apps"] = {s["client_app"] for s in trusted if s.get("client_app")}
            inter = [s for s in trusted if s["log_type"] == "interactive"]
            u["last_legit_time"] = max((s["time"] for s in (inter or trusted) if s["time"]),
                                       default=None)

    def _is_user_network(self, u, s):
        """Is this sign-in on a network/device the user legitimately uses? A fleet
        deviceId confers trust ONLY off hosting/tainted infrastructure - otherwise it
        is a replayed claim. (No first-party/Microsoft suppression: every network is
        evaluated, so a TA operating from Microsoft/Azure infra is not auto-cleared.)"""
        if s.get("net") and s["net"] in u.get("baseline_nets", set()):
            return True
        if s.get("asn") and s["asn"] in u.get("baseline_asns", set()):
            return True
        if (s.get("device_id") and s["device_id"] in u.get("device_fleet", set())
                and s.get("net") not in u.get("tainted_nets", set())
                and s.get("asn") not in u.get("tainted_asns", set())
                and s.get("asn") not in self.hosting_asns):
            return True
        return False

    def _machine_side(self, u, s):
        """Classify a sign-in's MACHINE against the user's legitimate footprint. A
        fleet deviceId is trusted ONLY off hosting/tainted infra; on VPS/proxy infra a
        matching deviceId is a REPLAYED claim (the TA spoofing the victim's device)."""
        clean_fleet = (s.get("device_id") and s["device_id"] in u.get("device_fleet", set())
                       and s.get("net") not in u.get("tainted_nets", set())
                       and s.get("asn") not in u.get("tainted_asns", set())
                       and s.get("asn") not in self.hosting_asns)
        if clean_fleet:
            return "legit-fleet", "deviceId in user's trusted device fleet"
        if s.get("device_id") and s["device_id"] in u.get("device_fleet", set()):
            return "ta", (f"REPLAYED device claim - victim deviceId presented from "
                          f"hosting/tainted infra (ASN {s.get('asn')})")
        dev = ("absent" if not s["device_id"] else "mismatch")
        ua = ("match" if s["user_agent"] in u.get("baseline_uas", set())
              else ("absent" if not s["user_agent"] else "mismatch"))
        if dev == "mismatch" or ua == "mismatch":
            return "ta", f"different machine (deviceId={dev}, UA={ua})"
        return "verify", f"no fleet deviceId; UA={ua} vs baseline"

    def _flag_ip(self, ip, reason):
        if ip:
            self.attacker_ips.setdefault(strip_port(ip), set()).add(reason)

    # -- detections --------------------------------------------------------- #
    def _user_of(self, key):
        return self.users.get((key or "").lower())

    def detect_session_redundancy(self):
        """Replay = a session/token appearing from a network OUTSIDE the user's
        footprint. NOT 'more than one IP' - a legitimate session routinely spans a
        laptop, a phone, rotating IPv6, a corporate /24 egress, and Microsoft service
        IPs. We collapse to /24-/64 networks and flag only networks the user does not
        normally use (and weight cross-country / concurrent higher)."""
        by_sid = defaultdict(list)
        by_uti = defaultdict(list)
        for s in self.signins:
            owner = s["upn"] or s["user_id"]
            if s["session_id"]:
                by_sid[s["session_id"]].append((owner, s))
            if s["uti"]:
                by_uti[s["uti"]].append((owner, s))
        for u in self.ual:
            if u["session_id"]:
                by_sid[u["session_id"]].append((u["actor"], u))
            if u["uti"]:
                by_uti[u["uti"]].append((u["actor"], u))

        def owner_user(items):
            for owner, _ in items:
                ur = self._user_of(owner)
                if ur:
                    return ur
            return None

        for sid, items in by_sid.items():
            ur = owner_user(items)
            if ur is None:
                continue
            nets = {it.get("net") for _, it in items if it.get("net")}
            if len(nets) <= 1:
                continue
            outside = [(it.get("net"), it.get("ip"), it.get("country"))
                       for _, it in items
                       if it.get("net") and not self._is_user_network(ur, it)]
            outside_nets = {o[0] for o in outside}
            if not outside_nets:
                continue  # multi-IP but all within the user's own footprint -> benign
            outside_ips = sorted({o[1] for o in outside if o[1]})
            countries = {o[2] for o in outside if o[2]} | set(ur.get("baseline_countries", set()))
            sev = "CRITICAL" if len(countries) > 1 else "HIGH"
            self.suspect_sessions[sid] = outside_ips
            for ip in outside_ips:
                self._flag_ip(ip, "session replayed from outside-footprint network")
            self.add(sev, "Token Replay",
                     f"Session {sid[:18]} used from {len(outside_nets)} network(s) outside the user footprint",
                     {"session_id": sid, "outside_ips": outside_ips,
                      "user_baseline_nets": sorted(ur.get("baseline_nets", set()))[:6],
                      "countries_involved": sorted(c for c in countries if c)},
                     "The session was exercised from a network the user does not normally "
                     "use: session/cookie replay. Revoke the session and sweep all activity "
                     "under this AADSessionId.",
                     entity=sid)

        for uti, items in by_uti.items():
            ur = owner_user(items)
            if ur is None:
                continue
            outside_ips = sorted({it.get("ip") for _, it in items
                                  if it.get("ip") and not self._is_user_network(ur, it)})
            nets = {it.get("net") for _, it in items if it.get("net")}
            if outside_ips and len(nets) > 1:
                for ip in outside_ips:
                    self._flag_ip(ip, "token (uti) used from outside-footprint network")
                self.add("CRITICAL", "Token Replay",
                         f"Token {uti[:18]} (uti) used from outside the user footprint",
                         {"uti": uti, "outside_ips": outside_ips},
                         "A single UniqueTokenId used from a network outside the user "
                         "footprint is literal bearer-token replay. Revoke immediately.",
                         entity=uti)

    def detect_replay_and_aitm(self):
        """Per user: flag token use / MFA-by-token from networks OUTSIDE the user's
        footprint (not raw 'new IP'), and composite AiTM scoring. De-duplicated per
        network so one attacker /24 is one finding, not hundreds."""
        for u in self.users.values():
            signins = sorted(u["signins"], key=lambda x: x["time"] or datetime.min.replace(tzinfo=timezone.utc))
            aitm_reasons = []
            first_interactive = next((s for s in signins
                                      if s["log_type"] == "interactive" and s["success"]), None)
            seen_net = set()  # collapse repeated hits from the same outside network

            for s in signins:
                if not s["success"] or not s["ip"]:
                    continue
                if self._is_user_network(u, s):
                    continue  # the user's own laptop/phone/egress/ISP - not suspicious
                side, side_detail = self._machine_side(u, s)
                if side == "legit-fleet":
                    continue  # trusted device on an unusual network -> roaming, skip
                net = s["net"]
                # every outside, non-fleet success enriches the TA profile (apps/appIds/
                # UA/client-app); the FINDING is deduped to one per network.
                if s not in u["ta_observations"]:
                    u["ta_observations"].append(s)
                # 1) token use from an outside network (one finding per network)
                if s["log_type"] == "noninteractive" and net not in seen_net:
                    seen_net.add(net)
                    self._flag_ip(s["ip"], "token use from outside-footprint network")
                    sev = "HIGH" if side == "ta" else "MEDIUM"
                    self.add(sev, "Token Replay",
                             f"Token used from outside-footprint network {net} for {u['key']}",
                             {"user": u["key"], "ip": s["ip"], "network": net,
                              "country": s["country"], "asn": s["asn"],
                              "device_id": s["device_id"] or "(none)",
                              "user_agent": (s["user_agent"] or "(none)")[:90],
                              "app": s["app"], "app_id": s["app_id"],
                              "client_app": s["client_app"],
                              "machine_assessment": side_detail,
                              "resource": s["resource"],
                              "time": fmt_dt(s["time"]),
                              "session_id": s["session_id"], "uti": s["uti"]},
                             "Token exercised from a network the user does not normally use, "
                             "on a device/UA outside the trusted fleet: stolen-token replay.",
                             entity=u["key"])
                    aitm_reasons.append(f"token use from {net} [{side_detail}]")
                # 2) MFA satisfied by token from an outside network
                if s["satisfied_by_token"]:
                    self._flag_ip(s["ip"], "MFA-by-token from outside-footprint network")
                    aitm_reasons.append(f"MFA satisfied by claim-in-token from {net}")
                    if s not in u["ta_observations"]:
                        u["ta_observations"].append(s)
                # 3) risky sign-in from an outside network
                if str(s["risk_state"]).lower() in ("atrisk", "confirmedcompromised") or \
                   str(s["risk_level"]).lower() in ("high", "medium"):
                    aitm_reasons.append(f"Entra risk={s['risk_level'] or s['risk_state']} at {net}")

            # composite AiTM: interactive success then token use from an outside network
            if first_interactive:
                for s in signins:
                    if (s["time"] and first_interactive["time"]
                            and s["time"] >= first_interactive["time"]
                            and s["log_type"] == "noninteractive" and s["success"]
                            and not self._is_user_network(u, s)
                            and self._machine_side(u, s)[0] != "legit-fleet"):
                        gap = ""
                        try:
                            mins = (s["time"] - first_interactive["time"]).total_seconds() / 60.0
                            gap = f" (+{int(mins)}m after interactive login)"
                        except Exception:
                            pass
                        aitm_reasons.append(
                            f"interactive login then token use from outside network {s['net']}{gap}")
                        break

            if aitm_reasons:
                sev = "CRITICAL" if len(set(aitm_reasons)) >= 2 else "HIGH"
                legit, ta = self._actor_profiles(u)
                self.add(sev, "AiTM / Account Compromise",
                         f"AiTM / session-theft indicators for {u['key']}",
                         {"user": u["key"], "indicators": sorted(set(aitm_reasons)),
                          "legitimate_profile": legit,
                          "threat_actor_profile": ta},
                         "Multiple credential-theft indicators converge on this account. "
                         "Revoke sessions/refresh tokens, reset credentials, review MFA "
                         "methods, and audit all O365 actions in the window.",
                         entity=u["key"])
                u["compromised"] = True
                u["legit_profile"] = legit
                u["ta_profile"] = ta

    def _actor_profiles(self, u):
        """Contrast the LEGITIMATE machine fingerprint with the THREAT ACTOR's,
        distinguishing by deviceId / user-agent AND IP / geo / time."""
        inter = [s for s in u["signins"] if s["log_type"] == "interactive" and s["success"]]
        legit = {
            "device_fleet": sorted(d for d in u.get("device_fleet", set())) or ["(none registered)"],
            "user_agents": sorted(u.get("baseline_uas", set()))[:4] or ["(none)"],
            "networks": sorted(u.get("baseline_nets", set()))[:8],
            "asns": sorted(str(a) for a in u.get("baseline_asns", set()) if a),
            "countries": sorted(c for c in u.get("baseline_countries", set()) if c),
            "apps": sorted(u.get("baseline_apps", set()))[:10],
            "client_apps": sorted(u.get("baseline_client_apps", set())),
            "last_interactive": fmt_dt(u.get("last_legit_time")),
        }
        obs = u.get("ta_observations", [])
        ta = {
            "device_ids": sorted({s["device_id"] or "(none/unregistered)" for s in obs}),
            "device_trust": sorted({s["device_trust"] for s in obs if s.get("device_trust")}) or ["(unmanaged/none)"],
            "user_agents": sorted({(s["user_agent"] or "(none)")[:90] for s in obs}),
            "apps": sorted({s["app"] for s in obs if s.get("app")}),
            "app_ids": sorted({s["app_id"] for s in obs if s.get("app_id")}),
            "resources": sorted({s["resource"] for s in obs if s.get("resource")}),
            "client_apps": sorted({s["client_app"] for s in obs if s.get("client_app")}),
            "networks": sorted({s["net"] for s in obs if s.get("net")}),
            "ips": sorted({s["ip"] for s in obs if s["ip"]}),
            "asns": sorted({str(s["asn"]) for s in obs if s.get("asn")}),
            "countries": sorted({s["country"] for s in obs if s["country"]}),
            "sessions": sorted({s["session_id"] for s in obs if s["session_id"]}),
            "utis": sorted({s["uti"] for s in obs if s["uti"]}),
            "first_seen": fmt_dt(min((s["time"] for s in obs if s["time"]), default=None)),
            "last_seen": fmt_dt(max((s["time"] for s in obs if s["time"]), default=None)),
        }
        # time factor: capture -> first replay gap vs the legit interactive login
        if u.get("last_legit_time") and obs:
            ft = min((s["time"] for s in obs if s["time"]), default=None)
            if ft:
                try:
                    mins = (ft - u["last_legit_time"]).total_seconds() / 60.0
                    ta["minutes_after_legit_login"] = round(mins, 1)
                    ta["concurrent_with_legit_session"] = abs(mins) < 60
                except Exception:
                    pass
        return legit, ta

    def detect_impossible_travel(self):
        for u in self.users.values():
            succ = sorted([s for s in u["signins"] if s["success"] and s["ip"]],
                          key=lambda x: x["time"] or datetime.min.replace(tzinfo=timezone.utc))
            seen_pairs = set()
            for a, b in zip(succ, succ[1:]):
                if not (a["time"] and b["time"]):
                    continue
                # both endpoints within the user's footprint -> normal device churn
                if self._is_user_network(u, a) and self._is_user_network(u, b):
                    continue
                if a["net"] == b["net"]:
                    continue
                pair = tuple(sorted((a["net"] or a["ip"], b["net"] or b["ip"])))
                if pair in seen_pairs:
                    continue
                dt_h = (b["time"] - a["time"]).total_seconds() / 3600.0
                if dt_h <= 0:
                    continue
                if None not in (a["lat"], a["lon"], b["lat"], b["lon"]):
                    km = haversine_km(a["lat"], a["lon"], b["lat"], b["lon"])
                    # require a real distance so geo-jitter within a metro doesn't fire
                    if km and km > 100 and dt_h < 24 and (km / dt_h) > self.travel_kmh:
                        seen_pairs.add(pair)
                        for ip in (a["ip"], b["ip"]):
                            if not self._is_user_network(u, a if ip == a["ip"] else b):
                                self._flag_ip(ip, "impossible travel (outside footprint)")
                        self.add("HIGH", "Impossible Travel",
                                 f"Impossible travel for {u['key']} ({int(km)} km in {dt_h:.1f}h)",
                                 {"user": u["key"], "from": f"{a['city']},{a['country']} ({a['ip']})",
                                  "to": f"{b['city']},{b['country']} ({b['ip']})",
                                  "km": int(km), "hours": round(dt_h, 2),
                                  "implied_kmh": int(km / dt_h)},
                                 "Two successful sign-ins too far apart to travel between, at "
                                 "least one outside the user footprint. Clear against VPN/egress.",
                                 entity=u["key"])
                elif a["country"] and b["country"] and a["country"] != b["country"] and dt_h < 1.0:
                    seen_pairs.add(pair)
                    for ip in (a["ip"], b["ip"]):
                        self._flag_ip(ip, "country change <1h")
                    self.add("MEDIUM", "Impossible Travel",
                             f"Country change for {u['key']} within {dt_h:.2f}h",
                             {"user": u["key"], "from": f"{a['country']} ({a['ip']})",
                              "to": f"{b['country']} ({b['ip']})", "hours": round(dt_h, 2)},
                             "Successful sign-ins from two countries within an hour (no geo "
                             "coords). Verify against VPN/egress.",
                             entity=u["key"])

    def detect_credential_attacks(self):
        """Password spray (one IP -> many users failing) and brute (user fails then succeeds)."""
        fails_by_ip = defaultdict(set)      # ip -> {users with 50126}
        fail_events_by_ip = defaultdict(int)
        for s in self.signins:
            code = str(s["error_code"]) if s["error_code"] is not None else ""
            if not s["success"] and code in ("50126", "50053", "50056"):
                if s["ip"]:
                    fails_by_ip[s["ip"]].add(s["upn"] or s["user_id"])
                    fail_events_by_ip[s["ip"]] += 1
        for ip, users in fails_by_ip.items():
            if len(users) >= self.spray_min_users:
                self._flag_ip(ip, "password spray source")
                self.add("HIGH", "Credential Attack",
                         f"Password spray from {ip} ({len(users)} users, {fail_events_by_ip[ip]} failures)",
                         {"ip": ip, "distinct_users": len(users),
                          "failures": fail_events_by_ip[ip],
                          "sample_users": sorted(u for u in users if u)[:8]},
                         "One source IP failing auth against many accounts is password "
                         "spray. Block the IP/ASN and check whether any of these users "
                         "subsequently succeeded.",
                         entity=ip)

        # brute success: user with >=5 failures then a success from same IP
        for u in self.users.values():
            seq = sorted(u["signins"], key=lambda x: x["time"] or datetime.min.replace(tzinfo=timezone.utc))
            fails = 0
            for s in seq:
                if not s["success"] and str(s["error_code"]) == "50126":
                    fails += 1
                elif s["success"] and fails >= 5:
                    self.add("HIGH", "Credential Attack",
                             f"Successful sign-in after {fails} failures for {u['key']}",
                             {"user": u["key"], "preceding_failures": fails,
                              "success_ip": s["ip"], "time": fmt_dt(s["time"])},
                             "Repeated credential failures followed by success suggests a "
                             "guessed/cracked password. Reset credentials and review session.",
                             entity=u["key"])
                    fails = 0

        # MFA fatigue: many 500121 for one user
        mfa_fail = defaultdict(int)
        for s in self.signins:
            if str(s["error_code"]) == "500121":
                mfa_fail[s["upn"] or s["user_id"]] += 1
        for user, n in mfa_fail.items():
            if n >= 5:
                self.add("MEDIUM", "Credential Attack",
                         f"Possible MFA fatigue against {user} ({n} MFA prompts denied/timed out)",
                         {"user": user, "mfa_denials": n},
                         "Repeated MFA challenges (error 500121) can indicate MFA-fatigue "
                         "push bombing. Confirm with the user; require number-matching.",
                         entity=user)

    def detect_cmsi_interrupt(self):
        """AADSTS50199 (CMSI interrupt) clusters. Often benign, but a burst - or any
        occurrence tied to an already-flagged user/IP - points at an embedded/proxied
        auth context (AiTM kit / webview / chrome-extension), which is a useful clue."""
        by_user = defaultdict(list)
        for s in self.signins:
            if str(s["error_code"]) == "50199":
                by_user[s["upn"] or s["user_id"]].append(s)
        for user, hits in by_user.items():
            ips = sorted({h["ip"] for h in hits if h["ip"]})
            apps = sorted({h["app"] for h in hits if h["app"]})
            tied = (user in (k for k, u in self.users.items() if u.get("compromised"))
                    or any(ip in self.attacker_ips for ip in ips))
            sev = "MEDIUM" if (tied or len(hits) >= 5) else "INFO"
            self.add(sev, "AiTM Clue (CMSI interrupt)",
                     f"AADSTS50199 CMSI interrupt x{len(hits)} for {user}",
                     {"user": user, "count": len(hits), "ips": ips, "apps": apps,
                      "meaning": ERROR_CODES["50199"],
                      "tied_to_flagged_user_or_ip": tied},
                     "CMSI interrupt is the anti-spoofing 'confirm this app' challenge. A "
                     "burst, or any occurrence from a flagged IP/user, suggests the sign-in "
                     "happened in an embedded/proxied context (AiTM kit, webview, "
                     "chrome-extension). Correlate the IP/UA with the suspect session.",
                     entity=user)

    def detect_mfa_wall(self):
        """AADSTS50074 / 50076 - strong auth required but not satisfied. When this
        comes from a NON-baseline IP/machine it is the signature of a TA replaying a
        stolen token/cookie that carries no MFA claim and cannot clear a fresh MFA
        challenge. Often the EARLIEST trace of an attempted compromise. If the same
        IP/session later SUCCEEDS, the attacker found an MFA-satisfied path -> escalate."""
        MFA_WALL_CODES = ("50074", "50076", "50079")
        for u in self.users.values():
            signins = sorted(u["signins"], key=lambda x: x["time"] or datetime.min.replace(tzinfo=timezone.utc))
            wall_hits = [s for s in signins
                         if (not s["success"]) and str(s["error_code"]) in MFA_WALL_CODES
                         and not self._is_user_network(u, s)]  # the user's own MFA prompts are normal
            for s in wall_hits:
                side, side_detail = self._machine_side(u, s)
                self._flag_ip(s["ip"], "MFA-wall (attempted stolen-token use)")
                if s not in u["ta_observations"]:
                    u["ta_observations"].append(s)
                sev = "HIGH" if side == "ta" else "MEDIUM"
                self.add(sev, "Attempted Token Replay (MFA wall)",
                         f"AADSTS{s['error_code']} strong-auth-required from outside-footprint network for {u['key']}",
                         {"user": u["key"], "ip": s["ip"], "network": s["net"],
                          "country": s["country"],
                          "device_id": s["device_id"] or "(none)",
                          "user_agent": (s["user_agent"] or "(none)")[:80],
                          "machine_assessment": side_detail,
                          "error": ERROR_CODES.get(str(s["error_code"]), s["error_code"]),
                          "app": s["app"], "time": fmt_dt(s["time"]),
                          "session_id": s["session_id"], "uti": s["uti"]},
                         "A stolen token/credential that could not satisfy MFA, used from a "
                         "network outside the user footprint. Treat as an attempted takeover; "
                         "check whether the same network/session later succeeded.",
                         entity=u["key"])

                # composite: MFA wall then success from same network or session = overcame MFA
                later_success = [x for x in signins
                                 if x["success"] and x["time"] and s["time"] and x["time"] >= s["time"]
                                 and ((x["net"] and x["net"] == s["net"])
                                      or (x["session_id"] and x["session_id"] == s["session_id"]))]
                if later_success:
                    win = later_success[0]
                    self._flag_ip(s["ip"], "overcame MFA wall (block then success)")
                    self.add("CRITICAL", "Account Compromise (MFA bypassed)",
                             f"MFA wall ({s['error_code']}) then SUCCESS for {u['key']}",
                             {"user": u["key"], "attacker_network": s["net"], "ip": s["ip"],
                              "blocked_at": fmt_dt(s["time"]),
                              "succeeded_at": fmt_dt(win["time"]),
                              "via": "same network" if win["net"] == s["net"] else "same session",
                              "session_id": win["session_id"]},
                             "An MFA-required failure from this network/session was followed by "
                             "a success - the attacker overcame MFA (fatigue, fallback method, "
                             "added auth method, or a newly MFA-satisfied token). Revoke "
                             "sessions, reset credentials, and audit MFA method changes.",
                             entity=u["key"])
                    u["compromised"] = True

    def detect_post_compromise(self):
        """Risky operations from Entra audit + UAL. Routine high-volume READ ops
        (MailItemsAccessed, FileAccessed, ...) are AGGREGATED, not emitted per-event -
        otherwise normal mailbox use produces hundreds of findings. A per-event
        finding is raised only for high-signal ops (rules, forwarding, consent, app
        secrets, privilege, MFA tamper) or reads BOUND to a suspect session/IP."""
        READ_OPS = {"mailitemsaccessed", "fileaccessed", "filepreviewed",
                    "filedownloaded", "filesyncdownloadedfull", "filemodified",
                    "fileuploaded", "filerenamed"}
        events = []
        for a in self.audits:
            events.append((a["operation"], a["actor"], a.get("ip"), a["session_id"],
                           a["time"], a["target"], "EntraAudit", None))
        for u in self.ual:
            events.append((u["operation"], u["actor"], u.get("ip"), u["session_id"],
                           u["time"], u["object"] or u["workload"], "UAL", u))

        read_tied = defaultdict(lambda: {"count": 0, "first": None, "last": None,
                                         "ips": set(), "items": []})
        read_free = defaultdict(lambda: {"count": 0, "first": None, "last": None})

        def _span(a, t):
            if t:
                a["first"] = min(a["first"], t) if a["first"] else t
                a["last"] = max(a["last"], t) if a["last"] else t

        for op, actor, ip, sid, t, tgt, src, ualrec in events:
            key = (op or "").strip().lower()
            match = next((meta for needle, meta in RISKY_OPS.items() if needle in key), None)
            if not match:
                continue
            category, sev, note = match
            ipn = strip_port(ip)
            tied = (sid and sid in self.suspect_sessions) or (ipn and ipn in self.attacker_ips)
            if key in READ_OPS:
                if tied:
                    a = read_tied[(actor, key, net_key(ip) or sid)]
                    a["count"] += 1; a["ips"].add(ipn); _span(a, t)
                    if ualrec:  # capture the mail-item evidence for the exfil inventory
                        for mi in ualrec.get("mail_items", []):
                            if mi.get("message_id"):
                                a["items"].append({**mi, "time": fmt_dt(t)})
                else:
                    a = read_free[(actor, key)]; a["count"] += 1; _span(a, t)
                continue
            # high-signal op -> per-event finding
            if tied and sev in ("HIGH", "MEDIUM"):
                sev = "CRITICAL" if sev == "HIGH" else "HIGH"
            ev = {"operation": op, "actor": actor, "ip": ipn, "session_id": sid,
                  "target": tgt, "time": fmt_dt(t), "source": src, "category": category}
            if ualrec and ualrec.get("subject"):
                ev["subject"] = ualrec["subject"]
            if ualrec and ualrec.get("client_info"):
                ev["client_info"] = ualrec["client_info"]
            # surface inbox-rule / forwarding PARAMETERS (the @domain it hides, where it
            # moves mail, forward targets) - these are the BEC IOCs
            if category in ("mail_rule", "forwarding") and ualrec:
                p = ualrec.get("parameters") or {}
                def _pv(*names):
                    for n in names:
                        for k in p:
                            if k.lower() == n.lower():
                                return p[k]
                    return ""
                rule = {
                    "name": _pv("Name"),
                    "from_contains": _pv("FromAddressContainsWords", "From"),
                    "subject_contains": _pv("SubjectContainsWords", "SubjectOrBodyContainsWords"),
                    "move_to": _pv("MoveToFolder"),
                    "delete": _pv("DeleteMessage"),
                    "mark_read": _pv("MarkAsRead"),
                    "forward_to": _pv("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo"),
                    "smtp_forward": _pv("ForwardingSmtpAddress", "ForwardingAddress"),
                    "stop_processing": _pv("StopProcessingRules"),
                }
                rule = {k: v for k, v in rule.items() if v not in ("", None)}
                if rule:
                    ev["rule"] = rule
                    ev["rule_summary"] = "; ".join(f"{k}={v}" for k, v in rule.items())
            if tied:
                ev["tied_to_suspect_session_or_ip"] = True
            self.add(sev, "Post-Compromise Action", f"{note}  [{actor or 'unknown actor'}]", ev,
                     "Confirm whether this action was authorized. If under a flagged "
                     "session/IP, treat as attacker action and remediate.",
                     entity=actor)
            rec = self.users.get(actor)
            if rec is not None:
                rec.setdefault("post_actions", []).append((category, op, t, ipn, sid, tied))

        # bulk reads BOUND to a suspect session/IP. A stolen session is often used by
        # BOTH the victim (from their own network) and the TA (from outside) - split
        # them by network so the analyst sees genuine exfil separately from the
        # victim's own access under the same shared session.
        for (actor, key, scope), a in read_tied.items():
            ur = self.users.get(actor)
            own_network = bool(ur) and scope in ur.get("baseline_nets", set())
            # mail-item inventory (InternetMessageId / folder / size / access time)
            items = a["items"]
            manifest = items[:60]
            total_bytes = sum(int(mi["size"]) for mi in items if str(mi.get("size") or "").isdigit())
            inv = {"accessed_items_total": len(items),
                   "accessed_bytes": total_bytes,
                   "sample_items": manifest,
                   "note": "subjects/senders require eDiscovery or Get-MessageTrace on the "
                           "InternetMessageId (not present in MailItemsAccessed itself)"} if items else {}
            if own_network:
                ev = {"actor": actor, "operation": key, "count": a["count"],
                      "network": scope, "ips": sorted(i for i in a["ips"] if i),
                      "window": f"{fmt_dt(a['first'])} -> {fmt_dt(a['last'])}",
                      "note": "session is shared/stolen but this access came from the "
                              "user's own network - most likely the victim, not the TA"}
                ev.update(inv)
                self.add("MEDIUM", "Data Access (shared session)",
                         f"{a['count']}x {key} under a suspect session from the user's OWN "
                         f"network ({scope}) for {actor}", ev,
                         "Access under the stolen session but from the user's own network. "
                         "Likely the victim's own activity; confirm against the TA-network "
                         "access to separate legitimate from attacker reads.",
                         entity=actor)
            else:
                ev = {"actor": actor, "operation": key, "count": a["count"],
                      "network": scope, "ips": sorted(i for i in a["ips"] if i),
                      "window": f"{fmt_dt(a['first'])} -> {fmt_dt(a['last'])}",
                      "tied_to_suspect_session_or_ip": True}
                ev.update(inv)
                self.add("HIGH", "Post-Compromise Action",
                         f"{a['count']}x {key} ({len(items)} items, {total_bytes/1e6:.1f} MB) from an "
                         f"OUTSIDE network under a suspect session for {actor}", ev,
                         "Bulk data access from a network OUTSIDE the user footprint under a "
                         "flagged session - treat as exfiltration. Resolve the listed "
                         "InternetMessageIds via eDiscovery / Get-MessageTrace for subjects.",
                         entity=actor)
            rec = self.users.get(actor)
            if rec is not None:
                rec.setdefault("post_actions", []).append(
                    (key, f"{a['count']}x {key}", a["last"],
                     sorted(a["ips"])[0] if a["ips"] else "", scope, not own_network))
        # routine reads NOT bound to anything = normal user activity (informational)
        for (actor, key), a in read_free.items():
            self.add("INFO", "Data Access (volume)",
                     f"{a['count']}x {key} for {actor} (routine, not session-bound)",
                     {"actor": actor, "operation": key, "count": a["count"],
                      "window": f"{fmt_dt(a['first'])} -> {fmt_dt(a['last'])}"},
                     "Read activity not tied to any suspect session/IP - most likely the "
                     "user's normal access. Review only if the volume is anomalous.",
                     entity=actor)

    def detect_aitm_chain(self):
        """AiTM relay signature, robust to UA/device spoofing: a proxy 'warm-up'
        failure (50132 token-refresh) and/or a 50199 CMSI interrupt from a network
        OUTSIDE the user footprint, immediately followed by a SUCCESS from that same
        network. Keys on the error-chain + network + timing, so it still fires even
        when the TA replays the victim's deviceId and spoofs the victim's user-agent
        during the relay (as happened in real AiTM kits)."""
        CHAIN_CODES = ("50132", "50199")
        for u in self.users.values():
            signins = sorted(u["signins"], key=lambda x: x["time"] or datetime.min.replace(tzinfo=timezone.utc))
            for s in signins:
                if s["success"] or str(s["error_code"]) not in CHAIN_CODES:
                    continue
                if self._is_user_network(u, s) or not s["net"]:
                    continue
                win = next((x for x in signins
                            if x["success"] and x["net"] == s["net"] and x["time"] and s["time"]
                            and 0 <= (x["time"] - s["time"]).total_seconds() <= 1800), None)
                if not win:
                    continue
                self._flag_ip(s["ip"], "AiTM relay (proxy warm-up then success)")
                for obs in (s, win):
                    if obs not in u["ta_observations"]:
                        u["ta_observations"].append(obs)
                u["compromised"] = True
                self.add("CRITICAL", "AiTM / Account Compromise",
                         f"AiTM relay chain (AADSTS{s['error_code']} then success) for {u['key']}",
                         {"user": u["key"], "network": s["net"], "ip": s["ip"],
                          "country": s["country"],
                          "warmup_code": s["error_code"],
                          "warmup_meaning": ERROR_CODES.get(str(s["error_code"]), ""),
                          "warmup_at": fmt_dt(s["time"]),
                          "success_at": fmt_dt(win["time"]),
                          "spoofed_ua": (win["user_agent"] or "")[:90],
                          "note": "deviceId/UA may be spoofed to match the victim; IP/network "
                                  "and the error-chain are the reliable distinguishers here"},
                         "AiTM proxy relay: a warm-up failure then an immediate success from "
                         "the same outside network. Robust to UA/device spoofing. Revoke the "
                         "session, reset credentials, and sweep activity on this network.",
                         entity=u["key"])
                break

    def detect_phishing(self):
        """Surface the phishing lure and any lure propagation. The lure itself is
        rarely labelled in logs, but the message(s) the victim read from their OWN
        device in the ~20 min BEFORE the AiTM relay is the strong candidate; and a
        forward/send during the incident window (especially under the suspect session)
        is likely the TA propagating the lure or exfiltrating via mail."""
        for u in self.users.values():
            if not u.get("compromised"):
                continue
            obs = u.get("ta_observations", [])
            chain_start = min((s["time"] for s in obs if s["time"]), default=None)
            chain_end = max((s["time"] for s in obs if s["time"]), default=None)

            # 1) candidate lure: victim mail read from a baseline network just before the relay
            if chain_start:
                w0 = chain_start - timedelta(minutes=20)
                lure = []
                for r in u["ual"]:
                    if not r["time"] or not (w0 <= r["time"] <= chain_start):
                        continue
                    if "mailitems" not in r["operation"].lower() and "messagebind" not in r["operation"].lower():
                        continue
                    if not self._is_user_network(u, r):
                        continue
                    for mi in r.get("mail_items", []):
                        if mi.get("message_id"):
                            lure.append({"message_id": mi["message_id"],
                                         "folder": mi.get("folder", ""),
                                         "accessed": fmt_dt(r["time"])})
                if lure:
                    self.add("MEDIUM", "Phishing (suspected lure)",
                             f"Mail read by {u['key']} from their own device just before the AiTM relay",
                             {"user": u["key"],
                              "window": f"{fmt_dt(w0)} -> {fmt_dt(chain_start)}",
                              "candidate_lure_items": lure[:15],
                              "note": "the message read immediately before the AiTM auth is a "
                                      "likely phishing lure; resolve subject/sender via eDiscovery "
                                      "on the InternetMessageId"},
                             "Pull these InternetMessageIds for analysis of the embedded link / "
                             "AiTM redirect, and sweep the lure subject from other mailboxes.",
                             entity=u["key"])

            # 2) lure propagation / mail exfil: forwards/sends in-window or under suspect session
            for r in u["ual"]:
                opl = (r["operation"] or "").lower()
                if opl not in ("send", "create", "forward", "reply", "replyall", "sendas", "sendonbehalf"):
                    continue
                subj = r.get("subject", "")
                in_window = (chain_start and chain_end and r["time"]
                             and chain_start - timedelta(minutes=20) <= r["time"] <= chain_end + timedelta(minutes=20))
                tied = (r["session_id"] and r["session_id"] in self.suspect_sessions) \
                    or (strip_port(r.get("ip")) in self.attacker_ips)
                if not (in_window or tied):
                    continue
                self.add("MEDIUM", "Phishing (possible propagation / mail exfil)",
                         f"Outbound mail '{(subj or r['operation'])[:60]}' by {u['key']}",
                         {"user": u["key"], "operation": r["operation"], "subject": subj or "(not in log)",
                          "time": fmt_dt(r["time"]), "ip": strip_port(r.get("ip")) or "(none in log)",
                          "session_id": r.get("session_id"),
                          "under_suspect_session": bool(tied),
                          "message_ids": [mi["message_id"] for mi in r.get("mail_items", []) if mi.get("message_id")][:5]},
                         "A forward/send during the incident window - possible lure propagation "
                         "or mail exfiltration. Recover the recipient via message headers "
                         "(Get-MessageTrace on the InternetMessageId) and check if sent under "
                         "the suspect session.",
                         entity=u["key"])

    def detect_containment_and_persistence(self):
        """Record the containment action (AADSTS50057 account-disable) and flag any
        sign-in attempt from OUTSIDE the user footprint AFTER it - a post-containment
        retry from attacker infra confirms the TA retained the stolen token."""
        for u in self.users.values():
            disabled = sorted([s for s in u["signins"]
                               if str(s["error_code"]) == "50057" and s["time"]],
                              key=lambda x: x["time"])
            if not disabled:
                continue
            t0 = disabled[0]["time"]
            self.add("INFO", "Containment",
                     f"Account disabled (AADSTS50057) for {u['key']} at {fmt_dt(t0)}",
                     {"user": u["key"], "disabled_at": fmt_dt(t0),
                      "total_50057_events": len(disabled),
                      "note": "first 50057 marks containment; later 50057s are blocked "
                              "attempts by the victim and/or the TA"},
                     "Confirms containment took effect. Use this timestamp to bound the "
                     "attacker dwell window and separate pre/post-containment activity.",
                     entity=u["key"])
            # persistence: post-containment attempts from outside the footprint
            seen = set()
            for s in sorted(u["signins"], key=lambda x: x["time"] or datetime.min.replace(tzinfo=timezone.utc)):
                if not s["time"] or s["time"] <= t0:
                    continue
                if self._is_user_network(u, s):
                    continue  # victim's own device locked out - not persistence
                if not s["net"] or s["net"] in seen:
                    continue
                seen.add(s["net"])
                self._flag_ip(s["ip"], "post-containment retry (token retained)")
                if s not in u["ta_observations"]:
                    u["ta_observations"].append(s)
                mins = (s["time"] - t0).total_seconds() / 60.0
                self.add("HIGH", "TA Persistence",
                         f"Post-containment retry from attacker network {s['net']} for {u['key']}",
                         {"user": u["key"], "ip": s["ip"], "network": s["net"], "asn": s["asn"],
                          "time": fmt_dt(s["time"]), "minutes_after_disable": round(mins, 1),
                          "error_code": s["error_code"], "app": s["app"],
                          "user_agent": (s["user_agent"] or "")[:80]},
                         "A sign-in attempt from attacker infrastructure AFTER the account was "
                         "disabled confirms the TA retained the stolen token and intended "
                         "further access. Keep the account disabled until all refresh tokens "
                         "are revoked and credentials reset.",
                         entity=u["key"])

    def run(self):
        self.build_users()
        self.detect_session_redundancy()
        self.detect_aitm_chain()      # robust AiTM detection (spoof-resistant), enriches TA profile
        self.detect_mfa_wall()        # blocked 50074 attempts enrich the TA profile
        self.detect_replay_and_aitm()
        self.detect_impossible_travel()
        self.detect_credential_attacks()
        self.detect_cmsi_interrupt()
        self.detect_post_compromise()
        self.detect_containment_and_persistence()
        self.detect_phishing()
        # ensure every compromised user has a legit-vs-TA profile for the report
        for u in self.users.values():
            if u.get("compromised") and not u.get("ta_profile"):
                legit, ta = self._actor_profiles(u)
                u["legit_profile"], u["ta_profile"] = legit, ta
        self.findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["category"]))
        return self.findings


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def build_summary(az):
    sev_counts = defaultdict(int)
    for f in az.findings:
        sev_counts[f["severity"]] += 1
    compromised = sorted(k for k, u in az.users.items() if u.get("compromised"))
    baseline_ips = set()
    for u in az.users.values():
        baseline_ips |= u["interactive_ips"]
    return {
        "users_analyzed": len(az.users),
        "signins_analyzed": len(az.signins),
        "audit_records": len(az.audits),
        "ual_records": len(az.ual),
        "findings_total": len(az.findings),
        "by_severity": dict(sev_counts),
        "compromised_accounts": compromised,
        "suspect_sessions": az.suspect_sessions,
        "baseline_ips": sorted(baseline_ips),
        "attacker_ips": {ip: sorted(r) for ip, r in az.attacker_ips.items()},
    }


def render_txt(az, summary, tz):
    L = []
    W = 78
    L.append("=" * W)
    L.append("MS_ANALYZER - ENTRA / PURVIEW LOGS-ONLY COMPROMISE REPORT")
    L.append("=" * W)
    L.append(f"Generated: {fmt_dt(datetime.now(timezone.utc), tz)}")
    L.append("")
    # 1. Executive summary
    L.append("-" * W)
    L.append("1. EXECUTIVE SUMMARY")
    L.append("-" * W)
    L.append(f"  Sign-ins analyzed : {summary['signins_analyzed']}")
    L.append(f"  Entra audit recs  : {summary['audit_records']}")
    L.append(f"  Purview/UAL recs  : {summary['ual_records']}")
    L.append(f"  Users analyzed    : {summary['users_analyzed']}")
    L.append(f"  Findings          : {summary['findings_total']}  " +
             ", ".join(f"{k}={v}" for k, v in sorted(summary['by_severity'].items(),
                                                      key=lambda x: SEV_ORDER.get(x[0], 9))))
    if summary["compromised_accounts"]:
        L.append(f"  COMPROMISED (AiTM/theft indicators): {', '.join(summary['compromised_accounts'])}")
    else:
        L.append("  No accounts met the AiTM/theft composite threshold.")
    L.append("")
    # 2. IOCs
    L.append("-" * W)
    L.append("2. SUSPECT IPs / SESSIONS (review & corroborate - not all are attacker-owned)")
    L.append("-" * W)
    baseline = set(summary.get("baseline_ips", []))
    if summary["attacker_ips"]:
        for ip, reasons in sorted(summary["attacker_ips"].items()):
            note = "  <- user baseline IP (likely victim side of a replayed session)" if ip in baseline else ""
            L.append(f"  {ip:<22} {', '.join(reasons)}{note}")
    else:
        L.append("  None flagged.")
    if summary["suspect_sessions"]:
        L.append("")
        L.append("  Suspect sessions (AADSessionId used from multiple IPs):")
        for sid, ips in summary["suspect_sessions"].items():
            L.append(f"    {sid}  <-  {', '.join(ips)}")
    L.append("")
    # 3. Findings
    L.append("-" * W)
    L.append("3. FINDINGS (highest severity first)")
    L.append("-" * W)
    if not az.findings:
        L.append("  No findings.")
    for f in az.findings:
        L.append(f"  [{f['severity']}] {f['title']}")
        L.append(f"          Category: {f['category']}")
        for k, v in f["evidence"].items():
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v[:8]) + (" ..." if len(v) > 8 else "")
            L.append(f"          {k}: {v}")
        L.append(f"          -> {f['recommendation']}")
        L.append("")
    # 4. Per-user access & O365 action summary
    L.append("-" * W)
    L.append("4. PER-USER ACCESS & O365 ACTION SUMMARY")
    L.append("-" * W)
    focus = [u for u in az.users.values() if u.get("compromised") or u.get("post_actions")]
    if not focus:
        focus = list(az.users.values())[:10]
    for u in sorted(focus, key=lambda x: (not x.get("compromised"), x["key"])):
        flag = "  *** COMPROMISED ***" if u.get("compromised") else ""
        L.append(f"  USER: {u['key']}{flag}")
        if u["display"]:
            L.append(f"    Display name : {u['display']}")
        L.append(f"    Sign-ins     : {len(u['signins'])}  "
                 f"(interactive IPs: {len(u['interactive_ips'])}, all IPs: {len(u['all_ips'])})")
        if u["interactive_ips"]:
            L.append(f"    Baseline IPs : {', '.join(sorted(u['interactive_ips'])[:6])}")
        anomalous = sorted(u["all_ips"] - u["interactive_ips"])
        if anomalous:
            L.append(f"    Other IPs    : {', '.join(anomalous[:6])}")
        if u["countries"]:
            L.append(f"    Countries    : {', '.join(sorted(c for c in u['countries'] if c))}")
        # apps / resources accessed
        apps = sorted({s["resource"] or s["app"] for s in u["signins"] if (s["resource"] or s["app"])})
        if apps:
            L.append(f"    Resources    : {', '.join(apps[:8])}")
        # LEGITIMATE vs THREAT ACTOR machine/network contrast
        if u.get("compromised") and u.get("ta_profile"):
            lp, tp = u.get("legit_profile", {}), u["ta_profile"]
            L.append("    .------------------- LEGITIMATE vs THREAT ACTOR -------------------.")
            L.append(f"      LEGIT  device fleet: {', '.join(lp.get('device_fleet', []))}")
            L.append(f"             user-agent  : {', '.join(lp.get('user_agents', []))[:66]}")
            L.append(f"             networks    : {', '.join(lp.get('networks', [])) or '?'}")
            L.append(f"             ASNs        : {', '.join(lp.get('asns', [])) or '?'}")
            L.append(f"             geo         : {', '.join(lp.get('countries', [])) or '?'}")
            L.append(f"             apps used   : {', '.join(lp.get('apps', [])) or '?'}")
            L.append(f"             last login  : {lp.get('last_interactive', '?')}")
            L.append(f"      T.A.   device(s)   : {', '.join(tp.get('device_ids', []))}  "
                     f"(trust: {', '.join(tp.get('device_trust', []))})")
            L.append(f"             user-agent  : {', '.join(tp.get('user_agents', []))[:66]}")
            L.append(f"             client app  : {', '.join(tp.get('client_apps', [])) or '?'}")
            L.append(f"             apps used   : {', '.join(tp.get('apps', [])) or '?'}")
            L.append(f"             app IDs      : {', '.join(tp.get('app_ids', [])) or '?'}")
            L.append(f"             resources   : {', '.join(tp.get('resources', [])) or '?'}")
            L.append(f"             networks    : {', '.join(tp.get('networks', [])) or '?'}")
            L.append(f"             IP(s)       : {', '.join(tp.get('ips', [])) or '?'}")
            L.append(f"             ASNs        : {', '.join(tp.get('asns', [])) or '?'}")
            L.append(f"             geo         : {', '.join(tp.get('countries', [])) or '?'}")
            L.append(f"             sessions    : {', '.join(tp.get('sessions', [])) or '?'}")
            if tp.get('utis'):
                L.append(f"             utis        : {', '.join(tp.get('utis', []))}")
            tline = f"             timeframe   : {tp.get('first_seen','?')} -> {tp.get('last_seen','?')}"
            if "minutes_after_legit_login" in tp:
                tline += f"  (+{tp['minutes_after_legit_login']}m after legit login"
                tline += ", CONCURRENT" if tp.get("concurrent_with_legit_session") else ""
                tline += ")"
            L.append(tline)
            L.append("    '------------------------------------------------------------------'")
        # O365 actions
        pa = u.get("post_actions", [])
        if pa:
            cats = defaultdict(int)
            for c, *_ in pa:
                cats[c] += 1
            L.append(f"    O365 ACTIONS : {len(pa)}  ({', '.join(f'{k}={v}' for k, v in sorted(cats.items()))})")
            for cat, op, t, ip, sid, tied in sorted(pa, key=lambda x: x[2] or datetime.min.replace(tzinfo=timezone.utc))[:12]:
                mark = "  [under suspect session/IP]" if tied else ""
                L.append(f"      - {fmt_dt(t, tz)}  {op}  ({cat}) from {ip or '?'}{mark}")
        L.append("")
    # 5. Validation
    L.append("-" * W)
    L.append("5. ANALYST VALIDATION CHECKLIST")
    L.append("-" * W)
    for line in [
        "Linkable identifiers (AADSessionId/UniqueTokenId) are an Entra preview-era",
        ">feature; confirm they are populated for your incident window before relying",
        ">on session/token redundancy findings.",
        "Replay baseline = IPs the user signed in from INTERACTIVELY. Confirm those",
        ">interactive sign-ins are genuinely the user (not attacker-interactive).",
        "Impossible travel uses geo-coordinates when present, else a country-change",
        ">time proxy. Clear every hit against corporate VPN / egress / known travel.",
        "Risk fields (riskState / riskLevelDuringSignIn) require Entra ID P2; absence",
        ">is not evidence of safety.",
        "All correlation is timestamp-based - confirm every log source is in UTC.",
        "Attribute O365 actions by actor AND by AADSessionId; an action under a flagged",
        ">session/IP is attacker activity until proven otherwise.",
    ]:
        if line.startswith(">"):
            L.append(f"      {line[1:]}")
        else:
            L.append(f"  - {line}")
    L.append("")
    # 6. Indicators of Compromise (handoff)
    L.append("-" * W)
    L.append("6. INDICATORS OF COMPROMISE  (handoff: block / hunt / eDiscovery)")
    L.append("-" * W)
    # ip -> asn map for annotation
    ip_asn = {}
    for s in az.signins:
        if s.get("ip") and s.get("asn") and s["ip"] not in ip_asn:
            ip_asn[s["ip"]] = s["asn"]
    if az.attacker_ips:
        L.append("  TA INFRASTRUCTURE (block at perimeter / submit to threat intel)")
        for ip, reasons in sorted(az.attacker_ips.items()):
            asn = ip_asn.get(ip)
            asn_s = f"  ASN {asn}" + (f" ({az.hosting_asns[asn]})" if asn in az.hosting_asns else "") if asn else ""
            L.append(f"    IP   {ip:<24}{asn_s}")
            L.append(f"         reasons: {', '.join(sorted(reasons))}")
    if az.suspect_sessions:
        L.append("  STOLEN / REPLAYED SESSIONS (revoke + sweep by AADSessionId/UniqueTokenId)")
        for sid, ips in az.suspect_sessions.items():
            L.append(f"    {sid}")
            if ips:
                L.append(f"         seen from: {', '.join(ips)}")
    # per-compromised-user TA fingerprint
    for u in az.users.values():
        tp = u.get("ta_profile")
        if not (u.get("compromised") and tp):
            continue
        L.append(f"  TA FINGERPRINT  [{u['key']}]")
        def _emit(label, vals):
            vals = [v for v in (vals or []) if v]
            if vals:
                L.append(f"    {label:<13}{', '.join(str(v) for v in vals)}")
        _emit("networks", tp.get("networks"))
        _emit("ASNs", tp.get("asns"))
        _emit("device(s)", tp.get("device_ids"))
        _emit("user-agents", tp.get("user_agents"))
        _emit("client app", tp.get("client_apps"))
        _emit("apps", tp.get("apps"))
        _emit("app IDs", tp.get("app_ids"))
        _emit("resources", tp.get("resources"))
        _emit("sessions", tp.get("sessions"))
        _emit("UTIs", tp.get("utis"))
    # phishing lure, exfil manifest, BEC artefacts pulled from findings
    lure, exfil, total_items, total_bytes, forwards, rules = [], [], 0, 0, [], []
    bec_addrs, containment, persistence = set(), [], []
    for f in az.findings:
        e = f.get("evidence", {})
        if "candidate_lure_items" in e:
            lure.extend(e["candidate_lure_items"])
        if "sample_items" in e and "OUTSIDE network" in f["title"]:
            exfil.extend(e["sample_items"])
            total_items += e.get("accessed_items_total", 0)
            total_bytes += e.get("accessed_bytes", 0)
        if f["category"].startswith("Phishing (possible propagation"):
            forwards.append((e.get("subject", ""), e.get("message_ids", [])))
        if "inbox rule" in f["title"].lower() or "New-InboxRule" in str(e.get("operation", "")):
            rules.append((e.get("target") or e.get("operation", ""), e.get("rule_summary", "")))
            r = e.get("rule", {})
            for v in (r.get("from_contains"), r.get("forward_to"), r.get("smtp_forward")):
                if v:
                    bec_addrs.add(str(v))
        if f["category"] == "Containment":
            containment.append(e.get("disabled_at", ""))
        if f["category"] == "TA Persistence":
            persistence.append((e.get("ip", ""), e.get("network", ""), e.get("time", ""),
                                e.get("minutes_after_disable", "")))
    if lure:
        L.append("  SUSPECTED PHISHING LURE (pull for analysis; sweep other mailboxes)")
        for mi in lure[:5]:
            L.append(f"    {mi.get('message_id','')}  {mi.get('folder','')}  read {mi.get('accessed','')}")
    if forwards:
        L.append("  OUTBOUND / LURE PROPAGATION (recover recipients via Get-MessageTrace)")
        for subj, mids in forwards[:8]:
            L.append(f"    subject: {subj}")
            for m in (mids or [])[:3]:
                L.append(f"      {m}")
    if rules or bec_addrs:
        L.append("  PERSISTENCE / BEC")
        for tgt, summary in rules[:8]:
            L.append(f"    inbox rule -> {tgt}")
            if summary:
                L.append(f"      {summary}")
        for a in sorted(bec_addrs):
            L.append(f"    BEC address/domain: {a}")
    if containment:
        L.append("  CONTAINMENT")
        for ts in containment[:4]:
            L.append(f"    account disabled (50057) at {ts}")
    if persistence:
        L.append("  TA PERSISTENCE (post-containment retries - token retained)")
        for ip, net, ts, mins in persistence[:8]:
            L.append(f"    {ip}  ({net})  at {ts}  (+{mins}m after disable)")
    if exfil:
        L.append(f"  MAILBOX ITEMS ACCESSED BY TA  (treat as exfiltrated; resolve subjects via eDiscovery)")
        L.append(f"    total: {total_items} items / {total_bytes/1e6:.1f} MB  "
                 f"(InternetMessageIds below, first {min(50, len(exfil))})")
        for mi in exfil[:50]:
            L.append(f"      {mi.get('message_id','')}  {mi.get('folder','')}")
        if len(exfil) > 50:
            L.append(f"      ... and {len(exfil) - 50} more (see ms_findings.json)")
    if not (az.attacker_ips or az.suspect_sessions):
        L.append("  No indicators of compromise identified.")
    L.append("")
    L.append("=" * W)
    L.append("END OF REPORT")
    L.append("=" * W)
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


# =========================================================================== #
# UNIFIED DRIVER - mode dispatch, host<->logs correlation bridge, one report
# =========================================================================== #

def _detect_kind(path):
    """Classify an evidence path as 'host' or 'logs' (or None if unknown)."""
    if not path:
        return None
    low = path.lower()
    if low.endswith(".zip"):
        return "host"
    if os.path.isdir(path):
        try:
            names = [n.lower() for n in os.listdir(path)]
        except OSError:
            return None
        if any(n in ("cookies.json", "history.json") for n in names) or \
           any(("webstorage" in n or "indexeddb" in n or "extensions" in n) for n in names):
            return "host"
        logkw = ("signin", "sign-in", "interactive", "noninteractive", "unifiedaudit",
                 "unified", "auditlog", "audit", "serviceprincipal", "managedidentity",
                 "purview", "ual", "logon")
        if any(any(k in n for k in logkw) for n in names):
            return "logs"
        if any(n.endswith((".json", ".csv", ".jsonl")) for n in names):
            return "logs"  # a dir of json/csv with no host markers -> treat as logs
    return None


def _run_host(args, tz_host, since_host, until_host, quiet):
    """Replicate the BAI host pipeline. Returns a result dict (or raises SystemExit)."""
    pkg = load_package(args.host)
    if "cookies.json" not in pkg and "history.json" not in pkg:
        raise SystemExit("[fatal] --host package has no cookies.json or history.json")
    if args.online and not quiet:
        print("[*] Online mode enabled - WHOIS/RDAP lookups for domain analysis")
    sessions, idp_cookies = analyze_cookies(pkg.get("cookies.json"),
                                            include_values=args.include_token_values)
    findings, supplementary = aggregate_findings(pkg, include_values=args.include_token_values,
                                                 online=args.online)
    aitm_view = build_aitm_view(pkg, findings)
    events = build_timeline(pkg, since=since_host, until=until_host)
    storage_tokens = supplementary["storage_tokens"] + supplementary["indexeddb_tokens"]
    theft_timeline = build_session_theft_timeline(pkg, sessions + storage_tokens)
    upn_accounts = discover_upn_accounts(pkg)
    tenant_upn_map = discover_tenant_upn_mapping(pkg)
    entra_sessions = discover_entra_sessions(pkg, tenant_upn_map)
    return {
        "pkg": pkg, "sessions": sessions, "idp_cookies": idp_cookies,
        "findings": findings, "aitm_view": aitm_view, "events": events,
        "storage_tokens": storage_tokens, "theft_timeline": theft_timeline,
        "upn_accounts": upn_accounts, "entra_sessions": entra_sessions,
    }


def _run_logs(args, since_logs, until_logs, quiet):
    """Replicate the ms_analyzer logs pipeline. Returns a result dict or None."""
    try:
        hosting_asns = load_hosting_asns(args.asn_intel)
    except Exception as e:
        print(f"[!] Could not read --asn-intel file ({e}); using built-in ASN list.")
        hosting_asns = dict(DEFAULT_HOSTING_ASNS)
    if not quiet and args.asn_intel:
        print(f"[*] Hosting-ASN list: {len(hosting_asns)} entries "
              f"({len(hosting_asns) - len(DEFAULT_HOSTING_ASNS)} custom)")
    logs = discover_logs(args.logs)
    total = sum(len(v) for v in logs.values())
    if total == 0:
        print("[!] No recognizable log records in --logs folder.")
        return None
    if not quiet:
        print(f"[*] Analyzing {total} log records...")
    az = Analyzer(logs, since=since_logs, until=until_logs,
                  spray_min_users=args.spray_min_users, travel_kmh=args.travel_kmh,
                  hosting_asns=hosting_asns)
    az.run()
    summary = build_summary(az)
    return {"az": az, "summary": summary, "logs_total": total}


def _correlate_host_logs(theft_timeline, az):
    """Pivot host-extracted linkable identifiers (uti/sid) into the log engine's
    sign-ins and UAL events for TOKEN-GRADE replay confirmation, and unify identity.

    This is what the 'both' mode buys over running the two engines separately: the
    host gives the actual stolen token's uti/sid and a precise auth_time birth; the
    logs show where that exact token/session was exercised."""
    host_utis, host_sids, host_ids = {}, {}, {}
    for s in theft_timeline.get("stealable_sessions", []):
        if s.get("uti"):
            host_utis[s["uti"]] = s
        if s.get("sid"):
            host_sids[s["sid"]] = s
        for k in (s.get("object_id"), s.get("upn")):
            if k:
                host_ids[k.lower()] = s
    births = {}
    for a in theft_timeline.get("session_birth_anchors", []):
        oid = (a.get("object_id") or "").lower()
        if oid and a.get("auth_time"):
            births.setdefault(oid, a["auth_time"])

    confirmations = []

    def _scan(events, kind):
        for e in events:
            uti = e.get("uti")
            sid = e.get("session_id")
            t = e.get("time")
            base = {"kind": kind, "ip": e.get("ip"), "network": e.get("net"),
                    "asn": e.get("asn"), "time": fmt_dt(t) if t else None}
            if uti and uti in host_utis:
                h = host_utis[uti]
                confirmations.append({**base, "match": "uti (UniqueTokenId)", "value": uti,
                                      "host_upn": h.get("upn"), "host_oid": h.get("object_id")})
            if sid and sid in host_sids:
                h = host_sids[sid]
                confirmations.append({**base, "match": "sid (AADSessionId)", "value": sid,
                                      "host_upn": h.get("upn"), "host_oid": h.get("object_id")})

    _scan(getattr(az, "signins", []), "sign-in")
    _scan(getattr(az, "ual", []), "UAL")

    matched_users = []
    for u in getattr(az, "users", {}).values():
        upn = (u.get("upn") or "").lower()
        oid = (u.get("user_id") or "").lower()
        if (upn and upn in host_ids) or (oid and oid in host_ids):
            matched_users.append(u.get("upn") or u.get("user_id"))

    return {"confirmations": confirmations, "matched_users": sorted(set(matched_users)),
            "births": births, "host_uti_count": len(host_utis), "host_sid_count": len(host_sids)}


def _verdict(host_res, logs_res, corr):
    if corr and corr.get("confirmations"):
        return "CONFIRMED token replay (host token seen in logs - token-grade attribution)"
    host_ch = host_res and any(f["severity"] in (Severity.CRITICAL.value, Severity.HIGH.value)
                               for f in host_res["findings"])
    logs_ch = logs_res and any(f["severity"] in ("CRITICAL", "HIGH") for f in logs_res["az"].findings)
    if host_ch or logs_ch:
        return "HIGH/CRITICAL indicators present - probable compromise; corroborate"
    return "No HIGH/CRITICAL indicators in the supplied evidence"


def _build_combined_report(mode, host_res, logs_res, corr, tz_host, tz_logs, args):
    bar = "=" * 78
    L = [bar,
         "  AiTM_analyzer - unified host + logs adversary-in-the-middle analysis",
         "  (c) 2026 Shane D. Shook. All rights reserved.",
         bar,
         f"  Evidence mode : {mode}",
         f"  Host evidence : {args.host or '(none)'}",
         f"  Log evidence  : {args.logs or '(none)'}",
         f"  Generated     : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}",
         f"  Verdict       : {_verdict(host_res, logs_res, corr)}",
         bar, ""]

    # Correlation FIRST - it is the highest-value output when both are present.
    if corr is not None:
        L.append("#" * 78)
        L.append("# HOST <-> LOG CORRELATION  (token-grade)")
        L.append("#" * 78)
        L.append(f"  Host linkable identifiers recovered: {corr['host_uti_count']} uti, "
                 f"{corr['host_sid_count']} sid")
        if corr["matched_users"]:
            L.append("  Identities matched host<->logs: " + ", ".join(corr["matched_users"]))
        if corr["confirmations"]:
            L.append("")
            L.append("  *** TOKEN-GRADE REPLAY CONFIRMATIONS ***")
            L.append("  A host-extracted token id was exercised in the logs. This is the stolen")
            L.append("  session by definition - not a heuristic IP/baseline inference.")
            for c in corr["confirmations"][:50]:
                where = f"{c.get('ip') or c.get('network') or '?'}"
                asn = f" ASN {c['asn']}" if c.get("asn") else ""
                L.append(f"    [{c['kind']}] {c['match']} = {c['value']}")
                L.append(f"        seen from {where}{asn} at {c.get('time')}  "
                         f"(host identity {c.get('host_upn') or c.get('host_oid')})")
            if corr["births"]:
                L.append("")
                L.append("  Precise session-birth anchors (auth_time) for theft-window bracketing:")
                for oid, t in list(corr["births"].items())[:10]:
                    L.append(f"    oid {oid}: birth {t}")
        else:
            L.append("")
            L.append("  No host uti/sid matched a log record. Possible reasons: linkable")
            L.append("  identifiers (UniqueTokenId/AADSessionId) not populated in the export, the")
            L.append("  ESTS cookie was opaque (no recoverable uti/sid), or the log window does")
            L.append("  not cover the replay. The independent host and log findings below still apply.")
        L.append("")

    if host_res is not None:
        L.append("#" * 78)
        L.append("# HOST EVIDENCE  (BAI browser artifacts)")
        L.append("#" * 78)
        rg = ReportGenerator(
            pkg=host_res["pkg"], findings=host_res["findings"], aitm_view=host_res["aitm_view"],
            sessions=host_res["sessions"], storage_tokens=host_res["storage_tokens"],
            events=host_res["events"], theft_timeline=host_res["theft_timeline"],
            entra_correlation=None, upn_accounts=host_res["upn_accounts"],
            entra_sessions=host_res["entra_sessions"], tz=tz_host)
        L.append(rg.generate_txt())
        L.append("")

    if logs_res is not None:
        L.append("#" * 78)
        L.append("# LOG EVIDENCE  (Entra sign-ins + Purview UAL)")
        L.append("#" * 78)
        L.append(render_txt(logs_res["az"], logs_res["summary"], tz_logs))
        L.append("")

    L.append(bar)
    L.append("  (c) 2026 Shane D. Shook. All rights reserved.")
    L.append(bar)
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(
        prog="AiTM_analyzer.py",
        description="Unified AiTM / token-theft analyzer - host, logs, or both.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              python3 AiTM_analyzer.py --host pkg.zip
              python3 AiTM_analyzer.py --logs ./logs --asn-intel hosting.json
              python3 AiTM_analyzer.py --host pkg.zip --logs ./logs --out ./case
              python3 AiTM_analyzer.py ./evidence_path            # auto-classified

            The --logs folder auto-detects (by filename): Interactive / NonInteractive /
            ServicePrincipal / ManagedIdentity sign-ins, AuditLogs, and UnifiedAuditLog
            (Purview). The --host path is a BAI package folder or .zip.
        """))
    ap.add_argument("evidence", nargs="?", default=None,
                    help="optional single evidence path; auto-classified as host or logs")
    ap.add_argument("--host", default=None, metavar="PATH",
                    help="BAI package folder or .zip (host evidence)")
    ap.add_argument("--logs", default=None, metavar="FOLDER",
                    help="folder of Entra/Purview logs (log evidence)")
    ap.add_argument("--out", default="./aitm_analysis", help="output directory")
    ap.add_argument("--format", choices=["txt", "html"], default="txt",
                    help="also emit the rich host HTML report when 'html' (default: txt)")
    ap.add_argument("--tz", default=None, help="display timezone, e.g. America/Los_Angeles")
    ap.add_argument("--since", default=None, help="only events on/after YYYY-MM-DD")
    ap.add_argument("--until", default=None, help="only events on/before YYYY-MM-DD")
    # logs passthrough
    ap.add_argument("--asn-intel", default=None, metavar="FILE",
                    help="JSON hosting/VPS ASN file merged with the built-in list (logs mode)")
    ap.add_argument("--spray-min-users", type=int, default=5,
                    help="distinct users failing from one IP to call it a spray (default 5)")
    ap.add_argument("--travel-kmh", type=float, default=900.0,
                    help="implied speed over which travel is 'impossible' (default 900)")
    # host passthrough
    ap.add_argument("--include-token-values", action="store_true",
                    help="DANGEROUS: write raw token values into host output JSON")
    ap.add_argument("--online", action="store_true",
                    help="enable WHOIS/RDAP lookups for domain age analysis (host mode)")
    ap.add_argument("--quiet", "-q", action="store_true", help="minimal console output")
    args = ap.parse_args()

    # resolve a single positional evidence path
    if args.evidence and not args.host and not args.logs:
        k = _detect_kind(args.evidence)
        if k == "host":
            args.host = args.evidence
        elif k == "logs":
            args.logs = args.evidence
        else:
            raise SystemExit("[fatal] could not classify evidence path; use --host or --logs")

    # the evidence you supply IS the mode: --host only = host, --logs only = logs,
    # both = both (correlated). No separate mode switch.
    if args.host and args.logs:
        mode = "both"
    elif args.host:
        mode = "host"
    elif args.logs:
        mode = "logs"
    else:
        raise SystemExit("[fatal] provide --host and/or --logs (or a positional evidence path)")

    quiet = args.quiet
    tz_host = _try_zoneinfo(args.tz)
    tz_logs = _load_tz(args.tz)
    since_host = parse_iso(args.since + "T00:00:00+00:00") if args.since else None
    until_host = parse_iso(args.until + "T23:59:59+00:00") if args.until else None
    since_logs = parse_time(args.since + "T00:00:00") if args.since else None
    until_logs = parse_time(args.until + "T23:59:59") if args.until else None

    os.makedirs(args.out, exist_ok=True)
    host_res = logs_res = corr = None

    if mode in ("host", "both"):
        if not quiet:
            print(f"[*] HOST analysis: {args.host}")
        host_res = _run_host(args, tz_host, since_host, until_host, quiet)
        write_timeline_csv(host_res["events"], tz_host, os.path.join(args.out, "timeline.csv"))
        write_findings_json(host_res["findings"], host_res["aitm_view"], host_res["theft_timeline"],
                            os.path.join(args.out, "findings.json"), None)
        write_auth_json(host_res["sessions"], host_res["idp_cookies"], host_res["storage_tokens"],
                        os.path.join(args.out, "auth_sessions.json"))

    if mode in ("logs", "both"):
        if not quiet:
            print(f"[*] LOG analysis: {args.logs}")
        logs_res = _run_logs(args, since_logs, until_logs, quiet)
        if logs_res:
            out = {"summary": logs_res["summary"], "findings": list(logs_res["az"].findings)}
            with open(os.path.join(args.out, "ms_findings.json"), "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2, default=str)

    if mode == "both" and host_res and logs_res:
        corr = _correlate_host_logs(host_res["theft_timeline"], logs_res["az"])
        with open(os.path.join(args.out, "correlation.json"), "w", encoding="utf-8") as f:
            json.dump(corr, f, indent=2, default=str)

    report = _build_combined_report(mode, host_res, logs_res, corr, tz_host, tz_logs, args)
    rpath = os.path.join(args.out, "AiTM_report.txt")
    with open(rpath, "w", encoding="utf-8") as f:
        f.write(report)

    if args.format == "html" and host_res:
        rg = ReportGenerator(
            pkg=host_res["pkg"], findings=host_res["findings"], aitm_view=host_res["aitm_view"],
            sessions=host_res["sessions"], storage_tokens=host_res["storage_tokens"],
            events=host_res["events"], theft_timeline=host_res["theft_timeline"],
            entra_correlation=None, upn_accounts=host_res["upn_accounts"],
            entra_sessions=host_res["entra_sessions"], tz=tz_host)
        with open(os.path.join(args.out, "report.html"), "w", encoding="utf-8") as f:
            f.write(rg.generate_html())

    if not quiet:
        print("\n" + report)
    print(f"\n[+] Combined report : {rpath}")
    if host_res:
        print(f"[+] Host artifacts  : findings.json, timeline.csv, auth_sessions.json")
    if logs_res:
        print(f"[+] Log findings    : ms_findings.json")
    if corr is not None:
        print(f"[+] Correlation     : correlation.json "
              f"({len(corr['confirmations'])} token-grade confirmation(s))")
    if args.include_token_values:
        print("[!] WARNING: raw token values were written - treat output as live credentials.")

    # exit codes: 2 = token-grade confirmed replay, 1 = HIGH/CRITICAL, 0 = clean
    if corr and corr.get("confirmations"):
        return 2
    host_ch = host_res and any(f["severity"] in (Severity.CRITICAL.value, Severity.HIGH.value)
                               for f in host_res["findings"])
    logs_ch = logs_res and any(f["severity"] in ("CRITICAL", "HIGH") for f in logs_res["az"].findings)
    return 1 if (host_ch or logs_ch) else 0


if __name__ == "__main__":
    sys.exit(main())
