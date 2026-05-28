#!/usr/bin/env python3
"""
(c) 2026, Shane D. Shook, PhD
╔══════════════════════════════════════════════════════════════════════════════╗
║         Entra ID Security Posture Assessment Tool  v2.0                      ║
║         16-module read-only assessment via Microsoft Graph API               ║
║         Authentication: Device Code Flow (no secrets required)               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Modules                                                                     ║
║  1  Tenant & Organization        8  Risky Users + Risk Detections            ║
║  2  Privileged Role Assignments  9  MFA Registration & Auth Methods          ║
║  3  User Hygiene                10  App Role Analysis & Audit History        ║
║  4  Conditional Access          11  Microsoft Defender Alerts                ║
║  5  Apps, AI Agents & Secrets   12  O365 / Exchange / BEC                    ║
║  6  Device Compliance           13  PIM Policy & Eligible Assignments        ║
║  7  Sign-in Logs, Spray,        14  Mailbox Forwarding & Inbox Rules         ║
║     Replay & Travel Detection                                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Usage                                                                       ║
║    python entra_assessment.py                  # 30-day window               ║
║    python entra_assessment.py --days 90        # 90-day window               ║
║    python entra_assessment.py --days 60 --json # + save JSON report          ║
║    python entra_assessment.py --skip-defender  # skip if no Defender license ║
║    python entra_assessment.py --skip-signin    # faster, less visibility     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Minimum account requirements                                                ║
║    • Security Reader + Reports Reader  — core modules                        ║
║    • Global Administrator              — CA policies, Security Defaults, PIM ║
║    • Entra ID P1 license               — sign-in logs, CA policies           ║
║    • Entra ID P2 license               — Identity Protection (module 8)      ║
║    • Microsoft Defender licensing      — Defender alerts (module 11)         ║
║                                                                              ║
║  This tool is READ-ONLY. No changes are made to your tenant.                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 0 — DEPENDENCY BOOTSTRAP
# Checks for required packages and offers to install them before doing anything
# ─────────────────────────────────────────────────────────────────────────────

import sys
import subprocess

REQUIRED_PACKAGES = {
    "azure.identity": "azure-identity>=1.15.0",
    "requests":       "requests>=2.31.0",
    "yaml":           "pyyaml>=6.0",
}

def check_and_install_dependencies():
    missing = []
    for module, pip_spec in REQUIRED_PACKAGES.items():
        try:
            # Handle dotted module names (e.g. azure.identity)
            top = module.split(".")[0]
            __import__(top)
            if "." in module:
                __import__(module)
        except ImportError:
            missing.append((module, pip_spec))

    if not missing:
        return  # All good

    print("\n  ┌─ Missing Dependencies ─────────────────────────────────────┐")
    for module, spec in missing:
        print(f"  │  • {spec}")
    print("  └────────────────────────────────────────────────────────────┘")
    print()

    answer = input("  Install missing packages now? [Y/n]: ").strip().lower()
    if answer in ("", "y", "yes"):
        for module, spec in missing:
            print(f"  Installing {spec}...")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", spec, "--quiet"],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                # Try with --break-system-packages for newer Linux distros
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", spec,
                     "--break-system-packages", "--quiet"],
                    capture_output=True, text=True
                )
            if result.returncode == 0:
                print(f"  ✓ {module} installed")
            else:
                print(f"  ✗ Failed to install {module}. Please run:")
                print(f"      pip install {spec}")
                sys.exit(1)
        print()
        # Re-check
        for module, _ in missing:
            try:
                __import__(module)
            except ImportError:
                print(f"  ✗ {module} still not importable after install. "
                      "Try restarting Python or installing manually.")
                sys.exit(1)
    else:
        print(f"\n  Please install manually:  pip install {' '.join(s for _,s in missing)}\n")
        sys.exit(0)

check_and_install_dependencies()

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — STANDARD IMPORTS (after dependency check)
# ─────────────────────────────────────────────────────────────────────────────

import json
import argparse
import time
from pathlib import Path
import requests
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# Microsoft Graph Command Line Tools — same client ID used by Connect-MgGraph.
# Supports device code flow without a custom app registration.
# For full assessment coverage (CA policies, PIM, Security Defaults),
# authenticate with a Global Administrator account.
CLIENT_ID      = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
DEFAULT_TENANT = "organizations"  # work/school accounts

# Request all pre-consented permissions via .default.
# Actual access depends on the authenticated account's roles.
GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"

# ─────────────────────────────────────────────────────────────────────────────
# ISO 3166-1 alpha-2 → full country name
# Used to expand the two-letter countryOrRegion codes returned by the Graph API
# location object into unambiguous human-readable strings for findings and the
# geographic authentication map. "CA" would otherwise be read as California;
# "GE" as Georgia; etc.  Unknown codes fall back to the raw code unchanged.
# ─────────────────────────────────────────────────────────────────────────────
_ISO3166: dict[str, str] = {
    "AF": "Afghanistan",       "AX": "Åland Islands",       "AL": "Albania",
    "DZ": "Algeria",           "AS": "American Samoa",       "AD": "Andorra",
    "AO": "Angola",            "AI": "Anguilla",             "AQ": "Antarctica",
    "AG": "Antigua and Barbuda","AR": "Argentina",           "AM": "Armenia",
    "AW": "Aruba",             "AU": "Australia",            "AT": "Austria",
    "AZ": "Azerbaijan",        "BS": "Bahamas",              "BH": "Bahrain",
    "BD": "Bangladesh",        "BB": "Barbados",             "BY": "Belarus",
    "BE": "Belgium",           "BZ": "Belize",               "BJ": "Benin",
    "BM": "Bermuda",           "BT": "Bhutan",               "BO": "Bolivia",
    "BQ": "Bonaire",           "BA": "Bosnia and Herzegovina","BW": "Botswana",
    "BV": "Bouvet Island",     "BR": "Brazil",               "IO": "British Indian Ocean Territory",
    "BN": "Brunei",            "BG": "Bulgaria",             "BF": "Burkina Faso",
    "BI": "Burundi",           "CV": "Cabo Verde",           "KH": "Cambodia",
    "CM": "Cameroon",          "CA": "Canada",               "KY": "Cayman Islands",
    "CF": "Central African Republic","TD": "Chad",           "CL": "Chile",
    "CN": "China",             "CX": "Christmas Island",     "CC": "Cocos Islands",
    "CO": "Colombia",          "KM": "Comoros",              "CD": "Congo (DRC)",
    "CG": "Congo",             "CK": "Cook Islands",         "CR": "Costa Rica",
    "CI": "Côte d'Ivoire",     "HR": "Croatia",              "CU": "Cuba",
    "CW": "Curaçao",           "CY": "Cyprus",               "CZ": "Czech Republic",
    "DK": "Denmark",           "DJ": "Djibouti",             "DM": "Dominica",
    "DO": "Dominican Republic","EC": "Ecuador",              "EG": "Egypt",
    "SV": "El Salvador",       "GQ": "Equatorial Guinea",    "ER": "Eritrea",
    "EE": "Estonia",           "SZ": "Eswatini",             "ET": "Ethiopia",
    "FK": "Falkland Islands",  "FO": "Faroe Islands",        "FJ": "Fiji",
    "FI": "Finland",           "FR": "France",               "GF": "French Guiana",
    "PF": "French Polynesia",  "TF": "French Southern Territories",
    "GA": "Gabon",             "GM": "Gambia",               "GE": "Georgia",
    "DE": "Germany",           "GH": "Ghana",                "GI": "Gibraltar",
    "GR": "Greece",            "GL": "Greenland",            "GD": "Grenada",
    "GP": "Guadeloupe",        "GU": "Guam",                 "GT": "Guatemala",
    "GG": "Guernsey",          "GN": "Guinea",               "GW": "Guinea-Bissau",
    "GY": "Guyana",            "HT": "Haiti",                "HM": "Heard Island",
    "VA": "Holy See",          "HN": "Honduras",             "HK": "Hong Kong",
    "HU": "Hungary",           "IS": "Iceland",              "IN": "India",
    "ID": "Indonesia",         "IR": "Iran",                 "IQ": "Iraq",
    "IE": "Ireland",           "IM": "Isle of Man",          "IL": "Israel",
    "IT": "Italy",             "JM": "Jamaica",              "JP": "Japan",
    "JE": "Jersey",            "JO": "Jordan",               "KZ": "Kazakhstan",
    "KE": "Kenya",             "KI": "Kiribati",             "KP": "North Korea",
    "KR": "South Korea",       "KW": "Kuwait",               "KG": "Kyrgyzstan",
    "LA": "Laos",              "LV": "Latvia",               "LB": "Lebanon",
    "LS": "Lesotho",           "LR": "Liberia",              "LY": "Libya",
    "LI": "Liechtenstein",     "LT": "Lithuania",            "LU": "Luxembourg",
    "MO": "Macao",             "MG": "Madagascar",           "MW": "Malawi",
    "MY": "Malaysia",          "MV": "Maldives",             "ML": "Mali",
    "MT": "Malta",             "MH": "Marshall Islands",     "MQ": "Martinique",
    "MR": "Mauritania",        "MU": "Mauritius",            "YT": "Mayotte",
    "MX": "Mexico",            "FM": "Micronesia",           "MD": "Moldova",
    "MC": "Monaco",            "MN": "Mongolia",             "ME": "Montenegro",
    "MS": "Montserrat",        "MA": "Morocco",              "MZ": "Mozambique",
    "MM": "Myanmar",           "NA": "Namibia",              "NR": "Nauru",
    "NP": "Nepal",             "NL": "Netherlands",          "NC": "New Caledonia",
    "NZ": "New Zealand",       "NI": "Nicaragua",            "NE": "Niger",
    "NG": "Nigeria",           "NU": "Niue",                 "NF": "Norfolk Island",
    "MK": "North Macedonia",   "MP": "Northern Mariana Islands",
    "NO": "Norway",            "OM": "Oman",                 "PK": "Pakistan",
    "PW": "Palau",             "PS": "Palestine",            "PA": "Panama",
    "PG": "Papua New Guinea",  "PY": "Paraguay",             "PE": "Peru",
    "PH": "Philippines",       "PN": "Pitcairn",             "PL": "Poland",
    "PT": "Portugal",          "PR": "Puerto Rico",          "QA": "Qatar",
    "RE": "Réunion",           "RO": "Romania",              "RU": "Russia",
    "RW": "Rwanda",            "BL": "Saint Barthélemy",     "SH": "Saint Helena",
    "KN": "Saint Kitts and Nevis","LC": "Saint Lucia",       "MF": "Saint Martin",
    "PM": "Saint Pierre and Miquelon","VC": "Saint Vincent and the Grenadines",
    "WS": "Samoa",             "SM": "San Marino",           "ST": "Sao Tome and Principe",
    "SA": "Saudi Arabia",      "SN": "Senegal",              "RS": "Serbia",
    "SC": "Seychelles",        "SL": "Sierra Leone",         "SG": "Singapore",
    "SX": "Sint Maarten",      "SK": "Slovakia",             "SI": "Slovenia",
    "SB": "Solomon Islands",   "SO": "Somalia",              "ZA": "South Africa",
    "GS": "South Georgia",     "SS": "South Sudan",          "ES": "Spain",
    "LK": "Sri Lanka",         "SD": "Sudan",                "SR": "Suriname",
    "SJ": "Svalbard",          "SE": "Sweden",               "CH": "Switzerland",
    "SY": "Syria",             "TW": "Taiwan",               "TJ": "Tajikistan",
    "TZ": "Tanzania",          "TH": "Thailand",             "TL": "Timor-Leste",
    "TG": "Togo",              "TK": "Tokelau",              "TO": "Tonga",
    "TT": "Trinidad and Tobago","TN": "Tunisia",             "TR": "Turkey",
    "TM": "Turkmenistan",      "TC": "Turks and Caicos Islands",
    "TV": "Tuvalu",            "UG": "Uganda",               "UA": "Ukraine",
    "AE": "United Arab Emirates","GB": "United Kingdom",     "US": "United States",
    "UM": "US Minor Outlying Islands","UY": "Uruguay",       "UZ": "Uzbekistan",
    "VU": "Vanuatu",           "VE": "Venezuela",            "VN": "Vietnam",
    "VG": "British Virgin Islands","VI": "US Virgin Islands","WF": "Wallis and Futuna",
    "EH": "Western Sahara",    "YE": "Yemen",                "ZM": "Zambia",
    "ZW": "Zimbabwe",
}

def _country_name(code: str) -> str:
    """Expand an ISO 3166-1 alpha-2 country code to its full English name.

    The Graph API location.countryOrRegion field returns two-letter codes
    (e.g. 'CA', 'GE', 'IN').  Without expansion these are ambiguous in
    report output — 'CA' reads as California, 'GE' as Georgia, 'IN' as
    Indiana.  Unknown codes are returned as-is so new or edge-case codes
    are never silently dropped.
    """
    if not code:
        return code
    return _ISO3166.get(code.upper(), code)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — INTELLIGENCE MAPS
# ─────────────────────────────────────────────────────────────────────────────

HIGH_PRIV_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "75941009-915a-4869-abe7-691bff18279e": "Skype for Business Administrator",
    "5d6b6bb7-de71-4623-b4af-96380a352509": "Security Reader",
    "11648597-926c-4cf3-9c36-bcebb0ba8dcc": "Power Platform Administrator",
    "0526716b-113d-4c15-b2c8-68e3c22b9f80": "Authentication Policy Administrator",
}

DANGEROUS_APP_PERMS = {
    # Mail / BEC / data exfil
    "Mail.Read":                         ("HIGH",     "Read all mailboxes in the org"),
    "Mail.ReadBasic.All":                ("MEDIUM",   "Read basic mail data for all mailboxes"),
    "Mail.ReadWrite":                    ("CRITICAL", "Read and write all mailboxes"),
    "Mail.Send":                         ("HIGH",     "Send mail as any user"),
    "MailboxSettings.ReadWrite":         ("HIGH",     "Modify mailbox settings (forwarding) for any user"),
    "Calendars.ReadWrite":               ("MEDIUM",   "Read and write all calendar data"),
    # Directory / identity control
    "Directory.ReadWrite.All":           ("CRITICAL", "Full directory read/write"),
    "RoleManagement.ReadWrite.Directory":("CRITICAL", "Assign/remove directory roles — privilege escalation"),
    "AppRoleAssignment.ReadWrite.All":   ("CRITICAL", "Grant app roles to any principal"),
    "Application.ReadWrite.All":         ("CRITICAL", "Create/modify app registrations and service principals"),
    "User.ReadWrite.All":                ("HIGH",     "Modify any user account including password reset"),
    "Group.ReadWrite.All":               ("HIGH",     "Modify group memberships including privileged groups"),
    "Policy.ReadWrite.ConditionalAccess":("CRITICAL", "Modify Conditional Access — can remove MFA enforcement"),
    "Policy.ReadWrite.AuthenticationMethod":("HIGH",  "Modify authentication method policies"),
    # Files / data exfil
    "Files.ReadWrite.All":               ("HIGH",     "Read and write all files across SharePoint/OneDrive"),
    "Sites.ReadWrite.All":               ("HIGH",     "Full SharePoint site access"),
    "Notes.ReadWrite.All":               ("MEDIUM",   "Read and write all OneNote notebooks"),
    # Teams
    "ChannelMessage.Read.All":           ("MEDIUM",   "Read all Teams channel messages"),
    "Chat.Read.All":                     ("HIGH",     "Read all Teams chats"),
    # Security / audit
    "SecurityEvents.ReadWrite.All":      ("HIGH",     "Read and update security events/alerts"),
    "AuditLog.Read.All":                 ("MEDIUM",   "Read all audit logs — reconnaissance capability"),
    "Reports.Read.All":                  ("MEDIUM",   "Read usage/sign-in reports — reconnaissance capability"),
    "UserAuthenticationMethod.ReadWrite.All": ("CRITICAL", "Modify MFA methods for any user — MFA bypass"),
}

DANGEROUS_COMBOS = [
    (
        {"Mail.Read", "Mail.Send"},
        "CRITICAL", "Mail.Read + Mail.Send",
        "Can read any mailbox AND send as any user — full BEC capability"
    ),
    (
        {"Mail.ReadWrite", "MailboxSettings.ReadWrite"},
        "CRITICAL", "Mail.ReadWrite + MailboxSettings.ReadWrite",
        "Full mailbox control — can read all mail AND configure forwarding rules to exfiltrate data"
    ),
    (
        {"Directory.ReadWrite.All", "Application.ReadWrite.All"},
        "CRITICAL", "Directory.ReadWrite + Application.ReadWrite",
        "Effectively Global Administrator — can modify directory AND create/modify apps"
    ),
    (
        {"RoleManagement.ReadWrite.Directory", "User.ReadWrite.All"},
        "CRITICAL", "RoleManagement.ReadWrite + User.ReadWrite",
        "Privilege escalation path — can assign admin roles to any user"
    ),
    (
        {"Files.ReadWrite.All", "Mail.Read"},
        "HIGH", "Files.ReadWrite + Mail.Read",
        "Dual exfiltration — can steal files AND read email across the entire org"
    ),
    (
        {"Chat.Read.All", "Files.ReadWrite.All"},
        "HIGH", "Chat.Read.All + Files.ReadWrite",
        "Can exfiltrate Teams conversations and all OneDrive/SharePoint files"
    ),
    (
        {"AuditLog.Read.All", "Directory.ReadWrite.All"},
        "HIGH", "AuditLog.Read + Directory.ReadWrite",
        "Can monitor audit logs (to evade detection) while modifying the directory"
    ),
]

MS_GRAPH_SP_APPID = "00000003-0000-0000-c000-000000000000"

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 — TERMINAL FORMATTING
# ─────────────────────────────────────────────────────────────────────────────

BOLD  = "\033[1m"
RESET = "\033[0m"
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[38;5;208m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[94m",
    "INFO":     "\033[37m",
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def sev_color(text, sev):
    return f"{SEVERITY_COLORS.get(sev, '')}{text}{RESET}"

def sev_icon(sev):
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(sev, "  ")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5 — AUTHENTICATION
# ─────────────────────────────────────────────────────────────────────────────

def load_config(cli_tenant=None, cli_client_id=None,
               cli_days=None, cli_skip_defender=False, cli_skip_signin=False):
    """Load config from config.yaml, env vars, or CLI args.
    Priority: CLI flags > env vars > config.yaml > built-in defaults.
    """
    import os
    import yaml

    cfg_file = {}
    config_path = Path("config.yaml")
    if config_path.exists():
        try:
            with open(config_path) as f:
                cfg_file = yaml.safe_load(f) or {}
            print("  ✓ Loaded config.yaml")
        except Exception as e:
            print(f"  ⚠  Could not parse config.yaml: {e}")

    entra      = cfg_file.get("entra", {}) or {}
    assessment = cfg_file.get("assessment", {}) or {}

    tenant_id     = entra.get("tenant_id")     or DEFAULT_TENANT
    client_id     = entra.get("client_id")     or CLIENT_ID
    days          = int(assessment.get("days", 30))
    skip_defender = bool(assessment.get("skip_defender", False))
    skip_signin   = bool(assessment.get("skip_signin",   False))

    tenant_id     = os.environ.get("ENTRA_TENANT_ID", tenant_id)
    client_id     = os.environ.get("ENTRA_CLIENT_ID",  client_id)

    if cli_tenant:        tenant_id     = cli_tenant
    if cli_client_id:     client_id     = cli_client_id
    if cli_days:          days          = cli_days
    if cli_skip_defender: skip_defender = True
    if cli_skip_signin:   skip_signin   = True

    return {
        "tenant_id":     tenant_id,
        "client_id":     client_id,
        "days":          days,
        "skip_defender": skip_defender,
        "skip_signin":   skip_signin,
    }


class _CachingTokenWrapper:
    """Wraps azure-identity credential to cache the token and avoid re-prompting.
    Caching credential wrapper for token reuse.
    """
    def __init__(self, inner):
        self._inner = inner
        self._cached = None

    def get_token(self, *scopes, **kwargs):
        import time
        if self._cached and self._cached.expires_on > time.time() + 300:
            return self._cached
        self._cached = self._inner.get_token(*scopes, **kwargs)
        return self._cached


def authenticate_device_code(tenant_id: str, client_id: str) -> str:
    """Authenticate via device code flow using azure-identity.

    Uses the same approach as Connect-MgGraph:
      - azure.identity.DeviceCodeCredential
      - tenant = "organizations" (work/school accounts)
      - scope  = https://graph.microsoft.com/.default
      - token cached in memory, never written to disk
    """
    from azure.identity import DeviceCodeCredential

    def _prompt(verification_uri: str, user_code: str, expires_on):
        print("\n" + "=" * 66)
        print("  AUTHENTICATION REQUIRED")
        print("=" * 66)
        print(f"\n  1. Open:  {verification_uri}")
        print(f"  2. Enter: {BOLD}{user_code}{RESET}")
        print(f"\n  Waiting for sign-in (expires: {expires_on}) ...")
        print("=" * 66 + "\n")

    cred = DeviceCodeCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        prompt_callback=_prompt,
        cache_persistence_options=None,   # no disk caching — memory only
    )

    # Pre-authenticate once and cache token — prevents re-prompting
    wrapper = _CachingTokenWrapper(cred)
    token   = wrapper.get_token(*GRAPH_SCOPES)

    upn = "unknown"
    try:
        # Decode UPN from JWT claims (no extra lib needed)
        import base64, json as _json
        payload = token.token.split(".")[1]
        payload += "=" * (-len(payload) % 4)   # fix padding
        claims  = _json.loads(base64.b64decode(payload))
        upn     = claims.get("upn") or claims.get("preferred_username", "unknown")
    except Exception:
        pass

    print(f"  ✓ Authenticated as: {upn}\n")
    return token.token

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6 — GRAPH API CLIENT
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceStore:
    """Forensic evidence store — writes raw API responses to disk immediately
    upon receipt, before any analysis. Each response is individually timestamped,
    SHA-256 hashed, and appended to a manifest for chain of custody.

    Directory layout:
        <case_dir>/
            MANIFEST.json          — chain of custody log (all entries, ordered)
            raw/
                <endpoint_slug>_<seq>.json   — raw API response as received
            report/
                findings.json      — analyst conclusions (separate from evidence)
                report.json        — full structured report
    """

    def __init__(self, case_dir: Path):
        self.case_dir   = case_dir
        self.raw_dir    = case_dir / "raw"
        self.report_dir = case_dir / "report"
        self.manifest_path = case_dir / "MANIFEST.json"
        self._seq       = 0
        self._manifest  = []

        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def _slug(self, url: str) -> str:
        """Convert a URL to a safe filename slug."""
        import re
        # Strip base URLs and query strings
        slug = url.split("?")[0]
        for base in ("https://graph.microsoft.com/v1.0/",
                     "https://graph.microsoft.com/beta/",
                     "https://graph.microsoft.com/"):
            slug = slug.replace(base, "")
        slug = re.sub(r"[^a-zA-Z0-9_-]", "_", slug)
        return slug[:80]

    def store(self, url: str, params: Optional[dict], response: dict,
              source: str = "graph_api") -> str:
        """Write raw response to disk and append to manifest. Returns file path."""
        import hashlib
        self._seq += 1
        slug     = self._slug(url)
        filename = f"{slug}_{self._seq:04d}.json"
        filepath = self.raw_dir / filename

        # Envelope: raw response + collection metadata
        envelope = {
            "collected_at":    datetime.now(timezone.utc).isoformat(),
            "source":          source,
            "url":             url,
            "params":          params,
            "sequence":        self._seq,
            "response":        response,
        }
        raw_bytes = json.dumps(envelope, indent=2, default=str,
                               ensure_ascii=False).encode("utf-8")

        # Write atomically
        filepath.write_bytes(raw_bytes)

        # SHA-256 of the written file
        sha256 = hashlib.sha256(raw_bytes).hexdigest()

        # Append to manifest
        entry = {
            "seq":          self._seq,
            "collected_at": envelope["collected_at"],
            "source":       source,
            "url":          url,
            "file":         str(filepath.relative_to(self.case_dir)),
            "sha256":       sha256,
            "record_count": (len(response.get("value", [response]))
                             if isinstance(response, dict) else 1),
        }
        self._manifest.append(entry)
        self._flush_manifest()
        return str(filepath)


    def store_ps(self, command: str, result, description: str = "") -> str:
        """Store PowerShell/subprocess result with its own manifest entry."""
        import hashlib
        self._seq += 1
        filename = f"powershell_{self._seq:04d}.json"
        filepath = self.raw_dir / filename

        envelope = {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "source":       "powershell",
            "command":      command,
            "description":  description,
            "sequence":     self._seq,
            "response":     result,
        }
        raw_bytes = json.dumps(envelope, indent=2, default=str,
                               ensure_ascii=False).encode("utf-8")
        filepath.write_bytes(raw_bytes)
        sha256 = hashlib.sha256(raw_bytes).hexdigest()

        entry = {
            "seq":          self._seq,
            "collected_at": envelope["collected_at"],
            "source":       "powershell",
            "command":      command,
            "description":  description,
            "file":         str(filepath.relative_to(self.case_dir)),
            "sha256":       sha256,
        }
        self._manifest.append(entry)
        self._flush_manifest()
        return str(filepath)

    def _flush_manifest(self):
        """Rewrite manifest atomically after every entry — survive interruption."""
        tmp = self.manifest_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(self._manifest, indent=2, default=str, ensure_ascii=False),
            encoding="utf-8"
        )
        tmp.replace(self.manifest_path)

    def write_report(self, report: dict, filename: str = "report.json"):
        """Write the final findings report to the report subdirectory."""
        import hashlib
        path      = self.report_dir / filename
        raw_bytes = json.dumps(report, indent=2, default=str,
                               ensure_ascii=False).encode("utf-8")
        path.write_bytes(raw_bytes)
        sha256 = hashlib.sha256(raw_bytes).hexdigest()

        # Record report generation in manifest
        entry = {
            "seq":          "REPORT",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "source":       "analysis",
            "file":         str(path.relative_to(self.case_dir)),
            "sha256":       sha256,
        }
        self._manifest.append(entry)
        self._flush_manifest()
        return path, sha256

    def summary(self) -> dict:
        """Return chain of custody summary."""
        evidence_entries = [e for e in self._manifest if e.get("source") != "analysis"]
        return {
            "total_api_calls":     len(evidence_entries),
            "total_records":       sum(e.get("record_count", 0) for e in evidence_entries),
            "evidence_files":      len(evidence_entries),
            "manifest_entries":    len(self._manifest),
            "case_directory":      str(self.case_dir),
            "manifest_path":       str(self.manifest_path),
        }


class GraphClient:
    """Microsoft Graph API client with forensic evidence preservation.

    Every API response is written to the EvidenceStore immediately upon receipt,
    before any analysis or transformation. The in-memory return value is derived
    from the same data that was written to disk.
    """

    def __init__(self, token: str, evidence: "EvidenceStore"):
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
            # NOTE: ConsistencyLevel: eventual is intentionally omitted globally.
            # It is only required for $count and $search queries, neither of which
            # this script uses. Sending it on every request — including auditLogs/signIns
            # — routes queries through an eventually-consistent replica index that
            # returns empty results for sign-in log queries on some tenants, even
            # when the data exists and permissions are correct. The consent test
            # (which does not send this header) confirms the endpoint is accessible.
        }
        self.stats    = defaultdict(int)
        self.evidence = evidence

    def get(self, url: str, params: dict = None) -> Optional[dict]:
        try:
            r = requests.get(url, headers=self.headers, params=params, timeout=60)
            self.stats["requests"] += 1
            if r.status_code == 200:
                data = r.json()
                # Preserve raw response immediately before any analysis
                self.evidence.store(url, params, data)
                return data
            if r.status_code == 403:
                self.stats["permission_errors"] += 1
                return None
            if r.status_code == 404:
                return None
            self.stats["errors"] += 1
            return None
        except Exception:
            self.stats["errors"] += 1
            return None

    def get_all(self, url: str, params: dict = None, max_pages: int = 200) -> list:
        results, current_url, page = [], url, 0
        while current_url and page < max_pages:
            data = self.get(current_url, params=params if page == 0 else None)
            if not data:
                break
            results.extend(data.get("value", []))
            current_url = data.get("@odata.nextLink")
            page += 1
        return results

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7 — ASSESSMENT ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class Assessment:
    def __init__(self, client: GraphClient, evidence: EvidenceStore,
                 days_back: int = 30, collector_upn: str = ""):
        self.client        = client
        self.evidence      = evidence
        self.days_back     = days_back
        self.collector_upn = collector_upn
        self.started_at    = datetime.now(timezone.utc)
        self.findings      = []
        self.metrics       = {}
        self.tenant        = {}
        self.since         = (
            self.started_at - timedelta(days=days_back)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

    def finding(self, severity, category, title, detail, count=1, items=None):
        self.findings.append({
            "severity":    severity,
            "category":    category,
            "title":       title,
            "detail":      detail,
            "count":       count,
            "items":       items or [],
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        })

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8 — ASSESSMENT MODULES 1–9  (Base)
# ─────────────────────────────────────────────────────────────────────────────

def module_01_tenant(a: Assessment):
    print("  [01/17] Tenant & Organization...")
    org = a.client.get(f"{GRAPH_BASE}/organization")
    if org and org.get("value"):
        o = org["value"][0]
        a.tenant = {
            "name":    o.get("displayName", "Unknown"),
            "id":      o.get("id", ""),
            "country": o.get("countryLetterCode", ""),
            "domains": [d["name"] for d in o.get("verifiedDomains", [])],
        }
    sec = a.client.get(f"{GRAPH_BETA}/policies/identitySecurityDefaultsEnforcementPolicy")
    if sec is None:
        a.finding("INFO", "Tenant",
            "Security Defaults — Policy.Read.All Required",
            "Retrieving Security Defaults status requires Policy.Read.All consent. "
            "Re-run with a Global Administrator account for full coverage. "
            "Manual check: Entra admin center → Overview → Properties → "
            "Manage Security Defaults.")
    if sec:
        enabled = sec.get("isEnabled", False)
        a.tenant["security_defaults"] = enabled
        if not enabled:
            a.finding("HIGH", "Tenant",
                "Security Defaults Disabled",
                "Security Defaults enforce MFA and block legacy auth as a baseline. "
                "Disabling them requires compensating Conditional Access policies. "
                "Verify CA coverage is equivalent or stronger.")
        else:
            a.finding("INFO", "Tenant",
                "Security Defaults Enabled",
                "Baseline protection is active. Consider migrating to Conditional Access "
                "policies for more granular control (requires Entra P1).")
    else:
        a.finding("INFO", "Tenant",
            "Security Defaults Status Unavailable",
            "Could not retrieve Security Defaults via Graph API or PowerShell. "
            "Check status manually: Entra admin center → Properties → "
            "Manage Security Defaults.")


def module_02_roles(a: Assessment):
    print("  [02/17] Privileged Role Assignments...")
    assignments = a.client.get_all(
        f"{GRAPH_BASE}/roleManagement/directory/roleAssignments",
        params={"$expand": "principal", "$top": "999"}
    )
    role_members    = defaultdict(list)
    guest_admins    = []
    sp_admins       = []
    permanent_privs = []
    privileged_upns = set()  # UPNs of all privileged role holders

    for ra in assignments:
        role_id   = ra.get("roleDefinitionId", "")
        principal = ra.get("principal") or {}
        odata     = principal.get("@odata.type", "")
        name      = principal.get("displayName", "Unknown")
        upn       = principal.get("userPrincipalName", "")
        role_name = HIGH_PRIV_ROLES.get(role_id, role_id[:8] + "…")

        role_members[role_name].append(name)

        if role_id in HIGH_PRIV_ROLES:
            # Track privileged user UPNs for cross-module reference
            if "#microsoft.graph.user" in odata and upn:
                privileged_upns.add(upn.lower())
            if ra.get("directoryScopeId") == "/":
                permanent_privs.append(f"{name} → {role_name}")
            if "#microsoft.graph.user" in odata and "#EXT#" in upn:
                guest_admins.append(f"{name} ({upn}) → {role_name}")
            if "#microsoft.graph.servicePrincipal" in odata:
                sp_admins.append(f"{name} → {role_name}")

    ga_count = len(role_members.get("Global Administrator", []))
    a.metrics["global_admins"]             = ga_count
    a.metrics["privileged_role_assignments"]= len(assignments)
    a.metrics["privileged_upns"]           = privileged_upns  # For module 17 severity escalation

    if ga_count > 5:
        a.finding("HIGH", "Privileged Access",
            f"Excessive Global Administrators ({ga_count})",
            f"Microsoft recommends 2–4 break-glass accounts only. "
            f"Found: {', '.join(role_members['Global Administrator'][:10])}",
            ga_count, role_members["Global Administrator"])
    elif ga_count > 2:
        a.finding("MEDIUM", "Privileged Access",
            f"High Number of Global Administrators ({ga_count})",
            f"Consider reducing to 2 break-glass accounts with PIM for all others. "
            f"Found: {', '.join(role_members['Global Administrator'])}",
            ga_count, role_members["Global Administrator"])

    if guest_admins:
        a.finding("CRITICAL", "Privileged Access",
            f"Guest Accounts with Admin Roles ({len(guest_admins)})",
            "External/guest identities with privileged roles cannot be fully controlled "
            "by your tenant — a significant supply-chain risk.",
            len(guest_admins), guest_admins)

    if sp_admins:
        a.finding("HIGH", "Privileged Access",
            f"Service Principals with Admin Roles ({len(sp_admins)})",
            "Workload identities with privileged directory roles are a high-value "
            "compromise target. Prefer managed identities with narrow scope.",
            len(sp_admins), sp_admins)

    if len(permanent_privs) > 5:
        a.finding("HIGH", "Privileged Access",
            f"Permanent (Non-PIM) Privileged Assignments ({len(permanent_privs)})",
            "Permanent assignments bypass just-in-time controls. Migrate to PIM-eligible "
            "assignments with approval workflows and justification requirements.",
            len(permanent_privs), permanent_privs)


def module_03_users(a: Assessment):
    print("  [03/17] User Hygiene...")
    users = a.client.get_all(
        f"{GRAPH_BASE}/users",
        params={
            "$select": "id,displayName,userPrincipalName,accountEnabled,createdDateTime,"
                       "lastPasswordChangeDateTime,passwordPolicies,userType,onPremisesSyncEnabled",
            "$top": "999",
        }
    )
    total    = len(users)
    enabled  = [u for u in users if u.get("accountEnabled")]
    guests   = [u for u in users if u.get("userType") == "Guest"]
    disabled = [u for u in users if not u.get("accountEnabled")]
    synced   = [u for u in users if u.get("onPremisesSyncEnabled")]

    stale_cutoff  = datetime.now(timezone.utc) - timedelta(days=365)
    stale         = []
    pw_no_expires = []

    for u in enabled:
        upn = u.get("userPrincipalName", "")
        if "#EXT#" in upn:
            continue
        last_pw = u.get("lastPasswordChangeDateTime")
        if last_pw:
            try:
                dt = datetime.fromisoformat(last_pw.replace("Z", "+00:00"))
                if dt < stale_cutoff:
                    stale.append(f"{u.get('displayName', upn)} (last change: {dt.strftime('%Y-%m-%d')})")
            except Exception:
                pass
        if "DisablePasswordExpiration" in (u.get("passwordPolicies") or ""):
            pw_no_expires.append(u.get("displayName", upn))

    a.metrics.update({
        "total_users":        total,
        "enabled_users":      len(enabled),
        "guest_users":        len(guests),
        "disabled_users":     len(disabled),
        "synced_from_onprem": len(synced),
    })

    # Large tenant detection — inform user of extended runtime
    if total >= 10000:
        a.metrics["large_tenant"] = True
        print(f"\n  ⚠️  Large tenant detected ({total:,} users)")
        print(f"      Some modules may take longer. Module 17 will process")
        print(f"      {(total + 19) // 20:,} batch requests with rate limiting.\n")
    else:
        a.metrics["large_tenant"] = False

    if total > 0:
        guest_pct = len(guests) / total * 100
        if guest_pct > 20:
            a.finding("HIGH", "User Hygiene",
                f"High Proportion of Guest Users ({len(guests)}, {guest_pct:.0f}%)",
                "Large guest populations increase attack surface. Enable Access Reviews "
                "and ensure CA policies cover external identities.",
                len(guests))
        elif guests:
            a.finding("MEDIUM", "User Hygiene",
                f"Guest Users Present ({len(guests)})",
                "Ensure all guests are reviewed regularly with Entra Access Reviews.",
                len(guests))

    if stale:
        a.finding("MEDIUM", "User Hygiene",
            f"Stale Accounts — Password Not Changed >365 Days ({len(stale)})",
            "Dormant accounts with old passwords should be reviewed and disabled if inactive.",
            len(stale), stale)

    if pw_no_expires:
        a.finding("MEDIUM", "User Hygiene",
            f"Accounts with Password Never Expires ({len(pw_no_expires)})",
            "Non-expiring passwords increase risk duration after credential compromise. "
            "Ensure service accounts have compensating controls.",
            len(pw_no_expires), pw_no_expires)


def module_04_ca(a: Assessment):
    print("  [04/17] Conditional Access Policies...")
    policies = a.client.get_all(f"{GRAPH_BETA}/identity/conditionalAccess/policies")
    if policies is None:
        a.finding("MEDIUM", "Conditional Access",
            "Conditional Access Policies — Policy.Read.All Required",
            "Policy.Read.All requires admin consent and is not available to this account. "
            "Re-run with a Global Administrator account for full CA policy coverage. "
            "Manual check: Entra admin center → Protection → Conditional Access → Policies.")
        return

    enabled     = [p for p in policies if p.get("state") == "enabled"]
    disabled    = [p for p in policies if p.get("state") == "disabled"]
    report_only = [p for p in policies if p.get("state") == "enabledForReportingButNotEnforced"]

    a.metrics.update({
        "ca_policies_total":       len(policies),
        "ca_policies_enabled":     len(enabled),
        "ca_policies_disabled":    len(disabled),
        "ca_policies_report_only": len(report_only),
    })

    if not policies:
        if not a.tenant.get("security_defaults"):
            a.finding("CRITICAL", "Conditional Access",
                "No CA Policies and Security Defaults Disabled",
                "Zero authentication protection baseline. Any user can authenticate from "
                "any location/device without MFA.")
        return

    all_users_mfa  = False
    legacy_blocked = False
    mfa_policies   = []

    for p in enabled:
        conditions     = p.get("conditions", {})
        grant          = p.get("grantControls") or {}
        users          = conditions.get("users", {})
        apps           = conditions.get("applications", {})
        client_apps    = conditions.get("clientAppTypes", [])
        builtin        = grant.get("builtInControls", [])
        include_users  = users.get("includeUsers", [])
        include_apps   = apps.get("includeApplications", [])

        if "mfa" in builtin or "authenticationStrength" in grant:
            mfa_policies.append(p.get("displayName", "Unnamed"))
            if ("All" in include_users or "all" in include_users) and \
               ("All" in include_apps  or "all" in include_apps  or "Office365" in include_apps):
                all_users_mfa = True

        if "block" in builtin:
            if any(c in (client_apps or []) for c in ["exchangeActiveSync", "other"]):
                legacy_blocked = True

    if not all_users_mfa:
        a.finding("HIGH", "Conditional Access",
            "No Universal MFA Policy (All Users + All Apps)",
            f"No policy enforces MFA for all users across all apps. "
            f"Found {len(mfa_policies)} MFA polic{'ies' if len(mfa_policies)!=1 else 'y'} with partial coverage: "
            f"{', '.join(mfa_policies) or 'None'}.",
            len(mfa_policies))

    if not legacy_blocked:
        a.finding("HIGH", "Conditional Access",
            "Legacy Authentication Protocols Not Blocked",
            "SMTP, IMAP, POP3, and legacy EAS cannot enforce MFA and are the primary "
            "password-spray attack vector. Block 'Exchange ActiveSync' + 'Other clients'.")

    if report_only:
        a.finding("MEDIUM", "Conditional Access",
            f"Policies in Report-Only Mode ({len(report_only)})",
            f"Not enforced: {', '.join(p.get('displayName','') for p in report_only)}. "
            "Review and enable or remove.",
            len(report_only), [p.get("displayName","") for p in report_only])

    if disabled:
        a.finding("LOW", "Conditional Access",
            f"Disabled CA Policies ({len(disabled)})",
            f"Clean up or document: {', '.join(p.get('displayName','') for p in disabled)}",
            len(disabled))


def module_05_apps(a: Assessment):
    print("  [05/17] Applications & Service Principals...")
    apps         = a.client.get_all(f"{GRAPH_BASE}/applications",
        params={"$select": "id,displayName,createdDateTime,passwordCredentials,keyCredentials", "$top": "999"})
    sps          = a.client.get_all(f"{GRAPH_BASE}/servicePrincipals",
        params={"$select": "id,displayName,servicePrincipalType", "$top": "999"})
    oauth_grants = a.client.get_all(f"{GRAPH_BASE}/oauth2PermissionGrants",
        params={"$top": "999"})

    a.metrics["app_registrations"] = len(apps)
    a.metrics["service_principals"]= len(sps)
    a.metrics["oauth_grants"]      = len(oauth_grants)

    now          = datetime.now(timezone.utc)
    expired      = []
    expiring     = []

    for app in apps:
        name = app.get("displayName", "Unknown")
        for cred in app.get("passwordCredentials", []):
            end = cred.get("endDateTime")
            if end:
                try:
                    exp = datetime.fromisoformat(end.replace("Z", "+00:00"))
                    if exp < now:
                        expired.append(f"{name} (expired {exp.strftime('%Y-%m-%d')})")
                    elif exp < now + timedelta(days=30):
                        expiring.append(f"{name} (expires {exp.strftime('%Y-%m-%d')})")
                except Exception:
                    pass

    if expired:
        a.finding("HIGH", "Applications",
            f"App Registrations with Expired Credentials ({len(expired)})",
            "Abandoned apps with expired secrets may still have assigned permissions. Audit and remove.",
            len(expired), expired)

    if expiring:
        a.finding("MEDIUM", "Applications",
            f"App Credentials Expiring Within 30 Days ({len(expiring)})",
            "Rotate credentials before expiry to prevent service disruption.",
            len(expiring), expiring)

    admin_consent = [g for g in oauth_grants if g.get("consentType") == "AllPrincipals"]
    if admin_consent:
        a.finding("MEDIUM", "Applications",
            f"Tenant-Wide Admin Consent Grants ({len(admin_consent)})",
            "Admin-consented delegated permissions apply to all users. Review each for necessity.",
            len(admin_consent))

    # ── AI agent / Copilot service principal detection  ──
    AI_PATTERNS = [
        "copilot", "openai", "langchain", "autogen", "mcp",
        "ai-agent", "ai agent", "llm", "gpt", "claude", "gemini",
        "power virtual", "copilot studio", "chatgpt", "anthropic",
        "azure openai", "semantic kernel",
    ]
    ai_sps = [
        sp.get("displayName","")
        for sp in sps
        if any(p in (sp.get("displayName","") or "").lower() for p in AI_PATTERNS)
    ]
    a.metrics["ai_agent_sps"] = len(ai_sps)
    if ai_sps:
        a.finding("MEDIUM", "Applications",
            f"AI Agent / Copilot Service Principals Detected ({len(ai_sps)})",
            "AI workload identities require the same access governance as human identities — "
            "possibly more, since they can act autonomously at scale. Verify each has least-privilege "
            "permissions, an owner, and is covered by a data governance policy.",
            len(ai_sps), ai_sps)

    # ── Long-lived app secrets (>180 days validity) ──────────────────────────
    long_lived = []
    for app in apps:
        name = app.get("displayName","Unknown")
        for cred in app.get("passwordCredentials",[]):
            start = cred.get("startDateTime")
            end   = cred.get("endDateTime")
            if start and end:
                try:
                    s = datetime.fromisoformat(start.replace("Z","+00:00"))
                    e = datetime.fromisoformat(end.replace("Z","+00:00"))
                    days_valid = (e - s).days
                    if days_valid > 180:
                        long_lived.append(f"{name}: {days_valid}-day secret (expires {e.strftime('%Y-%m-%d')})")
                except Exception:
                    pass
    if long_lived:
        a.finding("MEDIUM", "Applications",
            f"App Secrets Valid >180 Days ({len(long_lived)})",
            "Long-lived secrets increase the exposure window if leaked. "
            "Rotate secrets at least every 90 days and consider certificate credentials instead.",
            len(long_lived), long_lived)


def module_06_devices(a: Assessment):
    print("  [06/17] Device Compliance & Management...")
    devices = a.client.get_all(f"{GRAPH_BASE}/devices",
        params={
            "$select": "id,displayName,operatingSystem,isCompliant,isManaged,trustType,"
                       "approximateLastSignInDateTime",
            "$top": "999",
        })

    total       = len(devices)
    unmanaged   = [d for d in devices if not d.get("isManaged")]
    non_compl   = [d for d in devices if d.get("isCompliant") is False]
    stale_co    = datetime.now(timezone.utc) - timedelta(days=90)
    stale       = [d.get("displayName","?") for d in devices
                   if d.get("approximateLastSignInDateTime") and
                   datetime.fromisoformat(
                       d["approximateLastSignInDateTime"].replace("Z","+00:00")
                   ) < stale_co]

    a.metrics.update({
        "total_devices":    total,
        "unmanaged_devices":len(unmanaged),
        "non_compliant":    len(non_compl),
        "stale_devices":    len(stale),
    })

    if total > 0:
        pct = len(unmanaged) / total * 100
        sev = "HIGH" if pct > 30 else "MEDIUM"
        if unmanaged:
            a.finding(sev, "Devices",
                f"Unmanaged Devices ({len(unmanaged)}, {pct:.0f}%)",
                "Unmanaged devices cannot be assessed for compliance, patch level, or encryption. "
                "Enforce device compliance via Conditional Access.",
                len(unmanaged))

    if non_compl:
        a.finding("HIGH", "Devices",
            f"Non-Compliant Enrolled Devices ({len(non_compl)})",
            "Enrolled but non-compliant devices violate policy. CA should block non-compliant "
            "devices from sensitive resources.",
            len(non_compl))

    if stale:
        a.finding("MEDIUM", "Devices",
            f"Stale Devices — No Sign-in >90 Days ({len(stale)})",
            "Clean up stale device registrations to reduce attack surface.",
            len(stale), stale)


def module_07_signins(a: Assessment):
    print(f"  [07/17] Sign-in Logs (last {a.days_back} days)...")

    # NOTE: The Graph auditLogs/signIns endpoint silently returns an empty result set
    # (not a 400 error) when a bare createdDateTime range filter is used without an
    # equality predicate alongside it — this is a Graph API indexing constraint, not a
    # permission failure.  Module 15 works because it anchors on status/errorCode eq 0.
    # We mirror that approach here: two targeted queries (successes + failures) that each
    # carry an equality anchor, then merge and deduplicate locally by id.
    _select = (
        "id,createdDateTime,userPrincipalName,appDisplayName,ipAddress,location,"
        "status,riskLevelAggregated,conditionalAccessStatus,clientAppUsed,isInteractive"
    )
    _common = {
        "$select": _select,
        "$top":    "999",
        # NOTE: Do NOT add $orderby here. The auditLogs/signIns endpoint
        # silently returns empty results when $orderby is combined with $filter.
        # Sorting is done locally where needed.
    }

    successful = a.client.get_all(
        f"{GRAPH_BASE}/auditLogs/signIns",
        params={**_common,
                "$filter": f"createdDateTime ge {a.since} and status/errorCode eq 0"},
        max_pages=10
    )
    failed_raw = a.client.get_all(
        f"{GRAPH_BASE}/auditLogs/signIns",
        params={**_common,
                "$filter": f"createdDateTime ge {a.since} and status/errorCode ne 0"},
        max_pages=10
    )

    # Merge, deduplicate on id (Graph occasionally returns the same event in both
    # buckets near the errorCode eq 0 / ne 0 boundary due to index propagation lag).
    seen: set = set()
    sign_ins: list = []
    for s in (successful or []) + (failed_raw or []):
        eid = s.get("id") or id(s)
        if eid not in seen:
            seen.add(eid)
            sign_ins.append(s)

    if not sign_ins:
        a.finding("INFO", "Sign-in Analysis",
            "Sign-in Log Query Returned No Results (Module 07)",
            "Both the successful and failed sign-in queries returned no data. This is "
            "unlikely to be a Graph indexing issue since two independent compound-filter "
            "queries were used. Verify admin consent for AuditLog.Read.All on the "
            "Microsoft Graph Command Line Tools app and confirm the account holds "
            "Reports Reader or Security Reader role.")
        return

    total    = len(sign_ins)
    failed   = [s for s in sign_ins if (s.get("status") or {}).get("errorCode", 0) != 0]
    legacy   = [s for s in sign_ins if s.get("clientAppUsed") in
                {"ExchangeActiveSync","IMAP4","MAPI","POP3","SMTP","Other clients"}]
    risky    = [s for s in sign_ins if (s.get("riskLevelAggregated") or "") in ("high","medium")]
    # NOTE: authenticationRequirement is a beta-only field not available on
    # the v1.0 signIns endpoint. Requesting it causes a 400 for the entire
    # query. It is omitted from $select; this list will always be empty on
    # v1.0. Switch GRAPH_BASE to beta to re-enable this detection.
    no_mfa   = [s for s in sign_ins if s.get("isInteractive") and
                s.get("authenticationRequirement") == "singleFactorAuthentication" and
                (s.get("status") or {}).get("errorCode", 0) == 0]

    fail_by_user = defaultdict(int)
    fail_by_ip   = defaultdict(int)
    for s in failed:
        fail_by_user[s.get("userPrincipalName","unknown")] += 1
        fail_by_ip[s.get("ipAddress","unknown")] += 1

    countries = defaultdict(int)
    for s in sign_ins:
        c = _country_name((s.get("location") or {}).get("countryOrRegion", "Unknown"))
        countries[c] += 1

    a.metrics.update({
        "total_signins":            total,
        "failed_signins":           len(failed),
        "legacy_auth_signins":      len(legacy),
        "risky_signins":            len(risky),
        "mfa_not_required_signins": len(no_mfa),
        "signin_countries":         len(countries),
    })

    fail_rate = len(failed) / total * 100 if total else 0
    if fail_rate > 20:
        a.finding("HIGH", "Sign-in Analysis",
            f"High Sign-in Failure Rate ({fail_rate:.1f}%)",
            "May indicate credential spray, lockout loops, or misconfigured apps.",
            len(failed))

    if legacy:
        users = list(set(s.get("userPrincipalName","") for s in legacy))
        a.finding("HIGH", "Sign-in Analysis",
            f"Legacy Authentication Sign-ins ({len(legacy)} events, {len(users)} users)",
            f"Protocols bypassing MFA in use: "
            f"{', '.join(set(s.get('clientAppUsed','') for s in legacy))}. "
            f"Users: {', '.join(users)}",
            len(legacy), users)

    if risky:
        users = list(set(s.get("userPrincipalName","") for s in risky))
        a.finding("HIGH", "Sign-in Analysis",
            f"High/Medium Risk Sign-ins ({len(risky)})",
            "Identity Protection flagged these sign-ins. Investigate and remediate.",
            len(risky), users)

    if no_mfa:
        users = list(set(s.get("userPrincipalName","") for s in no_mfa))
        a.finding("HIGH", "Sign-in Analysis",
            f"Successful Single-Factor Sign-ins ({len(no_mfa)})",
            f"Interactive sign-ins completed without MFA. Gaps in CA coverage. "
            f"Users: {', '.join(users)}",
            len(no_mfa), users)

    heavy_fail_users = sorted(
        [(u,c) for u,c in fail_by_user.items() if c > 10],
        key=lambda x: x[1], reverse=True
    )
    if heavy_fail_users:
        a.finding("HIGH", "Sign-in Analysis",
            f"Accounts with >10 Sign-in Failures ({len(heavy_fail_users)})",
            f"Possible brute force or credential spray. "
            f"Top: {', '.join(f'{u}({c})' for u,c in heavy_fail_users)}",
            len(heavy_fail_users),
            [f"{u} ({c} failures)" for u,c in heavy_fail_users[:20]])

    heavy_fail_ips = sorted(
        [(ip,c) for ip,c in fail_by_ip.items() if c > 20],
        key=lambda x: x[1], reverse=True
    )
    if heavy_fail_ips:
        a.finding("MEDIUM", "Sign-in Analysis",
            f"IPs with >20 Failed Attempts ({len(heavy_fail_ips)})",
            f"Possible attack sources. Top: {', '.join(f'{ip}({c})' for ip,c in heavy_fail_ips)}",
            len(heavy_fail_ips),
            [f"{ip} ({c} failures)" for ip,c in heavy_fail_ips[:10]])

    # ── Per-user failure detail  ──────────────────
    # Report ALL users with any failures, with IP, location, app, timestamp
    all_fail_users = sorted(fail_by_user.items(), key=lambda x: x[1], reverse=True)
    if all_fail_users:
        items = []
        # Build per-user failure detail
        fail_events_by_user = defaultdict(list)
        for s in failed:
            upn = s.get("userPrincipalName","unknown")
            loc  = s.get("location") or {}
            city = loc.get("city","")
            country = _country_name(loc.get("countryOrRegion",""))
            location_str = f"{city}, {country}".strip(", ") or "Unknown"
            fail_events_by_user[upn].append({
                "time":  (s.get("createdDateTime",""))[:16].replace("T"," "),
                "ip":    s.get("ipAddress",""),
                "loc":   location_str,
                "app":   s.get("appDisplayName",""),
                "proto": s.get("clientAppUsed",""),
            })
        for upn, count in all_fail_users[:20]:
            events = sorted(fail_events_by_user[upn], key=lambda x: x["time"], reverse=True)
            item = f"{upn} ({count} failures)"
            for ev in events[:3]:
                item += ("\n               " +
                         f"{ev['time']} | {ev['ip']} ({ev['loc']}) | {ev['proto']} | {ev['app']}")
            if len(events) > 3:
                item += f"\n               ... and {len(events)-3} more"
            items.append(item)
        a.finding("INFO", "Sign-in Analysis",
            f"Sign-in Failure Detail — All Accounts ({len(all_fail_users)} accounts, {len(failed)} events)",
            "Full per-user sign-in failure breakdown with IP, location, protocol, and application.",
            len(failed), items)

    # ── Token replay detection  ─────────────────────────
    # Same user, same app, different IPs within 5 minutes — stolen token indicator
    success_by_user_app = defaultdict(list)
    for s in sign_ins:
        if (s.get("status") or {}).get("errorCode", 0) == 0:
            key = (s.get("userPrincipalName",""), s.get("appDisplayName",""))
            success_by_user_app[key].append(s)

    replay_indicators = []
    for (upn, app), events in success_by_user_app.items():
        if len(events) < 2:
            continue
        # Sort by time
        timed = []
        for ev in events:
            try:
                from datetime import datetime as _dt
                t = _dt.fromisoformat((ev.get("createdDateTime","")).replace("Z","+00:00"))
                timed.append((t, ev.get("ipAddress","")))
            except Exception:
                pass
        timed.sort(key=lambda x: x[0])
        # Check pairs within 5-minute window with different IPs
        for i in range(len(timed)-1):
            t1, ip1 = timed[i]
            t2, ip2 = timed[i+1]
            diff_secs = abs((t2 - t1).total_seconds())
            if diff_secs <= 300 and ip1 and ip2 and ip1 != ip2:
                replay_indicators.append(
                    f"{upn} — {app}: {ip1} and {ip2} within {int(diff_secs)}s"
                )
                break  # one finding per user/app pair

    if replay_indicators:
        a.finding("HIGH", "Sign-in Analysis",
            f"Token Replay Indicators ({len(replay_indicators)} events)",
            "Same user accessed same app from different IPs within 5 minutes. "
            "This pattern indicates possible stolen token replay by an attacker. "
            "Investigate each occurrence — check if the IPs correspond to known "
            "VPNs, proxies, or unexpected locations.",
            len(replay_indicators), replay_indicators)

    # ── Password spray detection ──────────────────────────────────────────────
    # Many different users failing from same IP in a short window
    fail_users_by_ip = defaultdict(set)
    for s in failed:
        if (s.get("status") or {}).get("errorCode") == 50126:  # invalid credentials
            fail_users_by_ip[s.get("ipAddress","")].add(s.get("userPrincipalName",""))
    spray_ips = [
        (ip, users) for ip, users in fail_users_by_ip.items()
        if len(users) >= 5  # 5+ unique users from same IP = spray
    ]
    if spray_ips:
        items = [f"{ip} targeted {len(users)} accounts: {', '.join(list(users))}"
                 for ip, users in sorted(spray_ips, key=lambda x: len(x[1]), reverse=True)[:10]]
        a.finding("CRITICAL", "Sign-in Analysis",
            f"Password Spray Indicators ({len(spray_ips)} source IPs)",
            "One or more IPs have invalid-credential failures against 5+ unique accounts. "
            "Classic password spray pattern. Block source IPs and check for successful "
            "logins from same IPs.",
            len(spray_ips), items)

    a.metrics["token_replay_indicators"] = len(replay_indicators)
    a.metrics["spray_source_ips"]        = len(spray_ips)


def module_08_risky_users(a: Assessment):
    print("  [08/17] Identity Protection — Risky Users & Risk Detections...")
    client = a.client

    # ── Risky users ──────────────────────────────────────────────────────────
    users = client.get_all(
        f"{GRAPH_BASE}/identityProtection/riskyUsers",
        params={"$filter": "riskLevel eq 'high' or riskLevel eq 'medium'", "$top": "100"}
    )
    if users is None:
        # 403 here means either no P2 license OR scope missing from token.
        # PS fallback won't help for licensing — skip it and report accurately.
        a.finding("INFO", "Identity Protection",
            "Risky Users Unavailable — Entra ID P2 License Not Present",
            "The Identity Protection risky users endpoint requires an Entra ID P2 license. "
            "If this tenant does not have P2, this data is not available regardless of "
            "authentication method. If P2 is licensed, verify IdentityRiskyUser.Read.All "
            "is consented on the Microsoft Graph Command Line Tools app.")
    if users is not None:
        high   = [u for u in users if u.get("riskLevel") == "high"]
        medium = [u for u in users if u.get("riskLevel") == "medium"]
        a.metrics["high_risk_users"]   = len(high)
        a.metrics["medium_risk_users"] = len(medium)

        if high:
            names = [u.get("userDisplayName", u.get("userPrincipalName","?")) for u in high]
            a.finding("CRITICAL", "Identity Protection",
                f"High-Risk Users ({len(high)})",
                "Immediate investigation required. Consider requiring password reset + MFA re-registration.",
                len(high), names)

        if medium:
            names = [u.get("userDisplayName", u.get("userPrincipalName","?")) for u in medium]
            a.finding("HIGH", "Identity Protection",
                f"Medium-Risk Users ({len(medium)})",
                "Investigate each account for signs of compromise.",
                len(medium), names)

    # ── Risk detections (individual events) ──────────────────────────────────
    # Requires IdentityRiskyUser.Read.All and Entra P2
    detections = client.get_all(
        f"{GRAPH_BETA}/identityProtection/riskDetections",
        params={
            "$filter": f"detectedDateTime ge {a.since}",
            "$select": "id,userPrincipalName,userDisplayName,riskType,riskEventType,"
                       "riskLevel,riskState,detectedDateTime,ipAddress,location,"
                       "activity,detectionTimingType,additionalInfo",
            "$orderby": "detectedDateTime desc",
            "$top": "500",
        },
        max_pages=5
    )
    if detections is None:
        pass  # IdentityRiskyUser.Read.All not available — gap reported by risky users module

    if detections:
        high_det   = [d for d in detections if d.get("riskLevel") in ("high","medium")]
        by_type    = defaultdict(int)
        by_user    = defaultdict(list)
        for d in detections:
            by_type[d.get("riskEventType") or d.get("riskType","unknown")] += 1
            by_user[d.get("userPrincipalName","unknown")].append(d)

        a.metrics["risk_detections_total"] = len(detections)
        a.metrics["risk_detections_high"]  = len(high_det)

        if high_det:
            items = []
            for d in high_det[:20]:
                loc  = d.get("location") or {}
                city = loc.get("city","")
                country = _country_name(loc.get("countryOrRegion",""))
                location_str = f"{city}, {country}".strip(", ") or "Unknown"
                items.append(
                    f"[{(d.get('riskLevel','?')).upper()}] {d.get('userPrincipalName','')} — "
                    f"{d.get('riskEventType') or d.get('riskType','?')} "
                    f"({(d.get('detectedDateTime',''))[:10]}, {location_str})"
                )
            a.finding("HIGH", "Identity Protection",
                f"High/Medium Risk Detections in Last {a.days_back} Days ({len(high_det)})",
                "Individual risk events flagged by Identity Protection. Each represents a "
                "specific detected behaviour: leaked credentials, anonymous IP, impossible "
                "travel, malware-linked IP, suspicious inbox rules, token issuer anomaly, etc.",
                len(high_det), items)

        # Top risk types summary
        if by_type:
            type_summary = ", ".join(
                f"{t}: {c}" for t, c in
                sorted(by_type.items(), key=lambda x: x[1], reverse=True)
            )
            a.finding("INFO", "Identity Protection",
                f"Risk Detection Types — Last {a.days_back} Days ({len(detections)} total)",
                f"Detection breakdown: {type_summary}",
                len(detections))

        # Users with multiple detections (persistent risk)
        repeat_risk = [(u, evts) for u, evts in by_user.items() if len(evts) >= 3]
        if repeat_risk:
            items = [f"{u}: {len(e)} detections" for u, e in
                     sorted(repeat_risk, key=lambda x: len(x[1]), reverse=True)[:15]]
            a.finding("HIGH", "Identity Protection",
                f"Users with Repeated Risk Detections ({len(repeat_risk)})",
                "Accounts with 3+ risk detections in the analysis window indicate "
                "persistent compromise or ongoing attack. Prioritise for immediate remediation.",
                len(repeat_risk), items)

    # ── Impossible travel detection from sign-in logs ─────────────────────────
    # Pull recent sign-ins specifically for travel analysis
    # (Uses sign-in data stored on assessment object if available)
    print("      → Running impossible travel analysis...")
    travel_signins = client.get_all(
        f"{GRAPH_BASE}/auditLogs/signIns",
        params={
            "$filter":  f"createdDateTime ge {a.since} and status/errorCode eq 0",
            "$select":  "createdDateTime,userPrincipalName,ipAddress,location",
            "$top":     "999",
            # NOTE: No $orderby — auditLogs/signIns silently returns empty with $orderby+$filter
        },
        max_pages=5
    )

    if travel_signins:
        # Sort locally by time (Graph can't do $orderby with $filter on this endpoint)
        travel_signins.sort(key=lambda x: x.get("createdDateTime", ""))
        # Group successful sign-ins by user, sorted by time
        by_user_travel = defaultdict(list)
        for s in travel_signins:
            upn = s.get("userPrincipalName","")
            loc = s.get("location") or {}
            country = _country_name(loc.get("countryOrRegion",""))
            if upn and country:
                by_user_travel[upn].append({
                    "time":    s.get("createdDateTime",""),
                    "country": country,
                    "city":    loc.get("city",""),
                    "ip":      s.get("ipAddress",""),
                })

        impossible_travel = []
        # Realistic max travel speed threshold: 900 km/h (commercial flight)
        # We use country change within 1 hour as the heuristic
        for upn, events in by_user_travel.items():
            sorted_events = sorted(events, key=lambda x: x["time"])
            for i in range(len(sorted_events) - 1):
                e1 = sorted_events[i]
                e2 = sorted_events[i+1]
                if e1["country"] == e2["country"]:
                    continue
                if not e1["time"] or not e2["time"]:
                    continue
                try:
                    t1 = datetime.fromisoformat(e1["time"].replace("Z","+00:00"))
                    t2 = datetime.fromisoformat(e2["time"].replace("Z","+00:00"))
                    diff_min = abs((t2 - t1).total_seconds()) / 60
                    if diff_min <= 60:  # different countries within 1 hour
                        impossible_travel.append(
                            f"{upn}: {e1['country']} ({e1['city']}) → "
                            f"{e2['country']} ({e2['city']}) "
                            f"in {int(diff_min)} min "
                            f"[{e1['ip']} → {e2['ip']}]"
                        )
                except Exception:
                    pass

        a.metrics["impossible_travel_events"] = len(impossible_travel)
        if impossible_travel:
            a.finding("HIGH", "Identity Protection",
                f"Impossible Travel Detected ({len(impossible_travel)} events)",
                "Successful sign-ins from different countries within 60 minutes. "
                "Physically impossible travel indicates VPN evasion, token theft, "
                "or account sharing. Each must be investigated.",
                len(impossible_travel), impossible_travel)


def _classify_account(upn: str, display_name: str, user_type: str) -> str:
    """Classify an account into: human | guest | service | resource.

    human    — interactive employee account requiring MFA
    guest    — B2B external identity (different remediation)
    service  — service/automation account (non-interactive, CA-secured)
    resource — room, equipment, shared mailbox (non-interactive by design)
    """
    upn_lower  = (upn or "").lower()
    name_lower = (display_name or "").lower()

    # Guests are identified by Entra directly
    if user_type == "guest" or "#ext#" in upn_lower:
        return "guest"

    # Resource account patterns (rooms, equipment, shared mailboxes)
    RESOURCE_PATTERNS = [
        "room", "conf", "conference", "meeting", "board",
        "equipment", "projector", "copier", "printer", "fax",
        "azalea", "madrone", "maple", "redwood", "cedar", "oak",
        "lobby", "reception", "kitchen", "breakroom",
    ]
    # Service / automation account patterns
    SERVICE_PATTERNS = [
        "svc", "service", "bot", "automation", "noreply", "no-reply",
        "no_reply", "donotreply", "do-not-reply", "admin@", "helpdesk",
        "support@", "info@", "hello@", "contact@", "jobs@", "careers@",
        "billing@", "invoices@", "accounts", "ap@", "ar@", "payroll",
        "notifications", "alerts@", "monitor",
        "scanner", "backup", "sync", "connector", "integration",
    ]

    for pat in RESOURCE_PATTERNS:
        if pat in upn_lower or pat in name_lower:
            return "resource"

    for pat in SERVICE_PATTERNS:
        if pat in upn_lower or pat in name_lower:
            return "service"

    return "human"


def module_09_mfa(a: Assessment):
    print("  [09/17] MFA Registration & Auth Methods...")

    # Pull report — paginate to get all users
    report = a.client.get_all(
        f"{GRAPH_BETA}/reports/authenticationMethods/userRegistrationDetails",
        params={"$top": "999"}
    )
    # Store raw report for module 17 cross-reference
    a.metrics["mfa_m09_raw_report"] = report

    if not report:
        a.finding("INFO", "MFA & Auth Methods",
            "MFA Registration Report Unavailable",
            "The authentication methods report returned no data. Most likely cause is "
            "missing admin consent on the Microsoft Graph Command Line Tools app — "
            "go to Enterprise Applications → Microsoft Graph Command Line Tools → "
            "Permissions → Grant admin consent for your org.")
        return

    # Also pull user list to get userType (guest vs member) and accountEnabled
    user_meta = {}
    raw_users = a.client.get_all(
        f"{GRAPH_BASE}/users",
        params={
            "$select": "id,userPrincipalName,userType,accountEnabled",
            "$top":    "999",
        }
    )
    for u in (raw_users or []):
        user_meta[u.get("userPrincipalName","").lower()] = {
            "userType":       u.get("userType","member"),
            "accountEnabled": u.get("accountEnabled", True),
            "id":             u.get("id",""),
        }

    # ── Classify every account in the MFA report ─────────────────────────────
    STRONG_METHODS = {
        "microsoftAuthenticatorPush", "microsoftAuthenticatorPasswordless",
        "fido2SecurityKey", "windowsHelloForBusiness", "softwareOneTimePasscode",
    }
    WEAK_METHODS = {"mobilePhone", "alternateMobilePhone", "officePhone", "email"}

    # Buckets
    human_mfa_reg      = []   # human + MFA registered
    human_mfa_missing  = []   # human + no MFA — the real risk number
    human_weak_only    = []   # human + only weak MFA methods
    human_strong       = []   # human + strong MFA
    guest_accounts     = []   # guest users
    service_accounts   = []   # service/automation accounts
    resource_accounts  = []   # rooms, equipment, shared mailboxes
    disabled_accounts  = []   # disabled — excluded from risk count

    for u in report:
        upn      = u.get("userPrincipalName","")
        name     = u.get("userDisplayName") or upn
        methods  = set(u.get("methodsRegistered") or [])
        is_reg   = u.get("isMfaRegistered", False)
        ut       = user_type = "member"

        meta = user_meta.get(upn.lower(), {})
        ut   = meta.get("userType","member")
        enabled = meta.get("accountEnabled", True)

        if not enabled:
            disabled_accounts.append(name)
            continue

        acct_class = _classify_account(upn, name, ut)

        if acct_class == "guest":
            guest_accounts.append(f"{name} ({upn})")
        elif acct_class == "resource":
            resource_accounts.append(f"{name} ({upn})")
        elif acct_class == "service":
            service_accounts.append(f"{name} ({upn})")
        else:
            # Human account
            if is_reg:
                human_mfa_reg.append(name)
                has_strong = bool(methods & STRONG_METHODS)
                has_weak   = bool(methods & WEAK_METHODS)
                if has_strong:
                    human_strong.append(name)
                elif has_weak:
                    human_weak_only.append(name)
            else:
                human_mfa_missing.append(f"{name} ({upn})")

    # ── Metrics ───────────────────────────────────────────────────────────────
    human_total = len(human_mfa_reg) + len(human_mfa_missing)
    a.metrics.update({
        "mfa_human_total":         human_total,
        "mfa_human_registered":    len(human_mfa_reg),
        "mfa_human_missing":       len(human_mfa_missing),
        "mfa_human_strong":        len(human_strong),
        "mfa_human_weak_only":     len(human_weak_only),
        "mfa_guest_accounts":      len(guest_accounts),
        "mfa_service_accounts":    len(service_accounts),
        "mfa_resource_accounts":   len(resource_accounts),
        "mfa_disabled_excluded":   len(disabled_accounts),
        # Legacy keys for report display compatibility
        "mfa_registered":          len(human_mfa_reg),
        "mfa_not_registered":      len(human_mfa_missing),
    })

    # ── Findings ──────────────────────────────────────────────────────────────

    # Human users without MFA — the real risk number
    # NOTE: This finding may be suppressed by module 17 if it runs successfully,
    # as module 17 has authoritative data from the live credential store.
    if human_total > 0:
        pct = len(human_mfa_reg) / human_total * 100
        sev = ("CRITICAL" if pct < 50 else
               "HIGH"     if pct < 80 else
               "MEDIUM"   if pct < 95 else None)
        if sev:
            a.finding(sev, "MFA & Auth Methods",
                f"Human User MFA Adoption {pct:.0f}% "
                f"({len(human_mfa_missing)} of {human_total} human users unregistered)",
                f"MFA adoption calculated for interactive human accounts only — "
                f"service accounts ({len(service_accounts)}), resource/room accounts "
                f"({len(resource_accounts)}), guests ({len(guest_accounts)}), and "
                f"disabled accounts ({len(disabled_accounts)}) are excluded from this count. "
                f"Enforce MFA registration via a CA policy targeting 'All Users' "
                f"with appropriate exclusions for service accounts.",
                len(human_mfa_missing), human_mfa_missing)
            # Flag for module 17 to know this finding was emitted
            a.metrics["mfa_m09_adoption_finding_emitted"] = True

    # Weak MFA — humans only
    if human_weak_only:
        a.finding("MEDIUM", "MFA & Auth Methods",
            f"Human Users with Weak MFA Only — SMS/Voice/Email ({len(human_weak_only)})",
            "These human accounts use only phishable MFA methods (SMS, voice call, email OTP). "
            "Vulnerable to SIM swapping and SS7 attacks. Migrate to Microsoft Authenticator "
            "push notifications, TOTP apps, or FIDO2 hardware security keys.",
            len(human_weak_only), human_weak_only)

    # SMS-only subset (subset of weak — flag separately as weakest)
    sms_only = [
        u.get("userDisplayName", u.get("userPrincipalName",""))
        for u in report
        if set(u.get("methodsRegistered") or []) <= {"mobilePhone","officeMobile"}
        and u.get("isMfaRegistered")
        and _classify_account(
            u.get("userPrincipalName",""),
            u.get("userDisplayName",""),
            user_meta.get(u.get("userPrincipalName","").lower(),{}).get("userType","member")
        ) == "human"
    ]
    if sms_only:
        a.finding("MEDIUM", "MFA & Auth Methods",
            f"Human Users with SMS/Voice as Only MFA Method ({len(sms_only)})",
            "SMS MFA is the weakest registered method. SIM swapping or SS7 attacks "
            "can bypass it entirely. These users should register Microsoft Authenticator "
            "or a FIDO2 hardware key as their primary method.",
            len(sms_only), sms_only)

    # Service accounts — note separately, different remediation
    if service_accounts:
        a.finding("MEDIUM", "MFA & Auth Methods",
            f"Service / Automation Accounts Without MFA ({len(service_accounts)})",
            "Service accounts cannot register MFA interactively. They must be secured via: "
            "(1) Conditional Access policies blocking interactive sign-in or restricting "
            "to known IPs/managed devices, (2) certificate-based auth or managed identities "
            "where possible, (3) workload identity federation for app-to-app scenarios. "
            "Do NOT enrol service accounts in MFA registration campaigns.",
            len(service_accounts), service_accounts)

    # Resource/room accounts — informational
    if resource_accounts:
        a.finding("INFO", "MFA & Auth Methods",
            f"Resource / Room Accounts Present ({len(resource_accounts)})",
            "Room, equipment, and shared mailbox accounts are non-interactive by design "
            "and do not require MFA. Ensure they are secured via CA policy blocking "
            "interactive sign-in, have complex passwords, and are not assigned "
            "privileged roles.",
            len(resource_accounts), resource_accounts)

    # Guests — different risk profile
    if guest_accounts:
        a.finding("INFO", "MFA & Auth Methods",
            f"Guest Accounts in MFA Report ({len(guest_accounts)})",
            "Guest accounts authenticate via their home tenant's MFA policies, not yours. "
            "You cannot enforce MFA registration on guests directly — use Conditional "
            "Access to require MFA claims from guest sign-ins regardless of home tenant policy.",
            len(guest_accounts), guest_accounts)

    # FIDO2 / passwordless
    fido2_users = [
        u.get("userDisplayName") or u.get("userPrincipalName","")
        for u in report
        if "fido2SecurityKey" in (u.get("methodsRegistered") or [])
        and _classify_account(
            u.get("userPrincipalName",""),
            u.get("userDisplayName",""),
            user_meta.get(u.get("userPrincipalName","").lower(),{}).get("userType","member")
        ) == "human"
    ]
    passkey_users = [
        u.get("userDisplayName") or u.get("userPrincipalName","")
        for u in report
        if "microsoftAuthenticatorPasswordless" in (u.get("methodsRegistered") or [])
        and _classify_account(
            u.get("userPrincipalName",""),
            u.get("userDisplayName",""),
            user_meta.get(u.get("userPrincipalName","").lower(),{}).get("userType","member")
        ) == "human"
    ]
    a.metrics["fido2_users"]   = len(fido2_users)
    a.metrics["passkey_users"] = len(passkey_users)

    if len(fido2_users) + len(passkey_users) == 0:
        a.finding("INFO", "MFA & Auth Methods",
            "No Phishing-Resistant Authentication Registered",
            "No human users are registered with phishing-resistant methods "
            "(FIDO2 security keys or Microsoft Authenticator Passwordless). "
            "Pilot with privileged accounts first — Global Admins, Privileged Role Admins, "
            "and Security Admins should use phishing-resistant MFA.")
    else:
        a.finding("INFO", "MFA & Auth Methods",
            f"Phishing-Resistant Auth: FIDO2={len(fido2_users)}, Passwordless={len(passkey_users)}",
            "Human users registered with phishing-resistant authentication. "
            "Expand adoption, prioritising privileged accounts.",
            len(fido2_users) + len(passkey_users),
            fido2_users + passkey_users)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 9 — ASSESSMENT MODULES 10–12  (Extended)
# ─────────────────────────────────────────────────────────────────────────────

def _audit_actor(event: dict) -> str:
    init = event.get("initiatedBy") or {}
    user = init.get("user") or {}
    app  = init.get("app") or {}
    return (user.get("userPrincipalName")
            or user.get("displayName")
            or (f"[App] {app['displayName']}" if app.get("displayName") else None)
            or "Unknown")

def _audit_target(event: dict) -> str:
    targets = event.get("targetResources") or []
    if not targets:
        return "Unknown"
    t = targets[0]
    return (t.get("displayName") or t.get("userPrincipalName") or t.get("id","Unknown"))


def module_10_app_roles(a: Assessment):
    print("  [10/17] App Role Analysis — Permissions, Combos & Audit History...")
    client = a.client

    # Resolve the Microsoft Graph SP in this tenant
    graph_sp_result = client.get(
        f"{GRAPH_BASE}/servicePrincipals",
        params={"$filter": f"appId eq '{MS_GRAPH_SP_APPID}'", "$select": "id,appRoles"}
    )
    graph_sp_id  = None
    graph_roles  = {}  # role id → permission value string
    if graph_sp_result and graph_sp_result.get("value"):
        graph_sp_id = graph_sp_result["value"][0].get("id")
        for r in graph_sp_result["value"][0].get("appRoles", []):
            graph_roles[r["id"]] = r.get("value", "")

    # Collect all app role grants targeting Microsoft Graph
    all_grants = []
    if graph_sp_id:
        grants = client.get_all(
            f"{GRAPH_BASE}/servicePrincipals/{graph_sp_id}/appRoleAssignedTo",
            params={"$top": "999"}
        )
        for g in grants:
            all_grants.append({
                "grantee":    g.get("principalDisplayName", "Unknown"),
                "permission": graph_roles.get(g.get("appRoleId",""), g.get("appRoleId","")),
                "type":       g.get("principalType",""),
                "created":    (g.get("createdDateTime",""))[:10],
            })

    a.metrics["graph_app_role_grants"] = len(all_grants)

    # Map SP → permissions granted
    sp_perms = defaultdict(set)
    for g in all_grants:
        sp_perms[g["grantee"]].add(g["permission"])

    # Flag individual dangerous permissions
    danger_by_sev = defaultdict(list)
    for sp, perms in sp_perms.items():
        for perm in perms:
            if perm in DANGEROUS_APP_PERMS:
                sev, desc = DANGEROUS_APP_PERMS[perm]
                danger_by_sev[sev].append(f"{sp} — {perm}: {desc}")

    a.metrics["dangerous_permission_grants"] = sum(len(v) for v in danger_by_sev.values())

    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        items = danger_by_sev[sev]
        if items:
            a.finding(sev, "App Role Analysis",
                f"{sev}-Risk Application Permissions Granted ({len(items)})",
                "Application permissions act without a signed-in user and cannot be MFA-protected. "
                "Each should be individually justified with a documented business need.",
                len(items), items)

    # Dangerous permission combinations
    critical_combos, high_combos = [], []
    for sp, perms in sp_perms.items():
        for combo_set, sev, label, explanation in DANGEROUS_COMBOS:
            if combo_set.issubset(perms):
                entry = f"{sp}: {label} — {explanation}"
                if sev == "CRITICAL":
                    critical_combos.append(entry)
                else:
                    high_combos.append(entry)

    if critical_combos:
        a.finding("CRITICAL", "App Role Analysis",
            f"Critical Permission Combinations Detected ({len(critical_combos)} apps)",
            "These permission combinations enable high-impact attacks including BEC, "
            "lateral movement, and full tenant compromise.",
            len(critical_combos), critical_combos)

    if high_combos:
        a.finding("HIGH", "App Role Analysis",
            f"High-Risk Permission Combinations ({len(high_combos)} apps)",
            "These combinations significantly expand attacker capability if the app is compromised.",
            len(high_combos), high_combos)

    # Over-privileged SPs (3+ dangerous permissions)
    over_priv = [
        f"{sp}: {', '.join(sorted(perms & set(DANGEROUS_APP_PERMS.keys())))}"
        for sp, perms in sp_perms.items()
        if len(perms & set(DANGEROUS_APP_PERMS.keys())) >= 3
    ]
    if over_priv:
        a.finding("HIGH", "App Role Analysis",
            f"Over-Privileged Service Principals — 3+ Dangerous Permissions ({len(over_priv)})",
            "Violates least-privilege. Each permission must be individually justified.",
            len(over_priv), over_priv)

    # Audit log: recent consent/role events
    audit_events = client.get_all(
        f"{GRAPH_BASE}/auditLogs/directoryAudits",
        params={
            "$filter": (
                f"activityDateTime ge {a.since} and ("
                f"activityDisplayName eq 'Consent to application' or "
                f"activityDisplayName eq 'Add app role assignment to service principal' or "
                f"activityDisplayName eq 'Add delegated permission grant' or "
                f"activityDisplayName eq 'Add service principal' or "
                f"activityDisplayName eq 'Add service principal credentials' or "
                f"activityDisplayName eq 'Add app role assignment')"
            ),
            "$select": "activityDateTime,activityDisplayName,initiatedBy,targetResources,result",
            "$top": "999",
        },
        max_pages=5
    )

    consents     = [e for e in audit_events if "Consent" in e.get("activityDisplayName","")]
    role_assigns = [e for e in audit_events if "role assignment" in e.get("activityDisplayName","").lower()]
    new_sps      = [e for e in audit_events if e.get("activityDisplayName","") == "Add service principal"]
    sp_creds     = [e for e in audit_events if "credentials" in e.get("activityDisplayName","").lower()]
    delegated    = [e for e in audit_events if "delegated permission" in e.get("activityDisplayName","").lower()]

    a.metrics.update({
        "recent_consent_grants":    len(consents),
        "recent_role_assignments":  len(role_assigns),
        "recent_new_sps":           len(new_sps),
        "sp_credential_additions":  len(sp_creds),
    })

    if consents:
        items = [f"{(e.get('activityDateTime',''))[:10]} — {_audit_actor(e)} → {_audit_target(e)}"
                 for e in consents[:20]]
        a.finding("HIGH", "App Role Analysis",
            f"OAuth Consent Grants in Last {a.days_back} Days ({len(consents)})",
            "Each consent grant should map to a known app deployment. "
            "OAuth phishing attacks use consent grants to achieve persistent BEC-capable access.",
            len(consents), items)

    if role_assigns:
        items = [f"{(e.get('activityDateTime',''))[:10]} — {_audit_actor(e)} → {_audit_target(e)}"
                 for e in role_assigns[:20]]
        a.finding("HIGH", "App Role Analysis",
            f"App Role Assignments in Last {a.days_back} Days ({len(role_assigns)})",
            "Verify each assignment has a documented business justification. "
            "Unauthorized app role assignments are a common post-compromise persistence technique.",
            len(role_assigns), items)

    if sp_creds:
        items = [f"{(e.get('activityDateTime',''))[:10]} — {_audit_actor(e)} → {_audit_target(e)}"
                 for e in sp_creds[:20]]
        a.finding("HIGH", "App Role Analysis",
            f"Service Principal Credential Additions ({len(sp_creds)})",
            "Adding credentials to existing SPs is a post-compromise persistence technique "
            "(app hijacking / Golden SAML). Each must be reviewed against expected change records.",
            len(sp_creds), items)

    if new_sps:
        items = [f"{(e.get('activityDateTime',''))[:10]} — {_audit_actor(e)} created: {_audit_target(e)}"
                 for e in new_sps[:20]]
        a.finding("MEDIUM", "App Role Analysis",
            f"New Service Principals Created in Last {a.days_back} Days ({len(new_sps)})",
            "Review each new SP for expected business context and verify the creator's intent.",
            len(new_sps), items)

    if delegated:
        items = [f"{_audit_actor(e)} → {_audit_target(e)}" for e in delegated]
        a.finding("HIGH", "App Role Analysis",
            f"Delegated Permission Grants in Last {a.days_back} Days ({len(delegated)})",
            "Delegated grants expand what apps can do on behalf of users. "
            "Review for OAuth phishing vs legitimate app deployments.",
            len(delegated), items)

    # Orphaned apps (no owner) — sample first 100
    apps = client.get_all(f"{GRAPH_BASE}/applications",
        params={"$select": "id,displayName", "$top": "100"}, max_pages=1)
    orphaned = []
    for app in apps[:100]:
        owners = client.get(f"{GRAPH_BASE}/applications/{app['id']}/owners",
                            params={"$select": "id", "$top": "1"})
        if owners and not owners.get("value"):
            orphaned.append(app.get("displayName","Unknown"))

    if orphaned:
        a.finding("MEDIUM", "App Role Analysis",
            f"Orphaned App Registrations — No Owner ({len(orphaned)} of {len(apps)} checked)",
            "Apps without owners lack accountability. Assign owners to all app registrations.",
            len(orphaned), orphaned)


def module_11_defender(a: Assessment):
    print(f"  [11/17] Microsoft Defender Alerts (last {a.days_back} days)...")
    alerts = a.client.get_all(
        f"{GRAPH_BASE}/security/alerts_v2",
        params={
            "$filter":  f"createdDateTime ge {a.since}",
            "$select":  "id,title,severity,status,category,serviceSource,detectionSource,"
                        "createdDateTime,description,recommendedActions,alertWebUrl,"
                        "actorDisplayName,threatDisplayName,classification,determination",
            "$top":     "999",
            "$orderby": "createdDateTime desc",
        },
        max_pages=10
    )

    if alerts is None:
        a.finding("INFO", "Defender Alerts",
            "Defender Alerts Require Admin-Consented SecurityAlert.Read.All",
            "The Defender alerts endpoint requires SecurityAlert.Read.All which must be "
            "admin-consented at the application level — it is not pre-consented on the "
            "Microsoft Graph Command Line Tools app. This scope cannot be added without "
            "granting consent on a shared enterprise app, creating tenant-wide exposure. "
            "Review Defender alerts directly in the Microsoft Defender portal: "
            "security.microsoft.com → Incidents & Alerts → Alerts.")
        return

    if not alerts:
        a.finding("INFO", "Defender Alerts",
            f"No Defender Alerts in Last {a.days_back} Days",
            "No detections returned. Verify Defender products are deployed and licensed.")
        return

    by_severity  = defaultdict(list)
    by_service   = defaultdict(int)
    unresolved   = []
    cred_alerts  = []
    identity_alerts = []

    CRED_KEYWORDS = {
        "credential","pass-the-hash","pass-the-ticket","kerberoast","brute force",
        "password spray","golden ticket","silver ticket","mimikatz","lsass",
        "ntlm relay","as-rep","kerberos","dcsync","dcshadow","overpass-the-hash",
        "forged","replication","suspicious authentication",
    }

    for al in alerts:
        sev     = (al.get("severity") or "unknown").lower()
        service = al.get("serviceSource","Unknown")
        status  = (al.get("status") or "").lower()
        title   = al.get("title","Untitled")
        dt      = (al.get("createdDateTime") or "")[:10]
        actor   = al.get("actorDisplayName","")

        by_severity[sev].append(al)
        by_service[service] += 1

        if status not in ("resolved",):
            unresolved.append(al)

        if any(kw in title.lower() for kw in CRED_KEYWORDS):
            cred_alerts.append(al)

        if service in ("microsoftDefenderForIdentity","azureAdIdentityProtection",
                       "microsoftCloudAppSecurity"):
            identity_alerts.append(al)

    total = len(alerts)
    a.metrics.update({
        "defender_total_alerts":       total,
        "defender_critical_high":      len(by_severity["high"]) + len(by_severity["critical"]),
        "defender_active_unresolved":  len(unresolved),
        "defender_identity_alerts":    len(identity_alerts),
        "defender_credential_alerts":  len(cred_alerts),
    })

    # Unresolved high/critical
    unresolved_hc = [al for al in unresolved
                     if (al.get("severity") or "").lower() in ("high","critical")]
    if unresolved_hc:
        items = []
        for al in unresolved_hc[:20]:
            line = f"[{(al.get('severity','?')).upper()}] {al.get('title','')} " \
                   f"({al.get('serviceSource','')}, {(al.get('createdDateTime',''))[:10]})"
            if al.get("actorDisplayName"):
                line += f" — actor: {al['actorDisplayName']}"
            items.append(line)
        a.finding("CRITICAL", "Defender Alerts",
            f"Unresolved High/Critical Defender Alerts ({len(unresolved_hc)})",
            f"Immediate investigation required across: "
            f"{', '.join(sorted(set(al.get('serviceSource','') for al in unresolved_hc)))}.",
            len(unresolved_hc), items)

    # Credential-theft alerts
    if cred_alerts:
        items = [
            f"[{(al.get('severity','?')).upper()}] {al.get('title','')} "
            f"({al.get('serviceSource','')}, {(al.get('createdDateTime',''))[:10]})"
            for al in cred_alerts[:15]
        ]
        sev = "CRITICAL" if any(
            (al.get("severity") or "").lower() in ("high","critical") for al in cred_alerts
        ) else "HIGH"
        a.finding(sev, "Defender Alerts",
            f"Credential-Themed Defender Alerts ({len(cred_alerts)})",
            "Alerts matching credential theft TTPs: pass-the-hash, Kerberoasting, DCSync, "
            "LSASS access, golden/silver ticket, NTLM relay, password spray.",
            len(cred_alerts), items)

    # Identity & Cloud App alerts
    if identity_alerts:
        title_counts = defaultdict(int)
        for al in identity_alerts:
            title_counts[al.get("title","Untitled")] += 1
        items = [f"{t} × {c}" for t, c in
                 sorted(title_counts.items(), key=lambda x: x[1], reverse=True)]
        sev = "HIGH" if any(
            (al.get("severity") or "").lower() in ("high","critical") for al in identity_alerts
        ) else "MEDIUM"
        a.finding(sev, "Defender Alerts",
            f"Identity & Cloud App Security Alerts ({len(identity_alerts)})",
            "Alerts from Defender for Identity, Identity Protection, and Cloud App Security.",
            len(identity_alerts), items)

    # Threat actor attribution
    named_actors = [al for al in alerts if al.get("actorDisplayName")]
    if named_actors:
        actor_counts = defaultdict(int)
        for al in named_actors:
            actor_counts[al["actorDisplayName"]] += 1
        items = [f"{actor} ({count} alerts)" for actor, count in
                 sorted(actor_counts.items(), key=lambda x: x[1], reverse=True)]
        a.finding("HIGH", "Defender Alerts",
            f"Threat Actor Attribution ({len(named_actors)} attributed alerts)",
            "Defender has attributed alerts to named threat actors. "
            "Review each actor's known TTPs against your environment's exposure.",
            len(named_actors), items)

    # Source breakdown
    service_summary = ", ".join(
        f"{s}: {c}" for s, c in sorted(by_service.items(), key=lambda x: x[1], reverse=True)[:8]
    )
    a.finding("INFO", "Defender Alerts",
        f"Alert Sources — Last {a.days_back} Days (total: {total})",
        f"By source: {service_summary}",
        total)


def module_12_o365_abuse(a: Assessment):
    print(f"  [12/17] O365 / Exchange Credential Abuse & BEC Indicators...")
    client = a.client

    # ── Audit events: BEC-relevant Entra operations ──
    bec_events = client.get_all(
        f"{GRAPH_BASE}/auditLogs/directoryAudits",
        params={
            "$filter": (
                f"activityDateTime ge {a.since} and ("
                f"activityDisplayName eq 'Consent to application' or "
                f"activityDisplayName eq 'Add delegated permission grant' or "
                f"activityDisplayName eq 'Add app role assignment to service principal' or "
                f"activityDisplayName eq 'Add service principal credentials' or "
                f"activityDisplayName eq 'Reset user password' or "
                f"activityDisplayName eq 'Set user password' or "
                f"activityDisplayName eq 'Add member to role' or "
                f"activityDisplayName eq 'Remove member from role' or "
                f"activityDisplayName eq 'Delete service principal'"
                f")"
            ),
            "$select": "activityDateTime,activityDisplayName,initiatedBy,targetResources,result",
            "$top": "999",
        },
        max_pages=8
    )

    consents         = [e for e in bec_events if "Consent" in e.get("activityDisplayName","")]
    delegated_grants = [e for e in bec_events if "delegated permission" in e.get("activityDisplayName","").lower()]
    sp_cred_adds     = [e for e in bec_events if "credentials" in e.get("activityDisplayName","").lower()]
    pw_resets        = [e for e in bec_events if "password" in e.get("activityDisplayName","").lower()]
    role_adds        = [e for e in bec_events if e.get("activityDisplayName","") == "Add member to role"]
    role_removes     = [e for e in bec_events if e.get("activityDisplayName","") == "Remove member from role"]

    # ── Tenant-wide OAuth grants with mail scopes ──
    oauth_grants = client.get_all(
        f"{GRAPH_BASE}/oauth2PermissionGrants",
        params={"$filter": "consentType eq 'AllPrincipals'", "$top": "999"}
    )
    mail_kws = {"mail", "mailbox", "Mail.Read", "Mail.ReadWrite", "Mail.Send", "MailboxSettings", "ews"}
    dangerous_mail_grants = []
    for grant in (oauth_grants or []):
        scope = (grant.get("scope") or "").lower()
        if any(kw.lower() in scope for kw in mail_kws):
            cid = grant.get("clientId","")
            sp_info = client.get(f"{GRAPH_BASE}/servicePrincipals/{cid}",
                                  params={"$select":"displayName"})
            sp_name = (sp_info or {}).get("displayName", cid[:12])
            dangerous_mail_grants.append(f"{sp_name}: {grant.get('scope','')}")

    # ── Exchange Online sign-in patterns ──
    exchange_signins = client.get_all(
        f"{GRAPH_BASE}/auditLogs/signIns",
        params={
            "$filter": (
                f"createdDateTime ge {a.since} and "
                f"(appDisplayName eq 'Office 365 Exchange Online' or "
                f"appDisplayName eq 'Exchange Online') and "
                f"status/errorCode eq 0"
            ),
            "$select": "createdDateTime,userPrincipalName,ipAddress,clientAppUsed,"
                       "isInteractive,riskLevelAggregated",
            "$top": "500",
        },
        max_pages=3
    )

    legacy_exchange   = []
    risky_exchange    = []
    no_mfa_exchange   = []
    LEGACY_CLIENTS    = {"IMAP4","POP3","SMTP","MAPI","ExchangeActiveSync","Other clients"}

    for s in (exchange_signins or []):
        ca = s.get("clientAppUsed","")
        risk = (s.get("riskLevelAggregated") or "").lower()
        auth = s.get("authenticationRequirement","")  # beta-only field; always "" on v1.0 — no_mfa_exchange will be empty

        if ca in LEGACY_CLIENTS:
            legacy_exchange.append(
                f"{s.get('userPrincipalName','')} via {ca} from {s.get('ipAddress','')}"
            )
        if risk in ("high","medium"):
            risky_exchange.append(
                f"{s.get('userPrincipalName','')} risk={risk} from {s.get('ipAddress','')}"
            )
        if auth == "singleFactorAuthentication" and not s.get("isInteractive"):
            no_mfa_exchange.append(s.get("userPrincipalName",""))

    # ── Update metrics ──
    a.metrics.update({
        "bec_audit_events":       len(bec_events),
        "dangerous_mail_oauth":   len(dangerous_mail_grants),
        "oauth_consent_events":   len(consents),
        "admin_password_resets":  len(pw_resets),
        "legacy_exchange_signins":len(legacy_exchange),
        "role_additions":         len(role_adds),
    })

    # ── Report findings ──
    if dangerous_mail_grants:
        a.finding("CRITICAL", "O365 Credential Abuse",
            f"Tenant-Wide OAuth Grants with Mail Permissions ({len(dangerous_mail_grants)})",
            "Applications with AllPrincipals consent for mail permissions can access every mailbox "
            "in the organization — the primary BEC enabler. Each must be individually justified.",
            len(dangerous_mail_grants), dangerous_mail_grants)

    if consents:
        items = [
            f"{(e.get('activityDateTime',''))[:10]} — {_audit_actor(e)} consented to: {_audit_target(e)}"
            for e in consents[:20]
        ]
        a.finding("HIGH", "O365 Credential Abuse",
            f"OAuth App Consent Events in Last {a.days_back} Days ({len(consents)}) — BEC Risk",
            "Attackers use OAuth phishing to gain persistent mail access via consented apps, "
            "completely bypassing MFA. Verify each consent is a known, approved app.",
            len(consents), items)

    if delegated_grants:
        items = [f"{_audit_actor(e)} → {_audit_target(e)}" for e in delegated_grants]
        a.finding("HIGH", "O365 Credential Abuse",
            f"Delegated Permission Grants in Audit Log ({len(delegated_grants)})",
            "Delegated OAuth grants allow apps to act on behalf of users — "
            "review for OAuth phishing persistence.",
            len(delegated_grants), items)

    if sp_cred_adds:
        items = [
            f"{(e.get('activityDateTime',''))[:10]} — {_audit_actor(e)} → {_audit_target(e)}"
            for e in sp_cred_adds[:15]
        ]
        a.finding("HIGH", "O365 Credential Abuse",
            f"Service Principal Credential Additions ({len(sp_cred_adds)})",
            "Adding secrets/certs to existing SPs is a post-compromise persistence technique. "
            "Each addition must map to a known change request.",
            len(sp_cred_adds), items)

    if pw_resets:
        items = [
            f"{(e.get('activityDateTime',''))[:10]} — {_audit_actor(e)} reset: {_audit_target(e)}"
            for e in pw_resets[:20]
        ]
        a.finding("HIGH", "O365 Credential Abuse",
            f"Admin Password Resets in Last {a.days_back} Days ({len(pw_resets)})",
            "Admin-initiated resets may indicate account takeover response, insider abuse, "
            "or attacker-controlled account preparation. Verify each against change records.",
            len(pw_resets), items)

    if role_adds:
        items = [
            f"{(e.get('activityDateTime',''))[:10]} — {_audit_actor(e)} → {_audit_target(e)}"
            for e in role_adds[:20]
        ]
        a.finding("HIGH", "O365 Credential Abuse",
            f"Directory Role Additions in Last {a.days_back} Days ({len(role_adds)})",
            "Unexpected role grants are a key post-compromise persistence technique. "
            "Each must map to an approved change request.",
            len(role_adds), items)

    if legacy_exchange:
        unique_users = list(set(s.split(" via ")[0] for s in legacy_exchange))
        a.finding("HIGH", "O365 Credential Abuse",
            f"Legacy Protocol Sign-ins to Exchange ({len(legacy_exchange)} events, {len(unique_users)} users)",
            "IMAP, POP3, SMTP, MAPI, and EAS cannot enforce MFA. Attackers use credential dumps "
            "to authenticate directly to Exchange, bypassing all modern auth controls.",
            len(legacy_exchange), legacy_exchange)

    if risky_exchange:
        a.finding("HIGH", "O365 Credential Abuse",
            f"High/Medium Risk Sign-ins to Exchange Online ({len(risky_exchange)})",
            "Identity Protection flagged these Exchange sign-ins as risky. "
            "May indicate compromised credentials used for mail access.",
            len(risky_exchange), risky_exchange)

    if no_mfa_exchange:
        unique = list(set(no_mfa_exchange))
        a.finding("MEDIUM", "O365 Credential Abuse",
            f"Exchange Non-Interactive Sign-ins Without MFA ({len(no_mfa_exchange)} events)",
            "Service account or legacy app flows to Exchange without MFA. "
            "Ensure these are expected and covered by dedicated service account CA policies.",
            len(no_mfa_exchange), unique)


def module_13_pim(a: Assessment):
    """PIM eligible assignments and policy quality checks."""
    print("  [13/17] PIM — Eligible Assignments & Policy Quality...")
    client = a.client

    # Eligible (PIM-managed) role assignments
    eligible = client.get_all(
        f"{GRAPH_BETA}/roleManagement/directory/roleEligibilitySchedules",
        params={"$expand": "principal,roleDefinition", "$top": "999"}
    )

    # Currently active PIM-activated assignments
    active_pim = client.get_all(
        f"{GRAPH_BETA}/roleManagement/directory/roleAssignmentSchedules",
        params={"$expand": "principal,roleDefinition", "$top": "999"}
    )

    # PIM role management policies (approval, MFA, justification settings)
    policies = client.get_all(
        f"{GRAPH_BETA}/policies/roleManagementPolicies",
        params={"$filter": "scopeType eq 'DirectoryRole'", "$top": "999"}
    )

    # Policy assignments — which policy applies to which role
    policy_assignments = client.get_all(
        f"{GRAPH_BETA}/policies/roleManagementPolicyAssignments",
        params={"$filter": "scopeType eq 'DirectoryRole'", "$top": "999"}
    )


    if eligible is None:
        a.finding("INFO", "PIM",
            "PIM Eligible Assignments — Specific Scopes Required",
            "PIM data requires RoleEligibilitySchedule.Read.Directory which is not "
            "pre-consented on the Graph Command Line Tools app. "
            "Re-run with a Global Administrator account for full PIM coverage. "
            "Manual check: Entra admin center → Identity Governance → "
            "Privileged Identity Management → Azure AD roles → Assignments.")
        return

    # Map role definition id -> policy rules
    policy_map = {}  # roleDefinitionId -> {mfa_required, approval_required, justification_required}
    if policies:
        for pol in policies:
            rules = pol.get("rules", []) or []
            pol_id = pol.get("id", "")
            mfa_required          = False
            approval_required     = False
            justification_required= False
            for rule in rules:
                rt = rule.get("@odata.type", "")
                if "AuthenticationContext" in rt or "MfaEnforce" in rt:
                    mfa_required = True
                if "Approval" in rt:
                    setting = rule.get("setting", {}) or {}
                    if setting.get("isApprovalRequired") or setting.get("isApprovalRequiredForExtension"):
                        approval_required = True
                if "Justification" in rt:
                    if rule.get("isRequired"):
                        justification_required = True
            policy_map[pol_id] = {
                "mfa":           mfa_required,
                "approval":      approval_required,
                "justification": justification_required,
            }

    # Map policy assignment: roleDefinitionId -> policy settings
    role_policy = {}  # roleDefinitionId -> policy settings dict
    if policy_assignments:
        for pa in policy_assignments:
            role_def_id = pa.get("roleDefinitionId", "")
            pol_id      = pa.get("policyId", "")
            if pol_id in policy_map:
                role_policy[role_def_id] = policy_map[pol_id]

    # Analyse eligible assignments
    eligible_by_role  = defaultdict(list)
    no_expiry         = []
    high_priv_eligible= []

    for e in eligible:
        principal   = e.get("principal") or {}
        role_def    = e.get("roleDefinition") or {}
        name        = principal.get("displayName", "Unknown")
        role_name   = role_def.get("displayName", "Unknown")
        role_id     = e.get("roleDefinitionId", "")
        schedule    = e.get("scheduleInfo") or {}
        expiration  = schedule.get("expiration") or {}
        exp_type    = expiration.get("type", "")

        eligible_by_role[role_name].append(name)

        if exp_type in ("noExpiration", ""):
            no_expiry.append(f"{name} → {role_name} (no expiry)")

        if role_id in HIGH_PRIV_ROLES:
            high_priv_eligible.append(f"{name} → {role_name}")

    # PIM policy quality checks for high-privilege roles
    weak_policies = []
    for role_id, role_name in HIGH_PRIV_ROLES.items():
        if role_id in role_policy:
            pol = role_policy[role_id]
            issues = []
            if not pol["mfa"]:           issues.append("no MFA required on activation")
            if not pol["approval"]:      issues.append("no approval required")
            if not pol["justification"]: issues.append("no justification required")
            if issues:
                weak_policies.append(f"{role_name}: {', '.join(issues)}")

    # Currently active PIM activations
    active_now = []
    for act in (active_pim or []):
        principal = act.get("principal") or {}
        role_def  = act.get("roleDefinition") or {}
        status    = act.get("status", "")
        if status == "Provisioned":
            active_now.append(
                f"{principal.get('displayName','?')} → {role_def.get('displayName','?')}"
            )

    a.metrics["pim_eligible_assignments"] = len(eligible)
    a.metrics["pim_active_now"]           = len(active_now)
    a.metrics["pim_no_expiry"]            = len(no_expiry)

    if not eligible:
        a.finding("HIGH", "PIM",
            "No PIM Eligible Assignments Found",
            "All privileged role assignments appear to be permanent. PIM should be configured "
            "to enforce just-in-time access with MFA, justification, and approval for all "
            "high-privilege roles.",
            0)
    if eligible is not None:
        a.finding("INFO", "PIM",
            f"PIM Eligible Assignments: {len(eligible)} across {len(eligible_by_role)} roles",
            f"Active PIM activations right now: {len(active_now)}. "
            f"Roles with eligible assignments: {', '.join(list(eligible_by_role.keys())[:10])}",
            len(eligible))

    if no_expiry:
        a.finding("MEDIUM", "PIM",
            f"PIM Eligible Assignments with No Expiry ({len(no_expiry)})",
            "Eligible assignments without an expiry date are permanently eligible and never "
            "require re-certification. Set time-bound eligibility (e.g. 6–12 months) and "
            "require periodic access reviews.",
            len(no_expiry), no_expiry)

    if weak_policies:
        a.finding("HIGH", "PIM",
            f"Weak PIM Activation Policies on Privileged Roles ({len(weak_policies)})",
            "PIM activation policies for high-privilege roles are missing key controls. "
            "Each high-privilege role should require MFA on activation, business justification, "
            "and manager/peer approval.",
            len(weak_policies), weak_policies)

    if active_now:
        a.finding("MEDIUM", "PIM",
            f"Currently Active PIM Activations ({len(active_now)})",
            "These privileged roles are currently activated via PIM. Verify each is expected "
            "and that the activation window is appropriate.",
            len(active_now), active_now)


def module_14_mailbox_forwarding(a: Assessment):
    """Check ALL mailboxes for server-side forwarding and inbox rules.

    Uses the Exchange Online PowerShell module (Get-EXOMailbox, Get-InboxRule)
    via subprocess because the Graph API delegated permission MailboxSettings.Read
    only reads the calling user's own mailbox — it cannot enumerate other users'
    mailboxes regardless of scope consent.

    Requires the assessment account to be a member of the Exchange Online role
    group: Entra Assessment - Read Only (View-Only Recipients + View-Only
    Configuration + View-Only Audit Logs).

    Prompts the user for a separate Exchange Online device code login.
    Raw results are written to the evidence store before analysis.
    """
    import shutil, tempfile, os

    print("  [14/17] Mailbox Forwarding and Inbox Rules (Exchange Online PowerShell)...")

    # Check for ExchangeOnlineManagement module
    ps_exe = shutil.which("pwsh") or shutil.which("powershell")
    if not ps_exe:
        a.finding("INFO", "Mailbox Forwarding",
            "Mailbox Forwarding Check Skipped — PowerShell Not Found",
            "The ExchangeOnlineManagement PowerShell module is required for mailbox "
            "forwarding checks. Install PowerShell and the module, then re-run: "
            "Install-Module ExchangeOnlineManagement -Scope CurrentUser")
        return

    # Verify ExchangeOnlineManagement is installed
    try:
        result = subprocess.run(
            [ps_exe, "-NoProfile", "-NonInteractive", "-Command",
             "Get-Module -ListAvailable ExchangeOnlineManagement "
             "| Select-Object -First 1 Version | ConvertTo-Json"],
            capture_output=True, text=True, timeout=15
        )
        if "Version" not in result.stdout:
            a.finding("INFO", "Mailbox Forwarding",
                "Mailbox Forwarding Check Skipped — ExchangeOnlineManagement Not Installed",
                "Install the module and re-run: "
                "Install-Module ExchangeOnlineManagement -Scope CurrentUser")
            return
    except Exception:
        a.finding("INFO", "Mailbox Forwarding",
            "Mailbox Forwarding Check Skipped — Module Check Failed",
            "Could not verify ExchangeOnlineManagement module. "
            "Install with: Install-Module ExchangeOnlineManagement -Scope CurrentUser")
        return

    # Write results to a temp file so stdout is free for the device code prompt
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w")
    tmp_path = tmp.name
    tmp.close()
    ps_tmp = tmp_path.replace("\\", "\\\\")

    # Detect which Connect-ExchangeOnline device auth parameter this version supports
    # Newer versions use -UseDeviceAuthentication; older versions use -Device
    ps_script = f"""
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Import-Module ExchangeOnlineManagement -ErrorAction Stop

$connectParams = @{{ ShowBanner = $false; ErrorAction = 'Stop' }}
$paramNames = (Get-Command Connect-ExchangeOnline).Parameters.Keys
if ($paramNames -contains 'UseDeviceAuthentication') {{
    $connectParams['UseDeviceAuthentication'] = $true
}} elseif ($paramNames -contains 'Device') {{
    $connectParams['Device'] = $true
}}
Connect-ExchangeOnline @connectParams

$results = @{{
    collected_at = (Get-Date -Format 'o')
    mailboxes    = @()
    inbox_rules  = @()
    errors       = @()
}}

# Server-side forwarding via Get-EXOMailbox (REST-based, respects role group)
try {{
    $mailboxes = Get-EXOMailbox -ResultSize Unlimited `
        -RecipientTypeDetails UserMailbox `
        -PropertySets Delivery `
        -ErrorAction Stop
    foreach ($mb in $mailboxes) {{
        $entry = @{{
            upn          = $mb.UserPrincipalName
            name         = $mb.DisplayName
            smtp_forward = if ($mb.ForwardingSmtpAddress) {{ "$($mb.ForwardingSmtpAddress)" }} else {{ $null }}
            ad_forward   = if ($mb.ForwardingAddress)     {{ "$($mb.ForwardingAddress)" }}     else {{ $null }}
            keep_copy    = [bool]$mb.DeliverToMailboxAndForward
        }}
        $results.mailboxes += $entry
    }}
}} catch {{
    $results.errors += "Get-EXOMailbox: $_"
}}

# Per-mailbox inbox rules via Get-InboxRule
try {{
    $mbList = Get-EXOMailbox -ResultSize Unlimited `
        -RecipientTypeDetails UserMailbox `
        -ErrorAction Stop | Select-Object UserPrincipalName
    foreach ($mb in $mbList) {{
        try {{
            $rules = Get-InboxRule -Mailbox $mb.UserPrincipalName `
                -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            foreach ($rule in $rules) {{
                if ($rule.ForwardTo -or $rule.RedirectTo -or
                    $rule.ForwardAsAttachmentTo -or $rule.DeleteMessage -or
                    $rule.MoveToFolder) {{
                    $entry = @{{
                        mailbox        = $mb.UserPrincipalName
                        rule_name      = $rule.Name
                        enabled        = [bool]$rule.Enabled
                        forward_to     = if ($rule.ForwardTo)             {{ ($rule.ForwardTo -join '; ')             }} else {{ $null }}
                        redirect_to    = if ($rule.RedirectTo)            {{ ($rule.RedirectTo -join '; ')            }} else {{ $null }}
                        fwd_attach_to  = if ($rule.ForwardAsAttachmentTo) {{ ($rule.ForwardAsAttachmentTo -join '; ') }} else {{ $null }}
                        delete_message = [bool]$rule.DeleteMessage
                        move_to_folder = if ($rule.MoveToFolder) {{ "$($rule.MoveToFolder)" }} else {{ $null }}
                    }}
                    $results.inbox_rules += $entry
                }}
            }}
        }} catch {{
            # Skip individual mailbox errors silently
        }}
    }}
}} catch {{
    $results.errors += "Get-InboxRule enumeration: $_"
}}

$results | ConvertTo-Json -Depth 5 | Out-File -FilePath '{ps_tmp}' -Encoding utf8
Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
"""

    print()
    print("  " + "=" * 62)
    print("  EXCHANGE ONLINE AUTHENTICATION REQUIRED (Module 14)")
    print("  " + "=" * 62)
    print("  A device code will appear below.")
    print("  Open the URL and enter the code to continue.")
    print("  Required role: Entra Assessment - Read Only (Exchange)")
    print("  " + "=" * 62)
    print()

    raw_data = None
    try:
        # Run without capturing stdout so device code prompt is visible
        result = subprocess.run(
            [ps_exe, "-NoProfile", "-Command", ps_script],
            timeout=900
        )

        if not os.path.exists(tmp_path):
            a.finding("INFO", "Mailbox Forwarding",
                "Mailbox Check Failed — No Output Written",
                "PowerShell completed but wrote no output. Authentication may have "
                "failed or the Exchange role group has not yet propagated (allow "
                "15-30 minutes after role group creation).")
            return

        with open(tmp_path, "r", encoding="utf-8-sig") as f:
            raw_text = f.read().strip()

        if not raw_text:
            a.finding("INFO", "Mailbox Forwarding",
                "Mailbox Check Failed — Empty Output",
                "Authentication may have failed or the Exchange role group has not "
                "yet propagated. Allow 15-30 minutes after role group creation.")
            return

        # Find and parse the JSON portion
        for i, ch in enumerate(raw_text):
            if ch in ("{", "["):
                try:
                    raw_data = json.loads(raw_text[i:])
                    break
                except Exception:
                    pass

        if raw_data is None:
            a.finding("INFO", "Mailbox Forwarding",
                "Mailbox Check Failed — Output Could Not Be Parsed",
                f"Raw output preview: {raw_text[:200]}")
            return

    except subprocess.TimeoutExpired:
        a.finding("INFO", "Mailbox Forwarding",
            "Mailbox Check Timed Out",
            "The Exchange Online PowerShell session exceeded 5 minutes. "
            "Re-run with --skip-mailbox if the tenant is very large.")
        return
    except Exception as e:
        a.finding("INFO", "Mailbox Forwarding",
            "Mailbox Check Failed — Unexpected Error",
            str(e)[:300])
        return
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    # Write raw data to evidence store before analysis
    a.evidence.store_ps(
        "Get-EXOMailbox + Get-InboxRule (ExchangeOnlineManagement)",
        raw_data,
        "Mailbox Forwarding and Inbox Rules"
    )

    # ── Analyse results ──────────────────────────────────────────────────────
    mailboxes   = raw_data.get("mailboxes", []) or []
    inbox_rules = raw_data.get("inbox_rules", []) or []
    errors      = raw_data.get("errors", []) or []

    EXTERNAL_DOMAINS = set(d.lower() for d in (a.tenant.get("domains") or []))
    JUNK_FOLDERS     = {"deleteditems", "junkemail", "recoverableitemsdeletions",
                        "archive", "trash", "deleted items"}

    # Server-side forwarding
    smtp_forwarders = [m for m in mailboxes if m.get("smtp_forward")]
    ad_forwarders   = [m for m in mailboxes if m.get("ad_forward")]

    # Inbox rule classification
    external_fwd_rules = []
    internal_fwd_rules = []
    delete_rules       = []
    hide_rules         = []

    for rule in inbox_rules:
        mailbox   = rule.get("mailbox", "")
        rule_name = rule.get("rule_name", "Unnamed")
        enabled   = rule.get("enabled", True)
        suffix    = "" if enabled else " [DISABLED]"

        # Forwarding rules — split external vs internal
        fwd_targets = " ".join(filter(None, [
            rule.get("forward_to"),
            rule.get("redirect_to"),
            rule.get("fwd_attach_to"),
        ]))
        if fwd_targets:
            # Check if any target address is external
            is_external = False
            for part in fwd_targets.split(";"):
                part = part.strip()
                if "@" in part:
                    domain = part.split("@")[-1].lower().rstrip("]").rstrip('"')
                    if domain and domain not in EXTERNAL_DOMAINS:
                        is_external = True
                        break
            entry = f"{mailbox} — '{rule_name}' → {fwd_targets}{suffix}"
            if is_external:
                external_fwd_rules.append(entry)
            else:
                internal_fwd_rules.append(entry)

        # Delete rules
        if rule.get("delete_message"):
            delete_rules.append(
                f"{mailbox} — '{rule_name}' DELETES matching emails{suffix}"
            )

        # Move to junk/deleted
        move_folder = (rule.get("move_to_folder") or "").lower()
        if move_folder and any(jf in move_folder for jf in JUNK_FOLDERS):
            hide_rules.append(
                f"{mailbox} — '{rule_name}' moves to {rule.get('move_to_folder')}{suffix}"
            )

    # ── Metrics ──────────────────────────────────────────────────────────────
    a.metrics["mailboxes_checked"]      = len(mailboxes)
    a.metrics["mailboxes_skipped"]      = 0
    a.metrics["external_forwarders"]    = len(smtp_forwarders) + len(external_fwd_rules)
    a.metrics["suspicious_inbox_rules"] = len(internal_fwd_rules)
    a.metrics["email_hiding_rules"]     = len(delete_rules) + len(hide_rules)

    # ── Findings ─────────────────────────────────────────────────────────────
    if smtp_forwarders:
        a.finding("CRITICAL", "Mailbox Forwarding",
            f"Server-Side SMTP Forwarding Configured ({len(smtp_forwarders)} mailboxes)",
            "ForwardingSmtpAddress silently copies or redirects all inbound email to an "
            "external address at the server level. This persists through password resets "
            "and MFA changes and is the most reliable BEC persistence mechanism. "
            "Cannot be seen by the mailbox owner in Outlook.",
            len(smtp_forwarders),
            [f"{m['upn']} → {m['smtp_forward']}"
             + (" (keeps copy)" if m.get("keep_copy") else " (redirects only)")
             for m in smtp_forwarders])

    if ad_forwarders:
        a.finding("HIGH", "Mailbox Forwarding",
            f"AD-Based Mailbox Forwarding ({len(ad_forwarders)} mailboxes)",
            "ForwardingAddress routes mail to an internal or mail-enabled external "
            "object. Review whether each is intentional and documented.",
            len(ad_forwarders),
            [f"{m['upn']} → {m['ad_forward']}" for m in ad_forwarders])

    if external_fwd_rules:
        a.finding("CRITICAL", "Mailbox Forwarding",
            f"Inbox Rules Forwarding to External Addresses ({len(external_fwd_rules)} rules)",
            "Inbox rules forwarding or redirecting email to external addresses are a "
            "primary BEC data exfiltration technique. Each must be verified as "
            "intentional and business-justified. Consider blocking auto-forwarding "
            "to external domains via an Exchange transport rule.",
            len(external_fwd_rules), external_fwd_rules)

    if delete_rules:
        a.finding("HIGH", "Mailbox Forwarding",
            f"Inbox Rules That Delete Email ({len(delete_rules)} rules)",
            "Delete rules suppress email from the mailbox owner. Attackers use these "
            "to hide wire transfer replies, security alert notifications, and MFA "
            "messages. Each should be verified as a legitimate user preference.",
            len(delete_rules), delete_rules)

    if hide_rules:
        a.finding("MEDIUM", "Mailbox Forwarding",
            f"Inbox Rules Moving Email to Junk or Deleted ({len(hide_rules)} rules)",
            "Rules moving email to junk or deleted folders can obscure BEC activity "
            "from the mailbox owner. Verify each as a legitimate user preference.",
            len(hide_rules), hide_rules)

    if internal_fwd_rules:
        a.finding("LOW", "Mailbox Forwarding",
            f"Internal Forwarding Rules ({len(internal_fwd_rules)} rules)",
            "Forwarding rules within the tenant may be legitimate delegation. "
            "Review for account sharing or unauthorized monitoring.",
            len(internal_fwd_rules), internal_fwd_rules)

    if errors:
        a.finding("INFO", "Mailbox Forwarding",
            f"Collection Errors ({len(errors)})",
            "Some mailbox data could not be collected. May indicate permission gaps "
            "or mailboxes without Exchange licenses.",
            len(errors), errors)

    if (not smtp_forwarders and not external_fwd_rules and
            not delete_rules and len(mailboxes) > 0):
        a.finding("INFO", "Mailbox Forwarding",
            f"No External Forwarding or Deletion Rules Found ({len(mailboxes)} mailboxes checked)",
            "No server-side forwarding or suspicious inbox rule patterns detected.",
            len(mailboxes))

    print(f"      → {len(mailboxes)} mailboxes checked, "
          f"{len(smtp_forwarders)} SMTP forwarders, "
          f"{len(external_fwd_rules)} external forward rules, "
          f"{len(delete_rules)} delete rules")


def module_15_signin_behavioral(a: Assessment):
    """Behavioral sign-in analysis: off-hours, IP diversity, SharePoint geo."""
    print("  [15/17] Sign-in Behavioral Analysis...")
    client = a.client

    # Brief pause after Exchange module to let Graph session settle
    # (token/session state can cause silent empty returns on auditLogs/signIns)
    time.sleep(2)

    all_signins = client.get_all(
        f"{GRAPH_BASE}/auditLogs/signIns",
        params={
            "$filter":  f"createdDateTime ge {a.since} and status/errorCode eq 0",
            "$select":  "createdDateTime,userPrincipalName,appDisplayName,"
                        "ipAddress,location,clientAppUsed,isInteractive",
            "$top":     "999",
            # NOTE: No $orderby — auditLogs/signIns silently returns empty with $orderby+$filter
        },
        max_pages=10
    )

    # Retry once if empty — auditLogs/signIns can return empty under throttling or token timing
    if not all_signins:
        print("      → Sign-in query returned empty, retrying after brief delay...")
        time.sleep(5)
        all_signins = client.get_all(
            f"{GRAPH_BASE}/auditLogs/signIns",
            params={
                "$filter":  f"createdDateTime ge {a.since} and status/errorCode eq 0",
                "$select":  "createdDateTime,userPrincipalName,appDisplayName,"
                            "ipAddress,location,clientAppUsed,isInteractive",
                "$top":     "999",
            },
            max_pages=10
        )

    if not all_signins:
        a.finding("INFO", "Behavioral Analysis",
            "Sign-in Behavioral Analysis Skipped",
            "No sign-in data available after retry. Requires AuditLog.Read.All and admin consent. "
            "This can also occur due to Graph API throttling or token timing issues.")
        return

    from collections import defaultdict

    # ── Off-hours authentication ──────────────────────────────────────────────
    # Business hours: 6am–10pm local (we use UTC as proxy — good enough for patterns)
    off_hours_by_user = defaultdict(list)
    for s in all_signins:
        dt_str = s.get("createdDateTime","")
        if not dt_str:
            continue
        try:
            dt = datetime.fromisoformat(dt_str.replace("Z","+00:00"))
            hour    = dt.hour
            weekday = dt.weekday()  # 0=Mon, 6=Sun
            is_weekend   = weekday >= 5
            is_late_night = hour < 6 or hour >= 22
            if is_weekend or is_late_night:
                upn = s.get("userPrincipalName","")
                off_hours_by_user[upn].append(
                    dt.strftime("%Y-%m-%d %H:%M")
                )
        except Exception:
            pass

    # Flag users with 5+ off-hours sign-ins
    heavy_offhours = [
        (upn, times) for upn, times in off_hours_by_user.items()
        if len(times) >= 5
    ]
    total_offhours = sum(len(t) for t in off_hours_by_user.values())
    a.metrics["off_hours_events"]    = total_offhours
    a.metrics["off_hours_users"]     = len(heavy_offhours)

    if heavy_offhours:
        heavy_offhours.sort(key=lambda x: len(x[1]), reverse=True)
        items = []
        for upn, times in heavy_offhours[:15]:
            sample = ", ".join(times[:4])
            items.append(f"{upn}: {len(times)} off-hours sign-ins at: {sample}")
        a.finding("LOW", "Behavioral Analysis",
            f"Off-Hours Authentication Activity ({total_offhours} events, {len(heavy_offhours)} users)",
            "Successful sign-ins outside business hours (10pm–6am or weekends) from users "
            "with 5+ events. While some may be legitimate, review for unauthorized access "
            "patterns — especially from accounts not expected to work outside hours.",
            len(heavy_offhours), items)

    # ── High IP diversity per user ─────────────────────────────────────────────
    ips_by_user     = defaultdict(set)
    ip_locs_by_user = defaultdict(list)
    for s in all_signins:
        upn = s.get("userPrincipalName","")
        ip  = s.get("ipAddress","")
        loc = s.get("location") or {}
        city    = loc.get("city","")
        country = _country_name(loc.get("countryOrRegion",""))
        if upn and ip:
            ips_by_user[upn].add(ip)
            loc_str = f"{city}, {country}".strip(", ")
            if loc_str and loc_str not in ip_locs_by_user[upn]:
                ip_locs_by_user[upn].append(loc_str)

    high_diversity = [
        (upn, ips, ip_locs_by_user[upn])
        for upn, ips in ips_by_user.items()
        if len(ips) >= 10
    ]
    a.metrics["high_ip_diversity_users"] = len(high_diversity)

    if high_diversity:
        high_diversity.sort(key=lambda x: len(x[1]), reverse=True)
        items = []
        for upn, ips, locs in high_diversity[:15]:
            sorted_ips = sorted(ips)
            ip_sample  = ", ".join(sorted_ips[:10])
            ip_tail    = f" … +{len(ips) - 10} more" if len(ips) > 10 else ""
            loc_sample = ", ".join(locs[:6])
            loc_tail   = f" … +{len(locs) - 6} more" if len(locs) > 6 else ""
            items.append(
                f"{upn} ({len(ips)} IPs, {len(locs)} locations)\n"
                f"               IPs: {ip_sample}{ip_tail}\n"
                f"               Locations: {loc_sample}{loc_tail}"
            )
        a.finding("MEDIUM", "Behavioral Analysis",
            f"High IP Address Diversity ({len(high_diversity)} users with 10+ IPs)",
            "Users authenticating from 10+ distinct IPs may indicate credential sharing, "
            "VPN rotation, or compromised credentials used by multiple actors simultaneously.",
            len(high_diversity), items)

    # ── SharePoint multi-location access ──────────────────────────────────────
    sp_locs_by_user = defaultdict(set)
    for s in all_signins:
        app = (s.get("appDisplayName") or "").lower()
        if "sharepoint" not in app and "onedrive" not in app:
            continue
        upn = s.get("userPrincipalName","")
        loc = s.get("location") or {}
        city    = loc.get("city","")
        country = _country_name(loc.get("countryOrRegion",""))
        loc_str = f"{city}, {country}".strip(", ")
        if upn and loc_str:
            sp_locs_by_user[upn].add(loc_str)

    sp_multi = [
        (upn, sorted(locs))
        for upn, locs in sp_locs_by_user.items()
        if len(locs) >= 3
    ]
    a.metrics["sharepoint_multi_location_users"] = len(sp_multi)

    if sp_multi:
        items = [
            f"{upn}: {len(locs)} locations — {', '.join(locs[:6])}"
            + (f" … +{len(locs) - 6} more" if len(locs) > 6 else "")
            for upn, locs in sorted(sp_multi, key=lambda x: len(x[1]), reverse=True)[:15]
        ]
        a.finding("LOW", "Behavioral Analysis",
            f"SharePoint Access from Multiple Locations ({len(sp_multi)} users)",
            "Users accessing SharePoint from 3+ distinct geographic locations. "
            "While common for traveling staff, verify these patterns are expected — "
            "unexpected location diversity may indicate credential compromise.",
            len(sp_multi), items)


def module_16_dns_and_user_hygiene(a: Assessment):
    """SPF/DKIM/DMARC DNS checks + inactive user and service account analysis."""
    print("  [16/17] DNS Email Security & Advanced User Hygiene...")
    import socket
    import re

    # ── SPF / DKIM / DMARC via DNS TXT lookups ───────────────────────────────
    domains = [
        d for d in (a.tenant.get("domains") or [])
        if not d.endswith(".onmicrosoft.com")
    ]

    dns_findings = []
    for domain in domains:
        spf_ok     = False
        dkim_ok    = False
        dmarc_ok   = False
        dmarc_policy = "none"

        # SPF
        try:
            import subprocess
            result = subprocess.run(
                ["nslookup", "-type=TXT", domain],
                capture_output=True, text=True, timeout=10
            )
            if "v=spf1" in result.stdout.lower():
                spf_ok = True
        except Exception:
            pass

        # DMARC
        try:
            result = subprocess.run(
                ["nslookup", "-type=TXT", f"_dmarc.{domain}"],
                capture_output=True, text=True, timeout=10
            )
            if "v=dmarc1" in result.stdout.lower():
                dmarc_ok = True
                m = re.search(r"p=([a-z]+)", result.stdout, re.IGNORECASE)
                if m:
                    dmarc_policy = m.group(1).lower()
        except Exception:
            pass

        # DKIM (selector1 and selector2 are default Exchange Online selectors)
        for selector in ("selector1", "selector2"):
            try:
                result = subprocess.run(
                    ["nslookup", "-type=TXT", f"{selector}._domainkey.{domain}"],
                    capture_output=True, text=True, timeout=10
                )
                if "p=" in result.stdout:
                    dkim_ok = True
                    break
            except Exception:
                pass

        status = (
            f"SPF: {'✓' if spf_ok else '✗'} | "
            f"DKIM: {'✓' if dkim_ok else '✗'} | "
            f"DMARC: {'✓' if dmarc_ok else '✗'}"
            + (f" p={dmarc_policy} — DMARC p=none provides monitoring only, no enforcement"
               if dmarc_ok and dmarc_policy == "none" else "")
        )
        dns_findings.append(f"{domain}: {status}")

        # Flag issues
        if not spf_ok:
            a.finding("HIGH", "Email Security",
                f"Missing SPF Record — {domain}",
                f"No SPF record found for {domain}. Without SPF, anyone can send email "
                f"appearing to come from your domain, enabling phishing and BEC.",
                1, [domain])
        if not dkim_ok:
            a.finding("HIGH", "Email Security",
                f"Missing DKIM Record — {domain}",
                f"No DKIM record found for {domain} (checked selector1/selector2). "
                f"DKIM provides cryptographic proof that email hasn't been tampered with.",
                1, [domain])
        if not dmarc_ok:
            a.finding("HIGH", "Email Security",
                f"Missing DMARC Record — {domain}",
                f"No DMARC record found for {domain}. DMARC tells receiving mail servers "
                f"what to do with SPF/DKIM failures. Without it, spoofed email is delivered.",
                1, [domain])
        elif dmarc_policy == "none":
            a.finding("MEDIUM", "Email Security",
                f"DMARC Policy set to None (monitoring only) — {domain}",
                f"DMARC is configured but p=none means spoofed email is still delivered — "
                f"only reported. Change to p=quarantine or p=reject to enforce protection.",
                1, [domain])

    if dns_findings:
        a.finding("INFO", "Email Security",
            f"Email Domain Security Summary ({len(domains)} domain(s))",
            "SPF/DKIM/DMARC status for all verified non-onmicrosoft.com domains.",
            len(domains), dns_findings)

    a.metrics["domains_checked_dns"] = len(domains)

    # ── Inactive users without MFA ────────────────────────────────────────────
    # Users with no MFA AND no sign-in in the analysis window
    # Pull users with lastSignInDateTime
    users_activity = a.client.get_all(
        f"{GRAPH_BASE}/users",
        params={
            "$filter":  "accountEnabled eq true and userType eq 'Member'",
            "$select":  "id,displayName,userPrincipalName,signInActivity",
            "$top":     "999",
        }
    )

    # Get MFA-unregistered UPNs from metrics if available
    # Cross-reference with last sign-in to find inactive + no MFA
    stale_no_mfa = []
    service_accounts = []

    SERVICE_PATTERNS = [
        "room", "copier", "printer", "fax", "noreply", "no-reply",
        "service", "svc", "bot", "automation", "shared", "generic",
        "admin@", "info@", "hello@", "contact@", "support@",
    ]

    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=a.days_back)

    for u in (users_activity or []):
        upn  = (u.get("userPrincipalName") or "").lower()
        name = u.get("displayName","")
        sign_in_activity = u.get("signInActivity") or {}
        last_signin_str  = sign_in_activity.get("lastSignInDateTime","")

        # Service account detection
        if any(p in upn for p in SERVICE_PATTERNS):
            service_accounts.append(f"{name} ({u.get('userPrincipalName','')})")
            continue

        # Inactive in analysis window
        if last_signin_str:
            try:
                last_signin = datetime.fromisoformat(last_signin_str.replace("Z","+00:00"))
                if last_signin < stale_cutoff:
                    stale_no_mfa.append(f"{name} ({u.get('userPrincipalName','')})")
            except Exception:
                pass
        else:
            # Never signed in
            stale_no_mfa.append(f"{name} ({u.get('userPrincipalName','')}) — never signed in")

    a.metrics["inactive_users"]      = len(stale_no_mfa)
    a.metrics["service_account_sps"] = len(service_accounts)

    if stale_no_mfa:
        a.finding("LOW", "User Hygiene",
            f"Inactive Users — No Sign-in in Last {a.days_back} Days ({len(stale_no_mfa)})",
            "Enabled accounts with no sign-in activity in the analysis window. "
            "These may be provisioned but unused accounts — disable or remove if no longer needed. "
            "Especially concerning if these accounts also lack MFA.",
            len(stale_no_mfa), stale_no_mfa)

    if service_accounts:
        a.finding("INFO", "User Hygiene",
            f"Room/Service Accounts Detected ({len(service_accounts)})",
            "Accounts matching service/room naming patterns. These typically do not require "
            "interactive MFA if access is restricted via Conditional Access. "
            "Verify each is secured appropriately — no shared passwords, no interactive sign-in.",
            len(service_accounts), service_accounts)

    # ── Guest user breakdown by domain ───────────────────────────────────────
    guests = a.client.get_all(
        f"{GRAPH_BASE}/users",
        params={
            "$filter":  "userType eq 'Guest'",
            "$select":  "id,displayName,userPrincipalName,externalUserState",
            "$top":     "999",
        }
    )

    if guests:
        by_domain = defaultdict(list)
        for g in guests:
            upn = g.get("userPrincipalName","")
            # Guest UPN format: user_domain.com#EXT#@tenant.onmicrosoft.com
            m = re.search(r"_([^_#]+\.[^_#]+)#EXT#", upn)
            domain = m.group(1) if m else "unknown"
            by_domain[domain].append(upn)

        items = [
            f"{domain}: {len(members)} guest(s) — {', '.join(members[:3])}"
            + (f" ... +{len(members)-3} more" if len(members) > 3 else "")
            for domain, members in sorted(by_domain.items(), key=lambda x: len(x[1]), reverse=True)
        ]
        a.finding("INFO", "User Hygiene",
            f"Guest Users by Domain ({len(guests)} guests from {len(by_domain)} domains)",
            "External guest accounts grouped by home domain. Review whether guests "
            "from each domain still require access, and ensure Access Reviews are enabled.",
            len(guests), items)


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 17 — MFA RECONCILIATION (Live Credential Store)
# ─────────────────────────────────────────────────────────────────────────────
# PURPOSE
#   Module 09 queries /beta/reports/authenticationMethods/userRegistrationDetails,
#   which reads the Microsoft Graph unified registration history (the new combined
#   security info experience, aka.ms/mysecurityinfo).  Tenants where MFA was set
#   up via the legacy per-user MFA portal (aka.ms/mfasetup / MSOnline MSOL) may
#   have registrations that never migrated to the unified registry.  Those users
#   show isMfaRegistered=false in module 09 even though they have working MFA.
#
#   This module queries the *live credential store* via the per-user endpoint:
#       GET /beta/users/{id}/authentication/methods
#   which returns every method currently registered regardless of which portal
#   was used.  It then cross-references module 09's output to:
#     1. Produce authoritative MFA registration findings (replaces module 09
#        severity findings for human MFA adoption).
#     2. Flag every user where the two APIs disagree as a registry-migration risk.
#     3. Emit a summary of users whose legacy-only registration will silently
#        stop satisfying MFA policy once Microsoft completes the registry migration.
#
# GRAPH PERMISSIONS REQUIRED (in addition to module 09 scopes)
#   UserAuthenticationMethod.Read.All
#   (Delegated or Application — must be admin-consented)
# ─────────────────────────────────────────────────────────────────────────────

# Method type classification for module 17
_M17_METHOD_TYPE_MAP = {
    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":
        "microsoftAuthenticatorPush",
    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod":
        "windowsHelloForBusiness",
    "#microsoft.graph.fido2AuthenticationMethod":
        "fido2SecurityKey",
    "#microsoft.graph.softwareOathAuthenticationMethod":
        "softwareOneTimePasscode",
    "#microsoft.graph.phoneAuthenticationMethod":
        "mobilePhone",          # could be SMS or voice — check phoneType field
    "#microsoft.graph.emailAuthenticationMethod":
        "email",
    "#microsoft.graph.temporaryAccessPassAuthenticationMethod":
        "temporaryAccessPass",
    "#microsoft.graph.passwordAuthenticationMethod":
        "password",             # always present; not an MFA method
}
_M17_STRONG_METHODS = {
    "microsoftAuthenticatorPush",
    "windowsHelloForBusiness",
    "fido2SecurityKey",
    "softwareOneTimePasscode",
}
_M17_WEAK_METHODS = {"mobilePhone", "email"}
_M17_NON_MFA      = {"password", "temporaryAccessPass"}


def _m17_parse_methods(raw_methods: list) -> dict:
    """Return a summary dict for a user's authentication/methods response."""
    canonical = set()
    has_push      = False
    has_whfb      = False
    has_fido2     = False
    has_totp      = False
    has_sms_voice = False
    has_email     = False

    for m in raw_methods:
        otype = m.get("@odata.type", "")
        name  = _M17_METHOD_TYPE_MAP.get(otype, otype)
        canonical.add(name)

        if name == "microsoftAuthenticatorPush":
            has_push  = True
        elif name == "windowsHelloForBusiness":
            has_whfb  = True
        elif name == "fido2SecurityKey":
            has_fido2 = True
        elif name == "softwareOneTimePasscode":
            has_totp  = True
        elif name == "mobilePhone":
            has_sms_voice = True
        elif name == "email":
            has_email = True

    has_strong = has_push or has_whfb or has_fido2 or has_totp
    has_weak   = has_sms_voice or has_email
    has_mfa    = has_strong or has_weak

    # Phishing-resistant = cannot be intercepted by real-time proxy attack
    phishing_resistant = has_whfb or has_fido2

    if not has_mfa:
        strength = "none"
    elif has_strong:
        strength = "strong"
    else:
        strength = "weak"

    return {
        "methods":            sorted(canonical - _M17_NON_MFA),
        "has_mfa":            has_mfa,
        "strength":           strength,     # "strong" | "weak" | "none"
        "phishing_resistant": phishing_resistant,
        "has_push":           has_push,
        "has_whfb":           has_whfb,
        "has_fido2":          has_fido2,
        "has_totp":           has_totp,
        "has_sms_voice":      has_sms_voice,
        "has_email_otp":      has_email,
    }


def _m17_batch_get_user_methods(client, user_ids: list) -> dict:
    """
    Fetch /beta/users/{id}/authentication/methods for a list of user IDs using
    the $batch endpoint (max 20 requests per batch call).

    Returns dict: { user_id: [method_objects] | None }
    None means the request failed (403 = permission denied, 404 = user gone).

    Rate limiting: 100ms delay between batches to avoid throttling on large
    tenants. Implements exponential backoff on 429 responses.
    """
    BATCH_SIZE    = 20
    BATCH_URL     = f"{GRAPH_BETA}/$batch"
    BATCH_DELAY   = 0.1   # 100ms between batches
    MAX_RETRIES   = 3
    results       = {}
    total_batches = (len(user_ids) + BATCH_SIZE - 1) // BATCH_SIZE

    for chunk_start in range(0, len(user_ids), BATCH_SIZE):
        chunk = user_ids[chunk_start: chunk_start + BATCH_SIZE]
        batch_num = chunk_start // BATCH_SIZE + 1

        batch_body = {
            "requests": [
                {
                    "id":     uid,
                    "method": "GET",
                    "url":    f"/users/{uid}/authentication/methods",
                }
                for uid in chunk
            ]
        }

        # Retry loop with exponential backoff for 429 throttling
        retry_delay = 1.0
        for attempt in range(MAX_RETRIES):
            try:
                resp = requests.post(
                    BATCH_URL,
                    headers={**client.headers, "Content-Type": "application/json"},
                    json=batch_body,
                    timeout=60,
                )
                client.stats["requests"] += 1

                # Handle throttling with exponential backoff
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", retry_delay))
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(retry_after)
                        retry_delay *= 2
                        continue
                    else:
                        client.stats["errors"] += 1
                        for uid in chunk:
                            results[uid] = None
                        break

                if resp.status_code != 200:
                    client.stats["errors"] += 1
                    for uid in chunk:
                        results[uid] = None
                    break

                data = resp.json()

                # Store raw batch response in evidence
                client.evidence.store(
                    f"{BATCH_URL}?chunk={chunk_start // BATCH_SIZE}",
                    {"user_ids": chunk},
                    data,
                )

                for item in data.get("responses", []):
                    uid    = item.get("id")
                    status = item.get("status", 0)
                    body   = item.get("body", {})
                    if status == 200:
                        results[uid] = body.get("value", [])
                    else:
                        results[uid] = None   # 403 or 404

                break  # Success - exit retry loop

            except Exception:
                client.stats["errors"] += 1
                for uid in chunk:
                    results[uid] = None
                break

        # Rate limit protection: small delay between batches for large tenants
        if batch_num < total_batches:
            time.sleep(BATCH_DELAY)

    return results


def module_17_mfa_reconciliation(a: Assessment):
    """
    Authoritative MFA credential inventory via per-user authentication/methods.
    Cross-references module 09 userRegistrationDetails to surface registry-
    migration risk and produce corrected human MFA adoption findings.
    """
    print("  [17/17] MFA Reconciliation — Per-User Authentication Methods...")

    client = a.client

    # ── 1. Collect human user IDs from module 03's user list ─────────────────
    # Re-query is cheap; users were already collected by module 03.
    raw_users = client.get_all(
        f"{GRAPH_BASE}/users",
        params={
            "$select": "id,userPrincipalName,displayName,userType,accountEnabled",
            "$top":    "999",
        },
    )
    if not raw_users:
        a.finding(
            "INFO", "MFA Reconciliation",
            "MFA Reconciliation Skipped — User List Unavailable",
            "Could not retrieve user list. Verify User.Read.All admin consent.",
        )
        return

    # Filter to enabled human accounts only (same logic as module 09)
    human_users = [
        u for u in raw_users
        if u.get("accountEnabled")
        and _classify_account(
            u.get("userPrincipalName", ""),
            u.get("displayName", ""),
            u.get("userType", "member"),
        ) == "human"
    ]

    if not human_users:
        a.finding(
            "INFO", "MFA Reconciliation",
            "MFA Reconciliation Skipped — No Human Accounts Found",
            "No enabled human accounts were identified after classification.",
        )
        return

    user_id_to_meta = {
        u["id"]: {
            "upn":  u.get("userPrincipalName", ""),
            "name": u.get("displayName", u.get("userPrincipalName", "")),
        }
        for u in human_users
        if u.get("id")
    }
    user_ids = list(user_id_to_meta.keys())

    # ── 2. Fetch per-user authentication methods via $batch ───────────────────
    print(f"         Querying authentication methods for {len(user_ids)} "
          f"human accounts ({(len(user_ids) + 19) // 20} batch requests)...")

    raw_methods = _m17_batch_get_user_methods(client, user_ids)

    # Check permission: if all results are None, scope is missing
    non_null = [v for v in raw_methods.values() if v is not None]
    if not non_null:
        a.finding(
            "INFO", "MFA Reconciliation",
            "MFA Reconciliation Skipped — UserAuthenticationMethod.Read.All Not Granted",
            "All per-user authentication method requests returned 403. "
            "Grant admin consent for UserAuthenticationMethod.Read.All on the "
            "assessment service principal, then re-run this module. "
            "Without this scope the tool cannot read the live credential store "
            "and module 09 registration details remain the only MFA data source.",
        )
        return

    # ── 3. Parse and classify each user ──────────────────────────────────────
    # Buckets
    no_mfa         = []   # (name, upn, methods_summary)
    weak_only      = []
    strong         = []
    phish_resistant= []
    permission_err = []   # 403 — could not read this user

    # For cross-reference with module 09
    m09_data = {}
    for u in (a.metrics.get("mfa_m09_raw_report") or []):
        upn = u.get("userPrincipalName", "").lower()
        m09_data[upn] = u

    registry_discrepancies = []   # users where module 09 and module 17 disagree

    for uid, methods_list in raw_methods.items():
        meta = user_id_to_meta.get(uid, {})
        upn  = meta.get("upn", "")
        name = meta.get("name", upn)
        label = f"{name} ({upn})"

        if methods_list is None:
            permission_err.append(label)
            continue

        summary = _m17_parse_methods(methods_list)

        if not summary["has_mfa"]:
            no_mfa.append((name, upn, summary))
        elif summary["strength"] == "weak":
            weak_only.append((name, upn, summary))
        else:
            strong.append((name, upn, summary))
            if summary["phishing_resistant"]:
                phish_resistant.append(label)

        # Cross-reference with module 09
        m09 = m09_data.get(upn.lower())
        if m09:
            m09_registered = m09.get("isMfaRegistered", False)
            m17_registered = summary["has_mfa"]
            if m09_registered != m17_registered:
                discrepancy_type = (
                    "legacy-only: MFA exists in live store but absent from unified registry"
                    if m17_registered and not m09_registered
                    else "unified-only: MFA in unified registry but absent from live store"
                )
                registry_discrepancies.append(
                    f"{label}: module 09 isMfaRegistered={m09_registered}, "
                    f"module 17 has_mfa={m17_registered} ({discrepancy_type})"
                )

    # ── 4. Update metrics ─────────────────────────────────────────────────────
    total_human = len(human_users)
    n_no_mfa    = len(no_mfa)
    n_weak      = len(weak_only)
    n_strong    = len(strong)
    n_phr       = len(phish_resistant)
    n_error     = len(permission_err)
    n_disc      = len(registry_discrepancies)
    pct_reg     = (n_strong + n_weak) / total_human * 100 if total_human else 0

    a.metrics.update({
        "mfa_m17_human_total":         total_human,
        "mfa_m17_no_mfa":              n_no_mfa,
        "mfa_m17_weak_only":           n_weak,
        "mfa_m17_strong":              n_strong,
        "mfa_m17_phishing_resistant":  n_phr,
        "mfa_m17_permission_errors":   n_error,
        "mfa_m17_registry_discrepancies": n_disc,
        "mfa_m17_pct_registered":      round(pct_reg, 1),
    })

    # ── 5. Emit findings ──────────────────────────────────────────────────────

    # 5a. Suppress module 09 MFA adoption severity finding if it was emitted
    # (module 09 sets this flag when it emits its adoption finding)
    if a.metrics.get("mfa_m09_adoption_finding_emitted"):
        a.findings = [
            f for f in a.findings
            if not (
                f["category"] == "MFA & Auth Methods"
                and "Human User MFA Adoption" in f["title"]
            )
        ]

    # 5b. No MFA — authoritative finding
    if no_mfa:
        # Severity based on percentage of users without MFA
        if n_no_mfa / total_human > 0.50:
            sev = "CRITICAL"
        elif n_no_mfa / total_human > 0.10:
            sev = "HIGH"
        else:
            sev = "HIGH"  # Any users without MFA is HIGH minimum

        items = [
            f"{name} ({upn}) — methods in live store: "
            f"{', '.join(s['methods']) if s['methods'] else 'none'}"
            for name, upn, s in sorted(no_mfa, key=lambda x: x[0])
        ]
        a.finding(
            sev, "MFA Reconciliation",
            f"Human Accounts With No MFA — Live Credential Store "
            f"({n_no_mfa} of {total_human}, authoritative)",
            f"Per-user authentication/methods endpoint (live credential store) "
            f"confirms {n_no_mfa} of {total_human} enabled human accounts have "
            f"no MFA method registered. This count is authoritative: it reads "
            f"the live credential store directly and reflects methods registered "
            f"through both the new combined registration experience and the legacy "
            f"per-user MFA portal. "
            f"Accounts: {', '.join(i.split(' —')[0] for i in items[:10])}"
            f"{'...' if n_no_mfa > 10 else ''}. "
            f"Enroll in Microsoft Authenticator push immediately.",
            n_no_mfa,
            items,
        )

    # 5c. Weak MFA only — per-user methods endpoint
    if weak_only:
        # Escalate to HIGH if any privileged accounts have weak MFA
        privileged_upns = a.metrics.get("privileged_upns") or set()
        has_privileged_weak = any(
            upn.lower() in privileged_upns
            for _, upn, _ in weak_only
        )
        sev = "HIGH" if has_privileged_weak else "MEDIUM"

        items = [
            f"{name} ({upn}) — registered: {', '.join(s['methods'])}"
            for name, upn, s in sorted(weak_only, key=lambda x: x[0])
        ]
        a.finding(
            sev, "MFA Reconciliation",
            f"Human Accounts With Weak MFA Only — SMS, Voice, or Email "
            f"({n_weak} accounts, live credential store)",
            f"{n_weak} enabled human accounts have only SMS, voice call, or "
            f"email OTP registered. These methods are susceptible to SIM-swap, "
            f"SS7 interception, and real-time phishing proxy attacks. None "
            f"satisfy phishing-resistant MFA requirements. "
            f"{'⚠️ INCLUDES PRIVILEGED ACCOUNTS. ' if has_privileged_weak else ''}"
            f"Migrate to Microsoft Authenticator push, FIDO2, or Windows Hello.",
            n_weak,
            items,
        )

    # 5d. Registry discrepancies — migration risk
    if registry_discrepancies:
        a.finding(
            "MEDIUM", "MFA Reconciliation",
            f"MFA Registry Discrepancy: {n_disc} Accounts Differ Between "
            f"Live Credential Store and Unified Registration Registry",
            f"{n_disc} accounts show different MFA registration state between "
            f"the Microsoft Graph unified registration registry (module 09, "
            f"userRegistrationDetails endpoint) and the live credential store "
            f"(this module, per-user authentication/methods endpoint). "
            f"Accounts with MFA in the live store but absent from the unified "
            f"registry registered via the legacy per-user MFA portal and have "
            f"not been migrated to the new combined registration experience. "
            f"As Microsoft progressively enforces the unified registry for "
            f"Conditional Access MFA satisfaction, these users' MFA will "
            f"silently stop satisfying policy without administrator notification. "
            f"Remediation: require all affected users to re-register at "
            f"aka.ms/mysecurityinfo to migrate their credentials to the unified "
            f"registry. This does not invalidate existing credentials — it "
            f"creates a unified registry entry alongside the legacy one.",
            n_disc,
            registry_discrepancies,
        )

    # 5e. Permission errors — partial data warning
    if permission_err:
        a.finding(
            "INFO", "MFA Reconciliation",
            f"MFA Reconciliation Partial — {n_error} Users Could Not Be Queried",
            f"UserAuthenticationMethod.Read.All permission was denied for "
            f"{n_error} user(s). These users are excluded from the authoritative "
            f"MFA counts. Grant admin consent for UserAuthenticationMethod.Read.All "
            f"and re-run to obtain complete coverage.",
            n_error,
            permission_err,
        )

    # 5f. Summary INFO — reconciliation complete
    suppressed_note = (
        "Module 09 MFA adoption finding suppressed — this module is authoritative."
        if a.metrics.get("mfa_m09_adoption_finding_emitted") else ""
    )
    a.finding(
        "INFO", "MFA Reconciliation",
        f"MFA Reconciliation Complete — Live Credential Store "
        f"({total_human} human accounts, {pct_reg:.0f}% registered)",
        f"Per-user authentication methods queried for {total_human} enabled "
        f"human accounts via {(len(user_ids) + 19) // 20} Graph $batch requests. "
        f"Results: {n_strong} strong MFA ({n_phr} phishing-resistant), "
        f"{n_weak} weak MFA only (SMS/voice/email), "
        f"{n_no_mfa} no MFA. "
        f"Registry discrepancies between unified registry (module 09) and "
        f"live credential store (this module): {n_disc} accounts. "
        f"{suppressed_note}",
        total_human,
    )


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10 — REPORTING
# ─────────────────────────────────────────────────────────────────────────────

def print_report(a: Assessment, skip_defender: bool = False):
    findings = sorted(a.findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    counts   = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1

    score = (counts["CRITICAL"] * 20 + counts["HIGH"] * 10 +
             counts["MEDIUM"] * 5  + counts["LOW"] * 1)

    # ── Header ──
    print("\n" + "═" * 70)
    print(f"{BOLD}  ENTRA SECURITY POSTURE ASSESSMENT REPORT{RESET}")
    print("═" * 70)
    if a.tenant:
        print(f"\n  Tenant:    {a.tenant.get('name','Unknown')}  ({a.tenant.get('id','')[:8]}…)")
        print(f"  Domains:   {', '.join(a.tenant.get('domains',[]))}")
        print(f"  Country:   {a.tenant.get('country','Unknown')}")
    print(f"  Window:    Last {a.days_back} days  |  {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC")

    # ── Risk summary ──
    print("\n" + "─" * 70)
    print(f"{BOLD}  RISK SUMMARY{RESET}")
    print("─" * 70)
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        print(f"  {sev_color(f'{sev:<10} {counts[sev]:>3} findings', sev)}")

    print(f"\n  Overall Risk Score: {BOLD}{score}{RESET}  ", end="")
    if score >= 50:
        print(sev_color("HIGH RISK", "CRITICAL"))
    elif score >= 25:
        print(sev_color("ELEVATED RISK", "HIGH"))
    elif score >= 10:
        print(sev_color("MODERATE RISK", "MEDIUM"))
    else:
        print(sev_color("LOWER RISK", "LOW"))

    # ── Key metrics ──
    print("\n" + "─" * 70)
    print(f"{BOLD}  KEY METRICS{RESET}")
    print("─" * 70)
    m = a.metrics
    metric_rows = [
        ("Total Users",               m.get("total_users","N/A")),
        ("Enabled Users",             m.get("enabled_users","N/A")),
        ("Guest Users",               m.get("guest_users","N/A")),
        ("Global Admins",             m.get("global_admins","N/A")),
        ("Privileged Assignments",    m.get("privileged_role_assignments","N/A")),
        ("CA Policies (enabled)",     m.get("ca_policies_enabled","N/A")),
        ("App Registrations",         m.get("app_registrations","N/A")),
        ("Total Devices",             m.get("total_devices","N/A")),
        ("Unmanaged Devices",         m.get("unmanaged_devices","N/A")),
        (f"Sign-ins ({a.days_back}d)",m.get("total_signins","N/A")),
        ("Failed Sign-ins",           m.get("failed_signins","N/A")),
        ("Legacy Auth Sign-ins",      m.get("legacy_auth_signins","N/A")),
        ("Risky Sign-ins",            m.get("risky_signins","N/A")),
        ("Token Replay Indicators",   m.get("token_replay_indicators","N/A")),
        ("Password Spray Source IPs", m.get("spray_source_ips","N/A")),
        ("MFA Human Total",           m.get("mfa_human_total","N/A")),
        ("MFA Human Registered",      m.get("mfa_human_registered","N/A")),
        ("MFA Human Missing",         m.get("mfa_human_missing","N/A")),
        ("MFA Human Strong Methods",  m.get("mfa_human_strong","N/A")),
        ("MFA Human Weak Only",       m.get("mfa_human_weak_only","N/A")),
        ("MFA Guest Accounts",        m.get("mfa_guest_accounts","N/A")),
        ("MFA Service Accounts",      m.get("mfa_service_accounts","N/A")),
        ("MFA Resource/Room Accounts",m.get("mfa_resource_accounts","N/A")),
        ("MFA Disabled (excluded)",   m.get("mfa_disabled_excluded","N/A")),
        ("MFA M17 No MFA (auth)",     m.get("mfa_m17_no_mfa","N/A")),
        ("MFA M17 Weak Only (auth)",  m.get("mfa_m17_weak_only","N/A")),
        ("MFA M17 Strong (auth)",     m.get("mfa_m17_strong","N/A")),
        ("MFA M17 Phish-Resistant",   m.get("mfa_m17_phishing_resistant","N/A")),
        ("MFA Registry Discrepancies",m.get("mfa_m17_registry_discrepancies","N/A")),
        ("High-Risk Users (IDP)",     m.get("high_risk_users","N/A")),
        ("Graph App Role Grants",     m.get("graph_app_role_grants","N/A")),
        ("Dangerous Perm Grants",     m.get("dangerous_permission_grants","N/A")),
        ("Recent Consent Grants",     m.get("recent_consent_grants","N/A")),
        ("Defender Alerts (total)",   m.get("defender_total_alerts","N/A") if not skip_defender else "skipped"),
        ("Defender High/Critical",    m.get("defender_critical_high","N/A") if not skip_defender else "skipped"),
        ("Dangerous Mail OAuth",      m.get("dangerous_mail_oauth","N/A")),
        ("Admin Password Resets",     m.get("admin_password_resets","N/A")),
        ("Legacy Exchange Sign-ins",  m.get("legacy_exchange_signins","N/A")),
        ("PIM Eligible Assignments",   m.get("pim_eligible_assignments","N/A")),
        ("PIM Active Now",             m.get("pim_active_now","N/A")),
        ("PIM No-Expiry",              m.get("pim_no_expiry","N/A")),
        ("Risk Detections (total)",    m.get("risk_detections_total","N/A")),
        ("Risk Detections (high/med)", m.get("risk_detections_high","N/A")),
        ("Impossible Travel Events",   m.get("impossible_travel_events","N/A")),
        ("Token Replay Indicators",    m.get("token_replay_indicators","N/A")),
        ("Password Spray IPs",         m.get("spray_source_ips","N/A")),
        ("AI Agent SPs",               m.get("ai_agent_sps","N/A")),
        ("MFA Strong Only",            m.get("mfa_strong_only","N/A")),
        ("MFA Weak Only",              m.get("mfa_weak_only","N/A")),
        ("FIDO2 Users",                m.get("fido2_users","N/A")),
        ("Passkey Users",              m.get("passkey_users","N/A")),
        ("Mailboxes Checked",          m.get("mailboxes_checked","N/A")),
        ("Mailboxes Skipped (no mbx)", m.get("mailboxes_skipped","N/A")),
        ("External Forwarders",        m.get("external_forwarders","N/A")),
        ("Email Hiding Rules",         m.get("email_hiding_rules","N/A")),
        ("Off-Hours Sign-in Events",   m.get("off_hours_events","N/A")),
        ("High IP Diversity Users",    m.get("high_ip_diversity_users","N/A")),
        ("SP Multi-Location Users",    m.get("sharepoint_multi_location_users","N/A")),
        ("Domains DNS Checked",        m.get("domains_checked_dns","N/A")),
        ("Inactive Users",             m.get("inactive_users","N/A")),
    ]
    for label, value in metric_rows:
        print(f"  {label:<34} {value}")

    # ── Findings ──
    print("\n" + "═" * 70)
    print(f"{BOLD}  FINDINGS{RESET}")
    print("═" * 70)

    current_cat = None
    for f in findings:
        if f["category"] != current_cat:
            current_cat = f["category"]
            print(f"\n  ┌─ {BOLD}{f['category'].upper()}{RESET}")

        sev   = f["severity"]
        icon  = sev_icon(sev)
        title = f["title"]
        print(f"  │  {icon} {sev_color(sev, sev):<10}  {BOLD}{title}{RESET}")

        # Word-wrap detail at 88 chars
        words, line = f["detail"].split(), "  │             "
        for word in words:
            if len(line) + len(word) > 88:
                print(line)
                line = "  │             " + word + " "
            else:
                line += word + " "
        if line.strip():
            print(line)

        items = f.get("items", [])
        for item in items[:25]:
            # Wrap long items at 100 chars
            item_str = str(item)
            if len(item_str) <= 100:
                print(f"  │               • {item_str}")
            else:
                # Print first line then indent continuation
                words = item_str.split(" ")
                line  = "  │               • "
                for word in words:
                    if len(line) + len(word) > 102:
                        print(line)
                        line = "  │                 " + word + " "
                    else:
                        line += word + " "
                if line.strip():
                    print(line)
        if len(items) > 25:
            print(f"  │               … and {len(items)-25} more (see JSON report for full list)")
        print("  │")

    # ── Remediation priorities ──
    print("\n" + "═" * 70)
    print(f"{BOLD}  TOP REMEDIATION PRIORITIES{RESET}")
    print("═" * 70)
    priorities = [f for f in findings if f["severity"] in ("CRITICAL","HIGH")][:12]
    for i, f in enumerate(priorities, 1):
        print(f"  {i:>2}. {sev_icon(f['severity'])} {f['title']}")

    # ── Footer ──
    print("\n" + "─" * 70)
    print(f"  API Requests: {a.client.stats['requests']}  |  "
          f"Permission Errors: {a.client.stats['permission_errors']}  |  "
          f"Errors: {a.client.stats['errors']}")
    print("─" * 70 + "\n")


def save_json_report(a: Assessment, path: str = None):
    """Save full untruncated report through the evidence store for CoC integrity."""
    evidence_summary = a.evidence.summary()

    report = {
        "chain_of_custody": {
            "case_directory":        evidence_summary["case_directory"],
            "manifest_path":         evidence_summary["manifest_path"],
            "total_api_calls":       evidence_summary["total_api_calls"],
            "total_records_collected": evidence_summary["total_records"],
            "evidence_files":        evidence_summary["evidence_files"],
            "collector_upn":         a.collector_upn,
            "assessment_started":    a.started_at.isoformat(),
            "report_generated":      datetime.now(timezone.utc).isoformat(),
            "analysis_window_days":  a.days_back,
            "note": (
                "This report is the analyst conclusions layer. "
                "Raw evidence is in the case directory raw/ subdirectory. "
                "Verify integrity via SHA-256 hashes in MANIFEST.json."
            ),
        },
        "tenant":       a.tenant,
        "metrics":      a.metrics,
        "findings":     a.findings,
        "summary": {
            sev.lower(): sum(1 for f in a.findings if f["severity"] == sev)
            for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")
        },
        "finding_detail_counts": {
            f["title"]: {
                "severity":       f["severity"],
                "count":          f["count"],
                "items_recorded": len(f.get("items", [])),
            }
            for f in a.findings
        },
    }

    # Write through evidence store — gets hashed + added to manifest
    report_path, sha256 = a.evidence.write_report(report, "report.json")

    # Also write to any user-specified path
    if path:
        Path(path).write_text(
            json.dumps(report, indent=2, default=str, ensure_ascii=False),
            encoding="utf-8"
        )

    total_items = sum(len(f.get("items",[])) for f in a.findings)
    print(f"  📄 Report → {report_path}")
    print(f"     SHA-256: {sha256}")
    print(f"     {len(a.findings)} findings | {total_items} detail items | fully untruncated")
    print(f"  📁 Evidence → {evidence_summary['case_directory']}")
    print(f"     {evidence_summary['total_api_calls']} API calls | "
          f"{evidence_summary['total_records']} records collected")
    print(f"  🔗 Manifest → {evidence_summary['manifest_path']}")
    if path:
        print(f"  📄 Copy also saved → {path}")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 11 — PRE-FLIGHT CONFIGURATION CHECK
# ─────────────────────────────────────────────────────────────────────────────

def preflight_checks():
    """Verify Python version and environment before starting."""
    errors   = []
    warnings = []

    # Python version
    if sys.version_info < (3, 8):
        errors.append(f"Python 3.8+ required (running {sys.version.split()[0]})")

    # Network reachability (quick check)
    try:
        r = requests.get("https://login.microsoftonline.com", timeout=5)
        if r.status_code not in (200, 400):
            warnings.append("Unexpected response from login.microsoftonline.com — check network/proxy")
    except Exception as e:
        errors.append(f"Cannot reach login.microsoftonline.com: {e}")

    if errors:
        print("\n  ✗ Pre-flight checks FAILED:")
        for e in errors:
            print(f"    • {e}")
        sys.exit(1)

    if warnings:
        print("\n  ⚠  Pre-flight warnings:")
        for w in warnings:
            print(f"    • {w}")

    print("  ✓ Pre-flight checks passed\n")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 12 — ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="entra_assessment.py",
        description="Entra ID Security Posture Assessment — 12 modules, read-only, device code auth",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modules run:
  01 Tenant & Organization       07 Sign-in Logs (30-90 days)
  02 Privileged Role Assignments 08 Risky Users (Identity Protection)
  03 User Hygiene                09 MFA Registration & Auth Methods
  04 Conditional Access          10 App Role Analysis & Audit History
  05 Applications & Credentials  11 Microsoft Defender Alerts
  06 Device Compliance           12 O365 / Exchange Credential Abuse

Examples:
  python entra_assessment.py                       # 30-day window, all modules
  python entra_assessment.py --days 90             # 90-day window
  python entra_assessment.py --days 60 --json      # + JSON report
  python entra_assessment.py --json my_report.json # custom JSON path
  python entra_assessment.py --skip-defender       # skip if no Defender license
  python entra_assessment.py --skip-signin              # faster, less visibility
  python entra_assessment.py --tenant contoso.com       # specify tenant (recommended)
  python entra_assessment.py --tenant <guid>            # or use tenant ID directly
        """
    )
    parser.add_argument("--days", type=int, default=30, choices=[7,14,30,60,90],
                        help="Days of log history to analyze (default: 30)")
    parser.add_argument("--output-dir", metavar="DIR", default=".",
                        help="Directory to create the case folder in (default: current dir)")
    parser.add_argument("--tenant", metavar="TENANT",
                        help="Target tenant ID (GUID) or domain e.g. contoso.com. "
                             "Can also be set in config.yaml or ENTRA_TENANT_ID env var.")
    parser.add_argument("--client-id", metavar="CLIENT_ID",
                        help="App client ID for device code auth. "
                             "Can also be set in config.yaml or ENTRA_CLIENT_ID env var.")
    parser.add_argument("--json", nargs="?", const="entra_assessment_report.json",
                        metavar="FILE", help="Save findings as JSON report")
    parser.add_argument("--skip-signin",   action="store_true",
                        help="Skip sign-in log module (faster)")
    parser.add_argument("--init", action="store_true",
                        help="Create a fresh config.yaml template and exit")
    parser.add_argument("--skip-defender", action="store_true",
                        help="Skip Defender alerts module (if no Defender licensing)")
    args = parser.parse_args()

    print(__doc__)  # Print the banner at the top of the file

    # --init: write a fresh config.yaml and exit
    if getattr(args, 'init', False):
        config_path = Path("config.yaml")
        if config_path.exists():
            print(f"  config.yaml already exists. Delete it first to regenerate.")
        else:
            config_text = (
                "# Entra Security Assessment - config.yaml\n"
                "# Fill in tenant_id then run: python entra_assessment.py\n"
                "\n"
                "entra:\n"
                "  tenant_id: \"\"   # REQUIRED - e.g. contoso.com or tenant GUID\n"
                "  client_id: \"14d82eec-204b-4c2f-b7e8-296a70dab67e\"   # Microsoft Graph Command Line Tools\n"
                "  auth_mode: device_code\n"
                "\n"
                "assessment:\n"
                "  days: 30            # 7 / 14 / 30 / 60 / 90\n"
                "  skip_defender: false\n"
                "  skip_signin: false\n"
            )
            config_path.write_text(config_text, encoding='utf-8')
            print(f"  config.yaml created. Open it, fill in tenant_id, then run:")
            print(f"  python entra_assessment.py")
        sys.exit(0)

    preflight_checks()

    try:
        cfg    = load_config(
            cli_tenant        = args.tenant,
            cli_client_id     = args.client_id,
            cli_days          = args.days,
            cli_skip_defender = args.skip_defender,
            cli_skip_signin   = args.skip_signin,
        )
        token  = authenticate_device_code(tenant_id=cfg["tenant_id"], client_id=cfg["client_id"])

        # ── Create forensic case directory ──────────────────────────────────
        # Named by tenant + timestamp so each assessment run is distinct
        ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        case_name = f"entra_assessment_{ts}"
        case_dir  = Path(args.output_dir) / case_name if args.output_dir else Path(case_name)
        evidence  = EvidenceStore(case_dir)

        # Write chain of custody header immediately
        # Decode UPN from token claims for the custody record
        try:
            import base64 as _b64, json as _jj
            payload = token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            claims  = _jj.loads(_b64.b64decode(payload))
            collector_upn = claims.get("upn") or claims.get("preferred_username","unknown")
            collector_tid = claims.get("tid","unknown")
        except Exception:
            collector_upn = "unknown"
            collector_tid = cfg["tenant_id"]

        custody_header = {
            "case_id":            case_name,
            "tool":               "Entra Security Posture Assessment",
            "version":            "2.0",
            "assessment_started": datetime.now(timezone.utc).isoformat(),
            "collector_upn":      collector_upn,
            "collector_tenant":   collector_tid,
            "target_tenant":      cfg["tenant_id"],
            "analysis_window_days": cfg["days"],
            "client_id_used":     cfg["client_id"],
            "case_directory":     str(case_dir.resolve()),
            "note": (
                "Raw API responses are preserved in the raw/ subdirectory. "
                "Each file is individually SHA-256 hashed and recorded in MANIFEST.json. "
                "The report/ subdirectory contains analyst conclusions derived from that evidence. "
                "Raw evidence files must not be modified after collection."
            ),
        }
        (case_dir / "CUSTODY.json").write_text(
            json.dumps(custody_header, indent=2), encoding="utf-8"
        )
        print(f"  📁 Case directory: {case_dir.resolve()}")
        print(f"  🔗 Chain of custody: {case_dir / 'CUSTODY.json'}")
        print()

        client = GraphClient(token, evidence)
        a      = Assessment(client, evidence, days_back=cfg["days"],
                            collector_upn=collector_upn)

        print(f"{BOLD}  Running Assessment Modules...{RESET}\n")

        module_01_tenant(a)
        module_02_roles(a)
        module_03_users(a)
        module_04_ca(a)
        module_05_apps(a)
        module_06_devices(a)

        if cfg["skip_signin"]:
            print("  [07/17] Sign-in Logs — SKIPPED")
        else:
            module_07_signins(a)

        module_08_risky_users(a)
        module_09_mfa(a)
        module_10_app_roles(a)

        if cfg["skip_defender"]:
            print("  [11/17] Defender Alerts — SKIPPED")
        else:
            module_11_defender(a)

        module_12_o365_abuse(a)
        module_13_pim(a)
        module_14_mailbox_forwarding(a)
        module_15_signin_behavioral(a)
        module_16_dns_and_user_hygiene(a)
        module_17_mfa_reconciliation(a)

        print(f"\n{BOLD}  Assessment complete — generating report...{RESET}")

        print_report(a, skip_defender=cfg["skip_defender"])

        # Always save through evidence store; --json also writes a user-facing copy
        save_json_report(a, args.json if args.json else None)

    except KeyboardInterrupt:
        print("\n\n  Assessment cancelled.\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n  ❌ Fatal error: {e}\n")
        raise


if __name__ == "__main__":
    main()
