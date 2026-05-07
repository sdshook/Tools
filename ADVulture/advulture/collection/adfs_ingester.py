# (c) 2025 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture — ADFS Log Ingester
Parses Microsoft-Windows-ADFS/Admin and Operational logs.
Detects Golden SAML indicators, claim rule abuse, and
authorisation grants not backed by AD group membership.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict
from pathlib import Path

log = logging.getLogger(__name__)

# ADFS event IDs on federation servers
ADFS_EVENT_IDS = {
    299:  "token_issued",           # Successful token issuance
    324:  "authz_failure",          # Authorisation failure
    403:  "claim_rule_changed",     # Issuance transform rule modified — HIGH RISK
    410:  "claims_issued",          # Claims placed in token
    500:  "trust_added",            # New claims provider / relying party
    501:  "trust_removed",
    510:  "incoming_claims",        # Claims from upstream IdP
    1007: "cert_operation",         # Token signing cert operations — Golden SAML risk
    # WAP (Web Application Proxy)
    12019: "wap_published_app_auth",
    12023: "wap_invalid_request",
}

# Golden SAML detection signatures
GOLDEN_SAML_INDICATORS = [
    "token_without_auth_event",
    "unexpected_signing_cert",
    "cross_subnet_federation",
    "claim_rule_modified_then_used",
]


@dataclass
class ADFSClaim:
    claim_type: str
    claim_value: str
    issuer: str = ""
    original_issuer: str = ""


@dataclass
class ADFSTokenEvent:
    timestamp: datetime
    event_id: int
    source_host: str
    user_identifier: str
    relying_party: str
    auth_method: str
    client_ip: str
    claims: List[ADFSClaim] = field(default_factory=list)
    result: str = "success"         # success / failure
    failure_reason: str = ""
    # Golden SAML indicators
    has_preceding_auth: bool = True
    signing_cert_thumbprint: str = ""
    golden_saml_flags: List[str] = field(default_factory=list)
    # AuthZ analysis
    ad_group_backed_claims: List[str] = field(default_factory=list)
    unbacked_claims: List[str] = field(default_factory=list)


@dataclass
class ADFSClaimRuleChange:
    timestamp: datetime
    rule_set: str           # issuance_transform / issuance_authorization
    relying_party: str
    changed_by: str
    old_rule: str = ""
    new_rule: str = ""
    risk_level: str = "HIGH"   # claim rule changes are always HIGH


@dataclass
class ADFSTrustEvent:
    timestamp: datetime
    trust_name: str
    trust_type: str         # claims_provider / relying_party
    action: str             # added / removed
    performed_by: str = ""


@dataclass
class ADFSSurface:
    token_events: List[ADFSTokenEvent] = field(default_factory=list)
    claim_rule_changes: List[ADFSClaimRuleChange] = field(default_factory=list)
    trust_events: List[ADFSTrustEvent] = field(default_factory=list)
    # Derived
    relying_parties: List[str] = field(default_factory=list)
    golden_saml_suspects: List[ADFSTokenEvent] = field(default_factory=list)
    unbacked_claim_grants: List[ADFSTokenEvent] = field(default_factory=list)


class ADFSLogIngester:
    """
    Parses ADFS Admin and Operational event logs.
    Correlates token issuance with authentication events to
    detect Golden SAML and claim rule override patterns.
    """

    ADFS_CHANNELS = [
        "Microsoft-Windows-ADFS/Admin",
        "Microsoft-Windows-ADFS/Operational",
        "Microsoft-Windows-WebApplicationProxy/Admin",
        "Security",
    ]

    def __init__(self, evtx_paths: Optional[List[Path]] = None,
                 adfs_hosts: Optional[List[str]] = None):
        self.evtx_paths = evtx_paths or []
        self.adfs_hosts = adfs_hosts or []
        self._auth_events: Dict[str, List[datetime]] = {}  # ip → auth timestamps

    def ingest(self, auth_event_stream=None) -> ADFSSurface:
        surface = ADFSSurface()

        # Load preceding auth events for Golden SAML correlation
        if auth_event_stream:
            self._index_auth_events(auth_event_stream)

        for path in self.evtx_paths:
            self._parse_evtx(path, surface)

        # Derive summary fields
        surface.relying_parties = list({
            e.relying_party for e in surface.token_events if e.relying_party
        })
        surface.golden_saml_suspects = [
            e for e in surface.token_events if e.golden_saml_flags
        ]
        surface.unbacked_claim_grants = [
            e for e in surface.token_events if e.unbacked_claims
        ]

        if surface.golden_saml_suspects:
            log.warning(
                "GOLDEN SAML INDICATORS: %d suspicious token events detected",
                len(surface.golden_saml_suspects)
            )

        return surface

    def _index_auth_events(self, auth_stream) -> None:
        """Index auth events by IP for Golden SAML correlation."""
        for event in auth_stream.filter(ids=[4624]):
            ip = event.target_host or ""
            if ip:
                self._auth_events.setdefault(ip, []).append(event.timestamp)

    def _parse_evtx(self, path: Path, surface: ADFSSurface) -> None:
        try:
            from Evtx.Evtx import Evtx
            import xml.etree.ElementTree as ET
            with Evtx(str(path)) as evtx:
                for record in evtx.records():
                    try:
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        self._dispatch(root, surface)
                    except Exception as ex:
                        log.debug("ADFS parse error: %s", ex)
        except ImportError:
            log.warning("python-evtx not installed for ADFS log parsing.")

    def _dispatch(self, root, surface: ADFSSurface) -> None:
        import xml.etree.ElementTree as ET
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        sys_node = root.find("e:System", ns)
        if sys_node is None:
            return
        eid_node = sys_node.find("e:EventID", ns)
        if eid_node is None:
            return
        try:
            event_id = int(eid_node.text)
        except (TypeError, ValueError):
            return

        data: Dict[str, str] = {}
        event_data = root.find("e:EventData", ns)
        if event_data is not None:
            for item in event_data:
                name = item.get("Name", "")
                if name:
                    data[name] = item.text or ""

        time_node = sys_node.find("e:TimeCreated", ns)
        ts_str = time_node.get("SystemTime", "") if time_node is not None else ""
        try:
            timestamp = datetime.fromisoformat(ts_str.rstrip("Z"))
        except ValueError:
            timestamp = datetime.now(timezone.utc)

        comp_node = sys_node.find("e:Computer", ns)
        host = comp_node.text if comp_node is not None else ""

        if event_id == 299:
            self._parse_token_issued(timestamp, host, data, surface)
        elif event_id == 324:
            self._parse_authz_failure(timestamp, host, data, surface)
        elif event_id == 403:
            self._parse_claim_rule_change(timestamp, host, data, surface)
        elif event_id in (500, 501):
            self._parse_trust_event(timestamp, host, data, event_id, surface)

    def _parse_token_issued(self, timestamp: datetime, host: str,
                            data: Dict[str, str], surface: ADFSSurface) -> None:
        token = ADFSTokenEvent(
            timestamp=timestamp,
            event_id=299,
            source_host=host,
            user_identifier=data.get("UserIdentifier", ""),
            relying_party=data.get("RelyingParty", ""),
            auth_method=data.get("AuthMethod", ""),
            client_ip=data.get("IpAddress", ""),
        )
        # Parse claims from token
        raw_claims = data.get("Claims", "")
        token.claims = self._parse_claims_string(raw_claims)

        # Golden SAML check 1: was there a preceding auth event from this IP?
        preceding_auths = self._auth_events.get(token.client_ip, [])
        has_preceding = any(
            abs((timestamp - auth_ts).total_seconds()) < 60
            for auth_ts in preceding_auths
        )
        token.has_preceding_auth = has_preceding
        if not has_preceding and token.client_ip:
            token.golden_saml_flags.append("token_without_auth_event")

        # Check for unbacked claims (claim value not derivable from AD group)
        for claim in token.claims:
            if self._is_privileged_claim(claim) and not self._is_ad_backed(claim):
                token.unbacked_claims.append(f"{claim.claim_type}={claim.claim_value}")

        surface.token_events.append(token)

    def _parse_authz_failure(self, timestamp: datetime, host: str,
                             data: Dict[str, str], surface: ADFSSurface) -> None:
        # Authorisation failures can indicate policy probing
        log.debug("ADFS AuthZ failure at %s from %s for %s",
                  timestamp, data.get("IpAddress"), data.get("RelyingParty"))

    def _parse_claim_rule_change(self, timestamp: datetime, host: str,
                                 data: Dict[str, str], surface: ADFSSurface) -> None:
        change = ADFSClaimRuleChange(
            timestamp=timestamp,
            rule_set=data.get("RuleSetName", ""),
            relying_party=data.get("RelyingPartyName", ""),
            changed_by=data.get("UserData", ""),
        )
        surface.claim_rule_changes.append(change)
        log.warning("ADFS claim rule modified at %s for relying party %s",
                    timestamp, change.relying_party)

    def _parse_trust_event(self, timestamp: datetime, host: str,
                           data: Dict[str, str], event_id: int,
                           surface: ADFSSurface) -> None:
        trust = ADFSTrustEvent(
            timestamp=timestamp,
            trust_name=data.get("TrustName", ""),
            trust_type="relying_party" if "relying" in data.get("TrustType", "").lower()
                       else "claims_provider",
            action="added" if event_id == 500 else "removed",
        )
        surface.trust_events.append(trust)

    def _parse_claims_string(self, raw: str) -> List[ADFSClaim]:
        claims = []
        for line in raw.split("\n"):
            line = line.strip()
            if ":" in line:
                parts = line.split(":", 1)
                claims.append(ADFSClaim(
                    claim_type=parts[0].strip(),
                    claim_value=parts[1].strip() if len(parts) > 1 else "",
                ))
        return claims

    def _is_privileged_claim(self, claim: ADFSClaim) -> bool:
        privileged_keywords = ["admin", "role", "privilege", "group", "member"]
        return any(kw in claim.claim_type.lower() or kw in claim.claim_value.lower()
                   for kw in privileged_keywords)

    def _is_ad_backed(self, claim: ADFSClaim) -> bool:
        # In production: cross-reference claim value against AD groups
        # For now, flag any role claim as requiring verification
        return False
