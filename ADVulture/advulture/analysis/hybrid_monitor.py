# (c) 2025-2026 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture — Hybrid Identity Monitoring Module
Security monitoring for Azure AD Connect, PTA, Seamless SSO, and ADFS environments.

Detects:
- Sync account (MSOL_/AAD_) abuse
- Pass-through authentication anomalies
- Seamless SSO (AZUREADSSOACC) targeting
- Hybrid sync discrepancies
- ADFS federation security issues
- Golden SAML attack prerequisites

Based on learnings from entra_assessment.py and hybrid identity attack patterns.
"""

from __future__ import annotations
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Any, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from advulture.collection.ldap_enumerator import ADSnapshot, ADUser, ADComputer
    from advulture.collection.entra_ingester import EntraSnapshot, EntraSignIn

log = logging.getLogger(__name__)


@dataclass
class HybridFinding:
    """A hybrid identity security finding."""
    finding_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # sync_account, pta, seamless_sso, adfs, sync_discrepancy
    title: str
    description: str
    affected_objects: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[datetime] = None
    remediation: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "type": self.finding_type,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "affected_objects": self.affected_objects[:50],
            "affected_count": len(self.affected_objects),
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "remediation": self.remediation,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Sync Account Patterns
# ─────────────────────────────────────────────────────────────────────────────

SYNC_ACCOUNT_PATTERNS = ["MSOL_", "AAD_", "Sync_"]
ADFS_ACCOUNT_PATTERNS = ["adfs", "federation", "fs_"]


# ─────────────────────────────────────────────────────────────────────────────
# Azure AD Connect Sync Account Monitor
# ─────────────────────────────────────────────────────────────────────────────

class SyncAccountMonitor:
    """
    Monitor Azure AD Connect synchronization accounts for security issues.
    
    The sync account (MSOL_* or AAD_*) has DCSync-equivalent rights by design.
    Compromise of this account = full domain compromise.
    """
    
    def __init__(self, ad_snapshot: "ADSnapshot"):
        self.ad_snapshot = ad_snapshot
        self.sync_accounts = self._find_sync_accounts()
    
    def _find_sync_accounts(self) -> List["ADUser"]:
        """Identify Azure AD Connect sync accounts."""
        sync_accounts = []
        for user in self.ad_snapshot.users:
            sam = user.sam_account_name
            if any(sam.upper().startswith(p.upper()) for p in SYNC_ACCOUNT_PATTERNS):
                sync_accounts.append(user)
        return sync_accounts
    
    def assess(self) -> List[HybridFinding]:
        """Assess sync account security posture."""
        findings = []
        
        if not self.sync_accounts:
            findings.append(HybridFinding(
                finding_type="NO_SYNC_ACCOUNT",
                severity="INFO",
                category="sync_account",
                title="No Azure AD Connect Sync Account Found",
                description="May be cloud-only tenant or using different sync method (cloud sync)",
            ))
            return findings
        
        for account in self.sync_accounts:
            # Old password (should rotate with AAD Connect upgrades)
            if account.password_age_days > 180:
                findings.append(HybridFinding(
                    finding_type="SYNC_ACCOUNT_OLD_PASSWORD",
                    severity="MEDIUM",
                    category="sync_account",
                    title=f"Sync Account Old Password: {account.sam_account_name}",
                    description=f"Password is {account.password_age_days:.0f} days old",
                    affected_objects=[account.sam_account_name],
                    evidence={"password_age_days": account.password_age_days},
                    remediation="Password should rotate with AAD Connect upgrades (at least annually)",
                ))
            
            # Check for excessive group membership
            privileged_memberships = [
                m for m in account.member_of
                if any(g in m.lower() for g in ["domain admins", "enterprise admins", "schema admins"])
            ]
            
            if privileged_memberships:
                findings.append(HybridFinding(
                    finding_type="SYNC_ACCOUNT_EXCESSIVE_RIGHTS",
                    severity="HIGH",
                    category="sync_account",
                    title=f"Sync Account in Privileged Groups: {account.sam_account_name}",
                    description="Sync account has more rights than required (DCSync is sufficient)",
                    affected_objects=[account.sam_account_name],
                    evidence={"groups": privileged_memberships},
                    remediation="Remove sync account from Domain Admins/Enterprise Admins",
                ))
            
            # Kerberoastable sync account (has SPN)
            if account.has_spn:
                findings.append(HybridFinding(
                    finding_type="SYNC_ACCOUNT_KERBEROASTABLE",
                    severity="CRITICAL",
                    category="sync_account",
                    title=f"Sync Account is Kerberoastable: {account.sam_account_name}",
                    description="Sync account with SPN can be Kerberoasted for offline cracking",
                    affected_objects=[account.sam_account_name],
                    evidence={"spns": account.service_principal_names},
                    remediation="Remove SPNs from sync account or use gMSA",
                ))
        
        return findings
    
    def detect_abuse(self, events: List[Dict]) -> List[HybridFinding]:
        """
        Detect suspicious activity from sync accounts.
        
        Sync accounts should only authenticate from the AAD Connect server.
        Any other source or interactive logon is suspicious.
        """
        findings = []
        sync_names = {a.sam_account_name.lower() for a in self.sync_accounts}
        
        if not sync_names:
            return findings
        
        sources_by_account: Dict[str, Set[str]] = defaultdict(set)
        interactive_logons = []
        
        for event in events:
            account = (event.get("TargetUserName") or "").lower()
            if account not in sync_names:
                continue
            
            source = event.get("IpAddress") or event.get("WorkstationName")
            logon_type = event.get("LogonType")
            
            if source and source not in ("-", "::1", "127.0.0.1"):
                sources_by_account[account].add(source)
            
            # Interactive logon from sync account = critical
            if logon_type in (2, 10, 11):
                interactive_logons.append({
                    "account": account,
                    "logon_type": logon_type,
                    "source": source,
                    "timestamp": event.get("TimeCreated"),
                })
        
        # Flag interactive logons
        for logon in interactive_logons:
            findings.append(HybridFinding(
                finding_type="SYNC_ACCOUNT_INTERACTIVE_LOGON",
                severity="CRITICAL",
                category="sync_account",
                title=f"Sync Account Interactive Logon: {logon['account']}",
                description=f"Interactive logon from {logon['source']} - potential compromise",
                affected_objects=[logon["account"]],
                evidence=logon,
                timestamp=logon.get("timestamp"),
                remediation="Immediately investigate; sync accounts should never have interactive logons",
            ))
        
        # Flag multiple sources
        for account, sources in sources_by_account.items():
            if len(sources) > 2:  # AAD Connect server + possibly localhost
                findings.append(HybridFinding(
                    finding_type="SYNC_ACCOUNT_MULTIPLE_SOURCES",
                    severity="HIGH",
                    category="sync_account",
                    title=f"Sync Account Multiple Sources: {account}",
                    description=f"Authenticating from {len(sources)} different sources",
                    affected_objects=[account],
                    evidence={"sources": list(sources)},
                    remediation="Verify all sources are legitimate AAD Connect servers",
                ))
        
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Seamless SSO Monitor
# ─────────────────────────────────────────────────────────────────────────────

class SeamlessSSOMonitor:
    """
    Monitor the AZUREADSSOACC computer account for Seamless SSO.
    
    This account's Kerberos key is used to decrypt SSO tokens.
    Compromise allows forging SSO tokens for any user (Silver Ticket variant).
    """
    
    def __init__(self, ad_snapshot: "ADSnapshot"):
        self.ad_snapshot = ad_snapshot
        self.sso_account = self._find_sso_account()
    
    def _find_sso_account(self) -> Optional["ADComputer"]:
        """Find the Seamless SSO computer account."""
        for computer in self.ad_snapshot.computers:
            if computer.sam_account_name.upper() == "AZUREADSSOACC$":
                return computer
        return None
    
    def assess(self) -> List[HybridFinding]:
        """Assess Seamless SSO configuration security."""
        findings = []
        
        if not self.sso_account:
            findings.append(HybridFinding(
                finding_type="NO_SSO_ACCOUNT",
                severity="INFO",
                category="seamless_sso",
                title="Seamless SSO Not Configured",
                description="AZUREADSSOACC computer account not found",
            ))
            return findings
        
        findings.append(HybridFinding(
            finding_type="SSO_ENABLED",
            severity="INFO",
            category="seamless_sso",
            title="Seamless SSO is Configured",
            description="AZUREADSSOACC account found; ensure password is rotated every 30 days",
            affected_objects=["AZUREADSSOACC$"],
            remediation="Rotate AZUREADSSOACC password every 30 days via Update-AzureADSSOForest",
        ))
        
        return findings
    
    def detect_abuse(self, events: List[Dict]) -> List[HybridFinding]:
        """
        Detect suspicious activity targeting the SSO account.
        
        Any Kerberos service ticket requests for AZUREADSSOACC are suspicious
        and may indicate Silver Ticket attack preparation.
        """
        findings = []
        
        for event in events:
            if event.get("EventID") != 4769:  # TGS request
                continue
            
            service_name = (event.get("ServiceName") or "").upper()
            if "AZUREADSSOACC" in service_name:
                findings.append(HybridFinding(
                    finding_type="SSO_ACCOUNT_TGS_REQUEST",
                    severity="CRITICAL",
                    category="seamless_sso",
                    title="Suspicious TGS Request for AZUREADSSOACC",
                    description=f"TGS request from {event.get('TargetUserName')} - potential Silver Ticket attack",
                    evidence={
                        "requesting_user": event.get("TargetUserName"),
                        "source_ip": event.get("IpAddress"),
                        "timestamp": event.get("TimeCreated"),
                    },
                    timestamp=event.get("TimeCreated"),
                    remediation="Immediately investigate; rotate AZUREADSSOACC password",
                ))
        
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Hybrid Sync Validator
# ─────────────────────────────────────────────────────────────────────────────

class HybridSyncValidator:
    """
    Validate consistency between on-prem AD and Entra ID.
    
    Discrepancies may indicate:
    - Sync issues
    - Malicious manipulation
    - Orphaned accounts
    """
    
    def __init__(self, ad_snapshot: "ADSnapshot", entra_snapshot: "EntraSnapshot"):
        self.ad_snapshot = ad_snapshot
        self.entra_snapshot = entra_snapshot
    
    def validate(self) -> List[HybridFinding]:
        """Find sync discrepancies between AD and Entra."""
        findings = []
        
        # Build lookups
        ad_by_sid = {u.sid: u for u in self.ad_snapshot.users}
        ad_by_upn = {
            u.user_principal_name.lower(): u 
            for u in self.ad_snapshot.users 
            if u.user_principal_name
        }
        
        entra_by_sid = {}
        for u in self.entra_snapshot.users:
            if u.on_prem_sid:
                entra_by_sid[u.on_prem_sid] = u
        
        # Find synced Entra users with no on-prem match
        orphaned_entra = []
        for entra_user in self.entra_snapshot.users:
            if not entra_user.on_prem_sync:
                continue  # Cloud-only, expected
            
            if entra_user.on_prem_sid and entra_user.on_prem_sid not in ad_by_sid:
                orphaned_entra.append(entra_user.user_principal_name)
        
        if orphaned_entra:
            findings.append(HybridFinding(
                finding_type="ORPHANED_ENTRA_USERS",
                severity="HIGH",
                category="sync_discrepancy",
                title=f"Synced Entra Users Missing On-Prem: {len(orphaned_entra)}",
                description="Users marked as synced but source AD account not found",
                affected_objects=orphaned_entra,
                remediation="Verify source accounts or initiate hard-delete in Entra",
            ))
        
        # Find enabled state mismatches
        enabled_mismatches = []
        for sid, entra_user in entra_by_sid.items():
            ad_user = ad_by_sid.get(sid)
            if not ad_user:
                continue
            
            if entra_user.account_enabled != ad_user.enabled:
                enabled_mismatches.append({
                    "user": entra_user.user_principal_name,
                    "entra_enabled": entra_user.account_enabled,
                    "ad_enabled": ad_user.enabled,
                })
        
        if enabled_mismatches:
            findings.append(HybridFinding(
                finding_type="ENABLED_STATE_MISMATCH",
                severity="MEDIUM",
                category="sync_discrepancy",
                title=f"Enabled State Mismatches: {len(enabled_mismatches)}",
                description="Users with different enabled state in Entra vs AD",
                affected_objects=[m["user"] for m in enabled_mismatches],
                evidence={"mismatches": enabled_mismatches[:20]},
                remediation="Verify sync health and delta sync timing",
            ))
        
        # Find cloud-only admins (bypass on-prem controls)
        cloud_only_admins = []
        for entra_user in self.entra_snapshot.users:
            if entra_user.on_prem_sync:
                continue
            if entra_user.is_critical_role:
                cloud_only_admins.append({
                    "user": entra_user.user_principal_name,
                    "roles": entra_user.assigned_roles,
                    "mfa_registered": entra_user.mfa_registered,
                })
        
        if cloud_only_admins:
            # Severity depends on MFA status
            no_mfa_admins = [a for a in cloud_only_admins if not a["mfa_registered"]]
            severity = "HIGH" if no_mfa_admins else "INFO"
            
            findings.append(HybridFinding(
                finding_type="CLOUD_ONLY_ADMINS",
                severity=severity,
                category="sync_discrepancy",
                title=f"Cloud-Only Admin Accounts: {len(cloud_only_admins)}",
                description="Admin accounts that bypass on-prem security controls",
                affected_objects=[a["user"] for a in cloud_only_admins],
                evidence={"admins": cloud_only_admins[:20]},
                remediation="Ensure cloud-only admins have strong MFA; consider syncing from on-prem",
            ))
        
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# ADFS Monitor
# ─────────────────────────────────────────────────────────────────────────────

class ADFSMonitor:
    """
    Monitor ADFS for security issues in federated authentication.
    
    Detects:
    - Token replay attempts
    - Password spray against ADFS
    - Extranet lockouts
    - Golden SAML prerequisites
    """
    
    def __init__(self, ad_snapshot: "ADSnapshot"):
        self.ad_snapshot = ad_snapshot
        self.adfs_accounts = self._find_adfs_accounts()
    
    def _find_adfs_accounts(self) -> List["ADUser"]:
        """Find ADFS service accounts."""
        adfs_accounts = []
        for user in self.ad_snapshot.users:
            sam_lower = user.sam_account_name.lower()
            desc_lower = (user.description or "").lower()
            
            if any(p in sam_lower for p in ADFS_ACCOUNT_PATTERNS):
                adfs_accounts.append(user)
            elif "federation" in desc_lower or "adfs" in desc_lower:
                adfs_accounts.append(user)
        
        return adfs_accounts
    
    def assess_golden_saml_risk(self) -> List[HybridFinding]:
        """
        Check for Golden SAML attack prerequisites.
        
        Attack requires:
        1. ADFS service account credentials
        2. Token signing certificate private key
        
        We check for weaknesses in #1.
        """
        findings = []
        
        for account in self.adfs_accounts:
            # Kerberoastable ADFS account = Golden SAML risk
            if account.has_spn:
                findings.append(HybridFinding(
                    finding_type="ADFS_KERBEROASTABLE",
                    severity="CRITICAL",
                    category="adfs",
                    title=f"ADFS Account Kerberoastable: {account.sam_account_name}",
                    description="ADFS service account can be Kerberoasted - Golden SAML risk",
                    affected_objects=[account.sam_account_name],
                    evidence={"spns": account.service_principal_names},
                    remediation="Use gMSA for ADFS service account; rotate to strong password",
                ))
            
            # Old password
            if account.password_age_days > 365:
                findings.append(HybridFinding(
                    finding_type="ADFS_OLD_PASSWORD",
                    severity="HIGH",
                    category="adfs",
                    title=f"ADFS Account Old Password: {account.sam_account_name}",
                    description=f"Password is {account.password_age_days:.0f} days old",
                    affected_objects=[account.sam_account_name],
                    evidence={"password_age_days": account.password_age_days},
                    remediation="Rotate ADFS service account password annually",
                ))
        
        return findings
    
    def analyze_events(self, adfs_events: List[Dict]) -> List[HybridFinding]:
        """
        Analyze ADFS audit events for security issues.
        
        ADFS Event IDs:
        - 1200: Token issued successfully
        - 1201: Token request failed
        - 411: Token replay detected
        - 516: Extranet lockout
        """
        findings = []
        
        token_replays = []
        failed_by_ip: Dict[str, List] = defaultdict(list)
        extranet_lockouts = []
        
        for event in adfs_events:
            event_id = event.get("EventID")
            
            if event_id == 411:  # Token replay
                token_replays.append(event)
            
            elif event_id == 1201:  # Failed auth
                ip = event.get("IpAddress") or event.get("ClientIP")
                if ip:
                    failed_by_ip[ip].append(event)
            
            elif event_id == 516:  # Extranet lockout
                extranet_lockouts.append(event)
        
        # Token replays are critical
        if token_replays:
            findings.append(HybridFinding(
                finding_type="ADFS_TOKEN_REPLAY",
                severity="CRITICAL",
                category="adfs",
                title=f"ADFS Token Replay Detected: {len(token_replays)} events",
                description="Token replay attempts indicate active attack or stolen tokens",
                evidence={
                    "count": len(token_replays),
                    "samples": [
                        {"user": e.get("UserName"), "ip": e.get("IpAddress")}
                        for e in token_replays[:10]
                    ],
                },
                remediation="Investigate affected users; enforce MFA; check for token theft",
            ))
        
        # Password spray detection
        spray_ips = [
            (ip, events) for ip, events in failed_by_ip.items()
            if len(events) >= 10
        ]
        
        if spray_ips:
            findings.append(HybridFinding(
                finding_type="ADFS_PASSWORD_SPRAY",
                severity="HIGH",
                category="adfs",
                title=f"Password Spray Against ADFS: {len(spray_ips)} source IPs",
                description=f"High failure rates from {len(spray_ips)} IPs indicate password spray",
                affected_objects=[ip for ip, _ in spray_ips],
                evidence={
                    "source_ips": [
                        {"ip": ip, "failure_count": len(events)}
                        for ip, events in spray_ips
                    ],
                },
                remediation="Block source IPs; enable extranet lockout; review for successful attempts",
            ))
        
        # Extranet lockouts
        if extranet_lockouts:
            locked_users = list(set(e.get("UserName") for e in extranet_lockouts if e.get("UserName")))
            findings.append(HybridFinding(
                finding_type="ADFS_EXTRANET_LOCKOUTS",
                severity="MEDIUM",
                category="adfs",
                title=f"ADFS Extranet Lockouts: {len(extranet_lockouts)} events",
                description=f"{len(locked_users)} users experienced extranet lockout",
                affected_objects=locked_users[:50],
                evidence={"lockout_count": len(extranet_lockouts)},
                remediation="Review for legitimate vs attack-triggered lockouts",
            ))
        
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Unified Hybrid Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class HybridIdentityAnalyzer:
    """
    Unified analyzer for hybrid identity environments.
    
    Combines all hybrid monitoring capabilities into a single entry point.
    """
    
    def __init__(
        self,
        ad_snapshot: "ADSnapshot",
        entra_snapshot: Optional["EntraSnapshot"] = None,
    ):
        self.ad_snapshot = ad_snapshot
        self.entra_snapshot = entra_snapshot
        
        # Initialize component monitors
        self.sync_monitor = SyncAccountMonitor(ad_snapshot)
        self.sso_monitor = SeamlessSSOMonitor(ad_snapshot)
        self.adfs_monitor = ADFSMonitor(ad_snapshot)
        
        if entra_snapshot:
            self.sync_validator = HybridSyncValidator(ad_snapshot, entra_snapshot)
        else:
            self.sync_validator = None
    
    def analyze_all(
        self,
        onprem_events: Optional[List[Dict]] = None,
        adfs_events: Optional[List[Dict]] = None,
    ) -> Dict[str, List[HybridFinding]]:
        """
        Run all hybrid identity analyses.
        
        Returns findings organized by category.
        """
        results = {
            "sync_account": [],
            "seamless_sso": [],
            "adfs": [],
            "sync_discrepancy": [],
        }
        
        # Sync account assessment
        results["sync_account"].extend(self.sync_monitor.assess())
        if onprem_events:
            results["sync_account"].extend(self.sync_monitor.detect_abuse(onprem_events))
        
        # Seamless SSO assessment
        results["seamless_sso"].extend(self.sso_monitor.assess())
        if onprem_events:
            results["seamless_sso"].extend(self.sso_monitor.detect_abuse(onprem_events))
        
        # ADFS assessment
        results["adfs"].extend(self.adfs_monitor.assess_golden_saml_risk())
        if adfs_events:
            results["adfs"].extend(self.adfs_monitor.analyze_events(adfs_events))
        
        # Sync validation (requires Entra data)
        if self.sync_validator:
            results["sync_discrepancy"].extend(self.sync_validator.validate())
        
        # Log summary
        total = sum(len(f) for f in results.values())
        critical = sum(1 for findings in results.values() for f in findings if f.severity == "CRITICAL")
        high = sum(1 for findings in results.values() for f in findings if f.severity == "HIGH")
        
        log.info(
            "Hybrid identity analysis complete: %d findings (%d critical, %d high)",
            total, critical, high
        )
        
        return results
