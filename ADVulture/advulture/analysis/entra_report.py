# (c) 2025-2026 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture - Entra ID Report Generator
Generates factual security findings from collected Entra ID data.
No AI interpretation - purely data-driven findings.

Enhanced with behavioral analysis from entra_assessment.py learnings.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from enum import Enum
from pathlib import Path

# Import behavioral analysis module
try:
    from advulture.analysis.behavioral import (
        BehavioralAnalyzer,
        ServiceAccountAnalyzer,
        AuthEvent,
        normalize_entra_signin,
    )
    BEHAVIORAL_AVAILABLE = True
except ImportError:
    BEHAVIORAL_AVAILABLE = False

log = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    MFA_POSTURE = "MFA_POSTURE"
    PRIVILEGED_ACCESS = "PRIVILEGED_ACCESS"
    ROLE_HYGIENE = "ROLE_HYGIENE"
    SERVICE_PRINCIPAL = "SERVICE_PRINCIPAL"
    OAUTH_CONSENT = "OAUTH_CONSENT"
    AUTHENTICATION = "AUTHENTICATION"
    LEGACY_AUTH = "LEGACY_AUTH"
    RISK_DETECTION = "RISK_DETECTION"
    SUSPICIOUS_LOGIN = "SUSPICIOUS_LOGIN"
    CREDENTIAL_MISUSE = "CREDENTIAL_MISUSE"
    # New categories for O365/Defender
    SECURITY_ALERT = "SECURITY_ALERT"
    EMAIL_SECURITY = "EMAIL_SECURITY"
    APP_PERMISSIONS = "APP_PERMISSIONS"
    SHAREPOINT_SECURITY = "SHAREPOINT_SECURITY"
    # Configuration and governance categories
    GUEST_ACCESS = "GUEST_ACCESS"
    CONDITIONAL_ACCESS = "CONDITIONAL_ACCESS"
    IDENTITY_PROTECTION = "IDENTITY_PROTECTION"
    PASSWORD_POLICY = "PASSWORD_POLICY"
    DOMAIN_SECURITY = "DOMAIN_SECURITY"
    # Behavioral analysis categories (from entra_assessment.py learnings)
    BEHAVIORAL = "BEHAVIORAL"
    TOKEN_REPLAY = "TOKEN_REPLAY"
    IMPOSSIBLE_TRAVEL = "IMPOSSIBLE_TRAVEL"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"


@dataclass
class Finding:
    """A security finding from Entra ID analysis."""
    id: str
    severity: Severity
    category: Category
    title: str
    description: str
    affected_count: int
    affected_objects: List[str] = field(default_factory=list)
    recommendation: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "affected_count": self.affected_count,
            "affected_objects": self.affected_objects,
            "recommendation": self.recommendation,
            "references": self.references,
        }


@dataclass
class EntraReport:
    """Complete Entra ID security assessment report."""
    timestamp: datetime
    tenant_id: str
    organization_name: str = ""
    
    # Collection stats
    user_count: int = 0
    service_principal_count: int = 0
    role_definition_count: int = 0
    role_assignment_count: int = 0
    oauth_grant_count: int = 0
    signin_count: int = 0
    audit_count: int = 0
    
    # MFA stats - eligible users are interactive member accounts (not room/service/guest)
    eligible_user_count: int = 0  # Member users eligible for MFA
    ineligible_user_count: int = 0  # Room/service accounts (MFA not required)
    guest_user_count: int = 0  # External guests (MFA via home tenant)
    mfa_registered_count: int = 0  # Eligible users with any MFA
    mfa_capable_count: int = 0  # Eligible users with strong MFA (phishing-resistant)
    no_mfa_count: int = 0  # Eligible users without MFA
    weak_mfa_count: int = 0  # Eligible users with only weak MFA (SMS/email)
    
    # Findings
    findings: List[Finding] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "tenant_id": self.tenant_id,
            "organization_name": self.organization_name,
            "collection_stats": {
                "users": self.user_count,
                "service_principals": self.service_principal_count,
                "role_definitions": self.role_definition_count,
                "role_assignments": self.role_assignment_count,
                "oauth_grants": self.oauth_grant_count,
                "signins": self.signin_count,
                "audits": self.audit_count,
            },
            "mfa_stats": {
                "eligible_users": self.eligible_user_count,
                "ineligible_users": self.ineligible_user_count,
                "guest_users": self.guest_user_count,
                "registered": self.mfa_registered_count,
                "capable": self.mfa_capable_count,
                "no_mfa": self.no_mfa_count,
                "weak_mfa": self.weak_mfa_count,
            },
            "findings_summary": {
                "critical": len([f for f in self.findings if f.severity == Severity.CRITICAL]),
                "high": len([f for f in self.findings if f.severity == Severity.HIGH]),
                "medium": len([f for f in self.findings if f.severity == Severity.MEDIUM]),
                "low": len([f for f in self.findings if f.severity == Severity.LOW]),
                "info": len([f for f in self.findings if f.severity == Severity.INFO]),
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_markdown(self) -> str:
        """Generate markdown report with all affected objects."""
        lines = [
            f"# Entra ID Security Assessment Report",
            f"",
            f"**Generated:** {self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Tenant ID:** {self.tenant_id}",
            f"**Organization:** {self.organization_name or 'N/A'}",
            f"",
            f"## Collection Summary",
            f"",
            f"| Category | Count |",
            f"|----------|-------|",
            f"| Users | {self.user_count} |",
            f"| Service Principals | {self.service_principal_count} |",
            f"| Role Definitions | {self.role_definition_count} |",
            f"| Role Assignments | {self.role_assignment_count} |",
            f"| OAuth Grants | {self.oauth_grant_count} |",
            f"| Sign-in Events | {self.signin_count} |",
            f"| Audit Events | {self.audit_count} |",
            f"",
            f"## MFA Posture",
            f"",
            f"| Category | Count | Notes |",
            f"|----------|-------|-------|",
        ]
        
        if self.user_count > 0:
            # Calculate percentages based on eligible users only
            eligible = self.eligible_user_count or 1  # Avoid division by zero
            lines.extend([
                f"| **Eligible Members** | {self.eligible_user_count} | Interactive member accounts expected to have MFA |",
                f"| **Room/Service Accounts** | {self.ineligible_user_count} | MFA not required (see finding for list) |",
                f"| **External Guests** | {self.guest_user_count} | MFA handled by home tenant |",
                f"|  |  |  |",
                f"| Eligible with MFA | {self.mfa_registered_count} | {self.mfa_registered_count/eligible*100:.1f}% of eligible |",
                f"| Eligible with Strong MFA | {self.mfa_capable_count} | {self.mfa_capable_count/eligible*100:.1f}% of eligible (FIDO2, Authenticator, WHfB) |",
                f"| **Eligible without MFA** | {self.no_mfa_count} | {self.no_mfa_count/eligible*100:.1f}% of eligible - **see finding below** |",
                f"| Eligible with Weak MFA | {self.weak_mfa_count} | {self.weak_mfa_count/eligible*100:.1f}% of eligible (SMS/email only) |",
            ])
        
        lines.extend([
            f"",
            f"## Findings Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| CRITICAL | {len([f for f in self.findings if f.severity == Severity.CRITICAL])} |",
            f"| HIGH | {len([f for f in self.findings if f.severity == Severity.HIGH])} |",
            f"| MEDIUM | {len([f for f in self.findings if f.severity == Severity.MEDIUM])} |",
            f"| LOW | {len([f for f in self.findings if f.severity == Severity.LOW])} |",
            f"| INFO | {len([f for f in self.findings if f.severity == Severity.INFO])} |",
            f"",
            f"## Detailed Findings",
            f"",
        ])
        
        for i, finding in enumerate(self.findings, 1):
            lines.extend([
                f"### {i}. [{finding.severity.value}] {finding.title}",
                f"",
                f"**Category:** {finding.category.value}",
                f"",
                f"{finding.description}",
                f"",
                f"**Affected:** {finding.affected_count} objects",
                f"",
            ])
            if finding.affected_objects:
                lines.append("**Affected objects:**")
                for obj in finding.affected_objects:
                    lines.append(f"- {obj}")
                lines.append("")
            if finding.recommendation:
                lines.append(f"**Recommendation:** {finding.recommendation}")
                lines.append("")
        
        return "\n".join(lines)


class EntraReportGenerator:
    """
    Generates factual security findings from Entra ID snapshot and events.
    All findings are data-driven with no AI interpretation.
    """
    
    # High-privilege role names
    HIGH_PRIVILEGE_ROLES = {
        "Global Administrator",
        "Privileged Role Administrator", 
        "Privileged Authentication Administrator",
        "Security Administrator",
        "User Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "Intune Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Authentication Administrator",
        "Helpdesk Administrator",
        "Password Administrator",
        "Groups Administrator",
    }
    
    # High-risk OAuth scopes
    HIGH_RISK_SCOPES = {
        "Mail.ReadWrite", "Mail.ReadWrite.All",
        "Files.ReadWrite.All", 
        "Directory.ReadWrite.All",
        "User.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "Application.ReadWrite.All",
    }
    
    def __init__(self, snapshot, events=None):
        """
        Initialize report generator.
        
        Args:
            snapshot: EntraSnapshot from collection
            events: Optional EntraEventStream from log collection
        """
        self.snapshot = snapshot
        self.events = events
        self.findings: List[Finding] = []
        self._finding_id = 0
        # Build IP-to-location and device lookup tables from sign-in logs
        self._ip_locations = {}  # ip -> "City, Country"
        self._device_details = {}  # (user, device_id) -> "OS Browser/App"
        self._build_lookup_tables()
    
    def _build_lookup_tables(self):
        """Build lookup tables for IP geolocation and device details from sign-ins."""
        if not self.events or not self.events.signins:
            return
        
        for s in self.events.signins:
            # IP to location mapping
            if s.ip_address and s.ip_address not in self._ip_locations:
                location = getattr(s, 'location', None)
                if location:
                    city = location.get('city', '') if isinstance(location, dict) else getattr(location, 'city', '')
                    country = location.get('countryOrRegion', '') if isinstance(location, dict) else getattr(location, 'country_or_region', '')
                    if city or country:
                        self._ip_locations[s.ip_address] = f"{city}, {country}".strip(', ')
            
            # Device details mapping
            device_detail = getattr(s, 'device_detail', None)
            if device_detail and s.user_principal_name:
                device_id = None
                if isinstance(device_detail, dict):
                    device_id = device_detail.get('deviceId', device_detail.get('displayName', ''))
                    os_name = device_detail.get('operatingSystem', '')
                    browser = device_detail.get('browser', '')
                else:
                    device_id = getattr(device_detail, 'device_id', getattr(device_detail, 'display_name', ''))
                    os_name = getattr(device_detail, 'operating_system', '')
                    browser = getattr(device_detail, 'browser', '')
                
                if device_id or os_name or browser:
                    key = (s.user_principal_name, device_id or 'unknown')
                    if key not in self._device_details:
                        parts = []
                        if os_name:
                            parts.append(os_name)
                        if browser:
                            parts.append(browser)
                        self._device_details[key] = ' / '.join(parts) if parts else 'Unknown device'
    
    def _format_ip(self, ip: str) -> str:
        """Format IP with geolocation if available."""
        if not ip:
            return "Unknown IP"
        location = self._ip_locations.get(ip, '')
        if location:
            return f"{ip} ({location})"
        return ip
    
    def _format_device(self, user: str, device_id: str = None) -> str:
        """Format device with details if available."""
        if device_id:
            details = self._device_details.get((user, device_id), '')
            if details:
                return f"{device_id}: {details}"
            return device_id
        # Try to find any device for this user
        for (u, d), details in self._device_details.items():
            if u == user:
                return f"{d}: {details}"
        return "Unknown device"
    
    def _next_finding_id(self) -> str:
        self._finding_id += 1
        return f"ENTRA-{self._finding_id:03d}"
    
    def generate(self) -> EntraReport:
        """Generate the complete report."""
        self.findings = []
        self._finding_id = 0
        
        # Core identity analysis
        self._analyze_mfa_posture()
        self._analyze_privileged_access()
        self._analyze_service_principals()
        self._analyze_service_principal_credentials()
        self._analyze_oauth_grants()
        self._analyze_guest_access()
        self._analyze_conditional_access()
        self._analyze_domain_security()
        
        if self.events:
            self._analyze_authentication_logs()
            self._analyze_risk_detections()
            self._analyze_suspicious_signins()
            self._analyze_credential_misuse()
            # Advanced analysis
            self._analyze_mfa_fatigue()
            self._analyze_token_anomalies()
            self._analyze_consent_anomalies()
            self._analyze_cross_app_movement()
            # O365/Defender analysis
            self._analyze_security_alerts()
            self._analyze_email_security()
            self._analyze_app_permissions()
            self._analyze_sharepoint_security()
            # Behavioral analysis (from entra_assessment.py learnings)
            self._analyze_behavioral_patterns()
        
        # Sort findings by severity
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        self.findings.sort(key=lambda f: severity_order[f.severity])
        
        # Categorize users for MFA summary:
        # - Eligible: interactive member accounts expected to have MFA
        # - Ineligible: room/service accounts (MFA not required)
        # - Guests: external accounts (MFA handled by home tenant, shown separately)
        def is_room_service(user) -> bool:
            """Determine if user is a room/service account."""
            upn = (user.user_principal_name or '').lower()
            patterns = [
                'room', 'copier', 'printer', 'fax', 'scanner', 
                'shared', 'noreply', 'donotreply', 'service', 
                'mailbox', 'resource', 'conference', 'meeting',
                'zoom', 'teams', 'webex', 'zoomroom'
            ]
            return any(p in upn for p in patterns)
        
        def is_guest(user) -> bool:
            """Determine if user is an external guest."""
            return '#EXT#' in (user.user_principal_name or '')
        
        enabled_users = [u for u in self.snapshot.users if u.account_enabled]
        guest_users = [u for u in enabled_users if is_guest(u)]
        room_service_users = [u for u in enabled_users if is_room_service(u) and not is_guest(u)]
        eligible_users = [u for u in enabled_users if not is_room_service(u) and not is_guest(u)]
        ineligible_users = room_service_users  # Room/service accounts shown as ineligible
        
        # Build report with eligible-only MFA stats
        report = EntraReport(
            timestamp=datetime.now(timezone.utc),
            tenant_id=self.snapshot.tenant_id,
            organization_name=getattr(self.snapshot, 'organization_name', ''),
            user_count=len(self.snapshot.users),
            service_principal_count=len(self.snapshot.service_principals),
            role_definition_count=len(self.snapshot.role_definitions),
            role_assignment_count=len(self.snapshot.all_role_assignments),
            oauth_grant_count=len(self.snapshot.oauth_grants),
            signin_count=len(self.events.signins) if self.events else 0,
            audit_count=len(self.events.audits) if self.events else 0,
            eligible_user_count=len(eligible_users),
            ineligible_user_count=len(ineligible_users),
            guest_user_count=len(guest_users),
            mfa_registered_count=sum(1 for u in eligible_users if u.mfa_registered),
            mfa_capable_count=sum(1 for u in eligible_users if u.mfa_capable),
            no_mfa_count=sum(1 for u in eligible_users if not u.mfa_registered),
            weak_mfa_count=sum(1 for u in eligible_users if u.mfa_registered and not u.mfa_capable),
            findings=self.findings,
        )
        
        return report
    
    def _analyze_mfa_posture(self):
        """Analyze MFA registration status with sign-in context."""
        users = self.snapshot.users
        enabled_users = [u for u in users if u.account_enabled]
        
        # Categorization patterns (same as used in summary)
        def is_room_service(upn: str) -> bool:
            upn_lower = upn.lower()
            return any(p in upn_lower for p in [
                'room', 'copier', 'printer', 'fax', 'scanner', 
                'shared', 'noreply', 'donotreply', 'service', 
                'mailbox', 'resource', 'conference', 'meeting',
                'zoom', 'teams', 'webex', 'zoomroom'
            ])
        
        def is_guest(upn: str) -> bool:
            return '#EXT#' in upn
        
        # Users without MFA
        no_mfa = [u for u in enabled_users if not u.mfa_registered]
        
        if no_mfa:
            # Cross-reference with sign-in activity to provide context
            signin_users = set()
            external_signin_users = set()  # Users signing in from external/public IPs
            
            if self.events and self.events.signins:
                for s in self.events.signins:
                    if s.result == "success" or (hasattr(s.result, 'value') and s.result.value == "success"):
                        signin_users.add(s.user_principal_name)
                        # Heuristic: public IPs (non-RFC1918) suggest external access
                        if s.ip_address:
                            ip = s.ip_address
                            is_private = (ip.startswith('10.') or 
                                         ip.startswith('172.16.') or ip.startswith('172.17.') or 
                                         ip.startswith('172.18.') or ip.startswith('172.19.') or
                                         ip.startswith('172.2') or ip.startswith('172.30.') or ip.startswith('172.31.') or
                                         ip.startswith('192.168.') or ip.startswith('127.') or
                                         ip.startswith('fc') or ip.startswith('fd'))  # IPv6 private
                            if not is_private:
                                external_signin_users.add(s.user_principal_name)
            
            # Categorize no-MFA users by type and risk level
            room_service_accounts = []
            guest_accounts = []
            active_external_users = []  # HIGH risk - signing in from public IPs without MFA
            active_internal_users = []  # MEDIUM risk - signing in but only from private IPs
            inactive_users = []  # LOWER risk - not signing in recently
            
            for u in no_mfa:
                upn = u.user_principal_name or ''
                
                if is_room_service(upn):
                    room_service_accounts.append(upn)
                elif is_guest(upn):
                    guest_accounts.append(upn)
                elif upn in external_signin_users:
                    active_external_users.append(upn)
                elif upn in signin_users:
                    active_internal_users.append(upn)
                else:
                    inactive_users.append(upn)
            
            # Calculate eligible users (excluding room/service and guests) for summary reconciliation
            eligible_no_mfa = active_external_users + active_internal_users + inactive_users
            
            # Create a summary finding that reconciles with the MFA Posture table
            if eligible_no_mfa:
                summary_lines = [
                    f"**Summary of {len(eligible_no_mfa)} eligible users without MFA:**",
                    f"",
                ]
                if active_external_users:
                    summary_lines.append(f"**CRITICAL - Active External ({len(active_external_users)}):** signing in from public IPs")
                    for u in sorted(active_external_users):
                        summary_lines.append(f"  - {u}")
                if active_internal_users:
                    summary_lines.append(f"**MEDIUM - Active Internal ({len(active_internal_users)}):** signing in from private IPs only")
                    for u in sorted(active_internal_users):
                        summary_lines.append(f"  - {u}")
                if inactive_users:
                    summary_lines.append(f"**LOW - Inactive ({len(inactive_users)}):** no recent sign-in activity")
                    for u in sorted(inactive_users):
                        summary_lines.append(f"  - {u}")
                
                # Determine overall severity based on worst case
                if active_external_users:
                    severity = Severity.CRITICAL
                elif active_internal_users:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW
                
                self.findings.append(Finding(
                    id=self._next_finding_id(),
                    severity=severity,
                    category=Category.MFA_POSTURE,
                    title=f"Eligible Users Without MFA ({len(eligible_no_mfa)})",
                    description=f"{len(eligible_no_mfa)} interactive user accounts have no MFA registered. "
                               f"Breakdown: {len(active_external_users)} active external (CRITICAL), "
                               f"{len(active_internal_users)} active internal (MEDIUM), "
                               f"{len(inactive_users)} inactive (LOW). "
                               f"This reconciles with the MFA Posture summary table above.",
                    affected_count=len(eligible_no_mfa),
                    affected_objects=summary_lines,
                    recommendation="Prioritize MFA enrollment: (1) Active external users immediately, "
                                  "(2) Active internal users unless CA-protected, (3) Inactive users or disable.",
                ))
            
            # INFO: Room/service accounts (often don't need MFA if properly secured)
            if room_service_accounts:
                self.findings.append(Finding(
                    id=self._next_finding_id(),
                    severity=Severity.INFO,
                    category=Category.MFA_POSTURE,
                    title=f"Room/Service Accounts Without MFA ({len(room_service_accounts)})",
                    description=f"{len(room_service_accounts)} accounts appear to be room resources or service "
                               f"accounts based on naming patterns. These often don't require MFA if secured via "
                               f"Conditional Access (block external) or used non-interactively.",
                    affected_count=len(room_service_accounts),
                    affected_objects=room_service_accounts,
                    recommendation="Verify these accounts are secured via CA policies blocking external access, "
                                  "or are non-interactive with strong passwords. Consider converting to "
                                  "resource mailboxes where appropriate.",
                ))
            
            # Note: Guest accounts are NOT flagged for MFA here - their MFA is handled by their
            # home tenant during B2B authentication. Guest governance is handled in _analyze_guest_access()
        
        # Users with weak MFA
        weak_mfa = [u for u in enabled_users if u.mfa_registered and not u.mfa_capable]
        if weak_mfa:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.MEDIUM,
                category=Category.MFA_POSTURE,
                title=f"Users with Weak MFA Only ({len(weak_mfa)} users)",
                description=f"{len(weak_mfa)} users have only weak MFA methods (SMS or email) registered. "
                           f"These methods are vulnerable to SIM swapping and phishing attacks.",
                affected_count=len(weak_mfa),
                affected_objects=[u.user_principal_name for u in weak_mfa],
                recommendation="Migrate users to phishing-resistant MFA (FIDO2, Windows Hello, or Authenticator app).",
            ))
    
    def _analyze_privileged_access(self):
        """Analyze privileged role assignments and governance."""
        assignments = self.snapshot.all_role_assignments
        users = self.snapshot.users
        
        # Critical admin roles to track
        CRITICAL_ROLES = {
            "Global Administrator": "highest privilege - full tenant control",
            "Privileged Role Administrator": "can assign any role including Global Admin",
            "Privileged Authentication Administrator": "can reset any user's MFA/password",
            "Authentication Administrator": "can reset MFA/password for non-admins",
            "User Administrator": "can reset passwords for non-admins",
            "Exchange Administrator": "full Exchange/mail control",
            "SharePoint Administrator": "full SharePoint/OneDrive control",
            "Application Administrator": "can create apps with any permission",
            "Cloud Application Administrator": "can manage enterprise apps",
            "Intune Administrator": "full device management control",
            "Security Administrator": "can manage security settings",
            "Compliance Administrator": "can manage compliance settings",
            "Billing Administrator": "financial access",
            "Helpdesk Administrator": "can reset passwords for non-admins",
            "Password Administrator": "can reset passwords for non-admins",
        }
        
        # Find privileged assignments
        priv_assignments = [a for a in assignments if a.is_privileged]
        
        # Group by principal with role details
        principals_with_priv: Dict[str, List[str]] = {}
        for a in priv_assignments:
            key = a.principal_name or a.principal_id
            if key not in principals_with_priv:
                principals_with_priv[key] = []
            principals_with_priv[key].append(a.role_name)
        
        # 1. Global Administrator Analysis
        global_admins = [a for a in assignments if a.role_name == "Global Administrator"]
        ga_principals = []
        for a in global_admins:
            principal_name = a.principal_name or a.principal_id
            principal_type = a.principal_type or "unknown"
            assignment_type = "permanent"  # Default - would be 'eligible' if PIM
            if hasattr(a, 'assignment_type'):
                assignment_type = a.assignment_type
            
            # Check if user is cloud-only or synced
            source = "unknown"
            for u in users:
                if u.user_principal_name == principal_name or u.id == a.principal_id:
                    source = "cloud-only" if not getattr(u, 'on_premises_sync_enabled', False) else "synced from on-premises"
                    break
            
            ga_principals.append(f"{principal_name} ({principal_type}, {assignment_type}, {source})")
        
        if global_admins:
            severity = Severity.CRITICAL if len(global_admins) > 5 else Severity.HIGH if len(global_admins) > 2 else Severity.MEDIUM
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=severity,
                category=Category.PRIVILEGED_ACCESS,
                title=f"Global Administrator Count ({len(global_admins)})",
                description=f"Found {len(global_admins)} Global Administrator assignments. "
                           f"Microsoft recommends 2-4 Global Admins maximum. "
                           f"Best practice: use cloud-only accounts, PIM eligible assignments, and break-glass procedures.",
                affected_count=len(global_admins),
                affected_objects=ga_principals,
                recommendation="Reduce Global Admin count to 2-4. Use PIM for eligible (not permanent) assignments. "
                              "Ensure at least 2 cloud-only break-glass accounts exist.",
            ))
        
        # 2. Analyze each critical role
        role_summary = []
        for role_name, role_desc in CRITICAL_ROLES.items():
            role_assignments = [a for a in assignments if a.role_name == role_name]
            if role_assignments:
                principals = [a.principal_name or a.principal_id for a in role_assignments]
                role_summary.append(f"{role_name} ({len(role_assignments)}): {', '.join(principals)}")
        
        if role_summary:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.INFO,
                category=Category.PRIVILEGED_ACCESS,
                title=f"Critical Role Assignment Summary ({len(role_summary)} roles in use)",
                description="Summary of assignments to critical administrative roles. "
                           "Review each role to ensure assignments follow least-privilege principles.",
                affected_count=len(role_summary),
                affected_objects=role_summary,
                recommendation="Document business justification for each privileged assignment. "
                              "Consider using PIM for just-in-time activation.",
            ))
        
        # 3. Standing (permanent) vs eligible assignments
        permanent_priv = [a for a in priv_assignments if not getattr(a, 'is_eligible', False)]
        if len(permanent_priv) > 5:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH,
                category=Category.PRIVILEGED_ACCESS,
                title=f"Standing Privileged Access ({len(permanent_priv)} permanent assignments)",
                description=f"{len(permanent_priv)} privileged role assignments are permanent (always-on) rather than "
                           f"eligible (just-in-time via PIM). Standing access increases exposure window for compromised accounts.",
                affected_count=len(permanent_priv),
                affected_objects=[f"{a.principal_name or a.principal_id}: {a.role_name} (permanent)" for a in permanent_priv],
                recommendation="Enable Privileged Identity Management (PIM) and convert permanent assignments to eligible. "
                              "Require justification and approval for activation.",
            ))
        
        # 4. Check for users with multiple privileged roles
        multi_priv = {k: v for k, v in principals_with_priv.items() if len(v) >= 3}
        if multi_priv:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH,
                category=Category.ROLE_HYGIENE,
                title=f"Principals with Multiple Privileged Roles ({len(multi_priv)})",
                description=f"{len(multi_priv)} principals hold 3 or more privileged roles. "
                           f"This violates the principle of least privilege and increases blast radius.",
                affected_count=len(multi_priv),
                affected_objects=[f"{k}: {len(v)} roles ({', '.join(v)})" for k, v in list(multi_priv.items())],
                recommendation="Review and consolidate role assignments. Use PIM for just-in-time access.",
            ))
        
        # 5. Check for privileged users without MFA
        priv_user_names = set(principals_with_priv.keys())
        priv_users_no_mfa = [
            u for u in self.snapshot.users 
            if u.user_principal_name in priv_user_names and not u.mfa_registered
        ]
        if priv_users_no_mfa:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.CRITICAL,
                category=Category.PRIVILEGED_ACCESS,
                title=f"Privileged Users Without MFA ({len(priv_users_no_mfa)})",
                description=f"{len(priv_users_no_mfa)} users with privileged roles have no MFA registered. "
                           f"Privileged accounts are high-value targets and must have strong MFA.",
                affected_count=len(priv_users_no_mfa),
                affected_objects=[u.user_principal_name for u in priv_users_no_mfa],
                recommendation="Immediately enable phishing-resistant MFA for all privileged accounts.",
            ))
    
    def _analyze_service_principals(self):
        """Analyze service principal configurations."""
        assignments = self.snapshot.all_role_assignments
        
        # Service principals with privileged roles
        sp_priv = [a for a in assignments if a.is_privileged and a.principal_type == "servicePrincipal"]
        if sp_priv:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.MEDIUM,
                category=Category.SERVICE_PRINCIPAL,
                title=f"Service Principals with Privileged Roles ({len(sp_priv)})",
                description=f"{len(sp_priv)} service principals have privileged directory roles. "
                           f"These automated accounts may have credentials stored in code or config files.",
                affected_count=len(sp_priv),
                affected_objects=[f"{a.principal_name}: {a.role_name}" for a in sp_priv],
                recommendation="Review service principal permissions. Use managed identities where possible.",
            ))
    
    def _analyze_oauth_grants(self):
        """Analyze OAuth consent grants."""
        grants = self.snapshot.oauth_grants
        
        # Build a map of client_id -> app name from service principals
        sp_name_map = {}
        for sp in self.snapshot.service_principals:
            if isinstance(sp, dict):
                sp_id = sp.get("appId", sp.get("id", ""))
                sp_name = sp.get("displayName", "Unknown App")
            else:
                sp_id = getattr(sp, "app_id", getattr(sp, "id", ""))
                sp_name = getattr(sp, "display_name", "Unknown App")
            if sp_id:
                sp_name_map[sp_id] = sp_name
        
        # Find high-risk grants (grants are stored as dicts)
        risky_grants = []
        for g in grants:
            # Handle both dict and object forms
            if isinstance(g, dict):
                scope = g.get("scope", "") or ""
                client_id = g.get("clientId", g.get("client_id", "unknown"))
                principal_id = g.get("principalId", "")
            else:
                scope = getattr(g, "scope", "") or ""
                client_id = getattr(g, "client_id", "unknown")
                principal_id = getattr(g, "principal_id", "")
            
            if any(risk_scope in scope for risk_scope in self.HIGH_RISK_SCOPES):
                app_name = sp_name_map.get(client_id, client_id)
                risky_grants.append({"client_id": client_id, "app_name": app_name, "scope": scope})
        
        if risky_grants:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH if len(risky_grants) > 10 else Severity.MEDIUM,
                category=Category.OAUTH_CONSENT,
                title=f"High-Risk OAuth Consent Grants ({len(risky_grants)})",
                description=f"{len(risky_grants)} OAuth grants include high-risk scopes that allow "
                           f"applications to read/write sensitive data (mail, files, directory).",
                affected_count=len(risky_grants),
                affected_objects=[f"{g['app_name']} ({g['client_id']}): {g['scope']}" for g in risky_grants],
                recommendation="Review and revoke unnecessary OAuth grants. Implement admin consent workflow.",
            ))
    
    def _analyze_authentication_logs(self):
        """Analyze sign-in and audit logs."""
        if not self.events:
            return
        
        signins = self.events.signins
        
        # Legacy authentication
        legacy = [s for s in signins if s.legacy_auth]
        if legacy:
            pct = len(legacy) / len(signins) * 100 if signins else 0
            unique_users = list(set(s.user_principal_name for s in legacy))
            
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.MEDIUM,
                category=Category.LEGACY_AUTH,
                title=f"Legacy Authentication Usage ({len(legacy)} events, {pct:.1f}%)",
                description=f"{len(legacy)} sign-ins used legacy authentication protocols which bypass MFA. "
                           f"{len(unique_users)} unique users affected.",
                affected_count=len(unique_users),
                affected_objects=unique_users,
                recommendation="Block legacy authentication via Conditional Access policy.",
            ))
        
        # Failed sign-ins
        failed = [s for s in signins if s.result != "success"]
        if len(failed) > 50:
            # Group by user with failure details
            from collections import defaultdict
            user_failures = defaultdict(list)
            for s in failed:
                result_val = s.result.value if hasattr(s.result, 'value') else str(s.result)
                user_failures[s.user_principal_name].append({
                    'time': s.timestamp.strftime("%Y-%m-%d %H:%M"),
                    'reason': result_val,
                    'ip': s.ip_address or 'N/A',
                    'app': s.app_display_name or 'Unknown'
                })
            
            # Build table format per user
            user_tables = []
            for user, failures in sorted(user_failures.items(), key=lambda x: -len(x[1])):
                user_tables.append(f"**{user}** ({len(failures)} failures):")
                # Show up to 10 most recent failures per user
                for f in failures[:10]:
                    ip_formatted = self._format_ip(f['ip']) if f['ip'] != 'N/A' else 'N/A'
                    user_tables.append(f"  - {f['time']} | {ip_formatted} | {f['reason']} | {f['app']}")
                if len(failures) > 10:
                    user_tables.append(f"  - ... and {len(failures) - 10} more")
            
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.INFO,
                category=Category.AUTHENTICATION,
                title=f"Failed Sign-in Attempts ({len(failed)} events)",
                description=f"{len(failed)} failed sign-in attempts from {len(user_failures)} unique accounts. "
                           f"Review for potential brute-force or credential stuffing attacks.",
                affected_count=len(user_failures),
                affected_objects=user_tables,
                recommendation="Investigate repeated failures. Consider smart lockout policies.",
            ))

    def _analyze_risk_detections(self):
        """Analyze Identity Protection risk detections."""
        if not self.events or not self.events.risk_detections:
            return
        
        detections = self.events.risk_detections
        
        # Map risk event types to human-readable descriptions
        RISK_TYPE_DESCRIPTIONS = {
            "unfamiliarFeatures": "Unfamiliar sign-in properties",
            "impossibleTravel": "Impossible travel (geographically impossible)",
            "maliciousIPAddress": "Sign-in from known malicious IP",
            "suspiciousIPAddress": "Sign-in from suspicious IP",
            "leakedCredentials": "Leaked credentials detected",
            "anonymizedIPAddress": "Sign-in from anonymized IP (VPN/Tor)",
            "malwareInfectedIPAddress": "Sign-in from malware-infected IP",
            "suspiciousBrowser": "Suspicious browser fingerprint",
            "passwordSpray": "Password spray attack detected",
            "anomalousToken": "Anomalous token activity",
            "tokenIssuerAnomaly": "Token issuer anomaly",
            "suspiciousInboxForwardingRules": "Suspicious inbox forwarding rules",
            "anomalousUserActivity": "Anomalous user activity",
            "investigationsThreatIntelligence": "Microsoft threat intelligence",
            "riskyIPAddress": "Sign-in from risky IP",
            "mcasSuspiciousInboxManipulationRules": "Suspicious inbox manipulation",
        }
        
        # Group by risk level
        high_risk = [r for r in detections if r.get("riskLevel") == "high"]
        medium_risk = [r for r in detections if r.get("riskLevel") == "medium"]
        
        # High-risk detections - CRITICAL
        if high_risk:
            unique_users = list(set(r.get("userPrincipalName", "unknown") for r in high_risk))
            risk_types = list(set(r.get("riskEventType", "unknown") for r in high_risk))
            
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.CRITICAL,
                category=Category.RISK_DETECTION,
                title=f"High-Risk Identity Protection Alerts ({len(high_risk)} detections)",
                description=f"Microsoft Identity Protection flagged {len(high_risk)} high-risk events "
                           f"affecting {len(unique_users)} users. Risk types: {', '.join(risk_types)}. "
                           f"These indicate potential active compromise or credential theft.",
                affected_count=len(unique_users),
                affected_objects=[f"{r.get('userPrincipalName', 'N/A')}: {RISK_TYPE_DESCRIPTIONS.get(r.get('riskEventType'), r.get('riskEventType', 'unknown'))} "
                                 f"from {r.get('ipAddress', 'N/A')}" for r in high_risk],
                recommendation="Immediately investigate all high-risk users. Reset credentials, revoke sessions, "
                              "and review audit logs for signs of compromise.",
                references=["https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk"],
            ))
        
        # Medium-risk detections - HIGH
        if medium_risk:
            unique_users = list(set(r.get("userPrincipalName", "unknown") for r in medium_risk))
            risk_types = list(set(r.get("riskEventType", "unknown") for r in medium_risk))
            
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH,
                category=Category.RISK_DETECTION,
                title=f"Medium-Risk Identity Protection Alerts ({len(medium_risk)} detections)",
                description=f"{len(medium_risk)} medium-risk events affecting {len(unique_users)} users. "
                           f"Risk types: {', '.join(risk_types)}. "
                           f"These may indicate attempted compromise or policy violations.",
                affected_count=len(unique_users),
                affected_objects=[f"{r.get('userPrincipalName', 'N/A')}: {RISK_TYPE_DESCRIPTIONS.get(r.get('riskEventType'), r.get('riskEventType', 'unknown'))}" 
                                 for r in medium_risk],
                recommendation="Review affected users and require MFA re-registration or password reset as appropriate.",
            ))
        
        # Analyze by specific high-concern risk types
        impossible_travel = [r for r in detections if r.get("riskEventType") == "impossibleTravel"]
        if impossible_travel:
            unique_users = list(set(r.get("userPrincipalName", "unknown") for r in impossible_travel))
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH,
                category=Category.RISK_DETECTION,
                title=f"Impossible Travel Detected ({len(impossible_travel)} events)",
                description=f"Sign-ins from geographically impossible locations detected for {len(unique_users)} users. "
                           f"This typically indicates credential theft with attacker sign-in from a different location.",
                affected_count=len(unique_users),
                affected_objects=[f"{r.get('userPrincipalName', 'N/A')}: {r.get('location', {}).get('city', 'N/A')}, "
                                 f"{r.get('location', {}).get('country', 'N/A')}" for r in impossible_travel],
                recommendation="Verify with users if travel is legitimate. If not, treat as credential compromise.",
            ))
        
        leaked_creds = [r for r in detections if r.get("riskEventType") == "leakedCredentials"]
        if leaked_creds:
            unique_users = list(set(r.get("userPrincipalName", "unknown") for r in leaked_creds))
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.CRITICAL,
                category=Category.RISK_DETECTION,
                title=f"Leaked Credentials Detected ({len(leaked_creds)} users)",
                description=f"Microsoft detected {len(unique_users)} users with credentials appearing in "
                           f"dark web dumps or public breaches. These accounts are at immediate risk of takeover.",
                affected_count=len(unique_users),
                affected_objects=unique_users,
                recommendation="Force immediate password reset for all affected accounts. Enable MFA if not already enabled.",
            ))
        
        anon_ip = [r for r in detections if r.get("riskEventType") == "anonymizedIPAddress"]
        if len(anon_ip) > 5:
            unique_users = list(set(r.get("userPrincipalName", "unknown") for r in anon_ip))
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.MEDIUM,
                category=Category.RISK_DETECTION,
                title=f"Anonymized IP Sign-ins ({len(anon_ip)} events)",
                description=f"{len(anon_ip)} sign-ins from anonymized IPs (VPN/Tor/proxy) by {len(unique_users)} users. "
                           f"May indicate policy violation or attempt to hide malicious activity.",
                affected_count=len(unique_users),
                affected_objects=unique_users,
                recommendation="Review if VPN usage is authorized. Consider blocking anonymized IPs via Conditional Access.",
            ))

    def _analyze_suspicious_signins(self):
        """Analyze sign-in patterns for suspicious behavior."""
        if not self.events or not self.events.signins:
            return
        
        signins = self.events.signins
        from collections import defaultdict
        from datetime import timedelta
        
        # 1. Risky sign-ins (risk level during sign-in)
        risky_signins = [s for s in signins if s.risk_level_during in ("high", "medium")]
        if risky_signins:
            unique_users = list(set(s.user_principal_name for s in risky_signins))
            high_risk = [s for s in risky_signins if s.risk_level_during == "high"]
            
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH if high_risk else Severity.MEDIUM,
                category=Category.SUSPICIOUS_LOGIN,
                title=f"Risky Sign-ins Detected ({len(risky_signins)} events)",
                description=f"{len(risky_signins)} sign-ins flagged as risky ({len(high_risk)} high, "
                           f"{len(risky_signins) - len(high_risk)} medium) affecting {len(unique_users)} users. "
                           f"These passed authentication but exhibited risk indicators.",
                affected_count=len(unique_users),
                affected_objects=[f"{s.user_principal_name}: {s.risk_level_during} risk from {s.ip_address}" 
                                 for s in risky_signins],
                recommendation="Review risky sign-ins. Consider requiring reauthentication for elevated risk.",
            ))
        
        # 2. Off-hours authentication (weekdays 10pm-6am, or weekends)
        off_hours = []
        for s in signins:
            if s.result == "success" or (hasattr(s.result, 'value') and s.result.value == "success"):
                hour = s.timestamp.hour
                weekday = s.timestamp.weekday()
                # Off hours: 10pm-6am or weekends
                if hour < 6 or hour >= 22 or weekday >= 5:
                    off_hours.append(s)
        
        if len(off_hours) > 20:
            # Group by user to find unusual patterns
            user_off_hours = defaultdict(list)
            for s in off_hours:
                user_off_hours[s.user_principal_name].append(s)
            
            # Flag users with significant off-hours activity
            suspicious_users = {u: events for u, events in user_off_hours.items() if len(events) >= 5}
            
            if suspicious_users:
                # Build table per user with timestamp, IP+location, device, app
                user_tables = []
                for u, events in sorted(suspicious_users.items(), key=lambda x: -len(x[1])):
                    user_tables.append(f"**{u}** ({len(events)} off-hours sign-ins):")
                    # Sort by time and show up to 10
                    sorted_events = sorted(events, key=lambda e: e.timestamp)[:10]
                    for e in sorted_events:
                        time_str = e.timestamp.strftime("%Y-%m-%d %H:%M")
                        ip_str = self._format_ip(e.ip_address) if e.ip_address else "N/A"
                        app_str = e.app_display_name or "Unknown"
                        # Get device details
                        device_detail = getattr(e, 'device_detail', None)
                        if device_detail:
                            if isinstance(device_detail, dict):
                                os_name = device_detail.get('operatingSystem', '')
                                browser = device_detail.get('browser', '')
                            else:
                                os_name = getattr(device_detail, 'operating_system', '')
                                browser = getattr(device_detail, 'browser', '')
                            device_str = f"{os_name} / {browser}".strip(' /') or "Unknown device"
                        else:
                            device_str = "Unknown device"
                        user_tables.append(f"  - {time_str} | {ip_str} | {device_str} | {app_str}")
                    if len(events) > 10:
                        user_tables.append(f"  - ... and {len(events) - 10} more")
                
                self.findings.append(Finding(
                    id=self._next_finding_id(),
                    severity=Severity.LOW,
                    category=Category.SUSPICIOUS_LOGIN,
                    title=f"Off-Hours Authentication Activity ({len(off_hours)} events)",
                    description=f"{len(off_hours)} successful sign-ins occurred outside business hours "
                               f"(10pm-6am or weekends) from {len(suspicious_users)} users with 5+ events. "
                               f"While some may be legitimate, review for unauthorized access.",
                    affected_count=len(suspicious_users),
                    affected_objects=user_tables,
                    recommendation="Verify off-hours access aligns with user job requirements. "
                                  "Consider time-based Conditional Access for sensitive roles.",
                ))
        
        # 3. Multi-geography sign-ins (same user, different countries in short window)
        user_signins = defaultdict(list)
        for s in signins:
            if s.location and s.location.get("countryOrRegion"):
                user_signins[s.user_principal_name].append(s)
        
        geo_anomalies = []
        for user, user_events in user_signins.items():
            if len(user_events) < 2:
                continue
            # Sort by time
            sorted_events = sorted(user_events, key=lambda x: x.timestamp)
            for i in range(1, len(sorted_events)):
                prev, curr = sorted_events[i-1], sorted_events[i]
                prev_country = prev.location.get("countryOrRegion", "") if prev.location else ""
                curr_country = curr.location.get("countryOrRegion", "") if curr.location else ""
                time_diff = (curr.timestamp - prev.timestamp).total_seconds() / 3600  # hours
                
                # Different countries within 2 hours is suspicious
                if prev_country and curr_country and prev_country != curr_country and time_diff < 2:
                    geo_anomalies.append({
                        "user": user,
                        "from_country": prev_country,
                        "to_country": curr_country,
                        "time_diff_hours": round(time_diff, 1),
                    })
        
        if geo_anomalies:
            unique_users = list(set(a["user"] for a in geo_anomalies))
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH,
                category=Category.SUSPICIOUS_LOGIN,
                title=f"Rapid Geography Changes ({len(geo_anomalies)} events)",
                description=f"{len(geo_anomalies)} instances of users signing in from different countries "
                           f"within 2 hours. Affects {len(unique_users)} users. This may indicate credential sharing or theft.",
                affected_count=len(unique_users),
                affected_objects=[f"{a['user']}: {a['from_country']} → {a['to_country']} in {a['time_diff_hours']}h" 
                                 for a in geo_anomalies],
                recommendation="Investigate each case. Legitimate travel is rare within 2 hours across countries.",
            ))
        
        # 4. Unusual IP diversity (one user, many IPs in short period)
        user_ips = defaultdict(set)
        for s in signins:
            if s.ip_address:
                user_ips[s.user_principal_name].add(s.ip_address)
        
        ip_diversity_threshold = 10
        diverse_users = {u: ips for u, ips in user_ips.items() if len(ips) >= ip_diversity_threshold}
        
        if diverse_users:
            # Build table per user with IP + geolocation
            user_tables = []
            for user, ips in diverse_users.items():
                user_tables.append(f"**{user}** ({len(ips)} IPs):")
                for ip in sorted(ips):
                    user_tables.append(f"  - {self._format_ip(ip)}")
            
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.MEDIUM,
                category=Category.SUSPICIOUS_LOGIN,
                title=f"High IP Address Diversity ({len(diverse_users)} users)",
                description=f"{len(diverse_users)} users authenticated from {ip_diversity_threshold}+ distinct "
                           f"IP addresses during the analysis period. May indicate credential sharing, "
                           f"VPN rotation, or compromised credentials used by multiple actors.",
                affected_count=len(diverse_users),
                affected_objects=user_tables,
                recommendation="Review if IP diversity is expected (mobile users, VPN). "
                              "Excessive diversity may indicate credential compromise.",
            ))

    def _analyze_credential_misuse(self):
        """Analyze patterns indicating credential misuse or compromise."""
        if not self.events:
            return
        
        signins = self.events.signins or []
        audits = self.events.audits or []
        from collections import defaultdict
        
        # 1. Password spray detection (many failed logins to many accounts from same IP)
        ip_failed_users = defaultdict(set)
        for s in signins:
            result_val = s.result.value if hasattr(s.result, 'value') else str(s.result)
            if result_val == "invalid_credentials" and s.ip_address:
                ip_failed_users[s.ip_address].add(s.user_principal_name)
        
        spray_ips = {ip: users for ip, users in ip_failed_users.items() if len(users) >= 5}
        
        if spray_ips:
            total_affected = set()
            for users in spray_ips.values():
                total_affected.update(users)
            
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.CRITICAL,
                category=Category.CREDENTIAL_MISUSE,
                title=f"Password Spray Attack Detected ({len(spray_ips)} source IPs)",
                description=f"Detected {len(spray_ips)} IP addresses attempting failed logins against "
                           f"5+ different accounts each. Total {len(total_affected)} accounts targeted. "
                           f"This is a classic password spray pattern attempting to avoid account lockout.",
                affected_count=len(total_affected),
                affected_objects=[f"{ip}: {len(users)} accounts targeted" for ip, users in list(spray_ips.items())],
                recommendation="Block attacking IPs. Verify no accounts were compromised. "
                              "Review password policies and implement smart lockout.",
            ))
        
        # 2. Credential stuffing (same account, many failed attempts from different IPs)
        user_failed_ips = defaultdict(set)
        for s in signins:
            result_val = s.result.value if hasattr(s.result, 'value') else str(s.result)
            if result_val == "invalid_credentials" and s.ip_address:
                user_failed_ips[s.user_principal_name].add(s.ip_address)
        
        stuffing_targets = {u: ips for u, ips in user_failed_ips.items() if len(ips) >= 5}
        
        if stuffing_targets:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH,
                category=Category.CREDENTIAL_MISUSE,
                title=f"Credential Stuffing Targets ({len(stuffing_targets)} accounts)",
                description=f"{len(stuffing_targets)} accounts received failed login attempts from 5+ "
                           f"different IP addresses. This pattern suggests credentials may have been leaked "
                           f"and attackers are attempting to use them.",
                affected_count=len(stuffing_targets),
                affected_objects=[f"{u}: {len(ips)} attacking IPs" for u, ips in list(stuffing_targets.items())],
                recommendation="Force password reset for targeted accounts. Verify MFA is enabled. "
                              "Check if credentials appear in breach databases.",
            ))
        
        # 3. Successful login after many failures (potential successful brute force)
        user_login_sequence = defaultdict(list)
        for s in sorted(signins, key=lambda x: x.timestamp):
            user_login_sequence[s.user_principal_name].append(s)
        
        brute_force_success = []
        for user, events in user_login_sequence.items():
            consecutive_failures = 0
            for event in events:
                result_val = event.result.value if hasattr(event.result, 'value') else str(event.result)
                if result_val == "invalid_credentials":
                    consecutive_failures += 1
                elif result_val == "success" and consecutive_failures >= 5:
                    brute_force_success.append({
                        "user": user,
                        "failures_before_success": consecutive_failures,
                        "success_ip": event.ip_address,
                        "success_time": event.timestamp.isoformat(),
                    })
                    consecutive_failures = 0
                else:
                    consecutive_failures = 0
        
        if brute_force_success:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.CRITICAL,
                category=Category.CREDENTIAL_MISUSE,
                title=f"Successful Login After Multiple Failures ({len(brute_force_success)} accounts)",
                description=f"{len(brute_force_success)} accounts had successful logins immediately after "
                           f"5+ consecutive failed attempts. This may indicate successful password guessing or "
                           f"user recovering from typos, but requires investigation.",
                affected_count=len(brute_force_success),
                affected_objects=[f"{b['user']}: {b['failures_before_success']} failures → success from {b['success_ip']}" 
                                 for b in brute_force_success],
                recommendation="Contact affected users to verify login was legitimate. "
                              "If not confirmed, treat as compromised and reset credentials.",
            ))
        
        # 4. Service account behavioral anomalies (service accounts signing in interactively)
        service_principals = {sp.display_name.lower() for sp in self.snapshot.service_principals}
        service_patterns = ["svc_", "svc-", "service", "_sa", "-sa", "automation", "api_", "api-"]
        
        potential_service_accounts = []
        for user in self.snapshot.users:
            upn_lower = user.user_principal_name.lower()
            name_lower = user.display_name.lower()
            if any(p in upn_lower or p in name_lower for p in service_patterns):
                potential_service_accounts.append(user.user_principal_name)
        
        # Check if these "service accounts" have interactive sign-ins
        service_interactive = []
        for s in signins:
            result_val = s.result.value if hasattr(s.result, 'value') else str(s.result)
            if s.user_principal_name in potential_service_accounts and result_val == "success":
                # Check if it's an interactive sign-in (not API/service)
                if s.app_display_name and "Azure Portal" in s.app_display_name or "Office" in s.app_display_name:
                    service_interactive.append(s)
        
        if service_interactive:
            unique_svc = list(set(s.user_principal_name for s in service_interactive))
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.MEDIUM,
                category=Category.CREDENTIAL_MISUSE,
                title=f"Service Accounts with Interactive Sign-ins ({len(unique_svc)} accounts)",
                description=f"{len(unique_svc)} accounts with service-account naming patterns have "
                           f"interactive sign-ins (Azure Portal, Office apps). Service accounts should "
                           f"typically only use API/automation flows, not interactive logins.",
                affected_count=len(unique_svc),
                affected_objects=[f"{s.user_principal_name}: {s.app_display_name} from {s.ip_address}" 
                                 for s in service_interactive],
                recommendation="Verify if interactive access is expected. Consider blocking interactive "
                              "sign-ins for service accounts via Conditional Access.",
            ))
        
        # 5. Dormant accounts suddenly active
        dormant_threshold_days = 90
        recent_threshold_days = 7
        from datetime import datetime, timezone, timedelta
        
        now = datetime.now(timezone.utc)
        dormant_cutoff = now - timedelta(days=dormant_threshold_days)
        recent_cutoff = now - timedelta(days=recent_threshold_days)
        
        reactivated_accounts = []
        for user in self.snapshot.users:
            if user.last_signin and user.last_signin < dormant_cutoff:
                # Account was dormant - check if there are recent sign-ins
                recent_signins = [s for s in signins 
                                 if s.user_principal_name == user.user_principal_name 
                                 and s.timestamp > recent_cutoff]
                if recent_signins:
                    reactivated_accounts.append({
                        "user": user.user_principal_name,
                        "last_known_signin": user.last_signin.isoformat(),
                        "recent_signin_count": len(recent_signins),
                    })
        
        if reactivated_accounts:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH,
                category=Category.CREDENTIAL_MISUSE,
                title=f"Dormant Accounts Reactivated ({len(reactivated_accounts)} accounts)",
                description=f"{len(reactivated_accounts)} accounts that were dormant for 90+ days "
                           f"have new sign-in activity in the past week. Dormant accounts are common "
                           f"targets for attackers as unusual activity may go unnoticed.",
                affected_count=len(reactivated_accounts),
                affected_objects=[f"{a['user']}: last seen {a['last_known_signin']}, {a['recent_signin_count']} recent sign-ins" 
                                 for a in reactivated_accounts],
                recommendation="Contact account owners to verify reactivation is legitimate. "
                              "Consider disabling accounts dormant for extended periods.",
            ))

    def _analyze_mfa_fatigue(self):
        """Detect MFA fatigue/push bombing attacks."""
        if not self.events or not self.events.signins:
            return
        
        signins = self.events.signins
        from collections import defaultdict
        from datetime import timedelta
        
        # Look for pattern: many MFA_REQUIRED followed by success
        user_mfa_events = defaultdict(list)
        for s in signins:
            result_val = s.result.value if hasattr(s.result, 'value') else str(s.result)
            if result_val in ("mfa_required", "mfa_completed", "success"):
                user_mfa_events[s.user_principal_name].append(s)
        
        fatigue_victims = []
        for user, events in user_mfa_events.items():
            sorted_events = sorted(events, key=lambda x: x.timestamp)
            
            # Look for bursts of MFA prompts
            mfa_burst_count = 0
            burst_start = None
            for i, event in enumerate(sorted_events):
                result_val = event.result.value if hasattr(event.result, 'value') else str(event.result)
                
                if result_val == "mfa_required":
                    if burst_start is None:
                        burst_start = event.timestamp
                    mfa_burst_count += 1
                elif result_val in ("mfa_completed", "success") and mfa_burst_count >= 3:
                    # Success after multiple MFA prompts
                    time_window = (event.timestamp - burst_start).total_seconds() / 60  # minutes
                    if time_window < 30:  # 3+ MFA prompts within 30 minutes
                        fatigue_victims.append({
                            "user": user,
                            "mfa_prompts": mfa_burst_count,
                            "time_window_min": round(time_window, 1),
                            "success_time": event.timestamp.isoformat()[:19],
                        })
                    mfa_burst_count = 0
                    burst_start = None
                else:
                    mfa_burst_count = 0
                    burst_start = None
        
        if fatigue_victims:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.CRITICAL,
                category=Category.CREDENTIAL_MISUSE,
                title=f"Potential MFA Fatigue Attacks ({len(fatigue_victims)} users)",
                description=f"{len(fatigue_victims)} users received multiple MFA push notifications "
                           f"in rapid succession followed by approval. This pattern indicates possible "
                           f"MFA fatigue/push bombing attacks where users approve out of frustration.",
                affected_count=len(fatigue_victims),
                affected_objects=[f"{v['user']}: {v['mfa_prompts']} prompts in {v['time_window_min']}min → approved" 
                                 for v in fatigue_victims],
                recommendation="Contact affected users immediately. If they did not initiate the MFA requests, "
                              "treat as compromised. Consider switching to phishing-resistant MFA (FIDO2/passkeys).",
                references=["https://learn.microsoft.com/en-us/entra/identity/authentication/concepts-mfa-fatigue"],
            ))

    def _analyze_token_anomalies(self):
        """Detect anomalous token usage patterns (potential token theft/replay)."""
        if not self.events or not self.events.signins:
            return
        
        signins = self.events.signins
        from collections import defaultdict
        
        # Look for same user, same app, different IPs in short succession
        user_app_signins = defaultdict(list)
        for s in signins:
            result_val = s.result.value if hasattr(s.result, 'value') else str(s.result)
            if result_val == "success":
                key = (s.user_principal_name, s.app_display_name)
                user_app_signins[key].append(s)
        
        token_anomalies = []
        for (user, app), events in user_app_signins.items():
            if len(events) < 2:
                continue
            
            sorted_events = sorted(events, key=lambda x: x.timestamp)
            for i in range(1, len(sorted_events)):
                prev, curr = sorted_events[i-1], sorted_events[i]
                if not prev.ip_address or not curr.ip_address:
                    continue
                
                # Different IPs within 5 minutes is suspicious for same app
                time_diff = (curr.timestamp - prev.timestamp).total_seconds()
                if prev.ip_address != curr.ip_address and time_diff < 300:
                    token_anomalies.append({
                        "user": user,
                        "app": app,
                        "ip1": prev.ip_address,
                        "ip2": curr.ip_address,
                        "time_diff_sec": int(time_diff),
                    })
        
        if token_anomalies:
            unique_users = list(set(a["user"] for a in token_anomalies))
            # Build table with IP geolocation
            anomaly_details = []
            for a in token_anomalies:
                ip1_fmt = self._format_ip(a['ip1'])
                ip2_fmt = self._format_ip(a['ip2'])
                anomaly_details.append(f"**{a['user']}** ({a['app']}): {ip1_fmt} → {ip2_fmt} in {a['time_diff_sec']}s")
            
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH,
                category=Category.CREDENTIAL_MISUSE,
                title=f"Token Replay Indicators ({len(token_anomalies)} events)",
                description=f"Detected {len(token_anomalies)} instances where the same user accessed "
                           f"the same application from different IP addresses within 5 minutes. "
                           f"This may indicate stolen tokens being replayed by an attacker.",
                affected_count=len(unique_users),
                affected_objects=anomaly_details,
                recommendation="Review if users were using VPN or mobile networks. If not, "
                              "revoke sessions and investigate for token theft.",
            ))

    def _analyze_consent_anomalies(self):
        """Detect suspicious OAuth consent grants."""
        if not self.events:
            return
        
        audits = self.events.audits or []
        
        # Look for consent grant events
        consent_events = [a for a in audits if "consent" in a.activity_display_name.lower() 
                         or "permission" in a.activity_display_name.lower()]
        
        # High-risk permissions to flag
        RISKY_SCOPES = {
            "Mail.Read", "Mail.ReadWrite", "Mail.Send",
            "Files.ReadWrite.All", "Files.Read.All",
            "Directory.ReadWrite.All", "User.ReadWrite.All",
            "offline_access",  # Can refresh tokens indefinitely
        }
        
        risky_consents = []
        for event in consent_events:
            # Check if any risky scopes in target resources
            for target in event.target_resources:
                if any(scope in str(target) for scope in RISKY_SCOPES):
                    risky_consents.append({
                        "user": event.initiated_by_upn,
                        "activity": event.activity_display_name,
                        "target": str(target),
                        "timestamp": event.timestamp.isoformat()[:19],
                    })
        
        if risky_consents:
            unique_users = list(set(c["user"] for c in risky_consents))
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH,
                category=Category.APP_PERMISSIONS,
                title=f"Risky OAuth Consent Events ({len(risky_consents)} grants)",
                description=f"Detected {len(risky_consents)} consent grants for high-risk permissions "
                           f"(Mail, Files, Directory access) from {len(unique_users)} users. "
                           f"Attackers use consent phishing to gain persistent access.",
                affected_count=len(unique_users),
                affected_objects=[f"{c['user']}: {c['activity']}" for c in risky_consents],
                recommendation="Review all consent grants. Revoke unauthorized app permissions. "
                              "Consider enabling admin consent workflow.",
                references=["https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow"],
            ))

    def _analyze_cross_app_movement(self):
        """Detect unusual cross-application access patterns (lateral movement via apps)."""
        if not self.events or not self.events.signins:
            return
        
        signins = self.events.signins
        from collections import defaultdict
        
        # Track apps accessed per user
        user_apps = defaultdict(set)
        user_app_times = defaultdict(list)
        
        for s in signins:
            result_val = s.result.value if hasattr(s.result, 'value') else str(s.result)
            if result_val == "success" and s.app_display_name:
                user_apps[s.user_principal_name].add(s.app_display_name)
                user_app_times[s.user_principal_name].append((s.timestamp, s.app_display_name))
        
        # Define sensitive app combinations (accessing both in short time is suspicious)
        SENSITIVE_COMBOS = [
            ({"Azure Portal", "Microsoft Azure CLI", "Azure PowerShell"}, 
             {"Exchange Online", "SharePoint Online", "Microsoft Teams"}),
            ({"Microsoft Graph Explorer", "Graph API"}, 
             {"Exchange Online", "SharePoint Online"}),
        ]
        
        cross_app_suspects = []
        for user, apps in user_apps.items():
            # Check for unusual app diversity
            if len(apps) > 15:
                cross_app_suspects.append({
                    "user": user,
                    "issue": "high_app_diversity",
                    "app_count": len(apps),
                    "apps": list(apps),
                })
            
            # Check for admin tool + data access combination
            admin_apps = {"Azure Portal", "Microsoft Azure CLI", "Azure PowerShell", 
                         "Entra Admin Center", "Microsoft 365 admin center"}
            data_apps = {"SharePoint Online", "OneDrive", "Exchange Online", "Microsoft Teams"}
            
            accessed_admin = apps & admin_apps
            accessed_data = apps & data_apps
            
            if accessed_admin and accessed_data:
                # Check timing - both accessed in same session?
                times = sorted(user_app_times[user], key=lambda x: x[0])
                admin_times = [t for t, app in times if app in admin_apps]
                data_times = [t for t, app in times if app in data_apps]
                
                if admin_times and data_times:
                    min_gap = min(abs((a - d).total_seconds()) 
                                 for a in admin_times for d in data_times)
                    if min_gap < 600:  # Within 10 minutes
                        cross_app_suspects.append({
                            "user": user,
                            "issue": "admin_data_combo",
                            "admin_apps": list(accessed_admin),
                            "data_apps": list(accessed_data),
                            "min_gap_sec": int(min_gap),
                        })
        
        if cross_app_suspects:
            high_diversity = [s for s in cross_app_suspects if s["issue"] == "high_app_diversity"]
            admin_combo = [s for s in cross_app_suspects if s["issue"] == "admin_data_combo"]
            
            if admin_combo:
                self.findings.append(Finding(
                    id=self._next_finding_id(),
                    severity=Severity.MEDIUM,
                    category=Category.SUSPICIOUS_LOGIN,
                    title=f"Admin + Data Access Patterns ({len(admin_combo)} users)",
                    description=f"{len(admin_combo)} users accessed both admin portals and data applications "
                               f"(SharePoint/Exchange/Teams) within short time windows. While this may be legitimate "
                               f"for admins, it's a common pattern during account compromise.",
                    affected_count=len(admin_combo),
                    affected_objects=[f"{s['user']}: {s['admin_apps']} + {s['data_apps']}" 
                                     for s in admin_combo],
                    recommendation="Verify these users require both admin and data access. "
                                  "Consider separating admin and user accounts.",
                ))

    def _analyze_security_alerts(self):
        """Analyze Microsoft Defender / Security alerts."""
        if not self.events or not hasattr(self.events, 'security_alerts'):
            return
        
        alerts = self.events.security_alerts or []
        if not alerts:
            return
        
        # Group by category
        from collections import defaultdict
        by_category = defaultdict(list)
        for alert in alerts:
            by_category[alert.category].append(alert)
        
        # Critical/High severity alerts
        critical_alerts = [a for a in alerts if a.severity in ("high", "critical")]
        if critical_alerts:
            unique_users = list(set(a.user_principal_name for a in critical_alerts if a.user_principal_name))
            categories = list(set(a.category for a in critical_alerts))
            
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.CRITICAL,
                category=Category.SECURITY_ALERT,
                title=f"Microsoft Defender High/Critical Alerts ({len(critical_alerts)})",
                description=f"Microsoft Defender detected {len(critical_alerts)} high or critical severity alerts "
                           f"affecting {len(unique_users)} users. Categories: {', '.join(categories)}. "
                           f"These require immediate investigation.",
                affected_count=len(unique_users),
                affected_objects=[f"[{a.severity.upper()}] {a.title}: {a.user_principal_name or 'N/A'}" 
                                 for a in critical_alerts],
                recommendation="Investigate all critical alerts immediately. Follow Defender recommended actions.",
            ))
        
        # Phishing-specific alerts
        phishing_keywords = ["phish", "credential", "bec", "business email", "impersonation"]
        phishing_alerts = [a for a in alerts 
                          if any(kw in a.title.lower() or kw in a.category.lower() 
                                for kw in phishing_keywords)]
        
        if phishing_alerts:
            unique_users = list(set(a.user_principal_name for a in phishing_alerts if a.user_principal_name))
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH,
                category=Category.EMAIL_SECURITY,
                title=f"Phishing/BEC Alerts ({len(phishing_alerts)} detections)",
                description=f"Detected {len(phishing_alerts)} phishing or business email compromise alerts "
                           f"from Microsoft Defender for Office 365. {len(unique_users)} users targeted.",
                affected_count=len(unique_users),
                affected_objects=[f"{a.title}: {a.user_principal_name}" for a in phishing_alerts],
                recommendation="Quarantine affected messages. Check if users clicked links or provided credentials. "
                              "Consider security awareness training.",
            ))

    def _analyze_email_security(self):
        """Analyze email security: forwarding rules, inbox manipulation."""
        if not self.events or not hasattr(self.events, 'mailbox_rules'):
            return
        
        rules = self.events.mailbox_rules or []
        if not rules:
            return
        
        # External forwarding rules - HIGH RISK
        external_fwd = [r for r in rules if r.is_external_forward and r.is_enabled]
        if external_fwd:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.CRITICAL,
                category=Category.EMAIL_SECURITY,
                title=f"External Email Forwarding Rules ({len(external_fwd)} rules)",
                description=f"Found {len(external_fwd)} active inbox rules forwarding or redirecting email "
                           f"to external addresses. This is a common persistence technique for BEC and "
                           f"data exfiltration attacks.",
                affected_count=len(external_fwd),
                affected_objects=[f"{r.user_principal_name}: '{r.display_name}' → {r.forwards_to + r.redirects_to}" 
                                 for r in external_fwd],
                recommendation="Immediately review and disable unauthorized forwarding rules. "
                              "Block external auto-forwarding at the transport level.",
                references=["https://learn.microsoft.com/en-us/exchange/policy-and-compliance/mail-flow-rules/mail-flow-rules"],
            ))
        
        # Rules that delete messages (hiding tracks)
        delete_rules = [r for r in rules if r.delete_message and r.is_enabled]
        if delete_rules:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH,
                category=Category.EMAIL_SECURITY,
                title=f"Email Deletion Rules ({len(delete_rules)} rules)",
                description=f"Found {len(delete_rules)} inbox rules that automatically delete messages. "
                           f"Attackers use these to hide evidence like password reset notifications "
                           f"or security alerts from compromised users.",
                affected_count=len(delete_rules),
                affected_objects=[f"{r.user_principal_name}: '{r.display_name}'" for r in delete_rules],
                recommendation="Review deletion rules. Legitimate rules are rare - investigate any you find.",
            ))

    def _analyze_app_permissions(self):
        """Analyze application permission grants."""
        if not self.events or not hasattr(self.events, 'app_permission_grants'):
            return
        
        grants = self.events.app_permission_grants or []
        if not grants:
            return
        
        # High-risk permission grants
        high_risk = [g for g in grants if g.is_high_risk]
        if high_risk:
            # Group by app
            from collections import defaultdict
            by_app = defaultdict(list)
            for g in high_risk:
                by_app[g.app_display_name].append(g.permission)
            
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH,
                category=Category.APP_PERMISSIONS,
                title=f"High-Risk Application Permissions ({len(high_risk)} grants)",
                description=f"Found {len(high_risk)} high-risk Graph API permissions granted to "
                           f"{len(by_app)} applications. These permissions allow reading/writing "
                           f"mail, files, or directory data.",
                affected_count=len(by_app),
                affected_objects=[f"{app}: {', '.join(perms[:3])}{'...' if len(perms) > 3 else ''}" 
                                 for app, perms in list(by_app.items())],
                recommendation="Review if each application requires these permissions. "
                              "Remove unnecessary grants. Prefer delegated over application permissions.",
            ))
        
        # Apps with Mail.Send (can send as users)
        mail_send = [g for g in grants if "Mail.Send" in g.permission]
        if mail_send:
            apps_with_send = list(set(g.app_display_name for g in mail_send))
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.MEDIUM,
                category=Category.APP_PERMISSIONS,
                title=f"Applications with Mail.Send Permission ({len(apps_with_send)} apps)",
                description=f"{len(apps_with_send)} applications have Mail.Send permission, allowing them "
                           f"to send email on behalf of users. If compromised, these apps could be used "
                           f"for phishing or BEC attacks.",
                affected_count=len(apps_with_send),
                affected_objects=apps_with_send,
                recommendation="Verify each app requires Mail.Send. Consider using send-on-behalf-of with "
                              "specific mailboxes instead of tenant-wide permission.",
            ))

    def _analyze_sharepoint_security(self):
        """Analyze SharePoint/OneDrive security indicators."""
        if not self.events or not hasattr(self.events, 'unified_audit_logs'):
            return
        
        audit_logs = self.events.unified_audit_logs or []
        if not audit_logs:
            return
        
        # Anonymous sharing links
        anon_links = [e for e in audit_logs if e.get("type") == "SharePointAnonymousLink"]
        if anon_links:
            sites = list(set(e.get("site_name", "Unknown") for e in anon_links))
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.MEDIUM,
                category=Category.SHAREPOINT_SECURITY,
                title=f"SharePoint Anonymous Sharing Links ({len(anon_links)} links)",
                description=f"Found {len(anon_links)} anonymous (anyone with the link) sharing permissions "
                           f"across {len(sites)} SharePoint sites. These links can be forwarded to "
                           f"unintended recipients without tracking.",
                affected_count=len(sites),
                affected_objects=[f"Site: {e.get('site_name', 'Unknown')}" for e in anon_links],
                recommendation="Review anonymous links for sensitive content. Consider restricting "
                              "to 'People in your organization' or specific people.",
            ))
        
        # Unusual SharePoint access patterns (many different sites in short time)
        sp_access = [e for e in audit_logs if e.get("type") == "SharePointAccess"]
        if sp_access:
            from collections import defaultdict
            user_access = defaultdict(set)
            for e in sp_access:
                if e.get("status") == "success":
                    user_access[e.get("user", "")].add(e.get("app", ""))
            
            # Users accessing from many different locations
            from collections import Counter
            user_locations = defaultdict(set)
            for e in sp_access:
                location = e.get("location", {})
                if location and e.get("user"):
                    loc_key = f"{location.get('city', '')}, {location.get('country', '')}"
                    if loc_key != ", ":
                        user_locations[e.get("user")].add(loc_key)
            
            multi_location = {u: locs for u, locs in user_locations.items() if len(locs) >= 3}
            if multi_location:
                self.findings.append(Finding(
                    id=self._next_finding_id(),
                    severity=Severity.LOW,
                    category=Category.SHAREPOINT_SECURITY,
                    title=f"SharePoint Access from Multiple Locations ({len(multi_location)} users)",
                    description=f"{len(multi_location)} users accessed SharePoint from 3+ different "
                               f"geographic locations. While this may be normal for traveling users, "
                               f"verify if access patterns are expected.",
                    affected_count=len(multi_location),
                    affected_objects=[f"{u}: {len(locs)} locations - {', '.join(sorted(locs))}" for u, locs in list(multi_location.items())],
                    recommendation="Review if geographic diversity is expected for these users.",
                ))

    def _analyze_guest_access(self):
        """Analyze guest/external user governance."""
        users = self.snapshot.users
        
        # Identify guest users
        guests = [u for u in users if '#EXT#' in (u.user_principal_name or '') or 
                  getattr(u, 'user_type', '') == 'Guest']
        
        if guests:
            # Group by source domain
            from collections import defaultdict
            domain_guests = defaultdict(list)
            for g in guests:
                upn = g.user_principal_name or ''
                if '#EXT#' in upn:
                    # Extract original domain from UPN like user_domain.com#EXT#@tenant.onmicrosoft.com
                    original = upn.split('#EXT#')[0]
                    if '_' in original:
                        domain = original.rsplit('_', 1)[-1]
                    else:
                        domain = 'unknown'
                else:
                    domain = upn.split('@')[-1] if '@' in upn else 'unknown'
                domain_guests[domain].append(g.user_principal_name)
            
            # Build summary
            domain_summary = [f"{domain}: {len(users)} guests ({', '.join(users)})" 
                            for domain, users in sorted(domain_guests.items(), key=lambda x: -len(x[1]))]
            
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.MEDIUM if len(guests) > 20 else Severity.LOW,
                category=Category.GUEST_ACCESS,
                title=f"External Guest Users ({len(guests)} accounts from {len(domain_guests)} domains)",
                description=f"Found {len(guests)} guest/external user accounts from {len(domain_guests)} external domains. "
                           f"Guest accounts can access shared resources and should be governed via access reviews.",
                affected_count=len(guests),
                affected_objects=domain_summary,
                recommendation="Implement guest access reviews. Configure B2B collaboration settings. "
                              "Consider blocking guest access to sensitive apps via Conditional Access.",
            ))
            
            # Check for guests with privileged roles
            guest_upns = set(g.user_principal_name for g in guests)
            assignments = self.snapshot.all_role_assignments
            guest_priv = [a for a in assignments if a.is_privileged and 
                         (a.principal_name in guest_upns)]
            
            if guest_priv:
                self.findings.append(Finding(
                    id=self._next_finding_id(),
                    severity=Severity.CRITICAL,
                    category=Category.GUEST_ACCESS,
                    title=f"Guest Users with Privileged Roles ({len(guest_priv)})",
                    description=f"{len(guest_priv)} guest/external users have privileged directory roles. "
                               f"This is extremely high-risk as external identities are outside your control.",
                    affected_count=len(guest_priv),
                    affected_objects=[f"{a.principal_name}: {a.role_name}" for a in guest_priv],
                    recommendation="Remove privileged roles from guest accounts immediately. "
                                  "External users should never have admin access to your tenant.",
                ))

    def _analyze_conditional_access(self):
        """Analyze Conditional Access policy coverage and configuration."""
        ca_policies = getattr(self.snapshot, 'ca_policies', []) or []
        
        if not ca_policies:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH,
                category=Category.CONDITIONAL_ACCESS,
                title="No Conditional Access Policies Found",
                description="No Conditional Access policies were retrieved. This could mean: "
                           "(1) No policies are configured - critical security gap, or "
                           "(2) Insufficient permissions to read CA policies (Policy.Read.All required).",
                affected_count=0,
                affected_objects=["Unable to enumerate CA policies"],
                recommendation="Configure Conditional Access policies for: MFA enforcement, "
                              "device compliance, trusted locations, risky sign-in blocking, "
                              "and legacy auth blocking.",
            ))
            return
        
        # Categorize policies by state
        enabled = [p for p in ca_policies if p.get('state') == 'enabled']
        report_only = [p for p in ca_policies if p.get('state') == 'enabledForReportingButNotEnforced']
        disabled = [p for p in ca_policies if p.get('state') == 'disabled']
        
        # Analyze what controls are covered
        has_mfa_policy = False
        has_device_compliance = False
        has_trusted_location = False
        has_legacy_auth_block = False
        has_risky_signin_block = False
        has_admin_protection = False
        
        policy_details = []
        for p in ca_policies:
            name = p.get('displayName', 'Unknown')
            state = p.get('state', 'unknown')
            grant_controls = p.get('grantControls', {})
            conditions = p.get('conditions', {})
            
            controls = grant_controls.get('builtInControls', []) if grant_controls else []
            
            # Check what's covered
            if 'mfa' in controls:
                has_mfa_policy = True
            if 'compliantDevice' in controls or 'domainJoinedDevice' in controls:
                has_device_compliance = True
            if 'block' in controls:
                # Check if it's blocking risky sign-ins or legacy auth
                apps = conditions.get('applications', {}) or {}
                client_app_types = conditions.get('clientAppTypes', []) or []
                
                if 'exchangeActiveSync' in str(client_app_types) or 'other' in str(client_app_types):
                    has_legacy_auth_block = True
            
            # Check for admin protection
            users = conditions.get('users', {}) or {}
            include_roles = users.get('includeRoles', []) if isinstance(users, dict) else []
            if include_roles:
                has_admin_protection = True
            
            control_str = ', '.join(controls) if controls else 'no controls'
            policy_details.append(f"{name}: [{state}] - Controls: {control_str}")
        
        # Generate finding for CA policy overview
        self.findings.append(Finding(
            id=self._next_finding_id(),
            severity=Severity.INFO,
            category=Category.CONDITIONAL_ACCESS,
            title=f"Conditional Access Policy Summary ({len(ca_policies)} policies)",
            description=f"Found {len(enabled)} enabled, {len(report_only)} report-only, "
                       f"and {len(disabled)} disabled policies.",
            affected_count=len(ca_policies),
            affected_objects=policy_details,
            recommendation="Review policy coverage. Ensure all critical controls are enforced, not report-only.",
        ))
        
        # Check for gaps
        gaps = []
        if not has_mfa_policy:
            gaps.append("No MFA enforcement policy found")
        if not has_legacy_auth_block:
            gaps.append("No legacy authentication blocking policy found")
        if not has_admin_protection:
            gaps.append("No policy specifically protecting admin roles")
        if len(report_only) > len(enabled):
            gaps.append(f"{len(report_only)} policies in report-only mode vs {len(enabled)} enforced")
        
        if gaps:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH if len(gaps) >= 2 else Severity.MEDIUM,
                category=Category.CONDITIONAL_ACCESS,
                title=f"Conditional Access Coverage Gaps ({len(gaps)} issues)",
                description="Conditional Access policy stack has gaps that may leave users or scenarios unprotected.",
                affected_count=len(gaps),
                affected_objects=gaps,
                recommendation="Address each gap: (1) Require MFA for all users, "
                              "(2) Block legacy auth, (3) Protect admin accounts with stricter controls, "
                              "(4) Move report-only policies to enforced after testing.",
            ))

    def _analyze_service_principal_credentials(self):
        """Analyze service principal credential hygiene."""
        sps = self.snapshot.service_principals
        
        # Check for SPs with credentials (secrets/certs)
        sps_with_creds = []
        expired_creds = []
        expiring_soon = []
        
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        soon = now + timedelta(days=30)
        
        for sp in sps:
            if isinstance(sp, dict):
                sp_name = sp.get('displayName', sp.get('appId', 'Unknown'))
                sp_id = sp.get('id', '')
                key_creds = sp.get('keyCredentials', [])
                pwd_creds = sp.get('passwordCredentials', [])
            else:
                sp_name = getattr(sp, 'display_name', getattr(sp, 'app_id', 'Unknown'))
                sp_id = getattr(sp, 'id', '')
                key_creds = getattr(sp, 'key_credentials', []) or []
                pwd_creds = getattr(sp, 'password_credentials', []) or []
            
            creds = []
            for cred in key_creds:
                cred_type = 'certificate'
                end_date = cred.get('endDateTime') if isinstance(cred, dict) else getattr(cred, 'end_date_time', None)
                if end_date:
                    if isinstance(end_date, str):
                        try:
                            end_date = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                        except:
                            end_date = None
                    if end_date:
                        if end_date < now:
                            expired_creds.append(f"{sp_name}: {cred_type} expired {end_date.date()}")
                        elif end_date < soon:
                            expiring_soon.append(f"{sp_name}: {cred_type} expires {end_date.date()}")
                        creds.append(f"{cred_type} (expires {end_date.date()})")
                else:
                    creds.append(cred_type)
            
            for cred in pwd_creds:
                cred_type = 'secret'
                end_date = cred.get('endDateTime') if isinstance(cred, dict) else getattr(cred, 'end_date_time', None)
                if end_date:
                    if isinstance(end_date, str):
                        try:
                            end_date = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                        except:
                            end_date = None
                    if end_date:
                        if end_date < now:
                            expired_creds.append(f"{sp_name}: {cred_type} expired {end_date.date()}")
                        elif end_date < soon:
                            expiring_soon.append(f"{sp_name}: {cred_type} expires {end_date.date()}")
                        creds.append(f"{cred_type} (expires {end_date.date()})")
                else:
                    creds.append(cred_type)
            
            if creds:
                sps_with_creds.append(f"{sp_name}: {', '.join(creds)}")
        
        if expired_creds:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.MEDIUM,
                category=Category.SERVICE_PRINCIPAL,
                title=f"Service Principals with Expired Credentials ({len(expired_creds)})",
                description=f"{len(expired_creds)} service principal credentials have expired. "
                           f"While expired creds can't be used, they indicate poor lifecycle management "
                           f"and the apps may be orphaned or abandoned.",
                affected_count=len(expired_creds),
                affected_objects=expired_creds,
                recommendation="Review expired credentials. Remove orphaned service principals. "
                              "Implement credential rotation policies.",
            ))
        
        if expiring_soon:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH,
                category=Category.SERVICE_PRINCIPAL,
                title=f"Service Principal Credentials Expiring Soon ({len(expiring_soon)})",
                description=f"{len(expiring_soon)} service principal credentials will expire within 30 days. "
                           f"If not rotated, dependent applications will break.",
                affected_count=len(expiring_soon),
                affected_objects=expiring_soon,
                recommendation="Rotate credentials before expiry. Consider using managed identities "
                              "to eliminate credential management overhead.",
            ))
        
        if sps_with_creds:
            # Count secrets vs certs
            secrets = sum(1 for s in sps_with_creds if 'secret' in s.lower())
            certs = sum(1 for s in sps_with_creds if 'certificate' in s.lower())
            
            if secrets > certs:
                self.findings.append(Finding(
                    id=self._next_finding_id(),
                    severity=Severity.LOW,
                    category=Category.SERVICE_PRINCIPAL,
                    title=f"Service Principals Using Secrets vs Certificates",
                    description=f"Found {secrets} service principals using client secrets vs {certs} using certificates. "
                               f"Certificates are more secure than secrets and should be preferred.",
                    affected_count=len(sps_with_creds),
                    affected_objects=sps_with_creds,
                    recommendation="Migrate from client secrets to certificates where possible. "
                                  "Best practice: use managed identities to eliminate credentials entirely.",
                ))

    def _analyze_domain_security(self):
        """Analyze email domain security (SPF, DKIM, DMARC)."""
        try:
            import dns.resolver
        except ImportError:
            # dnspython not installed, skip this analysis
            return
        
        # Get primary domain from users or tenant
        domains = set()
        for u in self.snapshot.users:
            upn = u.user_principal_name or ''
            if '@' in upn and '#EXT#' not in upn:
                domain = upn.split('@')[-1]
                if not domain.endswith('.onmicrosoft.com'):
                    domains.add(domain)
        
        if not domains:
            return
        
        domain_findings = []
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        for domain in list(domains)[:5]:  # Check up to 5 domains
            spf_ok = False
            dkim_ok = False
            dmarc_ok = False
            dmarc_policy = None
            spf_record = None
            dmarc_record = None
            issues = []
            
            try:
                # Check SPF
                try:
                    answers = resolver.resolve(domain, 'TXT')
                    for rdata in answers:
                        txt = str(rdata).strip('"')
                        if 'v=spf1' in txt:
                            spf_ok = True
                            spf_record = txt
                            if '-all' in txt:
                                pass  # strict SPF - good
                            elif '~all' in txt:
                                issues.append("SPF soft-fail (~all) - consider -all for strict enforcement")
                            elif '?all' in txt:
                                issues.append("SPF neutral (?all) - provides no protection")
                            elif '+all' in txt:
                                issues.append("SPF +all allows anyone to send - CRITICAL misconfiguration")
                            break
                except dns.resolver.NXDOMAIN:
                    issues.append("Domain does not exist in DNS")
                except dns.resolver.NoAnswer:
                    issues.append("No SPF record found")
                except Exception:
                    issues.append("No SPF record found")
                
                if not spf_ok and "Domain does not exist" not in str(issues):
                    issues.append("No SPF record found")
                
                # Check DMARC
                try:
                    answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
                    for rdata in answers:
                        txt = str(rdata).strip('"')
                        if 'v=DMARC1' in txt:
                            dmarc_ok = True
                            dmarc_record = txt
                            if 'p=reject' in txt:
                                dmarc_policy = 'reject'
                            elif 'p=quarantine' in txt:
                                dmarc_policy = 'quarantine'
                                issues.append("DMARC quarantine - consider p=reject for full protection")
                            elif 'p=none' in txt:
                                dmarc_policy = 'none'
                                issues.append("DMARC p=none provides monitoring only, no enforcement")
                            break
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                except Exception:
                    pass
                
                if not dmarc_ok:
                    issues.append("No DMARC record - emails can be spoofed without detection")
                
                # Check DKIM (common selectors for M365 and Google)
                dkim_selectors = ['selector1', 'selector2', 'google', 'default', 's1', 's2']
                for selector in dkim_selectors:
                    try:
                        answers = resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
                        for rdata in answers:
                            txt = str(rdata).strip('"')
                            if 'v=DKIM1' in txt or 'k=rsa' in txt or 'p=' in txt:
                                dkim_ok = True
                                break
                        if dkim_ok:
                            break
                    except Exception:
                        continue
                
                if not dkim_ok:
                    issues.append("No DKIM record found (checked: selector1, selector2, google, default)")
                
            except Exception as e:
                issues.append(f"DNS lookup error: {str(e)}")
            
            # Build status line
            status = []
            status.append(f"SPF: {'✓' if spf_ok else '✗'}")
            status.append(f"DKIM: {'✓' if dkim_ok else '✗'}")
            status.append(f"DMARC: {'✓ p=' + dmarc_policy if dmarc_ok else '✗'}")
            
            finding_line = f"{domain}: {' | '.join(status)}"
            if issues:
                finding_line += f" — {'; '.join(issues)}"
            domain_findings.append(finding_line)
        
        # Determine severity based on findings
        has_missing_dmarc = any('DMARC: ✗' in d for d in domain_findings)
        has_missing_spf = any('SPF: ✗' in d for d in domain_findings)
        has_weak_dmarc = any('p=none' in d for d in domain_findings)
        
        if domain_findings:
            if has_missing_dmarc or has_missing_spf:
                severity = Severity.HIGH
            elif has_weak_dmarc:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW
            
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=severity,
                category=Category.DOMAIN_SECURITY,
                title=f"Email Domain Security (SPF/DKIM/DMARC) for {len(domains)} domain(s)",
                description=f"Analyzed email authentication records for {len(domain_findings)} domain(s). "
                           f"Missing or weak SPF/DKIM/DMARC enables email spoofing and phishing attacks "
                           f"impersonating your organization.",
                affected_count=len(domain_findings),
                affected_objects=domain_findings,
                recommendation="Implement SPF with -all (hard fail), DKIM signing via M365/Google, "
                              "and DMARC p=reject. This is critical given the Mail.Send permissions in this tenant.",
            ))

    def _analyze_behavioral_patterns(self):
        """
        Analyze sign-in behavioral patterns using the unified BehavioralAnalyzer.
        
        Detects:
        - Token replay (same session from different IPs)
        - Impossible travel (physically impossible location changes)
        - Off-hours authentication
        - High IP diversity per user
        - Lateral movement patterns
        
        Based on entra_assessment.py behavioral analysis modules.
        """
        if not BEHAVIORAL_AVAILABLE:
            log.debug("Behavioral analysis module not available, skipping")
            return
        
        if not self.events or not self.events.signins:
            return
        
        # Convert sign-ins to AuthEvent format
        auth_events = []
        for signin in self.events.signins:
            try:
                auth_event = normalize_entra_signin(signin)
                auth_events.append(auth_event)
            except Exception as e:
                log.debug("Failed to normalize sign-in: %s", e)
                continue
        
        if not auth_events:
            return
        
        log.info("Running behavioral analysis on %d sign-in events", len(auth_events))
        
        # Run behavioral analysis
        analyzer = BehavioralAnalyzer()
        results = analyzer.analyze_all(auth_events)
        
        # Convert behavioral anomalies to findings
        
        # Token replay - CRITICAL
        for anomaly in results.get("token_replay", []):
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.CRITICAL,
                category=Category.TOKEN_REPLAY,
                title=f"Token Replay Detected: {anomaly.user}",
                description=f"Same session used from {anomaly.evidence.get('source1')} then "
                           f"{anomaly.evidence.get('source2')} within {anomaly.evidence.get('delta_minutes')} minutes. "
                           f"This indicates potential token theft and replay attack.",
                affected_count=1,
                affected_objects=[anomaly.user],
                recommendation="Immediately investigate the user account. Consider requiring re-authentication "
                              "and review sign-in logs for the affected time period.",
                references=[
                    "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection"
                ],
            ))
        
        # Impossible travel - HIGH
        for anomaly in results.get("impossible_travel", []):
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH,
                category=Category.IMPOSSIBLE_TRAVEL,
                title=f"Impossible Travel: {anomaly.user}",
                description=f"Authentication from {anomaly.evidence.get('from_location')} then "
                           f"{anomaly.evidence.get('to_location')} ({anomaly.evidence.get('distance_km')} km) "
                           f"in {anomaly.evidence.get('time_hours')} hours requires "
                           f"{anomaly.evidence.get('required_speed_kmh')} km/h travel speed.",
                affected_count=1,
                affected_objects=[anomaly.user],
                recommendation="Verify if user has legitimate reasons (VPN, corporate proxy). "
                              "If not, investigate potential credential compromise.",
                references=[
                    "https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks"
                ],
            ))
        
        # Off-hours authentication - MEDIUM
        for anomaly in results.get("off_hours", []):
            severity = Severity.HIGH if anomaly.affected_count >= 20 else Severity.MEDIUM
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=severity,
                category=Category.BEHAVIORAL,
                title=f"Off-Hours Authentication: {anomaly.user}",
                description=f"{anomaly.affected_count} authentications outside business hours "
                           f"(weekends or 10pm-6am). Sample times: {', '.join(anomaly.evidence.get('sample_times', [])[:3])}",
                affected_count=anomaly.affected_count,
                affected_objects=[anomaly.user],
                recommendation="Review if this pattern is expected for the user's role. "
                              "Unusual off-hours activity may indicate compromised credentials.",
            ))
        
        # IP diversity - MEDIUM/HIGH
        for anomaly in results.get("ip_diversity", []):
            severity = Severity.HIGH if anomaly.evidence.get("ip_count", 0) >= 20 else Severity.MEDIUM
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=severity,
                category=Category.BEHAVIORAL,
                title=f"High IP Diversity: {anomaly.user}",
                description=f"Authenticated from {anomaly.evidence.get('ip_count')} distinct IP addresses. "
                           f"Locations: {', '.join(anomaly.evidence.get('locations', [])[:5])}",
                affected_count=anomaly.evidence.get("ip_count", 0),
                affected_objects=[anomaly.user] + anomaly.evidence.get("sample_ips", [])[:10],
                recommendation="High IP diversity may indicate credential sharing, VPN rotation by attacker, "
                              "or compromised credentials used from multiple locations.",
            ))
        
        # Lateral movement - MEDIUM/HIGH
        for anomaly in results.get("lateral_movement", []):
            severity = Severity.HIGH if anomaly.evidence.get("target_count", 0) >= 10 else Severity.MEDIUM
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=severity,
                category=Category.LATERAL_MOVEMENT,
                title=f"Potential Lateral Movement: {anomaly.user}",
                description=f"Accessed {anomaly.evidence.get('target_count')} different applications/resources "
                           f"in a 1-hour window ({anomaly.evidence.get('window')}). "
                           f"Apps: {', '.join(anomaly.evidence.get('targets', [])[:5])}",
                affected_count=anomaly.evidence.get("target_count", 0),
                affected_objects=[anomaly.user],
                recommendation="Review if this access pattern is normal for the user. "
                              "Rapid access to many resources may indicate reconnaissance or data collection.",
            ))
        
        log.info(
            "Behavioral analysis complete: %d token replay, %d impossible travel, "
            "%d off-hours, %d IP diversity, %d lateral movement",
            len(results.get("token_replay", [])),
            len(results.get("impossible_travel", [])),
            len(results.get("off_hours", [])),
            len(results.get("ip_diversity", [])),
            len(results.get("lateral_movement", [])),
        )
