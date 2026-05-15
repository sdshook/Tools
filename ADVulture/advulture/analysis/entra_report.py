# (c) 2025 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture - Entra ID Report Generator
Generates factual security findings from collected Entra ID data.
No AI interpretation - purely data-driven findings.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from enum import Enum
from pathlib import Path

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
            "affected_objects": self.affected_objects[:20],  # Limit for display
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
    
    # MFA stats
    mfa_registered_count: int = 0
    mfa_capable_count: int = 0
    no_mfa_count: int = 0
    weak_mfa_count: int = 0
    
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
        """Generate markdown report."""
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
            f"| Metric | Count | Percentage |",
            f"|--------|-------|------------|",
        ]
        
        if self.user_count > 0:
            lines.extend([
                f"| Users with MFA | {self.mfa_registered_count} | {self.mfa_registered_count/self.user_count*100:.1f}% |",
                f"| Users with Strong MFA | {self.mfa_capable_count} | {self.mfa_capable_count/self.user_count*100:.1f}% |",
                f"| Users without MFA | {self.no_mfa_count} | {self.no_mfa_count/self.user_count*100:.1f}% |",
                f"| Users with Weak MFA Only | {self.weak_mfa_count} | {self.weak_mfa_count/self.user_count*100:.1f}% |",
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
                lines.append("**Sample affected objects:**")
                for obj in finding.affected_objects[:5]:
                    lines.append(f"- {obj}")
                if len(finding.affected_objects) > 5:
                    lines.append(f"- ... and {len(finding.affected_objects) - 5} more")
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
    
    def _next_finding_id(self) -> str:
        self._finding_id += 1
        return f"ENTRA-{self._finding_id:03d}"
    
    def generate(self) -> EntraReport:
        """Generate the complete report."""
        self.findings = []
        self._finding_id = 0
        
        # Analyze each area
        self._analyze_mfa_posture()
        self._analyze_privileged_access()
        self._analyze_service_principals()
        self._analyze_oauth_grants()
        if self.events:
            self._analyze_authentication_logs()
        
        # Sort findings by severity
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        self.findings.sort(key=lambda f: severity_order[f.severity])
        
        # Build report
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
            mfa_registered_count=sum(1 for u in self.snapshot.users if u.mfa_registered),
            mfa_capable_count=sum(1 for u in self.snapshot.users if u.mfa_capable),
            no_mfa_count=sum(1 for u in self.snapshot.users if not u.mfa_registered),
            weak_mfa_count=sum(1 for u in self.snapshot.users if u.mfa_registered and not u.mfa_capable),
            findings=self.findings,
        )
        
        return report
    
    def _analyze_mfa_posture(self):
        """Analyze MFA registration status."""
        users = self.snapshot.users
        enabled_users = [u for u in users if u.account_enabled]
        
        # Users without MFA
        no_mfa = [u for u in enabled_users if not u.mfa_registered]
        if no_mfa:
            pct = len(no_mfa) / len(users) * 100 if users else 0
            severity = Severity.CRITICAL if pct > 50 else Severity.HIGH if pct > 20 else Severity.MEDIUM
            
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=severity,
                category=Category.MFA_POSTURE,
                title=f"Users Without MFA ({len(no_mfa)} users, {pct:.0f}%)",
                description=f"{len(no_mfa)} enabled users have no MFA methods registered. "
                           f"These accounts are protected only by passwords and are vulnerable to "
                           f"phishing, credential stuffing, and password spray attacks.",
                affected_count=len(no_mfa),
                affected_objects=[u.user_principal_name for u in no_mfa],
                recommendation="Implement mandatory MFA enrollment. Use Conditional Access to require MFA for all sign-ins.",
                references=["https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-getstarted"],
            ))
        
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
        """Analyze privileged role assignments."""
        assignments = self.snapshot.all_role_assignments
        
        # Find privileged assignments
        priv_assignments = [a for a in assignments if a.is_privileged]
        
        # Group by principal
        principals_with_priv: Dict[str, List[str]] = {}
        for a in priv_assignments:
            key = a.principal_name or a.principal_id
            if key not in principals_with_priv:
                principals_with_priv[key] = []
            principals_with_priv[key].append(a.role_name)
        
        # Check for users with multiple privileged roles
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
                affected_objects=[f"{k}: {len(v)} roles ({', '.join(v[:3])}...)" for k, v in list(multi_priv.items())[:10]],
                recommendation="Review and consolidate role assignments. Use PIM for just-in-time access.",
            ))
        
        # Check for privileged users without MFA
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
                affected_objects=[f"{a.principal_name}: {a.role_name}" for a in sp_priv[:10]],
                recommendation="Review service principal permissions. Use managed identities where possible.",
            ))
    
    def _analyze_oauth_grants(self):
        """Analyze OAuth consent grants."""
        grants = self.snapshot.oauth_grants
        
        # Find high-risk grants (grants are stored as dicts)
        risky_grants = []
        for g in grants:
            # Handle both dict and object forms
            if isinstance(g, dict):
                scope = g.get("scope", "") or ""
                client_id = g.get("clientId", g.get("client_id", "unknown"))
            else:
                scope = getattr(g, "scope", "") or ""
                client_id = getattr(g, "client_id", "unknown")
            
            if any(risk_scope in scope for risk_scope in self.HIGH_RISK_SCOPES):
                risky_grants.append({"client_id": client_id, "scope": scope})
        
        if risky_grants:
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.HIGH if len(risky_grants) > 10 else Severity.MEDIUM,
                category=Category.OAUTH_CONSENT,
                title=f"High-Risk OAuth Consent Grants ({len(risky_grants)})",
                description=f"{len(risky_grants)} OAuth grants include high-risk scopes that allow "
                           f"applications to read/write sensitive data (mail, files, directory).",
                affected_count=len(risky_grants),
                affected_objects=[f"{g['client_id']}: {g['scope']}" for g in risky_grants[:10]],
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
                affected_objects=unique_users[:10],
                recommendation="Block legacy authentication via Conditional Access policy.",
            ))
        
        # Failed sign-ins
        failed = [s for s in signins if s.result != "success"]
        if len(failed) > 50:
            unique_users = list(set(s.user_principal_name for s in failed))
            
            self.findings.append(Finding(
                id=self._next_finding_id(),
                severity=Severity.INFO,
                category=Category.AUTHENTICATION,
                title=f"Failed Sign-in Attempts ({len(failed)} events)",
                description=f"{len(failed)} failed sign-in attempts from {len(unique_users)} unique accounts. "
                           f"Review for potential brute-force or credential stuffing attacks.",
                affected_count=len(unique_users),
                affected_objects=unique_users[:10],
                recommendation="Investigate repeated failures. Consider smart lockout policies.",
            ))
