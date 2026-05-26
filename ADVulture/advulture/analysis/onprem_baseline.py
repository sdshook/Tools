# (c) 2025-2026 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture — On-Premise AD Security Baseline Assessment
Evaluates GPO policies, privileged access, and security configuration.

Equivalent to Entra ID's Security Defaults and Conditional Access analysis,
but for on-premise Active Directory environments.

Based on learnings from entra_assessment.py security baseline modules.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Any, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from advulture.collection.ldap_enumerator import ADSnapshot, ADUser, ADComputer, ADGroup

log = logging.getLogger(__name__)


@dataclass
class BaselineFinding:
    """A security baseline finding."""
    finding_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # password_policy, kerberos_policy, audit_policy, privileged_access, etc.
    title: str
    description: str
    current_value: Any = None
    recommended_value: Any = None
    affected_objects: List[str] = field(default_factory=list)
    remediation: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "type": self.finding_type,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "current_value": self.current_value,
            "recommended_value": self.recommended_value,
            "affected_objects": self.affected_objects[:50],
            "affected_count": len(self.affected_objects),
            "remediation": self.remediation,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Tier 0 Group Definitions
# ─────────────────────────────────────────────────────────────────────────────

TIER0_GROUPS = {
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "DnsAdmins",
    "Domain Controllers",
    "Read-only Domain Controllers",
    "Group Policy Creator Owners",
    "Cert Publishers",
}

TIER0_RIDS = {"512", "519", "518", "516", "517", "520"}  # Well-known RID suffixes


# ─────────────────────────────────────────────────────────────────────────────
# Security Baseline Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class OnPremSecurityBaseline:
    """
    Assess on-premise AD security baseline configuration.
    
    This is the on-prem equivalent of Entra's Security Defaults detection.
    Evaluates:
    - Password policies (GPO)
    - Kerberos policies (GPO)
    - Audit policies (GPO)
    - LAPS deployment
    - Privileged group membership
    - Protected Users utilization
    - Authentication policies/silos (2012 R2+)
    """
    
    def __init__(self, snapshot: "ADSnapshot", gpo_data: Optional[Dict] = None):
        """
        Args:
            snapshot: ADSnapshot from LDAP enumeration
            gpo_data: Optional GPO policy data (from GPMC export or registry)
        """
        self.snapshot = snapshot
        self.gpo_data = gpo_data or {}
    
    def assess_all(self) -> Dict[str, List[BaselineFinding]]:
        """Run all baseline assessments."""
        results = {
            "password_policy": self.assess_password_policy(),
            "kerberos_policy": self.assess_kerberos_policy(),
            "audit_policy": self.assess_audit_policy(),
            "laps": self.assess_laps_deployment(),
            "privileged_access": self.assess_privileged_membership(),
            "protected_users": self.assess_protected_users(),
            "delegation": self.assess_delegation_security(),
            "service_accounts": self.assess_service_accounts(),
        }
        
        total = sum(len(f) for f in results.values())
        critical = sum(1 for findings in results.values() for f in findings if f.severity == "CRITICAL")
        high = sum(1 for findings in results.values() for f in findings if f.severity == "HIGH")
        
        log.info("Baseline assessment complete: %d findings (%d critical, %d high)", total, critical, high)
        
        return results
    
    # ─────────────────────────────────────────────────────────────────────────
    # Password Policy Assessment
    # ─────────────────────────────────────────────────────────────────────────
    
    def assess_password_policy(self) -> List[BaselineFinding]:
        """
        Assess Default Domain Policy password settings.
        Equivalent to Entra's password policies.
        """
        findings = []
        policy = self.gpo_data.get("default_domain_policy", {})
        
        # If no GPO data, assess from user attributes
        if not policy:
            return self._assess_password_policy_from_users()
        
        min_length = policy.get("MinimumPasswordLength", 0)
        max_age = policy.get("MaximumPasswordAge", 42)
        complexity = policy.get("PasswordComplexity", False)
        history = policy.get("PasswordHistorySize", 0)
        lockout_threshold = policy.get("LockoutBadCount", 0)
        lockout_duration = policy.get("LockoutDuration", 0)
        
        # Minimum password length
        if min_length < 14:
            findings.append(BaselineFinding(
                finding_type="WEAK_PASSWORD_LENGTH",
                severity="HIGH",
                category="password_policy",
                title=f"Minimum Password Length: {min_length} characters",
                description=f"Current minimum password length ({min_length}) is below recommended 14 characters",
                current_value=min_length,
                recommended_value=14,
                remediation="Set 'Minimum password length' to 14+ in Default Domain Policy",
            ))
        
        # Complexity requirement
        if not complexity:
            findings.append(BaselineFinding(
                finding_type="NO_COMPLEXITY",
                severity="HIGH",
                category="password_policy",
                title="Password Complexity Disabled",
                description="Password complexity requirement is disabled, allowing weak passwords",
                current_value=False,
                recommended_value=True,
                remediation="Enable 'Password must meet complexity requirements' in Default Domain Policy",
            ))
        
        # Account lockout
        if lockout_threshold == 0:
            findings.append(BaselineFinding(
                finding_type="NO_LOCKOUT",
                severity="CRITICAL",
                category="password_policy",
                title="Account Lockout Disabled",
                description="Account lockout is disabled, enabling unlimited password spray attempts",
                current_value=0,
                recommended_value="5-10",
                remediation="Set 'Account lockout threshold' to 5-10 in Default Domain Policy",
            ))
        elif lockout_threshold > 10:
            findings.append(BaselineFinding(
                finding_type="HIGH_LOCKOUT_THRESHOLD",
                severity="MEDIUM",
                category="password_policy",
                title=f"High Lockout Threshold: {lockout_threshold}",
                description=f"Lockout threshold of {lockout_threshold} allows many spray attempts per account",
                current_value=lockout_threshold,
                recommended_value="5-10",
                remediation="Reduce 'Account lockout threshold' to 5-10",
            ))
        
        # Password history
        if history < 24:
            findings.append(BaselineFinding(
                finding_type="LOW_PASSWORD_HISTORY",
                severity="LOW",
                category="password_policy",
                title=f"Low Password History: {history}",
                description="Low password history enables password cycling back to old passwords",
                current_value=history,
                recommended_value=24,
                remediation="Set 'Enforce password history' to 24 in Default Domain Policy",
            ))
        
        return findings
    
    def _assess_password_policy_from_users(self) -> List[BaselineFinding]:
        """Assess password hygiene from user attributes when GPO data unavailable."""
        findings = []
        
        # Check for password never expires
        never_expires = [
            u for u in self.snapshot.users 
            if u.password_never_expires and u.enabled
        ]
        
        if never_expires:
            findings.append(BaselineFinding(
                finding_type="PASSWORD_NEVER_EXPIRES",
                severity="MEDIUM",
                category="password_policy",
                title=f"Accounts with Password Never Expires: {len(never_expires)}",
                description="Accounts with non-expiring passwords increase credential risk duration",
                affected_objects=[u.sam_account_name for u in never_expires],
                remediation="Remove 'Password never expires' flag unless required for service accounts",
            ))
        
        # Check for stale passwords (>365 days)
        stale_passwords = [
            u for u in self.snapshot.users
            if u.enabled and u.password_age_days > 365
        ]
        
        if stale_passwords:
            findings.append(BaselineFinding(
                finding_type="STALE_PASSWORDS",
                severity="MEDIUM",
                category="password_policy",
                title=f"Accounts with Stale Passwords (>365 days): {len(stale_passwords)}",
                description="Accounts with very old passwords may indicate weak password hygiene",
                affected_objects=[f"{u.sam_account_name} ({u.password_age_days:.0f} days)" for u in stale_passwords[:50]],
                remediation="Enforce password rotation or verify these are managed service accounts",
            ))
        
        return findings
    
    # ─────────────────────────────────────────────────────────────────────────
    # Kerberos Policy Assessment
    # ─────────────────────────────────────────────────────────────────────────
    
    def assess_kerberos_policy(self) -> List[BaselineFinding]:
        """Assess Kerberos policy settings for security issues."""
        findings = []
        policy = self.gpo_data.get("kerberos_policy", {})
        
        max_ticket_age = policy.get("MaxTicketAge", 10)  # hours
        max_service_age = policy.get("MaxServiceAge", 600)  # minutes
        max_clock_skew = policy.get("MaxClockSkew", 5)  # minutes
        
        if max_ticket_age > 10:
            findings.append(BaselineFinding(
                finding_type="LONG_TGT_LIFETIME",
                severity="MEDIUM",
                category="kerberos_policy",
                title=f"TGT Lifetime: {max_ticket_age} hours",
                description=f"TGT lifetime of {max_ticket_age}h extends attack window for stolen tickets",
                current_value=max_ticket_age,
                recommended_value=10,
                remediation="Set 'Maximum lifetime for user ticket' to 10 hours in Default Domain Policy",
            ))
        
        # Check for RC4 Kerberos usage (from user attributes or events)
        # This would typically come from event log analysis
        
        return findings
    
    # ─────────────────────────────────────────────────────────────────────────
    # Audit Policy Assessment
    # ─────────────────────────────────────────────────────────────────────────
    
    def assess_audit_policy(self) -> List[BaselineFinding]:
        """Check if critical security events are being audited."""
        findings = []
        audit = self.gpo_data.get("audit_policy", {})
        
        if not audit:
            findings.append(BaselineFinding(
                finding_type="AUDIT_POLICY_UNKNOWN",
                severity="INFO",
                category="audit_policy",
                title="Audit Policy Not Collected",
                description="GPO audit policy data not available for assessment",
                remediation="Export GPO settings for complete audit policy assessment",
            ))
            return findings
        
        critical_categories = {
            "AuditLogonEvents": ("Logon/Logoff", "Detects interactive and network logons"),
            "AuditAccountLogon": ("Account Logon", "Detects Kerberos authentication events"),
            "AuditPrivilegeUse": ("Privilege Use", "Detects sensitive privilege usage"),
            "AuditObjectAccess": ("Object Access", "Detects access to protected objects"),
            "AuditPolicyChange": ("Policy Change", "Detects GPO and security policy changes"),
            "AuditAccountManage": ("Account Management", "Detects user/group modifications"),
            "AuditDSAccess": ("Directory Service Access", "Detects AD object access"),
        }
        
        for setting, (name, purpose) in critical_categories.items():
            value = audit.get(setting, "None")
            
            if value in ("None", "No Auditing", None):
                findings.append(BaselineFinding(
                    finding_type="MISSING_AUDIT",
                    severity="HIGH",
                    category="audit_policy",
                    title=f"Audit Disabled: {name}",
                    description=f"{name} auditing disabled. {purpose}",
                    current_value="Disabled",
                    recommended_value="Success and Failure",
                    remediation=f"Enable '{name}' auditing for Success and Failure in Default Domain Policy",
                ))
            elif "Success" not in str(value) or "Failure" not in str(value):
                findings.append(BaselineFinding(
                    finding_type="INCOMPLETE_AUDIT",
                    severity="MEDIUM",
                    category="audit_policy",
                    title=f"Incomplete Audit: {name}",
                    description=f"{name} should audit both Success and Failure",
                    current_value=value,
                    recommended_value="Success and Failure",
                    remediation=f"Configure '{name}' to audit both Success and Failure",
                ))
        
        return findings
    
    # ─────────────────────────────────────────────────────────────────────────
    # LAPS Deployment Assessment
    # ─────────────────────────────────────────────────────────────────────────
    
    def assess_laps_deployment(self) -> List[BaselineFinding]:
        """
        Check LAPS (Local Administrator Password Solution) deployment.
        Equivalent to checking for managed local admin credentials.
        """
        findings = []
        computers = self.snapshot.computers
        
        if not computers:
            return findings
        
        laps_enabled = [c for c in computers if c.laps_expiry is not None]
        laps_missing = [c for c in computers if c.laps_expiry is None and c.enabled]
        
        coverage = len(laps_enabled) / len(computers) * 100
        
        if coverage < 80:
            severity = "HIGH"
        elif coverage < 95:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        if laps_missing:
            findings.append(BaselineFinding(
                finding_type="LAPS_COVERAGE_GAP",
                severity=severity,
                category="laps",
                title=f"LAPS Coverage: {coverage:.1f}%",
                description=f"{len(laps_missing)} computers without LAPS, risking shared local admin passwords",
                current_value=f"{coverage:.1f}%",
                recommended_value="100%",
                affected_objects=[c.sam_account_name for c in laps_missing],
                remediation="Deploy LAPS to all domain-joined workstations and servers",
            ))
        
        return findings
    
    # ─────────────────────────────────────────────────────────────────────────
    # Privileged Group Membership Assessment
    # ─────────────────────────────────────────────────────────────────────────
    
    def assess_privileged_membership(self) -> List[BaselineFinding]:
        """
        Assess privileged group membership hygiene.
        On-prem equivalent of PIM assessment.
        """
        findings = []
        
        for group in self.snapshot.groups:
            if group.sam_account_name not in TIER0_GROUPS:
                # Also check RID-based detection
                sid_parts = group.sid.split("-")
                if not (sid_parts and sid_parts[-1] in TIER0_RIDS):
                    continue
            
            # Find direct user members
            user_members = []
            for member_dn in group.members:
                user = next(
                    (u for u in self.snapshot.users if u.distinguished_name == member_dn),
                    None
                )
                if user:
                    user_members.append(user)
            
            # Check for concerning patterns
            for user in user_members:
                # Service account in privileged group
                if user.has_spn:
                    findings.append(BaselineFinding(
                        finding_type="SERVICE_ACCOUNT_PRIVILEGED",
                        severity="CRITICAL",
                        category="privileged_access",
                        title=f"Service Account in {group.sam_account_name}",
                        description=f"Service account {user.sam_account_name} is member of privileged group",
                        affected_objects=[user.sam_account_name],
                        remediation="Remove service accounts from privileged groups; use delegation instead",
                    ))
                
                # Stale privileged account
                if user.days_since_last_logon > 90 and user.enabled:
                    findings.append(BaselineFinding(
                        finding_type="STALE_PRIVILEGED_ACCOUNT",
                        severity="HIGH",
                        category="privileged_access",
                        title=f"Inactive Privileged Account: {user.sam_account_name}",
                        description=f"Privileged account inactive for {user.days_since_last_logon:.0f} days",
                        current_value=f"{user.days_since_last_logon:.0f} days",
                        affected_objects=[user.sam_account_name],
                        remediation="Disable or remove inactive privileged accounts",
                    ))
                
                # Password never expires on privileged account
                if user.password_never_expires:
                    findings.append(BaselineFinding(
                        finding_type="PRIVILEGED_PASSWORD_NEVER_EXPIRES",
                        severity="HIGH",
                        category="privileged_access",
                        title=f"Privileged Account Password Never Expires: {user.sam_account_name}",
                        description=f"Privileged account {user.sam_account_name} password never expires",
                        affected_objects=[user.sam_account_name],
                        remediation="Remove 'Password never expires' from privileged accounts",
                    ))
                
                # Old password on privileged account
                if user.password_age_days > 180:
                    findings.append(BaselineFinding(
                        finding_type="PRIVILEGED_STALE_PASSWORD",
                        severity="MEDIUM",
                        category="privileged_access",
                        title=f"Privileged Account Old Password: {user.sam_account_name}",
                        description=f"Privileged account password is {user.password_age_days:.0f} days old",
                        current_value=f"{user.password_age_days:.0f} days",
                        recommended_value="<90 days",
                        affected_objects=[user.sam_account_name],
                        remediation="Rotate privileged account passwords every 90 days",
                    ))
            
            # Too many members in privileged group
            if len(user_members) > 5:
                findings.append(BaselineFinding(
                    finding_type="EXCESSIVE_PRIVILEGED_MEMBERS",
                    severity="MEDIUM",
                    category="privileged_access",
                    title=f"Excessive Members in {group.sam_account_name}: {len(user_members)}",
                    description=f"{group.sam_account_name} has {len(user_members)} direct user members",
                    current_value=len(user_members),
                    recommended_value="<5",
                    affected_objects=[u.sam_account_name for u in user_members],
                    remediation="Minimize privileged group membership; use JIT access where possible",
                ))
        
        return findings
    
    # ─────────────────────────────────────────────────────────────────────────
    # Protected Users Assessment
    # ─────────────────────────────────────────────────────────────────────────
    
    def assess_protected_users(self) -> List[BaselineFinding]:
        """
        Assess Protected Users group utilization.
        Equivalent to Entra's security baseline for privileged accounts.
        """
        findings = []
        
        # Find Protected Users group
        protected_users_group = next(
            (g for g in self.snapshot.groups if g.sam_account_name == "Protected Users"),
            None
        )
        
        if not protected_users_group:
            findings.append(BaselineFinding(
                finding_type="NO_PROTECTED_USERS_GROUP",
                severity="INFO",
                category="protected_users",
                title="Protected Users Group Not Found",
                description="May indicate older domain functional level (requires 2012 R2+)",
                remediation="Upgrade domain functional level to 2012 R2 or higher",
            ))
            return findings
        
        protected_members = set(protected_users_group.members)
        
        # Find Tier 0 users not in Protected Users
        tier0_users = [u for u in self.snapshot.users if u.tier == 0 and u.enabled]
        not_protected = [
            u for u in tier0_users
            if u.distinguished_name not in protected_members
        ]
        
        if not_protected:
            findings.append(BaselineFinding(
                finding_type="TIER0_NOT_PROTECTED",
                severity="MEDIUM",
                category="protected_users",
                title=f"Tier 0 Accounts Not in Protected Users: {len(not_protected)}",
                description="Tier 0 accounts should be in Protected Users for credential protection",
                affected_objects=[u.sam_account_name for u in not_protected],
                remediation="Add Tier 0 accounts to Protected Users group (verify no NTLM dependencies)",
            ))
        
        # Check for orphaned adminCount
        orphaned = [
            u for u in self.snapshot.users
            if u.admin_count == 1 and u.tier > 0
        ]
        
        if orphaned:
            findings.append(BaselineFinding(
                finding_type="ORPHANED_ADMIN_COUNT",
                severity="LOW",
                category="protected_users",
                title=f"Orphaned AdminCount: {len(orphaned)} accounts",
                description="Accounts with adminCount=1 but not in protected groups",
                affected_objects=[u.sam_account_name for u in orphaned],
                remediation="Clear adminCount attribute or verify intended protected status",
            ))
        
        return findings
    
    # ─────────────────────────────────────────────────────────────────────────
    # Delegation Security Assessment
    # ─────────────────────────────────────────────────────────────────────────
    
    def assess_delegation_security(self) -> List[BaselineFinding]:
        """Assess Kerberos delegation configuration security."""
        findings = []
        
        # Unconstrained delegation
        unconstrained_computers = [
            c for c in self.snapshot.computers
            if c.unconstrained_delegation and c.enabled
        ]
        
        # Exclude domain controllers (they need unconstrained delegation)
        non_dc_unconstrained = [
            c for c in unconstrained_computers
            if "domain controller" not in c.os.lower()
        ]
        
        if non_dc_unconstrained:
            findings.append(BaselineFinding(
                finding_type="UNCONSTRAINED_DELEGATION",
                severity="CRITICAL",
                category="delegation",
                title=f"Unconstrained Delegation: {len(non_dc_unconstrained)} computers",
                description="Non-DC computers with unconstrained delegation can impersonate any user",
                affected_objects=[c.sam_account_name for c in non_dc_unconstrained],
                remediation="Migrate to constrained delegation; add sensitive accounts to 'Cannot be delegated'",
            ))
        
        # Users with unconstrained delegation (very rare but critical)
        unconstrained_users = [
            u for u in self.snapshot.users
            if hasattr(u, "unconstrained_delegation") and u.unconstrained_delegation
        ]
        
        if unconstrained_users:
            findings.append(BaselineFinding(
                finding_type="USER_UNCONSTRAINED_DELEGATION",
                severity="CRITICAL",
                category="delegation",
                title=f"Users with Unconstrained Delegation: {len(unconstrained_users)}",
                description="User accounts with unconstrained delegation are high-value targets",
                affected_objects=[u.sam_account_name for u in unconstrained_users],
                remediation="Remove unconstrained delegation from user accounts",
            ))
        
        # Tier 0 accounts missing "cannot be delegated" flag
        tier0_delegatable = [
            u for u in self.snapshot.users
            if u.tier == 0 and u.enabled
            and not (u.user_account_control & 0x100000)  # NOT_DELEGATED flag
        ]
        
        if tier0_delegatable:
            findings.append(BaselineFinding(
                finding_type="TIER0_DELEGATABLE",
                severity="HIGH",
                category="delegation",
                title=f"Tier 0 Accounts Without 'Cannot be Delegated': {len(tier0_delegatable)}",
                description="Tier 0 accounts should be marked 'Account is sensitive and cannot be delegated'",
                affected_objects=[u.sam_account_name for u in tier0_delegatable],
                remediation="Enable 'Account is sensitive and cannot be delegated' for all Tier 0 accounts",
            ))
        
        return findings
    
    # ─────────────────────────────────────────────────────────────────────────
    # Service Account Assessment
    # ─────────────────────────────────────────────────────────────────────────
    
    def assess_service_accounts(self) -> List[BaselineFinding]:
        """Assess service account security configuration."""
        findings = []
        
        # Find Kerberoastable accounts (users with SPNs)
        kerberoastable = [
            u for u in self.snapshot.users
            if u.has_spn and u.enabled
        ]
        
        if kerberoastable:
            # Separate by password age (old passwords = higher risk)
            high_risk = [u for u in kerberoastable if u.password_age_days > 365]
            medium_risk = [u for u in kerberoastable if 90 < u.password_age_days <= 365]
            
            findings.append(BaselineFinding(
                finding_type="KERBEROASTABLE_ACCOUNTS",
                severity="HIGH" if high_risk else "MEDIUM",
                category="service_accounts",
                title=f"Kerberoastable Service Accounts: {len(kerberoastable)}",
                description=f"Accounts with SPNs vulnerable to offline password cracking ({len(high_risk)} with old passwords)",
                affected_objects=[f"{u.sam_account_name} ({u.password_age_days:.0f} days)" for u in kerberoastable],
                remediation="Use gMSA, rotate to 25+ char passwords, or enforce AES-only Kerberos",
            ))
        
        # AS-REP Roastable accounts
        asrep_roastable = [
            u for u in self.snapshot.users
            if u.no_preauth_required and u.enabled
        ]
        
        if asrep_roastable:
            findings.append(BaselineFinding(
                finding_type="ASREP_ROASTABLE",
                severity="HIGH",
                category="service_accounts",
                title=f"AS-REP Roastable Accounts: {len(asrep_roastable)}",
                description="Accounts with 'Do not require Kerberos preauthentication' enabled",
                affected_objects=[u.sam_account_name for u in asrep_roastable],
                remediation="Remove 'Do not require Kerberos preauthentication' unless absolutely necessary",
            ))
        
        return findings
