# (c) 2025 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture — Unified Finding Model
All six risk classes produce findings in this common schema.
No class is structurally privileged over another.
Gradient contribution determines rank, not category.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List
import hashlib
import json


class RiskClass(str, Enum):
    AUTHN_HYGIENE        = "A"
    AUTHZ_STRUCTURE      = "B"
    AUTHZ_BEHAVIOUR      = "C"
    PRIVILEGE_ESCALATION = "D"
    DELEGATION_OVERRIDE  = "E"
    AI_AGENT_SURFACE     = "F"

    @property
    def label(self) -> str:
        return {
            "A": "AuthN Hygiene",
            "B": "AuthZ Structure",
            "C": "AuthZ Behaviour",
            "D": "Privilege Escalation",
            "E": "Delegation Override",
            "F": "AI Agent Surface",
        }[self.value]


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def numeric(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]


@dataclass
class Finding:
    """
    Universal finding container. Every risk class produces findings in this
    format. Gradient contribution determines rank — not manual severity weight.
    """

    # Identity
    category: str                               # e.g. 'kerberoastable_account'
    title: str
    risk_class: RiskClass
    severity: Severity

    # Scope
    affected_identities: List[str] = field(default_factory=list)
    affected_resources: List[str] = field(default_factory=list)
    affected_hosts: List[str] = field(default_factory=list)

    # Evidence — what we actually saw
    evidence_sources: List[str] = field(default_factory=list)
    evidence_detail: str = ""
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    observation_count: int = 0
    active_signal: bool = False     # being probed / exploited RIGHT NOW

    # Risk quantification
    gradient_contribution: float = 0.0     # ∂π_tier0/∂this_finding
    steady_state_impact: float = 0.0       # reduction in π_tier0 if remediated
    tier0_reachable_paths: int = 0         # attack paths to DA through this finding
    mean_steps_to_tier0: float = 999.0     # Markov mean first passage time

    # Compound risk
    compound_findings: List[str] = field(default_factory=list)  # finding IDs
    compound_multiplier: float = 1.0    # risk amplification from compounding

    # Remediation
    controls: List[str] = field(default_factory=list)       # θ parameter names
    remediation_steps: List[str] = field(default_factory=list)
    remediation_complexity: str = "MEDIUM"  # LOW / MEDIUM / HIGH
    estimated_effort_hours: int = 0

    # Dependency analysis
    breaks_if_changed: List[str] = field(default_factory=list)
    dependency_count: int = 0

    # Classification
    mitre_techniques: List[str] = field(default_factory=list)
    cve_references: List[str] = field(default_factory=list)
    historical_exploitation: bool = False

    # Computed ID
    id: str = field(default="", init=False)

    def __post_init__(self):
        self.id = self._compute_id()

    def _compute_id(self) -> str:
        key = f"{self.risk_class.value}:{self.category}:{':'.join(sorted(self.affected_identities))}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def weighted_priority(self) -> float:
        return abs(self.gradient_contribution) * self.compound_multiplier

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "risk_class": self.risk_class.value,
            "risk_class_label": self.risk_class.label,
            "category": self.category,
            "title": self.title,
            "severity": self.severity.value,
            "gradient_contribution": round(self.gradient_contribution, 4),
            "steady_state_impact": round(self.steady_state_impact, 4),
            "active_signal": self.active_signal,
            "affected_identities": self.affected_identities[:10],
            "affected_count": len(self.affected_identities),
            "evidence_sources": self.evidence_sources,
            "evidence_detail": self.evidence_detail,
            "controls": self.controls,
            "remediation_steps": self.remediation_steps,
            "mitre_techniques": self.mitre_techniques,
            "tier0_reachable_paths": self.tier0_reachable_paths,
            "compound_findings": self.compound_findings,
            "breaks_if_changed": self.breaks_if_changed,
        }


# ── Pre-defined finding templates for each scenario ──────────────────────────

def make_kerberoast_finding(accounts: List[str], active: bool = False) -> Finding:
    return Finding(
        category="kerberoastable_account",
        title=f"Kerberoastable Service Account(s): {len(accounts)} affected",
        risk_class=RiskClass.AUTHN_HYGIENE,
        severity=Severity.HIGH,
        affected_identities=accounts,
        evidence_sources=["ldap_spn", "4769_rc4_events"],
        active_signal=active,
        mitre_techniques=["T1558.003"],
        historical_exploitation=True,
        controls=["service_account_managed_passwords", "aes_encryption_enforcement"],
        remediation_steps=[
            "Rotate service account passwords (25+ chars)",
            "Enforce AES encryption for Kerberos (disable RC4)",
            "Use Group Managed Service Accounts (gMSA) where possible",
            "Remove unnecessary SPNs from user accounts",
        ],
        remediation_complexity="MEDIUM",
    )


def make_esc1_finding(templates: List[str], active: bool = False) -> Finding:
    return Finding(
        category="adcs_esc1_vulnerable_template",
        title=f"ADCS ESC1: Certificate Template(s) Allow Subject Alternative Name",
        risk_class=RiskClass.AUTHZ_STRUCTURE,
        severity=Severity.CRITICAL,
        affected_resources=templates,
        evidence_sources=["ldap_template_flags", "4886_events"],
        active_signal=active,
        mitre_techniques=["T1649"],
        historical_exploitation=True,
        controls=["adcs_template_hardened"],
        remediation_steps=[
            "Set CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0 on vulnerable templates",
            "Enable Manager Approval on templates with auth EKU",
            "Restrict enrollment rights to specific security groups",
            "Enable ADCS audit logging (4886, 4887, 4888)",
        ],
        remediation_complexity="LOW",
    )


def make_unconstrained_delegation_finding(computers: List[str]) -> Finding:
    return Finding(
        category="unconstrained_delegation",
        title=f"Unconstrained Kerberos Delegation: {len(computers)} computer(s)",
        risk_class=RiskClass.DELEGATION_OVERRIDE,
        severity=Severity.CRITICAL,
        affected_hosts=computers,
        evidence_sources=["ldap_uac_trusted_for_delegation"],
        mitre_techniques=["T1558"],
        historical_exploitation=True,
        controls=["constrained_delegation_migration", "delegation_audit"],
        remediation_steps=[
            "Migrate to constrained delegation with specific SPN targets",
            "Consider resource-based constrained delegation",
            "Ensure Tier 0 accounts are marked 'Account is sensitive and cannot be delegated'",
            "Monitor 4769 TGT forwardable ticket requests from these machines",
        ],
        remediation_complexity="HIGH",
    )


def make_lpe_finding(accounts: List[str], hosts: List[str], privilege: str) -> Finding:
    return Finding(
        category="dangerous_privilege_grant",
        title=f"Local Privilege Escalation Surface: {privilege}",
        risk_class=RiskClass.PRIVILEGE_ESCALATION,
        severity=Severity.CRITICAL,
        affected_identities=accounts,
        affected_hosts=hosts,
        evidence_sources=["4672_events"],
        active_signal=False,
        mitre_techniques=["T1134.001", "T1548"],
        historical_exploitation=True,
        controls=["edr_coverage"],
        evidence_detail=(
            f"{privilege} grants local privilege escalation capability. "
            "Primary control is EDR — AD-based controls have zero suppression effect. "
            "ImpersonatePrivilege enables Potato attacks to SYSTEM."
        ),
        remediation_steps=[
            "Deploy EDR on all affected hosts (primary control)",
            "Audit services running with SeImpersonatePrivilege",
            "Where possible, run services as virtualised service accounts",
            "Monitor for Sysmon Event 10 (LSASS access) from service processes",
        ],
        remediation_complexity="MEDIUM",
    )


def make_shadow_admin_finding(accounts: List[str], paths: List[str]) -> Finding:
    return Finding(
        category="shadow_admin",
        title=f"Shadow Administrator Accounts: {len(accounts)} via ACL chain",
        risk_class=RiskClass.AUTHZ_STRUCTURE,
        severity=Severity.HIGH,
        affected_identities=accounts,
        evidence_sources=["ldap_acl_computed"],
        evidence_detail=f"Effective admin control via: {'; '.join(paths[:3])}",
        mitre_techniques=["T1078.002"],
        historical_exploitation=True,
        controls=["acl_remediation", "tiered_admin"],
        remediation_steps=[
            "Remove excessive ACE grants: GenericAll, WriteDacl, GenericWrite on Tier0",
            "Implement tiered admin model separating Tier 0/1/2 management",
            "Audit AdminSDHolder protected objects and ACL inheritance",
            "Enable 4670 auditing on Tier 0 objects",
        ],
        remediation_complexity="HIGH",
    )


def make_ai_agent_finding(agents: List[str], vectors: List[str]) -> Finding:
    return Finding(
        category="ai_agent_injection_surface",
        title=f"AI Agent Prompt Injection Surface: {len(agents)} agent(s)",
        risk_class=RiskClass.AI_AGENT_SURFACE,
        severity=Severity.HIGH,
        affected_identities=agents,
        evidence_sources=["entra_app_permissions", "mcp_manifest"],
        active_signal=False,
        evidence_detail=(
            "AI agents with broad OAuth scopes and external content processing "
            "capability are weaponisable via prompt injection. Exploitation "
            "produces legitimate-looking log events — no ACL violation, "
            "no authentication anomaly."
        ),
        controls=["mcp_scope_restriction", "agent_content_isolation"],
        remediation_steps=[
            "Restrict OAuth scopes to minimum required for agent function",
            "Implement content isolation: agent should not process and act on external input",
            "Review MCP server tool permissions and remove code execution where unnecessary",
            "Add human-in-the-loop approval for sensitive agent actions",
            "Monitor Graph API activity logs for anomalous agent-initiated access",
        ],
        remediation_complexity="MEDIUM",
        mitre_techniques=["T1059"],
    )
