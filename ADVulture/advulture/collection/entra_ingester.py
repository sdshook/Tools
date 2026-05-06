# (c) 2025 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture — Entra ID (Azure AD) Enumerator and Log Ingester
Microsoft Graph API collection for cloud and hybrid environments.
Note: Azure AD was rebranded to Microsoft Entra ID in 2023.
Both names refer to the same service and the same APIs.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

log = logging.getLogger(__name__)


class SignInResult(str, Enum):
    SUCCESS         = "success"
    MFA_REQUIRED    = "mfa_required"
    MFA_COMPLETED   = "mfa_completed"
    CA_BLOCKED      = "conditional_access_blocked"
    INVALID_CREDS   = "invalid_credentials"
    ACCOUNT_LOCKED  = "account_locked"
    LEGACY_AUTH     = "legacy_auth_success"   # bypasses CA
    CONSENT_REQUIRED= "consent_required"
    OTHER           = "other"


ENTRA_RESULT_MAP: Dict[int, SignInResult] = {
    0:      SignInResult.SUCCESS,
    50074:  SignInResult.MFA_REQUIRED,
    50076:  SignInResult.MFA_COMPLETED,
    53003:  SignInResult.CA_BLOCKED,
    50126:  SignInResult.INVALID_CREDS,
    50053:  SignInResult.ACCOUNT_LOCKED,
    65001:  SignInResult.CONSENT_REQUIRED,
    50034:  SignInResult.INVALID_CREDS,  # no such user
}

# Critical Entra roles (Global Admin equivalent and near-equivalent)
CRITICAL_ROLE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "8ac3be0f-9b86-4bce-9054-bba9c94b5aa6": "Hybrid Identity Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "69091246-20e8-4a56-aa4d-066075b2a7a8": "Teams Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
}

# High-risk OAuth app permissions
DANGEROUS_APP_PERMISSIONS = {
    "RoleManagement.ReadWrite.Directory",   # Effectively Global Admin
    "Directory.ReadWrite.All",
    "User.ReadWrite.All",
    "Mail.ReadWrite",
    "Files.ReadWrite.All",
    "Sites.FullControl.All",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "GroupMember.ReadWrite.All",
}


@dataclass
class EntraUser:
    id: str
    user_principal_name: str
    display_name: str = ""
    on_prem_sam: str = ""           # onPremisesSamAccountName
    on_prem_sid: str = ""           # onPremisesSecurityIdentifier
    on_prem_sync: bool = False      # onPremisesSyncEnabled
    account_enabled: bool = True
    mfa_methods: List[str] = field(default_factory=list)
    last_signin: Optional[datetime] = None
    risk_level: str = "none"        # from Identity Protection
    risk_state: str = "none"
    password_policies: str = ""
    assigned_roles: List[str] = field(default_factory=list)
    is_critical_role: bool = False


@dataclass
class EntraServicePrincipal:
    id: str
    display_name: str
    app_id: str
    account_enabled: bool = True
    app_roles: List[str] = field(default_factory=list)
    oauth2_permissions: List[str] = field(default_factory=list)
    key_credentials: List[dict] = field(default_factory=list)
    password_credentials: List[dict] = field(default_factory=list)
    dangerous_permissions: List[str] = field(default_factory=list)
    is_ai_agent: bool = False       # detected from display name patterns


@dataclass
class EntraSignIn:
    id: str
    timestamp: datetime
    user_id: str
    user_principal_name: str
    app_display_name: str
    ip_address: str
    result_type: int
    result: SignInResult
    auth_requirement: str = ""      # singleFactorAuthentication / multiFactorAuthentication
    mfa_detail: Optional[dict] = None
    ca_policies_applied: List[dict] = field(default_factory=list)
    risk_level_during: str = "none"
    risk_level_aggregated: str = "none"
    token_issuer_type: str = ""     # AzureAD vs ADFS
    legacy_auth: bool = False       # True = auth protocol bypasses CA
    device_compliant: Optional[bool] = None
    location: Optional[dict] = None


@dataclass
class EntraAuditEvent:
    id: str
    timestamp: datetime
    activity_display_name: str
    category: str
    initiated_by_upn: str
    target_resources: List[str] = field(default_factory=list)
    result: str = "success"


@dataclass
class EntraSnapshot:
    timestamp: datetime
    tenant_id: str
    users: List[EntraUser] = field(default_factory=list)
    service_principals: List[EntraServicePrincipal] = field(default_factory=list)
    critical_role_assignments: List[dict] = field(default_factory=list)
    ca_policies: List[dict] = field(default_factory=list)
    pim_assignments: List[dict] = field(default_factory=list)
    sync_enabled: bool = False
    on_prem_sync_timestamp: Optional[datetime] = None
    federation_enabled: bool = False


@dataclass
class EntraEventStream:
    signins: List[EntraSignIn] = field(default_factory=list)
    audits: List[EntraAuditEvent] = field(default_factory=list)
    risk_detections: List[dict] = field(default_factory=list)

    def get_spray_candidates(self, window_hours: int = 1) -> List[dict]:
        """Detect password spray: many failures across many users in short window."""
        cutoff = datetime.utcnow() - timedelta(hours=window_hours)
        failures = [
            s for s in self.signins
            if s.timestamp >= cutoff
            and s.result == SignInResult.INVALID_CREDS
        ]
        by_ip: Dict[str, set] = {}
        for f in failures:
            by_ip.setdefault(f.ip_address, set()).add(f.user_principal_name)
        return [
            {"ip": ip, "targeted_users": len(users), "events": list(users)}
            for ip, users in by_ip.items()
            if len(users) >= 10  # 10+ unique users = spray
        ]

    def get_legacy_auth_signins(self) -> List[EntraSignIn]:
        return [s for s in self.signins if s.legacy_auth and
                s.result == SignInResult.SUCCESS]


class EntraEnumerator:
    """
    Microsoft Graph API enumeration for Entra ID (Azure AD).
    Requires: AuditLog.Read.All, Directory.Read.All,
              IdentityProtection.Read.All, Policy.Read.All,
              Reports.Read.All, RoleManagement.Read.Directory
    """

    # AI agent identity name patterns for classification
    AI_AGENT_PATTERNS = [
        "copilot", "openai", "langchain", "autogen", "mcp",
        "ai-agent", "llm", "gpt", "claude", "gemini",
        "power virtual", "copilot studio",
    ]

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                from azure.identity import ClientSecretCredential
                from msgraph import GraphServiceClient
                cred = ClientSecretCredential(
                    self.tenant_id, self.client_id, self.client_secret
                )
                self._client = GraphServiceClient(credentials=cred)
            except ImportError:
                log.warning("msgraph-sdk or azure-identity not installed.")
        return self._client

    async def enumerate_all(self) -> EntraSnapshot:
        log.info("Enumerating Entra ID tenant: %s", self.tenant_id)
        snapshot = EntraSnapshot(
            timestamp=datetime.utcnow(),
            tenant_id=self.tenant_id,
        )

        # In production, these would be async Graph API calls
        # Stubbed here for structure — implement with actual SDK calls
        snapshot.users = await self._get_users()
        snapshot.service_principals = await self._get_service_principals()
        snapshot.critical_role_assignments = await self._get_critical_roles()
        snapshot.ca_policies = await self._get_ca_policies()
        snapshot.pim_assignments = await self._get_pim_assignments()
        org = await self._get_org_config()
        snapshot.sync_enabled = org.get("onPremisesSyncEnabled", False)

        return snapshot

    async def _get_users(self) -> List[EntraUser]:
        """Fetch all users with security-relevant attributes."""
        # Production: use self._get_client() and make Graph API calls
        # Returns paginated results from /v1.0/users with $select
        log.info("Fetching Entra ID users...")
        return []  # Replace with: await self._paginate("/users", fields)

    async def _get_service_principals(self) -> List[EntraServicePrincipal]:
        """Identify service principals including AI agent identities."""
        log.info("Fetching service principals...")
        sps = []  # Replace with Graph API call
        for sp in sps:
            dangerous = [
                p for p in sp.get("appRoles", [])
                if p.get("value") in DANGEROUS_APP_PERMISSIONS
            ]
            display = sp.get("displayName", "").lower()
            is_ai = any(pat in display for pat in self.AI_AGENT_PATTERNS)
            sps.append(EntraServicePrincipal(
                id=sp.get("id", ""),
                display_name=sp.get("displayName", ""),
                app_id=sp.get("appId", ""),
                account_enabled=sp.get("accountEnabled", True),
                dangerous_permissions=dangerous,
                is_ai_agent=is_ai,
            ))
        return sps

    async def _get_critical_roles(self) -> List[dict]:
        """Fetch assignments to critical directory roles."""
        assignments = []
        for role_id, role_name in CRITICAL_ROLE_IDS.items():
            # GET /directoryRoles(roleTemplateId='{id}')/members
            members = []  # Replace with Graph API call
            for member in members:
                assignments.append({
                    "role_id": role_id,
                    "role_name": role_name,
                    "member_id": member.get("id"),
                    "member_upn": member.get("userPrincipalName"),
                })
        return assignments

    async def _get_ca_policies(self) -> List[dict]:
        """Fetch Conditional Access policies — gaps are AuthN hygiene findings."""
        return []  # GET /policies/conditionalAccessPolicies

    async def _get_pim_assignments(self) -> List[dict]:
        """Fetch PIM eligible and active role assignments."""
        return []  # GET /privilegedAccess/aadRoles/resources/...

    async def _get_org_config(self) -> dict:
        """Fetch organisation-level config including sync status."""
        return {}  # GET /organization


class EntraLogIngester:
    """
    Fetches sign-in and audit logs from Microsoft Graph API.
    Maps Entra events to the same semantic categories as Windows Event Logs.
    """

    LEGACY_AUTH_PROTOCOLS = {
        "exchange active sync", "imap4", "pop3", "smtp",
        "mapi over http", "rpc over http",
        "basic authentication", "legacy auth",
    }

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

    async def collect_window(self, days: int = 30) -> EntraEventStream:
        since = datetime.utcnow() - timedelta(days=days)
        stream = EntraEventStream()
        stream.signins = await self._get_signins(since)
        stream.audits = await self._get_audits(since)
        stream.risk_detections = await self._get_risk_detections(since)
        log.info(
            "Collected %d sign-ins, %d audits, %d risk events from Entra ID",
            len(stream.signins), len(stream.audits), len(stream.risk_detections)
        )
        return stream

    async def _get_signins(self, since: datetime) -> List[EntraSignIn]:
        """
        GET /auditLogs/signIns?$filter=createdDateTime ge {since}
        Returns up to 100,000 records per request with pagination.
        """
        signins = []
        raw = []  # Replace with Graph API paginated call
        for s in raw:
            error_code = s.get("status", {}).get("errorCode", 0)
            result = ENTRA_RESULT_MAP.get(error_code, SignInResult.OTHER)
            client_app = s.get("clientAppUsed", "").lower()
            is_legacy = any(p in client_app for p in self.LEGACY_AUTH_PROTOCOLS)
            signins.append(EntraSignIn(
                id=s.get("id", ""),
                timestamp=datetime.fromisoformat(
                    s.get("createdDateTime", "").rstrip("Z")
                ),
                user_id=s.get("userId", ""),
                user_principal_name=s.get("userPrincipalName", ""),
                app_display_name=s.get("appDisplayName", ""),
                ip_address=s.get("ipAddress", ""),
                result_type=error_code,
                result=result,
                auth_requirement=s.get("authenticationRequirement", ""),
                mfa_detail=s.get("mfaDetail"),
                ca_policies_applied=s.get("appliedConditionalAccessPolicies", []),
                risk_level_during=s.get("riskLevelDuringSignIn", "none"),
                risk_level_aggregated=s.get("riskLevelAggregated", "none"),
                token_issuer_type=s.get("tokenIssuerType", ""),
                legacy_auth=is_legacy,
                location=s.get("location"),
            ))
        return signins

    async def _get_audits(self, since: datetime) -> List[EntraAuditEvent]:
        """GET /auditLogs/directoryAudits"""
        return []

    async def _get_risk_detections(self, since: datetime) -> List[dict]:
        """GET /identityProtection/riskDetections"""
        return []
