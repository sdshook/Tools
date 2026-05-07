# (c) 2025 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture — Entra ID (Azure AD) Enumerator and Log Ingester
Microsoft Graph API collection for cloud and hybrid environments.
Note: Azure AD was rebranded to Microsoft Entra ID in 2023.
Both names refer to the same service and the same APIs.

Authentication Options:
- device_code:      Interactive login via device code flow (CLI/SSH-friendly)
- interactive:      Interactive login via browser popup (desktop)
- client_secret:    App registration with client secret (automation)
- certificate:      App registration with certificate (more secure automation)
- managed_identity: Azure Managed Identity (Azure-hosted workloads only)

For interactive modes (device_code, interactive), no app registration is required.
ADVulture uses Microsoft's well-known Azure CLI client ID by default.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any, TYPE_CHECKING
from enum import Enum

if TYPE_CHECKING:
    from advulture.config import EntraConfig

log = logging.getLogger(__name__)

# Well-known Microsoft public client IDs (no app registration needed)
AZURE_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
AZURE_POWERSHELL_CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2"
GRAPH_POWERSHELL_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

# Default client ID for interactive auth (Azure CLI - widely trusted)
DEFAULT_CLIENT_ID = AZURE_CLI_CLIENT_ID

# Default tenant for multi-tenant auth (any work/school account)
DEFAULT_TENANT = "organizations"


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
        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
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
    
    Supports multiple authentication modes:
    - device_code:      Interactive login via device code (best for CLI/SSH)
    - interactive:      Interactive login via browser popup (desktop)
    - client_secret:    App registration with client secret
    - certificate:      App registration with certificate
    - managed_identity: Azure Managed Identity (Azure-hosted only)
    
    Required Permissions (Application or Delegated):
        AuditLog.Read.All, Directory.Read.All,
        IdentityProtection.Read.All, Policy.Read.All,
        Reports.Read.All, RoleManagement.Read.Directory
    
    For delegated permissions, the signed-in user must have appropriate
    admin roles (e.g., Global Reader, Security Reader, Reports Reader).
    """

    # AI agent identity name patterns for classification
    AI_AGENT_PATTERNS = [
        "copilot", "openai", "langchain", "autogen", "mcp",
        "ai-agent", "llm", "gpt", "claude", "gemini",
        "power virtual", "copilot studio",
    ]

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        certificate_path: Optional[str] = None,
        certificate_password: Optional[str] = None,
        auth_mode: str = "device_code",
    ):
        """
        Initialize Entra ID enumerator with flexible authentication.
        
        For interactive modes (device_code, interactive), no parameters are required.
        Just instantiate and call enumerate_all() - you'll be prompted to log in,
        and your credentials determine which tenant you access.
        
        Args:
            tenant_id: Azure AD tenant ID or "organizations"/"common".
                       Optional for interactive auth (defaults to "organizations").
            client_id: Application (client) ID. Optional for interactive auth
                       (defaults to Azure CLI's well-known public client ID).
            client_secret: Client secret (only for auth_mode="client_secret")
            certificate_path: Path to .pem certificate (only for auth_mode="certificate")
            certificate_password: Optional certificate password
            auth_mode: One of: device_code, interactive, client_secret, 
                       certificate, managed_identity
        """
        # For interactive auth, use sensible defaults (no app registration needed)
        self.auth_mode = auth_mode.lower() if isinstance(auth_mode, str) else auth_mode
        
        if self.auth_mode in ("device_code", "interactive"):
            self.tenant_id = tenant_id or DEFAULT_TENANT
            self.client_id = client_id or DEFAULT_CLIENT_ID
        else:
            # Non-interactive modes require explicit IDs
            if not tenant_id:
                raise ValueError(f"tenant_id required for auth_mode='{auth_mode}'")
            if not client_id:
                raise ValueError(f"client_id required for auth_mode='{auth_mode}'")
            self.tenant_id = tenant_id
            self.client_id = client_id
            
        self.client_secret = client_secret
        self.certificate_path = certificate_path
        self.certificate_password = certificate_password
        self._client = None
        self._credential = None
        self._authenticated_tenant_id = None  # Actual tenant after auth

    @classmethod
    def from_config(cls, config: "EntraConfig") -> "EntraEnumerator":
        """Create enumerator from EntraConfig object."""
        return cls(
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret or None,
            certificate_path=config.certificate_path or None,
            certificate_password=config.certificate_password or None,
            auth_mode=config.auth_mode.value if hasattr(config.auth_mode, 'value') else config.auth_mode,
        )

    def _get_credential(self):
        """
        Build Azure credential based on configured auth_mode.
        
        Returns appropriate credential for the configured authentication mode.
        For interactive modes, will prompt user for authentication.
        """
        if self._credential is not None:
            return self._credential

        try:
            from azure.identity import (
                ClientSecretCredential,
                CertificateCredential,
                DeviceCodeCredential,
                InteractiveBrowserCredential,
                ManagedIdentityCredential,
                ChainedTokenCredential,
            )
        except ImportError as e:
            log.error("azure-identity not installed: %s", e)
            raise ImportError(
                "azure-identity package required. Install with: "
                "pip install azure-identity"
            ) from e

        mode = self.auth_mode.lower() if isinstance(self.auth_mode, str) else self.auth_mode

        if mode == "device_code":
            log.info("Using device code authentication — check terminal for login URL")
            self._credential = DeviceCodeCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                # Callback to display device code message
                prompt_callback=self._device_code_prompt,
            )

        elif mode == "interactive":
            log.info("Using interactive browser authentication")
            self._credential = InteractiveBrowserCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
            )

        elif mode == "client_secret":
            if not self.client_secret:
                raise ValueError("client_secret required for auth_mode='client_secret'")
            log.info("Using client secret authentication")
            self._credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )

        elif mode == "certificate":
            if not self.certificate_path:
                raise ValueError("certificate_path required for auth_mode='certificate'")
            log.info("Using certificate authentication")
            self._credential = CertificateCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                certificate_path=self.certificate_path,
                password=self.certificate_password,
            )

        elif mode == "managed_identity":
            log.info("Using managed identity authentication")
            self._credential = ManagedIdentityCredential(
                client_id=self.client_id if self.client_id else None,
            )

        else:
            # Default: try managed identity first, fall back to device code
            log.info("Using chained authentication (managed identity → device code)")
            self._credential = ChainedTokenCredential(
                ManagedIdentityCredential(),
                DeviceCodeCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    prompt_callback=self._device_code_prompt,
                ),
            )

        return self._credential

    def _device_code_prompt(self, verification_uri: str, user_code: str, expires_on: datetime):
        """Callback to display device code authentication instructions."""
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
        console.print(Panel.fit(
            f"[bold cyan]🔐 Entra ID Authentication Required[/bold cyan]\n\n"
            f"1. Open: [link={verification_uri}]{verification_uri}[/link]\n"
            f"2. Enter code: [bold yellow]{user_code}[/bold yellow]\n"
            f"3. Sign in with an admin account\n\n"
            f"[dim]Code expires: {expires_on}[/dim]",
            title="Device Code Login",
            border_style="cyan",
        ))

    def _get_client(self):
        """Get or create Microsoft Graph client with configured authentication."""
        if self._client is None:
            try:
                from msgraph import GraphServiceClient
            except ImportError as e:
                log.error("msgraph-sdk not installed: %s", e)
                raise ImportError(
                    "msgraph-sdk package required. Install with: "
                    "pip install msgraph-sdk"
                ) from e

            credential = self._get_credential()
            self._client = GraphServiceClient(credentials=credential)
            log.info("Microsoft Graph client initialized (auth_mode=%s)", self.auth_mode)

        return self._client

    async def enumerate_all(self) -> EntraSnapshot:
        log.info("Enumerating Entra ID tenant: %s", self.tenant_id)
        snapshot = EntraSnapshot(
            timestamp=datetime.now(timezone.utc),
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
        if not self._token:
            return []
        
        try:
            url = f"{self.GRAPH_BASE}/policies/conditionalAccessPolicies"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers={"Authorization": f"Bearer {self._token}"},
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("value", [])
                    else:
                        log.debug("Failed to fetch CA policies: %s", resp.status)
        except Exception as e:
            log.debug("Error fetching CA policies: %s", e)
        return []

    async def _get_pim_assignments(self) -> List[dict]:
        """Fetch PIM eligible and active role assignments.
        
        Requires RoleManagement.Read.All or PrivilegedAccess.Read.AzureADGroup permissions.
        """
        if not self._token:
            return []
        
        assignments = []
        try:
            # Get eligible role assignments
            eligible_url = f"{self.GRAPH_BASE}/roleManagement/directory/roleEligibilityScheduleInstances"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    eligible_url,
                    headers={"Authorization": f"Bearer {self._token}"},
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("value", []):
                            assignments.append({
                                "principalId": item.get("principalId"),
                                "roleDefinitionId": item.get("roleDefinitionId"),
                                "assignmentType": "eligible",
                                "startDateTime": item.get("startDateTime"),
                                "endDateTime": item.get("endDateTime"),
                            })
                    elif resp.status == 403:
                        log.debug("No permission for PIM eligible assignments")
                    else:
                        log.debug("Failed to fetch PIM eligible: %s", resp.status)
            
            # Get active role assignments
            active_url = f"{self.GRAPH_BASE}/roleManagement/directory/roleAssignmentScheduleInstances"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    active_url,
                    headers={"Authorization": f"Bearer {self._token}"},
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("value", []):
                            assignments.append({
                                "principalId": item.get("principalId"),
                                "roleDefinitionId": item.get("roleDefinitionId"),
                                "assignmentType": "active",
                                "startDateTime": item.get("startDateTime"),
                                "endDateTime": item.get("endDateTime"),
                            })
        except Exception as e:
            log.debug("Error fetching PIM assignments: %s", e)
        
        return assignments

    async def _get_org_config(self) -> dict:
        """Fetch organisation-level config including sync status."""
        if not self._token:
            return {}
        
        try:
            url = f"{self.GRAPH_BASE}/organization"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers={"Authorization": f"Bearer {self._token}"},
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        orgs = data.get("value", [])
                        if orgs:
                            return orgs[0]
        except Exception as e:
            log.debug("Error fetching org config: %s", e)
        return {}


class EntraLogIngester:
    """
    Fetches sign-in and audit logs from Microsoft Graph API.
    Maps Entra events to the same semantic categories as Windows Event Logs.
    
    Supports the same authentication modes as EntraEnumerator:
    - device_code, interactive, client_secret, certificate, managed_identity
    """

    LEGACY_AUTH_PROTOCOLS = {
        "exchange active sync", "imap4", "pop3", "smtp",
        "mapi over http", "rpc over http",
        "basic authentication", "legacy auth",
    }

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        certificate_path: Optional[str] = None,
        certificate_password: Optional[str] = None,
        auth_mode: str = "device_code",
    ):
        """
        Initialize Entra ID log ingester with flexible authentication.
        
        For interactive modes (device_code, interactive), no parameters are required.
        Just instantiate and call collect_window() - you'll be prompted to log in.
        
        Args:
            tenant_id: Azure AD tenant ID or "organizations"/"common".
                       Optional for interactive auth.
            client_id: Application (client) ID. Optional for interactive auth.
            client_secret: Client secret (only for auth_mode="client_secret")
            certificate_path: Path to .pem certificate (only for auth_mode="certificate")
            certificate_password: Optional certificate password
            auth_mode: One of: device_code, interactive, client_secret,
                       certificate, managed_identity
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.certificate_path = certificate_path
        self.certificate_password = certificate_password
        self.auth_mode = auth_mode
        self._enumerator: Optional[EntraEnumerator] = None

    @classmethod
    def from_config(cls, config: "EntraConfig") -> "EntraLogIngester":
        """Create log ingester from EntraConfig object."""
        return cls(
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret or None,
            certificate_path=config.certificate_path or None,
            certificate_password=config.certificate_password or None,
            auth_mode=config.auth_mode.value if hasattr(config.auth_mode, 'value') else config.auth_mode,
        )

    def _get_enumerator(self) -> EntraEnumerator:
        """Get shared EntraEnumerator for Graph client access."""
        if self._enumerator is None:
            self._enumerator = EntraEnumerator(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
                certificate_path=self.certificate_path,
                certificate_password=self.certificate_password,
                auth_mode=self.auth_mode,
            )
        return self._enumerator

    async def collect_window(self, days: int = 30) -> EntraEventStream:
        since = datetime.now(timezone.utc) - timedelta(days=days)
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
