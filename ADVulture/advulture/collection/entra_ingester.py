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

# Default client ID for interactive auth
# Graph PowerShell supports AuditLog.Read.All for sign-in logs via delegated auth
# This enables full security analysis without requiring app registration
DEFAULT_CLIENT_ID = GRAPH_POWERSHELL_CLIENT_ID

# Default tenant for multi-tenant auth (any work/school account)
DEFAULT_TENANT = "organizations"


class CachingCredentialWrapper:
    """Wrapper that caches tokens from a DeviceCodeCredential to prevent re-prompting.
    
    The msgraph SDK may request tokens multiple times. This wrapper ensures
    the device code flow only prompts once by caching the AccessToken.
    """
    
    def __init__(self, inner_credential):
        self._inner = inner_credential
        self._cached_token = None
        self._token_scope = None
    
    def get_token(self, *scopes, **kwargs):
        """Get token, returning cached token if valid."""
        import time
        
        # Check if we have a valid cached token
        if self._cached_token is not None:
            # Token is valid if it doesn't expire in the next 5 minutes
            if self._cached_token.expires_on > time.time() + 300:
                log.debug("Returning cached token (expires_on=%s)", self._cached_token.expires_on)
                return self._cached_token
            else:
                log.debug("Cached token expiring soon, refreshing...")
        
        # Get fresh token from inner credential
        log.debug("Requesting new token for scopes: %s", scopes)
        self._cached_token = self._inner.get_token(*scopes, **kwargs)
        self._token_scope = scopes
        return self._cached_token
    
    async def get_token_async(self, *scopes, **kwargs):
        """Async version - delegates to sync since DeviceCodeCredential is sync."""
        return self.get_token(*scopes, **kwargs)


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
    mfa_methods: List[str] = field(default_factory=list)  # e.g., ["microsoftAuthenticator", "fido2", "phone"]
    mfa_registered: bool = False    # True if ANY MFA method registered
    mfa_capable: bool = False       # True if strong MFA (not just SMS/voice)
    last_signin: Optional[datetime] = None
    risk_level: str = "none"        # from Identity Protection
    risk_state: str = "none"
    password_policies: str = ""
    assigned_roles: List[str] = field(default_factory=list)
    is_critical_role: bool = False


# MFA method categories for security assessment
STRONG_MFA_METHODS = {
    "microsoftAuthenticator",
    "fido2SecurityKey",
    "windowsHelloForBusiness",
    "softwareOath",  # TOTP apps like Google Authenticator
}

WEAK_MFA_METHODS = {
    "phone",         # SMS/Voice call
    "email",         # Email OTP
}

ALL_MFA_METHOD_TYPES = {
    "microsoftAuthenticator": "Microsoft Authenticator (Push/TOTP)",
    "fido2SecurityKey": "FIDO2 Security Key",
    "windowsHelloForBusiness": "Windows Hello for Business", 
    "softwareOath": "TOTP App (Google Authenticator, etc.)",
    "phone": "Phone (SMS/Voice) - WEAK",
    "email": "Email OTP - WEAK",
    "temporaryAccessPass": "Temporary Access Pass",
    "password": "Password Only - NO MFA",
}


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
class EntraRoleDefinition:
    """Entra ID directory role definition."""
    id: str
    template_id: str
    display_name: str
    description: str = ""
    is_built_in: bool = True
    is_enabled: bool = True
    is_privileged: bool = False  # We'll flag high-privilege roles


@dataclass
class EntraRoleAssignment:
    """Entra ID role assignment (active or eligible)."""
    id: str
    role_definition_id: str
    role_name: str
    principal_id: str
    principal_name: str
    principal_type: str  # User, ServicePrincipal, Group
    directory_scope_id: str = "/"  # "/" = tenant-wide, or AU ID
    assignment_type: str = "active"  # active or eligible (PIM)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None  # None = permanent
    created_time: Optional[datetime] = None


@dataclass
class EntraSnapshot:
    timestamp: datetime
    tenant_id: str
    users: List[EntraUser] = field(default_factory=list)
    service_principals: List[EntraServicePrincipal] = field(default_factory=list)
    critical_role_assignments: List[dict] = field(default_factory=list)  # Legacy - kept for compatibility
    ca_policies: List[dict] = field(default_factory=list)
    pim_assignments: List[dict] = field(default_factory=list)
    sync_enabled: bool = False
    on_prem_sync_timestamp: Optional[datetime] = None
    federation_enabled: bool = False
    # Enhanced role analysis
    role_definitions: List[EntraRoleDefinition] = field(default_factory=list)
    all_role_assignments: List[EntraRoleAssignment] = field(default_factory=list)
    oauth_grants: List[dict] = field(default_factory=list)  # User consent grants


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
        
        Security Note: Token persistence is explicitly disabled to prevent
        sensitive credentials from being written to disk. This is critical
        for forensic tooling where token artifacts could contaminate evidence
        or create security risks if the analysis workstation is compromised.
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
                TokenCachePersistenceOptions,
            )
        except ImportError as e:
            log.error("azure-identity not installed: %s", e)
            raise ImportError(
                "azure-identity package required. Install with: "
                "pip install azure-identity"
            ) from e

        mode = self.auth_mode.lower() if isinstance(self.auth_mode, str) else self.auth_mode
        
        # SECURITY: Disable persistent token caching to prevent tokens from
        # being written to disk. Tokens are held in memory only for this session.
        # This prevents:
        # 1. Token artifacts contaminating forensic evidence
        # 2. Cached credentials persisting after analysis completes
        # 3. Security risks from token theft on analysis workstations
        #
        # Note: cache_persistence_options=None explicitly disables MSAL's
        # default disk-based token caching behavior.
        no_persist_cache = None  # Explicitly disable persistence

        if mode == "device_code":
            log.info("Using device code authentication — check terminal for login URL")
            self._credential = DeviceCodeCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                prompt_callback=self._device_code_prompt,
                cache_persistence_options=no_persist_cache,
            )

        elif mode == "interactive":
            log.info("Using interactive browser authentication")
            self._credential = InteractiveBrowserCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                cache_persistence_options=no_persist_cache,
            )

        elif mode == "client_secret":
            if not self.client_secret:
                raise ValueError("client_secret required for auth_mode='client_secret'")
            log.info("Using client secret authentication")
            self._credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
                # Note: ClientSecretCredential doesn't use token cache persistence
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
                # Note: CertificateCredential doesn't use token cache persistence
            )

        elif mode == "managed_identity":
            log.info("Using managed identity authentication")
            self._credential = ManagedIdentityCredential(
                client_id=self.client_id if self.client_id else None,
                # Note: ManagedIdentityCredential doesn't use token cache persistence
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
                    cache_persistence_options=no_persist_cache,
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
        """Get or create Microsoft Graph client with configured authentication.
        
        For device_code auth, wraps the credential in CachingCredentialWrapper
        to prevent double authentication prompts from the msgraph SDK.
        """
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
            
            # Wrap device_code credentials to cache tokens and prevent re-prompting
            if self.auth_mode == "device_code":
                log.info("Wrapping credential with token cache for device code flow")
                credential = CachingCredentialWrapper(credential)
                # Pre-authenticate to trigger device code prompt once
                log.info("Authenticating (this will prompt for device code)...")
                credential.get_token("https://graph.microsoft.com/.default")
                log.info("Authentication successful, token cached")
            
            self._client = GraphServiceClient(credentials=credential)
            log.info("Microsoft Graph client initialized (auth_mode=%s)", self.auth_mode)

        return self._client

    async def enumerate_all(self) -> EntraSnapshot:
        log.info("Enumerating Entra ID tenant: %s", self.tenant_id)
        snapshot = EntraSnapshot(
            timestamp=datetime.now(timezone.utc),
            tenant_id=self.tenant_id,
        )

        # Core enumeration
        snapshot.users = await self._get_users()
        snapshot.service_principals = await self._get_service_principals()
        snapshot.critical_role_assignments = await self._get_critical_roles()
        snapshot.ca_policies = await self._get_ca_policies()
        snapshot.pim_assignments = await self._get_pim_assignments()
        org = await self._get_org_config()
        snapshot.sync_enabled = org.get("onPremisesSyncEnabled", False)
        
        # Enhanced role analysis - enumerate ALL roles and assignments
        snapshot.role_definitions = await self._get_all_role_definitions()
        snapshot.all_role_assignments = await self._get_all_role_assignments(snapshot.role_definitions)
        snapshot.oauth_grants = await self._get_oauth_grants()
        
        # Enrich users with MFA method information
        await self._enrich_users_with_mfa(snapshot.users)

        return snapshot

    async def _get_users(self) -> List[EntraUser]:
        """Fetch all users with security-relevant attributes.
        
        Uses msgraph SDK with pagination to fetch all users including
        security-relevant attributes like MFA status, risk level, etc.
        """
        log.info("Fetching Entra ID users...")
        users = []
        
        try:
            client = self._get_client()
            
            # Build request with select for relevant fields
            from msgraph.generated.users.users_request_builder import UsersRequestBuilder
            from kiota_abstractions.base_request_configuration import RequestConfiguration
            
            query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                select=[
                    "id", "userPrincipalName", "displayName", 
                    "onPremisesSamAccountName", "onPremisesSecurityIdentifier",
                    "onPremisesSyncEnabled", "accountEnabled",
                    "signInActivity", "passwordPolicies",
                ],
                top=999,
            )
            request_config = RequestConfiguration(query_parameters=query_params)
            
            result = await client.users.get(request_configuration=request_config)
            
            while result:
                if result.value:
                    for u in result.value:
                        try:
                            # Parse last sign-in time
                            last_signin = None
                            if u.sign_in_activity and u.sign_in_activity.last_sign_in_date_time:
                                last_signin = u.sign_in_activity.last_sign_in_date_time.replace(tzinfo=timezone.utc)
                            
                            user = EntraUser(
                                id=u.id or "",
                                user_principal_name=u.user_principal_name or "",
                                display_name=u.display_name or "",
                                on_prem_sam=u.on_premises_sam_account_name or "",
                                on_prem_sid=u.on_premises_security_identifier or "",
                                on_prem_sync=u.on_premises_sync_enabled or False,
                                account_enabled=u.account_enabled if u.account_enabled is not None else True,
                                last_signin=last_signin,
                                password_policies=u.password_policies or "",
                            )
                            users.append(user)
                        except Exception as parse_err:
                            log.debug("Failed to parse user record: %s", parse_err)
                            continue
                
                # Check for next page
                if hasattr(result, 'odata_next_link') and result.odata_next_link:
                    result = await client.users.with_url(result.odata_next_link).get()
                else:
                    break
            
            log.info("Fetched %d users from Entra ID", len(users))
            
        except ImportError as ie:
            log.warning("msgraph-sdk not available: %s", ie)
        except Exception as e:
            log.warning("Failed to fetch users from Graph API: %s", e)
            
        return users

    async def _get_service_principals(self) -> List[EntraServicePrincipal]:
        """Identify service principals including AI agent identities.
        
        Uses the msgraph SDK to fetch service principals and identify
        those with dangerous permissions or AI agent patterns.
        """
        log.info("Fetching service principals...")
        result_sps = []
        
        try:
            client = self._get_client()
            # Fetch service principals from Graph API
            result = await client.service_principals.get()
            
            if result and result.value:
                for sp in result.value:
                    # Check for dangerous app permissions
                    dangerous = []
                    if sp.app_roles:
                        for role in sp.app_roles:
                            if role.value in DANGEROUS_APP_PERMISSIONS:
                                dangerous.append(role.value)
                    
                    # Check OAuth2 permission scopes
                    oauth2_perms = []
                    if sp.oauth2_permission_scopes:
                        for scope in sp.oauth2_permission_scopes:
                            oauth2_perms.append(scope.value or scope.id)
                            if scope.value in DANGEROUS_APP_PERMISSIONS:
                                dangerous.append(scope.value)
                    
                    # Check for AI agent patterns in display name
                    display = (sp.display_name or "").lower()
                    is_ai = any(pat in display for pat in self.AI_AGENT_PATTERNS)
                    
                    result_sps.append(EntraServicePrincipal(
                        id=sp.id or "",
                        display_name=sp.display_name or "",
                        app_id=sp.app_id or "",
                        account_enabled=sp.account_enabled if sp.account_enabled is not None else True,
                        app_roles=[r.value for r in (sp.app_roles or []) if r.value],
                        oauth2_permissions=oauth2_perms,
                        dangerous_permissions=dangerous,
                        is_ai_agent=is_ai,
                    ))
                    
            log.info("Fetched %d service principals", len(result_sps))
            
        except Exception as e:
            log.warning("Error fetching service principals: %s", e)
        
        return result_sps

    async def _get_critical_roles(self) -> List[dict]:
        """Fetch assignments to critical directory roles.
        
        Uses msgraph SDK to enumerate role assignments for critical
        Entra ID roles like Global Administrator.
        """
        log.info("Fetching critical role assignments...")
        assignments = []
        
        try:
            client = self._get_client()
            
            # First, get all directory roles (active role assignments)
            result = await client.directory_roles.get()
            
            if result and result.value:
                for role in result.value:
                    # Check if this is a critical role
                    role_template_id = role.role_template_id
                    if role_template_id not in CRITICAL_ROLE_IDS:
                        continue
                    
                    role_name = CRITICAL_ROLE_IDS[role_template_id]
                    
                    # Fetch members of this role
                    try:
                        members_result = await client.directory_roles.by_directory_role_id(role.id).members.get()
                        
                        if members_result and members_result.value:
                            for member in members_result.value:
                                # Extract UPN if available (users) or display name (service principals)
                                member_upn = getattr(member, 'user_principal_name', None)
                                if not member_upn:
                                    member_upn = getattr(member, 'display_name', member.id)
                                
                                assignments.append({
                                    "role_id": role_template_id,
                                    "role_name": role_name,
                                    "member_id": member.id,
                                    "member_upn": member_upn,
                                    "member_type": member.odata_type.split('.')[-1] if member.odata_type else "unknown",
                                })
                    except Exception as member_err:
                        log.debug("Failed to fetch members for role %s: %s", role_name, member_err)
                        continue
            
            log.info("Fetched %d critical role assignments", len(assignments))
            
        except ImportError as ie:
            log.warning("msgraph-sdk not available: %s", ie)
        except Exception as e:
            log.warning("Failed to fetch critical roles from Graph API: %s", e)
            
        return assignments

    async def _get_ca_policies(self) -> List[dict]:
        """Fetch Conditional Access policies — gaps are AuthN hygiene findings.
        
        Uses the msgraph SDK to fetch policies via Graph API.
        """
        policies = []
        try:
            client = self._get_client()
            # Use the SDK's identity/conditionalAccess/policies endpoint
            result = await client.identity.conditional_access.policies.get()
            if result and result.value:
                for policy in result.value:
                    policies.append({
                        "id": policy.id,
                        "displayName": policy.display_name,
                        "state": policy.state.value if policy.state else "unknown",
                        "conditions": {
                            "users": getattr(policy.conditions, 'users', None),
                            "applications": getattr(policy.conditions, 'applications', None),
                        } if policy.conditions else {},
                        "grantControls": {
                            "builtInControls": policy.grant_controls.built_in_controls 
                                if policy.grant_controls else [],
                        } if policy.grant_controls else {},
                    })
        except Exception as e:
            log.debug("Error fetching CA policies: %s", e)
        return policies

    async def _get_pim_assignments(self) -> List[dict]:
        """Fetch PIM eligible and active role assignments.
        
        Requires RoleManagement.Read.All or PrivilegedAccess.Read.AzureADGroup permissions.
        Uses the msgraph SDK for API calls.
        """
        assignments = []
        try:
            client = self._get_client()
            
            # Get eligible role assignments
            try:
                eligible = await client.role_management.directory.role_eligibility_schedule_instances.get()
                if eligible and eligible.value:
                    for item in eligible.value:
                        assignments.append({
                            "principalId": item.principal_id,
                            "roleDefinitionId": item.role_definition_id,
                            "assignmentType": "eligible",
                            "startDateTime": str(item.start_date_time) if item.start_date_time else None,
                            "endDateTime": str(item.end_date_time) if item.end_date_time else None,
                        })
            except Exception as e:
                log.debug("No permission for PIM eligible assignments: %s", e)
            
            # Get active role assignments
            try:
                active = await client.role_management.directory.role_assignment_schedule_instances.get()
                if active and active.value:
                    for item in active.value:
                        assignments.append({
                            "principalId": item.principal_id,
                            "roleDefinitionId": item.role_definition_id,
                            "assignmentType": "active",
                            "startDateTime": str(item.start_date_time) if item.start_date_time else None,
                            "endDateTime": str(item.end_date_time) if item.end_date_time else None,
                        })
            except Exception as e:
                log.debug("No permission for PIM active assignments: %s", e)
                
        except Exception as e:
            log.debug("Error fetching PIM assignments: %s", e)
        
        return assignments

    async def _get_org_config(self) -> dict:
        """Fetch organisation-level config including sync status.
        
        Uses the msgraph SDK to fetch organization configuration.
        """
        try:
            client = self._get_client()
            result = await client.organization.get()
            if result and result.value and len(result.value) > 0:
                org = result.value[0]
                return {
                    "id": org.id,
                    "displayName": org.display_name,
                    "onPremisesSyncEnabled": org.on_premises_sync_enabled or False,
                    "onPremisesLastSyncDateTime": str(org.on_premises_last_sync_date_time) 
                        if org.on_premises_last_sync_date_time else None,
                    "verifiedDomains": [d.name for d in (org.verified_domains or [])],
                }
        except Exception as e:
            log.debug("Error fetching org config: %s", e)
        return {}

    # =========================================================================
    # Enhanced Role Analysis Methods
    # =========================================================================
    
    # High-privilege roles that warrant extra scrutiny
    HIGH_PRIVILEGE_ROLES = {
        "Global Administrator",
        "Privileged Role Administrator", 
        "Privileged Authentication Administrator",
        "Security Administrator",
        "User Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Authentication Administrator",
        "Helpdesk Administrator",
        "Password Administrator",
        "Groups Administrator",
        "License Administrator",
        "Intune Administrator",
        "Azure DevOps Administrator",
        "Hybrid Identity Administrator",
        "Identity Governance Administrator",
        "Conditional Access Administrator",
    }

    async def _get_all_role_definitions(self) -> List[EntraRoleDefinition]:
        """Fetch ALL Entra ID role definitions (built-in and custom).
        
        Returns complete list of available roles in the tenant,
        including custom roles if any exist.
        """
        log.info("Fetching all Entra ID role definitions...")
        roles = []
        
        try:
            client = self._get_client()
            
            # Use roleManagement/directory/roleDefinitions for complete list
            result = await client.role_management.directory.role_definitions.get()
            
            while result:
                if result.value:
                    for role_def in result.value:
                        is_privileged = role_def.display_name in self.HIGH_PRIVILEGE_ROLES
                        
                        roles.append(EntraRoleDefinition(
                            id=role_def.id,
                            template_id=getattr(role_def, 'template_id', role_def.id) or role_def.id,
                            display_name=role_def.display_name or "",
                            description=role_def.description or "",
                            is_built_in=getattr(role_def, 'is_built_in', True) or True,
                            is_enabled=getattr(role_def, 'is_enabled', True) or True,
                            is_privileged=is_privileged,
                        ))
                
                # Handle pagination
                if hasattr(result, 'odata_next_link') and result.odata_next_link:
                    result = await client.role_management.directory.role_definitions.with_url(
                        result.odata_next_link
                    ).get()
                else:
                    break
            
            log.info("Fetched %d role definitions (%d privileged)", 
                     len(roles), len([r for r in roles if r.is_privileged]))
                     
        except Exception as e:
            log.warning("Failed to fetch role definitions: %s", e)
            
        return roles

    async def _get_all_role_assignments(
        self, 
        role_definitions: List[EntraRoleDefinition]
    ) -> List[EntraRoleAssignment]:
        """Fetch ALL role assignments (active and eligible).
        
        Correlates assignments with role definitions and principal names.
        """
        log.info("Fetching all Entra ID role assignments...")
        assignments = []
        
        # Build role lookup
        role_lookup = {r.id: r.display_name for r in role_definitions}
        
        try:
            client = self._get_client()
            
            # Get active role assignments
            result = await client.role_management.directory.role_assignments.get()
            
            while result:
                if result.value:
                    for assignment in result.value:
                        role_name = role_lookup.get(
                            assignment.role_definition_id, 
                            "Unknown Role"
                        )
                        
                        # Get principal name (requires additional lookup)
                        principal_name = await self._resolve_principal_name(
                            assignment.principal_id
                        )
                        
                        assignments.append(EntraRoleAssignment(
                            id=assignment.id,
                            role_definition_id=assignment.role_definition_id,
                            role_name=role_name,
                            principal_id=assignment.principal_id,
                            principal_name=principal_name,
                            principal_type=await self._get_principal_type(assignment.principal_id),
                            directory_scope_id=getattr(assignment, 'directory_scope_id', '/') or '/',
                            assignment_type="active",
                        ))
                
                # Handle pagination
                if hasattr(result, 'odata_next_link') and result.odata_next_link:
                    result = await client.role_management.directory.role_assignments.with_url(
                        result.odata_next_link
                    ).get()
                else:
                    break
            
            # Also get PIM eligible assignments if available
            try:
                eligible = await self._get_pim_eligible_assignments(role_lookup)
                assignments.extend(eligible)
            except Exception as pim_err:
                log.debug("PIM eligible assignments not available: %s", pim_err)
            
            log.info("Fetched %d total role assignments", len(assignments))
            
        except Exception as e:
            log.warning("Failed to fetch role assignments: %s", e)
            
        return assignments

    async def _get_pim_eligible_assignments(
        self, 
        role_lookup: dict
    ) -> List[EntraRoleAssignment]:
        """Fetch PIM eligible role assignments (JIT access).
        
        These are roles that users CAN activate but aren't currently active.
        """
        eligible = []
        
        try:
            client = self._get_client()
            result = await client.role_management.directory.role_eligibility_schedules.get()
            
            while result:
                if result.value:
                    for schedule in result.value:
                        role_name = role_lookup.get(
                            schedule.role_definition_id,
                            "Unknown Role"
                        )
                        
                        principal_name = await self._resolve_principal_name(
                            schedule.principal_id
                        )
                        
                        eligible.append(EntraRoleAssignment(
                            id=schedule.id,
                            role_definition_id=schedule.role_definition_id,
                            role_name=role_name,
                            principal_id=schedule.principal_id,
                            principal_name=principal_name,
                            principal_type=await self._get_principal_type(schedule.principal_id),
                            directory_scope_id=getattr(schedule, 'directory_scope_id', '/') or '/',
                            assignment_type="eligible",
                            start_time=getattr(schedule, 'start_date_time', None),
                            end_time=getattr(schedule, 'end_date_time', None),
                        ))
                
                if hasattr(result, 'odata_next_link') and result.odata_next_link:
                    result = await client.role_management.directory.role_eligibility_schedules.with_url(
                        result.odata_next_link
                    ).get()
                else:
                    break
                    
            log.info("Fetched %d PIM eligible assignments", len(eligible))
            
        except Exception as e:
            log.debug("PIM not available or no eligible assignments: %s", e)
            
        return eligible

    async def _resolve_principal_name(self, principal_id: str) -> str:
        """Resolve a principal ID to a display name or UPN."""
        try:
            client = self._get_client()
            
            # Try as user first
            try:
                user = await client.users.by_user_id(principal_id).get()
                if user:
                    return user.user_principal_name or user.display_name or principal_id
            except:
                pass
            
            # Try as service principal
            try:
                sp = await client.service_principals.by_service_principal_id(principal_id).get()
                if sp:
                    return sp.display_name or principal_id
            except:
                pass
            
            # Try as group
            try:
                group = await client.groups.by_group_id(principal_id).get()
                if group:
                    return f"[Group] {group.display_name}" or principal_id
            except:
                pass
                
        except Exception:
            pass
            
        return principal_id

    async def _get_principal_type(self, principal_id: str) -> str:
        """Determine the type of a principal (User, ServicePrincipal, Group)."""
        try:
            client = self._get_client()
            
            try:
                await client.users.by_user_id(principal_id).get()
                return "User"
            except:
                pass
            
            try:
                await client.service_principals.by_service_principal_id(principal_id).get()
                return "ServicePrincipal"
            except:
                pass
            
            try:
                await client.groups.by_group_id(principal_id).get()
                return "Group"
            except:
                pass
                
        except Exception:
            pass
            
        return "Unknown"

    async def _get_oauth_grants(self) -> List[dict]:
        """Fetch OAuth2 permission grants (user consent grants).
        
        These represent permissions users have granted to applications.
        High-risk grants (Mail.Read, Files.ReadWrite) are security concerns.
        """
        log.info("Fetching OAuth permission grants...")
        grants = []
        
        try:
            client = self._get_client()
            result = await client.oauth2_permission_grants.get()
            
            while result:
                if result.value:
                    for grant in result.value:
                        grants.append({
                            "id": grant.id,
                            "client_id": grant.client_id,  # App that received consent
                            "principal_id": grant.principal_id,  # User who consented (None = admin)
                            "consent_type": grant.consent_type,  # AllPrincipals or Principal
                            "scope": grant.scope,  # Permissions granted
                            "resource_id": grant.resource_id,  # API being accessed
                        })
                
                if hasattr(result, 'odata_next_link') and result.odata_next_link:
                    result = await client.oauth2_permission_grants.with_url(
                        result.odata_next_link
                    ).get()
                else:
                    break
            
            log.info("Fetched %d OAuth permission grants", len(grants))
            
        except Exception as e:
            log.warning("Failed to fetch OAuth grants: %s", e)
            
        return grants

    async def _enrich_users_with_mfa(self, users: List[EntraUser]) -> None:
        """Fetch authentication methods for each user and enrich user objects.
        
        Requires UserAuthenticationMethod.Read.All permission.
        Categorizes MFA methods as strong (Authenticator, FIDO2) or weak (SMS, Voice).
        """
        log.info("Enriching %d users with MFA method information...", len(users))
        
        try:
            client = self._get_client()
            enriched_count = 0
            no_mfa_count = 0
            weak_only_count = 0
            
            for user in users:
                try:
                    # Fetch authentication methods for this user
                    result = await client.users.by_user_id(user.id).authentication.methods.get()
                    
                    if result and result.value:
                        methods = []
                        has_strong = False
                        has_weak = False
                        
                        for method in result.value:
                            # Extract method type from odata_type
                            method_type = None
                            if method.odata_type:
                                # e.g., "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"
                                type_name = method.odata_type.split('.')[-1]
                                # Convert to simpler name
                                if "microsoftAuthenticator" in type_name:
                                    method_type = "microsoftAuthenticator"
                                elif "fido2" in type_name.lower():
                                    method_type = "fido2SecurityKey"
                                elif "windowsHello" in type_name.lower():
                                    method_type = "windowsHelloForBusiness"
                                elif "softwareOath" in type_name.lower():
                                    method_type = "softwareOath"
                                elif "phone" in type_name.lower():
                                    method_type = "phone"
                                elif "email" in type_name.lower():
                                    method_type = "email"
                                elif "temporaryAccessPass" in type_name.lower():
                                    method_type = "temporaryAccessPass"
                                elif "password" in type_name.lower():
                                    method_type = "password"
                                else:
                                    method_type = type_name
                            
                            if method_type and method_type != "password":
                                methods.append(method_type)
                                if method_type in STRONG_MFA_METHODS:
                                    has_strong = True
                                elif method_type in WEAK_MFA_METHODS:
                                    has_weak = True
                        
                        # Update user object
                        user.mfa_methods = methods
                        user.mfa_registered = len(methods) > 0
                        user.mfa_capable = has_strong  # Strong MFA available
                        
                        if not methods:
                            no_mfa_count += 1
                        elif not has_strong and has_weak:
                            weak_only_count += 1
                        
                        enriched_count += 1
                        
                except Exception as user_err:
                    # Some users may not be accessible (guests, etc.)
                    log.debug("Could not fetch MFA for user %s: %s", 
                             user.user_principal_name, user_err)
                    continue
            
            log.info(
                "MFA enrichment complete: %d users enriched, %d without MFA, %d weak MFA only",
                enriched_count, no_mfa_count, weak_only_count
            )
            
        except Exception as e:
            log.warning("Failed to enrich users with MFA data: %s", e)

    async def _get_mfa_registration_report(self) -> dict:
        """Get authentication methods registration summary.
        
        Uses the authenticationMethodsPolicy for tenant-wide MFA status.
        Returns summary statistics.
        """
        summary = {
            "total_users": 0,
            "mfa_registered": 0,
            "mfa_capable": 0,  # Strong MFA
            "weak_mfa_only": 0,
            "no_mfa": 0,
            "by_method": {},
        }
        
        try:
            client = self._get_client()
            
            # Try to get registration details report
            # This requires Reports.Read.All permission
            result = await client.reports.authentication_methods.users_registered_by_method.get()
            
            if result and result.value:
                for item in result.value:
                    method = getattr(item, 'authentication_method', 'unknown')
                    count = getattr(item, 'user_count', 0)
                    summary["by_method"][method] = count
                    
        except Exception as e:
            log.debug("Could not fetch MFA registration report: %s", e)
            
        return summary


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

    async def collect_window(self, days: int = 30, progress_callback=None) -> EntraEventStream:
        """
        Collect sign-in logs, audit logs, and risk detections for the specified window.
        
        Args:
            days: Number of days to look back
            progress_callback: Optional callback(stage, current, total) for progress updates
        """
        since = datetime.now(timezone.utc) - timedelta(days=days)
        stream = EntraEventStream()
        
        # Collect each data type with progress updates
        if progress_callback:
            progress_callback("sign-ins", 0, 3)
        stream.signins = await self._get_signins(since)
        
        if progress_callback:
            progress_callback("audits", 1, 3)
        stream.audits = await self._get_audits(since)
        
        if progress_callback:
            progress_callback("risk_detections", 2, 3)
        stream.risk_detections = await self._get_risk_detections(since)
        
        if progress_callback:
            progress_callback("complete", 3, 3)
            
        log.info(
            "Collected %d sign-ins, %d audits, %d risk events from Entra ID",
            len(stream.signins), len(stream.audits), len(stream.risk_detections)
        )
        return stream

    async def _get_signins(self, since: datetime) -> List[EntraSignIn]:
        """
        GET /auditLogs/signIns?$filter=createdDateTime ge {since}
        Uses msgraph SDK with automatic pagination.
        """
        signins = []
        try:
            enumerator = self._get_enumerator()
            client = enumerator._get_client()
            
            # Format datetime for OData filter
            since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            # Build request configuration
            from msgraph.generated.audit_logs.sign_ins.sign_ins_request_builder import SignInsRequestBuilder
            from kiota_abstractions.base_request_configuration import RequestConfiguration
            
            query_params = SignInsRequestBuilder.SignInsRequestBuilderGetQueryParameters(
                filter=f"createdDateTime ge {since_str}",
                orderby=["createdDateTime desc"],
                top=999,  # Max per page
            )
            request_config = RequestConfiguration(query_parameters=query_params)
            
            # Fetch with pagination
            result = await client.audit_logs.sign_ins.get(request_configuration=request_config)
            
            while result:
                if result.value:
                    for s in result.value:
                        try:
                            error_code = s.status.error_code if s.status else 0
                            result_type = ENTRA_RESULT_MAP.get(error_code, SignInResult.OTHER)
                            client_app = (s.client_app_used or "").lower()
                            is_legacy = any(p in client_app for p in self.LEGACY_AUTH_PROTOCOLS)
                            
                            # Handle optional attributes that may not exist in all SDK versions
                            mfa_detail_obj = getattr(s, 'mfa_detail', None)
                            mfa_detail = None
                            if mfa_detail_obj:
                                mfa_detail = {"method": getattr(mfa_detail_obj, 'auth_method', None)}
                            
                            token_issuer = getattr(s, 'token_issuer_type', None)
                            token_issuer_str = token_issuer.value if token_issuer else ""
                            
                            signin = EntraSignIn(
                                id=s.id or "",
                                timestamp=s.created_date_time.replace(tzinfo=timezone.utc) if s.created_date_time else datetime.now(timezone.utc),
                                user_id=s.user_id or "",
                                user_principal_name=s.user_principal_name or "",
                                app_display_name=s.app_display_name or "",
                                ip_address=s.ip_address or "",
                                result_type=error_code,
                                result=result_type,
                                auth_requirement=getattr(s, 'authentication_requirement', None) or "",
                                mfa_detail=mfa_detail,
                                ca_policies_applied=[
                                    {"displayName": p.display_name, "result": p.result.value if p.result else "unknown"}
                                    for p in (s.applied_conditional_access_policies or [])
                                ],
                                risk_level_during=s.risk_level_during_sign_in.value if s.risk_level_during_sign_in else "none",
                                risk_level_aggregated=s.risk_level_aggregated.value if s.risk_level_aggregated else "none",
                                token_issuer_type=token_issuer_str,
                                legacy_auth=is_legacy,
                                location={"city": s.location.city, "country": s.location.country_or_region} if s.location else None,
                            )
                            signins.append(signin)
                        except Exception as parse_err:
                            log.debug("Failed to parse sign-in record: %s", parse_err)
                            continue
                
                # Check for next page
                if hasattr(result, 'odata_next_link') and result.odata_next_link:
                    result = await client.audit_logs.sign_ins.with_url(result.odata_next_link).get()
                else:
                    break
                    
            log.info("Fetched %d sign-in records from Entra ID", len(signins))
            
        except ImportError as ie:
            log.warning("msgraph-sdk not available: %s", ie)
        except Exception as e:
            log.warning("Failed to fetch sign-ins from Graph API: %s", e)
            
        return signins

    async def _get_audits(self, since: datetime) -> List[EntraAuditEvent]:
        """
        GET /auditLogs/directoryAudits
        Uses msgraph SDK with automatic pagination.
        """
        audits = []
        try:
            enumerator = self._get_enumerator()
            client = enumerator._get_client()
            
            # Format datetime for OData filter
            since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            from msgraph.generated.audit_logs.directory_audits.directory_audits_request_builder import DirectoryAuditsRequestBuilder
            from kiota_abstractions.base_request_configuration import RequestConfiguration
            
            query_params = DirectoryAuditsRequestBuilder.DirectoryAuditsRequestBuilderGetQueryParameters(
                filter=f"activityDateTime ge {since_str}",
                orderby=["activityDateTime desc"],
                top=999,
            )
            request_config = RequestConfiguration(query_parameters=query_params)
            
            result = await client.audit_logs.directory_audits.get(request_configuration=request_config)
            
            while result:
                if result.value:
                    for a in result.value:
                        try:
                            # Extract initiator UPN
                            initiated_by_upn = ""
                            if a.initiated_by:
                                if a.initiated_by.user:
                                    initiated_by_upn = a.initiated_by.user.user_principal_name or a.initiated_by.user.display_name or ""
                                elif a.initiated_by.app:
                                    initiated_by_upn = f"app:{a.initiated_by.app.display_name or a.initiated_by.app.app_id}"
                            
                            audit = EntraAuditEvent(
                                id=a.id or "",
                                timestamp=a.activity_date_time.replace(tzinfo=timezone.utc) if a.activity_date_time else datetime.now(timezone.utc),
                                activity_display_name=a.activity_display_name or "",
                                category=a.category or "",
                                initiated_by_upn=initiated_by_upn,
                                target_resources=[
                                    t.display_name or t.id or "" 
                                    for t in (a.target_resources or [])
                                ],
                                result=a.result.value if a.result else "success",
                            )
                            audits.append(audit)
                        except Exception as parse_err:
                            log.debug("Failed to parse audit record: %s", parse_err)
                            continue
                
                # Check for next page
                if hasattr(result, 'odata_next_link') and result.odata_next_link:
                    result = await client.audit_logs.directory_audits.with_url(result.odata_next_link).get()
                else:
                    break
                    
            log.info("Fetched %d audit records from Entra ID", len(audits))
            
        except ImportError as ie:
            log.warning("msgraph-sdk not available: %s", ie)
        except Exception as e:
            log.warning("Failed to fetch audits from Graph API: %s", e)
            
        return audits

    async def _get_risk_detections(self, since: datetime) -> List[dict]:
        """
        GET /identityProtection/riskDetections
        Uses msgraph SDK with automatic pagination.
        """
        detections = []
        try:
            enumerator = self._get_enumerator()
            client = enumerator._get_client()
            
            # Format datetime for OData filter
            since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            from msgraph.generated.identity_protection.risk_detections.risk_detections_request_builder import RiskDetectionsRequestBuilder
            from kiota_abstractions.base_request_configuration import RequestConfiguration
            
            query_params = RiskDetectionsRequestBuilder.RiskDetectionsRequestBuilderGetQueryParameters(
                filter=f"detectedDateTime ge {since_str}",
                orderby=["detectedDateTime desc"],
                top=999,
            )
            request_config = RequestConfiguration(query_parameters=query_params)
            
            result = await client.identity_protection.risk_detections.get(request_configuration=request_config)
            
            while result:
                if result.value:
                    for r in result.value:
                        try:
                            detection = {
                                "id": r.id,
                                "detectedDateTime": str(r.detected_date_time) if r.detected_date_time else None,
                                "lastUpdatedDateTime": str(r.last_updated_date_time) if r.last_updated_date_time else None,
                                "userId": r.user_id,
                                "userPrincipalName": r.user_principal_name,
                                "userDisplayName": r.user_display_name,
                                "riskType": r.risk_type,
                                "riskEventType": r.risk_event_type,
                                "riskLevel": r.risk_level.value if r.risk_level else "none",
                                "riskState": r.risk_state.value if r.risk_state else "none",
                                "riskDetail": r.risk_detail.value if r.risk_detail else None,
                                "source": r.source,
                                "detectionTimingType": r.detection_timing_type.value if r.detection_timing_type else None,
                                "activity": r.activity.value if r.activity else None,
                                "ipAddress": r.ip_address,
                                "location": {
                                    "city": r.location.city if r.location else None,
                                    "country": r.location.country_or_region if r.location else None,
                                } if r.location else None,
                            }
                            detections.append(detection)
                        except Exception as parse_err:
                            log.debug("Failed to parse risk detection record: %s", parse_err)
                            continue
                
                # Check for next page
                if hasattr(result, 'odata_next_link') and result.odata_next_link:
                    result = await client.identity_protection.risk_detections.with_url(result.odata_next_link).get()
                else:
                    break
                    
            log.info("Fetched %d risk detection records from Entra ID", len(detections))
            
        except ImportError as ie:
            log.warning("msgraph-sdk not available: %s", ie)
        except Exception as e:
            log.warning("Failed to fetch risk detections from Graph API: %s", e)
            
        return detections
