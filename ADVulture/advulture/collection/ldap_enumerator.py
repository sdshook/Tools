# (c) 2025 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture — LDAP Enumerator
Direct AD enumeration via LDAP3. Replaces SharpHound collection
without external tooling dependency.

Authentication Options:
- prompt:    Prompt for credentials at runtime (default, no stored creds)
- kerberos:  Use current Kerberos ticket (domain-joined machine)
- ntlm:      NTLM authentication with provided credentials
- simple:    Simple LDAP bind with credentials from config
"""

from __future__ import annotations
import logging
import os
import socket
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Any, Dict, Tuple, TYPE_CHECKING
from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES, SASL, NTLM
from ldap3.core.exceptions import LDAPException

if TYPE_CHECKING:
    from advulture.config import LDAPConfig

log = logging.getLogger(__name__)

# Try to import impacket for ACL parsing
try:
    from impacket.ldap import ldaptypes
    from impacket.uuid import bin_to_string
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    log.debug("impacket not available - ACL parsing will be limited")

# Well-known dangerous rights GUIDs
DANGEROUS_RIGHTS = {
    "00000000-0000-0000-0000-000000000000": "GenericAll",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}

# Access mask bits for GenericAll, WriteDacl, WriteOwner, etc.
ADS_RIGHT_GENERIC_ALL = 0x10000000
ADS_RIGHT_WRITE_DACL = 0x00040000
ADS_RIGHT_WRITE_OWNER = 0x00080000
ADS_RIGHT_GENERIC_WRITE = 0x40000000
ADS_RIGHT_DS_WRITE_PROP = 0x00000020
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100


@dataclass
class ADUser:
    sid: str
    sam_account_name: str
    distinguished_name: str
    user_principal_name: str = ""
    admin_count: int = 0
    service_principal_names: List[str] = field(default_factory=list)
    member_of: List[str] = field(default_factory=list)
    user_account_control: int = 0
    password_last_set: Optional[datetime] = None
    last_logon_timestamp: Optional[datetime] = None
    when_created: Optional[datetime] = None
    description: str = ""
    manager: str = ""
    mail: str = ""
    # Computed
    enabled: bool = True
    password_never_expires: bool = False
    no_preauth_required: bool = False   # AS-REP roastable
    has_spn: bool = False               # Kerberoastable
    delegation_type: str = "none"       # unconstrained / constrained / rbcd / none
    constrained_delegation_targets: List[str] = field(default_factory=list)
    password_age_days: float = 0.0
    days_since_last_logon: float = 9999.0
    tier: int = 2
    security_descriptor: Optional[bytes] = None


@dataclass
class ADComputer:
    sid: str
    sam_account_name: str
    distinguished_name: str
    dns_hostname: str = ""
    os: str = ""
    os_version: str = ""
    member_of: List[str] = field(default_factory=list)
    user_account_control: int = 0
    last_logon_timestamp: Optional[datetime] = None
    service_principal_names: List[str] = field(default_factory=list)
    # Security
    unconstrained_delegation: bool = False
    constrained_delegation_targets: List[str] = field(default_factory=list)
    rbcd_principals: List[str] = field(default_factory=list)   # msDS-AllowedToActOnBehalfOfOtherIdentity
    laps_expiry: Optional[datetime] = None  # ms-Mcs-AdmPwdExpirationTime
    enabled: bool = True
    tier: int = 2
    security_descriptor: Optional[bytes] = None


@dataclass
class ADGroup:
    sid: str
    sam_account_name: str
    distinguished_name: str
    members: List[str] = field(default_factory=list)
    member_of: List[str] = field(default_factory=list)
    admin_count: int = 0
    group_type: int = 0
    security_descriptor: Optional[bytes] = None


@dataclass
class ADTrust:
    name: str
    trust_direction: int    # 1=inbound, 2=outbound, 3=bidirectional
    trust_type: int
    trust_attributes: int
    security_identifier: str
    sid_filtering_enabled: bool = True


@dataclass
class ADCertTemplate:
    name: str
    distinguished_name: str
    name_flag: int          # msPKI-Certificate-Name-Flag
    enrollment_flag: int    # msPKI-Enrollment-Flag
    ra_signature: int       # msPKI-RA-Signature
    eku: List[str] = field(default_factory=list)
    security_descriptor: Optional[bytes] = None
    # Computed vulnerability flags
    esc1: bool = False      # SAN allowed + auth EKU + no manager approval
    esc2: bool = False      # Any purpose EKU
    esc4: bool = False      # Write rights to template
    enrollee_supplies_subject: bool = False


@dataclass
class ACLEdge:
    """Represents a dangerous ACL-based edge between AD objects."""
    source_sid: str          # Who has the right
    target_dn: str           # Object the right applies to
    right_type: str          # GenericAll, WriteDacl, DCSync, etc.
    is_inherited: bool = False


@dataclass
class ADSnapshot:
    domain: str
    domain_sid: str
    base_dn: str
    timestamp: datetime
    users: List[ADUser] = field(default_factory=list)
    computers: List[ADComputer] = field(default_factory=list)
    groups: List[ADGroup] = field(default_factory=list)
    trusts: List[ADTrust] = field(default_factory=list)
    cert_templates: List[ADCertTemplate] = field(default_factory=list)
    acl_edges: List[ACLEdge] = field(default_factory=list)  # Dangerous ACL edges
    gpo_links: dict = field(default_factory=dict)
    ou_structure: List[dict] = field(default_factory=list)

    def all_objects(self):
        return self.users + self.computers + self.groups

    @property
    def tier0_users(self) -> List[ADUser]:
        return [u for u in self.users if u.tier == 0]


# UAC flag masks
UAC_ACCOUNTDISABLE        = 0x00000002
UAC_PASSWD_NOTREQD        = 0x00000020
UAC_TRUSTED_FOR_DELEGATION= 0x00080000  # Unconstrained
UAC_NOT_DELEGATED         = 0x00100000
UAC_DONT_REQ_PREAUTH      = 0x00400000  # AS-REP roastable
UAC_PASSWORD_EXPIRED      = 0x00800000
UAC_NO_AUTH_DATA_REQUIRED = 0x02000000

# ADCS ESC1: ENROLLEE_SUPPLIES_SUBJECT
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
# Authentication EKUs
AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2",   # Client Authentication
    "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
    "1.3.6.1.5.2.3.4",     # PKINIT Client Auth
}

# Tier 0 group SIDs (well-known)
TIER0_GROUPS = {
    "S-1-5-32-544",    # BUILTIN\Administrators
    "512",             # Domain Admins (RID suffix)
    "519",             # Enterprise Admins
    "518",             # Schema Admins
    "520",             # Group Policy Creator Owners
}


class LDAPEnumerator:
    """
    Full Active Directory enumeration via LDAP3.
    Collects users, computers, groups, ACLs, trusts, ADCS templates.
    
    Authentication modes:
    - prompt:    Interactive credential prompt (no stored creds)
    - kerberos:  Use current Kerberos ticket (domain-joined machine)
    - ntlm:      NTLM authentication
    - simple:    Simple LDAP bind
    
    For the simplest usage, just instantiate with no arguments and it will
    auto-discover the domain and prompt for credentials.
    """

    USER_ATTRS = [
        "sAMAccountName", "userPrincipalName", "objectSid",
        "distinguishedName", "memberOf", "adminCount",
        "servicePrincipalName", "userAccountControl",
        "pwdLastSet", "lastLogonTimestamp", "whenCreated",
        "description", "manager", "mail",
        "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "nTSecurityDescriptor",
    ]

    COMPUTER_ATTRS = [
        "sAMAccountName", "objectSid", "distinguishedName",
        "dNSHostName", "operatingSystem", "operatingSystemVersion",
        "memberOf", "userAccountControl", "lastLogonTimestamp",
        "servicePrincipalName",
        "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "ms-Mcs-AdmPwdExpirationTime",
        "nTSecurityDescriptor",
    ]

    GROUP_ATTRS = [
        "sAMAccountName", "objectSid", "distinguishedName",
        "member", "memberOf", "adminCount", "groupType",
        "nTSecurityDescriptor",
    ]

    TEMPLATE_ATTRS = [
        "cn", "distinguishedName",
        "msPKI-Certificate-Name-Flag",
        "msPKI-Enrollment-Flag",
        "msPKI-RA-Signature",
        "pKIExtendedKeyUsage",
        "nTSecurityDescriptor",
    ]

    def __init__(
        self,
        server: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        base_dn: Optional[str] = None,
        domain: Optional[str] = None,
        use_ssl: bool = True,
        auth_mode: str = "prompt",
    ):
        """
        Initialize LDAP enumerator with flexible authentication.
        
        For interactive use, all parameters are optional:
        - Domain and DC will be auto-discovered
        - Credentials will be prompted at runtime
        
        Args:
            server: DC hostname/IP (auto-discovered if not provided)
            username: DOMAIN\\user or user@domain (prompted if not provided)
            password: Password (prompted if not provided)
            base_dn: LDAP base DN (derived from domain if not provided)
            domain: Domain name (auto-discovered if not provided)
            use_ssl: Use LDAPS (default True)
            auth_mode: prompt, kerberos, ntlm, or simple
        """
        self.server_uri = server
        self.username = username
        self.password = password
        self.base_dn = base_dn
        self.domain = domain
        self.use_ssl = use_ssl
        self.auth_mode = auth_mode.lower()
        self._conn: Optional[Connection] = None

    @classmethod
    def from_config(cls, config: "LDAPConfig") -> "LDAPEnumerator":
        """Create enumerator from LDAPConfig object."""
        return cls(
            server=config.server or None,
            username=config.username or None,
            password=config.password or None,
            base_dn=config.base_dn or None,
            domain=config.domain or None,
            use_ssl=config.use_ssl,
            auth_mode=config.auth_mode.value if hasattr(config.auth_mode, 'value') else config.auth_mode,
        )

    def _auto_discover_domain(self) -> str:
        """Auto-discover domain from machine's DNS suffix or environment."""
        # Try USERDNSDOMAIN (Windows domain-joined)
        domain = os.environ.get("USERDNSDOMAIN")
        if domain:
            return domain.lower()
        
        # Try machine's FQDN
        try:
            fqdn = socket.getfqdn()
            if "." in fqdn:
                return ".".join(fqdn.split(".")[1:]).lower()
        except Exception:
            pass
        
        return ""

    def _auto_discover_dc(self, domain: str) -> str:
        """Auto-discover domain controller via DNS SRV lookup."""
        import dns.resolver
        try:
            # Query _ldap._tcp.dc._msdcs.DOMAIN
            srv_query = f"_ldap._tcp.dc._msdcs.{domain}"
            answers = dns.resolver.resolve(srv_query, "SRV")
            if answers:
                dc = str(answers[0].target).rstrip(".")
                log.info("Auto-discovered DC: %s", dc)
                return dc
        except Exception as e:
            log.debug("DNS SRV lookup failed: %s", e)
        
        # Fallback: try common DC naming patterns
        for prefix in ["dc1", "dc01", "dc"]:
            try:
                candidate = f"{prefix}.{domain}"
                socket.gethostbyname(candidate)
                log.info("Found DC by name: %s", candidate)
                return candidate
            except socket.gaierror:
                continue
        
        return ""

    def _domain_to_base_dn(self, domain: str) -> str:
        """Convert domain.com to DC=domain,DC=com."""
        parts = domain.lower().split(".")
        return ",".join(f"DC={p}" for p in parts)

    def _prompt_credentials(self):
        """Prompt user for credentials interactively."""
        from rich.console import Console
        from rich.prompt import Prompt
        from rich.panel import Panel
        import getpass
        
        console = Console()
        console.print(Panel.fit(
            "[bold cyan]🔐 Active Directory Authentication[/bold cyan]\n\n"
            f"Domain: [yellow]{self.domain or 'auto-detect'}[/yellow]\n"
            f"Server: [yellow]{self.server_uri or 'auto-detect'}[/yellow]",
            border_style="cyan",
        ))
        
        if not self.username:
            self.username = Prompt.ask(
                "Username",
                default=f"{self.domain}\\administrator" if self.domain else None
            )
        
        if not self.password:
            self.password = getpass.getpass("Password: ")

    def connect(self):
        """Connect to Active Directory with configured authentication."""
        # Auto-discover domain if needed
        if not self.domain:
            self.domain = self._auto_discover_domain()
            if not self.domain:
                raise ValueError(
                    "Could not auto-discover domain. Please specify --domain or "
                    "run from a domain-joined machine."
                )
        
        # Auto-discover DC if needed  
        if not self.server_uri:
            dc = self._auto_discover_dc(self.domain)
            if dc:
                protocol = "ldaps" if self.use_ssl else "ldap"
                self.server_uri = f"{protocol}://{dc}"
            else:
                raise ValueError(
                    f"Could not discover DC for domain {self.domain}. "
                    "Please specify --server."
                )
        
        # Derive base_dn if needed
        if not self.base_dn:
            self.base_dn = self._domain_to_base_dn(self.domain)
        
        # Handle authentication modes
        srv = Server(self.server_uri, get_info=ALL)
        
        if self.auth_mode == "kerberos":
            # Use GSSAPI/Kerberos with current ticket
            log.info("Using Kerberos authentication (current ticket)")
            self._conn = Connection(
                srv,
                authentication=SASL,
                sasl_mechanism="GSSAPI",
                auto_bind=True,
                read_only=True,
            )
            
        elif self.auth_mode == "ntlm":
            # NTLM authentication
            if not self.username or not self.password:
                self._prompt_credentials()
            log.info("Using NTLM authentication as %s", self.username)
            self._conn = Connection(
                srv,
                user=self.username,
                password=self.password,
                authentication=NTLM,
                auto_bind=True,
                read_only=True,
            )
            
        elif self.auth_mode == "prompt":
            # Prompt for credentials if not provided
            if not self.username or not self.password:
                self._prompt_credentials()
            log.info("Using simple bind as %s", self.username)
            self._conn = Connection(
                srv,
                user=self.username,
                password=self.password,
                auto_bind=True,
                read_only=True,
            )
            
        else:  # simple
            # Simple bind with provided credentials
            if not self.username or not self.password:
                raise ValueError("Username and password required for auth_mode='simple'")
            log.info("Using simple bind as %s", self.username)
            self._conn = Connection(
                srv,
                user=self.username,
                password=self.password,
                auto_bind=True,
                read_only=True,
            )
        
        log.info("Connected to %s (base: %s)", self.server_uri, self.base_dn)

    def disconnect(self):
        if self._conn:
            self._conn.unbind()

    def enumerate_all(self) -> ADSnapshot:
        if not self._conn:
            self.connect()

        domain, domain_sid = self._get_domain_info()
        log.info("Enumerating domain: %s", domain)

        snapshot = ADSnapshot(
            domain=domain,
            domain_sid=domain_sid,
            base_dn=self.base_dn,
            timestamp=datetime.now(timezone.utc),
        )

        snapshot.users = self._enumerate_users()
        log.info("Collected %d users", len(snapshot.users))

        snapshot.computers = self._enumerate_computers()
        log.info("Collected %d computers", len(snapshot.computers))

        snapshot.groups = self._enumerate_groups()
        log.info("Collected %d groups", len(snapshot.groups))

        snapshot.trusts = self._enumerate_trusts()
        snapshot.cert_templates = self._enumerate_cert_templates()
        snapshot.ou_structure = self._enumerate_ous()
        
        # Parse ACLs from security descriptors
        snapshot.acl_edges = self._enumerate_acl_edges(snapshot)
        if snapshot.acl_edges:
            log.info("Collected %d dangerous ACL edges", len(snapshot.acl_edges))

        self._compute_tiers(snapshot)
        self._compute_esc_flags(snapshot)

        return snapshot
    
    def _enumerate_acl_edges(self, snapshot: ADSnapshot) -> List[ACLEdge]:
        """Parse security descriptors from all objects to find dangerous ACL edges."""
        if not IMPACKET_AVAILABLE:
            log.debug("impacket not available - skipping ACL parsing")
            return []
        
        all_edges = []
        
        # Parse user ACLs
        for user in snapshot.users:
            if user.security_descriptor:
                edges = self._parse_security_descriptor(
                    user.security_descriptor, user.distinguished_name
                )
                all_edges.extend(edges)
        
        # Parse computer ACLs
        for computer in snapshot.computers:
            if computer.security_descriptor:
                edges = self._parse_security_descriptor(
                    computer.security_descriptor, computer.distinguished_name
                )
                all_edges.extend(edges)
        
        # Parse group ACLs
        for group in snapshot.groups:
            if group.security_descriptor:
                edges = self._parse_security_descriptor(
                    group.security_descriptor, group.distinguished_name
                )
                all_edges.extend(edges)
        
        # Parse domain ACL for DCSync rights
        domain_edges = self._enumerate_domain_acl()
        all_edges.extend(domain_edges)
        
        return all_edges
    
    def _enumerate_domain_acl(self) -> List[ACLEdge]:
        """Enumerate ACL on the domain object to find DCSync rights."""
        edges = []
        try:
            self._conn.search(
                self.base_dn,
                "(objectClass=domain)",
                search_scope=SUBTREE,
                attributes=["nTSecurityDescriptor", "distinguishedName"],
            )
            if self._conn.entries:
                entry = self._conn.entries[0]
                if hasattr(entry, 'nTSecurityDescriptor') and entry.nTSecurityDescriptor:
                    edges = self._parse_security_descriptor(
                        bytes(entry.nTSecurityDescriptor),
                        str(entry.distinguishedName)
                    )
        except Exception as e:
            log.debug("Failed to enumerate domain ACL: %s", e)
        return edges

    def _get_domain_info(self) -> tuple[str, str]:
        self._conn.search(
            self.base_dn, "(objectClass=domain)",
            attributes=["distinguishedName", "objectSid"],
        )
        if self._conn.entries:
            entry = self._conn.entries[0]
            return str(entry.distinguishedName), str(entry.objectSid)
        return self.base_dn, ""

    def _enumerate_users(self) -> List[ADUser]:
        users = []
        self._conn.search(
            self.base_dn,
            "(&(objectCategory=person)(objectClass=user))",
            search_scope=SUBTREE,
            attributes=self.USER_ATTRS,
            paged_size=1000,
        )
        now = datetime.now(timezone.utc)
        for entry in self._conn.entries:
            uac = int(entry.userAccountControl.value or 0)
            pwd_last_set = self._to_datetime(entry.pwdLastSet)
            last_logon = self._to_datetime(entry.lastLogonTimestamp)
            spns = list(entry.servicePrincipalName) if entry.servicePrincipalName else []
            delegation_targets = list(entry["msDS-AllowedToDelegateTo"]) \
                if entry["msDS-AllowedToDelegateTo"] else []
            deleg_type = "none"
            if uac & UAC_TRUSTED_FOR_DELEGATION:
                deleg_type = "unconstrained"
            elif delegation_targets:
                deleg_type = "constrained"

            u = ADUser(
                sid=str(entry.objectSid),
                sam_account_name=str(entry.sAMAccountName),
                distinguished_name=str(entry.distinguishedName),
                user_principal_name=str(entry.userPrincipalName or ""),
                admin_count=int(entry.adminCount.value or 0),
                service_principal_names=spns,
                member_of=[str(m) for m in (entry.memberOf or [])],
                user_account_control=uac,
                password_last_set=pwd_last_set,
                last_logon_timestamp=last_logon,
                enabled=not bool(uac & UAC_ACCOUNTDISABLE),
                password_never_expires=bool(uac & 0x10000),
                no_preauth_required=bool(uac & UAC_DONT_REQ_PREAUTH),
                has_spn=bool(spns),
                delegation_type=deleg_type,
                constrained_delegation_targets=delegation_targets,
                password_age_days=(
                    (now - pwd_last_set).days if pwd_last_set else 9999
                ),
                days_since_last_logon=(
                    (now - last_logon).days if last_logon else 9999
                ),
                security_descriptor=bytes(entry.nTSecurityDescriptor)
                    if entry.nTSecurityDescriptor else None,
            )
            users.append(u)
        return users

    def _enumerate_computers(self) -> List[ADComputer]:
        computers = []
        self._conn.search(
            self.base_dn,
            "(objectClass=computer)",
            search_scope=SUBTREE,
            attributes=self.COMPUTER_ATTRS,
            paged_size=1000,
        )
        for entry in self._conn.entries:
            uac = int(entry.userAccountControl.value or 0)
            deleg_targets = list(entry["msDS-AllowedToDelegateTo"]) \
                if entry["msDS-AllowedToDelegateTo"] else []
            rbcd_raw = entry["msDS-AllowedToActOnBehalfOfOtherIdentity"]
            rbcd_principals = self._parse_rbcd(rbcd_raw) if rbcd_raw else []

            computers.append(ADComputer(
                sid=str(entry.objectSid),
                sam_account_name=str(entry.sAMAccountName),
                distinguished_name=str(entry.distinguishedName),
                dns_hostname=str(entry.dNSHostName or ""),
                os=str(entry.operatingSystem or ""),
                os_version=str(entry.operatingSystemVersion or ""),
                member_of=[str(m) for m in (entry.memberOf or [])],
                user_account_control=uac,
                last_logon_timestamp=self._to_datetime(entry.lastLogonTimestamp),
                service_principal_names=list(entry.servicePrincipalName or []),
                unconstrained_delegation=bool(uac & UAC_TRUSTED_FOR_DELEGATION),
                constrained_delegation_targets=deleg_targets,
                rbcd_principals=rbcd_principals,
                laps_expiry=self._to_datetime(entry["ms-Mcs-AdmPwdExpirationTime"]),
                enabled=not bool(uac & UAC_ACCOUNTDISABLE),
                security_descriptor=bytes(entry.nTSecurityDescriptor)
                    if entry.nTSecurityDescriptor else None,
            ))
        return computers

    def _enumerate_groups(self) -> List[ADGroup]:
        groups = []
        self._conn.search(
            self.base_dn,
            "(objectClass=group)",
            search_scope=SUBTREE,
            attributes=self.GROUP_ATTRS,
            paged_size=1000,
        )
        for entry in self._conn.entries:
            groups.append(ADGroup(
                sid=str(entry.objectSid),
                sam_account_name=str(entry.sAMAccountName),
                distinguished_name=str(entry.distinguishedName),
                members=[str(m) for m in (entry.member or [])],
                member_of=[str(m) for m in (entry.memberOf or [])],
                admin_count=int(entry.adminCount.value or 0),
                group_type=int(entry.groupType.value or 0),
                security_descriptor=bytes(entry.nTSecurityDescriptor)
                    if entry.nTSecurityDescriptor else None,
            ))
        return groups

    def _enumerate_trusts(self) -> List[ADTrust]:
        trusts = []
        self._conn.search(
            self.base_dn,
            "(objectClass=trustedDomain)",
            search_scope=SUBTREE,
            attributes=["cn", "trustDirection", "trustType",
                        "trustAttributes", "securityIdentifier", "flatName"],
        )
        for entry in self._conn.entries:
            attrs = int(entry.trustAttributes.value or 0)
            # Bit 0x4 = QUARANTINED (SID filtering ON)
            # If not set, SID filtering OFF = risk
            sid_filtering = bool(attrs & 0x4)
            trusts.append(ADTrust(
                name=str(entry.cn),
                trust_direction=int(entry.trustDirection.value or 0),
                trust_type=int(entry.trustType.value or 0),
                trust_attributes=attrs,
                security_identifier=str(entry.securityIdentifier or ""),
                sid_filtering_enabled=sid_filtering,
            ))
        return trusts

    def _enumerate_cert_templates(self) -> List[ADCertTemplate]:
        templates = []
        pki_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.base_dn}"
        try:
            self._conn.search(
                pki_base,
                "(objectClass=pKICertificateTemplate)",
                search_scope=SUBTREE,
                attributes=self.TEMPLATE_ATTRS,
            )
            for entry in self._conn.entries:
                name_flag = int(entry["msPKI-Certificate-Name-Flag"].value or 0)
                enroll_flag = int(entry["msPKI-Enrollment-Flag"].value or 0)
                ra_sig = int(entry["msPKI-RA-Signature"].value or 0)
                eku = list(entry.pKIExtendedKeyUsage or [])
                templates.append(ADCertTemplate(
                    name=str(entry.cn),
                    distinguished_name=str(entry.distinguishedName),
                    name_flag=name_flag,
                    enrollment_flag=enroll_flag,
                    ra_signature=ra_sig,
                    eku=eku,
                    enrollee_supplies_subject=bool(
                        name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                    ),
                    security_descriptor=bytes(entry.nTSecurityDescriptor)
                        if entry.nTSecurityDescriptor else None,
                ))
        except LDAPException as e:
            log.warning("Could not enumerate ADCS templates: %s", e)
        return templates

    def _enumerate_ous(self) -> List[dict]:
        ous = []
        self._conn.search(
            self.base_dn,
            "(objectClass=organizationalUnit)",
            search_scope=SUBTREE,
            attributes=["distinguishedName", "gpLink", "gPOptions"],
        )
        for entry in self._conn.entries:
            ous.append({
                "dn": str(entry.distinguishedName),
                "gp_link": str(entry.gpLink or ""),
            })
        return ous

    def _compute_tiers(self, snapshot: ADSnapshot):
        """Classify objects into Tier 0 / 1 / 2 based on group membership."""
        tier0_dns = set()
        for group in snapshot.groups:
            # Check well-known Tier 0 group RIDs
            sid_parts = group.sid.split("-")
            if sid_parts and sid_parts[-1] in {"512", "519", "518", "520", "516", "517"}:
                tier0_dns.add(group.distinguished_name)
                for member_dn in group.members:
                    tier0_dns.add(member_dn)

        for user in snapshot.users:
            if user.distinguished_name in tier0_dns or user.admin_count == 1:
                user.tier = 0
            elif any("admins" in mo.lower() for mo in user.member_of):
                user.tier = 1

        for computer in snapshot.computers:
            if "domain controller" in computer.os.lower():
                computer.tier = 0

    def _compute_esc_flags(self, snapshot: ADSnapshot):
        """Flag ADCS template vulnerabilities."""
        for tmpl in snapshot.cert_templates:
            has_auth_eku = bool(set(tmpl.eku) & AUTH_EKUS) or not tmpl.eku
            # ESC1: SAN + auth EKU + no manager approval + no RA signature
            tmpl.esc1 = (
                tmpl.enrollee_supplies_subject
                and has_auth_eku
                and not (tmpl.enrollment_flag & 0x2)  # no manager approval
                and tmpl.ra_signature == 0
            )
            # ESC2: Any purpose EKU or no EKU (unrestricted)
            tmpl.esc2 = (
                "2.5.29.37.0" in tmpl.eku  # anyExtendedKeyUsage
                or (not tmpl.eku and not tmpl.enrollee_supplies_subject)
            )

    @staticmethod
    def _to_datetime(value: Any) -> Optional[datetime]:
        if not value:
            return None
        try:
            val = value.value if hasattr(value, "value") else value
            if isinstance(val, datetime):
                return val.replace(tzinfo=None)
            if isinstance(val, (int, float)):
                # Windows FILETIME
                if val == 0 or val == 9223372036854775807:
                    return None
                epoch = datetime(1601, 1, 1)
                return epoch + __import__("datetime").timedelta(microseconds=val // 10)
        except Exception:
            return None
        return None

    @staticmethod
    def _parse_rbcd(raw_value: Any) -> List[str]:
        """Parse msDS-AllowedToActOnBehalfOfOtherIdentity to principal SIDs.
        
        This attribute contains a security descriptor with ACEs that specify
        which principals can delegate to this computer.
        """
        if not raw_value or not IMPACKET_AVAILABLE:
            return []
        
        try:
            # Convert to bytes if needed
            if isinstance(raw_value, str):
                raw_bytes = raw_value.encode('latin-1')
            elif isinstance(raw_value, (bytes, bytearray)):
                raw_bytes = bytes(raw_value)
            else:
                return []
            
            # Parse the security descriptor
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_bytes)
            
            principal_sids = []
            if sd['Dacl']:
                for ace in sd['Dacl']['Data']:
                    # Get the SID from the ACE
                    if hasattr(ace['Ace'], 'fields') and 'Sid' in ace['Ace'].fields:
                        sid = ace['Ace']['Sid']
                        sid_str = sid.formatCanonical()
                        principal_sids.append(sid_str)
            
            return principal_sids
        except Exception as e:
            log.debug("Failed to parse RBCD attribute: %s", e)
            return []
    
    @staticmethod
    def _parse_security_descriptor(raw_value: Any, target_dn: str) -> List[ACLEdge]:
        """Parse nTSecurityDescriptor to extract dangerous ACL edges.
        
        Looks for:
        - GenericAll rights
        - WriteDacl rights  
        - WriteOwner rights
        - DCSync rights (DS-Replication-Get-Changes + DS-Replication-Get-Changes-All)
        - Write property rights
        """
        if not raw_value or not IMPACKET_AVAILABLE:
            return []
        
        edges = []
        try:
            # Convert to bytes if needed
            if isinstance(raw_value, str):
                raw_bytes = raw_value.encode('latin-1')
            elif isinstance(raw_value, (bytes, bytearray)):
                raw_bytes = bytes(raw_value)
            else:
                return []
            
            # Parse the security descriptor
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_bytes)
            
            if not sd['Dacl']:
                return []
            
            for ace in sd['Dacl']['Data']:
                # Skip deny ACEs for now (focus on allow)
                ace_type = ace['TypeName']
                if 'DENIED' in ace_type:
                    continue
                
                try:
                    sid = ace['Ace']['Sid'].formatCanonical()
                    mask = ace['Ace']['Mask']['Mask']
                    is_inherited = bool(ace['AceFlags'] & 0x10)  # INHERITED_ACE
                    
                    # Check for dangerous rights
                    if mask & ADS_RIGHT_GENERIC_ALL:
                        edges.append(ACLEdge(
                            source_sid=sid,
                            target_dn=target_dn,
                            right_type="GenericAll",
                            is_inherited=is_inherited,
                        ))
                    elif mask & ADS_RIGHT_WRITE_DACL:
                        edges.append(ACLEdge(
                            source_sid=sid,
                            target_dn=target_dn,
                            right_type="WriteDacl",
                            is_inherited=is_inherited,
                        ))
                    elif mask & ADS_RIGHT_WRITE_OWNER:
                        edges.append(ACLEdge(
                            source_sid=sid,
                            target_dn=target_dn,
                            right_type="WriteOwner",
                            is_inherited=is_inherited,
                        ))
                    
                    # Check for extended rights (like DCSync)
                    if mask & ADS_RIGHT_DS_CONTROL_ACCESS:
                        if 'ObjectType' in ace['Ace'].fields:
                            obj_type = ace['Ace']['ObjectType']
                            if obj_type:
                                guid_str = bin_to_string(bytes(obj_type)).lower()
                                if guid_str in DANGEROUS_RIGHTS:
                                    edges.append(ACLEdge(
                                        source_sid=sid,
                                        target_dn=target_dn,
                                        right_type=DANGEROUS_RIGHTS[guid_str],
                                        is_inherited=is_inherited,
                                    ))
                except Exception as ace_err:
                    log.debug("Failed to parse ACE: %s", ace_err)
                    continue
            
            return edges
        except Exception as e:
            log.debug("Failed to parse security descriptor for %s: %s", target_dn, e)
            return []
