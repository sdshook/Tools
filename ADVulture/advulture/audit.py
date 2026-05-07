# (c) 2025 Shane D. Shook, PhD - All Rights Reserved
"""
ADVulture Offline Audit Module

Analyzes offline Active Directory artifacts:
- NTDS.dit (AD database)
- SYSTEM registry hive (contains boot key for NTDS decryption)
- DC Security/System event logs (EVTX files)

This module enables forensic analysis of AD environments without live
network access, using extracted artifacts from domain controllers.
"""

from __future__ import annotations
import logging
import hashlib
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple, Iterator
from enum import Enum
import json

log = logging.getLogger(__name__)


class AuditError(Exception):
    """Base exception for audit module errors."""
    pass


class NTDSParseError(AuditError):
    """Error parsing NTDS.dit database."""
    pass


class RegistryParseError(AuditError):
    """Error parsing SYSTEM registry hive."""
    pass


@dataclass
class OfflineUser:
    """User account extracted from NTDS.dit."""
    sam_account_name: str
    distinguished_name: str
    sid: str
    user_account_control: int
    pwd_last_set: Optional[datetime] = None
    last_logon: Optional[datetime] = None
    bad_pwd_count: int = 0
    logon_count: int = 0
    member_of: List[str] = field(default_factory=list)
    service_principal_names: List[str] = field(default_factory=list)
    admin_count: int = 0
    description: str = ""
    nt_hash: Optional[str] = None  # If extracted
    lm_hash: Optional[str] = None  # If extracted
    
    @property
    def enabled(self) -> bool:
        return not bool(self.user_account_control & 0x0002)
    
    @property
    def password_never_expires(self) -> bool:
        return bool(self.user_account_control & 0x10000)
    
    @property
    def dont_require_preauth(self) -> bool:
        return bool(self.user_account_control & 0x400000)
    
    @property
    def trusted_for_delegation(self) -> bool:
        return bool(self.user_account_control & 0x80000)
    
    @property
    def password_not_required(self) -> bool:
        return bool(self.user_account_control & 0x0020)
    
    @property
    def is_kerberoastable(self) -> bool:
        return len(self.service_principal_names) > 0 and self.enabled
    
    @property
    def is_asrep_roastable(self) -> bool:
        return self.dont_require_preauth and self.enabled
    
    @property
    def password_age_days(self) -> Optional[int]:
        if self.pwd_last_set:
            return (datetime.now(timezone.utc) - self.pwd_last_set).days
        return None


@dataclass
class OfflineComputer:
    """Computer account extracted from NTDS.dit."""
    sam_account_name: str
    distinguished_name: str
    sid: str
    user_account_control: int
    operating_system: str = ""
    operating_system_version: str = ""
    dns_hostname: str = ""
    last_logon: Optional[datetime] = None
    pwd_last_set: Optional[datetime] = None
    member_of: List[str] = field(default_factory=list)
    ms_ds_allowed_to_delegate_to: List[str] = field(default_factory=list)
    ms_ds_allowed_to_act_on_behalf: List[str] = field(default_factory=list)
    
    @property
    def trusted_for_delegation(self) -> bool:
        return bool(self.user_account_control & 0x80000)
    
    @property
    def trusted_to_auth_for_delegation(self) -> bool:
        return bool(self.user_account_control & 0x1000000)
    
    @property
    def is_domain_controller(self) -> bool:
        return bool(self.user_account_control & 0x2000)


@dataclass
class OfflineGroup:
    """Group extracted from NTDS.dit."""
    sam_account_name: str
    distinguished_name: str
    sid: str
    members: List[str] = field(default_factory=list)
    member_of: List[str] = field(default_factory=list)
    admin_count: int = 0
    description: str = ""
    
    @property
    def is_privileged(self) -> bool:
        priv_sids = [
            "-512",   # Domain Admins
            "-519",   # Enterprise Admins
            "-518",   # Schema Admins
            "-516",   # Domain Controllers
            "-498",   # Enterprise Domain Controllers
            "-500",   # Administrator
        ]
        return any(self.sid.endswith(s) for s in priv_sids) or self.admin_count == 1


@dataclass
class OfflineTrust:
    """Domain trust extracted from NTDS.dit."""
    name: str
    partner_name: str
    direction: str  # Inbound, Outbound, Bidirectional
    trust_type: str  # Forest, External, etc.
    trust_attributes: int
    sid_filtering_enabled: bool = True
    
    @property
    def is_forest_trust(self) -> bool:
        return self.trust_type.lower() == "forest"


@dataclass 
class OfflineSnapshot:
    """Complete offline AD snapshot from NTDS.dit."""
    domain: str
    domain_sid: str
    forest_name: str
    functional_level: str
    timestamp: datetime
    ntds_path: str
    system_hive_path: Optional[str] = None
    
    users: List[OfflineUser] = field(default_factory=list)
    computers: List[OfflineComputer] = field(default_factory=list)
    groups: List[OfflineGroup] = field(default_factory=list)
    trusts: List[OfflineTrust] = field(default_factory=list)
    
    # Extracted hashes (if decryption succeeded)
    hash_extraction_succeeded: bool = False
    hash_count: int = 0
    
    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "domain_sid": self.domain_sid,
            "forest_name": self.forest_name,
            "functional_level": self.functional_level,
            "timestamp": self.timestamp.isoformat(),
            "user_count": len(self.users),
            "computer_count": len(self.computers),
            "group_count": len(self.groups),
            "trust_count": len(self.trusts),
            "hash_extraction_succeeded": self.hash_extraction_succeeded,
        }


@dataclass
class AuditFinding:
    """Security finding from offline audit."""
    category: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    affected_objects: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "affected_objects": self.affected_objects[:20],  # Limit for readability
            "affected_count": len(self.affected_objects),
            "evidence": self.evidence,
            "recommendations": self.recommendations,
            "mitre_techniques": self.mitre_techniques,
        }


@dataclass
class AuditReport:
    """Complete offline audit report."""
    timestamp: datetime
    snapshot: OfflineSnapshot
    findings: List[AuditFinding] = field(default_factory=list)
    evtx_files_analyzed: List[str] = field(default_factory=list)
    event_count: int = 0
    
    # Summary statistics
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    def compute_counts(self):
        self.critical_count = sum(1 for f in self.findings if f.severity == "CRITICAL")
        self.high_count = sum(1 for f in self.findings if f.severity == "HIGH")
        self.medium_count = sum(1 for f in self.findings if f.severity == "MEDIUM")
        self.low_count = sum(1 for f in self.findings if f.severity == "LOW")
    
    def to_dict(self) -> dict:
        self.compute_counts()
        return {
            "timestamp": self.timestamp.isoformat(),
            "snapshot": self.snapshot.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "evtx_files_analyzed": self.evtx_files_analyzed,
            "event_count": self.event_count,
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": len(self.findings),
            },
        }
    
    def summary(self) -> str:
        self.compute_counts()
        return (
            f"ADVulture Offline Audit Report\n"
            f"{'=' * 60}\n"
            f"Domain: {self.snapshot.domain}\n"
            f"Users: {len(self.snapshot.users)}  |  "
            f"Computers: {len(self.snapshot.computers)}  |  "
            f"Groups: {len(self.snapshot.groups)}\n"
            f"Findings: CRITICAL={self.critical_count}  HIGH={self.high_count}  "
            f"MEDIUM={self.medium_count}  LOW={self.low_count}\n"
            f"Events analyzed: {self.event_count}\n"
        )


class NTDSParser:
    """
    Parser for NTDS.dit Active Directory database.
    
    Uses impacket's secretsdump functionality when available,
    falls back to ESE database parsing for metadata extraction.
    """
    
    def __init__(self, ntds_path: Path, system_hive_path: Optional[Path] = None):
        self.ntds_path = Path(ntds_path)
        self.system_hive_path = Path(system_hive_path) if system_hive_path else None
        
        if not self.ntds_path.exists():
            raise NTDSParseError(f"NTDS.dit not found: {self.ntds_path}")
        
        self._bootkey: Optional[bytes] = None
        self._ese_db = None
    
    def parse(self, extract_hashes: bool = False) -> OfflineSnapshot:
        """
        Parse NTDS.dit and extract AD objects.
        
        Args:
            extract_hashes: If True and SYSTEM hive provided, attempt hash extraction
            
        Returns:
            OfflineSnapshot with all extracted objects
        """
        log.info("Parsing NTDS.dit: %s", self.ntds_path)
        
        # Try impacket first (most complete)
        try:
            return self._parse_with_impacket(extract_hashes)
        except ImportError:
            log.warning("impacket not available, using fallback parser")
        except Exception as e:
            log.warning("impacket parsing failed: %s, using fallback", e)
        
        # Try dissect.esedb
        try:
            return self._parse_with_dissect()
        except ImportError:
            log.warning("dissect.esedb not available, using basic parser")
        except Exception as e:
            log.warning("dissect parsing failed: %s", e)
        
        # Basic fallback: just validate file and return empty snapshot
        return self._parse_basic()
    
    def _parse_with_impacket(self, extract_hashes: bool) -> OfflineSnapshot:
        """Parse using impacket's secretsdump."""
        from impacket.examples.secretsdump import LocalOperations, NTDSHashes
        from impacket.examples.secretsdump import SAMHashes
        
        snapshot = OfflineSnapshot(
            domain="",
            domain_sid="",
            forest_name="",
            functional_level="",
            timestamp=datetime.now(timezone.utc),
            ntds_path=str(self.ntds_path),
            system_hive_path=str(self.system_hive_path) if self.system_hive_path else None,
        )
        
        # Extract bootkey from SYSTEM hive
        if self.system_hive_path and extract_hashes:
            local_ops = LocalOperations(str(self.system_hive_path))
            self._bootkey = local_ops.getBootKey()
            log.info("Extracted bootkey from SYSTEM hive")
        
        # Parse NTDS.dit
        ntds = NTDSHashes(
            str(self.ntds_path),
            self._bootkey,
            isRemote=False,
            history=False,
            noLMHash=True,
            useVSSMethod=False,
        )
        
        # Extract domain info
        snapshot.domain = ntds.getDomainName() or "unknown"
        snapshot.domain_sid = ntds.getDomainSid() or ""
        
        # Enumerate objects
        users, computers, groups = [], [], []
        
        def user_callback(user_data):
            try:
                user = self._parse_ntds_user(user_data)
                if user:
                    users.append(user)
            except Exception as e:
                log.debug("Error parsing user: %s", e)
        
        ntds.dump(callback=user_callback)
        
        snapshot.users = users
        snapshot.hash_extraction_succeeded = extract_hashes and self._bootkey is not None
        snapshot.hash_count = len([u for u in users if u.nt_hash])
        
        return snapshot
    
    def _parse_ntds_user(self, user_data: dict) -> Optional[OfflineUser]:
        """Convert impacket user data to OfflineUser."""
        sam_name = user_data.get("sAMAccountName", "")
        if not sam_name:
            return None
        
        return OfflineUser(
            sam_account_name=sam_name,
            distinguished_name=user_data.get("distinguishedName", ""),
            sid=user_data.get("objectSid", ""),
            user_account_control=user_data.get("userAccountControl", 0),
            pwd_last_set=user_data.get("pwdLastSet"),
            last_logon=user_data.get("lastLogon"),
            bad_pwd_count=user_data.get("badPwdCount", 0),
            logon_count=user_data.get("logonCount", 0),
            member_of=user_data.get("memberOf", []),
            service_principal_names=user_data.get("servicePrincipalName", []),
            admin_count=user_data.get("adminCount", 0),
            description=user_data.get("description", ""),
            nt_hash=user_data.get("ntHash"),
            lm_hash=user_data.get("lmHash"),
        )
    
    def _parse_with_dissect(self) -> OfflineSnapshot:
        """Parse using dissect.esedb for ESE database access."""
        from dissect.esedb import EseDB
        
        snapshot = OfflineSnapshot(
            domain="",
            domain_sid="",
            forest_name="",
            functional_level="",
            timestamp=datetime.now(timezone.utc),
            ntds_path=str(self.ntds_path),
        )
        
        with open(self.ntds_path, "rb") as f:
            db = EseDB(f)
            
            # Get datatable
            if "datatable" not in db.tables():
                raise NTDSParseError("datatable not found in NTDS.dit")
            
            datatable = db.table("datatable")
            
            users, computers, groups = [], [], []
            
            for record in datatable.records():
                obj_class = record.get("objectClass")
                
                if obj_class == "user":
                    user = self._record_to_user(record)
                    if user:
                        users.append(user)
                elif obj_class == "computer":
                    computer = self._record_to_computer(record)
                    if computer:
                        computers.append(computer)
                elif obj_class == "group":
                    group = self._record_to_group(record)
                    if group:
                        groups.append(group)
            
            snapshot.users = users
            snapshot.computers = computers
            snapshot.groups = groups
        
        return snapshot
    
    def _record_to_user(self, record) -> Optional[OfflineUser]:
        """Convert ESE record to OfflineUser."""
        sam_name = record.get("sAMAccountName")
        if not sam_name:
            return None
        
        return OfflineUser(
            sam_account_name=str(sam_name),
            distinguished_name=str(record.get("distinguishedName", "")),
            sid=str(record.get("objectSid", "")),
            user_account_control=int(record.get("userAccountControl", 0)),
            admin_count=int(record.get("adminCount", 0)),
            description=str(record.get("description", "")),
        )
    
    def _record_to_computer(self, record) -> Optional[OfflineComputer]:
        """Convert ESE record to OfflineComputer."""
        sam_name = record.get("sAMAccountName")
        if not sam_name:
            return None
        
        return OfflineComputer(
            sam_account_name=str(sam_name),
            distinguished_name=str(record.get("distinguishedName", "")),
            sid=str(record.get("objectSid", "")),
            user_account_control=int(record.get("userAccountControl", 0)),
            operating_system=str(record.get("operatingSystem", "")),
            dns_hostname=str(record.get("dNSHostName", "")),
        )
    
    def _record_to_group(self, record) -> Optional[OfflineGroup]:
        """Convert ESE record to OfflineGroup."""
        sam_name = record.get("sAMAccountName")
        if not sam_name:
            return None
        
        return OfflineGroup(
            sam_account_name=str(sam_name),
            distinguished_name=str(record.get("distinguishedName", "")),
            sid=str(record.get("objectSid", "")),
            admin_count=int(record.get("adminCount", 0)),
            description=str(record.get("description", "")),
        )
    
    def _parse_basic(self) -> OfflineSnapshot:
        """Basic parsing: validate file structure, extract minimal metadata."""
        log.info("Using basic NTDS.dit validation")
        
        # Check ESE database signature
        with open(self.ntds_path, "rb") as f:
            header = f.read(4)
            if header != b"\xef\xcd\xab\x89":
                raise NTDSParseError("Invalid NTDS.dit file: bad ESE signature")
        
        # File size sanity check
        file_size = self.ntds_path.stat().st_size
        if file_size < 1024 * 1024:  # Less than 1MB is suspicious
            log.warning("NTDS.dit file unusually small: %d bytes", file_size)
        
        return OfflineSnapshot(
            domain="unknown",
            domain_sid="",
            forest_name="",
            functional_level="",
            timestamp=datetime.now(timezone.utc),
            ntds_path=str(self.ntds_path),
        )


class OfflineAuditor:
    """
    Main auditor class for offline AD artifact analysis.
    
    Analyzes:
    - NTDS.dit for user/group/computer configuration
    - SYSTEM hive for bootkey extraction
    - EVTX logs for authentication/authorization events
    """
    
    def __init__(
        self,
        ntds_path: Optional[Path] = None,
        system_hive_path: Optional[Path] = None,
        evtx_paths: Optional[List[Path]] = None,
        extract_hashes: bool = False,
    ):
        self.ntds_path = Path(ntds_path) if ntds_path else None
        self.system_hive_path = Path(system_hive_path) if system_hive_path else None
        self.evtx_paths = [Path(p) for p in (evtx_paths or [])]
        self.extract_hashes = extract_hashes
        
        self.snapshot: Optional[OfflineSnapshot] = None
        self.events: List[Dict] = []
    
    def audit(self) -> AuditReport:
        """
        Run complete offline audit.
        
        Returns:
            AuditReport with all findings
        """
        log.info("Starting offline AD audit")
        
        # Parse NTDS.dit if provided
        if self.ntds_path:
            parser = NTDSParser(self.ntds_path, self.system_hive_path)
            self.snapshot = parser.parse(extract_hashes=self.extract_hashes)
            log.info(
                "Parsed NTDS.dit: %d users, %d computers, %d groups",
                len(self.snapshot.users),
                len(self.snapshot.computers),
                len(self.snapshot.groups),
            )
        else:
            self.snapshot = OfflineSnapshot(
                domain="unknown",
                domain_sid="",
                forest_name="",
                functional_level="",
                timestamp=datetime.now(timezone.utc),
                ntds_path="",
            )
        
        # Parse EVTX logs
        if self.evtx_paths:
            self.events = self._parse_evtx_logs()
            log.info("Parsed %d events from %d EVTX files", 
                     len(self.events), len(self.evtx_paths))
        
        # Generate findings
        findings: List[AuditFinding] = []
        
        if self.snapshot.users:
            findings.extend(self._audit_kerberoastable())
            findings.extend(self._audit_asrep_roastable())
            findings.extend(self._audit_password_policy())
            findings.extend(self._audit_privileged_accounts())
            findings.extend(self._audit_delegation())
            findings.extend(self._audit_stale_accounts())
        
        if self.snapshot.computers:
            findings.extend(self._audit_unconstrained_delegation())
            findings.extend(self._audit_rbcd())
            findings.extend(self._audit_legacy_os())
        
        if self.snapshot.groups:
            findings.extend(self._audit_privileged_groups())
        
        if self.snapshot.trusts:
            findings.extend(self._audit_trusts())
        
        if self.events:
            findings.extend(self._audit_authentication_events())
            findings.extend(self._audit_privilege_use())
            findings.extend(self._audit_account_management())
        
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda f: severity_order.get(f.severity, 5))
        
        report = AuditReport(
            timestamp=datetime.now(timezone.utc),
            snapshot=self.snapshot,
            findings=findings,
            evtx_files_analyzed=[str(p) for p in self.evtx_paths],
            event_count=len(self.events),
        )
        
        log.info("Audit complete: %d findings", len(findings))
        return report
    
    def _parse_evtx_logs(self) -> List[Dict]:
        """Parse EVTX log files."""
        events = []
        
        try:
            from evtx import PyEvtxParser
            
            for evtx_path in self.evtx_paths:
                if not evtx_path.exists():
                    log.warning("EVTX file not found: %s", evtx_path)
                    continue
                
                try:
                    parser = PyEvtxParser(str(evtx_path))
                    for record in parser.records_json():
                        try:
                            event = json.loads(record["data"])
                            events.append(event)
                        except json.JSONDecodeError:
                            continue
                except Exception as e:
                    log.warning("Error parsing %s: %s", evtx_path, e)
        
        except ImportError:
            log.warning("evtx library not available, skipping EVTX parsing")
        
        return events
    
    # ── Audit Methods ──────────────────────────────────────────────────────────
    
    def _audit_kerberoastable(self) -> List[AuditFinding]:
        """Find Kerberoastable accounts."""
        findings = []
        
        kerberoastable = [u for u in self.snapshot.users if u.is_kerberoastable]
        
        if kerberoastable:
            # Separate by privilege level
            privileged = [u for u in kerberoastable if u.admin_count == 1]
            regular = [u for u in kerberoastable if u.admin_count == 0]
            
            if privileged:
                findings.append(AuditFinding(
                    category="kerberoast_privileged",
                    title=f"Privileged Kerberoastable Accounts: {len(privileged)}",
                    severity="CRITICAL",
                    description=(
                        "Service accounts with SPNs and adminCount=1 are Kerberoastable "
                        "and have direct or indirect administrative privileges. An attacker "
                        "can request service tickets offline and crack the password."
                    ),
                    affected_objects=[u.sam_account_name for u in privileged],
                    evidence={
                        "total_count": len(privileged),
                        "accounts": [
                            {
                                "name": u.sam_account_name,
                                "spns": u.service_principal_names[:5],
                                "password_age_days": u.password_age_days,
                            }
                            for u in privileged[:10]
                        ],
                    },
                    recommendations=[
                        "Convert to Group Managed Service Accounts (gMSA) where possible",
                        "Implement 25+ character passwords on remaining service accounts",
                        "Enable AES encryption only (disable RC4)",
                        "Remove unnecessary SPNs",
                        "Rotate passwords immediately for affected accounts",
                    ],
                    mitre_techniques=["T1558.003"],
                ))
            
            if regular:
                findings.append(AuditFinding(
                    category="kerberoast_standard",
                    title=f"Kerberoastable Service Accounts: {len(regular)}",
                    severity="HIGH",
                    description=(
                        "Service accounts with SPNs are vulnerable to Kerberoasting. "
                        "While these accounts lack adminCount=1, they may still provide "
                        "lateral movement paths or access to sensitive systems."
                    ),
                    affected_objects=[u.sam_account_name for u in regular],
                    evidence={
                        "total_count": len(regular),
                        "stale_passwords": len([
                            u for u in regular 
                            if u.password_age_days and u.password_age_days > 365
                        ]),
                    },
                    recommendations=[
                        "Audit downstream access for each service account",
                        "Convert to gMSA where possible",
                        "Implement strong password policy for service accounts",
                        "Enable AES encryption, disable RC4",
                    ],
                    mitre_techniques=["T1558.003"],
                ))
        
        return findings
    
    def _audit_asrep_roastable(self) -> List[AuditFinding]:
        """Find AS-REP Roastable accounts."""
        findings = []
        
        asrep = [u for u in self.snapshot.users if u.is_asrep_roastable]
        
        if asrep:
            findings.append(AuditFinding(
                category="asrep_roast",
                title=f"AS-REP Roastable Accounts: {len(asrep)}",
                severity="HIGH",
                description=(
                    "Accounts with 'Do not require Kerberos preauthentication' enabled "
                    "allow unauthenticated retrieval of encrypted AS-REP data that can "
                    "be cracked offline to recover the password."
                ),
                affected_objects=[u.sam_account_name for u in asrep],
                evidence={
                    "total_count": len(asrep),
                    "privileged_count": len([u for u in asrep if u.admin_count == 1]),
                },
                recommendations=[
                    "Disable 'Do not require Kerberos preauthentication' flag",
                    "Reset passwords for affected accounts",
                    "Investigate why preauth was disabled",
                ],
                mitre_techniques=["T1558.004"],
            ))
        
        return findings
    
    def _audit_password_policy(self) -> List[AuditFinding]:
        """Audit password policy violations."""
        findings = []
        
        # Password never expires
        never_expires = [
            u for u in self.snapshot.users 
            if u.password_never_expires and u.enabled
        ]
        
        if never_expires:
            findings.append(AuditFinding(
                category="pwd_never_expires",
                title=f"Accounts with Non-Expiring Passwords: {len(never_expires)}",
                severity="MEDIUM",
                description=(
                    "Accounts configured with non-expiring passwords increase risk "
                    "of credential compromise persisting indefinitely."
                ),
                affected_objects=[u.sam_account_name for u in never_expires],
                evidence={
                    "total_count": len(never_expires),
                    "privileged_count": len([u for u in never_expires if u.admin_count == 1]),
                },
                recommendations=[
                    "Remove 'Password never expires' flag where not required",
                    "For service accounts, convert to gMSA with automatic rotation",
                    "Document exceptions and implement compensating controls",
                ],
                mitre_techniques=["T1078"],
            ))
        
        # Password not required
        no_pwd = [
            u for u in self.snapshot.users 
            if u.password_not_required and u.enabled
        ]
        
        if no_pwd:
            findings.append(AuditFinding(
                category="pwd_not_required",
                title=f"Accounts Not Requiring Password: {len(no_pwd)}",
                severity="CRITICAL",
                description=(
                    "Accounts with PASSWD_NOTREQD flag can authenticate without a "
                    "password, representing a critical security vulnerability."
                ),
                affected_objects=[u.sam_account_name for u in no_pwd],
                evidence={"total_count": len(no_pwd)},
                recommendations=[
                    "Remove PASSWD_NOTREQD flag immediately",
                    "Set strong passwords on all affected accounts",
                    "Investigate how this configuration was set",
                ],
                mitre_techniques=["T1078"],
            ))
        
        return findings
    
    def _audit_privileged_accounts(self) -> List[AuditFinding]:
        """Audit privileged account configurations."""
        findings = []
        
        privileged = [u for u in self.snapshot.users if u.admin_count == 1 and u.enabled]
        
        if privileged:
            # Check for concerning patterns
            stale = [u for u in privileged if u.password_age_days and u.password_age_days > 180]
            never_logged_on = [u for u in privileged if not u.last_logon]
            
            findings.append(AuditFinding(
                category="privileged_account_summary",
                title=f"Privileged Account Summary: {len(privileged)} accounts",
                severity="INFO",
                description=(
                    "Summary of accounts protected by AdminSDHolder (adminCount=1)."
                ),
                affected_objects=[u.sam_account_name for u in privileged],
                evidence={
                    "total_privileged": len(privileged),
                    "stale_passwords_180d": len(stale),
                    "never_logged_on": len(never_logged_on),
                },
                recommendations=[
                    "Review all privileged accounts quarterly",
                    "Implement tiered administration model",
                    "Rotate stale privileged account passwords",
                ],
                mitre_techniques=["T1078.002"],
            ))
            
            if stale:
                findings.append(AuditFinding(
                    category="stale_privileged_passwords",
                    title=f"Stale Privileged Account Passwords: {len(stale)}",
                    severity="HIGH",
                    description=(
                        "Privileged accounts with passwords unchanged for over 180 days "
                        "increase risk of undetected credential compromise."
                    ),
                    affected_objects=[u.sam_account_name for u in stale],
                    evidence={
                        "accounts": [
                            {"name": u.sam_account_name, "age_days": u.password_age_days}
                            for u in stale[:10]
                        ],
                    },
                    recommendations=[
                        "Rotate passwords for all affected accounts",
                        "Implement 90-day maximum password age for privileged accounts",
                        "Consider Privileged Access Workstations (PAW)",
                    ],
                    mitre_techniques=["T1078.002"],
                ))
        
        return findings
    
    def _audit_delegation(self) -> List[AuditFinding]:
        """Audit delegation configurations on user accounts."""
        findings = []
        
        trusted_delegation = [
            u for u in self.snapshot.users 
            if u.trusted_for_delegation and u.enabled
        ]
        
        if trusted_delegation:
            findings.append(AuditFinding(
                category="user_unconstrained_delegation",
                title=f"Users Trusted for Delegation: {len(trusted_delegation)}",
                severity="HIGH",
                description=(
                    "User accounts with 'Trust this user for delegation to any service' "
                    "can impersonate any user to any service, enabling privilege escalation."
                ),
                affected_objects=[u.sam_account_name for u in trusted_delegation],
                evidence={"total_count": len(trusted_delegation)},
                recommendations=[
                    "Remove unconstrained delegation from user accounts",
                    "Use constrained delegation or RBCD instead",
                    "Implement Protected Users group membership",
                ],
                mitre_techniques=["T1558"],
            ))
        
        return findings
    
    def _audit_stale_accounts(self) -> List[AuditFinding]:
        """Find stale/dormant accounts."""
        findings = []
        
        now = datetime.now(timezone.utc)
        
        # Users who haven't logged in for 90+ days
        stale_users = [
            u for u in self.snapshot.users
            if u.enabled and u.last_logon 
            and (now - u.last_logon).days > 90
        ]
        
        if stale_users:
            findings.append(AuditFinding(
                category="stale_user_accounts",
                title=f"Stale User Accounts (90+ days): {len(stale_users)}",
                severity="MEDIUM",
                description=(
                    "Enabled accounts with no logon activity for 90+ days may indicate "
                    "dormant accounts that could be compromised without detection."
                ),
                affected_objects=[u.sam_account_name for u in stale_users[:50]],
                evidence={
                    "total_count": len(stale_users),
                    "privileged_count": len([u for u in stale_users if u.admin_count == 1]),
                },
                recommendations=[
                    "Disable accounts with no business justification",
                    "Implement automated stale account detection",
                    "Review privileged stale accounts immediately",
                ],
                mitre_techniques=["T1078"],
            ))
        
        return findings
    
    def _audit_unconstrained_delegation(self) -> List[AuditFinding]:
        """Find computers with unconstrained delegation."""
        findings = []
        
        unconstrained = [
            c for c in self.snapshot.computers
            if c.trusted_for_delegation and not c.is_domain_controller
        ]
        
        if unconstrained:
            findings.append(AuditFinding(
                category="computer_unconstrained_delegation",
                title=f"Non-DC Computers with Unconstrained Delegation: {len(unconstrained)}",
                severity="CRITICAL",
                description=(
                    "Computers with unconstrained delegation receive the TGT of every "
                    "user who authenticates to them. Compromise of these systems yields "
                    "credentials for all users who have connected."
                ),
                affected_objects=[c.sam_account_name for c in unconstrained],
                evidence={
                    "computers": [
                        {"name": c.sam_account_name, "os": c.operating_system}
                        for c in unconstrained[:10]
                    ],
                },
                recommendations=[
                    "Remove unconstrained delegation immediately",
                    "Use constrained delegation or RBCD",
                    "Add sensitive accounts to Protected Users group",
                    "Mark high-value accounts as 'Account is sensitive and cannot be delegated'",
                ],
                mitre_techniques=["T1558"],
            ))
        
        return findings
    
    def _audit_rbcd(self) -> List[AuditFinding]:
        """Audit Resource-Based Constrained Delegation configurations."""
        findings = []
        
        rbcd_configured = [
            c for c in self.snapshot.computers
            if c.ms_ds_allowed_to_act_on_behalf
        ]
        
        if rbcd_configured:
            findings.append(AuditFinding(
                category="rbcd_configured",
                title=f"Computers with RBCD Configured: {len(rbcd_configured)}",
                severity="MEDIUM",
                description=(
                    "Resource-Based Constrained Delegation is configured on these computers. "
                    "Any principal with write access to msDS-AllowedToActOnBehalfOfOtherIdentity "
                    "can configure delegation to impersonate users."
                ),
                affected_objects=[c.sam_account_name for c in rbcd_configured],
                evidence={
                    "computers": [
                        {
                            "name": c.sam_account_name,
                            "allowed_principals": c.ms_ds_allowed_to_act_on_behalf[:5],
                        }
                        for c in rbcd_configured[:10]
                    ],
                },
                recommendations=[
                    "Audit write permissions to this attribute",
                    "Remove RBCD configurations unless explicitly required",
                    "Monitor for S4U2Proxy Kerberos events",
                ],
                mitre_techniques=["T1558"],
            ))
        
        return findings
    
    def _audit_legacy_os(self) -> List[AuditFinding]:
        """Find computers running legacy/unsupported operating systems."""
        findings = []
        
        legacy_patterns = [
            "Windows Server 2003",
            "Windows Server 2008",
            "Windows XP",
            "Windows Vista",
            "Windows 7",
        ]
        
        legacy = [
            c for c in self.snapshot.computers
            if any(p.lower() in c.operating_system.lower() for p in legacy_patterns)
        ]
        
        if legacy:
            findings.append(AuditFinding(
                category="legacy_os",
                title=f"Legacy Operating Systems: {len(legacy)}",
                severity="HIGH",
                description=(
                    "Computers running unsupported operating systems lack security updates "
                    "and represent significant compromise risk."
                ),
                affected_objects=[c.sam_account_name for c in legacy],
                evidence={
                    "by_os": {},  # Could aggregate by OS version
                    "computers": [
                        {"name": c.sam_account_name, "os": c.operating_system}
                        for c in legacy[:20]
                    ],
                },
                recommendations=[
                    "Upgrade or decommission legacy systems",
                    "Isolate legacy systems on separate network segments",
                    "Implement enhanced monitoring for legacy systems",
                    "Document business justification for exceptions",
                ],
                mitre_techniques=["T1210"],
            ))
        
        return findings
    
    def _audit_privileged_groups(self) -> List[AuditFinding]:
        """Audit privileged group membership."""
        findings = []
        
        privileged_groups = [g for g in self.snapshot.groups if g.is_privileged]
        
        if privileged_groups:
            total_members = sum(len(g.members) for g in privileged_groups)
            
            findings.append(AuditFinding(
                category="privileged_groups",
                title=f"Privileged Group Membership Summary: {total_members} members",
                severity="INFO",
                description=(
                    "Summary of membership in high-privilege groups."
                ),
                affected_objects=[g.sam_account_name for g in privileged_groups],
                evidence={
                    "groups": [
                        {"name": g.sam_account_name, "member_count": len(g.members)}
                        for g in privileged_groups
                    ],
                },
                recommendations=[
                    "Minimize privileged group membership",
                    "Implement Just-In-Time (JIT) access",
                    "Review membership quarterly",
                ],
                mitre_techniques=["T1078.002"],
            ))
        
        return findings
    
    def _audit_trusts(self) -> List[AuditFinding]:
        """Audit domain trust configurations."""
        findings = []
        
        # Trusts without SID filtering
        no_sid_filter = [
            t for t in self.snapshot.trusts
            if not t.sid_filtering_enabled
        ]
        
        if no_sid_filter:
            findings.append(AuditFinding(
                category="trust_no_sid_filtering",
                title=f"Trusts Without SID Filtering: {len(no_sid_filter)}",
                severity="HIGH",
                description=(
                    "Trusts without SID filtering allow SID history injection, "
                    "enabling privilege escalation across trust boundaries."
                ),
                affected_objects=[t.partner_name for t in no_sid_filter],
                evidence={
                    "trusts": [
                        {"partner": t.partner_name, "type": t.trust_type}
                        for t in no_sid_filter
                    ],
                },
                recommendations=[
                    "Enable SID filtering on all external trusts",
                    "Enable Selective Authentication where possible",
                    "Review trust necessity",
                ],
                mitre_techniques=["T1134.005"],
            ))
        
        return findings
    
    def _audit_authentication_events(self) -> List[AuditFinding]:
        """Analyze authentication events from EVTX logs."""
        findings = []
        
        # Look for specific event IDs
        event_4625 = [e for e in self.events if self._get_event_id(e) == 4625]  # Failed logons
        event_4768 = [e for e in self.events if self._get_event_id(e) == 4768]  # TGT requests
        event_4769 = [e for e in self.events if self._get_event_id(e) == 4769]  # Service tickets
        
        # Password spray detection
        if len(event_4625) > 50:
            # Group by target account
            by_account: Dict[str, int] = {}
            for e in event_4625:
                account = self._get_event_data(e, "TargetUserName", "")
                by_account[account] = by_account.get(account, 0) + 1
            
            spray_candidates = [a for a, c in by_account.items() if c > 5]
            
            if len(spray_candidates) > 20:
                findings.append(AuditFinding(
                    category="password_spray_detected",
                    title=f"Potential Password Spray: {len(spray_candidates)} accounts targeted",
                    severity="HIGH",
                    description=(
                        "Multiple failed authentication attempts across many accounts "
                        "may indicate a password spray attack."
                    ),
                    affected_objects=spray_candidates[:50],
                    evidence={
                        "failed_logon_count": len(event_4625),
                        "unique_targets": len(by_account),
                    },
                    recommendations=[
                        "Investigate source IPs for failed logons",
                        "Enable account lockout policies",
                        "Implement MFA",
                        "Check for successful logons following failures",
                    ],
                    mitre_techniques=["T1110.003"],
                ))
        
        # Kerberoasting detection (RC4 service ticket requests)
        rc4_tickets = [
            e for e in event_4769
            if self._get_event_data(e, "TicketEncryptionType", "") == "0x17"
        ]
        
        if len(rc4_tickets) > 10:
            findings.append(AuditFinding(
                category="kerberoast_activity",
                title=f"Kerberoasting Activity Detected: {len(rc4_tickets)} RC4 tickets",
                severity="HIGH",
                description=(
                    "Service ticket requests using RC4 encryption (0x17) may indicate "
                    "Kerberoasting attacks attempting to crack service account passwords."
                ),
                affected_objects=list(set(
                    self._get_event_data(e, "ServiceName", "") for e in rc4_tickets
                ))[:20],
                evidence={
                    "rc4_ticket_count": len(rc4_tickets),
                    "total_service_tickets": len(event_4769),
                },
                recommendations=[
                    "Enable AES encryption for service accounts",
                    "Investigate requesting accounts",
                    "Review affected service account passwords",
                ],
                mitre_techniques=["T1558.003"],
            ))
        
        return findings
    
    def _audit_privilege_use(self) -> List[AuditFinding]:
        """Analyze privilege use events."""
        findings = []
        
        # Sensitive privilege use (4672, 4673)
        event_4672 = [e for e in self.events if self._get_event_id(e) == 4672]
        
        if event_4672:
            # Find accounts with SeDebugPrivilege or SeImpersonatePrivilege
            debug_priv = [
                e for e in event_4672
                if "SeDebugPrivilege" in self._get_event_data(e, "PrivilegeList", "")
            ]
            
            if len(debug_priv) > 5:
                accounts = list(set(
                    self._get_event_data(e, "SubjectUserName", "") for e in debug_priv
                ))
                
                findings.append(AuditFinding(
                    category="debug_privilege_use",
                    title=f"SeDebugPrivilege Use: {len(debug_priv)} events",
                    severity="MEDIUM",
                    description=(
                        "SeDebugPrivilege enables process injection and credential dumping. "
                        "Review whether this privilege use is legitimate."
                    ),
                    affected_objects=accounts[:20],
                    evidence={
                        "event_count": len(debug_priv),
                        "unique_accounts": len(accounts),
                    },
                    recommendations=[
                        "Audit accounts with SeDebugPrivilege",
                        "Implement Credential Guard",
                        "Monitor for LSASS access",
                    ],
                    mitre_techniques=["T1134"],
                ))
        
        return findings
    
    def _audit_account_management(self) -> List[AuditFinding]:
        """Analyze account management events."""
        findings = []
        
        # Security-enabled group membership changes (4728, 4732, 4756)
        group_changes = [
            e for e in self.events
            if self._get_event_id(e) in [4728, 4732, 4756]
        ]
        
        if group_changes:
            findings.append(AuditFinding(
                category="group_membership_changes",
                title=f"Group Membership Changes: {len(group_changes)} events",
                severity="INFO",
                description=(
                    "Security group membership changes detected. Review for unauthorized "
                    "privilege escalation."
                ),
                affected_objects=[],
                evidence={
                    "event_count": len(group_changes),
                    "event_ids": {
                        4728: len([e for e in group_changes if self._get_event_id(e) == 4728]),
                        4732: len([e for e in group_changes if self._get_event_id(e) == 4732]),
                        4756: len([e for e in group_changes if self._get_event_id(e) == 4756]),
                    },
                },
                recommendations=[
                    "Review changes to privileged groups",
                    "Implement change management for group membership",
                    "Alert on Domain Admins/Enterprise Admins changes",
                ],
                mitre_techniques=["T1098"],
            ))
        
        return findings
    
    # ── Helper Methods ─────────────────────────────────────────────────────────
    
    def _get_event_id(self, event: Dict) -> int:
        """Extract event ID from event dict."""
        try:
            return int(event.get("Event", {}).get("System", {}).get("EventID", 0))
        except (TypeError, ValueError):
            return 0
    
    def _get_event_data(self, event: Dict, field: str, default: str = "") -> str:
        """Extract field from event data."""
        try:
            data = event.get("Event", {}).get("EventData", {})
            return str(data.get(field, default))
        except (TypeError, AttributeError):
            return default


def run_audit(
    ntds_path: Optional[str] = None,
    system_hive_path: Optional[str] = None,
    evtx_paths: Optional[List[str]] = None,
    extract_hashes: bool = False,
    output_path: Optional[str] = None,
    output_format: str = "both",
) -> AuditReport:
    """
    Convenience function to run offline audit.
    
    Args:
        ntds_path: Path to NTDS.dit file
        system_hive_path: Path to SYSTEM registry hive
        evtx_paths: List of paths to EVTX log files
        extract_hashes: Whether to attempt hash extraction
        output_path: Directory for output reports
        output_format: 'json', 'html', or 'both'
    
    Returns:
        AuditReport with all findings
    """
    auditor = OfflineAuditor(
        ntds_path=Path(ntds_path) if ntds_path else None,
        system_hive_path=Path(system_hive_path) if system_hive_path else None,
        evtx_paths=[Path(p) for p in (evtx_paths or [])],
        extract_hashes=extract_hashes,
    )
    
    report = auditor.audit()
    
    # Write output if path specified
    if output_path:
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        
        if output_format in ("json", "both"):
            json_path = output_dir / f"audit_{timestamp}.json"
            with open(json_path, "w") as f:
                json.dump(report.to_dict(), f, indent=2)
            log.info("JSON report written: %s", json_path)
        
        if output_format in ("html", "both"):
            html_path = output_dir / f"audit_{timestamp}.html"
            _write_html_report(report, html_path)
            log.info("HTML report written: %s", html_path)
    
    return report


def _write_html_report(report: AuditReport, path: Path):
    """Generate HTML report."""
    report.compute_counts()
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>ADVulture Offline Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
        h2 {{ color: #16213e; margin-top: 30px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; flex: 1; }}
        .stat .value {{ font-size: 2em; font-weight: bold; }}
        .stat.critical {{ border-left: 4px solid #dc3545; }}
        .stat.high {{ border-left: 4px solid #fd7e14; }}
        .stat.medium {{ border-left: 4px solid #ffc107; }}
        .stat.low {{ border-left: 4px solid #28a745; }}
        .finding {{ background: #fff; border: 1px solid #dee2e6; border-radius: 8px; margin: 15px 0; padding: 20px; }}
        .finding.CRITICAL {{ border-left: 4px solid #dc3545; }}
        .finding.HIGH {{ border-left: 4px solid #fd7e14; }}
        .finding.MEDIUM {{ border-left: 4px solid #ffc107; }}
        .finding.LOW {{ border-left: 4px solid #28a745; }}
        .finding.INFO {{ border-left: 4px solid #17a2b8; }}
        .severity {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
        .severity.CRITICAL {{ background: #dc3545; color: white; }}
        .severity.HIGH {{ background: #fd7e14; color: white; }}
        .severity.MEDIUM {{ background: #ffc107; color: black; }}
        .severity.LOW {{ background: #28a745; color: white; }}
        .severity.INFO {{ background: #17a2b8; color: white; }}
        .recommendations {{ background: #e8f4f8; padding: 15px; border-radius: 4px; margin-top: 10px; }}
        .recommendations li {{ margin: 5px 0; }}
        .mitre {{ font-family: monospace; background: #f1f1f1; padding: 2px 6px; border-radius: 3px; }}
        .affected {{ font-family: monospace; font-size: 0.9em; color: #666; }}
        footer {{ text-align: center; margin-top: 40px; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🦅 ADVulture Offline Audit Report</h1>
        <p><strong>Generated:</strong> {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        <p><strong>Domain:</strong> {report.snapshot.domain}</p>
        
        <div class="summary">
            <div class="stat critical">
                <div class="value">{report.critical_count}</div>
                <div>Critical</div>
            </div>
            <div class="stat high">
                <div class="value">{report.high_count}</div>
                <div>High</div>
            </div>
            <div class="stat medium">
                <div class="value">{report.medium_count}</div>
                <div>Medium</div>
            </div>
            <div class="stat low">
                <div class="value">{report.low_count}</div>
                <div>Low</div>
            </div>
        </div>
        
        <h2>Environment Summary</h2>
        <ul>
            <li><strong>Users:</strong> {len(report.snapshot.users)}</li>
            <li><strong>Computers:</strong> {len(report.snapshot.computers)}</li>
            <li><strong>Groups:</strong> {len(report.snapshot.groups)}</li>
            <li><strong>Trusts:</strong> {len(report.snapshot.trusts)}</li>
            <li><strong>Events Analyzed:</strong> {report.event_count}</li>
        </ul>
        
        <h2>Findings</h2>
"""
    
    for finding in report.findings:
        affected_preview = ", ".join(finding.affected_objects[:5])
        if len(finding.affected_objects) > 5:
            affected_preview += f" (+{len(finding.affected_objects) - 5} more)"
        
        mitre_html = " ".join(
            f'<span class="mitre">{t}</span>' for t in finding.mitre_techniques
        )
        
        recs_html = "\n".join(f"<li>{r}</li>" for r in finding.recommendations)
        
        html += f"""
        <div class="finding {finding.severity}">
            <span class="severity {finding.severity}">{finding.severity}</span>
            <h3>{finding.title}</h3>
            <p>{finding.description}</p>
            <p class="affected"><strong>Affected:</strong> {affected_preview}</p>
            <p><strong>MITRE ATT&CK:</strong> {mitre_html}</p>
            <div class="recommendations">
                <strong>Recommendations:</strong>
                <ul>{recs_html}</ul>
            </div>
        </div>
"""
    
    html += f"""
        <footer>
            <p>(c) 2025 Shane D. Shook, PhD - All Rights Reserved</p>
            <p>ADVulture Offline Audit Module</p>
        </footer>
    </div>
</body>
</html>
"""
    
    with open(path, "w") as f:
        f.write(html)
