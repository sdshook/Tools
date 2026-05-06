"""
ADVulture — Windows Event Log Ingester
Parses Windows Security, System, and ADFS event logs from
EVTX files, WinRM endpoints, or SIEM APIs.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Iterator
from pathlib import Path
from enum import Enum

log = logging.getLogger(__name__)

# ── Semantic event categories ────────────────────────────────────────────────

class EventCategory(str, Enum):
    # AuthN
    LOGON_SUCCESS       = "logon_success"
    LOGON_FAILURE       = "logon_failure"
    EXPLICIT_CREDS      = "explicit_credentials"
    LOGOFF              = "logoff"
    # Kerberos
    TGT_REQUEST         = "tgt_request"
    SERVICE_TICKET      = "service_ticket_request"
    KERBEROS_FAILURE    = "kerberos_preauth_failed"
    NTLM_VALIDATION     = "ntlm_validation"
    # Privilege
    SPECIAL_PRIVILEGES  = "special_privileges_logon"
    PRIVILEGED_SERVICE  = "privileged_service_called"
    # AuthZ — object access
    OBJECT_HANDLE       = "object_handle_requested"
    OBJECT_ACCESSED     = "object_accessed"
    PERMISSIONS_CHANGED = "object_permissions_changed"
    SHARE_ACCESSED      = "share_accessed"
    SHARE_FILE_ACCESSED = "share_file_accessed"
    # AuthZ — directory
    DIR_OBJECT_OP       = "directory_object_operation"   # 4662 — DCSync
    LDAP_EXPENSIVE      = "ldap_expensive_query"         # 1644
    # Group changes
    GROUP_MEMBER_ADDED  = "group_member_added"
    GROUP_MEMBER_REMOVED= "group_member_removed"
    # Account
    ACCOUNT_CREATED     = "account_created"
    ACCOUNT_CHANGED     = "account_changed"
    ACCOUNT_LOCKED      = "account_locked"
    ACCOUNT_DISABLED    = "account_disabled"
    # Rights
    USER_RIGHT_ASSIGNED = "user_right_assigned"
    # Services and tasks
    SERVICE_INSTALLED   = "service_installed"
    TASK_CREATED        = "scheduled_task_created"
    TASK_UPDATED        = "scheduled_task_updated"
    # ADFS
    ADFS_TOKEN_ISSUED   = "adfs_token_issued"
    ADFS_AUTHZ_FAILURE  = "adfs_authz_failure"
    ADFS_CLAIM_RULE_CHG = "adfs_claim_rule_changed"
    ADFS_TRUST_ADDED    = "adfs_trust_added"
    ADFS_CLAIMS_ISSUED  = "adfs_claims_issued"
    ADFS_CERT_OP        = "adfs_cert_operation"
    # Certificates
    CERT_REQUESTED      = "certificate_requested"
    CERT_ISSUED         = "certificate_issued"
    CERT_DENIED         = "certificate_denied"
    UNKNOWN             = "unknown"


# ── Event ID → category mapping ──────────────────────────────────────────────

EVENT_CATEGORY_MAP: Dict[int, EventCategory] = {
    4624:  EventCategory.LOGON_SUCCESS,
    4625:  EventCategory.LOGON_FAILURE,
    4648:  EventCategory.EXPLICIT_CREDS,
    4634:  EventCategory.LOGOFF,
    4647:  EventCategory.LOGOFF,
    4768:  EventCategory.TGT_REQUEST,
    4769:  EventCategory.SERVICE_TICKET,
    4771:  EventCategory.KERBEROS_FAILURE,
    4776:  EventCategory.NTLM_VALIDATION,
    4672:  EventCategory.SPECIAL_PRIVILEGES,
    4673:  EventCategory.PRIVILEGED_SERVICE,
    4656:  EventCategory.OBJECT_HANDLE,
    4663:  EventCategory.OBJECT_ACCESSED,
    4670:  EventCategory.PERMISSIONS_CHANGED,
    5140:  EventCategory.SHARE_ACCESSED,
    5145:  EventCategory.SHARE_FILE_ACCESSED,
    4662:  EventCategory.DIR_OBJECT_OP,
    1644:  EventCategory.LDAP_EXPENSIVE,
    4728:  EventCategory.GROUP_MEMBER_ADDED,
    4729:  EventCategory.GROUP_MEMBER_REMOVED,
    4732:  EventCategory.GROUP_MEMBER_ADDED,
    4733:  EventCategory.GROUP_MEMBER_REMOVED,
    4756:  EventCategory.GROUP_MEMBER_ADDED,
    4757:  EventCategory.GROUP_MEMBER_REMOVED,
    4720:  EventCategory.ACCOUNT_CREATED,
    4738:  EventCategory.ACCOUNT_CHANGED,
    4740:  EventCategory.ACCOUNT_LOCKED,
    4725:  EventCategory.ACCOUNT_DISABLED,
    4704:  EventCategory.USER_RIGHT_ASSIGNED,
    7045:  EventCategory.SERVICE_INSTALLED,
    4698:  EventCategory.TASK_CREATED,
    4702:  EventCategory.TASK_UPDATED,
    # ADFS
    299:   EventCategory.ADFS_TOKEN_ISSUED,
    324:   EventCategory.ADFS_AUTHZ_FAILURE,
    403:   EventCategory.ADFS_CLAIM_RULE_CHG,
    500:   EventCategory.ADFS_TRUST_ADDED,
    510:   EventCategory.ADFS_CLAIMS_ISSUED,
    1007:  EventCategory.ADFS_CERT_OP,
    # ADCS
    4886:  EventCategory.CERT_REQUESTED,
    4887:  EventCategory.CERT_ISSUED,
    4888:  EventCategory.CERT_DENIED,
}

# DCSync GUID — 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
DCSYNC_GUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"

# Dangerous privileges (appear in 4672 events)
DANGEROUS_PRIVILEGES = {
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeDebugPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeCreateTokenPrivilege",
    "SeTcbPrivilege",
}


@dataclass
class ParsedEvent:
    event_id: int
    category: EventCategory
    timestamp: datetime
    source_host: str
    channel: str
    # Subject (who performed action)
    subject_sid: str = ""
    subject_account: str = ""
    subject_domain: str = ""
    # Target / Object
    target_sid: str = ""
    target_account: str = ""
    target_domain: str = ""
    target_host: str = ""
    # Auth details
    logon_type: int = 0
    auth_package: str = ""
    # Kerberos details
    ticket_encryption_type: str = ""    # 0x17 = RC4, 0x12 = AES256
    ticket_options: str = ""
    transited_services: str = ""        # populated on delegation
    service_name: str = ""
    # Privilege details
    privileges: List[str] = field(default_factory=list)
    has_dangerous_privilege: bool = False
    # Object access details
    object_name: str = ""
    object_type: str = ""
    access_mask: str = ""
    # Share access
    share_name: str = ""
    relative_target_name: str = ""
    # GUID for DCSync detection
    properties_guid: str = ""
    is_dcsync: bool = False
    # Computed flags
    is_rc4_downgrade: bool = False
    is_ntlm_on_kerb_capable: bool = False
    is_delegation: bool = False
    raw: dict = field(default_factory=dict)


@dataclass
class EdgeTensor:
    """
    Behavioural summary for a (src, dst) pair derived from event history.
    This is the temporal dimension that makes AuthZ analysis real.
    """
    src_sid: str
    dst_identifier: str             # host, share, object
    edge_type: str

    traversal_count_30d: int = 0
    traversal_count_7d: int = 0
    unique_sources_30d: int = 0
    last_traversal: Optional[datetime] = None
    traversal_hours: List[int] = field(default_factory=list)  # hour of day
    mean_session_seconds: float = 0.0

    # Anomaly signals
    ntlm_ratio: float = 0.0         # NTLM / total on Kerberos-capable edges
    rc4_downgrade_ratio: float = 0.0
    explicit_cred_ratio: float = 0.0
    off_hours_ratio: float = 0.0    # outside 07:00-19:00
    failed_before_success: int = 0
    new_source_flag: bool = False
    ldap_enum_preceded: bool = False
    delegation_used: bool = False
    anomaly_score: float = 0.0      # computed composite

    def compute_anomaly_score(self) -> float:
        score = (
            0.25 * self.ntlm_ratio +
            0.20 * self.rc4_downgrade_ratio +
            0.20 * self.explicit_cred_ratio +
            0.15 * self.off_hours_ratio +
            0.10 * min(1.0, self.failed_before_success / 5.0) +
            0.05 * float(self.new_source_flag) +
            0.05 * float(self.ldap_enum_preceded)
        )
        self.anomaly_score = min(1.0, score)
        return self.anomaly_score

    def velocity(self) -> float:
        """Rate of acceleration — rising traversal velocity is threat signal."""
        if self.traversal_count_30d == 0:
            return 0.0
        # 7d normalised to 30d for fair comparison
        expected_7d = self.traversal_count_30d * (7 / 30)
        if expected_7d == 0:
            return 0.0
        return self.traversal_count_7d / expected_7d


class EventStream:
    """Container and query interface for parsed events."""

    def __init__(self, events: List[ParsedEvent]):
        self.events = events
        self._by_id: Dict[int, List[ParsedEvent]] = {}
        for e in events:
            self._by_id.setdefault(e.event_id, []).append(e)

    def filter(
        self,
        ids: Optional[List[int]] = None,
        category: Optional[EventCategory] = None,
        since: Optional[datetime] = None,
        host: Optional[str] = None,
        exclude_dcs: bool = False,
        dc_hostnames: Optional[List[str]] = None,
    ) -> List[ParsedEvent]:
        result = self.events
        if ids:
            result = [e for e in result if e.event_id in ids]
        if category:
            result = [e for e in result if e.category == category]
        if since:
            result = [e for e in result if e.timestamp >= since]
        if host:
            result = [e for e in result if e.source_host == host]
        if exclude_dcs and dc_hostnames:
            result = [e for e in result if e.source_host not in dc_hostnames]
        return result

    def count(
        self,
        event_id: int,
        filters: Optional[Dict[str, str]] = None,
        since: Optional[datetime] = None,
    ) -> int:
        events = self._by_id.get(event_id, [])
        if since:
            events = [e for e in events if e.timestamp >= since]
        if filters:
            for attr, val in filters.items():
                events = [e for e in events if getattr(e, attr, None) == val]
        return len(events)

    def build_edge_tensors(self, window_days: int = 30) -> Dict[tuple, EdgeTensor]:
        """Build behavioural edge tensors from event history."""
        cutoff = datetime.utcnow() - timedelta(days=window_days)
        tensors: Dict[tuple, EdgeTensor] = {}

        for event in self.events:
            if event.timestamp < cutoff:
                continue
            if event.category not in (
                EventCategory.LOGON_SUCCESS, EventCategory.SHARE_ACCESSED,
                EventCategory.OBJECT_ACCESSED, EventCategory.SERVICE_TICKET,
            ):
                continue

            key = (event.subject_sid, event.target_host or event.share_name or event.service_name)
            if not all(key):
                continue

            if key not in tensors:
                tensors[key] = EdgeTensor(
                    src_sid=key[0],
                    dst_identifier=key[1],
                    edge_type=event.category.value,
                )
            t = tensors[key]
            t.traversal_count_30d += 1
            t.last_traversal = max(t.last_traversal or event.timestamp, event.timestamp)
            if event.timestamp >= datetime.utcnow() - timedelta(days=7):
                t.traversal_count_7d += 1
            if event.is_ntlm_on_kerb_capable:
                t.ntlm_ratio = (t.ntlm_ratio * (t.traversal_count_30d - 1) + 1.0) / t.traversal_count_30d
            if event.is_rc4_downgrade:
                t.rc4_downgrade_ratio = (t.rc4_downgrade_ratio * (t.traversal_count_30d - 1) + 1.0) / t.traversal_count_30d
            hour = event.timestamp.hour
            t.traversal_hours.append(hour)
            if hour < 7 or hour > 19:
                t.off_hours_ratio = (t.off_hours_ratio * (t.traversal_count_30d - 1) + 1.0) / t.traversal_count_30d

        for t in tensors.values():
            t.compute_anomaly_score()

        return tensors


class EVTXIngester:
    """Parse Windows EVTX files into ParsedEvent stream."""

    def __init__(self, paths: List[Path]):
        self.paths = paths

    def ingest(self) -> EventStream:
        events: List[ParsedEvent] = []
        for path in self.paths:
            events.extend(self._parse_file(path))
        log.info("Parsed %d events from %d EVTX files", len(events), len(self.paths))
        return EventStream(events)

    def _parse_file(self, path: Path) -> List[ParsedEvent]:
        try:
            from Evtx.Evtx import Evtx
            import xml.etree.ElementTree as ET
            events = []
            with Evtx(str(path)) as evtx:
                for record in evtx.records():
                    try:
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        event = self._parse_xml(root)
                        if event:
                            events.append(event)
                    except Exception as ex:
                        log.debug("Failed to parse record: %s", ex)
            return events
        except ImportError:
            log.warning("python-evtx not installed; cannot parse EVTX files.")
            return []

    def _parse_xml(self, root) -> Optional[ParsedEvent]:
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        sys_node = root.find("e:System", ns)
        if sys_node is None:
            return None

        event_id_node = sys_node.find("e:EventID", ns)
        if event_id_node is None:
            return None
        try:
            event_id = int(event_id_node.text)
        except (TypeError, ValueError):
            return None

        category = EVENT_CATEGORY_MAP.get(event_id, EventCategory.UNKNOWN)

        time_created = sys_node.find("e:TimeCreated", ns)
        ts_str = time_created.get("SystemTime", "") if time_created is not None else ""
        try:
            timestamp = datetime.fromisoformat(ts_str.rstrip("Z"))
        except ValueError:
            timestamp = datetime.utcnow()

        computer_node = sys_node.find("e:Computer", ns)
        source_host = computer_node.text if computer_node is not None else ""

        channel_node = sys_node.find("e:Channel", ns)
        channel = channel_node.text if channel_node is not None else ""

        # Parse EventData fields
        data: Dict[str, str] = {}
        event_data = root.find("e:EventData", ns)
        if event_data is not None:
            for named in event_data.findall("e:Data", ns):
                name = named.get("Name", "")
                if name:
                    data[name] = named.text or ""

        privileges_raw = data.get("PrivilegeList", "")
        privileges = [p.strip() for p in privileges_raw.split("\n") if p.strip()]
        has_dangerous = bool(set(privileges) & DANGEROUS_PRIVILEGES)

        encryption_type = data.get("TicketEncryptionType", "")
        is_rc4 = encryption_type in ("0x17", "0x17 (RC4-HMAC)", "23")

        transited = data.get("TransitedServices", "")
        is_delegation = bool(transited and transited != "-" and transited != "%%1796")

        properties_guid = data.get("Properties", "")
        is_dcsync = DCSYNC_GUID in properties_guid

        auth_package = data.get("AuthenticationPackageName", "")
        logon_type = int(data.get("LogonType", "0") or "0")
        is_ntlm = auth_package.upper() in ("NTLM", "NTLMSSP") and logon_type == 3

        return ParsedEvent(
            event_id=event_id,
            category=category,
            timestamp=timestamp,
            source_host=source_host,
            channel=channel,
            subject_sid=data.get("SubjectUserSid", ""),
            subject_account=data.get("SubjectUserName", ""),
            subject_domain=data.get("SubjectDomainName", ""),
            target_sid=data.get("TargetUserSid", ""),
            target_account=data.get("TargetUserName", ""),
            target_domain=data.get("TargetDomainName", ""),
            target_host=data.get("WorkstationName", "") or data.get("IpAddress", ""),
            logon_type=logon_type,
            auth_package=auth_package,
            ticket_encryption_type=encryption_type,
            ticket_options=data.get("TicketOptions", ""),
            transited_services=transited,
            service_name=data.get("ServiceName", ""),
            privileges=privileges,
            has_dangerous_privilege=has_dangerous,
            object_name=data.get("ObjectName", ""),
            object_type=data.get("ObjectType", ""),
            access_mask=data.get("AccessMask", ""),
            share_name=data.get("ShareName", ""),
            relative_target_name=data.get("RelativeTargetName", ""),
            properties_guid=properties_guid,
            is_dcsync=is_dcsync,
            is_rc4_downgrade=is_rc4,
            is_ntlm_on_kerb_capable=is_ntlm,
            is_delegation=is_delegation,
            raw=data,
        )
