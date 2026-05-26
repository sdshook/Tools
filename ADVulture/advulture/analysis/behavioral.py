# (c) 2025-2026 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture — Behavioral Analysis Module
Unified behavioral analysis for Entra ID, On-Premise AD, and Hybrid environments.

Detects anomalous authentication patterns including:
- Off-hours authentication
- High IP/source diversity
- Token/ticket replay indicators
- Impossible travel
- Lateral movement patterns
- Service account behavioral anomalies

Based on learnings from entra_assessment.py behavioral analysis modules.
"""

from __future__ import annotations
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from math import radians, sin, cos, sqrt, atan2
from typing import List, Dict, Optional, Any, Set, Tuple

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data Classes for Behavioral Events
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AuthEvent:
    """Unified authentication event for behavioral analysis."""
    timestamp: datetime
    user_id: str
    user_name: str  # UPN or SAM
    source_ip: Optional[str] = None
    source_host: Optional[str] = None
    target_resource: Optional[str] = None  # App name or service/host
    event_type: str = "auth"  # auth, tgs, ntlm, adfs
    result: str = "success"  # success, failure
    location: Optional[Dict[str, Any]] = None  # {city, country, lat, lon}
    auth_method: Optional[str] = None  # mfa, password, kerberos, etc.
    is_interactive: bool = False
    raw_event: Optional[Dict] = None


@dataclass
class BehavioralAnomaly:
    """Represents a detected behavioral anomaly."""
    anomaly_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    user: str
    description: str
    timestamp: Optional[datetime] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    affected_count: int = 1
    
    def to_dict(self) -> Dict:
        return {
            "type": self.anomaly_type,
            "severity": self.severity,
            "user": self.user,
            "description": self.description,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "evidence": self.evidence,
            "affected_count": self.affected_count,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Geographic Utilities
# ─────────────────────────────────────────────────────────────────────────────

def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate distance between two points on Earth in kilometers."""
    R = 6371  # Earth's radius in km
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
    return R * 2 * atan2(sqrt(a), sqrt(1-a))


# ─────────────────────────────────────────────────────────────────────────────
# Behavioral Analyzer - Core Class
# ─────────────────────────────────────────────────────────────────────────────

class BehavioralAnalyzer:
    """
    Unified behavioral analysis for authentication events.
    
    Works with events from:
    - Entra ID sign-in logs
    - Windows Security logs (4624, 4768, 4769, 4776)
    - ADFS audit logs
    
    All events are normalized to AuthEvent format before analysis.
    """
    
    def __init__(
        self,
        business_hours_start: int = 6,
        business_hours_end: int = 22,
        ip_diversity_threshold: int = 10,
        source_diversity_threshold: int = 5,
        off_hours_threshold: int = 5,
        replay_window_minutes: int = 10,
        travel_max_speed_kmh: int = 1000,
        lateral_movement_threshold: int = 5,
        subnet_locations: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize behavioral analyzer with configurable thresholds.
        
        Args:
            business_hours_start: Start of business hours (0-23, default 6am)
            business_hours_end: End of business hours (0-23, default 10pm)
            ip_diversity_threshold: IPs per user to flag (default 10)
            source_diversity_threshold: Sources for service accounts (default 5)
            off_hours_threshold: Off-hours events per user to flag (default 5)
            replay_window_minutes: Window for replay detection (default 10)
            travel_max_speed_kmh: Max travel speed before flagging (default 1000)
            lateral_movement_threshold: Hosts per hour to flag (default 5)
            subnet_locations: Mapping of subnet prefix to location name (on-prem)
        """
        self.business_hours_start = business_hours_start
        self.business_hours_end = business_hours_end
        self.ip_diversity_threshold = ip_diversity_threshold
        self.source_diversity_threshold = source_diversity_threshold
        self.off_hours_threshold = off_hours_threshold
        self.replay_window_minutes = replay_window_minutes
        self.travel_max_speed_kmh = travel_max_speed_kmh
        self.lateral_movement_threshold = lateral_movement_threshold
        self.subnet_locations = subnet_locations or {}
    
    def analyze_all(self, events: List[AuthEvent]) -> Dict[str, List[BehavioralAnomaly]]:
        """
        Run all behavioral analyses on the provided events.
        
        Returns dict with anomaly lists by category.
        """
        results = {
            "off_hours": self.detect_off_hours(events),
            "ip_diversity": self.detect_ip_diversity(events),
            "token_replay": self.detect_token_replay(events),
            "impossible_travel": self.detect_impossible_travel(events),
            "lateral_movement": self.detect_lateral_movement(events),
        }
        
        # Calculate summary stats
        total_anomalies = sum(len(v) for v in results.values())
        critical_count = sum(
            1 for anomalies in results.values() 
            for a in anomalies if a.severity == "CRITICAL"
        )
        high_count = sum(
            1 for anomalies in results.values() 
            for a in anomalies if a.severity == "HIGH"
        )
        
        log.info(
            "Behavioral analysis complete: %d anomalies (%d critical, %d high)",
            total_anomalies, critical_count, high_count
        )
        
        return results
    
    # ─────────────────────────────────────────────────────────────────────────
    # Off-Hours Authentication Detection
    # ─────────────────────────────────────────────────────────────────────────
    
    def detect_off_hours(self, events: List[AuthEvent]) -> List[BehavioralAnomaly]:
        """
        Detect authentication outside business hours.
        
        Flags users with multiple successful authentications during:
        - Weekends (Saturday/Sunday)
        - Late night / early morning (outside business_hours_start to business_hours_end)
        """
        off_hours_by_user: Dict[str, List[AuthEvent]] = defaultdict(list)
        
        for event in events:
            if event.result != "success":
                continue
            
            hour = event.timestamp.hour
            weekday = event.timestamp.weekday()
            
            is_weekend = weekday >= 5
            is_late_night = hour < self.business_hours_start or hour >= self.business_hours_end
            
            if is_weekend or is_late_night:
                off_hours_by_user[event.user_name].append(event)
        
        anomalies = []
        for user, user_events in off_hours_by_user.items():
            if len(user_events) >= self.off_hours_threshold:
                # Get sample timestamps
                sample_times = [e.timestamp.strftime("%Y-%m-%d %H:%M") for e in user_events[:5]]
                unique_sources = list(set(
                    e.source_ip or e.source_host or "unknown" 
                    for e in user_events
                ))
                
                anomalies.append(BehavioralAnomaly(
                    anomaly_type="OFF_HOURS_AUTH",
                    severity="MEDIUM" if len(user_events) < 20 else "HIGH",
                    user=user,
                    description=f"{len(user_events)} off-hours authentications detected",
                    timestamp=user_events[-1].timestamp,
                    evidence={
                        "event_count": len(user_events),
                        "sample_times": sample_times,
                        "unique_sources": unique_sources[:10],
                    },
                    affected_count=len(user_events),
                ))
        
        return anomalies
    
    # ─────────────────────────────────────────────────────────────────────────
    # IP/Source Diversity Detection
    # ─────────────────────────────────────────────────────────────────────────
    
    def detect_ip_diversity(self, events: List[AuthEvent]) -> List[BehavioralAnomaly]:
        """
        Detect users authenticating from unusually many distinct sources.
        
        High diversity may indicate:
        - Credential sharing
        - Compromised credentials used by multiple actors
        - VPN/proxy rotation by attacker
        """
        sources_by_user: Dict[str, Dict[str, Set]] = defaultdict(
            lambda: {"ips": set(), "hosts": set(), "locations": set()}
        )
        
        for event in events:
            if event.result != "success":
                continue
            
            user_data = sources_by_user[event.user_name]
            
            if event.source_ip and event.source_ip not in ("-", "::1", "127.0.0.1"):
                user_data["ips"].add(event.source_ip)
            
            if event.source_host and event.source_host != "-":
                user_data["hosts"].add(event.source_host)
            
            if event.location:
                city = event.location.get("city", "")
                country = event.location.get("country", "")
                loc_str = f"{city}, {country}".strip(", ")
                if loc_str:
                    user_data["locations"].add(loc_str)
        
        anomalies = []
        for user, data in sources_by_user.items():
            total_sources = len(data["ips"]) + len(data["hosts"])
            
            if len(data["ips"]) >= self.ip_diversity_threshold:
                anomalies.append(BehavioralAnomaly(
                    anomaly_type="HIGH_IP_DIVERSITY",
                    severity="HIGH" if len(data["ips"]) >= 20 else "MEDIUM",
                    user=user,
                    description=f"Authenticated from {len(data['ips'])} distinct IPs",
                    evidence={
                        "ip_count": len(data["ips"]),
                        "sample_ips": list(data["ips"])[:15],
                        "locations": list(data["locations"])[:10],
                    },
                    affected_count=len(data["ips"]),
                ))
        
        return anomalies
    
    # ─────────────────────────────────────────────────────────────────────────
    # Token/Ticket Replay Detection
    # ─────────────────────────────────────────────────────────────────────────
    
    def detect_token_replay(self, events: List[AuthEvent]) -> List[BehavioralAnomaly]:
        """
        Detect potential token/ticket replay attacks.
        
        Pattern: Same user+resource accessed from different sources within
        a short time window (impossible without credential/token theft).
        
        Works for:
        - Entra ID: Same token used from different IPs
        - Kerberos: Same TGS requested from different workstations
        """
        anomalies = []
        
        # Group by user + target resource
        sessions: Dict[Tuple[str, str], List[AuthEvent]] = defaultdict(list)
        for event in events:
            if event.result != "success":
                continue
            key = (event.user_name, event.target_resource or "default")
            sessions[key].append(event)
        
        for (user, resource), session_events in sessions.items():
            # Sort by timestamp
            sorted_events = sorted(session_events, key=lambda x: x.timestamp)
            
            for i in range(1, len(sorted_events)):
                prev = sorted_events[i-1]
                curr = sorted_events[i]
                
                # Get source identifiers
                prev_source = prev.source_ip or prev.source_host
                curr_source = curr.source_ip or curr.source_host
                
                if not prev_source or not curr_source:
                    continue
                
                if prev_source == curr_source:
                    continue
                
                time_diff_minutes = (curr.timestamp - prev.timestamp).total_seconds() / 60
                
                if time_diff_minutes <= self.replay_window_minutes:
                    anomalies.append(BehavioralAnomaly(
                        anomaly_type="TOKEN_REPLAY",
                        severity="CRITICAL",
                        user=user,
                        description=f"Same session from {prev_source} then {curr_source} in {time_diff_minutes:.1f} min",
                        timestamp=curr.timestamp,
                        evidence={
                            "resource": resource,
                            "source1": prev_source,
                            "source2": curr_source,
                            "time1": prev.timestamp.isoformat(),
                            "time2": curr.timestamp.isoformat(),
                            "delta_minutes": round(time_diff_minutes, 1),
                        },
                    ))
        
        return anomalies
    
    # ─────────────────────────────────────────────────────────────────────────
    # Impossible Travel Detection
    # ─────────────────────────────────────────────────────────────────────────
    
    def detect_impossible_travel(self, events: List[AuthEvent]) -> List[BehavioralAnomaly]:
        """
        Detect physically impossible travel between authentication locations.
        
        For Entra: Uses GeoIP coordinates from sign-in logs
        For On-Prem: Uses subnet-to-location mapping (if configured)
        """
        anomalies = []
        
        # Group by user
        by_user: Dict[str, List[AuthEvent]] = defaultdict(list)
        for event in events:
            if event.result != "success":
                continue
            
            # Need location data
            has_coords = (
                event.location and 
                event.location.get("lat") is not None and 
                event.location.get("lon") is not None
            )
            has_subnet_location = (
                event.source_ip and 
                self._get_subnet_location(event.source_ip)
            )
            
            if has_coords or has_subnet_location:
                by_user[event.user_name].append(event)
        
        for user, user_events in by_user.items():
            sorted_events = sorted(user_events, key=lambda x: x.timestamp)
            
            for i in range(1, len(sorted_events)):
                prev = sorted_events[i-1]
                curr = sorted_events[i]
                
                # Get locations
                prev_loc = self._get_event_location(prev)
                curr_loc = self._get_event_location(curr)
                
                if not prev_loc or not curr_loc:
                    continue
                
                # Skip if same location
                if prev_loc["name"] == curr_loc["name"]:
                    continue
                
                # Calculate distance and time
                if prev_loc.get("lat") and curr_loc.get("lat"):
                    distance_km = haversine_km(
                        prev_loc["lat"], prev_loc["lon"],
                        curr_loc["lat"], curr_loc["lon"]
                    )
                else:
                    # For subnet-based locations without coords, assume significant distance
                    distance_km = 500  # Conservative estimate
                
                time_hours = (curr.timestamp - prev.timestamp).total_seconds() / 3600
                
                if time_hours <= 0:
                    continue
                
                required_speed = distance_km / time_hours
                
                # Flag if impossible (faster than max speed and significant distance)
                if required_speed > self.travel_max_speed_kmh and distance_km > 100:
                    anomalies.append(BehavioralAnomaly(
                        anomaly_type="IMPOSSIBLE_TRAVEL",
                        severity="HIGH",
                        user=user,
                        description=f"Travel from {prev_loc['name']} to {curr_loc['name']} requires {required_speed:.0f} km/h",
                        timestamp=curr.timestamp,
                        evidence={
                            "from_location": prev_loc["name"],
                            "to_location": curr_loc["name"],
                            "from_ip": prev.source_ip,
                            "to_ip": curr.source_ip,
                            "distance_km": round(distance_km),
                            "time_hours": round(time_hours, 2),
                            "required_speed_kmh": round(required_speed),
                        },
                    ))
        
        return anomalies
    
    def _get_subnet_location(self, ip: str) -> Optional[str]:
        """Map IP to location based on configured subnet mappings."""
        if not ip:
            return None
        for prefix, location in self.subnet_locations.items():
            if ip.startswith(prefix):
                return location
        return None
    
    def _get_event_location(self, event: AuthEvent) -> Optional[Dict]:
        """Get location info from event (GeoIP or subnet-based)."""
        # Try GeoIP first
        if event.location and event.location.get("lat"):
            city = event.location.get("city", "")
            country = event.location.get("country", "")
            return {
                "name": f"{city}, {country}".strip(", ") or "Unknown",
                "lat": event.location["lat"],
                "lon": event.location["lon"],
            }
        
        # Try subnet mapping
        subnet_loc = self._get_subnet_location(event.source_ip)
        if subnet_loc:
            return {"name": subnet_loc, "lat": None, "lon": None}
        
        return None
    
    # ─────────────────────────────────────────────────────────────────────────
    # Lateral Movement Detection
    # ─────────────────────────────────────────────────────────────────────────
    
    def detect_lateral_movement(self, events: List[AuthEvent]) -> List[BehavioralAnomaly]:
        """
        Detect potential lateral movement patterns.
        
        Pattern: User authenticating to many different resources/hosts
        within a short time window.
        
        For Entra: Multiple apps/services accessed
        For On-Prem: Multiple hosts authenticated to
        """
        anomalies = []
        
        # Group by user + hourly window
        by_user_window: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
        
        for event in events:
            if event.result != "success":
                continue
            
            target = event.target_resource or event.source_host
            if not target or target == "-":
                continue
            
            # Create hourly window key
            window_key = event.timestamp.strftime("%Y-%m-%d-%H")
            by_user_window[event.user_name][window_key].add(target)
        
        for user, windows in by_user_window.items():
            for window_key, targets in windows.items():
                if len(targets) >= self.lateral_movement_threshold:
                    anomalies.append(BehavioralAnomaly(
                        anomaly_type="LATERAL_MOVEMENT",
                        severity="HIGH" if len(targets) >= 10 else "MEDIUM",
                        user=user,
                        description=f"Accessed {len(targets)} resources in 1 hour",
                        evidence={
                            "window": window_key,
                            "target_count": len(targets),
                            "targets": list(targets)[:20],
                        },
                        affected_count=len(targets),
                    ))
        
        return anomalies


# ─────────────────────────────────────────────────────────────────────────────
# Service Account Behavioral Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class ServiceAccountAnalyzer:
    """
    Specialized analyzer for service account behavioral anomalies.
    
    Service accounts should have:
    - Limited, predictable source IPs/hosts
    - No interactive logons
    - Consistent authentication patterns
    """
    
    SERVICE_PATTERNS = [
        "svc_", "svc-", "service", "_sa", "-sa",
        "sql", "iis", "app_", "task_", "batch_",
        "msol_", "aad_", "sync_",  # Azure AD Connect
    ]
    
    def __init__(
        self,
        service_accounts: Optional[List[str]] = None,
        source_threshold: int = 3,
    ):
        """
        Args:
            service_accounts: Explicit list of service account names
            source_threshold: Max sources before flagging (default 3)
        """
        self.explicit_service_accounts = set(
            s.lower() for s in (service_accounts or [])
        )
        self.source_threshold = source_threshold
    
    def is_service_account(self, username: str) -> bool:
        """Determine if username is likely a service account."""
        username_lower = username.lower()
        
        # Check explicit list
        if username_lower in self.explicit_service_accounts:
            return True
        
        # Check patterns
        return any(p in username_lower for p in self.SERVICE_PATTERNS)
    
    def analyze(self, events: List[AuthEvent]) -> List[BehavioralAnomaly]:
        """Analyze service account behavior for anomalies."""
        anomalies = []
        
        # Filter to service account events
        svc_events: Dict[str, List[AuthEvent]] = defaultdict(list)
        for event in events:
            if self.is_service_account(event.user_name):
                svc_events[event.user_name].append(event)
        
        for account, account_events in svc_events.items():
            # Check source diversity
            sources = set()
            interactive_logons = []
            
            for event in account_events:
                source = event.source_ip or event.source_host
                if source and source not in ("-", "::1", "127.0.0.1"):
                    sources.add(source)
                
                if event.is_interactive and event.result == "success":
                    interactive_logons.append(event)
            
            # Flag high source diversity
            if len(sources) >= self.source_threshold:
                severity = "CRITICAL" if len(sources) >= 10 else "HIGH"
                anomalies.append(BehavioralAnomaly(
                    anomaly_type="SERVICE_ACCOUNT_SOURCE_DIVERSITY",
                    severity=severity,
                    user=account,
                    description=f"Service account authenticating from {len(sources)} sources",
                    evidence={
                        "sources": list(sources)[:20],
                        "event_count": len(account_events),
                    },
                    affected_count=len(sources),
                ))
            
            # Flag interactive logons
            for event in interactive_logons:
                anomalies.append(BehavioralAnomaly(
                    anomaly_type="SERVICE_ACCOUNT_INTERACTIVE",
                    severity="CRITICAL",
                    user=account,
                    description=f"Service account used for interactive logon",
                    timestamp=event.timestamp,
                    evidence={
                        "source": event.source_ip or event.source_host,
                        "auth_method": event.auth_method,
                    },
                ))
        
        return anomalies


# ─────────────────────────────────────────────────────────────────────────────
# Event Normalizers - Convert source-specific events to AuthEvent
# ─────────────────────────────────────────────────────────────────────────────

def normalize_entra_signin(signin: Any) -> AuthEvent:
    """
    Convert Entra ID sign-in to AuthEvent.
    
    Args:
        signin: EntraSignIn object or dict from Graph API
    """
    if hasattr(signin, "timestamp"):
        # EntraSignIn object
        location = None
        if signin.location:
            location = {
                "city": signin.location.get("city"),
                "country": signin.location.get("countryOrRegion"),
                "lat": signin.location.get("geoCoordinates", {}).get("latitude"),
                "lon": signin.location.get("geoCoordinates", {}).get("longitude"),
            }
        
        return AuthEvent(
            timestamp=signin.timestamp,
            user_id=signin.user_id,
            user_name=signin.user_principal_name,
            source_ip=signin.ip_address,
            target_resource=signin.app_display_name,
            event_type="entra_signin",
            result="success" if signin.result_type == 0 else "failure",
            location=location,
            auth_method=signin.auth_requirement,
            is_interactive=signin.is_interactive if hasattr(signin, "is_interactive") else True,
            raw_event=signin.__dict__ if hasattr(signin, "__dict__") else signin,
        )
    else:
        # Dict from Graph API
        location = None
        loc_data = signin.get("location", {})
        if loc_data:
            geo = loc_data.get("geoCoordinates", {})
            location = {
                "city": loc_data.get("city"),
                "country": loc_data.get("countryOrRegion"),
                "lat": geo.get("latitude"),
                "lon": geo.get("longitude"),
            }
        
        # Parse timestamp
        ts_str = signin.get("createdDateTime", "")
        try:
            timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            timestamp = datetime.now(timezone.utc)
        
        return AuthEvent(
            timestamp=timestamp,
            user_id=signin.get("userId", ""),
            user_name=signin.get("userPrincipalName", ""),
            source_ip=signin.get("ipAddress"),
            target_resource=signin.get("appDisplayName"),
            event_type="entra_signin",
            result="success" if signin.get("status", {}).get("errorCode") == 0 else "failure",
            location=location,
            auth_method=signin.get("authenticationRequirement"),
            is_interactive=signin.get("isInteractive", True),
            raw_event=signin,
        )


def normalize_windows_event(event: Dict) -> AuthEvent:
    """
    Convert Windows Security Event to AuthEvent.
    
    Handles:
    - 4624: Logon
    - 4768: Kerberos TGT request
    - 4769: Kerberos TGS request
    - 4776: NTLM authentication
    """
    event_id = event.get("EventID")
    timestamp = event.get("TimeCreated")
    
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except ValueError:
            timestamp = datetime.now(timezone.utc)
    
    # Determine if interactive
    logon_type = event.get("LogonType")
    is_interactive = logon_type in (2, 10, 11) if logon_type else False
    
    # Map event type
    event_type_map = {
        4624: "logon",
        4768: "tgt",
        4769: "tgs",
        4776: "ntlm",
    }
    
    return AuthEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        user_id=event.get("TargetUserSid", ""),
        user_name=event.get("TargetUserName", "") or event.get("AccountName", ""),
        source_ip=event.get("IpAddress"),
        source_host=event.get("WorkstationName"),
        target_resource=event.get("ServiceName") or event.get("TargetServerName"),
        event_type=event_type_map.get(event_id, "auth"),
        result="success" if event.get("Status") in (None, "0x0", 0) else "failure",
        is_interactive=is_interactive,
        raw_event=event,
    )


def normalize_adfs_event(event: Dict) -> AuthEvent:
    """Convert ADFS audit event to AuthEvent."""
    event_id = event.get("EventID")
    timestamp = event.get("TimeCreated")
    
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except ValueError:
            timestamp = datetime.now(timezone.utc)
    
    # ADFS event IDs
    # 1200: Token issued successfully
    # 1201: Token request failed
    result = "success" if event_id == 1200 else "failure"
    
    return AuthEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        user_id=event.get("UserSid", ""),
        user_name=event.get("UserName", ""),
        source_ip=event.get("IpAddress") or event.get("ClientIP"),
        target_resource=event.get("RelyingParty"),
        event_type="adfs",
        result=result,
        raw_event=event,
    )
