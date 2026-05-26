# ADVulture Enhancement Plan
## Incorporating Learnings from entra_assessment.py

This document outlines enhancements to ADVulture based on proven capabilities
developed and tuned in the ModernCRA/Entra/entra_assessment.py tool.

---

## Part 1: Entra ID Module Enhancements

### 1.1 Security Defaults Detection
**Source:** entra_assessment.py module_01_tenant (lines 732-759)

**Current Gap:** ADVulture collects CA policies but doesn't check Security Defaults status.

**Enhancement:**
```python
# Add to EntraEnumerator or EntraLogIngester
async def _get_security_defaults(self) -> dict:
    """Check if Security Defaults are enabled/disabled."""
    try:
        # Use beta endpoint for security defaults
        result = await client.policies.identity_security_defaults_enforcement_policy.get()
        return {
            "enabled": result.is_enabled if result else None,
            "id": result.id if result else None,
        }
    except Exception as e:
        log.debug("Security Defaults check failed: %s", e)
        return {"enabled": None, "error": str(e)}
```

**Finding to Generate:**
- CRITICAL if disabled AND no CA policies exist
- HIGH if disabled (CA policies may compensate)
- INFO if enabled (baseline protection active)

---

### 1.2 Token Replay Detection
**Source:** entra_assessment.py module_07_signins (lines 1301-1341)

**Current Gap:** ADVulture collects sign-ins but doesn't analyze for replay patterns.

**Enhancement:** Add to `EntraEventStream` analysis:
```python
def detect_token_replay(self, signins: List[EntraSignIn], window_minutes: int = 10) -> List[dict]:
    """
    Detect potential token replay: same token/session used from different IPs
    within a short time window (impossible without token theft).
    """
    replay_indicators = []
    
    # Group by user + app + auth session
    sessions = defaultdict(list)
    for s in signins:
        if s.result == SignInResult.SUCCESS:
            key = (s.user_id, s.app_display_name)
            sessions[key].append(s)
    
    for (user_id, app), events in sessions.items():
        events_sorted = sorted(events, key=lambda x: x.timestamp)
        for i in range(1, len(events_sorted)):
            prev, curr = events_sorted[i-1], events_sorted[i]
            time_diff = (curr.timestamp - prev.timestamp).total_seconds() / 60
            
            if time_diff <= window_minutes and prev.ip_address != curr.ip_address:
                # Same user+app, different IP, within window = suspicious
                replay_indicators.append({
                    "user": curr.user_principal_name,
                    "app": app,
                    "ip1": prev.ip_address,
                    "ip2": curr.ip_address,
                    "time1": prev.timestamp.isoformat(),
                    "time2": curr.timestamp.isoformat(),
                    "delta_minutes": round(time_diff, 1),
                })
    
    return replay_indicators
```

**Finding:** CRITICAL severity - indicates active token theft/replay attack.

---

### 1.3 Impossible Travel Detection
**Source:** entra_assessment.py module_07_signins (lines 1477-1540)

**Current Gap:** ADVulture doesn't calculate geographic feasibility.

**Enhancement:**
```python
from math import radians, sin, cos, sqrt, atan2

def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate distance between two points on Earth in kilometers."""
    R = 6371  # Earth's radius in km
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
    return R * 2 * atan2(sqrt(a), sqrt(1-a))

def detect_impossible_travel(self, signins: List[EntraSignIn], max_speed_kmh: int = 1000) -> List[dict]:
    """
    Detect physically impossible travel between consecutive sign-ins.
    Default max_speed assumes commercial aviation (~1000 km/h).
    """
    impossible = []
    
    by_user = defaultdict(list)
    for s in signins:
        if s.result == SignInResult.SUCCESS and s.location:
            by_user[s.user_id].append(s)
    
    for user_id, events in by_user.items():
        events_sorted = sorted(events, key=lambda x: x.timestamp)
        for i in range(1, len(events_sorted)):
            prev, curr = events_sorted[i-1], events_sorted[i]
            
            # Skip if missing coordinates
            if not (prev.location.get('lat') and curr.location.get('lat')):
                continue
            
            distance_km = haversine_km(
                prev.location['lat'], prev.location['lon'],
                curr.location['lat'], curr.location['lon']
            )
            time_hours = (curr.timestamp - prev.timestamp).total_seconds() / 3600
            
            if time_hours > 0:
                required_speed = distance_km / time_hours
                if required_speed > max_speed_kmh and distance_km > 500:
                    impossible.append({
                        "user": curr.user_principal_name,
                        "from_location": f"{prev.location.get('city')}, {prev.location.get('country')}",
                        "to_location": f"{curr.location.get('city')}, {curr.location.get('country')}",
                        "distance_km": round(distance_km),
                        "time_hours": round(time_hours, 2),
                        "required_speed_kmh": round(required_speed),
                        "from_ip": prev.ip_address,
                        "to_ip": curr.ip_address,
                    })
    
    return impossible
```

**Finding:** HIGH severity - indicates VPN evasion, credential sharing, or token theft.

---

### 1.4 Behavioral Analysis Module
**Source:** entra_assessment.py module_15_signin_behavioral (lines 2853-2995)

**Current Gap:** ADVulture lacks behavioral baseline analysis entirely.

**New Module:** Create `advulture/analysis/behavioral.py`

```python
class BehavioralAnalyzer:
    """Analyze sign-in patterns for anomalies."""
    
    def analyze_off_hours(self, signins: List[EntraSignIn], 
                          business_start: int = 6, business_end: int = 22) -> dict:
        """
        Detect authentication outside business hours (weekends, late night).
        Returns users with 5+ off-hours events.
        """
        off_hours_by_user = defaultdict(list)
        
        for s in signins:
            if s.result != SignInResult.SUCCESS:
                continue
            hour = s.timestamp.hour
            weekday = s.timestamp.weekday()
            
            is_weekend = weekday >= 5
            is_late_night = hour < business_start or hour >= business_end
            
            if is_weekend or is_late_night:
                off_hours_by_user[s.user_principal_name].append(s.timestamp)
        
        return {
            upn: times for upn, times in off_hours_by_user.items()
            if len(times) >= 5
        }
    
    def analyze_ip_diversity(self, signins: List[EntraSignIn], threshold: int = 10) -> dict:
        """
        Detect users authenticating from unusually many distinct IPs.
        High diversity may indicate credential sharing or compromise.
        """
        ips_by_user = defaultdict(set)
        locations_by_user = defaultdict(set)
        
        for s in signins:
            if s.result == SignInResult.SUCCESS and s.ip_address:
                ips_by_user[s.user_principal_name].add(s.ip_address)
                if s.location:
                    loc = f"{s.location.get('city', '')}, {s.location.get('country', '')}"
                    locations_by_user[s.user_principal_name].add(loc.strip(', '))
        
        return {
            upn: {"ips": list(ips), "locations": list(locations_by_user[upn])}
            for upn, ips in ips_by_user.items()
            if len(ips) >= threshold
        }
    
    def analyze_sharepoint_geo(self, signins: List[EntraSignIn], threshold: int = 3) -> dict:
        """
        Detect SharePoint/OneDrive access from multiple geographic locations.
        Data exfiltration often involves accessing file storage from unusual locations.
        """
        sp_locations_by_user = defaultdict(set)
        
        for s in signins:
            if s.result != SignInResult.SUCCESS:
                continue
            app_lower = (s.app_display_name or '').lower()
            if 'sharepoint' not in app_lower and 'onedrive' not in app_lower:
                continue
            if s.location:
                loc = f"{s.location.get('city', '')}, {s.location.get('country', '')}"
                sp_locations_by_user[s.user_principal_name].add(loc.strip(', '))
        
        return {
            upn: list(locs) for upn, locs in sp_locations_by_user.items()
            if len(locs) >= threshold
        }
```

---

### 1.5 PIM Policy Quality Assessment
**Source:** entra_assessment.py module_13_pim (lines 2340-2500)

**Current Gap:** ADVulture collects PIM assignments but doesn't evaluate policy quality.

**Enhancement:** Add policy rule extraction and quality checks:
```python
async def _get_pim_policy_rules(self) -> Dict[str, dict]:
    """
    Fetch PIM policy rules to assess MFA, approval, and justification requirements.
    """
    policy_quality = {}
    
    try:
        # Get role management policy assignments
        assignments = await client.policies.role_management_policy_assignments.get()
        
        for pa in (assignments.value or []):
            role_def_id = pa.role_definition_id
            policy_id = pa.policy_id
            
            # Get the actual policy rules
            rules = await client.policies.role_management_policies.by_id(policy_id).rules.get()
            
            mfa_required = False
            approval_required = False
            justification_required = False
            
            for rule in (rules.value or []):
                rule_type = rule.odata_type or ''
                
                if 'AuthenticationContextRule' in rule_type:
                    # Check for MFA claim requirement
                    if rule.claim_value:
                        mfa_required = True
                        
                elif 'ApprovalRule' in rule_type:
                    if rule.setting and rule.setting.is_approval_required:
                        approval_required = True
                        
                elif 'EnablementRule' in rule_type:
                    enabled_rules = rule.enabled_rules or []
                    if 'Justification' in enabled_rules:
                        justification_required = True
                    if 'MultiFactorAuthentication' in enabled_rules:
                        mfa_required = True
            
            policy_quality[role_def_id] = {
                "mfa_required": mfa_required,
                "approval_required": approval_required,
                "justification_required": justification_required,
            }
    
    except Exception as e:
        log.warning("PIM policy rule extraction failed: %s", e)
    
    return policy_quality
```

**Finding Logic:**
- CRITICAL: Global Administrator eligible without MFA requirement
- HIGH: Any privileged role eligible without MFA
- MEDIUM: Privileged roles without approval or justification

---

### 1.6 Enhanced CA Policy Analysis
**Source:** entra_assessment.py module_04_ca (lines 901-980)

**Current Gap:** ADVulture collects CA policies but doesn't evaluate for specific gaps.

**Enhancement:** Add targeted gap detection:
```python
def analyze_ca_gaps(self, ca_policies: List[dict], security_defaults_enabled: bool) -> List[dict]:
    """
    Analyze CA policies for critical security gaps.
    """
    gaps = []
    
    has_universal_mfa = False
    has_legacy_auth_block = False
    has_guest_mfa = False
    
    for policy in ca_policies:
        if policy.get('state') != 'enabled':
            continue
        
        conditions = policy.get('conditions', {})
        grant_controls = policy.get('grantControls', {})
        built_in = grant_controls.get('builtInControls', [])
        
        users = conditions.get('users', {})
        apps = conditions.get('applications', {})
        client_app_types = conditions.get('clientAppTypes', [])
        
        include_users = users.get('includeUsers', []) if users else []
        include_apps = apps.get('includeApplications', []) if apps else []
        
        # Check for universal MFA (All Users + All Apps + MFA)
        if ('All' in include_users and 'All' in include_apps and 
            'mfa' in [c.lower() for c in built_in]):
            has_universal_mfa = True
        
        # Check for legacy auth blocking
        if 'other' in [c.lower() for c in client_app_types]:
            if 'block' in [c.lower() for c in built_in]:
                has_legacy_auth_block = True
        
        # Check for guest MFA
        if 'GuestsOrExternalUsers' in include_users:
            if 'mfa' in [c.lower() for c in built_in]:
                has_guest_mfa = True
    
    if not has_universal_mfa and not security_defaults_enabled:
        gaps.append({
            "type": "NO_UNIVERSAL_MFA",
            "severity": "CRITICAL",
            "description": "No CA policy enforces MFA for all users across all apps",
        })
    
    if not has_legacy_auth_block and not security_defaults_enabled:
        gaps.append({
            "type": "LEGACY_AUTH_NOT_BLOCKED",
            "severity": "HIGH",
            "description": "Legacy authentication protocols not blocked via CA policy. "
                          "Target 'Other clients' (not 'Exchange ActiveSync') to block.",
        })
    
    if not has_guest_mfa:
        gaps.append({
            "type": "NO_GUEST_MFA",
            "severity": "MEDIUM",
            "description": "No CA policy requires MFA for guest/external users",
        })
    
    return gaps
```

---

### 1.7 DNS Email Security (SPF/DKIM/DMARC)
**Source:** entra_assessment.py module_16_dns_and_user_hygiene (lines 2998-3095)

**Current Gap:** ADVulture has this in entra_report.py but uses dnspython dependency.

**Enhancement:** Use subprocess/nslookup approach (no external dependency):
```python
import subprocess
import re

def check_email_security(self, domains: List[str]) -> List[dict]:
    """
    Check SPF/DKIM/DMARC for tenant domains using nslookup (no dependencies).
    """
    results = []
    
    for domain in domains:
        if domain.endswith('.onmicrosoft.com'):
            continue
        
        result = {"domain": domain, "spf": False, "dkim": False, "dmarc": False, "dmarc_policy": None}
        
        # SPF check
        try:
            proc = subprocess.run(
                ["nslookup", "-type=TXT", domain],
                capture_output=True, text=True, timeout=10
            )
            if "v=spf1" in proc.stdout.lower():
                result["spf"] = True
        except Exception:
            pass
        
        # DMARC check
        try:
            proc = subprocess.run(
                ["nslookup", "-type=TXT", f"_dmarc.{domain}"],
                capture_output=True, text=True, timeout=10
            )
            if "v=dmarc1" in proc.stdout.lower():
                result["dmarc"] = True
                match = re.search(r"p=([a-z]+)", proc.stdout, re.IGNORECASE)
                if match:
                    result["dmarc_policy"] = match.group(1).lower()
        except Exception:
            pass
        
        # DKIM check (M365 default selectors)
        for selector in ("selector1", "selector2"):
            try:
                proc = subprocess.run(
                    ["nslookup", "-type=TXT", f"{selector}._domainkey.{domain}"],
                    capture_output=True, text=True, timeout=10
                )
                if "p=" in proc.stdout:
                    result["dkim"] = True
                    break
            except Exception:
                pass
        
        results.append(result)
    
    return results
```

---

## Part 2: On-Premise AD Module Enhancements

These enhancements provide equivalent detection capabilities for pure on-premise
Active Directory environments, matching the depth of Entra enhancements.

### 2.1 Security Baseline Assessment (Equivalent to Security Defaults)
**Entra Equivalent:** Security Defaults detection

On-premise AD doesn't have "Security Defaults" but has equivalent GPO-based
security baselines that should be assessed.

```python
class OnPremSecurityBaseline:
    """Assess on-premise AD security baseline configuration."""
    
    def __init__(self, snapshot: ADSnapshot, gpo_data: dict):
        self.snapshot = snapshot
        self.gpo_data = gpo_data
    
    def assess_password_policy(self) -> dict:
        """
        Check Default Domain Policy password settings.
        Equivalent to Entra's password policies.
        """
        findings = []
        policy = self.gpo_data.get('default_domain_policy', {})
        
        min_length = policy.get('MinimumPasswordLength', 0)
        max_age = policy.get('MaximumPasswordAge', 0)
        complexity = policy.get('PasswordComplexity', False)
        history = policy.get('PasswordHistorySize', 0)
        lockout_threshold = policy.get('LockoutBadCount', 0)
        
        if min_length < 14:
            findings.append({
                "type": "WEAK_PASSWORD_LENGTH",
                "severity": "HIGH",
                "current": min_length,
                "recommended": 14,
                "description": f"Minimum password length is {min_length} (recommend 14+)",
            })
        
        if not complexity:
            findings.append({
                "type": "NO_COMPLEXITY",
                "severity": "HIGH",
                "description": "Password complexity requirement disabled",
            })
        
        if lockout_threshold == 0:
            findings.append({
                "type": "NO_LOCKOUT",
                "severity": "CRITICAL",
                "description": "Account lockout disabled - enables unlimited password spray",
            })
        elif lockout_threshold > 10:
            findings.append({
                "type": "HIGH_LOCKOUT_THRESHOLD",
                "severity": "MEDIUM",
                "current": lockout_threshold,
                "recommended": "5-10",
                "description": f"Lockout threshold {lockout_threshold} allows many attempts",
            })
        
        if history < 24:
            findings.append({
                "type": "LOW_PASSWORD_HISTORY",
                "severity": "LOW",
                "current": history,
                "recommended": 24,
                "description": "Low password history enables password cycling",
            })
        
        return {
            "policy": policy,
            "findings": findings,
            "compliant": len([f for f in findings if f['severity'] in ('CRITICAL', 'HIGH')]) == 0,
        }
    
    def assess_kerberos_policy(self) -> dict:
        """
        Check Kerberos policy settings for security issues.
        """
        findings = []
        policy = self.gpo_data.get('kerberos_policy', {})
        
        max_ticket_age = policy.get('MaxTicketAge', 10)  # hours
        max_service_age = policy.get('MaxServiceAge', 600)  # minutes
        max_clock_skew = policy.get('MaxClockSkew', 5)  # minutes
        
        if max_ticket_age > 10:
            findings.append({
                "type": "LONG_TGT_LIFETIME",
                "severity": "MEDIUM",
                "current": max_ticket_age,
                "recommended": 10,
                "description": f"TGT lifetime {max_ticket_age}h extends attack window",
            })
        
        return {"policy": policy, "findings": findings}
    
    def assess_audit_policy(self) -> dict:
        """
        Check if critical security events are being audited.
        """
        findings = []
        audit = self.gpo_data.get('audit_policy', {})
        
        critical_categories = {
            'AuditLogonEvents': 'Logon/Logoff',
            'AuditAccountLogon': 'Account Logon (Kerberos)',
            'AuditPrivilegeUse': 'Privilege Use',
            'AuditObjectAccess': 'Object Access',
            'AuditPolicyChange': 'Policy Change',
            'AuditAccountManage': 'Account Management',
            'AuditDSAccess': 'Directory Service Access',
        }
        
        for setting, name in critical_categories.items():
            value = audit.get(setting, 'None')
            if value == 'None' or value == 'No Auditing':
                findings.append({
                    "type": "MISSING_AUDIT",
                    "severity": "HIGH",
                    "category": name,
                    "description": f"{name} auditing disabled - blind to attacks",
                })
            elif 'Success' not in value or 'Failure' not in value:
                findings.append({
                    "type": "INCOMPLETE_AUDIT",
                    "severity": "MEDIUM",
                    "category": name,
                    "current": value,
                    "description": f"{name} should audit both Success and Failure",
                })
        
        return {"audit_policy": audit, "findings": findings}
    
    def assess_laps_deployment(self) -> dict:
        """
        Check LAPS (Local Administrator Password Solution) deployment.
        Equivalent to checking for managed local admin credentials.
        """
        computers = self.snapshot.computers
        laps_enabled = [c for c in computers if c.laps_expiry is not None]
        laps_missing = [c for c in computers if c.laps_expiry is None and c.enabled]
        
        coverage = len(laps_enabled) / max(len(computers), 1) * 100
        
        finding = {
            "total_computers": len(computers),
            "laps_enabled": len(laps_enabled),
            "laps_missing": len(laps_missing),
            "coverage_pct": round(coverage, 1),
        }
        
        if coverage < 80:
            finding["severity"] = "HIGH"
            finding["description"] = f"LAPS coverage {coverage:.1f}% - local admin passwords at risk"
        elif coverage < 95:
            finding["severity"] = "MEDIUM"
            finding["description"] = f"LAPS coverage {coverage:.1f}% - some systems unprotected"
        else:
            finding["severity"] = "LOW"
            finding["description"] = f"LAPS coverage {coverage:.1f}% - good coverage"
        
        finding["missing_computers"] = [c.sam_account_name for c in laps_missing[:50]]
        
        return finding
```

---

### 2.2 Off-Hours Kerberos/NTLM Authentication
**Entra Equivalent:** Behavioral Analysis - Off-hours authentication

```python
def analyze_onprem_off_hours(self, events: List[dict], 
                              business_start: int = 6, 
                              business_end: int = 22) -> dict:
    """
    Detect off-hours authentication from Windows Security logs.
    Event IDs: 4624 (logon), 4769 (TGS request), 4776 (NTLM validation)
    
    This is the on-prem equivalent of Entra sign-in behavioral analysis.
    """
    off_hours_by_account = defaultdict(list)
    
    RELEVANT_EVENTS = {
        4624: "Interactive/Network Logon",
        4769: "Kerberos Service Ticket",
        4776: "NTLM Authentication",
        4768: "Kerberos TGT Request",
    }
    
    for event in events:
        event_id = event.get('EventID')
        if event_id not in RELEVANT_EVENTS:
            continue
        
        timestamp = event.get('TimeCreated')
        if not timestamp:
            continue
        
        hour = timestamp.hour
        weekday = timestamp.weekday()
        
        is_weekend = weekday >= 5
        is_late_night = hour < business_start or hour >= business_end
        
        if is_weekend or is_late_night:
            account = event.get('TargetUserName') or event.get('AccountName')
            # Skip computer accounts and system accounts
            if account and not account.endswith('$') and account.lower() not in ('system', 'anonymous logon'):
                off_hours_by_account[account].append({
                    'timestamp': timestamp,
                    'event_type': RELEVANT_EVENTS[event_id],
                    'source': event.get('IpAddress') or event.get('WorkstationName'),
                    'logon_type': event.get('LogonType'),
                })
    
    # Flag users with 5+ off-hours events
    flagged = {}
    for account, events_list in off_hours_by_account.items():
        if len(events_list) >= 5:
            flagged[account] = {
                "count": len(events_list),
                "events": events_list[:20],  # Sample
                "unique_sources": list(set(e['source'] for e in events_list if e['source'])),
            }
    
    return {
        "total_off_hours_events": sum(len(e) for e in off_hours_by_account.values()),
        "flagged_accounts": flagged,
        "severity": "MEDIUM" if flagged else "INFO",
    }
```

---

### 2.3 Service Account Behavioral Baseline
**Entra Equivalent:** IP diversity analysis + service principal monitoring

```python
class ServiceAccountAnalyzer:
    """
    Analyze service account behavior for anomalies.
    Service accounts should have predictable, limited authentication patterns.
    """
    
    def __init__(self, snapshot: ADSnapshot):
        self.snapshot = snapshot
        self.service_accounts = self._identify_service_accounts()
    
    def _identify_service_accounts(self) -> List[ADUser]:
        """Identify service accounts by SPN, naming, or group membership."""
        svc_accounts = []
        
        SERVICE_PATTERNS = [
            'svc_', 'svc-', 'service', '_sa', '-sa', 
            'sql', 'iis', 'app_', 'task_', 'batch_',
        ]
        
        for user in self.snapshot.users:
            is_service = False
            
            # Has SPN = definitely a service account
            if user.has_spn:
                is_service = True
            
            # Name pattern match
            sam_lower = user.sam_account_name.lower()
            if any(p in sam_lower for p in SERVICE_PATTERNS):
                is_service = True
            
            # In a service accounts OU
            if 'ou=service' in user.distinguished_name.lower():
                is_service = True
            
            if is_service:
                svc_accounts.append(user)
        
        return svc_accounts
    
    def analyze_source_diversity(self, events: List[dict]) -> dict:
        """
        Service accounts should authenticate from limited, predictable sources.
        High source diversity indicates potential compromise or misuse.
        """
        sources_by_svc = defaultdict(lambda: {"ips": set(), "workstations": set(), "events": []})
        
        svc_names = {u.sam_account_name.lower() for u in self.service_accounts}
        
        for event in events:
            account = (event.get('TargetUserName') or '').lower()
            if account not in svc_names:
                continue
            
            ip = event.get('IpAddress')
            workstation = event.get('WorkstationName')
            
            if ip and ip not in ('-', '::1', '127.0.0.1'):
                sources_by_svc[account]["ips"].add(ip)
            if workstation and workstation != '-':
                sources_by_svc[account]["workstations"].add(workstation)
            
            sources_by_svc[account]["events"].append(event.get('TimeCreated'))
        
        anomalies = []
        for account, data in sources_by_svc.items():
            total_sources = len(data["ips"]) + len(data["workstations"])
            
            if total_sources >= 5:
                severity = "CRITICAL" if total_sources >= 10 else "HIGH"
                anomalies.append({
                    "account": account,
                    "severity": severity,
                    "unique_ips": list(data["ips"]),
                    "unique_workstations": list(data["workstations"]),
                    "total_sources": total_sources,
                    "event_count": len(data["events"]),
                    "description": f"Service account authenticating from {total_sources} sources",
                })
            elif total_sources >= 3:
                anomalies.append({
                    "account": account,
                    "severity": "MEDIUM",
                    "unique_ips": list(data["ips"]),
                    "unique_workstations": list(data["workstations"]),
                    "total_sources": total_sources,
                    "event_count": len(data["events"]),
                })
        
        return {
            "service_accounts_analyzed": len(svc_names),
            "anomalies": anomalies,
        }
    
    def analyze_interactive_logons(self, events: List[dict]) -> List[dict]:
        """
        Service accounts should NOT have interactive logons.
        Interactive logon (type 2, 10, 11) indicates potential misuse.
        """
        INTERACTIVE_TYPES = {2: "Interactive", 10: "RemoteInteractive", 11: "CachedInteractive"}
        
        svc_names = {u.sam_account_name.lower() for u in self.service_accounts}
        interactive_logons = []
        
        for event in events:
            if event.get('EventID') != 4624:
                continue
            
            account = (event.get('TargetUserName') or '').lower()
            logon_type = event.get('LogonType')
            
            if account in svc_names and logon_type in INTERACTIVE_TYPES:
                interactive_logons.append({
                    "account": account,
                    "logon_type": INTERACTIVE_TYPES[logon_type],
                    "timestamp": event.get('TimeCreated'),
                    "workstation": event.get('WorkstationName'),
                    "source_ip": event.get('IpAddress'),
                    "severity": "HIGH",
                    "description": f"Service account {account} used for {INTERACTIVE_TYPES[logon_type]} logon",
                })
        
        return interactive_logons
```

---

### 2.4 Kerberos Ticket Replay Detection
**Entra Equivalent:** Token Replay detection

```python
def detect_ticket_replay(self, events: List[dict], window_minutes: int = 5) -> List[dict]:
    """
    Detect potential Kerberos ticket replay from 4769 events.
    Same service ticket requested from different sources in short window = theft.
    
    This is the on-prem equivalent of Entra token replay detection.
    """
    replay_indicators = []
    
    # Group by user + service
    tgs_requests = defaultdict(list)
    for event in events:
        if event.get('EventID') != 4769:
            continue
        if event.get('Status') != '0x0':  # Only successful requests
            continue
        
        # Skip computer accounts requesting their own tickets
        target = event.get('TargetUserName', '')
        if target.endswith('$'):
            continue
        
        key = (target, event.get('ServiceName'))
        tgs_requests[key].append({
            'timestamp': event.get('TimeCreated'),
            'source': event.get('IpAddress'),
            'encryption': event.get('TicketEncryptionType'),
        })
    
    for (user, service), requests in tgs_requests.items():
        requests_sorted = sorted(requests, key=lambda x: x['timestamp'])
        for i in range(1, len(requests_sorted)):
            prev, curr = requests_sorted[i-1], requests_sorted[i]
            time_diff = (curr['timestamp'] - prev['timestamp']).total_seconds() / 60
            
            if time_diff <= window_minutes and prev['source'] != curr['source']:
                replay_indicators.append({
                    "user": user,
                    "service": service,
                    "source1": prev['source'],
                    "source2": curr['source'],
                    "time1": prev['timestamp'].isoformat(),
                    "time2": curr['timestamp'].isoformat(),
                    "delta_minutes": round(time_diff, 1),
                    "severity": "CRITICAL",
                    "description": f"Same TGS for {service} from {prev['source']} then {curr['source']} in {time_diff:.1f}min",
                })
    
    return replay_indicators


def detect_tgt_anomalies(self, events: List[dict]) -> List[dict]:
    """
    Detect TGT request anomalies from 4768 events.
    - RC4 encryption (downgrade attack indicator)
    - Pre-auth disabled requests (AS-REP roasting)
    - Unusual encryption types
    """
    anomalies = []
    
    for event in events:
        if event.get('EventID') != 4768:
            continue
        
        account = event.get('TargetUserName', '')
        encryption = event.get('TicketEncryptionType', '')
        pre_auth = event.get('PreAuthType', '')
        status = event.get('Status', '')
        
        # RC4 downgrade (0x17 = RC4-HMAC)
        if encryption == '0x17':
            anomalies.append({
                "type": "RC4_TGT",
                "account": account,
                "timestamp": event.get('TimeCreated'),
                "source": event.get('IpAddress'),
                "severity": "HIGH",
                "description": f"TGT requested with RC4 encryption - potential downgrade attack",
            })
        
        # Pre-auth failure with specific status may indicate AS-REP roast attempt
        if status == '0x18':  # KDC_ERR_PREAUTH_FAILED
            anomalies.append({
                "type": "PREAUTH_FAILED",
                "account": account,
                "timestamp": event.get('TimeCreated'),
                "source": event.get('IpAddress'),
                "severity": "MEDIUM",
                "description": f"Pre-authentication failed for {account}",
            })
    
    return anomalies
```

---

### 2.5 Workstation-Based Impossible Travel
**Entra Equivalent:** Impossible Travel detection

For on-prem, we use workstation/subnet mapping instead of GeoIP.

```python
class OnPremTravelAnalyzer:
    """
    Detect impossible travel patterns using workstation/subnet topology.
    Requires subnet-to-location mapping configuration.
    """
    
    def __init__(self, subnet_locations: Dict[str, str] = None):
        """
        subnet_locations: mapping of subnet prefix to physical location
        e.g., {"10.1.": "New York HQ", "10.2.": "London Office", "192.168.5.": "Home VPN"}
        """
        self.subnet_locations = subnet_locations or {}
    
    def _get_location(self, ip: str) -> Optional[str]:
        """Map IP to location based on subnet."""
        if not ip:
            return None
        for prefix, location in self.subnet_locations.items():
            if ip.startswith(prefix):
                return location
        return f"Unknown ({ip})"
    
    def detect_location_anomalies(self, events: List[dict], 
                                   window_minutes: int = 30) -> List[dict]:
        """
        Detect rapid location changes that are physically implausible.
        Without GeoIP, we use subnet-to-office mapping.
        """
        anomalies = []
        
        by_user = defaultdict(list)
        for event in events:
            if event.get('EventID') not in (4624, 4769):
                continue
            
            account = event.get('TargetUserName', '')
            if account.endswith('$'):  # Skip computers
                continue
            
            ip = event.get('IpAddress')
            location = self._get_location(ip)
            
            by_user[account].append({
                'timestamp': event.get('TimeCreated'),
                'ip': ip,
                'location': location,
            })
        
        for account, auth_events in by_user.items():
            events_sorted = sorted(auth_events, key=lambda x: x['timestamp'])
            
            for i in range(1, len(events_sorted)):
                prev, curr = events_sorted[i-1], events_sorted[i]
                
                if prev['location'] == curr['location']:
                    continue
                if 'Unknown' in (prev['location'] or '') or 'Unknown' in (curr['location'] or ''):
                    continue
                
                time_diff = (curr['timestamp'] - prev['timestamp']).total_seconds() / 60
                
                if time_diff <= window_minutes:
                    anomalies.append({
                        "account": account,
                        "from_location": prev['location'],
                        "to_location": curr['location'],
                        "from_ip": prev['ip'],
                        "to_ip": curr['ip'],
                        "delta_minutes": round(time_diff, 1),
                        "severity": "HIGH",
                        "description": f"{account} authenticated from {prev['location']} then {curr['location']} in {time_diff:.1f}min",
                    })
        
        return anomalies
```

---

### 2.6 Lateral Movement Detection
**Entra Equivalent:** SharePoint multi-location access / IP diversity

```python
def detect_lateral_movement(self, events: List[dict], 
                            window_hours: int = 1,
                            threshold: int = 5) -> List[dict]:
    """
    Detect potential lateral movement patterns.
    User authenticating to many different systems in short window.
    
    This is the on-prem equivalent of high IP diversity detection.
    """
    lateral_indicators = []
    
    # Group by user within time windows
    by_user_window = defaultdict(lambda: defaultdict(set))
    
    for event in events:
        if event.get('EventID') not in (4624, 4769):
            continue
        
        account = event.get('TargetUserName', '')
        if account.endswith('$'):
            continue
        
        timestamp = event.get('TimeCreated')
        target = event.get('TargetServerName') or event.get('WorkstationName')
        
        if not target or target == '-':
            continue
        
        # Create hourly window key
        window_key = timestamp.strftime('%Y-%m-%d-%H')
        by_user_window[account][window_key].add(target)
    
    for account, windows in by_user_window.items():
        for window_key, targets in windows.items():
            if len(targets) >= threshold:
                lateral_indicators.append({
                    "account": account,
                    "window": window_key,
                    "target_count": len(targets),
                    "targets": list(targets)[:20],
                    "severity": "HIGH" if len(targets) >= 10 else "MEDIUM",
                    "description": f"{account} accessed {len(targets)} systems in 1 hour",
                })
    
    return lateral_indicators
```

---

### 2.7 Privileged Group Monitoring (Equivalent to PIM)
**Entra Equivalent:** PIM Policy Quality assessment

On-prem doesn't have PIM, but we can assess privileged group hygiene.

```python
class PrivilegedGroupAnalyzer:
    """
    Analyze privileged group membership - on-prem equivalent of PIM assessment.
    """
    
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
    }
    
    def __init__(self, snapshot: ADSnapshot):
        self.snapshot = snapshot
    
    def assess_privileged_membership(self) -> dict:
        """
        Assess privileged group membership hygiene.
        - Direct vs nested membership
        - Service accounts in privileged groups
        - Stale privileged accounts
        """
        findings = []
        
        for group in self.snapshot.groups:
            if group.sam_account_name not in self.TIER0_GROUPS:
                continue
            
            members = group.members
            
            # Find direct user members
            user_members = []
            for member_dn in members:
                user = next((u for u in self.snapshot.users 
                            if u.distinguished_name == member_dn), None)
                if user:
                    user_members.append(user)
            
            # Check for concerning patterns
            for user in user_members:
                # Service account in privileged group
                if user.has_spn:
                    findings.append({
                        "type": "SERVICE_ACCOUNT_PRIVILEGED",
                        "severity": "CRITICAL",
                        "account": user.sam_account_name,
                        "group": group.sam_account_name,
                        "description": f"Service account {user.sam_account_name} is member of {group.sam_account_name}",
                    })
                
                # Stale privileged account (no logon in 90+ days)
                if user.days_since_last_logon > 90:
                    findings.append({
                        "type": "STALE_PRIVILEGED_ACCOUNT",
                        "severity": "HIGH",
                        "account": user.sam_account_name,
                        "group": group.sam_account_name,
                        "days_inactive": user.days_since_last_logon,
                        "description": f"Privileged account {user.sam_account_name} inactive {user.days_since_last_logon:.0f} days",
                    })
                
                # Password never expires on privileged account
                if user.password_never_expires:
                    findings.append({
                        "type": "PRIVILEGED_PASSWORD_NEVER_EXPIRES",
                        "severity": "HIGH",
                        "account": user.sam_account_name,
                        "group": group.sam_account_name,
                        "description": f"Privileged account {user.sam_account_name} password never expires",
                    })
                
                # Old password on privileged account
                if user.password_age_days > 365:
                    findings.append({
                        "type": "PRIVILEGED_STALE_PASSWORD",
                        "severity": "MEDIUM",
                        "account": user.sam_account_name,
                        "group": group.sam_account_name,
                        "password_age_days": user.password_age_days,
                        "description": f"Privileged account {user.sam_account_name} password is {user.password_age_days:.0f} days old",
                    })
            
            # Too many members in privileged group
            if len(user_members) > 5:
                findings.append({
                    "type": "EXCESSIVE_PRIVILEGED_MEMBERS",
                    "severity": "MEDIUM",
                    "group": group.sam_account_name,
                    "member_count": len(user_members),
                    "members": [u.sam_account_name for u in user_members],
                    "description": f"{group.sam_account_name} has {len(user_members)} direct user members (recommend < 5)",
                })
        
        return {"findings": findings}
    
    def assess_adminsdholder(self) -> dict:
        """
        Check AdminSDHolder protection status.
        Accounts with adminCount=1 should be intentionally privileged.
        """
        protected_users = [u for u in self.snapshot.users if u.admin_count == 1]
        
        orphaned = []
        for user in protected_users:
            # Check if user is actually in a protected group
            is_in_protected_group = any(
                g.sam_account_name in self.TIER0_GROUPS 
                for g in self.snapshot.groups 
                if user.distinguished_name in g.members
            )
            
            if not is_in_protected_group:
                orphaned.append({
                    "account": user.sam_account_name,
                    "description": "adminCount=1 but not in protected group - may be orphaned",
                })
        
        return {
            "protected_users": len(protected_users),
            "orphaned_protection": orphaned,
        }
```

---

### 2.8 Authentication Policy Assessment
**Entra Equivalent:** CA Policy analysis

Windows Server 2012 R2+ supports Authentication Policies and Silos.

```python
def assess_auth_policies(self, snapshot: ADSnapshot) -> dict:
    """
    Assess Authentication Policies and Silos (Windows Server 2012 R2+).
    These are the on-prem equivalent of Conditional Access policies.
    """
    findings = []
    
    # Check if any auth policies exist
    # This would require LDAP query to CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,CN=Configuration
    
    # For now, check if Tier 0 accounts have "Account is sensitive" flag
    tier0_users = snapshot.tier0_users
    
    sensitive_flag_missing = []
    for user in tier0_users:
        # UAC flag 0x100000 = NOT_DELEGATED (account is sensitive)
        if not (user.user_account_control & 0x100000):
            sensitive_flag_missing.append(user.sam_account_name)
    
    if sensitive_flag_missing:
        findings.append({
            "type": "TIER0_MISSING_SENSITIVE_FLAG",
            "severity": "HIGH",
            "accounts": sensitive_flag_missing,
            "description": f"{len(sensitive_flag_missing)} Tier 0 accounts missing 'Account is sensitive and cannot be delegated'",
        })
    
    # Check Protected Users group membership for Tier 0
    protected_users_group = next(
        (g for g in snapshot.groups if g.sam_account_name == "Protected Users"), 
        None
    )
    
    if protected_users_group:
        protected_members = set(protected_users_group.members)
        tier0_not_protected = [
            u.sam_account_name for u in tier0_users 
            if u.distinguished_name not in protected_members
        ]
        
        if tier0_not_protected:
            findings.append({
                "type": "TIER0_NOT_IN_PROTECTED_USERS",
                "severity": "MEDIUM",
                "accounts": tier0_not_protected,
                "description": f"{len(tier0_not_protected)} Tier 0 accounts not in Protected Users group",
            })
    else:
        findings.append({
            "type": "NO_PROTECTED_USERS_GROUP",
            "severity": "INFO",
            "description": "Protected Users group not found - may indicate older domain functional level",
        })
    
    return {"findings": findings}

---

## Part 3: Hybrid/Joined Domain Enhancements

These enhancements address environments with Azure AD Connect synchronization,
hybrid Azure AD join, pass-through authentication, or ADFS federation.

### 3.1 Azure AD Connect Sync Account Monitoring
**Critical:** The sync account (MSOL_*) has DCSync-equivalent rights.

```python
class HybridSyncMonitor:
    """
    Monitor Azure AD Connect synchronization for security issues.
    The sync account is a high-value target - compromise = full domain compromise.
    """
    
    SYNC_ACCOUNT_PATTERNS = ['MSOL_', 'AAD_', 'Sync_']
    
    def __init__(self, snapshot: ADSnapshot, entra_snapshot=None):
        self.snapshot = snapshot
        self.entra_snapshot = entra_snapshot
        self.sync_accounts = self._find_sync_accounts()
    
    def _find_sync_accounts(self) -> List[ADUser]:
        """Identify Azure AD Connect sync accounts."""
        sync_accounts = []
        for user in self.snapshot.users:
            sam = user.sam_account_name
            if any(sam.startswith(p) for p in self.SYNC_ACCOUNT_PATTERNS):
                sync_accounts.append(user)
        return sync_accounts
    
    def assess_sync_account_security(self) -> dict:
        """
        Check sync account security posture.
        These accounts have DCSync rights by design - must be highly protected.
        """
        findings = []
        
        for account in self.sync_accounts:
            # Check if password is old (should be rotated with AAD Connect upgrades)
            if account.password_age_days > 180:
                findings.append({
                    "type": "SYNC_ACCOUNT_OLD_PASSWORD",
                    "severity": "MEDIUM",
                    "account": account.sam_account_name,
                    "password_age_days": account.password_age_days,
                    "description": f"Sync account {account.sam_account_name} password is {account.password_age_days:.0f} days old",
                })
            
            # Check if in Protected Users (should NOT be - breaks sync)
            # This is informational - just verify expected state
            
            # Check for unexpected group memberships
            privileged_memberships = [
                m for m in account.member_of 
                if any(g in m.lower() for g in ['admin', 'operator', 'schema'])
            ]
            # Note: Sync account needs specific rights, but not full Domain Admin
            if any('domain admins' in m.lower() for m in account.member_of):
                findings.append({
                    "type": "SYNC_ACCOUNT_DOMAIN_ADMIN",
                    "severity": "HIGH",
                    "account": account.sam_account_name,
                    "description": f"Sync account {account.sam_account_name} is Domain Admin - excessive rights",
                })
        
        if not self.sync_accounts:
            findings.append({
                "type": "NO_SYNC_ACCOUNT_FOUND",
                "severity": "INFO",
                "description": "No Azure AD Connect sync account found - may be cloud-only or using different sync method",
            })
        
        return {
            "sync_accounts": [a.sam_account_name for a in self.sync_accounts],
            "findings": findings,
        }
    
    def detect_sync_account_abuse(self, events: List[dict]) -> List[dict]:
        """
        Detect suspicious activity from sync accounts.
        Sync accounts should only authenticate from the AAD Connect server.
        """
        abuse_indicators = []
        sync_names = {a.sam_account_name.lower() for a in self.sync_accounts}
        
        # Track unique sources per sync account
        sources_by_account = defaultdict(set)
        
        for event in events:
            account = (event.get('TargetUserName') or '').lower()
            if account not in sync_names:
                continue
            
            source = event.get('IpAddress') or event.get('WorkstationName')
            logon_type = event.get('LogonType')
            
            if source:
                sources_by_account[account].add(source)
            
            # Interactive logon from sync account = very suspicious
            if logon_type in (2, 10, 11):  # Interactive, RemoteInteractive, CachedInteractive
                abuse_indicators.append({
                    "type": "SYNC_ACCOUNT_INTERACTIVE",
                    "severity": "CRITICAL",
                    "account": account,
                    "logon_type": logon_type,
                    "source": source,
                    "timestamp": event.get('TimeCreated'),
                    "description": f"Sync account {account} used for interactive logon from {source}",
                })
        
        # Flag if sync account authenticates from multiple sources
        for account, sources in sources_by_account.items():
            if len(sources) > 2:  # Should be 1-2 (AAD Connect server + maybe localhost)
                abuse_indicators.append({
                    "type": "SYNC_ACCOUNT_MULTIPLE_SOURCES",
                    "severity": "HIGH",
                    "account": account,
                    "sources": list(sources),
                    "description": f"Sync account {account} authenticating from {len(sources)} sources",
                })
        
        return abuse_indicators
```

---

### 3.2 Pass-Through Authentication Monitoring
**For PTA deployments:** Monitor the PTA agent authentication patterns.

```python
class PTAMonitor:
    """
    Monitor Pass-Through Authentication for anomalies.
    PTA agents forward auth requests - compromise = credential interception.
    """
    
    def detect_pta_anomalies(self, entra_signins: List, onprem_events: List[dict]) -> List[dict]:
        """
        Cross-reference Entra sign-ins with on-prem auth events for PTA environments.
        
        In PTA:
        1. User authenticates to Entra ID
        2. Entra sends auth request to PTA agent
        3. PTA agent validates against on-prem AD
        4. Result returned to Entra
        
        Anomaly: Entra shows successful PTA auth, but no corresponding on-prem event
        """
        anomalies = []
        
        # Get Entra sign-ins that used PTA
        pta_signins = [
            s for s in entra_signins 
            if 'pass-through' in (s.auth_detail or '').lower()
            or s.authentication_protocol == 'password'  # May indicate PTA
        ]
        
        # Build lookup of on-prem auth events by user+time (with tolerance)
        onprem_by_user_time = defaultdict(list)
        for event in onprem_events:
            if event.get('EventID') not in (4776, 4624):
                continue
            account = event.get('TargetUserName', '').lower()
            timestamp = event.get('TimeCreated')
            if account and timestamp:
                # Round to minute for matching
                time_key = timestamp.strftime('%Y-%m-%d-%H-%M')
                onprem_by_user_time[(account, time_key)].append(event)
        
        # Check for PTA sign-ins without corresponding on-prem events
        for signin in pta_signins:
            upn = signin.user_principal_name.lower()
            sam = upn.split('@')[0]  # Approximate SAM from UPN
            time_key = signin.timestamp.strftime('%Y-%m-%d-%H-%M')
            
            # Check this minute and adjacent minutes
            found_onprem = False
            for offset in [-1, 0, 1]:
                check_time = (signin.timestamp + timedelta(minutes=offset)).strftime('%Y-%m-%d-%H-%M')
                if onprem_by_user_time.get((sam, check_time)):
                    found_onprem = True
                    break
            
            if not found_onprem and signin.result == SignInResult.SUCCESS:
                anomalies.append({
                    "type": "PTA_NO_ONPREM_EVENT",
                    "severity": "HIGH",
                    "user": signin.user_principal_name,
                    "entra_timestamp": signin.timestamp.isoformat(),
                    "entra_ip": signin.ip_address,
                    "description": f"PTA sign-in for {upn} with no corresponding on-prem auth event",
                })
        
        return anomalies
```

---

### 3.3 Seamless SSO (AZUREADSSOACC) Monitoring
**For Seamless SSO:** The computer account holds the Kerberos decryption key.

```python
class SeamlessSSOMonitor:
    """
    Monitor the AZUREADSSOACC computer account.
    This account's password is the Kerberos decryption key for Seamless SSO.
    Compromise = forge SSO tokens for any user.
    """
    
    def find_sso_account(self, snapshot: ADSnapshot) -> Optional[ADComputer]:
        """Find the Seamless SSO computer account."""
        for computer in snapshot.computers:
            if computer.sam_account_name.upper() == 'AZUREADSSOACC$':
                return computer
        return None
    
    def assess_sso_account(self, snapshot: ADSnapshot) -> dict:
        """
        Assess Seamless SSO account security.
        Password should be rotated every 30 days (Microsoft recommendation).
        """
        findings = []
        sso_account = self.find_sso_account(snapshot)
        
        if not sso_account:
            return {
                "sso_enabled": False,
                "findings": [{
                    "type": "NO_SSO_ACCOUNT",
                    "severity": "INFO",
                    "description": "AZUREADSSOACC not found - Seamless SSO not configured",
                }],
            }
        
        # Check password age (attribute: pwdLastSet)
        # This is tricky for computer accounts - may need to check via different attribute
        
        # Check for unusual permissions on the account
        # Should only be readable by AAD Connect service
        
        findings.append({
            "type": "SSO_ACCOUNT_FOUND",
            "severity": "INFO",
            "description": "Seamless SSO is configured. Ensure AZUREADSSOACC password is rotated every 30 days.",
        })
        
        return {
            "sso_enabled": True,
            "account": sso_account.sam_account_name,
            "findings": findings,
        }
    
    def detect_sso_abuse(self, events: List[dict]) -> List[dict]:
        """
        Detect suspicious activity targeting the SSO account.
        Any Kerberos requests for AZUREADSSOACC are suspicious.
        """
        abuse_indicators = []
        
        for event in events:
            if event.get('EventID') != 4769:  # TGS request
                continue
            
            service_name = event.get('ServiceName', '').upper()
            if 'AZUREADSSOACC' in service_name:
                abuse_indicators.append({
                    "type": "SSO_ACCOUNT_TGS_REQUEST",
                    "severity": "CRITICAL",
                    "requesting_user": event.get('TargetUserName'),
                    "source_ip": event.get('IpAddress'),
                    "timestamp": event.get('TimeCreated'),
                    "description": f"TGS request for AZUREADSSOACC from {event.get('TargetUserName')} - potential Silver Ticket attack",
                })
        
        return abuse_indicators
```

---

### 3.4 Hybrid Identity Sync Discrepancy Detection
**Cross-reference Entra and on-prem for inconsistencies.**

```python
class HybridSyncValidator:
    """
    Validate consistency between on-prem AD and Entra ID.
    Discrepancies may indicate sync issues or malicious manipulation.
    """
    
    def __init__(self, ad_snapshot: ADSnapshot, entra_snapshot):
        self.ad_snapshot = ad_snapshot
        self.entra_snapshot = entra_snapshot
    
    def find_sync_discrepancies(self) -> dict:
        """
        Find users that exist in one directory but not the other,
        or have mismatched attributes.
        """
        findings = []
        
        # Build lookup by on-prem SID (immutableId in Entra is typically based on this)
        ad_users_by_sid = {u.sid: u for u in self.ad_snapshot.users}
        ad_users_by_upn = {u.user_principal_name.lower(): u for u in self.ad_snapshot.users if u.user_principal_name}
        
        entra_users_by_sid = {}
        entra_users_by_upn = {}
        for u in self.entra_snapshot.users:
            if u.on_prem_sid:
                entra_users_by_sid[u.on_prem_sid] = u
            if u.user_principal_name:
                entra_users_by_upn[u.user_principal_name.lower()] = u
        
        # Find synced Entra users with no on-prem match
        for entra_user in self.entra_snapshot.users:
            if not entra_user.on_prem_sync:
                continue  # Cloud-only user, skip
            
            if entra_user.on_prem_sid and entra_user.on_prem_sid not in ad_users_by_sid:
                findings.append({
                    "type": "ENTRA_USER_NO_ONPREM",
                    "severity": "HIGH",
                    "user": entra_user.user_principal_name,
                    "on_prem_sid": entra_user.on_prem_sid,
                    "description": f"Synced user {entra_user.user_principal_name} has no matching on-prem account",
                })
        
        # Find enabled state mismatches
        for sid, entra_user in entra_users_by_sid.items():
            ad_user = ad_users_by_sid.get(sid)
            if not ad_user:
                continue
            
            if entra_user.account_enabled != ad_user.enabled:
                findings.append({
                    "type": "ENABLED_STATE_MISMATCH",
                    "severity": "MEDIUM",
                    "user": entra_user.user_principal_name,
                    "entra_enabled": entra_user.account_enabled,
                    "ad_enabled": ad_user.enabled,
                    "description": f"User {entra_user.user_principal_name} enabled state differs: Entra={entra_user.account_enabled}, AD={ad_user.enabled}",
                })
        
        # Find privileged role mismatches
        # Users with Entra privileged roles should match on-prem privileged status
        for entra_user in self.entra_snapshot.users:
            if not entra_user.is_critical_role:
                continue
            if not entra_user.on_prem_sid:
                continue  # Cloud-only admin, expected
            
            ad_user = ad_users_by_sid.get(entra_user.on_prem_sid)
            if ad_user and ad_user.tier > 0:  # Not Tier 0 on-prem
                findings.append({
                    "type": "PRIVILEGED_ROLE_MISMATCH",
                    "severity": "MEDIUM",
                    "user": entra_user.user_principal_name,
                    "entra_roles": entra_user.assigned_roles,
                    "ad_tier": ad_user.tier,
                    "description": f"User {entra_user.user_principal_name} has Entra admin role but is Tier {ad_user.tier} on-prem",
                })
        
        return {"findings": findings}
    
    def detect_cloud_only_admins(self) -> List[dict]:
        """
        Find cloud-only accounts with privileged Entra roles.
        These bypass on-prem security controls entirely.
        """
        cloud_admins = []
        
        for user in self.entra_snapshot.users:
            if user.on_prem_sync:
                continue  # Synced user, not cloud-only
            
            if user.is_critical_role:
                cloud_admins.append({
                    "user": user.user_principal_name,
                    "roles": user.assigned_roles,
                    "mfa_registered": user.mfa_registered,
                    "severity": "INFO" if user.mfa_registered else "HIGH",
                    "description": f"Cloud-only admin {user.user_principal_name} with roles: {', '.join(user.assigned_roles[:3])}",
                })
        
        return cloud_admins
```

---

### 3.5 ADFS Federation Monitoring
**For ADFS environments:** Monitor federation trust and token issuance.

```python
class ADFSMonitor:
    """
    Monitor ADFS for security issues in federated authentication.
    """
    
    def analyze_adfs_events(self, adfs_events: List[dict]) -> dict:
        """
        Analyze ADFS audit events for anomalies.
        Event IDs: 
        - 1200: ADFS issued token successfully
        - 1201: ADFS token request failed
        - 1202-1203: Authentication events
        - 411: Token replay detected
        - 516: Extranet lockout
        """
        findings = []
        
        token_replays = []
        failed_auths_by_ip = defaultdict(list)
        extranet_lockouts = []
        successful_tokens = []
        
        for event in adfs_events:
            event_id = event.get('EventID')
            
            if event_id == 411:  # Token replay
                token_replays.append({
                    "timestamp": event.get('TimeCreated'),
                    "user": event.get('UserName'),
                    "source_ip": event.get('IpAddress'),
                })
            
            elif event_id == 1201:  # Failed auth
                ip = event.get('IpAddress')
                failed_auths_by_ip[ip].append(event)
            
            elif event_id == 516:  # Extranet lockout
                extranet_lockouts.append({
                    "timestamp": event.get('TimeCreated'),
                    "user": event.get('UserName'),
                    "source_ip": event.get('IpAddress'),
                })
            
            elif event_id == 1200:
                successful_tokens.append(event)
        
        if token_replays:
            findings.append({
                "type": "ADFS_TOKEN_REPLAY",
                "severity": "CRITICAL",
                "count": len(token_replays),
                "events": token_replays[:10],
                "description": f"ADFS detected {len(token_replays)} token replay attempts",
            })
        
        # Check for spray patterns
        spray_ips = [
            (ip, events) for ip, events in failed_auths_by_ip.items()
            if len(events) >= 10
        ]
        if spray_ips:
            findings.append({
                "type": "ADFS_PASSWORD_SPRAY",
                "severity": "HIGH",
                "source_ips": [ip for ip, _ in spray_ips],
                "description": f"Password spray detected from {len(spray_ips)} IPs against ADFS",
            })
        
        if extranet_lockouts:
            findings.append({
                "type": "ADFS_EXTRANET_LOCKOUTS",
                "severity": "MEDIUM",
                "count": len(extranet_lockouts),
                "events": extranet_lockouts[:10],
                "description": f"{len(extranet_lockouts)} extranet lockout events detected",
            })
        
        return {
            "total_tokens_issued": len(successful_tokens),
            "findings": findings,
        }
    
    def check_golden_saml_indicators(self, snapshot: ADSnapshot) -> List[dict]:
        """
        Check for Golden SAML attack prerequisites.
        Attack requires: ADFS service account credentials + token signing cert.
        """
        findings = []
        
        # Find ADFS service account
        adfs_accounts = [
            u for u in snapshot.users
            if 'adfs' in u.sam_account_name.lower() 
            or 'federation' in u.description.lower()
        ]
        
        for account in adfs_accounts:
            if account.has_spn:
                # Kerberoastable ADFS account = Golden SAML risk
                findings.append({
                    "type": "ADFS_ACCOUNT_KERBEROASTABLE",
                    "severity": "CRITICAL",
                    "account": account.sam_account_name,
                    "spns": account.service_principal_names,
                    "description": f"ADFS service account {account.sam_account_name} is Kerberoastable - Golden SAML risk",
                })
            
            if account.password_age_days > 365:
                findings.append({
                    "type": "ADFS_ACCOUNT_OLD_PASSWORD",
                    "severity": "HIGH",
                    "account": account.sam_account_name,
                    "password_age_days": account.password_age_days,
                    "description": f"ADFS service account password is {account.password_age_days:.0f} days old",
                })
        
        return findings
```

---

## Part 4: Integration with ADVulture's ML Architecture

These new detection capabilities should feed into ADVulture's existing:
- **Finding model** (risk_class assignment)
- **Gradient engine** (control effectiveness mapping)
- **Markov chain** (attack path probability)

### Risk Class Mapping for New Findings

| Finding Type | Risk Class | Controls |
|-------------|------------|----------|
| Token Replay | C (AuthZ Behaviour) | `session_binding`, `token_protection` |
| Impossible Travel | C (AuthZ Behaviour) | `named_locations`, `ca_location_policy` |
| Off-Hours Auth | C (AuthZ Behaviour) | `time_based_ca`, `monitoring` |
| IP Diversity | A (AuthN Hygiene) | `mfa_coverage`, `ca_compliance` |
| PIM No MFA | A (AuthN Hygiene) | `pim_mfa_enforcement` |
| Legacy Auth | A (AuthN Hygiene) | `legacy_auth_block` |
| Missing SPF/DKIM/DMARC | A (AuthN Hygiene) | `email_auth_records` |
| Service Acct IP Diversity | C (AuthZ Behaviour) | `service_account_monitoring` |
| Ticket Replay | C (AuthZ Behaviour) | `kerberos_armoring` |

---

## Implementation Priority

### Phase 1: Entra ID Enhancements (High Priority)
| # | Enhancement | Complexity | Impact |
|---|-------------|------------|--------|
| 1 | Security Defaults detection | Low | High |
| 2 | Token Replay detection | Medium | Critical |
| 3 | Impossible Travel detection | Medium | High |
| 4 | PIM Policy Quality assessment | Medium | High |
| 5 | CA Policy gap analysis | Low | High |
| 6 | Behavioral Analysis (off-hours, IP diversity) | Medium | Medium |
| 7 | DNS email security (SPF/DKIM/DMARC) | Low | Medium |

### Phase 2: On-Premise AD Enhancements (High Priority)
| # | Enhancement | Complexity | Impact |
|---|-------------|------------|--------|
| 8 | Security Baseline Assessment (GPO policies) | Medium | High |
| 9 | Off-hours Kerberos/NTLM analysis | Medium | Medium |
| 10 | Service Account Behavioral Baseline | Medium | High |
| 11 | Kerberos Ticket Replay detection | Medium | Critical |
| 12 | Lateral Movement detection | Medium | High |
| 13 | Privileged Group Monitoring (PIM equivalent) | Low | High |
| 14 | Authentication Policy Assessment | Medium | Medium |
| 15 | LAPS Deployment Assessment | Low | High |

### Phase 3: Hybrid/Joined Domain Enhancements (High Priority)
| # | Enhancement | Complexity | Impact |
|---|-------------|------------|--------|
| 16 | Azure AD Connect Sync Account Monitoring | Medium | Critical |
| 17 | Pass-Through Authentication Monitoring | High | High |
| 18 | Seamless SSO (AZUREADSSOACC) Monitoring | Medium | Critical |
| 19 | Hybrid Identity Sync Discrepancy Detection | High | High |
| 20 | ADFS Federation Monitoring | Medium | High |
| 21 | Golden SAML Indicator Detection | Low | Critical |

### Phase 4: Integration & Testing
| # | Enhancement | Complexity | Impact |
|---|-------------|------------|--------|
| 22 | Risk Class mapping for all new findings | Low | High |
| 23 | Gradient engine control mappings | Medium | High |
| 24 | Cross-environment correlation | High | High |
| 25 | Test suite for new detections | Medium | High |

---

## Files to Modify/Create

### New Files
| File | Purpose |
|------|---------|
| `advulture/analysis/behavioral.py` | Behavioral analysis for all environments |
| `advulture/analysis/onprem_baseline.py` | On-prem security baseline assessment |
| `advulture/analysis/hybrid_monitor.py` | Hybrid/sync/federation monitoring |

### Modified Files - Entra
| File | Changes |
|------|---------|
| `advulture/collection/entra_ingester.py` | Add Security Defaults, PIM policy rules collection |
| `advulture/analysis/entra_report.py` | Add token replay, impossible travel, CA gap analysis |

### Modified Files - On-Premise
| File | Changes |
|------|---------|
| `advulture/collection/ldap_enumerator.py` | Add GPO policy extraction, LAPS status |
| `advulture/collection/log_ingester.py` | Add off-hours, lateral movement, ticket replay detection |
| `advulture/analysis/posture.py` | Integrate new on-prem findings |

### Modified Files - Hybrid
| File | Changes |
|------|---------|
| `advulture/collection/adfs_ingester.py` | Add ADFS security event analysis |
| `advulture/analysis/finding.py` | Add finding templates for all new detection types |

### Modified Files - Integration
| File | Changes |
|------|---------|
| `advulture/ml/markov/chain.py` | Add control mappings for new findings |
| `advulture/graph/builder.py` | Add hybrid edges (Entra ↔ On-prem relationships) |

---

## Equivalency Matrix

This matrix shows how each detection capability maps across environments:

| Detection | Entra ID | On-Premise AD | Hybrid |
|-----------|----------|---------------|--------|
| Security Baseline | Security Defaults | GPO Password/Kerberos/Audit Policy | Both apply |
| Token/Ticket Replay | Token from multiple IPs | TGS from multiple workstations | Cross-reference both |
| Impossible Travel | GeoIP sign-in analysis | Subnet-to-location mapping | Correlate cloud + on-prem |
| Behavioral (Off-hours) | Sign-in timestamps | 4624/4769/4776 timestamps | Unified analysis |
| Behavioral (IP diversity) | Source IP per user | Workstation per user | Unified analysis |
| Service Account Monitoring | Service principal creds | SPN accounts, gMSA | Sync account special handling |
| Privileged Access | PIM policy quality | Protected Users, AdminSDHolder | Cloud-only admin detection |
| CA/Auth Policy | Conditional Access gaps | Auth Policies/Silos | Both apply |
| Email Security | SPF/DKIM/DMARC | N/A (cloud mail) | SPF/DKIM/DMARC |
| Password Spray | Sign-in failures by IP | 4776 failures by IP | ADFS extranet lockouts |
| Lateral Movement | SharePoint multi-geo | Multi-host auth patterns | Correlate both |
| Sync Integrity | N/A | N/A | Sync discrepancy detection |
| Federation Security | N/A | N/A | ADFS monitoring, Golden SAML |

---

*Document created: 2026-05-26*
*Based on learnings from ModernCRA/Entra/entra_assessment.py v2.0*
*Covers: Entra-only, On-premise AD, and Hybrid/Joined environments*
