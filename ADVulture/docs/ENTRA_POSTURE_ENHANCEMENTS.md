# ADVulture Entra ID Posture Enhancement Roadmap

## Current State vs. Proposed Enhancements

### 1. PRIVILEGED ACCESS MANAGEMENT (Priority: Critical)

#### Currently Implemented:
- 10 hardcoded critical roles tracked
- Stale privileged accounts (>90 days inactive)
- Password age for privileged accounts

#### Proposed Enhancements:

| Check | Risk | Data Source | Severity |
|-------|------|-------------|----------|
| **All Entra Role Enumeration** | Role sprawl, excessive permissions | `roleManagement/directory/roleDefinitions` | HIGH |
| **Dormant Privileged Roles** | Assigned roles never used (no sign-in correlation) | Role assignments + sign-in logs | HIGH |
| **Excessive Role Stacking** | Users with 3+ privileged roles | Role assignments | MEDIUM |
| **PIM Eligible vs Active** | Standing access instead of JIT | `roleManagement/directory/roleEligibilitySchedules` | HIGH |
| **Role Assignment Without Scope** | Tenant-wide vs Administrative Unit scoped | Role assignments + AU membership | MEDIUM |
| **Privileged Accounts Without MFA** | High-value targets without strong auth | Users + authenticationMethods | CRITICAL |
| **Privileged Sign-ins from Risky Locations** | Admins signing in from unusual geos | Sign-in logs + role correlation | HIGH |
| **Break-Glass Account Audit** | Emergency access accounts - last use, MFA bypass | Named accounts + sign-in history | MEDIUM |

---

### 2. APPLICATION & SERVICE PRINCIPAL SECURITY (Priority: Critical)

#### Currently Implemented:
- Dangerous app permissions detection (9 permissions)
- Service principal enumeration

#### Proposed Enhancements:

| Check | Risk | Data Source | Severity |
|-------|------|-------------|----------|
| **OAuth Consent Grant Sprawl** | Users granting permissions to risky apps | `oauth2PermissionGrants` | HIGH |
| **Apps With Mail/Files Access** | Data exfiltration vector | App permissions | HIGH |
| **Unverified Publisher Apps** | Potentially malicious third-party apps | `servicePrincipals.verifiedPublisher` | MEDIUM |
| **Dormant Apps With Permissions** | Apps not used 90+ days still have access | App sign-ins + permissions | MEDIUM |
| **Credential Expiry Audit** | Service principal secrets/certs expiring | `servicePrincipals.passwordCredentials` | MEDIUM |
| **Secrets vs Certificates** | Secrets are weaker than certificates | Credential type analysis | LOW |
| **Multi-Tenant Apps** | Cross-tenant data access risk | `servicePrincipals.appOwnerOrganizationId` | MEDIUM |
| **App-Only vs Delegated** | App-only permissions bypass user context | Permission type analysis | HIGH |

---

### 3. AUTHENTICATION HYGIENE (Priority: Critical)

#### Currently Implemented:
- Legacy authentication detection (5 protocols)
- MFA detail capture (partial)
- Sign-in result analysis

#### Proposed Enhancements:

| Check | Risk | Data Source | Severity |
|-------|------|-------------|----------|
| **Users Without MFA Registered** | Single-factor only accounts | `authenticationMethods` | CRITICAL |
| **Weak Auth Methods Only** | SMS/Voice only, no Authenticator/FIDO | Auth methods analysis | HIGH |
| **Password Spray Indicators** | Multiple failed sign-ins across accounts | Sign-in logs pattern analysis | HIGH |
| **Credential Stuffing Detection** | Failed sign-ins from known bad IPs | Sign-in logs + threat intel | HIGH |
| **Self-Service Password Reset Config** | SSPR without strong verification | Policy analysis | MEDIUM |
| **Password Writeback Risks** | On-prem password sync vulnerabilities | Hybrid config | MEDIUM |
| **Banned Password Compliance** | Custom banned password list effectiveness | Policy + audit logs | LOW |

---

### 4. CONDITIONAL ACCESS GAPS (Priority: High)

#### Currently Implemented:
- CA policy enumeration
- Basic policy analysis

#### Proposed Enhancements:

| Check | Risk | Data Source | Severity |
|-------|------|-------------|----------|
| **CA Coverage Gaps** | Users/apps excluded from ALL policies | Policy analysis + user/app lists | CRITICAL |
| **Policies Without MFA** | Sign-in allowed without strong auth | Policy conditions analysis | HIGH |
| **Legacy Auth Allowed** | Policies that don't block legacy protocols | Policy conditions | HIGH |
| **No Device Compliance Required** | Unmanaged devices allowed | Policy conditions | MEDIUM |
| **Overly Broad Exclusions** | "Exclude: All Admins" defeats purpose | Policy exclusions | HIGH |
| **Missing Break-Glass Exclusion** | Emergency accounts locked out | Policy analysis | MEDIUM |
| **Session Control Gaps** | No sign-in frequency limits | Session controls | LOW |
| **Named Location Weaknesses** | Trusted locations too broad | Named locations analysis | MEDIUM |

---

### 5. IDENTITY LIFECYCLE & GOVERNANCE (Priority: High)

#### Currently Implemented:
- Basic user enumeration
- Account enabled status

#### Proposed Enhancements:

| Check | Risk | Data Source | Severity |
|-------|------|-------------|----------|
| **Stale Accounts** | Accounts inactive >90 days | `signInActivity.lastSignInDateTime` | MEDIUM |
| **Orphaned Accounts** | No manager assigned, no recent activity | User properties + activity | MEDIUM |
| **Guest User Sprawl** | External users with broad access | Guest users + permissions | HIGH |
| **Guest Access Not Reviewed** | B2B guests without access reviews | Access review status | MEDIUM |
| **Disabled But Not Deleted** | Terminated employees still in directory | User status analysis | LOW |
| **License Assignment Gaps** | Users with roles but missing licenses | License + role correlation | LOW |
| **Group Membership Sprawl** | Users in excessive groups | Group membership count | LOW |

---

### 6. HYBRID IDENTITY SECURITY (Priority: High)

#### Currently Implemented:
- On-prem sync status detection
- SID correlation

#### Proposed Enhancements:

| Check | Risk | Data Source | Severity |
|-------|------|-------------|----------|
| **Azure AD Connect Health** | Sync failures, connector issues | Connect health API | HIGH |
| **Password Hash Sync Status** | PHS disabled = weaker security | Sync configuration | MEDIUM |
| **Seamless SSO Risks** | Kerberos key exposure | SSO configuration | MEDIUM |
| **On-Prem Admin Sync** | Domain Admins synced to cloud | Synced privileged accounts | CRITICAL |
| **Writeback Configuration** | Password/group writeback risks | Sync settings | MEDIUM |
| **Cloud-Only vs Synced Ratio** | Over-reliance on on-prem | User source analysis | LOW |

---

### 7. DATA PROTECTION & SHARING (Priority: Medium)

#### Proposed Enhancements:

| Check | Risk | Data Source | Severity |
|-------|------|-------------|----------|
| **External Sharing Settings** | SharePoint/OneDrive open to anyone | Sharing policies | HIGH |
| **Teams External Access** | Federation with any domain | Teams policies | MEDIUM |
| **Sensitivity Labels Adoption** | Low labeling = unprotected data | Label statistics | MEDIUM |
| **DLP Policy Coverage** | Gaps in data loss prevention | DLP policies | MEDIUM |
| **Guest Sharing Links** | Anonymous sharing links active | Sharing audit | HIGH |

---

### 8. MONITORING & DETECTION GAPS (Priority: Medium)

#### Proposed Enhancements:

| Check | Risk | Data Source | Severity |
|-------|------|-------------|----------|
| **Sign-in Log Retention** | Logs deleted before investigation | Diagnostic settings | MEDIUM |
| **Audit Log Gaps** | Missing audit categories | Diagnostic settings | MEDIUM |
| **Identity Protection Disabled** | No risky sign-in detection | IDP policies | HIGH |
| **Alert Fatigue Risk** | Too many alerts = ignored | Alert volume analysis | LOW |
| **SIEM Integration** | Logs not forwarded to SIEM | Diagnostic settings | MEDIUM |

---

## Implementation Priority

### Phase 1: Privileged Access (This Session)
1. ✅ Enumerate ALL Entra roles (not just 10)
2. ✅ Correlate role assignments with sign-in activity
3. ✅ Detect dormant privileged roles
4. ✅ Flag excessive role stacking
5. ✅ Identify privileged accounts without MFA

### Phase 2: Application Security
1. OAuth consent grant analysis
2. Dormant app detection
3. Credential expiry audit
4. Publisher verification check

### Phase 3: CA & Auth Hygiene
1. CA coverage gap analysis
2. Users without MFA registered
3. Legacy auth volume trending

### Phase 4: Governance & Lifecycle
1. Stale/orphaned account detection
2. Guest user sprawl analysis
3. Access review status

---

## API Endpoints Required

```
# Privileged Access
GET /roleManagement/directory/roleDefinitions
GET /roleManagement/directory/roleAssignments
GET /roleManagement/directory/roleEligibilitySchedules (PIM)

# Applications
GET /oauth2PermissionGrants
GET /servicePrincipals?$select=verifiedPublisher,passwordCredentials

# Authentication
GET /users/{id}/authentication/methods
GET /policies/authenticationMethodsPolicy

# Conditional Access (already implemented)
GET /identity/conditionalAccess/policies

# Governance
GET /identityGovernance/accessReviews/definitions
```

---

## Risk Scoring Model

| Finding Category | Base Score | Multipliers |
|-----------------|------------|-------------|
| Privileged Access | 10 | x2 if Global Admin, x1.5 if no MFA |
| Application Permissions | 8 | x2 if app-only, x1.5 if unverified |
| Authentication Hygiene | 7 | x2 if legacy auth, x1.5 if no MFA |
| Conditional Access | 6 | x2 if excludes admins |
| Identity Lifecycle | 5 | x1.5 if privileged |
| Monitoring Gaps | 4 | x1.5 if no SIEM |

