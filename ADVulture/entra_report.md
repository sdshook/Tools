# Entra ID Security Assessment Report

**Generated:** 2026-05-20 21:20:47 UTC
**Tenant ID:** organizations
**Organization:** N/A

## Collection Summary

| Category | Count |
|----------|-------|
| Users | 103 |
| Service Principals | 100 |
| Role Definitions | 143 |
| Role Assignments | 97 |
| OAuth Grants | 107 |
| Sign-in Events | 758 |
| Audit Events | 74 |

## MFA Posture

| Metric | Count | Percentage |
|--------|-------|------------|
| Users with MFA | 33 | 32.0% |
| Users with Strong MFA | 33 | 32.0% |
| Users without MFA | 70 | 68.0% |
| Users with Weak MFA Only | 0 | 0.0% |

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 4 |
| MEDIUM | 3 |
| LOW | 2 |
| INFO | 1 |

## Detailed Findings

### 1. [HIGH] Users Without MFA (27 users, 26%)

**Category:** MFA_POSTURE

27 enabled users have no MFA methods registered. These accounts are protected only by passwords and are vulnerable to phishing, credential stuffing, and password spray attacks.

**Affected:** 27 objects

**Sample affected objects:**
- andrea.cooley_opusagency.com#EXT#@forgepointcap.onmicrosoft.com
- anna.tantoco_pwc.com#EXT#@forgepointcap.onmicrosoft.com
- ap@forgepointcap.com
- azalearoom@forgepointcap.com
- copier@forgepointcap.com
- ... and 22 more

**Recommendation:** Implement mandatory MFA enrollment. Use Conditional Access to require MFA for all sign-ins.

### 2. [HIGH] High-Risk OAuth Consent Grants (12)

**Category:** OAUTH_CONSENT

12 OAuth grants include high-risk scopes that allow applications to read/write sensitive data (mail, files, directory).

**Affected:** 12 objects

**Sample affected objects:**
- 0fbc13cf-1b80-4598-9e29-d25ee68b50cc:  openid email profile offline_access Mail.ReadWrite Mail.Send Calendars.Read Calendars.ReadWrite User.Read
- f394ff39-48be-4d67-aebf-a94d20f6f0a8: SensitivityLabel.Read AppCatalog.Read.All AppCatalog.Submit Channel.ReadBasic.All EduAssignments.ReadBasic EduRoster.ReadBasic Files.Read.All Files.ReadWrite.All Group.Read.All People.Read People.Read.All Presence.Read.All TeamsAppInstallation.ReadWriteSelfForTeam User.Read User.ReadBasic.All Tasks.ReadWrite Group-Conversation.ReadWrite.All Team.ReadBasic.All Channel.Create Sites.Read.All TeamsAppInstallation.ReadWriteForTeam PrinterShare.ReadBasic.All PrintJob.Create PrintJob.ReadBasic FileStorageContainer.Selected Calendars.Read Files.Read GroupMember.Read.All InformationProtectionPolicy.Read TeamsTab.Create ChatMember.Read
- f394ff39-48be-4d67-aebf-a94d20f6f0a8: Files.ReadWrite.All TermStore.ReadWrite.All Sites.ReadWrite.All Sites.FullControl.All
- e509dbc4-7f75-425f-b3af-c27330de3398: Sites.FullControl.All Sites.Manage.All Tasks.Read offline_access Sites.Read.All Files.ReadWrite.All Files.ReadWrite Contacts.ReadWrite Calendars.ReadWrite Mail.ReadWrite Directory.AccessAsUser.All Directory.ReadWrite.All Group.ReadWrite.All User.Read.All User.ReadBasic.All Files.ReadWrite.AppFolder Files.ReadWrite.Selected
- e509dbc4-7f75-425f-b3af-c27330de3398: Mail.ReadWrite.All Calendars.ReadWrite.All Contacts.ReadWrite.All Tasks.ReadWrite User.ReadBasic.All Group.ReadWrite.All Group.Read.All Contacts.ReadWrite Calendars.ReadWrite Mail.ReadWrite EWS.AccessAsUser.All
- ... and 5 more

**Recommendation:** Review and revoke unnecessary OAuth grants. Implement admin consent workflow.

### 3. [HIGH] Token Replay Indicators (1 events)

**Category:** CREDENTIAL_MISUSE

Detected 1 instances where the same user accessed the same application from different IP addresses within 5 minutes. This may indicate stolen tokens being replayed by an attacker.

**Affected:** 1 objects

**Sample affected objects:**
- amcclure@forgepointcap.com (Microsoft Authentication Broker): 2601:647:6700:4060:788f:89ba:4f60:f2b3 → 2601:647:6700:4060:e9b8:9961:6702:8e in 80s

**Recommendation:** Review if users were using VPN or mobile networks. If not, revoke sessions and investigate for token theft.

### 4. [HIGH] High-Risk Application Permissions (28 grants)

**Category:** APP_PERMISSIONS

Found 28 high-risk Graph API permissions granted to 7 applications. These permissions allow reading/writing mail, files, or directory data.

**Affected:** 7 objects

**Sample affected objects:**
- CTD.ai - Metadata, Send: Mail.Send
- CloudAlly V2: TeamSettings.ReadWrite.All, Mail.ReadWrite, User.ReadWrite.All...
- Custom-CinchyMail: Mail.Send
- Sentinel Baseline: AppRoleAssignment.ReadWrite.All
- CloudAlly: Directory.ReadWrite.All, Directory.ReadWrite.All, Contacts.ReadWrite...
- ... and 2 more

**Recommendation:** Review if each application requires these permissions. Remove unnecessary grants. Prefer delegated over application permissions.

### 5. [MEDIUM] Legacy Authentication Usage (3 events, 0.4%)

**Category:** LEGACY_AUTH

3 sign-ins used legacy authentication protocols which bypass MFA. 1 unique users affected.

**Affected:** 1 objects

**Sample affected objects:**
- copier@forgepointcap.com

**Recommendation:** Block legacy authentication via Conditional Access policy.

### 6. [MEDIUM] High IP Address Diversity (1 users)

**Category:** SUSPICIOUS_LOGIN

1 users authenticated from 10+ distinct IP addresses during the analysis period. May indicate credential sharing, VPN rotation, or compromised credentials used by multiple actors.

**Affected:** 1 objects

**Sample affected objects:**
- sshook@forgepointcap.com: 10 unique IPs

**Recommendation:** Review if IP diversity is expected (mobile users, VPN). Excessive diversity may indicate credential compromise.

### 7. [MEDIUM] Applications with Mail.Send Permission (3 apps)

**Category:** APP_PERMISSIONS

3 applications have Mail.Send permission, allowing them to send email on behalf of users. If compromised, these apps could be used for phishing or BEC attacks.

**Affected:** 3 objects

**Sample affected objects:**
- Custom-CinchyMail
- CloudAlly V2
- CTD.ai - Metadata, Send

**Recommendation:** Verify each app requires Mail.Send. Consider using send-on-behalf-of with specific mailboxes instead of tenant-wide permission.

### 8. [LOW] Off-Hours Authentication Activity (144 events)

**Category:** SUSPICIOUS_LOGIN

144 successful sign-ins occurred outside business hours (10pm-6am or weekends) from 10 users with 5+ events. While some may be legitimate, review for unauthorized access.

**Affected:** 10 objects

**Sample affected objects:**
- jhuang@forgepointcap.com: 7 off-hours sign-ins
- llee@forgepointcap.com: 12 off-hours sign-ins
- amcclure@forgepointcap.com: 38 off-hours sign-ins
- ebio@forgepointcap.com: 5 off-hours sign-ins
- nbassi@forgepointcap.com: 6 off-hours sign-ins
- ... and 5 more

**Recommendation:** Verify off-hours access aligns with user job requirements. Consider time-based Conditional Access for sensitive roles.

### 9. [LOW] SharePoint Access from Multiple Locations (3 users)

**Category:** SHAREPOINT_SECURITY

3 users accessed SharePoint from 3+ different geographic locations. While this may be normal for traveling users, verify if access patterns are expected.

**Affected:** 3 objects

**Sample affected objects:**
- jlau@forgepointcap.com: 3 locations
- ayepez@forgepointcap.com: 3 locations
- nbassi@forgepointcap.com: 3 locations

**Recommendation:** Review if geographic diversity is expected for these users.

### 10. [INFO] Failed Sign-in Attempts (120 events)

**Category:** AUTHENTICATION

120 failed sign-in attempts from 14 unique accounts. Review for potential brute-force or credential stuffing attacks.

**Affected:** 14 objects

**Sample affected objects:**
- kshih@forgepointcap.com
- sshook@forgepointcap.com
- wlin@forgepointcap.com
- rkirton@forgepointcap.com
- jgoyarrola@forgepointcap.com
- ... and 5 more

**Recommendation:** Investigate repeated failures. Consider smart lockout policies.
