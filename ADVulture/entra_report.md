# Entra ID Security Assessment Report

**Generated:** 2026-05-20 22:19:37 UTC
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
| Sign-in Events | 762 |
| Audit Events | 75 |

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
| HIGH | 5 |
| MEDIUM | 4 |
| LOW | 4 |
| INFO | 3 |

## Detailed Findings

### 1. [HIGH] Global Administrator Count (4)

**Category:** PRIVILEGED_ACCESS

Found 4 Global Administrator assignments. Microsoft recommends 2-4 Global Admins maximum. Best practice: use cloud-only accounts, PIM eligible assignments, and break-glass procedures.

**Affected:** 4 objects

**Affected objects:**
- hsharafali@forgepointcap.com (User, active, cloud-only)
- llee.admin@forgepointcap.com (User, active, cloud-only)
- cloudally-admin@forgepointcap.onmicrosoft.com (User, active, cloud-only)
- admin.sshook@forgepointcap.com (User, active, cloud-only)

**Recommendation:** Reduce Global Admin count to 2-4. Use PIM for eligible (not permanent) assignments. Ensure at least 2 cloud-only break-glass accounts exist.

### 2. [HIGH] High-Risk OAuth Consent Grants (12)

**Category:** OAUTH_CONSENT

12 OAuth grants include high-risk scopes that allow applications to read/write sensitive data (mail, files, directory).

**Affected:** 12 objects

**Affected objects:**
- 0fbc13cf-1b80-4598-9e29-d25ee68b50cc (0fbc13cf-1b80-4598-9e29-d25ee68b50cc):  openid email profile offline_access Mail.ReadWrite Mail.Send Calendars.Read Calendars.ReadWrite User.Read
- f394ff39-48be-4d67-aebf-a94d20f6f0a8 (f394ff39-48be-4d67-aebf-a94d20f6f0a8): SensitivityLabel.Read AppCatalog.Read.All AppCatalog.Submit Channel.ReadBasic.All EduAssignments.ReadBasic EduRoster.ReadBasic Files.Read.All Files.ReadWrite.All Group.Read.All People.Read People.Read.All Presence.Read.All TeamsAppInstallation.ReadWriteSelfForTeam User.Read User.ReadBasic.All Tasks.ReadWrite Group-Conversation.ReadWrite.All Team.ReadBasic.All Channel.Create Sites.Read.All TeamsAppInstallation.ReadWriteForTeam PrinterShare.ReadBasic.All PrintJob.Create PrintJob.ReadBasic FileStorageContainer.Selected Calendars.Read Files.Read GroupMember.Read.All InformationProtectionPolicy.Read TeamsTab.Create ChatMember.Read
- f394ff39-48be-4d67-aebf-a94d20f6f0a8 (f394ff39-48be-4d67-aebf-a94d20f6f0a8): Files.ReadWrite.All TermStore.ReadWrite.All Sites.ReadWrite.All Sites.FullControl.All
- e509dbc4-7f75-425f-b3af-c27330de3398 (e509dbc4-7f75-425f-b3af-c27330de3398): Sites.FullControl.All Sites.Manage.All Tasks.Read offline_access Sites.Read.All Files.ReadWrite.All Files.ReadWrite Contacts.ReadWrite Calendars.ReadWrite Mail.ReadWrite Directory.AccessAsUser.All Directory.ReadWrite.All Group.ReadWrite.All User.Read.All User.ReadBasic.All Files.ReadWrite.AppFolder Files.ReadWrite.Selected
- e509dbc4-7f75-425f-b3af-c27330de3398 (e509dbc4-7f75-425f-b3af-c27330de3398): Mail.ReadWrite.All Calendars.ReadWrite.All Contacts.ReadWrite.All Tasks.ReadWrite User.ReadBasic.All Group.ReadWrite.All Group.Read.All Contacts.ReadWrite Calendars.ReadWrite Mail.ReadWrite EWS.AccessAsUser.All
- e509dbc4-7f75-425f-b3af-c27330de3398 (e509dbc4-7f75-425f-b3af-c27330de3398): TermStore.ReadWrite.All Sites.Search.All AllSites.Write AllSites.Manage AllSites.FullControl MyFiles.Write User.ReadWrite.All
- 639096ad-9937-449c-b114-64097599b8d9 (639096ad-9937-449c-b114-64097599b8d9): Calendars.ReadWrite Channel.Create Channel.ReadBasic.All ChannelMessage.Read.All Chat.ReadWrite Contacts.ReadWrite Directory.Read.All Files.ReadWrite.All Group.ReadWrite.All GroupMember.Read.All Mail.ReadWrite MailboxFolder.ReadWrite MailboxItem.ImportExport MailboxItem.Read MailboxSettings.ReadWrite Notes.ReadWrite Notes.ReadWrite.All Sites.ReadWrite.All Tasks.ReadWrite TeamSettings.ReadWrite.All TeamsTab.ReadWrite.All User.Read.All
- fbeba2db-1035-4d27-8ae6-030270aaded6 (fbeba2db-1035-4d27-8ae6-030270aaded6): Files.ReadWrite.All
- 1f76d3e2-35c4-4c82-8c4d-36c9a591edec (1f76d3e2-35c4-4c82-8c4d-36c9a591edec): offline_access Calendars.Read Calendars.ReadWrite openid email User.Read Mail.Send Mail.ReadWrite
- 44c0f7fb-15fa-475e-9c69-00e4fd9587a4 (44c0f7fb-15fa-475e-9c69-00e4fd9587a4):  openid profile offline_access User.Read Mail.Read Mail.ReadWrite Mail.Send
- 7d7cce17-0672-40d5-9f19-0878238ff279 (7d7cce17-0672-40d5-9f19-0878238ff279): AccessReview.ReadWrite.All AccessReview.ReadWrite.Membership AdministrativeUnit.ReadWrite.All Agreement.ReadWrite.All AgreementAcceptance.Read.All Application.ReadWrite.All AppRoleAssignment.ReadWrite.All AuditLog.Read.All BrowserSiteLists.ReadWrite.All Channel.Create Channel.Delete.All Channel.ReadBasic.All ChannelMember.Read.All ChannelMember.ReadWrite.All ChannelSettings.ReadWrite.All CloudPC.ReadWrite.All ConsentRequest.ReadWrite.All CrossTenantInformation.ReadBasic.All CrossTenantUserProfileSharing.ReadWrite.All CustomSecAttributeAssignment.ReadWrite.All CustomSecAttributeDefinition.ReadWrite.All DelegatedAdminRelationship.Read.All DelegatedPermissionGrant.ReadWrite.All Device.Command Device.Read.All Device.ReadWrite.All DeviceManagementApps.Read.All DeviceManagementConfiguration.Read.All DeviceManagementManagedDevices.Read.All DeviceManagementRBAC.Read.All DeviceManagementServiceConfig.Read.All Directory.AccessAsUser.All Directory.ReadWrite.All DirectoryRecommendations.ReadWrite.All Domain.ReadWrite.All IdentityProvider.Read.All IdentityRiskEvent.Read.All IdentityRiskyServicePrincipal.Read.All IdentityRiskyUser.Read.All IdentityUserFlow.Read.All InformationProtectionPolicy.Read.All MailboxSettings.ReadWrite ManagedTenants.Read.All Member.Read.Hidden OnPremDirectorySynchronization.ReadWrite.All OnPremisesPublishingProfiles.ReadWrite.All Organization.ReadWrite.All Policy.Read.All Policy.ReadWrite.AuthenticationMethod Policy.ReadWrite.Authorization Policy.ReadWrite.ConditionalAccess PrintConnector.Read.All Printer.Read.All PrinterShare.Read.All PrintJob.ReadBasic.All PrintSettings.Read.All RecordsManagement.ReadWrite.All Reports.Read.All RoleManagement.Read.Directory RoleManagement.Read.Exchange RoleManagementPolicy.Read.Directory SecurityActions.Read.All SecurityAlert.Read.All SecurityEvents.Read.All SecurityIncident.Read.All ServiceHealth.Read.All ServiceMessage.Read.All Synchronization.ReadWrite.All Team.ReadBasic.All TeamMember.ReadWrite.All TeamSettings.ReadWrite.All User.ManageIdentities.All UserAuthenticationMethod.ReadWrite.All
- f1a007b0-8825-4ebb-a43e-1716bbf596b1 (f1a007b0-8825-4ebb-a43e-1716bbf596b1):  Mail.ReadWrite Mail.Send User.Read offline_access

**Recommendation:** Review and revoke unnecessary OAuth grants. Implement admin consent workflow.

### 3. [HIGH] No Conditional Access Policies Found

**Category:** CONDITIONAL_ACCESS

No Conditional Access policies were retrieved. This could mean: (1) No policies are configured - critical security gap, or (2) Insufficient permissions to read CA policies (Policy.Read.All required).

**Affected:** 0 objects

**Affected objects:**
- Unable to enumerate CA policies

**Recommendation:** Configure Conditional Access policies for: MFA enforcement, device compliance, trusted locations, risky sign-in blocking, and legacy auth blocking.

### 4. [HIGH] Token Replay Indicators (2 events)

**Category:** CREDENTIAL_MISUSE

Detected 2 instances where the same user accessed the same application from different IP addresses within 5 minutes. This may indicate stolen tokens being replayed by an attacker.

**Affected:** 2 objects

**Affected objects:**
- **sshook@forgepointcap.com** (Microsoft Graph Command Line Tools): 208.250.98.39 (Washington) → 34.29.175.97 (Council Bluffs) in 228s
- **amcclure@forgepointcap.com** (Microsoft Authentication Broker): 2601:647:6700:4060:788f:89ba:4f60:f2b3 (Newark) → 2601:647:6700:4060:e9b8:9961:6702:8e (Newark) in 80s

**Recommendation:** Review if users were using VPN or mobile networks. If not, revoke sessions and investigate for token theft.

### 5. [HIGH] High-Risk Application Permissions (28 grants)

**Category:** APP_PERMISSIONS

Found 28 high-risk Graph API permissions granted to 7 applications. These permissions allow reading/writing mail, files, or directory data.

**Affected:** 7 objects

**Affected objects:**
- CTD.ai - Metadata, Send: Mail.Send
- CloudAlly V2: TeamSettings.ReadWrite.All, Mail.ReadWrite, User.ReadWrite.All...
- Custom-CinchyMail: Mail.Send
- Sentinel Baseline: AppRoleAssignment.ReadWrite.All
- CloudAlly: Directory.ReadWrite.All, Directory.ReadWrite.All, Contacts.ReadWrite...
- SkyKick Cloud Manager - Exchange Online: RoleManagement.ReadWrite.Directory
- Nudge Security: DelegatedPermissionGrant.ReadWrite.All, AppRoleAssignment.ReadWrite.All

**Recommendation:** Review if each application requires these permissions. Remove unnecessary grants. Prefer delegated over application permissions.

### 6. [MEDIUM] Email Domain Security (SPF/DKIM/DMARC) for 1 domain(s)

**Category:** DOMAIN_SECURITY

Analyzed email authentication records for 1 domain(s). Missing or weak SPF/DKIM/DMARC enables email spoofing and phishing attacks impersonating your organization.

**Affected:** 1 objects

**Affected objects:**
- forgepointcap.com: SPF: ✓ | DKIM: ✓ | DMARC: ✓ p=none — DMARC p=none provides monitoring only, no enforcement

**Recommendation:** Implement SPF with -all (hard fail), DKIM signing via M365/Google, and DMARC p=reject. This is critical given the Mail.Send permissions in this tenant.

### 7. [MEDIUM] Legacy Authentication Usage (3 events, 0.4%)

**Category:** LEGACY_AUTH

3 sign-ins used legacy authentication protocols which bypass MFA. 1 unique users affected.

**Affected:** 1 objects

**Affected objects:**
- copier@forgepointcap.com

**Recommendation:** Block legacy authentication via Conditional Access policy.

### 8. [MEDIUM] High IP Address Diversity (1 users)

**Category:** SUSPICIOUS_LOGIN

1 users authenticated from 10+ distinct IP addresses during the analysis period. May indicate credential sharing, VPN rotation, or compromised credentials used by multiple actors.

**Affected:** 1 objects

**Affected objects:**
- **sshook@forgepointcap.com** (10 IPs):
-   - 208.250.98.39 (Washington)
-   - 2606:40c6:516f:d2e9:6e16:ced:ad3e:b4e8 (Englewood)
-   - 2606:40c6:5990:5ccd:d62f:e572:2554:b895 (Englewood)
-   - 2606:40c6:f7d3:37bb:162f:cc8e:3f78:33a2 (Englewood)
-   - 34.136.162.246 (Council Bluffs)
-   - 34.29.175.97 (Council Bluffs)
-   - 34.45.0.142 (Council Bluffs)
-   - 34.70.174.52 (Council Bluffs)
-   - 35.222.133.153 (Council Bluffs)
-   - 67.180.226.228 (Los Gatos)

**Recommendation:** Review if IP diversity is expected (mobile users, VPN). Excessive diversity may indicate credential compromise.

### 9. [MEDIUM] Applications with Mail.Send Permission (3 apps)

**Category:** APP_PERMISSIONS

3 applications have Mail.Send permission, allowing them to send email on behalf of users. If compromised, these apps could be used for phishing or BEC attacks.

**Affected:** 3 objects

**Affected objects:**
- Custom-CinchyMail
- CloudAlly V2
- CTD.ai - Metadata, Send

**Recommendation:** Verify each app requires Mail.Send. Consider using send-on-behalf-of with specific mailboxes instead of tenant-wide permission.

### 10. [LOW] Inactive Users Without MFA (7)

**Category:** MFA_POSTURE

7 enabled users have no MFA and no recent sign-in activity in the analysis period. These may be provisioned but unused accounts.

**Affected:** 7 objects

**Affected objects:**
- ap@forgepointcap.com
- deallog@forgepointcap.com
- Forgepoint@forgepointcap.com
- glau@forgepointcap.com
- jobs@forgepointcap.com
- pbotas@forgepointcap.com
- talent@forgepointcap.com

**Recommendation:** Review if these accounts are needed. Consider disabling unused accounts or require MFA enrollment before first use.

### 11. [LOW] External Guest Users (15 accounts from 4 domains)

**Category:** GUEST_ACCESS

Found 15 guest/external user accounts from 4 external domains. Guest accounts can access shared resources and should be governed via access reviews.

**Affected:** 15 objects

**Affected objects:**
- portland-communications.com: 7 guests (louise.northam_portland-communications.com#EXT#@forgepointcap.onmicrosoft.com, matthew.owen_portland-communications.com#EXT#@forgepointcap.onmicrosoft.com, matthew.peacock_portland-communications.com#EXT#@forgepointcap.onmicrosoft.com, pauline.guenot_portland-communications.com#EXT#@forgepointcap.onmicrosoft.com, priscilla.truong_portland-communications.com#EXT#@forgepointcap.onmicrosoft.com, rosie.johnstone_portland-communications.com#EXT#@forgepointcap.onmicrosoft.com, tristan.peniston-bird_portland-communications.com#EXT#@forgepointcap.onmicrosoft.com)
- pwc.com: 4 guests (anna.tantoco_pwc.com#EXT#@forgepointcap.onmicrosoft.com, jackie.day_pwc.com#EXT#@forgepointcap.onmicrosoft.com, katherine.cage_pwc.com#EXT#@forgepointcap.onmicrosoft.com, maggie.y.piper_pwc.com#EXT#@forgepointcap.onmicrosoft.com)
- microsoft.com: 3 guests (demoriecrowe_microsoft.com#EXT#@forgepointcap.onmicrosoft.com, v-acooley_microsoft.com#EXT#@forgepointcap.onmicrosoft.com, dasha.zenkovich_microsoft.com#EXT#@forgepointcap.onmicrosoft.com)
- opusagency.com: 1 guests (andrea.cooley_opusagency.com#EXT#@forgepointcap.onmicrosoft.com)

**Recommendation:** Implement guest access reviews. Configure B2B collaboration settings. Consider blocking guest access to sensitive apps via Conditional Access.

### 12. [LOW] Off-Hours Authentication Activity (141 events)

**Category:** SUSPICIOUS_LOGIN

141 successful sign-ins occurred outside business hours (10pm-6am or weekends) from 11 users with 5+ events. While some may be legitimate, review for unauthorized access.

**Affected:** 11 objects

**Affected objects:**
- sshook@forgepointcap.com: 7 off-hours sign-ins at: 2026-05-13 22:38, 2026-05-13 23:32, 2026-05-13 23:34, 2026-05-13 23:34, 2026-05-14 22:00, 2026-05-14 22:02, 2026-05-20 22:10
- mcaprara@forgepointcap.com: 6 off-hours sign-ins at: 2026-05-13 23:33, 2026-05-15 22:29, 2026-05-15 23:01, 2026-05-19 23:21, 2026-05-20 22:08, 2026-05-20 22:08
- jhuang@forgepointcap.com: 7 off-hours sign-ins at: 2026-05-14 00:19, 2026-05-16 04:37, 2026-05-16 13:27, 2026-05-18 02:37, 2026-05-19 02:14, 2026-05-20 00:16, 2026-05-20 05:33
- llee@forgepointcap.com: 12 off-hours sign-ins at: 2026-05-14 01:44, 2026-05-15 03:55, 2026-05-15 22:02, 2026-05-15 22:02, 2026-05-16 05:08, 2026-05-16 17:56, 2026-05-16 23:11, 2026-05-18 03:30, 2026-05-19 00:50, 2026-05-19 22:46, 2026-05-20 00:41, 2026-05-20 04:59
- amcclure@forgepointcap.com: 38 off-hours sign-ins at: 2026-05-14 22:39, 2026-05-14 22:39, 2026-05-15 22:08, 2026-05-16 02:10, 2026-05-16 02:24, 2026-05-16 02:24, 2026-05-16 02:25, 2026-05-16 02:25, 2026-05-16 02:25, 2026-05-16 02:25, 2026-05-16 02:25, 2026-05-16 02:25, 2026-05-16 02:25, 2026-05-16 02:25, 2026-05-16 02:25, 2026-05-16 02:25, 2026-05-16 02:25, 2026-05-16 02:26, 2026-05-16 02:26, 2026-05-16 02:26, 2026-05-16 02:26, 2026-05-16 02:26, 2026-05-16 02:26, 2026-05-16 02:26, 2026-05-16 02:26, 2026-05-16 02:26, 2026-05-16 02:26, 2026-05-16 02:26, 2026-05-16 02:28, 2026-05-16 02:28, 2026-05-16 02:28, 2026-05-16 02:29, 2026-05-16 21:59, 2026-05-18 00:59, 2026-05-18 02:36, 2026-05-19 02:05, 2026-05-19 23:42, 2026-05-20 04:47
- ebio@forgepointcap.com: 5 off-hours sign-ins at: 2026-05-13 22:39, 2026-05-15 00:55, 2026-05-16 19:14, 2026-05-18 23:04, 2026-05-19 23:38
- nbassi@forgepointcap.com: 6 off-hours sign-ins at: 2026-05-14 23:33, 2026-05-15 22:00, 2026-05-16 01:41, 2026-05-17 19:36, 2026-05-19 02:02, 2026-05-19 23:25
- schung@forgepointcap.com: 11 off-hours sign-ins at: 2026-05-14 22:09, 2026-05-14 22:12, 2026-05-14 22:12, 2026-05-14 22:13, 2026-05-14 22:13, 2026-05-14 22:16, 2026-05-14 22:16, 2026-05-15 22:13, 2026-05-19 02:34, 2026-05-19 02:34, 2026-05-19 02:34
- hsharafali@forgepointcap.com: 14 off-hours sign-ins at: 2026-05-16 02:19, 2026-05-16 02:19, 2026-05-16 02:20, 2026-05-16 02:20, 2026-05-16 02:20, 2026-05-16 02:30, 2026-05-16 02:35, 2026-05-16 02:35, 2026-05-16 02:35, 2026-05-16 02:35, 2026-05-16 02:53, 2026-05-18 02:15, 2026-05-18 22:29, 2026-05-19 01:42
- jlau@forgepointcap.com: 10 off-hours sign-ins at: 2026-05-13 22:36, 2026-05-13 22:36, 2026-05-13 22:36, 2026-05-13 22:36, 2026-05-13 22:48, 2026-05-13 22:52, 2026-05-14 22:07, 2026-05-15 22:34, 2026-05-15 22:37, 2026-05-18 23:00
- jpark@forgepointcap.com: 6 off-hours sign-ins at: 2026-05-14 02:48, 2026-05-15 03:07, 2026-05-15 23:29, 2026-05-16 04:47, 2026-05-17 22:51, 2026-05-18 04:10

**Recommendation:** Verify off-hours access aligns with user job requirements. Consider time-based Conditional Access for sensitive roles.

### 13. [LOW] SharePoint Access from Multiple Locations (3 users)

**Category:** SHAREPOINT_SECURITY

3 users accessed SharePoint from 3+ different geographic locations. While this may be normal for traveling users, verify if access patterns are expected.

**Affected:** 3 objects

**Affected objects:**
- chiggins@forgepointcap.com: 3 locations - Boston, US, Roanoke, US, Salem, US
- jlau@forgepointcap.com: 3 locations - Belmont, US, Brentwood (Contra Costa), US, San Francisco, US
- nbassi@forgepointcap.com: 3 locations - Atherton, US, East Palo Alto, US, San Mateo, US

**Recommendation:** Review if geographic diversity is expected for these users.

### 14. [INFO] Room/Service Accounts Without MFA (6)

**Category:** MFA_POSTURE

6 accounts appear to be room resources or service accounts based on naming patterns. These often don't require MFA if secured via Conditional Access (block external) or used non-interactively.

**Affected:** 6 objects

**Affected objects:**
- azalearoom@forgepointcap.com
- copier@forgepointcap.com
- madroneroom@forgepointcap.com
- mapleroom@forgepointcap.com
- redwoodroom@forgepointcap.com
- zoomroomuser@forgepointcap.com

**Recommendation:** Verify these accounts are secured via CA policies blocking external access, or are non-interactive with strong passwords. Consider converting to resource mailboxes where appropriate.

### 15. [INFO] Critical Role Assignment Summary (15 roles in use)

**Category:** PRIVILEGED_ACCESS

Summary of assignments to critical administrative roles. Review each role to ensure assignments follow least-privilege principles.

**Affected:** 15 objects

**Affected objects:**
- Global Administrator (4): hsharafali@forgepointcap.com, llee.admin@forgepointcap.com, cloudally-admin@forgepointcap.onmicrosoft.com, admin.sshook@forgepointcap.com
- Privileged Role Administrator (1): admin.sshook@forgepointcap.com
- Privileged Authentication Administrator (1): admin.sshook@forgepointcap.com
- Authentication Administrator (2): admin.sshook@forgepointcap.com, sshook@forgepointcap.com
- User Administrator (2): llee.admin@forgepointcap.com, admin.sshook@forgepointcap.com
- Exchange Administrator (3): llee.admin@forgepointcap.com, admin.sshook@forgepointcap.com, SkyKick Cloud Manager - Exchange Online
- SharePoint Administrator (2): llee.admin@forgepointcap.com, admin.sshook@forgepointcap.com
- Application Administrator (1): admin.sshook@forgepointcap.com
- Cloud Application Administrator (1): admin.sshook@forgepointcap.com
- Intune Administrator (1): admin.sshook@forgepointcap.com
- Security Administrator (1): admin.sshook@forgepointcap.com
- Compliance Administrator (1): admin.sshook@forgepointcap.com
- Billing Administrator (1): admin.sshook@forgepointcap.com
- Helpdesk Administrator (2): llee.admin@forgepointcap.com, admin.sshook@forgepointcap.com
- Password Administrator (1): admin.sshook@forgepointcap.com

**Recommendation:** Document business justification for each privileged assignment. Consider using PIM for just-in-time activation.

### 16. [INFO] Failed Sign-in Attempts (125 events)

**Category:** AUTHENTICATION

125 failed sign-in attempts from 14 unique accounts. Review for potential brute-force or credential stuffing attacks.

**Affected:** 14 objects

**Affected objects:**
- **sshook@forgepointcap.com** (77 failures):
-   - 2026-05-20 22:10 | 34.29.175.97 (Council Bluffs) | other | Microsoft Graph Command Line Tools
-   - 2026-05-20 21:59 | 34.29.175.97 (Council Bluffs) | other | Microsoft Graph Command Line Tools
-   - 2026-05-20 21:55 | 208.250.98.39 (Washington) | other | Microsoft Graph Command Line Tools
-   - 2026-05-20 21:50 | 34.29.175.97 (Council Bluffs) | other | Microsoft Graph Command Line Tools
-   - 2026-05-20 21:37 | 34.29.175.97 (Council Bluffs) | other | Microsoft Graph Command Line Tools
-   - 2026-05-20 21:28 | 34.29.175.97 (Council Bluffs) | other | Microsoft Graph Command Line Tools
-   - 2026-05-20 21:19 | 208.250.98.39 (Washington) | other | Microsoft Graph Command Line Tools
-   - 2026-05-20 21:18 | 34.29.175.97 (Council Bluffs) | other | Microsoft Graph Command Line Tools
-   - 2026-05-20 21:12 | 208.250.98.39 (Washington) | other | Microsoft Azure PowerShell
-   - 2026-05-20 20:55 | 34.29.175.97 (Council Bluffs) | other | Microsoft Graph Command Line Tools
-   - ... and 67 more
- **schung@forgepointcap.com** (16 failures):
-   - 2026-05-20 16:39 | 2600:1700:8fda:56b0:1ca2:9797:e091:bd28 (South San Francisco) | other | Office 365 SharePoint Online
-   - 2026-05-20 15:50 | 2600:1700:8fda:56b0:3cf0:3ec1:519a:7715 (South San Francisco) | other | Windows Sign In
-   - 2026-05-19 22:58 | 2600:1700:8fda:56b0:3cf0:3ec1:519a:7715 (South San Francisco) | other | Windows Sign In
-   - 2026-05-19 16:28 | 108.223.47.93 (East Palo Alto) | other | Windows Sign In
-   - 2026-05-19 15:42 | 2600:1700:8fda:56b0:f056:a2d1:220c:ad5f (South San Francisco) | other | Windows Sign In
-   - 2026-05-19 00:31 | 2600:1700:8fda:56b0:f056:a2d1:220c:ad5f (South San Francisco) | other | Windows Sign In
-   - 2026-05-18 16:14 | 108.223.47.93 (East Palo Alto) | other | Windows Sign In
-   - 2026-05-17 19:51 | 2600:1700:8fda:56b0:a56c:8406:fcdc:259c (South San Francisco) | other | Windows Sign In
-   - 2026-05-15 15:03 | 2600:1700:8fda:56b0:a56c:8406:fcdc:259c (South San Francisco) | other | Windows Sign In
-   - 2026-05-15 03:45 | 2600:1700:8fda:56b0:a56c:8406:fcdc:259c (South San Francisco) | other | Windows Sign In
-   - ... and 6 more
- **ayepez@forgepointcap.com** (8 failures):
-   - 2026-05-20 16:42 | 4.4.89.67 (Washington) | invalid_credentials | Office 365 SharePoint Online
-   - 2026-05-20 16:41 | 4.4.89.67 (Washington) | invalid_credentials | Office 365 SharePoint Online
-   - 2026-05-20 16:40 | 4.4.89.67 (Washington) | invalid_credentials | Office 365 SharePoint Online
-   - 2026-05-20 12:20 | 2606:40c6:c918:5533:b698:8869:e705:ce73 (Ashburn) | invalid_credentials | Microsoft Azure CLI
-   - 2026-05-20 01:16 | 4.4.89.67 (Washington) | other | Office 365 SharePoint Online
-   - 2026-05-20 01:16 | 4.4.89.67 (Washington) | other | Office 365 SharePoint Online
-   - 2026-05-20 01:16 | 4.4.89.67 (Washington) | other | Office 365 SharePoint Online
-   - 2026-05-16 22:33 | 24.130.254.240 (Oakland) | other | Office 365 SharePoint Online
- **amcclure@forgepointcap.com** (6 failures):
-   - 2026-05-18 14:31 | 2601:647:6700:4060:60d8:e27e:2309:c2bc (Newark) | other | Office 365 SharePoint Online
-   - 2026-05-18 14:30 | 2601:647:6700:4060:60d8:e27e:2309:c2bc (Newark) | invalid_credentials | Office 365 SharePoint Online
-   - 2026-05-16 02:35 | 2601:647:6700:4060:788f:89ba:4f60:f2b3 (Newark) | other | Microsoft 365 Support Service
-   - 2026-05-16 02:30 | 2601:647:6700:4060:e9b8:9961:6702:8e (Newark) | other | Apple Internet Accounts
-   - 2026-05-16 02:30 | 2601:647:6700:4060:e9b8:9961:6702:8e (Newark) | other | Apple Internet Accounts
-   - 2026-05-14 17:54 | 2606:40c6:9a9f:6565:3d3e:deff:2602:f6b (Englewood) | invalid_credentials | Microsoft Office
- **tkelly@forgepointcap.com** (3 failures):
-   - 2026-05-20 16:26 | 192.145.118.235 (Santa Clara) | other | One Outlook Web
-   - 2026-05-18 01:58 | 76.226.67.180 (Palo Alto) | other | One Outlook Web
-   - 2026-05-15 17:11 | 76.226.67.180 (Palo Alto) | other | One Outlook Web
- **tloh@forgepointcap.com** (3 failures):
-   - 2026-05-14 18:03 | 2606:40c6:114d:c4ff:d4e1:9372:f3ec:58ab (Englewood) | invalid_credentials | Azure Active Directory PowerShell
-   - 2026-05-14 18:01 | 2606:40c6:eb69:3ec4:74a1:9782:3da7:c901 (Englewood) | invalid_credentials | SharePoint
-   - 2026-05-14 17:56 | 2606:40c6:cc10:490d:86f4:dc07:f56d:cf63 (Englewood) | invalid_credentials | Microsoft Azure PowerShell
- **jlau@forgepointcap.com** (2 failures):
-   - 2026-05-15 22:34 | 2601:645:c683:e830:9df7:2bd4:922:2efe (San Francisco) | other | One Outlook Web
-   - 2026-05-15 21:51 | 2601:645:c683:e830:9df7:2bd4:922:2efe (San Francisco) | other | One Outlook Web
- **rkirton@forgepointcap.com** (2 failures):
-   - 2026-05-14 18:56 | 2606:40c6:bcd0:dfd6:4101:5e91:2f17:35b (Englewood) | invalid_credentials | Microsoft Azure CLI
-   - 2026-05-14 18:34 | 2606:40c6:29dd:79e5:e353:ae45:8f55:d8c3 (Englewood) | invalid_credentials | Azure Active Directory PowerShell
- **wlin@forgepointcap.com** (2 failures):
-   - 2026-05-14 18:05 | 2606:40c6:511a:65d9:f01a:c80d:d32c:6d00 (Englewood) | invalid_credentials | Azure Active Directory PowerShell
-   - 2026-05-14 18:03 | 2606:40c6:688f:d4cd:1dcd:b7d2:a00a:3fe7 (Englewood) | invalid_credentials | Microsoft Office
- **aandreu@forgepointcap.com** (2 failures):
-   - 2026-05-14 17:59 | 2606:40c6:165:1c7:487f:891e:2a7e:8f8c (Englewood) | invalid_credentials | Microsoft Azure CLI
-   - 2026-05-14 17:59 | 2606:40c6:da0:346b:1a1e:1ab9:b534:d3f0 (Englewood) | invalid_credentials | Microsoft Office
- **jgoyarrola@forgepointcap.com** (1 failures):
-   - 2026-05-20 07:21 | 2606:40c6:3838:91a8:1b12:815b:bfc0:c97e (Englewood) | invalid_credentials | Microsoft Azure CLI
- **llee@forgepointcap.com** (1 failures):
-   - 2026-05-18 21:15 | 108.223.47.93 (East Palo Alto) | other | JCI B2C
- **dhenault@forgepointcap.com** (1 failures):
-   - 2026-05-17 10:32 | 188.214.8.189 (Croydon) | other | Office 365 SharePoint Online
- **kshih@forgepointcap.com** (1 failures):
-   - 2026-05-14 18:23 | 2606:40c6:556a:8c83:3b32:80dc:373c:a0b8 (Englewood) | invalid_credentials | Azure Active Directory PowerShell

**Recommendation:** Investigate repeated failures. Consider smart lockout policies.
