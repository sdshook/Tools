# Requirements and Prerequisites

All nine scripts are read-only (no Set-/New-/Remove-/Add- cmdlets), target
PowerShell 5.1+ (tested on 7.4.6, validated for 5.1 compatibility since
that's the more common runtime for RSAT/EMS/Veeam/AD FS environments), and
were functionally tested end to end against stub/mock cmdlets before
delivery, including edge cases, not just syntax-checked.

The REST API and event-log scripts (Tenable.SC, AlienVault, CyberArk PVWA,
AD FS) output raw JSON rather than curated CSV. Those APIs' and event
schemas can vary by client configuration and server version in ways the
AD/Exchange/Veeam cmdlets don't, so guessing field names or running
several separately-filtered queries at collection time would put schema
risk on whoever runs the script. Raw JSON removes that risk entirely;
filtering and interpretation happen downstream during analysis against the
same complete data instead.

No credentials or secrets are ever written to output. The Veeam script's
credential inventory exports usernames only. The CyberArk script exports
account metadata only; no vault passwords are requested or returned by the
API calls made.

DC, Exchange, and Veeam output plain CSV, readable directly in Excel.
Tenable.SC, AlienVault, CyberArk, and both AD FS scripts output raw JSON,
readable in any text editor or via `ConvertFrom-Json` in PowerShell.

---

## 1. DC_ZeroTrust_Collection.ps1

**Module:** `ActiveDirectory` (RSAT), hard-required via `#Requires`, fails
fast with a clear message if missing rather than partway through. Install:
Windows Settings > Optional Features > RSAT: Active Directory Domain
Services and Lightweight Directory Tools, or already present on any DC.

**Optional:** `GroupPolicy` (GPO sections) and `DnsServer` (DNS cross-check
in the segmentation section) - both skip gracefully with a console message
if absent, rather than erroring.

**Access:** standard AD read, delegated read-only account. No elevated or
write rights needed anywhere.

**Run context:** any domain-joined host with the modules above, able to
reach every domain passed via `-Domains`.

| Parameter | Required | Default | Notes |
|---|---|---|---|
| `-Domains` | No | Two example placeholder domains | String array, e.g. `-Domains @('contoso.com','contoso-west.com')` |
| `-OutputRoot` | No | Timestamped folder, current directory | Each domain gets its own subfolder |

---

## 2. Exchange_ZeroTrust_Collection.ps1

**Environment:** an active Exchange Management Shell (EMS) session on an
Exchange server, or a workstation with the Exchange management tools and a
remote EMS session established. EMS cmdlets load via implicit remoting,
not `Import-Module`, so there's no `#Requires -Modules` gate here, running
outside an EMS session simply fails immediately with "cmdlet not
recognized," which is an acceptably clear failure mode. Microsoft doesn't
officially support EMS under PowerShell 7, run this one in 5.1.

**Access:** built-in **View-Only Organization Management** RBAC role,
sufficient for every cmdlet, no mailbox content is opened, only
configuration/metadata.

**Performance:** sections 6, 8, and 9 iterate every mailbox individually
(required for correctness, Exchange doesn't expose these settings in bulk).
Budget extra time on large mailbox counts; consider running off-hours.

| Parameter | Required | Default | Notes |
|---|---|---|---|
| `-OutputPath` | No | Timestamped folder, current directory | |

---

## 3. Veeam_ZeroTrust_Collection.ps1

**Module:** `Veeam.Backup.PowerShell` (confirmed v12, build 12.3.2.3617),
hard-required via `#Requires`. Ships with the Veeam B&R console; install
the console component if running from a separate management workstation.
Every cmdlet and property in this script is verified against current
Veeam PowerShell reference documentation, not guessed.

**Access:** Veeam read-only/viewer role covers every cmdlet except one,
the service account check uses `Get-CimInstance` against `Win32_Service`,
which needs local admin or remote WMI/CIM read access on the Veeam server
itself. Without it, that section fails gracefully and tells you to either
re-run on the Veeam console or pull the account manually (Services
console > VeeamBackupSvc > Log On tab).

**Deliberately excluded, no confirmed method exists:** job-to-repository
resolution, server-to-credential mapping (the real methods are
type-specific: `GetSoapCreds` for vCenter/ESXi, `GetSshCreds` for Linux,
`FindCreds` for Hyper-V, too fragile to script universally), and
replication job source/target host mapping. Check these in the Veeam
console directly if needed, the script says so at each relevant point
rather than guessing a property name that might not exist or might
silently return wrong data.

**Run context:** the Veeam B&R server itself, or a console-connected host.

**Out of scope by design:** NetBackup (v10.4.0.1) is Oracle-only, a
narrower scope than this assessment prioritizes. Request a manual export
from the NetBackup/Oracle DBA team separately if it becomes relevant.

| Parameter | Required | Default | Notes |
|---|---|---|---|
| `-OutputPath` | No | Timestamped folder, current directory | |

---

## 4. TenableSC_ZeroTrust_Collection.ps1

**Module:** none, only built-in `Invoke-RestMethod`/`ConvertTo-Json`
(available since PS 3.0).

**Access:** a **read-only API key pair** (not admin) with at least
**Security Analyst** role, generated under Tenable.SC > username (top
right) > My Account > API Keys. Every query here is GET or a read-only
POST /analysis, no scans or config changes.

**Network:** HTTPS (443) reachability to the Tenable.SC instance. For a
self-signed/internal cert, use `-IgnoreCertificateErrors` rather than
disabling certificate validation system-wide, off by default since
silently bypassing cert checks is a real security-reducing default. Works
correctly on both PS 5.1 and 7+, tested on both code paths.

**Output is raw JSON, not CSV.** One full, unfiltered vulnerability pull
and one asset pull, both exactly as the API returns them. Severity,
exploitability, and EOL-OS filtering happen downstream during analysis
against this same data, rather than the collection script guessing which
filtered views matter and running a separate query for each.

**Fully paginated.** The vulnerability pull loops through
`startOffset`/`endOffset` until it reaches the API's own `totalRecords`
count, so the export contains every matching vulnerability, not just the
first 1,000-record page. Tested against a simulated 2,500-record,
3-page response before delivery to confirm no records are dropped or
duplicated. The vulnerability pull is unwindowed by date on purpose,
vulnerability data is current state, not a time-windowed log, see
`VisionOne_Hunting_Playbook.md` for why a 30-day filter would be wrong
here.

**Validate first:** step `[0/2]` runs a live connectivity/auth test before
the full collection and exits immediately with a clear message on failure.

| Parameter | Required | Default | Notes |
|---|---|---|---|
| `-TenableScHost` | Yes | | Hostname only, no `https://` prefix |
| `-AccessKey` | Yes | | From the API key pair above |
| `-SecretKey` | Yes | | From the API key pair above |
| `-OutputPath` | No | Timestamped folder, current directory | |
| `-IgnoreCertificateErrors` | No | Off | Only for a confirmed self-signed/internal cert |

---

## 5. AlienVault_ZeroTrust_Collection.ps1

**Module:** none, only built-in `Invoke-RestMethod`.

**Access:** an API client (Client ID + Secret) created under USM Anywhere
> Profile Settings > API Clients, requires the **Manager** role to create
(the client itself only needs read access to alarms/events once created).
Available on Standard and Premium editions only.

**Auth:** OAuth 2.0 client-credentials flow, handled automatically by the
script, including token refresh (tokens expire after 30 minutes; the
script refreshes a few minutes early rather than waiting for a 401).

**Known limitation, a real product constraint:** the API only reaches
alarm/event data in local (non-cold) storage, older data per the client's
retention settings may need a console-based export instead.

**Output is raw JSON, not CSV.** Two files, alarms and events, exactly as
the API returns them, no field selection or value filtering happens in
this script. USM Anywhere's event schema varies by client (depends on
which data source plugins are configured), so guessing field names or
filter values at collection time is unreliable, that risk and burden
belongs with analysis, not with whoever runs this script. A single-item
result is still wrapped in a JSON array for consistency, this was tested
explicitly since PowerShell's `ConvertTo-Json` silently collapses
single-element arrays into a bare object otherwise.

**Fully paginated.** Follows the API's `_links.next.href` across every
page until it's absent, so exports contain every matching record within
the lookback window, not just the first page. Tested against a simulated
3-page, 5-record response before delivery to confirm the loop terminates
correctly and no records are dropped.

**Default lookback is 30 days**, matching the rest of this engagement's
collection windows.

| Parameter | Required | Default | Notes |
|---|---|---|---|
| `-Subdomain` | Yes | | The `<subdomain>` in `https://<subdomain>.alienvault.cloud` |
| `-ClientId` | Yes | | From the API client created above |
| `-ClientSecret` | Yes | | From the API client created above |
| `-OutputPath` | No | Timestamped folder, current directory | |
| `-LookbackDays` | No | 30 | Query window for alarms/events |

---

## 6. ZT_ADFS_Collection.ps1

**Module:** `ADFS`, hard-required via `#Requires`. Present by default on
every AD FS server; not available remotely without the federation proxy
tools. Run this script on the AD FS server itself — not a member server
or workstation.

**Access:** account with AD FS read/audit rights. Local administrator on
the AD FS server is the simplest option; a delegated account is sufficient
if it has been granted AD FS audit role access explicitly.

**Event log dependency:** step 9 (observed authentication events) requires
Security event log read access and AD FS auditing enabled at the farm
level. If auditing is off, step 9 writes an `_UNAVAILABLE` file noting
the gap and the rest of the script completes normally. To check the
current audit level without changing it: `Get-AdfsProperties |
Select-Object AuditLevel`. An `AuditLevel` of `None` means no events
will be present regardless of log read access.

**Output is raw JSON.** Every `Get-Adfs*` cmdlet returns the full object
exactly as the server reports it, including nested structures that CSV
would flatten into useless `System.Object[]` strings. X.509 certificate
objects and Windows event log records are the two exceptions — both carry
non-serializable handles; those sections extract the fields that are
actually usable (thumbprint, subject, not-after date; TimeCreated, Id,
Message) rather than attempting a full object dump.

**Run context:** the AD FS server, or a federation proxy server with the
ADFS module installed.

| Parameter | Required | Default | Notes |
|---|---|---|---|
| `-OutputPath` | No | Timestamped folder, current directory | |
| `-EventLogDays` | No | 30 | Lookback window for step 9 auth events |
| `-JsonDepth` | No | 8 | ConvertTo-Json depth; increase if nested objects truncate |

---

## 7. ZT_ADFS_SSO_Usage_Analysis.ps1

**Module:** `ADFS`, hard-required. Same constraint as script 6 — run on
the AD FS server directly.

**Optional:** `ActiveDirectory` (RSAT) for the account cross-reference
step (step 2). If the AD FS server does not have RSAT installed, pass
`-SkipADCorrelation` to skip that step; the event-log collection (step 3)
still runs and is the primary output of this script.

**Event log dependency:** same as script 6. AD FS auditing must be enabled
for step 3 to return data. Without it, step 3 produces an `_UNAVAILABLE`
file and the script still completes.

**Output is raw JSON.** Authentication events are stored as the full raw
XML string (via `.ToXml()`) rather than parsed field extractions. AD FS
audit event schema field names are not consistent across server versions
and audit levels, so baking in field-name assumptions at collection time
would produce silently empty columns on a mismatched version. The raw XML
is parseable offline once the actual field names for this deployment are
known.

**Run context:** the AD FS server, with the same account as script 6.

| Parameter | Required | Default | Notes |
|---|---|---|---|
| `-OutputPath` | No | Timestamped folder, current directory | |
| `-EventLogDays` | No | 90 | Lookback window for auth event collection |
| `-SkipADCorrelation` | No | Off | Skip the AD account cross-reference if RSAT is not present |
| `-JsonDepth` | No | 10 | ConvertTo-Json depth |

---

## 8. ZT_CyberArk_Collection.ps1

**Module:** none. Uses only built-in `Invoke-RestMethod` against the PVWA
REST API. Tested against PVWA REST API v12+ URL conventions; endpoint
paths can shift slightly between versions — verify against the PVWA's own
Swagger/API reference at `https://<pvwa>/PasswordVault/swagger` if a call
returns 404.

**Access:** a PVWA account with the **Auditor** role, or a custom role
with at minimum: List Safes, View Safe Details, List Accounts, View
Accounts, View Safe Members. A dedicated read-only auditor account is
strongly preferred over an admin account. Credentials are prompted
interactively via `Get-Credential` and are not written anywhere.

**Auth type:** `-AuthType` defaults to `CyberArk` (native vault
authentication). Change to `LDAP`, `RADIUS`, or `Windows` if the auditor
account authenticates via those methods. RADIUS authentication will prompt
for an OTP code during the `Get-Credential` step — the OTP is passed as
part of the password field, separated by a comma, per CyberArk's RADIUS
convention.

**Network:** HTTPS (443) reachability to the PVWA from the machine running
the script.

**Fully paginated.** The accounts endpoint loops in 1,000-record pages
until the API returns a partial page, so the export contains every vaulted
account, not just the first page.

**Output is raw JSON.** The PVWA API's account object schema — especially
the nested `secretManagement` and `platformAccountProperties` structures —
varies by platform configuration and PVWA version. Raw JSON preserves
whatever the API returns, including those nested structures; a curated CSV
would flatten or lose them.

**No passwords are returned.** The PVWA API does not return credential
values on account list or detail endpoints; this script makes no attempt
to retrieve them.

| Parameter | Required | Default | Notes |
|---|---|---|---|
| `-PVWAUrl` | Yes | | Full base URL, e.g. `https://pvwa.contoso.com/PasswordVault` |
| `-AuthType` | No | `CyberArk` | `CyberArk`, `LDAP`, `RADIUS`, or `Windows` |
| `-OutputPath` | No | Timestamped folder, current directory | |
| `-JsonDepth` | No | 10 | ConvertTo-Json depth |

---

## 9. ZT_SafeNet_RADIUS_Collection.ps1

**Two independent parts.** Run whichever applies to the deployment — often
both, but from different machines. Pass `-SkipSAS` to run Part B only, or
`-SkipNPS` to run Part A only.

**Part A — SafeNet Authentication Service (SAS) API**

**Module:** none. Uses only built-in `Invoke-RestMethod`.

**Access:** SAS admin account with read-only / reporting access.

**API path caveat:** the `-SASBaseUrl` default matches the common
on-premises BSIDCA REST interface. Thales/SafeNet does not have a single
universal API path across on-premises SAS, SAS Cloud, and SafeNet Trusted
Access (STA). Verify the correct base URL against the SAS Admin Guide for
this specific deployment before running. If API calls return 404, the
manual fallback is a console export from the SAS Admin Console: Token
Status report and User Enrollment report. Note in findings that automated
collection was not possible and the reason.

**Network:** HTTPS reachability to the SAS instance.

**Part B — NPS/RADIUS Accounting Logs**

**Run context:** the NPS server fronting VPN or other RADIUS-authenticated
access. Not a general-purpose host — `netsh nps export` and the Security
event log queries in Part B are only meaningful on the NPS server itself.

**Access:** local administrator, or Security Event Log read access on the
NPS server.

**Event log dependency:** Part B's accounting events (event IDs 6272/6273)
require NPS accounting logging to the Security log to be enabled. If
logging is off, Part B writes an `_UNAVAILABLE` file noting the gap and
the NPS policy XML export (via `netsh`) still runs. The absence of NPS
accounting logs is itself a finding — without them, VPN MFA enforcement
cannot be verified against observed logon behavior.

**Output:** Part A outputs raw JSON (SAS API responses exactly as returned).
Part B outputs the NPS policy as a native XML export and security event
log records as minimally-extracted JSON (TimeCreated, Id, Message) — raw
EventLogRecord objects carry non-serializable handles, so a full object
dump is not possible; the three extracted fields are what's analyzable.

| Parameter | Required | Default | Notes |
|---|---|---|---|
| `-SASBaseUrl` | Conditional | | Required for Part A. Leave blank or use `-SkipSAS` to skip Part A |
| `-SkipSAS` | No | Off | Skip Part A entirely |
| `-SkipNPS` | No | Off | Skip Part B entirely |
| `-NPSLogDays` | No | 30 | Lookback window for Part B event log query |
| `-OutputPath` | No | Timestamped folder, current directory | |
| `-JsonDepth` | No | 8 | ConvertTo-Json depth for Part A |
