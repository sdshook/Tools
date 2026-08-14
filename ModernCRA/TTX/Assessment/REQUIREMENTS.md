# Requirements and Prerequisites

All five scripts are read-only (no Set-/New-/Remove-/Add- cmdlets), target
PowerShell 5.1+ (tested on 7.4.6, validated for 5.1 compatibility since
that's the more common runtime for RSAT/EMS/Veeam environments), and were
functionally tested end to end against stub/mock cmdlets before delivery,
including edge cases (never-rotated passwords, orphaned GPOs, forwarding
rules, audit bypass, expired API credentials, single-item API results),
not just syntax-checked.

The two REST API scripts (Tenable.SC, AlienVault) output raw JSON rather
than curated CSV. Those APIs' data shape can vary by client configuration
in ways the AD/Exchange/Veeam cmdlets don't, so guessing field names or
running several separately-filtered queries at collection time would put
schema risk on whoever runs the script. Raw JSON removes that risk
entirely; filtering and interpretation happen downstream during analysis
against the same complete data instead.

No credentials or secrets are ever written to output. The Veeam script's
credential inventory exports usernames only, verified during testing.

DC, Exchange, and Veeam output plain CSV, readable directly in Excel.
Tenable.SC and AlienVault output raw JSON, readable in any text editor or
via `ConvertFrom-Json` in PowerShell.

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
