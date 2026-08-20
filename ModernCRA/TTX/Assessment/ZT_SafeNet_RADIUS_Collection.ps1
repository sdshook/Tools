#Requires -Version 5.1
<#
.SYNOPSIS
    Zero Trust Assessment - SafeNet MFA Enrollment & Enforcement Collection
.DESCRIPTION
    READ-ONLY. Two independent parts - run whichever applies to the client's
    deployment (often both):
      PART A: SafeNet Authentication Service (SAS) enrollment data via the
              BSIDCA admin API (on-prem SAS or SAS Cloud).
      PART B: NPS/RADIUS server logs - shows what actually enforced MFA at
              the network/VPN edge, independent of what SAS claims is
              enrolled. Run on the NPS server(s) fronting VPN and any other
              RADIUS-authenticated access.

    Captures RAW objects as JSON rather than curated property lists. This
    matters especially for Part A, since Thales/SafeNet's admin API paths
    and field names vary meaningfully across on-prem SAS, SAS Cloud, and
    STA - a hand-picked property list is the most likely thing in this
    entire toolkit to silently return blank columns.
.NOTES
    Verify the SAS API paths against the client's SAS Admin Guide/API
    reference before relying on Part A output, and adjust -SASBaseUrl
    accordingly. If the API is inaccessible, the SAS Admin Console can
    usually export the same enrollment/token reports manually as a
    fallback. EXCEPTION: Windows event log records (NPS accounting events
    in Part B) don't serialize cleanly to JSON - that section extracts the
    handful of fields that are analyzable instead of the raw event object.
#>

[CmdletBinding()]
param(
    [string]$SASBaseUrl,                # e.g. https://sas.client.local/BSIDCA/RA (leave blank to skip Part A)
    [switch]$SkipSAS,
    [switch]$SkipNPS,
    [int]$NPSLogDays = 30,
    [string]$OutputPath = ".\ZT_Assessment_SafeNet_$(Get-Date -Format 'yyyyMMdd_HHmm')",
    [int]$JsonDepth = 8
)

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
Write-Host "Output path: $OutputPath" -ForegroundColor Cyan

function Export-RawJson {
    param($InputObject, [string]$FileName)
    $path = Join-Path $OutputPath $FileName
    # Explicit [] for null/empty results so "nothing found" is visually distinct from a
    # truncated/failed write - PowerShell's ConvertTo-Json otherwise emits a 0-byte file
    # for an empty array, which looks identical to a broken collection at a glance.
    if ($null -eq $InputObject -or (($InputObject -is [array]) -and $InputObject.Count -eq 0)) {
        "[]" | Out-File $path -Encoding utf8
    } else {
        $InputObject | ConvertTo-Json -Depth $JsonDepth | Out-File $path -Encoding utf8
    }
}

# ============================================================
# PART A: SafeNet Authentication Service enrollment data
# ============================================================
if (-not $SkipSAS -and $SASBaseUrl) {
    Write-Host "`n=== PART A: SafeNet Authentication Service (SAS) ===" -ForegroundColor Magenta
    $cred = Get-Credential -Message "SAS admin API read-only credentials"

    try {
        $authBody = @{ username = $cred.UserName; password = $cred.GetNetworkCredential().Password } | ConvertTo-Json
        $session = Invoke-RestMethod -Uri "$SASBaseUrl/session" -Method Post -Body $authBody -ContentType "application/json" -SessionVariable sasSession
        Write-Host "Authenticated to SAS." -ForegroundColor Green

        # A1. Token/enrollment inventory - who actually HAS a token/authenticator, not just who's "supposed to" - raw
        Write-Host "[A1] Token enrollment inventory..." -ForegroundColor Yellow
        try {
            $tokens = Invoke-RestMethod -Uri "$SASBaseUrl/tokens" -Method Get -WebSession $sasSession -ErrorAction Stop
            Export-RawJson $tokens "A1_SafeNet_Token_Enrollment_RAW.json"
        } catch {
            Write-Host "  Token endpoint failed - path/version likely differs from this template. Fall back to manual SAS Admin Console export." -ForegroundColor DarkGray
        }

        # A2. User enrollment status - flags users with NO enrolled authenticator at all - raw.
        # The "not enrolled" filter references fields that are common across SAS versions
        # (tokenCount / enrollmentStatus) but verify these names against this deployment; if
        # they differ, the filtered file will simply be empty rather than wrong - the raw
        # A2 dump is the ground truth regardless.
        Write-Host "[A2] User enrollment status..." -ForegroundColor Yellow
        try {
            $users = Invoke-RestMethod -Uri "$SASBaseUrl/users" -Method Get -WebSession $sasSession -ErrorAction Stop
            Export-RawJson $users "A2_SafeNet_User_Enrollment_Status_RAW.json"

            $notEnrolled = $users | Where-Object { $_.tokenCount -eq 0 -or $_.enrollmentStatus -notmatch 'enrolled|active' }
            Export-RawJson $notEnrolled "A3_SafeNet_Users_NOT_Enrolled_RAW.json"
        } catch {
            Write-Host "  User endpoint failed - path/version likely differs from this template. Fall back to manual SAS Admin Console export." -ForegroundColor DarkGray
        }

        # A3. Policy/group enforcement configuration - raw
        Write-Host "[A3] Authentication policies..." -ForegroundColor Yellow
        try {
            $policies = Invoke-RestMethod -Uri "$SASBaseUrl/policies" -Method Get -WebSession $sasSession -ErrorAction Stop
            Export-RawJson $policies "A4_SafeNet_Auth_Policies_RAW.json"
        } catch {
            Write-Host "  Policy endpoint failed - export manually from Admin Console if needed." -ForegroundColor DarkGray
        }

        try { Invoke-RestMethod -Uri "$SASBaseUrl/session" -Method Delete -WebSession $sasSession | Out-Null } catch {}
    } catch {
        Write-Warning "SAS authentication failed: $_. If the BSIDCA API path/auth model differs for this deployment, use the SAS Admin Console's built-in enrollment/usage reports as the collection source instead."
    }
} else {
    Write-Host "`nPART A (SAS API) skipped - no -SASBaseUrl provided or -SkipSAS set." -ForegroundColor DarkGray
}

# ============================================================
# PART B: NPS/RADIUS observed enforcement (VPN edge)
# ============================================================
if (-not $SkipNPS) {
    Write-Host "`n=== PART B: NPS/RADIUS (run on the NPS server) ===" -ForegroundColor Magenta

    # B1. NPS network policies - confirms SafeNet RADIUS proxy/vendor-specific attribute is
    # actually required, not optional. Already raw (native XML export, not a PowerShell object).
    Write-Host "[B1] NPS network policy export..." -ForegroundColor Yellow
    try {
        $npsExportPath = "$OutputPath\B1_NPS_Policy_Export.xml"
        netsh nps export filename="$npsExportPath" exportPSK=NO | Out-Null
        Write-Host "  NPS config exported to $npsExportPath - review conditions/constraints for each policy for a SafeNet/second-factor requirement." -ForegroundColor DarkGray
    } catch {
        Write-Host "  netsh nps export failed - may not be running on an NPS server, or insufficient rights." -ForegroundColor DarkGray
    }

    # B2. NPS accounting logs - observed RADIUS auth events (requires NPS accounting/logging
    # enabled). EXCEPTION: raw EventLogRecord objects carry non-serializable handles and won't
    # round-trip through ConvertTo-Json cleanly - extracting TimeCreated/Id/Message.
    Write-Host "[B2] NPS accounting log events (last $NPSLogDays days)..." -ForegroundColor Yellow
    try {
        $startTime = (Get-Date).AddDays(-$NPSLogDays)
        $npsEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 6272, 6273  # 6272 = granted, 6273 = denied
            StartTime = $startTime
        } -ErrorAction Stop

        $npsEvents | ForEach-Object {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                Id          = $_.Id
                Message     = $_.Message
            }
        } | ConvertTo-Json -Depth $JsonDepth | Out-File "$OutputPath\B2_NPS_Auth_Events.json" -Encoding utf8

        Write-Host "  Exported $($npsEvents.Count) NPS auth events. Parse for the SafeNet vendor-specific attribute/RADIUS class to confirm second-factor was present on granted sessions." -ForegroundColor DarkGray
    } catch {
        Write-Host "  Could not read NPS accounting events - NPS logging to Security log may be disabled, or this isn't the NPS server. This is itself a finding worth noting: without accounting logs, VPN MFA enforcement can't be independently verified." -ForegroundColor DarkGray
        Export-RawJson ([PSCustomObject]@{ Finding = "NPS accounting/logging appears disabled or inaccessible - VPN MFA enforcement cannot be validated against observed logon behavior" }) "B2_NPS_Auth_Events_UNAVAILABLE.json"
    }

    # B3. IAS/NPS SQL/text accounting log location check (if file-based logging is used instead
    # of Security log) - raw FileInfo objects
    Write-Host "[B3] File-based NPS accounting log check..." -ForegroundColor Yellow
    $iasLogPath = "$env:systemroot\System32\LogFiles"
    if (Test-Path $iasLogPath) {
        $iasLogFiles = Get-ChildItem $iasLogPath -Filter "IN*.log" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-$NPSLogDays) }
        Export-RawJson $iasLogFiles "B3_NPS_FileLog_Inventory_RAW.json"
        Write-Host "  Listed candidate IAS/NPS log files (not parsed - format is fixed-width/CSV per RFC 2865/2866 attribute dump; parse separately if present)." -ForegroundColor DarkGray
    }
} else {
    Write-Host "`nPART B (NPS/RADIUS) skipped by -SkipNPS." -ForegroundColor DarkGray
}

Write-Host @"

SafeNet/RADIUS collection complete under '$OutputPath'.
Output is raw JSON (Part A) or minimally-extracted JSON (Part B event logs, for serialization reasons) - open with ConvertFrom-Json, a JSON viewer, or load into Python/pandas for analysis.
Notes:
- A3_SafeNet_Users_NOT_Enrolled_RAW.json (if produced) is the direct evidence for/against "MFA enforced for all accounts" - but confirm the field names it filtered on (tokenCount/enrollmentStatus) actually match what's in A2's raw dump for this SAS version.
- If Part A's API calls failed, the SAS Admin Console's built-in "Token Status" and "User Enrollment" reports are the manual fallback - note in your findings that automated collection wasn't possible and why.
- B1's exported NPS policy XML must be reviewed manually for whether the SafeNet RADIUS attribute/condition is mandatory on every policy that matches VPN connection requests, vs only some.
"@ -ForegroundColor Cyan
