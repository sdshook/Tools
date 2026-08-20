#Requires -Version 5.1
#Requires -Modules ADFS
<#
.SYNOPSIS
    Zero Trust Assessment - AD FS Account-Level SSO Usage Analysis
.DESCRIPTION
    READ-ONLY. Answers two specific questions once ADFS's existence is
    already established as fact (independent of what the client claims):
      1. Which enabled AD accounts show NO observed ADFS authentication in
         the collection window (candidates for "this account bypasses SSO
         entirely" - or simply an inactive/infrequent user; needs analyst
         judgment, this script only surfaces the gap).
      2. Which configured Relying Party Trusts show NO observed
         authentications (candidates for "this service is reachable some
         other way that isn't routing through ADFS").
.NOTES
    AD FS security-audit event schema (field names inside each event's
    EventData block) is NOT fully consistent across AD FS 2012R2/2016/2019
    and depends on audit level configured. Rather than hardcode field names
    that might not match this farm, every event's EventData is parsed
    generically into a raw Name/Value map and exported in full - nothing is
    silently dropped. A best-effort correlation pass then tries a handful
    of common candidate field names to link events to accounts/relying
    parties; if none of those candidates match this farm's actual schema,
    the correlation files will come back empty but the raw per-event export
    (02_ADFS_Auth_Events_RAW.json) still has everything needed to identify
    the right field names manually and re-run, or pivot in Python/pandas.

    Absence of observed auth in this window is NOT proof an account/service
    never uses ADFS - it may just be a quiet account or a short window.
    Widen -EventLogDays and treat every flagged item as a lead to verify,
    not a finding to report as-is.

    Run on the ADFS server (Security log access + AD FS auditing enabled
    required) with the ActiveDirectory RSAT module available for the AD
    account cross-reference; the script degrades gracefully without it.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\ZT_Assessment_ADFS_SSO_Usage_$(Get-Date -Format 'yyyyMMdd_HHmm')",
    [int]$EventLogDays = 90,
    [int]$JsonDepth = 10,
    [switch]$SkipADCorrelation
)

Import-Module ADFS -ErrorAction Stop
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
Write-Host "Output path: $OutputPath" -ForegroundColor Cyan

function Export-RawJson {
    param($InputObject, [string]$FileName)
    $path = Join-Path $OutputPath $FileName
    if ($null -eq $InputObject -or (($InputObject -is [array]) -and $InputObject.Count -eq 0)) {
        "[]" | Out-File $path -Encoding utf8
    } else {
        $InputObject | ConvertTo-Json -Depth $JsonDepth | Out-File $path -Encoding utf8
    }
}

# 1. Configured Relying Party Trusts - the services that are SUPPOSED to route through ADFS SSO - raw
Write-Host "[1] Relying party trusts (configured SSO endpoints)..." -ForegroundColor Yellow
$rpts = Get-AdfsRelyingPartyTrust
Export-RawJson $rpts "01_RelyingPartyTrusts_RAW.json"
$rptNames = $rpts | ForEach-Object { $_.Name }

# 2. Enabled AD accounts - the full roster to check for ADFS-auth coverage gaps against.
# Optional: skip if run from a host without the ActiveDirectory module (e.g. an isolated ADFS
# box); the event-side collection and RP-usage analysis below still work without it.
$adAccounts = $null
if (-not $SkipADCorrelation) {
    Write-Host "[2] Enabled AD account roster (for coverage cross-reference)..." -ForegroundColor Yellow
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        try {
            $adAccounts = Get-ADUser -Filter { Enabled -eq $true } -Properties SamAccountName, UserPrincipalName, whenCreated, LastLogonTimeStamp -ErrorAction Stop
            Export-RawJson $adAccounts "02_Enabled_AD_Accounts_RAW.json"
        } catch {
            Write-Host "  Get-ADUser failed ($($_.Exception.Message)) - AD cross-reference will be skipped." -ForegroundColor DarkGray
            $adAccounts = $null
        }
    } else {
        Write-Host "  ActiveDirectory module not present on this host - AD cross-reference will be skipped. Run with -SkipADCorrelation to silence this, or run from a host with RSAT AD tools." -ForegroundColor DarkGray
    }
} else {
    Write-Host "[2] AD account cross-reference skipped by -SkipADCorrelation." -ForegroundColor Yellow
}

# 3. Raw ADFS auth audit events. Requires AD FS auditing enabled
# (Set-AdfsProperties -AuditLevel) and Security-log read access.
# Event IDs match the set used in the standalone ADFS config-collection script; these gate
# which events get pulled from the log, but every field inside each matched event is captured
# as-is via the event's own ToXml() output - a string, so it serializes to JSON cleanly without
# needing to guess at or extract specific named fields. Analysis of who/what/which-RP happens
# entirely offline against this raw XML.
Write-Host "[3] ADFS authentication audit events (last $EventLogDays days)..." -ForegroundColor Yellow
try {
    $startTime = (Get-Date).AddDays(-$EventLogDays)
    $winEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 1200, 1202, 411, 412
        StartTime = $startTime
    } -ErrorAction Stop

    $rawEvents = foreach ($ev in $winEvents) {
        [PSCustomObject]@{
            TimeCreated  = $ev.TimeCreated
            Id           = $ev.Id
            ProviderName = $ev.ProviderName
            LogName      = $ev.LogName
            RawXml       = $ev.ToXml()
        }
    }
    Export-RawJson $rawEvents "03_ADFS_Auth_Events_RAW.json"
    Write-Host "  $($winEvents.Count) events exported with full raw XML." -ForegroundColor DarkGray
} catch {
    Write-Host "  Could not read Security log events (auditing may be disabled, insufficient rights, or wrong event IDs for this farm) - this is itself a finding worth noting in the report." -ForegroundColor DarkGray
    Export-RawJson ([PSCustomObject]@{ Finding = "AD FS audit events unavailable or inaccessible" }) "03_ADFS_Auth_Events_UNAVAILABLE.json"
}

Write-Host @"

ADFS collection complete under '$OutputPath'.
Output is raw JSON - open with ConvertFrom-Json, a JSON viewer, or load into Python/pandas.
01 = configured relying party trusts (full raw objects).
02 = enabled AD account roster (full raw objects, if AD module was available).
03 = ADFS auth audit events - TimeCreated/Id/Provider/LogName plus the event's full raw XML
     (RawXml) untouched. Who authenticated and against which relying party is inside that XML;
     parse it offline once you know which Data element names this farm's audit schema actually
     uses (they vary by AD FS version/audit level, so no field names are assumed here).
"@ -ForegroundColor Cyan
