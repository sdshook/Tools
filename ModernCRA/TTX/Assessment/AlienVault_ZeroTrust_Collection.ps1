#Requires -Version 5.1
<#
.SYNOPSIS
    Zero Trust Assessment - AlienVault USM Anywhere API Collection
.DESCRIPTION
    READ-ONLY REST API pull (GET only, no config changes). Uses OAuth 2.0
    client-credentials auth per USM Anywhere API v2.0. Fully paginates
    through every page of results, not just the first one.
.NOTES
    Deliberately simple: this dumps raw alarm and event objects as JSON,
    unmodified, rather than picking specific fields into CSV. USM
    Anywhere's exact event schema varies by client, so guessing field
    names at collection time is unreliable, that risk belongs with
    analysis, not collection.

    Confirmed real endpoints: /oauth/token (auth), /alarms, /events.
    Confirmed real pagination: responses are HAL-style, with
    _links.next.href present on every page except the last, and a page
    object (size, totalElements, totalPages, number). This script follows
    _links.next.href until it's absent, so exports contain every matching
    record, not just the first page.

    IMPORTANT LIMITATION, a real product constraint: this API only reaches
    alarm/event data in local (non-cold) storage. Older data per the
    client's retention settings needs a console-based export instead.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Subdomain,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,
    [string]$OutputPath = ".\ZT_AlienVault_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmm')",
    [int]$LookbackDays = 30
)

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
Write-Host "Output folder: $OutputPath" -ForegroundColor Cyan

$baseUri = "https://$Subdomain.alienvault.cloud/api/2.0"
$script:tokenExpiry = Get-Date

function Get-USMToken {
    $pair = "$ClientId`:$ClientSecret"
    $basicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
    $resp = Invoke-RestMethod -Uri "$baseUri/oauth/token?grant_type=client_credentials" -Method Post -Headers @{ Authorization = "Basic $basicAuth" }
    $script:token = $resp.access_token
    $script:tokenExpiry = (Get-Date).AddMinutes(25)  # real token expiry is 30 min; refresh a bit early
}

function Invoke-USMQuery {
    param([string]$Uri)
    if ((Get-Date) -ge $script:tokenExpiry) { Get-USMToken }
    try {
        return Invoke-RestMethod -Uri $Uri -Method Get -Headers @{ Authorization = "Bearer $script:token" }
    } catch {
        Write-Host "  Query failed: $Uri - $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Follows _links.next.href across every page until it's absent, so the export
# contains every record matching the query, not just the first page.
function Get-USMAllPages {
    param([string]$FirstUri, [string]$EmbeddedKey)
    $allRecords = @()
    $uri = $FirstUri
    $pageNum = 0
    while ($uri) {
        $resp = Invoke-USMQuery -Uri $uri
        if (-not $resp) { break }
        if ($resp._embedded -and $resp._embedded.$EmbeddedKey) {
            $allRecords += $resp._embedded.$EmbeddedKey
        }
        $pageNum++
        $totalPages = if ($resp.page) { $resp.page.totalPages } else { '?' }
        Write-Host "  Page $pageNum of $totalPages, $($allRecords.Count) records so far..." -ForegroundColor DarkGray
        $uri = if ($resp._links -and $resp._links.next) { $resp._links.next.href } else { $null }
    }
    return $allRecords
}

Get-USMToken
Write-Host "Authenticated to $Subdomain.alienvault.cloud" -ForegroundColor Green

$sinceEpochMs = [DateTimeOffset]::UtcNow.AddDays(-$LookbackDays).ToUnixTimeMilliseconds()

Write-Host "[1/2] Security alarms, all pages, raw ($LookbackDays-day window)..." -ForegroundColor Yellow
$alarms = Get-USMAllPages -FirstUri "$baseUri/alarms?size=100&status=open&timestamp_occured_gte=$sinceEpochMs" -EmbeddedKey "alarms"
ConvertTo-Json -InputObject @($alarms) -Depth 20 | Out-File "$OutputPath\01_Alarms_Raw.json" -Encoding utf8
Write-Host "  $($alarms.Count) total alarms exported." -ForegroundColor Green

Write-Host "[2/2] Events, all pages, raw, unfiltered by value ($LookbackDays-day window)..." -ForegroundColor Yellow
$events = Get-USMAllPages -FirstUri "$baseUri/events?size=100&timestamp_occured_gte=$sinceEpochMs" -EmbeddedKey "events"
ConvertTo-Json -InputObject @($events) -Depth 20 | Out-File "$OutputPath\02_Events_Raw.json" -Encoding utf8
Write-Host "  $($events.Count) total events exported." -ForegroundColor Green

Write-Host @"

Collection complete. Zip and return the '$OutputPath' folder.
This API only reaches alarm/event data in local (non-cold) storage - older data may need a console-based export instead.
Both files contain every matching record across all pages, not just the first page.
Interpretation and filtering (what counts as a logon, a process-creation event, a VPN session, etc. in this environment) happens downstream during analysis, not here.
"@ -ForegroundColor Cyan
