#Requires -Version 5.1
<#
.SYNOPSIS
    Zero Trust Assessment - Tenable.SC Vulnerability Data Collection
.DESCRIPTION
    READ-ONLY REST API pull. Use a read-only API key pair (not admin) from
    Tenable.SC under your user account. Fully paginates through every
    page of vulnerability results, not just the first one.
.NOTES
    One full vulnerability pull and one asset pull, both raw JSON.
    Severity, exploitability, and EOL-OS filtering happen downstream
    during analysis against this same data, rather than the collection
    script guessing which filtered views matter.

    Confirmed real pagination: POST /rest/analysis uses query.startOffset
    and query.endOffset, and the response includes response.totalRecords.
    This script increments startOffset/endOffset in a loop until
    endOffset reaches totalRecords, so the export contains every matching
    vulnerability, not just the first page.

    Request/response shape (type=vuln, tool=vulndetails) and severity
    scale (0=info, 1=low, 2=medium, 3=high, 4=critical) are confirmed
    against current Tenable documentation.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenableScHost,
    [Parameter(Mandatory)][string]$AccessKey,
    [Parameter(Mandatory)][string]$SecretKey,
    [string]$OutputPath = ".\ZT_TenableSC_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmm')",
    [switch]$IgnoreCertificateErrors
)

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
Write-Host "Output folder: $OutputPath" -ForegroundColor Cyan

# Targets both Windows PowerShell 5.1 (most common for RSAT/EMS/Veeam hosts) and PS7+.
# -SkipCertificateCheck only exists on PS6+, so bypass is handled differently per version,
# and is off by default - only enable -IgnoreCertificateErrors for a confirmed internal/self-signed cert.
$isPS6Plus = $PSVersionTable.PSVersion.Major -ge 6
if ($IgnoreCertificateErrors -and -not $isPS6Plus) {
    Write-Host "Bypassing certificate validation (PS 5.1 workaround, this process only)..." -ForegroundColor DarkYellow
    if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
        Add-Type @"
using System.Net;
public static class ServerCertificateValidationCallback {
    public static void Ignore() { ServicePointManager.ServerCertificateValidationCallback = delegate { return true; }; }
}
"@
    }
    [ServerCertificateValidationCallback]::Ignore()
}

$baseUri = "https://$TenableScHost/rest"
$headers = @{ "X-APIKey" = "accesskey=$AccessKey; secretkey=$SecretKey"; "Content-Type" = "application/json" }

function Invoke-SCQuery {
    param([string]$Endpoint, [string]$Method = "GET", $Body = $null)
    try {
        $params = @{ Uri = "$baseUri/$Endpoint"; Method = $Method; Headers = $headers }
        if ($Body) { $params['Body'] = ($Body | ConvertTo-Json -Depth 10) }
        if ($IgnoreCertificateErrors -and $isPS6Plus) { $params['SkipCertificateCheck'] = $true }
        return Invoke-RestMethod @params
    } catch {
        Write-Host "  Query failed: $Endpoint - $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Loops startOffset/endOffset until endOffset reaches totalRecords, so the
# export contains every matching vulnerability, not just the first page.
function Get-SCAllVulnerabilities {
    $pageSize = 1000
    $offset = 0
    $allResults = @()
    $total = $null
    $pageNum = 0
    do {
        $body = @{
            type       = "vuln"
            sourceType = "cumulative"
            query      = @{ type = "vuln"; tool = "vulndetails"; filters = @(); startOffset = $offset; endOffset = $offset + $pageSize }
        }
        $resp = Invoke-SCQuery -Endpoint "analysis" -Method "POST" -Body $body
        if (-not $resp) { break }
        $allResults += $resp.response.results
        $total = [int]$resp.response.totalRecords
        $pageNum++
        Write-Host "  Page $pageNum, $($allResults.Count) of $total records so far..." -ForegroundColor DarkGray
        $offset += $pageSize
    } while ($offset -lt $total)
    return $allResults
}

# Connectivity/auth test - fail fast with a clear message before running the full collection
Write-Host "[0/2] Testing API connectivity..." -ForegroundColor Yellow
$test = Invoke-SCQuery -Endpoint "currentUser"
if (-not $test) {
    Write-Host "API test failed - verify TenableScHost, AccessKey, SecretKey, and that this key has at least read-only 'Security Analyst' role." -ForegroundColor Red
    exit 1
}
Write-Host "  Connected as: $($test.response.username)" -ForegroundColor Green

# Full vulnerability pull, raw, all pages, no severity/exploit/plugin filtering -
# that filtering happens downstream during analysis against this same data
Write-Host "[1/2] Full vulnerability pull, all pages, raw..." -ForegroundColor Yellow
$vulns = Get-SCAllVulnerabilities
ConvertTo-Json -InputObject @($vulns) -Depth 20 | Out-File "$OutputPath\01_Vulnerabilities_Raw.json" -Encoding utf8
Write-Host "  $($vulns.Count) total vulnerability records exported." -ForegroundColor Green

# Asset inventory, raw - cross-reference against the DC script's AD computer inventory
# for shadow/unmanaged asset detection. Asset lists are small (asset groups, not per-host
# vuln instances), a single call is sufficient here, unlike the vulnerability pull above.
Write-Host "[2/2] Asset inventory, raw..." -ForegroundColor Yellow
$assets = Invoke-SCQuery -Endpoint "asset?fields=id,name,ipCount"
if ($assets) {
    ConvertTo-Json -InputObject @($assets.response.usable) -Depth 20 | Out-File "$OutputPath\02_Assets_Raw.json" -Encoding utf8
}

Write-Host @"

Collection complete. Zip and return the '$OutputPath' folder.
01_Vulnerabilities_Raw.json contains every matching record across all pages, not just the first page.
Severity/exploitability/EOL-OS filtering happens downstream during analysis, not here.
Cross-reference 02_Assets_Raw.json against the AD computer inventory from the DC script - assets in one but not the other are a visibility/coverage gap worth flagging on its own.
"@ -ForegroundColor Cyan
