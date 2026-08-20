#Requires -Version 5.1
<#
.SYNOPSIS
    Zero Trust Assessment - CyberArk PAM Collection (PVWA REST API)
.DESCRIPTION
    READ-ONLY. Uses GET calls only against the PVWA REST API. No account
    changes, no vault modifications, no CPM actions triggered.

    Captures RAW API response objects as JSON rather than curated property
    lists. PVWA's REST schema varies meaningfully by version/configuration,
    so hand-picking properties risks silently blank columns if a field is
    named or nested differently on this deployment. The raw JSON preserves
    whatever the API actually returned; analysis happens downstream.
.NOTES
    Requires a PVWA user with Audit/Read privileges (a dedicated read-only
    "Auditor" role account is strongly preferred over using an admin
    account for this collection). Supports CyberArk (LDAP/RADIUS/SAML)
    authentication - adjust the logon endpoint if using a different method.
    Tested against PVWA REST API v12+ URL conventions; endpoint paths can
    shift slightly between versions - verify against your PVWA's Swagger/
    API reference if a call 404s.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PVWAUrl,          # e.g. https://pvwa.client.local/PasswordVault
    [string]$AuthType = "CyberArk",                  # CyberArk, LDAP, RADIUS, Windows, SAML
    [string]$OutputPath = ".\ZT_Assessment_CyberArk_$(Get-Date -Format 'yyyyMMdd_HHmm')",
    [int]$JsonDepth = 10
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

# --- Authenticate ---
$cred = Get-Credential -Message "CyberArk PVWA read-only auditor credentials"
$logonBody = @{
    username = $cred.UserName
    password = $cred.GetNetworkCredential().Password
    concurrentSession = $true
} | ConvertTo-Json

try {
    $token = Invoke-RestMethod -Uri "$PVWAUrl/api/auth/$AuthType/Logon" -Method Post -Body $logonBody -ContentType "application/json"
} catch {
    Write-Error "PVWA logon failed: $_"
    return
}
$headers = @{ Authorization = $token }
Write-Host "Authenticated to PVWA." -ForegroundColor Green

function Invoke-PVWAGet {
    param([string]$Endpoint, [string]$Description)
    try {
        Invoke-RestMethod -Uri "$PVWAUrl/api$Endpoint" -Method Get -Headers $headers -ErrorAction Stop
    } catch {
        Write-Host "  Skipped ($Description): $($_.Exception.Message)" -ForegroundColor DarkGray
        $null
    }
}

# 1. Safes inventory - raw
Write-Host "[1] Safes inventory..." -ForegroundColor Yellow
$safes = Invoke-PVWAGet -Endpoint "/Safes?limit=1000" -Description "safes list"
if ($safes) { Export-RawJson $safes.value "01_Safes_Inventory_RAW.json" }

# 2. Vaulted accounts inventory (the core "is this account actually in PAM" list) - raw
Write-Host "[2] Vaulted accounts inventory..." -ForegroundColor Yellow
$allAccounts = @()
$offset = 0; $limit = 1000
do {
    $page = Invoke-PVWAGet -Endpoint "/Accounts?offset=$offset&limit=$limit" -Description "accounts page offset $offset"
    if ($page -and $page.value) {
        $allAccounts += $page.value
        $offset += $limit
    } else { break }
} while ($page.value.Count -eq $limit)

Export-RawJson $allAccounts "02_Vaulted_Accounts_Inventory_RAW.json"
Write-Host "  $($allAccounts.Count) vaulted accounts collected." -ForegroundColor DarkGray

# 3. Platforms - confirms rotation policy actually configured per platform (not just default) - raw
Write-Host "[3] Platform configurations..." -ForegroundColor Yellow
$platforms = Invoke-PVWAGet -Endpoint "/Platforms" -Description "platforms list"
if ($platforms) { Export-RawJson $platforms.Platforms "03_Platform_Configurations_RAW.json" }

# 4. Accounts with automatic management DISABLED - static/unrotated creds hiding in the vault.
# Filter necessarily references the nested secretManagement property to target the flag;
# flagged output remains the full raw account object.
Write-Host "[4] Accounts with automatic rotation disabled..." -ForegroundColor Yellow
$autoRotationDisabled = $allAccounts | Where-Object { $_.secretManagement.automaticManagementEnabled -eq $false }
Export-RawJson $autoRotationDisabled "04_Accounts_AutoRotation_Disabled_RAW.json"

# 5. Safe members / permissions - who has access to each safe (least-privilege check).
# SafeName is injected as context since the per-safe API call doesn't return it on the
# member object itself; the member sub-object is otherwise captured raw and unmodified.
Write-Host "[5] Safe membership & permissions..." -ForegroundColor Yellow
$safeMembers = foreach ($safe in $safes.value) {
    $members = Invoke-PVWAGet -Endpoint "/Safes/$([uri]::EscapeDataString($safe.safeName))/Members?limit=1000" -Description "members of $($safe.safeName)"
    if ($members) {
        foreach ($m in $members.value) {
            [PSCustomObject]@{
                SafeName = $safe.safeName
                Member   = $m
            }
        }
    }
}
Export-RawJson $safeMembers "05_Safe_Membership_Permissions_RAW.json"

# 6. PSM (session recording/isolation) usage - confirms privileged sessions are actually
# broker-mediated, not just password-vaulted. Filter targets a nested property; flagged
# output is the full raw platform object.
Write-Host "[6] PSM-enabled platform check..." -ForegroundColor Yellow
if ($platforms) {
    $psmPlatforms = $platforms.Platforms | Where-Object { $_.Properties.'General'.PSMServerId }
    Export-RawJson $psmPlatforms "06_Platforms_With_PSM_RAW.json"
}

# 7. Vault users - PVWA/vault-level user accounts and their auth methods (does CyberArk itself
# require MFA to log in?) - raw
Write-Host "[7] Vault-level user accounts..." -ForegroundColor Yellow
$vaultUsers = Invoke-PVWAGet -Endpoint "/Users?limit=1000" -Description "vault users"
if ($vaultUsers) { Export-RawJson $vaultUsers.Users "07_Vault_User_Accounts_RAW.json" }

# 8. Discovered/pending accounts - unmanaged privileged accounts CyberArk has found but not yet
# onboarded - raw
Write-Host "[8] Pending/discovered (not yet onboarded) accounts..." -ForegroundColor Yellow
$discovered = Invoke-PVWAGet -Endpoint "/DiscoveredAccounts?limit=1000" -Description "discovered accounts"
if ($discovered) { Export-RawJson $discovered.value "08_Discovered_Unmanaged_Accounts_RAW.json" }

# --- Logoff ---
try { Invoke-RestMethod -Uri "$PVWAUrl/api/auth/Logoff" -Method Post -Headers $headers | Out-Null } catch {}

Write-Host @"

CyberArk collection complete under '$OutputPath'.
Output is raw JSON per endpoint - open with ConvertFrom-Json, a JSON viewer, or load into Python/pandas for analysis.
Notes:
- 02_Vaulted_Accounts_Inventory_RAW.json is the authoritative list of what IS in PAM.
- 08_Discovered_Unmanaged_Accounts_RAW.json shows privileged accounts CyberArk found on the network but that are NOT yet vaulted - a direct "PAM enforced for all accounts" gap.
- 04_Accounts_AutoRotation_Disabled_RAW.json flags vaulted-but-not-actually-rotating accounts.
- 07_Vault_User_Accounts_RAW.json's authenticationMethod field (name may vary by version - check the raw object) shows whether MFA/RADIUS is required to reach the vault itself.
"@ -ForegroundColor Cyan
