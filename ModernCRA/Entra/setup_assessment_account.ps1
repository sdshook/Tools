<#
.SYNOPSIS
    Entra Security Assessment Account Setup
    Run ONCE with a Global Administrator account.

.PARAMETER AssessmentUPN
    UPN of the account that will run assessments.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File setup_assessment_account.ps1 -AssessmentUPN user@example.com
#>

param([string]$AssessmentUPN = "")

if (-not $AssessmentUPN) {
    $AssessmentUPN = Read-Host "  Assessment account UPN"
}
if (-not $AssessmentUPN) {
    Write-Host "  No UPN provided. Exiting." -ForegroundColor Red
    exit 1
}

$ErrorActionPreference = "Stop"

function Write-Step { param($msg) Write-Host "" ; Write-Host "  -- $msg" -ForegroundColor Cyan }
function Write-OK   { param($msg) Write-Host "  OK  : $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "  WARN: $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "  FAIL: $msg" -ForegroundColor Red }

# Stable role definition GUIDs (same across all tenants)
$ENTRA_ROLES = @{
    "Global Reader"   = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
    "Security Reader" = "5d6b6bb7-de71-4623-b4af-96380a352509"
    "Reports Reader"  = "4a5d8f65-41da-4de4-8968-e035b65339cf"
}

$GRAPH_CLI_APPID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
$GRAPH_APPID     = "00000003-0000-0000-c000-000000000000"

$ADDITIONAL_SCOPES = @(
    "Policy.Read.All"
    "RoleEligibilitySchedule.Read.Directory"
    "RoleAssignmentSchedule.Read.Directory"
    "RoleManagementPolicy.Read.Directory"
    "UserAuthenticationMethod.Read.All"
)

# Scopes needed for this setup script
$SETUP_SCOPES = "https://graph.microsoft.com/RoleManagement.ReadWrite.Directory " +
                "https://graph.microsoft.com/Application.Read.All " +
                "https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All " +
                "https://graph.microsoft.com/DelegatedPermissionGrant.ReadWrite.All " +
                "https://graph.microsoft.com/Directory.Read.All " +
                "https://graph.microsoft.com/User.Read.All"

Write-Host ""
Write-Host "  ============================================================" -ForegroundColor White
Write-Host "  Entra Security Assessment Account Setup" -ForegroundColor White
Write-Host "  ============================================================" -ForegroundColor White
Write-Host "  Assessment account : $AssessmentUPN"
Write-Host "  Run by             : $env:USERNAME"
Write-Host "  Time               : $([System.DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss UTC'))"
Write-Host ""

# ============================================================================
# SECTION 1: Get access token via raw device code flow (no PS module bugs)
# ============================================================================
Write-Step "Authenticating to Microsoft Graph via device code"

$deviceCodeBody = @{
    client_id = $GRAPH_CLI_APPID
    scope     = $SETUP_SCOPES
}

$deviceCodeResponse = Invoke-RestMethod `
    -Method POST `
    -Uri "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode" `
    -Body $deviceCodeBody

Write-Host ""
Write-Host "  $($deviceCodeResponse.message)"
Write-Host ""

# Poll for token
$tokenBody = @{
    grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
    client_id   = $GRAPH_CLI_APPID
    device_code = $deviceCodeResponse.device_code
}

$token         = $null
$pollInterval  = [int]($deviceCodeResponse.interval)
$expiresAt     = (Get-Date).AddSeconds([int]($deviceCodeResponse.expires_in))

Write-Host "  Waiting for sign-in..." -NoNewline

while ((Get-Date) -lt $expiresAt) {
    Start-Sleep -Seconds $pollInterval
    Write-Host "." -NoNewline
    try {
        $tokenResponse = Invoke-RestMethod `
            -Method POST `
            -Uri "https://login.microsoftonline.com/organizations/oauth2/v2.0/token" `
            -Body $tokenBody `
            -ErrorAction Stop
        $token = $tokenResponse.access_token
        break
    } catch {
        $errBody = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($errBody.error -eq "authorization_pending") {
            continue
        } elseif ($errBody.error -eq "slow_down") {
            $pollInterval += 5
            continue
        } else {
            Write-Host ""
            Write-Fail "Authentication error: $($errBody.error) - $($errBody.error_description)"
            exit 1
        }
    }
}

if (-not $token) {
    Write-Host ""
    Write-Fail "Authentication timed out."
    exit 1
}

Write-Host ""

# Decode UPN from JWT claims
$jwtParts = $token.Split(".")
$payload  = $jwtParts[1]
$padding  = 4 - ($payload.Length % 4)
if ($padding -ne 4) { $payload += "=" * $padding }
$claims = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
$signedInAs = if ($claims.upn) { $claims.upn } elseif ($claims.preferred_username) { $claims.preferred_username } else { "unknown" }
$tenantId   = $claims.tid

Write-OK "Authenticated as: $signedInAs"
Write-OK "Tenant ID: $tenantId"

$headers = @{
    Authorization  = "Bearer $token"
    "Content-Type" = "application/json"
}

# Helper: call Graph REST API
function Invoke-Graph {
    param([string]$Method = "GET", [string]$Path, [hashtable]$Body = $null)
    $uri = "https://graph.microsoft.com/v1.0$Path"
    if ($Body) {
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers `
            -Body ($Body | ConvertTo-Json -Depth 5) -ErrorAction Stop
    } else {
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers `
            -ErrorAction Stop
    }
}

# ============================================================================
# SECTION 2: Verify Global Administrator role
# ============================================================================
Write-Step "Verifying Global Administrator role"

$meData = Invoke-Graph -Path "/me"
$meId   = $meData.id
Write-OK "Resolved signed-in user ID: $meId"

$roleAssignments = Invoke-Graph -Path "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$meId'&`$expand=roleDefinition"
$isGA = $roleAssignments.value | Where-Object { $_.roleDefinition.displayName -eq "Global Administrator" }

if (-not $isGA) {
    Write-Fail "Connected account is not a Global Administrator. Aborting."
    exit 1
}
Write-OK "Global Administrator role confirmed"

# ============================================================================
# SECTION 3: Resolve assessment account
# ============================================================================
Write-Step "Resolving assessment account: $AssessmentUPN"

try {
    $assessUser = Invoke-Graph -Path "/users/$([uri]::EscapeDataString($AssessmentUPN))"
    Write-OK "Found: $($assessUser.displayName) (ID: $($assessUser.id))"
} catch {
    Write-Fail "User not found: $AssessmentUPN"
    Write-Fail "$_"
    exit 1
}

# ============================================================================
# SECTION 4: Assign Entra ID roles
# ============================================================================
Write-Step "Assigning Entra ID roles to $AssessmentUPN"

foreach ($roleName in $ENTRA_ROLES.Keys) {
    $roleId = $ENTRA_ROLES[$roleName]

    # Check if already assigned
    $existing = Invoke-Graph -Path "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($assessUser.id)' and roleDefinitionId eq '$roleId'"

    if ($existing.value.Count -gt 0) {
        Write-OK "$roleName -- already assigned"
    } else {
        try {
            Invoke-Graph -Method POST -Path "/roleManagement/directory/roleAssignments" -Body @{
                principalId      = $assessUser.id
                roleDefinitionId = $roleId
                directoryScopeId = "/"
            } | Out-Null
            Write-OK "$roleName -- assigned"
        } catch {
            Write-Warn "$roleName -- failed: $_"
        }
    }
}

# ============================================================================
# SECTION 5: Grant admin consent for additional Graph scopes on CLI app
# ============================================================================
Write-Step "Granting admin consent for additional Graph scopes on Graph CLI app"

# Get Graph CLI service principal in this tenant
$cliSPResult = Invoke-Graph -Path "/servicePrincipals?`$filter=appId eq '$GRAPH_CLI_APPID'"
if ($cliSPResult.value.Count -eq 0) {
    Write-Fail "Microsoft Graph Command Line Tools app not found in this tenant."
    exit 1
}
$cliSPId = $cliSPResult.value[0].id
Write-OK "Graph CLI app SP ID: $cliSPId"

# Get Microsoft Graph service principal
$graphSPResult = Invoke-Graph -Path "/servicePrincipals?`$filter=appId eq '$GRAPH_APPID'"
$graphSPId     = $graphSPResult.value[0].id
Write-OK "Microsoft Graph SP ID: $graphSPId"

# Check for existing grant
$existingGrants = Invoke-Graph -Path "/oauth2PermissionGrants?`$filter=clientId eq '$cliSPId' and resourceId eq '$graphSPId' and consentType eq 'AllPrincipals'"

if ($existingGrants.value.Count -gt 0) {
    $grant = $existingGrants.value[0]
    $currentScopes = ($grant.scope -split " " | Where-Object { $_ })
    $mergedScopes  = ($currentScopes + $ADDITIONAL_SCOPES) | Select-Object -Unique
    $scopeString   = $mergedScopes -join " "

    Invoke-Graph -Method PATCH -Path "/oauth2PermissionGrants/$($grant.id)" -Body @{
        scope = $scopeString
    } | Out-Null
    Write-OK "Updated existing consent grant"
} else {
    Invoke-Graph -Method POST -Path "/oauth2PermissionGrants" -Body @{
        clientId    = $cliSPId
        resourceId  = $graphSPId
        consentType = "AllPrincipals"
        scope       = ($ADDITIONAL_SCOPES -join " ")
    } | Out-Null
    Write-OK "Created new consent grant"
}

foreach ($s in $ADDITIONAL_SCOPES) { Write-OK "Scope consented: $s" }

# ============================================================================
# SECTION 6: Exchange Online role assignment
# ============================================================================
Write-Step "Checking ExchangeOnlineManagement module"
if (-not (Get-Module -ListAvailable ExchangeOnlineManagement -ErrorAction SilentlyContinue)) {
    Write-Warn "ExchangeOnlineManagement not installed -- installing..."
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
}
Write-OK "ExchangeOnlineManagement found"

Import-Module ExchangeOnlineManagement -ErrorAction Stop

Write-Step "Connecting to Exchange Online"

# Detect which device code parameter this version of the module supports
$exoParams = (Get-Command Connect-ExchangeOnline).Parameters.Keys
if ($exoParams -contains "UseDeviceAuthentication") {
    Connect-ExchangeOnline -UseDeviceAuthentication -ShowBanner:$false -ErrorAction Stop
} elseif ($exoParams -contains "Device") {
    Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
} else {
    # Older versions: use interactive browser (no device code flag needed)
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
}
Write-OK "Connected to Exchange Online"

# Create a dedicated read-only role group scoped to exactly what the
# assessment needs: View-Only Recipients (mailbox enumeration + inbox rules)
# and View-Only Configuration (transport rules, accepted domains).
# This is the minimum Exchange access for mailbox forwarding checks.
$RoleGroupName = "Entra Assessment - Read Only"

try {
    $existingGroup = Get-RoleGroup $RoleGroupName -ErrorAction SilentlyContinue
    if ($existingGroup) {
        Write-OK "Role group '$RoleGroupName' already exists"
    } else {
        New-RoleGroup -Name $RoleGroupName `
            -Roles "View-Only Recipients","View-Only Configuration" `
            -Description "Minimum read-only access for Entra security assessments. No write permissions." `
            -ErrorAction Stop | Out-Null
        Write-OK "Created role group: $RoleGroupName"
        Write-OK "  Roles: View-Only Recipients, View-Only Configuration"
        Write-OK "  No write permissions assigned"
    }

    $members = Get-RoleGroupMember $RoleGroupName -ErrorAction Stop
    $already = $members | Where-Object { $_.PrimarySmtpAddress -ieq $AssessmentUPN }
    if ($already) {
        Write-OK "$AssessmentUPN already a member of $RoleGroupName"
    } else {
        Add-RoleGroupMember -Identity $RoleGroupName `
            -Member $AssessmentUPN -ErrorAction Stop
        Write-OK "Added $AssessmentUPN to $RoleGroupName"
        Write-Warn "Exchange role changes take 15-30 minutes to propagate"
    }
} catch {
    Write-Warn "Could not configure Exchange role group: $_"
    Write-Warn "Assign manually in Exchange admin center:"
    Write-Warn "  admin.exchange.microsoft.com -> Roles -> Admin roles"
    Write-Warn "  -> New role group: '$RoleGroupName'"
    Write-Warn "  -> Add roles: View-Only Recipients, View-Only Configuration"
    Write-Warn "  -> Add member: $AssessmentUPN"
}

Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
Write-OK "Disconnected from Exchange Online"

# ============================================================================
# SUMMARY
# ============================================================================
Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Green
Write-Host "  Setup Complete" -ForegroundColor Green
Write-Host "  ============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Account configured : $AssessmentUPN"
Write-Host "  Tenant             : $tenantId"
Write-Host ""
Write-Host "  Entra ID roles assigned:"
foreach ($r in $ENTRA_ROLES.Keys) { Write-Host "    - $r" }
Write-Host ""
Write-Host "  Graph CLI app scopes consented:"
foreach ($s in $ADDITIONAL_SCOPES) { Write-Host "    - $s" }
Write-Host ""
Write-Host "  Exchange Online:"
Write-Host "    - View-Only Organization Management"
Write-Host ""
Write-Host "  IMPORTANT: Sign $AssessmentUPN out and back in before running." -ForegroundColor Yellow
Write-Host "  Exchange role propagation takes 15-30 minutes." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Run the assessment with:" -ForegroundColor Cyan
Write-Host "    python entra_assessment.py --json report.json" -ForegroundColor Cyan
Write-Host ""
