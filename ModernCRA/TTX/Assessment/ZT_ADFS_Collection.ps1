#Requires -Version 5.1
#Requires -Modules ADFS
<#
.SYNOPSIS
    Zero Trust Assessment - AD FS Configuration & MFA Enforcement Collection
.DESCRIPTION
    READ-ONLY. No Set-/New-/Remove- cmdlets. Run directly on an AD FS server
    (or a management host with the ADFS PowerShell module and rights to
    query the farm) using an account with at least AD FS read/audit rights.

    Captures RAW objects as JSON rather than curated property lists. This
    avoids silently dropped/blank columns when a cmdlet's property set
    differs across AD FS versions - whatever the cmdlet actually returns is
    what gets written, in full, including nested structures that CSV would
    otherwise flatten into useless "System.Object[]" strings. Analysis
    happens downstream against the JSON (PowerShell ConvertFrom-Json,
    Python json/pandas, jq, etc.) rather than at collection time.
.NOTES
    Two exceptions keep minimal field extraction instead of full rawness:
    Windows event log records (Get-WinEvent) and X509 certificate objects
    don't serialize cleanly/completely to JSON (non-serializable handles,
    circular references) - those sections pull out the handful of fields
    that matter and note the exception inline.

    The single biggest source of "we enforce MFA" claims turning out to be
    false is a per-relying-party exception in AdditionalAuthenticationRules,
    or an exclusion group referenced in a claim rule. This script surfaces
    both explicitly - do not skip sections 3-4.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\ZT_Assessment_ADFS_$(Get-Date -Format 'yyyyMMdd_HHmm')",
    [int]$EventLogDays = 30,
    [int]$JsonDepth = 8
)

Import-Module ADFS -ErrorAction Stop
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

# 1. Farm / server overview - raw
Write-Host "[1] AD FS farm properties..." -ForegroundColor Yellow
Export-RawJson (Get-AdfsProperties) "01_ADFS_Farm_Properties.json"
Export-RawJson (Get-AdfsSyncProperties) "02_ADFS_Sync_Properties.json"

# 2. Global authentication policy - the top-level MFA switch - raw
Write-Host "[2] Global authentication policy..." -ForegroundColor Yellow
Export-RawJson (Get-AdfsGlobalAuthenticationPolicy) "03_Global_Authentication_Policy.json"

# 3. Registered authentication providers - confirms SafeNet is actually wired in - raw
Write-Host "[3] Authentication providers (confirms SafeNet registration)..." -ForegroundColor Yellow
Export-RawJson (Get-AdfsAuthenticationProvider) "04_Authentication_Providers.json"

# Not a property-selection cmdlet - returns rule text directly, kept as-is
Get-AdfsAdditionalAuthenticationRule | Out-File "$OutputPath\05_Global_Additional_Auth_Rule.txt"

# 4. Relying Party Trusts - THE critical section. Per-app MFA exceptions live here.
# Raw dump already includes AdditionalAuthenticationRules, IssuanceAuthorizationRules,
# IssuanceTransformRules, and AccessControlPolicyName natively - no need to hand-select them.
Write-Host "[4] Relying party trusts & per-app MFA rules (check carefully)..." -ForegroundColor Yellow
$rpts = Get-AdfsRelyingPartyTrust
Export-RawJson $rpts "06_RelyingPartyTrusts_RAW.json"

# Flag RPs with NO additional-auth rule at all (silently inherit global only -
# fine if global covers everyone, but worth confirming) and RPs whose rule
# text references common exclusion patterns (group SID/name based exemptions).
# Filters reference specific properties by necessity (that's what a targeted
# flag requires) but the flagged output is still the full raw RP object.
$noAddlRule = $rpts | Where-Object { [string]::IsNullOrWhiteSpace($_.AdditionalAuthenticationRules) }
Export-RawJson $noAddlRule "07_RPs_With_No_AdditionalAuthRule.json"

$exclusionPattern = 'exclude|exempt|bypass|skip|legacy|break.?glass|svc-|service.?account'
$possibleExclusions = $rpts | Where-Object {
    $_.AdditionalAuthenticationRules -match $exclusionPattern -or $_.IssuanceAuthorizationRules -match $exclusionPattern
}
Export-RawJson $possibleExclusions "08_RPs_Possible_MFA_Exclusions.json"

# 5. Claims Provider Trusts (usually just Active Directory, but check for others) - raw
Write-Host "[5] Claims provider trusts..." -ForegroundColor Yellow
Export-RawJson (Get-AdfsClaimsProviderTrust) "09_ClaimsProviderTrusts.json"

# 6. Access control policies (2016+) - modern equivalent of per-RP MFA rules - raw.
# (RP-to-policy mapping is already covered by AccessControlPolicyName inside 06_RelyingPartyTrusts_RAW.json)
Write-Host "[6] Access control policies..." -ForegroundColor Yellow
try {
    Export-RawJson (Get-AdfsAccessControlPolicy -ErrorAction Stop) "10_Access_Control_Policies.json"
} catch {
    Write-Host "  Access control policy cmdlets unavailable (pre-2016 farm) - skipping." -ForegroundColor DarkGray
}

# 7. Certificates - token signing/decrypting cert health (not MFA, but standard ZT hygiene item).
# EXCEPTION: the nested X509Certificate2 object doesn't serialize meaningfully/completely to
# JSON (raw key material, non-serializable handles) - pulling the fields that matter for review.
Write-Host "[7] AD FS certificates..." -ForegroundColor Yellow
Get-AdfsCertificate | ForEach-Object {
    [PSCustomObject]@{
        CertificateType = $_.CertificateType
        IsPrimary       = $_.IsPrimary
        Thumbprint      = $_.Certificate.Thumbprint
        Subject         = $_.Certificate.Subject
        NotBefore       = $_.Certificate.NotBefore
        NotAfter        = $_.Certificate.NotAfter
    }
} | ConvertTo-Json -Depth $JsonDepth | Out-File "$OutputPath\11_ADFS_Certificates.json" -Encoding utf8

# 8. Web Application Proxy trust (extranet path - confirms extranet actually forces MFA too) - raw
Write-Host "[8] WAP relying party publishing (if run from WAP-aware context)..." -ForegroundColor Yellow
try {
    Export-RawJson (Get-WebApplicationProxyApplication -ErrorAction Stop) "12_WAP_Published_Applications.json"
} catch {
    Write-Host "  Not run on a WAP server or module unavailable - skipping." -ForegroundColor DarkGray
}

# 9. Observed authentication events - what actually happened, not just what's configured.
# EXCEPTION: raw EventLogRecord objects carry non-serializable handles and won't round-trip
# through ConvertTo-Json cleanly - extracting TimeCreated/Id/Message, which is what's
# analyzable anyway. Requires AD FS auditing enabled (Set-AdfsProperties -AuditLevel) and
# read access to the Security log.
Write-Host "[9] Observed authentication events (last $EventLogDays days)..." -ForegroundColor Yellow
try {
    $startTime = (Get-Date).AddDays(-$EventLogDays)
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 1200, 1202, 411, 412
        StartTime = $startTime
    } -ErrorAction Stop

    $events | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Id          = $_.Id
            Message     = $_.Message
        }
    } | ConvertTo-Json -Depth $JsonDepth | Out-File "$OutputPath\13_Observed_Auth_Events.json" -Encoding utf8

    Write-Host "  Exported $($events.Count) events. Parse message text per-RP to build observed-vs-configured MFA comparison." -ForegroundColor DarkGray
} catch {
    Write-Host "  Could not read Security log events (auditing may be disabled, or insufficient rights) - skipping. This is itself a finding: without AD FS auditing enabled, MFA enforcement cannot be verified against actual logons." -ForegroundColor DarkGray
    Export-RawJson ([PSCustomObject]@{ Finding = "AD FS auditing appears disabled or inaccessible - configured MFA policy cannot be validated against observed logon behavior" }) "13_Observed_Auth_Events_UNAVAILABLE.json"
}

Write-Host @"

AD FS collection complete under '$OutputPath'.
Output is raw JSON per cmdlet - open with ConvertFrom-Json, a JSON viewer, or load into Python/pandas for analysis.
Priority review order:
1. 08_RPs_Possible_MFA_Exclusions.json and 07_RPs_With_No_AdditionalAuthRule.json - manually read every RP's raw rule text in 06_RelyingPartyTrusts_RAW.json to confirm MFA truly applies to all of them.
2. 04_Authentication_Providers.json - confirm SafeNet appears here, not just installed on the box.
3. 13_Observed_Auth_Events*.json - cross-check configured MFA against what actually happened. If this is the UNAVAILABLE variant, flag that auditing gaps prevent full validation.
4. 11_ADFS_Certificates.json - flag any cert within 60 days of NotAfter.
"@ -ForegroundColor Cyan
