#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Zero Trust Assessment - Active Directory Data Collection (multi-domain)
.DESCRIPTION
    READ-ONLY. No Set-/New-/Remove- cmdlets. Requires only standard AD read
    access (a few sections note extra module/rights needs inline).
.NOTES
    Run from a host with RSAT (ActiveDirectory; GroupPolicy and DnsServer
    optional, sections skip gracefully if absent). Each domain in -Domains
    gets its own output subfolder for cross-domain comparison.
#>

[CmdletBinding()]
param(
    [string[]]$Domains = @('domain1.example.local','domain2.example.local'),
    [string]$OutputRoot = ".\ZT_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmm')"
)

Import-Module ActiveDirectory -ErrorAction Stop
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
Write-Host "Output root: $OutputRoot" -ForegroundColor Cyan

function Invoke-DomainCollection {
    param(
        [Parameter(Mandatory)][string]$DomainDnsRoot,
        [Parameter(Mandatory)][string]$OutputRoot
    )

    $OutputPath = Join-Path $OutputRoot $DomainDnsRoot
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Host "`n=== Domain: $DomainDnsRoot ===" -ForegroundColor Magenta

    # 1. Domain/forest overview + trusts (SID filtering state matters for cross-domain trust risk)
    Write-Host "[1] Domain overview & trusts..." -ForegroundColor Yellow
    Get-ADDomain -Server $DomainDnsRoot |
        Select-Object DNSRoot, NetBIOSName, DomainMode, PDCEmulator, Forest |
        Export-Csv "$OutputPath\01_Domain_Overview.csv" -NoTypeInformation

    Get-ADTrust -Filter * -Server $DomainDnsRoot -Properties * -ErrorAction SilentlyContinue |
        Select-Object Name, Direction, TrustType, ForestTransitive, SIDFilteringForestAware, SIDFilteringQuarantined |
        Export-Csv "$OutputPath\02_Domain_Trusts.csv" -NoTypeInformation

    # 2. Domain Controllers
    Write-Host "[2] Domain Controllers..." -ForegroundColor Yellow
    Get-ADDomainController -Filter * -Server $DomainDnsRoot |
        Select-Object HostName, OperatingSystem, OperatingSystemVersion, Site, IsGlobalCatalog, IsReadOnly |
        Export-Csv "$OutputPath\03_Domain_Controllers.csv" -NoTypeInformation

    # 3. Privileged group membership (standing access - opposite of least-privilege/JIT)
    Write-Host "[3] Privileged groups..." -ForegroundColor Yellow
    $privGroups = @(
        "Domain Admins","Enterprise Admins","Schema Admins","Administrators",
        "Account Operators","Backup Operators","Server Operators","Print Operators",
        "DnsAdmins","Group Policy Creator Owners"
    )
    $privMembers = foreach ($g in $privGroups) {
        try {
            Get-ADGroupMember -Identity $g -Server $DomainDnsRoot -Recursive -ErrorAction Stop |
                ForEach-Object { [PSCustomObject]@{ Group = $g; Member = $_.SamAccountName; ObjectClass = $_.objectClass } }
        } catch { }
    }
    $privMembers | Export-Csv "$OutputPath\04_Privileged_Group_Members.csv" -NoTypeInformation

    # 4. Kerberos delegation (unconstrained delegation = full-domain-compromise risk)
    Write-Host "[4] Kerberos delegation settings..." -ForegroundColor Yellow
    Get-ADObject -Filter { (UserAccountControl -band 0x0080000) -OR (UserAccountControl -band 0x1000000) } `
        -Server $DomainDnsRoot -Properties UserAccountControl, msDS-AllowedToDelegateTo, servicePrincipalName |
        Select-Object Name, ObjectClass,
            @{N='UnconstrainedDelegation';E={[bool]($_.UserAccountControl -band 0x0080000)}},
            @{N='ConstrainedDelegation';E={[bool]($_.UserAccountControl -band 0x1000000)}},
            @{N='AllowedToDelegateTo';E={$_.'msDS-AllowedToDelegateTo' -join ';'}} |
        Export-Csv "$OutputPath\05_Kerberos_Delegation.csv" -NoTypeInformation

    # 5. Kerberoastable accounts (user accounts with an SPN set)
    Write-Host "[5] SPN / Kerberoastable accounts..." -ForegroundColor Yellow
    Get-ADUser -Filter { ServicePrincipalName -like "*" } -Server $DomainDnsRoot -Properties ServicePrincipalName, PasswordLastSet |
        Select-Object SamAccountName, PasswordLastSet, @{N='SPNCount';E={$_.ServicePrincipalName.Count}} |
        Export-Csv "$OutputPath\06_Kerberoastable_Accounts.csv" -NoTypeInformation

    # 6. Stale enabled accounts (>90 days) - valid, unmonitored credentials
    Write-Host "[6] Stale accounts (>90 days inactive)..." -ForegroundColor Yellow
    $cutoff = (Get-Date).AddDays(-90)
    Get-ADUser -Filter { LastLogonTimeStamp -lt $cutoff -AND Enabled -eq $true } -Server $DomainDnsRoot -Properties LastLogonTimeStamp, PasswordLastSet |
        Select-Object SamAccountName, @{N='LastLogon';E={[DateTime]::FromFileTime($_.LastLogonTimeStamp)}}, PasswordLastSet |
        Export-Csv "$OutputPath\07_Stale_Enabled_Accounts.csv" -NoTypeInformation

    # 7. Non-expiring passwords
    Write-Host "[7] Non-expiring password accounts..." -ForegroundColor Yellow
    Get-ADUser -Filter { PasswordNeverExpires -eq $true -AND Enabled -eq $true } -Server $DomainDnsRoot -Properties PasswordNeverExpires, PasswordLastSet |
        Select-Object SamAccountName, PasswordLastSet |
        Export-Csv "$OutputPath\08_NonExpiring_Password_Accounts.csv" -NoTypeInformation

    # 8. Password policy - compare across domains once collected; inconsistency across a trust is a finding
    Write-Host "[8] Password policies..." -ForegroundColor Yellow
    Get-ADDefaultDomainPasswordPolicy -Server $DomainDnsRoot |
        Select-Object ComplexityEnabled, MinPasswordLength, LockoutThreshold, LockoutDuration, MaxPasswordAge |
        Export-Csv "$OutputPath\09_Default_Password_Policy.csv" -NoTypeInformation

    Get-ADFineGrainedPasswordPolicy -Filter * -Server $DomainDnsRoot -ErrorAction SilentlyContinue |
        Export-Csv "$OutputPath\10_FineGrained_Password_Policies.csv" -NoTypeInformation

    # 9. LAPS schema check (absence = shared/static local admin creds = lateral movement risk)
    Write-Host "[9] LAPS schema check..." -ForegroundColor Yellow
    $lapsAttr = Get-ADObject -SearchBase (Get-ADRootDSE -Server $DomainDnsRoot).schemaNamingContext `
        -Server $DomainDnsRoot -Filter { lDAPDisplayName -eq "ms-Mcs-AdmPwd" } -ErrorAction SilentlyContinue
    [PSCustomObject]@{ LAPS_Schema_Present = [bool]$lapsAttr } |
        Export-Csv "$OutputPath\11_LAPS_Schema_Check.csv" -NoTypeInformation

    # 10. Computer OS inventory
    Write-Host "[10] Computer OS inventory..." -ForegroundColor Yellow
    Get-ADComputer -Filter * -Server $DomainDnsRoot -Properties OperatingSystem, OperatingSystemVersion, LastLogonTimeStamp |
        Select-Object Name, OperatingSystem, OperatingSystemVersion,
            @{N='LastLogon';E={ if ($_.LastLogonTimeStamp) {[DateTime]::FromFileTime($_.LastLogonTimeStamp)} }} |
        Export-Csv "$OutputPath\12_Computer_OS_Inventory.csv" -NoTypeInformation

    # 11. GPOs - inventory, OU linkage, edit permissions (edit rights = privilege-escalation path)
    if (Get-Module -ListAvailable -Name GroupPolicy) {
        Write-Host "[11] GPO inventory, links, and permissions..." -ForegroundColor Yellow
        Import-Module GroupPolicy

        $allGPOs = Get-GPO -All -Domain $DomainDnsRoot
        $allGPOs | Select-Object DisplayName, Id, GpoStatus, CreationTime, ModificationTime |
            Export-Csv "$OutputPath\13_GPO_Summary.csv" -NoTypeInformation

        [xml]$domainGpoReport = Get-GPOReport -All -Domain $DomainDnsRoot -ReportType Xml
        $gpoLinks = foreach ($gpo in $domainGpoReport.GPOs.GPO) {
            [PSCustomObject]@{
                GPOName    = $gpo.Name
                Enabled    = $gpo.LinksTo.Enabled -join ';'
                LinkedTo   = $gpo.LinksTo.SOMPath -join ';'
                NoOverride = $gpo.LinksTo.NoOverride -join ';'
            }
        }
        $gpoLinks | Export-Csv "$OutputPath\14_GPO_OU_Links.csv" -NoTypeInformation

        $allGPOs | Where-Object {
            $gpoDisplayName = $_.DisplayName
            -not ($domainGpoReport.GPOs.GPO | Where-Object { $_.Name -eq $gpoDisplayName -and $_.LinksTo })
        } | Select-Object DisplayName, Id, ModificationTime |
            Export-Csv "$OutputPath\15_GPO_Unlinked_Orphaned.csv" -NoTypeInformation

        $gpoPerms = foreach ($gpo in $allGPOs) {
            Get-GPPermission -Guid $gpo.Id -Domain $DomainDnsRoot -All -ErrorAction SilentlyContinue |
                Where-Object { $_.Permission -in @('GpoEditDeleteModifySecurity','GpoEdit') } |
                Select-Object @{N='GPOName';E={$gpo.DisplayName}}, Trustee, Permission
        }
        $gpoPerms | Export-Csv "$OutputPath\16_GPO_Edit_Permissions.csv" -NoTypeInformation
    } else {
        Write-Host "[11] GroupPolicy module not available - skipping GPO collection." -ForegroundColor DarkGray
    }

    # 12. AD-side access restrictions - closest functional equivalent to Conditional Access (no ADFS/Entra here)
    Write-Host "[12] AD-side access restrictions..." -ForegroundColor Yellow
    Get-ADUser -Filter { LogonWorkstations -like "*" -or SmartcardLogonRequired -eq $true } -Server $DomainDnsRoot `
        -Properties LogonWorkstations, SmartcardLogonRequired |
        Select-Object SamAccountName, LogonWorkstations, SmartcardLogonRequired |
        Export-Csv "$OutputPath\17_AD_LogonRestriction_Accounts.csv" -NoTypeInformation

    # 13. Never-rotated passwords since provisioning - read-only proxy for reused deployment passwords, no hash access
    Write-Host "[13] Never-rotated password check..." -ForegroundColor Yellow
    $rotationThresholdHours = 24

    Get-ADUser -Filter * -Server $DomainDnsRoot -Properties PasswordLastSet, whenCreated, Enabled |
        Where-Object { $_.PasswordLastSet -and (($_.PasswordLastSet - $_.whenCreated).TotalHours -lt $rotationThresholdHours) } |
        Select-Object SamAccountName, Enabled, whenCreated, PasswordLastSet,
            @{N='HoursBetweenCreateAndPwdSet';E={[math]::Round(($_.PasswordLastSet - $_.whenCreated).TotalHours,1)}} |
        Export-Csv "$OutputPath\18_Users_NeverRotated_Password.csv" -NoTypeInformation

    Get-ADComputer -Filter * -Server $DomainDnsRoot -Properties PasswordLastSet, whenCreated |
        Where-Object { $_.PasswordLastSet -and (($_.PasswordLastSet - $_.whenCreated).TotalHours -lt $rotationThresholdHours) } |
        Select-Object Name, whenCreated, PasswordLastSet,
            @{N='HoursBetweenCreateAndPwdSet';E={[math]::Round(($_.PasswordLastSet - $_.whenCreated).TotalHours,1)}} |
        Export-Csv "$OutputPath\19_Computers_NeverRotated_Password.csv" -NoTypeInformation

    Get-ADComputer -Filter * -Server $DomainDnsRoot -Properties PasswordLastSet |
        Where-Object { $_.PasswordLastSet -and $_.PasswordLastSet -lt (Get-Date).AddDays(-90) } |
        Select-Object Name, PasswordLastSet |
        Export-Csv "$OutputPath\20_Computers_StaleMachinePassword_90Days.csv" -NoTypeInformation

    # 14. AD CS presence check (common ESC1/ESC8 exposure)
    Write-Host "[14] AD CS presence check..." -ForegroundColor Yellow
    $pkiContainer = "CN=Certification Authorities,CN=Public Key Services,CN=Services,$((Get-ADRootDSE -Server $DomainDnsRoot).configurationNamingContext)"
    Get-ADObject -SearchBase $pkiContainer -Server $DomainDnsRoot -Filter * -ErrorAction SilentlyContinue |
        Select-Object Name, ObjectClass |
        Export-Csv "$OutputPath\21_ADCS_CA_Presence.csv" -NoTypeInformation

    # 15. Network segmentation - declared topology (Sites/Subnets/DNS), compare against observed traffic separately
    Write-Host "[15] AD Sites & Subnets (declared network map)..." -ForegroundColor Yellow
    Get-ADReplicationSite -Filter * -Server $DomainDnsRoot -Properties Description |
        Select-Object Name, Description |
        Export-Csv "$OutputPath\22_AD_Sites.csv" -NoTypeInformation

    Get-ADReplicationSubnet -Filter * -Server $DomainDnsRoot -Properties Description, Site |
        Select-Object Name, Site, Description |
        Export-Csv "$OutputPath\23_AD_Subnets.csv" -NoTypeInformation

    if (Get-Module -ListAvailable -Name DnsServer) {
        Import-Module DnsServer
        try {
            $zones = Get-DnsServerZone -ComputerName $DomainDnsRoot | Where-Object { -not $_.IsReverseLookupZone -and -not $_.IsAutoCreated }
            $aRecords = foreach ($zone in $zones) {
                Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -ComputerName $DomainDnsRoot -RRType A -ErrorAction SilentlyContinue |
                    Select-Object @{N='Zone';E={$zone.ZoneName}}, HostName, @{N='IPAddress';E={$_.RecordData.IPv4Address}}, Timestamp
            }
            $aRecords | Export-Csv "$OutputPath\24_DNS_A_Records.csv" -NoTypeInformation
        } catch {
            Write-Host "  DNS query failed or insufficient rights - skipping." -ForegroundColor DarkGray
        }
    }

    # 16. Account expiration / time-bound access - standing indefinite access is a third-party/insider risk pattern
    Write-Host "[16] Account expiration check..." -ForegroundColor Yellow
    Get-ADUser -Filter * -Server $DomainDnsRoot -Properties AccountExpirationDate, Enabled, whenCreated, Description |
        Select-Object SamAccountName, Enabled, whenCreated, AccountExpirationDate, Description |
        Export-Csv "$OutputPath\25_All_Accounts_Expiration_Status.csv" -NoTypeInformation

    Get-ADUser -Filter { Enabled -eq $true -and AccountExpirationDate -notlike "*" } -Server $DomainDnsRoot -Properties AccountExpirationDate, whenCreated, Description |
        Select-Object SamAccountName, whenCreated, Description |
        Export-Csv "$OutputPath\26_Enabled_Accounts_No_Expiration.csv" -NoTypeInformation

    # 17. Vendor/contractor/partner self-discovery via naming/OU/UPN-domain pattern match (best-effort, not confirmed categorization)
    Write-Host "[17] Vendor/contractor/partner self-discovery..." -ForegroundColor Yellow
    $extPatterns = 'vendor|contractor|consult|partner|3rd.?party|third.?party|temp|external|ext-|svc-ext|b2b'

    Get-ADOrganizationalUnit -Filter * -Server $DomainDnsRoot -Properties Description |
        Where-Object { $_.Name -match $extPatterns -or $_.Description -match $extPatterns } |
        Select-Object Name, DistinguishedName, Description |
        Export-Csv "$OutputPath\27_Candidate_External_OUs.csv" -NoTypeInformation

    Get-ADGroup -Filter * -Server $DomainDnsRoot -Properties Description |
        Where-Object { $_.Name -match $extPatterns -or $_.Description -match $extPatterns } |
        Select-Object Name, GroupCategory, GroupScope, Description |
        Export-Csv "$OutputPath\28_Candidate_External_Groups.csv" -NoTypeInformation

    Get-ADUser -Filter * -Server $DomainDnsRoot -Properties Description, UserPrincipalName, DistinguishedName, Enabled, AccountExpirationDate |
        Where-Object {
            $_.SamAccountName -match $extPatterns -or $_.Description -match $extPatterns -or $_.DistinguishedName -match $extPatterns -or
            ($_.UserPrincipalName -and ($_.UserPrincipalName -split '@')[1] -ne $DomainDnsRoot)
        } | Select-Object SamAccountName, UserPrincipalName, Enabled, AccountExpirationDate, Description, DistinguishedName |
        Export-Csv "$OutputPath\29_Candidate_External_Accounts.csv" -NoTypeInformation

    Write-Host "Domain $DomainDnsRoot complete." -ForegroundColor Green
}

foreach ($d in $Domains) {
    Invoke-DomainCollection -DomainDnsRoot $d -OutputRoot $OutputRoot
}

$sidNote = if ($Domains.Count -gt 1) {
@"

- Check 02_Domain_Trusts.csv for SID filtering status between $($Domains -join ' <-> '). If disabled, a privileged account in one domain can potentially assert privilege in another via SID history injection.
"@
} else { "" }

Write-Host @"

All domains collected under '$OutputRoot'.
Analysis notes:
- Compare 09_Default_Password_Policy.csv across domain subfolders; inconsistent policy across a trust is a finding.
- Join 23_AD_Subnets.csv against 24_DNS_A_Records.csv per domain to find undeclared/shadow subnets.
- Cross-reference 29_Candidate_External_Accounts.csv against 04_Privileged_Group_Members.csv and 26_Enabled_Accounts_No_Expiration.csv for the highest-priority third-party access findings.$sidNote
"@ -ForegroundColor Cyan
