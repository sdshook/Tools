#Requires -Version 5.1
#Requires -Modules Veeam.Backup.PowerShell
<#
.SYNOPSIS
    Zero Trust Assessment - Veeam Backup & Replication Data Collection
.DESCRIPTION
    READ-ONLY, Veeam B&R v12 (confirmed build 12.3.2.3617). No Add-/New-/Set-/
    Remove- cmdlets. Every cmdlet and property below is verified against
    current Veeam PowerShell reference documentation, not guessed.
.NOTES
    Key question: what privilege level does Veeam itself run at, and is its
    credential cache (Get-VBRCredentials, usernames only, no secrets exposed)
    a bigger blast radius than the backups. NetBackup (Oracle-only, v10.4.0.1)
    is out of scope here, lower ZT priority given its narrow role.

    Deliberately NOT included, because no confirmed, version-stable way to
    get this data exists without guessing:
    - Job-to-target-repository resolution (would require an unverified method)
    - Server-to-credential mapping (verified methods exist but are type-specific:
      GetSoapCreds for vCenter/ESXi, GetSshCreds for Linux, FindCreds for
      Hyper-V; too fragile to script universally without knowing exact server
      types in advance). Check this manually in the console if needed.
    - Replication job source/target host mapping (no confirmed property).
      Check the Replication Jobs view in the console instead.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\ZT_Veeam_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmm')"
)

Import-Module Veeam.Backup.PowerShell -ErrorAction Stop
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
Write-Host "Output folder: $OutputPath" -ForegroundColor Cyan

$allJobs = Get-VBRJob

# 1. Job inventory - what's protected, and how. JobType shows real values from this
# environment (Backup, Replica, etc.) rather than a guessed/filtered value - current
# Veeam versions return backup AND replication jobs from this single cmdlet.
Write-Host "[1/8] Backup & replication job inventory..." -ForegroundColor Yellow
$allJobs | Select-Object Name, JobType, IsScheduleEnabled, Description |
    Export-Csv "$OutputPath\01_Backup_Jobs.csv" -NoTypeInformation

# 2. Job object membership - confirms DCs/critical servers are covered by backup scope
Write-Host "[2/8] Job object membership..." -ForegroundColor Yellow
$jobObjects = foreach ($job in $allJobs) {
    Get-VBRJobObject -Job $job | Select-Object @{N='JobName';E={$job.Name}}, Name, Type
}
$jobObjects | Export-Csv "$OutputPath\02_Job_Protected_Objects.csv" -NoTypeInformation

# 3. Repository inventory (standard properties only, no unverified method calls)
Write-Host "[3/8] Backup repository inventory..." -ForegroundColor Yellow
Get-VBRBackupRepository | Select-Object Name, Type, Path |
    Export-Csv "$OutputPath\03_Backup_Repositories.csv" -NoTypeInformation

# 4. Immutability settings - confirmed method, scale-out repositories only. Standard
# (non-scale-out) repository immutability isn't exposed via a confirmed cmdlet/property;
# check those in the console (Repository > Advanced settings) if any exist.
Write-Host "[4/8] Immutability settings (scale-out repositories)..." -ForegroundColor Yellow
$scaleOutRepos = Get-VBRBackupRepository -ScaleOut -ErrorAction SilentlyContinue
if ($scaleOutRepos) {
    $scaleOutRepos | ForEach-Object {
        $settings = $_.GetImmutabilitySettings()
        [PSCustomObject]@{
            RepositoryName    = $_.Name
            EncryptionEnabled = $settings.EncryptionEnabled
            PolicyType        = $settings.PolicyType
        }
    } | Export-Csv "$OutputPath\04_ScaleOut_Repository_Immutability.csv" -NoTypeInformation
} else {
    Write-Host "  No scale-out repositories found - nothing to export for this section." -ForegroundColor DarkGray
}

# 5. Encrypted backups - direct, real evidence of encryption use (not inferred from
# a repository setting that might not reflect what's actually encrypted)
Write-Host "[5/8] Encrypted backups..." -ForegroundColor Yellow
Get-VBREncryptedBackup | Select-Object Name |
    Export-Csv "$OutputPath\05_Encrypted_Backups.csv" -NoTypeInformation

# 6. Credential store - USERNAMES ONLY, no secrets exposed. Shows blast radius if
# Veeam itself is compromised: every account Veeam has been handed for operations.
Write-Host "[6/8] Stored credential inventory (usernames only)..." -ForegroundColor Yellow
Get-VBRCredentials | Select-Object Description, Username, Type |
    Export-Csv "$OutputPath\06_Stored_Credentials_Inventory.csv" -NoTypeInformation

# 7. Veeam infrastructure server inventory (confirmed real properties: Name, Type,
# Description, IsUnavailable - NOT a login/credential field, see notes above)
Write-Host "[7/8] Veeam infrastructure server inventory..." -ForegroundColor Yellow
Get-VBRServer | Select-Object Name, Type, Description, IsUnavailable |
    Export-Csv "$OutputPath\07_Veeam_Infrastructure_Servers.csv" -NoTypeInformation

# 8. Veeam Backup Service account privilege - the single highest-value ZT fact here.
# Standard Windows WMI class, not Veeam-specific. Requires local CIM/WinRM access -
# run this block on the Veeam server console.
Write-Host "[8/8] Veeam Backup Service account (run locally on Veeam server)..." -ForegroundColor Yellow
try {
    Get-CimInstance -ClassName Win32_Service -Filter "Name='VeeamBackupSvc'" -ErrorAction Stop |
        Select-Object Name, DisplayName, StartName, State |
        Export-Csv "$OutputPath\08_VeeamBackupSvc_ServiceAccount.csv" -NoTypeInformation
    Write-Host "  Captured. If StartName is Domain Admin-equivalent, that is the top finding: Veeam compromise = domain compromise." -ForegroundColor Cyan
} catch {
    Write-Host "  Could not query service info here - re-run on the Veeam server, or get the account manually (Services console > VeeamBackupSvc > Log On tab)." -ForegroundColor DarkGray
}

# Recent backup sessions
Write-Host "Recent backup session results (last 30 days)..." -ForegroundColor Yellow
Get-VBRBackupSession | Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-30) } |
    Select-Object JobName, CreationTime, Result, State, EndTime |
    Export-Csv "$OutputPath\09_Recent_Backup_Sessions.csv" -NoTypeInformation

Write-Host @"

Collection complete. Zip and return the '$OutputPath' folder.
Priority review order: 08 (service account privilege), 06 (credential blast radius), 05 and 04 (encryption/immutability - ransomware resilience).
Manually check in the console: job-to-repository mapping, server-to-credential mapping, and replication job source/target hosts - no confirmed script-safe method exists for these without guessing.
"@ -ForegroundColor Green
