#Requires -Version 5.1
<#
.SYNOPSIS
    Zero Trust Assessment - On-Premises Exchange Data Collection
.DESCRIPTION
    READ-ONLY. Run in an Exchange Management Shell (EMS) session with the
    built-in "View-Only Organization Management" RBAC role - sufficient for
    every cmdlet here; no mailbox content is opened, only configuration/metadata.
.NOTES
    Focus: ActiveSync/OWA auth posture, mail-flow persistence indicators
    (forwarding/inbox rules), delegation, and patch level.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\ZT_Exchange_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmm')"
)

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
Write-Host "Output folder: $OutputPath" -ForegroundColor Cyan

# 1. Exchange server inventory + patch level
Write-Host "[1/10] Exchange server inventory & patch level..." -ForegroundColor Yellow
Get-ExchangeServer | Select-Object Name, Edition, AdminDisplayVersion, ServerRole |
    Export-Csv "$OutputPath\01_Exchange_Server_Inventory.csv" -NoTypeInformation

# 2. ActiveSync organization settings - confirms whether EAS enforces the same auth/MFA posture as OWA
Write-Host "[2/10] ActiveSync organization settings..." -ForegroundColor Yellow
Get-ActiveSyncOrganizationSettings | Export-Csv "$OutputPath\02_ActiveSync_Org_Settings.csv" -NoTypeInformation

# 3. ActiveSync device access rules (allow/block/quarantine by device type)
Write-Host "[3/10] ActiveSync device access rules..." -ForegroundColor Yellow
Get-ActiveSyncDeviceAccessRule | Select-Object Characteristic, QueryString, AccessLevel |
    Export-Csv "$OutputPath\03_ActiveSync_Access_Rules.csv" -NoTypeInformation

# 4. Mobile device mailbox policies (password/PIN, encryption)
Write-Host "[4/10] Mobile device mailbox policies..." -ForegroundColor Yellow
Get-MobileDeviceMailboxPolicy | Select-Object Name, PasswordEnabled, AlphanumericPasswordRequired, `
    MinPasswordLength, DeviceEncryptionEnabled, MaxInactivityTimeLock, IsDefault |
    Export-Csv "$OutputPath\04_Mobile_Device_Mailbox_Policies.csv" -NoTypeInformation

# 5. Per-mailbox protocol enablement (who actually has EAS/OWA access enabled)
Write-Host "[5/10] Per-mailbox ActiveSync/OWA enablement (this may take a while)..." -ForegroundColor Yellow
Get-CASMailbox -ResultSize Unlimited |
    Select-Object Identity, ActiveSyncEnabled, OWAEnabled, PopEnabled, ImapEnabled, MAPIEnabled, EwsEnabled |
    Export-Csv "$OutputPath\05_CASMailbox_Protocol_Enablement.csv" -NoTypeInformation

# Fetched once, reused below (6, 8, 9) - the slowest cmdlet in this script; no reason to call it four times
Write-Host "Fetching full mailbox list (used by steps 6, 8, 9)..." -ForegroundColor DarkGray
$allMailboxes = Get-Mailbox -ResultSize Unlimited

# 6. Registered ActiveSync devices
Write-Host "[6/10] Registered ActiveSync devices..." -ForegroundColor Yellow
$deviceStats = foreach ($mbx in $allMailboxes) {
    Get-ActiveSyncDeviceStatistics -Mailbox $mbx.Identity -ErrorAction SilentlyContinue |
        Select-Object @{N='MailboxOwner';E={$mbx.PrimarySmtpAddress}}, Identity, DeviceType, DeviceOS, DeviceAccessState, FirstSyncTime, LastSuccessSync
}
$deviceStats | Export-Csv "$OutputPath\06_ActiveSync_Registered_Devices.csv" -NoTypeInformation

# 7. OWA/Autodiscover virtual directory auth config - forms vs. Windows/Basic auth, external exposure
Write-Host "[7/10] OWA virtual directory auth config..." -ForegroundColor Yellow
Get-OwaVirtualDirectory | Select-Object Server, Name, InternalUrl, ExternalUrl, `
    BasicAuthentication, WindowsAuthentication, FormsAuthentication, DigestAuthentication |
    Export-Csv "$OutputPath\07_OWA_VirtualDirectory_Config.csv" -NoTypeInformation

Get-AutodiscoverVirtualDirectory -ErrorAction SilentlyContinue |
    Select-Object Server, Name, InternalUrl, ExternalUrl, BasicAuthentication, WindowsAuthentication |
    Export-Csv "$OutputPath\08_Autodiscover_VirtualDirectory_Config.csv" -NoTypeInformation

# 8. Mail forwarding/inbox rules - top persistence/exfil indicator; APT/BEC actors also use
# MoveToFolder/DeleteMessage/MarkAsRead rules to hide alerts and bounce-backs from the owner
Write-Host "[8/10] Mailbox forwarding configuration (may take a while)..." -ForegroundColor Yellow
$allMailboxes | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } |
    Select-Object PrimarySmtpAddress, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward |
    Export-Csv "$OutputPath\09_Mailbox_AutoForward_Config.csv" -NoTypeInformation

$allInboxRules = foreach ($mbx in $allMailboxes) {
    Get-InboxRule -Mailbox $mbx.Identity -ErrorAction SilentlyContinue |
        Select-Object @{N='Mailbox';E={$mbx.PrimarySmtpAddress}}, Name, Enabled, Priority, `
            ForwardTo, RedirectTo, ForwardAsAttachmentTo, MoveToFolder, DeleteMessage, `
            MarkAsRead, StopProcessingRules, Description
}
$allInboxRules | Export-Csv "$OutputPath\10_InboxRules_All.csv" -NoTypeInformation

$allInboxRules | Where-Object { $_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo -or $_.DeleteMessage -or $_.MoveToFolder } |
    Export-Csv "$OutputPath\10a_InboxRules_Flagged_ForTriage.csv" -NoTypeInformation

# 8b. Mailbox audit config + bypass list - audit bypass is a common way a privileged actor hides their own activity
Write-Host "[8b/10] Mailbox audit config & bypass list..." -ForegroundColor Yellow
Get-AdminAuditLogConfig | Select-Object AdminAuditLogEnabled, UnifiedAuditLogIngestionEnabled, LogLevel |
    Export-Csv "$OutputPath\10b_Org_Audit_Log_Config.csv" -NoTypeInformation

$allMailboxes | Select-Object PrimarySmtpAddress, AuditEnabled, AuditLogAgeLimit |
    Export-Csv "$OutputPath\10c_Mailbox_Audit_Status.csv" -NoTypeInformation

Get-MailboxAuditBypassAssociation -ResultSize Unlimited -ErrorAction SilentlyContinue |
    Where-Object { $_.AuditBypassEnabled -eq $true } |
    Select-Object Identity, AuditBypassEnabled |
    Export-Csv "$OutputPath\10d_Mailbox_Audit_Bypass_Accounts.csv" -NoTypeInformation

# 9. High-privilege mailbox delegation (Full Access)
Write-Host "[9/10] Mailbox delegation (Full Access / Send As)..." -ForegroundColor Yellow
$delegation = foreach ($mbx in $allMailboxes) {
    Get-MailboxPermission -Identity $mbx.Identity -ErrorAction SilentlyContinue |
        Where-Object { $_.AccessRights -contains "FullAccess" -and -not $_.IsInherited -and $_.User -notlike "NT AUTHORITY\*" } |
        Select-Object @{N='Mailbox';E={$mbx.PrimarySmtpAddress}}, User, @{N='AccessRights';E={$_.AccessRights -join ';'}}
}
$delegation | Export-Csv "$OutputPath\11_Mailbox_FullAccess_Delegation.csv" -NoTypeInformation

# 10. Transport rules - mail-flow interception/exfil vector check
Write-Host "[10/10] Transport rules..." -ForegroundColor Yellow
Get-TransportRule | Select-Object Name, State, Priority, Description |
    Export-Csv "$OutputPath\12_Transport_Rules.csv" -NoTypeInformation

Write-Host "`nCollection complete. Zip and return the '$OutputPath' folder." -ForegroundColor Green
Write-Host "Note: steps 6, 8, and 9 iterate every mailbox and are the slowest - run outside business hours on large environments." -ForegroundColor DarkGray
