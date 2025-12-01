# DSPA (c) Shane D. Shook, 2025 All Rights Reserved

<#
.SYNOPSIS
    Data Security Posture Activity (DSPA) Report Generator for SharePoint Audit Logs
    
.DESCRIPTION
    This script retrieves SharePoint audit log activities and generates comprehensive security reports.
    It produces both raw activity logs and suspicious activity summaries with IP geolocation data.
    
.PARAMETER Users
    Comma-separated list of user UPNs to analyze. Use "ALL" for all users.
    
.PARAMETER StartDate
    Start date in MMDDYYYY format. If not specified, uses maximum available history.
    
.PARAMETER EndDate
    End date in MMDDYYYY format. If not specified, uses current date.
    
.PARAMETER DaysBack
    Number of days back from current date to analyze (alternative to date range).
    
.PARAMETER OutputPath
    Directory path for output reports. Defaults to current directory.
    
.PARAMETER TenantId
    Azure AD Tenant ID (optional if using interactive authentication).
    
.PARAMETER ClientId
    Azure AD Application Client ID for authentication.
    
.PARAMETER CertificateThumbprint
    Certificate thumbprint for certificate-based authentication.
    
.PARAMETER ClientSecret
    Azure AD Application Client Secret for Graph API authentication (alternative to certificate).
    
.EXAMPLE
    .\DSPA.ps1 -Users "user1@domain.com,user2@domain.com" -DaysBack 30
    
.EXAMPLE
    .\DSPA.ps1 -Users "ALL" -StartDate "01012024" -EndDate "01312024"
    
.EXAMPLE
    .\DSPA.ps1 -Users "ALL" -DaysBack 7 -TenantId "your-tenant-id" -ClientId "your-app-id" -ClientSecret "your-secret"
    
.EXAMPLE
    .\DSPA.ps1 -Users "user@domain.com" -DaysBack 30 -TenantId "your-tenant-id" -ClientId "your-app-id" -CertificateThumbprint "your-cert-thumbprint"
    
.NOTES
    Author: OpenHands AI Assistant
    Version: 3.0
    Requires: PnP PowerShell Module, Microsoft Graph PowerShell Modules
    
    Authentication Method:
    Microsoft Graph API: Uses Connect-MgGraph and Graph API endpoints
    
    Note: Exchange Online PowerShell method removed due to Search-UnifiedAuditLog deprecation (April 2025)
    
    Graph API Benefits:
    - Modern authentication with service principals
    - Better rate limiting and performance
    - Unified API across Microsoft 365 services
    - Enhanced security with granular permissions
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Users,
    
    [Parameter(Mandatory = $false)]
    [string]$StartDate,
    
    [Parameter(Mandatory = $false)]
    [string]$EndDate,
    
    [Parameter(Mandatory = $false)]
    [int]$DaysBack,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".",
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientId,
    
    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientSecret
)

# Global variables
$Script:AuditData = @()
$Script:IPLocationCache = @{}
$Script:UserBaselineCache = @{}
$Script:SuspiciousActivities = @()

# Import required modules
function Import-RequiredModules {
    Write-Host "Checking and importing required modules..." -ForegroundColor Yellow
    
    $RequiredModules = @(
        'PnP.PowerShell',
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Security',
        'Microsoft.Graph.Reports'
    )
    
    foreach ($Module in $RequiredModules) {
        try {
            if (!(Get-Module -ListAvailable -Name $Module)) {
                Write-Host "Installing module: $Module" -ForegroundColor Yellow
                Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser
            }
            Import-Module $Module -Force
            Write-Host "✓ Module $Module imported successfully" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to import module $Module`: $_"
            exit 1
        }
    }
}

# Authentication function for Microsoft Graph API
function Connect-GraphAPI {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [string]$ClientSecret
    )
    
    Write-Host "Connecting to Microsoft Graph API..." -ForegroundColor Yellow
    
    try {
        # Define required scopes for audit log access
        $Scopes = @(
            "AuditLog.Read.All",
            "Directory.Read.All",
            "Reports.Read.All",
            "SecurityEvents.Read.All"
        )
        
        if ($ClientId -and $TenantId) {
            if ($CertificateThumbprint) {
                # Certificate-based authentication
                Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint
                Write-Host "✓ Connected to Microsoft Graph using certificate authentication" -ForegroundColor Green
            }
            elseif ($ClientSecret) {
                # Client secret authentication
                $SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
                $Credential = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret)
                Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $Credential
                Write-Host "✓ Connected to Microsoft Graph using client secret authentication" -ForegroundColor Green
            }
            else {
                # Interactive authentication with specific scopes
                Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -Scopes $Scopes
                Write-Host "✓ Connected to Microsoft Graph using interactive authentication" -ForegroundColor Green
            }
        }
        else {
            # Interactive authentication with default app
            Connect-MgGraph -Scopes $Scopes
            Write-Host "✓ Connected to Microsoft Graph using interactive authentication" -ForegroundColor Green
        }
        
        # Verify connection
        $Context = Get-MgContext
        if ($Context) {
            Write-Host "✓ Graph API connection verified - Tenant: $($Context.TenantId)" -ForegroundColor Green
        }
        else {
            throw "Failed to establish Graph API context"
        }
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph API: $_"
        exit 1
    }
}

# Date parsing function
function Parse-DateRange {
    param(
        [string]$StartDate,
        [string]$EndDate,
        [int]$DaysBack
    )
    
    $DateRange = @{}
    
    if ($DaysBack -gt 0) {
        $DateRange.EndDate = Get-Date
        $DateRange.StartDate = (Get-Date).AddDays(-$DaysBack)
    }
    elseif ($StartDate -and $EndDate) {
        try {
            $DateRange.StartDate = [DateTime]::ParseExact($StartDate, "MMddyyyy", $null)
            $DateRange.EndDate = [DateTime]::ParseExact($EndDate, "MMddyyyy", $null)
        }
        catch {
            Write-Error "Invalid date format. Use MMDDYYYY format."
            exit 1
        }
    }
    else {
        # Default to last 90 days (maximum for unified audit log)
        $DateRange.EndDate = Get-Date
        $DateRange.StartDate = (Get-Date).AddDays(-90)
    }
    
    Write-Host "Date range: $($DateRange.StartDate.ToString('yyyy-MM-dd')) to $($DateRange.EndDate.ToString('yyyy-MM-dd'))" -ForegroundColor Cyan
    return $DateRange
}

# IP Geolocation function
function Get-IPGeolocation {
    param([string]$IPAddress)
    
    if ($Script:IPLocationCache.ContainsKey($IPAddress)) {
        return $Script:IPLocationCache[$IPAddress]
    }
    
    try {
        # Using ip-api.com for geolocation (free tier)
        $Response = Invoke-RestMethod -Uri "http://ip-api.com/json/$IPAddress" -TimeoutSec 10
        
        $LocationInfo = @{
            Country = $Response.country
            City = $Response.city
            Region = $Response.regionName
            Organization = $Response.org
            ISP = $Response.isp
            ASN = $Response.as
            Timezone = $Response.timezone
            Latitude = $Response.lat
            Longitude = $Response.lon
        }
        
        $Script:IPLocationCache[$IPAddress] = $LocationInfo
        Start-Sleep -Milliseconds 100  # Rate limiting
        return $LocationInfo
    }
    catch {
        Write-Warning "Failed to get geolocation for IP $IPAddress`: $_"
        $DefaultInfo = @{
            Country = "Unknown"
            City = "Unknown"
            Region = "Unknown"
            Organization = "Unknown"
            ISP = "Unknown"
            ASN = "Unknown"
            Timezone = "Unknown"
            Latitude = $null
            Longitude = $null
        }
        $Script:IPLocationCache[$IPAddress] = $DefaultInfo
        return $DefaultInfo
    }
}

# Retrieve SharePoint audit logs using Microsoft Graph API
function Get-SharePointAuditLogsGraph {
    param(
        [string[]]$UserList,
        [DateTime]$StartDate,
        [DateTime]$EndDate
    )
    
    Write-Host "Retrieving SharePoint audit logs using Microsoft Graph API..." -ForegroundColor Yellow
    
    $SharePointActivities = @(
        'FileAccessed', 'FileDownloaded', 'FileUploaded', 'FileModified', 'FileDeleted',
        'FileMoved', 'FileCopied', 'FileRenamed', 'FolderCreated', 'FolderDeleted',
        'SiteAccessed', 'PageViewed', 'SearchQueryPerformed', 'SharingSet',
        'SharingRevoked', 'SharingInvitationCreated', 'AnonymousLinkCreated',
        'SecureLinkCreated', 'AddedToSecureLink', 'RemovedFromSecureLink'
    )
    
    $AllAuditData = @()
    $CurrentDate = $StartDate
    
    # Process in 24-hour chunks to manage API rate limits
    while ($CurrentDate -lt $EndDate) {
        $ChunkEndDate = $CurrentDate.AddDays(1)
        if ($ChunkEndDate -gt $EndDate) { $ChunkEndDate = $EndDate }
        
        Write-Host "Processing chunk: $($CurrentDate.ToString('yyyy-MM-dd')) to $($ChunkEndDate.ToString('yyyy-MM-dd'))" -ForegroundColor Cyan
        
        try {
            # Build filter for Graph API
            $StartDateISO = $CurrentDate.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            $EndDateISO = $ChunkEndDate.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            
            # Use Graph API to get audit logs
            $Filter = "createdDateTime ge $StartDateISO and createdDateTime le $EndDateISO"
            
            if ($UserList -notcontains "ALL" -and $UserList.Count -gt 0) {
                $UserFilter = ($UserList | ForEach-Object { "userPrincipalName eq '$_'" }) -join " or "
                $Filter += " and ($UserFilter)"
            }
            
            # Get audit logs using Graph API
            $GraphAuditLogs = @()
            $NextLink = $null
            
            do {
                try {
                    if ($NextLink) {
                        $Response = Invoke-MgGraphRequest -Uri $NextLink -Method GET
                    }
                    else {
                        $Uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$Filter&`$top=1000"
                        $Response = Invoke-MgGraphRequest -Uri $Uri -Method GET
                    }
                    
                    if ($Response.value) {
                        $GraphAuditLogs += $Response.value
                        Write-Host "Retrieved $($Response.value.Count) records from Graph API" -ForegroundColor Cyan
                    }
                    
                    $NextLink = $Response.'@odata.nextLink'
                    
                    # Rate limiting - pause between requests
                    Start-Sleep -Milliseconds 100
                }
                catch {
                    Write-Warning "Error in Graph API request: $_"
                    break
                }
            } while ($NextLink)
            
            # Also try to get SharePoint-specific audit logs from Security API
            try {
                $SecurityFilter = "createdDateTime ge $StartDateISO and createdDateTime le $EndDateISO"
                $SecurityUri = "https://graph.microsoft.com/v1.0/security/alerts?`$filter=$SecurityFilter&`$top=1000"
                $SecurityResponse = Invoke-MgGraphRequest -Uri $SecurityUri -Method GET -ErrorAction SilentlyContinue
                
                if ($SecurityResponse.value) {
                    Write-Host "Retrieved $($SecurityResponse.value.Count) security events from Graph API" -ForegroundColor Cyan
                    $GraphAuditLogs += $SecurityResponse.value
                }
            }
            catch {
                Write-Verbose "Security API not accessible or no data: $_"
            }
            
            # Convert Graph API format to unified audit log format for compatibility
            foreach ($GraphRecord in $GraphAuditLogs) {
                try {
                    $ConvertedRecord = [PSCustomObject]@{
                        CreationDate = $GraphRecord.activityDateTime ?? $GraphRecord.createdDateTime
                        UserIds = $GraphRecord.initiatedBy.user.userPrincipalName ?? $GraphRecord.userPrincipalName
                        Operations = $GraphRecord.activityDisplayName ?? $GraphRecord.category
                        AuditData = ($GraphRecord | ConvertTo-Json -Depth 10)
                        ResultIndex = $AllAuditData.Count
                        ResultCount = 1
                        Identity = $GraphRecord.id
                        IsValid = $true
                        ObjectId = $GraphRecord.targetResources[0].id ?? $GraphRecord.id
                    }
                    $AllAuditData += $ConvertedRecord
                }
                catch {
                    Write-Verbose "Error converting Graph record: $_"
                }
            }
            
            Write-Host "Found $($GraphAuditLogs.Count) records for this chunk" -ForegroundColor Green
        }
        catch {
            Write-Warning "Error retrieving audit logs from Graph API for chunk $($CurrentDate.ToString('yyyy-MM-dd')): $_"
        }
        
        $CurrentDate = $ChunkEndDate
    }
    
    Write-Host "Total audit records retrieved from Graph API: $($AllAuditData.Count)" -ForegroundColor Green
    return $AllAuditData
}

# Process audit data and enrich with geolocation
function Process-AuditData {
    param([array]$RawAuditData)
    
    Write-Host "Processing and enriching audit data..." -ForegroundColor Yellow
    
    $ProcessedData = @()
    $Counter = 0
    
    foreach ($Record in $RawAuditData) {
        $Counter++
        if ($Counter % 100 -eq 0) {
            Write-Host "Processed $Counter of $($RawAuditData.Count) records..." -ForegroundColor Cyan
        }
        
        try {
            $AuditData = $Record.AuditData | ConvertFrom-Json
            
            # Extract IP address
            $IPAddress = $AuditData.ClientIP
            if ($IPAddress -and $IPAddress -ne "Unknown") {
                $IPAddress = $IPAddress.Split(':')[0]  # Remove port if present
                $LocationInfo = Get-IPGeolocation -IPAddress $IPAddress
            }
            else {
                $LocationInfo = @{
                    Country = "Unknown"; City = "Unknown"; Region = "Unknown"
                    Organization = "Unknown"; ISP = "Unknown"; ASN = "Unknown"
                    Timezone = "Unknown"; Latitude = $null; Longitude = $null
                }
            }
            
            # Create enriched record
            $EnrichedRecord = [PSCustomObject]@{
                DateTime = $Record.CreationDate
                EventType = $AuditData.Operation
                ActivityType = $AuditData.Workload
                UserName = $AuditData.UserId
                IPAddress = $IPAddress
                Country = $LocationInfo.Country
                City = $LocationInfo.City
                Region = $LocationInfo.Region
                Organization = $LocationInfo.Organization
                ISP = $LocationInfo.ISP
                ASN = $LocationInfo.ASN
                Timezone = $LocationInfo.Timezone
                BrowserAgent = $AuditData.UserAgent
                DeviceName = $AuditData.DeviceName
                DeviceInfo = $AuditData.DeviceProperties
                ApplicationName = $AuditData.ApplicationDisplayName
                AppId = $AuditData.ApplicationId
                FilePath = $AuditData.SourceRelativeUrl
                FileName = $AuditData.SourceFileName
                SiteName = $AuditData.SiteUrl
                ObjectId = $AuditData.ObjectId
                CorrelationId = $AuditData.CorrelationId
                SessionId = $AuditData.SessionId
                RecordType = $Record.RecordType
                ResultStatus = $AuditData.ResultStatus
                RawData = $Record.AuditData
            }
            
            $ProcessedData += $EnrichedRecord
        }
        catch {
            Write-Warning "Error processing record: $_"
        }
    }
    
    Write-Host "Successfully processed $($ProcessedData.Count) records" -ForegroundColor Green
    return $ProcessedData
}

# Build user baseline profiles
function Build-UserBaselines {
    param([array]$AuditData)
    
    Write-Host "Building user baseline profiles..." -ForegroundColor Yellow
    
    $UserBaselines = @{}
    
    foreach ($Record in $AuditData) {
        $User = $Record.UserName
        if (-not $UserBaselines.ContainsKey($User)) {
            $UserBaselines[$User] = @{
                CommonCountries = @{}
                CommonCities = @{}
                CommonIPs = @{}
                CommonHours = @{}
                CommonDays = @{}
                TotalActivities = 0
                FirstSeen = $Record.DateTime
                LastSeen = $Record.DateTime
            }
        }
        
        $Baseline = $UserBaselines[$User]
        $Baseline.TotalActivities++
        
        # Track countries
        if ($Record.Country -ne "Unknown") {
            if ($Baseline.CommonCountries.ContainsKey($Record.Country)) {
                $Baseline.CommonCountries[$Record.Country]++
            }
            else {
                $Baseline.CommonCountries[$Record.Country] = 1
            }
        }
        
        # Track cities
        if ($Record.City -ne "Unknown") {
            if ($Baseline.CommonCities.ContainsKey($Record.City)) {
                $Baseline.CommonCities[$Record.City]++
            }
            else {
                $Baseline.CommonCities[$Record.City] = 1
            }
        }
        
        # Track IPs
        if ($Record.IPAddress -and $Record.IPAddress -ne "Unknown") {
            if ($Baseline.CommonIPs.ContainsKey($Record.IPAddress)) {
                $Baseline.CommonIPs[$Record.IPAddress]++
            }
            else {
                $Baseline.CommonIPs[$Record.IPAddress] = 1
            }
        }
        
        # Track hours and days
        $Hour = $Record.DateTime.Hour
        $DayOfWeek = $Record.DateTime.DayOfWeek
        
        if ($Baseline.CommonHours.ContainsKey($Hour)) {
            $Baseline.CommonHours[$Hour]++
        }
        else {
            $Baseline.CommonHours[$Hour] = 1
        }
        
        if ($Baseline.CommonDays.ContainsKey($DayOfWeek)) {
            $Baseline.CommonDays[$DayOfWeek]++
        }
        else {
            $Baseline.CommonDays[$DayOfWeek] = 1
        }
        
        # Update time range
        if ($Record.DateTime -lt $Baseline.FirstSeen) {
            $Baseline.FirstSeen = $Record.DateTime
        }
        if ($Record.DateTime -gt $Baseline.LastSeen) {
            $Baseline.LastSeen = $Record.DateTime
        }
    }
    
    $Script:UserBaselineCache = $UserBaselines
    Write-Host "Built baselines for $($UserBaselines.Count) users" -ForegroundColor Green
}

# Detect suspicious activities
function Detect-SuspiciousActivities {
    param([array]$AuditData)
    
    Write-Host "Analyzing for suspicious activities..." -ForegroundColor Yellow
    
    $SuspiciousActivities = @()
    
    foreach ($Record in $AuditData) {
        $User = $Record.UserName
        $Suspicions = @()
        
        if ($Script:UserBaselineCache.ContainsKey($User)) {
            $Baseline = $Script:UserBaselineCache[$User]
            
            # Check for unusual country
            if ($Record.Country -ne "Unknown" -and $Baseline.CommonCountries.Count -gt 0) {
                $CountryFrequency = if ($Baseline.CommonCountries.ContainsKey($Record.Country)) { 
                    $Baseline.CommonCountries[$Record.Country] / $Baseline.TotalActivities 
                } else { 0 }
                
                if ($CountryFrequency -lt 0.05) {  # Less than 5% of activities
                    $Suspicions += "Unusual country: $($Record.Country) (frequency: $([math]::Round($CountryFrequency * 100, 2))%)"
                }
            }
            
            # Check for unusual time
            $Hour = $Record.DateTime.Hour
            $HourFrequency = if ($Baseline.CommonHours.ContainsKey($Hour)) { 
                $Baseline.CommonHours[$Hour] / $Baseline.TotalActivities 
            } else { 0 }
            
            if ($HourFrequency -lt 0.02) {  # Less than 2% of activities
                $Suspicions += "Unusual time: $($Hour):00 (frequency: $([math]::Round($HourFrequency * 100, 2))%)"
            }
            
            # Check for new IP address
            if ($Record.IPAddress -and $Record.IPAddress -ne "Unknown") {
                if (-not $Baseline.CommonIPs.ContainsKey($Record.IPAddress)) {
                    $Suspicions += "New IP address: $($Record.IPAddress)"
                }
            }
            
            # Check for suspicious activities
            $HighRiskActivities = @('FileDownloaded', 'FileDeleted', 'SharingSet', 'AnonymousLinkCreated')
            if ($Record.EventType -in $HighRiskActivities) {
                $Suspicions += "High-risk activity: $($Record.EventType)"
            }
        }
        
        if ($Suspicions.Count -gt 0) {
            $SuspiciousActivity = [PSCustomObject]@{
                DateTime = $Record.DateTime
                UserName = $Record.UserName
                EventType = $Record.EventType
                IPAddress = $Record.IPAddress
                Country = $Record.Country
                City = $Record.City
                Organization = $Record.Organization
                FileName = $Record.FileName
                FilePath = $Record.FilePath
                SuspicionReasons = ($Suspicions -join "; ")
                RiskLevel = if ($Suspicions.Count -ge 3) { "High" } elseif ($Suspicions.Count -eq 2) { "Medium" } else { "Low" }
            }
            $SuspiciousActivities += $SuspiciousActivity
        }
    }
    
    Write-Host "Identified $($SuspiciousActivities.Count) suspicious activities" -ForegroundColor Green
    return $SuspiciousActivities
}

# Generate reports
function Generate-Reports {
    param(
        [array]$AuditData,
        [array]$SuspiciousActivities,
        [string]$OutputPath
    )
    
    Write-Host "Generating reports..." -ForegroundColor Yellow
    
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Raw activity report
    $RawReportPath = Join-Path $OutputPath "DSPA_RawActivity_$Timestamp.csv"
    $AuditData | Export-Csv -Path $RawReportPath -NoTypeInformation
    Write-Host "✓ Raw activity report saved: $RawReportPath" -ForegroundColor Green
    
    # Suspicious activity report
    $SuspiciousReportPath = Join-Path $OutputPath "DSPA_SuspiciousActivity_$Timestamp.csv"
    $SuspiciousActivities | Export-Csv -Path $SuspiciousReportPath -NoTypeInformation
    Write-Host "✓ Suspicious activity report saved: $SuspiciousReportPath" -ForegroundColor Green
    
    # Summary report
    $SummaryReportPath = Join-Path $OutputPath "DSPA_Summary_$Timestamp.txt"
    $Summary = @"
Data Security Posture Activity (DSPA) Report Summary
Generated: $(Get-Date)
Analysis Period: $($AuditData[0].DateTime.ToString('yyyy-MM-dd')) to $($AuditData[-1].DateTime.ToString('yyyy-MM-dd'))

OVERVIEW:
- Total Activities Analyzed: $($AuditData.Count)
- Unique Users: $(($AuditData | Select-Object -Unique UserName).Count)
- Unique IP Addresses: $(($AuditData | Where-Object {$_.IPAddress -ne "Unknown"} | Select-Object -Unique IPAddress).Count)
- Unique Countries: $(($AuditData | Where-Object {$_.Country -ne "Unknown"} | Select-Object -Unique Country).Count)

SUSPICIOUS ACTIVITY SUMMARY:
- Total Suspicious Activities: $($SuspiciousActivities.Count)
- High Risk: $(($SuspiciousActivities | Where-Object {$_.RiskLevel -eq "High"}).Count)
- Medium Risk: $(($SuspiciousActivities | Where-Object {$_.RiskLevel -eq "Medium"}).Count)
- Low Risk: $(($SuspiciousActivities | Where-Object {$_.RiskLevel -eq "Low"}).Count)

TOP RISK INDICATORS:
$(if ($SuspiciousActivities.Count -gt 0) {
    $TopCountries = $SuspiciousActivities | Group-Object Country | Sort-Object Count -Descending | Select-Object -First 5
    "- Countries with most suspicious activities:"
    foreach ($Country in $TopCountries) {
        "  * $($Country.Name): $($Country.Count) activities"
    }
    
    $TopUsers = $SuspiciousActivities | Group-Object UserName | Sort-Object Count -Descending | Select-Object -First 5
    "`n- Users with most suspicious activities:"
    foreach ($User in $TopUsers) {
        "  * $($User.Name): $($User.Count) activities"
    }
} else {
    "- No significant risk indicators identified"
})

RECOMMENDATIONS:
$(if (($SuspiciousActivities | Where-Object {$_.RiskLevel -eq "High"}).Count -gt 0) {
    "- IMMEDIATE ACTION REQUIRED: Review high-risk activities"
    "- Consider implementing additional access controls"
    "- Review user access permissions for affected accounts"
} else {
    "- Continue monitoring user activities"
    "- Review medium and low-risk activities for patterns"
})
- Implement conditional access policies for unusual locations
- Enable multi-factor authentication for all users
- Regular review of sharing permissions and external access

FILES GENERATED:
- Raw Activity Log: $RawReportPath
- Suspicious Activities: $SuspiciousReportPath
- Summary Report: $SummaryReportPath
"@
    
    $Summary | Out-File -FilePath $SummaryReportPath -Encoding UTF8
    Write-Host "✓ Summary report saved: $SummaryReportPath" -ForegroundColor Green
    
    return @{
        RawReport = $RawReportPath
        SuspiciousReport = $SuspiciousReportPath
        SummaryReport = $SummaryReportPath
    }
}

# Main execution function
function Main {
    try {
        Write-Host "=== Data Security Posture Activity (DSPA) Report Generator ===" -ForegroundColor Magenta
        Write-Host "Starting analysis..." -ForegroundColor Yellow
        
        # Import modules and connect
        Import-RequiredModules
        
        # Connect using Microsoft Graph API
        Write-Host "Using Microsoft Graph API for audit log retrieval..." -ForegroundColor Cyan
        Connect-GraphAPI -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -ClientSecret $ClientSecret
        
        # Parse parameters
        $UserList = if ($Users -eq "ALL") { @("ALL") } else { $Users.Split(',').Trim() }
        $DateRange = Parse-DateRange -StartDate $StartDate -EndDate $EndDate -DaysBack $DaysBack
        
        # Retrieve and process audit data using Microsoft Graph API
        $RawAuditData = Get-SharePointAuditLogsGraph -UserList $UserList -StartDate $DateRange.StartDate -EndDate $DateRange.EndDate
        
        if ($RawAuditData.Count -eq 0) {
            Write-Warning "No audit data found for the specified criteria."
            return
        }
        
        $ProcessedAuditData = Process-AuditData -RawAuditData $RawAuditData
        
        # Analyze for suspicious activities
        Build-UserBaselines -AuditData $ProcessedAuditData
        $SuspiciousActivities = Detect-SuspiciousActivities -AuditData $ProcessedAuditData
        
        # Generate reports
        $Reports = Generate-Reports -AuditData $ProcessedAuditData -SuspiciousActivities $SuspiciousActivities -OutputPath $OutputPath
        
        Write-Host "`n=== ANALYSIS COMPLETE ===" -ForegroundColor Green
        Write-Host "Reports generated successfully!" -ForegroundColor Green
        Write-Host "Check the following files for detailed results:" -ForegroundColor Cyan
        Write-Host "- Raw Activity: $($Reports.RawReport)" -ForegroundColor White
        Write-Host "- Suspicious Activity: $($Reports.SuspiciousReport)" -ForegroundColor White
        Write-Host "- Summary: $($Reports.SummaryReport)" -ForegroundColor White
    }
    catch {
        Write-Error "Script execution failed: $_"
        exit 1
    }
    finally {
        # Cleanup connections
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Write-Host "✓ Disconnected from Microsoft Graph API" -ForegroundColor Green
        }
        catch {
            # Ignore cleanup errors
        }
    }
}

# Execute main function
Main