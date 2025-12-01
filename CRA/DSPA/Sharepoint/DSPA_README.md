# DSPA (c) Shane D. Shook, 2025 All Rights Reserved

# Data Security Posture Activity (DSPA) Report Generator

## Overview

The DSPA.ps1 script is a comprehensive PowerShell tool designed to analyze SharePoint audit logs and generate detailed security reports. It provides both raw activity data and intelligent analysis of suspicious activities to help organizations maintain their data security posture.

**Author:** Shane D. Shook, PhD

## Features

### Core Capabilities
- **Multi-user Analysis**: Analyze specific users, multiple users, or all users in the organization
- **Flexible Date Ranges**: Support for custom date ranges (MMDDYYYY format) or days-back analysis
- **Comprehensive Data Collection**: Captures all required audit fields including datetime, event types, IP addresses, device information, and file details
- **IP Geolocation**: Automatically enriches IP addresses with country, city, organization, and ASN information
- **Baseline Analysis**: Builds user behavior baselines to identify anomalous activities
- **Suspicious Activity Detection**: Identifies unusual access patterns, locations, and times
- **Dual Report Generation**: Produces both raw activity logs and executive summary reports
- **Multiple Authentication Methods**: Supports three different authentication methods for maximum flexibility

### Security Features
- **Exchange Online PowerShell (Default)**: Uses Search-UnifiedAuditLog cmdlet for traditional audit log access
- **Microsoft Graph API**: Modern Graph API for enhanced security and performance
- **Purview Audit Search Graph API**: Advanced Purview audit capabilities for comprehensive analysis
- **Certificate-based Authentication**: Supports secure, non-interactive authentication
- **Client Secret Authentication**: Alternative authentication method for Graph API
- **Interactive Authentication**: User-friendly authentication for all methods
- **Credential Protection**: No hardcoded credentials or sensitive data exposure
- **Rate Limiting**: Implements API rate limiting to prevent service disruption
- **Error Handling**: Comprehensive error handling and logging

## Prerequisites

### Required PowerShell Modules
The script will automatically install these modules based on the authentication method chosen:

**All Methods:**
- `PnP.PowerShell`

**Exchange Online PowerShell (Default):**
- `ExchangeOnlineManagement`

**Microsoft Graph API (-UseGraphAPI) and Purview API (-UsePurviewAPI):**
- `Microsoft.Graph.Authentication`
- `Microsoft.Graph.Security`
- `Microsoft.Graph.Reports`

### Permissions Required

**Exchange Online PowerShell:**
- **Required Roles:**
  - `View-Only Audit Logs` or `Audit Logs` role
  - `Exchange Administrator` or `Global Administrator`
- **Permissions:** Access to Search-UnifiedAuditLog cmdlet

**Microsoft Graph API:**
- **Required Graph API Scopes:**
  - `AuditLog.Read.All`
  - `Directory.Read.All`
  - `Reports.Read.All`
  - `SecurityEvents.Read.All`
- **Azure AD App Registration**: Required for service principal authentication

**Purview Audit Search Graph API:**
- **Required Graph API Scopes:**
  - `AuditLog.Read.All`
  - `SecurityEvents.Read.All`
  - `Directory.Read.All`
- **Azure AD App Registration**: Required for service principal authentication
- **Purview Permissions**: Access to Purview audit search capabilities

## Installation

1. Download the `DSPA.ps1` script to your desired location
2. Ensure PowerShell execution policy allows script execution:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## Usage Examples

### Exchange Online PowerShell (Default Method)

#### Basic Usage - Last 30 Days for Specific Users
```powershell
.\DSPA.ps1 -Users "user1@domain.com,user2@domain.com" -DaysBack 30
```

#### Analyze All Users for Custom Date Range
```powershell
.\DSPA.ps1 -Users "ALL" -StartDate "01012024" -EndDate "01312024" -OutputPath "C:\Reports"
```

#### Exchange Online with Certificate Authentication
```powershell
.\DSPA.ps1 -Users "ALL" -DaysBack 7 -TenantId "your-tenant-id" -ClientId "your-app-id" -CertificateThumbprint "your-cert-thumbprint"
```

### Microsoft Graph API Method

#### Graph API with Client Secret
```powershell
.\DSPA.ps1 -Users "ALL" -DaysBack 7 -UseGraphAPI -TenantId "your-tenant-id" -ClientId "your-app-id" -ClientSecret "your-client-secret"
```

#### Graph API with Certificate
```powershell
.\DSPA.ps1 -Users "user@domain.com" -DaysBack 30 -UseGraphAPI -TenantId "your-tenant-id" -ClientId "your-app-id" -CertificateThumbprint "your-cert-thumbprint"
```

#### Interactive Graph API Authentication
```powershell
.\DSPA.ps1 -Users "ALL" -StartDate "11012024" -EndDate "11302024" -UseGraphAPI
```

### Purview Audit Search Graph API Method

#### Purview API with Client Secret
```powershell
.\DSPA.ps1 -Users "ALL" -DaysBack 7 -UsePurviewAPI -TenantId "your-tenant-id" -ClientId "your-app-id" -ClientSecret "your-client-secret"
```

#### Purview API with Certificate
```powershell
.\DSPA.ps1 -Users "user@domain.com" -DaysBack 30 -UsePurviewAPI -TenantId "your-tenant-id" -ClientId "your-app-id" -CertificateThumbprint "your-cert-thumbprint"
```

#### Interactive Purview API Authentication
```powershell
.\DSPA.ps1 -Users "ALL" -StartDate "11012024" -EndDate "11302024" -UsePurviewAPI
```

### Single User Analysis with Custom Output
```powershell
.\DSPA.ps1 -Users "john.doe@company.com" -StartDate "11012024" -EndDate "11302024" -OutputPath "C:\SecurityReports"
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `Users` | String | Yes | Comma-separated user UPNs or "ALL" for all users |
| `StartDate` | String | No | Start date in MMDDYYYY format |
| `EndDate` | String | No | End date in MMDDYYYY format |
| `DaysBack` | Integer | No | Number of days back from current date |
| `OutputPath` | String | No | Directory for output files (default: current directory) |
| `TenantId` | String | No | Azure AD Tenant ID for authentication |
| `ClientId` | String | No | Azure AD Application Client ID |
| `CertificateThumbprint` | String | No | Certificate thumbprint for certificate auth |
| `ClientSecret` | String | No | Azure AD Application Client Secret |
| `UseGraphAPI` | Switch | No | Use Microsoft Graph API instead of Exchange Online PowerShell |
| `UsePurviewAPI` | Switch | No | Use Purview Audit Search Graph API for enhanced capabilities |

## Authentication Methods

### Method Selection Priority
1. **Purview API**: If `-UsePurviewAPI` is specified
2. **Graph API**: If `-UseGraphAPI` is specified  
3. **Exchange Online PowerShell**: Default method (Search-UnifiedAuditLog)

### Method Comparison

| Feature | Exchange Online | Graph API | Purview API |
|---------|----------------|-----------|-------------|
| **Authentication** | Interactive/Certificate | Interactive/Certificate/Secret | Interactive/Certificate/Secret |
| **Data Retention** | 90 days | 90 days | Extended retention |
| **Rate Limits** | Moderate | High | High |
| **Advanced Features** | Basic | Enhanced | Most Advanced |
| **Setup Complexity** | Low | Medium | Medium |
| **Recommended For** | Quick analysis | Production environments | Advanced security analysis |

## Output Files

The script generates three types of reports:

### 1. Raw Activity Report (`DSPA_RawActivity_YYYYMMDD_HHMMSS.csv`)
Contains all audit log entries with the following fields:
- DateTime, EventType, ActivityType, UserName
- IPAddress, Country, City, Region, Organization, ISP, ASN
- BrowserAgent, DeviceName, DeviceInfo
- ApplicationName, AppId, FilePath, FileName
- SiteName, ObjectId, CorrelationId, SessionId
- RecordType, ResultStatus, RawData

### 2. Suspicious Activity Report (`DSPA_SuspiciousActivity_YYYYMMDD_HHMMSS.csv`)
Filtered view of activities flagged as suspicious:
- All fields from raw report
- SuspicionReasons (detailed explanation)
- RiskLevel (High/Medium/Low)

### 3. Summary Report (`DSPA_Summary_YYYYMMDD_HHMMSS.txt`)
Executive summary including:
- Analysis overview and statistics
- Suspicious activity counts by risk level
- Top risk indicators and affected users
- Security recommendations
- File locations for detailed reports

## Suspicious Activity Detection

The script identifies suspicious activities based on:

### Location Anomalies
- Access from countries representing <5% of user's historical activity
- New IP addresses not seen in user's baseline
- Access from high-risk geographic regions

### Temporal Anomalies
- Activity during hours representing <2% of user's normal pattern
- Access during unusual days of the week

### Activity-based Risks
- High-risk operations: File downloads, deletions, sharing changes
- Anonymous link creation
- Bulk file operations

### Risk Levels
- **High**: 3+ suspicious indicators
- **Medium**: 2 suspicious indicators  
- **Low**: 1 suspicious indicator

## Authentication Methods

### Exchange Online PowerShell (Default)
**Pros:**
- Mature and stable API
- Comprehensive audit log coverage
- Well-documented and widely used

**Cons:**
- Legacy authentication methods
- Limited to Exchange Online scope
- May have performance limitations

**Usage:**
```powershell
# Interactive authentication
.\DSPA.ps1 -Users "ALL" -DaysBack 7

# Certificate-based authentication
.\DSPA.ps1 -Users "ALL" -DaysBack 7 -TenantId "tenant-id" -ClientId "app-id" -CertificateThumbprint "thumbprint"
```

### Microsoft Graph API (-UseGraphAPI)
**Pros:**
- Modern, unified API across Microsoft 365
- Better performance and rate limiting
- Enhanced security with granular permissions
- Future-proof approach

**Cons:**
- Requires Azure AD app registration
- More complex initial setup
- May have different data format

**Usage:**
```powershell
# Interactive authentication
.\DSPA.ps1 -Users "ALL" -DaysBack 7 -UseGraphAPI

# Client secret authentication
.\DSPA.ps1 -Users "ALL" -DaysBack 7 -UseGraphAPI -TenantId "tenant-id" -ClientId "app-id" -ClientSecret "secret"

# Certificate authentication
.\DSPA.ps1 -Users "ALL" -DaysBack 7 -UseGraphAPI -TenantId "tenant-id" -ClientId "app-id" -CertificateThumbprint "thumbprint"
```

## Security Considerations

### Data Protection
- IP geolocation data is cached locally during execution
- No sensitive data is stored permanently
- All connections use secure protocols (HTTPS/TLS)

### Authentication Security
- Supports certificate-based authentication for automated scenarios
- Interactive authentication for manual execution
- No credential storage in script or logs
- Graph API provides enhanced security with granular permissions

### API Rate Limiting
- Implements delays between geolocation API calls
- Processes audit logs in manageable chunks
- Handles API timeouts gracefully
- Graph API includes built-in rate limiting and retry logic

## Troubleshooting

### Common Issues

**Module Installation Failures**
```powershell
# Run as Administrator if needed
Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber -Scope AllUsers
```

**Authentication Errors**
- Verify user has required permissions
- Check certificate installation for cert-based auth
- Ensure tenant ID and client ID are correct

**Graph API Authentication Issues**
- Verify Azure AD app registration has required API permissions
- Ensure admin consent has been granted for application permissions
- Check that the correct tenant ID is being used
- Verify client secret hasn't expired (if using client secret auth)

**No Audit Data Found**
- Verify audit logging is enabled in Microsoft 365
- Check date ranges (audit logs have retention limits)
- Confirm users exist and have activity in the specified period
- For Graph API: Ensure the app has access to audit logs in the tenant

**Geolocation API Errors**
- Script continues with "Unknown" values if API fails
- Rate limiting prevents API abuse
- Consider using premium geolocation services for production

### Performance Optimization

**Large Datasets**
- Use smaller date ranges for better performance
- Consider running during off-peak hours
- Monitor memory usage for very large result sets

**Network Considerations**
- Ensure stable internet connection for API calls
- Consider running from Azure Cloud Shell for better connectivity
- Use certificate authentication to avoid interactive prompts

## Advanced Configuration

### Custom Geolocation Provider
To use a different IP geolocation service, modify the `Get-IPGeolocation` function:

```powershell
# Example: Using IPStack API
$Response = Invoke-RestMethod -Uri "http://api.ipstack.com/$IPAddress?access_key=YOUR_KEY"
```

### Additional Suspicious Activity Rules
Extend the `Detect-SuspiciousActivities` function to add custom detection logic:

```powershell
# Example: Flag activities outside business hours
if ($Hour -lt 8 -or $Hour -gt 18) {
    $Suspicions += "Outside business hours: $Hour"
}
```

## Support and Maintenance

### Regular Updates
- Monitor Microsoft Graph API changes
- Update PowerShell modules regularly
- Review and adjust suspicious activity thresholds

### Monitoring
- Set up scheduled execution for regular reports
- Monitor script execution logs
- Review false positive rates and adjust detection rules

## License and Disclaimer

This script is provided as-is for security analysis purposes. Users are responsible for:
- Ensuring compliance with organizational policies
- Protecting generated reports containing sensitive data
- Regular testing and validation of results
- Maintaining appropriate access controls

For support or feature requests, please refer to your organization's IT security team.