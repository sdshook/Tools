# Data Security Posture Activity (DSPA) Report Generator

## Overview

The DSPA.ps1 script is a comprehensive PowerShell tool designed to analyze SharePoint audit logs and generate detailed security reports. It provides both raw activity data and intelligent analysis of suspicious activities to help organizations maintain their data security posture.

## Features

### Core Capabilities
- **Multi-user Analysis**: Analyze specific users, multiple users, or all users in the organization
- **Flexible Date Ranges**: Support for custom date ranges (MMDDYYYY format) or days-back analysis
- **Comprehensive Data Collection**: Captures all required audit fields including datetime, event types, IP addresses, device information, and file details
- **IP Geolocation**: Automatically enriches IP addresses with country, city, organization, and ASN information
- **Baseline Analysis**: Builds user behavior baselines to identify anomalous activities
- **Suspicious Activity Detection**: Identifies unusual access patterns, locations, and times
- **Dual Report Generation**: Produces both raw activity logs and executive summary reports

### Security Features
- **Certificate-based Authentication**: Supports secure, non-interactive authentication
- **Credential Protection**: No hardcoded credentials or sensitive data exposure
- **Rate Limiting**: Implements API rate limiting to prevent service disruption
- **Error Handling**: Comprehensive error handling and logging

## Prerequisites

### Required PowerShell Modules
The script will automatically install these modules if not present:
- `ExchangeOnlineManagement`
- `PnP.PowerShell`
- `Microsoft.Graph.Authentication`

### Permissions Required
- **Exchange Online**: Audit Log Reader or higher
- **SharePoint Online**: SharePoint Administrator or Global Administrator
- **Azure AD**: Application permissions if using certificate authentication

## Installation

1. Download the `DSPA.ps1` script to your desired location
2. Ensure PowerShell execution policy allows script execution:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## Usage Examples

### Basic Usage - Last 30 Days for Specific Users
```powershell
.\DSPA.ps1 -Users "user1@domain.com,user2@domain.com" -DaysBack 30
```

### Analyze All Users for Custom Date Range
```powershell
.\DSPA.ps1 -Users "ALL" -StartDate "01012024" -EndDate "01312024" -OutputPath "C:\Reports"
```

### Certificate-based Authentication
```powershell
.\DSPA.ps1 -Users "ALL" -DaysBack 7 -TenantId "your-tenant-id" -ClientId "your-app-id" -CertificateThumbprint "your-cert-thumbprint"
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
| `TenantId` | String | No | Azure AD Tenant ID for certificate auth |
| `ClientId` | String | No | Azure AD Application Client ID |
| `CertificateThumbprint` | String | No | Certificate thumbprint for auth |

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

## Security Considerations

### Data Protection
- IP geolocation data is cached locally during execution
- No sensitive data is stored permanently
- All connections use secure protocols (HTTPS/TLS)

### Authentication Security
- Supports certificate-based authentication for automated scenarios
- Interactive authentication for manual execution
- No credential storage in script or logs

### API Rate Limiting
- Implements delays between geolocation API calls
- Processes audit logs in manageable chunks
- Handles API timeouts gracefully

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

**No Audit Data Found**
- Verify audit logging is enabled in Microsoft 365
- Check date ranges (audit logs have retention limits)
- Confirm users exist and have activity in the specified period

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