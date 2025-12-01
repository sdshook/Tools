<!-- DSPA (c) Shane D. Shook, 2025 All Rights Reserved -->
# Data Security Posture Activity (DSPA) Tools Suite

**DSPA (c) Shane D. Shook, 2025 All Rights Reserved**

This suite provides comprehensive Data Security Posture Activity reporting tools for major cloud storage platforms. Each tool retrieves audit logs, analyzes user activities, and generates security reports including suspicious activity detection.

**Author:** Shane D. Shook, PhD

## 🚀 NEW: Unified DSPA Tool

The **Unified DSPA Tool** (`unified_dspa.py`) is a single Python script that supports all four cloud services through their respective APIs. This is the recommended approach for new deployments.

### Quick Start with Unified Tool
```bash
# Install dependencies
pip install -r requirements.txt

# Configure credentials
cp dspa_config.json dspa_config_production.json
# Edit dspa_config_production.json with your API credentials

# Run analysis
python unified_dspa.py sharepoint -u user@company.com -d 30
python unified_dspa.py googledrive -u ALL --start-date 01012024 --end-date 01312024
python unified_dspa.py box -u "user1@company.com,user2@company.com" -d 7
python unified_dspa.py dropbox -u ALL -d 14
```

**[📖 Jump to Unified Tool Documentation](#unified-dspa-tool)**

## Available Tools

### 📁 [SharePoint DSPA](./Sharepoint/) (PowerShell)
- **Platform**: Microsoft SharePoint Online
- **Language**: PowerShell
- **Authentication**: Exchange Online PowerShell, Graph API, Purview API
- **Features**: Multi-method authentication, comprehensive audit log retrieval

### 🔍 [Google Drive DSPA](./GDrive/) (Python)
- **Platform**: Google Workspace Drive
- **Language**: Python
- **Authentication**: Google Service Account with domain-wide delegation
- **Features**: Admin SDK Reports API integration, user activity analysis

### 📦 [Box DSPA](./Box/) (Python)
- **Platform**: Box Enterprise/Business
- **Language**: Python
- **Authentication**: OAuth2 with Box API
- **Features**: Box Events API integration, enterprise audit logs

### 📂 [Dropbox DSPA](./DropBox/) (Python)
- **Platform**: Dropbox Business/Enterprise
- **Language**: Python
- **Authentication**: Dropbox Team API access token
- **Features**: Team Log API integration, team member activity analysis

## Common Features

All DSPA tools provide:

### 🔍 **Comprehensive Audit Log Retrieval**
- Pull complete audit logs from respective platforms
- Support for user filtering (all users or specific users)
- Flexible date range options (custom dates or days-back)

### 🌍 **IP Geolocation Enrichment**
- Automatic IP address geolocation lookup
- Country, city, organization, and ASN information
- Private network detection and handling

### 🚨 **Suspicious Activity Detection**
- **Unusual Locations**: Activities from uncommon geographic locations
- **Unusual Times**: Activities during off-hours (outside 6 AM - 10 PM UTC)
- **High-Risk Activities**: Platform-specific high-risk events (delete, download, share, etc.)

### 📊 **Dual Report Generation**
1. **Raw Activity Report (CSV)**: Complete audit log data with enriched IP information
2. **Suspicious Activity Report (JSON)**: Analyzed suspicious activities with context and reasoning

## Quick Start Guide

### 1. Choose Your Platform
Navigate to the appropriate folder based on your cloud storage platform:
- SharePoint: `cd Sharepoint/`
- Google Drive: `cd GDrive/`
- Box: `cd Box/`
- Dropbox: `cd DropBox/`

### 2. Install Dependencies
Each tool has its own requirements file:
```bash
# For Python tools
pip install -r requirements.txt

# For PowerShell tool (SharePoint)
# See SharePoint README for module installation
```

### 3. Configure Authentication
Each platform requires different authentication setup:
- **SharePoint**: Exchange Online PowerShell, Graph API, or Purview API
- **Google Drive**: Service account with domain-wide delegation
- **Box**: OAuth2 application with enterprise permissions
- **Dropbox**: Team API access token

### 4. Run Analysis
Basic usage examples:
```bash
# SharePoint (PowerShell)
.\DSPA.ps1 -Users "ALL" -DaysBack 30

# Google Drive (Python)
python gdrive_dspa.py --credentials creds.json --domain example.com --days-back 30

# Box (Python)
python box_dspa.py --client-id ID --client-secret SECRET --access-token TOKEN --days-back 30

# Dropbox (Python)
python dropbox_dspa.py --access-token TOKEN --days-back 30
```

## Output Files

All tools generate two types of reports:

### Raw Activity Report (CSV)
Contains complete audit log data with fields like:
- Timestamp and event details
- User information
- IP address with geolocation data
- File/folder information
- Device and application details

### Suspicious Activity Report (JSON)
Contains analyzed suspicious activities:
- Unusual location activities
- Unusual time activities  
- High-risk activities
- Summary statistics

## Security Considerations

### 🔐 **Credential Management**
- Store API credentials securely
- Use environment variables or secure credential stores
- Implement proper token refresh mechanisms
- Restrict access to credential files

### 🌐 **Network Security**
- IP geolocation requests go to external services
- Consider using internal geolocation services for sensitive environments
- Monitor network traffic for security compliance

### 📋 **Data Privacy**
- Audit logs contain sensitive user activity data
- Ensure compliance with data protection regulations
- Implement proper data retention policies
- Secure report storage and transmission

### 🔄 **API Rate Limits**
- All platforms have API rate limits
- Implement proper retry logic and backoff strategies
- Consider running during off-peak hours for large datasets
- Monitor API usage and quotas

## Platform Comparison

| Feature | SharePoint | Google Drive | Box | Dropbox |
|---------|------------|--------------|-----|---------|
| **Language** | PowerShell | Python | Python | Python |
| **Auth Methods** | 3 options | Service Account | OAuth2 | Access Token |
| **User Filtering** | Email/UPN | Email | ID/Email | ID/Email |
| **Date Formats** | MMDDYYYY | MMDDYYYY | MMDDYYYY | MMDDYYYY |
| **IP Geolocation** | ✅ | ✅ | ✅ | ✅ |
| **Device Info** | ✅ | Limited | ✅ | ✅ |
| **App Info** | ✅ | Limited | Limited | ✅ |
| **File Paths** | ✅ | Limited | ✅ | ✅ |

## Troubleshooting

### Common Issues Across All Platforms

1. **Authentication Failures**
   - Verify credentials and permissions
   - Check API access and authorization
   - Ensure proper scopes/permissions are granted

2. **No Data Retrieved**
   - Verify date range parameters
   - Check user permissions and status
   - Ensure audit logging is enabled on the platform

3. **API Rate Limits**
   - Implement delays between requests
   - Reduce scope (date range, user count)
   - Use exponential backoff for retries

4. **IP Geolocation Issues**
   - External service may be unavailable
   - Consider alternative geolocation services
   - Implement fallback mechanisms

## Support and Documentation

Each tool has detailed documentation in its respective folder:
- [SharePoint DSPA Documentation](./Sharepoint/DSPA_README.md)
- [Google Drive DSPA Documentation](./GDrive/README.md)
- [Box DSPA Documentation](./Box/README.md)
- [Dropbox DSPA Documentation](./DropBox/README.md)

## Version History

- **v1.0.0** - Initial release of all four DSPA tools
  - SharePoint DSPA v4.0 (PowerShell)
  - Google Drive DSPA v1.0 (Python)
  - Box DSPA v1.0 (Python)
  - Dropbox DSPA v1.0 (Python)

## Contributing

When contributing to any DSPA tool:
1. Follow the existing code style and structure
2. Update documentation for any new features
3. Test with multiple user scenarios and date ranges
4. Consider security implications of changes
5. Update version numbers appropriately

---

# Unified DSPA Tool

## Overview

The Unified DSPA Tool is a comprehensive Python-based security analysis solution that retrieves audit log activities from multiple cloud storage services and generates detailed security posture reports. This single tool supports SharePoint, Google Drive, Box, and Dropbox through their respective APIs.

## Features

- **Multi-Service Support**: Single tool for SharePoint, Google Drive, Box, and Dropbox
- **Comprehensive Audit Logging**: Retrieves detailed activity logs including:
  - Date/time of events
  - Event and activity types
  - User information
  - IP addresses with geolocation
  - Device and browser information
  - File paths and names
  - Application details
- **Suspicious Activity Detection**: Automated analysis identifying:
  - Unusual IP addresses
  - Uncommon access times
  - Suspicious geographic locations
  - Anomalous user behavior patterns
- **Dual Report Generation**:
  - Raw activity log (CSV format)
  - Suspicious activity summary (CSV format)
- **IP Geolocation**: Automatic country, city, and organization lookup
- **Flexible Date Ranges**: Support for specific date ranges or days-back queries

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Appropriate API access for target services

### Install Dependencies

```bash
pip install -r requirements.txt
```

## Configuration

### 1. Copy Configuration Template

```bash
cp dspa_config.json dspa_config_production.json
```

### 2. Configure Each Service

Edit `dspa_config_production.json` with your API credentials:

#### SharePoint (Microsoft Graph API)

**Required Permissions:**
- `AuditLog.Read.All`
- `SecurityEvents.Read.All`
- `Directory.Read.All`

**Setup Steps:**
1. Register application in Azure AD
2. Grant required permissions
3. Generate client secret
4. Update configuration:

```json
"sharepoint_api": {
  "tenant_id": "your-tenant-id",
  "client_id": "your-client-id",
  "client_secret": "your-client-secret"
}
```

**Setup Guide:** https://docs.microsoft.com/en-us/graph/auth-register-app-v2

#### Google Drive (Admin SDK Reports API)

**Required Scopes:**
- `https://www.googleapis.com/auth/admin.reports.audit.readonly`

**Setup Steps:**
1. Create service account in Google Cloud Console
2. Enable Admin SDK API
3. Download service account key file
4. Grant domain-wide delegation
5. Update configuration:

```json
"googledrive_api": {
  "service_account_file": "/path/to/service-account-key.json",
  "domain": "your-domain.com"
}
```

**Setup Guide:** https://developers.google.com/admin-sdk/reports/v1/guides/authorizing

#### Box (Events API)

**Required Scopes:**
- `manage_enterprise_properties`

**Setup Steps:**
1. Create Box application
2. Configure OAuth 2.0 or JWT authentication
3. Generate access token
4. Update configuration:

```json
"box_api": {
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "access_token": "your-access-token"
}
```

**Setup Guide:** https://developer.box.com/guides/authentication/

#### Dropbox (Team Log API)

**Required Permissions:**
- `team_data.governance.read`
- `team_info.read`

**Setup Steps:**
1. Create Dropbox Business app
2. Generate team access token
3. Update configuration:

```json
"dropbox_api": {
  "access_token": "your-team-access-token",
  "app_key": "your-app-key",
  "app_secret": "your-app-secret"
}
```

**Setup Guide:** https://www.dropbox.com/developers/apps

## Usage

### Command Line Syntax

```bash
python unified_dspa.py <service> -u <users> [options]
```

### Parameters

- `service`: Choose from `sharepoint`, `googledrive`, `box`, or `dropbox`
- `-u, --users`: Comma-separated user emails or "ALL" for all users
- `-d, --days-back`: Number of days back to analyze
- `--start-date`: Start date in MMDDYYYY format
- `--end-date`: End date in MMDDYYYY format
- `-c, --config`: Configuration file path (default: dspa_config.json)
- `-o, --output-prefix`: Output file prefix (default: dspa_report)
- `-v, --verbose`: Enable verbose logging

### Examples

#### SharePoint Analysis
```bash
# Analyze specific user for last 30 days
python unified_dspa.py sharepoint -u user@company.com -d 30

# Analyze all users for specific date range
python unified_dspa.py sharepoint -u ALL --start-date 01012024 --end-date 01312024

# Multiple users with custom output
python unified_dspa.py sharepoint -u "user1@company.com,user2@company.com" -d 7 -o sharepoint_security_audit
```

#### Google Drive Analysis
```bash
# All users, last 14 days
python unified_dspa.py googledrive -u ALL -d 14

# Specific user, custom date range
python unified_dspa.py googledrive -u admin@company.com --start-date 12012024 --end-date 12312024
```

#### Box Analysis
```bash
# Multiple users, last week
python unified_dspa.py box -u "user1@company.com,user2@company.com" -d 7

# All users with verbose logging
python unified_dspa.py box -u ALL -d 30 -v
```

#### Dropbox Analysis
```bash
# Team analysis for last month
python unified_dspa.py dropbox -u ALL -d 30

# Specific users, custom config file
python unified_dspa.py dropbox -u "user1@company.com,user2@company.com" -d 14 -c custom_config.json
```

## Output Files

The tool generates two CSV reports:

### 1. Raw Activity Report
**Filename:** `{prefix}_{service}_raw_{timestamp}.csv`

**Columns:**
- `datetime`: Event timestamp
- `event_type`: Type of event
- `activity_type`: Specific activity
- `user_name`: User email/identifier
- `ip_address`: Source IP address
- `country`: IP geolocation country
- `city`: IP geolocation city
- `organization`: IP owner organization
- `user_agent`: Browser/client information
- `device_name`: Device identifier
- `device_info`: Device details
- `application_name`: Application used
- `app_id`: Application ID
- `file_path`: File path
- `file_name`: File name

### 2. Suspicious Activity Report
**Filename:** `{prefix}_{service}_suspicious_{timestamp}.csv`

**Columns:**
- `datetime`: Event timestamp
- `user_name`: User identifier
- `activity_type`: Activity performed
- `ip_address`: Source IP
- `country`: IP country
- `city`: IP city
- `organization`: IP organization
- `suspicion_reasons`: Why flagged as suspicious
- `file_name`: Affected file
- `file_path`: File location

## Suspicious Activity Detection

The tool automatically identifies suspicious patterns:

### Unusual IP Addresses
- IPs used less than 10% of the time by a user
- First-time IP addresses for established users

### Unusual Access Times
- Access outside normal business hours (6 AM - 10 PM)
- Times used less than 5% by the user

### Unusual Geographic Locations
- Countries accessed less than 10% of the time
- New geographic regions for established users

### Configuration Thresholds

Adjust detection sensitivity in `dspa_config.json`:

```json
"suspicious_activity_thresholds": {
  "min_activities_for_profile": 10,
  "unusual_ip_threshold": 0.1,
  "unusual_time_threshold": 0.05,
  "unusual_location_threshold": 0.1
}
```

## Security Considerations

### Credential Security
- Store configuration files securely
- Use environment variables for sensitive data
- Implement proper access controls
- Rotate API keys regularly

### API Rate Limits
- Each service has different rate limits
- Tool implements appropriate delays
- Monitor API usage quotas

### Data Privacy
- Audit logs contain sensitive information
- Implement data retention policies
- Secure report storage and transmission
- Follow organizational privacy guidelines

## Troubleshooting

### Common Issues

#### Missing Dependencies
```bash
pip install -r requirements.txt
```

#### Authentication Errors
- Verify API credentials in configuration
- Check required permissions/scopes
- Ensure tokens haven't expired

#### No Data Retrieved
- Verify date ranges
- Check user permissions
- Confirm API access rights

#### Rate Limiting
- Reduce query scope
- Implement delays between requests
- Check service-specific limits

### Logging

Enable verbose logging for troubleshooting:
```bash
python unified_dspa.py <service> -u <users> -v
```

## API Limitations

### SharePoint (Microsoft Graph)
- Requires Azure AD application registration
- Limited audit log retention (90 days default)
- Rate limits: 10,000 requests per 10 minutes

### Google Drive (Admin SDK)
- Requires G Suite/Google Workspace admin
- Service account with domain-wide delegation
- Rate limits: 1,500 requests per 100 seconds

### Box (Events API)
- Enterprise account required
- Limited event retention (1 year)
- Rate limits: 60 requests per minute

### Dropbox (Team Log API)
- Dropbox Business account required
- Limited log retention (180 days)
- Rate limits: 25 requests per second

## License

**DSPA (c) Shane D. Shook, 2025 All Rights Reserved**

This software is proprietary and confidential. Unauthorized copying, distribution, or use is strictly prohibited.