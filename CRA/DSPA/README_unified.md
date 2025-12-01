# Unified Data Security Posture Activity (DSPA) Tool

**DSPA (c) Shane D. Shook, 2025 All Rights Reserved**

## Author
**Shane D. Shook, PhD**

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

## Support and Maintenance

### Version Information
- **Version:** 1.0.0
- **Last Updated:** December 2024
- **Python Compatibility:** 3.8+

### Updates and Patches
- Monitor API changes from service providers
- Update dependencies regularly
- Test with new service API versions

### Contributing
This tool is proprietary software. For support or feature requests, contact the author.

## License

**DSPA (c) Shane D. Shook, 2025 All Rights Reserved**

This software is proprietary and confidential. Unauthorized copying, distribution, or use is strictly prohibited.

---

**Author:** Shane D. Shook, PhD  
**Contact:** [Contact information]  
**Documentation Version:** 1.0.0