# Google Drive Data Security Posture Activity (DSPA) Tool

This Python tool retrieves Google Drive audit log activities and generates comprehensive security posture reports, including analysis of suspicious activities.

## Features

- **Comprehensive Audit Log Retrieval**: Pulls Google Drive activity logs using the Google Admin SDK Reports API
- **User Filtering**: Analyze all users or specific users by email address
- **Flexible Date Ranges**: Support for custom date ranges or days-back from current date
- **IP Geolocation Enrichment**: Automatically enriches IP addresses with country, city, organization, and ASN data
- **Suspicious Activity Detection**: Identifies unusual locations, unusual access times, and high-risk activities
- **Dual Report Generation**: Produces both raw activity logs (CSV) and suspicious activity analysis (JSON)

## Prerequisites

### Google Workspace Admin Access
- Google Workspace Super Admin privileges
- Access to Google Admin Console
- Domain-wide delegation enabled for service account

### API Setup
1. **Create a Google Cloud Project**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing project

2. **Enable Required APIs**
   - Admin SDK API
   - Google Drive API (optional, for enhanced file information)

3. **Create Service Account**
   - Go to IAM & Admin > Service Accounts
   - Create new service account
   - Download JSON credentials file
   - Enable domain-wide delegation

4. **Configure Domain-Wide Delegation**
   - In Google Admin Console, go to Security > API Controls
   - Add the service account client ID with required scopes:
     - `https://www.googleapis.com/auth/admin.reports.audit.readonly`
     - `https://www.googleapis.com/auth/admin.directory.user.readonly`

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Tools/CRA/DSPA/GDrive
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up credentials**
   - Place your service account JSON file in a secure location
   - Note the path for use with the `--credentials` parameter

## Usage

### Basic Usage

```bash
# Analyze all users for last 30 days (default)
python gdrive_dspa.py --credentials /path/to/service_account.json --domain example.com

# Analyze specific users
python gdrive_dspa.py --credentials /path/to/service_account.json --domain example.com --users "user1@example.com,user2@example.com"

# Analyze last 7 days
python gdrive_dspa.py --credentials /path/to/service_account.json --domain example.com --days-back 7

# Analyze specific date range
python gdrive_dspa.py --credentials /path/to/service_account.json --domain example.com --start-date 11012024 --end-date 11302024
```

### Command Line Parameters

| Parameter | Required | Description | Example |
|-----------|----------|-------------|---------|
| `--credentials` | Yes | Path to Google service account JSON file | `/path/to/creds.json` |
| `--domain` | Yes | Google Workspace domain | `example.com` |
| `--users` | No | Comma-separated user emails or "ALL" | `user1@example.com,user2@example.com` |
| `--start-date` | No | Start date in MMDDYYYY format | `11012024` |
| `--end-date` | No | End date in MMDDYYYY format | `11302024` |
| `--days-back` | No | Number of days back from today | `7` |
| `--output-dir` | No | Output directory for reports | `./reports` |

## Output Files

### Raw Activity Report (CSV)
File: `gdrive_dspa_raw_YYYYMMDD_HHMMSS.csv`

Contains all audit log entries with the following fields:
- `datetime` - Event timestamp
- `user_email` - User email address
- `ip_address` - Source IP address
- `country` - IP geolocation country
- `city` - IP geolocation city
- `organization` - IP organization/ISP
- `asn` - Autonomous System Number
- `event_type` - Type of event
- `event_name` - Specific event name
- `file_name` - File name (if applicable)
- `file_id` - Google Drive file ID
- `file_type` - File type
- `visibility` - File visibility setting
- `user_agent` - User agent information

### Suspicious Activity Report (JSON)
File: `gdrive_dspa_suspicious_YYYYMMDD_HHMMSS.json`

Contains analysis of suspicious activities:
- `unusual_locations` - Activities from uncommon geographic locations
- `unusual_times` - Activities during unusual hours (outside 6 AM - 10 PM UTC)
- `high_risk_activities` - High-risk events (delete, download, share, visibility changes)
- `summary` - Analysis summary statistics

## Available Event Types

The tool captures various Google Drive events including:
- File access and downloads
- File sharing and permission changes
- File creation, modification, and deletion
- Folder operations
- Collaboration activities
- Visibility and access control changes

## Security Considerations

- **Credential Security**: Store service account credentials securely and restrict access
- **API Quotas**: Be aware of Google API quotas and rate limits
- **Data Privacy**: Audit logs contain sensitive user activity data
- **Network Security**: IP geolocation requests are made to external services

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify service account has proper permissions
   - Ensure domain-wide delegation is configured
   - Check that required APIs are enabled

2. **No Data Retrieved**
   - Verify date range parameters
   - Check user permissions and status
   - Ensure audit logging is enabled in Google Workspace

3. **API Quota Exceeded**
   - Implement delays between requests
   - Reduce date range or user scope
   - Consider using multiple service accounts

### Error Messages

- `Access denied`: Service account lacks required permissions
- `Invalid date format`: Use MMDDYYYY format for dates
- `No users found`: Check domain and user specifications
- `Authentication failed`: Verify credentials file and permissions

## API Rate Limits

Google Admin SDK has the following limits:
- 1,500 requests per 100 seconds per user
- 100 requests per 100 seconds per user per scope

The tool implements basic rate limiting, but for large datasets, consider:
- Running during off-peak hours
- Using smaller date ranges
- Implementing exponential backoff

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review Google Admin SDK documentation
3. Verify API permissions and quotas
4. Check Google Workspace audit log settings

## Version History

- **v1.0.0** - Initial release with basic audit log retrieval and suspicious activity analysis