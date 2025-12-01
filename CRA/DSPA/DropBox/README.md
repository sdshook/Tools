# Dropbox Data Security Posture Activity (DSPA) Tool

This Python tool retrieves Dropbox audit log activities and generates comprehensive security posture reports, including analysis of suspicious activities.

## Features

- **Comprehensive Audit Log Retrieval**: Pulls Dropbox activity logs using the Dropbox Team Log API
- **User Filtering**: Analyze all team members or specific users by ID or email address
- **Flexible Date Ranges**: Support for custom date ranges or days-back from current date
- **IP Geolocation Enrichment**: Automatically enriches IP addresses with country, city, organization, and ASN data
- **Suspicious Activity Detection**: Identifies unusual locations, unusual access times, and high-risk activities
- **Dual Report Generation**: Produces both raw activity logs (CSV) and suspicious activity analysis (JSON)

## Prerequisites

### Dropbox Business Account
- Dropbox Business or Enterprise account
- Team admin privileges
- Access to Dropbox Admin Console

### API Setup
1. **Create a Dropbox App**
   - Go to [Dropbox App Console](https://www.dropbox.com/developers/apps)
   - Create new app
   - Choose "Scoped access" and "Team" access type
   - Select required permissions

2. **Configure App Permissions**
   Required scopes:
   - `team_info.read` - Read team information
   - `members.read` - Read team member information
   - `events.read` - Read team events/audit logs

3. **Generate Access Token**
   - Generate access token in app settings
   - For production, implement OAuth2 flow
   - Store token securely

4. **Team Authorization**
   - Admin must install/authorize the app for the team
   - Verify app has necessary permissions

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Tools/CRA/DSPA/DropBox
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up credentials**
   - Obtain Dropbox API access token
   - Ensure token has team-level permissions

## Usage

### Basic Usage

```bash
# Analyze all team members for last 30 days (default)
python dropbox_dspa.py --access-token YOUR_ACCESS_TOKEN

# Analyze specific users by email
python dropbox_dspa.py --access-token YOUR_ACCESS_TOKEN --users "user1@example.com,user2@example.com"

# Analyze last 7 days
python dropbox_dspa.py --access-token YOUR_ACCESS_TOKEN --days-back 7

# Analyze specific date range
python dropbox_dspa.py --access-token YOUR_ACCESS_TOKEN --start-date 11012024 --end-date 11302024
```

### Command Line Parameters

| Parameter | Required | Description | Example |
|-----------|----------|-------------|---------|
| `--access-token` | Yes | Dropbox API access token | `your_access_token` |
| `--users` | No | Comma-separated user emails/IDs or "ALL" | `user1@example.com,user2@example.com` |
| `--start-date` | No | Start date in MMDDYYYY format | `11012024` |
| `--end-date` | No | End date in MMDDYYYY format | `11302024` |
| `--days-back` | No | Number of days back from today | `7` |
| `--output-dir` | No | Output directory for reports | `./reports` |

## Output Files

### Raw Activity Report (CSV)
File: `dropbox_dspa_raw_YYYYMMDD_HHMMSS.csv`

Contains all audit log entries with the following fields:
- `datetime` - Event timestamp
- `event_type` - Type of event
- `user_id` - Dropbox team member ID
- `user_name` - User display name
- `user_email` - User email address
- `ip_address` - Source IP address
- `country` - IP geolocation country
- `city` - IP geolocation city
- `organization` - IP organization/ISP
- `asn` - Autonomous System Number
- `file_name` - File name (if applicable)
- `file_path` - Full file path
- `file_id` - Dropbox file ID
- `device_name` - Device name
- `app_name` - Application name
- `user_agent` - User agent information

### Suspicious Activity Report (JSON)
File: `dropbox_dspa_suspicious_YYYYMMDD_HHMMSS.json`

Contains analysis of suspicious activities:
- `unusual_locations` - Activities from uncommon geographic locations
- `unusual_times` - Activities during unusual hours (outside 6 AM - 10 PM UTC)
- `high_risk_activities` - High-risk events (delete, download, share, folder operations)
- `summary` - Analysis summary statistics

## Available Event Types

The tool captures various Dropbox events including:
- `file_delete` - File deletion
- `file_download` - File downloads
- `file_share` / `file_unshare` - File sharing activities
- `shared_folder_create` - Shared folder creation
- `shared_folder_invite` - Shared folder invitations
- `shared_folder_leave` - Leaving shared folders
- `file_copy` / `file_move` / `file_rename` - File operations
- `paper_doc_delete` / `paper_doc_download` / `paper_doc_share` - Paper document activities

## Security Considerations

- **Token Security**: Store access tokens securely and implement token rotation
- **API Rate Limits**: Be aware of Dropbox API rate limits
- **Data Privacy**: Audit logs contain sensitive user activity data
- **Team Permissions**: Ensure proper team admin permissions for audit access

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify access token is valid and not expired
   - Check app permissions in Dropbox App Console
   - Ensure app is installed for the team

2. **No Data Retrieved**
   - Verify date range parameters
   - Check user identifiers and team membership
   - Ensure audit logging is enabled

3. **API Rate Limit Exceeded**
   - Implement delays between requests
   - Reduce date range or user scope
   - Use exponential backoff for retries

### Error Messages

- `Access denied`: App lacks required permissions or not authorized for team
- `Invalid date format`: Use MMDDYYYY format for dates
- `User not found`: Check user email addresses or team member IDs
- `Authentication failed`: Verify access token and permissions

## API Rate Limits

Dropbox API has the following limits:
- Standard rate limits apply per app and per user
- Team endpoints may have additional restrictions
- Specific limits depend on account type and API endpoint

The tool implements basic rate limiting, but for large datasets, consider:
- Running during off-peak hours
- Using smaller date ranges
- Implementing request queuing and retry logic

## Team Log API Considerations

### Event Retention
- Dropbox retains team events for different periods based on account type
- Business accounts: 180 days
- Enterprise accounts: Longer retention periods

### Event Categories
The Team Log API provides events in categories:
- File and folder operations
- Sharing and collaboration
- Account and authentication
- Device and app activities
- Admin actions

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review Dropbox API documentation
3. Verify app permissions and team authorization
4. Check Dropbox Admin Console settings

## Version History

- **v1.0.0** - Initial release with basic audit log retrieval and suspicious activity analysis