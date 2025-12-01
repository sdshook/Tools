# Box Data Security Posture Activity (DSPA) Tool

This Python tool retrieves Box audit log activities and generates comprehensive security posture reports, including analysis of suspicious activities.

## Features

- **Comprehensive Audit Log Retrieval**: Pulls Box activity logs using the Box Events API
- **User Filtering**: Analyze all users or specific users by ID or email address
- **Flexible Date Ranges**: Support for custom date ranges or days-back from current date
- **IP Geolocation Enrichment**: Automatically enriches IP addresses with country, city, organization, and ASN data
- **Suspicious Activity Detection**: Identifies unusual locations, unusual access times, and high-risk activities
- **Dual Report Generation**: Produces both raw activity logs (CSV) and suspicious activity analysis (JSON)

## Prerequisites

### Box Enterprise Account
- Box Enterprise or Business account
- Admin privileges to create applications
- Access to Box Admin Console

### API Setup
1. **Create a Box Application**
   - Go to [Box Developer Console](https://developer.box.com/)
   - Create new application
   - Choose "Custom App" with "OAuth 2.0 with JWT" or "OAuth 2.0"

2. **Configure Application Permissions**
   - Enable "Manage enterprise properties"
   - Enable "Manage users"
   - Enable "Generate user access tokens"

3. **Get OAuth2 Credentials**
   - Note Client ID and Client Secret
   - Configure redirect URI (for OAuth2 flow)
   - Generate access token and refresh token

4. **Enterprise Authorization** (if using JWT)
   - Submit application for enterprise authorization
   - Admin must approve the application in Box Admin Console

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Tools/CRA/DSPA/Box
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up credentials**
   - Obtain OAuth2 access token and refresh token
   - Note Client ID and Client Secret

## Usage

### Basic Usage

```bash
# Analyze all users for last 30 days (default)
python box_dspa.py --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET --access-token YOUR_ACCESS_TOKEN --refresh-token YOUR_REFRESH_TOKEN

# Analyze specific users by ID
python box_dspa.py --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET --access-token YOUR_ACCESS_TOKEN --refresh-token YOUR_REFRESH_TOKEN --users "12345,67890"

# Analyze last 7 days
python box_dspa.py --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET --access-token YOUR_ACCESS_TOKEN --refresh-token YOUR_REFRESH_TOKEN --days-back 7

# Analyze specific date range
python box_dspa.py --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET --access-token YOUR_ACCESS_TOKEN --refresh-token YOUR_REFRESH_TOKEN --start-date 11012024 --end-date 11302024
```

### Command Line Parameters

| Parameter | Required | Description | Example |
|-----------|----------|-------------|---------|
| `--client-id` | Yes | Box application client ID | `abc123def456` |
| `--client-secret` | Yes | Box application client secret | `xyz789uvw012` |
| `--access-token` | Yes | OAuth2 access token | `your_access_token` |
| `--refresh-token` | No | OAuth2 refresh token | `your_refresh_token` |
| `--users` | No | Comma-separated user IDs or "ALL" | `12345,67890` |
| `--start-date` | No | Start date in MMDDYYYY format | `11012024` |
| `--end-date` | No | End date in MMDDYYYY format | `11302024` |
| `--days-back` | No | Number of days back from today | `7` |
| `--output-dir` | No | Output directory for reports | `./reports` |

## Output Files

### Raw Activity Report (CSV)
File: `box_dspa_raw_YYYYMMDD_HHMMSS.csv`

Contains all audit log entries with the following fields:
- `datetime` - Event timestamp
- `event_id` - Unique event identifier
- `event_type` - Type of event
- `user_id` - Box user ID
- `user_name` - User display name
- `user_email` - User email address
- `ip_address` - Source IP address
- `country` - IP geolocation country
- `city` - IP geolocation city
- `organization` - IP organization/ISP
- `asn` - Autonomous System Number
- `session_id` - Session identifier
- `file_id` - Box file/folder ID
- `file_name` - File/folder name
- `file_type` - Object type (file/folder)
- `user_agent` - User agent information
- `device_name` - Device name (if available)

### Suspicious Activity Report (JSON)
File: `box_dspa_suspicious_YYYYMMDD_HHMMSS.json`

Contains analysis of suspicious activities:
- `unusual_locations` - Activities from uncommon geographic locations
- `unusual_times` - Activities during unusual hours (outside 6 AM - 10 PM UTC)
- `high_risk_activities` - High-risk events (delete, download, share, collaboration changes)
- `summary` - Analysis summary statistics

## Available Event Types

The tool captures various Box events including:
- `DELETE` - File/folder deletion
- `DOWNLOAD` - File downloads
- `SHARE` / `UNSHARE` - Sharing activities
- `COLLABORATION_INVITE` - Collaboration invitations
- `COLLABORATION_ROLE_CHANGE` - Permission changes
- `ITEM_SHARED_UPDATE` - Shared item updates
- `COPY` / `MOVE` / `RENAME` - File operations
- `ITEM_SYNC` / `ITEM_UNSYNC` - Sync activities

## Security Considerations

- **Credential Security**: Store OAuth2 tokens securely and implement token refresh
- **API Rate Limits**: Be aware of Box API rate limits
- **Data Privacy**: Audit logs contain sensitive user activity data
- **Token Management**: Implement proper token refresh and expiration handling

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify OAuth2 tokens are valid and not expired
   - Check application permissions in Box Admin Console
   - Ensure application is authorized for enterprise

2. **No Data Retrieved**
   - Verify date range parameters
   - Check user IDs and permissions
   - Ensure events API access is enabled

3. **API Rate Limit Exceeded**
   - Implement delays between requests
   - Reduce date range or user scope
   - Use exponential backoff for retries

### Error Messages

- `Access denied`: Application lacks required permissions
- `Invalid date format`: Use MMDDYYYY format for dates
- `User not found`: Check user IDs or email addresses
- `Authentication failed`: Verify OAuth2 credentials

## API Rate Limits

Box API has the following limits:
- 1,000 API calls per minute per application
- Additional limits may apply based on account type

The tool implements basic rate limiting, but for large datasets, consider:
- Running during off-peak hours
- Using smaller date ranges
- Implementing request queuing

## OAuth2 Token Management

### Getting Initial Tokens
1. Use Box OAuth2 flow to get initial access token
2. Store refresh token securely for token renewal
3. Implement automatic token refresh in production

### Token Refresh
```python
# Example token refresh (implement in production)
oauth = OAuth2(client_id, client_secret, access_token, refresh_token)
oauth.refresh(access_token)
```

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review Box API documentation
3. Verify application permissions and authorization
4. Check Box Admin Console settings

## Version History

- **v1.0.0** - Initial release with basic audit log retrieval and suspicious activity analysis