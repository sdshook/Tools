# Data Security Posture Activity (DSPA) Tools Suite

This suite provides comprehensive Data Security Posture Activity reporting tools for major cloud storage platforms. Each tool retrieves audit logs, analyzes user activities, and generates security reports including suspicious activity detection.

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

## License

These tools are provided as-is for security analysis purposes. Ensure compliance with your organization's policies and applicable regulations when using these tools.