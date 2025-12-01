# DSPA (c) Shane D. Shook, 2025 All Rights Reserved

# Microsoft Graph API Setup Guide for DSPA

This guide provides step-by-step instructions for setting up Microsoft Graph API authentication for the DSPA script.

**Author:** Shane D. Shook, PhD

## Prerequisites

- Azure AD Global Administrator or Application Administrator role
- PowerShell 5.1 or PowerShell 7+
- Microsoft Graph PowerShell modules (installed automatically by DSPA script)

## Azure AD App Registration

### Step 1: Create App Registration

1. Sign in to the [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** > **App registrations**
3. Click **New registration**
4. Configure the application:
   - **Name**: `DSPA-SharePoint-Audit`
   - **Supported account types**: `Accounts in this organizational directory only`
   - **Redirect URI**: Leave blank for now
5. Click **Register**

### Step 2: Note Application Details

After registration, note these values:
- **Application (client) ID**: Found on the Overview page
- **Directory (tenant) ID**: Found on the Overview page

### Step 3: Configure API Permissions

1. Go to **API permissions** in your app registration
2. Click **Add a permission**
3. Select **Microsoft Graph**
4. Choose **Application permissions**
5. Add the following permissions:
   - `AuditLog.Read.All`
   - `Directory.Read.All`
   - `Reports.Read.All`
   - `SecurityEvents.Read.All`
6. Click **Add permissions**
7. Click **Grant admin consent for [Your Organization]**
8. Confirm by clicking **Yes**

## Authentication Methods

### Method 1: Client Secret Authentication

#### Create Client Secret
1. Go to **Certificates & secrets** in your app registration
2. Click **New client secret**
3. Add description: `DSPA Script Secret`
4. Choose expiration: `24 months` (recommended)
5. Click **Add**
6. **Important**: Copy the secret value immediately (it won't be shown again)

#### Usage Example
```powershell
.\DSPA.ps1 -Users "ALL" -DaysBack 7 -UseGraphAPI -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-client-secret"
```

### Method 2: Certificate Authentication

#### Create Self-Signed Certificate
```powershell
# Create certificate
$cert = New-SelfSignedCertificate -Subject "CN=DSPA-Certificate" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256

# Export certificate
Export-Certificate -Cert $cert -FilePath "C:\temp\DSPA-Certificate.cer"

# Get thumbprint
$cert.Thumbprint
```

#### Upload Certificate to Azure AD
1. Go to **Certificates & secrets** in your app registration
2. Click **Upload certificate**
3. Select the `.cer` file created above
4. Add description: `DSPA Script Certificate`
5. Click **Add**

#### Usage Example
```powershell
.\DSPA.ps1 -Users "ALL" -DaysBack 7 -UseGraphAPI -TenantId "your-tenant-id" -ClientId "your-client-id" -CertificateThumbprint "your-cert-thumbprint"
```

### Method 3: Interactive Authentication

For testing or one-time use, you can use interactive authentication:

```powershell
.\DSPA.ps1 -Users "ALL" -DaysBack 7 -UseGraphAPI
```

This will open a browser window for authentication.

## Security Best Practices

### Client Secret Security
- Store client secrets securely (Azure Key Vault, encrypted files)
- Rotate secrets regularly (before expiration)
- Use least-privilege principle
- Monitor secret usage

### Certificate Security
- Store certificates in secure certificate stores
- Use hardware security modules (HSMs) for production
- Implement certificate rotation procedures
- Monitor certificate expiration

### Application Security
- Regularly review app permissions
- Monitor app usage through Azure AD logs
- Implement conditional access policies
- Use managed identities when possible

## Troubleshooting

### Common Issues

**Permission Denied Errors**
```
Error: Insufficient privileges to complete the operation
```
- Verify admin consent has been granted
- Check that all required permissions are assigned
- Ensure the user/app has necessary roles

**Authentication Failures**
```
Error: AADSTS70011: The provided value for the input parameter 'scope' is not valid
```
- Verify tenant ID and client ID are correct
- Check that the app registration exists in the correct tenant

**Certificate Issues**
```
Error: Certificate with thumbprint 'xxx' not found
```
- Verify certificate is installed in the correct certificate store
- Check certificate hasn't expired
- Ensure certificate has private key

### Testing Connection

Test your Graph API connection:

```powershell
# Install Microsoft Graph module
Install-Module Microsoft.Graph.Authentication -Force

# Test connection with client secret
$SecureSecret = ConvertTo-SecureString "your-client-secret" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential("your-client-id", $SecureSecret)
Connect-MgGraph -TenantId "your-tenant-id" -ClientSecretCredential $Credential

# Test connection with certificate
Connect-MgGraph -ClientId "your-client-id" -TenantId "your-tenant-id" -CertificateThumbprint "your-cert-thumbprint"

# Verify connection
Get-MgContext

# Test API access
Get-MgAuditLogDirectoryAudit -Top 1
```

## Migration from Exchange Online

If you're currently using the Exchange Online method, here's how to migrate:

### 1. Set up Graph API authentication (follow steps above)

### 2. Test with limited scope first
```powershell
# Test with single user and short time range
.\DSPA.ps1 -Users "test.user@domain.com" -DaysBack 1 -UseGraphAPI -TenantId "tenant-id" -ClientId "client-id" -ClientSecret "secret"
```

### 3. Compare results
Run the same query with both methods and compare outputs:
```powershell
# Exchange Online method
.\DSPA.ps1 -Users "test.user@domain.com" -DaysBack 1 -OutputPath "C:\temp\exchange"

# Graph API method  
.\DSPA.ps1 -Users "test.user@domain.com" -DaysBack 1 -UseGraphAPI -TenantId "tenant-id" -ClientId "client-id" -ClientSecret "secret" -OutputPath "C:\temp\graph"
```

### 4. Gradually increase scope
Once satisfied with results, gradually increase the scope of your Graph API usage.

## Support

For issues specific to Graph API setup:
1. Check Azure AD audit logs for authentication failures
2. Review app registration configuration
3. Verify API permissions and admin consent
4. Test with Microsoft Graph Explorer: https://developer.microsoft.com/graph/graph-explorer

For DSPA script issues:
1. Enable verbose logging: `$VerbosePreference = "Continue"`
2. Check PowerShell execution policy
3. Verify all required modules are installed
4. Review script output for specific error messages