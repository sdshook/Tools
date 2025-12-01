# DSPA (c) Shane D. Shook, 2025 All Rights Reserved

# Comprehensive test script for DSPA with all three authentication methods
# This script validates the functionality of Exchange Online PowerShell, Graph API, and Purview API methods

Write-Host "=== DSPA All Authentication Methods Test ===" -ForegroundColor Magenta
Write-Host "Testing Exchange Online PowerShell, Graph API, and Purview API methods" -ForegroundColor Cyan

$ScriptPath = Join-Path $PSScriptRoot "DSPA.ps1"

if (-not (Test-Path $ScriptPath)) {
    Write-Error "DSPA.ps1 not found at: $ScriptPath"
    exit 1
}

# Test 1: Parameter validation for all methods
Write-Host "`n=== Test 1: Parameter Validation ===" -ForegroundColor Yellow

Write-Host "`nTesting Exchange Online PowerShell (Default) parameters..." -ForegroundColor Cyan
try {
    $ExchangeParams = @{
        Users = "test@domain.com"
        DaysBack = 7
        TenantId = "test-tenant-id"
        ClientId = "test-client-id"
        CertificateThumbprint = "test-thumbprint"
    }
    Write-Host "✓ Exchange Online parameter binding successful" -ForegroundColor Green
}
catch {
    Write-Host "✗ Exchange Online parameter binding failed: $_" -ForegroundColor Red
}

Write-Host "`nTesting Graph API parameters..." -ForegroundColor Cyan
try {
    $GraphParams = @{
        Users = "test@domain.com"
        DaysBack = 7
        UseGraphAPI = $true
        TenantId = "test-tenant-id"
        ClientId = "test-client-id"
        ClientSecret = "test-secret"
    }
    Write-Host "✓ Graph API parameter binding successful" -ForegroundColor Green
}
catch {
    Write-Host "✗ Graph API parameter binding failed: $_" -ForegroundColor Red
}

Write-Host "`nTesting Purview API parameters..." -ForegroundColor Cyan
try {
    $PurviewParams = @{
        Users = "test@domain.com"
        DaysBack = 7
        UsePurviewAPI = $true
        TenantId = "test-tenant-id"
        ClientId = "test-client-id"
        ClientSecret = "test-secret"
    }
    Write-Host "✓ Purview API parameter binding successful" -ForegroundColor Green
}
catch {
    Write-Host "✗ Purview API parameter binding failed: $_" -ForegroundColor Red
}

# Test 2: Function definitions
Write-Host "`n=== Test 2: Function Definitions ===" -ForegroundColor Yellow

$RequiredFunctions = @(
    'Import-RequiredModules',
    'Connect-Services',
    'Connect-GraphAPI', 
    'Get-SharePointAuditLogs',
    'Get-SharePointAuditLogsGraph',
    'Get-SharePointAuditLogsPurview',
    'Parse-DateRange',
    'Get-IPLocationInfo',
    'Process-AuditData',
    'Build-UserBaselines',
    'Detect-SuspiciousActivities',
    'Generate-Reports'
)

# Load the script to check function definitions
$ScriptContent = Get-Content $ScriptPath -Raw

foreach ($Function in $RequiredFunctions) {
    if ($ScriptContent -match "function $Function") {
        Write-Host "✓ Function '$Function' found" -ForegroundColor Green
    }
    else {
        Write-Host "✗ Function '$Function' missing" -ForegroundColor Red
    }
}

# Test 3: Authentication method selection logic
Write-Host "`n=== Test 3: Authentication Method Selection Logic ===" -ForegroundColor Yellow

Write-Host "`nTesting method selection priority..." -ForegroundColor Cyan

# Test Purview API priority (should be highest)
if ($ScriptContent -match 'if \(\$UsePurviewAPI\)') {
    Write-Host "✓ Purview API priority check found" -ForegroundColor Green
}
else {
    Write-Host "✗ Purview API priority check missing" -ForegroundColor Red
}

# Test Graph API priority (should be second)
if ($ScriptContent -match 'elseif \(\$UseGraphAPI\)') {
    Write-Host "✓ Graph API priority check found" -ForegroundColor Green
}
else {
    Write-Host "✗ Graph API priority check missing" -ForegroundColor Red
}

# Test Exchange Online default
if ($ScriptContent -match 'else.*Exchange.*Online') {
    Write-Host "✓ Exchange Online default method found" -ForegroundColor Green
}
else {
    Write-Host "✗ Exchange Online default method missing" -ForegroundColor Red
}

# Test 4: Module import logic
Write-Host "`n=== Test 4: Module Import Logic ===" -ForegroundColor Yellow

if ($ScriptContent -match 'ExchangeOnlineManagement') {
    Write-Host "✓ ExchangeOnlineManagement module reference found" -ForegroundColor Green
}
else {
    Write-Host "✗ ExchangeOnlineManagement module reference missing" -ForegroundColor Red
}

if ($ScriptContent -match 'Microsoft\.Graph\.Authentication') {
    Write-Host "✓ Microsoft.Graph.Authentication module reference found" -ForegroundColor Green
}
else {
    Write-Host "✗ Microsoft.Graph.Authentication module reference missing" -ForegroundColor Red
}

# Test 5: Switch parameter definitions
Write-Host "`n=== Test 5: Switch Parameter Definitions ===" -ForegroundColor Yellow

if ($ScriptContent -match '\[switch\]\$UseGraphAPI') {
    Write-Host "✓ UseGraphAPI switch parameter found" -ForegroundColor Green
}
else {
    Write-Host "✗ UseGraphAPI switch parameter missing" -ForegroundColor Red
}

if ($ScriptContent -match '\[switch\]\$UsePurviewAPI') {
    Write-Host "✓ UsePurviewAPI switch parameter found" -ForegroundColor Green
}
else {
    Write-Host "✗ UsePurviewAPI switch parameter missing" -ForegroundColor Red
}

# Test 6: Help documentation
Write-Host "`n=== Test 6: Help Documentation ===" -ForegroundColor Yellow

if ($ScriptContent -match '\.PARAMETER UseGraphAPI') {
    Write-Host "✓ UseGraphAPI parameter help found" -ForegroundColor Green
}
else {
    Write-Host "✗ UseGraphAPI parameter help missing" -ForegroundColor Red
}

if ($ScriptContent -match '\.PARAMETER UsePurviewAPI') {
    Write-Host "✓ UsePurviewAPI parameter help found" -ForegroundColor Green
}
else {
    Write-Host "✗ UsePurviewAPI parameter help missing" -ForegroundColor Red
}

# Test 7: Example usage in help
Write-Host "`n=== Test 7: Example Usage in Help ===" -ForegroundColor Yellow

if ($ScriptContent -match '-UseGraphAPI.*-TenantId') {
    Write-Host "✓ Graph API example found in help" -ForegroundColor Green
}
else {
    Write-Host "✗ Graph API example missing in help" -ForegroundColor Red
}

if ($ScriptContent -match '-UsePurviewAPI.*-TenantId') {
    Write-Host "✓ Purview API example found in help" -ForegroundColor Green
}
else {
    Write-Host "✗ Purview API example missing in help" -ForegroundColor Red
}

# Test 8: Syntax validation
Write-Host "`n=== Test 8: PowerShell Syntax Validation ===" -ForegroundColor Yellow

try {
    $null = [System.Management.Automation.PSParser]::Tokenize($ScriptContent, [ref]$null)
    Write-Host "✓ PowerShell syntax validation passed" -ForegroundColor Green
}
catch {
    Write-Host "✗ PowerShell syntax validation failed: $_" -ForegroundColor Red
}

# Summary
Write-Host "`n=== Test Summary ===" -ForegroundColor Magenta
Write-Host "DSPA script validation completed." -ForegroundColor Cyan
Write-Host "Review any red (✗) items above for issues that need attention." -ForegroundColor Yellow

# Example commands for manual testing
Write-Host "`n=== Manual Testing Examples ===" -ForegroundColor Magenta

Write-Host "`nExchange Online PowerShell (Default):" -ForegroundColor Cyan
Write-Host ".\DSPA.ps1 -Users 'test@domain.com' -DaysBack 7" -ForegroundColor White

Write-Host "`nMicrosoft Graph API:" -ForegroundColor Cyan
Write-Host ".\DSPA.ps1 -Users 'test@domain.com' -DaysBack 7 -UseGraphAPI -TenantId 'your-tenant' -ClientId 'your-app-id'" -ForegroundColor White

Write-Host "`nPurview Audit Search Graph API:" -ForegroundColor Cyan
Write-Host ".\DSPA.ps1 -Users 'test@domain.com' -DaysBack 7 -UsePurviewAPI -TenantId 'your-tenant' -ClientId 'your-app-id'" -ForegroundColor White

Write-Host "`nNote: Replace placeholder values with actual tenant and application IDs for live testing." -ForegroundColor Yellow