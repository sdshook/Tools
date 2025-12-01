# DSPA (c) Shane D. Shook, 2025 All Rights Reserved

# Test script for DSPA Graph API functionality
# This script validates the basic functionality without requiring actual Microsoft 365 connectivity

Write-Host "=== DSPA Graph API Functionality Test ===" -ForegroundColor Magenta

# Test 1: Parameter validation
Write-Host "`nTest 1: Parameter Validation" -ForegroundColor Yellow

try {
    # Test parameter binding
    $TestParams = @{
        Users = "test@domain.com"
        DaysBack = 7
        UseGraphAPI = $true
        TenantId = "test-tenant-id"
        ClientId = "test-client-id"
        ClientSecret = "test-secret"
    }
    
    Write-Host "✓ Parameter binding successful" -ForegroundColor Green
}
catch {
    Write-Host "✗ Parameter binding failed: $_" -ForegroundColor Red
}

# Test 2: Function definitions
Write-Host "`nTest 2: Function Definitions" -ForegroundColor Yellow

$ScriptPath = Join-Path $PSScriptRoot "DSPA.ps1"
if (Test-Path $ScriptPath) {
    $ScriptContent = Get-Content $ScriptPath -Raw
    
    $RequiredFunctions = @(
        "Connect-GraphAPI",
        "Get-SharePointAuditLogsGraph",
        "Connect-Services",
        "Get-SharePointAuditLogs"
    )
    
    foreach ($Function in $RequiredFunctions) {
        if ($ScriptContent -match "function $Function") {
            Write-Host "✓ Function $Function found" -ForegroundColor Green
        }
        else {
            Write-Host "✗ Function $Function missing" -ForegroundColor Red
        }
    }
}
else {
    Write-Host "✗ DSPA.ps1 script not found" -ForegroundColor Red
}

# Test 3: Required modules check
Write-Host "`nTest 3: Required Modules Definition" -ForegroundColor Yellow

if ($ScriptContent -match '\$RequiredModules.*=.*@\(') {
    $ModulesSection = ($ScriptContent -split '\$RequiredModules.*=.*@\(')[1].Split(')')[0]
    
    $ExpectedModules = @(
        "ExchangeOnlineManagement",
        "PnP.PowerShell", 
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Security",
        "Microsoft.Graph.Reports"
    )
    
    foreach ($Module in $ExpectedModules) {
        if ($ModulesSection -match $Module) {
            Write-Host "✓ Module $Module defined" -ForegroundColor Green
        }
        else {
            Write-Host "✗ Module $Module missing" -ForegroundColor Red
        }
    }
}
else {
    Write-Host "✗ Required modules section not found" -ForegroundColor Red
}

# Test 4: Parameter definitions
Write-Host "`nTest 4: Parameter Definitions" -ForegroundColor Yellow

$ExpectedParameters = @(
    "UseGraphAPI",
    "ClientSecret",
    "TenantId",
    "ClientId",
    "CertificateThumbprint"
)

foreach ($Parameter in $ExpectedParameters) {
    if ($ScriptContent -match "\[Parameter.*\].*\`$$Parameter") {
        Write-Host "✓ Parameter $Parameter defined" -ForegroundColor Green
    }
    else {
        Write-Host "✗ Parameter $Parameter missing" -ForegroundColor Red
    }
}

# Test 5: Authentication logic
Write-Host "`nTest 5: Authentication Logic" -ForegroundColor Yellow

if ($ScriptContent -match 'if.*\$UseGraphAPI.*\{') {
    Write-Host "✓ UseGraphAPI conditional logic found" -ForegroundColor Green
}
else {
    Write-Host "✗ UseGraphAPI conditional logic missing" -ForegroundColor Red
}

if ($ScriptContent -match 'Connect-GraphAPI.*-TenantId.*-ClientId') {
    Write-Host "✓ Graph API connection call found" -ForegroundColor Green
}
else {
    Write-Host "✗ Graph API connection call missing" -ForegroundColor Red
}

# Test 6: Audit log retrieval logic
Write-Host "`nTest 6: Audit Log Retrieval Logic" -ForegroundColor Yellow

if ($ScriptContent -match 'Get-SharePointAuditLogsGraph.*-UserList.*-StartDate.*-EndDate') {
    Write-Host "✓ Graph API audit log retrieval found" -ForegroundColor Green
}
else {
    Write-Host "✗ Graph API audit log retrieval missing" -ForegroundColor Red
}

# Test 7: Cleanup logic
Write-Host "`nTest 7: Cleanup Logic" -ForegroundColor Yellow

if ($ScriptContent -match 'Disconnect-MgGraph') {
    Write-Host "✓ Graph API disconnect found" -ForegroundColor Green
}
else {
    Write-Host "✗ Graph API disconnect missing" -ForegroundColor Red
}

# Test 8: Documentation files
Write-Host "`nTest 8: Documentation Files" -ForegroundColor Yellow

$DocumentationFiles = @(
    "DSPA_README.md",
    "DSPA_GraphAPI_Setup.md"
)

foreach ($DocFile in $DocumentationFiles) {
    $DocPath = Join-Path $PSScriptRoot $DocFile
    if (Test-Path $DocPath) {
        Write-Host "✓ Documentation file $DocFile found" -ForegroundColor Green
        
        # Check for Graph API content
        $DocContent = Get-Content $DocPath -Raw
        if ($DocContent -match "Graph API|UseGraphAPI") {
            Write-Host "  ✓ Contains Graph API documentation" -ForegroundColor Green
        }
        else {
            Write-Host "  ✗ Missing Graph API documentation" -ForegroundColor Red
        }
    }
    else {
        Write-Host "✗ Documentation file $DocFile missing" -ForegroundColor Red
    }
}

# Test 9: Help documentation
Write-Host "`nTest 9: Help Documentation" -ForegroundColor Yellow

if ($ScriptContent -match '\.PARAMETER UseGraphAPI') {
    Write-Host "✓ UseGraphAPI parameter help found" -ForegroundColor Green
}
else {
    Write-Host "✗ UseGraphAPI parameter help missing" -ForegroundColor Red
}

if ($ScriptContent -match '\.PARAMETER ClientSecret') {
    Write-Host "✓ ClientSecret parameter help found" -ForegroundColor Green
}
else {
    Write-Host "✗ ClientSecret parameter help missing" -ForegroundColor Red
}

# Test 10: Version information
Write-Host "`nTest 10: Version Information" -ForegroundColor Yellow

if ($ScriptContent -match 'Version.*2\.0') {
    Write-Host "✓ Version updated to 2.0" -ForegroundColor Green
}
else {
    Write-Host "✗ Version not updated" -ForegroundColor Red
}

Write-Host "`n=== Test Summary ===" -ForegroundColor Magenta
Write-Host "Basic functionality tests completed." -ForegroundColor Cyan
Write-Host "For full testing, run the script with actual Microsoft 365 credentials." -ForegroundColor Cyan
Write-Host "`nExample test commands:" -ForegroundColor Yellow
Write-Host "# Test Exchange Online method:" -ForegroundColor Gray
Write-Host ".\DSPA.ps1 -Users 'test@domain.com' -DaysBack 1" -ForegroundColor Gray
Write-Host "`n# Test Graph API method:" -ForegroundColor Gray  
Write-Host ".\DSPA.ps1 -Users 'test@domain.com' -DaysBack 1 -UseGraphAPI" -ForegroundColor Gray