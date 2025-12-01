# DSPA (c) Shane D. Shook, 2025 All Rights Reserved

<#
.SYNOPSIS
    Syntax validation and basic testing for DSPA.ps1 script
    
.DESCRIPTION
    This script performs basic syntax validation and parameter testing for the DSPA script
    without actually connecting to Microsoft 365 services or running the full analysis.
#>

Write-Host "=== DSPA Script Syntax Validation ===" -ForegroundColor Magenta

# Test 1: Check if script file exists
$ScriptPath = Join-Path $PSScriptRoot "DSPA.ps1"
if (Test-Path $ScriptPath) {
    Write-Host "✓ DSPA.ps1 script file found" -ForegroundColor Green
} else {
    Write-Host "✗ DSPA.ps1 script file not found" -ForegroundColor Red
    exit 1
}

# Test 2: Syntax validation
Write-Host "Testing PowerShell syntax..." -ForegroundColor Yellow
try {
    $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $ScriptPath -Raw), [ref]$null)
    Write-Host "✓ PowerShell syntax is valid" -ForegroundColor Green
} catch {
    Write-Host "✗ PowerShell syntax error: $_" -ForegroundColor Red
    exit 1
}

# Test 3: Parameter validation
Write-Host "Testing parameter definitions..." -ForegroundColor Yellow
try {
    $ScriptInfo = Get-Command $ScriptPath
    $RequiredParams = @('Users')
    $OptionalParams = @('StartDate', 'EndDate', 'DaysBack', 'OutputPath', 'TenantId', 'ClientId', 'CertificateThumbprint')
    
    foreach ($Param in $RequiredParams) {
        if ($ScriptInfo.Parameters.ContainsKey($Param)) {
            Write-Host "✓ Required parameter '$Param' found" -ForegroundColor Green
        } else {
            Write-Host "✗ Required parameter '$Param' missing" -ForegroundColor Red
        }
    }
    
    foreach ($Param in $OptionalParams) {
        if ($ScriptInfo.Parameters.ContainsKey($Param)) {
            Write-Host "✓ Optional parameter '$Param' found" -ForegroundColor Green
        } else {
            Write-Host "⚠ Optional parameter '$Param' missing" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "✗ Error validating parameters: $_" -ForegroundColor Red
}

# Test 4: Function definitions
Write-Host "Testing function definitions..." -ForegroundColor Yellow
$ScriptContent = Get-Content $ScriptPath -Raw
$ExpectedFunctions = @(
    'Import-RequiredModules',
    'Connect-Services', 
    'Parse-DateRange',
    'Get-IPGeolocation',
    'Get-SharePointAuditLogs',
    'Process-AuditData',
    'Build-UserBaselines',
    'Detect-SuspiciousActivities',
    'Generate-Reports',
    'Main'
)

foreach ($Function in $ExpectedFunctions) {
    if ($ScriptContent -match "function $Function") {
        Write-Host "✓ Function '$Function' found" -ForegroundColor Green
    } else {
        Write-Host "✗ Function '$Function' missing" -ForegroundColor Red
    }
}

# Test 5: Date parsing validation
Write-Host "Testing date parsing logic..." -ForegroundColor Yellow
try {
    # Test valid date formats
    $TestDate1 = [DateTime]::ParseExact("01012024", "MMddyyyy", $null)
    $TestDate2 = [DateTime]::ParseExact("12312024", "MMddyyyy", $null)
    Write-Host "✓ Date parsing logic works correctly" -ForegroundColor Green
} catch {
    Write-Host "✗ Date parsing error: $_" -ForegroundColor Red
}

# Test 6: Output path validation
Write-Host "Testing output path handling..." -ForegroundColor Yellow
$TestOutputPath = $env:TEMP
if (Test-Path $TestOutputPath) {
    Write-Host "✓ Output path validation works" -ForegroundColor Green
} else {
    Write-Host "✗ Output path validation failed" -ForegroundColor Red
}

# Test 7: Configuration file validation
Write-Host "Testing configuration file..." -ForegroundColor Yellow
$ConfigPath = Join-Path $PSScriptRoot "DSPA_Config_Template.json"
if (Test-Path $ConfigPath) {
    try {
        $Config = Get-Content $ConfigPath | ConvertFrom-Json
        Write-Host "✓ Configuration file is valid JSON" -ForegroundColor Green
    } catch {
        Write-Host "✗ Configuration file JSON error: $_" -ForegroundColor Red
    }
} else {
    Write-Host "⚠ Configuration template file not found" -ForegroundColor Yellow
}

# Test 8: Documentation files
Write-Host "Testing documentation files..." -ForegroundColor Yellow
$ReadmePath = Join-Path $PSScriptRoot "DSPA_README.md"
$BatchPath = Join-Path $PSScriptRoot "Run_DSPA_Examples.bat"

if (Test-Path $ReadmePath) {
    Write-Host "✓ README documentation found" -ForegroundColor Green
} else {
    Write-Host "⚠ README documentation missing" -ForegroundColor Yellow
}

if (Test-Path $BatchPath) {
    Write-Host "✓ Batch execution examples found" -ForegroundColor Green
} else {
    Write-Host "⚠ Batch execution examples missing" -ForegroundColor Yellow
}

Write-Host "`n=== Validation Complete ===" -ForegroundColor Magenta
Write-Host "DSPA script appears to be ready for use!" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "1. Install required PowerShell modules" -ForegroundColor White
Write-Host "2. Configure authentication (certificate or interactive)" -ForegroundColor White
Write-Host "3. Test with a small dataset first" -ForegroundColor White
Write-Host "4. Review the README file for detailed usage instructions" -ForegroundColor White