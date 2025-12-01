@echo off
REM DSPA (c) Shane D. Shook, 2025 All Rights Reserved
REM Data Security Posture Activity (DSPA) Report Generator - Example Executions
REM This batch file provides common usage examples for the DSPA.ps1 script

echo ========================================
echo DSPA Report Generator - Example Runs
echo ========================================
echo.

:MENU
echo Please select an option:
echo.
echo === Exchange Online PowerShell (Default) ===
echo 1. Analyze specific user for last 30 days
echo 2. Analyze all users for last 7 days  
echo 3. Analyze multiple users for custom date range
echo 4. Quick security check (all users, last 3 days)
echo 5. Full monthly report (all users, last 30 days)
echo.
echo === Microsoft Graph API ===
echo 6. Graph API - Analyze all users for last 7 days
echo 7. Graph API - Quick security check (last 3 days)
echo.
echo === Purview Audit Search Graph API ===
echo 8. Purview API - Analyze all users for last 7 days
echo 9. Purview API - Quick security check (last 3 days)
echo.
echo 0. Exit
echo.
set /p choice="Enter your choice (0-9): "

if "%choice%"=="1" goto SINGLE_USER
if "%choice%"=="2" goto ALL_USERS_WEEK
if "%choice%"=="3" goto MULTI_USER_CUSTOM
if "%choice%"=="4" goto QUICK_CHECK
if "%choice%"=="5" goto MONTHLY_REPORT
if "%choice%"=="6" goto GRAPH_ALL_USERS
if "%choice%"=="7" goto GRAPH_QUICK_CHECK
if "%choice%"=="8" goto PURVIEW_ALL_USERS
if "%choice%"=="9" goto PURVIEW_QUICK_CHECK
if "%choice%"=="0" goto EXIT
goto MENU

:SINGLE_USER
echo.
set /p username="Enter user email (e.g., john.doe@company.com): "
echo Running analysis for %username% - last 30 days...
powershell.exe -ExecutionPolicy Bypass -File "DSPA.ps1" -Users "%username%" -DaysBack 30
pause
goto MENU

:ALL_USERS_WEEK
echo.
echo Running analysis for ALL users - last 7 days...
powershell.exe -ExecutionPolicy Bypass -File "DSPA.ps1" -Users "ALL" -DaysBack 7
pause
goto MENU

:MULTI_USER_CUSTOM
echo.
set /p users="Enter user emails (comma-separated): "
set /p startdate="Enter start date (MMDDYYYY): "
set /p enddate="Enter end date (MMDDYYYY): "
echo Running analysis for specified users and date range...
powershell.exe -ExecutionPolicy Bypass -File "DSPA.ps1" -Users "%users%" -StartDate "%startdate%" -EndDate "%enddate%"
pause
goto MENU

:QUICK_CHECK
echo.
echo Running quick security check - ALL users, last 3 days...
powershell.exe -ExecutionPolicy Bypass -File "DSPA.ps1" -Users "ALL" -DaysBack 3
pause
goto MENU

:MONTHLY_REPORT
echo.
echo Running full monthly report - ALL users, last 30 days...
echo This may take several minutes to complete...
powershell.exe -ExecutionPolicy Bypass -File "DSPA.ps1" -Users "ALL" -DaysBack 30
pause
goto MENU

:GRAPH_ALL_USERS
echo.
echo Running Graph API analysis for ALL users - last 7 days...
echo Note: Requires Azure AD app registration and appropriate permissions
set /p tenantid="Enter Tenant ID (or press Enter to use interactive auth): "
if "%tenantid%"=="" (
    powershell.exe -ExecutionPolicy Bypass -File "DSPA.ps1" -Users "ALL" -DaysBack 7 -UseGraphAPI
) else (
    set /p clientid="Enter Client ID: "
    powershell.exe -ExecutionPolicy Bypass -File "DSPA.ps1" -Users "ALL" -DaysBack 7 -UseGraphAPI -TenantId "%tenantid%" -ClientId "%clientid%"
)
pause
goto MENU

:GRAPH_QUICK_CHECK
echo.
echo Running Graph API quick security check - ALL users, last 3 days...
echo Note: Requires Azure AD app registration and appropriate permissions
set /p tenantid="Enter Tenant ID (or press Enter to use interactive auth): "
if "%tenantid%"=="" (
    powershell.exe -ExecutionPolicy Bypass -File "DSPA.ps1" -Users "ALL" -DaysBack 3 -UseGraphAPI
) else (
    set /p clientid="Enter Client ID: "
    powershell.exe -ExecutionPolicy Bypass -File "DSPA.ps1" -Users "ALL" -DaysBack 3 -UseGraphAPI -TenantId "%tenantid%" -ClientId "%clientid%"
)
pause
goto MENU

:PURVIEW_ALL_USERS
echo.
echo Running Purview API analysis for ALL users - last 7 days...
echo Note: Requires Azure AD app registration and Purview permissions
set /p tenantid="Enter Tenant ID (or press Enter to use interactive auth): "
if "%tenantid%"=="" (
    powershell.exe -ExecutionPolicy Bypass -File "DSPA.ps1" -Users "ALL" -DaysBack 7 -UsePurviewAPI
) else (
    set /p clientid="Enter Client ID: "
    powershell.exe -ExecutionPolicy Bypass -File "DSPA.ps1" -Users "ALL" -DaysBack 7 -UsePurviewAPI -TenantId "%tenantid%" -ClientId "%clientid%"
)
pause
goto MENU

:PURVIEW_QUICK_CHECK
echo.
echo Running Purview API quick security check - ALL users, last 3 days...
echo Note: Requires Azure AD app registration and Purview permissions
set /p tenantid="Enter Tenant ID (or press Enter to use interactive auth): "
if "%tenantid%"=="" (
    powershell.exe -ExecutionPolicy Bypass -File "DSPA.ps1" -Users "ALL" -DaysBack 3 -UsePurviewAPI
) else (
    set /p clientid="Enter Client ID: "
    powershell.exe -ExecutionPolicy Bypass -File "DSPA.ps1" -Users "ALL" -DaysBack 3 -UsePurviewAPI -TenantId "%tenantid%" -ClientId "%clientid%"
)
pause
goto MENU

:EXIT
echo.
echo Exiting DSPA Report Generator
exit /b 0