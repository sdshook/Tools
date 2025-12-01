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
echo 1. Analyze specific user for last 30 days
echo 2. Analyze all users for last 7 days  
echo 3. Analyze multiple users for custom date range
echo 4. Quick security check (all users, last 3 days)
echo 5. Full monthly report (all users, last 30 days)
echo 6. Exit
echo.
set /p choice="Enter your choice (1-6): "

if "%choice%"=="1" goto SINGLE_USER
if "%choice%"=="2" goto ALL_USERS_WEEK
if "%choice%"=="3" goto MULTI_USER_CUSTOM
if "%choice%"=="4" goto QUICK_CHECK
if "%choice%"=="5" goto MONTHLY_REPORT
if "%choice%"=="6" goto EXIT
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

:EXIT
echo.
echo Exiting DSPA Report Generator
exit /b 0