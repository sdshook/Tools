#!/usr/bin/env python3
"""
Test script to query Microsoft 365 Usage Reports for actual platform usage.

These reports show ACTUAL USAGE by platform (mobile, desktop, web), not just
authentication events. This is more accurate for determining technology reliance.

Reports tested:
- getM365AppUserDetail: M365 app usage by platform per user
- getEmailAppUsageUserDetail: Email client usage by platform
- getOffice365ActiveUserDetail: Active users by platform

Usage:
    python3 test_m365_usage.py

Requires: 
- Reports.Read.All permission (admin consent required)
- requests, msal
"""

import json
import sys
from datetime import datetime, timezone, timedelta

try:
    import requests
    import msal
except ImportError:
    print("Missing dependencies. Install with:")
    print("  pip install requests msal")
    sys.exit(1)

# Custom app registration for Shane's PowerShell/Graph queries
# Device code flow - no secret needed
CLIENT_ID = "ed120d50-6c8e-47bb-8b56-dae9be69fff7"
TENANT = "forgepointcap.com"  # Tenant-specific app, not multi-tenant
SCOPES = ["https://graph.microsoft.com/.default"]

def get_token():
    """Authenticate via device code flow."""
    app = msal.PublicClientApplication(CLIENT_ID, authority=f"https://login.microsoftonline.com/{TENANT}")
    
    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        print(f"Failed to create device flow: {flow.get('error_description', 'Unknown error')}")
        sys.exit(1)
    
    print(f"\n{flow['message']}\n")
    
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        print(f"Authentication failed: {result.get('error_description', 'Unknown error')}")
        sys.exit(1)
    
    return result["access_token"]


def test_report(token, description, url):
    """Execute a report query and analyze results."""
    print(f"\n{'='*70}")
    print(f"TEST: {description}")
    print(f"URL: {url}")
    print("-"*70)
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }
    
    try:
        resp = requests.get(url, headers=headers, timeout=60)
        
        if resp.status_code == 403:
            print(f"❌ PERMISSION DENIED: Reports.Read.All not consented")
            print(f"   Grant admin consent for Reports.Read.All on the")
            print(f"   'Microsoft Graph Command Line Tools' app in Entra ID")
            return None
            
        if resp.status_code != 200:
            print(f"❌ FAILED: HTTP {resp.status_code}")
            try:
                err = resp.json()
                print(f"   Error: {err.get('error', {}).get('message', resp.text[:200])}")
            except:
                print(f"   Response: {resp.text[:200]}")
            return None
        
        data = resp.json()
        records = data.get("value", [])
        
        if not records:
            print(f"⚠️  EMPTY: Report returned 0 records")
            return []
        
        print(f"✓ SUCCESS: {len(records)} user records returned")
        return records
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return None


def analyze_m365_app_usage(records):
    """Analyze M365 app usage by platform."""
    print(f"\n{'='*70}")
    print("M365 APP USAGE ANALYSIS (Last 7 Days)")
    print("="*70)
    
    # Platform usage counters
    platforms = {
        "windows": 0,
        "mac": 0,
        "mobile": 0,
        "web": 0,
    }
    
    # Per-app platform breakdown
    apps = ["outlook", "word", "excel", "powerpoint", "teams", "oneNote", "oneDrive"]
    app_platforms = {app: {"windows": 0, "mac": 0, "mobile": 0, "web": 0} for app in apps}
    
    for user in records:
        upn = user.get("userPrincipalName", "unknown")
        
        # Check each app's platform usage
        for app in apps:
            win_key = f"{app}Windows"
            mac_key = f"{app}Mac"
            mobile_key = f"{app}Mobile"
            web_key = f"{app}Web"
            
            if user.get(win_key):
                platforms["windows"] += 1
                app_platforms[app]["windows"] += 1
            if user.get(mac_key):
                platforms["mac"] += 1
                app_platforms[app]["mac"] += 1
            if user.get(mobile_key):
                platforms["mobile"] += 1
                app_platforms[app]["mobile"] += 1
            if user.get(web_key):
                platforms["web"] += 1
                app_platforms[app]["web"] += 1
    
    total_users = len(records)
    print(f"\nTotal users in report: {total_users}")
    
    print(f"\n--- OVERALL PLATFORM USAGE (user-app combinations) ---")
    total_platform_usage = sum(platforms.values())
    for plat, count in sorted(platforms.items(), key=lambda x: x[1], reverse=True):
        pct = count / total_platform_usage * 100 if total_platform_usage > 0 else 0
        print(f"  {plat.capitalize():10} {count:5} ({pct:.1f}%)")
    
    print(f"\n--- PER-APP BREAKDOWN ---")
    for app in apps:
        app_total = sum(app_platforms[app].values())
        if app_total > 0:
            print(f"\n  {app.upper()}:")
            for plat, count in sorted(app_platforms[app].items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    pct = count / app_total * 100
                    print(f"    {plat.capitalize():10} {count:4} users ({pct:.1f}%)")
    
    # Calculate mobile vs desktop ratio
    mobile_users = platforms["mobile"]
    desktop_users = platforms["windows"] + platforms["mac"]
    
    print(f"\n--- MOBILE vs DESKTOP ---")
    print(f"  Mobile users (any M365 app): {mobile_users}")
    print(f"  Desktop users (Windows+Mac): {desktop_users}")
    if mobile_users + desktop_users > 0:
        mobile_pct = mobile_users / (mobile_users + desktop_users) * 100
        print(f"  Mobile share: {mobile_pct:.1f}%")
    
    return platforms, app_platforms


def analyze_email_usage(records):
    """Analyze email app usage by platform."""
    print(f"\n{'='*70}")
    print("EMAIL APP USAGE ANALYSIS")
    print("="*70)
    
    # Count users by email client platform
    clients = {}
    
    for user in records:
        upn = user.get("userPrincipalName", "unknown")
        
        # These fields indicate which platforms the user used for email
        # Fields: outlookMac, outlookWindows, outlookMobile, outlookWeb,
        #         mailForMac, popMail, imapMail, smtpMail
        
        used_platforms = []
        if user.get("outlookWindows"):
            used_platforms.append("Outlook Windows")
        if user.get("outlookMac"):
            used_platforms.append("Outlook Mac")
        if user.get("outlookMobile"):
            used_platforms.append("Outlook Mobile")
        if user.get("outlookWeb"):
            used_platforms.append("Outlook Web")
        if user.get("mailForMac"):
            used_platforms.append("Mail for Mac")
        if user.get("popMail"):
            used_platforms.append("POP client")
        if user.get("imapMail"):
            used_platforms.append("IMAP client")
        if user.get("smtpMail"):
            used_platforms.append("SMTP client")
        
        for plat in used_platforms:
            clients[plat] = clients.get(plat, 0) + 1
    
    print(f"\nTotal users: {len(records)}")
    print(f"\n--- EMAIL CLIENT USAGE ---")
    for client, count in sorted(clients.items(), key=lambda x: x[1], reverse=True):
        pct = count / len(records) * 100 if records else 0
        print(f"  {client:20} {count:4} users ({pct:.1f}%)")
    
    # Mobile vs Desktop for email
    mobile_email = clients.get("Outlook Mobile", 0)
    desktop_email = clients.get("Outlook Windows", 0) + clients.get("Outlook Mac", 0) + clients.get("Mail for Mac", 0)
    web_email = clients.get("Outlook Web", 0)
    
    print(f"\n--- EMAIL: MOBILE vs DESKTOP vs WEB ---")
    print(f"  Mobile (Outlook Mobile): {mobile_email}")
    print(f"  Desktop (Outlook Win/Mac): {desktop_email}")
    print(f"  Web (Outlook Web/OWA): {web_email}")
    
    total_modern = mobile_email + desktop_email + web_email
    if total_modern > 0:
        print(f"\n  Mobile share of email users: {mobile_email / total_modern * 100:.1f}%")
    
    return clients


def main():
    print("="*70)
    print("MICROSOFT 365 USAGE REPORTS TEST")
    print("="*70)
    print("\nThis script queries M365 usage reports to determine ACTUAL platform")
    print("usage patterns (mobile vs desktop vs web), not just authentication events.")
    print("\nUsage reports show which platforms users ACTUALLY used apps from,")
    print("regardless of how many sign-in events were generated.")
    
    # Authenticate
    print("\n" + "="*70)
    print("AUTHENTICATION")
    print("="*70)
    token = get_token()
    print("✓ Authenticated successfully")
    
    # Period for reports (D7 = last 7 days, D30 = last 30 days)
    period = "D7"
    
    # Test reports
    results = {}
    
    # Test 1: M365 App User Detail
    url1 = f"https://graph.microsoft.com/v1.0/reports/getM365AppUserDetail(period='{period}')"
    records1 = test_report(token, f"M365 App Usage by Platform ({period})", url1)
    if records1:
        results["m365_app"] = analyze_m365_app_usage(records1)
    
    # Test 2: Email App Usage
    url2 = f"https://graph.microsoft.com/v1.0/reports/getEmailAppUsageUserDetail(period='{period}')"
    records2 = test_report(token, f"Email App Usage by Platform ({period})", url2)
    if records2:
        results["email"] = analyze_email_usage(records2)
    
    # Test 3: Office 365 Active Users
    url3 = f"https://graph.microsoft.com/v1.0/reports/getOffice365ActiveUserDetail(period='{period}')"
    records3 = test_report(token, f"Office 365 Active User Detail ({period})", url3)
    if records3:
        print(f"\n{'='*70}")
        print("OFFICE 365 ACTIVE USERS")
        print("="*70)
        print(f"\nTotal active users: {len(records3)}")
        
        # Sample first user to show available fields
        if records3:
            print(f"\nSample user fields available:")
            sample = records3[0]
            for key in sorted(sample.keys()):
                val = sample[key]
                if val and key not in ["id", "userPrincipalName", "displayName"]:
                    print(f"  {key}: {val}")
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    if not results:
        print("\n❌ No usage reports accessible.")
        print("\nTo enable usage reports:")
        print("1. Go to Entra ID → App registrations → Microsoft Graph Command Line Tools")
        print("2. API permissions → Add permission → Microsoft Graph → Application")
        print("3. Add: Reports.Read.All")
        print("4. Grant admin consent")
    else:
        print("\n✓ Usage reports provide accurate platform usage data")
        print("\nThese reports show which platforms users ACTUALLY used,")
        print("not just which platforms generated sign-in events.")
        print("\nFor mobile-heavy organizations, this will show higher mobile")
        print("usage than sign-in logs because mobile apps stay authenticated.")
    
    print("\nDone.")


if __name__ == "__main__":
    main()
