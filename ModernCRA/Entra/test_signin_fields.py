#!/usr/bin/env python3
"""
Test script to verify which sign-in log fields are available via Graph API.

Tests various combinations of:
- v1.0 vs beta endpoints
- With and without $filter
- With and without deviceDetail in $select

Usage:
    python3 test_signin_fields.py

Requires: requests, msal
"""

import json
import sys
from datetime import datetime, timedelta

try:
    import requests
    import msal
except ImportError:
    print("Missing dependencies. Install with:")
    print("  pip install requests msal")
    sys.exit(1)

# Microsoft Graph CLI app (same as main assessment tool)
CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
TENANT = "common"
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

def test_query(token, description, url, params):
    """Execute a test query and report results."""
    print(f"\n{'='*70}")
    print(f"TEST: {description}")
    print(f"URL: {url}")
    print(f"Params: {json.dumps(params, indent=2)}")
    print("-"*70)
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        
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
            print(f"⚠️  EMPTY: Query returned 0 records")
            return []
        
        print(f"✓ SUCCESS: {len(records)} records returned")
        
        # Analyze first record for available fields
        first = records[0]
        print(f"\nFields in first record:")
        for key, val in first.items():
            if key == "deviceDetail" and isinstance(val, dict):
                print(f"  • deviceDetail:")
                for dk, dv in val.items():
                    display_val = dv if dv is not None else "(null)"
                    if isinstance(display_val, str) and len(display_val) > 50:
                        display_val = display_val[:50] + "..."
                    print(f"      - {dk}: {display_val}")
            else:
                display_val = val if val is not None else "(null)"
                if isinstance(display_val, str) and len(display_val) > 50:
                    display_val = display_val[:50] + "..."
                elif isinstance(display_val, dict):
                    display_val = f"{{...}} ({len(display_val)} keys)"
                elif isinstance(display_val, list):
                    display_val = f"[...] ({len(display_val)} items)"
                print(f"  • {key}: {display_val}")
        
        return records
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return None

def main():
    print("="*70)
    print("SIGN-IN LOG FIELD AVAILABILITY TEST")
    print("="*70)
    print("\nThis script tests which fields can be retrieved from auditLogs/signIns")
    print("under various conditions (v1.0 vs beta, with/without filters, etc.)")
    
    # Authenticate
    print("\n" + "="*70)
    print("AUTHENTICATION")
    print("="*70)
    token = get_token()
    print("✓ Authenticated successfully")
    
    # Calculate date filter (last 7 days)
    since = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%dT00:00:00Z")
    
    # Define test cases
    tests = [
        # Test 1: v1.0, no filter, no $select (all default fields)
        {
            "desc": "v1.0 - No filter, no $select (defaults)",
            "url": "https://graph.microsoft.com/v1.0/auditLogs/signIns",
            "params": {"$top": "1"}
        },
        # Test 2: v1.0, no filter, with deviceDetail in $select
        {
            "desc": "v1.0 - No filter, $select includes deviceDetail",
            "url": "https://graph.microsoft.com/v1.0/auditLogs/signIns",
            "params": {
                "$top": "1",
                "$select": "id,createdDateTime,userPrincipalName,clientAppUsed,deviceDetail"
            }
        },
        # Test 3: v1.0, with filter, without deviceDetail
        {
            "desc": "v1.0 - With $filter, $select WITHOUT deviceDetail",
            "url": "https://graph.microsoft.com/v1.0/auditLogs/signIns",
            "params": {
                "$top": "5",
                "$filter": f"createdDateTime ge {since} and status/errorCode eq 0",
                "$select": "id,createdDateTime,userPrincipalName,clientAppUsed,location"
            }
        },
        # Test 4: v1.0, with filter, WITH deviceDetail
        {
            "desc": "v1.0 - With $filter, $select WITH deviceDetail",
            "url": "https://graph.microsoft.com/v1.0/auditLogs/signIns",
            "params": {
                "$top": "5",
                "$filter": f"createdDateTime ge {since} and status/errorCode eq 0",
                "$select": "id,createdDateTime,userPrincipalName,clientAppUsed,deviceDetail"
            }
        },
        # Test 5: beta, no filter, with deviceDetail
        {
            "desc": "BETA - No filter, $select includes deviceDetail",
            "url": "https://graph.microsoft.com/beta/auditLogs/signIns",
            "params": {
                "$top": "1",
                "$select": "id,createdDateTime,userPrincipalName,clientAppUsed,deviceDetail"
            }
        },
        # Test 6: beta, with filter, WITH deviceDetail
        {
            "desc": "BETA - With $filter, $select WITH deviceDetail",
            "url": "https://graph.microsoft.com/beta/auditLogs/signIns",
            "params": {
                "$top": "5",
                "$filter": f"createdDateTime ge {since} and status/errorCode eq 0",
                "$select": "id,createdDateTime,userPrincipalName,clientAppUsed,deviceDetail"
            }
        },
        # Test 7: v1.0, filter only on createdDateTime (no errorCode)
        {
            "desc": "v1.0 - Filter on createdDateTime only, WITH deviceDetail",
            "url": "https://graph.microsoft.com/v1.0/auditLogs/signIns",
            "params": {
                "$top": "5",
                "$filter": f"createdDateTime ge {since}",
                "$select": "id,createdDateTime,userPrincipalName,clientAppUsed,deviceDetail"
            }
        },
        # Test 8: beta with more fields
        {
            "desc": "BETA - With $filter, extended $select (authenticationDetails, etc.)",
            "url": "https://graph.microsoft.com/beta/auditLogs/signIns",
            "params": {
                "$top": "3",
                "$filter": f"createdDateTime ge {since} and status/errorCode eq 0",
                "$select": "id,createdDateTime,userPrincipalName,clientAppUsed,deviceDetail,"
                          "authenticationDetails,authenticationMethodsUsed,mfaDetail"
            }
        },
    ]
    
    results = {}
    for test in tests:
        result = test_query(token, test["desc"], test["url"], test["params"])
        results[test["desc"]] = "SUCCESS" if result else ("EMPTY" if result == [] else "FAILED")
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    for desc, status in results.items():
        icon = "✓" if status == "SUCCESS" else ("⚠️" if status == "EMPTY" else "❌")
        print(f"{icon} {desc}: {status}")
    
    print("\n" + "="*70)
    print("RECOMMENDATIONS")
    print("="*70)
    
    # Check specific results
    v1_filter_device = results.get("v1.0 - With $filter, $select WITH deviceDetail", "FAILED")
    beta_filter_device = results.get("BETA - With $filter, $select WITH deviceDetail", "FAILED")
    v1_no_filter = results.get("v1.0 - No filter, $select includes deviceDetail", "FAILED")
    
    if v1_filter_device == "SUCCESS":
        print("• v1.0 with $filter + deviceDetail WORKS - use in production")
    elif beta_filter_device == "SUCCESS":
        print("• BETA endpoint with $filter + deviceDetail WORKS - consider using beta")
    elif v1_no_filter == "SUCCESS":
        print("• deviceDetail requires unfiltered query - would need separate API call")
    else:
        print("• deviceDetail may not be available with current permissions")
    
    print("\nDone.")

if __name__ == "__main__":
    main()
