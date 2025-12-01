#!/usr/bin/env python3
"""
Google Drive Data Security Posture Activity (DSPA) Report Tool

This script retrieves Google Drive audit log activities for users and generates
security posture reports including suspicious activity analysis.

Author: OpenHands AI Assistant
Version: 1.0.0
Date: 2024-12-01
"""

import argparse
import json
import csv
import os
import sys
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import requests
import ipaddress
from collections import defaultdict, Counter

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    print("Error: Google API client libraries not installed.")
    print("Please install with: pip install google-api-python-client google-auth google-auth-oauthlib google-auth-httplib2")
    sys.exit(1)

class GDriveDSPA:
    """Google Drive Data Security Posture Activity analyzer"""
    
    def __init__(self, credentials_path: str, domain: str):
        """
        Initialize the Google Drive DSPA analyzer
        
        Args:
            credentials_path: Path to service account credentials JSON file
            domain: Google Workspace domain
        """
        self.credentials_path = credentials_path
        self.domain = domain
        self.service = None
        self.reports_service = None
        
    def authenticate(self):
        """Authenticate with Google APIs using service account"""
        try:
            # Define the required scopes
            scopes = [
                'https://www.googleapis.com/auth/admin.reports.audit.readonly',
                'https://www.googleapis.com/auth/admin.directory.user.readonly'
            ]
            
            # Load service account credentials
            credentials = service_account.Credentials.from_service_account_file(
                self.credentials_path, scopes=scopes
            )
            
            # Build the Admin SDK Reports service
            self.reports_service = build('admin', 'reports_v1', credentials=credentials)
            
            # Build the Admin SDK Directory service for user info
            self.service = build('admin', 'directory_v1', credentials=credentials)
            
            print(f"✓ Successfully authenticated with Google Workspace domain: {self.domain}")
            return True
            
        except Exception as e:
            print(f"✗ Authentication failed: {str(e)}")
            return False
    
    def get_users(self, user_filter: str = "ALL") -> List[str]:
        """
        Get list of users to analyze
        
        Args:
            user_filter: "ALL" for all users, or comma-separated list of email addresses
            
        Returns:
            List of user email addresses
        """
        if user_filter.upper() == "ALL":
            try:
                # Get all users in the domain
                users = []
                request = self.service.users().list(domain=self.domain, maxResults=500)
                
                while request is not None:
                    response = request.execute()
                    for user in response.get('users', []):
                        if not user.get('suspended', False):
                            users.append(user['primaryEmail'])
                    
                    request = self.service.users().list_next(request, response)
                
                print(f"✓ Found {len(users)} active users in domain")
                return users
                
            except HttpError as e:
                print(f"✗ Error retrieving users: {str(e)}")
                return []
        else:
            # Parse comma-separated user list
            users = [email.strip() for email in user_filter.split(',')]
            print(f"✓ Analyzing {len(users)} specified users")
            return users
    
    def parse_date_range(self, start_date: str = None, end_date: str = None, days_back: int = None) -> Dict[str, datetime]:
        """
        Parse date range parameters
        
        Args:
            start_date: Start date in MMDDYYYY format
            end_date: End date in MMDDYYYY format  
            days_back: Number of days back from today
            
        Returns:
            Dictionary with 'start' and 'end' datetime objects
        """
        end_dt = datetime.now()
        
        if days_back:
            start_dt = end_dt - timedelta(days=days_back)
        elif start_date and end_date:
            try:
                start_dt = datetime.strptime(start_date, '%m%d%Y')
                end_dt = datetime.strptime(end_date, '%m%d%Y')
            except ValueError:
                print("✗ Invalid date format. Use MMDDYYYY format.")
                sys.exit(1)
        elif start_date:
            try:
                start_dt = datetime.strptime(start_date, '%m%d%Y')
            except ValueError:
                print("✗ Invalid start date format. Use MMDDYYYY format.")
                sys.exit(1)
        else:
            # Default to last 30 days
            start_dt = end_dt - timedelta(days=30)
        
        return {'start': start_dt, 'end': end_dt}
    
    def get_drive_audit_logs(self, users: List[str], date_range: Dict[str, datetime]) -> List[Dict[str, Any]]:
        """
        Retrieve Google Drive audit logs
        
        Args:
            users: List of user email addresses
            date_range: Dictionary with start and end datetime objects
            
        Returns:
            List of audit log entries
        """
        audit_logs = []
        
        try:
            # Format dates for API
            start_time = date_range['start'].strftime('%Y-%m-%dT%H:%M:%S.000Z')
            end_time = date_range['end'].strftime('%Y-%m-%dT%H:%M:%S.000Z')
            
            print(f"📊 Retrieving Drive audit logs from {start_time} to {end_time}")
            
            # Get Drive audit logs
            request = self.reports_service.activities().list(
                userKey='all',
                applicationName='drive',
                startTime=start_time,
                endTime=end_time,
                maxResults=1000
            )
            
            page_count = 0
            while request is not None:
                page_count += 1
                print(f"📄 Processing page {page_count}...")
                
                try:
                    response = request.execute()
                    activities = response.get('items', [])
                    
                    for activity in activities:
                        # Filter by users if not ALL
                        if users and users[0].upper() != "ALL":
                            if activity.get('actor', {}).get('email', '') not in users:
                                continue
                        
                        # Parse activity data
                        parsed_activity = self.parse_activity(activity)
                        if parsed_activity:
                            audit_logs.append(parsed_activity)
                    
                    request = self.reports_service.activities().list_next(request, response)
                    
                except HttpError as e:
                    if e.resp.status == 403:
                        print("✗ Access denied. Ensure service account has proper permissions.")
                        break
                    else:
                        print(f"✗ API error: {str(e)}")
                        break
            
            print(f"✓ Retrieved {len(audit_logs)} audit log entries")
            return audit_logs
            
        except Exception as e:
            print(f"✗ Error retrieving audit logs: {str(e)}")
            return []
    
    def parse_activity(self, activity: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse a single activity entry into standardized format
        
        Args:
            activity: Raw activity data from Google API
            
        Returns:
            Parsed activity dictionary or None if invalid
        """
        try:
            # Extract basic information
            timestamp = activity.get('id', {}).get('time', '')
            user_email = activity.get('actor', {}).get('email', '')
            ip_address = activity.get('ipAddress', '')
            user_agent = activity.get('actor', {}).get('profileId', '')  # Limited user agent info
            
            # Extract events
            events = activity.get('events', [])
            if not events:
                return None
            
            # Process each event in the activity
            parsed_events = []
            for event in events:
                event_type = event.get('type', '')
                event_name = event.get('name', '')
                
                # Extract parameters
                parameters = {}
                for param in event.get('parameters', []):
                    param_name = param.get('name', '')
                    param_value = param.get('value', '') or param.get('multiValue', [])
                    parameters[param_name] = param_value
                
                # Extract file information
                file_name = parameters.get('doc_title', '')
                file_id = parameters.get('doc_id', '')
                file_type = parameters.get('doc_type', '')
                visibility = parameters.get('visibility', '')
                
                parsed_event = {
                    'datetime': timestamp,
                    'user_email': user_email,
                    'ip_address': ip_address,
                    'user_agent': user_agent,
                    'event_type': event_type,
                    'event_name': event_name,
                    'file_name': file_name,
                    'file_id': file_id,
                    'file_type': file_type,
                    'visibility': visibility,
                    'parameters': parameters,
                    'raw_activity': activity
                }
                
                parsed_events.append(parsed_event)
            
            return parsed_events[0] if parsed_events else None
            
        except Exception as e:
            print(f"⚠ Error parsing activity: {str(e)}")
            return None
    
    def enrich_ip_data(self, audit_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich audit logs with IP geolocation data
        
        Args:
            audit_logs: List of audit log entries
            
        Returns:
            Enriched audit logs with IP geolocation data
        """
        print("🌍 Enriching IP address data...")
        
        # Cache for IP lookups to avoid duplicate requests
        ip_cache = {}
        
        for log_entry in audit_logs:
            ip_address = log_entry.get('ip_address', '')
            
            if not ip_address or ip_address in ip_cache:
                if ip_address in ip_cache:
                    log_entry.update(ip_cache[ip_address])
                continue
            
            try:
                # Check if it's a private IP
                ip_obj = ipaddress.ip_address(ip_address)
                if ip_obj.is_private:
                    geo_data = {
                        'country': 'Private Network',
                        'city': 'Private Network',
                        'organization': 'Private Network',
                        'asn': 'Private'
                    }
                else:
                    # Use a free IP geolocation service (ip-api.com)
                    response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        geo_data = {
                            'country': data.get('country', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'organization': data.get('org', 'Unknown'),
                            'asn': data.get('as', 'Unknown')
                        }
                    else:
                        geo_data = {
                            'country': 'Unknown',
                            'city': 'Unknown', 
                            'organization': 'Unknown',
                            'asn': 'Unknown'
                        }
                
                # Cache the result
                ip_cache[ip_address] = geo_data
                log_entry.update(geo_data)
                
            except Exception as e:
                print(f"⚠ Error enriching IP {ip_address}: {str(e)}")
                log_entry.update({
                    'country': 'Unknown',
                    'city': 'Unknown',
                    'organization': 'Unknown', 
                    'asn': 'Unknown'
                })
        
        print(f"✓ Enriched {len(audit_logs)} entries with IP geolocation data")
        return audit_logs
    
    def analyze_suspicious_activity(self, audit_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze audit logs for suspicious activities
        
        Args:
            audit_logs: List of enriched audit log entries
            
        Returns:
            Dictionary containing suspicious activity analysis
        """
        print("🔍 Analyzing for suspicious activities...")
        
        # Group activities by user
        user_activities = defaultdict(list)
        for log in audit_logs:
            user_activities[log['user_email']].append(log)
        
        suspicious_activities = {
            'unusual_locations': [],
            'unusual_times': [],
            'high_risk_activities': [],
            'summary': {}
        }
        
        for user_email, activities in user_activities.items():
            # Analyze location patterns
            user_countries = Counter(activity['country'] for activity in activities)
            user_ips = Counter(activity['ip_address'] for activity in activities)
            
            # Find unusual locations (countries used less than 10% of the time)
            total_activities = len(activities)
            common_countries = {country for country, count in user_countries.items() 
                             if count / total_activities >= 0.1}
            
            for activity in activities:
                # Flag activities from unusual countries
                if activity['country'] not in common_countries and activity['country'] != 'Unknown':
                    suspicious_activities['unusual_locations'].append({
                        'user': user_email,
                        'datetime': activity['datetime'],
                        'ip_address': activity['ip_address'],
                        'country': activity['country'],
                        'city': activity['city'],
                        'event_type': activity['event_type'],
                        'file_name': activity['file_name'],
                        'reason': f"Unusual location: {activity['country']} (used in {user_countries[activity['country']]}/{total_activities} activities)"
                    })
                
                # Flag activities during unusual hours (outside 6 AM - 10 PM local time)
                try:
                    activity_time = datetime.fromisoformat(activity['datetime'].replace('Z', '+00:00'))
                    hour = activity_time.hour
                    if hour < 6 or hour > 22:  # Assuming UTC for simplicity
                        suspicious_activities['unusual_times'].append({
                            'user': user_email,
                            'datetime': activity['datetime'],
                            'hour': hour,
                            'event_type': activity['event_type'],
                            'file_name': activity['file_name'],
                            'reason': f"Activity at unusual hour: {hour}:00 UTC"
                        })
                except:
                    pass
                
                # Flag high-risk activities
                high_risk_events = ['delete', 'download', 'share', 'change_visibility']
                if any(risk_event in activity['event_name'].lower() for risk_event in high_risk_events):
                    suspicious_activities['high_risk_activities'].append({
                        'user': user_email,
                        'datetime': activity['datetime'],
                        'event_type': activity['event_type'],
                        'event_name': activity['event_name'],
                        'file_name': activity['file_name'],
                        'ip_address': activity['ip_address'],
                        'country': activity['country'],
                        'reason': f"High-risk activity: {activity['event_name']}"
                    })
        
        # Generate summary statistics
        suspicious_activities['summary'] = {
            'total_activities': len(audit_logs),
            'unique_users': len(user_activities),
            'unusual_location_count': len(suspicious_activities['unusual_locations']),
            'unusual_time_count': len(suspicious_activities['unusual_times']),
            'high_risk_activity_count': len(suspicious_activities['high_risk_activities']),
            'analysis_date': datetime.now().isoformat()
        }
        
        print(f"✓ Found {suspicious_activities['summary']['unusual_location_count']} unusual location activities")
        print(f"✓ Found {suspicious_activities['summary']['unusual_time_count']} unusual time activities")
        print(f"✓ Found {suspicious_activities['summary']['high_risk_activity_count']} high-risk activities")
        
        return suspicious_activities
    
    def export_raw_data(self, audit_logs: List[Dict[str, Any]], output_file: str):
        """
        Export raw audit data to CSV
        
        Args:
            audit_logs: List of audit log entries
            output_file: Output CSV file path
        """
        print(f"📄 Exporting raw data to {output_file}")
        
        if not audit_logs:
            print("⚠ No data to export")
            return
        
        # Define CSV headers
        headers = [
            'datetime', 'user_email', 'ip_address', 'country', 'city', 'organization', 'asn',
            'event_type', 'event_name', 'file_name', 'file_id', 'file_type', 'visibility', 'user_agent'
        ]
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            
            for log_entry in audit_logs:
                # Create row with only the headers we want
                row = {header: log_entry.get(header, '') for header in headers}
                writer.writerow(row)
        
        print(f"✓ Exported {len(audit_logs)} entries to {output_file}")
    
    def export_suspicious_activities(self, suspicious_activities: Dict[str, Any], output_file: str):
        """
        Export suspicious activities analysis to JSON
        
        Args:
            suspicious_activities: Suspicious activities analysis
            output_file: Output JSON file path
        """
        print(f"🚨 Exporting suspicious activities to {output_file}")
        
        with open(output_file, 'w', encoding='utf-8') as jsonfile:
            json.dump(suspicious_activities, jsonfile, indent=2, default=str)
        
        print(f"✓ Exported suspicious activities analysis to {output_file}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Google Drive Data Security Posture Activity (DSPA) Report Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all users for last 30 days
  python gdrive_dspa.py --credentials service_account.json --domain example.com

  # Analyze specific users for date range
  python gdrive_dspa.py --credentials service_account.json --domain example.com --users "user1@example.com,user2@example.com" --start-date 11012024 --end-date 11302024

  # Analyze last 7 days
  python gdrive_dspa.py --credentials service_account.json --domain example.com --days-back 7
        """
    )
    
    parser.add_argument('--credentials', required=True, help='Path to Google service account credentials JSON file')
    parser.add_argument('--domain', required=True, help='Google Workspace domain')
    parser.add_argument('--users', default='ALL', help='Comma-separated list of user emails or "ALL" for all users')
    parser.add_argument('--start-date', help='Start date in MMDDYYYY format')
    parser.add_argument('--end-date', help='End date in MMDDYYYY format')
    parser.add_argument('--days-back', type=int, help='Number of days back from today')
    parser.add_argument('--output-dir', default='.', help='Output directory for reports')
    
    args = parser.parse_args()
    
    # Validate credentials file
    if not os.path.exists(args.credentials):
        print(f"✗ Credentials file not found: {args.credentials}")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Initialize DSPA analyzer
    dspa = GDriveDSPA(args.credentials, args.domain)
    
    # Authenticate
    if not dspa.authenticate():
        sys.exit(1)
    
    # Get users to analyze
    users = dspa.get_users(args.users)
    if not users:
        print("✗ No users found to analyze")
        sys.exit(1)
    
    # Parse date range
    date_range = dspa.parse_date_range(args.start_date, args.end_date, args.days_back)
    print(f"📅 Analyzing period: {date_range['start'].strftime('%Y-%m-%d')} to {date_range['end'].strftime('%Y-%m-%d')}")
    
    # Get audit logs
    audit_logs = dspa.get_drive_audit_logs(users, date_range)
    if not audit_logs:
        print("✗ No audit logs found")
        sys.exit(1)
    
    # Enrich with IP data
    enriched_logs = dspa.enrich_ip_data(audit_logs)
    
    # Analyze suspicious activities
    suspicious_activities = dspa.analyze_suspicious_activity(enriched_logs)
    
    # Generate output filenames
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    raw_output = os.path.join(args.output_dir, f'gdrive_dspa_raw_{timestamp}.csv')
    suspicious_output = os.path.join(args.output_dir, f'gdrive_dspa_suspicious_{timestamp}.json')
    
    # Export reports
    dspa.export_raw_data(enriched_logs, raw_output)
    dspa.export_suspicious_activities(suspicious_activities, suspicious_output)
    
    print("\n" + "="*60)
    print("📊 GOOGLE DRIVE DSPA ANALYSIS COMPLETE")
    print("="*60)
    print(f"📄 Raw data report: {raw_output}")
    print(f"🚨 Suspicious activities report: {suspicious_output}")
    print(f"📈 Total activities analyzed: {len(enriched_logs)}")
    print(f"👥 Users analyzed: {len(users) if users[0].upper() != 'ALL' else suspicious_activities['summary']['unique_users']}")
    print(f"🚩 Suspicious activities found: {suspicious_activities['summary']['unusual_location_count'] + suspicious_activities['summary']['unusual_time_count'] + suspicious_activities['summary']['high_risk_activity_count']}")

if __name__ == '__main__':
    main()