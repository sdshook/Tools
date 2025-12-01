#!/usr/bin/env python3
"""
Box Data Security Posture Activity (DSPA) Report Tool

This script retrieves Box audit log activities for users and generates
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
    from boxsdk import OAuth2, Client
    from boxsdk.exception import BoxAPIException
except ImportError:
    print("Error: Box SDK not installed.")
    print("Please install with: pip install boxsdk")
    sys.exit(1)

class BoxDSPA:
    """Box Data Security Posture Activity analyzer"""
    
    def __init__(self, client_id: str, client_secret: str, access_token: str = None, refresh_token: str = None):
        """
        Initialize the Box DSPA analyzer
        
        Args:
            client_id: Box application client ID
            client_secret: Box application client secret
            access_token: OAuth2 access token (optional)
            refresh_token: OAuth2 refresh token (optional)
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.client = None
        
    def authenticate(self):
        """Authenticate with Box API using OAuth2"""
        try:
            if self.access_token:
                # Use existing access token
                oauth = OAuth2(
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    access_token=self.access_token,
                    refresh_token=self.refresh_token
                )
            else:
                print("✗ Access token required for Box API authentication")
                print("Please provide access_token and refresh_token parameters")
                return False
            
            self.client = Client(oauth)
            
            # Test authentication by getting current user
            current_user = self.client.user().get()
            print(f"✓ Successfully authenticated as: {current_user.name} ({current_user.login})")
            return True
            
        except BoxAPIException as e:
            print(f"✗ Box API authentication failed: {str(e)}")
            return False
        except Exception as e:
            print(f"✗ Authentication failed: {str(e)}")
            return False
    
    def get_users(self, user_filter: str = "ALL") -> List[Dict[str, Any]]:
        """
        Get list of users to analyze
        
        Args:
            user_filter: "ALL" for all users, or comma-separated list of user IDs/emails
            
        Returns:
            List of user dictionaries
        """
        if user_filter.upper() == "ALL":
            try:
                # Get all users in the enterprise
                users = []
                for user in self.client.users(limit=1000):
                    if user.status == 'active':
                        users.append({
                            'id': user.id,
                            'name': user.name,
                            'login': user.login
                        })
                
                print(f"✓ Found {len(users)} active users")
                return users
                
            except BoxAPIException as e:
                print(f"✗ Error retrieving users: {str(e)}")
                return []
        else:
            # Parse comma-separated user list
            user_identifiers = [uid.strip() for uid in user_filter.split(',')]
            users = []
            
            for identifier in user_identifiers:
                try:
                    # Try to get user by ID first, then by email
                    if identifier.isdigit():
                        user = self.client.user(identifier).get()
                    else:
                        # Search for user by email
                        search_results = list(self.client.search().query(identifier, type='user', limit=1))
                        if search_results:
                            user = search_results[0]
                        else:
                            print(f"⚠ User not found: {identifier}")
                            continue
                    
                    users.append({
                        'id': user.id,
                        'name': user.name,
                        'login': user.login
                    })
                    
                except BoxAPIException as e:
                    print(f"⚠ Error getting user {identifier}: {str(e)}")
                    continue
            
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
    
    def get_box_audit_logs(self, users: List[Dict[str, Any]], date_range: Dict[str, datetime]) -> List[Dict[str, Any]]:
        """
        Retrieve Box audit logs using Events API
        
        Args:
            users: List of user dictionaries
            date_range: Dictionary with start and end datetime objects
            
        Returns:
            List of audit log entries
        """
        audit_logs = []
        
        try:
            print(f"📊 Retrieving Box audit logs from {date_range['start']} to {date_range['end']}")
            
            # Box Events API parameters
            stream_position = 'now'
            limit = 500
            
            # Get enterprise events
            events = self.client.events().get_events(
                limit=limit,
                stream_position=stream_position,
                created_after=date_range['start'],
                created_before=date_range['end']
            )
            
            event_count = 0
            for event in events['entries']:
                event_count += 1
                
                # Filter by users if not ALL
                if users and len(users) > 0:
                    user_ids = [user['id'] for user in users]
                    if event.get('created_by', {}).get('id') not in user_ids:
                        continue
                
                # Parse event data
                parsed_event = self.parse_event(event)
                if parsed_event:
                    audit_logs.append(parsed_event)
                
                if event_count % 100 == 0:
                    print(f"📄 Processed {event_count} events...")
            
            print(f"✓ Retrieved {len(audit_logs)} relevant audit log entries")
            return audit_logs
            
        except BoxAPIException as e:
            print(f"✗ Box API error retrieving audit logs: {str(e)}")
            return []
        except Exception as e:
            print(f"✗ Error retrieving audit logs: {str(e)}")
            return []
    
    def parse_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse a single event entry into standardized format
        
        Args:
            event: Raw event data from Box API
            
        Returns:
            Parsed event dictionary or None if invalid
        """
        try:
            # Extract basic information
            event_id = event.get('event_id', '')
            event_type = event.get('event_type', '')
            created_at = event.get('created_at', '')
            
            # Extract user information
            created_by = event.get('created_by', {})
            user_id = created_by.get('id', '')
            user_name = created_by.get('name', '')
            user_login = created_by.get('login', '')
            
            # Extract IP and session information
            ip_address = event.get('ip_address', '')
            session_id = event.get('session_id', '')
            
            # Extract source information (file/folder)
            source = event.get('source', {})
            file_id = source.get('id', '')
            file_name = source.get('name', '')
            file_type = source.get('type', '')
            
            # Extract additional event details
            additional_details = event.get('additional_details', {})
            
            parsed_event = {
                'datetime': created_at,
                'event_id': event_id,
                'event_type': event_type,
                'user_id': user_id,
                'user_name': user_name,
                'user_email': user_login,
                'ip_address': ip_address,
                'session_id': session_id,
                'file_id': file_id,
                'file_name': file_name,
                'file_type': file_type,
                'user_agent': additional_details.get('user_agent', ''),
                'device_name': additional_details.get('device_name', ''),
                'additional_details': additional_details,
                'raw_event': event
            }
            
            return parsed_event
            
        except Exception as e:
            print(f"⚠ Error parsing event: {str(e)}")
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
                high_risk_events = [
                    'DELETE', 'DOWNLOAD', 'SHARE', 'UNSHARE', 'COLLABORATION_INVITE',
                    'COLLABORATION_ROLE_CHANGE', 'ITEM_SHARED_UPDATE', 'ITEM_SYNC',
                    'ITEM_UNSYNC', 'COPY', 'MOVE', 'RENAME'
                ]
                if activity['event_type'] in high_risk_events:
                    suspicious_activities['high_risk_activities'].append({
                        'user': user_email,
                        'datetime': activity['datetime'],
                        'event_type': activity['event_type'],
                        'file_name': activity['file_name'],
                        'ip_address': activity['ip_address'],
                        'country': activity['country'],
                        'device_name': activity['device_name'],
                        'reason': f"High-risk activity: {activity['event_type']}"
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
            'datetime', 'event_id', 'event_type', 'user_id', 'user_name', 'user_email',
            'ip_address', 'country', 'city', 'organization', 'asn', 'session_id',
            'file_id', 'file_name', 'file_type', 'user_agent', 'device_name'
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
        description='Box Data Security Posture Activity (DSPA) Report Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all users for last 30 days
  python box_dspa.py --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET --access-token YOUR_ACCESS_TOKEN --refresh-token YOUR_REFRESH_TOKEN

  # Analyze specific users for date range
  python box_dspa.py --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET --access-token YOUR_ACCESS_TOKEN --refresh-token YOUR_REFRESH_TOKEN --users "12345,67890" --start-date 11012024 --end-date 11302024

  # Analyze last 7 days
  python box_dspa.py --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET --access-token YOUR_ACCESS_TOKEN --refresh-token YOUR_REFRESH_TOKEN --days-back 7
        """
    )
    
    parser.add_argument('--client-id', required=True, help='Box application client ID')
    parser.add_argument('--client-secret', required=True, help='Box application client secret')
    parser.add_argument('--access-token', required=True, help='OAuth2 access token')
    parser.add_argument('--refresh-token', help='OAuth2 refresh token')
    parser.add_argument('--users', default='ALL', help='Comma-separated list of user IDs or "ALL" for all users')
    parser.add_argument('--start-date', help='Start date in MMDDYYYY format')
    parser.add_argument('--end-date', help='End date in MMDDYYYY format')
    parser.add_argument('--days-back', type=int, help='Number of days back from today')
    parser.add_argument('--output-dir', default='.', help='Output directory for reports')
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Initialize DSPA analyzer
    dspa = BoxDSPA(args.client_id, args.client_secret, args.access_token, args.refresh_token)
    
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
    audit_logs = dspa.get_box_audit_logs(users, date_range)
    if not audit_logs:
        print("✗ No audit logs found")
        sys.exit(1)
    
    # Enrich with IP data
    enriched_logs = dspa.enrich_ip_data(audit_logs)
    
    # Analyze suspicious activities
    suspicious_activities = dspa.analyze_suspicious_activity(enriched_logs)
    
    # Generate output filenames
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    raw_output = os.path.join(args.output_dir, f'box_dspa_raw_{timestamp}.csv')
    suspicious_output = os.path.join(args.output_dir, f'box_dspa_suspicious_{timestamp}.json')
    
    # Export reports
    dspa.export_raw_data(enriched_logs, raw_output)
    dspa.export_suspicious_activities(suspicious_activities, suspicious_output)
    
    print("\n" + "="*60)
    print("📊 BOX DSPA ANALYSIS COMPLETE")
    print("="*60)
    print(f"📄 Raw data report: {raw_output}")
    print(f"🚨 Suspicious activities report: {suspicious_output}")
    print(f"📈 Total activities analyzed: {len(enriched_logs)}")
    print(f"👥 Users analyzed: {len(users) if users[0] != 'ALL' else suspicious_activities['summary']['unique_users']}")
    print(f"🚩 Suspicious activities found: {suspicious_activities['summary']['unusual_location_count'] + suspicious_activities['summary']['unusual_time_count'] + suspicious_activities['summary']['high_risk_activity_count']}")

if __name__ == '__main__':
    main()