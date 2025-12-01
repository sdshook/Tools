#!/usr/bin/env python3
"""
Dropbox Data Security Posture Activity (DSPA) Report Tool

This script retrieves Dropbox audit log activities for users and generates
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
    import dropbox
    from dropbox.exceptions import ApiError, AuthError
except ImportError:
    print("Error: Dropbox SDK not installed.")
    print("Please install with: pip install dropbox")
    sys.exit(1)

class DropboxDSPA:
    """Dropbox Data Security Posture Activity analyzer"""
    
    def __init__(self, access_token: str):
        """
        Initialize the Dropbox DSPA analyzer
        
        Args:
            access_token: Dropbox API access token
        """
        self.access_token = access_token
        self.client = None
        
    def authenticate(self):
        """Authenticate with Dropbox API"""
        try:
            self.client = dropbox.DropboxTeam(self.access_token)
            
            # Test authentication by getting team info
            team_info = self.client.team_get_info()
            print(f"✓ Successfully authenticated with team: {team_info.name}")
            return True
            
        except AuthError as e:
            print(f"✗ Dropbox authentication failed: {str(e)}")
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
                # Get all team members
                users = []
                members = self.client.team_members_list()
                
                for member in members.members:
                    if member.profile.status.is_active():
                        users.append({
                            'team_member_id': member.profile.team_member_id,
                            'account_id': member.profile.account_id,
                            'name': member.profile.name.display_name,
                            'email': member.profile.email
                        })
                
                # Handle pagination
                while members.has_more:
                    members = self.client.team_members_list_continue(members.cursor)
                    for member in members.members:
                        if member.profile.status.is_active():
                            users.append({
                                'team_member_id': member.profile.team_member_id,
                                'account_id': member.profile.account_id,
                                'name': member.profile.name.display_name,
                                'email': member.profile.email
                            })
                
                print(f"✓ Found {len(users)} active team members")
                return users
                
            except ApiError as e:
                print(f"✗ Error retrieving team members: {str(e)}")
                return []
        else:
            # Parse comma-separated user list
            user_identifiers = [uid.strip() for uid in user_filter.split(',')]
            users = []
            
            # Get all team members first
            all_members = []
            members = self.client.team_members_list()
            all_members.extend(members.members)
            
            while members.has_more:
                members = self.client.team_members_list_continue(members.cursor)
                all_members.extend(members.members)
            
            # Filter by specified identifiers
            for identifier in user_identifiers:
                for member in all_members:
                    if (identifier == member.profile.team_member_id or 
                        identifier == member.profile.account_id or
                        identifier == member.profile.email):
                        users.append({
                            'team_member_id': member.profile.team_member_id,
                            'account_id': member.profile.account_id,
                            'name': member.profile.name.display_name,
                            'email': member.profile.email
                        })
                        break
                else:
                    print(f"⚠ User not found: {identifier}")
            
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
    
    def get_dropbox_audit_logs(self, users: List[Dict[str, Any]], date_range: Dict[str, datetime]) -> List[Dict[str, Any]]:
        """
        Retrieve Dropbox audit logs using Team Log API
        
        Args:
            users: List of user dictionaries
            date_range: Dictionary with start and end datetime objects
            
        Returns:
            List of audit log entries
        """
        audit_logs = []
        
        try:
            print(f"📊 Retrieving Dropbox audit logs from {date_range['start']} to {date_range['end']}")
            
            # Dropbox Team Log API parameters
            limit = 1000
            
            # Get team events
            events = self.client.team_log_get_events(
                limit=limit,
                time=dropbox.team_log.TimeRange(
                    start_time=date_range['start'],
                    end_time=date_range['end']
                )
            )
            
            event_count = 0
            while True:
                for event in events.events:
                    event_count += 1
                    
                    # Filter by users if not ALL
                    if users and len(users) > 0:
                        user_ids = [user['team_member_id'] for user in users]
                        actor = getattr(event, 'actor', None)
                        if actor and hasattr(actor, 'user') and actor.user:
                            if actor.user.team_member_id not in user_ids:
                                continue
                        else:
                            continue  # Skip events without user actor
                    
                    # Parse event data
                    parsed_event = self.parse_event(event)
                    if parsed_event:
                        audit_logs.append(parsed_event)
                    
                    if event_count % 100 == 0:
                        print(f"📄 Processed {event_count} events...")
                
                # Check for more events
                if events.has_more:
                    events = self.client.team_log_get_events_continue(events.cursor)
                else:
                    break
            
            print(f"✓ Retrieved {len(audit_logs)} relevant audit log entries")
            return audit_logs
            
        except ApiError as e:
            print(f"✗ Dropbox API error retrieving audit logs: {str(e)}")
            return []
        except Exception as e:
            print(f"✗ Error retrieving audit logs: {str(e)}")
            return []
    
    def parse_event(self, event) -> Optional[Dict[str, Any]]:
        """
        Parse a single event entry into standardized format
        
        Args:
            event: Raw event data from Dropbox API
            
        Returns:
            Parsed event dictionary or None if invalid
        """
        try:
            # Extract basic information
            timestamp = event.timestamp.isoformat() if event.timestamp else ''
            event_type = event.event_type._tag if hasattr(event.event_type, '_tag') else str(type(event.event_type).__name__)
            
            # Extract actor information
            actor = getattr(event, 'actor', None)
            user_id = ''
            user_name = ''
            user_email = ''
            
            if actor and hasattr(actor, 'user') and actor.user:
                user_id = actor.user.team_member_id
                user_name = actor.user.display_name
                user_email = actor.user.email
            elif actor and hasattr(actor, 'admin') and actor.admin:
                user_id = actor.admin.team_member_id
                user_name = actor.admin.display_name
                user_email = actor.admin.email
            
            # Extract context information
            context = getattr(event, 'context', None)
            ip_address = ''
            user_agent = ''
            
            if context:
                ip_address = getattr(context, 'ip_address', '')
                user_agent = getattr(context, 'user_agent', '')
            
            # Extract event-specific details
            event_details = {}
            if hasattr(event, 'details'):
                details = event.details
                event_details = self.extract_event_details(details)
            
            parsed_event = {
                'datetime': timestamp,
                'event_type': event_type,
                'user_id': user_id,
                'user_name': user_name,
                'user_email': user_email,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'file_name': event_details.get('file_name', ''),
                'file_path': event_details.get('file_path', ''),
                'file_id': event_details.get('file_id', ''),
                'device_name': event_details.get('device_name', ''),
                'app_name': event_details.get('app_name', ''),
                'event_details': event_details,
                'raw_event': str(event)
            }
            
            return parsed_event
            
        except Exception as e:
            print(f"⚠ Error parsing event: {str(e)}")
            return None
    
    def extract_event_details(self, details) -> Dict[str, Any]:
        """
        Extract specific details from event details object
        
        Args:
            details: Event details object
            
        Returns:
            Dictionary of extracted details
        """
        extracted = {}
        
        try:
            # Common file-related fields
            if hasattr(details, 'path_display'):
                extracted['file_path'] = details.path_display
                extracted['file_name'] = os.path.basename(details.path_display)
            elif hasattr(details, 'path'):
                extracted['file_path'] = details.path
                extracted['file_name'] = os.path.basename(details.path)
            
            # File ID
            if hasattr(details, 'file_id'):
                extracted['file_id'] = details.file_id
            
            # Device information
            if hasattr(details, 'device_display_name'):
                extracted['device_name'] = details.device_display_name
            elif hasattr(details, 'device_name'):
                extracted['device_name'] = details.device_name
            
            # App information
            if hasattr(details, 'app_display_name'):
                extracted['app_name'] = details.app_display_name
            elif hasattr(details, 'app_name'):
                extracted['app_name'] = details.app_name
            
            # Additional context
            if hasattr(details, 'shared_folder_name'):
                extracted['shared_folder_name'] = details.shared_folder_name
            
            if hasattr(details, 'target_user'):
                extracted['target_user'] = details.target_user.display_name if details.target_user else ''
            
        except Exception as e:
            print(f"⚠ Error extracting event details: {str(e)}")
        
        return extracted
    
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
                    activity_time = datetime.fromisoformat(activity['datetime'])
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
                    'file_delete', 'file_download', 'file_share', 'file_unshare',
                    'shared_folder_create', 'shared_folder_invite', 'shared_folder_leave',
                    'file_copy', 'file_move', 'file_rename', 'paper_doc_delete',
                    'paper_doc_download', 'paper_doc_share'
                ]
                if any(risk_event in activity['event_type'].lower() for risk_event in high_risk_events):
                    suspicious_activities['high_risk_activities'].append({
                        'user': user_email,
                        'datetime': activity['datetime'],
                        'event_type': activity['event_type'],
                        'file_name': activity['file_name'],
                        'file_path': activity['file_path'],
                        'ip_address': activity['ip_address'],
                        'country': activity['country'],
                        'device_name': activity['device_name'],
                        'app_name': activity['app_name'],
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
            'datetime', 'event_type', 'user_id', 'user_name', 'user_email',
            'ip_address', 'country', 'city', 'organization', 'asn',
            'file_name', 'file_path', 'file_id', 'device_name', 'app_name', 'user_agent'
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
        description='Dropbox Data Security Posture Activity (DSPA) Report Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all users for last 30 days
  python dropbox_dspa.py --access-token YOUR_ACCESS_TOKEN

  # Analyze specific users for date range
  python dropbox_dspa.py --access-token YOUR_ACCESS_TOKEN --users "user1@example.com,user2@example.com" --start-date 11012024 --end-date 11302024

  # Analyze last 7 days
  python dropbox_dspa.py --access-token YOUR_ACCESS_TOKEN --days-back 7
        """
    )
    
    parser.add_argument('--access-token', required=True, help='Dropbox API access token')
    parser.add_argument('--users', default='ALL', help='Comma-separated list of user emails/IDs or "ALL" for all users')
    parser.add_argument('--start-date', help='Start date in MMDDYYYY format')
    parser.add_argument('--end-date', help='End date in MMDDYYYY format')
    parser.add_argument('--days-back', type=int, help='Number of days back from today')
    parser.add_argument('--output-dir', default='.', help='Output directory for reports')
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Initialize DSPA analyzer
    dspa = DropboxDSPA(args.access_token)
    
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
    audit_logs = dspa.get_dropbox_audit_logs(users, date_range)
    if not audit_logs:
        print("✗ No audit logs found")
        sys.exit(1)
    
    # Enrich with IP data
    enriched_logs = dspa.enrich_ip_data(audit_logs)
    
    # Analyze suspicious activities
    suspicious_activities = dspa.analyze_suspicious_activity(enriched_logs)
    
    # Generate output filenames
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    raw_output = os.path.join(args.output_dir, f'dropbox_dspa_raw_{timestamp}.csv')
    suspicious_output = os.path.join(args.output_dir, f'dropbox_dspa_suspicious_{timestamp}.json')
    
    # Export reports
    dspa.export_raw_data(enriched_logs, raw_output)
    dspa.export_suspicious_activities(suspicious_activities, suspicious_output)
    
    print("\n" + "="*60)
    print("📊 DROPBOX DSPA ANALYSIS COMPLETE")
    print("="*60)
    print(f"📄 Raw data report: {raw_output}")
    print(f"🚨 Suspicious activities report: {suspicious_output}")
    print(f"📈 Total activities analyzed: {len(enriched_logs)}")
    print(f"👥 Users analyzed: {len(users) if users[0] != 'ALL' else suspicious_activities['summary']['unique_users']}")
    print(f"🚩 Suspicious activities found: {suspicious_activities['summary']['unusual_location_count'] + suspicious_activities['summary']['unusual_time_count'] + suspicious_activities['summary']['high_risk_activity_count']}")

if __name__ == '__main__':
    main()