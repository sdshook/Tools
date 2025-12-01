#!/usr/bin/env python3
"""
DSPA (c) Shane D. Shook, 2025 All Rights Reserved

Unified Data Security Posture Activity (DSPA) Tool

This unified script retrieves audit log activities from SharePoint, Google Drive, 
Box, or Dropbox and generates comprehensive security posture reports including 
suspicious activity analysis with IP geolocation.

Author: Shane D. Shook, PhD
Version: 1.0.0
Date: 2024-12-01
"""

import argparse
import json
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import requests
import csv
from collections import defaultdict, Counter
import ipaddress
import logging

# Service-specific imports (will be imported conditionally)
try:
    from msal import ConfidentialClientApplication
    MSAL_AVAILABLE = True
except ImportError:
    MSAL_AVAILABLE = False

try:
    from google.oauth2.service_account import Credentials as ServiceAccountCredentials
    from googleapiclient.discovery import build
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False

try:
    from boxsdk import OAuth2, Client
    BOX_AVAILABLE = True
except ImportError:
    BOX_AVAILABLE = False

try:
    import dropbox
    from dropbox.team_log import GetEventsArg, TimeRange
    DROPBOX_AVAILABLE = True
except ImportError:
    DROPBOX_AVAILABLE = False


class DSPAConfig:
    """Configuration manager for DSPA unified tool"""
    
    def __init__(self, config_path: str = "dspa_config.json"):
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logging.error(f"Configuration file {self.config_path} not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in configuration file: {e}")
            sys.exit(1)
    
    def get_service_config(self, service: str) -> Dict[str, Any]:
        """Get configuration for specific service"""
        service_key = f"{service.lower()}_api"
        if service_key not in self.config:
            logging.error(f"Configuration for {service} not found")
            sys.exit(1)
        return self.config[service_key]
    
    def get_general_config(self) -> Dict[str, Any]:
        """Get general configuration settings"""
        return self.config.get("general", {})


class IPGeolocation:
    """IP Geolocation service using ip-api.com"""
    
    @staticmethod
    def get_location(ip_address: str) -> Dict[str, str]:
        """Get geolocation information for IP address"""
        try:
            # Skip private/local IP addresses
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                return {
                    'country': 'Private/Local',
                    'city': 'Private/Local',
                    'org': 'Private/Local Network'
                }
        except ValueError:
            return {'country': 'Unknown', 'city': 'Unknown', 'org': 'Unknown'}
        
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'org': data.get('org', 'Unknown')
                }
        except requests.RequestException:
            pass
        
        return {'country': 'Unknown', 'city': 'Unknown', 'org': 'Unknown'}


class SharePointDSPA:
    """SharePoint DSPA implementation using Microsoft Graph API"""
    
    def __init__(self, config: Dict[str, Any]):
        if not MSAL_AVAILABLE:
            raise ImportError("msal library not available. Install with: pip install msal")
        
        self.tenant_id = config['tenant_id']
        self.client_id = config['client_id']
        self.client_secret = config['client_secret']
        self.app = ConfidentialClientApplication(
            self.client_id,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
            client_credential=self.client_secret
        )
    
    def get_access_token(self) -> str:
        """Get access token for Microsoft Graph API"""
        result = self.app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        
        if "access_token" in result:
            return result["access_token"]
        else:
            raise Exception(f"Failed to acquire token: {result.get('error_description')}")
    
    def get_audit_logs(self, users: List[str], start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Retrieve SharePoint audit logs"""
        token = self.get_access_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        activities = []
        
        # Use Microsoft Graph Security API for audit logs
        url = "https://graph.microsoft.com/v1.0/security/alerts"
        
        # Note: This is a simplified implementation
        # Full implementation would use the appropriate Graph API endpoints
        # for SharePoint audit logs (which may require different permissions)
        
        logging.warning("SharePoint implementation requires specific Graph API permissions for audit logs")
        return activities


class GoogleDriveDSPA:
    """Google Drive DSPA implementation using Admin SDK Reports API"""
    
    def __init__(self, config: Dict[str, Any]):
        if not GOOGLE_AVAILABLE:
            raise ImportError("Google API libraries not available. Install with: pip install google-api-python-client google-auth")
        
        self.service_account_file = config['service_account_file']
        self.domain = config['domain']
        self.service = self._build_service()
    
    def _build_service(self):
        """Build Google Admin SDK Reports service"""
        credentials = ServiceAccountCredentials.from_service_account_file(
            self.service_account_file,
            scopes=['https://www.googleapis.com/auth/admin.reports.audit.readonly']
        )
        return build('admin', 'reports_v1', credentials=credentials)
    
    def get_audit_logs(self, users: List[str], start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Retrieve Google Drive audit logs"""
        activities = []
        
        try:
            # Get Drive activities
            results = self.service.activities().list(
                userKey='all' if 'ALL' in users else users[0],
                applicationName='drive',
                startTime=start_date.isoformat() + 'Z',
                endTime=end_date.isoformat() + 'Z'
            ).execute()
            
            for activity in results.get('items', []):
                for event in activity.get('events', []):
                    activities.append({
                        'datetime': activity.get('id', {}).get('time'),
                        'event_type': event.get('type'),
                        'activity_type': event.get('name'),
                        'user_name': activity.get('actor', {}).get('email'),
                        'ip_address': activity.get('ipAddress'),
                        'user_agent': activity.get('events', [{}])[0].get('parameters', {}).get('user_agent'),
                        'file_name': self._extract_file_name(event),
                        'file_path': self._extract_file_path(event)
                    })
        
        except Exception as e:
            logging.error(f"Error retrieving Google Drive logs: {e}")
        
        return activities
    
    def _extract_file_name(self, event: Dict[str, Any]) -> str:
        """Extract file name from event parameters"""
        parameters = event.get('parameters', [])
        for param in parameters:
            if param.get('name') == 'doc_title':
                return param.get('value', '')
        return ''
    
    def _extract_file_path(self, event: Dict[str, Any]) -> str:
        """Extract file path from event parameters"""
        parameters = event.get('parameters', [])
        for param in parameters:
            if param.get('name') == 'doc_id':
                return f"/drive/files/{param.get('value', '')}"
        return ''


class BoxDSPA:
    """Box DSPA implementation using Box Events API"""
    
    def __init__(self, config: Dict[str, Any]):
        if not BOX_AVAILABLE:
            raise ImportError("Box SDK not available. Install with: pip install boxsdk")
        
        oauth = OAuth2(
            client_id=config['client_id'],
            client_secret=config['client_secret'],
            access_token=config['access_token']
        )
        self.client = Client(oauth)
    
    def get_audit_logs(self, users: List[str], start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Retrieve Box audit logs"""
        activities = []
        
        try:
            # Get enterprise events
            events = self.client.events().get_enterprise_events(
                limit=500,
                created_after=start_date,
                created_before=end_date
            )
            
            for event in events:
                activities.append({
                    'datetime': event.created_at,
                    'event_type': event.event_type,
                    'activity_type': event.event_type,
                    'user_name': event.created_by.login if event.created_by else '',
                    'ip_address': event.ip_address,
                    'user_agent': getattr(event, 'user_agent', ''),
                    'file_name': event.source.name if event.source else '',
                    'file_path': self._get_file_path(event.source) if event.source else ''
                })
        
        except Exception as e:
            logging.error(f"Error retrieving Box logs: {e}")
        
        return activities
    
    def _get_file_path(self, source) -> str:
        """Get file path from Box source object"""
        try:
            if hasattr(source, 'path_collection'):
                path_parts = [entry.name for entry in source.path_collection.entries]
                path_parts.append(source.name)
                return '/' + '/'.join(path_parts)
        except:
            pass
        return f"/files/{source.id}" if hasattr(source, 'id') else ''


class DropboxDSPA:
    """Dropbox DSPA implementation using Team Log API"""
    
    def __init__(self, config: Dict[str, Any]):
        if not DROPBOX_AVAILABLE:
            raise ImportError("Dropbox SDK not available. Install with: pip install dropbox")
        
        self.client = dropbox.DropboxTeam(config['access_token'])
    
    def get_audit_logs(self, users: List[str], start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Retrieve Dropbox audit logs"""
        activities = []
        
        try:
            # Get team events
            time_range = TimeRange(start_time=start_date, end_time=end_date)
            events = self.client.team_log_get_events(GetEventsArg(time=time_range))
            
            for event in events.events:
                activities.append({
                    'datetime': event.timestamp,
                    'event_type': event.event_type._tag,
                    'activity_type': event.event_type._tag,
                    'user_name': self._extract_user_email(event),
                    'ip_address': getattr(event.origin, 'geo_location', {}).get('ip_address', ''),
                    'user_agent': '',  # Not available in Dropbox API
                    'file_name': self._extract_file_name(event),
                    'file_path': self._extract_file_path(event)
                })
        
        except Exception as e:
            logging.error(f"Error retrieving Dropbox logs: {e}")
        
        return activities
    
    def _extract_user_email(self, event) -> str:
        """Extract user email from event"""
        if hasattr(event, 'actor') and hasattr(event.actor, 'user'):
            return getattr(event.actor.user, 'email', '')
        return ''
    
    def _extract_file_name(self, event) -> str:
        """Extract file name from event"""
        # This would need to be implemented based on specific event types
        return ''
    
    def _extract_file_path(self, event) -> str:
        """Extract file path from event"""
        # This would need to be implemented based on specific event types
        return ''


class SuspiciousActivityAnalyzer:
    """Analyze activities for suspicious patterns"""
    
    def __init__(self):
        self.user_profiles = defaultdict(lambda: {
            'common_ips': Counter(),
            'common_hours': Counter(),
            'common_countries': Counter()
        })
    
    def analyze_activities(self, activities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze activities and identify suspicious patterns"""
        # Build user profiles
        self._build_user_profiles(activities)
        
        suspicious_activities = []
        
        for activity in activities:
            suspicion_reasons = []
            
            # Check for unusual IP addresses
            if self._is_unusual_ip(activity):
                suspicion_reasons.append("Unusual IP address")
            
            # Check for unusual time of access
            if self._is_unusual_time(activity):
                suspicion_reasons.append("Unusual access time")
            
            # Check for unusual location
            if self._is_unusual_location(activity):
                suspicion_reasons.append("Unusual geographic location")
            
            if suspicion_reasons:
                activity['suspicion_reasons'] = suspicion_reasons
                suspicious_activities.append(activity)
        
        return suspicious_activities
    
    def _build_user_profiles(self, activities: List[Dict[str, Any]]):
        """Build user behavior profiles"""
        for activity in activities:
            user = activity.get('user_name', '')
            if not user:
                continue
            
            # Track IP addresses
            ip = activity.get('ip_address', '')
            if ip:
                self.user_profiles[user]['common_ips'][ip] += 1
            
            # Track access hours
            try:
                dt = datetime.fromisoformat(activity.get('datetime', '').replace('Z', '+00:00'))
                hour = dt.hour
                self.user_profiles[user]['common_hours'][hour] += 1
            except:
                pass
            
            # Track countries (would need IP geolocation)
            geo_info = IPGeolocation.get_location(ip)
            country = geo_info.get('country', '')
            if country and country != 'Unknown':
                self.user_profiles[user]['common_countries'][country] += 1
    
    def _is_unusual_ip(self, activity: Dict[str, Any]) -> bool:
        """Check if IP address is unusual for user"""
        user = activity.get('user_name', '')
        ip = activity.get('ip_address', '')
        
        if not user or not ip or user not in self.user_profiles:
            return False
        
        common_ips = self.user_profiles[user]['common_ips']
        total_accesses = sum(common_ips.values())
        
        if total_accesses < 10:  # Not enough data
            return False
        
        ip_frequency = common_ips.get(ip, 0) / total_accesses
        return ip_frequency < 0.1  # Less than 10% of accesses
    
    def _is_unusual_time(self, activity: Dict[str, Any]) -> bool:
        """Check if access time is unusual for user"""
        user = activity.get('user_name', '')
        
        try:
            dt = datetime.fromisoformat(activity.get('datetime', '').replace('Z', '+00:00'))
            hour = dt.hour
        except:
            return False
        
        if not user or user not in self.user_profiles:
            return False
        
        common_hours = self.user_profiles[user]['common_hours']
        total_accesses = sum(common_hours.values())
        
        if total_accesses < 10:  # Not enough data
            return False
        
        # Consider unusual if outside normal business hours and rare for user
        if hour < 6 or hour > 22:  # Outside 6 AM - 10 PM
            hour_frequency = common_hours.get(hour, 0) / total_accesses
            return hour_frequency < 0.05  # Less than 5% of accesses
        
        return False
    
    def _is_unusual_location(self, activity: Dict[str, Any]) -> bool:
        """Check if geographic location is unusual for user"""
        user = activity.get('user_name', '')
        ip = activity.get('ip_address', '')
        
        if not user or not ip or user not in self.user_profiles:
            return False
        
        geo_info = IPGeolocation.get_location(ip)
        country = geo_info.get('country', '')
        
        if not country or country == 'Unknown':
            return False
        
        common_countries = self.user_profiles[user]['common_countries']
        total_accesses = sum(common_countries.values())
        
        if total_accesses < 10:  # Not enough data
            return False
        
        country_frequency = common_countries.get(country, 0) / total_accesses
        return country_frequency < 0.1  # Less than 10% of accesses


class DSPAReportGenerator:
    """Generate DSPA reports"""
    
    @staticmethod
    def generate_raw_report(activities: List[Dict[str, Any]], output_file: str):
        """Generate raw activity report"""
        if not activities:
            logging.warning("No activities to report")
            return
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'datetime', 'event_type', 'activity_type', 'user_name',
                'ip_address', 'country', 'city', 'organization',
                'user_agent', 'device_name', 'device_info',
                'application_name', 'app_id', 'file_path', 'file_name'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for activity in activities:
                # Add geolocation data
                ip = activity.get('ip_address', '')
                geo_info = IPGeolocation.get_location(ip)
                
                row = {
                    'datetime': activity.get('datetime', ''),
                    'event_type': activity.get('event_type', ''),
                    'activity_type': activity.get('activity_type', ''),
                    'user_name': activity.get('user_name', ''),
                    'ip_address': ip,
                    'country': geo_info.get('country', ''),
                    'city': geo_info.get('city', ''),
                    'organization': geo_info.get('org', ''),
                    'user_agent': activity.get('user_agent', ''),
                    'device_name': activity.get('device_name', ''),
                    'device_info': activity.get('device_info', ''),
                    'application_name': activity.get('application_name', ''),
                    'app_id': activity.get('app_id', ''),
                    'file_path': activity.get('file_path', ''),
                    'file_name': activity.get('file_name', '')
                }
                writer.writerow(row)
        
        logging.info(f"Raw report generated: {output_file}")
    
    @staticmethod
    def generate_suspicious_report(suspicious_activities: List[Dict[str, Any]], output_file: str):
        """Generate suspicious activity report"""
        if not suspicious_activities:
            logging.info("No suspicious activities detected")
            return
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'datetime', 'user_name', 'activity_type', 'ip_address',
                'country', 'city', 'organization', 'suspicion_reasons',
                'file_name', 'file_path'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for activity in suspicious_activities:
                ip = activity.get('ip_address', '')
                geo_info = IPGeolocation.get_location(ip)
                
                row = {
                    'datetime': activity.get('datetime', ''),
                    'user_name': activity.get('user_name', ''),
                    'activity_type': activity.get('activity_type', ''),
                    'ip_address': ip,
                    'country': geo_info.get('country', ''),
                    'city': geo_info.get('city', ''),
                    'organization': geo_info.get('org', ''),
                    'suspicion_reasons': '; '.join(activity.get('suspicion_reasons', [])),
                    'file_name': activity.get('file_name', ''),
                    'file_path': activity.get('file_path', '')
                }
                writer.writerow(row)
        
        logging.info(f"Suspicious activity report generated: {output_file}")


def parse_date(date_str: str) -> datetime:
    """Parse date string in MMDDYYYY format"""
    try:
        return datetime.strptime(date_str, '%m%d%Y')
    except ValueError:
        raise ValueError(f"Invalid date format: {date_str}. Use MMDDYYYY format.")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Unified Data Security Posture Activity (DSPA) Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python unified_dspa.py sharepoint -u user@domain.com -d 30
  python unified_dspa.py googledrive -u ALL --start-date 01012024 --end-date 01312024
  python unified_dspa.py box -u user1@domain.com,user2@domain.com -d 7
  python unified_dspa.py dropbox -u ALL -d 14
        """
    )
    
    parser.add_argument('service', choices=['sharepoint', 'googledrive', 'box', 'dropbox'],
                       help='Cloud service to analyze')
    parser.add_argument('-u', '--users', required=True,
                       help='Comma-separated list of user emails or "ALL" for all users')
    parser.add_argument('-d', '--days-back', type=int,
                       help='Number of days back to analyze')
    parser.add_argument('--start-date',
                       help='Start date in MMDDYYYY format')
    parser.add_argument('--end-date',
                       help='End date in MMDDYYYY format')
    parser.add_argument('-c', '--config', default='dspa_config.json',
                       help='Configuration file path (default: dspa_config.json)')
    parser.add_argument('-o', '--output-prefix', default='dspa_report',
                       help='Output file prefix (default: dspa_report)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Parse date range
    if args.days_back:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=args.days_back)
    elif args.start_date and args.end_date:
        start_date = parse_date(args.start_date)
        end_date = parse_date(args.end_date)
    else:
        # Default to last 30 days
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
    
    # Parse users
    users = [u.strip() for u in args.users.split(',')]
    
    # Load configuration
    config = DSPAConfig(args.config)
    
    # Initialize service handler
    service_handlers = {
        'sharepoint': SharePointDSPA,
        'googledrive': GoogleDriveDSPA,
        'box': BoxDSPA,
        'dropbox': DropboxDSPA
    }
    
    try:
        handler_class = service_handlers[args.service]
        service_config = config.get_service_config(args.service)
        handler = handler_class(service_config)
        
        logging.info(f"Starting DSPA analysis for {args.service}")
        logging.info(f"Date range: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
        logging.info(f"Users: {', '.join(users)}")
        
        # Get audit logs
        activities = handler.get_audit_logs(users, start_date, end_date)
        logging.info(f"Retrieved {len(activities)} activities")
        
        # Generate raw report
        raw_output = f"{args.output_prefix}_{args.service}_raw_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        DSPAReportGenerator.generate_raw_report(activities, raw_output)
        
        # Analyze for suspicious activities
        analyzer = SuspiciousActivityAnalyzer()
        suspicious_activities = analyzer.analyze_activities(activities)
        
        # Generate suspicious activity report
        suspicious_output = f"{args.output_prefix}_{args.service}_suspicious_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        DSPAReportGenerator.generate_suspicious_report(suspicious_activities, suspicious_output)
        
        logging.info(f"Analysis complete. Found {len(suspicious_activities)} suspicious activities.")
        
    except ImportError as e:
        logging.error(f"Missing required dependencies: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error during analysis: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()