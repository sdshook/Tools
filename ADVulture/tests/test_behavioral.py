# (c) 2025-2026 Shane D. Shook, PhD - All Rights Reserved

"""
Tests for the behavioral analysis module.
Validates detection logic for token replay, impossible travel, off-hours, etc.
"""

import pytest
from datetime import datetime, timezone, timedelta

from advulture.analysis.behavioral import (
    BehavioralAnalyzer,
    ServiceAccountAnalyzer,
    AuthEvent,
    BehavioralAnomaly,
    haversine_km,
)


class TestHaversine:
    """Test geographic distance calculation."""
    
    def test_same_location(self):
        """Same coordinates should return 0 distance."""
        assert haversine_km(40.7128, -74.0060, 40.7128, -74.0060) == 0
    
    def test_nyc_to_london(self):
        """NYC to London is approximately 5570 km."""
        distance = haversine_km(40.7128, -74.0060, 51.5074, -0.1278)
        assert 5500 < distance < 5700
    
    def test_nyc_to_la(self):
        """NYC to LA is approximately 3940 km."""
        distance = haversine_km(40.7128, -74.0060, 34.0522, -118.2437)
        assert 3900 < distance < 4000


class TestBehavioralAnalyzer:
    """Test the main BehavioralAnalyzer class."""
    
    @pytest.fixture
    def analyzer(self):
        return BehavioralAnalyzer()
    
    @pytest.fixture
    def base_time(self):
        return datetime(2026, 5, 26, 14, 0, 0, tzinfo=timezone.utc)  # 2pm UTC weekday
    
    def test_off_hours_detection_weekend(self, analyzer, base_time):
        """Weekend authentication should be flagged as off-hours."""
        # Saturday at 2pm
        saturday = base_time + timedelta(days=(5 - base_time.weekday()) % 7)
        
        events = [
            AuthEvent(
                timestamp=saturday + timedelta(hours=i),
                user_id="user1",
                user_name="user1@example.com",
                source_ip="192.168.1.1",
                result="success",
            )
            for i in range(6)  # 6 events to exceed threshold of 5
        ]
        
        anomalies = analyzer.detect_off_hours(events)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "OFF_HOURS_AUTH"
        assert anomalies[0].user == "user1@example.com"
    
    def test_off_hours_detection_late_night(self, analyzer, base_time):
        """Late night authentication (after 10pm) should be flagged."""
        late_night = base_time.replace(hour=23)  # 11pm
        
        events = [
            AuthEvent(
                timestamp=late_night + timedelta(minutes=i*10),
                user_id="user1",
                user_name="user1@example.com",
                source_ip="192.168.1.1",
                result="success",
            )
            for i in range(6)
        ]
        
        anomalies = analyzer.detect_off_hours(events)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "OFF_HOURS_AUTH"
    
    def test_off_hours_business_hours_not_flagged(self, analyzer, base_time):
        """Business hours authentication should not be flagged."""
        events = [
            AuthEvent(
                timestamp=base_time + timedelta(hours=i),
                user_id="user1",
                user_name="user1@example.com",
                source_ip="192.168.1.1",
                result="success",
            )
            for i in range(6)  # 2pm-7pm
        ]
        
        anomalies = analyzer.detect_off_hours(events)
        assert len(anomalies) == 0
    
    def test_ip_diversity_detection(self, analyzer, base_time):
        """User with 10+ distinct IPs should be flagged."""
        events = [
            AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                user_id="user1",
                user_name="user1@example.com",
                source_ip=f"192.168.1.{i}",
                result="success",
            )
            for i in range(12)  # 12 distinct IPs
        ]
        
        anomalies = analyzer.detect_ip_diversity(events)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "HIGH_IP_DIVERSITY"
        assert anomalies[0].evidence["ip_count"] == 12
    
    def test_ip_diversity_below_threshold(self, analyzer, base_time):
        """User with fewer than 10 IPs should not be flagged."""
        events = [
            AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                user_id="user1",
                user_name="user1@example.com",
                source_ip=f"192.168.1.{i}",
                result="success",
            )
            for i in range(5)  # Only 5 IPs
        ]
        
        anomalies = analyzer.detect_ip_diversity(events)
        assert len(anomalies) == 0
    
    def test_token_replay_detection(self, analyzer, base_time):
        """Same user+app from different IPs within window should be flagged."""
        events = [
            AuthEvent(
                timestamp=base_time,
                user_id="user1",
                user_name="user1@example.com",
                source_ip="192.168.1.1",
                target_resource="Office 365",
                result="success",
            ),
            AuthEvent(
                timestamp=base_time + timedelta(minutes=5),  # 5 minutes later
                user_id="user1",
                user_name="user1@example.com",
                source_ip="10.0.0.1",  # Different IP
                target_resource="Office 365",
                result="success",
            ),
        ]
        
        anomalies = analyzer.detect_token_replay(events)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "TOKEN_REPLAY"
        assert anomalies[0].severity == "CRITICAL"
    
    def test_token_replay_outside_window(self, analyzer, base_time):
        """Same user+app from different IPs outside window should not be flagged."""
        events = [
            AuthEvent(
                timestamp=base_time,
                user_id="user1",
                user_name="user1@example.com",
                source_ip="192.168.1.1",
                target_resource="Office 365",
                result="success",
            ),
            AuthEvent(
                timestamp=base_time + timedelta(minutes=30),  # 30 minutes later
                user_id="user1",
                user_name="user1@example.com",
                source_ip="10.0.0.1",
                target_resource="Office 365",
                result="success",
            ),
        ]
        
        anomalies = analyzer.detect_token_replay(events)
        assert len(anomalies) == 0
    
    def test_impossible_travel_detection(self, analyzer, base_time):
        """Travel faster than possible should be flagged."""
        events = [
            AuthEvent(
                timestamp=base_time,
                user_id="user1",
                user_name="user1@example.com",
                source_ip="1.1.1.1",
                result="success",
                location={"city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060},
            ),
            AuthEvent(
                timestamp=base_time + timedelta(hours=1),  # 1 hour later
                user_id="user1",
                user_name="user1@example.com",
                source_ip="2.2.2.2",
                result="success",
                # London - ~5500km from NYC, would require 5500 km/h to reach in 1 hour
                location={"city": "London", "country": "UK", "lat": 51.5074, "lon": -0.1278},
            ),
        ]
        
        anomalies = analyzer.detect_impossible_travel(events)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "IMPOSSIBLE_TRAVEL"
        assert anomalies[0].evidence["required_speed_kmh"] > 1000
    
    def test_impossible_travel_reasonable_speed(self, analyzer, base_time):
        """Travel at reasonable speed should not be flagged."""
        events = [
            AuthEvent(
                timestamp=base_time,
                user_id="user1",
                user_name="user1@example.com",
                source_ip="1.1.1.1",
                result="success",
                location={"city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060},
            ),
            AuthEvent(
                timestamp=base_time + timedelta(hours=8),  # 8 hours later
                user_id="user1",
                user_name="user1@example.com",
                source_ip="2.2.2.2",
                result="success",
                # London - reachable in 8 hours by plane
                location={"city": "London", "country": "UK", "lat": 51.5074, "lon": -0.1278},
            ),
        ]
        
        anomalies = analyzer.detect_impossible_travel(events)
        assert len(anomalies) == 0
    
    def test_lateral_movement_detection(self, analyzer, base_time):
        """Accessing many resources in short window should be flagged."""
        events = [
            AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                user_id="user1",
                user_name="user1@example.com",
                source_ip="192.168.1.1",
                target_resource=f"App{i}",
                result="success",
            )
            for i in range(7)  # 7 apps in 7 minutes
        ]
        
        anomalies = analyzer.detect_lateral_movement(events)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "LATERAL_MOVEMENT"
        assert anomalies[0].evidence["target_count"] == 7


class TestServiceAccountAnalyzer:
    """Test service account behavioral analysis."""
    
    @pytest.fixture
    def base_time(self):
        return datetime(2026, 5, 26, 14, 0, 0, tzinfo=timezone.utc)
    
    def test_identifies_service_accounts_by_pattern(self):
        """Should identify service accounts by naming patterns."""
        analyzer = ServiceAccountAnalyzer()
        
        assert analyzer.is_service_account("svc_backup")
        assert analyzer.is_service_account("MSOL_abc123")
        assert analyzer.is_service_account("sql_service")
        assert not analyzer.is_service_account("john.doe")
    
    def test_service_account_source_diversity(self, base_time):
        """Service account from many sources should be flagged."""
        analyzer = ServiceAccountAnalyzer(source_threshold=3)
        
        events = [
            AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                user_id="svc1",
                user_name="svc_backup",
                source_ip=f"192.168.1.{i}",
                result="success",
            )
            for i in range(5)  # 5 different sources
        ]
        
        anomalies = analyzer.analyze(events)
        source_diversity = [a for a in anomalies if a.anomaly_type == "SERVICE_ACCOUNT_SOURCE_DIVERSITY"]
        assert len(source_diversity) == 1
        assert source_diversity[0].severity == "HIGH"
    
    def test_service_account_interactive_logon(self, base_time):
        """Interactive logon by service account should be CRITICAL."""
        analyzer = ServiceAccountAnalyzer()
        
        events = [
            AuthEvent(
                timestamp=base_time,
                user_id="svc1",
                user_name="svc_backup",
                source_ip="192.168.1.1",
                result="success",
                is_interactive=True,
            ),
        ]
        
        anomalies = analyzer.analyze(events)
        interactive = [a for a in anomalies if a.anomaly_type == "SERVICE_ACCOUNT_INTERACTIVE"]
        assert len(interactive) == 1
        assert interactive[0].severity == "CRITICAL"


class TestAnalyzeAll:
    """Test the combined analyze_all method."""
    
    def test_analyze_all_returns_all_categories(self):
        """analyze_all should return dict with all anomaly categories."""
        analyzer = BehavioralAnalyzer()
        events = []  # Empty events
        
        results = analyzer.analyze_all(events)
        
        assert "off_hours" in results
        assert "ip_diversity" in results
        assert "token_replay" in results
        assert "impossible_travel" in results
        assert "lateral_movement" in results


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
