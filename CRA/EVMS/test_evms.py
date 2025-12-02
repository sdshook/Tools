#!/usr/bin/env python3
"""
EVMS Test Suite
Basic tests to validate EVMS functionality
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from evms import (
    ToolManager, CVEDatabase, VulnerabilityPrioritizer, 
    Vulnerability, ScanResult, EVMSScanner
)

class TestToolManager(unittest.TestCase):
    """Test ToolManager functionality"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.tools = ToolManager(self.temp_dir)
    
    def test_check_tools(self):
        """Test tool availability checking"""
        status = self.tools.check_tools()
        
        # Should return status for all tools
        expected_tools = ['masscan', 'nuclei', 'httpx', 'subfinder', 'zeek']
        for tool in expected_tools:
            self.assertIn(tool, status)
            self.assertIsInstance(status[tool], bool)
    
    def test_tool_paths(self):
        """Test tool path configuration"""
        self.assertTrue(self.tools.tools['masscan'].name == 'masscan')
        self.assertTrue(self.tools.tools['nuclei'].name == 'nuclei')

class TestCVEDatabase(unittest.TestCase):
    """Test CVE database functionality"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cve_db = CVEDatabase(self.temp_dir)
    
    def test_database_initialization(self):
        """Test database initialization"""
        self.assertTrue(self.cve_db.db_path.exists())
    
    def test_cve_storage(self):
        """Test CVE data storage and retrieval"""
        # Mock CVE data
        test_cve = {
            'cve': {
                'id': 'CVE-2023-12345',
                'descriptions': [{'lang': 'en', 'value': 'Test vulnerability'}],
                'metrics': {
                    'cvssMetricV31': [{
                        'cvssData': {
                            'baseScore': 9.8,
                            'baseSeverity': 'CRITICAL'
                        }
                    }]
                },
                'published': '2023-01-01T00:00:00.000',
                'lastModified': '2023-01-01T00:00:00.000'
            }
        }
        
        # Store test data
        asyncio.run(self.cve_db.store_cve_data([test_cve]))
        
        # Retrieve and verify
        cve_info = self.cve_db.get_cve_info('CVE-2023-12345')
        self.assertIsNotNone(cve_info)
        self.assertEqual(cve_info['cve_id'], 'CVE-2023-12345')
        self.assertEqual(cve_info['cvss_score'], 9.8)
        self.assertEqual(cve_info['severity'], 'CRITICAL')

class TestVulnerabilityPrioritizer(unittest.TestCase):
    """Test vulnerability prioritization logic"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cve_db = CVEDatabase(self.temp_dir)
        
        # Mock GraphRL engine
        self.graph_engine = Mock()
        self.graph_engine.get_network_context.return_value = {
            'asset_count': 5,  # Multiple assets for lateral movement
            'assets': ['192.168.1.1', '192.168.1.2'],
            'avg_risk_score': 7.5
        }
        
        self.prioritizer = VulnerabilityPrioritizer(self.cve_db, self.graph_engine)
    
    def test_critical_priority(self):
        """Test critical priority assignment"""
        # Mock exploit availability
        self.cve_db.check_exploit_availability = Mock(return_value=(True, 'functional'))
        
        vuln = Vulnerability(
            cve_id='CVE-2023-12345',
            cvss_score=9.8,
            severity='CRITICAL',
            description='Critical vulnerability',
            exploit_available=True,
            exploit_maturity='functional',
            affected_service='apache',
            target='192.168.1.1',
            port=80
        )
        
        priority = self.prioritizer.prioritize_vulnerability(vuln, '192.168.1.1')
        self.assertEqual(priority, 'Critical')
    
    def test_high_priority(self):
        """Test high priority assignment"""
        self.cve_db.check_exploit_availability = Mock(return_value=(True, 'proof-of-concept'))
        
        vuln = Vulnerability(
            cve_id='CVE-2023-12346',
            cvss_score=6.5,
            severity='MEDIUM',
            description='Medium vulnerability',
            exploit_available=True,
            exploit_maturity='proof-of-concept',
            affected_service='nginx',
            target='192.168.1.1',
            port=443
        )
        
        priority = self.prioritizer.prioritize_vulnerability(vuln, '192.168.1.1')
        self.assertEqual(priority, 'High')
    
    def test_low_priority_weak_config(self):
        """Test low priority for weak configurations"""
        self.cve_db.check_exploit_availability = Mock(return_value=(False, 'none'))
        
        vuln = Vulnerability(
            cve_id='CVE-2023-12347',
            cvss_score=3.0,
            severity='LOW',
            description='Weak RDP configuration',
            exploit_available=False,
            exploit_maturity='none',
            affected_service='rdp',
            target='192.168.1.1',
            port=3389
        )
        
        priority = self.prioritizer.prioritize_vulnerability(vuln, '192.168.1.1')
        self.assertEqual(priority, 'Low')

class TestEVMSIntegration(unittest.IsolatedAsyncioTestCase):
    """Integration tests for EVMS components"""
    
    async def test_scan_workflow(self):
        """Test complete scan workflow"""
        # Mock configuration
        config = {
            'tools_dir': tempfile.mkdtemp(),
            'data_dir': tempfile.mkdtemp(),
            'neo4j_uri': 'bolt://localhost:7687',
            'neo4j_user': 'neo4j',
            'neo4j_password': 'password',
            'nats_url': 'nats://localhost:4222',
            'openai_api_key': 'test-key'
        }
        
        # Create scanner with mocked components
        scanner = EVMSScanner(config)
        
        # Mock tool outputs
        scanner.tools.run_masscan = AsyncMock(return_value=[
            {'ip': '192.168.1.1', 'port': 80, 'protocol': 'tcp', 'status': 'open'}
        ])
        
        scanner.tools.run_nuclei = AsyncMock(return_value=[
            {
                'template-id': 'apache-version',
                'info': {
                    'name': 'Apache Version Detection',
                    'severity': 'info',
                    'description': 'Apache version detected'
                },
                'matched-at': 'http://192.168.1.1:80'
            }
        ])
        
        scanner.tools.run_httpx = AsyncMock(return_value=[
            {
                'url': 'http://192.168.1.1:80',
                'status_code': 200,
                'title': 'Apache Test Page',
                'tech': ['Apache']
            }
        ])
        
        # Mock database operations
        scanner.graph_engine.store_scan_results = Mock()
        scanner.cve_db.update_cve_feeds = AsyncMock()
        
        # Mock NATS
        scanner.nats_client = Mock()
        scanner.js_context = Mock()
        scanner.js_context.publish = AsyncMock()
        
        # Test target type detection
        self.assertEqual(scanner.detect_target_type('192.168.1.1'), 'ip')
        self.assertEqual(scanner.detect_target_type('192.168.1.0/24'), 'cidr')
        self.assertEqual(scanner.detect_target_type('example.com'), 'domain')
        self.assertEqual(scanner.detect_target_type('AS15169'), 'asn')

class TestReportGeneration(unittest.TestCase):
    """Test report generation functionality"""
    
    def test_json_report_structure(self):
        """Test JSON report structure"""
        # Create test scan result
        vuln = Vulnerability(
            cve_id='CVE-2023-12345',
            cvss_score=7.5,
            severity='HIGH',
            description='Test vulnerability',
            exploit_available=True,
            exploit_maturity='functional',
            affected_service='apache',
            target='192.168.1.1',
            port=80
        )
        
        scan_result = ScanResult(
            target='192.168.1.1',
            timestamp=asyncio.get_event_loop().time(),
            open_ports=[{'port': 80, 'protocol': 'tcp'}],
            services=[{'service': 'apache', 'version': '2.4.41'}],
            vulnerabilities=[vuln],
            risk_assessment={'total_score': 7.5, 'risk_level': 'High'},
            lateral_movement_potential=True,
            priority='High'
        )
        
        # Test report data structure
        report_data = {
            'target': scan_result.target,
            'priority': scan_result.priority,
            'vulnerabilities': len(scan_result.vulnerabilities),
            'risk_score': scan_result.risk_assessment['total_score']
        }
        
        self.assertEqual(report_data['target'], '192.168.1.1')
        self.assertEqual(report_data['priority'], 'High')
        self.assertEqual(report_data['vulnerabilities'], 1)
        self.assertEqual(report_data['risk_score'], 7.5)

def run_tests():
    """Run all tests"""
    print("Running EVMS Test Suite...")
    print("=" * 50)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestToolManager))
    suite.addTests(loader.loadTestsFromTestCase(TestCVEDatabase))
    suite.addTests(loader.loadTestsFromTestCase(TestVulnerabilityPrioritizer))
    suite.addTests(loader.loadTestsFromTestCase(TestEVMSIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestReportGeneration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 50)
    if result.wasSuccessful():
        print("✅ All tests passed!")
    else:
        print(f"❌ {len(result.failures)} failures, {len(result.errors)} errors")
        
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)