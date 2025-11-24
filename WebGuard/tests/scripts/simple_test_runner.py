#!/usr/bin/env python3
"""
Simple WebGuard Test Runner
Tests the WebGuard system using direct Rust compilation
"""

import subprocess
import json
import os
import sys
from pathlib import Path
import tempfile

class SimpleWebGuardTester:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent.parent
        self.results = []
        
    def run_single_test(self, payload, expected_threat=False):
        """Run a single test through WebGuard system"""
        try:
            # Create a simple Rust test program
            test_code = f'''
use webguard::simple_webguard::SimpleWebGuardSystem;

fn main() {{
    let mut system = SimpleWebGuardSystem::new();
    let payload = r#"{payload.replace('"', '\\"')}"#;
    let result = system.analyze_request(payload);
    
    println!("{{}}|{{:.3}}|{{}}", result.is_threat, result.confidence, result.threat_type.unwrap_or_else(|| "None".to_string()));
}}
'''
            
            # Write test file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rs', delete=False) as f:
                f.write(test_code)
                test_file = f.name
            
            try:
                # Compile and run
                result = subprocess.run([
                    'rustc', '--edition', '2021', 
                    '-L', str(self.base_dir / "target" / "debug" / "deps"),
                    '--extern', f'webguard={self.base_dir}/target/debug/libwebguard.rlib',
                    test_file, '-o', test_file.replace('.rs', '')
                ], capture_output=True, text=True, cwd=self.base_dir)
                
                if result.returncode != 0:
                    print(f"Compilation failed: {result.stderr}")
                    return None
                
                # Run the test
                run_result = subprocess.run([test_file.replace('.rs', '')], 
                                          capture_output=True, text=True, cwd=self.base_dir)
                
                if run_result.returncode == 0:
                    output = run_result.stdout.strip()
                    parts = output.split('|')
                    if len(parts) >= 3:
                        is_threat = parts[0] == 'true'
                        confidence = float(parts[1])
                        threat_type = parts[2] if parts[2] != 'None' else None
                        
                        return {
                            'payload': payload,
                            'expected_threat': expected_threat,
                            'detected_threat': is_threat,
                            'confidence': confidence,
                            'threat_type': threat_type,
                            'correct': is_threat == expected_threat
                        }
                else:
                    print(f"Runtime error: {run_result.stderr}")
                    return None
                    
            finally:
                # Clean up
                try:
                    os.unlink(test_file)
                    os.unlink(test_file.replace('.rs', ''))
                except:
                    pass
                    
        except Exception as e:
            print(f"Test error: {e}")
            return None
    
    def run_comprehensive_tests(self):
        """Run comprehensive test suite"""
        print("🚀 Starting Simple WebGuard Test Suite...")
        
        # Build the library first
        print("🔨 Building WebGuard library...")
        build_result = subprocess.run(['cargo', 'build', '--lib'], 
                                    cwd=self.base_dir, capture_output=True, text=True)
        
        if build_result.returncode != 0:
            print(f"❌ Build failed: {build_result.stderr}")
            return False
        
        print("✅ Build successful")
        
        # Test cases
        threat_samples = [
            "' OR '1'='1",
            "<script>alert('xss')</script>",
            "../../etc/passwd",
            "'; DROP TABLE users; --",
            "%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E",
            "admin'--",
            "../../../windows/system32/config/sam",
            "javascript:alert('xss')",
            "1' UNION SELECT * FROM users--",
            "<img src=x onerror=alert('xss')>"
        ]
        
        benign_samples = [
            "hello world",
            "user@example.com",
            "search query",
            "normal text input",
            "123456",
            "product name",
            "category filter",
            "date: 2024-01-01",
            "price: $19.99",
            "description text"
        ]
        
        print(f"🎯 Testing {len(threat_samples)} threat samples...")
        threat_results = []
        for payload in threat_samples:
            result = self.run_single_test(payload, expected_threat=True)
            if result:
                threat_results.append(result)
                status = "✅" if result['correct'] else "❌"
                print(f"{status} Threat: {payload[:50]}... -> {result['detected_threat']} ({result['confidence']:.3f})")
        
        print(f"🌐 Testing {len(benign_samples)} benign samples...")
        benign_results = []
        for payload in benign_samples:
            result = self.run_single_test(payload, expected_threat=False)
            if result:
                benign_results.append(result)
                status = "✅" if result['correct'] else "❌"
                print(f"{status} Benign: {payload[:50]}... -> {result['detected_threat']} ({result['confidence']:.3f})")
        
        # Calculate metrics
        all_results = threat_results + benign_results
        if not all_results:
            print("❌ No test results available")
            return False
        
        correct = sum(1 for r in all_results if r['correct'])
        total = len(all_results)
        accuracy = correct / total
        
        # Threat detection metrics
        threat_detected = sum(1 for r in threat_results if r['detected_threat'])
        threat_total = len(threat_results)
        threat_detection_rate = threat_detected / threat_total if threat_total > 0 else 0
        
        # False positive rate
        false_positives = sum(1 for r in benign_results if r['detected_threat'])
        benign_total = len(benign_results)
        false_positive_rate = false_positives / benign_total if benign_total > 0 else 0
        
        print("\n" + "="*60)
        print("📊 TEST RESULTS SUMMARY")
        print("="*60)
        print(f"Total Tests: {total}")
        print(f"Correct Predictions: {correct}")
        print(f"Overall Accuracy: {accuracy:.1%}")
        print(f"Threat Detection Rate: {threat_detection_rate:.1%}")
        print(f"False Positive Rate: {false_positive_rate:.1%}")
        print("="*60)
        
        # Success criteria
        success = accuracy >= 0.7 and threat_detection_rate >= 0.5
        if success:
            print("🎉 Tests PASSED!")
        else:
            print("❌ Tests FAILED - Need improvement")
        
        return success

def main():
    tester = SimpleWebGuardTester()
    success = tester.run_comprehensive_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()