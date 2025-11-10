#!/usr/bin/env python3
"""
JSON Timeline Diagnostic Script
Analyzes the structure of plaso JSON timeline files
"""

import json
import sys
from pathlib import Path

def analyze_json_file(json_path):
    """Analyze the structure of a JSON timeline file"""
    print(f"🔍 Analyzing JSON file: {json_path}")
    print(f"📊 File size: {json_path.stat().st_size / 1024 / 1024:.1f} MB")
    
    # Read first few lines to understand structure
    with open(json_path, 'r', encoding='utf-8') as f:
        print("\n📋 First 10 lines:")
        for i in range(10):
            try:
                line = f.readline().strip()
                if not line:
                    break
                print(f"Line {i+1}: {line[:200]}{'...' if len(line) > 200 else ''}")
                
                # Try to parse as JSON
                if i < 3:  # Only try parsing first 3 lines
                    try:
                        parsed = json.loads(line)
                        print(f"  ✅ Valid JSON - Keys: {list(parsed.keys())}")
                        if i == 0:  # Show full structure of first entry
                            print(f"  📝 Sample structure:")
                            for key, value in parsed.items():
                                if isinstance(value, str) and len(value) > 100:
                                    print(f"    {key}: {str(value)[:100]}...")
                                else:
                                    print(f"    {key}: {value}")
                    except json.JSONDecodeError as e:
                        print(f"  ❌ JSON parse error: {e}")
                        
            except Exception as e:
                print(f"  ⚠️  Error reading line {i+1}: {e}")
                break
    
    # Check if it's a single JSON array
    print("\n🔍 Checking if file is a single JSON array...")
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            first_char = f.read(1)
            if first_char == '[':
                print("  ✅ File starts with '[' - might be a JSON array")
            else:
                print(f"  ℹ️  File starts with '{first_char}' - likely JSONL format")
    except Exception as e:
        print(f"  ⚠️  Error checking file start: {e}")
    
    # Count total lines
    print("\n📊 Counting total lines...")
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            line_count = sum(1 for _ in f)
        print(f"  📈 Total lines: {line_count:,}")
    except Exception as e:
        print(f"  ⚠️  Error counting lines: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python json_diagnostic.py <json_file>")
        print("Example: python json_diagnostic.py CASE001_timeline.json")
        sys.exit(1)
    
    json_file = Path(sys.argv[1])
    
    if not json_file.exists():
        print(f"❌ JSON file not found: {json_file}")
        sys.exit(1)
    
    analyze_json_file(json_file)

if __name__ == "__main__":
    main()