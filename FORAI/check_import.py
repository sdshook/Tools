#!/usr/bin/env python3
"""
Check Import Status Script
Checks the status of database import and shows sample records
"""

import sqlite3
import sys
from pathlib import Path

def check_database(db_path):
    """Check database contents"""
    if not db_path.exists():
        print(f"❌ Database not found: {db_path}")
        return
    
    print(f"🔍 Checking database: {db_path}")
    print(f"📊 File size: {db_path.stat().st_size / 1024 / 1024:.1f} MB")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check total records
        cursor.execute("SELECT COUNT(*) FROM evidence")
        total_records = cursor.fetchone()[0]
        print(f"📈 Total records: {total_records:,}")
        
        if total_records > 0:
            # Check flagged records
            cursor.execute("SELECT COUNT(*) FROM evidence WHERE flagged = 1")
            flagged_records = cursor.fetchone()[0]
            print(f"🚩 Flagged records: {flagged_records:,}")
            
            # Check data types
            cursor.execute("SELECT source, COUNT(*) FROM evidence GROUP BY source ORDER BY COUNT(*) DESC LIMIT 10")
            sources = cursor.fetchall()
            print(f"\n📊 Top data sources:")
            for source, count in sources:
                print(f"  {source}: {count:,}")
            
            # Show sample records
            cursor.execute("SELECT timestamp, source, message FROM evidence LIMIT 5")
            samples = cursor.fetchall()
            print(f"\n📋 Sample records:")
            for i, (timestamp, source, message) in enumerate(samples, 1):
                print(f"  {i}. [{source}] {message[:100]}{'...' if len(message) > 100 else ''}")
            
            # Check keywords
            cursor.execute("SELECT COUNT(*) FROM keywords")
            keyword_count = cursor.fetchone()[0]
            print(f"\n🔑 Keywords loaded: {keyword_count}")
            
            if keyword_count > 0:
                cursor.execute("SELECT keyword FROM keywords LIMIT 5")
                keywords = cursor.fetchall()
                print(f"📝 Sample keywords: {', '.join([k[0] for k in keywords])}")
        
    except Exception as e:
        print(f"❌ Error checking database: {e}")
    
    finally:
        conn.close()

def main():
    if len(sys.argv) != 2:
        print("Usage: python check_import.py <case_id>")
        print("Example: python check_import.py CASE001")
        sys.exit(1)
    
    case_id = sys.argv[1]
    
    # Check both databases
    bhsm_db = Path(f"{case_id}_bhsm.db")
    forai_db = Path("forai.db")
    
    print(f"🔍 Checking import status for case {case_id}\n")
    
    check_database(bhsm_db)
    print()
    check_database(forai_db)

if __name__ == "__main__":
    main()