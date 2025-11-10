#!/usr/bin/env python3
"""
Streaming JSON Timeline Import Script for FORAI
Handles large, potentially malformed JSON files by streaming and parsing incrementally
"""

import json
import sqlite3
import sys
import re
from pathlib import Path
from datetime import datetime
import hashlib

def create_database_schema(db_path):
    """Create the FORAI database schema"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create evidence table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            timestamp TEXT,
            datetime_utc TEXT,
            source TEXT,
            source_long TEXT,
            message TEXT,
            parser TEXT,
            display_name TEXT,
            filename TEXT,
            inode TEXT,
            notes TEXT,
            format TEXT,
            extra TEXT,
            sha256_hash TEXT,
            artifact_type TEXT,
            flagged INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_evidence_timestamp ON evidence(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_evidence_source ON evidence(source)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_evidence_flagged ON evidence(flagged)')
    
    # Create keywords table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            keyword TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print(f"✅ Database schema created: {db_path}")

def extract_json_events(file_path):
    """Extract JSON events from file using regex pattern matching"""
    print(f"🔍 Streaming JSON file: {file_path}")
    
    # Pattern to match event entries
    event_pattern = re.compile(r'"event_(\d+)":\s*({[^}]*(?:{[^}]*}[^}]*)*})')
    
    events_found = 0
    chunk_size = 1024 * 1024  # 1MB chunks
    buffer = ""
    
    with open(file_path, 'r', encoding='utf-8') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
                
            buffer += chunk
            
            # Find all complete event matches in buffer
            matches = list(event_pattern.finditer(buffer))
            
            if matches:
                # Process all complete matches
                last_end = 0
                for match in matches:
                    event_num = match.group(1)
                    event_json = match.group(2)
                    
                    try:
                        event_data = json.loads(event_json)
                        yield f"event_{event_num}", event_data
                        events_found += 1
                        
                        if events_found % 10000 == 0:
                            print(f"📈 Extracted {events_found:,} events...")
                            
                    except json.JSONDecodeError as e:
                        print(f"⚠️  JSON error in event_{event_num}: {e}")
                        continue
                    
                    last_end = match.end()
                
                # Keep unprocessed part of buffer
                buffer = buffer[last_end:]
    
    print(f"✅ Total events extracted: {events_found:,}")

def import_json_timeline_streaming(json_path, db_path, case_id):
    """Import JSON timeline using streaming approach"""
    print(f"📥 Importing JSON timeline: {json_path}")
    print(f"📊 File size: {json_path.stat().st_size / 1024 / 1024:.1f} MB")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    imported_count = 0
    batch_size = 1000
    batch = []
    
    try:
        for event_key, event_data in extract_json_events(json_path):
            try:
                # Extract fields from plaso JSON event structure
                timestamp = str(event_data.get('timestamp', ''))
                
                # Convert timestamp to readable datetime if it's a WebKit timestamp
                datetime_utc = ''
                if timestamp and timestamp != '0' and timestamp != '-11644473600000000':
                    try:
                        # Convert WebKit timestamp to Unix timestamp
                        webkit_ts = int(timestamp)
                        if webkit_ts > 0:
                            unix_ts = (webkit_ts / 1000000) - 11644473600
                            datetime_utc = datetime.fromtimestamp(unix_ts).isoformat()
                    except:
                        pass
                
                source = event_data.get('data_type', '')
                source_long = event_data.get('parser', '')
                message = event_data.get('message', '')
                parser = event_data.get('parser', '')
                display_name = event_data.get('display_name', '')
                filename = event_data.get('filename', '')
                inode = event_data.get('inode', '')
                format_type = event_data.get('data_type', '')
                
                # Store additional data as JSON
                extra_data = {
                    'host': event_data.get('host', ''),
                    'url': event_data.get('url', ''),
                    'cookie_name': event_data.get('cookie_name', ''),
                    'timestamp_desc': event_data.get('timestamp_desc', ''),
                    'md5_hash': event_data.get('md5_hash', ''),
                    'pathspec': event_data.get('pathspec', {}),
                    'query': event_data.get('query', '')
                }
                extra = json.dumps(extra_data)
                
                # Create SHA256 hash of the entry
                entry_str = f"{timestamp}{source}{message}{filename}"
                sha256_hash = hashlib.sha256(entry_str.encode()).hexdigest()[:16]
                
                batch.append((
                    case_id, timestamp, datetime_utc, source, source_long,
                    message, parser, display_name, filename, inode,
                    '', format_type, extra, sha256_hash, 'timeline', 0
                ))
                
                if len(batch) >= batch_size:
                    cursor.executemany('''
                        INSERT INTO evidence (
                            case_id, timestamp, datetime_utc, source, source_long,
                            message, parser, display_name, filename, inode,
                            notes, format, extra, sha256_hash, artifact_type, flagged
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', batch)
                    conn.commit()
                    imported_count += len(batch)
                    batch = []
                    
                    if imported_count % 50000 == 0:
                        print(f"💾 Imported {imported_count:,} records...")
                    
            except Exception as e:
                print(f"⚠️  Warning: Error processing event {event_key}: {e}")
                continue
        
        # Insert remaining batch
        if batch:
            cursor.executemany('''
                INSERT INTO evidence (
                    case_id, timestamp, datetime_utc, source, source_long,
                    message, parser, display_name, filename, inode,
                    notes, format, extra, sha256_hash, artifact_type, flagged
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', batch)
            conn.commit()
            imported_count += len(batch)
    
    finally:
        conn.close()
    
    print(f"✅ Import completed: {imported_count:,} records imported")
    return imported_count

def inject_keywords(db_path, case_id, keywords_file):
    """Inject keywords into database"""
    if not keywords_file.exists():
        print(f"⚠️  Keywords file not found: {keywords_file}")
        return
    
    keywords = []
    with open(keywords_file, 'r', encoding='utf-8') as f:
        for line in f:
            keyword = line.strip()
            if keyword and not keyword.startswith('#'):
                keywords.append(keyword.lower())
    
    if not keywords:
        print("⚠️  No keywords found")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Insert keywords
    for keyword in keywords:
        cursor.execute('INSERT INTO keywords (case_id, keyword) VALUES (?, ?)', (case_id, keyword))
    
    # Flag evidence containing keywords
    flagged_count = 0
    for keyword in keywords:
        cursor.execute('''
            UPDATE evidence 
            SET flagged = 1 
            WHERE case_id = ? AND (
                LOWER(message) LIKE ? OR 
                LOWER(source) LIKE ? OR 
                LOWER(filename) LIKE ?
            )
        ''', (case_id, f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'))
        flagged_count += cursor.rowcount
    
    conn.commit()
    conn.close()
    
    print(f"✅ Keywords injected: {len(keywords)} keywords, {flagged_count} records flagged")

def main():
    if len(sys.argv) != 4:
        print("Usage: python streaming_import.py <json_file> <case_id> <keywords_file>")
        print("Example: python streaming_import.py CASE001_timeline.json CASE001 keywords.txt")
        sys.exit(1)
    
    json_file = Path(sys.argv[1])
    case_id = sys.argv[2]
    keywords_file = Path(sys.argv[3])
    
    if not json_file.exists():
        print(f"❌ JSON file not found: {json_file}")
        sys.exit(1)
    
    # Create database paths
    bhsm_db = json_file.parent / f"{case_id}_bhsm.db"
    forai_db = json_file.parent / "forai.db"
    
    print(f"🚀 Starting streaming import for case {case_id}")
    print(f"📁 JSON file: {json_file}")
    print(f"🗄️  BHSM database: {bhsm_db}")
    print(f"🗄️  FORAI database: {forai_db}")
    
    # Create databases
    create_database_schema(bhsm_db)
    create_database_schema(forai_db)
    
    # Import timeline using streaming approach
    count = import_json_timeline_streaming(json_file, bhsm_db, case_id)
    
    # Copy to forai.db as well
    import shutil
    shutil.copy2(bhsm_db, forai_db)
    
    # Inject keywords
    inject_keywords(bhsm_db, case_id, keywords_file)
    inject_keywords(forai_db, case_id, keywords_file)
    
    print(f"\n🎉 Streaming import completed successfully!")
    print(f"📊 Total records: {count:,}")
    print(f"🗄️  Database size: {bhsm_db.stat().st_size / 1024 / 1024:.1f} MB")
    print(f"\n✅ Ready for autonomous analysis!")

if __name__ == "__main__":
    main()