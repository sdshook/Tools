#!/usr/bin/env python3
"""
EVMS - Enterprise Vulnerability Management Scanner
(c) Shane D. Shook, PhD, 2025 All Rights Reserved

A streamlined, single-script vulnerability management solution with:
- Automated discovery and scanning (masscan, nuclei, httpx, subfinder, zeek)
- GraphDB with Ensemble ML for intelligent vulnerability prioritization
- LLM/RAG deterministic analysis
- Simple web interface for control and reporting
- CVE/TIP feed integration
- Intelligent prioritization based on exploit availability and lateral movement
"""

import asyncio
import csv
import io
import json
import logging
import os
import platform
import re
import sys
import subprocess
import threading

import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import argparse
import ipaddress
import socket
import requests
from dataclasses import dataclass, asdict

import sqlite3


# Web framework and async support
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
import asyncio
import aiohttp


# Graph database and ML
try:
    import neo4j
except ImportError:
    neo4j = None
try:
    import numpy as np
    from sklearn.preprocessing import StandardScaler
except ImportError:
    np = None
    StandardScaler = None

try:
    from sklearn.ensemble import RandomForestClassifier
except ImportError:
    RandomForestClassifier = None
try:
    import xgboost as xgb
except ImportError:
    xgb = None
try:
    import lightgbm as lgb
except ImportError:
    lgb = None


# Simple event system for internal coordination
from collections import defaultdict

# LLM integration
try:
    import openai
except ImportError:
    openai = None
try:
    from sentence_transformers import SentenceTransformer
except ImportError:
    SentenceTransformer = None

# Report generation
from jinja2 import Template
try:
    import pdfkit
except ImportError:
    pdfkit = None
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('evms.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('EVMS')

class SimpleEventBus:
    """Lightweight event system for single-process EVMS"""
    
    def __init__(self):
        self.subscribers = defaultdict(list)
    
    def subscribe(self, event_type: str, callback):
        """Subscribe to an event type"""
        self.subscribers[event_type].append(callback)
        logger.debug(f"Subscribed to event: {event_type}")
    
    def publish(self, event_type: str, data: Any):
        """Publish an event to all subscribers"""
        logger.debug(f"Publishing event: {event_type}")
        for callback in self.subscribers[event_type]:
            try:
                if asyncio.iscoroutinefunction(callback):
                    asyncio.create_task(callback(data))
                else:
                    callback(data)
            except Exception as e:
                logger.error(f"Event callback error for {event_type}: {e}")
    
    def unsubscribe(self, event_type: str, callback):
        """Unsubscribe from an event type"""
        if callback in self.subscribers[event_type]:
            self.subscribers[event_type].remove(callback)

# Global event bus instance
event_bus = SimpleEventBus()

@dataclass
class ScanTarget:
    """Represents a scan target (IP, CIDR, domain, etc.)"""
    target: str
    target_type: str  # 'ip', 'cidr', 'domain', 'asn'
    ports: List[int] = None
    services: Dict[str, Any] = None
    vulnerabilities: List[Dict] = None
    risk_score: float = 0.0
    priority: str = 'Low'
    
@dataclass
class Vulnerability:
    """Represents a discovered vulnerability"""
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    exploit_available: bool
    exploit_maturity: str
    affected_service: str
    target: str
    port: int
    remediation: str = ""
    references: List[str] = None

@dataclass
class ScanResult:
    """Complete scan results for a target"""
    target: str
    timestamp: datetime
    open_ports: List[Dict]
    services: List[Dict]
    vulnerabilities: List[Vulnerability]
    risk_assessment: Dict
    lateral_movement_potential: bool
    priority: str

class ToolManager:
    """Manages external security tools"""
    
    def __init__(self, tools_dir: Path):
        self.tools_dir = Path(tools_dir)
        self.is_windows = platform.system().lower() == 'windows'
        
        # Configure tools based on platform
        self.tools = {
            'nuclei': self.tools_dir / 'nuclei' / 'nuclei',
            'httpx': self.tools_dir / 'httpx' / 'httpx',
            'subfinder': self.tools_dir / 'subfinder' / 'subfinder',
            'zeek': self.tools_dir / 'zeek' / 'bin' / 'zeek'
        }
        
        # Platform-specific port scanner configuration
        if self.is_windows:
            # Use nmap on Windows (masscan not available)
            self.tools['nmap'] = 'nmap'  # Assume nmap is in PATH after installation
            self.port_scanner = 'nmap'
        else:
            # Use masscan on Linux/Unix
            self.tools['masscan'] = self.tools_dir / 'masscan' / 'bin' / 'masscan'
            self.port_scanner = 'masscan'
        
    def check_tools(self) -> Dict[str, bool]:
        """Check if required tools are available"""
        status = {}
        for tool, path in self.tools.items():
            if tool == 'nmap':
                # Check if nmap is available in PATH
                try:
                    result = subprocess.run(['nmap', '--version'], 
                                          capture_output=True, text=True, timeout=5)
                    status[tool] = result.returncode == 0
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    status[tool] = False
                if not status[tool]:
                    logger.warning(f"Required tool {tool} not found in PATH")
            elif tool == 'zeek':  # Optional
                status[tool] = path.exists()
            else:  # Required
                status[tool] = path.exists()
                if not status[tool]:
                    logger.warning(f"Required tool {tool} not found at {path}")
        return status
    
    async def run_masscan(self, target: str, ports: str = "1-65535", rate: int = 1000) -> List[Dict]:
        """Run masscan for port discovery"""
        cmd = [
            str(self.tools['masscan']),
            target,
            '-p', ports,
            '--rate', str(rate),
            '--output-format', 'json',
            '--output-filename', '-'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                # Parse masscan JSON output
                open_ports = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            port_data = json.loads(line)
                            open_ports.append(port_data)
                        except json.JSONDecodeError:
                            continue
                return open_ports
        except subprocess.TimeoutExpired:
            logger.error(f"Masscan timeout for target {target}")
        except Exception as e:
            logger.error(f"Masscan error for {target}: {e}")
        
        return []
    
    async def run_nmap(self, target: str, ports: str = "1-65535") -> List[Dict]:
        """Run nmap for port discovery (Windows alternative to masscan)"""
        cmd = [
            str(self.tools['nmap']),
            '-p', ports,
            '--open',
            '--min-rate', '1000',
            '-T4',
            '-oX', '-',  # XML output to stdout
            target
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                # Parse nmap XML output to match masscan format
                open_ports = []
                import xml.etree.ElementTree as ET
                
                try:
                    root = ET.fromstring(result.stdout)
                    for host in root.findall('host'):
                        # Get IP address
                        ip_elem = host.find('address[@addrtype="ipv4"]')
                        if ip_elem is None:
                            continue
                        ip = ip_elem.get('addr')
                        
                        # Get open ports
                        ports_elem = host.find('ports')
                        if ports_elem is not None:
                            for port in ports_elem.findall('port'):
                                state = port.find('state')
                                if state is not None and state.get('state') == 'open':
                                    port_num = int(port.get('portid'))
                                    protocol = port.get('protocol', 'tcp')
                                    
                                    # Format to match masscan output structure
                                    port_data = {
                                        'ip': ip,
                                        'port': port_num,
                                        'proto': protocol,
                                        'status': 'open'
                                    }
                                    open_ports.append(port_data)
                except ET.ParseError as e:
                    logger.error(f"Failed to parse nmap XML output: {e}")
                
                return open_ports
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap timeout for target {target}")
        except Exception as e:
            logger.error(f"Nmap error for {target}: {e}")
        
        return []
    
    async def run_port_scan(self, target: str, ports: str = "1-65535", rate: int = 1000) -> List[Dict]:
        """Run port scanning using the appropriate tool for the platform"""
        if self.port_scanner == 'nmap':
            return await self.run_nmap(target, ports)
        else:
            return await self.run_masscan(target, ports, rate)
    
    async def run_nuclei(self, target: str, templates_dir: str = None) -> List[Dict]:
        """Run nuclei for vulnerability scanning"""
        cmd = [
            str(self.tools['nuclei']),
            '-target', target,
            '-json',
            '-silent',
            '-no-color'
        ]
        
        if templates_dir:
            cmd.extend(['-t', templates_dir])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                vulnerabilities = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            vuln_data = json.loads(line)
                            vulnerabilities.append(vuln_data)
                        except json.JSONDecodeError:
                            continue
                return vulnerabilities
        except subprocess.TimeoutExpired:
            logger.error(f"Nuclei timeout for target {target}")
        except Exception as e:
            logger.error(f"Nuclei error for {target}: {e}")
        
        return []
    
    async def run_httpx(self, targets: List[str]) -> List[Dict]:
        """Run httpx for service fingerprinting"""
        cmd = [
            str(self.tools['httpx']),
            '-json',
            '-silent',
            '-no-color',
            '-tech-detect',
            '-title',
            '-status-code'
        ]
        
        # Add targets
        for target in targets:
            cmd.extend(['-target', target])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                services = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            service_data = json.loads(line)
                            services.append(service_data)
                        except json.JSONDecodeError:
                            continue
                return services
        except subprocess.TimeoutExpired:
            logger.error("Httpx timeout")
        except Exception as e:
            logger.error(f"Httpx error: {e}")
        
        return []
    
    async def run_subfinder(self, domain: str) -> List[str]:
        """Run subfinder for subdomain discovery"""
        cmd = [
            str(self.tools['subfinder']),
            '-d', domain,
            '-json',
            '-silent'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                subdomains = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            subdomain_data = json.loads(line)
                            subdomains.append(subdomain_data.get('host', ''))
                        except json.JSONDecodeError:
                            # Fallback to plain text
                            subdomains.append(line.strip())
                return subdomains
        except subprocess.TimeoutExpired:
            logger.error(f"Subfinder timeout for domain {domain}")
        except Exception as e:
            logger.error(f"Subfinder error for {domain}: {e}")
        
        return []

class CVEDatabase:
    """Manages CVE and threat intelligence feeds"""
    
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.db_path = self.data_dir / 'cve_database.db'
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for CVE data"""
        self.data_dir.mkdir(exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # CVE table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                cvss_score REAL,
                severity TEXT,
                description TEXT,
                published_date TEXT,
                modified_date TEXT,
                cpe_matches TEXT,
                exploit_available INTEGER DEFAULT 0,
                exploit_maturity TEXT,
                reference_urls TEXT
            )
        ''')
        
        # Exploits table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                exploit_db_id TEXT,
                metasploit_module TEXT,
                maturity TEXT,
                reliability TEXT,
                exploit_type TEXT,
                platform TEXT,
                description TEXT,
                date_published TEXT,
                author TEXT,
                verified INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create index for faster CVE lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_exploits_cve_id ON exploits (cve_id)
        ''')
        
        # Create index for maturity-based queries
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_exploits_maturity ON exploits (maturity)
        ''')
        
        conn.commit()
        conn.close()
    
    async def update_cve_feeds(self):
        """Update CVE database from NVD and other sources"""
        logger.info("Updating CVE feeds...")
        
        # NVD CVE feed
        nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        try:
            async with aiohttp.ClientSession() as session:
                # Get recent CVEs (last 30 days)
                params = {
                    'pubStartDate': (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S.000'),
                    'pubEndDate': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000')
                }
                
                async with session.get(nvd_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        await self.store_cve_data(data.get('vulnerabilities', []))
                
                # Update Exploit DB data
                await self.update_exploit_feeds(session)
                        
        except Exception as e:
            logger.error(f"Error updating CVE feeds: {e}")
    
    async def update_exploit_feeds(self, session: aiohttp.ClientSession):
        """Update exploit database from Exploit-DB"""
        logger.info("Updating Exploit-DB feeds...")
        
        # Exploit-DB CSV URL (GitLab raw file)
        exploitdb_url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
        
        try:
            # Use custom headers to avoid robots.txt blocking
            headers = {
                'User-Agent': 'EVMS-Security-Scanner/1.0 (Vulnerability Research)',
                'Accept': 'text/csv,text/plain,*/*'
            }
            
            async with session.get(exploitdb_url, headers=headers) as response:
                if response.status == 200:
                    csv_content = await response.text()
                    await self.parse_exploit_csv(csv_content)
                else:
                    logger.warning(f"Failed to fetch Exploit-DB CSV: HTTP {response.status}")
                    # Fallback: try alternative sources or skip
                    
        except Exception as e:
            logger.error(f"Error updating Exploit-DB feeds: {e}")
    
    async def parse_exploit_csv(self, csv_content: str):
        """Parse Exploit-DB CSV and store exploit data"""
        logger.info("Parsing Exploit-DB CSV data...")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Clear existing exploit data for fresh update
        cursor.execute('DELETE FROM exploits')
        
        csv_reader = csv.reader(io.StringIO(csv_content))
        header = next(csv_reader, None)  # Skip header row
        
        exploit_count = 0
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
        
        for row in csv_reader:
            try:
                if len(row) < 3:  # Ensure minimum required columns
                    continue
                
                # Typical Exploit-DB CSV format:
                # id,file,description,date,author,type,platform,port
                edb_id = row[0].strip() if len(row) > 0 else ''
                file_path = row[1].strip() if len(row) > 1 else ''
                description = row[2].strip() if len(row) > 2 else ''
                date_published = row[3].strip() if len(row) > 3 else ''
                author = row[4].strip() if len(row) > 4 else ''
                exploit_type = row[5].strip() if len(row) > 5 else ''
                platform = row[6].strip() if len(row) > 6 else ''
                
                # Extract CVE IDs from description
                cve_matches = cve_pattern.findall(description)
                
                # Determine exploit maturity based on type and description
                maturity = self.determine_exploit_maturity(description, exploit_type, file_path)
                
                # Store exploit for each CVE found
                for cve_id in cve_matches:
                    cursor.execute('''
                        INSERT OR REPLACE INTO exploits 
                        (cve_id, exploit_db_id, metasploit_module, maturity, reliability, 
                         exploit_type, platform, description, date_published, author, verified)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        cve_id.upper(),
                        edb_id,
                        'metasploit' if 'metasploit' in file_path.lower() else None,
                        maturity,
                        'normal',  # Default reliability
                        exploit_type,
                        platform,
                        description[:500],  # Truncate long descriptions
                        date_published,
                        author,
                        1 if 'verified' in description.lower() else 0
                    ))
                    exploit_count += 1
                
                # If no CVE found but exploit exists, we might want to store it anyway
                # for future CVE mapping improvements
                
            except Exception as e:
                logger.debug(f"Error parsing exploit row: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        logger.info(f"Stored {exploit_count} exploit-to-CVE mappings from Exploit-DB")
    
    def determine_exploit_maturity(self, description: str, exploit_type: str, file_path: str) -> str:
        """Determine exploit maturity level based on available information"""
        desc_lower = description.lower()
        type_lower = exploit_type.lower()
        path_lower = file_path.lower()
        
        # Functional exploits (highest maturity)
        if any(keyword in desc_lower for keyword in [
            'remote code execution', 'rce', 'shell', 'privilege escalation',
            'authentication bypass', 'sql injection'
        ]):
            return 'functional'
        
        # Metasploit modules are typically functional
        if 'metasploit' in path_lower or '.rb' in path_lower:
            return 'functional'
        
        # Proof-of-concept indicators
        if any(keyword in desc_lower for keyword in [
            'poc', 'proof of concept', 'proof-of-concept', 'demonstration',
            'denial of service', 'dos', 'crash'
        ]):
            return 'proof-of-concept'
        
        # Default to proof-of-concept for safety
        return 'proof-of-concept'
    
    async def store_cve_data(self, vulnerabilities: List[Dict]):
        """Store CVE data in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for vuln in vulnerabilities:
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', '')
            
            # Extract CVSS score
            cvss_score = 0.0
            severity = 'Unknown'
            
            metrics = cve_data.get('metrics', {})
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'Unknown')
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'Unknown')
            
            description = ''
            descriptions = cve_data.get('descriptions', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Store CVE
            cursor.execute('''
                INSERT OR REPLACE INTO cves 
                (cve_id, cvss_score, severity, description, published_date, modified_date)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                cve_id,
                cvss_score,
                severity,
                description,
                cve_data.get('published', ''),
                cve_data.get('lastModified', '')
            ))
        
        conn.commit()
        conn.close()
        logger.info(f"Stored {len(vulnerabilities)} CVE records")
    
    def get_cve_info(self, cve_id: str) -> Optional[Dict]:
        """Get CVE information from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM cves WHERE cve_id = ?', (cve_id,))
        result = cursor.fetchone()
        
        conn.close()
        
        if result:
            columns = ['cve_id', 'cvss_score', 'severity', 'description', 
                      'published_date', 'modified_date', 'cpe_matches', 
                      'exploit_available', 'exploit_maturity', 'references']
            return dict(zip(columns, result))
        
        return None
    
    def check_exploit_availability(self, cve_id: str) -> Tuple[bool, str]:
        """Check if exploits are available for a CVE"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT maturity, metasploit_module, verified, exploit_db_id, platform, exploit_type
            FROM exploits 
            WHERE cve_id = ? 
            ORDER BY 
                CASE maturity 
                    WHEN 'functional' THEN 1 
                    WHEN 'proof-of-concept' THEN 2 
                    ELSE 3 
                END,
                verified DESC
        ''', (cve_id,))
        results = cursor.fetchall()
        
        conn.close()
        
        if results:
            # Get the best exploit (highest maturity, verified if possible)
            best_exploit = results[0]
            maturity, metasploit_module, verified, edb_id, platform, exploit_type = best_exploit
            
            # Count different types of exploits
            functional_count = sum(1 for r in results if r[0] == 'functional')
            poc_count = sum(1 for r in results if r[0] == 'proof-of-concept')
            metasploit_count = sum(1 for r in results if r[1] is not None)
            verified_count = sum(1 for r in results if r[2] == 1)
            
            # Build detailed maturity description
            details = []
            if functional_count > 0:
                details.append(f"{functional_count} functional")
            if poc_count > 0:
                details.append(f"{poc_count} PoC")
            if metasploit_count > 0:
                details.append(f"{metasploit_count} Metasploit")
            if verified_count > 0:
                details.append(f"{verified_count} verified")
            
            maturity_desc = maturity
            if details:
                maturity_desc += f" ({', '.join(details)})"
            
            return True, maturity_desc
        
        return False, 'none'
    
    def get_exploit_details(self, cve_id: str) -> List[Dict]:
        """Get detailed exploit information for a CVE"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT exploit_db_id, metasploit_module, maturity, reliability, 
                   exploit_type, platform, description, date_published, author, verified
            FROM exploits 
            WHERE cve_id = ?
            ORDER BY 
                CASE maturity 
                    WHEN 'functional' THEN 1 
                    WHEN 'proof-of-concept' THEN 2 
                    ELSE 3 
                END,
                verified DESC
        ''', (cve_id,))
        results = cursor.fetchall()
        
        conn.close()
        
        exploits = []
        for row in results:
            exploits.append({
                'exploit_db_id': row[0],
                'metasploit_module': row[1],
                'maturity': row[2],
                'reliability': row[3],
                'exploit_type': row[4],
                'platform': row[5],
                'description': row[6],
                'date_published': row[7],
                'author': row[8],
                'verified': bool(row[9])
            })
        
        return exploits

class GraphEnsembleEngine:
    """Graph-based Ensemble Classifier for vulnerability prioritization"""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        self.driver = neo4j.GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.scaler = StandardScaler()
        self.ensemble_models = {}
        self.feature_cache = {}
        self.init_graph_schema()
        self.init_ensemble_models()
        
    def init_graph_schema(self):
        """Initialize Neo4j graph schema with enhanced indexes for ensemble features"""
        with self.driver.session() as session:
            # Create constraints and indexes
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (a:Asset) REQUIRE a.ip IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE")
            
            # Enhanced indexes for ensemble feature extraction
            session.run("CREATE INDEX IF NOT EXISTS FOR (a:Asset) ON (a.risk_score)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (v:Vulnerability) ON (v.cvss_score)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (a:Asset) ON (a.subnet)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (s:Service) ON (s.port)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)")
    
    def init_ensemble_models(self):
        """Initialize ensemble models optimized for different aspects"""
        # Model 1: CVSS and exploit-focused (XGBoost)
        self.ensemble_models['cvss_exploit'] = xgb.XGBClassifier(
            objective='multi:softprob',
            num_class=4,  # Critical, High, Medium, Low
            max_depth=6,
            learning_rate=0.1,
            n_estimators=100,
            random_state=42
        )
        
        # Model 2: Network topology-focused (LightGBM)
        self.ensemble_models['network_topology'] = lgb.LGBMClassifier(
            objective='multiclass',
            num_class=4,
            max_depth=8,
            learning_rate=0.05,
            n_estimators=150,
            random_state=42
        )
        
        # Model 3: Service and port-focused (Random Forest)
        self.ensemble_models['service_context'] = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_split=5,
            random_state=42
        )
        
        logger.info("Initialized ensemble models: CVSS/Exploit, Network Topology, Service Context")
    
    def store_scan_results(self, scan_result: ScanResult):
        """Store scan results in graph database with enhanced metadata for ensemble features"""
        with self.driver.session() as session:
            # Extract subnet for network topology features
            try:
                network = ipaddress.ip_network(f"{scan_result.target}/24", strict=False)
                subnet = str(network.network_address)
            except:
                subnet = scan_result.target.rsplit('.', 1)[0] + '.0'
            
            # Create asset node with enhanced properties
            session.run("""
                MERGE (a:Asset {ip: $ip})
                SET a.last_scanned = datetime(),
                    a.risk_score = $risk_score,
                    a.priority = $priority,
                    a.lateral_movement_potential = $lateral_movement,
                    a.subnet = $subnet,
                    a.service_count = $service_count,
                    a.vulnerability_count = $vuln_count,
                    a.critical_vuln_count = $critical_count,
                    a.high_vuln_count = $high_count
            """, {
                'ip': scan_result.target,
                'risk_score': scan_result.risk_assessment.get('total_score', 0.0),
                'priority': scan_result.priority,
                'lateral_movement': scan_result.lateral_movement_potential,
                'subnet': subnet,
                'service_count': len(scan_result.services),
                'vuln_count': len(scan_result.vulnerabilities),
                'critical_count': len([v for v in scan_result.vulnerabilities if v.severity == 'Critical']),
                'high_count': len([v for v in scan_result.vulnerabilities if v.severity == 'High'])
            })
            
            # Create service nodes with enhanced properties
            for service in scan_result.services:
                session.run("""
                    MATCH (a:Asset {ip: $ip})
                    MERGE (s:Service {id: $service_id})
                    SET s.name = $service_name,
                        s.version = $version,
                        s.port = $port,
                        s.protocol = $protocol,
                        s.is_web_service = $is_web,
                        s.is_database = $is_db,
                        s.is_remote_access = $is_remote
                    MERGE (a)-[:RUNS]->(s)
                """, {
                    'ip': scan_result.target,
                    'service_id': f"{scan_result.target}:{service.get('port', 0)}",
                    'service_name': service.get('service', 'unknown'),
                    'version': service.get('version', ''),
                    'port': service.get('port', 0),
                    'protocol': service.get('protocol', 'tcp'),
                    'is_web': service.get('port', 0) in [80, 443, 8080, 8443],
                    'is_db': service.get('service', '').lower() in ['mysql', 'postgresql', 'mongodb', 'redis'],
                    'is_remote': service.get('port', 0) in [22, 3389, 5900, 23]
                })
            
            # Create vulnerability nodes with enhanced relationships
            for vuln in scan_result.vulnerabilities:
                session.run("""
                    MERGE (v:Vulnerability {cve_id: $cve_id})
                    SET v.cvss_score = $cvss_score,
                        v.severity = $severity,
                        v.description = $description,
                        v.exploit_available = $exploit_available,
                        v.exploit_maturity = $exploit_maturity,
                        v.affects_web_service = $affects_web,
                        v.affects_database = $affects_db,
                        v.affects_remote_access = $affects_remote
                    
                    MATCH (a:Asset {ip: $target})
                    MERGE (a)-[:HAS_VULNERABILITY {discovered: datetime()}]->(v)
                    
                    MATCH (s:Service {id: $service_id})
                    MERGE (s)-[:AFFECTED_BY {impact_level: $impact}]->(v)
                """, {
                    'cve_id': vuln.cve_id,
                    'cvss_score': vuln.cvss_score,
                    'severity': vuln.severity,
                    'description': vuln.description,
                    'exploit_available': vuln.exploit_available,
                    'exploit_maturity': vuln.exploit_maturity,
                    'target': vuln.target,
                    'service_id': f"{vuln.target}:{vuln.port}",
                    'affects_web': vuln.port in [80, 443, 8080, 8443],
                    'affects_db': any(db in vuln.description.lower() for db in ['mysql', 'postgresql', 'mongodb']),
                    'affects_remote': vuln.port in [22, 3389, 5900],
                    'impact': 'high' if vuln.severity in ['Critical', 'High'] else 'medium'
                })
    
    def extract_graph_features(self, vulnerability: Vulnerability, target_ip: str) -> Dict:
        """Extract comprehensive features from GraphDB for ensemble models"""
        features = {}
        
        with self.driver.session() as session:
            # 1. CVSS and Exploit Features
            cvss_features = self._extract_cvss_features(session, vulnerability)
            features.update(cvss_features)
            
            # 2. Network Topology Features
            network_features = self._extract_network_features(session, target_ip)
            features.update(network_features)
            
            # 3. Service Context Features
            service_features = self._extract_service_features(session, vulnerability, target_ip)
            features.update(service_features)
            
            # 4. Historical Pattern Features
            historical_features = self._extract_historical_features(session, vulnerability.cve_id)
            features.update(historical_features)
            
        return features
    
    def _extract_cvss_features(self, session, vulnerability: Vulnerability) -> Dict:
        """Extract CVSS and exploit-related features"""
        return {
            'cvss_score': vulnerability.cvss_score,
            'severity_critical': 1 if vulnerability.severity == 'Critical' else 0,
            'severity_high': 1 if vulnerability.severity == 'High' else 0,
            'severity_medium': 1 if vulnerability.severity == 'Medium' else 0,
            'exploit_available': 1 if vulnerability.exploit_available else 0,
            'exploit_maturity_functional': 1 if vulnerability.exploit_maturity == 'functional' else 0,
            'exploit_maturity_high': 1 if vulnerability.exploit_maturity == 'high' else 0,
            'exploit_maturity_proof': 1 if vulnerability.exploit_maturity == 'proof-of-concept' else 0
        }
    
    def _extract_network_features(self, session, target_ip: str) -> Dict:
        """Extract network topology and lateral movement features"""
        try:
            network = ipaddress.ip_network(f"{target_ip}/24", strict=False)
            subnet = str(network.network_address)
        except:
            subnet = target_ip.rsplit('.', 1)[0] + '.0'
        
        # Get subnet-level statistics
        result = session.run("""
            MATCH (a:Asset {subnet: $subnet})
            OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN 
                count(DISTINCT a) as subnet_asset_count,
                avg(a.risk_score) as avg_subnet_risk,
                count(DISTINCT v) as subnet_vuln_count,
                sum(CASE WHEN v.severity = 'Critical' THEN 1 ELSE 0 END) as subnet_critical_count,
                sum(CASE WHEN a.lateral_movement_potential = true THEN 1 ELSE 0 END) as lateral_movement_assets
        """, {'subnet': subnet})
        
        record = result.single()
        if record:
            return {
                'subnet_asset_count': record['subnet_asset_count'] or 0,
                'avg_subnet_risk': record['avg_subnet_risk'] or 0.0,
                'subnet_vuln_density': (record['subnet_vuln_count'] or 0) / max(record['subnet_asset_count'] or 1, 1),
                'subnet_critical_density': (record['subnet_critical_count'] or 0) / max(record['subnet_asset_count'] or 1, 1),
                'lateral_movement_ratio': (record['lateral_movement_assets'] or 0) / max(record['subnet_asset_count'] or 1, 1)
            }
        else:
            return {
                'subnet_asset_count': 0,
                'avg_subnet_risk': 0.0,
                'subnet_vuln_density': 0.0,
                'subnet_critical_density': 0.0,
                'lateral_movement_ratio': 0.0
            }
    
    def _extract_service_features(self, session, vulnerability: Vulnerability, target_ip: str) -> Dict:
        """Extract service and port-related features"""
        result = session.run("""
            MATCH (a:Asset {ip: $target_ip})-[:RUNS]->(s:Service)-[:AFFECTED_BY]->(v:Vulnerability {cve_id: $cve_id})
            RETURN 
                s.port as port,
                s.is_web_service as is_web,
                s.is_database as is_db,
                s.is_remote_access as is_remote,
                count(*) as service_vuln_count
        """, {'target_ip': target_ip, 'cve_id': vulnerability.cve_id})
        
        record = result.single()
        if record:
            return {
                'port_number': record['port'] or 0,
                'affects_web_service': 1 if record['is_web'] else 0,
                'affects_database': 1 if record['is_db'] else 0,
                'affects_remote_access': 1 if record['is_remote'] else 0,
                'service_vuln_count': record['service_vuln_count'] or 0,
                'is_common_port': 1 if (record['port'] or 0) in [22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 1723, 3389, 5900] else 0
            }
        else:
            return {
                'port_number': vulnerability.port,
                'affects_web_service': 1 if vulnerability.port in [80, 443, 8080, 8443] else 0,
                'affects_database': 0,
                'affects_remote_access': 1 if vulnerability.port in [22, 3389, 5900] else 0,
                'service_vuln_count': 1,
                'is_common_port': 1 if vulnerability.port in [22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 1723, 3389, 5900] else 0
            }
    
    def _extract_historical_features(self, session, cve_id: str) -> Dict:
        """Extract historical patterns for this CVE across the network"""
        result = session.run("""
            MATCH (v:Vulnerability {cve_id: $cve_id})<-[:HAS_VULNERABILITY]-(a:Asset)
            RETURN 
                count(DISTINCT a) as total_affected_assets,
                avg(a.risk_score) as avg_affected_asset_risk,
                count(CASE WHEN a.lateral_movement_potential = true THEN 1 END) as lateral_movement_affected
        """, {'cve_id': cve_id})
        
        record = result.single()
        if record:
            return {
                'cve_prevalence': record['total_affected_assets'] or 0,
                'avg_cve_asset_risk': record['avg_affected_asset_risk'] or 0.0,
                'cve_lateral_movement_count': record['lateral_movement_affected'] or 0
            }
        else:
            return {
                'cve_prevalence': 0,
                'avg_cve_asset_risk': 0.0,
                'cve_lateral_movement_count': 0
            }
    
    def get_network_context(self, target_ip: str) -> Dict:
        """Enhanced network context for lateral movement assessment"""
        return self._extract_network_features(None, target_ip)
    
    def train_ensemble_models(self):
        """Train ensemble classifier models using historical graph data"""
        logger.info("Training ensemble classifier models...")
        
        # Extract training data from graph
        training_data = self._extract_training_data()
        
        if len(training_data) < 10:
            logger.warning("Insufficient training data, using default model weights")
            return
        
        # Prepare features and labels
        X, y = self._prepare_training_data(training_data)
        
        # Train each ensemble model
        for model_name, model in self.ensemble_models.items():
            logger.info(f"Training {model_name} model...")
            try:
                model.fit(X, y)
                logger.info(f"{model_name} model training completed")
            except Exception as e:
                logger.error(f"Error training {model_name}: {e}")
        
        logger.info("Ensemble model training completed")
    
    def _extract_training_data(self) -> List[Dict]:
        """Extract historical vulnerability data for training"""
        with self.driver.session() as session:
            result = session.run("""
                MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                RETURN 
                    v.cve_id as cve_id,
                    v.cvss_score as cvss_score,
                    v.severity as severity,
                    v.exploit_available as exploit_available,
                    v.exploit_maturity as exploit_maturity,
                    a.ip as target_ip,
                    a.priority as priority
                LIMIT 1000
            """)
            
            training_data = []
            for record in result:
                if record['priority']:  # Only use records with known priorities
                    training_data.append({
                        'cve_id': record['cve_id'],
                        'cvss_score': record['cvss_score'],
                        'severity': record['severity'],
                        'exploit_available': record['exploit_available'],
                        'exploit_maturity': record['exploit_maturity'],
                        'target_ip': record['target_ip'],
                        'priority': record['priority']
                    })
            
            return training_data
    
    def _prepare_training_data(self, training_data: List[Dict]) -> tuple:
        """Prepare training data for ensemble models"""
        features = []
        labels = []
        
        priority_map = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        
        for data in training_data:
            # Create mock vulnerability object for feature extraction
            vuln = type('Vulnerability', (), {
                'cve_id': data['cve_id'],
                'cvss_score': data['cvss_score'],
                'severity': data['severity'],
                'exploit_available': data['exploit_available'],
                'exploit_maturity': data['exploit_maturity'],
                'port': 80  # Default port for training
            })()
            
            # Extract features
            feature_dict = self.extract_graph_features(vuln, data['target_ip'])
            feature_vector = list(feature_dict.values())
            
            features.append(feature_vector)
            labels.append(priority_map.get(data['priority'], 3))
        
        return np.array(features), np.array(labels)
    
    def predict_priority(self, vulnerability: Vulnerability, target_ip: str) -> str:
        """Predict vulnerability priority using ensemble models"""
        # Extract features
        features = self.extract_graph_features(vulnerability, target_ip)
        feature_vector = np.array(list(features.values())).reshape(1, -1)
        
        # Get predictions from each model
        predictions = {}
        for model_name, model in self.ensemble_models.items():
            try:
                if hasattr(model, 'predict_proba'):
                    pred_proba = model.predict_proba(feature_vector)[0]
                    predictions[model_name] = pred_proba
                else:
                    pred = model.predict(feature_vector)[0]
                    predictions[model_name] = pred
            except Exception as e:
                logger.warning(f"Error in {model_name} prediction: {e}")
                # Fallback to CVSS-based prediction
                predictions[model_name] = self._fallback_prediction(vulnerability)
        
        # Ensemble voting
        final_priority = self._ensemble_vote(predictions, features)
        return final_priority
    
    def _ensemble_vote(self, predictions: Dict, features: Dict) -> str:
        """Combine predictions from ensemble models with weighted voting"""
        priority_labels = ['Critical', 'High', 'Medium', 'Low']
        
        # Weights based on model strengths for different scenarios
        weights = {
            'cvss_exploit': 0.4,      # Strong for CVSS and exploit data
            'network_topology': 0.35,  # Strong for lateral movement
            'service_context': 0.25    # Strong for service-specific risks
        }
        
        # Adjust weights based on feature characteristics
        if features.get('lateral_movement_ratio', 0) > 0.3:
            weights['network_topology'] += 0.1
            weights['cvss_exploit'] -= 0.05
            weights['service_context'] -= 0.05
        
        if features.get('affects_remote_access', 0) == 1:
            weights['service_context'] += 0.1
            weights['cvss_exploit'] -= 0.05
            weights['network_topology'] -= 0.05
        
        # Calculate weighted average
        final_scores = np.zeros(4)
        total_weight = 0
        
        for model_name, pred in predictions.items():
            if model_name in weights:
                weight = weights[model_name]
                if isinstance(pred, np.ndarray):
                    final_scores += weight * pred
                else:
                    # Convert single prediction to probability distribution
                    prob_dist = np.zeros(4)
                    prob_dist[int(pred)] = 1.0
                    final_scores += weight * prob_dist
                total_weight += weight
        
        if total_weight > 0:
            final_scores /= total_weight
            predicted_class = np.argmax(final_scores)
            return priority_labels[predicted_class]
        else:
            return self._fallback_prediction(vulnerability)
    
    def _fallback_prediction(self, vulnerability: Vulnerability) -> str:
        """Fallback prediction based on CVSS score and exploit availability"""
        if vulnerability.cvss_score >= 9.0 and vulnerability.exploit_available:
            return 'Critical'
        elif vulnerability.cvss_score >= 7.0 and vulnerability.exploit_available:
            return 'High'
        elif vulnerability.cvss_score >= 7.0 or vulnerability.exploit_available:
            return 'High'
        elif vulnerability.cvss_score >= 4.0:
            return 'Medium'
        else:
            return 'Low'

class LLMAnalyzer:
    """LLM/RAG system for deterministic vulnerability analysis"""
    
    def __init__(self, openai_api_key: str, graph_engine: GraphEnsembleEngine):
        self.client = openai.OpenAI(api_key=openai_api_key)
        self.graph_engine = graph_engine
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
    def analyze_vulnerabilities(self, scan_result: ScanResult) -> Dict:
        """Analyze vulnerabilities using LLM with graph context"""
        # Get graph context
        context = self.get_vulnerability_context(scan_result.vulnerabilities)
        
        # Prepare prompt
        prompt = f"""
        Analyze the following vulnerability scan results for {scan_result.target}:
        
        Vulnerabilities found:
        {json.dumps([asdict(v) for v in scan_result.vulnerabilities], indent=2)}
        
        Network context:
        {json.dumps(context, indent=2)}
        
        Provide a deterministic analysis including:
        1. Risk assessment summary
        2. Critical vulnerabilities requiring immediate attention
        3. Recommended remediation steps
        4. Potential attack vectors
        5. Business impact assessment
        
        Base your analysis on factual data only. Cite specific CVE IDs and CVSS scores.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert providing factual vulnerability analysis based on scan data."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,  # Low temperature for deterministic responses
                max_tokens=2048
            )
            
            return {
                'analysis': response.choices[0].message.content,
                'confidence': 0.9,  # High confidence due to factual data
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"LLM analysis error: {e}")
            return {
                'analysis': f"Analysis failed: {str(e)}",
                'confidence': 0.0,
                'timestamp': datetime.now().isoformat()
            }
    
    def get_vulnerability_context(self, vulnerabilities: List[Vulnerability]) -> Dict:
        """Get additional context for vulnerabilities from graph database"""
        context = {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_distribution': {},
            'exploit_availability': {},
            'affected_services': set()
        }
        
        for vuln in vulnerabilities:
            # Count by severity
            context['severity_distribution'][vuln.severity] = \
                context['severity_distribution'].get(vuln.severity, 0) + 1
            
            # Count exploit availability
            if vuln.exploit_available:
                context['exploit_availability'][vuln.exploit_maturity] = \
                    context['exploit_availability'].get(vuln.exploit_maturity, 0) + 1
            
            # Track affected services
            context['affected_services'].add(vuln.affected_service)
        
        context['affected_services'] = list(context['affected_services'])
        return context

class VulnerabilityPrioritizer:
    """Enhanced vulnerability prioritization using ensemble classifier and rule-based logic"""
    
    def __init__(self, cve_db: CVEDatabase, graph_engine: GraphEnsembleEngine):
        self.cve_db = cve_db
        self.graph_engine = graph_engine
        self.use_ensemble = True  # Flag to enable/disable ensemble prediction
    
    def prioritize_vulnerability(self, vuln: Vulnerability, target_ip: str) -> str:
        """
        Enhanced prioritization using ensemble classifier with fallback to rule-based logic
        
        Priority levels:
        - Critical: High/Critical exploit + lateral movement potential (ensemble-enhanced)
        - High: Medium exploit + lateral movement potential, or High/Critical exploit limited to host
        - Medium: Low/Info exploit + lateral movement potential, or Medium exploit limited to host  
        - Low: Weak configuration, or Low/Info exploit limited to host
        """
        
        # Enrich vulnerability with CVE database information
        exploit_available, exploit_maturity = self.cve_db.check_exploit_availability(vuln.cve_id)
        vuln.exploit_available = exploit_available
        vuln.exploit_maturity = exploit_maturity
        
        # Try ensemble prediction first
        if self.use_ensemble:
            try:
                ensemble_priority = self.graph_engine.predict_priority(vuln, target_ip)
                logger.debug(f"Ensemble prediction for {vuln.cve_id}: {ensemble_priority}")
                
                # Validate ensemble prediction with rule-based check
                rule_priority = self._rule_based_prioritization(vuln, target_ip)
                
                # Use ensemble if it's reasonable, otherwise fall back to rules
                if self._validate_ensemble_prediction(ensemble_priority, rule_priority, vuln):
                    return ensemble_priority
                else:
                    logger.debug(f"Ensemble prediction {ensemble_priority} overridden by rules: {rule_priority}")
                    return rule_priority
                    
            except Exception as e:
                logger.warning(f"Ensemble prediction failed for {vuln.cve_id}: {e}")
                # Fall back to rule-based prioritization
                return self._rule_based_prioritization(vuln, target_ip)
        else:
            return self._rule_based_prioritization(vuln, target_ip)
    
    def _rule_based_prioritization(self, vuln: Vulnerability, target_ip: str) -> str:
        """Original rule-based prioritization logic as fallback"""
        # Get network context for lateral movement assessment
        network_context = self.graph_engine.get_network_context(target_ip)
        lateral_movement_potential = network_context.get('subnet_asset_count', 0) > 1
        
        # Apply prioritization logic
        if vuln.exploit_available and vuln.exploit_maturity in ['functional', 'proof-of-concept']:
            if vuln.severity.upper() in ['CRITICAL', 'HIGH'] and lateral_movement_potential:
                return 'Critical'
            elif vuln.severity.upper() == 'MEDIUM' and lateral_movement_potential:
                return 'High'
            elif vuln.severity.upper() in ['CRITICAL', 'HIGH'] and not lateral_movement_potential:
                return 'High'
            elif vuln.severity.upper() in ['LOW', 'INFORMATIONAL'] and lateral_movement_potential:
                return 'Medium'
            elif vuln.severity.upper() == 'MEDIUM' and not lateral_movement_potential:
                return 'Medium'
            elif vuln.severity.upper() in ['LOW', 'INFORMATIONAL'] and not lateral_movement_potential:
                return 'Low'
        
        # Check for weak configurations
        weak_services = ['rdp', 'vnc', 'telnet', 'ftp', 'ssh']
        if hasattr(vuln, 'affected_service') and any(service in vuln.affected_service.lower() for service in weak_services):
            return 'Low'
        
        # Default based on CVSS score
        if vuln.cvss_score >= 9.0:
            return 'Critical'
        elif vuln.cvss_score >= 7.0:
            return 'High'
        elif vuln.cvss_score >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    
    def _validate_ensemble_prediction(self, ensemble_priority: str, rule_priority: str, vuln: Vulnerability) -> bool:
        """Validate ensemble prediction against rule-based logic"""
        priority_levels = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        
        ensemble_level = priority_levels.get(ensemble_priority, 3)
        rule_level = priority_levels.get(rule_priority, 3)
        
        # Allow ensemble to be more conservative (higher priority) but not too lenient
        # Accept ensemble if it's within 1 level of rule-based prediction
        if abs(ensemble_level - rule_level) <= 1:
            return True
        
        # Always accept ensemble for Critical vulnerabilities with high CVSS
        if ensemble_priority == 'Critical' and vuln.cvss_score >= 8.0:
            return True
        
        # Reject ensemble if it's too lenient for high CVSS scores
        if vuln.cvss_score >= 9.0 and ensemble_level > 1:  # Not Critical or High
            return False
        
        return False

class EVMSScanner:
    """Main EVMS scanning engine"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.tools = ToolManager(config['tools_dir'])
        self.cve_db = CVEDatabase(config['data_dir'])
        self.graph_engine = GraphEnsembleEngine(
            config['neo4j_uri'],
            config['neo4j_user'], 
            config['neo4j_password']
        )
        self.llm_analyzer = LLMAnalyzer(config['openai_api_key'], self.graph_engine)
        self.prioritizer = VulnerabilityPrioritizer(self.cve_db, self.graph_engine)
        
    async def initialize(self):
        """Initialize EVMS components"""
        logger.info("Initializing EVMS...")
        
        # Check tools
        tool_status = self.tools.check_tools()
        missing_tools = [tool for tool, available in tool_status.items() 
                        if not available and tool != 'zeek']
        
        if missing_tools:
            logger.error(f"Missing required tools: {missing_tools}")
            return False
        
        # Update CVE database
        await self.cve_db.update_cve_feeds()
        
        # Train ensemble models
        self.graph_engine.train_ensemble_models()
        
        logger.info("EVMS initialization completed")
        return True
    
    async def scan_target(self, target: str, target_type: str = 'auto') -> ScanResult:
        """Perform comprehensive scan of target"""
        logger.info(f"Starting scan of {target}")
        
        # Determine target type if auto
        if target_type == 'auto':
            target_type = self.detect_target_type(target)
        
        # Phase 1: Discovery - Get all targets (IPs/domains)
        discovery_targets = await self.discovery_phase(target, target_type)
        logger.info(f"Discovery found {len(discovery_targets)} targets")
        
        # Phase 2: Port scanning - Find open ports/services
        all_open_ports = []
        for t in discovery_targets:
            logger.info(f"Port scanning {t}")
            ports = await self.tools.run_port_scan(t)
            all_open_ports.extend(ports)
        
        logger.info(f"Found {len(all_open_ports)} open ports")
        
        # Phase 3: Build service URLs from discovered ports
        service_urls = self.build_service_urls(all_open_ports)
        logger.info(f"Built {len(service_urls)} service URLs")
        
        # Phase 4: Service fingerprinting on discovered services
        services = []
        if service_urls:
            services = await self.tools.run_httpx(service_urls)
        
        # Phase 5: Vulnerability scanning on discovered services
        vulnerabilities = []
        for service_url in service_urls:
            logger.info(f"Vulnerability scanning {service_url}")
            vulns = await self.tools.run_nuclei(service_url)
            for vuln_data in vulns:
                vuln = self.parse_nuclei_result(vuln_data, service_url)
                if vuln:
                    vulnerabilities.append(vuln)
        
        # Phase 5: Risk assessment and prioritization
        risk_assessment = self.calculate_risk_assessment(vulnerabilities, target)
        lateral_movement_potential = self.assess_lateral_movement(target)
        
        # Prioritize vulnerabilities
        for vuln in vulnerabilities:
            vuln.priority = self.prioritizer.prioritize_vulnerability(vuln, target)
        
        # Determine overall priority
        priorities = [v.priority for v in vulnerabilities]
        if 'Critical' in priorities:
            overall_priority = 'Critical'
        elif 'High' in priorities:
            overall_priority = 'High'
        elif 'Medium' in priorities:
            overall_priority = 'Medium'
        else:
            overall_priority = 'Low'
        
        # Create scan result
        scan_result = ScanResult(
            target=target,
            timestamp=datetime.now(),
            open_ports=all_open_ports,
            services=services,
            vulnerabilities=vulnerabilities,
            risk_assessment=risk_assessment,
            lateral_movement_potential=lateral_movement_potential,
            priority=overall_priority
        )
        
        # Store in graph database
        self.graph_engine.store_scan_results(scan_result)
        
        # Publish scan completion event
        event_bus.publish('scan.completed', {
            'target': scan_result.target,
            'priority': scan_result.priority,
            'vulnerability_count': len(scan_result.vulnerabilities),
            'timestamp': scan_result.timestamp.isoformat(),
            'risk_score': scan_result.risk_assessment.get('total_score', 0.0)
        })
        
        logger.info(f"Scan completed for {target} - Priority: {overall_priority}")
        return scan_result
    
    def detect_target_type(self, target: str) -> str:
        """Detect target type (IP, CIDR, domain, ASN)"""
        try:
            ipaddress.ip_address(target)
            return 'ip'
        except ValueError:
            pass
        
        try:
            ipaddress.ip_network(target, strict=False)
            return 'cidr'
        except ValueError:
            pass
        
        # Check if it's an ASN (various formats)
        asn_patterns = [
            r'^AS\d+$',      # AS1234
            r'^as\d+$',      # as1234
            r'^\d+$'         # 1234 (plain number, could be ASN)
        ]
        
        for pattern in asn_patterns:
            if re.match(pattern, target):
                # For plain numbers, only treat as ASN if it's a reasonable ASN range
                if pattern == r'^\d+$':
                    asn_num = int(target)
                    if 1 <= asn_num <= 4294967295:  # Valid ASN range
                        return 'asn'
                else:
                    return 'asn'
        
        return 'domain'
    
    async def discovery_phase(self, target: str, target_type: str) -> List[str]:
        """Discovery phase - expand target to list of IPs"""
        targets = []
        
        if target_type == 'ip':
            targets = [target]
        elif target_type == 'cidr':
            network = ipaddress.ip_network(target, strict=False)
            # Intelligent CIDR handling based on network size
            if network.num_addresses > 10000:  # /18 or larger
                logger.info(f"Large CIDR {target} ({network.num_addresses} addresses), sampling 1000 IPs")
                targets = self.sample_network_ips(network, 1000)
            elif network.num_addresses > 1000:  # /22 to /18
                logger.info(f"Medium CIDR {target} ({network.num_addresses} addresses), sampling 500 IPs")
                targets = self.sample_network_ips(network, 500)
            else:  # /22 or smaller
                logger.info(f"Small CIDR {target} ({network.num_addresses} addresses), scanning all")
                targets = [str(ip) for ip in network.hosts()]
        elif target_type == 'domain':
            # Subdomain discovery
            subdomains = await self.tools.run_subfinder(target)
            all_domains = [target] + subdomains
            
            # Resolve all domains to IPs
            targets = []
            for domain in all_domains:
                try:
                    # Resolve domain to IP addresses
                    result = socket.getaddrinfo(domain, None, socket.AF_INET)
                    ips = list(set([r[4][0] for r in result]))
                    targets.extend(ips)
                    logger.info(f"Resolved {domain} to {ips}")
                except socket.gaierror as e:
                    logger.warning(f"Failed to resolve {domain}: {e}")
                    continue
        elif target_type == 'asn':
            # ASN to IP ranges using BGP data
            asn_ranges = await self.discover_asn_ranges(target)
            targets = []
            for cidr in asn_ranges:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    # Limit large networks to avoid overwhelming scans
                    if network.num_addresses > 1000:
                        # Sample IPs from large networks
                        targets.extend(self.sample_network_ips(network, 500))
                    else:
                        targets.extend([str(ip) for ip in network.hosts()])
                except ValueError as e:
                    logger.warning(f"Invalid CIDR from ASN {target}: {cidr} - {e}")
                    continue
        
        # Remove duplicates
        targets = list(set(targets))
        return targets
    
    def build_service_urls(self, open_ports: List[Dict]) -> List[str]:
        """Build service URLs from masscan open port results"""
        service_urls = []
        
        for port_info in open_ports:
            ip = port_info.get('ip', '')
            port = port_info.get('port', 0)
            protocol = port_info.get('protocol', 'tcp')
            
            if not ip or not port:
                continue
            
            # Build URLs based on common port/service mappings
            if port in [80, 8080, 8000, 8008, 8888]:
                service_urls.append(f"http://{ip}:{port}")
            elif port in [443, 8443, 9443]:
                service_urls.append(f"https://{ip}:{port}")
            elif port in [21]:  # FTP
                service_urls.append(f"ftp://{ip}:{port}")
            elif port in [22]:  # SSH
                service_urls.append(f"ssh://{ip}:{port}")
            elif port in [23]:  # Telnet
                service_urls.append(f"telnet://{ip}:{port}")
            elif port in [25, 587, 465]:  # SMTP
                service_urls.append(f"smtp://{ip}:{port}")
            elif port in [53]:  # DNS
                service_urls.append(f"dns://{ip}:{port}")
            elif port in [110, 995]:  # POP3
                service_urls.append(f"pop3://{ip}:{port}")
            elif port in [143, 993]:  # IMAP
                service_urls.append(f"imap://{ip}:{port}")
            elif port in [3389]:  # RDP
                service_urls.append(f"rdp://{ip}:{port}")
            elif port in [5900, 5901, 5902]:  # VNC
                service_urls.append(f"vnc://{ip}:{port}")
            else:
                # For unknown ports, try both HTTP and HTTPS
                service_urls.append(f"http://{ip}:{port}")
                if port != 80:  # Don't duplicate port 80
                    service_urls.append(f"https://{ip}:{port}")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in service_urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        
        return unique_urls
    
    async def discover_asn_ranges(self, asn: str) -> List[str]:
        """Discover IP ranges for a given ASN using multiple methods"""
        ranges = []
        
        # Clean ASN input (remove AS prefix if present)
        asn_number = asn.replace('AS', '').replace('as', '')
        
        # Method 1: Try bgpview.io API
        try:
            url = f"https://api.bgpview.io/asn/{asn_number}/prefixes"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'ok':
                    prefixes = data.get('data', {}).get('ipv4_prefixes', [])
                    for prefix in prefixes:
                        cidr = prefix.get('prefix')
                        if cidr:
                            ranges.append(cidr)
                    logger.info(f"BGPView API found {len(ranges)} prefixes for ASN {asn_number}")
        except Exception as e:
            logger.warning(f"BGPView API failed for ASN {asn_number}: {e}")
        
        # Method 2: Try whois command as fallback
        if not ranges:
            try:
                result = subprocess.run(['whois', f'AS{asn_number}'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    # Parse whois output for CIDR ranges
                    lines = result.stdout.split('\n')
                    for line in lines:
                        line = line.strip()
                        # Look for route/inetnum entries
                        if line.startswith('route:') or line.startswith('inetnum:'):
                            parts = line.split()
                            if len(parts) > 1:
                                potential_cidr = parts[1]
                                # Validate CIDR format
                                try:
                                    ipaddress.ip_network(potential_cidr, strict=False)
                                    ranges.append(potential_cidr)
                                except ValueError:
                                    continue
                    logger.info(f"Whois found {len(ranges)} ranges for ASN {asn_number}")
            except Exception as e:
                logger.warning(f"Whois lookup failed for ASN {asn_number}: {e}")
        
        # Method 3: Try RIPE API for European ASNs
        if not ranges:
            try:
                url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_number}"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    prefixes = data.get('data', {}).get('prefixes', [])
                    for prefix_info in prefixes:
                        prefix = prefix_info.get('prefix')
                        if prefix:
                            ranges.append(prefix)
                    logger.info(f"RIPE API found {len(ranges)} prefixes for ASN {asn_number}")
            except Exception as e:
                logger.warning(f"RIPE API failed for ASN {asn_number}: {e}")
        
        if not ranges:
            logger.error(f"No IP ranges found for ASN {asn_number}")
            return []
        
        # Remove duplicates and sort
        ranges = list(set(ranges))
        ranges.sort()
        
        logger.info(f"Total unique ranges found for ASN {asn_number}: {len(ranges)}")
        return ranges
    
    def sample_network_ips(self, network: ipaddress.IPv4Network, sample_size: int) -> List[str]:
        """Intelligently sample IPs from a large network"""
        
        all_hosts = list(network.hosts())
        total_hosts = len(all_hosts)
        
        if total_hosts <= sample_size:
            return [str(ip) for ip in all_hosts]
        
        # Intelligent sampling strategy
        sampled_ips = []
        
        # 1. Always include network boundaries (first and last few IPs)
        boundary_size = min(10, sample_size // 10)
        sampled_ips.extend(all_hosts[:boundary_size])  # First IPs
        sampled_ips.extend(all_hosts[-boundary_size:])  # Last IPs
        
        # 2. Sample from common server ranges (.1, .10, .100, etc.)
        common_endings = [1, 10, 50, 100, 200, 250, 254]
        for ending in common_endings:
            try:
                target_ip = ipaddress.IPv4Address(str(network.network_address + ending))
                if target_ip in network and target_ip not in sampled_ips:
                    sampled_ips.append(target_ip)
                    if len(sampled_ips) >= sample_size:
                        break
            except (ipaddress.AddressValueError, ValueError):
                continue
        
        # 3. Random sampling for the rest
        remaining_size = sample_size - len(sampled_ips)
        if remaining_size > 0:
            # Exclude already sampled IPs
            remaining_hosts = [ip for ip in all_hosts if ip not in sampled_ips]
            if remaining_hosts:
                random_sample = random.sample(remaining_hosts, 
                                            min(remaining_size, len(remaining_hosts)))
                sampled_ips.extend(random_sample)
        
        # Convert to strings and remove duplicates
        result = list(set([str(ip) for ip in sampled_ips]))
        
        logger.info(f"Sampled {len(result)} IPs from {network} ({total_hosts} total hosts)")
        return result
    
    def parse_nuclei_result(self, nuclei_data: Dict, target: str) -> Optional[Vulnerability]:
        """Parse nuclei scan result into Vulnerability object"""
        try:
            template_id = nuclei_data.get('template-id', '')
            info = nuclei_data.get('info', {})
            
            # Extract CVE if available
            cve_id = ''
            if 'classification' in info:
                cve_refs = info['classification'].get('cve-id', [])
                if cve_refs:
                    cve_id = cve_refs[0]
            
            # Get CVE details from database
            cve_info = None
            if cve_id:
                cve_info = self.cve_db.get_cve_info(cve_id)
            
            # Extract port from matched URL
            port = 80  # Default
            matched_at = nuclei_data.get('matched-at', '')
            if ':' in matched_at:
                try:
                    port = int(matched_at.split(':')[-1].split('/')[0])
                except:
                    pass
            
            # Check exploit availability
            exploit_available = False
            exploit_maturity = 'none'
            if cve_id:
                exploit_available, exploit_maturity = self.cve_db.check_exploit_availability(cve_id)
            
            return Vulnerability(
                cve_id=cve_id or template_id,
                cvss_score=cve_info.get('cvss_score', 0.0) if cve_info else 0.0,
                severity=info.get('severity', 'unknown').upper(),
                description=info.get('description', ''),
                exploit_available=exploit_available,
                exploit_maturity=exploit_maturity,
                affected_service=info.get('name', 'unknown'),
                target=target,
                port=port,
                remediation=info.get('remediation', ''),
                references=info.get('reference', [])
            )
            
        except Exception as e:
            logger.error(f"Error parsing nuclei result: {e}")
            return None
    
    def calculate_risk_assessment(self, vulnerabilities: List[Vulnerability], target: str) -> Dict:
        """Calculate overall risk assessment"""
        if not vulnerabilities:
            return {'total_score': 0.0, 'risk_level': 'Low'}
        
        # Calculate weighted risk score
        total_score = 0.0
        weights = {'Critical': 1.0, 'High': 0.8, 'Medium': 0.5, 'Low': 0.2}
        
        for vuln in vulnerabilities:
            severity_weight = weights.get(vuln.severity.title(), 0.2)
            exploit_weight = 1.5 if vuln.exploit_available else 1.0
            cvss_normalized = vuln.cvss_score / 10.0
            
            vuln_score = cvss_normalized * severity_weight * exploit_weight
            total_score += vuln_score
        
        # Normalize to 0-10 scale
        total_score = min(total_score / len(vulnerabilities) * 10, 10.0)
        
        # Determine risk level
        if total_score >= 8.0:
            risk_level = 'Critical'
        elif total_score >= 6.0:
            risk_level = 'High'
        elif total_score >= 4.0:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        return {
            'total_score': total_score,
            'risk_level': risk_level,
            'vulnerability_count': len(vulnerabilities),
            'exploit_count': sum(1 for v in vulnerabilities if v.exploit_available)
        }
    
    def assess_lateral_movement(self, target: str) -> bool:
        """Assess lateral movement potential"""
        network_context = self.graph_engine.get_network_context(target)
        return network_context['asset_count'] > 1

class EVMSWebInterface:
    """Simple web interface for EVMS control and reporting"""
    
    def __init__(self, scanner: EVMSScanner, port: int = 5000):
        self.scanner = scanner
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'evms-secret-key'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        self.port = port
        
        self.setup_routes()
        self.setup_socketio()
        self.setup_event_subscriptions()
    
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def index():
            return render_template('index.html')
        
        @self.app.route('/api/scan', methods=['POST'])
        def start_scan():
            data = request.json
            target = data.get('target')
            target_type = data.get('target_type', 'auto')
            
            if not target:
                return jsonify({'error': 'Target required'}), 400
            
            # Start scan in background
            threading.Thread(
                target=self.run_scan_async,
                args=(target, target_type)
            ).start()
            
            return jsonify({'status': 'Scan started', 'target': target})
        
        @self.app.route('/api/results/<target>')
        def get_results(target):
            # Get results from graph database
            with self.scanner.graph_engine.driver.session() as session:
                result = session.run("""
                    MATCH (a:Asset {ip: $target})-[:HAS_VULNERABILITY]->(v:Vulnerability)
                    RETURN a, collect(v) as vulnerabilities
                """, {'target': target})
                
                record = result.single()
                if record:
                    return jsonify({
                        'asset': dict(record['a']),
                        'vulnerabilities': [dict(v) for v in record['vulnerabilities']]
                    })
            
            return jsonify({'error': 'No results found'}), 404
        
        @self.app.route('/api/report/<target>/<format>')
        def generate_report(target, format):
            return self.generate_report_file(target, format)
    
    def setup_socketio(self):
        """Setup SocketIO events"""
        
        @self.socketio.on('connect')
        def handle_connect():
            emit('status', {'message': 'Connected to EVMS'})
        
        @self.socketio.on('chat_message')
        def handle_chat_message(data):
            message = data.get('message', '')
            
            # Simple chat responses (could integrate with LLM)
            if 'scan' in message.lower():
                response = "To start a scan, use the scan form or API endpoint /api/scan"
            elif 'status' in message.lower():
                response = "EVMS is running. Check the dashboard for current status."
            else:
                response = "I can help with scanning and vulnerability management. Try asking about scans or status."
            
            emit('chat_response', {'message': response})
    
    def setup_event_subscriptions(self):
        """Setup event bus subscriptions"""
        
        def on_scan_complete(data):
            """Handle scan completion events"""
            self.socketio.emit('scan_complete', data)
        
        def on_scan_error(data):
            """Handle scan error events"""
            self.socketio.emit('scan_error', data)
        
        # Subscribe to events
        event_bus.subscribe('scan.completed', on_scan_complete)
        event_bus.subscribe('scan.error', on_scan_error)
    
    def run_scan_async(self, target: str, target_type: str):
        """Run scan asynchronously and emit updates"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            scan_result = loop.run_until_complete(
                self.scanner.scan_target(target, target_type)
            )
            
            # Scan completion event is already published by the scanner
            # The event bus will notify the web interface
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            event_bus.publish('scan.error', {
                'target': target,
                'error': str(e)
            })
    
    def generate_report_file(self, target: str, format: str):
        """Generate and return report file"""
        # Get scan results
        with self.scanner.graph_engine.driver.session() as session:
            result = session.run("""
                MATCH (a:Asset {ip: $target})-[:HAS_VULNERABILITY]->(v:Vulnerability)
                RETURN a, collect(v) as vulnerabilities
            """, {'target': target})
            
            record = result.single()
            if not record:
                return jsonify({'error': 'No results found'}), 404
            
            asset_data = dict(record['a'])
            vulnerabilities = [dict(v) for v in record['vulnerabilities']]
        
        # Generate report content
        report_data = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'asset': asset_data,
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'critical_count': len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL']),
                'high_count': len([v for v in vulnerabilities if v.get('severity') == 'HIGH']),
                'medium_count': len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM']),
                'low_count': len([v for v in vulnerabilities if v.get('severity') == 'LOW'])
            }
        }
        
        if format == 'json':
            return jsonify(report_data)
        elif format == 'html':
            return self.generate_html_report(report_data)
        elif format == 'pdf':
            return self.generate_pdf_report(report_data)
        else:
            return jsonify({'error': 'Unsupported format'}), 400
    
    def generate_html_report(self, data: Dict) -> str:
        """Generate HTML report"""
        template = Template("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>EVMS Vulnerability Report - {{ data.target }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background: #2c3e50; color: white; padding: 20px; }
                .summary { background: #ecf0f1; padding: 15px; margin: 20px 0; }
                .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; }
                .critical { border-left: 5px solid #e74c3c; }
                .high { border-left: 5px solid #f39c12; }
                .medium { border-left: 5px solid #f1c40f; }
                .low { border-left: 5px solid #27ae60; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>EVMS Vulnerability Report</h1>
                <p>Target: {{ data.target }}</p>
                <p>Generated: {{ data.timestamp }}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p>Total Vulnerabilities: {{ data.summary.total_vulnerabilities }}</p>
                <p>Critical: {{ data.summary.critical_count }}</p>
                <p>High: {{ data.summary.high_count }}</p>
                <p>Medium: {{ data.summary.medium_count }}</p>
                <p>Low: {{ data.summary.low_count }}</p>
            </div>
            
            <h2>Vulnerability Details</h2>
            {% for vuln in data.vulnerabilities %}
            <div class="vulnerability {{ vuln.severity.lower() }}">
                <h3>{{ vuln.cve_id }}</h3>
                <p><strong>Severity:</strong> {{ vuln.severity }}</p>
                <p><strong>CVSS Score:</strong> {{ vuln.cvss_score }}</p>
                <p><strong>Description:</strong> {{ vuln.description }}</p>
                {% if vuln.exploit_available %}
                <p><strong>Exploit Available:</strong> Yes ({{ vuln.exploit_maturity }})</p>
                {% endif %}
            </div>
            {% endfor %}
        </body>
        </html>
        """)
        
        return template.render(data=data)
    
    def generate_pdf_report(self, data: Dict):
        """Generate PDF report"""
        html_content = self.generate_html_report(data)
        
        try:
            pdf_path = f"/tmp/evms_report_{data['target'].replace('.', '_')}.pdf"
            pdfkit.from_string(html_content, pdf_path)
            return send_file(pdf_path, as_attachment=True)
        except Exception as e:
            logger.error(f"PDF generation error: {e}")
            return jsonify({'error': 'PDF generation failed'}), 500
    
    def run(self):
        """Run the web interface"""
        self.socketio.run(self.app, host='0.0.0.0', port=self.port, debug=False)

# HTML template for web interface
WEB_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>EVMS - Enterprise Vulnerability Management Scanner</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .card { background: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input, select, textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 3px; }
        button { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer; }
        button:hover { background: #2980b9; }
        .status { padding: 10px; border-radius: 3px; margin-bottom: 10px; }
        .status.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .status.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .chat-container { height: 300px; border: 1px solid #ddd; padding: 10px; overflow-y: auto; background: white; }
        .chat-message { margin-bottom: 10px; }
        .chat-user { color: #2980b9; font-weight: bold; }
        .chat-bot { color: #27ae60; font-weight: bold; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        @media (max-width: 768px) { .grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ EVMS - Enterprise Vulnerability Management Scanner</h1>
            <p>Streamlined vulnerability scanning with Ensemble ML and LLM analysis</p>
        </div>
        
        <div class="grid">
            <div class="card">
                <h2>Scan Target</h2>
                <form id="scanForm">
                    <div class="form-group">
                        <label for="target">Target (IP, CIDR, Domain, ASN):</label>
                        <input type="text" id="target" name="target" placeholder="192.168.1.1 or example.com" required>
                    </div>
                    <div class="form-group">
                        <label for="targetType">Target Type:</label>
                        <select id="targetType" name="targetType">
                            <option value="auto">Auto-detect</option>
                            <option value="ip">IP Address</option>
                            <option value="cidr">CIDR Range</option>
                            <option value="domain">Domain</option>
                            <option value="asn">ASN</option>
                        </select>
                    </div>
                    <button type="submit">Start Scan</button>
                </form>
                
                <div id="scanStatus"></div>
            </div>
            
            <div class="card">
                <h2>Chat Interface</h2>
                <div id="chatContainer" class="chat-container"></div>
                <div class="form-group">
                    <input type="text" id="chatInput" placeholder="Ask about scans, vulnerabilities, or status...">
                    <button onclick="sendChatMessage()">Send</button>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>Recent Scans</h2>
            <div id="recentScans">
                <p>No scans completed yet.</p>
            </div>
        </div>
        
        <div class="card">
            <h2>Generate Reports</h2>
            <div class="form-group">
                <label for="reportTarget">Target:</label>
                <input type="text" id="reportTarget" placeholder="Enter target IP or domain">
            </div>
            <div class="form-group">
                <label for="reportFormat">Format:</label>
                <select id="reportFormat">
                    <option value="json">JSON</option>
                    <option value="html">HTML</option>
                    <option value="pdf">PDF</option>
                </select>
            </div>
            <button onclick="generateReport()">Generate Report</button>
        </div>
    </div>

    <script>
        const socket = io();
        
        // Socket event handlers
        socket.on('connect', function() {
            addChatMessage('System', 'Connected to EVMS');
        });
        
        socket.on('scan_complete', function(data) {
            showStatus(`Scan completed for ${data.target} - Priority: ${data.priority}`, 'success');
            updateRecentScans(data);
        });
        
        socket.on('scan_error', function(data) {
            showStatus(`Scan failed for ${data.target}: ${data.error}`, 'error');
        });
        
        socket.on('chat_response', function(data) {
            addChatMessage('EVMS', data.message);
        });
        
        // Form handlers
        document.getElementById('scanForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const target = document.getElementById('target').value;
            const targetType = document.getElementById('targetType').value;
            
            fetch('/api/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target: target, target_type: targetType})
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showStatus(data.error, 'error');
                } else {
                    showStatus(`Scan started for ${target}`, 'success');
                }
            })
            .catch(error => {
                showStatus('Scan request failed', 'error');
            });
        });
        
        // Chat functions
        function sendChatMessage() {
            const input = document.getElementById('chatInput');
            const message = input.value.trim();
            if (message) {
                addChatMessage('You', message);
                socket.emit('chat_message', {message: message});
                input.value = '';
            }
        }
        
        function addChatMessage(sender, message) {
            const container = document.getElementById('chatContainer');
            const messageDiv = document.createElement('div');
            messageDiv.className = 'chat-message';
            messageDiv.innerHTML = `<span class="chat-${sender.toLowerCase()}">${sender}:</span> ${message}`;
            container.appendChild(messageDiv);
            container.scrollTop = container.scrollHeight;
        }
        
        // Report generation
        function generateReport() {
            const target = document.getElementById('reportTarget').value;
            const format = document.getElementById('reportFormat').value;
            
            if (!target) {
                showStatus('Please enter a target for the report', 'error');
                return;
            }
            
            window.open(`/api/report/${target}/${format}`, '_blank');
        }
        
        // Utility functions
        function showStatus(message, type) {
            const statusDiv = document.getElementById('scanStatus');
            statusDiv.innerHTML = `<div class="status ${type}">${message}</div>`;
            setTimeout(() => {
                statusDiv.innerHTML = '';
            }, 5000);
        }
        
        function updateRecentScans(scanData) {
            const container = document.getElementById('recentScans');
            const scanDiv = document.createElement('div');
            scanDiv.innerHTML = `
                <p><strong>${scanData.target}</strong> - ${scanData.priority} priority 
                (${scanData.vulnerability_count} vulnerabilities) - ${new Date(scanData.timestamp).toLocaleString()}</p>
            `;
            container.insertBefore(scanDiv, container.firstChild);
        }
        
        // Enter key for chat
        document.getElementById('chatInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendChatMessage();
            }
        });
    </script>
</body>
</html>
"""

async def main():
    """Main EVMS entry point"""
    parser = argparse.ArgumentParser(description='EVMS - Enterprise Vulnerability Management Scanner')
    parser.add_argument('--target', help='Target to scan (IP, CIDR, domain, ASN)')
    parser.add_argument('--target-type', default='auto', choices=['auto', 'ip', 'cidr', 'domain', 'asn'])
    parser.add_argument('--web-only', action='store_true', help='Start web interface only')
    parser.add_argument('--config', default='evms_config.json', help='Configuration file')
    parser.add_argument('--port', type=int, default=5000, help='Web interface port')
    
    args = parser.parse_args()
    
    # Load configuration
    config = {
        'tools_dir': './tools',
        'data_dir': './data',
        'reports_dir': './reports',
        'neo4j_uri': os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
        'neo4j_user': os.getenv('NEO4J_USER', 'neo4j'),
        'neo4j_password': os.getenv('NEO4J_PASSWORD', 'password'),
        'openai_api_key': os.getenv('OPENAI_API_KEY', ''),
        'web_port': args.port
    }
    
    # Load config file if exists
    if os.path.exists(args.config):
        with open(args.config, 'r') as f:
            file_config = json.load(f)
            config.update(file_config)
    
    # Create directories
    for dir_key in ['tools_dir', 'data_dir', 'reports_dir']:
        Path(config[dir_key]).mkdir(exist_ok=True)
    
    # Create web template
    templates_dir = Path('templates')
    templates_dir.mkdir(exist_ok=True)
    with open(templates_dir / 'index.html', 'w') as f:
        f.write(WEB_TEMPLATE)
    
    # Initialize EVMS
    scanner = EVMSScanner(config)
    
    if not await scanner.initialize():
        logger.error("EVMS initialization failed")
        return 1
    
    # Start web interface
    web_interface = EVMSWebInterface(scanner, config['web_port'])
    
    if args.web_only:
        logger.info(f"Starting EVMS web interface on port {config['web_port']}")
        web_interface.run()
    elif args.target:
        # Command line scan
        logger.info(f"Starting scan of {args.target}")
        scan_result = await scanner.scan_target(args.target, args.target_type)
        
        # Print results
        print(f"\n=== EVMS Scan Results for {args.target} ===")
        print(f"Priority: {scan_result.priority}")
        print(f"Risk Score: {scan_result.risk_assessment['total_score']:.2f}")
        print(f"Vulnerabilities Found: {len(scan_result.vulnerabilities)}")
        print(f"Lateral Movement Potential: {scan_result.lateral_movement_potential}")
        
        if scan_result.vulnerabilities:
            print("\nTop Vulnerabilities:")
            for vuln in sorted(scan_result.vulnerabilities, key=lambda x: x.cvss_score, reverse=True)[:5]:
                print(f"  - {vuln.cve_id}: {vuln.severity} (CVSS: {vuln.cvss_score})")
                if vuln.exploit_available:
                    print(f"    ⚠️  Exploit available ({vuln.exploit_maturity})")
        
        # Start web interface for further interaction
        print(f"\nStarting web interface on http://localhost:{config['web_port']}")
        web_interface.run()
    else:
        # Interactive mode
        print("EVMS - Enterprise Vulnerability Management Scanner")
        print(f"Web interface available at http://localhost:{config['web_port']}")
        web_interface.run()
    
    return 0

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("EVMS shutdown requested")
        sys.exit(0)
    except Exception as e:
        logger.error(f"EVMS fatal error: {e}")
        sys.exit(1)