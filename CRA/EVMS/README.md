# EVMS - Enterprise Vulnerability Management Scanner

**(c) Shane D. Shook, PhD, 2025 All Rights Reserved**

**A streamlined, single-script enterprise vulnerability scanner**

EVMS is a focused, practical enterprise vulnerability scanner that performs automated discovery, scanning, prioritization, and reporting against ASN, CIDR, TLD, FQDN, or IP addresses.

## 🎯 Core Objectives

1. **Single Python Script**: Everything runs from one executable script
2. **Automated Scanning**: Discovery, port scanning, service fingerprinting, and vulnerability detection
3. **Intelligent Prioritization**: Risk-based prioritization using exploit availability and lateral movement potential
4. **Comprehensive Reporting**: HTML, PDF, JSON, and CSV reports with LLM-powered analysis
5. **Enterprise Web Dashboard**: Professional web interface with real-time metrics, AI assistant, and comprehensive scanning management capabilities

## 🛠 Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   EVMS Core     │    │   Security Tools │    │  External APIs  │
│                 │    │                  │    │                 │
│ • Scanner       │◄──►│ • masscan/WSL2   │    │ • CVE Feeds     │
│ • Prioritizer   │    │ • nuclei         │    │ • Exploit DB    │
│ • Ensemble ML   │    │ • httpx          │    │ • OpenAI API    │
│ • LLM Analyzer  │    │ • subfinder      │    │                 │
│ • Web Interface │    │ • zeek (optional)│    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
         ┌─────────────────────────────────────────────────┐
         │              Data Layer                         │
         │                                                 │
         │ ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │
         │ │   Neo4j     │  │ Event Bus   │  │  SQLite   │ │
         │ │  GraphDB    │  │ (Internal)  │  │CVE+Exploit│ │
         │ └─────────────┘  └─────────────┘  └───────────┘ │
         └─────────────────────────────────────────────────┘
```

**Data Layer Components:**
- **Neo4j GraphDB**: Network topology, asset relationships, lateral movement analysis
- **SQLite CVE+Exploit DB**: NVD vulnerability data + Exploit-DB integration with daily updates
- **Event Bus**: Real-time scan progress and WebSocket communication

## 🚀 Quick Start

## 🪟 Windows Installation Guide

EVMS fully supports Windows 10/11 with the following setup:

### Prerequisites
1. **Python 3.8+**: Download from [python.org](https://python.org) or install via Microsoft Store
2. **Git for Windows**: Download from [git-scm.com](https://git-scm.com/download/win)
3. **Windows Package Manager (winget)**: Included in Windows 10 1709+ and Windows 11

### Windows-Specific Tool Support
| Tool | Windows Support | Alternative | Notes |
|------|----------------|-------------|-------|
| **nuclei** | ✅ Native Windows binary | - | Full support |
| **httpx** | ✅ Native Windows binary | - | Full support |
| **subfinder** | ✅ Native Windows binary | - | Full support |
| **masscan** | ⚡ WSL2 support | **nmap** (fallback) | Preferred via WSL2 for speed |

### Port Scanner Options on Windows
EVMS automatically detects and configures the best available port scanner:

1. **masscan via WSL2** (Preferred) - Fastest option, requires WSL2 setup
2. **nmap** (Fallback) - Native Windows support, slower but reliable

**WSL2 Setup for masscan (Recommended):**
```powershell
# Enable WSL2 (requires restart)
wsl --install

# Install Ubuntu and masscan
wsl --install -d Ubuntu
wsl -d Ubuntu -e sudo apt update
wsl -d Ubuntu -e sudo apt install -y masscan

# Verify installation
wsl masscan --version
```

**Manual Scanner Selection:**
```bash
# Force use of specific scanner
python evms.py --scanner masscan --target 192.168.1.0/24
python evms.py --scanner nmap --target 192.168.1.0/24
```

### Windows Setup Steps
```powershell
# 1. Clone repository
git clone <repository>
cd EVMS

# 2. Run automated setup
python setup.py

# 3. Configure environment
copy .env.example .env
notepad .env  # Edit configuration

# 4. Start services (requires Docker Desktop)
docker-compose up -d

# 5. Run EVMS
python evms.py --web-only
```

### Windows Docker Setup
For full functionality, install **Docker Desktop for Windows**:
1. Download from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)
2. Enable WSL 2 backend (recommended)
3. Start Docker Desktop
4. Run `docker-compose up -d` in EVMS directory

### Alternative: Neo4j Desktop
If Docker is not available, install **Neo4j Desktop**:
1. Download from [neo4j.com/download](https://neo4j.com/download/)
2. Create a new database with password "password"
3. Start the database
4. Update `.env` file with connection details

### 1. Setup Environment

#### Linux/macOS
```bash
# Clone and setup
git clone <repository>
cd EVMS

# Run setup (installs dependencies and tools)
python setup.py

# Configure environment
cp .env.example .env
# Edit .env with your configuration
```

#### Windows
```powershell
# Clone and setup
git clone <repository>
cd EVMS

# Run setup (installs dependencies and tools)
python setup.py

# Configure environment
copy .env.example .env
# Edit .env with your configuration
```

**Windows Prerequisites:**
- Python 3.8+ (from [python.org](https://python.org) or Microsoft Store)
- Git for Windows
- Windows Package Manager (winget) - included in Windows 10 1709+

### 2. Start Services

#### Linux/macOS
```bash
# Start Neo4j (if using Docker)
docker-compose up -d

# Or install manually:
# - Neo4j: https://neo4j.com/download/
```

#### Windows
```powershell
# Start Neo4j (if using Docker Desktop)
docker-compose up -d

# Or install manually:
# - Neo4j Desktop: https://neo4j.com/download/
# - Docker Desktop: https://www.docker.com/products/docker-desktop
```

### 3. Run EVMS

**Supported Target Types:** ASN, CIDR, TLD (Top-Level Domain), FQDN (Fully Qualified Domain Name), or IP Address

#### Linux/macOS
```bash
# Web interface only
python evms.py --web-only

# IP Address scanning
python evms.py --target 192.168.1.100

# CIDR range scanning
python evms.py --target 192.168.1.0/24

# TLD scanning (domain + all subdomains)
python evms.py --target example.com --target-type domain

# FQDN scanning (specific host)
python evms.py --target www.example.com --target-type domain

# ASN scanning (Autonomous System Number)
python evms.py --target AS15169 --target-type asn

# Interactive mode (scan + web interface)
python evms.py --target 10.0.0.1
```

#### Windows
```powershell
# Web interface only
python evms.py --web-only

# IP Address scanning
python evms.py --target 192.168.1.100

# CIDR range scanning
python evms.py --target 192.168.1.0/24

# TLD scanning (domain + all subdomains)
python evms.py --target example.com --target-type domain

# FQDN scanning (specific host)
python evms.py --target www.example.com --target-type domain

# ASN scanning (Autonomous System Number)
python evms.py --target AS15169 --target-type asn

# Interactive mode (scan + web interface)
python evms.py --target 10.0.0.1
```

## 🔧 Platform-Aware Scanning

EVMS automatically detects your platform and configures the optimal scanning tools:

### Scanning Workflow
```
┌─────────────────┐
│ Platform Check  │
└─────────┬───────┘
          │
    ┌─────▼─────┐
    │  Windows? │
    └─────┬─────┘
          │
    ┌─────▼─────┐     ┌─────────────┐
    │ WSL2      │────►│ masscan     │ (Preferred - Fast)
    │ Available?│     │ via WSL2    │
    └─────┬─────┘     └─────────────┘
          │
          ▼
    ┌─────────────┐
    │ nmap        │ (Fallback - Reliable)
    │ (Native)    │
    └─────────────┘
```

### Scanner Selection Priority
1. **Linux/Unix**: Native masscan (fastest)
2. **Windows + WSL2**: masscan via WSL2 (fast, recommended)
3. **Windows only**: nmap (reliable fallback)

### Manual Override
```bash
# Check available scanners
python evms.py --help

# Force specific scanner
python evms.py --scanner masscan --target 192.168.1.0/24
python evms.py --scanner nmap --target 192.168.1.0/24
```

## 📊 Enhanced Vulnerability Prioritization

EVMS uses an advanced ensemble classifier combined with rule-based validation for intelligent vulnerability prioritization:

### Priority Levels

- **🔴 Critical**: High/Critical CVSS + exploit availability + network exposure (ensemble-enhanced)
- **🟠 High**: Medium exploit + lateral movement potential, or High/Critical exploit limited to host
- **🟡 Medium**: Low/Info exploit + lateral movement potential, or Medium exploit limited to host
- **🟢 Low**: Weak configuration (RDP, VNC, Telnet, etc.), or Low/Info exploit limited to host

### Ensemble Prioritization Logic

```python
def prioritize_vulnerability(vuln, target_ip):
    # Extract comprehensive features from GraphDB
    features = extract_graph_features(vuln, target_ip)
    
    # Get ensemble prediction from specialized models
    ensemble_priority = predict_priority_ensemble(features)
    
    # Validate with rule-based logic
    rule_priority = rule_based_prioritization(vuln, target_ip)
    
    # Use ensemble if validated, otherwise fallback to rules
    if validate_ensemble_prediction(ensemble_priority, rule_priority, vuln):
        return ensemble_priority
    else:
        return rule_priority

def extract_graph_features(vuln, target_ip):
    return {
        # CVSS & Exploit Features (8)
        'cvss_score': vuln.cvss_score,
        'severity_critical': 1 if vuln.severity == 'Critical' else 0,
        'exploit_available': 1 if vuln.exploit_available else 0,
        'exploit_maturity_functional': 1 if vuln.exploit_maturity == 'functional' else 0,
        
        # Network Topology Features (5) 
        'subnet_asset_count': get_subnet_asset_count(target_ip),
        'lateral_movement_ratio': get_lateral_movement_ratio(target_ip),
        'subnet_vuln_density': get_subnet_vulnerability_density(target_ip),
        
        # Service Context Features (6)
        'affects_web_service': 1 if vuln.port in [80, 443, 8080, 8443] else 0,
        'affects_remote_access': 1 if vuln.port in [22, 3389, 5900] else 0,
        'is_common_port': 1 if vuln.port in COMMON_PORTS else 0,
        
        # Historical Pattern Features (3)
        'cve_prevalence': get_cve_network_prevalence(vuln.cve_id),
        'avg_cve_asset_risk': get_average_cve_asset_risk(vuln.cve_id)
    }
```

### Ensemble Model Weights

- **XGBoost (CVSS/Exploit)**: 40% - Optimized for CVSS scores and exploit data
- **LightGBM (Network Topology)**: 35% - Specialized in lateral movement analysis  
- **Random Forest (Service Context)**: 25% - Expert in service-specific vulnerabilities

*Weights dynamically adjust based on vulnerability characteristics*

## 🔧 Security Tools Integration

### Required Tools
- **masscan/nmap**: Fast port scanner (platform-aware: masscan on Linux, nmap on Windows)
- **nuclei**: Vulnerability scanner with templates
- **httpx**: HTTP service fingerprinting
- **subfinder**: Subdomain discovery

### Required ML Libraries
- **xgboost**: Gradient boosting for CVSS/exploit analysis
- **lightgbm**: Fast gradient boosting for network topology
- **scikit-learn**: Random Forest and ensemble utilities
- **numpy**: Numerical computing for feature vectors

### Optional Tools
- **zeek**: Network flow capture and analysis (passive mode)

### Tool Configuration
```json
{
  "scanning": {
    "masscan_rate": 1000,
    "nuclei_templates": "./tools/nuclei/templates",
    "scan_timeout": 600,
    "max_targets": 100
  }
}
```

## 🗃️ Vulnerability Data Sources

EVMS integrates multiple authoritative sources for comprehensive vulnerability intelligence:

### CVE Database (NVD)
- **Source**: NIST National Vulnerability Database
- **Update Frequency**: Daily automatic updates
- **Data**: CVSS scores, severity ratings, vulnerability descriptions, CPE matches
- **Status**: ✅ **Fully Implemented** - Automatic feed updates with 30-day rolling window

### Exploit Database Integration
- **Source**: Exploit-DB (GitLab repository)
- **Update Frequency**: Daily automatic updates from `files_exploits.csv`
- **Data**: Exploit availability, maturity classification, platform details, author information
- **Features**:
  - Automatic CVE extraction from exploit descriptions
  - Intelligent maturity classification (functional vs proof-of-concept)
  - Metasploit module detection
  - Platform-specific exploit mapping
- **Status**: ✅ **Fully Implemented** - Complete integration with CVE-based prioritization

### Data Processing Pipeline
```python
# Automatic daily updates
await cve_db.update_cve_feeds()      # NVD CVE data
await cve_db.update_exploit_feeds()  # Exploit-DB CSV data

# Exploit availability checking
available, maturity = cve_db.check_exploit_availability("CVE-2024-12345")
# Returns: (True, "functional (2 functional, 1 PoC)")

# Detailed exploit information
exploits = cve_db.get_exploit_details("CVE-2024-12345")
# Returns: [{'exploit_db_id': '52177', 'maturity': 'functional', 'platform': 'linux', ...}]
```

## 🧠 Ensemble Machine Learning & GraphDB

### Graph Database Schema
```cypher
// Assets and their relationships
(Asset)-[:RUNS]->(Service)
(Asset)-[:HAS_VULNERABILITY]->(Vulnerability)
(Service)-[:AFFECTED_BY]->(Vulnerability)
(Asset)-[:CONNECTED_TO]->(Asset)  // Network topology

// Enhanced indexes for ensemble features
CREATE INDEX asset_subnet FOR (a:Asset) ON (a.subnet)
CREATE INDEX service_classification FOR (s:Service) ON (s.is_web_service, s.is_database, s.is_remote_access)
CREATE INDEX vulnerability_impact FOR (v:Vulnerability) ON (v.impact)
```

### Ensemble Classifier Architecture
- **XGBoost Model**: CVSS score and exploit availability analysis
- **LightGBM Model**: Network topology and lateral movement assessment  
- **Random Forest Model**: Service-specific vulnerability context
- **Weighted Voting**: Intelligent ensemble prediction with dynamic weight adjustment

### ML Features (22 total)
- **CVSS Features**: Score, severity levels, exploit maturity (8 features)
- **Network Features**: Subnet analysis, asset density, lateral movement potential (5 features)
- **Service Features**: Port analysis, service classification, common vulnerabilities (6 features)
- **Historical Features**: CVE prevalence, risk patterns across network (3 features)

### GraphDB-Powered Intelligence
- **Feature Engineering**: Comprehensive graph-based feature extraction
- **Network Context**: Subnet-level vulnerability density analysis
- **Service Classification**: Automated categorization of web, database, and remote access services
- **Historical Patterns**: CVE prevalence and risk correlation across the network

## 🤖 LLM/RAG Analysis

### Deterministic Analysis
- **Graph-Grounded Responses**: All analysis based on actual scan data
- **Source Attribution**: Clear citations of CVE IDs and CVSS scores
- **Confidence Scoring**: Reliability metrics for each analysis
- **Factual Reporting**: No hallucination, only data-driven insights

### Analysis Types
- **Risk Assessment**: Overall security posture evaluation
- **Attack Vector Analysis**: Potential exploitation paths
- **Remediation Guidance**: Prioritized fix recommendations
- **Business Impact**: Risk quantification and business context

## 🌐 Enterprise Web Dashboard

EVMS features a comprehensive enterprise-grade web interface that transforms vulnerability scanning from command-line operations into a professional, intuitive dashboard experience.

### 🎯 Dashboard Overview

The EVMS web interface provides a complete vulnerability scanning platform with:

- **Professional UI**: Modern, responsive design optimized for security teams
- **Real-time Metrics**: Live vulnerability counts, asset inventory, and system status
- **Interactive Visualizations**: Chart.js-powered vulnerability distribution charts
- **Tabbed Navigation**: Organized sections for different management functions
- **AI Security Assistant**: Intelligent chat interface with LLM integration

### 🚀 Key Features

#### 1. **Executive Dashboard**
- **Real-time Metrics Cards**: Critical/High/Medium/Low vulnerability counts
- **System Status Indicators**: Scanner, database, and LLM analyzer health
- **Quick Scan Interface**: Immediate scanning with auto-detection
- **Recent Activity Feed**: Live updates on scan progress and results

#### 2. **Advanced Scan Management**
- **Scan Queue**: Track multiple concurrent scans with progress bars
- **Advanced Configuration**: Port ranges, scan rates, target type selection
- **Scan History**: Complete audit trail with timestamps and results
- **Real-time Monitoring**: Live progress updates via WebSocket

#### 3. **Vulnerability Dashboard**
- **Interactive Charts**: Severity distribution with drill-down capabilities
- **Top Vulnerabilities**: Prioritized list with CVSS scores and CVE details
- **Detailed Views**: Comprehensive vulnerability information and affected assets
- **Advanced Filtering**: Search and filter by severity, CVE, asset, or status

#### 4. **Asset Inventory**
- **Network Discovery**: Comprehensive asset database with risk scoring
- **Asset Details**: OS detection, open ports, service enumeration
- **Risk Assessment**: Automated risk scoring per asset
- **Network Topology**: Visual representation of discovered assets

#### 5. **Advanced Reporting**
- **Multiple Formats**: HTML, PDF, JSON, CSV export options
- **Report Templates**: Executive summaries, technical details, compliance reports
- **Custom Reports**: Configurable report generation with filtering
- **Report History**: Archive and management of generated reports

#### 6. **AI Security Assistant**
- **LLM Integration**: Connected to EVMS LLM analyzer for intelligent responses
- **Context-Aware**: Understands current vulnerability state and scan results
- **Security Expertise**: Provides recommendations, analysis, and remediation guidance
- **Fallback Logic**: Enhanced rule-based responses when LLM unavailable

### 🎨 Technical Implementation

#### Modern Architecture
- **Responsive Design**: Mobile and desktop optimized interface
- **Chart.js Integration**: Interactive vulnerability visualization
- **SocketIO**: Real-time bidirectional communication
- **RESTful APIs**: Comprehensive backend endpoints
- **Error Handling**: Graceful degradation and robust error recovery

#### Real-time Features
- **Live Metrics**: Dashboard updates without page refresh
- **Scan Progress**: Real-time progress bars and status updates
- **Notifications**: Instant alerts for scan completion and errors
- **Chat Integration**: Live AI assistant responses

### 🔧 API Endpoints

#### Dashboard APIs
```
GET  /api/metrics           # Real-time vulnerability and asset metrics
GET  /api/status            # System health and component status
GET  /api/scans             # Active and completed scan information
GET  /api/vulnerabilities   # Vulnerability data with chart information
GET  /api/assets            # Asset inventory with risk scores
```

#### Management APIs
```
POST /api/scan              # Initiate new scans with configuration
GET  /api/results/<target>  # Get detailed scan results
GET  /api/report/<target>/<format>  # Generate reports (HTML/PDF/JSON/CSV)
```

#### WebSocket Events
```
scan_complete       # Scan finished notification with results
scan_error          # Scan failure notification with error details
chat_response       # LLM chat response from AI assistant
ai_chat_message     # Enhanced AI chat with context awareness
status              # System status updates and health checks
```

### 🚀 Getting Started with Web Interface

#### Quick Start
```bash
# Start web interface only
python evms.py --web-only

# Start with custom port
python evms.py --web-only --port 8080

# Start with scan and web interface
python evms.py --target 192.168.1.0/24
```

#### Access the Dashboard
1. **URL**: http://localhost:5000 (or custom port)
2. **Mobile**: Fully responsive design works on all devices
3. **Features**: All functionality available through intuitive interface

#### Dashboard Navigation
- **Dashboard Tab**: Overview metrics, quick scan, system status
- **Scans Tab**: Advanced scan management and monitoring
- **Vulnerabilities Tab**: Detailed vulnerability analysis and charts
- **Assets Tab**: Network inventory and asset management
- **Reports Tab**: Report generation and history
- **AI Assistant Tab**: Intelligent security consultation

### 🎯 Use Cases

#### For Security Teams
- **Centralized Scanning**: Single pane of glass for vulnerability scanning operations
- **Real-time Visibility**: Live updates on scan progress and vulnerability discovery
- **Intelligent Analysis**: AI-powered insights and vulnerability prioritization
- **Comprehensive Reporting**: Multiple formats for different stakeholders

#### For Management
- **Executive Dashboard**: High-level metrics and risk visualization
- **Trend Analysis**: Historical vulnerability and risk trends
- **Compliance Reports**: Automated compliance documentation
- **ROI Tracking**: Scan efficiency and vulnerability reduction metrics

#### For Operations
- **Automated Scanning**: Scheduled and on-demand vulnerability scanning
- **Asset Discovery**: Comprehensive network asset discovery and inventory
- **Integration Ready**: API-first design for integration with security tools
- **Scalable Architecture**: Enterprise-grade scanning performance and reliability

### 🔒 Security Features

- **Secure Communication**: HTTPS support and secure WebSocket connections
- **Access Control**: Built-in authentication and authorization (configurable)
- **Data Protection**: Secure handling of vulnerability scan data and asset information
- **Audit Trail**: Complete logging of all scan activities and system events

## 📋 Usage Examples

### Command Line Scanning

**Available Target Types:** ASN, CIDR, TLD (Top-Level Domain), FQDN (Fully Qualified Domain Name), or IP Address

```bash
# IP Address - Scan single IP
python evms.py --target 192.168.1.100

# CIDR - Scan network range
python evms.py --target 10.0.0.0/24

# TLD - Scan domain with subdomain discovery
python evms.py --target example.com --target-type domain

# FQDN - Scan specific fully qualified domain name
python evms.py --target www.example.com --target-type domain

# ASN - Scan Autonomous System Number (requires BGP data)
python evms.py --target AS15169 --target-type asn
```

### Web Dashboard Usage

#### Getting Started
1. **Start Dashboard**: `python evms.py --web-only`
2. **Access Interface**: http://localhost:5000
3. **Navigate Tabs**: Use tabbed interface for different functions

#### Dashboard Workflow
1. **Overview**: Check system status and metrics on Dashboard tab
2. **Quick Scan**: Use the quick scan form for immediate scanning
3. **Advanced Scanning**: Go to Scans tab for detailed configuration
4. **Monitor Progress**: Watch real-time scan progress and notifications
5. **Analyze Results**: Use Vulnerabilities tab for detailed analysis
6. **Asset Management**: Review discovered assets in Assets tab
7. **Generate Reports**: Create reports in Reports tab with multiple formats
8. **AI Consultation**: Ask the AI Assistant for security insights and recommendations

#### Key Dashboard Features
- **Real-time Metrics**: Live vulnerability counts and system health
- **Interactive Charts**: Click and explore vulnerability distributions
- **Scan Management**: Queue, monitor, and configure scans
- **Asset Inventory**: Complete network asset discovery and risk assessment
- **AI Assistant**: Intelligent security analysis and recommendations
- **Report Generation**: Professional reports in HTML, PDF, JSON, CSV formats

### API Usage

```python
import requests

# Dashboard APIs - Get real-time metrics
metrics = requests.get('http://localhost:5000/api/metrics').json()
print(f"Critical vulnerabilities: {metrics['critical']}")

# System status
status = requests.get('http://localhost:5000/api/status').json()
print(f"Scanner: {status['scanner']}, Database: {status['database']}")

# Start scan with configuration
response = requests.post('http://localhost:5000/api/scan', 
                        json={'target': '192.168.1.1', 'target_type': 'ip'})

# Get vulnerability data with charts
vulns = requests.get('http://localhost:5000/api/vulnerabilities').json()
chart_data = vulns['chart_data']
vulnerability_list = vulns['vulnerabilities']

# Get asset inventory
assets = requests.get('http://localhost:5000/api/assets').json()
for asset in assets['assets']:
    print(f"Asset: {asset['ip']}, Risk Score: {asset['risk_score']}")

# Get scan results
results = requests.get('http://localhost:5000/api/results/192.168.1.1').json()

# Generate reports in multiple formats
pdf_report = 'http://localhost:5000/api/report/192.168.1.1/pdf'
html_report = 'http://localhost:5000/api/report/192.168.1.1/html'
json_report = 'http://localhost:5000/api/report/192.168.1.1/json'
csv_report = 'http://localhost:5000/api/report/192.168.1.1/csv'
```

## 📋 Complete CLI & API Reference

### Command Line Interface (CLI) Options

| Option | Type | Default | Description | Example |
|--------|------|---------|-------------|---------|
| `--target` | string | None | Target to scan (IP, CIDR, TLD, FQDN, ASN) | `--target 192.168.1.100` |
| `--target-type` | choice | `auto` | Target type: `auto`, `ip`, `cidr`, `domain`, `asn` | `--target-type domain` |
| `--web-only` | flag | False | Start web interface only (no scanning) | `--web-only` |
| `--config` | string | `evms_config.json` | Configuration file path | `--config custom_config.json` |
| `--port` | integer | `5000` | Web interface port | `--port 8080` |

### CLI Usage Examples

#### Linux/macOS
```bash
# Auto-detect target type and scan
python evms.py --target 192.168.1.100

# TLD scanning (domain + subdomains)
python evms.py --target example.com --target-type domain

# FQDN scanning (specific host)
python evms.py --target mail.example.com --target-type domain

# Web interface only on custom port
python evms.py --web-only --port 8080

# Custom configuration file
python evms.py --target 10.0.0.0/24 --config production_config.json
```

#### Windows
```powershell
# Auto-detect target type and scan
python evms.py --target 192.168.1.100

# TLD scanning (domain + subdomains)
python evms.py --target example.com --target-type domain

# FQDN scanning (specific host)
python evms.py --target mail.example.com --target-type domain

# Web interface only on custom port
python evms.py --web-only --port 8080

# Custom configuration file
python evms.py --target 10.0.0.0/24 --config production_config.json
```

**Windows Notes:**
- **Automatic Platform Detection**: EVMS automatically detects Windows and uses **nmap** for port scanning instead of masscan
- **Seamless Operation**: No configuration changes needed - the same commands work on both Windows and Linux
- **Compatible Output**: nmap results are automatically converted to match masscan format for consistent processing
- All ProjectDiscovery tools (nuclei, httpx, subfinder) have native Windows support
- Requires Docker Desktop or Neo4j Desktop for database functionality

### REST API Endpoints

| Method | Endpoint | Description | Request Body | Response |
|--------|----------|-------------|--------------|----------|
| `GET` | `/` | Web interface homepage | None | HTML page |
| `POST` | `/api/scan` | Start new scan | `{"target": "string", "target_type": "string"}` | `{"status": "string", "target": "string"}` |
| `GET` | `/api/results/<target>` | Get scan results for target | None | `{"asset": {}, "vulnerabilities": []}` |
| `GET` | `/api/report/<target>/<format>` | Generate report (html/pdf/json) | None | Report file or JSON |

### API Request/Response Examples

#### Start Scan
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.100", "target_type": "ip"}'

# Response
{"status": "Scan started", "target": "192.168.1.100"}
```

#### Get Results
```bash
curl http://localhost:5000/api/results/192.168.1.100

# Response
{
  "asset": {
    "ip": "192.168.1.100",
    "hostname": "server.local",
    "ports": [22, 80, 443]
  },
  "vulnerabilities": [
    {
      "cve_id": "CVE-2023-1234",
      "severity": "High",
      "cvss_score": 7.5,
      "description": "Remote code execution vulnerability"
    }
  ]
}
```

#### Generate Report
```bash
# HTML Report
curl http://localhost:5000/api/report/192.168.1.100/html

# PDF Report
curl http://localhost:5000/api/report/192.168.1.100/pdf

# JSON Report
curl http://localhost:5000/api/report/192.168.1.100/json
```

### WebSocket Events

| Event | Direction | Description | Data Format |
|-------|-----------|-------------|-------------|
| `connect` | Client → Server | Client connection established | None |
| `status` | Server → Client | Connection status message | `{"message": "string"}` |
| `chat_message` | Client → Server | Send chat message | `{"message": "string"}` |
| `chat_response` | Server → Client | Chat response from EVMS | `{"message": "string"}` |
| `scan_complete` | Server → Client | Scan completion notification | `{"target": "string", "status": "complete"}` |
| `scan_error` | Server → Client | Scan error notification | `{"target": "string", "error": "string"}` |

### WebSocket Usage Example

```javascript
// Connect to WebSocket
const socket = io();

// Listen for status updates
socket.on('status', (data) => {
    console.log('Status:', data.message);
});

// Send chat message
socket.emit('chat_message', {message: 'What is the scan status?'});

// Listen for chat responses
socket.on('chat_response', (data) => {
    console.log('EVMS:', data.message);
});

// Listen for scan completion
socket.on('scan_complete', (data) => {
    console.log('Scan completed for:', data.target);
});
```

## 🎯 Target Discovery & Scanning

EVMS supports comprehensive target discovery for all input types with intelligent sampling and complete attack surface mapping.

### Supported Target Types

#### TLD (Top-Level Domain) Discovery
```bash
python evms.py --target example.com
```
**Process:**
1. **Subdomain Enumeration**: Uses subfinder to discover all subdomains
2. **DNS Resolution**: Resolves all domains to unique IP addresses  
3. **Complete Coverage**: Scans entire domain infrastructure

#### FQDN (Fully Qualified Domain Name) Discovery
```bash
python evms.py --target www.example.com
```
**Process:**
1. **Direct Resolution**: Resolves specific FQDN to IP address
2. **Targeted Scanning**: Focuses on single host infrastructure
3. **Service Discovery**: Enumerates services on resolved IP

**TLD Example Flow:**
```
Input: example.com (TLD)
↓
Subfinder Discovery: [www.example.com, api.example.com, mail.example.com]
↓
DNS Resolution: [192.168.1.1, 192.168.1.2, 192.168.1.3]
↓
Complete Infrastructure Scan: All IPs + Services
```

**FQDN Example Flow:**
```
Input: www.example.com (FQDN)
↓
Direct DNS Resolution: 192.168.1.1
↓
Targeted Host Scan: Single IP + Services
```

#### ASN Discovery
```bash
python evms.py --target AS15169    # Google
python evms.py --target as1234     # Lowercase
python evms.py --target 1234       # Plain number
```
**Process:**
1. **BGP Data Sources**: Multiple fallback APIs (BGPView, RIPE, whois)
2. **CIDR Extraction**: Discovers all network ranges for the ASN
3. **Intelligent Sampling**: Smart IP selection based on network size

**Sampling Strategy:**
- **Small networks** (<1000 IPs): Scan all hosts
- **Medium networks** (1000-10000 IPs): Sample 500 IPs
- **Large networks** (>10000 IPs): Sample 1000 IPs

#### CIDR Discovery
```bash
python evms.py --target 192.168.1.0/24    # Small network - scan all
python evms.py --target 10.0.0.0/22       # Medium network - sample 500
python evms.py --target 172.16.0.0/16     # Large network - sample 1000
```
**Smart Sampling Strategy:**
1. **Network Boundaries**: Always include first/last IPs
2. **Common Server IPs**: Target typical server addresses (.1, .10, .100)
3. **Random Sampling**: Fill remaining slots with random IPs

#### IP Discovery
```bash
python evms.py --target 192.168.1.100
```
**Process:** Direct scanning of specified IP address

### Complete Scanning Flow

```
1. Target Input → Target Type Detection
2. Target Discovery → IP List Generation
3. Port Scanning (masscan/nmap) → Open Ports Discovery
4. Service URL Building → Service URLs Creation
5. Service Fingerprinting (httpx) → Web Technologies
6. Vulnerability Scanning (nuclei) → Vulnerabilities
7. Risk Assessment → Prioritized Results
```

### Performance Considerations

#### ASN Scanning
- **API Rate Limits**: Multiple fallback sources prevent failures
- **Large ASNs**: Intelligent sampling prevents overwhelming scans
- **Timeout Handling**: 30-second timeouts for API calls

#### CIDR Scanning
- **Memory Usage**: Streaming IP generation for large networks
- **Scan Time**: Sampling reduces scan time from hours to minutes
- **Coverage**: Smart sampling ensures good coverage of likely targets

#### Domain Scanning
- **DNS Resolution**: Parallel resolution with error handling
- **Duplicate Removal**: Multiple domains may resolve to same IP
- **Subdomain Limits**: Subfinder naturally limits results

### Error Handling

- **API Unavailable**: Falls back to whois command for ASN data
- **DNS Failures**: Logs warning and continues with other domains
- **Invalid Formats**: Validates and skips malformed inputs
- **Memory Limits**: Streaming generation for large networks

## 📊 Report Formats

### JSON Report
```json
{
  "target": "192.168.1.100",
  "timestamp": "2025-12-02T10:30:00Z",
  "priority": "High",
  "risk_score": 7.5,
  "vulnerabilities": [...],
  "llm_analysis": "...",
  "recommendations": [...]
}
```

### HTML Report
- Executive summary with risk metrics
- Detailed vulnerability listings
- Remediation recommendations
- Visual charts and graphs

### PDF Report
- Professional formatting
- Executive and technical sections
- Compliance-ready documentation
- Printable format

## ⚙️ Configuration

### Environment Variables
```bash
# Database connections
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password

# LLM configuration
OPENAI_API_KEY=your_api_key_here

# Scanning parameters
MASSCAN_RATE=1000
SCAN_TIMEOUT=600
```

### Configuration File (evms_config.json)
```json
{
  "tools_dir": "./tools",
  "data_dir": "./data",
  "reports_dir": "./reports",
  "web_port": 5000,
  "scanning": {
    "masscan_rate": 1000,
    "scan_timeout": 600,
    "max_targets": 100
  },
  "prioritization": {
    "critical_cvss_threshold": 9.0,
    "high_cvss_threshold": 7.0,
    "medium_cvss_threshold": 4.0,
    "use_ensemble": true,
    "ensemble_weights": {
      "cvss_exploit": 0.4,
      "network_topology": 0.35,
      "service_context": 0.25
    }
  },
  "machine_learning": {
    "training_data_limit": 1000,
    "min_training_samples": 10,
    "model_validation_threshold": 1,
    "xgboost_params": {
      "max_depth": 6,
      "learning_rate": 0.1,
      "n_estimators": 100
    },
    "lightgbm_params": {
      "max_depth": 8,
      "learning_rate": 0.05,
      "n_estimators": 150
    },
    "random_forest_params": {
      "n_estimators": 200,
      "max_depth": 10,
      "min_samples_split": 5
    }
  }
}
```

## 🔒 Security Considerations

### Scanning Ethics
- **Passive Mode**: Default non-intrusive scanning
- **Rate Limiting**: Configurable scan rates to avoid DoS
- **Target Validation**: Ensure authorization before scanning
- **Network Isolation**: Consider network segmentation

### Data Protection
- **Local Storage**: All data stored locally by default
- **Encryption**: Sensitive data encrypted at rest
- **Access Control**: Web interface authentication
- **Audit Logging**: Complete audit trail of all activities

## 🚨 Troubleshooting

### Common Issues

**Tools Not Found**
```bash
# Re-run setup to download tools
python setup.py

# Check tool status
ls -la tools/*/
```

**Database Connection Failed**
```bash
# Check services
docker-compose ps

# Restart services
docker-compose restart
```

**Scan Timeout**
```bash
# Increase timeout in config
"scan_timeout": 1200  # 20 minutes
```

**Permission Denied**
```bash
# Make tools executable
chmod +x tools/*/bin/*
chmod +x tools/*/*
```

**ML Libraries Missing**
```bash
# Install required ML libraries
pip install xgboost lightgbm scikit-learn numpy

# Verify installation
python -c "import xgboost, lightgbm, sklearn; print('ML libraries installed successfully')"
```

**Ensemble Prediction Errors**
```bash
# Check training data availability
# Ensemble falls back to rule-based prioritization if insufficient data

# Disable ensemble temporarily
# Set "use_ensemble": false in configuration
```

## 📈 Performance Tuning

### Scanning Performance
- **Masscan Rate**: Adjust based on network capacity
- **Concurrent Scans**: Limit based on system resources
- **Target Batching**: Process large ranges in batches

### Database Performance
- **Neo4j Memory**: Increase heap size for large datasets
- **Indexing**: Ensure proper indexes on frequently queried fields
- **Connection Pooling**: Configure appropriate pool sizes

### Machine Learning Performance
- **Feature Extraction**: GraphDB indexes optimize feature queries
- **Model Training**: Adjust ensemble parameters based on dataset size
- **Prediction Caching**: Results cached to avoid redundant ML inference
- **Batch Processing**: Process multiple vulnerabilities simultaneously for efficiency

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Submit pull request

## 📄 License

(c) Shane D. Shook, PhD, 2025 All Rights Reserved

## 🪟 Windows Troubleshooting

### Common Windows Issues

#### Python Not Found
```powershell
# Install Python from Microsoft Store or python.org
winget install Python.Python.3.12

# Or download from python.org and add to PATH
```

#### Git Not Found
```powershell
# Install Git for Windows
winget install Git.Git

# Or download from git-scm.com
```

#### Docker Issues
```powershell
# Install Docker Desktop
winget install Docker.DockerDesktop

# Enable WSL 2 (recommended)
wsl --install
```

#### Tool Installation Failures
```powershell
# Check winget availability
winget --version

# Manual nmap installation if winget fails
# Download from: https://nmap.org/download.html
```

#### Permission Errors
```powershell
# Run PowerShell as Administrator for setup
# Right-click PowerShell → "Run as administrator"

# Or use Windows Terminal with admin privileges
```

#### Path Issues
```powershell
# Add Python to PATH manually
$env:PATH += ";C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python312"

# Verify Python installation
python --version
```

### Windows-Specific Configuration

#### Neo4j Desktop Setup
1. Download Neo4j Desktop from [neo4j.com/download](https://neo4j.com/download/)
2. Create new project and database
3. Set password to "password" (or update .env file)
4. Start database before running EVMS

#### Docker Desktop Setup
1. Install Docker Desktop for Windows
2. Enable WSL 2 integration (Settings → General → Use WSL 2)
3. Start Docker Desktop
4. Verify with: `docker --version`

#### Firewall Configuration
Windows Defender may block EVMS web interface:
1. Allow Python through Windows Firewall
2. Or temporarily disable firewall for testing
3. Add exception for port 5000 (or custom port)

## 🆘 Support

For issues and questions:
1. Check troubleshooting section (including Windows-specific issues above)
2. Review logs in `evms.log`
3. Open GitHub issue with details
4. Include configuration and error messages

---

**EVMS - Streamlined vulnerability management for the modern enterprise**