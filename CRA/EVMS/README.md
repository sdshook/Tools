# EVMS - Enterprise Vulnerability Management Scanner

**(c) Shane D. Shook, PhD, 2025 All Rights Reserved**

**A streamlined, single-script vulnerability management solution**

EVMS is a focused, practical vulnerability management tool that performs automated discovery, scanning, prioritization, and reporting against ASN, CIDR, TLD, FQDN, or IP addresses.

## 🎯 Core Objectives

1. **Single Python Script**: Everything runs from one executable script
2. **Automated Scanning**: Discovery, port scanning, service fingerprinting, and vulnerability detection
3. **Intelligent Prioritization**: Risk-based prioritization using exploit availability and lateral movement potential
4. **Comprehensive Reporting**: HTML, PDF, and JSON reports with LLM-powered analysis
5. **Real-time Interface**: Simple web interface for control, monitoring, and interaction

## 🛠 Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   EVMS Core     │    │   Security Tools │    │  External APIs  │
│                 │    │                  │    │                 │
│ • Scanner       │◄──►│ • masscan        │    │ • CVE Feeds     │
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
         │ │  GraphDB    │  │ (Internal)  │  │  CVE DB   │ │
         │ └─────────────┘  └─────────────┘  └───────────┘ │
         └─────────────────────────────────────────────────┘
```

## 🚀 Quick Start

## 🪟 Windows Installation Guide

EVMS fully supports Windows 10/11 with the following setup:

### Prerequisites
1. **Python 3.8+**: Download from [python.org](https://python.org) or install via Microsoft Store
2. **Git for Windows**: Download from [git-scm.com](https://git-scm.com/download/win)
3. **Windows Package Manager (winget)**: Included in Windows 10 1709+ and Windows 11

### Windows-Specific Tool Support
| Tool | Windows Support | Alternative |
|------|----------------|-------------|
| **nuclei** | ✅ Native Windows binary | - |
| **httpx** | ✅ Native Windows binary | - |
| **subfinder** | ✅ Native Windows binary | - |
| **masscan** | ❌ Not available | **nmap** (auto-installed) |

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
- **masscan**: Fast port scanner
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

## 🌐 Web Interface

### Features
- **Scan Control**: Start scans for any target type
- **Real-time Updates**: WebSocket-based live notifications
- **Chat Interface**: Natural language interaction with scan results
- **Dashboard**: Visual representation of scan results and trends
- **Report Generation**: On-demand HTML, PDF, and JSON reports

### API Endpoints
```
POST /api/scan              # Start new scan
GET  /api/results/<target>  # Get scan results
GET  /api/report/<target>/<format>  # Generate report
```

### WebSocket Events
```
scan_complete    # Scan finished notification
scan_error       # Scan failure notification
chat_response    # LLM chat response
```

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

### Web Interface Usage

1. **Start Web Interface**: `python evms.py --web-only`
2. **Access**: http://localhost:5000
3. **Start Scan**: Enter target in scan form
4. **Monitor Progress**: Real-time updates in interface
5. **Generate Reports**: Select target and format
6. **Chat Analysis**: Ask questions about scan results

### API Usage

```python
import requests

# Start scan
response = requests.post('http://localhost:5000/api/scan', 
                        json={'target': '192.168.1.1', 'target_type': 'ip'})

# Get results
results = requests.get('http://localhost:5000/api/results/192.168.1.1').json()

# Generate PDF report
report_url = 'http://localhost:5000/api/report/192.168.1.1/pdf'
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
- Uses **nmap** instead of masscan for port scanning
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
3. Port Scanning (masscan) → Open Ports Discovery
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