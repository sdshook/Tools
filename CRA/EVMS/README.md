# EVMS - Enterprise Vulnerability Management Scanner

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
│ • GraphRL       │    │ • httpx          │    │ • OpenAI API    │
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
         │ │   Neo4j     │  │    NATS     │  │  SQLite   │ │
         │ │  GraphDB    │  │ JetStream   │  │  CVE DB   │ │
         │ └─────────────┘  └─────────────┘  └───────────┘ │
         └─────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### 1. Setup Environment

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

### 2. Start Services

```bash
# Start Neo4j and NATS (if using Docker)
docker-compose up -d

# Or install manually:
# - Neo4j: https://neo4j.com/download/
# - NATS: https://nats.io/download/
```

### 3. Run EVMS

```bash
# Web interface only
python evms.py --web-only

# Command line scan
python evms.py --target 192.168.1.0/24

# Scan with specific type
python evms.py --target example.com --target-type domain

# Interactive mode (scan + web interface)
python evms.py --target 10.0.0.1
```

## 📊 Vulnerability Prioritization

EVMS uses intelligent prioritization based on exploit availability and lateral movement potential:

### Priority Levels

- **🔴 Critical**: Service with High/Critical exploit + lateral movement potential
- **🟠 High**: Service with Medium exploit + lateral movement potential  
- **🟡 Medium**: Service with Low/Info exploit + no lateral movement potential
- **🟢 Low**: Weak configuration (RDP, VNC, Telnet, etc.)

### Prioritization Logic

```python
def prioritize_vulnerability(vuln, target_ip):
    exploit_available, maturity = check_exploit_availability(vuln.cve_id)
    lateral_movement = assess_lateral_movement_potential(target_ip)
    
    if exploit_available and maturity in ['functional', 'poc']:
        if vuln.severity in ['CRITICAL', 'HIGH'] and lateral_movement:
            return 'Critical'
        elif vuln.severity == 'MEDIUM' and lateral_movement:
            return 'High'
        elif vuln.severity in ['LOW', 'INFO'] and not lateral_movement:
            return 'Medium'
    
    if is_weak_configuration(vuln.service):
        return 'Low'
    
    return cvss_based_priority(vuln.cvss_score)
```

## 🔧 Security Tools Integration

### Required Tools
- **masscan**: Fast port scanner
- **nuclei**: Vulnerability scanner with templates
- **httpx**: HTTP service fingerprinting
- **subfinder**: Subdomain discovery

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

## 🧠 GraphRL & Machine Learning

### Graph Database Schema
```cypher
// Assets and their relationships
(Asset)-[:RUNS]->(Service)
(Asset)-[:HAS_VULNERABILITY]->(Vulnerability)
(Service)-[:AFFECTED_BY]->(Vulnerability)
(Asset)-[:CONNECTED_TO]->(Asset)  // Network topology
```

### GraphRL Features
- **Vulnerability Correlation**: ML-based vulnerability relationship discovery
- **Risk Scoring**: Graph-based risk propagation
- **Lateral Movement Assessment**: Network topology analysis
- **Gradient Descent**: Continuous learning from scan results

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

```bash
# Scan single IP
python evms.py --target 192.168.1.100

# Scan CIDR range
python evms.py --target 10.0.0.0/24

# Scan domain with subdomains
python evms.py --target example.com --target-type domain

# ASN scanning (requires BGP data)
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
NATS_URL=nats://localhost:4222

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
    "medium_cvss_threshold": 4.0
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

## 📈 Performance Tuning

### Scanning Performance
- **Masscan Rate**: Adjust based on network capacity
- **Concurrent Scans**: Limit based on system resources
- **Target Batching**: Process large ranges in batches

### Database Performance
- **Neo4j Memory**: Increase heap size for large datasets
- **Indexing**: Ensure proper indexes on frequently queried fields
- **Connection Pooling**: Configure appropriate pool sizes

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Submit pull request

## 📄 License

(c) Shane D. Shook, PhD, 2025 All Rights Reserved

## 🆘 Support

For issues and questions:
1. Check troubleshooting section
2. Review logs in `evms.log`
3. Open GitHub issue with details
4. Include configuration and error messages

---

**EVMS - Streamlined vulnerability management for the modern enterprise**