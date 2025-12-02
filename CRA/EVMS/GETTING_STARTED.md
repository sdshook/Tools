<!-- EVMS (c) Shane D. Shook, 2025 All Rights Reserved -->
# Getting Started with EVMS

## Quick Start Guide

Welcome to the Exposure and Vulnerability Management System (EVMS)! This guide will help you get up and running with EVMS in just a few minutes.

## Prerequisites

Before you begin, ensure you have the following installed on your system:

### Required Software
- **Docker** (version 20.10+) and **Docker Compose** (version 2.0+)
- **Node.js** (version 18+) and **npm** (version 8+)
- **Git** for version control
- **Python** (version 3.9+) for GraphRL components

### System Requirements
- **Minimum**: 8GB RAM, 4 CPU cores, 50GB storage
- **Recommended**: 16GB RAM, 8 CPU cores, 100GB SSD storage
- **Network**: Internet connection for vulnerability database updates

## Installation

### Option 1: Docker Compose (Recommended for Quick Start)

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd EVMS
   ```

2. **Configure Environment**
   ```bash
   # Copy the example environment file
   cp .env.example .env
   
   # Edit the configuration (optional for quick start)
   nano .env
   ```

3. **Start All Services**
   ```bash
   # Start the complete EVMS stack
   docker-compose up -d
   
   # Verify all services are running
   docker-compose ps
   ```

4. **Initialize the System**
   ```bash
   # Wait for services to be ready (about 2-3 minutes)
   sleep 180
   
   # Initialize databases and load sample data
   docker-compose exec orchestrator npm run db:init
   docker-compose exec orchestrator npm run db:seed
   ```

5. **Access the Dashboard**
   - Open your browser and navigate to: `http://localhost:3001`
   - Default credentials: `admin` / `admin123`

### Option 2: Manual Development Setup

1. **Clone and Install Dependencies**
   ```bash
   git clone <repository-url>
   cd EVMS
   npm install
   
   # Set up Python environment for GraphRL
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Start Infrastructure Services**
   ```bash
   # Start only the infrastructure (databases, messaging)
   docker-compose -f docker-compose.infrastructure.yml up -d
   ```

3. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your local configuration
   ```

4. **Initialize Databases**
   ```bash
   npm run db:init
   npm run db:seed
   ```

5. **Start Application Services**
   ```bash
   # Terminal 1: Start Orchestrator
   npm run start:orchestrator
   
   # Terminal 2: Start Agents
   npm run start:agents
   
   # Terminal 3: Start GraphRL (with Python venv activated)
   npm run start:graphrl
   
   # Terminal 4: Start Dashboard
   npm run start:dashboard
   ```

## First Steps

### 1. Verify Installation

Check that all services are running correctly:

```bash
# Check service health
curl http://localhost:3000/health
curl http://localhost:3001/health

# Check database connectivity
docker-compose exec neo4j cypher-shell -u neo4j -p evms_password "RETURN 'Neo4j Connected' as status"
docker-compose exec redis redis-cli ping
docker-compose exec nats nats-cli server check
```

### 2. Access the Dashboard

1. **Open the Web Interface**
   - Navigate to `http://localhost:3001`
   - Login with default credentials: `admin` / `admin123`

2. **Explore the Interface**
   - **Overview Dashboard**: Real-time system status and metrics
   - **Asset Management**: View and manage discovered assets
   - **Vulnerability Reports**: Browse detected vulnerabilities
   - **Risk Assessment**: Review risk scores and recommendations
   - **HOTL Interface**: Human oversight and approval workflows
   - **Chat Interface**: Natural language interaction with the system

### 3. Configure Your First Scan

1. **Add Target Networks**
   ```bash
   # Using the API
   curl -X POST http://localhost:3000/api/v1/targets \
     -H "Content-Type: application/json" \
     -d '{
       "name": "Internal Network",
       "cidr": "192.168.1.0/24",
       "description": "Internal corporate network",
       "priority": "high"
     }'
   ```

2. **Or Use the Web Interface**
   - Go to "Asset Management" → "Add Target"
   - Enter your network range (e.g., `192.168.1.0/24`)
   - Set scan priority and schedule
   - Click "Add Target"

### 4. Run Your First Scan

1. **Initiate a Discovery Scan**
   ```bash
   # Using the API
   curl -X POST http://localhost:3000/api/v1/scans \
     -H "Content-Type: application/json" \
     -d '{
       "type": "discovery",
       "targets": ["192.168.1.0/24"],
       "priority": "high"
     }'
   ```

2. **Monitor Scan Progress**
   - Watch the dashboard for real-time updates
   - Check the "Active Scans" section
   - View logs in the "System Logs" panel

3. **Review Results**
   - Navigate to "Scan Results" when complete
   - Explore discovered assets and services
   - Review any detected vulnerabilities

## Understanding the System

### Core Concepts

#### Assets
- **Definition**: Any discoverable network resource (servers, workstations, IoT devices)
- **Properties**: IP address, hostname, OS, services, criticality score
- **Relationships**: Network connections, service dependencies, vulnerability associations

#### Vulnerabilities
- **Definition**: Security weaknesses identified in assets
- **Sources**: CVE database, configuration audits, custom rules
- **Scoring**: CVSS base score enhanced with environmental factors
- **Lifecycle**: Discovery → Analysis → Risk Assessment → Remediation

#### Scans
- **Types**: Discovery, Vulnerability Assessment, Configuration Audit, Compliance Check
- **Scheduling**: On-demand, scheduled, event-triggered, AI-recommended
- **Agents**: Distributed scanning engines with specialized capabilities
- **Results**: Structured data stored in graph database for correlation

#### Risk Assessment
- **Calculation**: Multi-factor risk scoring combining CVSS, exploitability, asset criticality
- **GraphRL**: AI-driven risk prioritization and action recommendations
- **Context**: Business impact, network exposure, threat intelligence
- **Evolution**: Dynamic risk scores that adapt to changing conditions

#### HOTL (Human-On-The-Loop)
- **Purpose**: Human oversight for critical decisions and model training
- **Triggers**: High-risk findings, model uncertainty, policy violations
- **Workflow**: Review → Approve/Reject/Modify → Feedback → Model Learning
- **Interface**: Web dashboard with detailed context and recommendations

### System Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Dashboard   │◄──►│Orchestrator │◄──►│   Agents    │
│ (Web UI)    │    │ (Coordinator)│    │ (Scanners)  │
└─────────────┘    └─────────────┘    └─────────────┘
       ▲                   ▲                   ▲
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    HOTL     │    │   GraphRL   │    │ Data Layer  │
│ (Human Loop)│    │ (AI Engine) │    │(Graph+Cache)│
└─────────────┘    └─────────────┘    └─────────────┘
```

### Data Flow

1. **Task Creation**: Orchestrator creates scanning tasks based on schedules or AI recommendations
2. **Agent Execution**: Distributed agents execute scans and collect data
3. **Data Processing**: Results are processed, enriched, and stored in graph database
4. **AI Analysis**: GraphRL analyzes data, calculates risks, and suggests actions
5. **Human Review**: High-risk items are queued for HOTL review and approval
6. **Action Execution**: Approved actions are executed, results feed back to AI
7. **Continuous Learning**: System learns from outcomes and human feedback

## Common Tasks

### Adding New Targets

```bash
# Add a single host
curl -X POST http://localhost:3000/api/v1/targets \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Web Server",
    "host": "192.168.1.100",
    "tags": ["web", "production"],
    "criticality": "high"
  }'

# Add a network range
curl -X POST http://localhost:3000/api/v1/targets \
  -H "Content-Type: application/json" \
  -d '{
    "name": "DMZ Network",
    "cidr": "10.0.1.0/24",
    "tags": ["dmz", "external"],
    "criticality": "critical"
  }'
```

### Scheduling Regular Scans

```bash
# Schedule daily vulnerability scans
curl -X POST http://localhost:3000/api/v1/schedules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Daily Vuln Scan",
    "type": "vulnerability",
    "targets": ["all"],
    "schedule": "0 2 * * *",
    "enabled": true
  }'
```

### Viewing Scan Results

```bash
# List recent scans
curl http://localhost:3000/api/v1/scans?limit=10

# Get detailed scan results
curl http://localhost:3000/api/v1/scans/{scan-id}/results

# Get vulnerability summary
curl http://localhost:3000/api/v1/vulnerabilities?severity=high&limit=20
```

### Managing HOTL Reviews

```bash
# List pending reviews
curl http://localhost:3000/api/v1/hotl/reviews?status=pending

# Approve a finding
curl -X POST http://localhost:3000/api/v1/hotl/reviews/{review-id}/approve \
  -H "Content-Type: application/json" \
  -d '{"comment": "Approved for remediation"}'

# Reject a finding
curl -X POST http://localhost:3000/api/v1/hotl/reviews/{review-id}/reject \
  -H "Content-Type: application/json" \
  -d '{"comment": "False positive - service is properly configured"}'
```

## Configuration

### Environment Variables

Key configuration options in `.env`:

```bash
# Core Settings
NODE_ENV=development
LOG_LEVEL=info
PORT=3000

# Database Connections
NATS_URL=nats://localhost:4222
GRAPH_DB_URL=bolt://localhost:7687
REDIS_URL=redis://localhost:6379

# Security
JWT_SECRET=your-secret-key
BCRYPT_ROUNDS=12

# GraphRL Settings
GRAPHRL_LEARNING_RATE=0.001
GRAPHRL_TRAINING_ENABLED=true
GRAPHRL_EPSILON_START=1.0

# Scanning Configuration
MAX_CONCURRENT_SCANS=10
SCAN_TIMEOUT=3600
DEFAULT_SCAN_SCHEDULE="0 2 * * *"

# HOTL Configuration
HOTL_REVIEW_THRESHOLD=8.0
HOTL_TIMEOUT=3600
```

### Customizing Scan Policies

Create custom scan policies in `config/scan-policies.json`:

```json
{
  "policies": [
    {
      "name": "Critical Infrastructure",
      "targets": ["tag:critical"],
      "scans": ["vulnerability", "configuration", "compliance"],
      "frequency": "daily",
      "priority": "critical",
      "hotl_required": true
    },
    {
      "name": "Development Environment",
      "targets": ["tag:development"],
      "scans": ["vulnerability"],
      "frequency": "weekly",
      "priority": "low",
      "hotl_required": false
    }
  ]
}
```

## Monitoring and Troubleshooting

### Health Checks

```bash
# Check overall system health
curl http://localhost:3000/health

# Check individual service health
curl http://localhost:3000/health/orchestrator
curl http://localhost:3000/health/agents
curl http://localhost:3000/health/graphrl
curl http://localhost:3000/health/database
```

### Viewing Logs

```bash
# Docker Compose logs
docker-compose logs -f orchestrator
docker-compose logs -f agents
docker-compose logs -f graphrl

# Application logs (if running manually)
tail -f logs/orchestrator.log
tail -f logs/agents.log
tail -f logs/graphrl.log
```

### Common Issues

#### Services Not Starting
```bash
# Check Docker resources
docker system df
docker system prune

# Restart services
docker-compose restart
```

#### Database Connection Issues
```bash
# Test Neo4j connection
docker-compose exec neo4j cypher-shell -u neo4j -p evms_password "RETURN 1"

# Test Redis connection
docker-compose exec redis redis-cli ping

# Test NATS connection
docker-compose exec nats nats-cli server check
```

#### Performance Issues
```bash
# Check resource usage
docker stats

# Monitor system metrics
curl http://localhost:9090/metrics  # Prometheus metrics
```

## Next Steps

### Learning More
- Read the [Architecture Documentation](ARCHITECTURE.md) for system design details
- Explore the [GraphRL Design](GRAPHRL_DESIGN.md) for AI/ML implementation
- Review the [Deployment Guide](DEPLOYMENT.md) for production setup

### Customization
- Develop custom scanning agents
- Create specialized vulnerability rules
- Integrate with existing security tools
- Build custom dashboard widgets

### Integration
- Connect to SIEM systems
- Integrate with ticketing systems
- Set up automated remediation workflows
- Configure compliance reporting

### Community
- Join our Discord server for support
- Contribute to the project on GitHub
- Share your use cases and feedback
- Help improve documentation

## Support

If you encounter any issues or have questions:

1. **Check the Documentation**: Most common questions are answered in our docs
2. **Search Issues**: Look through existing GitHub issues for solutions
3. **Community Support**: Ask questions in our Discord community
4. **Create an Issue**: Report bugs or request features on GitHub
5. **Professional Support**: Contact us for enterprise support options

Welcome to EVMS! We're excited to see what you'll build with our platform.