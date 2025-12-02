<!-- EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved -->
# EVMS - Exposure and Vulnerability Management System

## Overview

The Exposure and Vulnerability Management System (EVMS) is an autonomous, Human-On-The-Loop (HOTL) supported vulnerability scanning and risk assessment platform that leverages Graph Reinforcement Learning (GraphRL) for intelligent threat discovery, correlation, and risk prioritization.

## Architecture

### Core Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Orchestrator  │───▶│     Agents      │───▶│   Persistence   │
│                 │    │                 │    │                 │
│ - Task Dispatch │    │ - Vulnerability │    │ - NATS JetStream│
│ - Coordination  │    │   Scanning      │    │ - Graph DB      │
│ - Scheduling    │    │ - Asset Discovery│    │ - KVS Storage   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         ▲                       ▲                       │
         │                       │                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   HOTL Interface│    │   GraphRL       │    │ Feature Pipeline│
│                 │    │                 │    │                 │
│ - Review/Override│    │ - Risk Scoring  │    │ - Data Transform│
│ - Approval      │    │ - Action Suggest│    │ - Graph Updates │
│ - Feedback      │    │ - Learning      │    │ - Correlation   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         ▲                       ▲                       ▲
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌─────────────────┐
                    │ LLM/RAG Dashboard│
                    │                 │
                    │ - Chat Interface│
                    │ - Reporting     │
                    │ - Visualization │
                    └─────────────────┘
```

## System Flow

### 1. Task Orchestration
- **Orchestrator** issues scanning tasks based on:
  - Scheduled assessments
  - Risk-based prioritization
  - GraphRL recommendations
  - HOTL directives

### 2. Agent Execution
- **Scanning Agents** perform:
  - Network discovery and enumeration
  - Vulnerability assessment
  - Configuration analysis
  - Compliance checking
  - CVE/CWE correlation

### 3. Data Persistence
- **NATS JetStream** provides:
  - Reliable message delivery
  - Event streaming
  - Fault tolerance
  - Key-Value storage
  - Object storage
- **Graph Database** stores:
  - Asset relationships
  - Vulnerability correlations
  - Risk dependencies
- **NATS KV Store** maintains:
  - Configuration state
  - Agent metadata
  - Scan results cache
  - Session data

### 4. Feature Engineering
- **Pipeline** processes:
  - Raw scan data transformation
  - Graph relationship updates
  - Feature vector generation
  - Correlation analysis

### 5. GraphRL Intelligence
- **Reinforcement Learning** provides:
  - Dynamic risk scoring
  - Action recommendations
  - Adaptive scanning strategies
  - Continuous learning from outcomes

### 6. Human Oversight
- **HOTL Interface** enables:
  - Review of high-risk findings
  - Override of automated decisions
  - Approval of remediation actions
  - Feedback for model training

### 7. Gradient Descent Learning
- **Training Loop**:
  - Reward signals from HOTL feedback
  - Backpropagation through graph networks
  - Model parameter updates
  - Performance optimization

## Technology Stack

### Open Source Core Components
- **Masscan**: Ultra-fast network discovery and port scanning
- **Nuclei**: Template-based vulnerability scanner with extensive community templates
- **Zeek**: Network security monitoring and protocol analysis
- **NATS.io + JetStream**: Event bus, message streaming and persistence
- **GraphRL**: Custom graph-based reinforcement learning for risk prioritization
- **LLM/RAG**: Large Language Models with Retrieval-Augmented Generation for natural language queries

### Integrated Security Tools
- **Masscan**: High-speed port scanner for network discovery and enumeration
- **Nuclei**: Template-based vulnerability scanner with community-driven detection rules
- **Subfinder**: Subdomain discovery tool for comprehensive asset mapping
- **Httpx**: HTTP toolkit for web service probing and technology fingerprinting

### Supporting Infrastructure
- **Neo4j**: Graph database for unified asset relationships
- **NATS KV Store**: High-performance key-value storage and caching
- **Node.js**: Runtime environment for orchestration and services
- **Python**: Machine learning and data processing components

### Capabilities Delivered
- **Active Discovery**: Masscan for rapid network enumeration
- **Passive Discovery**: Zeek for traffic-based asset identification
- **Fingerprinting**: Service and OS detection via Nuclei templates
- **Identity Flows**: User and service authentication tracking
- **Behavioral Flows**: Network communication pattern analysis
- **Protocol Intelligence**: Deep packet inspection and protocol analysis
- **Device Classification**: ML-based device type and role identification
- **Exposure Mapping**: Attack surface visualization and analysis
- **Risk Scoring**: GraphRL-powered intelligent risk prioritization
- **Unified Asset Graph**: Comprehensive relationship modeling
- **Natural-language ESM Queries**: LLM-powered security analytics interface

### User Interface
- **Dashboard**: Real-time risk visualization and metrics
- **Chat Interface**: LLM/RAG-powered natural language interaction for queries, analysis, and reporting
- **Reporting**: Automated and on-demand report generation with multiple formats
- **WebSocket Integration**: Real-time updates and notifications

## Key Features

### Autonomous Operation
- **Self-Directed Scanning**: AI-driven target selection
- **Adaptive Strategies**: Learning from scan results
- **Dynamic Prioritization**: Risk-based task scheduling
- **Continuous Improvement**: Model refinement through feedback

### Vulnerability Intelligence
- **CVE/CWE Correlation**: Automated vulnerability mapping
- **Configuration Analysis**: "Worst practice" detection
- **Asset Discovery**: Network topology mapping
- **Risk Aggregation**: Multi-factor risk scoring

### Human-AI Collaboration
- **HOTL Workflow**: Human oversight for critical decisions
- **Explainable AI**: Transparent reasoning for recommendations
- **Feedback Loop**: Human input improves model performance
- **Override Capability**: Human control over automated actions

### C3CI Integration
- **Command**: Centralized control interface
- **Control**: Distributed agent management
- **Coordination**: Multi-agent task synchronization
- **Intelligence**: Threat intelligence integration

## Data Flow

```
Scan Request → Orchestrator → Agent Pool → Target Systems
     ↓              ↓             ↓            ↓
Task Queue → NATS JetStream → Scan Results → Raw Data
     ↓              ↓             ↓            ↓
Feature Pipeline → Graph Updates → ML Training → Model Updates
     ↓              ↓             ↓            ↓
Risk Scores → HOTL Review → Feedback → Gradient Descent
     ↓              ↓             ↓            ↓
Dashboard → Reports → Actions → Remediation
```

## Security Considerations

### Data Protection
- **Encryption**: All data encrypted in transit and at rest
- **Access Control**: Role-based permissions
- **Audit Logging**: Complete activity tracking
- **Data Retention**: Configurable retention policies

### Network Security
- **Secure Communications**: TLS/mTLS for all connections
- **Network Segmentation**: Isolated scanning networks
- **Credential Management**: Secure secret storage
- **Agent Authentication**: Certificate-based identity

### Compliance
- **Regulatory Alignment**: SOC2, ISO27001, NIST frameworks
- **Privacy Protection**: GDPR/CCPA compliance
- **Data Classification**: Sensitivity-based handling
- **Incident Response**: Automated breach detection

## Deployment Architecture

### Microservices Design
```
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Orchestrator   │  │   Agent Pool    │  │  Data Services  │
│   Service       │  │    Services     │  │                 │
│                 │  │                 │  │ - Graph DB      │
│ - Task Mgmt     │  │ - Vuln Scanner  │  │ - NATS Cluster  │
│ - Scheduling    │  │ - Asset Disc    │  │ - Redis KVS     │
│ - Coordination  │  │ - Config Audit  │  │                 │
└─────────────────┘  └─────────────────┘  └─────────────────┘

┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   ML Services   │  │  API Gateway    │  │  UI Services    │
│                 │  │                 │  │                 │
│ - GraphRL       │  │ - Authentication│  │ - Dashboard     │
│ - Feature Eng   │  │ - Rate Limiting │  │ - Chat Bot      │
│ - Model Training│  │ - Load Balancing│  │ - Reporting     │
│                 │  │                 │  │                 │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

### Scalability Features
- **Horizontal Scaling**: Auto-scaling agent pools
- **Load Distribution**: Intelligent task distribution
- **Resource Management**: Dynamic resource allocation
- **Performance Monitoring**: Real-time metrics and alerting

## Getting Started

### Prerequisites
- Node.js 18+ runtime environment
- NATS Server with JetStream enabled
- Graph database (Neo4j/ArangoDB)
- Redis for key-value storage
- GPU resources for ML training (optional but recommended)

### Security Tools Setup
The following tools must be installed in the `tools/` directory:

```bash
# Create tools directory structure
mkdir -p tools/{masscan/bin,nuclei,subfinder,httpx}

# Install Masscan (compile from source or download binary)
# Place binary at: tools/masscan/bin/masscan

# Install Nuclei
# Download from: https://github.com/projectdiscovery/nuclei
# Place binary at: tools/nuclei/nuclei

# Install Subfinder  
# Download from: https://github.com/projectdiscovery/subfinder
# Place binary at: tools/subfinder/subfinder

# Install Httpx
# Download from: https://github.com/projectdiscovery/httpx
# Place binary at: tools/httpx/httpx
```

**Note**: EVMS includes built-in fallback scanning capabilities when tools are not available, but the integrated tools provide enhanced performance and detection capabilities.

### Installation
```bash
# Clone the repository
git clone <repository-url>
cd EVMS

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Initialize database
npm run db:init

# Start services
npm run start:all
```

### LLM/RAG Chat System

### Natural Language Interface
EVMS includes a sophisticated chat interface powered by Large Language Models and Retrieval-Augmented Generation:

#### **Capabilities**
- **Interactive Queries**: Ask questions about vulnerabilities, assets, risks, and compliance in natural language
- **Deterministic Responses**: Answers grounded in actual graph database data with source citations
- **On-Demand Reports**: Generate custom reports through conversational requests
- **Dashboard Population**: Request specific dashboard widgets and metrics
- **Analysis & Insights**: Deep analysis of security data with actionable recommendations

#### **Chat Features**
- **Session Management**: Persistent chat history with context awareness
- **Real-Time Updates**: WebSocket-based live notifications and responses
- **Multi-Format Reports**: Generate reports in Markdown, HTML, JSON, or plain text
- **Intent Classification**: Automatic routing of queries to appropriate handlers
- **Metadata Enrichment**: Responses include confidence scores, data sources, and relevance metrics

#### **RAG Pipeline**
- **Graph Database Integration**: Retrieves relevant data from Neo4j knowledge graph
- **Semantic Search**: Intelligent query analysis and data retrieval
- **Context Ranking**: Relevance scoring and result prioritization
- **Source Attribution**: Clear citations and data provenance
- **Fallback Handling**: Graceful degradation when data is unavailable

#### **Report Generation**
- **Template-Based**: Professional report formats for different audiences
- **Dynamic Content**: LLM-generated sections based on current data
- **Multiple Formats**: Support for various output formats and styles
- **Executive & Technical**: Tailored content for different stakeholder needs

### Usage Examples
```
User: "Show me critical vulnerabilities discovered in the last 24 hours"
EVMS: "I found 12 critical vulnerabilities in the past 24 hours affecting 8 assets..."

User: "Generate an executive risk assessment report"
EVMS: "I've generated an executive risk assessment report. You can access it here..."

User: "What's the current security posture of our web servers?"
EVMS: "Based on the latest scans, your web servers show the following security posture..."
```

## Configuration
- **NATS Configuration**: Connection strings and credentials
- **Database Setup**: Graph DB and KVS connection details
- **ML Parameters**: Model hyperparameters and training settings
- **Scanning Policies**: Target definitions and scan schedules
- **LLM Configuration**: OpenAI API keys, model selection, and temperature settings
- **RAG Parameters**: Retrieval limits, similarity thresholds, and context windows

## API Documentation

### REST Endpoints
- `GET /api/v1/scans` - List all scans
- `POST /api/v1/scans` - Initiate new scan
- `GET /api/v1/risks` - Retrieve risk assessments
- `POST /api/v1/hotl/review` - Submit HOTL review
- `GET /api/v1/dashboard/metrics` - Dashboard data
- `POST /api/chat/message` - Send chat message to LLM/RAG system
- `GET /api/chat/history/:sessionId` - Retrieve chat history
- `POST /api/reports/generate` - Generate on-demand reports
- `GET /api/dashboard/populate` - Populate dashboard widgets

### WebSocket Events
- `scan.started` - Scan initiation notification
- `scan.completed` - Scan completion with results
- `risk.updated` - Risk score changes
- `chat_response` - LLM response to user message
- `chat_history` - Historical chat messages
- `system_update` - Real-time system notifications
- `report_generated` - Report generation completion
- `hotl.required` - Human review needed

### GraphQL Schema
```graphql
type Asset {
  id: ID!
  hostname: String!
  ipAddress: String!
  vulnerabilities: [Vulnerability!]!
  riskScore: Float!
}

type Vulnerability {
  id: ID!
  cveId: String
  severity: Severity!
  description: String!
  assets: [Asset!]!
}
```

## Monitoring and Observability

### Metrics Collection
- **System Metrics**: CPU, memory, network utilization
- **Application Metrics**: Scan rates, detection accuracy
- **ML Metrics**: Model performance, training loss
- **Business Metrics**: Risk reduction, MTTR

### Logging Strategy
- **Structured Logging**: JSON format with correlation IDs
- **Log Levels**: DEBUG, INFO, WARN, ERROR, FATAL
- **Log Aggregation**: Centralized log collection
- **Log Analysis**: Automated anomaly detection

### Alerting Rules
- **Critical Vulnerabilities**: Immediate notification
- **System Failures**: Service degradation alerts
- **Model Drift**: ML performance degradation
- **Capacity Limits**: Resource exhaustion warnings

## Contributing

### Development Workflow
1. Fork the repository
2. Create feature branch
3. Implement changes with tests
4. Submit pull request
5. Code review and approval
6. Merge to main branch

### Code Standards
- **ESLint**: JavaScript/TypeScript linting
- **Prettier**: Code formatting
- **Jest**: Unit testing framework
- **Documentation**: JSDoc comments required

### Testing Strategy
- **Unit Tests**: Component-level testing
- **Integration Tests**: Service interaction testing
- **E2E Tests**: Full workflow validation
- **Performance Tests**: Load and stress testing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:
- **Documentation**: [Wiki](wiki-url)
- **Issues**: [GitHub Issues](issues-url)
- **Discussions**: [GitHub Discussions](discussions-url)
- **Email**: evms-support@organization.com

---

*EVMS - Intelligent, Autonomous Vulnerability Management for Modern Infrastructure*