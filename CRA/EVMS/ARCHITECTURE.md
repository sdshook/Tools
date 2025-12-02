<!-- EVMS (c) Shane D. Shook, 2025 All Rights Reserved -->
# EVMS Architecture Deep Dive

## System Architecture Overview

The EVMS platform is built on a distributed, event-driven architecture that combines traditional cybersecurity scanning with advanced machine learning capabilities. The system is designed for high availability, scalability, and autonomous operation with human oversight.

## Core Components

### 1. Orchestrator Service

**Purpose**: Central coordination and task management
**Technology**: Node.js with Express.js framework
**Responsibilities**:
- Task scheduling and dispatch
- Agent lifecycle management
- Resource allocation and load balancing
- Priority-based queue management
- Health monitoring and failover

**Key Modules**:
```javascript
// Task Scheduler
class TaskScheduler {
  scheduleVulnerabilityScan(targets, priority, schedule)
  scheduleComplianceAudit(policies, assets)
  scheduleAssetDiscovery(networks, credentials)
}

// Agent Manager
class AgentManager {
  deployAgent(type, configuration)
  scaleAgentPool(targetSize, constraints)
  monitorAgentHealth()
  redistributeTasks()
}
```

### 2. Scanning Agents

**Purpose**: Distributed vulnerability assessment and data collection
**Technology**: Node.js workers with specialized scanning libraries
**Agent Types**:

#### Network Discovery Agent
- Port scanning and service enumeration
- OS fingerprinting and version detection
- Network topology mapping
- Asset inventory management

#### Vulnerability Scanner Agent
- CVE database correlation
- Exploit availability checking
- Patch level assessment
- Configuration weakness detection

#### Configuration Audit Agent
- Security baseline compliance
- "Worst practice" identification
- Policy violation detection
- Drift analysis

#### Threat Intelligence Agent
- IOC correlation and matching
- Threat actor attribution
- Campaign tracking
- Risk context enrichment

### 3. NATS.io Messaging Infrastructure

**Purpose**: Reliable, scalable message streaming and persistence
**Configuration**:
```yaml
jetstream:
  enabled: true
  store_dir: "/data/jetstream"
  max_memory: "1GB"
  max_file: "10GB"

streams:
  scan_tasks:
    subjects: ["scan.task.*"]
    retention: "workqueue"
    max_age: "24h"
  
  scan_results:
    subjects: ["scan.result.*"]
    retention: "limits"
    max_age: "30d"
    
  ml_training:
    subjects: ["ml.training.*"]
    retention: "interest"
    max_age: "7d"
```

**Message Patterns**:
- `scan.task.{agent_type}.{priority}` - Task dispatch
- `scan.result.{scan_id}.{asset_id}` - Scan results
- `ml.training.{model_id}.{epoch}` - Training data
- `hotl.review.{finding_id}` - Human review requests

### 4. Graph Database Layer

**Purpose**: Relationship modeling and graph-based analytics
**Technology**: Neo4j with APOC extensions
**Schema Design**:

```cypher
// Core Entities
CREATE CONSTRAINT asset_id FOR (a:Asset) REQUIRE a.id IS UNIQUE;
CREATE CONSTRAINT vuln_id FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE;
CREATE CONSTRAINT cve_id FOR (c:CVE) REQUIRE c.id IS UNIQUE;

// Relationships
(:Asset)-[:HAS_VULNERABILITY]->(:Vulnerability)
(:Vulnerability)-[:MAPS_TO]->(:CVE)
(:Asset)-[:CONNECTS_TO]->(:Asset)
(:Asset)-[:BELONGS_TO]->(:Network)
(:Vulnerability)-[:EXPLOITS]->(:Weakness)
(:Asset)-[:RUNS]->(:Service)
```

**Graph Algorithms**:
- PageRank for asset criticality scoring
- Community detection for network segmentation
- Shortest path for attack path analysis
- Centrality measures for risk propagation

### 5. GraphRL Intelligence Engine

**Purpose**: Reinforcement learning for autonomous decision making
**Technology**: PyTorch with DGL (Deep Graph Library)
**Architecture**:

```python
class GraphRLAgent:
    def __init__(self, state_dim, action_dim, hidden_dim=256):
        self.gnn = GraphNeuralNetwork(state_dim, hidden_dim)
        self.q_network = DQN(hidden_dim, action_dim)
        self.target_network = DQN(hidden_dim, action_dim)
        self.optimizer = torch.optim.Adam(self.parameters())
    
    def select_action(self, graph_state, epsilon=0.1):
        # Epsilon-greedy action selection
        if random.random() < epsilon:
            return random.choice(self.action_space)
        
        node_embeddings = self.gnn(graph_state)
        q_values = self.q_network(node_embeddings)
        return torch.argmax(q_values).item()
    
    def update(self, batch):
        # Double DQN update with graph neural networks
        states, actions, rewards, next_states, dones = batch
        
        current_q = self.q_network(self.gnn(states))
        next_q = self.target_network(self.gnn(next_states))
        
        target_q = rewards + (1 - dones) * torch.max(next_q, dim=1)[0]
        loss = F.mse_loss(current_q.gather(1, actions), target_q)
        
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
```

**State Representation**:
- Node features: Asset properties, vulnerability counts, risk scores
- Edge features: Connection types, trust relationships, data flows
- Graph features: Network topology, security zones, compliance status

**Action Space**:
- Scan prioritization decisions
- Resource allocation choices
- Risk threshold adjustments
- Remediation recommendations

**Reward Function**:
```python
def calculate_reward(action, outcome, hotl_feedback):
    base_reward = 0
    
    # Successful vulnerability detection
    if outcome.vulnerabilities_found > 0:
        base_reward += outcome.vulnerabilities_found * 10
    
    # False positive penalty
    if outcome.false_positives > 0:
        base_reward -= outcome.false_positives * 5
    
    # HOTL approval bonus
    if hotl_feedback.approved:
        base_reward += 50
    elif hotl_feedback.rejected:
        base_reward -= 25
    
    # Risk reduction reward
    risk_reduction = outcome.risk_before - outcome.risk_after
    base_reward += risk_reduction * 100
    
    return base_reward
```

### 6. Feature Pipeline

**Purpose**: Data transformation and feature engineering
**Technology**: Apache Kafka Streams with custom processors
**Pipeline Stages**:

```javascript
// Raw data ingestion
const rawDataStream = kafka.stream('scan-results')

// Feature extraction
const featureStream = rawDataStream
  .map(extractVulnerabilityFeatures)
  .map(extractAssetFeatures)
  .map(extractNetworkFeatures)

// Graph updates
const graphUpdateStream = featureStream
  .filter(hasGraphChanges)
  .map(generateGraphUpdates)
  .to('graph-updates')

// ML training data
const trainingStream = featureStream
  .map(createTrainingExamples)
  .to('ml-training-data')
```

**Feature Types**:
- **Vulnerability Features**: CVSS scores, exploit availability, patch age
- **Asset Features**: OS type, service versions, configuration state
- **Network Features**: Connectivity patterns, traffic analysis, zone membership
- **Temporal Features**: Scan frequency, change velocity, incident history

### 7. HOTL Interface

**Purpose**: Human oversight and feedback collection
**Technology**: React.js with WebSocket real-time updates
**Components**:

```jsx
// Review Dashboard
const HOTLDashboard = () => {
  const [pendingReviews, setPendingReviews] = useState([]);
  const [riskThresholds, setRiskThresholds] = useState({});
  
  return (
    <div className="hotl-dashboard">
      <ReviewQueue reviews={pendingReviews} />
      <RiskConfiguration thresholds={riskThresholds} />
      <ModelPerformance metrics={mlMetrics} />
      <FeedbackHistory history={feedbackLog} />
    </div>
  );
};

// Review Item Component
const ReviewItem = ({ finding, onApprove, onReject, onModify }) => {
  return (
    <Card className="review-item">
      <FindingDetails finding={finding} />
      <RiskAssessment score={finding.riskScore} />
      <RecommendedActions actions={finding.recommendations} />
      <ReviewActions 
        onApprove={onApprove}
        onReject={onReject}
        onModify={onModify}
      />
    </Card>
  );
};
```

**Review Workflows**:
- **High-Risk Findings**: Mandatory human review
- **Model Uncertainty**: Review when confidence < threshold
- **Policy Violations**: Compliance officer review
- **False Positive Feedback**: Continuous model improvement

## Data Flow Architecture

### 1. Ingestion Layer
```
External Sources → API Gateway → Message Queue → Processing Pipeline
     ↓                ↓              ↓               ↓
- Threat Intel   - Authentication  - NATS         - Validation
- CVE Feeds      - Rate Limiting   - JetStream    - Enrichment
- Asset Data     - Load Balancing  - Persistence  - Transformation
```

### 2. Processing Layer
```
Raw Data → Feature Extraction → Graph Updates → ML Training
    ↓            ↓                   ↓              ↓
- Parsing    - Normalization     - Node Updates  - Batch Creation
- Validation - Feature Eng       - Edge Updates  - Model Training
- Enrichment - Correlation       - Index Rebuild - Performance Eval
```

### 3. Intelligence Layer
```
Graph State → GraphRL Agent → Action Selection → Execution
     ↓             ↓               ↓               ↓
- Node Embed  - Policy Network  - Task Priority  - Agent Dispatch
- Edge Embed  - Value Function  - Resource Alloc - Scan Execution
- Graph Embed - Action Space    - Risk Threshold - Result Collection
```

### 4. Presentation Layer
```
Processed Data → Dashboard → User Interface → Actions
      ↓             ↓           ↓              ↓
- Risk Scores   - Visualization - Chat Bot    - Manual Override
- Findings      - Reports       - HOTL Review - Policy Updates
- Trends        - Alerts        - API Access  - Configuration
```

## Security Architecture

### 1. Network Security
```
Internet → WAF → Load Balancer → API Gateway → Services
    ↓       ↓         ↓             ↓           ↓
- DDoS    - SQL Inj  - SSL Term   - AuthN/Z    - mTLS
- Bot Det - XSS      - Health     - Rate Limit - Encryption
- GeoBlock- CSRF     - Failover   - Logging    - Validation
```

### 2. Data Security
- **Encryption at Rest**: AES-256 for all stored data
- **Encryption in Transit**: TLS 1.3 for all communications
- **Key Management**: HashiCorp Vault integration
- **Data Classification**: Automatic sensitivity tagging
- **Access Control**: RBAC with attribute-based policies

### 3. Application Security
- **Input Validation**: Comprehensive sanitization
- **Output Encoding**: Context-aware encoding
- **Session Management**: Secure token handling
- **Error Handling**: No information disclosure
- **Logging**: Security event correlation

## Scalability Design

### 1. Horizontal Scaling
- **Stateless Services**: All services designed for horizontal scaling
- **Load Distribution**: Consistent hashing for data partitioning
- **Auto-scaling**: Kubernetes HPA based on custom metrics
- **Resource Isolation**: Container-based deployment

### 2. Performance Optimization
- **Caching Strategy**: Multi-level caching with NATS KV Store
- **Database Optimization**: Query optimization and indexing
- **Async Processing**: Event-driven, non-blocking operations
- **Connection Pooling**: Efficient resource utilization

### 3. Fault Tolerance
- **Circuit Breakers**: Prevent cascade failures
- **Retry Logic**: Exponential backoff with jitter
- **Health Checks**: Comprehensive service monitoring
- **Graceful Degradation**: Partial functionality during outages

## Deployment Patterns

### 1. Microservices Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: evms-orchestrator
spec:
  replicas: 3
  selector:
    matchLabels:
      app: evms-orchestrator
  template:
    metadata:
      labels:
        app: evms-orchestrator
    spec:
      containers:
      - name: orchestrator
        image: evms/orchestrator:latest
        ports:
        - containerPort: 3000
        env:
        - name: NATS_URL
          value: "nats://nats-cluster:4222"
        - name: GRAPH_DB_URL
          valueFrom:
            secretKeyRef:
              name: graph-db-secret
              key: url
```

### 2. Data Persistence
- **Graph Database**: Neo4j cluster with read replicas
- **Message Streaming**: NATS JetStream cluster
- **Cache Layer**: NATS Key-Value Store with persistence
- **File Storage**: S3-compatible object storage

### 3. Monitoring Stack
- **Metrics**: Prometheus with custom exporters
- **Logging**: ELK stack with structured logging
- **Tracing**: Jaeger for distributed tracing
- **Alerting**: AlertManager with PagerDuty integration

This architecture provides a robust, scalable foundation for autonomous vulnerability management with human oversight and continuous learning capabilities.