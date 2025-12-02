<!-- EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved -->
# EVMS Technology Stack

## Open Source Foundation

EVMS is built on a carefully selected stack of proven open-source technologies, each chosen for their specific strengths in cybersecurity, network analysis, and intelligent automation.

## Core Components

### 1. Masscan - Active Network Discovery
**Repository**: https://github.com/robertdavidgraham/masscan  
**License**: AGPL v3  
**Purpose**: Ultra-fast network discovery and port scanning

#### Capabilities
- **Speed**: Scan the entire Internet in under 6 minutes
- **Asynchronous I/O**: Non-blocking network operations
- **Custom Packet Crafting**: Raw socket implementation
- **Rate Control**: Configurable packet transmission rates
- **Output Formats**: XML, JSON, binary, and custom formats

#### Integration in EVMS
```javascript
// Masscan wrapper for active discovery
class MasscanAgent extends BaseAgent {
  async scanNetwork(cidr, ports = 'top-ports:1000') {
    const command = `masscan ${cidr} -p${ports} --rate=10000 --output-format json`;
    const results = await this.executeCommand(command);
    return this.parseResults(results);
  }
  
  async parseResults(rawOutput) {
    return rawOutput.map(result => ({
      ip: result.ip,
      port: result.port,
      protocol: result.proto,
      timestamp: result.timestamp,
      status: 'open'
    }));
  }
}
```

#### Configuration
```yaml
masscan:
  rate: 10000              # Packets per second
  retries: 3               # Retry attempts
  timeout: 10              # Connection timeout
  exclude_file: exclude.txt # IPs to exclude
  interface: eth0          # Network interface
  source_port: 40000       # Source port range
```

### 2. Nuclei - Template-Based Vulnerability Scanning
**Repository**: https://github.com/projectdiscovery/nuclei  
**License**: MIT  
**Purpose**: Fast and customizable vulnerability scanner

#### Capabilities
- **Template Engine**: YAML-based vulnerability templates
- **Community Templates**: 4000+ community-maintained templates
- **Multi-Protocol Support**: HTTP, DNS, TCP, SSL, and more
- **Custom Workflows**: Complex scanning logic
- **Integration Ready**: API and webhook support

#### Integration in EVMS
```javascript
// Nuclei wrapper for vulnerability assessment
class NucleiAgent extends BaseAgent {
  async scanTargets(targets, templates = 'all') {
    const command = `nuclei -l ${targets} -t ${templates} -json -o results.json`;
    const results = await this.executeCommand(command);
    return this.parseVulnerabilities(results);
  }
  
  async parseVulnerabilities(rawOutput) {
    return rawOutput.map(vuln => ({
      templateId: vuln.template_id,
      info: vuln.info,
      host: vuln.host,
      severity: vuln.info.severity,
      cve: vuln.info.classification?.cve,
      cwe: vuln.info.classification?.cwe,
      matched: vuln.matched_at,
      extractedResults: vuln.extracted_results
    }));
  }
}
```

#### Custom Templates
```yaml
# Custom EVMS template example
id: evms-custom-check
info:
  name: EVMS Custom Security Check
  author: evms-team
  severity: medium
  description: Custom security check for EVMS platform
  classification:
    cwe-id: CWE-200
  tags: evms,custom,information-disclosure

http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/config"
      - "{{BaseURL}}/.env"
    
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "password"
          - "secret"
          - "api_key"
        condition: or
```

### 3. Zeek - Network Security Monitoring
**Repository**: https://github.com/zeek/zeek  
**License**: BSD 3-Clause  
**Purpose**: Passive network monitoring and protocol analysis

#### Capabilities
- **Protocol Analysis**: Deep inspection of 50+ protocols
- **Event-Driven Architecture**: Real-time network event processing
- **Scripting Language**: Custom analysis scripts
- **Log Generation**: Structured logs for all network activity
- **Cluster Support**: Distributed monitoring across multiple sensors

#### Integration in EVMS
```javascript
// Zeek integration for passive discovery
class ZeekAgent extends BaseAgent {
  constructor() {
    super();
    this.zeekLogPath = '/opt/zeek/logs/current';
    this.logParsers = {
      'conn.log': this.parseConnections,
      'dns.log': this.parseDNS,
      'http.log': this.parseHTTP,
      'ssl.log': this.parseSSL,
      'x509.log': this.parseX509
    };
  }
  
  async monitorNetwork(interface = 'eth0') {
    // Start Zeek monitoring
    const zeekCmd = `zeek -i ${interface} local`;
    await this.executeCommand(zeekCmd);
    
    // Monitor log files for new entries
    this.watchLogFiles();
  }
  
  parseConnections(logEntry) {
    return {
      timestamp: logEntry.ts,
      uid: logEntry.uid,
      sourceIP: logEntry['id.orig_h'],
      sourcePort: logEntry['id.orig_p'],
      destIP: logEntry['id.resp_h'],
      destPort: logEntry['id.resp_p'],
      protocol: logEntry.proto,
      service: logEntry.service,
      duration: logEntry.duration,
      origBytes: logEntry.orig_bytes,
      respBytes: logEntry.resp_bytes,
      connState: logEntry.conn_state
    };
  }
}
```

#### Custom Zeek Scripts
```zeek
# Custom EVMS Zeek script for device classification
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http

module EVMS;

export {
    # Device classification based on behavior
    type DeviceInfo: record {
        ip: addr;
        mac: string &optional;
        device_type: string &optional;
        os_guess: string &optional;
        services: set[string] &optional;
        first_seen: time;
        last_seen: time;
    };
    
    global devices: table[addr] of DeviceInfo;
}

# Classify devices based on HTTP User-Agent
event http_request(c: connection, method: string, original_URI: string,
                  unescaped_URI: string, version: string) {
    local src_ip = c$id$orig_h;
    
    if (src_ip !in devices) {
        devices[src_ip] = DeviceInfo($ip=src_ip, $first_seen=network_time());
    }
    
    devices[src_ip]$last_seen = network_time();
    
    # Device classification logic
    if (c$http?$user_agent) {
        local ua = c$http$user_agent;
        if (/Windows/ in ua) {
            devices[src_ip]$os_guess = "Windows";
        } else if (/Linux/ in ua) {
            devices[src_ip]$os_guess = "Linux";
        } else if (/iPhone|iPad/ in ua) {
            devices[src_ip]$device_type = "iOS Device";
        }
    }
}
```

### 4. NATS - Event Bus and Messaging
**Repository**: https://github.com/nats-io/nats-server  
**License**: Apache 2.0  
**Purpose**: High-performance messaging system and event bus

#### Capabilities
- **JetStream**: Persistent messaging and event streaming
- **Key-Value Store**: Distributed KV storage
- **Object Store**: Blob storage for large data
- **Clustering**: Multi-server clustering with automatic failover
- **Security**: TLS, authentication, and authorization

#### Integration in EVMS
```javascript
// NATS integration for event-driven architecture and KV storage
class NATSEventBus {
  constructor(servers = ['nats://localhost:4222']) {
    this.nc = null;
    this.js = null;
    this.kv = null;
    this.servers = servers;
  }
  
  async connect() {
    this.nc = await connect({ servers: this.servers });
    this.js = this.nc.jetstream();
    
    // Initialize Key-Value store
    this.kv = await this.js.views.kv('evms-cache', {
      history: 5,
      ttl: 3600000 // 1 hour TTL
    });
    
    // Create streams for different event types
    await this.createStreams();
  }
  
  async createStreams() {
    const streams = [
      {
        name: 'SCAN_EVENTS',
        subjects: ['scan.started', 'scan.completed', 'scan.failed'],
        retention: RetentionPolicy.Workqueue,
        max_age: nanos(24 * 60 * 60 * 1000000000) // 24 hours
      },
      {
        name: 'DISCOVERY_EVENTS',
        subjects: ['discovery.asset.new', 'discovery.service.new', 'discovery.vuln.new'],
        retention: RetentionPolicy.Limits,
        max_age: nanos(30 * 24 * 60 * 60 * 1000000000) // 30 days
      },
      {
        name: 'RISK_EVENTS',
        subjects: ['risk.score.updated', 'risk.threshold.exceeded', 'risk.action.recommended'],
        retention: RetentionPolicy.Interest,
        max_age: nanos(7 * 24 * 60 * 60 * 1000000000) // 7 days
      }
    ];
    
    for (const stream of streams) {
      try {
        await this.js.streams.add(stream);
      } catch (err) {
        if (err.code !== '10058') { // Stream already exists
          throw err;
        }
      }
    }
  }
  
  async publishScanEvent(eventType, data) {
    const subject = `scan.${eventType}`;
    await this.js.publish(subject, JSON.stringify(data));
  }
  
  async subscribeToEvents(subject, handler) {
    const sub = await this.js.subscribe(subject);
    
    for await (const msg of sub) {
      try {
        const data = JSON.parse(msg.data);
        await handler(data);
        msg.ack();
      } catch (err) {
        console.error('Error processing message:', err);
        msg.nak();
      }
    }
  }
  
  // Key-Value store operations
  async setCache(key, value, ttl = 3600000) {
    await this.kv.put(key, JSON.stringify(value), { ttl });
  }
  
  async getCache(key) {
    try {
      const entry = await this.kv.get(key);
      return entry ? JSON.parse(entry.string()) : null;
    } catch (err) {
      if (err.code === '404') return null;
      throw err;
    }
  }
  
  async deleteCache(key) {
    await this.kv.delete(key);
  }
  
  async listCacheKeys(prefix = '') {
    const keys = [];
    const iter = await this.kv.keys(prefix + '*');
    for await (const key of iter) {
      keys.push(key);
    }
    return keys;
  }
}
```

### 5. GraphRL - Risk Prioritization Engine
**Custom Implementation**  
**License**: MIT (EVMS Project)  
**Purpose**: Graph-based reinforcement learning for intelligent risk scoring

#### Capabilities
- **Graph Neural Networks**: Deep learning on network topology
- **Reinforcement Learning**: Adaptive decision making
- **Risk Scoring**: Multi-factor risk assessment
- **Action Recommendation**: Automated prioritization
- **Continuous Learning**: Improvement through feedback

#### Core Architecture
```python
# GraphRL implementation for EVMS
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_mean_pool

class EVMSGraphRL(nn.Module):
    def __init__(self, node_features, edge_features, hidden_dim=256):
        super(EVMSGraphRL, self).__init__()
        
        # Graph neural network layers
        self.node_encoder = nn.Linear(node_features, hidden_dim)
        self.edge_encoder = nn.Linear(edge_features, hidden_dim)
        
        self.gnn_layers = nn.ModuleList([
            GCNConv(hidden_dim, hidden_dim) for _ in range(4)
        ])
        
        # Risk scoring head
        self.risk_scorer = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid()
        )
        
        # Action recommendation head
        self.action_recommender = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 10)  # 10 possible actions
        )
    
    def forward(self, x, edge_index, edge_attr, batch):
        # Encode node and edge features
        x = self.node_encoder(x)
        edge_attr = self.edge_encoder(edge_attr)
        
        # Apply graph convolutions
        for layer in self.gnn_layers:
            x = F.relu(layer(x, edge_index))
        
        # Global graph representation
        graph_repr = global_mean_pool(x, batch)
        
        # Risk scores and action recommendations
        risk_scores = self.risk_scorer(x)
        actions = self.action_recommender(graph_repr)
        
        return risk_scores, actions

# Risk calculation with multiple factors
class RiskCalculator:
    def __init__(self):
        self.weights = {
            'cvss_score': 0.3,
            'exploitability': 0.25,
            'asset_criticality': 0.2,
            'network_exposure': 0.15,
            'threat_intelligence': 0.1
        }
    
    def calculate_risk(self, vulnerability, asset, network_context):
        factors = {
            'cvss_score': vulnerability.cvss_score / 10.0,
            'exploitability': self.get_exploitability_score(vulnerability),
            'asset_criticality': asset.criticality_score,
            'network_exposure': self.calculate_exposure(asset, network_context),
            'threat_intelligence': self.get_threat_intel_score(vulnerability)
        }
        
        risk_score = sum(
            self.weights[factor] * score 
            for factor, score in factors.items()
        )
        
        return min(risk_score, 1.0)  # Cap at 1.0
```

### 6. LLM/RAG - Natural Language Interface
**Components**: OpenAI GPT-4, Anthropic Claude, or Local LLMs  
**Vector Database**: Qdrant, Pinecone, or Weaviate  
**Purpose**: Natural language queries and intelligent reporting

#### Capabilities
- **Natural Language Queries**: Ask questions in plain English
- **Context-Aware Responses**: RAG with security knowledge base
- **Report Generation**: Automated security reports
- **Threat Analysis**: AI-powered threat intelligence
- **Remediation Guidance**: Step-by-step fix instructions

#### Implementation
```javascript
// LLM/RAG integration for natural language interface
class EVMSChatInterface {
  constructor(llmProvider, vectorDB) {
    this.llm = llmProvider;
    this.vectorDB = vectorDB;
    this.systemPrompt = this.buildSystemPrompt();
  }
  
  buildSystemPrompt() {
    return `You are EVMS AI, an expert cybersecurity analyst assistant. You have access to:
    - Real-time network scan data from Masscan and Nuclei
    - Network traffic analysis from Zeek
    - Risk assessments from GraphRL
    - Vulnerability databases and threat intelligence
    
    Provide accurate, actionable security insights and recommendations.
    Always cite your sources and explain your reasoning.`;
  }
  
  async processQuery(userQuery, context = {}) {
    // Retrieve relevant context from vector database
    const relevantDocs = await this.vectorDB.search(userQuery, {
      limit: 5,
      threshold: 0.7
    });
    
    // Build context from current system state
    const systemContext = await this.buildSystemContext(context);
    
    // Generate response using LLM
    const response = await this.llm.chat([
      { role: 'system', content: this.systemPrompt },
      { role: 'user', content: this.buildPrompt(userQuery, relevantDocs, systemContext) }
    ]);
    
    return {
      answer: response.content,
      sources: relevantDocs,
      confidence: response.confidence || 0.8
    };
  }
  
  buildPrompt(query, docs, context) {
    return `
    User Query: ${query}
    
    Relevant Documentation:
    ${docs.map(doc => `- ${doc.content}`).join('\n')}
    
    Current System Context:
    - Active Assets: ${context.assetCount}
    - High-Risk Vulnerabilities: ${context.highRiskVulns}
    - Recent Scan Results: ${context.recentScans}
    - Network Activity: ${context.networkActivity}
    
    Please provide a comprehensive answer based on this information.
    `;
  }
}

// Example queries the system can handle:
const exampleQueries = [
  "What are the highest risk vulnerabilities in our network right now?",
  "Show me all assets that haven't been scanned in the last 7 days",
  "What unusual network activity has Zeek detected today?",
  "Generate a security report for the executive team",
  "What's the attack path to our most critical servers?",
  "How should we prioritize remediation efforts this week?",
  "Are there any indicators of compromise in our network?",
  "What compliance gaps do we have according to the latest scans?"
];
```

## Integration Architecture

### Data Flow
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Masscan   │───▶│    NATS     │───▶│   GraphRL   │
│ (Active)    │    │ (Event Bus) │    │ (Risk AI)   │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   ▲                   │
       ▼                   │                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Nuclei    │───▶│   Neo4j     │◄───│   LLM/RAG   │
│ (Vulns)     │    │ (Graph DB)  │    │ (Chat/UI)   │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   ▲                   ▲
       ▼                   │                   │
┌─────────────┐           │            ┌─────────────┐
│    Zeek     │───────────┘            │    HOTL     │
│ (Passive)   │                        │ (Human)     │
└─────────────┘                        └─────────────┘
```

### Event-Driven Workflows
1. **Discovery Phase**: Masscan discovers assets → NATS events → Graph updates
2. **Analysis Phase**: Nuclei scans vulnerabilities → Risk calculation → Prioritization
3. **Monitoring Phase**: Zeek monitors traffic → Behavioral analysis → Anomaly detection
4. **Intelligence Phase**: GraphRL processes data → Risk scores → Action recommendations
5. **Human Loop**: HOTL reviews high-risk items → Feedback → Model improvement
6. **Reporting Phase**: LLM/RAG generates insights → Natural language reports

## Open Source Compliance

### Licenses and Attribution
- **Masscan**: AGPL v3 - Robert David Graham
- **Nuclei**: MIT - ProjectDiscovery Team
- **Zeek**: BSD 3-Clause - The Zeek Project
- **NATS**: Apache 2.0 - NATS.io Team
- **Neo4j Community**: GPL v3 - Neo4j, Inc.
- **Redis**: BSD 3-Clause - Redis Ltd.

### Contribution Guidelines
All open-source components maintain their original licenses and contribution requirements. EVMS-specific code and integrations are released under MIT license to encourage community adoption and contribution.

### Community Engagement
- Regular contributions back to upstream projects
- Bug reports and feature requests
- Documentation improvements
- Template and script sharing
- Security research collaboration

This technology stack provides a robust, scalable, and intelligent foundation for modern vulnerability management while leveraging the best of open-source security tools.