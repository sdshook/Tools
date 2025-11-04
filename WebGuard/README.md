# WebGuard: Adaptive Cybersecurity Web Service Protection Agent
## Neuromorphic Defense with Reinforced Hebbian Learning
**(c) Shane D. Shook, All Rights Reserved 2025**

## Project Overview

This project introduces a novel adaptive cybersecurity web service protection agent that combines neuromorphic computing principles with reinforcement learning to create autonomous, locally-learning endpoint protection. The system, implemented as both a Cognitive Mesh Neural Network (CMNN) and Endpoint Protection Platform (EPP), represents a first-of-its-kind architecture for real-time, self-adaptive defense.

## Core Innovation

### The Unique Combination
The system fuses six key components that have rarely been integrated:
- **True Bidirectional Hebbian Learning**: "Neurons that fire together, wire together" - explicit connection weights between memory traces that strengthen with co-activation and reward
- **Reinforcement-Modulated Plasticity**: Reward/punishment signals directly modulate Hebbian learning rates and connection strengths in real-time
- **Persistent Semantic Index (PSI)**: Long-term memory structure storing reinforced associations across unlimited time horizons
- **Host-Based Mesh Cognition**: Cross-service learning between web processes on the same host, enabling collaborative defense
- **EQ/IQ Behavioral Regulation**: Emotional intelligence (empathy, social awareness) balanced with analytical intelligence for context-aware decision making
- **Retrospective Learning System**: Enhanced learning from false negatives (missed threats) discovered after initial analysis, mimicking natural learning from mistakes
- **Isolation Forest Experiential Learning**: Unsupervised anomaly detection integrated as experiential contributor to cognitive model with EQ/IQ regulation and fear mitigation

## Technical Architecture

### Learning Mechanism
- **Host-standalone learning** on each endpoint without cloud or network dependencies
- **True Hebbian Plasticity**: Each memory trace maintains bidirectional connection weights that strengthen when patterns co-occur with positive rewards
- **Reinforcement-Modulated Learning**: Reward signals directly scale Hebbian learning rates - stronger rewards create stronger synaptic changes
- **Multi-service Hebbian memory** with individual BDH instances per web service process (e.g., ecommerce-api, user-portal, admin-dashboard)
- **Cross-service knowledge sharing** where attack patterns learned by one web service process protect others on the same host
- **Shared long-term memory** (PSI) consolidating significant patterns across all host services
- **Collective valence control** coordinating aggression levels across all web services
- **Enhanced retrieval** using Hebbian connection weights to boost similarity matching

### Key Components
1. **Featurizer**: Produces L2-normalized semantic vectors representing per-process behavior windows including:
   - Entropy measurements
   - Syscall patterns
   - Deserialization signals (blob scores, payload entropy, admin API flags)
   - Endpoint rarity metrics

2. **Host-Based Memory System**:
   - **Individual Service Memory**: Each web service process (e.g., ecommerce-api, user-portal, auth-service) maintains its own BDH memory
   - **Cross-Service Learning**: Attack patterns learned by one web service process are shared with others on the same host
   - **Shared PSI Index**: Consolidated long-term memory storing significant patterns from all service processes
   - **Collective Valence**: Host-level aggression control coordinating defensive posture across service processes
   - **Cosine Similarity Retrieval**: Efficient pattern matching within and across service process memories

3. **EQ/IQ Behavioral Regulation System**:
   - **Emotional Intelligence (EQ)**: Empathy modeling, social context awareness, and emotional state tracking
   - **Analytical Intelligence (IQ)**: Pattern recognition, logical reasoning, and systematic analysis
   - **Dynamic Balance**: Adaptive weighting between emotional and analytical responses based on context
   - **Contextual Decision Making**: Considers both emotional and analytical factors for nuanced threat response
   - **Empathic Accuracy**: Measures system's ability to understand and predict user/attacker behavior

4. **Retrospective Learning System**:
   - **False Negative Learning**: Enhanced learning from missed threats discovered after initial analysis
   - **Threat Discovery Methods**: Supports learning from security audits, incident response, external detection, user reports, forensic analysis, and threat intelligence
   - **Temporal Pattern Analysis**: Time-based decay and relevance weighting for discovered threats
   - **Consequence Severity Tracking**: Adjusts learning intensity based on threat impact (1.0-3.0 scale)
   - **Enhanced Learning Rate**: 2.0x multiplier for false negative corrections to accelerate adaptation
   - **Feature Similarity Matching**: Identifies related threat patterns for comprehensive learning

5. **Isolation Forest Experiential Learning System**:
   - **Unsupervised Anomaly Detection**: Isolation Forest algorithm identifies anomalous patterns without requiring labeled training data
   - **Experiential Contributor**: Anomaly detection results contribute to cognitive model as experiential learning data
   - **PSI Semantic Integration**: Anomaly patterns are semantically encoded in PSI for long-term memory consolidation
   - **BDH Memory Enhancement**: Experiential context from anomalies enriches Hebbian memory with fear mitigation capabilities
   - **EQ/IQ Regulation**: Emotional-analytical balance prevents fear-based decision paralysis from negative experiences
   - **Fear Mitigation System**: Prevents negative anomaly experiences from causing system paralysis while maintaining learning
   - **Adaptive Threshold Management**: Dynamic anomaly thresholds based on experiential learning and cognitive feedback
   - **Security-First Approach**: Configured to prefer false positives over false negatives for maximum protection

6. **Adaptive Defense**:
   - ValenceController adjusts aggression based on reward history and EQ/IQ balance
   - Produces actuations that modify the runtime environment:
     - Process respawn/reseed
     - Seccomp/job object changes
     - Isolate/throttle/restart actions
   - Implements Moving Target Defense (MTD) strategies
   - Integrates retrospective learning feedback for continuous improvement

## Distinctive Features

### What Sets This Apart

| Aspect | Traditional Systems | This Project |
|--------|-------------------|--------------|
| **Training** | Centralized, cloud-based | Local, autonomous learning |
| **Learning Type** | Supervised/Statistical | Reinforcement + Hebbian + EQ/IQ |
| **Context** | Limited telemetry | Deep process state embedding |
| **Adaptation** | Requires retraining | Continuous, experiential |
| **Defense** | Detect → Alert | Detect → Learn → Adapt |
| **Memory** | Model drift prone | Persistent consolidation |
| **Platform** | Vendor-specific | Cross-process (multiple processes of same web server type) |
| **Feedback** | Often ignored | Integrated as reinforcement |
| **False Negatives** | Manual analysis | Automated retrospective learning |
| **Intelligence** | Single-mode analysis | Dual EQ/IQ balanced reasoning |
| **Mistake Learning** | Limited/manual | Enhanced 2.0x learning rate |
| **Anomaly Detection** | Supervised/threshold-based | Unsupervised Isolation Forest with experiential learning |
| **Fear Management** | No consideration | EQ/IQ regulated fear mitigation prevents decision paralysis |

## Key Innovations

### 1. **Emergent Intelligence**
- Synaptic strengths evolve through network interactions, not preset rules
- System develops defensive "instincts" organically through experience
- Builds context-independent knowledge for responding to novel threats

### 2. **Host-Based Cross-Process Learning**
- **Multi-Process Architecture**: Individual BDH memory per web server process on the same host
- **Collaborative Defense**: Attack patterns learned by one web server process (e.g., IIS w3wp.exe PID 1001) immediately inform other processes of the same type (w3wp.exe PIDs 1002-1006)
- **Shared Intelligence**: Consolidated PSI memory accessible to all web server processes on the host
- **Transfer Learning**: Cross-process knowledge sharing through mesh cognition, not retraining

### 3. **EQ/IQ Behavioral Regulation**
- **Dual Intelligence System**: Balances emotional intelligence (empathy, social awareness) with analytical intelligence (pattern recognition, logic)
- **Context-Aware Decision Making**: Adapts response style based on situational context and threat characteristics
- **Empathic Accuracy**: Measures and improves system's ability to understand user and attacker behavior patterns
- **Dynamic Balance**: Automatically adjusts EQ/IQ weighting based on feedback and performance metrics
- **Behavioral Adaptation**: Learns optimal emotional vs. analytical response patterns for different threat types

### 4. **Retrospective Learning from Mistakes**
- **False Negative Enhancement**: Implements 2.0x enhanced learning rate when threats are discovered after initial miss
- **Natural Learning Principle**: Mimics biological learning where mistakes provide stronger learning signals than successes
- **Multi-Source Discovery**: Learns from threats discovered via security audits, incident response, external detection, user reports, forensic analysis, and threat intelligence
- **Temporal Intelligence**: Applies time-based decay and relevance weighting to discovered threats
- **Consequence-Weighted Learning**: Adjusts learning intensity based on actual threat impact and severity
- **Pattern Generalization**: Uses feature similarity matching to apply lessons from missed threats to related patterns

### 5. **Embodied Defense**
- System doesn't just detect—it actively modifies its attack surface
- Learning rewards survivability, not just accuracy
- Defensive behaviors emerge through trial and reinforcement
- Integrates EQ/IQ balance and retrospective learning into defense strategies

### 6. **Isolation Forest Experiential Learning Integration**
- **Unsupervised Anomaly Detection**: Isolation Forest algorithm provides experiential learning data without requiring labeled training datasets
- **Cognitive Model Integration**: Anomaly detection results become experiential contributors to the cognitive learning system
- **PSI-BDH Memory Synergy**: Anomaly patterns are semantically encoded in PSI and enriched with experiential context in BDH memory
- **EQ/IQ Fear Mitigation**: Emotional-analytical balance prevents negative anomaly experiences from causing decision paralysis
- **Adaptive Learning Enhancement**: Experiential anomaly data improves cognitive adaptation and threat recognition capabilities
- **Security-First Configuration**: System tuned to prefer false positives over false negatives, ensuring maximum protection

### 7. **Operator Integration**
- Real-time feedback loop with human operators
- UI feedback ("good isolate," "false positive") becomes reinforcement signal
- Model evolves decision boundaries based on operational outcomes
- Retrospective learning system incorporates post-incident analysis and lessons learned

## Implementation Details

### Current Features
- Implemented in both Rust and Python for platform flexibility
- Simulator and replay tooling for testing
- Persistence layer with append-only evidence store
- Snapshot capabilities for state preservation
- Direct process hooks for real-time monitoring

### Novel Aspects
- **Host-Based Mesh Cognition**: Cross-service learning within a single host, not network-dependent
- **Multi-Service Coordination**: Web service processes (APIs, web apps, microservices) learning collaboratively on the same server
- **No context window constraints**: Unlike LLMs, can recall associations regardless of temporal distance
- **Self-regulating plasticity**: Through host-level mesh interactions, not pre-constrained design
- **Contextual anomaly cognition**: Not threshold-based detection, but pattern generalization
- **Service-agnostic deployment**: Works across diverse web service combinations on one host

## Why This Hasn't Been Done Before

This project sits at the intersection of multiple challenging domains:
- **Neuroscience**: Biological learning principles
- **Reinforcement Learning**: Adaptive policy optimization
- **Cybersecurity**: Real-time threat response
- **Systems Programming**: Low-level process control

The combination requires:
- Cross-domain expertise rarely found in single teams
- Technical sophistication to manage stability and convergence
- Philosophical shift from optimization-based to emergent intelligence
- Integration challenges across traditionally separate fields

## Host-Based Mesh Cognition Architecture

### **Multi-Service Collaborative Defense**

WebGuard implements a novel **host-based mesh cognition** system adapted from the BHSM Cognitive Mesh Neural Network (CMNN). Unlike network-based mesh systems, this architecture focuses on **collaborative learning between multiple processes of the same web server type within a single host**. For example, multiple IIS w3wp.exe processes serving different applications share collective intelligence:

```
┌─────────────────── IIS Web Server Host ───────────────────┐
│                                                            │
│  ┌─w3wp.exe─┐  ┌─w3wp.exe─┐  ┌─w3wp.exe─┐  ┌─w3wp.exe─┐  │
│  │PID: 1001 │  │PID: 1002 │  │PID: 1003 │  │PID: 1004 │  │
│  │ECommerce │  │User      │  │Admin     │  │API       │  │
│  │BDH Memory│◄─┤Portal    │◄─┤Dashboard │◄─┤Gateway   │  │
│  └──────────┘  │BDH Memory│  │BDH Memory│  │BDH Memory│  │
│       │        └──────────┘  └──────────┘  └──────────┘  │
│       │             │             │             │        │
│  ┌─w3wp.exe─┐  ┌─w3wp.exe─┐       │             │        │
│  │PID: 1005 │  │PID: 1006 │       │             │        │
│  │Auth      │  │Payment   │       │             │        │
│  │Service   │◄─┤Service   │◄──────┼─────────────┘        │
│  │BDH Memory│  │BDH Memory│       │                      │
│  └──────────┘  └──────────┘       │                      │
│       │             │             │                      │
│       └─────────────┼─────────────┘                      │
│                     │                                    │
│              ┌──────▼──────────────┐                     │
│              │   Shared PSI Index  │                     │
│              │  (Long-term Memory) │                     │
│              └─────────────────────┘                     │
│                                                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │      Host Valence Controller                     │  │
│  │   (Collective Aggression Management)             │  │
│  └───────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

### **Key Benefits:**
- **Immediate Cross-Process Protection**: Attack learned on one web server process instantly protects other processes of the same type
- **Host-Standalone Operation**: No network dependencies, pure endpoint protection
- **Collective Intelligence**: All processes benefit from any process's defensive experience
- **Resource Efficiency**: Shared long-term memory, distributed short-term learning
- **Coordinated MTD**: Moving Target Defense strategies across all host processes

### **Reinforced Hebbian Learning Flow:**
1. **Pattern Detection**: IIS w3wp.exe process (PID 1001) serving ECommerce app detects deserialization attack → creates memory trace with negative valence
2. **Hebbian Connection Formation**: New trace forms bidirectional connections with similar existing patterns
3. **Reinforcement Modulation**: Negative reward strengthens connections to defensive responses, weakens connections to permissive responses
4. **Cross-Process Propagation**: Pattern propagates to other IIS w3wp.exe processes (PIDs 1002-1006) serving User Portal, Admin Dashboard, API Gateway, Auth Service, and Payment Service with dampened Hebbian weights
5. **Synaptic Strengthening**: Repeated co-activation of attack pattern + defensive response strengthens their Hebbian connection
6. **Enhanced Retrieval**: Future similar attacks benefit from strengthened Hebbian connections for faster, more accurate recognition

### **True Hebbian Implementation:**
- **Connection Weights**: Explicit bidirectional weights between memory traces (not just similarity)
- **Co-activation Rule**: Δw = η × activation_pre × activation_post × reward_modulation
- **Synaptic Decay**: Unused connections gradually weaken to prevent memory saturation
- **Reinforcement Scaling**: Reward magnitude directly modulates learning rate and connection strength
- **Bidirectional Propagation**: Weight updates flow both forward and backward between connected traces

### **Isolation Forest Experiential Learning Integration:**

The Isolation Forest integration represents a breakthrough in unsupervised experiential learning for cybersecurity. Unlike traditional supervised anomaly detection, this system learns from experience without requiring pre-labeled attack data.

#### **Technical Architecture:**

```
┌─────────────────── Isolation Forest Experiential Learning ───────────────────┐
│                                                                                │
│  ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────────┐  │
│  │   Input Data    │───▶│  Isolation Forest │───▶│   Anomaly Detection     │  │
│  │  (Features)     │    │   Algorithm       │    │     Results             │  │
│  └─────────────────┘    └──────────────────┘    └─────────────────────────┘  │
│                                                             │                  │
│                                                             ▼                  │
│  ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────────┐  │
│  │  EQ/IQ Balance  │◄───┤ Experiential     │◄───┤   PSI Semantic          │  │
│  │   Regulation    │    │ Learning         │    │   Encoding              │  │
│  └─────────────────┘    │ Integration      │    └─────────────────────────┘  │
│           │              └──────────────────┘                                 │
│           ▼                        │                                          │
│  ┌─────────────────┐              ▼                                          │
│  │ Fear Mitigation │    ┌─────────────────────────┐                          │
│  │    System       │    │   BDH Memory            │                          │
│  └─────────────────┘    │   Enhancement           │                          │
│                         │ (Experiential Context)  │                          │
│                         └─────────────────────────┘                          │
└────────────────────────────────────────────────────────────────────────────────┘
```

#### **Integration Benefits:**

1. **Unsupervised Learning**: No need for labeled attack data - system learns from behavioral patterns
2. **Experiential Enrichment**: Anomaly detection results become experiential learning data for cognitive model
3. **PSI Semantic Encoding**: Anomaly patterns are semantically encoded for long-term memory consolidation
4. **BDH Memory Enhancement**: Experiential context from anomalies enriches Hebbian memory connections
5. **EQ/IQ Fear Mitigation**: Prevents negative experiences from causing decision paralysis
6. **Adaptive Thresholds**: Dynamic anomaly detection thresholds based on experiential feedback

#### **Cognitive Learning Flow:**

1. **Anomaly Detection**: Isolation Forest identifies anomalous behavioral patterns in real-time
2. **Experiential Encoding**: Anomaly results are encoded as experiential learning data
3. **PSI Integration**: Semantic patterns from anomalies are stored in Persistent Semantic Index
4. **BDH Memory Enhancement**: Experiential context enriches Hebbian memory with fear mitigation
5. **EQ/IQ Regulation**: Emotional-analytical balance prevents fear-based decision paralysis
6. **Cognitive Adaptation**: System adapts threat recognition based on experiential anomaly learning
7. **Cross-Process Propagation**: Experiential learning spreads across all host processes

#### **Fear Mitigation System:**

The system implements sophisticated fear mitigation to prevent negative anomaly experiences from causing decision paralysis:

- **EQ/IQ Balance**: Maintains optimal emotional-analytical balance during anomaly processing
- **Fear Detection**: Identifies when negative experiences might prevent necessary actions
- **Mitigation Strategies**: Applies cognitive techniques to overcome fear-based hesitation
- **Learning Preservation**: Maintains learning benefits while preventing paralysis
- **Adaptive Adjustment**: Dynamically adjusts fear mitigation based on context and outcomes

#### **Security-First Approach:**

The Isolation Forest integration is specifically tuned for cybersecurity applications:

- **False Positive Preference**: System configured to prefer false positives over false negatives
- **Threat Prioritization**: Anomaly detection prioritizes potential security threats
- **Rapid Response**: Experiential learning enables faster adaptation to new attack patterns
- **Memory Consolidation**: Important anomaly patterns are consolidated in long-term memory
- **Cross-Process Protection**: Anomaly learning protects all processes on the host

## What Happens When An Intrusion or Exploitation Happens?

When WebGuard's Reinforced Hebbian Learning (RHL) system detects an anomaly, it triggers a sophisticated multi-stage response process:

### 1. **Anomaly Detection Process**
- The system continuously monitors telemetry from web server processes (e.g., IIS w3wp.exe processes)
- Each telemetry event is **featurized** into a 32-dimensional vector
- The BDH (Behavioral Decision Hierarchy) memory retrieves **similar past experiences** and computes:
  - `top_sim`: Similarity score to most similar past event
  - `avg_valence`: Average emotional valence (positive/negative) of similar experiences

### 2. **Policy Decision Engine**
The system uses a **reinforcement learning policy** that considers:
- **Similarity score**: How similar this event is to known patterns
- **Valence**: Emotional context (threat level) from past experiences  
- **Host aggression**: Current defensive posture of the system
- **Configuration parameters**: β (valence weight), γ (score weight), ε (exploration rate)

### 3. **Response Actions Available**
Based on the policy decision, the system can take these actions:

```rust
pub enum Action {
    Log,              // Record event only
    Notify,           // Alert administrators  
    Throttle,         // Rate limit connections
    Isolate,          // Block/quarantine process
    Restart,          // Restart the process
    SnapshotAndKill,  // Capture evidence then terminate
}
```

### 4. **Logging and Evidence Collection**

**Yes, anomalies are logged with datetime and details:**

- **Standard logging**: Every detection event is logged with:
  ```
  "Telemetry pid={} sim_score={} avg_valence={:?} action={:?}"
  ```

- **Evidence snapshots**: For severe threats (`SnapshotAndKill` action), the system:
  - Calls `evidence::snapshot_evidence(pid, "policy_snapshot")`
  - Creates timestamped JSON entries in `evidence.log`:
    ```json
    {"pid":1001,"reason":"policy_snapshot","time":1698765432}
    ```

### 5. **MTD-Style Defensive Actions**

**Yes, the system can interfere with process connections when configured:**

- **Throttle**: Rate limits incoming connections to the affected process
- **Isolate**: Blocks network access or quarantines the process  
- **SnapshotAndKill**: Terminates the compromised process after evidence collection
- **Restart**: Restarts the process to clear any compromise

The actual implementation is in `actuators::apply_nginx_mitigation()` (designed for real defensive actions).

### 6. **Cross-Process Learning**
When one IIS w3wp.exe process detects an anomaly:
- The learning is **immediately shared** with other w3wp.exe processes on the same host
- This creates **collective immunity** - if one process learns about a threat, all processes become resistant
- The shared PSI Index stores long-term memory accessible to all processes

### 7. **Adaptive Aggression**
The system maintains a **host-level aggression score** that:
- Increases when threats are detected
- Makes the system more sensitive to future anomalies
- Influences the severity of defensive responses

This creates a **living defense system** that learns from attacks and becomes more protective over time, with immediate cross-process threat sharing and configurable MTD-style responses.

## Advanced Learning Systems

### EQ/IQ Behavioral Regulation System

WebGuard implements a novel **dual-intelligence system** that balances emotional intelligence (EQ) with analytical intelligence (IQ) for context-aware cybersecurity decision making:

#### **Emotional Intelligence (EQ) Components:**
- **Empathy Modeling**: Tracks and predicts user behavior patterns to distinguish legitimate users from attackers
- **Social Context Awareness**: Considers organizational context, user roles, and behavioral norms
- **Emotional State Tracking**: Monitors system "mood" and stress levels based on recent threat activity
- **Empathic Accuracy**: Measures system's ability to correctly interpret user intentions and predict behavior

#### **Analytical Intelligence (IQ) Components:**
- **Pattern Recognition**: Traditional ML-based threat detection and classification
- **Logical Reasoning**: Rule-based analysis and systematic threat evaluation
- **Statistical Analysis**: Quantitative risk assessment and probability calculations
- **Systematic Processing**: Structured approach to threat analysis and response planning

#### **Dynamic Balance Mechanism:**
```rust
pub struct EqIqBalance {
    pub eq_weight: f32,     // Emotional intelligence weighting (0.0-1.0)
    pub iq_weight: f32,     // Analytical intelligence weighting (0.0-1.0)
    pub balance: f32,       // Overall balance factor for learning modulation
}
```

The system automatically adjusts the EQ/IQ balance based on:
- **Context Type**: High-stakes environments favor IQ, social environments favor EQ
- **Threat Characteristics**: Known attack patterns favor IQ, novel behaviors favor EQ
- **Performance Feedback**: System learns optimal balance through reinforcement
- **Temporal Patterns**: Time-of-day and usage patterns influence balance

### Retrospective Learning System

WebGuard implements **enhanced learning from false negatives** - threats that were initially missed but discovered later through various means:

#### **Threat Discovery Methods:**
```rust
pub enum ThreatDiscoveryMethod {
    SecurityAudit,        // Discovered during security audit
    IncidentResponse,     // Found during incident investigation
    ExternalDetection,    // Detected by external security tools
    UserReport,           // Reported by users or administrators
    ForensicAnalysis,     // Uncovered during forensic investigation
    ThreatIntelligence,   // Identified through threat intelligence feeds
}
```

#### **Enhanced Learning Process:**
1. **Missed Threat Reporting**: System accepts reports of previously missed threats with context
2. **Temporal Analysis**: Calculates time decay and relevance weighting
3. **Consequence Assessment**: Evaluates actual impact and severity (1.0-3.0 scale)
4. **Feature Similarity**: Identifies related patterns in memory for comprehensive learning
5. **Enhanced Learning Rate**: Applies 2.0x learning multiplier for false negative corrections
6. **Pattern Generalization**: Updates related threat patterns based on similarity matching

#### **Natural Learning Principle:**
The system mimics biological learning where **mistakes provide stronger learning signals than successes**. This addresses the common cybersecurity challenge where systems learn well from detected threats but poorly from missed ones.

#### **Integration with Memory Systems:**
- **BDH Memory Updates**: Retrospective learning directly updates Hebbian connection weights
- **PSI Index Enhancement**: Long-term memory incorporates lessons from missed threats
- **Cross-Process Propagation**: Retrospective learning spreads across all host processes
- **EQ/IQ Integration**: Missed threats inform optimal EQ/IQ balance for similar future scenarios

---

## Impact

This represents a new class of cognitive, self-adaptive cybersecurity system—emergent, biologically inspired, and locally learning. Rather than reinventing existing tools, this project creates an adaptive "suspension system" that enables the cybersecurity infrastructure to learn and adapt to new terrain autonomously.

The system transforms endpoint protection from static, signature-based defense to a dynamic, learning organism that develops its own understanding of normal and abnormal behavior specific to each deployment context, with **collaborative intelligence across all web services on the same host**.

---

## Project Setup Status

### Current Directory Structure
The project has been set up with the following structure based on analysis of the provided files:

```
WebGuard/
├── Cargo.toml                      # Rust project configuration
├── README.md                       # This file
├── src/
│   ├── actuators/                  # Defense actuators module
│   ├── memory_engine/              # Hebbian memory system
│   ├── sensors/                    # Behavioral sensors module
│   ├── eq_iq_regulator.rs         # EQ/IQ behavioral regulation system
│   ├── retrospective_learning.rs  # False negative learning system
│   ├── experiential_anomaly.rs    # Isolation Forest experiential learning
│   ├── experiential_learning_test.rs # Experiential learning test suite
│   ├── mesh_cognition.rs          # Host-based mesh cognition
│   ├── featurizer.rs              # Feature extraction and vectorization
│   ├── policy.rs                  # Decision policy engine
│   └── main.rs                    # Main application entry point
├── tests/
│   ├── test_eq_iq_integration.rs  # EQ/IQ system integration tests
│   └── test_retrospective_learning.rs # Retrospective learning tests
├── src/bin/
│   ├── adaptive_learning_test.rs  # Multi-pass adaptive learning test
│   └── experiential_learning_test.rs # Isolation Forest experiential learning test
└── tools/                         # Development and testing tools
```

## Testing the Isolation Forest Integration

The Isolation Forest experiential learning integration can be tested using the dedicated test binary:

```bash
# Run the comprehensive experiential learning test
cargo run --bin experiential_learning_test

# Build and run with optimizations for performance testing
cargo build --release
./target/release/experiential_learning_test
```

### Test Results Interpretation

The experiential learning test validates several key aspects:

1. **Cognitive Learning Validation**: Measures improvement in threat detection across multiple learning passes
2. **EQ/IQ Regulation Testing**: Validates emotional-analytical balance maintenance
3. **Fear Mitigation Effectiveness**: Ensures negative experiences don't cause decision paralysis
4. **Memory Utilization**: Tracks efficient use of BDH memory and PSI integration
5. **Security-First Validation**: Confirms preference for false positives over false negatives

### Expected Test Output

```
🧠 WebGuard Experiential Learning Test with Isolation Forest Integration
🎯 Testing cognitive learning improvements with EQ/IQ regulation
🛡️  Security-first approach: Preferring false positives over false negatives
⚖️  Fear mitigation: Preventing decision paralysis from negative experiences

🔄 Learning Pass 1/5
   📈 Threat Detection Rate: 94.7%
   🚨 False Positive Rate: 8.0%
   ⚠️  False Negative Rate: 0.0%
   🎯 Confidence Score: 0.450
   🧠 Memory Utilization: 15.0%
   ⚖️  EQ/IQ Balance: 0.500
   🛡️  Fear Mitigation Applied: 786 times
   💭 Experiential Context Used: 150 times

✅ SYSTEM VALIDATION: Isolation Forest experiential learning operational
✅ EQ/IQ REGULATION: Emotional-analytical balance maintained
✅ FEAR MITIGATION: Decision paralysis prevention active
✅ SECURITY-FIRST: Low false negative rate achieved
```

The test demonstrates successful integration of:
- Isolation Forest anomaly detection as experiential contributor
- PSI semantic encoding for anomaly patterns
- BDH memory enhancement with experiential context
- EQ/IQ regulation preventing fear-based decision paralysis
- Fear mitigation system maintaining learning while preventing paralysis
