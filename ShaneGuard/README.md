# ShaneGuard: Adaptive Cybersecurity Web Service Protection Agent
## Neuromorphic Defense with Reinforced Hebbian Learning
**(c) Shane D. Shook, All Rights Reserved 2025**

## Project Overview

This project introduces a novel adaptive cybersecurity web service protection agent that combines neuromorphic computing principles with reinforcement learning to create autonomous, locally-learning endpoint protection. The system, implemented as both a Cognitive Mesh Neural Network (CMNN) and Endpoint Protection Platform (EPP), represents a first-of-its-kind architecture for real-time, self-adaptive defense.

## Core Innovation

### The Unique Combination
The system fuses four key components that have rarely been integrated:
- **Bidirectional Hebbian Learning**: Weight updates propagate both forward and backward between nodes, enabling reciprocal reinforcement
- **Reinforcement Learning Signals**: Reward/punishment feedback modulates Hebbian weight changes in real-time
- **Persistent Semantic Index (PSI)**: Long-term memory structure storing reinforced associations across unlimited time horizons
- **Host-Based Mesh Cognition**: Cross-service learning between web processes on the same host, enabling collaborative defense

## Technical Architecture

### Learning Mechanism
- **Host-standalone learning** on each endpoint without cloud or network dependencies
- **Multi-service Hebbian memory** with individual BDH instances per web service (Apache, NGINX, IIS)
- **Cross-service knowledge sharing** where attack patterns learned by one service protect others on the same host
- **Shared long-term memory** (PSI) consolidating significant patterns across all host services
- **Collective valence control** coordinating aggression levels across all web services
- **Contextual bandit policy** for action selection with memory updates from observed rewards

### Key Components
1. **Featurizer**: Produces L2-normalized semantic vectors representing per-process behavior windows including:
   - Entropy measurements
   - Syscall patterns
   - Deserialization signals (blob scores, payload entropy, admin API flags)
   - Endpoint rarity metrics

2. **Host-Based Memory System**:
   - **Individual Service Memory**: Each web service (Apache, NGINX, IIS) maintains its own BDH memory
   - **Cross-Service Learning**: Attack patterns learned by one service are shared with others on the same host
   - **Shared PSI Index**: Consolidated long-term memory storing significant patterns from all services
   - **Collective Valence**: Host-level aggression control coordinating defensive posture across services
   - **Cosine Similarity Retrieval**: Efficient pattern matching within and across service memories

3. **Adaptive Defense**:
   - ValenceController adjusts aggression based on reward history
   - Produces actuations that modify the runtime environment:
     - Process respawn/reseed
     - Seccomp/job object changes
     - Isolate/throttle/restart actions
   - Implements Moving Target Defense (MTD) strategies

## Distinctive Features

### What Sets This Apart

| Aspect | Traditional Systems | This Project |
|--------|-------------------|--------------|
| **Training** | Centralized, cloud-based | Local, autonomous learning |
| **Learning Type** | Supervised/Statistical | Reinforcement + Hebbian |
| **Context** | Limited telemetry | Deep process state embedding |
| **Adaptation** | Requires retraining | Continuous, experiential |
| **Defense** | Detect → Alert | Detect → Learn → Adapt |
| **Memory** | Model drift prone | Persistent consolidation |
| **Platform** | Vendor-specific | Cross-service (IIS, Apache, NGINX) |
| **Feedback** | Often ignored | Integrated as reinforcement |

## Key Innovations

### 1. **Emergent Intelligence**
- Synaptic strengths evolve through network interactions, not preset rules
- System develops defensive "instincts" organically through experience
- Builds context-independent knowledge for responding to novel threats

### 2. **Host-Based Cross-Service Learning**
- **Multi-Service Architecture**: Individual BDH memory per web service on the same host
- **Collaborative Defense**: Attack patterns learned by Apache immediately inform NGINX and IIS defense
- **Shared Intelligence**: Consolidated PSI memory accessible to all services on the host
- **Transfer Learning**: Cross-service knowledge sharing through mesh cognition, not retraining

### 3. **Embodied Defense**
- System doesn't just detect—it actively modifies its attack surface
- Learning rewards survivability, not just accuracy
- Defensive behaviors emerge through trial and reinforcement

### 4. **Operator Integration**
- Real-time feedback loop with human operators
- UI feedback ("good isolate," "false positive") becomes reinforcement signal
- Model evolves decision boundaries based on operational outcomes

## Implementation Details

### Current Features
- Implemented in both Rust and Python for platform flexibility
- Simulator and replay tooling for testing
- Persistence layer with append-only evidence store
- Snapshot capabilities for state preservation
- Direct process hooks for real-time monitoring

### Novel Aspects
- **Host-Based Mesh Cognition**: Cross-service learning within a single host, not network-dependent
- **Multi-Service Coordination**: Apache, NGINX, IIS learning collaboratively on the same server
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

ShaneGuard implements a novel **host-based mesh cognition** system adapted from the BHSM Cognitive Mesh Neural Network (CMNN). Unlike network-based mesh systems, this architecture focuses on **cross-service learning within a single host**:

```
┌─────────────────── Web Server Host ───────────────────┐
│                                                        │
│  ┌─Apache─┐    ┌─NGINX─┐    ┌─IIS─┐    ┌─Node.js─┐   │
│  │ BDH-A  │◄──►│ BDH-N │◄──►│BDH-I│◄──►│ BDH-JS │   │
│  │Memory  │    │Memory │    │Mem. │    │ Memory │   │
│  └────────┘    └───────┘    └─────┘    └────────┘   │
│       │            │           │            │        │
│       └────────────┼───────────┼────────────┘        │
│                    │           │                     │
│              ┌─────▼───────────▼─────┐               │
│              │   Shared PSI Index    │               │
│              │  (Long-term Memory)   │               │
│              └───────────────────────┘               │
│                                                       │
│  ┌─────────────────────────────────────────────────┐ │
│  │      Host Valence Controller                   │ │
│  │   (Collective Aggression Management)           │ │
│  └─────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────┘
```

### **Key Benefits:**
- **Immediate Cross-Service Protection**: Attack learned on Apache instantly protects NGINX
- **Host-Standalone Operation**: No network dependencies, pure endpoint protection
- **Collective Intelligence**: All services benefit from any service's defensive experience
- **Resource Efficiency**: Shared long-term memory, distributed short-term learning
- **Coordinated MTD**: Moving Target Defense strategies across all host services

### **Learning Flow Example:**
1. **Apache** detects deserialization attack → negative valence in BDH-A
2. **Mesh Signal** propagates pattern to NGINX and IIS with dampened strength
3. **Shared PSI** consolidates significant attack patterns from all services
4. **Host Valence** adjusts collective aggression based on overall threat level
5. **Future Attack** on NGINX already has defensive knowledge from Apache's experience

## Impact

This represents a new class of cognitive, self-adaptive cybersecurity system—emergent, biologically inspired, and locally learning. Rather than reinventing existing tools, this project creates an adaptive "suspension system" that enables the cybersecurity infrastructure to learn and adapt to new terrain autonomously.

The system transforms endpoint protection from static, signature-based defense to a dynamic, learning organism that develops its own understanding of normal and abnormal behavior specific to each deployment context, with **collaborative intelligence across all web services on the same host**.

---

## Project Setup Status

### Current Directory Structure
The project has been set up with the following structure based on analysis of the provided files:

```
ShaneGuard/
├── Cargo.toml              # Rust project configuration
├── README.md               # This file
├── src/
│   ├── actuators/          # Defense actuators module
│   ├── memory_engine/      # Hebbian memory system
│   └── sensors/            # Behavioral sensors module
└── tools/                  # Development and testing tools
```
