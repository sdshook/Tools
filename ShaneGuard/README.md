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
- **Persistent Symantic Index (PSI)**: Long-term memory structure storing reinforced associations across unlimited time horizons
- **Mesh-Mediated Cognition**: Cross-node feedback creating emergent behavior through distributed learning

## Technical Architecture

### Learning Mechanism
- **Local, autonomous learning** on each endpoint without cloud dependencies
- **Hebbian-style associative memory** (BDHMemory) combined with reinforcement signals
- **Contextual bandit policy** for action selection with memory updates from observed rewards
- **Synaptic plasticity** enabled through unlimited recall and cross-node RL signals

### Key Components
1. **Featurizer**: Produces L2-normalized semantic vectors representing per-process behavior windows including:
   - Entropy measurements
   - Syscall patterns
   - Deserialization signals (blob scores, payload entropy, admin API flags)
   - Endpoint rarity metrics

2. **Memory System**:
   - Stores and retrieves traces by cosine similarity
   - Promotes significant patterns to long-term PSI when reward thresholds are met
   - Uses bounded, incremental valence updates (exponential/Hebbian-style with learning rate)

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

### 2. **Cross-Platform Learning**
- Unified featurizer and memory across IIS, Apache, and NGINX
- Behavior learned on one service informs defense of others
- Transfer learning through associative recall, not retraining

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
- **No context window constraints**: Unlike LLMs, can recall associations regardless of temporal distance
- **Self-regulating plasticity**: Through mesh interactions, not pre-constrained design
- **Contextual anomaly cognition**: Not threshold-based detection, but pattern generalization
- **Language and platform agnostic**: Deployable across diverse environments

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

## Impact

This represents a new class of cognitive, self-adaptive cybersecurity system—emergent, biologically inspired, and locally learning. Rather than reinventing existing tools, this project creates an adaptive "suspension system" that enables the cybersecurity infrastructure to learn and adapt to new terrain autonomously.

The system transforms endpoint protection from static, signature-based defense to a dynamic, learning organism that develops its own understanding of normal and abnormal behavior specific to each deployment context.

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

### Setup Issues Encountered
Both provided zip files (`shaneguard_enhanced_wsus.zip` and `ShaneGuard.zip`) were corrupted or truncated:

**First attempt (`shaneguard_enhanced_wsus.zip`)**:
- File size: 19KB 
- Error: "Bad offset for central directory"
- Contains references to `Cargo.toml`

**Second attempt (`ShaneGuard.zip`)**:
- File size: 22KB
- Error: "Bad magic number for central directory" 
- Missing ~767MB of expected data

### Next Steps
To complete the project setup with the actual implementation files:
1. **Re-upload the complete, uncorrupted zip file**, or
2. **Provide the individual project files directly**, or
3. **Share the project via GitHub repository or another method**

The directory structure is ready to receive the implementation files for this groundbreaking neuromorphic cybersecurity system.