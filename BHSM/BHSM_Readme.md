# BHSM: Bidirectional Hebbian Memory System

**A Neuromorphic Architecture for Adaptive Experience Classification**

**Shane D. Shook, PhD | 2025**

---

## Abstract

The Bidirectional Hebbian Memory System (BHSM) is a neuromorphic architecture for adaptive classification that learns from operational experience and develops shared knowledge across co-located service instances. The architecture combines persistent memory storage, reward-gated learning, and constrained action spaces to address specific deployment scenarios where continuous adaptation is required.

This Python implementation provides a general-purpose BHSM library that can be extended for various classification domains including cybersecurity, content moderation, anomaly detection, and more.

---

## Architecture Overview

BHSM organizes into three layers with a strict semantic-execution boundary:

```
                              Raw Input
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    SYNAPTIC LAYER                            │
│    Reward-Gated Associative Memory (BDH) + Persistent        │
│    Semantic Index (PSI)                                      │
│    (Analyzes meaning through statistical properties)         │
├─────────────────────────────────────────────────────────────┤
│                    COGNITIVE LAYER                           │
│    Classification logic, confidence calibration, monitoring  │
│    Score Fusion: PSI(0.4) + BDH(0.3) + Baseline(0.3)        │
╞═════════════════════════════════════════════════════════════╡
│              SEMANTIC-EXECUTION BOUNDARY                     │
│         (Only verdicts cross—never raw input)                │
╞═════════════════════════════════════════════════════════════╡
│                    MECHANICAL LAYER                          │
│         Constrained action space (output bounding)           │
│    (Acts on verdicts: ALLOW / DETECT / BLOCK)               │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Principles

1. **Semantic-Execution Separation**: Raw input never reaches the action layer, preventing injection attacks
2. **Constrained Action Space**: Outputs bounded to predefined actions, limiting consequence of errors
3. **Reward-Gated Learning**: Behavioral adaptation from operational feedback
4. **Persistent Memory**: Experience accumulation across sessions
5. **Cross-Instance Learning**: Shared knowledge across co-located services

---

## Core Components

### Feature Extraction Pipeline (32 dimensions)

BHSM uses a fixed 32-dimensional embedding that captures statistical properties without encoding domain-specific patterns:

| Dimensions | Features |
|------------|----------|
| 0-3 | Length statistics (normalized length, line count, avg/max line length) |
| 4-7 | Entropy measures (byte entropy, bigram entropy, positional entropy, variance) |
| 8-15 | Character distribution (alpha, digit, special, whitespace, uppercase, etc.) |
| 16-23 | Structural features (nesting depth, repetition, token diversity, delimiters) |
| 24-27 | Encoding indicators (percent-encoding, hex sequences, base64, non-ASCII) |
| 28-31 | Derived composites (entropy×special, length×depth, anomaly score, complexity) |

### Memory Systems

**Reward-Gated Associative Memory (BDH)**:
- Stores traces with embeddings, valences, and Hebbian connection weights
- Update rule: `Δw = η × (pre × post) × reward_signal`
- Learning rate: η = 0.015 (base 0.05 × 0.3 reduction factor)
- Minimum learning rate floor: η_min = 0.001
- Memory management: Max 1000 traces, pruning at 80% utilization

**Persistent Semantic Index (PSI)**:
- Long-term storage with similarity-based retrieval
- Influence propagation to similar entries (cosine > 0.6)
- Cross-service sharing via thread-safe access
- Protected entries resist negative updates

### Score Fusion

```
score = (psi_valence × 0.4) + (bdh_differential × 0.3) + (statistical_baseline × 0.3)
```

Where:
- `psi_valence`: Valence-weighted average from top-k similar PSI entries
- `bdh_differential`: Difference between max threat and max benign similarity
- `statistical_baseline`: `(features[30] × 0.6) + (features[31] × 0.4)`

### Confidence Calibration

- Tracks accuracy of high-confidence predictions (confidence > 0.8)
- Applies penalty coefficient (0.3) when error rate exceeds 20%
- Prevents overconfidence from degrading system reliability

---

## Biological Computing Foundations

### Hebbian Learning Principles

Hebb's foundational work on synaptic plasticity established that connection strengths modify based on co-activation: "neurons that fire together, wire together." BHSM implements this through:

1. **Bidirectional Plasticity**: Synapses strengthen (potentiation) and weaken (depression) based on reward
2. **Eligibility Traces**: Temporal credit assignment for delayed rewards
3. **Memory Consolidation**: Significant experiences promoted to long-term storage
4. **Adaptive Regulation**: EQ/IQ balance prevents overconfidence

### Cognitive Mesh Architecture

BHSM implements a **Cognitive Mesh Neural Network (CMNN)** for distributed reasoning:

- **Distributed Processing**: Multiple nodes process information with different perspectives
- **Message Passing**: Nodes communicate and influence each other's decisions
- **Confidence Assessment**: Each node evaluates its certainty
- **Value Estimation**: Nodes predict utility of different actions

### Memory Systems Integration

1. **PSI (Persistent Semantic Index)**: Long-term declarative memory
2. **BDH (Bidirectional Hebbian Memory)**: Procedural memory for learned patterns

These systems mirror the dual-process theory of human cognition.

---

## Quick Start

### Installation

```bash
pip install torch numpy matplotlib
```

### Basic Usage

```python
from BHSM import BHSMClassifier, TextFeatureExtractor, Action

# Create a classifier
classifier = BHSMClassifier(name="my_classifier")

# Classify input
verdict = classifier.classify("some input to classify", return_details=True)
print(f"Score: {verdict.threat_score:.3f}")
print(f"Action: {verdict.action.name}")  # ALLOW, DETECT, or BLOCK
print(f"Confidence: {verdict.confidence:.3f}")

# Provide feedback for learning
classifier.learn_from_feedback("some input", was_correct=True, true_label="benign")
```

### Custom Feature Extractor

```python
from BHSM import FeatureExtractor, l2_norm
import numpy as np

class MyDomainExtractor(FeatureExtractor):
    """Custom feature extractor for your domain."""
    
    def extract(self, input_data) -> np.ndarray:
        features = np.zeros(32, dtype=np.float32)
        # Populate features based on your domain logic
        # Dims 0-3: Size statistics
        # Dims 4-7: Entropy measures
        # Dims 8-15: Distribution characteristics
        # Dims 16-23: Structural features
        # Dims 24-27: Encoding indicators
        # Dims 28-31: Derived composites
        return l2_norm(features)

# Use custom extractor
classifier = BHSMClassifier(
    feature_extractor=MyDomainExtractor(),
    name="custom_classifier"
)
```

### Configuring Action Thresholds

```python
from BHSM import BHSMClassifier, ActionThresholds

# Security-focused (aggressive blocking)
security_thresholds = ActionThresholds(allow_max=0.2, detect_max=0.4)

# Availability-focused (permissive)
availability_thresholds = ActionThresholds(allow_max=0.4, detect_max=0.7)

classifier = BHSMClassifier(
    action_thresholds=security_thresholds,
    name="security_classifier"
)
```

---

## Command Line Interface

```bash
# Basic component tests
python BHSM.py

# Interactive demonstration (50 events)
python BHSM.py --demo

# Comprehensive learning tests with dashboard generation
python BHSM.py --test 200    # 200-event test
python BHSM.py --test 1000   # 1000-event test

# TinyLLaMA integration demo (requires model download)
python tinyllama_bhsm_integration.py --mode demo

# Interactive chat with memory enhancement
python tinyllama_bhsm_integration.py --mode chat --max-turns 20
```

---

## API Reference

### Core Classes

| Class | Description |
|-------|-------------|
| `BHSMClassifier` | Complete classification pipeline with score fusion |
| `BDHMemory` | Reward-gated associative memory with pruning |
| `PSIIndex` | Persistent semantic index with propagation |
| `TextFeatureExtractor` | General-purpose text feature extraction |
| `FeatureExtractor` | Abstract base class for custom extractors |
| `ConfidenceCalibrator` | Confidence tracking and adjustment |
| `ActionThresholds` | Configurable action selection thresholds |
| `CognitiveMesh` | Distributed reasoning network |
| `SelfModelNode` | Metacognitive monitoring |

### Key Functions

| Function | Description |
|----------|-------------|
| `classifier.classify(input, return_details=False)` | Classify input, return `ClassificationVerdict` |
| `classifier.learn_from_feedback(input, was_correct, true_label)` | Update memory from feedback |
| `bdh.compute_differential_similarity(query)` | Get threat vs benign similarity difference |
| `psi.compute_valence_weighted_average(query, top_k)` | Get weighted valence from similar entries |
| `get_shared_psi()` | Get singleton PSI for cross-instance sharing |

### Data Classes

```python
@dataclass
class ClassificationVerdict:
    threat_score: float      # 0.0 to 1.0
    confidence: float        # 0.0 to 1.0  
    action: Action           # ALLOW, DETECT, or BLOCK
    semantic_class: str      # "benign", "suspicious", or "threat"
    metadata: Optional[Dict] # Detailed scores if return_details=True

class Action(Enum):
    ALLOW = auto()   # score < 0.3
    DETECT = auto()  # 0.3 ≤ score < 0.5
    BLOCK = auto()   # score ≥ 0.5
```

---

## Performance Characteristics

**Classification Latency**: 
- Feature extraction: O(n) in input size
- Memory queries: O(m) in trace count with m ≤ 1000 (bounded)
- Sub-millisecond classification for typical inputs

**Memory Footprint**:
- Each trace: ~200 bytes (32-float embedding + metadata)
- Maximum 1000 traces ≈ 200KB for BDH
- PSI adds similar overhead
- Total memory footprint < 1MB at capacity

---

## Operational Properties

### Experience-Based Learning

BHSM treats operational inputs as potential learning signal:
- Correctly classified inputs reinforce existing patterns
- Misclassifications trigger updates that improve future accuracy
- Learning rate depends on feedback availability and accuracy

### Bounded Output

The constrained action space ensures classification errors produce bounded consequences:
- Worst case: selection of wrong predefined action
- Never: arbitrary system behavior

### Confidence Tracking

Confidence calibration penalizes overconfidence:
- High-confidence errors trigger penalty mode
- Provides automatic uncertainty estimation based on performance

### Shared Learning

Multiple service instances can share a PSI:
- Thread-safe access via `get_shared_psi()`
- High-confidence patterns propagate across instances
- Dampened learning rate (0.5×) prevents single-service dominance

---

## Applications

BHSM is designed as a general-purpose adaptive classification framework. Example domains include:

### Cybersecurity
- Web application threat detection
- Network anomaly detection
- Malware classification
- Intrusion detection systems

### Content Moderation
- Spam detection
- Toxic content classification
- Policy violation detection

### Anomaly Detection
- Log analysis and alerting
- Fraud detection
- Quality control systems

### Conversational AI
- Intent classification
- Response appropriateness filtering
- Context-aware filtering

---

## Limitations and Considerations

### Current Implementation Scope

**Implemented**:
- Reward-Gated Associative Memory (BDH)
- Persistent Semantic Index (PSI)
- Confidence calibration
- Cross-instance learning
- Action constraints
- Memory pruning

**Not Implemented**:
- Federated learning across hosts
- Cryptographic authentication for shared updates
- Cold-start mitigation through pre-trained patterns

### Potential Vulnerabilities

**Adversarial drift**: Sustained access could shift learned patterns through gradual poisoning. Mitigated by:
- Low learning rate (0.015)
- Pruning of low-quality traces
- High-valence protection (|valence| > 0.8)

**Feedback dependency**: Learning quality depends on feedback accuracy. Incorrect feedback degrades performance.

**Cold start**: New deployments rely on statistical baseline until sufficient experience accumulates.

---

## File Structure

```
BHSM/
├── BHSM.py                           # Core BHSM implementation
├── eq_iq_regulator.py                # EQ/IQ balanced reward system
├── tinyllama_bhsm_integration.py     # LLM integration example
└── BHSM_Readme.md                    # This documentation
```

---

## Future Directions

- **Multi-Modal Integration**: Visual, auditory, and other sensory modalities
- **Distributed Learning**: Federated consolidation across organizations
- **Neuromorphic Hardware**: Spike-based processing for efficiency
- **Advanced Memory**: Hierarchical storage with compression

---

## Conclusion

BHSM provides an architecture combining:

1. **Persistent memory** enabling operational experience accumulation
2. **Reward-gated learning** enabling behavioral adaptation from feedback
3. **Constrained action spaces** bounding the consequence of classification errors
4. **Shared memory** enabling cross-instance knowledge aggregation

The architecture addresses a specific deployment scenario: classification applications requiring continuous adaptation where feedback is available and output bounding is valuable.

BHSM is best understood as an engineering integration of established techniques—embedding-based classification, reward-modulated learning, constrained outputs, shared databases—organized around principles motivated by biological memory systems.

---

**© 2025 Shane D. Shook, PhD, All Rights Reserved**

## References

1. Vaswani, A., Shazeer, N., Parmar, N., et al. (2017). "Attention Is All You Need." *NeurIPS*.

2. He, H. and Thinking Machines Lab. (2025). "Defeating Nondeterminism in LLM Inference." Thinking Machines Lab.

3. Hebb, D. O. (1949). *The Organization of Behavior: A Neuropsychological Theory*. Wiley.

4. Kandel, E. R. (2001). "The molecular biology of memory storage." *Science*, 294(5544), 1030-1038.

5. Kosowski, A., et al. (2025). "The Dragon Hatchling: The Missing Link Between the Transformer and Models of the Brain." arXiv:2509.26507.

6. Anthropic. (2025). "Managing context on the Claude Developer Platform." Anthropic News.
