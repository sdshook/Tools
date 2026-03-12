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
- `bdh_differential`: Difference between max threat and max benign similarity (enhanced with Hebbian consensus)
- `statistical_baseline`: `(features[30] × 0.6) + (features[31] × 0.4)`

### Hebbian Consensus Inference

In addition to distance-based similarity, BHSM computes a **Hebbian consensus signal** that actively uses learned weight matrices during classification:

```
hebbian_signal = Σ (activation_i × valence_i × weight_i) / Σ weight_i
```

Where each trace votes based on its Hebbian weight activation, with voting weight determined by:
- **Learning amount**: How many times the trace has been reinforced (uses)
- **Similarity**: Cosine similarity between query and trace
- **Valence strength**: Confidence of the trace's classification

This ensures Hebbian weights actively participate in inference decisions, not just learning—a critical distinction from systems that train associative weights but never use them.

### Confidence Calibration

- Tracks accuracy of high-confidence predictions (confidence > 0.8)
- Applies penalty coefficient (0.3) when error rate exceeds 20%
- Prevents overconfidence from degrading system reliability

---

## Temporal Reasoning: Beyond LLM Context Windows

### The Context Window Problem

Large Language Models operate within fixed context windows (8K-200K tokens). For classification applications where patterns unfold over extended periods, this creates fundamental limitations:

- Early warning signs fall out of context before patterns complete
- No memory of prior sessions without external augmentation
- Attention cost scales O(n²) with sequence length
- Learning is frozen at inference time

### BHSM's Unbounded Temporal Memory

BHSM provides **true temporal reasoning without context constraints** through persistent trace transitions and sequence modeling:

```
Trace Sequence Memory:
├── trace_A (event 1)    ──► stored in BDH (persists indefinitely)
│     │
│     └──► transition(A→B) weight: 0.3
│
├── trace_B (event 2)    ──► stored in BDH  
│     │
│     └──► transition(B→C) weight: 0.5
│
├── trace_C (event 3)    ──► stored in BDH
│
└── compute_sequence_escalation() 
    └── "Escalating pattern detected across extended timeframe"
```

### Temporal Modeling Components

**Trace Transitions**: Records sequences of behavioral patterns as a directed graph:
```python
TraceTransition:
    from_trace: str      # Source trace ID
    to_trace: str        # Target trace ID  
    weight: float        # Normalized transition probability
    timestamp: float     # When transition occurred
```

Transitions accumulate with reinforcement: `weight = weight × decay + increment`

**Temporal Context**: Recent patterns contribute time-weighted context:
```
temporal_context = Σ (valence_i × time_weight_i × similarity_i) / Σ weight_i
```
Where `time_weight = decay^(time_elapsed)` provides graceful decay rather than hard cutoffs.

**Escalation Detection**: Identifies increasing threat trends via slope analysis:
```
escalation = linear_regression_slope(recent_valences)
```
Positive escalation indicates a pattern of increasing threat—useful for detecting multi-stage progressions.

**Behavioral Prediction**: Predicts likely next patterns given current state:
```python
predict_next_traces(current_trace_id, top_k) → [(trace_id, probability), ...]
```

### Architectural Comparison: BHSM vs LLM

| Aspect | LLM Context Window | BHSM Temporal Memory |
|--------|-------------------|----------------------|
| **Temporal horizon** | Fixed (tokens) | Unbounded (persistent) |
| **Old patterns** | Forgotten at window edge | Compressed into Hebbian weights |
| **Sequence cost** | O(n²) attention | O(k) transition lookup |
| **Cross-session** | Requires external memory | Native (PSI persists) |
| **Learning** | Frozen at inference | Continuous online |
| **Forgetting** | Hard cutoff | Graceful decay with reinforcement |

### Complementary Detection Mechanisms

BHSM's temporal escalation detection (linear regression on valence trends) complements rather than competes with spatial anomaly detection (e.g., Isolation Forest):

| Mechanism | Question Answered | Data Scope |
|-----------|------------------|------------|
| **Spatial Anomaly** | "Is this point structurally unusual?" | Single feature vector |
| **Temporal Escalation** | "Is threat level trending upward?" | Sequence of valences |

These mechanisms cover orthogonal dimensions:
- Spatial anomaly detects novel/unusual individual events
- Temporal escalation detects multi-stage patterns that may individually appear benign

Together, they provide defense-in-depth across both feature space and time.

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

# Threat Education (pre-warm PSI with threat knowledge)
python BHSM.py --educate                        # Use built-in curricula
python BHSM.py --educate --test 200             # Educate then test
python BHSM.py --curriculum custom.json         # Load custom curricula
python BHSM.py --no-builtin --curriculum my.json  # Custom curricula only

# TinyLLaMA integration demo (requires model download)
python tinyllama_bhsm_integration.py --mode demo

# Interactive chat with memory enhancement
python tinyllama_bhsm_integration.py --mode chat --max-turns 20
```

### Threat Educator CLI Options

| Option | Description |
|--------|-------------|
| `--educate` | Enable threat education with built-in curricula |
| `--curriculum <PATH>` | Load custom curriculum from JSON file (repeatable) |
| `--no-builtin` | Disable built-in curricula (only use custom) |
| `--examples-per-curriculum <N>` | Examples to generate per curriculum (default: 10) |

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

## Threat Educator Module

BHSM includes a **ThreatEducator** module that enables structured, pedagogical knowledge transfer to PSI without requiring operational experience. This complements the existing learning pathways:

| Pathway | Source | Learning Type | Speed |
|---------|--------|---------------|-------|
| **Zero-shot** | Environment/Logs | Passive statistical | Slow (needs volume) |
| **One-shot** | Individual examples | Experiential | Medium (per-example) |
| **Educator** | Curriculum definitions | Pedagogical | Fast (batch injection) |

### How It Works

The ThreatEducator accepts **curriculum definitions** that describe threat categories declaratively:

```python
@dataclass
class ThreatCurriculum:
    name: str                           # e.g., "SQL Injection"
    category: ThreatCategory            # Taxonomy classification
    severity: Severity                  # low, medium, high, critical
    feature_profile: FeatureProfile     # Statistical characteristics
    signature_patterns: List[SignaturePattern]  # Characteristic n-grams
    templates: List[str]                # Generative templates
    mutations: List[MutationRule]       # Variation rules
```

### Example Curriculum (JSON)

```json
{
  "name": "SQL Injection - Boolean Based",
  "category": "INJECTION",
  "severity": "CRITICAL",
  "feature_profile": {
    "entropy_range": [0.55, 0.75],
    "special_char_ratio": [0.15, 0.35]
  },
  "signature_patterns": [
    { "pattern": "' OR", "weight": 0.9 },
    { "pattern": "1=1", "weight": 0.85 }
  ],
  "templates": [
    "' OR '1'='1",
    "' UNION SELECT * FROM {table}--"
  ],
  "mutations": [
    { "type": "case", "targets": ["OR", "SELECT", "UNION"] },
    { "type": "encoding", "variants": ["url", "unicode"] }
  ]
}
```

### Education Process

1. **Synthetic Generation**: Templates and mutations generate realistic variations
2. **Feature Extraction**: Each example is converted to a 32-dimensional embedding
3. **PSI Injection**: Entries are added with proper valence and Hebbian connections
4. **Prototype Creation**: A semantic "anchor" entry represents the category

### CLI Usage

```bash
# Enable threat education with built-in curricula
python BHSM.py --educate

# Educate then run learning test
python BHSM.py --educate --test 200

# Use custom curriculum files (can be repeated)
python BHSM.py --curriculum /path/to/custom_threats.json

# Disable built-in curricula, use only custom
python BHSM.py --no-builtin --curriculum /path/to/my_threats.json

# Generate more examples per curriculum
python BHSM.py --educate --examples-per-curriculum 25
```

**Startup Output:**
```
╔═══════════════════════════════════════════════════════════════════╗
║           THREAT EDUCATOR - Pre-warming PSI                       ║
╚═══════════════════════════════════════════════════════════════════╝

Loading built-in threat curricula...
  ✓ SQL Injection - 11 entries, prototype: yes
  ✓ Cross-Site Scripting (XSS) - 11 entries, prototype: yes
  ✓ Path Traversal - 11 entries, prototype: yes
  ✓ Command Injection - 11 entries, prototype: yes

╔═══════════════════════════════════════════════════════════════════╗
║  Threat Education Complete                                        ║
║  Curricula taught:   4                                           ║
║  PSI entries created:   44                                        ║
║  PSI total entries:    44                                         ║
╚═══════════════════════════════════════════════════════════════════╝
```

### Programmatic Usage

```python
from threat_educator import ThreatEducator, ThreatCurriculum
from BHSM import get_shared_psi

# Create educator and get shared PSI
educator = ThreatEducator(examples_per_curriculum=10)
psi = get_shared_psi()

# Teach built-in curricula
results = educator.teach_builtin(psi)
for result in results:
    print(f"Taught {result.curriculum_name}: {result.entries_created} entries")

# Or load and teach custom curricula
custom_curricula = ThreatEducator.load_curricula_from_file("my_threats.json")
educator.teach_all(custom_curricula, psi)
```

### Built-in Curricula

BHSM includes pre-defined curricula for common attack categories:
- **SQL Injection** (boolean, union, time-based patterns)
- **Cross-Site Scripting** (reflected, stored, DOM variants)
- **Path Traversal** (LFI, RFI, encoding bypass)
- **Command Injection** (shell metacharacters, command chaining)

### Design Philosophy

The educator maintains the **"learned, not coded"** principle by:
- Injecting learnable content (not detection rules)
- Using existing PSI infrastructure for storage
- Creating Hebbian associations that evolve with experience
- Generating traceable knowledge (tagged as `"educated"`)

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
- **ThreatEducator** (pedagogical knowledge transfer for cold-start mitigation)

**Not Implemented**:
- Federated learning across hosts
- Cryptographic authentication for shared updates

### Potential Vulnerabilities

**Adversarial drift**: Sustained access could shift learned patterns through gradual poisoning. Mitigated by:
- Low learning rate (0.015)
- Pruning of low-quality traces
- High-valence protection (|valence| > 0.8)

**Feedback dependency**: Learning quality depends on feedback accuracy. Incorrect feedback degrades performance.

**Cold start**: New deployments have no learned patterns and rely on statistical baseline until sufficient experience accumulates. **Mitigated by the ThreatEducator module**, which pre-warms PSI with threat curricula before deployment (see Threat Educator section below).

---

## File Structure

```
BHSM/
├── BHSM.py                           # Core BHSM implementation
├── threat_educator.py                # Pedagogical knowledge transfer module
├── eq_iq_regulator.py                # EQ/IQ balanced reward system
├── tinyllama_bhsm_integration.py     # LLM integration example
├── test_threat_educator.py           # ThreatEducator unit tests
├── BHSM_Readme.md                    # This documentation
├── examples/                         # Curriculum examples for different domains
│   ├── custom_curriculum_template.json  # Template with documentation
│   ├── web_security.json             # Web application security threats
│   ├── log_analysis.json             # Log-based threat detection
│   ├── network_ids.json              # Network intrusion detection
│   ├── fraud_detection.json          # Financial fraud patterns
│   └── content_moderation.json       # Content moderation threats
└── test/                             # Test outputs and visualizations
```

### Example Curricula

BHSM provides domain-specific curriculum examples for different use cases:

| File | Domain | Curricula Count | Description |
|------|--------|-----------------|-------------|
| `custom_curriculum_template.json` | - | 1 (template) | Documented template showing all fields |
| `web_security.json` | Web Apps | 5 | SQLi, XSS, SSRF, XXE |
| `log_analysis.json` | SIEM/Logs | 5 | Log injection, privilege escalation, brute force |
| `network_ids.json` | Network | 6 | Port scanning, C2, DNS tunneling, DDoS, lateral movement |
| `fraud_detection.json` | Financial | 5 | Account takeover, payment fraud, money laundering |
| `content_moderation.json` | Social/Content | 6 | Spam, phishing, harassment, misinformation |

**Usage:**
```bash
# Load domain-specific curricula
python BHSM.py --curriculum examples/web_security.json
python BHSM.py --curriculum examples/network_ids.json

# Combine multiple domains
python BHSM.py --curriculum examples/web_security.json \
               --curriculum examples/log_analysis.json
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
3. **Hebbian consensus inference** using learned weights actively during classification
4. **Temporal sequence modeling** detecting patterns across unlimited time horizons
5. **Constrained action spaces** bounding the consequence of classification errors
6. **Shared memory** enabling cross-instance knowledge aggregation

The architecture addresses a specific deployment scenario: classification applications requiring continuous adaptation where feedback is available and output bounding is valuable. Unlike LLM-based approaches constrained by fixed context windows, BHSM provides **true neuromorphic temporal reasoning**—patterns persist indefinitely, enabling detection of multi-stage progressions that unfold over hours, days, or weeks.

BHSM is best understood as an engineering integration of established techniques—embedding-based classification, reward-modulated learning, Hebbian associative memory, temporal sequence modeling, constrained outputs, shared databases—organized around principles motivated by biological memory systems.

---

**© 2025 Shane D. Shook, PhD, All Rights Reserved**

## References

1. Vaswani, A., Shazeer, N., Parmar, N., et al. (2017). "Attention Is All You Need." *NeurIPS*.

2. He, H. and Thinking Machines Lab. (2025). "Defeating Nondeterminism in LLM Inference." Thinking Machines Lab.

3. Hebb, D. O. (1949). *The Organization of Behavior: A Neuropsychological Theory*. Wiley.

4. Kandel, E. R. (2001). "The molecular biology of memory storage." *Science*, 294(5544), 1030-1038.

5. Kosowski, A., et al. (2025). "The Dragon Hatchling: The Missing Link Between the Transformer and Models of the Brain." arXiv:2509.26507.

6. Anthropic. (2025). "Managing context on the Claude Developer Platform." Anthropic News.
