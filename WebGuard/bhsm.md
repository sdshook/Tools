# Bidirectional Hebbian Memory System (BHSM)
## A Neuromorphic Architecture for Adaptive Experience Classification and Community Knowledge Development

**Shane D. Shook, PhD | 2025**

---

## Abstract

The Bidirectional Hebbian Memory System (BHSM) is a neuromorphic architecture for adaptive classification that learns from operational experience and develops shared knowledge across co-located service instances. The architecture combines persistent memory storage, reward-gated learning, and constrained action spaces to address specific deployment scenarios where continuous adaptation is required. This paper describes the BHSM architecture and presents WebGuard, a web server threat classification system, as a proof-of-concept implementation.

---

## 1. Motivation and Problem Context

### 1.1 The Deployment Adaptation Gap

Large language models acquire knowledge through training on static corpora [1]. Post-training techniques including retrieval-augmented generation (RAG), adapter fine-tuning (LoRA), and tool use enable forms of post-deployment adaptation. However, these approaches address knowledge retrieval rather than experiential learning—the system retrieves information but does not modify its behavior based on operational outcomes.

For classification applications in dynamic environments, this creates a gap: the classifier cannot learn from its successes and failures during operation. A threat classifier that misses a novel attack pattern does not improve its detection of similar patterns without explicit retraining or rule updates.

### 1.2 Context and Retrieval Limitations

RAG and vector database approaches effectively extend knowledge access beyond context windows by retrieving relevant information at inference time. These are proven techniques for knowledge augmentation.

However, retrieval addresses a different problem than experiential learning. RAG retrieves static documents; it does not accumulate operational experience or modify retrieval priorities based on classification outcomes. For applications requiring continuous behavioral adaptation, retrieval augmentation is complementary but insufficient.

### 1.3 Inference Variability

Language model inference can exhibit variability across invocations due to several factors: temperature sampling, floating-point non-determinism, and batching effects [2]. At temperature=0, modern LLMs are nearly deterministic, with minor variance from numerical precision.

For classification applications, even minor variability can be problematic when consistent behavior is required. Additionally, systems without rate limiting or session tracking may be vulnerable to retry-based exploitation. While these are partially deployment concerns, an architecture providing deterministic classification given fixed learned state simplifies operational guarantees.

### 1.4 Constrained Action Spaces

A separate concern from learning is execution bounding. In agentic systems, successful manipulation of the classifier can lead to arbitrary downstream actions. Constraining the action space to a defined set of outputs (e.g., {allow, block, flag}) limits the consequence of classification errors regardless of their cause.

This is an application of the principle of least privilege—a well-established security pattern. BHSM implements this at the architectural level, ensuring that classifier outputs map only to predefined actions.

### 1.5 The Semantic-Execution Separation Problem

Traditional computing architectures store code and data in the same memory space, making them indistinguishable at the hardware level. This architectural characteristic underlies virtually all injection attacks: SQL injection (data becomes database instructions), cross-site scripting (data becomes executable code), command injection (data becomes shell commands), and buffer overflows (data becomes machine instructions).

The fundamental challenge for any classification system is determining what input *means* without potentially *executing* it. BHSM addresses this through strict separation between semantic analysis and action execution—analogous to the Harvard architecture's separation of instruction and data memory. The semantic layer analyzes meaning through statistical properties without executing content; only abstract verdicts (not raw input) cross into the execution layer. This ensures that adversarial input cannot bypass the classification pathway to directly influence system actions—the worst case remains selection of an incorrect predefined action, not arbitrary system behavior.

---

## 2. Related Work and Conceptual Motivation

The BHSM architecture draws conceptual motivation from several research directions. The implementation is original and does not incorporate code or architectures from these sources.

### 2.1 Hebbian Learning Principles

Hebb's foundational work on synaptic plasticity [3] established that connection strengths between neurons modify based on co-activation: "neurons that fire together, wire together." Kandel's research on the molecular biology of memory [4] further demonstrated how these synaptic changes are consolidated into long-term storage. These biological principles suggest that memory systems can be self-modifying based on experience patterns.

Research on computational implementations of Hebbian learning, including the Dragon Hatchling architecture [5] exploring bidirectional associative memory and reward-modulated plasticity, motivated the Reward-Gated Associative Memory component of BHSM. The specific implementation is original.

### 2.2 Persistent Memory in Neural Systems

Work on context management and memory persistence in language model deployments [6] motivated the Persistent Semantic Index component. The concept of maintaining semantic memory across sessions, with retrieval based on similarity rather than recency, addresses the session isolation problem.

BHSM's implementation is original, drawing on general principles of semantic indexing and embedding-based retrieval rather than any specific external architecture.

### 2.3 World Models and Reinforcement Learning

World model research demonstrates that internal representations enabling prediction can be learned from experience. Reinforcement learning provides mechanisms for outcome-based behavioral modification.

BHSM combines these concepts: the Persistent Semantic Index accumulates a domain-specific "world model" (a representation of normal vs. anomalous patterns), while reward-gated updates provide the feedback mechanism for behavioral modification. The integration and specific implementation are original.

### 2.4 Memory-Augmented Neural Networks

Research on neural Turing machines and memory-augmented architectures demonstrates that external memory can extend neural network capabilities. BHSM's approach differs in that memory is persistent across sessions and modified during deployment rather than optimized during training. Where memory-augmented networks typically learn read/write controllers during supervised training, BHSM's memory modifications occur through reward-gated updates during operation.

---

## 3. Architecture

### 3.0 Feature Extraction Pipeline

Before classification, inputs are projected into a fixed-dimensional embedding space. For HTTP request analysis, the embedding captures statistical properties without encoding predefined attack patterns:

**Dimensional structure (32 features)**:
- Dimensions 0-3: Length statistics (normalized request length, line count, average/max line length)
- Dimensions 4-7: Entropy measures (byte entropy, bigram entropy, positional entropy, entropy variance)
- Dimensions 8-15: Character distribution (alpha, digit, special, whitespace, uppercase, printable, punctuation, unique character ratios)
- Dimensions 16-23: Structural features (nesting depth, repetition score, token diversity, delimiter density, quote/bracket balance, consecutive special ratio, word length variance)
- Dimensions 24-27: Encoding indicators (percent-encoding density, hex sequence density, base64 likelihood, non-ASCII ratio)
- Dimensions 28-31: Derived composites (entropy×special interaction, length×depth interaction, structural anomaly score, statistical complexity)

**Design rationale**: 32 dimensions is deliberately constrained to force the system to learn discriminative patterns from statistical features rather than memorizing specific payloads. The features are purely statistical—no pattern matching for known attack strings. This means the "world model" emerges from learning which statistical profiles correlate with threat/benign outcomes, not from predefined signatures.

BHSM organizes into three layers with a strict semantic-execution boundary:

```
                              Raw Input
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    SYNAPTIC LAYER                            │
│    Reward-Gated Associative Memory + Persistent Semantic Index│
│    (Analyzes meaning through statistical properties)         │
├─────────────────────────────────────────────────────────────┤
│                    COGNITIVE LAYER                           │
│    Classification logic, confidence calibration, monitoring  │
│    (Produces abstract verdict: score + confidence + class)   │
╞═════════════════════════════════════════════════════════════╡
│              SEMANTIC-EXECUTION BOUNDARY                     │
│         (Only verdicts cross—never raw input)                │
╞═════════════════════════════════════════════════════════════╡
│                    MECHANICAL LAYER                          │
│         Constrained action space (output bounding)           │
│    (Acts on verdicts, cannot access raw input)               │
└─────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                        Predefined Action Set
```

### 3.1 Synaptic Layer

The foundation implements persistent memory with experience-based modification. The component names (BDH, PSI) are internal to BHSM and do not reference external systems.

**Reward-Gated Associative Memory (BDH)** stores traces with embeddings, classification labels (valence), and connection weights. The update rule implements reward-modulated Hebbian learning:

```
Δw = η × (pre_activation × post_activation) × reward_signal
```

Where:
- `pre_activation` and `post_activation` are cosine similarities between the input embedding and stored trace embeddings (range: 0.0 to 1.0)
- `reward_signal` is +1.0 for correct classifications, -1.0 for misclassifications, scaled by confidence
- `η` (learning rate) is 0.015 for weight updates (base rate 0.05 × 0.3 reduction factor to prevent over-fitting)
- `η_min` (minimum learning rate) is 0.001, preventing complete learning shutdown even when confidence is heavily penalized

**Stability note on confidence scaling**: Scaling rewards by confidence creates two potential regimes: (1) a high-confidence attractor where established patterns become increasingly resistant to update, and (2) a low-confidence trap where degraded confidence suppresses learning. The architecture addresses this through multiple mechanisms: high-valence traces (|valence| > 0.8) receive reduced update magnitude regardless of confidence, preventing runaway reinforcement; the confidence penalty mechanism (Section 3.2) is multiplicative rather than additive, ensuring that even penalized confidence still permits learning; and the minimum learning rate floor (0.001) prevents complete learning shutdown. In practice, the system tends toward the high-confidence attractor for well-established patterns—which is desirable for security, as it makes confirmed threat patterns resistant to adversarial drift.

Positive classification outcomes strengthen connections between co-activated patterns; negative outcomes weaken them. This enables the system to modify its similarity judgments based on operational feedback.

**Role of inter-trace Hebbian connections**: The connections between stored traces primarily influence *learning* rather than *classification*. During classification, the BDH query finds similar traces independently (as shown in the appendix walkthrough). The inter-trace connections become active during learning: when a new pattern is stored, the Hebbian update strengthens connections to traces that were co-activated (high similarity) with the same valence, creating associative clusters. Over time, this biases the stored trace population toward coherent threat/benign clusters rather than randomly distributed points—which improves the discriminative power of the differential similarity metric used in classification. The connections do not directly modulate retrieval weights; they shape the learned representation by influencing which traces persist and how their valences evolve.

**Persistent Semantic Index (PSI)** provides long-term storage with similarity-based retrieval. Entries persist across sessions. When novel patterns are stored, influence propagates to existing memories with cosine similarity above 0.6, with update magnitude proportional to similarity × reward signal. This enables adaptation to new inputs without requiring exact matches.

**BDH/PSI Interaction During Classification**:

When classifying an input, the system queries both memory components and fuses their outputs:

1. **BDH query**: Compute differential threat similarity—the difference between maximum similarity to threat-labeled traces versus benign-labeled traces. This provides a learned discriminative signal.

2. **PSI query**: Retrieve top-k similar entries and compute valence-weighted average. This provides historical context from consolidated long-term memory.

3. **Fusion**: The final threat score combines both signals:
   ```
   score = (psi_valence × 0.4) + (bdh_differential × 0.3) + (statistical_baseline × 0.3)
   ```
   
   Where `statistical_baseline` is derived from the raw embedding features—specifically, a weighted combination of dimensions 30 (structural_anomaly_score) and 31 (statistical_complexity), computed as `(features[30] × 0.6 + features[31] × 0.4)`. This provides a heuristic fallback when memory is sparse and ensures the system can make reasonable classifications even before significant learning has occurred.

The 0.4/0.3/0.3 weighting prioritizes PSI (consolidated experience) while incorporating BDH (recent learning) and statistical features (cold-start fallback).

**Memory Management**:

Memory growth is bounded. BDH enforces a maximum of 1000 traces. When utilization exceeds 80%, low-quality traces are pruned based on |valence| × use_count. Weak Hebbian connections (weight < 0.01) are also pruned. This prevents unbounded growth while preserving high-confidence learned patterns.

**Pruning tradeoff**: This criterion favors frequently-seen, high-confidence patterns, which means rare-but-important patterns (e.g., a novel attack seen once with moderate confidence) are vulnerable to pruning. The cross-service PSI propagation partially mitigates this—patterns exceeding the cross-service threshold are replicated to the shared PSI before BDH pruning can remove them. Additionally, the confidence penalty mechanism slows learning rate for low-confidence traces, giving them more time to accumulate evidence before pruning.

### 3.2 Cognitive Layer

The cognitive layer implements classification and monitoring:

**Classification** queries memory systems, retrieves similar patterns, and computes scores from stored valences weighted by similarity.

**Confidence calibration** tracks prediction accuracy and adjusts confidence scores when high-confidence predictions produce poor outcomes. This is implemented as a penalty coefficient (0.3) applied to confidence scores when the error rate among predictions with confidence > 0.8 exceeds 20%.

**Monitoring** tracks coherence metrics and error rates to detect degradation.

**Shared learning** enables multiple service instances on the same host to contribute to a common PSI through a mesh architecture:

- Services share access to a thread-safe PSI via `Arc<Mutex<PsiIndex>>`
- When a service learns a high-confidence pattern (|valence| > cross_service_threshold), it propagates to the shared PSI with dampened learning rate (mesh_learning_rate × 0.5)
- Conflict resolution: later writes overwrite earlier ones; dampened learning rates prevent single-service dominance
- Updates are asynchronous—services don't block waiting for propagation

### 3.3 Mechanical Layer

The mechanical layer enforces output constraints and implements the semantic-execution boundary described in Section 1.5:

**Semantic-execution boundary**: The only data crossing from cognitive to mechanical layers is an abstract verdict structure containing threat score, confidence level, and semantic classification. Raw input never reaches the execution layer—the mechanical layer acts on verdicts, not content. This architectural constraint ensures that adversarial input cannot influence system actions except through the classification pathway.

**Constrained action set**: Regardless of cognitive layer computation, system output is restricted to a predefined action set. For the WebGuard implementation, this is {Detect, Allow, Block}. No pathway exists from input to arbitrary output—only to defined actions.

**Action thresholds** (configurable per deployment):
- score < 0.3 → **Allow** (low threat, permit request)
- 0.3 ≤ score < 0.5 → **Detect** (moderate threat, log and permit for analysis)
- score ≥ 0.5 → **Block** (high threat, deny request)

The 0.5 Block threshold reflects a security-first bias: the system errs toward blocking when uncertain. In deployments where availability is critical, this threshold can be raised (e.g., 0.7) at the cost of increased false negatives. The 0.3 Detect threshold ensures that even low-confidence anomalies are logged for retrospective analysis.

This bounds the consequence of any classification error: the worst case is selection of the wrong predefined action, not arbitrary system behavior.

---

## 4. Domain-Specific Application

BHSM constructs classification models through exposure rather than explicit programming:

**Embedding space**: Inputs are projected into a fixed-dimensional embedding space capturing features relevant to the domain.

**Valence accumulation**: Each memory trace carries a valence (classification label). As the system observes outcomes, valences update through reward signals. The distribution of valences across memory constitutes the learned classification model.

**Associative structure**: Connections between traces encode co-occurrence patterns, enabling generalization from observed examples to similar novel inputs.

The model improves as the system accumulates experience, with classification accuracy dependent on the quality and quantity of feedback received.

---

## 5. Operational Properties

### 5.1 Experience-Based Learning

BHSM treats operational inputs as potential learning signal. Correctly classified inputs reinforce existing patterns. Misclassifications, when identified through feedback, trigger updates that improve future accuracy.

The rate and quality of improvement depends on feedback availability and accuracy. Without feedback, the system does not learn.

### 5.2 Bounded Output

The constrained action space ensures that classification errors produce bounded consequences. This is the principle of least privilege applied at the architectural level.

### 5.3 Confidence Tracking

The confidence calibration mechanism penalizes overconfidence when high-confidence predictions produce errors. This provides a form of automatic uncertainty estimation based on observed performance.

---

## 6. Proof of Concept: WebGuard

WebGuard implements BHSM for web server threat classification.

### 6.1 Domain Characteristics

Web server security provides a suitable initial domain because:

- HTTP request structure provides natural feature extraction boundaries
- Attack categories (injection, traversal, etc.) have distinguishable statistical signatures  
- Operational feedback is available through incident response outcomes

**Self-learning design intent**: The architecture is designed for autonomous operation without human-in-the-loop (HOTL) intervention. The rationale is operational: security systems that require analyst labeling for every decision cannot operate at machine speed, and human feedback introduces latency that attackers can exploit. The goal is a system where behavioral adaptation emerges from accumulated operational experience rather than manual curation.

**Feedback mechanisms** (design intent, partially implemented):

- *Outcome heuristics*: Blocked requests with no subsequent complaint → likely correct; allowed requests followed by incident → likely incorrect. **Caveat**: These signals are noisy—users rarely complain about silently dropped requests (false positives go undetected), and "incident detection" requires external capability not provided by BHSM itself.
- *Retrospective correlation*: Batch analysis of historical logs against later-confirmed incidents. **Status**: Design intent; requires integration with external incident tracking.

**Current implementation**: The WebGuard proof-of-concept supports feedback injection via API but does not yet automate feedback collection. The evaluation results (Section 6.3) use explicit labeled feedback, not the heuristic mechanisms described above. Practical deployment would require integration with incident response workflows to close the feedback loop.

**Feedback quality dependency**: Learning quality is directly constrained by feedback reliability. The heuristics above have known failure modes, and their noise characteristics would need measurement in production deployments before strong claims about autonomous learning can be supported.

### 6.2 Implementation

WebGuard implements all three BHSM layers:

| Layer | Implementation |
|-------|----------------|
| Synaptic | Reward-Gated Associative Memory (32-dim embeddings), Persistent Semantic Index |
| Cognitive | Threat scoring, confidence calibration (penalty coefficient 0.3), cross-service learning |
| Mechanical | 3-action constraint: {Detect, Allow, Block} |

### 6.3 Preliminary Evaluation

Initial testing used synthetic traffic with labeled samples (68 attack patterns, 70 benign patterns per pass). Results across training passes:

| Pass | False Negative Rate | Overall Accuracy |
|------|---------------------|------------------|
| 0 (cold start) | 58.8% | 61.6% |
| 1 | 2.9% | 77.5% |
| 2 | 0% | 98.6% |
| 6+ | 0% | 100% |

**Important caveats**: 

- This is a small dataset (138 samples) without held-out test data
- The system is learning the specific patterns in the evaluation set
- No comparison to baseline classifiers (rule-based, random forest, etc.) was performed
- No adversarial evasion testing was conducted
- 100% accuracy on training data demonstrates memorization, not necessarily generalization

**Cross-format testing**: Training on nginx log format and testing on Apache/IIS/Node.js formats achieved consistent threat recall, suggesting the statistical features generalize across format variations. However, this may reflect shared attack signatures (SQL keywords, path traversal sequences) rather than deep generalization.

### 6.4 Demonstrated Properties

The proof-of-concept demonstrates:

1. Persistent memory spanning operational history
2. Consistent classification given fixed learned state
3. Accuracy improvement through feedback
4. Output constrained to three defined actions
5. Shared learning across service instances

These demonstrations are preliminary. Rigorous evaluation would require larger datasets, held-out test sets, baseline comparisons, and adversarial testing.

---

## 7. Limitations and Future Work

### 7.1 Current Implementation Scope

The WebGuard proof-of-concept implements core BHSM components:

**Implemented**: Reward-Gated Associative Memory, Persistent Semantic Index, confidence calibration, cross-instance learning, action constraints, **ThreatEducator** (pedagogical knowledge transfer).

**Not implemented**: Federated learning across hosts, cryptographic authentication for shared updates.

**Cold-start mitigation**: The ThreatEducator module provides structured knowledge transfer to PSI, enabling pre-deployment threat awareness without operational experience. Curricula define threat categories declaratively (feature profiles, signature patterns, generative templates) and the educator synthesizes examples that are injected via one-shot learning with proper Hebbian connections. This addresses the cold-start vulnerability by pre-warming PSI with threat knowledge before the first real request.

### 7.2 Evaluation Gaps

The current evaluation is insufficient to support strong claims:

- Dataset is too small (138 samples)
- No held-out test set for generalization measurement
- No baseline comparisons
- No adversarial testing
- "100% accuracy" reflects learning the evaluation set, not proven generalization

Future work should address these gaps with larger-scale evaluation against standard benchmarks and baseline systems.

### 7.3 Potential Vulnerabilities

**Adversarial drift**: An attacker with sustained access could potentially shift learned patterns through gradual poisoning. The low learning rate (0.015) and pruning of low-quality traces provide partial mitigation—an attacker would need sustained high-confidence poisoning to shift consolidated patterns. High-valence traces (|valence| > 0.8) receive reduced update magnitude, protecting well-established classifications.

**Feedback dependency**: Learning quality depends on feedback accuracy. Incorrect feedback degrades performance.

**Cold start**: New deployments have no learned patterns and rely on initial feature statistics until sufficient experience accumulates. This vulnerability is mitigated by the **ThreatEducator** module (Section 7.1), which pre-warms PSI with threat curricula before deployment.

### 7.4 Performance Characteristics

**Classification latency**: Feature extraction is O(n) in request size. Memory queries are O(m) in trace count with m ≤ 1000 (bounded). Empirically, classification completes in sub-millisecond time for typical HTTP requests on commodity hardware. Latency scales linearly with memory utilization, not request volume.

**Memory footprint**: Each trace stores a 32-float embedding plus metadata (~200 bytes). Maximum 1000 traces ≈ 200KB for BDH. PSI adds similar overhead. Total memory footprint remains under 1MB even at capacity.

---

## 8. Conclusion

BHSM provides an architecture combining:

1. Persistent memory enabling operational experience accumulation
2. Reward-gated learning enabling behavioral adaptation from feedback
3. Constrained action spaces bounding the consequence of classification errors
4. Shared memory enabling cross-instance knowledge aggregation

The architecture addresses a specific deployment scenario: classification applications requiring continuous adaptation where feedback is available and output bounding is valuable.

The WebGuard proof-of-concept demonstrates these properties in web server threat classification. The preliminary results are encouraging but insufficient for strong generalization claims. Rigorous evaluation against larger datasets, held-out test sets, and baseline systems is required to establish practical effectiveness.

BHSM is best understood as an engineering integration of established techniques—embedding-based classification, reward-modulated learning, constrained outputs, shared databases—organized around principles motivated by biological memory systems. The contribution is the specific integration and its application to adaptive classification, not novel individual components.

---

## References

1. Vaswani, A., Shazeer, N., Parmar, N., Uszkoreit, J., Jones, L., Gomez, A. N., Kaiser, Ł., and Polosukhin, I. (2017). Attention Is All You Need. *Advances in Neural Information Processing Systems (NIPS)*.

2. He, H. and Thinking Machines Lab. (2025). Defeating Nondeterminism in LLM Inference. Thinking Machines Lab: Connectionism. https://thinkingmachines.ai/blog/defeating-nondeterminism-in-llm-inference/

3. Hebb, D. O. (1949). *The Organization of Behavior: A Neuropsychological Theory*. John Wiley & Sons.

4. Kandel, E. R. (2001). The molecular biology of memory storage: a dialogue between genes and synapses. *Science*, Vol. 294, Issue 5544, pp. 1030-1038.

5. Kosowski, A., Uznański, P., Chorowski, J., Stamirowska, Z., & Bartoszkiewicz, M. (2025). The Dragon Hatchling: The Missing Link Between the Transformer and Models of the Brain. arXiv:2509.26507. https://arxiv.org/pdf/2509.26507

6. Anthropic. (2025). Managing context on the Claude Developer Platform. Anthropic News, September 29, 2025. https://www.anthropic.com/news/context-management

---

## Appendix: Classification Example Walkthrough

To illustrate how the components interact, consider classification of an HTTP request containing a SQL injection attempt. *Note: Embedding values below are approximate for illustration purposes, computed to be representative of the feature extraction logic rather than exact system outputs.*

**Input**: `GET /users?id=1' OR '1'='1`

**Step 1: Feature Extraction** (32-dim embedding)
```
[0.02,   # length: 25 chars / 2000 = 0.0125 → normalized
 0.02,   # line_count: 1 line
 0.78,   # avg_line_length: high for single line
 0.78,   # max_line_length: same as avg
 0.61,   # entropy: moderate (repeated characters reduce it)
 0.58,   # bigram_entropy: some repeated bigrams ('1'=)
 0.45,   # positional_entropy: clustered special chars
 0.22,   # entropy_variance: low variance
 0.48,   # alpha_ratio: letters present
 0.12,   # digit_ratio: "1" appears multiple times
 0.28,   # special_ratio: elevated (quotes, equals, apostrophe)
 0.04,   # whitespace_ratio: minimal
 0.16,   # uppercase_ratio: GET, OR
 0.96,   # printable_ratio: all printable
 0.20,   # punctuation_ratio: elevated
 0.64,   # unique_char_ratio: repeated chars reduce this
 0.0,    # nesting_depth: no nested structures
 0.35,   # repetition_score: '1' and '=' repeated
 0.45,   # token_diversity: limited token vocabulary
 0.12,   # delimiter_density: few delimiters
 0.0,    # quote_balance: unbalanced quotes
 0.0,    # bracket_balance: no brackets
 0.40,   # consecutive_special: '='1' sequence
 0.33,   # word_length_variance: mixed lengths
 0.08,   # percent_encoding: none
 0.0,    # hex_sequences: none
 0.0,    # base64_likelihood: not base64
 0.0,    # non_ascii: all ASCII
 0.17,   # entropy × special interaction
 0.0,    # length × depth interaction
 0.42,   # structural_anomaly: moderate
 0.38]   # statistical_complexity: moderate
```

**Step 2: BDH Query**
- Find most similar threat trace: similarity = 0.89 (previous SQL injection)
- Find most similar benign trace: similarity = 0.34 (normal query string)
- Differential = 0.89 - 0.34 = 0.55 (threat-leaning)

**Step 3: PSI Query**
- Top-3 similar entries: valences [0.92, 0.88, 0.71]
- Weighted average valence = 0.84 (high threat)

**Step 4: Score Fusion**
```
statistical_baseline = (0.42 × 0.6) + (0.38 × 0.4) = 0.252 + 0.152 = 0.404

score = (0.84 × 0.4) + (0.55 × 0.3) + (0.404 × 0.3)
      = 0.336 + 0.165 + 0.121
      = 0.622
```

**Step 5: Action Selection**
- Score 0.622 > block_threshold (0.5) → **Block**

**Step 6: Learning (if feedback confirms)**
- Add trace to BDH with valence = 0.8
- Strengthen Hebbian connections to similar threat patterns
- Propagate to shared PSI if |valence| > cross_service_threshold

---

*© 2025 Shane D. Shook, PhD. All Rights Reserved.*
