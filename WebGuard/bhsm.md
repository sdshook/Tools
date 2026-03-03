# Bidirectional Hebbian Memory System (BHSM)
## A Neuromorphic Architecture for Adaptive Experience Classification and Community Knowledge Development

**Shane D. Shook, PhD | 2025**

---

## Abstract

The Bidirectional Hebbian Memory System (BHSM) is a neuromorphic architecture for adaptive classification that learns from operational experience and develops shared knowledge across co-located service instances. The architecture combines persistent memory storage, reward-gated learning, and constrained action spaces to address specific deployment scenarios where continuous adaptation is required. This paper describes the BHSM architecture and presents WebGuard, a web server threat classification system, as a proof-of-concept implementation.

---

## 1. Motivation and Problem Context

### 1.1 The Deployment Adaptation Gap

Large language models acquire knowledge through training on static corpora [4]. Post-training techniques including retrieval-augmented generation (RAG), adapter fine-tuning (LoRA), and tool use enable forms of post-deployment adaptation. However, these approaches address knowledge retrieval rather than experiential learning—the system retrieves information but does not modify its behavior based on operational outcomes.

For classification applications in dynamic environments, this creates a gap: the classifier cannot learn from its successes and failures during operation. A threat classifier that misses a novel attack pattern does not improve its detection of similar patterns without explicit retraining or rule updates.

### 1.2 Context and Retrieval Limitations

RAG and vector database approaches effectively extend knowledge access beyond context windows by retrieving relevant information at inference time. These are proven techniques for knowledge augmentation.

However, retrieval addresses a different problem than experiential learning. RAG retrieves static documents; it does not accumulate operational experience or modify retrieval priorities based on classification outcomes. For applications requiring continuous behavioral adaptation, retrieval augmentation is complementary but insufficient.

### 1.3 Inference Variability

Language model inference can exhibit variability across invocations due to several factors: temperature sampling, floating-point non-determinism, and batching effects. At temperature=0, modern LLMs are nearly deterministic, with minor variance from numerical precision.

For classification applications, even minor variability can be problematic when consistent behavior is required. Additionally, systems without rate limiting or session tracking may be vulnerable to retry-based exploitation. While these are partially deployment concerns, an architecture providing deterministic classification given fixed learned state simplifies operational guarantees.

### 1.4 Constrained Action Spaces

A separate concern from learning is execution bounding. In agentic systems, successful manipulation of the classifier can lead to arbitrary downstream actions. Constraining the action space to a defined set of outputs (e.g., {allow, block, flag}) limits the consequence of classification errors regardless of their cause.

This is an application of the principle of least privilege—a well-established security pattern. BHSM implements this at the architectural level, ensuring that classifier outputs map only to predefined actions.

---

## 2. Related Work and Conceptual Motivation

The BHSM architecture draws conceptual motivation from several research directions. The implementation is original and does not incorporate code or architectures from these sources.

### 2.1 Hebbian Learning Principles

Hebb's foundational work on synaptic plasticity [1] established that connection strengths between neurons modify based on co-activation: "neurons that fire together, wire together." This principle suggests that memory systems can be self-modifying based on experience patterns.

Research on computational implementations of Hebbian learning, including work on bidirectional associative memory and reward-modulated plasticity, motivated the BDH (Bidirectional Hebbian) memory component of BHSM. The specific implementation is original.

### 2.2 Persistent Memory in Neural Systems

Work on context management and memory persistence in language model deployments motivated the PSI (Persistent Semantic Index) component. The concept of maintaining semantic memory across sessions, with retrieval based on similarity rather than recency, addresses the session isolation problem.

BHSM's PSI implementation is original, drawing on general principles of semantic indexing and embedding-based retrieval rather than any specific external architecture.

### 2.3 World Models and Reinforcement Learning

World model research [2] demonstrates that internal representations enabling prediction can be learned from experience. Reinforcement learning provides mechanisms for outcome-based behavioral modification.

BHSM combines these concepts: the PSI accumulates a domain-specific "world model" (a representation of normal vs. anomalous patterns), while reward-gated updates provide the feedback mechanism for behavioral modification. The integration and specific implementation are original.

### 2.4 Memory-Augmented Neural Networks

Research on neural Turing machines [3] and memory-augmented architectures demonstrates that external memory can extend neural network capabilities. BHSM's approach differs in that memory is persistent across sessions and modified during deployment rather than optimized during training.

---

## 3. Architecture

BHSM organizes into three layers:

```
┌─────────────────────────────────────────────────────────────┐
│                    MECHANICAL LAYER                          │
│         Constrained action space (output bounding)           │
├─────────────────────────────────────────────────────────────┤
│                    COGNITIVE LAYER                           │
│    Classification logic, confidence calibration, monitoring  │
├─────────────────────────────────────────────────────────────┤
│                    SYNAPTIC LAYER                            │
│    Reward-Gated Associative Memory + Persistent Semantic Index│
└─────────────────────────────────────────────────────────────┘
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

Positive classification outcomes strengthen connections between co-activated patterns; negative outcomes weaken them. This enables the system to modify its similarity judgments based on operational feedback.

**Persistent Semantic Index (PSI)** provides long-term storage with similarity-based retrieval. Entries persist across sessions. When novel patterns are stored, influence propagates to existing memories with cosine similarity above 0.6, with update magnitude proportional to similarity × reward signal. This enables adaptation to new inputs without requiring exact matches.

### 3.2 Cognitive Layer

The cognitive layer implements classification and monitoring:

**Classification** queries memory systems, retrieves similar patterns, and computes scores from stored valences weighted by similarity.

**Confidence calibration** tracks prediction accuracy and adjusts confidence scores when high-confidence predictions produce poor outcomes. This is implemented as a penalty coefficient (0.3) applied to confidence scores when the error rate among predictions with confidence > 0.8 exceeds 20%.

**Monitoring** tracks coherence metrics and error rates to detect degradation.

**Shared learning** enables multiple instances to contribute to a common PSI, aggregating experience across deployment instances.

### 3.3 Mechanical Layer

The mechanical layer enforces output constraints:

Regardless of cognitive layer computation, system output is restricted to a predefined action set. For the WebGuard implementation, this is {Detect, Allow, Block}. No pathway exists from input to arbitrary output—only to defined actions.

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

**Feedback availability caveat**: In production deployments, labeled feedback on every request is rarely available. Most traffic is never confirmed as benign or malicious. The WebGuard evaluation assumes feedback availability that may not reflect operational reality. Section 5.1 notes that without feedback, the system does not learn—feedback sparsity is a practical constraint on achievable adaptation rates.

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

**Implemented**: Reward-Gated Associative Memory, Persistent Semantic Index, confidence calibration, cross-instance learning, action constraints.

**Not implemented**: Federated learning across hosts, cryptographic authentication for shared updates, cold-start mitigation through pre-trained patterns.

### 7.2 Evaluation Gaps

The current evaluation is insufficient to support strong claims:

- Dataset is too small (138 samples)
- No held-out test set for generalization measurement
- No baseline comparisons
- No adversarial testing
- "100% accuracy" reflects learning the evaluation set, not proven generalization

Future work should address these gaps with larger-scale evaluation against standard benchmarks and baseline systems.

### 7.3 Potential Vulnerabilities

**Adversarial drift**: An attacker with sustained access could potentially shift learned patterns through gradual poisoning. Protected memory mechanisms (preventing modification of high-confidence patterns) provide partial mitigation.

**Feedback dependency**: Learning quality depends on feedback accuracy. Incorrect feedback degrades performance.

**Cold start**: New deployments have no learned patterns and rely on initial feature statistics until sufficient experience accumulates.

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

1. Hebb, D. O. (1949). *The Organization of Behavior: A Neuropsychological Theory*. Wiley.

2. Ha, D. and Schmidhuber, J. (2018). World Models. arXiv:1803.10122.

3. Graves, A., Wayne, G., and Danihelka, I. (2014). Neural Turing Machines. arXiv:1410.5401.

4. Vaswani, A., et al. (2017). Attention Is All You Need. *Advances in Neural Information Processing Systems*.

---

*© 2025 Shane D. Shook, PhD. All Rights Reserved.*
