# ADVulture ML Mode - Production Roadmap

## Current State

The ML pipeline is **architecturally complete** but needs calibration and training:

| Component | Status | Blocking Issue |
|-----------|--------|----------------|
| KillChainHMM | ✅ Working | Emission probabilities need tuning |
| AttackChainMarkov | ✅ Working | MFPT edge cases |
| GradientEngine | ⚠️ Partial | Coefficients produce near-zero gradients |
| ADRiskGNN | ⚠️ Untrained | No training data, random weights |
| GraphBuilder | ✅ Working | Needs torch_geometric |

---

## Issue 1: Training Data for GNN

### The Problem
The GNN (6M parameters) initializes with random weights. It needs supervised training to learn meaningful edge traversal probabilities.

### Data Sources

#### Option A: Synthetic Generation (Recommended Start)
Generate labeled attack graphs from known patterns:

```python
# Example: Generate Kerberoasting attack graph
def generate_kerberoast_training_sample():
    """
    Ground truth: Kerberoastable user → credential theft → lateral movement
    Label: edge (attacker → kerberoastable_user) has P=0.8 traversal
    """
    graph = {
        "nodes": [
            {"id": 0, "type": "User", "spn": True, "tier": 2},  # Kerberoastable
            {"id": 1, "type": "User", "tier": 0},  # Domain Admin
            {"id": 2, "type": "Computer", "tier": 1},  # Server
        ],
        "edges": [
            {"src": 0, "dst": 2, "type": "AdminTo", "label": 0.7},
            {"src": 2, "dst": 1, "type": "HasSession", "label": 0.5},
        ],
        "attack_succeeded": True,
        "path": [0, 2, 1],
    }
    return graph
```

**Attack patterns to generate:**
1. Kerberoasting → credential crack → lateral movement
2. AS-REP roasting → same
3. ESC1/ESC8 → certificate theft → impersonation
4. Unconstrained delegation → TGT theft
5. DCSync → full compromise
6. RBCD abuse → lateral movement
7. Golden Ticket → persistence
8. Shadow Credentials → persistence

#### Option B: BloodHound Sample Data
Use existing BloodHound datasets:
- [SpecterOps BadBlood](https://github.com/davidprowe/BadBlood) - generates vulnerable AD
- [BloodHound sample databases](https://github.com/BloodHoundAD/BloodHound/tree/master/examples)
- [DVAD (Damn Vulnerable AD)](https://github.com/WazeHell/vulnerable-AD)

```bash
# Import BloodHound JSON and label edges based on known attack paths
python -m advulture.ml.training.import_bloodhound \
    --input bloodhound_export.json \
    --label-attacks kerberoast,asrep,esc1 \
    --output training_data.pt
```

#### Option C: Red Team Data (Best but Rare)
If you have access to red team reports with:
- Attack paths taken
- Time to compromise
- Controls that blocked attacks

This provides ground-truth labels for edge traversal probabilities.

### Training Pipeline

```python
# advulture/ml/training/train_gnn.py

import torch
from torch_geometric.loader import DataLoader
from advulture.ml.gnn.model import ADRiskGNN

def train_gnn(
    training_graphs: List[HeteroData],
    labels: List[Dict],  # Edge traversal ground truth
    epochs: int = 100,
    lr: float = 0.001,
):
    model = ADRiskGNN()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = torch.nn.BCEWithLogitsLoss()
    
    for epoch in range(epochs):
        total_loss = 0
        for graph, label in zip(training_graphs, labels):
            optimizer.zero_grad()
            
            # Forward pass
            risk_scores, edge_probs = model(graph)
            
            # Loss: predicted edge probs vs labeled traversal probs
            loss = criterion(edge_probs, label["edge_traversal"])
            
            # Auxiliary loss: path prediction
            loss += path_prediction_loss(edge_probs, label["attack_path"])
            
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        
        print(f"Epoch {epoch}: loss={total_loss:.4f}")
    
    return model
```

### Minimum Training Data

| Attack Type | Samples Needed | Difficulty |
|-------------|----------------|------------|
| Kerberoasting | 100+ | Easy (synthetic) |
| AS-REP Roast | 100+ | Easy |
| ESC1/ESC8 | 50+ | Medium |
| Delegation abuse | 50+ | Medium |
| DCSync paths | 50+ | Medium |
| Full attack chains | 200+ | Hard |

**Total: ~500-1000 labeled graphs for initial training**

---

## Issue 2: Gradient Engine Coefficient Tuning

### The Problem
Current suppression factors are guesses:
```python
suppression = 1.0 - 0.3 * mfa - 0.2 * smb - 0.25 * tiered
```

These don't produce meaningful gradients because:
1. Coefficients too small relative to graph structure
2. Not calibrated to real-world control effectiveness

### Solution: Empirical Calibration

#### Step 1: Literature-Based Priors

| Control | Estimated Risk Reduction | Source |
|---------|-------------------------|--------|
| MFA | 99.9% of automated attacks | Microsoft |
| LAPS | 80% of lateral movement | SANS |
| Tiered Admin | 70% of privilege escalation | MITRE |
| SMB Signing | 60% of relay attacks | CIS |
| AES-only Kerberos | 90% of Kerberoasting | SpecterOps |

```python
# Updated coefficients based on literature
CONTROL_EFFECTIVENESS = {
    "mfa_coverage":        0.90,  # Blocks 90% of credential-based paths
    "laps_deployed":       0.70,  # Blocks 70% of local admin lateral movement
    "tiered_admin":        0.80,  # Blocks 80% of tier-crossing paths
    "smb_signing":         0.60,  # Blocks 60% of relay-based edges
    "aes_enforcement":     0.85,  # Blocks 85% of Kerberoasting edges
    "adcs_hardened":       0.95,  # Blocks 95% of ESC paths
    "delegation_audit":    0.75,  # Blocks 75% of delegation abuse
}
```

#### Step 2: Per-Edge-Type Suppression

Instead of global suppression, apply per-edge-type:

```python
def _suppression_factor(self, edge_type: str, theta: Dict) -> float:
    """
    Edge-specific suppression based on control relevance.
    """
    EDGE_CONTROL_MAP = {
        "KerberoastableVia": {
            "aes_enforcement": 0.90,
            "mfa_coverage": 0.30,  # MFA doesn't stop offline cracking
        },
        "AdminTo": {
            "laps_deployed": 0.80,
            "tiered_admin": 0.70,
        },
        "AuthenticatesViaNTLM": {
            "smb_signing": 0.70,
            "mfa_coverage": 0.50,
        },
        "UnconstrainedDelegation": {
            "delegation_audit": 0.85,
            "tiered_admin": 0.60,
        },
        "ESC1Vulnerable": {
            "adcs_hardened": 0.95,
        },
        "DCSync": {
            "tiered_admin": 0.90,
            "dcsync_audited": 0.40,  # Audit doesn't prevent, just detects
        },
    }
    
    controls = EDGE_CONTROL_MAP.get(edge_type, {})
    suppression = 1.0
    for ctrl, effectiveness in controls.items():
        deployment = theta.get(ctrl, 0.0)
        suppression *= (1.0 - effectiveness * deployment)
    
    return max(suppression, 0.01)  # Never fully eliminate
```

#### Step 3: Validation via A/B Testing

Once deployed, validate coefficients:
```python
def validate_coefficients(
    before_snapshot: ADSnapshot,
    after_snapshot: ADSnapshot,
    control_deployed: str,
    observed_risk_reduction: float,
):
    """
    Compare predicted vs observed risk reduction after deploying a control.
    Use to tune coefficients.
    """
    before_risk = compute_tier0_prob(before_snapshot)
    after_risk = compute_tier0_prob(after_snapshot)
    predicted_reduction = before_risk - after_risk
    
    error = abs(predicted_reduction - observed_risk_reduction)
    
    # Adjust coefficient if error > 10%
    if error > 0.10:
        adjust_coefficient(control_deployed, observed_risk_reduction)
```

---

## Issue 3: Robust MFPT Calculation

### The Problem
Mean First Passage Time calculation fails with singular matrices:
```python
N = np.linalg.solve(I - Q, np.ones(len(non_tier0)))  # Fails if I-Q singular
```

### Solution: Numerical Improvements

```python
def mean_first_passage_time_robust(self, P: torch.Tensor) -> float:
    """
    Robust MFPT calculation with multiple fallbacks.
    """
    non_tier0 = [i for i in range(self.n) if i not in self.tier0_ids]
    if not non_tier0:
        return 0.0
    
    Q = P[non_tier0][:, non_tier0].detach().numpy()
    I = np.eye(len(non_tier0))
    A = I - Q
    b = np.ones(len(non_tier0))
    
    # Method 1: Direct solve with condition check
    cond = np.linalg.cond(A)
    if cond < 1e10:
        try:
            N = np.linalg.solve(A, b)
            if np.all(N > 0) and np.all(np.isfinite(N)):
                return float(N.mean())
        except np.linalg.LinAlgError:
            pass
    
    # Method 2: Pseudo-inverse (handles singular/near-singular)
    try:
        A_pinv = np.linalg.pinv(A)
        N = A_pinv @ b
        if np.all(N > 0) and np.all(np.isfinite(N)):
            return float(N.mean())
    except:
        pass
    
    # Method 3: Iterative estimation via simulation
    try:
        return self._simulate_mfpt(P, num_walks=1000)
    except:
        pass
    
    # Method 4: Upper bound from graph diameter
    return float(self.n * 2)  # Rough upper bound


def _simulate_mfpt(self, P: torch.Tensor, num_walks: int = 1000) -> float:
    """
    Monte Carlo estimation of MFPT.
    """
    P_np = P.detach().numpy()
    tier0_set = set(self.tier0_ids)
    
    total_steps = 0
    completed = 0
    max_steps = self.n * 10
    
    for _ in range(num_walks):
        # Start from random non-tier0 node
        current = np.random.choice([i for i in range(self.n) if i not in tier0_set])
        
        for step in range(max_steps):
            if current in tier0_set:
                total_steps += step
                completed += 1
                break
            # Random walk
            current = np.random.choice(self.n, p=P_np[current])
    
    return total_steps / max(completed, 1)
```

---

## Issue 4: Real-World Testing and Validation

### Testing Environments

#### Tier 1: Lab Environments (Immediate)

1. **BadBlood AD Lab**
   ```bash
   # Deploy vulnerable AD in Azure/AWS
   git clone https://github.com/davidprowe/BadBlood
   # Creates 2500 users, groups, computers with attack paths
   ```

2. **DVAD (Damn Vulnerable AD)**
   ```bash
   git clone https://github.com/WazeHell/vulnerable-AD
   # Terraform deployment with known vulnerabilities
   ```

3. **DVAA (Damn Vulnerable Azure AD)**
   ```bash
   git clone https://github.com/Cloud-Architekt/AzureAD-Attack-Defense
   # Entra ID misconfigurations
   ```

#### Tier 2: CTF Datasets

- **HackTheBox ProLabs** - Full AD attack chains with writeups
- **TryHackMe AD rooms** - Guided attack scenarios
- **SANS NetWars** - Competition data (if accessible)

#### Tier 3: Production Validation (With Permission)

Partner with organizations for:
1. **Shadow mode**: Run ADVulture alongside existing tools, compare findings
2. **Red team validation**: Run during authorized red team, measure detection
3. **Post-incident analysis**: Validate predictions against actual breaches

### Validation Metrics

```python
@dataclass
class ValidationResult:
    # Classification metrics
    true_positives: int   # Predicted risky path that was exploited
    false_positives: int  # Predicted risky but not exploitable
    true_negatives: int   # Predicted safe and was safe
    false_negatives: int  # Predicted safe but was exploited
    
    # Probability calibration
    predicted_tier0_prob: float
    actual_compromise_rate: float
    calibration_error: float
    
    # Ranking quality
    top_k_precision: float  # Of top-k findings, how many were real issues?
    mean_reciprocal_rank: float  # Where did the actual attack path rank?


def validate_against_red_team(
    advulture_report: PostureReport,
    red_team_report: Dict,
) -> ValidationResult:
    """
    Compare ADVulture predictions against red team results.
    """
    predicted_paths = extract_attack_paths(advulture_report)
    actual_paths = red_team_report["attack_paths"]
    
    # Check path overlap
    tp = len(set(predicted_paths) & set(actual_paths))
    fp = len(set(predicted_paths) - set(actual_paths))
    fn = len(set(actual_paths) - set(predicted_paths))
    
    # Check probability calibration
    predicted_prob = advulture_report.tier0_steady_state_probability
    actual_success = red_team_report["reached_tier0"]
    
    return ValidationResult(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        predicted_tier0_prob=predicted_prob,
        actual_compromise_rate=1.0 if actual_success else 0.0,
        # ...
    )
```

---

## Implementation Roadmap

### Phase 1: Synthetic Data & Coefficient Tuning (2-3 weeks)

1. **Week 1**: Build synthetic data generator
   - [ ] Kerberoasting attack graphs
   - [ ] AS-REP roasting graphs
   - [ ] ESC1/ESC8 certificate abuse graphs
   - [ ] Delegation abuse graphs

2. **Week 2**: Tune coefficients
   - [ ] Implement per-edge-type suppression
   - [ ] Calibrate from literature values
   - [ ] Fix MFPT calculation

3. **Week 3**: Basic validation
   - [ ] Deploy BadBlood lab
   - [ ] Run ADVulture against known-vulnerable AD
   - [ ] Compare predictions vs BloodHound paths

### Phase 2: GNN Training (3-4 weeks)

4. **Week 4-5**: Training pipeline
   - [ ] Import BloodHound data format
   - [ ] Label edges from attack patterns
   - [ ] Implement training loop

5. **Week 6-7**: Training & validation
   - [ ] Train on synthetic + BloodHound data
   - [ ] Validate on held-out test set
   - [ ] Iterate on architecture if needed

### Phase 3: Real-World Validation (Ongoing)

6. **Week 8+**: Production testing
   - [ ] Shadow mode deployment
   - [ ] Red team validation
   - [ ] Continuous calibration

---

## Quick Wins (Do Now)

These can be done immediately to improve ML mode:

### 1. Fix MFPT (30 minutes)
```python
# In chain.py, replace mean_first_passage_time with robust version
```

### 2. Update coefficients (1 hour)
```python
# Use literature-based values instead of guesses
CONTROL_EFFECTIVENESS = {
    "mfa_coverage": 0.90,
    "laps_deployed": 0.70,
    # ...
}
```

### 3. Add coefficient validation logging (30 minutes)
```python
# Log predicted vs actual suppression for tuning
log.info(f"Control {ctrl}: deployment={deployment:.0%}, "
         f"predicted_suppression={suppression:.0%}")
```

### 4. Generate 100 synthetic training samples (2 hours)
```python
# Basic Kerberoast/ASREP/ESC1 attack graphs
# Good enough for initial GNN training
```

---

## Dependencies to Add

```toml
# pyproject.toml additions for ML training
[project.optional-dependencies]
ml = [
    "torch>=2.0",
    "torch-geometric>=2.4",
    "numpy>=1.24",
    "scikit-learn>=1.3",  # For metrics
    "tensorboard>=2.14",  # For training visualization
]
```

---

## Summary

| Issue | Solution | Effort | Impact |
|-------|----------|--------|--------|
| GNN Training Data | Synthetic + BloodHound | 3-4 weeks | High |
| Coefficient Tuning | Literature + per-edge | 1-2 weeks | High |
| MFPT Robustness | Numerical fixes | 1-2 days | Medium |
| Real-World Validation | Lab + red team | Ongoing | Critical |

**Recommendation**: Start with coefficient tuning and MFPT fixes (quick wins), then build synthetic training data, then pursue real-world validation.
