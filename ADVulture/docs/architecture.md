# ADVulture Architecture

**(c) 2025 Shane D. Shook, PhD - All Rights Reserved**

## Overview

ADVulture implements a four-layer architecture connecting raw AD data to
gradient-ranked remediation intelligence.

```
Collection → Graph → ML → Analysis → API/Reports
```

Each layer is independently operable. You can run collection alone to
build a snapshot, feed a pre-built graph to the ML layer, or run the
full pipeline end-to-end.

---

## Layer 1: Collection

### LDAP Enumerator (`collection/ldap_enumerator.py`)
Direct enumeration of Active Directory via LDAP3. No SharpHound, no agent
on the domain controller. Requires a domain account with read access.

Collects: Users, Computers, Groups, ACLs (nTSecurityDescriptor), Trusts,
ADCS Templates, OU structure, GPO links.

Key computed properties:
- `tier` — Tier 0/1/2 classification from group membership
- `esc1`, `esc2` — ADCS template vulnerability flags
- `delegation_type` — unconstrained / constrained / RBCD / none
- `password_age_days`, `days_since_last_logon` — hygiene metrics

### Event Log Ingester (`collection/log_ingester.py`)
Parses Windows EVTX files (Security, System, Sysmon channels).
Produces a typed `EventStream` with semantic categorisation.

Key events collected and why:

| Event ID | Meaning | ADVulture Use |
|----------|---------|---------------|
| 4624 | Logon success | Session mapping, PTH detection |
| 4625 | Logon failure | Spray detection |
| 4648 | Explicit credentials | Credential reuse signal |
| 4662 | Object operation | DCSync detection (specific GUID) |
| 4663 | Object access | AuthZ behaviour |
| 4669 | Deprecated | N/A |
| 4670 | Permissions changed | Shadow admin modification |
| 4672 | Special privileges at logon | LPE surface (Class D) |
| 4698/4702 | Scheduled task created/modified | LPE and persistence |
| 4720 | Account created | Persistence |
| 4728/4732/4756 | Group member added | Privilege escalation |
| 4768 | Kerberos TGT request | AS-REP roasting |
| 4769 | Kerberos service ticket | Kerberoasting, delegation |
| 4771 | Kerberos pre-auth failed | Spray |
| 4776 | NTLM validation | NTLM usage mapping |
| 5140 | Share accessed | AuthZ behaviour (Class C) |
| 5145 | Share file accessed | AuthZ behaviour (Class C) |
| 7045 | Service installed | LPE and persistence |
| 1644 | LDAP expensive query | BloodHound-style enum detection |
| Sysmon 10 | LSASS access | LPE → credential dump signal |

The `EdgeTensor` produced per (src, dst) pair encodes:
- Traversal counts (30d, 7d windows)
- NTLM ratio, RC4 downgrade ratio, off-hours ratio
- `velocity()` — rising acceleration = threat signal
- `anomaly_score` — composite 0–1 signal

### ADFS Ingester (`collection/adfs_ingester.py`)
Parses Microsoft-Windows-ADFS/Admin and Operational channels.
Produces `ADFSSurface` with:
- Token events (299) correlated with preceding auth events for Golden SAML detection
- Claim rule modifications (403) — always flagged HIGH
- Trust events (500/501)
- Unbacked claim analysis (claims not derivable from AD group membership)

### Entra ID Ingester (`collection/entra_ingester.py`)
Microsoft Graph API collection. Entra ID = Azure AD (rebranded 2023).

Endpoints used:
- `/v1.0/users` — with onPremisesSecurityIdentifier for hybrid join
- `/v1.0/servicePrincipals` — AI agent detection via name patterns
- `/v1.0/directoryRoles/*/members` — critical role assignments
- `/v1.0/policies/conditionalAccessPolicies` — CA gap analysis
- `/v1.0/auditLogs/signIns` — sign-in events with legacy auth flag
- `/v1.0/auditLogs/directoryAudits` — directory change events
- `/v1.0/identityProtection/riskDetections` — Entra risk signals

---

## Layer 2: Graph

### Builder (`graph/builder.py`)
Constructs a PyTorch Geometric `HeteroData` graph from the snapshot
and event stream. Node types: User, Computer, Group, CertTemplate,
Domain, Trust, EntraUser, ServicePrincipal, AIAgent, Resource.

22-dimensional User feature vector spans all six risk classes:
- Features 0–6: Class A (AuthN hygiene)
- Features 7–9: Class B (AuthZ structure)
- Features 10–12: Class C (AuthZ behaviour, from events)
- Feature 13: Class D (LPE signal from 4672 events)
- Features 14–16: Class E (delegation)
- Feature 17: Class F (AI agent identity)
- Features 18–21: Compound signals

Edge types are organised by risk class — see `ml/gnn/model.py` for
the complete EDGE_TYPES list.

---

## Layer 3: ML

### GNN (`ml/gnn/model.py`)
Heterogeneous Graph Transformer (HGT) architecture.
- Input: heterogeneous node features per type
- 3 HGT convolution layers with multi-head attention per relation type
- Output: node risk embeddings + per-edge traversal probabilities
- Control suppression: theta parameters modulate edge weights before
  message passing — suppression is differentiable

The GNN does NOT produce risk scores directly. It produces edge traversal
probabilities that feed the Markov chain. Risk is a property of the
system, not of individual nodes.

### Markov Stack (`ml/markov/chain.py`)

**AttackChainMarkov:**
- Builds N×N transition matrix P from GNN edge probabilities
- LPE transitions added separately: suppressed only by `edr_coverage`
- Absorbing states set at Tier 0 nodes
- Steady-state π via differentiable power iteration (150 steps, 1e-9 tol)
- MFPT via linear solve: `(I - Q)t = 1` on non-Tier0 submatrix

The loss function is `π_tier0 = π[tier0_nodes].sum()`.

**KillChainHMM:**
- 7-phase hidden state space (CLEAN → RECON → INITIAL_COMPROMISE →
  LATERAL_MOVEMENT → PRIVILEGE_ESCALATION → PERSISTENCE → EXECUTION)
- Graph-aware transition matrix: topology modulates phase advancement rates
- Observation emissions per phase: semantic event type probabilities
- Viterbi decoding for most-likely path
- `threat_velocity` = fraction of steps that advanced the phase

**GradientEngine:**
- Makes theta differentiable: `torch.tensor(v, requires_grad=True)`
- Calls `markov.analyze()` → `pi[tier0].sum()` → `.backward()`
- Collects `theta.grad` for each control
- Multiplies by phase relevance (PHASE_CONTROL_RELEVANCE matrix)
- Returns `RemediationItem` list sorted by `abs(grad) × phase_relevance`

### Random Forest (`ml/forest/model.py`)
Trained on (control_vector, env_features) → π_tier0.
Training data generated by sampling random control configurations
through the full Markov pipeline.

Key advantage: captures non-linear interaction effects.
Example: MFA alone suppresses credential theft partially.
LAPS alone suppresses PTH reuse. Together they suppress the full
credential theft → PTH → lateral movement chain — more than the
sum of individual gradient contributions.

---

## Layer 4: Analysis

### PostureAnalyzer (`analysis/posture.py`)
Main orchestrator. Calls all six risk class analyzers:
- `_analyze_authn_hygiene()` — Class A
- `_analyze_authz_structure()` — Class B
- `_analyze_authz_behaviour()` — Class C
- `_analyze_lpe()` — Class D
- `_analyze_delegation()` — Class E
- `_analyze_ai_agents()` — Class F

All findings share the unified `Finding` schema. Gradient contributions
are attached after the gradient engine runs. Findings are sorted by
gradient contribution — not by class.

### Regime Classification
```
ORDERED:  π < 0.15 AND top_grad < 0.3 AND MFPT > 20
CHAOTIC:  π > 0.45 OR  top_grad > 0.7 OR  MFPT < 5
CRITICAL: otherwise
```

---

## Storage

DuckDB (`advulture.duckdb`) — zero-server columnar store.
No Neo4j, no PostgreSQL. Single file, embeds in the process.

Tables:
- `snapshots` — point-in-time AD snapshots
- `findings` — all findings with metadata
- `edge_tensors` — behavioural edge summaries
- `markov_results` — per-run Markov outputs for trajectory analysis
- `gradient_history` — control gradient over time

---

## Deployment

ADVulture requires network access to:
- Domain Controllers (LDAP 389/636)
- For live log collection: WinRM (5985/5986) on event sources
- For Entra ID: outbound HTTPS to graph.microsoft.com
- For ADFS: WinRM to ADFS servers

Recommended service account permissions:
- Domain: Read-only LDAP access (standard user)
- ADCS: No special permissions required
- Event logs: Remote Event Log Readers group membership
- Entra ID: AuditLog.Read.All, Directory.Read.All, Reports.Read.All
