"""
ADVulture — Markov Stack
Three complementary Markov models:
  1. Attack Chain Markov (steady-state π_tier0 — the loss function)
  2. Kill-Chain HMM (attacker phase detection from log sequences)
  3. Second-Order MC (credential-aware path modelling)

The steady-state π_tier0 is the primary loss for gradient descent.
It captures the long-run probability of an attacker reaching Tier 0
given the current transition structure — more meaningful than any
point-in-time heuristic risk score.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Dict, Optional
import numpy as np
import torch
import torch.nn.functional as F

log = logging.getLogger(__name__)


# ── 1. Attack Chain Markov ────────────────────────────────────────────────────

@dataclass
class MarkovResult:
    P: torch.Tensor                   # transition matrix [N, N]
    pi: torch.Tensor                   # steady-state distribution [N]
    tier0_probability: float           # π[tier0_nodes].sum()
    mean_steps_to_tier0: float         # mean first passage time
    most_exposed_nodes: List[int]       # highest steady-state mass outside Tier0


class AttackChainMarkov:
    """
    Builds a transition matrix from GNN edge probabilities,
    applies control suppression, and computes the steady-state
    distribution via differentiable power iteration.

    The gradient ∂π_tier0/∂θ flows through power iteration via autograd.
    """

    def __init__(self, num_nodes: int, tier0_node_ids: List[int]):
        self.n = num_nodes
        self.tier0_ids = tier0_node_ids

    def build_transition_matrix(
        self,
        edge_index: torch.Tensor,       # [2, E]
        edge_probs: torch.Tensor,       # [E] from GNN
        theta: Dict[str, torch.Tensor],
        lpe_pairs: Optional[List] = None,
    ) -> torch.Tensor:
        """
        Constructs N×N differentiable transition matrix.
        LPE paths are added as additional transitions orthogonal to AD-based paths.
        """
        P = torch.zeros(self.n, self.n, requires_grad=False)

        # Standard AD graph transitions
        for idx in range(edge_index.shape[1]):
            src = edge_index[0, idx].item()
            dst = edge_index[1, idx].item()
            p = edge_probs[idx]
            P[src, dst] = torch.max(P[src, dst], p)

        # LPE transitions (suppressed only by EDR, not AD controls)
        if lpe_pairs:
            edr = theta.get("edr_coverage", torch.tensor(0.0))
            for lpe in lpe_pairs:
                src_id = lpe.get("account_node_id")
                sys_id = lpe.get("system_node_id")
                if src_id is not None and sys_id is not None:
                    lpe_p = torch.tensor(lpe.get("probability", 0.5)) * (1 - 0.80 * edr)
                    P[src_id, sys_id] = torch.max(P[src_id, sys_id], lpe_p)
                    # SYSTEM → cached credential nodes
                    for cred_node_id in lpe.get("credential_nodes", []):
                        P[sys_id, cred_node_id] = torch.tensor(0.95)

        # Absorbing states: once Tier0 is reached, attacker stays
        tier0 = torch.tensor(self.tier0_ids)
        P[tier0] = 0.0
        for t in self.tier0_ids:
            P[t, t] = 1.0

        # Row-normalise
        row_sums = P.sum(dim=1, keepdim=True).clamp(min=1e-10)
        P = P / row_sums
        return P

    def steady_state(self, P: torch.Tensor) -> torch.Tensor:
        """
        Power iteration — converges in ~150 steps.
        Differentiable through autograd: gradients flow back through
        each iteration to all parameters that affect P.
        """
        pi = torch.ones(self.n, device=P.device) / self.n
        for _ in range(150):
            pi_next = pi @ P
            if torch.norm(pi_next - pi) < 1e-9:
                break
            pi = pi_next
        return pi

    def mean_first_passage_time(self, P: torch.Tensor) -> float:
        """
        Solve (I - Q)t = 1 where Q is P restricted to non-Tier0 nodes.
        Returns expected steps for a random walker to reach Tier0.
        Low MFPT = attacker reaches DA quickly.
        """
        non_tier0 = [i for i in range(self.n) if i not in self.tier0_ids]
        if not non_tier0:
            return 0.0
        Q = P[non_tier0][:, non_tier0].detach().numpy()
        I = np.eye(len(non_tier0))
        try:
            N = np.linalg.solve(I - Q, np.ones(len(non_tier0)))
            return float(N.mean())
        except np.linalg.LinAlgError:
            return 999.0

    def analyze(
        self,
        edge_index: torch.Tensor,
        edge_probs: torch.Tensor,
        theta: Dict[str, torch.Tensor],
        lpe_pairs: Optional[List] = None,
    ) -> MarkovResult:
        P = self.build_transition_matrix(edge_index, edge_probs, theta, lpe_pairs)
        pi = self.steady_state(P)
        tier0_tensor = torch.tensor(self.tier0_ids)
        tier0_prob = pi[tier0_tensor].sum().item()
        mfpt = self.mean_first_passage_time(P)

        # Most exposed non-Tier0 nodes (high steady-state probability)
        pi_np = pi.detach().numpy()
        pi_np[self.tier0_ids] = 0.0
        top_exposed = np.argsort(pi_np)[::-1][:10].tolist()

        return MarkovResult(
            P=P,
            pi=pi,
            tier0_probability=tier0_prob,
            mean_steps_to_tier0=mfpt,
            most_exposed_nodes=top_exposed,
        )


# ── 2. Kill-Chain HMM ─────────────────────────────────────────────────────────

class Phase(IntEnum):
    CLEAN                = 0
    RECONNAISSANCE       = 1
    INITIAL_COMPROMISE   = 2
    LATERAL_MOVEMENT     = 3
    PRIVILEGE_ESCALATION = 4
    PERSISTENCE          = 5
    EXECUTION            = 6


@dataclass
class PhaseDetection:
    distribution: np.ndarray           # P(phase) over all phases
    most_likely: Phase
    confidence: float
    phase_history: List[Phase]          # Viterbi path
    threat_velocity: float              # phase advancement rate


class KillChainHMM:
    """
    Hidden Markov Model over kill-chain phases.
    Hidden states = attacker phases; observations = semantic event types.
    Graph-aware: transition probabilities scale with AD topology.
    """

    BASE_TRANSITIONS = np.array([
        #  CLN  RECON  INIT   LAT   PRIV   PERS   EXEC
        [0.98, 0.020, 0.000, 0.000, 0.000, 0.000, 0.000],  # CLEAN
        [0.10, 0.600, 0.280, 0.020, 0.000, 0.000, 0.000],  # RECON
        [0.05, 0.050, 0.550, 0.330, 0.020, 0.000, 0.000],  # INIT
        [0.02, 0.000, 0.050, 0.550, 0.350, 0.030, 0.000],  # LAT
        [0.01, 0.000, 0.000, 0.080, 0.500, 0.200, 0.210],  # PRIV
        [0.01, 0.000, 0.000, 0.050, 0.100, 0.650, 0.190],  # PERS
        [0.00, 0.000, 0.000, 0.000, 0.050, 0.100, 0.850],  # EXEC
    ], dtype=float)

    EMISSIONS: Dict[Phase, Dict[str, float]] = {
        Phase.CLEAN: {
            "logon_success": 0.75, "logoff": 0.20, "service_ticket": 0.04,
            "ldap_expensive_query": 0.01,
        },
        Phase.RECONNAISSANCE: {
            "ldap_expensive_query": 0.40, "service_ticket": 0.25,
            "logon_failure": 0.20, "logon_success": 0.10, "cert_requested": 0.05,
        },
        Phase.INITIAL_COMPROMISE: {
            "explicit_credentials": 0.35, "logon_success": 0.30,
            "logon_failure": 0.20, "ntlm_validation": 0.15,
        },
        Phase.LATERAL_MOVEMENT: {
            "share_accessed": 0.30, "logon_success": 0.25,
            "explicit_credentials": 0.25, "special_privileges_logon": 0.20,
        },
        Phase.PRIVILEGE_ESCALATION: {
            "service_ticket": 0.30, "cert_requested": 0.25,
            "directory_object_operation": 0.25, "special_privileges_logon": 0.20,
        },
        Phase.PERSISTENCE: {
            "account_created": 0.30, "group_member_added": 0.30,
            "account_changed": 0.25, "scheduled_task_created": 0.15,
        },
        Phase.EXECUTION: {
            "directory_object_operation": 0.50,  # DCSync
            "account_created": 0.20, "group_member_added": 0.15,
            "adfs_claim_rule_changed": 0.15,
        },
    }

    def build_graph_aware_transitions(self, graph_stats: Dict) -> np.ndarray:
        T = self.BASE_TRANSITIONS.copy()
        # More sprayable accounts → easier initial compromise
        T[Phase.RECONNAISSANCE, Phase.INITIAL_COMPROMISE] *= (
            1 + graph_stats.get("enabled_user_ratio", 0.5) * 0.5
        )
        # More Tier0-reachable paths → faster privilege escalation
        reachability = min(2.0, graph_stats.get("tier0_reachable_paths", 1) / 5.0)
        T[Phase.LATERAL_MOVEMENT, Phase.PRIVILEGE_ESCALATION] *= reachability
        # ESC1/ESC2 templates → faster cert-based escalation
        if graph_stats.get("esc_template_count", 0) > 0:
            T[Phase.LATERAL_MOVEMENT, Phase.PRIVILEGE_ESCALATION] = min(
                0.6, T[Phase.LATERAL_MOVEMENT, Phase.PRIVILEGE_ESCALATION] * 1.4
            )
        # Re-normalise rows
        row_sums = T.sum(axis=1, keepdims=True)
        return T / np.where(row_sums > 0, row_sums, 1)

    def viterbi(
        self,
        event_sequence: List[str],
        graph_stats: Optional[Dict] = None,
    ) -> PhaseDetection:
        if not event_sequence:
            dist = np.zeros(len(Phase))
            dist[Phase.CLEAN] = 1.0
            return PhaseDetection(dist, Phase.CLEAN, 1.0, [Phase.CLEAN], 0.0)

        T = self.build_graph_aware_transitions(graph_stats or {})
        n_phases = len(Phase)
        n_obs = len(event_sequence)

        delta = np.full((n_obs, n_phases), -np.inf)
        psi = np.zeros((n_obs, n_phases), dtype=int)

        # Initialise: assume clean state
        delta[0, Phase.CLEAN] = 0.0

        for t in range(1, n_obs):
            obs = event_sequence[t]
            for j in range(n_phases):
                emission = self.EMISSIONS[Phase(j)].get(obs, 1e-6)
                log_emission = np.log(emission)
                log_trans = np.log(T[:, j] + 1e-10)
                candidates = delta[t - 1] + log_trans
                best = candidates.argmax()
                delta[t, j] = candidates[best] + log_emission
                psi[t, j] = best

        # Backtrack
        path = [int(delta[-1].argmax())]
        for t in range(n_obs - 1, 0, -1):
            path.insert(0, int(psi[t, path[0]]))

        # Forward probability for current phase distribution
        log_alpha = delta[-1]
        log_alpha -= log_alpha.max()
        alpha = np.exp(log_alpha)
        alpha /= alpha.sum()

        current = Phase(path[-1])
        velocity = self._phase_velocity(path)

        return PhaseDetection(
            distribution=alpha,
            most_likely=current,
            confidence=float(alpha[current]),
            phase_history=[Phase(p) for p in path],
            threat_velocity=velocity,
        )

    def _phase_velocity(self, path: List[int]) -> float:
        if len(path) < 2:
            return 0.0
        advances = sum(1 for a, b in zip(path, path[1:]) if b > a)
        return advances / len(path)


# ── 3. Gradient Engine ────────────────────────────────────────────────────────

@dataclass
class RemediationItem:
    control: str
    gradient: float
    current_value: float
    phase_relevance: float
    weighted_priority: float
    explanation: str
    risk_classes_affected: List[str] = field(default_factory=list)


# Phase-to-control relevance matrix [phase_idx, control_idx]
# Controls ordered: mfa, laps, edr, adcs, tiered_admin, smb_signing,
#                   delegation_audit, dcsync_audited, mcp_scope, adfs_review
PHASE_CONTROL_RELEVANCE = np.array([
    # CLN  REC  INIT  LAT   PRIV  PERS  EXEC
    [0.1, 0.3, 0.9,  0.8,  0.5,  0.3,  0.2],  # mfa_coverage
    [0.1, 0.1, 0.4,  0.9,  0.6,  0.3,  0.2],  # laps_deployed
    [0.1, 0.2, 0.5,  0.7,  0.8,  0.4,  0.3],  # edr_coverage
    [0.1, 0.2, 0.2,  0.4,  0.9,  0.3,  0.5],  # adcs_hardened
    [0.2, 0.2, 0.3,  0.6,  0.9,  0.5,  0.4],  # tiered_admin
    [0.1, 0.1, 0.5,  0.9,  0.4,  0.2,  0.1],  # smb_signing
    [0.1, 0.2, 0.3,  0.5,  0.8,  0.4,  0.5],  # delegation_audit
    [0.1, 0.1, 0.1,  0.2,  0.4,  0.3,  0.9],  # dcsync_audited
    [0.0, 0.0, 0.1,  0.2,  0.3,  0.4,  0.5],  # mcp_scope_restriction
    [0.1, 0.1, 0.2,  0.3,  0.5,  0.4,  0.8],  # adfs_claim_review
])

CONTROL_NAMES = [
    "mfa_coverage", "laps_deployed", "edr_coverage", "adcs_hardened",
    "tiered_admin", "smb_signing", "delegation_audit", "dcsync_audited",
    "mcp_scope_restriction", "adfs_claim_review",
]


class GradientEngine:
    """
    Computes ∂π_tier0/∂θ for all controls simultaneously.
    Gradients flow through: θ → edge suppression → P → power_iteration → π_tier0
    """

    def compute_ranking(
        self,
        edge_index: torch.Tensor,
        edge_probs: torch.Tensor,
        theta_values: Dict[str, float],
        phase_detection: PhaseDetection,
        markov: AttackChainMarkov,
        lpe_pairs: Optional[List] = None,
    ) -> List[RemediationItem]:

        # Make theta differentiable
        theta = {
            k: torch.tensor(v, dtype=torch.float32, requires_grad=True)
            for k, v in theta_values.items()
        }

        # Forward: compute π_tier0
        result = markov.analyze(edge_index, edge_probs, theta, lpe_pairs)
        tier0_prob = result.pi[torch.tensor(markov.tier0_ids)].sum()

        # Backward: ∂π_tier0/∂theta
        tier0_prob.backward()

        # Phase-weighted priority
        phase_weights = self._phase_weights(phase_detection)

        items = []
        for ctrl, t in theta.items():
            grad = t.grad.item() if t.grad is not None else 0.0
            phase_rel = phase_weights.get(ctrl, 1.0)
            items.append(RemediationItem(
                control=ctrl,
                gradient=grad,
                current_value=theta_values[ctrl],
                phase_relevance=phase_rel,
                weighted_priority=abs(grad) * phase_rel,
                explanation=self._explain(ctrl, grad, phase_detection),
                risk_classes_affected=self._classes_for_control(ctrl),
            ))

        return sorted(items, key=lambda x: x.weighted_priority, reverse=True)

    def _phase_weights(self, detection: PhaseDetection) -> Dict[str, float]:
        dist = detection.distribution
        return {
            ctrl: float(np.dot(PHASE_CONTROL_RELEVANCE[i], dist))
            for i, ctrl in enumerate(CONTROL_NAMES)
            if i < len(PHASE_CONTROL_RELEVANCE)
        }

    def _explain(self, control: str, gradient: float,
                 detection: PhaseDetection) -> str:
        phase_name = detection.most_likely.name
        templates = {
            "edr_coverage": (
                f"EDR is the primary control for LPE paths (Class D). "
                f"AD-based controls have zero suppression effect on SeImpersonate "
                f"and Potato attack chains. Gradient: {gradient:.3f}."
            ),
            "adcs_hardened": (
                f"ESC1/ESC2 certificate templates allow subject alternative name "
                f"specification, enabling impersonation of any identity. "
                f"MFA is irrelevant for certificate-based auth. Gradient: {gradient:.3f}."
            ),
            "mfa_coverage": (
                f"MFA suppresses credential-based lateral movement. "
                f"Note: MFA does NOT protect against PTH, Kerberos delegation, "
                f"or certificate-based attacks. Phase context: {phase_name}. "
                f"Gradient: {gradient:.3f}."
            ),
            "laps_deployed": (
                f"LAPS randomises local admin passwords, breaking PTH reuse "
                f"across machines. Gradient: {gradient:.3f}."
            ),
            "delegation_audit": (
                f"Unconstrained and RBCD delegation chains expose any account "
                f"authenticating to delegation-capable hosts. Gradient: {gradient:.3f}."
            ),
            "mcp_scope_restriction": (
                f"AI agent OAuth scope and MCP tool capability reduction. "
                f"Prompt injection exploits authorised access — no ACL violation. "
                f"Gradient: {gradient:.3f}."
            ),
        }
        return templates.get(control, f"Gradient contribution: {gradient:.3f}. Phase: {phase_name}.")

    def _classes_for_control(self, control: str) -> List[str]:
        mapping = {
            "mfa_coverage":         ["A", "C"],
            "laps_deployed":        ["B", "C"],
            "edr_coverage":         ["D"],
            "adcs_hardened":        ["B"],
            "tiered_admin":         ["B", "E"],
            "smb_signing":          ["A", "C"],
            "delegation_audit":     ["E"],
            "dcsync_audited":       ["B"],
            "mcp_scope_restriction":["F"],
            "adfs_claim_review":    ["C"],
        }
        return mapping.get(control, ["B"])
