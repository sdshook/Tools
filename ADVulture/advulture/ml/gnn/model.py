# (c) 2025 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture — Graph Neural Network Model
Heterogeneous Graph Transformer (HGT) over the unified AD graph.
Learns node risk embeddings and edge traversal probabilities
across all six risk classes simultaneously.
"""

from __future__ import annotations
import logging
from typing import Dict, Optional, Tuple
import torch
import torch.nn as nn
import torch.nn.functional as F

log = logging.getLogger(__name__)

# Feature dimensions per node type (count of features in node feature vector)
NODE_FEATURE_DIMS = {
    "User":             22,
    "Computer":         14,
    "Group":            6,
    "CertTemplate":     8,
    "Domain":           4,
    "Trust":            5,
    "EntraUser":        12,
    "ServicePrincipal": 8,
    "AIAgent":          9,
    "Resource":         5,
}

# All edge types in the unified graph
EDGE_TYPES = [
    # Class A — AuthN Hygiene
    ("User", "KerberoastableVia", "User"),
    ("User", "ASREPRoastable", "Domain"),
    ("User", "UsesRC4", "Computer"),
    ("User", "NoMFAEnrolled", "Domain"),
    ("User", "AuthenticatesViaNTLM", "Computer"),
    # Class B — AuthZ Structure
    ("User", "MemberOf", "Group"),
    ("Group", "MemberOf", "Group"),
    ("User", "AdminTo", "Computer"),
    ("Group", "AdminTo", "Computer"),
    ("User", "GenericAll", "User"),
    ("User", "WriteDacl", "Group"),
    ("User", "DCSync", "Domain"),
    ("User", "CanEnrollInTemplate", "CertTemplate"),
    ("CertTemplate", "ESC1Vulnerable", "Domain"),
    # Class C — AuthZ Behaviour
    ("User", "ActuallyAccessed", "Resource"),
    ("User", "ShadowAccess", "Resource"),
    ("User", "LocalAdminOverride", "Computer"),
    ("User", "ADFSClaimGranted", "Resource"),
    # Class D — LPE
    ("User", "HasDangerousPrivilege", "Computer"),
    ("User", "LPEPathTo", "Computer"),
    ("Computer", "LSASSAccessible", "Computer"),
    # Class E — Delegation
    ("Computer", "UnconstrainedDelegation", "Domain"),
    ("User", "ConstrainedDelegation", "Computer"),
    ("Computer", "RBCDEnabled", "Computer"),
    ("User", "CanWriteRBCD", "Computer"),
    # Class F — AI Agents
    ("AIAgent", "AgentActsAs", "User"),
    ("AIAgent", "AgentCanAccess", "Resource"),
    ("AIAgent", "InjectionPathTo", "Resource"),
]


class ADRiskGNN(nn.Module):
    """
    Heterogeneous Graph Transformer for AD risk analysis.
    Operates over all six risk class edge types simultaneously.
    Outputs per-node risk embeddings and per-edge traversal probabilities.
    """

    def __init__(
        self,
        hidden_dim: int = 128,
        num_layers: int = 3,
        num_heads: int = 4,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        # Input projections: map each node type's feature dim to hidden_dim
        self.input_projections = nn.ModuleDict({
            node_type: nn.Linear(feat_dim, hidden_dim)
            for node_type, feat_dim in NODE_FEATURE_DIMS.items()
        })

        # HGT-style convolution layers
        # Using simplified attention-based message passing
        self.conv_layers = nn.ModuleList([
            HGTConvLayer(
                hidden_dim=hidden_dim,
                num_heads=num_heads,
                edge_types=EDGE_TYPES,
                dropout=dropout,
            )
            for _ in range(num_layers)
        ])

        # Risk head: node → scalar risk score ∈ [0, 1]
        self.risk_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 1),
            nn.Sigmoid(),
        )

        # Edge probability head: [src_emb || dst_emb] → traversal prob
        self.edge_prob_head = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid(),
        )

    def forward(
        self,
        x_dict: Dict[str, torch.Tensor],
        edge_index_dict: Dict[tuple, torch.Tensor],
        theta: Dict[str, torch.Tensor],
        edge_attr_dict: Optional[Dict[tuple, torch.Tensor]] = None,
    ) -> Tuple[Dict[str, torch.Tensor], Dict[tuple, torch.Tensor]]:
        """
        Args:
            x_dict:         {node_type: [N, feat_dim]} node features
            edge_index_dict:{edge_type: [2, E]} edge indices
            theta:          differentiable control parameters
            edge_attr_dict: optional edge behavioural tensors

        Returns:
            risk_scores:    {node_type: [N, 1]} per-node risk
            edge_probs:     {edge_type: [E, 1]} traversal probabilities
        """
        # Project all node types to hidden_dim
        h_dict = {
            nt: F.elu(self.input_projections[nt](x))
            for nt, x in x_dict.items()
            if nt in self.input_projections
        }

        # Apply control suppression to edge attributes before message passing
        suppressed_attrs = self._apply_control_suppression(
            edge_index_dict, edge_attr_dict or {}, theta
        )

        # Graph convolution layers
        for conv in self.conv_layers:
            h_dict = conv(h_dict, edge_index_dict, suppressed_attrs)
            h_dict = {k: F.elu(v) for k, v in h_dict.items()}

        # Node risk scores
        risk_scores = {
            nt: self.risk_head(h)
            for nt, h in h_dict.items()
        }

        # Edge traversal probabilities
        edge_probs: Dict[tuple, torch.Tensor] = {}
        for (src_type, rel, dst_type), edge_index in edge_index_dict.items():
            if src_type not in h_dict or dst_type not in h_dict:
                continue
            src_emb = h_dict[src_type][edge_index[0]]  # [E, hidden]
            dst_emb = h_dict[dst_type][edge_index[1]]  # [E, hidden]
            combined = torch.cat([src_emb, dst_emb], dim=-1)  # [E, 2*hidden]
            edge_probs[(src_type, rel, dst_type)] = self.edge_prob_head(combined)

        return risk_scores, edge_probs

    def _apply_control_suppression(
        self,
        edge_index_dict: Dict[tuple, torch.Tensor],
        edge_attr_dict: Dict[tuple, torch.Tensor],
        theta: Dict[str, torch.Tensor],
    ) -> Dict[tuple, torch.Tensor]:
        """
        Apply differentiable control suppression to edge attributes.
        High control deployment → reduced edge weight → less information flow
        along that edge type → lower risk propagation through graph.
        """
        suppressed = {}
        for edge_type, edge_index in edge_index_dict.items():
            _, rel, _ = edge_type
            attrs = edge_attr_dict.get(edge_type, torch.ones(edge_index.shape[1], 1))

            suppression = self._suppression_factor(rel, theta)
            suppressed[edge_type] = attrs * suppression

        return suppressed

    def _suppression_factor(
        self, rel: str, theta: Dict[str, torch.Tensor]
    ) -> torch.Tensor:
        """
        Map each edge relation type to its controlling theta parameters.
        All operations are differentiable — gradients flow through theta.
        """
        factors = {
            "KerberoastableVia":        1 - 0.80 * theta.get("aes_enforcement", torch.tensor(0.0)),
            "AuthenticatesViaNTLM":     1 - 0.70 * theta.get("ntlm_restriction", torch.tensor(0.0)),
            "NoMFAEnrolled":            1 - 0.90 * theta.get("mfa_coverage", torch.tensor(0.0)),
            "AdminTo":                  1 - 0.80 * theta.get("laps_deployed", torch.tensor(0.0)),
            "ESC1Vulnerable":           1 - 0.95 * theta.get("adcs_hardened", torch.tensor(0.0)),
            "DCSync":                   1 - 0.90 * theta.get("dcsync_audited", torch.tensor(0.0)),
            "UnconstrainedDelegation":  1 - 0.85 * theta.get("delegation_audit", torch.tensor(0.0)),
            "CanWriteRBCD":             1 - 0.80 * theta.get("rbcd_monitoring", torch.tensor(0.0)),
            "LocalAdminOverride":       1 - 0.60 * theta.get("local_admin_audit", torch.tensor(0.0)),
            "HasDangerousPrivilege":    1 - 0.80 * theta.get("edr_coverage", torch.tensor(0.0)),
            "LPEPathTo":                1 - 0.75 * theta.get("edr_coverage", torch.tensor(0.0)),
            "AgentCanAccess":           1 - 0.85 * theta.get("mcp_scope_restriction", torch.tensor(0.0)),
            "InjectionPathTo":          1 - 0.70 * theta.get("agent_content_isolation", torch.tensor(0.0)),
            "ADFSClaimGranted":         1 - 0.80 * theta.get("adfs_claim_review", torch.tensor(0.0)),
        }
        factor = factors.get(rel, torch.tensor(1.0))
        # Clamp to [0.01, 1.0] — never completely eliminate a path
        return torch.clamp(factor, min=0.01, max=1.0)


class HGTConvLayer(nn.Module):
    """
    Heterogeneous Graph Transformer convolution layer.
    
    This implements proper neighborhood attention where each destination node
    attends over its full set of incoming source nodes (not per-edge attention).
    
    Key design decisions:
    - Destination node is the query ("what do I need?")
    - Source nodes are keys/values ("what do I offer?")
    - Attention weights are learned per-relation type
    - Edge weights from control suppression modulate attention
    """

    def __init__(self, hidden_dim: int, num_heads: int,
                 edge_types: list, dropout: float = 0.1):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_heads = num_heads
        self.head_dim = hidden_dim // num_heads
        self.dropout = nn.Dropout(dropout)
        self.scale = (self.head_dim) ** -0.5

        # Per-relation Q/K/V projections (more efficient than MultiheadAttention for variable neighborhoods)
        self.rel_q = nn.ModuleDict()
        self.rel_k = nn.ModuleDict()
        self.rel_v = nn.ModuleDict()
        self.rel_msg = nn.ModuleDict()
        
        for src, rel, dst in edge_types:
            key = f"{src}__{rel}__{dst}"
            # Query from destination (what do I need?)
            self.rel_q[key] = nn.Linear(hidden_dim, hidden_dim, bias=False)
            # Key from source (what do I offer?)
            self.rel_k[key] = nn.Linear(hidden_dim, hidden_dim, bias=False)
            # Value from source (information to propagate)
            self.rel_v[key] = nn.Linear(hidden_dim, hidden_dim, bias=False)
            # Message transform
            self.rel_msg[key] = nn.Linear(hidden_dim, hidden_dim)

        # Per-relation importance weights (learned)
        self.rel_importance = nn.ParameterDict({
            f"{src}__{rel}__{dst}": nn.Parameter(torch.tensor(1.0))
            for src, rel, dst in edge_types
        })

        # Output projection per node type
        self.output_proj = nn.ModuleDict({
            nt: nn.Linear(hidden_dim, hidden_dim)
            for nt in NODE_FEATURE_DIMS
        })

        self.layer_norm = nn.ModuleDict({
            nt: nn.LayerNorm(hidden_dim)
            for nt in NODE_FEATURE_DIMS
        })

    def forward(
        self,
        h_dict: Dict[str, torch.Tensor],
        edge_index_dict: Dict[tuple, torch.Tensor],
        edge_attr_dict: Dict[tuple, torch.Tensor],
    ) -> Dict[str, torch.Tensor]:
        
        # Accumulate weighted messages per destination node type
        aggregated: Dict[str, list] = {nt: [] for nt in h_dict}
        importance_weights: Dict[str, list] = {nt: [] for nt in h_dict}

        for (src_type, rel, dst_type), edge_index in edge_index_dict.items():
            if src_type not in h_dict or dst_type not in h_dict:
                continue

            key = f"{src_type}__{rel}__{dst_type}"
            if key not in self.rel_q:
                continue

            src_features = h_dict[src_type]        # [N_src, D]
            dst_features = h_dict[dst_type]        # [N_dst, D]
            
            src_idx = edge_index[0]                # [E]
            dst_idx = edge_index[1]                # [E]
            
            if src_idx.numel() == 0:
                continue

            # Get features for edges
            src_h = src_features[src_idx]          # [E, D]
            dst_h = dst_features[dst_idx]          # [E, D]
            
            # Compute Q/K/V
            # Q from destination: "what does the destination need?"
            q = self.rel_q[key](dst_h)             # [E, D]
            # K from source: "what does the source offer?"
            k = self.rel_k[key](src_h)             # [E, D]
            # V from source: "what information to propagate"
            v = self.rel_v[key](src_h)             # [E, D]
            
            # Reshape for multi-head attention
            q = q.view(-1, self.num_heads, self.head_dim)  # [E, H, D/H]
            k = k.view(-1, self.num_heads, self.head_dim)  # [E, H, D/H]
            v = v.view(-1, self.num_heads, self.head_dim)  # [E, H, D/H]
            
            # Compute attention scores per edge
            # This gives each edge an attention weight based on Q-K similarity
            attn_scores = (q * k).sum(dim=-1) * self.scale  # [E, H]
            
            # Apply edge attribute weighting (from control suppression)
            edge_weight = edge_attr_dict.get((src_type, rel, dst_type))
            if edge_weight is not None:
                weight = edge_weight if edge_weight.dim() == 1 else edge_weight.squeeze(-1)
                attn_scores = attn_scores * weight.unsqueeze(-1)  # [E, H]
            
            # Softmax over each destination's neighborhood
            # We need to compute softmax per destination node across its incoming edges
            attn_probs = self._neighborhood_softmax(attn_scores, dst_idx, h_dict[dst_type].shape[0])
            
            # Weight values by attention
            weighted_v = v * attn_probs.unsqueeze(-1)  # [E, H, D/H]
            weighted_v = weighted_v.view(-1, self.hidden_dim)  # [E, D]
            
            # Transform message
            msg = self.rel_msg[key](weighted_v)    # [E, D]
            
            # Apply relation importance weight (learned)
            rel_weight = torch.sigmoid(self.rel_importance[key])
            msg = msg * rel_weight
            
            # Scatter aggregate to destination nodes
            num_dst = h_dict[dst_type].shape[0]
            agg = torch.zeros(num_dst, self.hidden_dim, device=msg.device)
            idx = dst_idx.unsqueeze(-1).expand(-1, self.hidden_dim)
            agg.scatter_add_(0, idx, msg)
            
            aggregated[dst_type].append(agg)
            importance_weights[dst_type].append(rel_weight.detach())

        # Combine aggregated messages with learned importance weighting
        out = {}
        for nt, h in h_dict.items():
            if aggregated[nt]:
                # Weight each relation's contribution by its learned importance
                weights = torch.stack([w for w in importance_weights[nt]])
                weights = F.softmax(weights, dim=0)
                
                messages = torch.stack(aggregated[nt], dim=0)  # [num_rels, N, D]
                combined = (messages * weights.view(-1, 1, 1)).sum(dim=0)  # [N, D]
                
                projected = self.output_proj[nt](combined)
                out[nt] = self.layer_norm[nt](h + self.dropout(projected))
            else:
                out[nt] = h
        return out
    
    def _neighborhood_softmax(
        self, 
        scores: torch.Tensor,      # [E, H]
        dst_idx: torch.Tensor,     # [E]
        num_dst: int,
    ) -> torch.Tensor:
        """
        Compute softmax over each destination node's neighborhood.
        This normalizes attention weights so they sum to 1 for each destination.
        """
        # Shift for numerical stability
        scores_max = torch.zeros(num_dst, scores.shape[1], device=scores.device)
        scores_max.scatter_reduce_(0, dst_idx.unsqueeze(-1).expand(-1, scores.shape[1]), 
                                   scores, reduce='amax', include_self=False)
        scores = scores - scores_max[dst_idx]
        
        # Compute exp
        exp_scores = torch.exp(scores)
        
        # Sum per destination
        exp_sum = torch.zeros(num_dst, scores.shape[1], device=scores.device)
        exp_sum.scatter_add_(0, dst_idx.unsqueeze(-1).expand(-1, scores.shape[1]), exp_scores)
        
        # Normalize
        return exp_scores / (exp_sum[dst_idx] + 1e-10)
