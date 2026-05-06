"""
ADVulture — Graph Builder
Constructs a PyTorch Geometric HeteroData graph from the AD snapshot
and event-log behavioural tensors. All six risk classes contribute
nodes, edges, and features simultaneously.
"""

from __future__ import annotations
import logging
from typing import Dict, List, Optional, Tuple
import numpy as np
import torch

from advulture.collection.ldap_enumerator import ADSnapshot, ADUser, ADComputer
from advulture.collection.log_ingester import EventStream, EdgeTensor

log = logging.getLogger(__name__)


class GraphBuilder:
    """
    Converts ADSnapshot + EventStream into a heterogeneous graph
    suitable for the GNN. Node indices are assigned per type and
    stored in self.node_index for cross-referencing.
    """

    def __init__(self, snapshot: ADSnapshot, events: Optional[EventStream] = None):
        self.snapshot = snapshot
        self.events = events
        # Maps: sid/dn → (node_type, node_idx)
        self.node_index: Dict[str, Tuple[str, int]] = {}
        self._edge_tensors: Dict[tuple, EdgeTensor] = {}

        if events:
            self._edge_tensors = events.build_edge_tensors()

    def build(self) -> "HeteroData":
        """Build and return the complete heterogeneous graph."""
        try:
            from torch_geometric.data import HeteroData
        except ImportError:
            log.warning("torch_geometric not installed; returning mock graph")
            return self._mock_graph()

        data = HeteroData()

        # Assign node indices and build feature matrices
        user_features  = self._build_user_features()
        comp_features  = self._build_computer_features()
        group_features = self._build_group_features()

        data["User"].x    = torch.tensor(user_features,  dtype=torch.float32)
        data["Computer"].x= torch.tensor(comp_features,  dtype=torch.float32)
        data["Group"].x   = torch.tensor(group_features, dtype=torch.float32)

        # Build edges
        self._add_membership_edges(data)
        self._add_authn_edges(data)
        self._add_authz_structural_edges(data)
        self._add_authz_behavioural_edges(data)
        self._add_lpe_edges(data)
        self._add_delegation_edges(data)

        log.info(
            "Graph built: %d users, %d computers, %d groups",
            len(self.snapshot.users),
            len(self.snapshot.computers),
            len(self.snapshot.groups),
        )
        return data

    # ── Node features ─────────────────────────────────────────────────────────

    def _build_user_features(self) -> np.ndarray:
        """22-dimensional feature vector per user (all six risk classes)."""
        rows = []
        for i, u in enumerate(self.snapshot.users):
            self.node_index[u.sid] = ("User", i)
            self.node_index[u.distinguished_name] = ("User", i)

            row = [
                # Class A — AuthN Hygiene
                min(u.password_age_days / 365.0, 5.0),          # 0
                float(u.password_never_expires),                  # 1
                float(u.no_preauth_required),                     # 2
                float(u.has_spn),                                 # 3
                float(not u.enabled),                             # 4  (disabled)
                min(u.days_since_last_logon / 365.0, 5.0),       # 5
                float(u.admin_count > 0),                         # 6
                # Class B — AuthZ Structure
                float(u.tier),                                    # 7
                float(u.tier == 0),                               # 8  is tier0
                float(len(u.member_of) > 10),                    # 9  many groups
                # Class C — AuthZ Behaviour (from events)
                self._user_shadow_access_score(u.sid),            # 10
                self._user_ntlm_ratio(u.sid),                     # 11
                self._user_off_hours_ratio(u.sid),                # 12
                # Class D — LPE
                self._user_has_lpe_signal(u.sid),                 # 13
                # Class E — Delegation
                float(u.delegation_type == "unconstrained"),      # 14
                float(u.delegation_type == "constrained"),        # 15
                float(len(u.constrained_delegation_targets) > 0), # 16
                # Class F — AI Agent
                self._is_ai_identity(u.sam_account_name),         # 17
                # Compound signals
                float(u.has_spn and u.delegation_type != "none"), # 18 kerberoas+deleg
                float(u.tier == 0 and u.days_since_last_logon > 180), # 19 stale tier0
                float(u.password_age_days > 365 and u.has_spn),  # 20 old+kerberoast
                float(u.admin_count > 0 and not u.enabled),       # 21 orphaned admin
            ]
            rows.append(row)
        return np.array(rows, dtype=np.float32) if rows else np.zeros((0, 22), dtype=np.float32)

    def _build_computer_features(self) -> np.ndarray:
        """14-dimensional feature vector per computer."""
        rows = []
        for i, c in enumerate(self.snapshot.computers):
            self.node_index[c.sid] = ("Computer", i)
            self.node_index[c.distinguished_name] = ("Computer", i)
            if c.dns_hostname:
                self.node_index[c.dns_hostname.lower()] = ("Computer", i)

            is_dc = "domain controller" in c.os.lower()
            has_laps = c.laps_expiry is not None

            row = [
                float(c.tier),                                    # 0
                float(is_dc),                                     # 1
                float(c.enabled),                                 # 2
                float(c.unconstrained_delegation and not is_dc),  # 3
                float(len(c.constrained_delegation_targets) > 0), # 4
                float(len(c.rbcd_principals) > 0),                # 5
                float(has_laps),                                   # 6
                float(len(c.service_principal_names) > 3),        # 7 many SPNs
                # Behavioural
                self._host_lpe_score(c.dns_hostname or c.sam_account_name), # 8
                self._host_ntlm_ratio(c.dns_hostname or c.sam_account_name),# 9
                self._host_has_tier0_sessions(c.dns_hostname or ""),         # 10
                # Compound
                float(c.unconstrained_delegation and self._host_has_tier0_sessions(c.dns_hostname or "")), # 11
                float(not has_laps and c.tier <= 1),              # 12 no LAPS, high tier
                float(len(c.rbcd_principals) > 0 and len(c.constrained_delegation_targets) > 0), # 13
            ]
            rows.append(row)
        return np.array(rows, dtype=np.float32) if rows else np.zeros((0, 14), dtype=np.float32)

    def _build_group_features(self) -> np.ndarray:
        """6-dimensional feature vector per group."""
        rows = []
        for i, g in enumerate(self.snapshot.groups):
            self.node_index[g.sid] = ("Group", i)
            self.node_index[g.distinguished_name] = ("Group", i)
            rows.append([
                float(g.admin_count > 0),
                float(len(g.members) > 50),
                float(len(g.member_of) > 5),
                float("admin" in g.sam_account_name.lower()),
                float("domain admin" in g.sam_account_name.lower()),
                float("enterprise" in g.sam_account_name.lower()),
            ])
        return np.array(rows, dtype=np.float32) if rows else np.zeros((0, 6), dtype=np.float32)

    # ── Edge builders ─────────────────────────────────────────────────────────

    def _add_membership_edges(self, data) -> None:
        """MemberOf and AdminTo edges (Class B)."""
        user_to_group_src, user_to_group_dst = [], []
        for u_idx, u in enumerate(self.snapshot.users):
            for group_dn in u.member_of:
                if group_dn in self.node_index:
                    _, g_idx = self.node_index[group_dn]
                    user_to_group_src.append(u_idx)
                    user_to_group_dst.append(g_idx)
        if user_to_group_src:
            data["User", "MemberOf", "Group"].edge_index = torch.tensor(
                [user_to_group_src, user_to_group_dst], dtype=torch.long
            )

    def _add_authn_edges(self, data) -> None:
        """Authentication hygiene edges — Kerberoastable, AS-REP etc (Class A)."""
        kerb_src, kerb_dst = [], []
        for u_idx, u in enumerate(self.snapshot.users):
            if u.has_spn and u.enabled:
                kerb_src.append(u_idx)
                kerb_dst.append(u_idx)  # self-loop marks the attribute
        if kerb_src:
            data["User", "KerberoastableVia", "User"].edge_index = torch.tensor(
                [kerb_src, kerb_dst], dtype=torch.long
            )

    def _add_authz_structural_edges(self, data) -> None:
        """ACL-based edges and ADCS (Class B)."""
        esc1_src, esc1_dst = [], []
        for t_idx, tmpl in enumerate(self.snapshot.cert_templates):
            if tmpl.esc1:
                # All users can enroll → ESC1 edge to all users (simplified)
                for u_idx in range(min(len(self.snapshot.users), 5)):
                    esc1_src.append(u_idx)
                    esc1_dst.append(t_idx)
        # Additional ACL edges would be added here from ACL parser

    def _add_authz_behavioural_edges(self, data) -> None:
        """Behavioural edges from event log analysis (Class C)."""
        shadow_src, shadow_dst = [], []
        for (sid, resource), tensor in self._edge_tensors.items():
            if tensor.anomaly_score > 0.7 and sid in self.node_index:
                _, src_idx = self.node_index[sid]
                shadow_src.append(src_idx)
                shadow_dst.append(src_idx)  # resource nodes added in full implementation
        # Full implementation maps resources to Resource node type

    def _add_lpe_edges(self, data) -> None:
        """LPE privilege edges from 4672 events (Class D)."""
        lpe_src, lpe_dst = [], []
        if not self.events:
            return
        for event in self.events.filter(ids=[4672]):
            if not event.has_dangerous_privilege:
                continue
            sid = event.subject_sid
            host = event.source_host.lower()
            if sid in self.node_index and host in self.node_index:
                _, u_idx = self.node_index[sid]
                _, c_idx = self.node_index[host]
                lpe_src.append(u_idx)
                lpe_dst.append(c_idx)
        if lpe_src:
            data["User", "HasDangerousPrivilege", "Computer"].edge_index = torch.tensor(
                [lpe_src, lpe_dst], dtype=torch.long
            )

    def _add_delegation_edges(self, data) -> None:
        """Delegation edges (Class E)."""
        unc_src, unc_dst = [], []
        for c_idx, computer in enumerate(self.snapshot.computers):
            if computer.unconstrained_delegation:
                for u_idx in range(min(len(self.snapshot.users), 3)):
                    unc_src.append(c_idx)
                    unc_dst.append(u_idx)
        if unc_src:
            data["Computer", "UnconstrainedDelegation", "User"].edge_index = torch.tensor(
                [unc_src, unc_dst], dtype=torch.long
            )

    # ── Behavioural signal helpers ────────────────────────────────────────────

    def _user_shadow_access_score(self, sid: str) -> float:
        relevant = [t for (s, _), t in self._edge_tensors.items() if s == sid]
        if not relevant:
            return 0.0
        scores = [t.anomaly_score for t in relevant]
        return float(np.mean(scores))

    def _user_ntlm_ratio(self, sid: str) -> float:
        relevant = [t for (s, _), t in self._edge_tensors.items() if s == sid]
        if not relevant:
            return 0.0
        return float(np.mean([t.ntlm_ratio for t in relevant]))

    def _user_off_hours_ratio(self, sid: str) -> float:
        relevant = [t for (s, _), t in self._edge_tensors.items() if s == sid]
        if not relevant:
            return 0.0
        return float(np.mean([t.off_hours_ratio for t in relevant]))

    def _user_has_lpe_signal(self, sid: str) -> float:
        if not self.events:
            return 0.0
        events = [e for e in self.events.filter(ids=[4672])
                  if e.subject_sid == sid and e.has_dangerous_privilege]
        return 1.0 if events else 0.0

    def _host_lpe_score(self, hostname: str) -> float:
        if not self.events:
            return 0.0
        events = [e for e in self.events.filter(ids=[4672])
                  if e.source_host.lower() == hostname.lower()
                  and e.has_dangerous_privilege]
        return min(1.0, len(events) / 10.0)

    def _host_ntlm_ratio(self, hostname: str) -> float:
        relevant = [t for (_, dst), t in self._edge_tensors.items()
                    if dst.lower() == hostname.lower()]
        if not relevant:
            return 0.0
        return float(np.mean([t.ntlm_ratio for t in relevant]))

    def _host_has_tier0_sessions(self, hostname: str) -> float:
        if not self.events or not hostname:
            return 0.0
        tier0_sids = {u.sid for u in self.snapshot.users if u.tier == 0}
        sessions = [
            e for e in self.events.filter(ids=[4624])
            if e.source_host.lower() == hostname.lower()
            and e.subject_sid in tier0_sids
        ]
        return 1.0 if sessions else 0.0

    def _is_ai_identity(self, sam: str) -> float:
        ai_patterns = ["copilot", "openai", "llm", "gpt", "agent", "mcp", "langchain"]
        return 1.0 if any(p in sam.lower() for p in ai_patterns) else 0.0

    def _mock_graph(self):
        """Return a simple namespace when torch_geometric is unavailable."""
        class MockGraph:
            node_types = ["User", "Computer", "Group"]
        return MockGraph()
