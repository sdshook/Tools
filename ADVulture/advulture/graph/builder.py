# (c) 2025 Shane D. Shook, PhD - All Rights Reserved

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
        """Authentication hygiene edges — Kerberoastable, AS-REP etc (Class A).
        
        Note: Kerberoastable status is already in feature vector index 3.
        This method adds explicit edges for graph-based risk propagation.
        """
        # AS-REP roastable edges (users who can be roasted to themselves as markers)
        asrep_users = []
        for u_idx, u in enumerate(self.snapshot.users):
            if u.no_preauth_required and u.enabled:
                asrep_users.append(u_idx)
        
        # RC4 downgrade edges from behavioral analysis
        rc4_src, rc4_dst = [], []
        if self.events:
            rc4_events = [e for e in self.events.filter(ids=[4769]) if e.is_rc4_downgrade]
            for event in rc4_events:
                if event.subject_sid in self.node_index and event.service_name:
                    _, src_idx = self.node_index[event.subject_sid]
                    # Link to service if known
                    rc4_src.append(src_idx)
                    rc4_dst.append(src_idx)  # Self-edge marks RC4 downgrade activity
        
        if rc4_src:
            data["User", "RC4DowngradeObserved", "User"].edge_index = torch.tensor(
                [rc4_src, rc4_dst], dtype=torch.long
            )

    def _add_authz_structural_edges(self, data) -> None:
        """ACL-based edges and ADCS (Class B)."""
        # ESC1 vulnerable template edges
        esc1_src, esc1_dst = [], []
        for t_idx, tmpl in enumerate(self.snapshot.cert_templates):
            if tmpl.esc1:
                # Connect all enabled users to vulnerable template
                # (represents enrollment capability)
                for u_idx, u in enumerate(self.snapshot.users):
                    if u.enabled:
                        esc1_src.append(u_idx)
                        esc1_dst.append(t_idx)
        
        # Assign template edges to graph if any exist
        if esc1_src:
            # Note: Requires adding CertTemplate node type to graph
            # For now, mark users with ESC1 access via self-edges
            data["User", "ESC1Vulnerable", "User"].edge_index = torch.tensor(
                [esc1_src, esc1_src], dtype=torch.long
            )
        
        # Nested group membership (transitive closure)
        group_to_group_src, group_to_group_dst = [], []
        for g_idx, g in enumerate(self.snapshot.groups):
            for member_dn in g.member_of:
                if member_dn in self.node_index:
                    _, parent_idx = self.node_index[member_dn]
                    group_to_group_src.append(g_idx)
                    group_to_group_dst.append(parent_idx)
        
        if group_to_group_src:
            data["Group", "MemberOf", "Group"].edge_index = torch.tensor(
                [group_to_group_src, group_to_group_dst], dtype=torch.long
            )
        
        # ACL-based dangerous edges from security descriptor parsing
        self._add_acl_edges(data)
    
    def _add_acl_edges(self, data) -> None:
        """Add edges from parsed ACL security descriptors (GenericAll, WriteDacl, DCSync)."""
        if not self.snapshot.acl_edges:
            return
        
        # Group edges by type for efficient tensor construction
        generic_all_src, generic_all_dst = [], []
        write_dacl_src, write_dacl_dst = [], []
        dcsync_src, dcsync_dst = [], []
        
        for edge in self.snapshot.acl_edges:
            # Resolve source SID to node index
            if edge.source_sid not in self.node_index:
                continue
            src_type, src_idx = self.node_index[edge.source_sid]
            
            # Resolve target DN to node index
            if edge.target_dn not in self.node_index:
                continue
            dst_type, dst_idx = self.node_index[edge.target_dn]
            
            # Only handle User -> User edges for now
            # (most dangerous attack paths)
            if src_type != "User":
                continue
            
            if edge.right_type == "GenericAll":
                generic_all_src.append(src_idx)
                generic_all_dst.append(dst_idx)
            elif edge.right_type == "WriteDacl":
                write_dacl_src.append(src_idx)
                write_dacl_dst.append(dst_idx)
            elif edge.right_type in ("DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All"):
                dcsync_src.append(src_idx)
                dcsync_dst.append(dst_idx)
        
        # Add GenericAll edges
        if generic_all_src:
            data["User", "GenericAll", "User"].edge_index = torch.tensor(
                [generic_all_src, generic_all_dst], dtype=torch.long
            )
            log.info("Added %d GenericAll edges", len(generic_all_src))
        
        # Add WriteDacl edges
        if write_dacl_src:
            data["User", "WriteDacl", "User"].edge_index = torch.tensor(
                [write_dacl_src, write_dacl_dst], dtype=torch.long
            )
            log.info("Added %d WriteDacl edges", len(write_dacl_src))
        
        # Add DCSync edges (mark users with DCSync rights)
        if dcsync_src:
            data["User", "DCSync", "User"].edge_index = torch.tensor(
                [dcsync_src, dcsync_src], dtype=torch.long  # Self-edge to mark capability
            )
            log.info("Added %d DCSync capable users", len(dcsync_src))

    def _add_authz_behavioural_edges(self, data) -> None:
        """Behavioural edges from event log analysis (Class C)."""
        # High anomaly score edges - users accessing resources anomalously
        anomaly_src, anomaly_dst = [], []
        for (sid, resource), tensor in self._edge_tensors.items():
            if tensor.anomaly_score > 0.7 and sid in self.node_index:
                _, src_idx = self.node_index[sid]
                # Try to resolve resource to a computer node
                resource_lower = resource.lower()
                if resource_lower in self.node_index:
                    _, dst_idx = self.node_index[resource_lower]
                    anomaly_src.append(src_idx)
                    anomaly_dst.append(dst_idx)
        
        if anomaly_src:
            data["User", "AnomalousAccess", "Computer"].edge_index = torch.tensor(
                [anomaly_src, anomaly_dst], dtype=torch.long
            )

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
        """Delegation edges (Class E).
        
        For unconstrained delegation machines, edges are created to users
        who have actually authenticated to them (per 4624 events), not
        to all users. This reflects actual credential exposure.
        """
        unc_src, unc_dst = [], []
        
        # Build index of computers with unconstrained delegation
        unc_deleg_computers = {}
        for c_idx, computer in enumerate(self.snapshot.computers):
            # Check if DC by OS name (ADComputer doesn't have is_domain_controller property)
            is_dc = "domain controller" in computer.os.lower()
            if computer.unconstrained_delegation and not is_dc:
                hostname = (computer.dns_hostname or computer.sam_account_name).lower()
                unc_deleg_computers[hostname] = c_idx
        
        if unc_deleg_computers and self.events:
            # Find users who authenticated to unconstrained delegation machines
            for event in self.events.filter(ids=[4624]):
                target_host = event.source_host.lower()
                if target_host in unc_deleg_computers:
                    c_idx = unc_deleg_computers[target_host]
                    # Find the user who authenticated
                    if event.subject_sid in self.node_index:
                        _, u_idx = self.node_index[event.subject_sid]
                        unc_src.append(c_idx)
                        unc_dst.append(u_idx)
        
        # Deduplicate edges
        if unc_src:
            edges_set = set(zip(unc_src, unc_dst))
            unc_src = [e[0] for e in edges_set]
            unc_dst = [e[1] for e in edges_set]
            data["Computer", "UnconstrainedDelegation", "User"].edge_index = torch.tensor(
                [unc_src, unc_dst], dtype=torch.long
            )
        
        # RBCD edges
        rbcd_src, rbcd_dst = [], []
        for c_idx, computer in enumerate(self.snapshot.computers):
            if computer.rbcd_principals:
                for principal_sid in computer.rbcd_principals:
                    if principal_sid in self.node_index:
                        node_type, p_idx = self.node_index[principal_sid]
                        if node_type == "User":
                            rbcd_src.append(p_idx)
                            rbcd_dst.append(c_idx)
        
        if rbcd_src:
            data["User", "RBCDConfigured", "Computer"].edge_index = torch.tensor(
                [rbcd_src, rbcd_dst], dtype=torch.long
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
