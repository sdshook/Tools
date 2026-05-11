# (c) 2025 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture — PostureAnalyzer
Unified entry point that orchestrates collection, graph building,
GNN inference, Markov analysis, gradient computation, and reporting.
All six risk classes are evaluated simultaneously.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict
import torch

from advulture.analysis.finding import Finding, RiskClass, Severity
from advulture.analysis.finding import (
    make_kerberoast_finding, make_esc1_finding,
    make_unconstrained_delegation_finding, make_lpe_finding,
    make_shadow_admin_finding, make_ai_agent_finding,
)
from advulture.ml.markov.chain import (
    AttackChainMarkov, KillChainHMM, GradientEngine,
    PhaseDetection, RemediationItem, Phase,
)
from advulture.config import Config

log = logging.getLogger(__name__)


@dataclass
class ScenarioResult:
    controls_proposed: Dict[str, float]
    baseline_tier0_prob: float
    scenario_tier0_prob: float
    absolute_reduction: float
    pct_reduction: float
    description: str = ""


@dataclass
class PostureReport:
    timestamp: datetime
    domain: str
    deployment_type: str              # on_prem / hybrid / cloud_only

    # Regime
    regime: str                        # ORDERED / CRITICAL / CHAOTIC
    regime_explanation: str

    # Markov outputs
    tier0_steady_state_probability: float
    mean_steps_to_tier0: float
    most_exposed_nodes: List[int] = field(default_factory=list)

    # Attacker phase
    attacker_phase: Optional[PhaseDetection] = None

    # All findings unified and ranked
    findings: List[Finding] = field(default_factory=list)
    remediation_ranking: List[RemediationItem] = field(default_factory=list)

    # RF scenario
    best_scenario: Optional[ScenarioResult] = None

    # Trajectory
    trajectory_30d: List[float] = field(default_factory=list)

    # Active signals
    active_signals: List[str] = field(default_factory=list)

    # Per-class counts
    finding_counts: Dict[str, int] = field(default_factory=dict)

    def summary(self) -> str:
        counts_str = "  ".join(
            f"[{cls}] {cnt}" for cls, cnt in self.finding_counts.items()
        )
        return (
            f"ADVulture Posture Report — {self.domain}\n"
            f"{'=' * 60}\n"
            f"Regime: {self.regime}  |  π_tier0: {self.tier0_steady_state_probability:.1%}  "
            f"|  Mean steps to DA: {self.mean_steps_to_tier0:.1f}\n"
            f"Phase: {self.attacker_phase.most_likely.name if self.attacker_phase else 'UNKNOWN'}  "
            f"|  Active signals: {len(self.active_signals)}\n"
            f"Findings: {counts_str}  |  Total: {len(self.findings)}\n"
        )

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "domain": self.domain,
            "regime": self.regime,
            "tier0_probability": round(self.tier0_steady_state_probability, 4),
            "mean_steps_to_tier0": round(self.mean_steps_to_tier0, 2),
            "attacker_phase": self.attacker_phase.most_likely.name
                if self.attacker_phase else "UNKNOWN",
            "phase_confidence": round(self.attacker_phase.confidence, 3)
                if self.attacker_phase else 0,
            "finding_counts": self.finding_counts,
            "total_findings": len(self.findings),
            "active_signals": self.active_signals,
            "remediation_top10": [
                {
                    "rank": i + 1,
                    "control": item.control,
                    "gradient": round(item.gradient, 4),
                    "risk_classes": item.risk_classes_affected,
                    "explanation": item.explanation,
                }
                for i, item in enumerate(self.remediation_ranking[:10])
            ],
            "findings": [f.to_dict() for f in self.findings],
        }


class PostureAnalyzer:
    """
    Main analysis orchestrator. Connects all subsystems and produces
    a unified PostureReport with findings from all six risk classes.
    """

    def __init__(self, config: Config):
        self.config = config
        self.hmm = KillChainHMM()
        self.gradient_engine = GradientEngine()

    def analyze(
        self,
        controls: Optional[Dict[str, float]] = None,
        evtx_paths: Optional[List] = None,
    ) -> PostureReport:
        """
        Run complete posture analysis.
        Controls: current deployment level for each security control [0,1].
        """
        if controls is None:
            controls = self._default_controls()

        log.info("Starting ADVulture posture analysis")

        # ── Collection ────────────────────────────────────────────────────
        snapshot = self._collect_ad(evtx_paths)
        event_stream = self._collect_logs(evtx_paths)

        # Entra ID (if configured)
        entra_snapshot = None
        if self.config.entra.enabled:
            entra_snapshot = self._collect_entra()

        # ADFS (if configured)
        adfs_surface = None
        if self.config.adfs.enabled:
            adfs_surface = self._collect_adfs(event_stream)

        # ── Findings from static analysis ─────────────────────────────────
        findings: List[Finding] = []
        findings += self._analyze_authn_hygiene(snapshot, event_stream)
        findings += self._analyze_authz_structure(snapshot)
        findings += self._analyze_authz_behaviour(snapshot, event_stream, adfs_surface)
        findings += self._analyze_lpe(event_stream)
        findings += self._analyze_delegation(snapshot, event_stream)
        if entra_snapshot:
            findings += self._analyze_ai_agents(entra_snapshot)

        # ── HMM phase detection ────────────────────────────────────────────
        event_sequence = self._build_event_sequence(event_stream)
        graph_stats = self._compute_graph_stats(snapshot, findings)
        phase_detection = self.hmm.viterbi(event_sequence, graph_stats)
        log.info(
            "HMM: phase=%s confidence=%.0f%% velocity=%.2f",
            phase_detection.most_likely.name,
            phase_detection.confidence * 100,
            phase_detection.threat_velocity,
        )

        # ── Markov analysis ────────────────────────────────────────────────
        num_nodes = len(snapshot.users) + len(snapshot.computers) + len(snapshot.groups)
        tier0_ids = [
            i for i, u in enumerate(snapshot.users) if u.tier == 0
        ]
        markov = AttackChainMarkov(
            num_nodes=max(num_nodes, 10),
            tier0_node_ids=tier0_ids or [0],
        )
        edge_index, edge_probs = self._build_graph_tensors(snapshot, event_stream)
        theta = {
            k: torch.tensor(v, dtype=torch.float32, requires_grad=True)
            for k, v in controls.items()
        }
        lpe_pairs = self._build_lpe_pairs(findings)
        mc_result = markov.analyze(edge_index, edge_probs, theta, lpe_pairs)

        # ── Gradient ranking ───────────────────────────────────────────────
        ranking = self.gradient_engine.compute_ranking(
            edge_index, edge_probs, controls, phase_detection, markov, lpe_pairs
        )

        # ── Attach gradient contributions to findings ──────────────────────
        ctrl_to_findings = self._map_controls_to_findings(findings)
        for item in ranking:
            for fid in ctrl_to_findings.get(item.control, []):
                matching = [f for f in findings if f.id == fid]
                for f in matching:
                    f.gradient_contribution = max(f.gradient_contribution, item.gradient)

        # Sort all findings by gradient contribution
        findings.sort(key=lambda f: f.gradient_contribution, reverse=True)

        # ── Regime classification ──────────────────────────────────────────
        regime, regime_explanation = self._classify_regime(mc_result, ranking)

        # ── Active signals ─────────────────────────────────────────────────
        active_signals = self._extract_active_signals(findings, event_stream)

        # ── Finding counts ─────────────────────────────────────────────────
        counts = {cls.value: 0 for cls in RiskClass}
        for f in findings:
            counts[f.risk_class.value] += 1

        report = PostureReport(
            timestamp=datetime.now(timezone.utc),
            domain=snapshot.domain,
            deployment_type="hybrid" if entra_snapshot else "on_prem",
            regime=regime,
            regime_explanation=regime_explanation,
            tier0_steady_state_probability=mc_result.tier0_probability,
            mean_steps_to_tier0=mc_result.mean_steps_to_tier0,
            most_exposed_nodes=mc_result.most_exposed_nodes,
            attacker_phase=phase_detection,
            findings=findings,
            remediation_ranking=ranking,
            active_signals=active_signals,
            finding_counts=counts,
        )

        log.info("Analysis complete. %d findings. Regime: %s. π_tier0: %.1f%%",
                 len(findings), regime, mc_result.tier0_probability * 100)
        return report

    # ── Risk class analyzers ───────────────────────────────────────────────────

    def _analyze_authn_hygiene(self, snapshot, events) -> List[Finding]:
        """Class A: AuthN hygiene findings from LDAP + event logs."""
        findings = []

        # Kerberoastable accounts
        kerberoastable = [
            u.sam_account_name for u in snapshot.users
            if u.has_spn and u.enabled
        ]
        if kerberoastable:
            # Check for active RC4 spray signal
            rc4_count = events.count(4769) if events else 0
            active = rc4_count > 100
            findings.append(make_kerberoast_finding(kerberoastable, active=active))

        # AS-REP roastable accounts
        asrep = [
            u.sam_account_name for u in snapshot.users
            if u.no_preauth_required and u.enabled
        ]
        if asrep:
            findings.append(Finding(
                category="asrep_roastable",
                title=f"AS-REP Roastable Accounts: {len(asrep)} affected",
                risk_class=RiskClass.AUTHN_HYGIENE,
                severity=Severity.HIGH,
                affected_identities=asrep,
                evidence_sources=["ldap_uac_dont_req_preauth"],
                mitre_techniques=["T1558.004"],
                controls=["preauth_enforcement"],
                remediation_steps=[
                    "Disable 'Do not require Kerberos preauthentication' on all user accounts",
                    "Audit accounts with DONT_REQ_PREAUTH UAC flag set",
                    "If required for application compatibility, isolate accounts and monitor 4768",
                ],
            ))

        # Stale privileged accounts
        stale_admins = [
            u.sam_account_name for u in snapshot.users
            if u.tier <= 1 and u.days_since_last_logon > 90 and u.enabled
        ]
        if stale_admins:
            findings.append(Finding(
                category="stale_privileged_account",
                title=f"Stale Privileged Accounts: {len(stale_admins)} inactive >90d",
                risk_class=RiskClass.AUTHN_HYGIENE,
                severity=Severity.MEDIUM,
                affected_identities=stale_admins,
                evidence_sources=["ldap_lastlogontimestamp"],
                controls=["account_lifecycle"],
                remediation_steps=[
                    "Disable accounts inactive >90 days",
                    "Implement regular access reviews for privileged accounts",
                    "Automate stale account detection and notification",
                ],
            ))

        # Password age violations
        old_password_admins = [
            u.sam_account_name for u in snapshot.users
            if u.tier <= 1 and u.password_age_days > 365 and u.enabled
        ]
        if old_password_admins:
            findings.append(Finding(
                category="privileged_account_old_password",
                title=f"Privileged Accounts: Password Age >365 Days ({len(old_password_admins)})",
                risk_class=RiskClass.AUTHN_HYGIENE,
                severity=Severity.HIGH,
                affected_identities=old_password_admins,
                evidence_sources=["ldap_pwdlastset"],
                controls=["service_account_managed_passwords"],
                remediation_steps=[
                    "Enforce password rotation policy for privileged accounts",
                    "Implement Group Managed Service Accounts (gMSA) for service accounts",
                    "Set Fine-Grained Password Policy: max 90 days for Tier 0/1 accounts",
                ],
            ))

        return findings

    def _analyze_authz_structure(self, snapshot) -> List[Finding]:
        """Class B: Static AuthZ structure from LDAP ACLs and ADCS."""
        findings = []

        # ADCS ESC1
        esc1_templates = [t.name for t in snapshot.cert_templates if t.esc1]
        if esc1_templates:
            findings.append(make_esc1_finding(esc1_templates))

        # Unconstrained delegation
        unconstrained = [
            c.dns_hostname or c.sam_account_name
            for c in snapshot.computers
            if c.unconstrained_delegation
               and "domain controller" not in c.os.lower()  # DCs exempt
        ]
        if unconstrained:
            findings.append(make_unconstrained_delegation_finding(unconstrained))

        # Trust without SID filtering
        unsafe_trusts = [
            t.name for t in snapshot.trusts
            if not t.sid_filtering_enabled
               and t.trust_direction in (2, 3)  # outbound or bidirectional
        ]
        if unsafe_trusts:
            findings.append(Finding(
                category="trust_no_sid_filtering",
                title=f"Domain Trust Without SID Filtering: {len(unsafe_trusts)} trust(s)",
                risk_class=RiskClass.AUTHZ_STRUCTURE,
                severity=Severity.CRITICAL,
                affected_resources=unsafe_trusts,
                evidence_sources=["ldap_trustattributes"],
                mitre_techniques=["T1134.005"],
                controls=["sid_filtering"],
                remediation_steps=[
                    "Enable SID filtering on all external trusts",
                    "Enable Selective Authentication on forest trusts",
                    "Audit cross-domain group memberships",
                ],
            ))

        return findings

    def _analyze_authz_behaviour(self, snapshot, events, adfs_surface) -> List[Finding]:
        """Class C: Behavioural AuthZ findings from event log analysis."""
        findings = []

        if events and adfs_surface:
            if adfs_surface.claim_rule_changes:
                findings.append(Finding(
                    category="adfs_claim_rule_modified",
                    title=f"ADFS Claim Rules Modified: {len(adfs_surface.claim_rule_changes)} change(s)",
                    risk_class=RiskClass.AUTHZ_BEHAVIOUR,
                    severity=Severity.CRITICAL,
                    evidence_sources=["adfs_event_403"],
                    active_signal=True,
                    mitre_techniques=["T1484.002"],
                    controls=["adfs_claim_review"],
                    remediation_steps=[
                        "Review all recent claim rule modifications",
                        "Verify relying party token issuance rules",
                        "Enable ADFS audit logging for all claim operations",
                        "Implement change control for ADFS configuration",
                    ],
                ))

            if adfs_surface.golden_saml_suspects:
                findings.append(Finding(
                    category="golden_saml_indicator",
                    title=f"Golden SAML Indicators: {len(adfs_surface.golden_saml_suspects)} suspicious token(s)",
                    risk_class=RiskClass.AUTHZ_BEHAVIOUR,
                    severity=Severity.CRITICAL,
                    active_signal=True,
                    evidence_sources=["adfs_event_299"],
                    mitre_techniques=["T1606.002"],
                    controls=["adfs_token_signing_rotation"],
                    remediation_steps=[
                        "Rotate ADFS token signing certificate immediately",
                        "Review ADFS server access logs and event 1007",
                        "Audit ADFS configuration database access",
                        "Consider rebuilding ADFS infrastructure if compromise suspected",
                    ],
                ))

        return findings

    def _analyze_lpe(self, events) -> List[Finding]:
        """Class D: Privilege escalation surface from event logs."""
        findings = []
        if not events:
            return findings

        dangerous_priv_events = [
            e for e in events.filter(ids=[4672])
            if e.has_dangerous_privilege
        ]
        if dangerous_priv_events:
            affected_accounts = list({e.subject_account for e in dangerous_priv_events})
            affected_hosts = list({e.source_host for e in dangerous_priv_events})
            findings.append(make_lpe_finding(
                accounts=affected_accounts,
                hosts=affected_hosts,
                privilege="SeImpersonatePrivilege / SeDebugPrivilege",
            ))

        # DCSync attempts
        dcsync_events = [e for e in events.filter(ids=[4662]) if e.is_dcsync]
        non_dc_dcsync = [
            e for e in dcsync_events if "dc" not in e.source_host.lower()
        ]
        if non_dc_dcsync:
            findings.append(Finding(
                category="dcsync_by_non_dc",
                title=f"DCSync from Non-Domain Controller: {len(non_dc_dcsync)} event(s)",
                risk_class=RiskClass.PRIVILEGE_ESCALATION,
                severity=Severity.CRITICAL,
                active_signal=True,
                affected_identities=[e.subject_account for e in non_dc_dcsync],
                affected_hosts=[e.source_host for e in non_dc_dcsync],
                evidence_sources=["4662_replication_guid"],
                mitre_techniques=["T1003.006"],
                controls=["dcsync_audited"],
                remediation_steps=[
                    "Immediately isolate accounts performing unauthorised DCSync",
                    "Audit replication rights on domain — remove from non-admin accounts",
                    "Review AdminSDHolder ACL for unexpected entries",
                    "Change krbtgt password twice to invalidate Kerberos tickets",
                ],
            ))

        return findings

    def _analyze_delegation(self, snapshot, events) -> List[Finding]:
        """Class E: Delegation override findings."""
        findings = []

        # RBCD misconfiguration
        rbcd_computers = [
            c.dns_hostname for c in snapshot.computers
            if c.rbcd_principals
        ]
        if rbcd_computers:
            findings.append(Finding(
                category="rbcd_configured",
                title=f"Resource-Based Constrained Delegation: {len(rbcd_computers)} computer(s)",
                risk_class=RiskClass.DELEGATION_OVERRIDE,
                severity=Severity.HIGH,
                affected_hosts=rbcd_computers,
                evidence_sources=["ldap_msds_allowedtoact"],
                mitre_techniques=["T1558"],
                controls=["rbcd_monitoring"],
                remediation_steps=[
                    "Audit msDS-AllowedToActOnBehalfOfOtherIdentity attribute on all computers",
                    "Remove RBCD configuration unless explicitly required",
                    "Audit write rights to this attribute — any writer can configure delegation",
                    "Monitor for S4U2Proxy Kerberos events (4769 with delegation fields)",
                ],
            ))

        return findings

    def _analyze_ai_agents(self, entra_snapshot) -> List[Finding]:
        """Class F: AI agent authorization surface."""
        findings = []
        ai_agents = [
            sp.display_name for sp in entra_snapshot.service_principals
            if sp.is_ai_agent and sp.account_enabled
        ]
        if ai_agents:
            findings.append(make_ai_agent_finding(
                agents=ai_agents,
                vectors=["email_content", "document_content"],
            ))
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _collect_ad(self, evtx_paths):
        from advulture.collection.ldap_enumerator import LDAPEnumerator, ADSnapshot
        from advulture.config import LDAPAuthMode
        from datetime import datetime, timezone
        cfg = self.config.ldap
        
        # Determine if we should attempt LDAP collection
        # PROMPT and KERBEROS modes support auto-discovery (no server required)
        # LDAPEnumerator.connect() handles DNS SRV lookup for DC discovery
        should_collect = (
            cfg.auth_mode == LDAPAuthMode.KERBEROS or
            cfg.auth_mode == LDAPAuthMode.PROMPT or
            (cfg.server and cfg.username and cfg.auth_mode in (LDAPAuthMode.SIMPLE, LDAPAuthMode.NTLM))
        )
        
        if should_collect:
            try:
                enum = LDAPEnumerator(
                    server=cfg.server or None,
                    username=cfg.username or None,
                    password=cfg.password or None,
                    base_dn=cfg.base_dn or None,
                    domain=cfg.domain or None,
                    auth_mode=cfg.auth_mode.value,
                )
                return enum.enumerate_all()
            except Exception as e:
                log.warning("LDAP collection failed: %s — using empty snapshot", e)
        
        return ADSnapshot(
            domain="unknown.local", domain_sid="", base_dn="",
            timestamp=datetime.now(timezone.utc)
        )

    def _collect_logs(self, evtx_paths):
        from advulture.collection.log_ingester import EVTXIngester, EventStream
        paths = evtx_paths or self.config.logs.evtx_paths
        if paths:
            return EVTXIngester(paths).ingest()
        return EventStream([])

    def _collect_entra(self):
        """Collect Entra ID data using async enumeration wrapped in asyncio.run()."""
        import asyncio
        from advulture.collection.entra_ingester import EntraEnumerator
        
        cfg = self.config.entra
        if not cfg.enabled:
            return None
        
        try:
            enumerator = EntraEnumerator(
                tenant_id=cfg.tenant_id,
                client_id=cfg.client_id,
                client_secret=cfg.client_secret or None,
                certificate_path=cfg.certificate_path or None,
                certificate_password=cfg.certificate_password or None,
                auth_mode=cfg.auth_mode.value if hasattr(cfg.auth_mode, 'value') else cfg.auth_mode,
            )
            # Run async enumeration in sync context
            return asyncio.run(enumerator.enumerate_all())
        except Exception as e:
            log.warning("Entra ID collection failed: %s — skipping cloud analysis", e)
            return None

    def _collect_adfs(self, event_stream):
        from advulture.collection.adfs_ingester import ADFSLogIngester
        adfs_evtx = self.config.logs.evtx_paths  # filter ADFS channels in production
        ingester = ADFSLogIngester(evtx_paths=adfs_evtx)
        return ingester.ingest(auth_event_stream=event_stream)

    def _build_event_sequence(self, events) -> List[str]:
        """Convert event stream to ordered semantic sequence for HMM."""
        if not events:
            return []
        return [e.category.value for e in sorted(events.events, key=lambda x: x.timestamp)]

    def _compute_graph_stats(self, snapshot, findings) -> Dict:
        tier0_reachable = sum(1 for f in findings if f.tier0_reachable_paths > 0)
        esc_count = sum(1 for t in snapshot.cert_templates if t.esc1 or t.esc2)
        return {
            "enabled_user_ratio": len([u for u in snapshot.users if u.enabled]) / max(len(snapshot.users), 1),
            "tier0_reachable_paths": tier0_reachable,
            "esc_template_count": esc_count,
            "dcsync_exposed_count": sum(1 for f in findings if f.category == "dcsync_by_non_dc"),
        }

    def _build_graph_tensors(self, snapshot, events):
        """Build graph tensors using GraphBuilder and optionally ADRiskGNN."""
        from advulture.graph.builder import GraphBuilder
        
        n = len(snapshot.users) + len(snapshot.computers) + len(snapshot.groups)
        if n < 2:
            # Fallback for empty snapshot
            return torch.randint(0, 2, (2, 10)), torch.rand(10) * 0.5
        
        try:
            builder = GraphBuilder(snapshot, events)
            hetero_data = builder.build()
            
            # Try to use GNN for edge probability prediction
            try:
                from advulture.ml.gnn.model import ADRiskGNN
                gnn = ADRiskGNN()
                edge_probs_dict = gnn(hetero_data)
                
                # Flatten heterogeneous edges to single edge_index/probs tensor
                edge_index_list = []
                edge_probs_list = []
                node_offset = {"User": 0, "Computer": len(snapshot.users),
                               "Group": len(snapshot.users) + len(snapshot.computers)}
                
                for edge_type, probs in edge_probs_dict.items():
                    src_type, _, dst_type = edge_type
                    if hasattr(hetero_data[edge_type], 'edge_index'):
                        ei = hetero_data[edge_type].edge_index
                        src_offset = node_offset.get(src_type, 0)
                        dst_offset = node_offset.get(dst_type, 0)
                        adjusted_ei = ei.clone()
                        adjusted_ei[0] += src_offset
                        adjusted_ei[1] += dst_offset
                        edge_index_list.append(adjusted_ei)
                        edge_probs_list.append(probs)
                
                if edge_index_list:
                    edge_index = torch.cat(edge_index_list, dim=1)
                    edge_probs = torch.cat(edge_probs_list)
                    return edge_index, edge_probs
                    
            except (ImportError, Exception) as e:
                log.debug("GNN inference skipped: %s — using structural edges only", e)
            
            # Fallback: extract edges from hetero_data without GNN inference
            edge_index_list = []
            node_offset = {"User": 0, "Computer": len(snapshot.users),
                           "Group": len(snapshot.users) + len(snapshot.computers)}
            
            for edge_type in hetero_data.edge_types:
                if hasattr(hetero_data[edge_type], 'edge_index'):
                    ei = hetero_data[edge_type].edge_index
                    src_type, _, dst_type = edge_type
                    src_offset = node_offset.get(src_type, 0)
                    dst_offset = node_offset.get(dst_type, 0)
                    adjusted_ei = ei.clone()
                    adjusted_ei[0] += src_offset
                    adjusted_ei[1] += dst_offset
                    edge_index_list.append(adjusted_ei)
            
            if edge_index_list:
                edge_index = torch.cat(edge_index_list, dim=1)
                # Assign uniform probs for structural-only analysis
                edge_probs = torch.ones(edge_index.shape[1]) * 0.5
                return edge_index, edge_probs
                
        except Exception as e:
            log.warning("Graph builder failed: %s — using synthetic edges", e)
        
        # Final fallback for any failure
        edge_count = min(n * 3, 100)
        edge_index = torch.randint(0, n, (2, edge_count))
        edge_probs = torch.rand(edge_count) * 0.5
        return edge_index, edge_probs

    def _build_lpe_pairs(self, findings) -> List[Dict]:
        lpe_findings = [f for f in findings if f.risk_class == RiskClass.PRIVILEGE_ESCALATION]
        return [{"probability": 0.7, "account_node_id": i, "system_node_id": i + 1}
                for i, _ in enumerate(lpe_findings)]

    def _map_controls_to_findings(self, findings) -> Dict[str, List[str]]:
        mapping: Dict[str, List[str]] = {}
        for f in findings:
            for ctrl in f.controls:
                mapping.setdefault(ctrl, []).append(f.id)
        return mapping

    def _extract_active_signals(self, findings, events) -> List[str]:
        signals = [f.title for f in findings if f.active_signal]
        return signals[:10]

    def _classify_regime(self, mc_result, ranking) -> tuple[str, str]:
        pi = mc_result.tier0_probability
        mfpt = mc_result.mean_steps_to_tier0
        top_grad = abs(ranking[0].gradient) if ranking else 0

        if pi < 0.15 and top_grad < 0.3 and mfpt > 20:
            return "ORDERED", (
                "Controls are broadly effective. Steady-state Tier0 probability is low. "
                "Maintain current posture and monitor for drift."
            )
        elif pi > 0.45 or top_grad > 0.7 or mfpt < 5:
            return "CHAOTIC", (
                "Multiple high-gradient paths to Tier0 exist simultaneously. "
                "Immediate intervention required on top-ranked controls. "
                f"Current π_tier0: {pi:.1%}. Mean steps to DA: {mfpt:.1f}."
            )
        else:
            return "CRITICAL", (
                "Environment sits at the edge of chaos. Specific control failures "
                "would cascade to full compromise. Focus on top-ranked gradient controls. "
                f"π_tier0: {pi:.1%}. Mean steps to DA: {mfpt:.1f}."
            )

    def _default_controls(self) -> Dict[str, float]:
        return {
            "mfa_coverage":             0.30,
            "laps_deployed":            0.40,
            "edr_coverage":             0.60,
            "adcs_hardened":            0.00,
            "tiered_admin":             0.10,
            "smb_signing":              0.50,
            "delegation_audit":         0.20,
            "dcsync_audited":           0.30,
            "mcp_scope_restriction":    0.05,
            "adfs_claim_review":        0.10,
            "aes_enforcement":          0.40,
            "ntlm_restriction":         0.20,
            "sid_filtering":            0.60,
            "rbcd_monitoring":          0.15,
            "local_admin_audit":        0.20,
            "agent_content_isolation":  0.00,
        }
