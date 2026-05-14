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
from pathlib import Path
from typing import Optional, List, Dict

# ML imports are optional - gracefully degrade if not available
try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None

from advulture.analysis.finding import Finding, RiskClass, Severity
from advulture.analysis.finding import (
    make_kerberoast_finding, make_esc1_finding,
    make_unconstrained_delegation_finding, make_lpe_finding,
    make_shadow_admin_finding, make_ai_agent_finding,
)

# ML modules are optional
try:
    from advulture.ml.markov.chain import (
        AttackChainMarkov, KillChainHMM, GradientEngine,
        PhaseDetection, RemediationItem, Phase,
    )
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    AttackChainMarkov = None
    KillChainHMM = None
    GradientEngine = None
    PhaseDetection = None
    RemediationItem = None
    Phase = None

from advulture.config import Config
from advulture.custody import ChainOfCustodyLogger, CustodyEventType
from advulture.evidence import EvidencePreserver, PreservationResult

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

    # Evidence preservation
    evidence_archive_path: Optional[str] = None
    evidence_manifest_hash: Optional[str] = None

    def summary(self) -> str:
        counts_str = "  ".join(
            f"[{cls}] {cnt}" for cls, cnt in self.finding_counts.items()
        )
        evidence_str = f"  |  Evidence: {self.evidence_manifest_hash[:16]}..." if self.evidence_manifest_hash else ""
        return (
            f"ADVulture Posture Report — {self.domain}\n"
            f"{'=' * 60}\n"
            f"Regime: {self.regime}  |  π_tier0: {self.tier0_steady_state_probability:.1%}  "
            f"|  Mean steps to DA: {self.mean_steps_to_tier0:.1f}\n"
            f"Phase: {self.attacker_phase.most_likely.name if self.attacker_phase else 'UNKNOWN'}  "
            f"|  Active signals: {len(self.active_signals)}{evidence_str}\n"
            f"Findings: {counts_str}  |  Total: {len(self.findings)}\n"
        )

    def to_dict(self) -> dict:
        result = {
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
        # Add evidence preservation info if available
        if self.evidence_archive_path:
            result["evidence"] = {
                "archive_path": self.evidence_archive_path,
                "manifest_hash": self.evidence_manifest_hash,
            }
        return result


class PostureAnalyzer:
    """
    Main analysis orchestrator. Connects all subsystems and produces
    a unified PostureReport with findings from all six risk classes.
    
    Supports two modes:
    - analyze(): Simple mode without progress indicators
    - analyze_with_progress(): Download-first mode with rich progress bars
    
    Evidence Preservation:
    - When preserve_evidence=True, creates a compressed, hashed archive of all
      collected data before analysis begins
    - Archives serve as forensic "system of record" for chain of custody
    """

    def __init__(self, config: Config):
        self.config = config
        self.hmm = KillChainHMM()
        self.gradient_engine = GradientEngine()
        # Cached data from download phase
        self._cached_snapshot = None
        self._cached_event_stream = None
        self._cached_entra_snapshot = None
        self._cached_entra_events = None
        # Evidence preservation
        self._evidence_preserver: Optional[EvidencePreserver] = None
        self._evidence_result: Optional[PreservationResult] = None
        # Shared Entra authenticator to avoid double device-code prompts
        self._shared_entra_enumerator = None

    def analyze_with_progress(
        self,
        progress,
        controls: Optional[Dict[str, float]] = None,
        evtx_paths: Optional[List] = None,
        preserve_evidence: bool = True,
        evidence_dir: Optional[Path] = None,
        case_id: Optional[str] = None,
    ) -> PostureReport:
        """
        Run complete posture analysis with progress indicators.
        
        Implements a download-first strategy:
        1. DOWNLOAD PHASE: Collect all data from sources with progress
        2. EVIDENCE PHASE: Compress and hash collected data for chain of custody
        3. ANALYSIS PHASE: Process cached data with progress
        
        Args:
            progress: rich.progress.Progress instance for displaying progress
            controls: current deployment level for each security control [0,1]
            evtx_paths: optional list of EVTX file paths
            preserve_evidence: if True, create compressed/hashed evidence archive
            evidence_dir: directory for evidence archives (default: ./evidence)
            case_id: optional case/ticket ID for evidence tracking
            
        Returns:
            PostureReport with all findings and recommendations
        """
        if controls is None:
            controls = self._default_controls()

        log.info("Starting ADVulture posture analysis (download-first mode)")
        
        # Initialize evidence preserver if enabled
        if preserve_evidence:
            self._evidence_preserver = EvidencePreserver(
                evidence_dir=evidence_dir or Path("evidence"),
            )
            self._evidence_preserver.start_collection(case_id=case_id)
            log.info("Evidence preservation enabled: %s", self._evidence_preserver._archive_path)
        
        # ════════════════════════════════════════════════════════════════════
        # PHASE 1: DOWNLOAD — Collect all data before processing
        # ════════════════════════════════════════════════════════════════════
        
        # Determine collection tasks based on config
        collection_tasks = []
        if not self.config.entra.enabled or (self.config.ldap.server or self.config.ldap.domain):
            collection_tasks.append(("ad", "Active Directory"))
        if self.config.logs.evtx_paths or evtx_paths:
            collection_tasks.append(("evtx", "Event Logs"))
        if self.config.entra.enabled:
            collection_tasks.append(("entra_objects", "Entra ID Objects"))
            collection_tasks.append(("entra_logs", "Entra ID Logs"))
        if self.config.adfs.enabled:
            collection_tasks.append(("adfs", "ADFS Logs"))
        
        # Create download task
        download_task = progress.add_task(
            "[cyan]📥 Downloading data...", 
            total=len(collection_tasks)
        )
        
        # Collect AD
        snapshot = None
        if ("ad", "Active Directory") in collection_tasks:
            progress.update(download_task, description="[cyan]📥 Collecting Active Directory...")
            snapshot = self._collect_ad(evtx_paths)
            progress.advance(download_task)
            log.info("AD collection complete: %d users, %d computers, %d groups",
                    len(snapshot.users), len(snapshot.computers), len(snapshot.groups))
        
        if snapshot is None:
            from advulture.collection.ldap_enumerator import ADSnapshot
            snapshot = ADSnapshot(
                domain="unknown.local", domain_sid="", base_dn="",
                timestamp=datetime.now(timezone.utc)
            )
        
        # Collect EVTX logs
        event_stream = None
        if ("evtx", "Event Logs") in collection_tasks:
            progress.update(download_task, description="[cyan]📥 Parsing event logs...")
            event_stream = self._collect_logs(evtx_paths)
            progress.advance(download_task)
            event_count = len(event_stream.events) if hasattr(event_stream, 'events') else 0
            log.info("EVTX collection complete: %d events", event_count)
        
        if event_stream is None:
            from advulture.collection.log_ingester import EventStream
            event_stream = EventStream([])
        
        # Collect Entra ID objects
        entra_snapshot = None
        if ("entra_objects", "Entra ID Objects") in collection_tasks:
            progress.update(download_task, description="[cyan]📥 Collecting Entra ID objects...")
            entra_snapshot = self._collect_entra()
            progress.advance(download_task)
            if entra_snapshot:
                log.info("Entra objects complete: %d users, %d service principals",
                        len(entra_snapshot.users), len(entra_snapshot.service_principals))
        
        # Collect Entra ID logs (sign-ins, audits, risk detections)
        entra_events = None
        if ("entra_logs", "Entra ID Logs") in collection_tasks:
            progress.update(download_task, description="[cyan]📥 Collecting Entra ID logs...")
            entra_events = self._collect_entra_logs()
            progress.advance(download_task)
            if entra_events:
                log.info("Entra logs complete: %d sign-ins, %d audits, %d risk detections",
                        len(entra_events.signins), len(entra_events.audits), 
                        len(entra_events.risk_detections))
        
        # Collect ADFS
        adfs_surface = None
        if ("adfs", "ADFS Logs") in collection_tasks:
            progress.update(download_task, description="[cyan]📥 Collecting ADFS logs...")
            adfs_surface = self._collect_adfs(event_stream)
            progress.advance(download_task)
        
        # Mark download complete
        progress.update(download_task, description="[green]✓ Download complete", completed=len(collection_tasks))
        
        # ════════════════════════════════════════════════════════════════════
        # PHASE 1.5: EVIDENCE PRESERVATION — Hash and compress raw data
        # ════════════════════════════════════════════════════════════════════
        
        evidence_archive_path = None
        evidence_manifest_hash = None
        
        if self._evidence_preserver is not None:
            # Count preservation steps
            preservation_steps = []
            if snapshot and snapshot.users:
                preservation_steps.append("ad_snapshot")
            if event_stream and hasattr(event_stream, 'events') and event_stream.events:
                preservation_steps.append("event_stream")
            if entra_snapshot:
                preservation_steps.append("entra_snapshot")
            if entra_events:
                preservation_steps.append("entra_events")
            # Add source file hashing
            actual_evtx = evtx_paths or self.config.logs.evtx_paths
            if actual_evtx:
                preservation_steps.append("source_hashes")
            preservation_steps.append("finalize")
            
            evidence_task = progress.add_task(
                "[magenta]🔒 Preserving evidence...",
                total=len(preservation_steps)
            )
            
            # Preserve AD snapshot
            if "ad_snapshot" in preservation_steps:
                progress.update(evidence_task, description="[magenta]🔒 Hashing AD snapshot...")
                self._evidence_preserver.preserve_ad_snapshot(snapshot)
                progress.advance(evidence_task)
            
            # Preserve event stream  
            if "event_stream" in preservation_steps:
                progress.update(evidence_task, description="[magenta]🔒 Hashing event stream...")
                self._evidence_preserver.preserve_event_stream(event_stream)
                progress.advance(evidence_task)
            
            # Preserve Entra snapshot
            if "entra_snapshot" in preservation_steps:
                progress.update(evidence_task, description="[magenta]🔒 Hashing Entra snapshot...")
                self._evidence_preserver.preserve_entra_snapshot(entra_snapshot)
                progress.advance(evidence_task)
            
            # Preserve Entra events
            if "entra_events" in preservation_steps:
                progress.update(evidence_task, description="[magenta]🔒 Hashing Entra events...")
                self._evidence_preserver.preserve_entra_events(entra_events)
                progress.advance(evidence_task)
            
            # Hash source files (EVTX)
            if "source_hashes" in preservation_steps:
                progress.update(evidence_task, description="[magenta]🔒 Hashing source files...")
                for evtx_path in (actual_evtx or []):
                    if Path(evtx_path).exists():
                        self._evidence_preserver.record_source_file_hash(Path(evtx_path))
                progress.advance(evidence_task)
            
            # Finalize archive
            progress.update(evidence_task, description="[magenta]🔒 Finalizing evidence archive...")
            self._evidence_result = self._evidence_preserver.finalize()
            progress.advance(evidence_task)
            
            # Update progress and log custody
            progress.update(evidence_task, description="[green]✓ Evidence preserved", completed=len(preservation_steps))
            
            evidence_archive_path = str(self._evidence_result.archive_path)
            evidence_manifest_hash = self._evidence_result.manifest.manifest_hash
            
            # Log to chain of custody
            custody = ChainOfCustodyLogger.get_instance()
            custody.log_export(
                export_type="evidence_archive",
                destination=evidence_archive_path,
                format="gzip+json",
                record_count=(
                    self._evidence_result.manifest.ad_snapshot_records +
                    self._evidence_result.manifest.entra_snapshot_records +
                    self._evidence_result.manifest.entra_events_records +
                    self._evidence_result.manifest.event_stream_records
                ),
                file_hash=evidence_manifest_hash,
            )
            
            log.info(
                "Evidence preserved: %s (hash=%s)",
                self._evidence_result.archive_path.name,
                evidence_manifest_hash[:16] + "...",
            )
        
        # ════════════════════════════════════════════════════════════════════
        # PHASE 2: ANALYSIS — Process cached data
        # ════════════════════════════════════════════════════════════════════
        
        analysis_steps = [
            ("findings", "Security findings"),
            ("phase", "Attack phase detection"),
            ("markov", "Markov analysis"),
            ("gradient", "Gradient ranking"),
            ("regime", "Regime classification"),
        ]
        
        analysis_task = progress.add_task(
            "[yellow]🔍 Analyzing...", 
            total=len(analysis_steps)
        )
        
        # Generate findings from static analysis
        progress.update(analysis_task, description="[yellow]🔍 Analyzing security findings...")
        findings: List[Finding] = []
        findings += self._analyze_authn_hygiene(snapshot, event_stream)
        findings += self._analyze_authz_structure(snapshot)
        findings += self._analyze_authz_behaviour(snapshot, event_stream, adfs_surface)
        findings += self._analyze_lpe(event_stream)
        findings += self._analyze_delegation(snapshot, event_stream)
        if entra_snapshot:
            findings += self._analyze_ai_agents(entra_snapshot)
        progress.advance(analysis_task)
        
        # HMM phase detection
        progress.update(analysis_task, description="[yellow]🔍 Detecting attack phase...")
        event_sequence = self._build_event_sequence(event_stream)
        graph_stats = self._compute_graph_stats(snapshot, findings)
        phase_detection = self.hmm.viterbi(event_sequence, graph_stats)
        progress.advance(analysis_task)
        log.info(
            "HMM: phase=%s confidence=%.0f%% velocity=%.2f",
            phase_detection.most_likely.name,
            phase_detection.confidence * 100,
            phase_detection.threat_velocity,
        )
        
        # Markov analysis
        progress.update(analysis_task, description="[yellow]🔍 Running Markov analysis...")
        num_nodes = len(snapshot.users) + len(snapshot.computers) + len(snapshot.groups)
        tier0_ids = [i for i, u in enumerate(snapshot.users) if u.tier == 0]
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
        progress.advance(analysis_task)
        
        # Gradient ranking
        progress.update(analysis_task, description="[yellow]🔍 Computing gradient ranking...")
        ranking = self.gradient_engine.compute_ranking(
            edge_index, edge_probs, controls, phase_detection, markov, lpe_pairs
        )
        
        # Attach gradient contributions to findings
        ctrl_to_findings = self._map_controls_to_findings(findings)
        for item in ranking:
            for fid in ctrl_to_findings.get(item.control, []):
                matching = [f for f in findings if f.id == fid]
                for f in matching:
                    f.gradient_contribution = max(f.gradient_contribution, item.gradient)
        findings.sort(key=lambda f: f.gradient_contribution, reverse=True)
        progress.advance(analysis_task)
        
        # Regime classification
        progress.update(analysis_task, description="[yellow]🔍 Classifying regime...")
        regime, regime_explanation = self._classify_regime(mc_result, ranking)
        active_signals = self._extract_active_signals(findings, event_stream)
        progress.advance(analysis_task)
        
        # Mark analysis complete
        progress.update(analysis_task, description="[green]✓ Analysis complete", completed=len(analysis_steps))
        
        # Build final report
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
            evidence_archive_path=evidence_archive_path,
            evidence_manifest_hash=evidence_manifest_hash,
        )

        log.info("Analysis complete. %d findings. Regime: %s. π_tier0: %.1f%%",
                 len(findings), regime, mc_result.tier0_probability * 100)
        
        # SECURITY: Clear credential references after analysis completes
        # This ensures tokens are not retained in memory longer than necessary
        self._clear_credentials()
        
        return report

    def _clear_credentials(self):
        """
        Clear cached credentials after analysis completes.
        
        Security measure to ensure authentication tokens are not retained
        in memory longer than necessary. While tokens are already configured
        to not persist to disk, this ensures they're also cleared from memory
        when the analysis session ends.
        """
        if self._shared_entra_enumerator is not None:
            # Clear the credential and client references
            if hasattr(self._shared_entra_enumerator, '_credential'):
                self._shared_entra_enumerator._credential = None
            if hasattr(self._shared_entra_enumerator, '_client'):
                self._shared_entra_enumerator._client = None
            self._shared_entra_enumerator = None
            log.debug("Cleared Entra credentials from memory")

    def _collect_entra_logs(self):
        """Collect Entra ID sign-in logs, audit logs, and risk detections."""
        import asyncio
        from advulture.collection.entra_ingester import EntraLogIngester
        
        custody = ChainOfCustodyLogger.get_instance()
        cfg = self.config.entra
        
        if not cfg.enabled:
            return None
        
        try:
            auth_mode = cfg.auth_mode.value if hasattr(cfg.auth_mode, 'value') else cfg.auth_mode
            
            # Reuse shared enumerator to avoid duplicate auth prompts
            # EntraLogIngester wraps EntraEnumerator for client access
            shared_enumerator = self._get_shared_entra_enumerator()
            
            ingester = EntraLogIngester(
                tenant_id=cfg.tenant_id,
                client_id=cfg.client_id,
                client_secret=cfg.client_secret or None,
                certificate_path=cfg.certificate_path or None,
                certificate_password=cfg.certificate_password or None,
                auth_mode=auth_mode,
            )
            # Inject the already-authenticated enumerator to avoid re-auth
            ingester._enumerator = shared_enumerator
            
            # Run async collection in sync context
            events = asyncio.run(ingester.collect_window(days=self.config.logs.authn_window_days))
            
            custody.log_collection(
                source="entra_logs",
                details={
                    "signins": len(events.signins),
                    "audits": len(events.audits),
                    "risk_detections": len(events.risk_detections),
                },
                record_count=len(events.signins) + len(events.audits) + len(events.risk_detections),
            )
            
            return events
        except Exception as e:
            log.warning("Entra ID log collection failed: %s — skipping", e)
            custody.log_error("entra_log_collection", str(e))
            return None

    def analyze(
        self,
        controls: Optional[Dict[str, float]] = None,
        evtx_paths: Optional[List] = None,
    ) -> PostureReport:
        """
        Run complete posture analysis (simple mode without progress indicators).
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
            findings += self._analyze_entra_privileged_access(entra_snapshot)
            findings += self._analyze_entra_role_hygiene(entra_snapshot)
            findings += self._analyze_entra_mfa_posture(entra_snapshot)

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
        
        # SECURITY: Clear credential references after analysis completes
        self._clear_credentials()
        
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

    # =========================================================================
    # Enhanced Entra ID Privileged Access Analysis
    # =========================================================================

    def _analyze_entra_privileged_access(self, entra_snapshot) -> List[Finding]:
        """Analyze Entra ID privileged role assignments for security risks."""
        findings = []
        
        if not hasattr(entra_snapshot, 'all_role_assignments') or not entra_snapshot.all_role_assignments:
            return findings
        
        assignments = entra_snapshot.all_role_assignments
        role_defs = {r.id: r for r in getattr(entra_snapshot, 'role_definitions', [])}
        
        # Build user-to-roles mapping
        user_roles = {}
        for assignment in assignments:
            if assignment.principal_type == "User":
                if assignment.principal_id not in user_roles:
                    user_roles[assignment.principal_id] = {
                        "name": assignment.principal_name,
                        "roles": [],
                        "privileged_roles": [],
                    }
                user_roles[assignment.principal_id]["roles"].append(assignment.role_name)
                
                # Check if this is a high-privilege role
                role_def = role_defs.get(assignment.role_definition_id)
                if role_def and role_def.is_privileged:
                    user_roles[assignment.principal_id]["privileged_roles"].append(assignment.role_name)
        
        # Finding 1: Excessive Role Stacking (users with 3+ privileged roles)
        excessive_roles = [
            (info["name"], info["privileged_roles"])
            for user_id, info in user_roles.items()
            if len(info["privileged_roles"]) >= 3
        ]
        if excessive_roles:
            findings.append(Finding(
                category="excessive_role_stacking",
                title=f"Excessive Privileged Role Assignments: {len(excessive_roles)} users with 3+ roles",
                risk_class=RiskClass.AUTHZ_STRUCTURE,
                severity=Severity.HIGH,
                affected_resources=[f"{name}: {', '.join(roles)}" for name, roles in excessive_roles],
                evidence_sources=["entra_role_assignments"],
                mitre_techniques=["T1078.004"],  # Valid Accounts: Cloud Accounts
                controls=["privileged_access_management", "role_separation"],
                remediation_steps=[
                    "Review necessity of each role assignment",
                    "Implement role separation - avoid stacking admin roles",
                    "Use PIM (Just-In-Time) instead of permanent assignments",
                    "Create custom roles with minimal necessary permissions",
                ],
                details={
                    "affected_users": [
                        {"user": name, "roles": roles, "role_count": len(roles)}
                        for name, roles in excessive_roles
                    ],
                },
            ))
        
        # Finding 2: Permanent privileged assignments (should use PIM/JIT)
        active_privileged = [
            a for a in assignments
            if a.assignment_type == "active" 
            and a.principal_type == "User"
            and any(r.is_privileged for r in role_defs.values() if r.id == a.role_definition_id)
        ]
        eligible_privileged = [
            a for a in assignments
            if a.assignment_type == "eligible"
        ]
        
        if active_privileged and len(eligible_privileged) < len(active_privileged) * 0.5:
            findings.append(Finding(
                category="standing_privileged_access",
                title=f"Standing Privileged Access: {len(active_privileged)} permanent assignments",
                risk_class=RiskClass.AUTHZ_STRUCTURE,
                severity=Severity.MEDIUM,
                affected_resources=[f"{a.principal_name}: {a.role_name}" for a in active_privileged[:20]],
                evidence_sources=["entra_role_assignments", "pim_eligibility"],
                mitre_techniques=["T1078.004"],
                controls=["privileged_identity_management"],
                remediation_steps=[
                    "Convert permanent assignments to PIM eligible",
                    "Implement Just-In-Time (JIT) access for privileged roles",
                    "Require justification and approval for role activation",
                    "Set maximum activation duration (e.g., 8 hours)",
                ],
                details={
                    "permanent_assignments": len(active_privileged),
                    "eligible_assignments": len(eligible_privileged),
                    "pim_coverage_pct": round(len(eligible_privileged) / max(len(active_privileged), 1) * 100, 1),
                },
            ))
        
        # Finding 3: Tenant-wide privileged access without scope restriction
        unscoped_privileged = [
            a for a in assignments
            if a.directory_scope_id == "/"
            and a.principal_type == "User"
            and any(r.is_privileged for r in role_defs.values() if r.id == a.role_definition_id)
        ]
        if len(unscoped_privileged) > 5:
            findings.append(Finding(
                category="unscoped_privileged_access",
                title=f"Tenant-Wide Privileged Access: {len(unscoped_privileged)} unscoped assignments",
                risk_class=RiskClass.AUTHZ_STRUCTURE,
                severity=Severity.MEDIUM,
                affected_resources=[f"{a.principal_name}: {a.role_name}" for a in unscoped_privileged[:15]],
                evidence_sources=["entra_role_assignments"],
                mitre_techniques=["T1078.004"],
                controls=["administrative_units", "scoped_access"],
                remediation_steps=[
                    "Use Administrative Units to scope role assignments",
                    "Assign roles at department/team level instead of tenant-wide",
                    "Create tiered administration model",
                    "Document justification for any tenant-wide assignments",
                ],
                details={
                    "unscoped_count": len(unscoped_privileged),
                },
            ))
        
        # Finding 4: Service principals with privileged roles
        sp_privileged = [
            a for a in assignments
            if a.principal_type == "ServicePrincipal"
            and any(r.is_privileged for r in role_defs.values() if r.id == a.role_definition_id)
        ]
        if sp_privileged:
            findings.append(Finding(
                category="service_principal_privileged_roles",
                title=f"Service Principals with Privileged Roles: {len(sp_privileged)} assignments",
                risk_class=RiskClass.AI_AUTHZ,
                severity=Severity.HIGH,
                affected_resources=[f"{a.principal_name}: {a.role_name}" for a in sp_privileged],
                evidence_sources=["entra_role_assignments"],
                mitre_techniques=["T1078.004", "T1098.001"],
                controls=["service_principal_governance"],
                remediation_steps=[
                    "Review necessity of each service principal's privileged access",
                    "Use managed identities instead of service principals where possible",
                    "Implement certificate-based auth instead of secrets",
                    "Set credential expiration and rotation policies",
                    "Enable continuous access evaluation (CAE)",
                ],
                details={
                    "service_principals": [
                        {"name": a.principal_name, "role": a.role_name}
                        for a in sp_privileged
                    ],
                },
            ))
        
        return findings

    def _analyze_entra_role_hygiene(self, entra_snapshot) -> List[Finding]:
        """Analyze Entra ID role configuration for hygiene issues."""
        findings = []
        
        # Role sprawl analysis
        role_defs = getattr(entra_snapshot, 'role_definitions', [])
        assignments = getattr(entra_snapshot, 'all_role_assignments', [])
        
        if not role_defs:
            return findings
        
        # Finding 1: Excessive number of roles defined
        custom_roles = [r for r in role_defs if not r.is_built_in]
        if len(role_defs) > 80 or len(custom_roles) > 10:
            findings.append(Finding(
                category="role_sprawl",
                title=f"Role Sprawl: {len(role_defs)} roles defined ({len(custom_roles)} custom)",
                risk_class=RiskClass.AUTHZ_STRUCTURE,
                severity=Severity.LOW,
                affected_resources=[r.display_name for r in custom_roles] if custom_roles else [],
                evidence_sources=["entra_role_definitions"],
                mitre_techniques=["T1078.004"],
                controls=["role_governance"],
                remediation_steps=[
                    "Review and consolidate custom roles",
                    "Remove unused or redundant role definitions",
                    "Prefer built-in roles over custom where possible",
                    "Document business justification for each custom role",
                ],
                details={
                    "total_roles": len(role_defs),
                    "builtin_roles": len(role_defs) - len(custom_roles),
                    "custom_roles": len(custom_roles),
                },
            ))
        
        # Finding 2: Unused roles with assignments
        roles_with_assignments = set(a.role_definition_id for a in assignments)
        unused_roles = [r for r in role_defs if r.id not in roles_with_assignments and r.is_enabled]
        if len(unused_roles) > 20:
            findings.append(Finding(
                category="unused_role_definitions",
                title=f"Unused Role Definitions: {len(unused_roles)} roles with no assignments",
                risk_class=RiskClass.AUTHZ_STRUCTURE,
                severity=Severity.INFO,
                affected_resources=[r.display_name for r in unused_roles[:20]],
                evidence_sources=["entra_role_definitions", "entra_role_assignments"],
                mitre_techniques=[],
                controls=["role_governance"],
                remediation_steps=[
                    "Review unused roles for potential cleanup",
                    "Document roles that are intentionally kept for future use",
                ],
                details={
                    "unused_count": len(unused_roles),
                },
            ))
        
        # Finding 3: Groups with privileged roles (membership = instant privilege)
        group_privileged = [
            a for a in assignments
            if a.principal_type == "Group"
        ]
        if group_privileged:
            findings.append(Finding(
                category="group_privileged_roles",
                title=f"Groups with Privileged Roles: {len(group_privileged)} group assignments",
                risk_class=RiskClass.AUTHZ_STRUCTURE,
                severity=Severity.MEDIUM,
                affected_resources=[f"{a.principal_name}: {a.role_name}" for a in group_privileged],
                evidence_sources=["entra_role_assignments"],
                mitre_techniques=["T1078.004", "T1098"],
                controls=["privileged_access_groups"],
                remediation_steps=[
                    "Review group membership for each privileged group",
                    "Consider using PIM for Groups instead of direct role assignment",
                    "Enable access reviews for privileged group membership",
                    "Require approval for group membership changes",
                ],
                details={
                    "groups": [
                        {"group": a.principal_name, "role": a.role_name}
                        for a in group_privileged
                    ],
                },
            ))
        
        # Finding 4: OAuth consent grant sprawl (risky app permissions)
        oauth_grants = getattr(entra_snapshot, 'oauth_grants', [])
        if oauth_grants:
            risky_scopes = {"Mail.Read", "Mail.ReadWrite", "Files.Read", "Files.ReadWrite", 
                          "Files.ReadWrite.All", "Sites.Read.All", "Sites.ReadWrite.All",
                          "Calendars.Read", "Calendars.ReadWrite", "User.ReadWrite.All"}
            risky_grants = []
            for grant in oauth_grants:
                scope = grant.get("scope", "")
                granted_scopes = set(scope.split())
                risky = granted_scopes & risky_scopes
                if risky:
                    risky_grants.append({
                        "client_id": grant.get("client_id"),
                        "consent_type": grant.get("consent_type"),
                        "risky_scopes": list(risky),
                    })
            
            if risky_grants:
                findings.append(Finding(
                    category="risky_oauth_consent",
                    title=f"Risky OAuth Consent Grants: {len(risky_grants)} apps with sensitive permissions",
                    risk_class=RiskClass.AI_AUTHZ,
                    severity=Severity.MEDIUM,
                    affected_resources=[f"App {g['client_id']}: {', '.join(g['risky_scopes'])}" for g in risky_grants[:10]],
                    evidence_sources=["oauth2_permission_grants"],
                    mitre_techniques=["T1550.001"],  # Use Alternate Authentication Material
                    controls=["app_consent_policy", "admin_consent_workflow"],
                    remediation_steps=[
                        "Review and revoke unnecessary consent grants",
                        "Implement admin consent workflow for sensitive permissions",
                        "Block user consent for high-risk permissions",
                        "Enable consent grant attack detection in Identity Protection",
                    ],
                    details={
                        "risky_grant_count": len(risky_grants),
                        "sample_grants": risky_grants[:5],
                    },
                ))
        
        return findings

    def _analyze_entra_mfa_posture(self, entra_snapshot) -> List[Finding]:
        """Analyze MFA registration and capability across users."""
        findings = []
        
        users = getattr(entra_snapshot, 'users', [])
        if not users:
            return findings
        
        # Categorize users by MFA status
        enabled_users = [u for u in users if u.account_enabled]
        no_mfa = [u for u in enabled_users if not u.mfa_registered]
        weak_mfa_only = [u for u in enabled_users if u.mfa_registered and not u.mfa_capable]
        strong_mfa = [u for u in enabled_users if u.mfa_capable]
        
        # Get privileged users for cross-reference
        role_assignments = getattr(entra_snapshot, 'all_role_assignments', [])
        role_defs = {r.id: r for r in getattr(entra_snapshot, 'role_definitions', [])}
        
        privileged_user_ids = set()
        for assignment in role_assignments:
            if assignment.principal_type == "User":
                role_def = role_defs.get(assignment.role_definition_id)
                if role_def and role_def.is_privileged:
                    privileged_user_ids.add(assignment.principal_id)
        
        privileged_no_mfa = [u for u in no_mfa if u.id in privileged_user_ids]
        privileged_weak_mfa = [u for u in weak_mfa_only if u.id in privileged_user_ids]
        
        # Finding 1: CRITICAL - Privileged accounts without MFA
        if privileged_no_mfa:
            findings.append(Finding(
                category="privileged_accounts_no_mfa",
                title=f"Privileged Accounts Without MFA: {len(privileged_no_mfa)} accounts",
                risk_class=RiskClass.AUTHN_HYGIENE,
                severity=Severity.CRITICAL,
                affected_resources=[u.user_principal_name for u in privileged_no_mfa],
                evidence_sources=["entra_users", "authentication_methods"],
                mitre_techniques=["T1078.004", "T1110"],
                controls=["mfa_enforcement", "conditional_access"],
                remediation_steps=[
                    "IMMEDIATELY require MFA registration for all privileged accounts",
                    "Create Conditional Access policy requiring MFA for admin roles",
                    "Consider blocking sign-in until MFA is registered",
                    "Enable Security Defaults if no CA policies exist",
                ],
                details={
                    "affected_count": len(privileged_no_mfa),
                    "accounts": [
                        {"upn": u.user_principal_name, "display_name": u.display_name}
                        for u in privileged_no_mfa
                    ],
                },
            ))
        
        # Finding 2: HIGH - Privileged accounts with weak MFA only (SMS/Voice)
        if privileged_weak_mfa:
            findings.append(Finding(
                category="privileged_accounts_weak_mfa",
                title=f"Privileged Accounts with Weak MFA: {len(privileged_weak_mfa)} using SMS/Voice only",
                risk_class=RiskClass.AUTHN_HYGIENE,
                severity=Severity.HIGH,
                affected_resources=[u.user_principal_name for u in privileged_weak_mfa],
                evidence_sources=["entra_users", "authentication_methods"],
                mitre_techniques=["T1078.004", "T1111"],  # MFA interception
                controls=["strong_mfa", "phishing_resistant_mfa"],
                remediation_steps=[
                    "Require phishing-resistant MFA for privileged accounts",
                    "Deploy FIDO2 security keys or Windows Hello for Business",
                    "Migrate from SMS/Voice to Microsoft Authenticator at minimum",
                    "Block SMS/Voice MFA via Authentication Methods Policy",
                ],
                details={
                    "affected_count": len(privileged_weak_mfa),
                    "accounts": [
                        {"upn": u.user_principal_name, "mfa_methods": u.mfa_methods}
                        for u in privileged_weak_mfa
                    ],
                },
            ))
        
        # Finding 3: MEDIUM - General users without MFA
        non_privileged_no_mfa = [u for u in no_mfa if u.id not in privileged_user_ids]
        if len(non_privileged_no_mfa) > 10:
            pct_no_mfa = round(len(non_privileged_no_mfa) / max(len(enabled_users), 1) * 100, 1)
            findings.append(Finding(
                category="users_without_mfa",
                title=f"Users Without MFA: {len(non_privileged_no_mfa)} accounts ({pct_no_mfa}%)",
                risk_class=RiskClass.AUTHN_HYGIENE,
                severity=Severity.MEDIUM if pct_no_mfa > 20 else Severity.LOW,
                affected_resources=[u.user_principal_name for u in non_privileged_no_mfa[:20]],
                evidence_sources=["entra_users", "authentication_methods"],
                mitre_techniques=["T1078.004"],
                controls=["mfa_enforcement", "security_defaults"],
                remediation_steps=[
                    "Enable MFA registration campaign",
                    "Create Conditional Access policy requiring MFA for all users",
                    "Enable Security Defaults if no Conditional Access",
                    "Set registration deadline with escalating notifications",
                ],
                details={
                    "total_enabled_users": len(enabled_users),
                    "users_without_mfa": len(non_privileged_no_mfa),
                    "percentage": pct_no_mfa,
                    "sample_accounts": [u.user_principal_name for u in non_privileged_no_mfa[:10]],
                },
            ))
        
        # Finding 4: LOW - Users relying on weak MFA only
        non_privileged_weak_mfa = [u for u in weak_mfa_only if u.id not in privileged_user_ids]
        if len(non_privileged_weak_mfa) > 20:
            pct_weak = round(len(non_privileged_weak_mfa) / max(len(enabled_users), 1) * 100, 1)
            findings.append(Finding(
                category="users_weak_mfa_only",
                title=f"Users with Weak MFA Only: {len(non_privileged_weak_mfa)} using SMS/Voice ({pct_weak}%)",
                risk_class=RiskClass.AUTHN_HYGIENE,
                severity=Severity.LOW,
                affected_resources=[u.user_principal_name for u in non_privileged_weak_mfa[:15]],
                evidence_sources=["entra_users", "authentication_methods"],
                mitre_techniques=["T1111"],
                controls=["strong_mfa"],
                remediation_steps=[
                    "Encourage migration to Microsoft Authenticator app",
                    "Deploy FIDO2 security keys for high-value users",
                    "Consider deprecating SMS/Voice MFA over time",
                ],
                details={
                    "weak_mfa_count": len(non_privileged_weak_mfa),
                    "percentage": pct_weak,
                },
            ))
        
        # MFA Summary for reporting
        if enabled_users:
            mfa_stats = {
                "total_enabled_users": len(enabled_users),
                "strong_mfa": len(strong_mfa),
                "weak_mfa_only": len(weak_mfa_only),
                "no_mfa": len(no_mfa),
                "privileged_no_mfa": len(privileged_no_mfa),
                "privileged_weak_mfa": len(privileged_weak_mfa),
                "strong_mfa_pct": round(len(strong_mfa) / len(enabled_users) * 100, 1),
            }
            log.info("MFA Posture: %s", mfa_stats)
        
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _collect_ad(self, evtx_paths):
        from advulture.collection.ldap_enumerator import LDAPEnumerator, ADSnapshot
        from advulture.config import LDAPAuthMode
        from datetime import datetime, timezone
        
        custody = ChainOfCustodyLogger.get_instance()
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
                start_time = datetime.now(timezone.utc)
                custody.log_auth(
                    method=cfg.auth_mode.value,
                    details={"server": cfg.server or "auto-discover", "domain": cfg.domain or "auto-discover"},
                    target="ldap"
                )
                
                enum = LDAPEnumerator(
                    server=cfg.server or None,
                    username=cfg.username or None,
                    password=cfg.password or None,
                    base_dn=cfg.base_dn or None,
                    domain=cfg.domain or None,
                    auth_mode=cfg.auth_mode.value,
                )
                snapshot = enum.enumerate_all()
                
                duration_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
                custody.log_collection(
                    source="active_directory",
                    details={
                        "domain": snapshot.domain,
                        "domain_sid": snapshot.domain_sid,
                    },
                    record_count=len(snapshot.users) + len(snapshot.computers) + len(snapshot.groups),
                    duration_ms=duration_ms
                )
                custody.log_data_access(
                    data_type="ad_objects",
                    operation="enumerate",
                    record_count=len(snapshot.users) + len(snapshot.computers) + len(snapshot.groups),
                    details={
                        "users": len(snapshot.users),
                        "computers": len(snapshot.computers),
                        "groups": len(snapshot.groups),
                        "cert_templates": len(snapshot.cert_templates),
                        "trusts": len(snapshot.trusts),
                    }
                )
                return snapshot
            except Exception as e:
                log.warning("LDAP collection failed: %s — using empty snapshot", e)
                custody.log_error("ldap_collection", str(e), {"server": cfg.server, "auth_mode": cfg.auth_mode.value})
        
        return ADSnapshot(
            domain="unknown.local", domain_sid="", base_dn="",
            timestamp=datetime.now(timezone.utc)
        )

    def _collect_logs(self, evtx_paths):
        from advulture.collection.log_ingester import EVTXIngester, EventStream
        from datetime import datetime, timezone
        
        custody = ChainOfCustodyLogger.get_instance()
        paths = evtx_paths or self.config.logs.evtx_paths
        
        if paths:
            start_time = datetime.now(timezone.utc)
            custody.log_collection(
                source="evtx_files",
                details={"paths": [str(p) for p in paths], "file_count": len(paths)}
            )
            
            stream = EVTXIngester(paths).ingest()
            duration_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            
            custody.log_data_access(
                data_type="security_events",
                operation="parse",
                record_count=len(stream.events) if hasattr(stream, 'events') else 0,
                details={"evtx_files": len(paths)}
            )
            return stream
        return EventStream([])

    def _get_shared_entra_enumerator(self):
        """Get or create a shared EntraEnumerator to avoid duplicate authentication prompts."""
        if self._shared_entra_enumerator is not None:
            return self._shared_entra_enumerator
        
        from advulture.collection.entra_ingester import EntraEnumerator
        
        cfg = self.config.entra
        auth_mode = cfg.auth_mode.value if hasattr(cfg.auth_mode, 'value') else cfg.auth_mode
        
        self._shared_entra_enumerator = EntraEnumerator(
            tenant_id=cfg.tenant_id,
            client_id=cfg.client_id,
            client_secret=cfg.client_secret or None,
            certificate_path=cfg.certificate_path or None,
            certificate_password=cfg.certificate_password or None,
            auth_mode=auth_mode,
        )
        return self._shared_entra_enumerator

    def _collect_entra(self):
        """Collect Entra ID data using async enumeration wrapped in asyncio.run()."""
        import asyncio
        from datetime import datetime, timezone
        
        custody = ChainOfCustodyLogger.get_instance()
        cfg = self.config.entra
        
        if not cfg.enabled:
            return None
        
        try:
            start_time = datetime.now(timezone.utc)
            auth_mode = cfg.auth_mode.value if hasattr(cfg.auth_mode, 'value') else cfg.auth_mode
            
            custody.log_auth(
                method=f"entra_{auth_mode}",
                details={"tenant_id": cfg.tenant_id or "organizations", "auth_mode": auth_mode},
                target="microsoft_graph"
            )
            
            # Use shared enumerator to avoid duplicate auth prompts
            enumerator = self._get_shared_entra_enumerator()
            
            # Run async enumeration in sync context
            snapshot = asyncio.run(enumerator.enumerate_all())
            
            duration_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            custody.log_collection(
                source="entra_id",
                details={"tenant": snapshot.tenant_id if hasattr(snapshot, 'tenant_id') else "unknown"},
                record_count=len(snapshot.users) + len(snapshot.service_principals),
                duration_ms=duration_ms
            )
            custody.log_data_access(
                data_type="entra_objects",
                operation="enumerate",
                record_count=len(snapshot.users) + len(snapshot.service_principals),
                details={
                    "users": len(snapshot.users),
                    "service_principals": len(snapshot.service_principals),
                    "role_assignments": len(snapshot.critical_role_assignments),
                    "ca_policies": len(snapshot.ca_policies),
                }
            )
            return snapshot
        except Exception as e:
            log.warning("Entra ID collection failed: %s — skipping cloud analysis", e)
            custody.log_error("entra_collection", str(e), {"auth_mode": auth_mode})
            return None

    def _collect_adfs(self, event_stream):
        from advulture.collection.adfs_ingester import ADFSLogIngester
        
        custody = ChainOfCustodyLogger.get_instance()
        adfs_evtx = self.config.logs.evtx_paths  # filter ADFS channels in production
        
        custody.log_collection(source="adfs_events", details={"evtx_count": len(adfs_evtx)})
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
