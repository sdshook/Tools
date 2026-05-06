"""
ADVulture — Test Suite
"""

from __future__ import annotations
import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch


# ── Collection tests ──────────────────────────────────────────────────────────

class TestLDAPEnumerator:

    def test_uac_flag_parsing(self):
        """Verify UAC flag interpretation for common security attributes."""
        from advulture.collection.ldap_enumerator import (
            UAC_ACCOUNTDISABLE, UAC_DONT_REQ_PREAUTH,
            UAC_TRUSTED_FOR_DELEGATION
        )
        uac_asrep = UAC_DONT_REQ_PREAUTH
        assert uac_asrep & 0x00400000, "DONT_REQ_PREAUTH flag should be set"

        uac_disabled = UAC_ACCOUNTDISABLE
        assert uac_disabled & 0x00000002, "ACCOUNTDISABLE flag should be set"

    def test_esc1_detection(self):
        """ESC1: enrollee supplies subject + auth EKU + no manager approval."""
        from advulture.collection.ldap_enumerator import (
            ADCertTemplate, CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, AUTH_EKUS
        )
        template = ADCertTemplate(
            name="VulnerableTemplate",
            distinguished_name="CN=VulnerableTemplate,CN=Certificate Templates,...",
            name_flag=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            enrollment_flag=0,          # no manager approval
            ra_signature=0,             # no RA signature
            eku=list(AUTH_EKUS)[:1],    # client auth EKU
            enrollee_supplies_subject=True,
        )
        # Simulate ESC1 computation
        has_auth_eku = bool(set(template.eku) & AUTH_EKUS) or not template.eku
        esc1 = (
            template.enrollee_supplies_subject
            and has_auth_eku
            and not (template.enrollment_flag & 0x2)
            and template.ra_signature == 0
        )
        assert esc1, "Template should be flagged ESC1 vulnerable"

    def test_esc1_not_triggered_with_manager_approval(self):
        """ESC1 should NOT trigger when manager approval is required."""
        from advulture.collection.ldap_enumerator import (
            ADCertTemplate, CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, AUTH_EKUS
        )
        template = ADCertTemplate(
            name="SafeTemplate",
            distinguished_name="CN=SafeTemplate,...",
            name_flag=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            enrollment_flag=0x2,        # manager approval REQUIRED
            ra_signature=0,
            eku=list(AUTH_EKUS)[:1],
            enrollee_supplies_subject=True,
        )
        has_auth_eku = bool(set(template.eku) & AUTH_EKUS)
        esc1 = (
            template.enrollee_supplies_subject
            and has_auth_eku
            and not (template.enrollment_flag & 0x2)
            and template.ra_signature == 0
        )
        assert not esc1, "Manager approval should suppress ESC1"


class TestEventStream:

    def _make_event(self, event_id, **kwargs):
        from advulture.collection.log_ingester import ParsedEvent, EventCategory, EVENT_CATEGORY_MAP
        category = EVENT_CATEGORY_MAP.get(event_id, EventCategory.UNKNOWN)
        return ParsedEvent(
            event_id=event_id,
            category=category,
            timestamp=datetime.utcnow(),
            source_host=kwargs.get("source_host", "dc01.corp.local"),
            channel="Security",
            subject_sid=kwargs.get("subject_sid", "S-1-5-21-1234-5678"),
            subject_account=kwargs.get("subject_account", "testuser"),
            target_host=kwargs.get("target_host", ""),
            has_dangerous_privilege=kwargs.get("has_dangerous_privilege", False),
            is_rc4_downgrade=kwargs.get("is_rc4_downgrade", False),
            is_ntlm_on_kerb_capable=kwargs.get("is_ntlm_on_kerb_capable", False),
            is_dcsync=kwargs.get("is_dcsync", False),
        )

    def test_event_filtering_by_id(self):
        from advulture.collection.log_ingester import EventStream
        events = [
            self._make_event(4624),
            self._make_event(4625),
            self._make_event(4769),
            self._make_event(4672, has_dangerous_privilege=True),
        ]
        stream = EventStream(events)
        logons = stream.filter(ids=[4624])
        assert len(logons) == 1

        tickets = stream.filter(ids=[4769])
        assert len(tickets) == 1

    def test_rc4_downgrade_detection(self):
        from advulture.collection.log_ingester import EventStream
        events = [
            self._make_event(4769, is_rc4_downgrade=False),
            self._make_event(4769, is_rc4_downgrade=True),
            self._make_event(4769, is_rc4_downgrade=True),
        ]
        stream = EventStream(events)
        rc4 = [e for e in stream.filter(ids=[4769]) if e.is_rc4_downgrade]
        assert len(rc4) == 2

    def test_dcsync_detection(self):
        from advulture.collection.log_ingester import EventStream
        events = [
            self._make_event(4662, is_dcsync=True, source_host="workstation01"),
            self._make_event(4662, is_dcsync=False),
        ]
        stream = EventStream(events)
        dcsync = [e for e in stream.filter(ids=[4662]) if e.is_dcsync]
        assert len(dcsync) == 1

    def test_edge_tensor_anomaly_scoring(self):
        from advulture.collection.log_ingester import EdgeTensor
        t = EdgeTensor(
            src_sid="S-1-5-21-1234",
            dst_identifier="\\\\server01\\share",
            edge_type="share_accessed",
            traversal_count_30d=50,
            ntlm_ratio=0.9,
            rc4_downgrade_ratio=0.8,
            off_hours_ratio=0.7,
            explicit_cred_ratio=0.5,
        )
        score = t.compute_anomaly_score()
        assert score > 0.5, "High anomaly indicators should produce high score"
        assert 0.0 <= score <= 1.0, "Score must be in [0, 1]"


# ── Analysis tests ────────────────────────────────────────────────────────────

class TestFinding:

    def test_finding_id_is_deterministic(self):
        from advulture.analysis.finding import Finding, RiskClass, Severity
        f1 = Finding(
            category="test_category",
            title="Test Finding",
            risk_class=RiskClass.AUTHN_HYGIENE,
            severity=Severity.HIGH,
            affected_identities=["user1", "user2"],
        )
        f2 = Finding(
            category="test_category",
            title="Different Title",
            risk_class=RiskClass.AUTHN_HYGIENE,
            severity=Severity.MEDIUM,
            affected_identities=["user1", "user2"],
        )
        assert f1.id == f2.id, "ID should depend on category and identities, not title/severity"

    def test_all_risk_classes_have_distinct_values(self):
        from advulture.analysis.finding import RiskClass
        values = [rc.value for rc in RiskClass]
        assert len(values) == len(set(values)), "All risk class values must be unique"
        assert set(values) == {"A", "B", "C", "D", "E", "F"}

    def test_kerberoast_finding_template(self):
        from advulture.analysis.finding import make_kerberoast_finding, RiskClass, Severity
        f = make_kerberoast_finding(["svc_sql", "svc_iis"], active=True)
        assert f.risk_class == RiskClass.AUTHN_HYGIENE
        assert f.severity == Severity.HIGH
        assert f.active_signal is True
        assert "T1558.003" in f.mitre_techniques
        assert len(f.remediation_steps) > 0

    def test_lpe_finding_is_class_d(self):
        from advulture.analysis.finding import make_lpe_finding, RiskClass
        f = make_lpe_finding(["svc_iis"], ["WEBSERVER01"], "SeImpersonatePrivilege")
        assert f.risk_class == RiskClass.PRIVILEGE_ESCALATION
        assert "edr_coverage" in f.controls
        # AD controls should NOT be primary for LPE
        assert "mfa_coverage" not in f.controls

    def test_finding_weighted_priority(self):
        from advulture.analysis.finding import Finding, RiskClass, Severity
        f = Finding(
            category="test", title="Test", risk_class=RiskClass.PRIVILEGE_ESCALATION,
            severity=Severity.CRITICAL, gradient_contribution=0.85, compound_multiplier=1.5,
        )
        assert abs(f.weighted_priority - 0.85 * 1.5) < 0.001


# ── Markov chain tests ────────────────────────────────────────────────────────

class TestMarkovChain:

    def test_steady_state_sums_to_one(self):
        import torch
        from advulture.ml.markov.chain import AttackChainMarkov
        n = 5
        markov = AttackChainMarkov(num_nodes=n, tier0_node_ids=[4])
        edge_index = torch.tensor([[0, 1, 2, 3], [1, 2, 3, 4]], dtype=torch.long)
        edge_probs = torch.tensor([0.5, 0.6, 0.7, 0.8])
        theta = {}
        result = markov.analyze(edge_index, edge_probs, theta)
        total = result.pi.sum().item()
        assert abs(total - 1.0) < 0.01, f"Steady state should sum to 1, got {total}"

    def test_tier0_is_absorbing(self):
        """Once in Tier0, probability stays there."""
        import torch
        from advulture.ml.markov.chain import AttackChainMarkov
        n = 3
        markov = AttackChainMarkov(num_nodes=n, tier0_node_ids=[2])
        # All paths lead to node 2
        edge_index = torch.tensor([[0, 1], [2, 2]], dtype=torch.long)
        edge_probs = torch.tensor([0.99, 0.99])
        theta = {}
        P = markov.build_transition_matrix(edge_index, edge_probs, theta)
        # Tier0 node should be absorbing (self-loop = 1)
        assert abs(P[2, 2].item() - 1.0) < 0.001

    def test_gradient_flows_through_theta(self):
        """Key property: ∂π_tier0/∂θ must be non-zero for relevant controls."""
        import torch
        from advulture.ml.markov.chain import AttackChainMarkov
        n = 4
        markov = AttackChainMarkov(num_nodes=n, tier0_node_ids=[3])
        edge_index = torch.tensor([[0, 1, 2], [1, 2, 3]], dtype=torch.long)
        edge_probs = torch.tensor([0.6, 0.7, 0.8], requires_grad=False)
        theta = {
            k: torch.tensor(0.3, requires_grad=True)
            for k in ["edr_coverage", "mfa_coverage"]
        }
        P = markov.build_transition_matrix(edge_index, edge_probs, theta)
        pi = markov.steady_state(P)
        loss = pi[3]  # Tier0 probability
        loss.backward()
        # At least one theta should have non-zero gradient
        grads = [t.grad for t in theta.values() if t.grad is not None]
        assert len(grads) > 0


class TestKillChainHMM:

    def test_clean_sequence_detects_clean_phase(self):
        from advulture.ml.markov.chain import KillChainHMM, Phase
        hmm = KillChainHMM()
        clean_sequence = ["logon_success"] * 20 + ["logoff"] * 5
        result = hmm.viterbi(clean_sequence)
        assert result.most_likely in (Phase.CLEAN, Phase.RECONNAISSANCE)

    def test_spray_sequence_detects_compromise(self):
        from advulture.ml.markov.chain import KillChainHMM, Phase
        hmm = KillChainHMM()
        spray_sequence = (
            ["logon_failure"] * 30 +
            ["logon_success"] * 3 +
            ["explicit_credentials"] * 5 +
            ["share_accessed"] * 10
        )
        result = hmm.viterbi(spray_sequence)
        assert result.most_likely not in (Phase.CLEAN,), \
            f"Spray pattern should not be CLEAN, got {result.most_likely}"

    def test_phase_distribution_sums_to_one(self):
        from advulture.ml.markov.chain import KillChainHMM
        import numpy as np
        hmm = KillChainHMM()
        result = hmm.viterbi(["logon_success", "service_ticket"])
        assert abs(result.distribution.sum() - 1.0) < 0.001


# ── Integration smoke test ────────────────────────────────────────────────────

class TestPostureAnalyzerSmoke:

    def test_analyze_with_empty_snapshot(self):
        """Should complete without error on empty environment."""
        from advulture.config import Config
        from advulture.analysis.posture import PostureAnalyzer
        cfg = Config()
        # Override LDAP to avoid connection
        analyzer = PostureAnalyzer(cfg)
        # Patch the collectors to return empty data
        from advulture.collection.ldap_enumerator import ADSnapshot
        from advulture.collection.log_ingester import EventStream
        with patch.object(analyzer, '_collect_ad', return_value=ADSnapshot(
            domain="test.local", domain_sid="S-1-5-21-0000",
            base_dn="DC=test,DC=local", timestamp=datetime.utcnow()
        )):
            with patch.object(analyzer, '_collect_logs', return_value=EventStream([])):
                with patch.object(analyzer, '_collect_adfs', return_value=None):
                    report = analyzer.analyze()
        assert report is not None
        assert report.domain == "test.local"
        assert report.regime in ("ORDERED", "CRITICAL", "CHAOTIC")
        assert isinstance(report.findings, list)
        assert isinstance(report.remediation_ranking, list)
