"""Unit tests for triage module."""

import pytest
from aitm_hunter.triage import (
    typosquat_score,
    score_risk,
    TriageResult,
    get_domain,
    DEFAULT_BRAND_DOMAINS,
    _is_legitimate_domain_or_subdomain,
)


class TestTyposquatScoring:
    """Tests for typosquat detection."""

    def test_exact_match_returns_zero(self):
        """Legitimate domains should not be flagged as typosquats."""
        brand, score = typosquat_score("microsoft.com", DEFAULT_BRAND_DOMAINS)
        assert score == 0.0
        assert brand == ""

    def test_subdomain_of_legitimate_returns_zero(self):
        """Subdomains of legitimate domains should not be flagged."""
        brand, score = typosquat_score("login.microsoftonline.com", DEFAULT_BRAND_DOMAINS)
        assert score == 0.0

    def test_typosquat_detected(self):
        """Typosquats should have high similarity scores."""
        brand, score = typosquat_score("micros0ft.com", DEFAULT_BRAND_DOMAINS)
        assert score > 70  # Should be high similarity
        assert brand == "microsoft"

    def test_unrelated_domain_low_score(self):
        """Unrelated domains should have low similarity scores."""
        brand, score = typosquat_score("totallyunrelatedwebsite.net", DEFAULT_BRAND_DOMAINS)
        assert score < 50

    def test_is_legitimate_domain(self):
        """Test the legitimate domain checker."""
        assert _is_legitimate_domain_or_subdomain("microsoft.com", DEFAULT_BRAND_DOMAINS)
        assert _is_legitimate_domain_or_subdomain("login.microsoftonline.com", DEFAULT_BRAND_DOMAINS)
        assert not _is_legitimate_domain_or_subdomain("micros0ft.com", DEFAULT_BRAND_DOMAINS)


class TestRiskScoring:
    """Tests for risk score calculation."""

    def test_clean_result_low_score(self):
        """A clean result should have a low risk score."""
        result = TriageResult(
            original_url="https://microsoft.com",
            final_url="https://microsoft.com",
            redirect_count=0,
            urlhaus_flagged=False,
            safe_browsing_flagged=False,
        )
        score, reasons = score_risk(result)
        assert score == 0
        assert len(reasons) == 0

    def test_urlhaus_flagged_high_score(self):
        """URLhaus flagged domains should get high risk score."""
        result = TriageResult(
            original_url="https://badsite.com",
            final_url="https://badsite.com",
            urlhaus_flagged=True,
        )
        score, reasons = score_risk(result)
        assert score >= 50
        assert any("URLhaus" in r for r in reasons)

    def test_safe_browsing_flagged_high_score(self):
        """Safe Browsing flagged domains should get high risk score."""
        result = TriageResult(
            original_url="https://badsite.com",
            final_url="https://badsite.com",
            safe_browsing_flagged=True,
            safe_browsing_threats=["SOCIAL_ENGINEERING"],
        )
        score, reasons = score_risk(result)
        assert score >= 50
        assert any("Safe Browsing" in r for r in reasons)

    def test_new_domain_increases_score(self):
        """Newly registered domains should increase risk score."""
        result = TriageResult(
            original_url="https://newsite.com",
            final_url="https://newsite.com",
            domain_age_days=5,
        )
        score, reasons = score_risk(result)
        assert score >= 25
        assert any("days ago" in r for r in reasons)

    def test_high_typosquat_increases_score(self):
        """High typosquat score should increase risk."""
        result = TriageResult(
            original_url="https://micros0ft.com",
            final_url="https://micros0ft.com",
            typosquat_target="microsoft",
            typosquat_score=90.0,
        )
        score, reasons = score_risk(result)
        assert score >= 30
        assert any("similarity" in r.lower() for r in reasons)

    def test_multiple_redirects_increases_score(self):
        """Multiple redirects should increase risk score."""
        result = TriageResult(
            original_url="https://somesite.com",
            final_url="https://finalsite.com",
            redirect_count=5,
        )
        score, reasons = score_risk(result)
        assert score >= 10
        assert any("redirect" in r.lower() for r in reasons)

    def test_combined_signals_cap_at_100(self):
        """Combined signals should cap at 100."""
        result = TriageResult(
            original_url="https://badsite.com",
            final_url="https://badsite.com",
            urlhaus_flagged=True,
            safe_browsing_flagged=True,
            safe_browsing_threats=["MALWARE"],
            domain_age_days=2,
            typosquat_target="microsoft",
            typosquat_score=95.0,
            redirect_count=5,
        )
        score, reasons = score_risk(result)
        assert score == 100


class TestDomainExtraction:
    """Tests for domain extraction."""

    def test_simple_domain(self):
        """Test extraction of simple domain."""
        domain = get_domain("https://example.com/path")
        assert "example.com" in domain

    def test_subdomain(self):
        """Test extraction preserves subdomain info."""
        domain = get_domain("https://login.microsoft.com/oauth")
        assert "microsoft.com" in domain
