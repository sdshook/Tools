"""Unit tests for fingerprint module."""

import pytest
from aitm_hunter.fingerprint import (
    KNOWN_MALWARE_JA4_CLIENT,
    KNOWN_AITM_JA4S_SIGNATURES,
    KNOWN_MALWARE_JA4X,
    KNOWN_MALWARE_JA4H,
    KNOWN_MALWARE_JA3,
    IDP_LIVE_RESOURCE_PROBES,
    check_known_kit_signature,
    check_all_signatures,
    FingerprintResult,
    FullFingerprintResult,
)
from aitm_hunter.signatures import get_signature_stats


class TestSignatureDatabases:
    """Tests for JA4+ signature databases."""

    def test_ja4_client_signatures_populated(self):
        """JA4 client signature database should have substantial entries."""
        assert len(KNOWN_MALWARE_JA4_CLIENT) >= 30
        # Check for known malware
        assert "t13d191000_9dc949149365_e7c285222651" in KNOWN_MALWARE_JA4_CLIENT
        assert "Evilginx" in KNOWN_MALWARE_JA4_CLIENT["t13d191000_9dc949149365_e7c285222651"]

    def test_ja4s_signatures_populated(self):
        """JA4S server signature database should have entries."""
        assert len(KNOWN_AITM_JA4S_SIGNATURES) >= 5

    def test_ja4x_signatures_populated(self):
        """JA4X certificate signature database should have entries."""
        assert len(KNOWN_MALWARE_JA4X) >= 5
        # Check for known C2
        assert "2166164053c1_2166164053c1_30d204a01551" in KNOWN_MALWARE_JA4X
        assert "Cobalt Strike" in KNOWN_MALWARE_JA4X["2166164053c1_2166164053c1_30d204a01551"]

    def test_ja4h_signatures_populated(self):
        """JA4H HTTP signature database should have substantial entries."""
        assert len(KNOWN_MALWARE_JA4H) >= 25
        
    def test_ja3_signatures_populated(self):
        """JA3 legacy signature database should have entries."""
        assert len(KNOWN_MALWARE_JA3) >= 5

    def test_total_signatures_substantial(self):
        """Total signature count should be substantial for detection coverage."""
        stats = get_signature_stats()
        assert stats["total_fingerprints"] >= 80
        assert stats["malware_families"] >= 20


class TestSignatureMatching:
    """Tests for signature matching functions."""

    def test_check_known_kit_signature_match(self):
        """Known JA4S signature should return kit name."""
        result = check_known_kit_signature("t120300_c030_5e2616a54c73")
        assert "IcedID" in result

    def test_check_known_kit_signature_no_match(self):
        """Unknown signature should return empty string."""
        result = check_known_kit_signature("unknown_hash_12345")
        assert result == ""

    def test_check_all_signatures_ja4_match(self):
        """JA4 client match should be detected."""
        matches = check_all_signatures(
            ja4_hash="t13d191000_9dc949149365_e7c285222651"
        )
        assert len(matches) == 1
        assert matches[0][0] == "JA4"
        assert "Evilginx" in matches[0][2]

    def test_check_all_signatures_ja4x_match(self):
        """JA4X certificate match should be detected."""
        matches = check_all_signatures(
            ja4x_hash="2bab15409345_af684594efb4_000000000000"
        )
        assert len(matches) == 1
        assert matches[0][0] == "JA4X"
        assert "Qakbot" in matches[0][2]

    def test_check_all_signatures_multiple_matches(self):
        """Multiple signature types can match simultaneously."""
        matches = check_all_signatures(
            ja4_hash="t13d201100_2b729b4bf6f3_9e7b989ebec8",  # IcedID client
            ja4s_hash="t120300_c030_5e2616a54c73",  # IcedID C2
        )
        assert len(matches) == 2

    def test_check_all_signatures_no_match(self):
        """No matches should return empty list."""
        matches = check_all_signatures(
            ja4_hash="unknown",
            ja4s_hash="unknown",
        )
        assert len(matches) == 0


class TestProbeResources:
    """Tests for IdP probe resource configuration."""

    def test_microsoft_probes_exist(self):
        """Microsoft should have probe resources defined."""
        assert "microsoft" in IDP_LIVE_RESOURCE_PROBES
        assert len(IDP_LIVE_RESOURCE_PROBES["microsoft"]) >= 1

    def test_google_probes_exist(self):
        """Google should have probe resources defined."""
        assert "google" in IDP_LIVE_RESOURCE_PROBES
        assert len(IDP_LIVE_RESOURCE_PROBES["google"]) >= 1

    def test_okta_probes_exist(self):
        """Okta should have probe resources defined."""
        assert "okta" in IDP_LIVE_RESOURCE_PROBES
        assert len(IDP_LIVE_RESOURCE_PROBES["okta"]) >= 1


class TestDataclasses:
    """Tests for result dataclasses."""

    def test_fingerprint_result_to_dict(self):
        """FingerprintResult should serialize to dict."""
        result = FingerprintResult(
            domain="example.com",
            ip_address="1.2.3.4",
            tls_version="TLSv1.3",
        )
        d = result.to_dict()
        assert d["domain"] == "example.com"
        assert d["ip_address"] == "1.2.3.4"
        assert d["tls_version"] == "TLSv1.3"

    def test_full_fingerprint_result_to_dict(self):
        """FullFingerprintResult should serialize to dict."""
        result = FullFingerprintResult(
            url="https://example.com",
            domain="example.com",
            is_likely_aitm=True,
            fingerprint_risk_score=50,
        )
        d = result.to_dict()
        assert d["url"] == "https://example.com"
        assert d["is_likely_aitm"] is True
        assert d["fingerprint_risk_score"] == 50
