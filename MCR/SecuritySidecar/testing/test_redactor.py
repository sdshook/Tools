"""
Tests for the SecuritySidecar redactor module.

Run with: pytest testing/test_redactor.py -v
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from redactor import (
    redact,
    redact_credentials,
    redact_pii,
    redact_internal_topology,
    build_placeholder,
)
from models import TrustLevel, RedactionResult


class TestCredentialRedaction:
    """Tests for credential and secret redaction."""

    def test_aws_access_key_redacted(self):
        text = "My key is AKIAIOSFODNN7EXAMPLE"
        result = redact_credentials(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result["redacted"]
        assert "[REDACTED:aws_key:" in result["redacted"]
        assert len(result["records"]) == 1

    def test_bearer_token_redacted(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = redact_credentials(text)
        assert "eyJ" not in result["redacted"]
        assert "[REDACTED:bearer_token:" in result["redacted"]

    def test_github_token_redacted(self):
        text = "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        result = redact_credentials(text)
        assert "ghp_" not in result["redacted"]
        assert "[REDACTED:github_token:" in result["redacted"]

    def test_private_key_redacted(self):
        text = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy
-----END RSA PRIVATE KEY-----"""
        result = redact_credentials(text)
        assert "BEGIN RSA PRIVATE KEY" not in result["redacted"]
        assert "[REDACTED:private_key:" in result["redacted"]

    def test_api_key_formats_redacted(self):
        text = "api_key=sk-proj-abc123def456ghi789"
        result = redact_credentials(text)
        assert "sk-proj" not in result["redacted"]

    def test_clean_text_unchanged(self):
        text = "This is a normal message with no secrets."
        result = redact_credentials(text)
        assert result["redacted"] == text
        assert len(result["records"]) == 0


class TestPIIRedaction:
    """Tests for personally identifiable information redaction."""

    def test_ssn_redacted(self):
        text = "SSN: 123-45-6789"
        result = redact_pii(text)
        assert "123-45-6789" not in result["redacted"]
        assert "[REDACTED:ssn:" in result["redacted"]

    def test_credit_card_redacted(self):
        text = "Card: 4111-1111-1111-1111"
        result = redact_pii(text)
        assert "4111" not in result["redacted"]
        assert "[REDACTED:credit_card:" in result["redacted"]

    def test_email_redacted(self):
        text = "Contact: user@example.com"
        result = redact_pii(text)
        assert "user@example.com" not in result["redacted"]
        assert "[REDACTED:email:" in result["redacted"]

    def test_phone_redacted(self):
        text = "Call me at (555) 123-4567"
        result = redact_pii(text)
        assert "555" not in result["redacted"]
        assert "[REDACTED:phone:" in result["redacted"]

    def test_multiple_pii_redacted(self):
        text = "Email: test@test.com, SSN: 111-22-3333"
        result = redact_pii(text)
        assert "test@test.com" not in result["redacted"]
        assert "111-22-3333" not in result["redacted"]
        assert len(result["records"]) == 2


class TestTopologyRedaction:
    """Tests for internal network topology redaction."""

    def test_private_ip_10_redacted(self):
        text = "Server at 10.0.0.1"
        result = redact_internal_topology(text)
        assert "10.0.0.1" not in result["redacted"]
        assert "[REDACTED:internal_ip:" in result["redacted"]

    def test_private_ip_172_redacted(self):
        text = "Connect to 172.16.0.100"
        result = redact_internal_topology(text)
        assert "172.16.0.100" not in result["redacted"]

    def test_private_ip_192_redacted(self):
        text = "Gateway: 192.168.1.1"
        result = redact_internal_topology(text)
        assert "192.168.1.1" not in result["redacted"]

    def test_internal_hostname_redacted(self):
        text = "Connect to db-prod-01.internal.corp"
        result = redact_internal_topology(text)
        assert "db-prod-01.internal.corp" not in result["redacted"]
        assert "[REDACTED:internal_host:" in result["redacted"]

    def test_subnet_redacted(self):
        text = "Subnet: 10.0.0.0/24"
        result = redact_internal_topology(text)
        assert "10.0.0.0/24" not in result["redacted"]

    def test_public_ip_unchanged(self):
        text = "External IP: 8.8.8.8"
        result = redact_internal_topology(text)
        assert "8.8.8.8" in result["redacted"]


class TestPlaceholderBuilder:
    """Tests for redaction placeholder generation."""

    def test_placeholder_format(self):
        placeholder = build_placeholder("api_key", "sk-secret123")
        assert placeholder.startswith("[REDACTED:api_key:")
        assert placeholder.endswith("]")
        assert len(placeholder) < 30  # Should be truncated hash

    def test_placeholder_hash_consistency(self):
        p1 = build_placeholder("email", "test@example.com")
        p2 = build_placeholder("email", "test@example.com")
        assert p1 == p2  # Same input should produce same hash

    def test_placeholder_hash_uniqueness(self):
        p1 = build_placeholder("email", "a@example.com")
        p2 = build_placeholder("email", "b@example.com")
        assert p1 != p2  # Different input should produce different hash


class TestFullRedaction:
    """Integration tests for the full redaction pipeline."""

    def test_high_trust_not_redacted(self):
        text = "SSN: 123-45-6789, IP: 10.0.0.1"
        result = redact(text, TrustLevel.HIGH)
        assert isinstance(result, RedactionResult)
        assert result.redacted_content == text  # No redaction for high trust
        assert len(result.records) == 0

    def test_low_trust_fully_redacted(self):
        text = "SSN: 123-45-6789, IP: 10.0.0.1, key: AKIAIOSFODNN7EXAMPLE"
        result = redact(text, TrustLevel.LOW)
        assert "123-45-6789" not in result.redacted_content
        assert "10.0.0.1" not in result.redacted_content
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_content
        assert len(result.records) >= 3

    def test_untrusted_fully_redacted(self):
        text = "Email: user@corp.com"
        result = redact(text, TrustLevel.UNTRUSTED)
        assert "user@corp.com" not in result.redacted_content

    def test_medium_trust_partial_redaction(self):
        # Medium trust redacts credentials but not all PII
        text = "Token: ghp_secret123"
        result = redact(text, TrustLevel.MEDIUM)
        assert "ghp_secret123" not in result.redacted_content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
