"""
Tests for the SecuritySidecar redactor module.

Run with: pytest testing/test_redactor.py -v
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from models import TrustLevel, RedactionResult


class TestCredentialRedaction:
    """Tests for credential and secret redaction via redact()."""

    def test_aws_access_key_redacted(self):
        from redactor import redact
        text = "My key is AKIAIOSFODNN7EXAMPLE"
        result = redact(text, TrustLevel.LOW)
        assert "AKIAIOSFODNN7EXAMPLE" not in result.content
        assert "[REDACTED:aws_access_key:" in result.content
        assert len(result.records) >= 1

    def test_github_token_redacted(self):
        from redactor import redact
        text = "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        result = redact(text, TrustLevel.LOW)
        assert "ghp_" not in result.content
        assert "[REDACTED:github_token:" in result.content

    def test_private_key_redacted(self):
        from redactor import redact
        text = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy
-----END RSA PRIVATE KEY-----"""
        result = redact(text, TrustLevel.LOW)
        assert "BEGIN RSA PRIVATE KEY" not in result.content
        assert "[REDACTED:private_key:" in result.content

    def test_openai_style_key_redacted(self):
        from redactor import redact
        text = "api_key=sk-proj-abc123def456ghi789jkl012mno345"
        result = redact(text, TrustLevel.UNTRUSTED)
        assert "sk-proj" not in result.content

    def test_clean_text_unchanged(self):
        from redactor import redact
        text = "This is a normal message with no secrets."
        result = redact(text, TrustLevel.LOW)
        assert result.content == text
        assert len(result.records) == 0


class TestPIIRedaction:
    """Tests for personally identifiable information redaction."""

    def test_ssn_redacted(self):
        from redactor import redact
        text = "SSN: 123-45-6789"
        result = redact(text, TrustLevel.LOW)
        assert "123-45-6789" not in result.content
        assert "[REDACTED:ssn:" in result.content

    def test_credit_card_redacted(self):
        from redactor import redact
        # Visa test number
        text = "Card: 4111111111111111"
        result = redact(text, TrustLevel.LOW)
        assert "4111111111111111" not in result.content
        assert "[REDACTED:credit_card:" in result.content

    def test_email_redacted(self):
        from redactor import redact
        text = "Contact: user@example.com"
        result = redact(text, TrustLevel.LOW)
        assert "user@example.com" not in result.content
        assert "[REDACTED:email:" in result.content

    def test_phone_redacted(self):
        from redactor import redact
        text = "Call me at (555) 123-4567"
        result = redact(text, TrustLevel.LOW)
        assert "555" not in result.content or "123-4567" not in result.content
        assert "[REDACTED:phone" in result.content

    def test_multiple_pii_redacted(self):
        from redactor import redact
        text = "Email: test@test.com, SSN: 111-22-3333"
        result = redact(text, TrustLevel.UNTRUSTED)
        assert "test@test.com" not in result.content
        assert "111-22-3333" not in result.content
        assert len(result.records) >= 2


class TestTopologyRedaction:
    """Tests for internal network topology redaction."""

    def test_private_ip_10_redacted(self):
        from redactor import redact
        text = "Server at 10.0.0.1"
        result = redact(text, TrustLevel.LOW)
        assert "10.0.0.1" not in result.content
        assert "[REDACTED:private_ip" in result.content

    def test_private_ip_172_redacted(self):
        from redactor import redact
        text = "Connect to 172.16.0.100"
        result = redact(text, TrustLevel.LOW)
        assert "172.16.0.100" not in result.content

    def test_private_ip_192_redacted(self):
        from redactor import redact
        text = "Gateway: 192.168.1.1"
        result = redact(text, TrustLevel.LOW)
        assert "192.168.1.1" not in result.content

    def test_internal_hostname_redacted(self):
        from redactor import redact
        text = "Connect to db-prod-01.internal"
        result = redact(text, TrustLevel.LOW)
        assert "db-prod-01.internal" not in result.content
        assert "[REDACTED:internal_host:" in result.content

    def test_subnet_redacted(self):
        from redactor import redact
        text = "Subnet: 10.0.0.0/24"
        result = redact(text, TrustLevel.LOW)
        assert "10.0.0.0/24" not in result.content

    def test_public_ip_unchanged(self):
        from redactor import redact
        text = "External IP: 8.8.8.8"
        result = redact(text, TrustLevel.LOW)
        assert "8.8.8.8" in result.content


class TestTrustLevelBehavior:
    """Tests for trust level affecting redaction behavior."""

    def test_high_trust_not_redacted(self):
        from redactor import redact
        text = "SSN: 123-45-6789, IP: 10.0.0.1"
        result = redact(text, TrustLevel.HIGH)
        assert isinstance(result, RedactionResult)
        assert result.content == text  # No redaction for high trust
        assert result.modified is False
        assert len(result.records) == 0

    def test_medium_trust_not_redacted(self):
        from redactor import redact
        text = "SSN: 123-45-6789"
        result = redact(text, TrustLevel.MEDIUM)
        assert result.content == text
        assert result.modified is False

    def test_low_trust_fully_redacted(self):
        from redactor import redact
        text = "SSN: 123-45-6789, IP: 10.0.0.1, key: AKIAIOSFODNN7EXAMPLE"
        result = redact(text, TrustLevel.LOW)
        assert "123-45-6789" not in result.content
        assert "10.0.0.1" not in result.content
        assert "AKIAIOSFODNN7EXAMPLE" not in result.content
        assert result.modified is True
        assert len(result.records) >= 3

    def test_untrusted_fully_redacted(self):
        from redactor import redact
        text = "Email: user@corp.com"
        result = redact(text, TrustLevel.UNTRUSTED)
        assert "user@corp.com" not in result.content
        assert result.modified is True


class TestRedactionRecords:
    """Tests for redaction record generation."""

    def test_record_contains_hash(self):
        from redactor import redact
        text = "Key: AKIAIOSFODNN7EXAMPLE"
        result = redact(text, TrustLevel.LOW)
        assert len(result.records) > 0
        record = result.records[0]
        assert record.original_hash is not None
        assert len(record.original_hash) == 64  # SHA-256 hex

    def test_record_contains_position(self):
        from redactor import redact
        text = "Key: AKIAIOSFODNN7EXAMPLE"
        result = redact(text, TrustLevel.LOW)
        assert len(result.records) > 0
        record = result.records[0]
        assert record.position >= 0

    def test_record_placeholder_format(self):
        from redactor import redact
        text = "Key: AKIAIOSFODNN7EXAMPLE"
        result = redact(text, TrustLevel.LOW)
        assert len(result.records) > 0
        record = result.records[0]
        assert record.placeholder.startswith("[REDACTED:")
        assert record.placeholder.endswith("]")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
