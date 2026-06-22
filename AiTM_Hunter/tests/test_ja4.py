"""Unit tests for JA4S computation module."""

import pytest
from aitm_hunter.ja4 import (
    is_grease,
    parse_server_hello,
    compute_ja4s,
    get_alpn_chars,
    TLSServerHello,
    JA4SResult,
    TLS_VERSION_MAP,
    GREASE_VALUES,
    cipher_name_to_hex,
)


class TestGREASE:
    """Tests for GREASE value detection."""

    def test_grease_values_detected(self):
        """All GREASE values should be detected."""
        grease_examples = [0x0a0a, 0x1a1a, 0x2a2a, 0xfafa]
        for val in grease_examples:
            assert is_grease(val), f"{hex(val)} should be GREASE"

    def test_non_grease_values(self):
        """Normal TLS values should not be GREASE."""
        normal_values = [0x0000, 0x0001, 0x1301, 0xc02f, 0x0035]
        for val in normal_values:
            assert not is_grease(val), f"{hex(val)} should not be GREASE"


class TestTLSVersionMapping:
    """Tests for TLS version mapping."""

    def test_tls13_mapping(self):
        """TLS 1.3 should map to '13'."""
        assert TLS_VERSION_MAP[0x0304] == "13"

    def test_tls12_mapping(self):
        """TLS 1.2 should map to '12'."""
        assert TLS_VERSION_MAP[0x0303] == "12"

    def test_ssl3_mapping(self):
        """SSL 3.0 should map to 's3'."""
        assert TLS_VERSION_MAP[0x0300] == "s3"


class TestCipherMapping:
    """Tests for cipher name to hex mapping."""

    def test_tls13_cipher(self):
        """TLS 1.3 cipher should map correctly."""
        assert cipher_name_to_hex("TLS_AES_128_GCM_SHA256") == "1301"
        assert cipher_name_to_hex("TLS_AES_256_GCM_SHA384") == "1302"

    def test_tls12_cipher(self):
        """TLS 1.2 cipher should map correctly."""
        assert cipher_name_to_hex("ECDHE-RSA-AES128-GCM-SHA256") == "c02f"
        assert cipher_name_to_hex("AES128-SHA") == "002f"

    def test_unknown_cipher(self):
        """Unknown cipher should return '0000'."""
        assert cipher_name_to_hex("UNKNOWN-CIPHER-XYZ") == "0000"


class TestALPNChars:
    """Tests for ALPN character extraction."""

    def test_alpn_h2(self):
        """HTTP/2 ALPN should return 'h2'."""
        assert get_alpn_chars("h2") == "h2"

    def test_alpn_http11(self):
        """HTTP/1.1 ALPN should return 'h1'."""
        assert get_alpn_chars("http/1.1") == "h1"

    def test_alpn_empty(self):
        """Empty ALPN should return '00'."""
        assert get_alpn_chars("") == "00"

    def test_alpn_single_char(self):
        """Single char ALPN should repeat the char."""
        assert get_alpn_chars("x") == "xx"


class TestJA4SComputation:
    """Tests for JA4S fingerprint computation."""

    def test_compute_ja4s_basic(self):
        """Basic JA4S computation should work with 7-char prefix."""
        server_hello = TLSServerHello(
            version=0x0303,  # TLS 1.2
            cipher_suite=0xc030,  # ECDHE-RSA-AES256-GCM-SHA384
            extensions=[0x0000, 0x000b, 0x000d],  # SNI, EC Points, Sig Algs
            session_id_length=0,
            compression_method=0,
            alpn_value="h2",
        )
        
        result = compute_ja4s(server_hello)
        
        # Format: t (1) + 12 (2) + 03 (2) + h2 (2) = 7 chars before underscore
        assert result.ja4s.startswith("t1203h2_c030_")
        assert len(result.ja4s.split("_")[0]) == 7  # 7 chars before first underscore
        assert result.version == "12"
        assert result.cipher == "c030"

    def test_compute_ja4s_no_extensions_no_alpn(self):
        """JA4S with no extensions or ALPN should use zeros."""
        server_hello = TLSServerHello(
            version=0x0304,  # TLS 1.3
            cipher_suite=0x1301,  # TLS_AES_128_GCM_SHA256
            extensions=[],
            session_id_length=0,
            compression_method=0,
            alpn_value="",
        )
        
        result = compute_ja4s(server_hello)
        
        # t + 13 + 00 + 00 = t130000
        assert result.ja4s == "t130000_1301_000000000000"
        assert result.extensions_hash == "000000000000"

    def test_compute_ja4s_with_alpn(self):
        """JA4S with ALPN should include ALPN chars."""
        server_hello = TLSServerHello(
            version=0x0304,
            cipher_suite=0x1302,
            extensions=[0x002b],  # supported_versions
            session_id_length=0,
            compression_method=0,
            alpn_value="h2",
        )
        
        result = compute_ja4s(server_hello)
        
        # t + 13 + 01 + h2 = t1301h2
        assert result.ja4s.startswith("t1301h2_1302_")

    def test_compute_ja4s_extensions_sorted(self):
        """Extensions should be sorted for hashing."""
        server_hello1 = TLSServerHello(
            version=0x0303,
            cipher_suite=0x002f,
            extensions=[0x0005, 0x0001, 0x0003],
            session_id_length=0,
            compression_method=0,
            alpn_value="",
        )
        
        server_hello2 = TLSServerHello(
            version=0x0303,
            cipher_suite=0x002f,
            extensions=[0x0003, 0x0005, 0x0001],  # Different order
            session_id_length=0,
            compression_method=0,
            alpn_value="",
        )
        
        result1 = compute_ja4s(server_hello1)
        result2 = compute_ja4s(server_hello2)
        
        assert result1.extensions_hash == result2.extensions_hash
        assert result1.ja4s == result2.ja4s


class TestJA4SResult:
    """Tests for JA4SResult dataclass."""

    def test_result_fields(self):
        """JA4SResult should have all expected fields."""
        result = JA4SResult(
            ja4s="t1200_002f_abc123def456",
            ja4s_raw="t1200_002f_0001,0005",
            version="12",
            cipher="002f",
            extensions_hash="abc123def456",
            extensions_list=[0x0001, 0x0005],
            error="",
        )
        
        assert result.ja4s == "t1200_002f_abc123def456"
        assert result.version == "12"
        assert len(result.extensions_list) == 2


class TestServerHelloParsing:
    """Tests for ServerHello parsing."""

    def test_parse_minimal_server_hello(self):
        """Should handle minimal ServerHello without extensions."""
        # Minimal ServerHello: version(2) + random(32) + session_id_len(1) + cipher(2) + compression(1)
        # Total: 38 bytes minimum
        data = bytes([
            0x03, 0x03,  # Version: TLS 1.2
        ] + [0x00] * 32 + [  # Random: 32 zero bytes
            0x00,  # Session ID length: 0
            0x00, 0x2f,  # Cipher: TLS_RSA_WITH_AES_128_CBC_SHA
            0x00,  # Compression: null
        ])
        
        result = parse_server_hello(data)
        
        assert result is not None
        assert result.version == 0x0303
        assert result.cipher_suite == 0x002f
        assert result.extensions == []
        assert result.alpn_value == ""

    def test_parse_too_short_data(self):
        """Should return None for too-short data."""
        result = parse_server_hello(b"\x03\x03")  # Only 2 bytes
        assert result is None

    def test_parse_with_alpn_extension(self):
        """Should extract ALPN value from extensions."""
        # Build ServerHello with ALPN extension
        # version(2) + random(32) + session_id_len(1) + cipher(2) + compression(1)
        # + extensions_len(2) + ALPN extension
        base = bytes([0x03, 0x03] + [0x00] * 32 + [0x00, 0x00, 0x2f, 0x00])
        
        # ALPN extension: type(0x0010) + len + list_len + string_len + "h2"
        alpn_ext = bytes([
            0x00, 0x10,  # ALPN extension type
            0x00, 0x05,  # Extension length: 5
            0x00, 0x03,  # ALPN list length: 3
            0x02,        # First ALPN string length: 2
            0x68, 0x32,  # "h2"
        ])
        
        extensions_len = bytes([0x00, len(alpn_ext)])
        data = base + extensions_len + alpn_ext
        
        result = parse_server_hello(data)
        
        assert result is not None
        assert result.alpn_value == "h2"
