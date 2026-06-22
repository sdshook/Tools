"""
JA4+ Fingerprint Computation Module

This module implements JA4S (TLS Server Fingerprinting) for real-time
detection of malicious server infrastructure.

ATTRIBUTION AND LICENSING:
--------------------------
JA4+ is a network fingerprinting methodology created by:
    John Althouse at FoxIO, LLC
    With contributions from Josh Atkins, Jeff Atkinson, and the security community

The JA4+ methodology is documented at:
    https://github.com/FoxIO-LLC/ja4
    https://blog.foxio.io/ja4+-network-fingerprinting

Licensing:
    - JA4 (TLS Client Fingerprinting): BSD 3-Clause License
    - JA4S, JA4H, JA4X, etc. (JA4+): FoxIO License 1.1
      Permissive for internal security and academic use.
      Commercial/monetized use requires OEM licensing from FoxIO.
      Contact: john@foxio.io

This implementation follows the JA4S specification:
    JA4S = (protocol)(version)(ext_count)(alpn)_(cipher)_(extension_hash)
    
    Where:
    - protocol: 't' for TLS, 'q' for QUIC, 'd' for DTLS (1 char)
    - version: TLS version code (2 chars: 13, 12, 11, 10, s3)
    - ext_count: Number of extensions excluding GREASE (2 chars)
    - alpn: First and last chars of server's ALPN response (2 chars)
    - cipher: 4-char hex of chosen cipher suite
    - extension_hash: 12-char truncated SHA256 of sorted extensions

Reference: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/

Copyright (c) 2024, FoxIO - JA4+ Methodology
Implementation for AiTM Hunter (c) 2026, Shane Shook
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import struct
from dataclasses import dataclass
from typing import Optional

# TLS Version mapping (per JA4 spec)
TLS_VERSION_MAP = {
    0x0304: "13",  # TLS 1.3
    0x0303: "12",  # TLS 1.2
    0x0302: "11",  # TLS 1.1
    0x0301: "10",  # TLS 1.0
    0x0300: "s3",  # SSL 3.0
    # DTLS versions
    0xfefd: "d2",  # DTLS 1.2
    0xfeff: "d1",  # DTLS 1.0
    0xfefc: "d3",  # DTLS 1.3
}

# GREASE values to ignore (per JA4 spec)
# https://datatracker.ietf.org/doc/html/draft-davidben-tls-grease-01
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

# TLS Record Types
TLS_HANDSHAKE = 22

# TLS Handshake Types
HANDSHAKE_SERVER_HELLO = 2


@dataclass
class TLSServerHello:
    """Parsed TLS ServerHello message."""
    version: int
    cipher_suite: int
    extensions: list[int]
    session_id_length: int
    compression_method: int
    alpn_value: str = ""  # Server's chosen ALPN (e.g., "h2", "http/1.1")
    raw_data: bytes = b""


@dataclass
class JA4SResult:
    """JA4S fingerprint computation result."""
    ja4s: str
    ja4s_raw: str
    version: str
    cipher: str
    extensions_hash: str
    extensions_list: list[int]
    error: str = ""


def is_grease(value: int) -> bool:
    """Check if a value is a GREASE value (should be ignored)."""
    return value in GREASE_VALUES


def parse_server_hello(data: bytes) -> Optional[TLSServerHello]:
    """
    Parse a TLS ServerHello message from raw bytes.
    
    ServerHello structure:
        - version (2 bytes)
        - random (32 bytes)
        - session_id_length (1 byte)
        - session_id (variable)
        - cipher_suite (2 bytes)
        - compression_method (1 byte)
        - extensions_length (2 bytes, if present)
        - extensions (variable)
    """
    if len(data) < 38:  # Minimum ServerHello size
        return None
    
    try:
        pos = 0
        
        # Version (2 bytes)
        version = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2
        
        # Random (32 bytes)
        pos += 32
        
        # Session ID
        session_id_length = data[pos]
        pos += 1 + session_id_length
        
        # Cipher Suite (2 bytes)
        if pos + 2 > len(data):
            return None
        cipher_suite = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2
        
        # Compression Method (1 byte)
        if pos >= len(data):
            return None
        compression_method = data[pos]
        pos += 1
        
        # Extensions (if present)
        extensions = []
        alpn_value = ""
        
        if pos + 2 <= len(data):
            extensions_length = struct.unpack("!H", data[pos:pos+2])[0]
            pos += 2
            extensions_end = pos + extensions_length
            
            while pos + 4 <= extensions_end and pos + 4 <= len(data):
                ext_type = struct.unpack("!H", data[pos:pos+2])[0]
                ext_length = struct.unpack("!H", data[pos+2:pos+4])[0]
                ext_data = data[pos+4:pos+4+ext_length] if pos+4+ext_length <= len(data) else b""
                
                # Extract ALPN value (extension type 0x0010)
                if ext_type == 0x0010 and len(ext_data) >= 3:
                    # ALPN extension: list_length(2) + [string_length(1) + string]*
                    alpn_list_len = struct.unpack("!H", ext_data[0:2])[0]
                    if alpn_list_len > 0 and len(ext_data) >= 3:
                        first_alpn_len = ext_data[2]
                        if len(ext_data) >= 3 + first_alpn_len:
                            alpn_value = ext_data[3:3+first_alpn_len].decode("ascii", errors="replace")
                
                pos += 4 + ext_length
                
                # Skip GREASE values
                if not is_grease(ext_type):
                    extensions.append(ext_type)
        
        return TLSServerHello(
            version=version,
            cipher_suite=cipher_suite,
            extensions=extensions,
            session_id_length=session_id_length,
            compression_method=compression_method,
            alpn_value=alpn_value,
            raw_data=data,
        )
    except (struct.error, IndexError):
        return None


def get_alpn_chars(alpn: str) -> str:
    """
    Get the first and last alphanumeric characters of an ALPN value.
    
    Per JA4 spec:
    - If ALPN is empty, return "00"
    - If first/last chars are alphanumeric (0-9, A-Z, a-z), use them
    - Otherwise, use first/last chars of the hex representation
    """
    if not alpn:
        return "00"
    
    if len(alpn) == 1:
        # Single char is both first and last
        c = alpn[0]
        if c.isalnum():
            return c + c
        return f"{ord(c):02x}"[0] + f"{ord(c):02x}"[-1]
    
    first_char = alpn[0]
    last_char = alpn[-1]
    
    # Check if alphanumeric
    if first_char.isalnum() and last_char.isalnum():
        return first_char + last_char
    
    # Use hex representation
    first_hex = f"{ord(first_char):02x}" if not first_char.isalnum() else first_char
    last_hex = f"{ord(last_char):02x}" if not last_char.isalnum() else last_char
    
    return (first_hex[0] if not first_char.isalnum() else first_char) + \
           (last_hex[-1] if not last_char.isalnum() else last_char)


def compute_ja4s(server_hello: TLSServerHello) -> JA4SResult:
    """
    Compute JA4S fingerprint from a parsed ServerHello.
    
    JA4S format: (protocol)(version)(extension_count)(alpn)_(cipher)_(extensions_hash)
    
    Example: t130200_1302_a56c5b993250
    
    Per FoxIO JA4S specification:
    - protocol: 't' for TLS, 'q' for QUIC, 'd' for DTLS (1 char)
    - version: 2-digit TLS version (2 chars)
    - extension_count: 2-digit count of extensions, excluding GREASE (2 chars)
    - alpn: first and last chars of server's ALPN response (2 chars)
    - cipher: 4-char lowercase hex of chosen cipher suite
    - extensions_hash: 12-char truncated SHA256 of sorted extension list
    
    Total JA4S_a: 7 characters before first underscore
    """
    # Determine protocol prefix (we only do TCP TLS here)
    protocol = "t"
    
    # Map version
    version_str = TLS_VERSION_MAP.get(server_hello.version, "00")
    
    # Count extensions (GREASE already filtered)
    ext_count = len(server_hello.extensions)
    ext_count_str = f"{min(ext_count, 99):02d}"
    
    # ALPN characters (first and last of server's chosen ALPN)
    alpn_chars = get_alpn_chars(server_hello.alpn_value)
    
    # Cipher in lowercase hex
    cipher_str = f"{server_hello.cipher_suite:04x}"
    
    # Extensions hash
    if server_hello.extensions:
        # Sort extensions and create comma-separated hex list
        sorted_exts = sorted(server_hello.extensions)
        ext_list_str = ",".join(f"{e:04x}" for e in sorted_exts)
        ext_hash = hashlib.sha256(ext_list_str.encode()).hexdigest()[:12]
    else:
        ext_hash = "000000000000"
    
    # Build JA4S: 7 chars before underscore
    ja4s_a = f"{protocol}{version_str}{ext_count_str}{alpn_chars}"
    ja4s = f"{ja4s_a}_{cipher_str}_{ext_hash}"
    
    # Raw format (for debugging)
    if server_hello.extensions:
        sorted_exts = sorted(server_hello.extensions)
        ext_list_raw = ",".join(f"{e:04x}" for e in sorted_exts)
    else:
        ext_list_raw = ""
    ja4s_raw = f"{ja4s_a}_{cipher_str}_{ext_list_raw}"
    
    return JA4SResult(
        ja4s=ja4s,
        ja4s_raw=ja4s_raw,
        version=version_str,
        cipher=cipher_str,
        extensions_hash=ext_hash,
        extensions_list=server_hello.extensions,
    )


def capture_server_hello(host: str, port: int = 443, timeout: int = 10) -> Optional[bytes]:
    """
    Capture raw TLS ServerHello by performing a TLS handshake.
    
    This uses a lower-level approach to capture the ServerHello bytes
    before the standard SSL library abstracts them away.
    
    Note: This is a best-effort approach. Some servers/configurations
    may not allow us to capture the raw bytes.
    """
    sock = None
    try:
        # Create raw socket
        sock = socket.create_connection((host, port), timeout=timeout)
        
        # Build a minimal TLS ClientHello
        client_hello = build_client_hello(host)
        
        # Send ClientHello
        sock.sendall(client_hello)
        
        # Receive ServerHello
        # TLS Record: type(1) + version(2) + length(2) + data
        header = sock.recv(5)
        if len(header) < 5:
            return None
        
        record_type = header[0]
        record_length = struct.unpack("!H", header[3:5])[0]
        
        if record_type != TLS_HANDSHAKE:
            return None
        
        # Read the handshake message
        data = b""
        while len(data) < record_length:
            chunk = sock.recv(record_length - len(data))
            if not chunk:
                break
            data += chunk
        
        # Check if it's a ServerHello (handshake type 2)
        if len(data) > 0 and data[0] == HANDSHAKE_SERVER_HELLO:
            # Skip handshake header (type + length = 4 bytes)
            return data[4:]
        
        return None
        
    except (socket.error, socket.timeout, OSError):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def build_client_hello(hostname: str) -> bytes:
    """
    Build a minimal TLS 1.2 ClientHello packet.
    
    This is used to initiate the TLS handshake and receive the ServerHello.
    """
    import os
    
    # Random (32 bytes)
    random_bytes = os.urandom(32)
    
    # Session ID (empty)
    session_id = b"\x00"
    
    # Cipher suites (common ones that most servers support)
    cipher_suites = bytes([
        0x00, 0x2f,  # TLS_RSA_WITH_AES_128_CBC_SHA
        0x00, 0x35,  # TLS_RSA_WITH_AES_256_CBC_SHA
        0xc0, 0x2f,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x30,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0x00, 0x9e,  # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        0x00, 0x9f,  # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        0x13, 0x01,  # TLS_AES_128_GCM_SHA256 (TLS 1.3)
        0x13, 0x02,  # TLS_AES_256_GCM_SHA384 (TLS 1.3)
        0x13, 0x03,  # TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
    ])
    cipher_suites_length = struct.pack("!H", len(cipher_suites))
    
    # Compression methods (null only)
    compression = b"\x01\x00"
    
    # Extensions
    extensions = b""
    
    # SNI extension (0x0000)
    hostname_bytes = hostname.encode("ascii")
    sni_data = struct.pack("!H", len(hostname_bytes) + 3)  # list length
    sni_data += b"\x00"  # host name type
    sni_data += struct.pack("!H", len(hostname_bytes))  # host name length
    sni_data += hostname_bytes
    extensions += struct.pack("!HH", 0x0000, len(sni_data)) + sni_data
    
    # Supported versions extension (0x002b) - advertise TLS 1.2 and 1.3
    supported_versions = b"\x05\x03\x04\x03\x03\x03\x02"  # length + TLS 1.3, 1.2, 1.1
    extensions += struct.pack("!HH", 0x002b, len(supported_versions)) + supported_versions
    
    # Signature algorithms extension (0x000d)
    sig_algs = bytes([
        0x04, 0x03,  # ECDSA-SECP256R1-SHA256
        0x05, 0x03,  # ECDSA-SECP384R1-SHA384
        0x08, 0x04,  # RSA-PSS-RSAE-SHA256
        0x08, 0x05,  # RSA-PSS-RSAE-SHA384
        0x08, 0x06,  # RSA-PSS-RSAE-SHA512
        0x04, 0x01,  # RSA-PKCS1-SHA256
        0x05, 0x01,  # RSA-PKCS1-SHA384
        0x06, 0x01,  # RSA-PKCS1-SHA512
    ])
    sig_algs_data = struct.pack("!H", len(sig_algs)) + sig_algs
    extensions += struct.pack("!HH", 0x000d, len(sig_algs_data)) + sig_algs_data
    
    # Supported groups extension (0x000a)
    supported_groups = bytes([
        0x00, 0x1d,  # x25519
        0x00, 0x17,  # secp256r1
        0x00, 0x18,  # secp384r1
        0x00, 0x19,  # secp521r1
    ])
    groups_data = struct.pack("!H", len(supported_groups)) + supported_groups
    extensions += struct.pack("!HH", 0x000a, len(groups_data)) + groups_data
    
    # EC point formats extension (0x000b)
    ec_formats = b"\x01\x00"  # length + uncompressed
    extensions += struct.pack("!HH", 0x000b, len(ec_formats)) + ec_formats
    
    extensions_length = struct.pack("!H", len(extensions))
    
    # Build ClientHello
    client_hello = b""
    client_hello += b"\x03\x03"  # Client version (TLS 1.2)
    client_hello += random_bytes
    client_hello += session_id
    client_hello += cipher_suites_length + cipher_suites
    client_hello += compression
    client_hello += extensions_length + extensions
    
    # Handshake header
    handshake = b"\x01"  # ClientHello type
    handshake += struct.pack("!I", len(client_hello))[1:]  # 3-byte length
    handshake += client_hello
    
    # TLS Record
    record = b"\x16"  # Handshake
    record += b"\x03\x01"  # TLS 1.0 for compatibility (actual version in ClientHello)
    record += struct.pack("!H", len(handshake))
    record += handshake
    
    return record


def get_ja4s(host: str, port: int = 443, timeout: int = 10) -> JA4SResult:
    """
    Get JA4S fingerprint for a server.
    
    This is the main entry point for JA4S computation.
    
    Args:
        host: Hostname or IP to fingerprint
        port: Port number (default 443)
        timeout: Connection timeout in seconds
        
    Returns:
        JA4SResult with the computed fingerprint or error message
    """
    try:
        # Try to capture raw ServerHello
        server_hello_bytes = capture_server_hello(host, port, timeout)
        
        if server_hello_bytes:
            server_hello = parse_server_hello(server_hello_bytes)
            if server_hello:
                return compute_ja4s(server_hello)
        
        # Fallback: Use standard SSL library to get basic info
        # This won't give us extensions, but we can still get version + cipher
        return get_ja4s_fallback(host, port, timeout)
        
    except Exception as e:
        return JA4SResult(
            ja4s="",
            ja4s_raw="",
            version="",
            cipher="",
            extensions_hash="",
            extensions_list=[],
            error=str(e),
        )


def get_ja4s_fallback(host: str, port: int = 443, timeout: int = 10) -> JA4SResult:
    """
    Fallback JA4S computation using Python's ssl module.
    
    This doesn't capture extensions or ALPN (Python's ssl abstracts them),
    but can still provide version + cipher for partial matching.
    
    Format: t{version}00{alpn}_{cipher}_{ext_hash}
    Since we can't get ALPN or extensions, we use "00" for both.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Try to negotiate with ALPN to get the selected protocol
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # Get negotiated version
                version = ssock.version()
                version_map = {
                    "TLSv1.3": "13",
                    "TLSv1.2": "12",
                    "TLSv1.1": "11",
                    "TLSv1": "10",
                    "TLSv1.0": "10",
                    "SSLv3": "s3",
                }
                version_str = version_map.get(version, "00")
                
                # Get cipher
                cipher_info = ssock.cipher()
                cipher_name = cipher_info[0] if cipher_info else ""
                cipher_hex = cipher_name_to_hex(cipher_name)
                
                # Try to get negotiated ALPN
                alpn = ""
                try:
                    alpn = ssock.selected_alpn_protocol() or ""
                except AttributeError:
                    pass  # Python < 3.5
                
                alpn_chars = get_alpn_chars(alpn)
                
                # Without raw capture, we can't know extensions
                ext_hash = "000000000000"
                
                # Build partial JA4S with correct 7-char format
                # t + version(2) + ext_count(2) + alpn(2) = 7 chars
                ja4s = f"t{version_str}00{alpn_chars}_{cipher_hex}_{ext_hash}"
                
                return JA4SResult(
                    ja4s=ja4s,
                    ja4s_raw=f"t{version_str}00{alpn_chars}_{cipher_hex}_[extensions_unavailable]",
                    version=version_str,
                    cipher=cipher_hex,
                    extensions_hash=ext_hash,
                    extensions_list=[],
                    error="partial: extensions not captured (fallback mode)",
                )
                
    except Exception as e:
        return JA4SResult(
            ja4s="",
            ja4s_raw="",
            version="",
            cipher="",
            extensions_hash="",
            extensions_list=[],
            error=f"fallback failed: {e}",
        )


def cipher_name_to_hex(name: str) -> str:
    """
    Map OpenSSL cipher name to TLS cipher suite hex code.
    
    This is a partial mapping of common ciphers.
    """
    # Common cipher name to hex code mapping
    cipher_map = {
        # TLS 1.3 ciphers
        "TLS_AES_128_GCM_SHA256": "1301",
        "TLS_AES_256_GCM_SHA384": "1302",
        "TLS_CHACHA20_POLY1305_SHA256": "1303",
        # TLS 1.2 ciphers
        "ECDHE-RSA-AES128-GCM-SHA256": "c02f",
        "ECDHE-RSA-AES256-GCM-SHA384": "c030",
        "ECDHE-ECDSA-AES128-GCM-SHA256": "c02b",
        "ECDHE-ECDSA-AES256-GCM-SHA384": "c02c",
        "DHE-RSA-AES128-GCM-SHA256": "009e",
        "DHE-RSA-AES256-GCM-SHA384": "009f",
        "AES128-GCM-SHA256": "009c",
        "AES256-GCM-SHA384": "009d",
        "AES128-SHA256": "003c",
        "AES256-SHA256": "003d",
        "AES128-SHA": "002f",
        "AES256-SHA": "0035",
        "ECDHE-RSA-AES128-SHA256": "c027",
        "ECDHE-RSA-AES256-SHA384": "c028",
        "ECDHE-RSA-AES128-SHA": "c013",
        "ECDHE-RSA-AES256-SHA": "c014",
        "ECDHE-RSA-CHACHA20-POLY1305": "cca8",
        "ECDHE-ECDSA-CHACHA20-POLY1305": "cca9",
    }
    return cipher_map.get(name, "0000")


# Convenience function for simple usage
def fingerprint_server(host: str, port: int = 443) -> str:
    """
    Get JA4S fingerprint for a server (simple interface).
    
    Returns the JA4S string, or empty string on error.
    """
    result = get_ja4s(host, port)
    return result.ja4s


if __name__ == "__main__":
    # Test the JA4S implementation
    import sys
    
    if len(sys.argv) > 1:
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    else:
        host = "google.com"
        port = 443
    
    print(f"Computing JA4S for {host}:{port}...")
    result = get_ja4s(host, port)
    
    print(f"JA4S: {result.ja4s}")
    print(f"JA4S_raw: {result.ja4s_raw}")
    print(f"Version: {result.version}")
    print(f"Cipher: {result.cipher}")
    print(f"Extensions: {result.extensions_list}")
    if result.error:
        print(f"Note: {result.error}")
