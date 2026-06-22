"""
JA4+ Malicious Signature Database

This module contains known-malicious network fingerprints for detecting:
- AiTM (Adversary-in-the-Middle) phishing kits
- C2 (Command and Control) frameworks
- Banking trojans and infostealers
- Other malware families

SOURCES:
--------
1. FoxIO ja4plus-mapping.csv (BSD 3-Clause for JA4, FoxIO License 1.1 for JA4+)
   https://github.com/FoxIO-LLC/ja4

2. ostweg/malicious-ja4-fingerprints (pcap-derived malware signatures)
   https://github.com/ostweg/malicious-ja4-fingerprints

3. r3m0s/malicious-ja4-database (C2 framework signatures, AGPL-3.0)
   https://github.com/r3m0s/malicious-ja4-database

UPDATING SIGNATURES:
--------------------
To update signatures, run: python -m aitm_hunter.update_signatures
Or manually pull from the sources above and update this file.

Last updated: 2026-06-22
"""

from __future__ import annotations

# =============================================================================
# JA4 CLIENT FINGERPRINTS (TLS Client Hello)
# These identify the CLIENT initiating connections
# =============================================================================

KNOWN_MALWARE_JA4_CLIENT: dict[str, str] = {
    # --- C2 Frameworks (from r3m0s) ---
    "t10i060500_4dc025c38c38_950472255fe9": "Covenant Grunt",
    "t13i131000_f57a46bbacb6_e5728521abd4": "Sliver C2",
    "t12i180600_4b22cbed5bed_2dae41c691ec": "Mythic Apollo / PoshC2",
    "t13i201100_2b729b4bf6f3_e24568c0d440": "Havoc Demon",
    "t12d180700_4b22cbed5bed_2dae41c691ec": "AADInternals / TokenTactics",
    "t13d201100_2b729b4bf6f3_36bf25f296df": "GraphRunner",
    "t13d9013h1_c6771aded2ed_57a60bdf03d1": "GraphSpy / ROADtools",
    "t13d1311h2_f57a46bbacb6_e7c285222651": "AzureHound",
    "t12d190800_d83cc789557e_7af1ed941c26": "Cobalt Strike",
    
    # --- C2 Frameworks (from FoxIO) ---
    "t13d201100_2b729b4bf6f3_9e7b989ebec8": "IcedID",
    "t13d190900_9dc949149365_97f8aa674fd9": "Sliver Agent / GoLang",
    "t13i190800_9dc949149365_97f8aa674fd9": "Sliver Agent / GoLang",
    "t12i190700_d83cc789557e_16bbda4055b2": "Cobalt Strike v4.9.1 (wininet)",
    "t12i210700_76e208dd3e22_16bbda4055b2": "Cobalt Strike v4.9.1 (winhttp)",
    "t12d190800_d83cc789557e_16bbda4055b2": "Cobalt Strike v4.9.1 (wininet)",
    "t12d210800_76e208dd3e22_16bbda4055b2": "Cobalt Strike v4.9.1 (winhttp)",
    "t13d191000_9dc949149365_e7c285222651": "Evilginx / GoLang net package",
    "t13d880900_fcb5b95cb75a_b0d3b4ac2a14": "SoftEther VPN Client",
    "t13i880900_fcb5b95cb75a_b0d3b4ac2a14": "SoftEther VPN Client",
    
    # --- Banking Trojans / Malware (from ostweg pcap analysis) ---
    "t10i460300_234845559c90_a875e5012fde": "Neris Botnet",
    "t10i290100_cdba58456bdf_e78b541c01a9": "Neris Botnet",
    "t10i110100_3609b414f052_bc98f8e001b5": "Neris / FastFlux",
    "t10i110000_3609b414f052_000000000000": "Neris Botnet",
    "t10d120300_d94e65cdb899_33a13ba74d1c": "Neris Botnet",  # Fixed: added 't' prefix
    "ts3i040000_79bb1f42e07b_000000000000": "Zeus / Shifu Banking Trojan",
    "t12d2011s1_8dd61975155f_06a4338d0495": "HTBot",
    "t12d2012s1_8dd61975155f_e278c6a1a25f": "HTBot",
    "t12d2011s1_8dd61975155f_f2efb249ca37": "HTBot",
    "t12d2010s1_8dd61975155f_5bb8d82126a6": "HTBot",
    "t10d2009s1_8dd61975155f_0e572411783b": "HTBot",
    "t10d2010s1_8dd61975155f_6c468f4fe2dd": "HTBot",
    "t11d2009s1_8dd61975155f_0e572411783b": "HTBot",
    "t10d360500_77f462745360_51f6d7389324": "HTBot",
    "t13d190600_bddd58785e8b_3395b7e3e426": "PhantomSteal Infostealer",
    "t13d150600_bddd58785e8b_97f8aa674fd9": "SmartAPeSG Loader",
    "t13d150700_bddd58785e8b_3e08f4260b31": "SmartAPeSG Loader",
    "t12d100700_b64dbd0c6b04_7f5b7c11cd79": "njRAT",
}

# =============================================================================
# JA4S SERVER FINGERPRINTS (TLS Server Hello)
# These identify the SERVER responding - useful for C2 infrastructure detection
# =============================================================================

KNOWN_AITM_JA4S_SIGNATURES: dict[str, str] = {
    # --- C2 Server Responses (from r3m0s) ---
    "t100400_c014_12a20535f9be": "Covenant C2 Server",
    "t120400_c030_12a20535f9be": "Covenant / PoshC2 Server",
    "t130200_1303_a56c5b993250": "Sliver C2 Server",
    "t120400_c02b_99765765853d": "Mythic C2 Server",
    "t130200_1301_a56c5b993250": "Havoc / Sliver C2 Server",
    
    # --- C2 Server Responses (from FoxIO) ---
    "t120300_c030_5e2616a54c73": "IcedID C2",
    "t120300_c030_52d195ce1d92": "Cobalt Strike C2",
}

# =============================================================================
# JA4X CERTIFICATE FINGERPRINTS
# These identify certificates commonly used by malware/C2
# =============================================================================

KNOWN_MALWARE_JA4X: dict[str, str] = {
    # --- From FoxIO ---
    "000000000000_4f24da86fad6_bf0f0589fc03": "Sliver/Havoc C2 Server",
    "000000000000_7c32fa18c13e_bf0f0589fc03": "Sliver/Havoc C2 Server",
    "2166164053c1_2166164053c1_30d204a01551": "Cobalt Strike C2",
    "2bab15409345_af684594efb4_000000000000": "Qakbot C2",
    "1a59268f55e5_1a59268f55e5_795797892f9c": "Pikabot C2",
    "d55f458d5a6c_d55f458d5a6c_0fc8c171b6ae": "SoftEther VPN Server",
    "fba10053814e_fba10053814e_795797892f9c": "Cisco RV32x (compromised?)",
}

# =============================================================================
# JA4H HTTP CLIENT FINGERPRINTS
# These identify HTTP client behavior patterns
# =============================================================================

KNOWN_MALWARE_JA4H: dict[str, str] = {
    # --- C2 HTTP Patterns (from r3m0s) ---
    "ge11cn030000_b0d6a43aa599_6efb8437d5a1_0277fba68047": "Covenant Grunt",
    "po11cn040000_d157cf9277e4_6efb8437d5a1_9b856eebda45": "Covenant Grunt",
    "po11nn050000_bb52516416a2_000000000000_000000000000": "Sliver C2",
    "ge11cn040000_6d5a62ca5b6a_0945df871f4d_23029da484aa": "Sliver C2",
    "po11cn050000_bb52516416a2_0945df871f4d_23029da484aa": "Sliver C2",
    "po11nn070000_0a01ba10cd10_000000000000_000000000000": "Mythic Apollo",
    "po11nn070000_517823f2c371_000000000000_000000000000": "Havoc Demon / Zeus",
    "ge11cr10enus_1e25179330e9_57b7887b63f1_c2c4e5f2aafc": "GraphSpy",
    
    # --- Banking Trojans / Malware HTTP Patterns (from ostweg) ---
    "ge11nn080000_758c01193da9_000000000000_000000000000": "Neris Botnet",
    "ge10nn030000_eb8a640ecb5c_000000000000_000000000000": "Neris Botnet",
    "ge10nn040000_20fab7dec508_000000000000_000000000000": "Neris Botnet",
    "ge11nr06zhcn_6b79811f20a8_000000000000_000000000000": "Neris Botnet",
    "po10nn050000_1f12603dda80_000000000000_000000000000": "Neris Botnet",
    "ge11nn070000_7e51f25b65a5_000000000000_000000000000": "Shifu Banking Trojan",
    "po11nn070000_517823f2c371_000000000000_000000000000": "Zeus Banking Trojan",
    "po11nn060000_aa65a35d2529_000000000000_000000000000": "Zeus Banking Trojan",
    "po11nn07enus_7d361e250c48_000000000000_000000000000": "Zeus Banking Trojan",
    "ge11cr06enus_8c2f9ef95269_f0de79df3412_7038a7187d0e": "Zeus Banking Trojan",
    "ge11cr06enus_8c2f9ef95269_546bb1a80ebc_ac611eab74b5": "Zeus Banking Trojan",
    "ge11nr06enus_8c2f9ef95269_000000000000_000000000000": "Zeus Banking Trojan",
    "ge11cn050000_a72e37bb2523_fe81d65a9ab0_76fcad8e67b9": "Zeus Banking Trojan",
    "ge11cn050000_a72e37bb2523_83f48846bcbc_4c9134a60cce": "Zeus Banking Trojan",
    "ge11nn040000_015c4bf7cafe_000000000000_000000000000": "Zeus Banking Trojan",
    "ge11nn050000_a72e37bb2523_000000000000_000000000000": "Zeus Banking Trojan",
    "co11nn030000_c8b241c27500_000000000000_000000000000": "HTBot",
    "co11nn040000_a72fe7d17c8f_000000000000_000000000000": "HTBot",
    "ge11cr07enus_4471ef9792a6_e53399760dfa_7b3e614152e3": "FastFlux Botnet",
    "ge11cr07enus_4471ef9792a6_275583a4a2b7_b6d9025c9c06": "FastFlux Botnet",
    "po11cr09ru00_130d8cd1913c_51511455dbaa_5713570a4da5": "FastFlux Botnet",
    "ge11cr07enus_4471ef9792a6_51511455dbaa_c00656b649b9": "FastFlux Botnet",
    "po10cr10enus_cf457ffe11e6_e1629b5f4dca_c79ffeed7d1c": "FastFlux Botnet",
    "ge11nn040000_17807bc4167d_000000000000_000000000000": "FastFlux Botnet",
    
    # --- From FoxIO (some partial signatures, padded with zeros for format compliance) ---
    "ge11cn020000_9ed1ff1f7b03_cd8dafe26982_000000000000": "IcedID Dropper",
    "ge11cn060000_4e59edc1297a_4da5efaf0cbd_000000000000": "Cobalt Strike beacon",
    "po10nn060000_cdb958d032b0_000000000000_000000000000": "Darkgate",
    "po11nn050000_d253db9d024b_000000000000_000000000000": "LummaC2",
}

# =============================================================================
# JA3 FINGERPRINTS (Legacy, still useful for older malware)
# =============================================================================

KNOWN_MALWARE_JA3: dict[str, str] = {
    # --- From r3m0s ---
    "43016d7f7f9336b17c884650d0d2545d": "Covenant Grunt / Mythic / PoshC2 (.NET)",
    "006598cf32b8feecd39e4337bdba9c44": "Sliver C2",
    "584900de6273bb0e673db58cc107a882": "Havoc Demon",
    "6a5d235ee78c6aede6a61448b4e9ff1e": "AADInternals / TokenTactics (PowerShell)",
    "2e3c8705644cd10b757b19f5e8e0546b": "AzureHound (Go)",
    "68b3ecfaf0034bb9fcbecd518b5ab8d4": "GraphRunner (PowerShell)",
    "1d573f07cf9592c93700cd3f524279e0": "GraphSpy / ROADtools (Python)",
}

# =============================================================================
# KNOWN EVILGINX / AITM PHISHING DOMAINS
# Confirmed malicious infrastructure - domains and IPs
# =============================================================================

KNOWN_EVILGINX_DOMAINS: dict[str, dict] = {
    # --- Confirmed Evilginx AiTM Infrastructure (from Shane Shook investigations) ---
    # --- Storm-2755 Campaign (April-June 2026) ---
    "armorprotect.com": {
        "type": "evilginx",
        "target": "Enterprise employee portals",
        "ip": "208.91.197.27",
        "asn": "AS40034",
        "hosting": "Confluence Networks Inc",
        "status": "seized",
        "wildcard_dns": True,
        "markers": ["rid=", "openresty"],
        "first_seen": "2026-06",
        "threat_actor": "Storm-2755",
        "notes": "Wildcard DNS, self-signed cert, targeted employee login portals",
    },
    "vlm.armorprotect.com": {
        "type": "evilginx",
        "target": "Enterprise employee portals",
        "ip": "208.91.197.27",
        "asn": "AS40034",
        "hosting": "Confluence Networks Inc",
        "status": "seized",
        "markers": ["rid=", "openresty"],
        "first_seen": "2026-06",
        "threat_actor": "Storm-2755",
        "notes": "Primary lure subdomain for employee portal phishing campaign",
    },
    "armorproshield.com": {
        "type": "evilginx",
        "target": "Enterprise employee portals",
        "ip": "104.21.37.58",
        "asn": "AS13335",
        "hosting": "Cloudflare (likely seized/parked)",
        "status": "seized",
        "markers": ["rid="],
        "first_seen": "2026-06",
        "threat_actor": "Storm-2755",
        "notes": "Related AiTM campaign infrastructure",
    },
    "vlm.armorproshield.com": {
        "type": "aitm_proxy",
        "target": "Enterprise employee portals",
        "hosting": "AWS",
        "status": "seized",
        "markers": ["rid="],
        "first_seen": "2026-04",
        "threat_actor": "Storm-2755",
        "delivery": "malvertising",
        "notes": "Backend AiTM proxy for Storm-2755 campaign, relays credentials to Microsoft auth endpoints",
    },
    "securitytop5.com": {
        "type": "evilginx",
        "target": "Enterprise employee portals",
        "ip": "104.21.43.172",
        "asn": "AS13335",
        "hosting": "Cloudflare (likely seized/parked)",
        "status": "seized",
        "markers": ["rid="],
        "first_seen": "2026-06",
        "threat_actor": "Storm-2755",
        "notes": "Related AiTM campaign infrastructure",
    },
    "pop-up.securitytop5.com": {
        "type": "lure_landing",
        "target": "Enterprise employee portals",
        "hosting": "Cloudflare-fronted",
        "status": "seized",
        "markers": ["Device Activation", "Armorproshield"],
        "first_seen": "2026-04",
        "threat_actor": "Storm-2755",
        "delivery": "malvertising",
        "backend_proxy": "vlm.armorproshield.com",
        "notes": "Cloudflare-fronted landing page with fake 'Device Activation' lure, redirects to AiTM proxy",
    },
    # --- Google Ads AiTM Campaign (June 2026) ---
    "colinandresw.com": {
        "type": "aitm_lure",
        "target": "Microsoft 365 / O365 login",
        "status": "reported",
        "markers": ["gclid"],
        "first_seen": "2026-06-20",
        "delivery": "google_ads_malvertising",
        "search_terms": ["o365 login", "365 login"],
        "gclid": "CjwKCAjw9NjRBhATEiwA_p2J8Sr-7ZV2dL-7G59D2FkKhab9Fcu8i_vAy9vt9zk0zQ1Egbx3bECCBoC84kQAvD_BwE",
        "gad_campaignid": "23869465194",
        "notes": "Google Ads malvertising spoofing Microsoft.com in search results for '365 login'",
    },
}

# Storm-2755 specific indicators
STORM_2755_INDICATORS: dict[str, list] = {
    "domains": [
        "armorprotect.com",
        "armorproshield.com",
        "securitytop5.com",
    ],
    "brand_patterns": [
        r"armor\w*",  # Armorprotect, Armorproshield, etc.
        r"security\w*\d+",  # securitytop5, etc.
    ],
    "lure_content": [
        "Device Activation",
        "Security Verification",
        "Account Verification Required",
        "Verify Your Identity",
    ],
    "ad_parameters": {
        "msclkid": "Microsoft Advertising click ID",
        "utm_source": ["bing"],
        "utm_medium": ["display", "cpc", "ppc"],
        "subid": ["microsoft.resp.1"],
    },
    "search_terms_targeted": [
        "outlook 365 login",
        "o365 login",
        "microsoft login",
        "outlook login",
        # Generic employee portal terms
        "employee portal login",
        "employee email login",
    ],
}

# Known malicious IPs associated with Evilginx infrastructure
KNOWN_EVILGINX_IPS: dict[str, dict] = {
    "208.91.197.27": {
        "domains": ["armorprotect.com", "vlm.armorprotect.com"],
        "asn": "AS40034",
        "hosting": "Confluence Networks Inc",
        "location": "Dallas, TX, US",
        "type": "bulletproof_hosting",
    },
}

# ASNs known to host malicious/bulletproof infrastructure
SUSPICIOUS_ASNS: dict[str, str] = {
    "AS40034": "Confluence Networks Inc - known bulletproof hosting",
    "AS44477": "Stark Industries - frequent malware hosting",
    "AS9009": "M247 Ltd - frequent abuse",
    "AS62904": "Eonix Corporation - bulletproof hosting",
    "AS60781": "LeaseWeb NL - frequent abuse",
}

# =============================================================================
# SUMMARY STATISTICS
# =============================================================================

def get_signature_stats() -> dict:
    """Return statistics about the signature database."""
    return {
        "ja4_client": len(KNOWN_MALWARE_JA4_CLIENT),
        "ja4s_server": len(KNOWN_AITM_JA4S_SIGNATURES),
        "ja4x_cert": len(KNOWN_MALWARE_JA4X),
        "ja4h_http": len(KNOWN_MALWARE_JA4H),
        "ja3_legacy": len(KNOWN_MALWARE_JA3),
        "evilginx_domains": len(KNOWN_EVILGINX_DOMAINS),
        "evilginx_ips": len(KNOWN_EVILGINX_IPS),
        "suspicious_asns": len(SUSPICIOUS_ASNS),
        "total_fingerprints": (
            len(KNOWN_MALWARE_JA4_CLIENT) +
            len(KNOWN_AITM_JA4S_SIGNATURES) +
            len(KNOWN_MALWARE_JA4X) +
            len(KNOWN_MALWARE_JA4H) +
            len(KNOWN_MALWARE_JA3)
        ),
        "malware_families": len(set(
            list(KNOWN_MALWARE_JA4_CLIENT.values()) +
            list(KNOWN_AITM_JA4S_SIGNATURES.values()) +
            list(KNOWN_MALWARE_JA4X.values()) +
            list(KNOWN_MALWARE_JA4H.values()) +
            list(KNOWN_MALWARE_JA3.values())
        )),
    }


def check_domain_ioc(domain: str) -> dict | None:
    """Check if a domain matches known Evilginx/AiTM infrastructure."""
    domain_lower = domain.lower()
    
    # Direct match
    if domain_lower in KNOWN_EVILGINX_DOMAINS:
        return KNOWN_EVILGINX_DOMAINS[domain_lower]
    
    # Check if subdomain of known bad domain
    for known_domain in KNOWN_EVILGINX_DOMAINS:
        if domain_lower.endswith('.' + known_domain) or domain_lower == known_domain:
            info = KNOWN_EVILGINX_DOMAINS[known_domain].copy()
            info['matched_domain'] = known_domain
            info['is_subdomain'] = domain_lower != known_domain
            return info
    
    return None


def check_ip_ioc(ip: str) -> dict | None:
    """Check if an IP matches known malicious infrastructure."""
    if ip in KNOWN_EVILGINX_IPS:
        return KNOWN_EVILGINX_IPS[ip]
    return None


def check_asn_reputation(asn: str) -> str | None:
    """Check if an ASN is known for hosting malicious infrastructure."""
    asn_upper = asn.upper()
    if not asn_upper.startswith('AS'):
        asn_upper = f'AS{asn_upper}'
    return SUSPICIOUS_ASNS.get(asn_upper)


if __name__ == "__main__":
    stats = get_signature_stats()
    print("AiTM Hunter Signature Database Statistics")
    print("=" * 50)
    print(f"JA4 Client Fingerprints:    {stats['ja4_client']:4d}")
    print(f"JA4S Server Fingerprints:   {stats['ja4s_server']:4d}")
    print(f"JA4X Cert Fingerprints:     {stats['ja4x_cert']:4d}")
    print(f"JA4H HTTP Fingerprints:     {stats['ja4h_http']:4d}")
    print(f"JA3 Legacy Fingerprints:    {stats['ja3_legacy']:4d}")
    print("-" * 50)
    print(f"Total Fingerprints:         {stats['total_fingerprints']:4d}")
    print(f"Malware Families:           {stats['malware_families']:4d}")
    print("-" * 50)
    print(f"Known Evilginx Domains:     {stats['evilginx_domains']:4d}")
    print(f"Known Evilginx IPs:         {stats['evilginx_ips']:4d}")
    print(f"Suspicious ASNs:            {stats['suspicious_asns']:4d}")
