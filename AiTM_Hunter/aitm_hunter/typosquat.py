"""
Typosquat Detection Module

Detects domain typosquatting using dnstwist-style algorithms to identify
potential AiTM lure domains that impersonate legitimate brands.

This is FINGERPRINT-BASED detection - it identifies attack patterns
(typosquatting) rather than relying on blacklists.

Techniques implemented:
- Homoglyphs (visual similarity: 0/o, 1/l, rn/m)
- Character omission (microsft.com)
- Character swap (microsfot.com)
- Character duplication (microsoftt.com)
- Character insertion (microsofat.com)
- Adjacent key substitution (mocrosoft.com)
- Bit flipping
- Common TLD variations
- Keyword additions (microsoft-login.com, office365-verify.com)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator
from urllib.parse import urlparse


@dataclass
class TyposquatMatch:
    """Result of typosquat detection."""
    domain: str
    is_typosquat: bool = False
    target_brand: str | None = None
    target_domain: str | None = None
    technique: str | None = None
    similarity_score: float = 0.0
    
    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "is_typosquat": self.is_typosquat,
            "target_brand": self.target_brand,
            "target_domain": self.target_domain,
            "technique": self.technique,
            "similarity_score": self.similarity_score,
        }


# Protected brands and their legitimate domains
# Typosquats of these are suspicious for AiTM
PROTECTED_BRANDS: dict[str, list[str]] = {
    "microsoft": [
        "microsoft.com",
        "office.com",
        "office365.com",
        "microsoftonline.com",
        "live.com",
        "outlook.com",
        "azure.com",
        "windows.com",
        "sharepoint.com",
        "onedrive.com",
    ],
    "google": [
        "google.com",
        "gmail.com",
        "googleapis.com",
        "googleusercontent.com",
    ],
    "okta": [
        "okta.com",
        "oktacdn.com",
    ],
    "amazon": [
        "amazon.com",
        "amazonaws.com",
        "aws.amazon.com",
    ],
    "apple": [
        "apple.com",
        "icloud.com",
    ],
    "salesforce": [
        "salesforce.com",
        "force.com",
    ],
}

# Flatten to domain -> brand mapping
LEGITIMATE_DOMAINS: dict[str, str] = {}
for brand, domains in PROTECTED_BRANDS.items():
    for domain in domains:
        LEGITIMATE_DOMAINS[domain.lower()] = brand

# Homoglyph mappings (visually similar characters)
HOMOGLYPHS: dict[str, list[str]] = {
    'a': ['à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'а', 'ạ', 'ą', '@'],
    'b': ['d', 'ḃ', 'ḅ', 'ɓ', 'Ь'],
    'c': ['ç', 'ć', 'ĉ', 'ċ', 'с', '¢'],
    'd': ['b', 'ḋ', 'ḍ', 'ɗ', 'đ'],
    'e': ['è', 'é', 'ê', 'ë', 'ē', 'ĕ', 'ė', 'ę', 'е', 'ẹ', 'ə', '3'],
    'f': ['ḟ', 'ƒ'],
    'g': ['ǵ', 'ġ', 'ģ', 'ɡ', 'ǧ', '9'],
    'h': ['ḣ', 'ḥ', 'ħ', 'һ'],
    'i': ['ì', 'í', 'î', 'ï', 'ı', 'і', 'ị', '1', 'l', '!', '|'],
    'j': ['ĵ', 'ј'],
    'k': ['ḱ', 'ḳ', 'ķ', 'κ'],
    'l': ['ĺ', 'ļ', 'ľ', 'ŀ', 'ł', '1', 'i', '|'],
    'm': ['ṁ', 'ṃ', 'rn', 'ɱ'],
    'n': ['ñ', 'ń', 'ņ', 'ň', 'ṅ', 'ṇ', 'ŋ', 'и'],
    'o': ['ò', 'ó', 'ô', 'õ', 'ö', 'ø', 'ō', 'ŏ', 'ő', 'о', 'ọ', '0'],
    'p': ['ṕ', 'ṗ', 'р'],
    'q': ['ɋ'],
    'r': ['ŕ', 'ŗ', 'ř', 'ṙ', 'ṛ', 'г'],
    's': ['ś', 'ŝ', 'ş', 'š', 'ṡ', 'ṣ', 'ș', '$', '5'],
    't': ['ţ', 'ť', 'ṫ', 'ṭ', 'ț', '7', '+'],
    'u': ['ù', 'ú', 'û', 'ü', 'ũ', 'ū', 'ŭ', 'ů', 'ű', 'ų', 'υ', 'ụ'],
    'v': ['ṽ', 'ṿ', 'ν'],
    'w': ['ŵ', 'ẁ', 'ẃ', 'ẅ', 'ω', 'vv'],
    'x': ['×', 'х'],
    'y': ['ý', 'ÿ', 'ŷ', 'у', 'ỳ', 'ỵ'],
    'z': ['ź', 'ż', 'ž', 'ẑ', 'ẓ'],
    '0': ['o', 'О', 'о'],
    '1': ['l', 'i', 'I', '|'],
}

# Keyboard adjacency for typo simulation
KEYBOARD_ADJACENT: dict[str, str] = {
    'q': 'wa', 'w': 'qeas', 'e': 'wrds', 'r': 'etdf', 't': 'ryfg',
    'y': 'tugh', 'u': 'yijh', 'i': 'uokj', 'o': 'iplk', 'p': 'ol',
    'a': 'qwsz', 's': 'awedxz', 'd': 'serfcx', 'f': 'drtgvc',
    'g': 'ftyhbv', 'h': 'gyujnb', 'j': 'huikmn', 'k': 'jiolm',
    'l': 'kop', 'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb',
    'b': 'vghn', 'n': 'bhjm', 'm': 'njk',
}

# Common TLDs for variation
COMMON_TLDS = ['.com', '.net', '.org', '.io', '.co', '.app', '.dev', '.online', '.site']

# Action keywords commonly added to phishing domains
PHISHING_KEYWORDS = [
    'login', 'signin', 'sign-in', 'auth', 'verify', 'secure', 'account',
    'password', 'update', 'confirm', 'portal', 'support', 'help', 'reset',
    'activate', 'validation', 'security', 'alert', 'notification',
]


def extract_domain_parts(domain: str) -> tuple[str, str]:
    """Extract the main domain name and TLD."""
    domain = domain.lower().strip()
    
    # Remove common prefixes
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Split off TLD
    parts = domain.rsplit('.', 1)
    if len(parts) == 2:
        return parts[0], '.' + parts[1]
    return domain, ''


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein (edit) distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def similarity_score(s1: str, s2: str) -> float:
    """Calculate similarity score (0-100) between two strings."""
    if s1 == s2:
        return 100.0
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 100.0
    distance = levenshtein_distance(s1, s2)
    return (1 - distance / max_len) * 100


def generate_homoglyphs(domain: str) -> Iterator[str]:
    """Generate homoglyph variations of a domain."""
    name, tld = extract_domain_parts(domain)
    
    for i, char in enumerate(name):
        if char.lower() in HOMOGLYPHS:
            for replacement in HOMOGLYPHS[char.lower()]:
                yield name[:i] + replacement + name[i+1:] + tld


def generate_omissions(domain: str) -> Iterator[str]:
    """Generate character omission variations."""
    name, tld = extract_domain_parts(domain)
    
    for i in range(len(name)):
        yield name[:i] + name[i+1:] + tld


def generate_swaps(domain: str) -> Iterator[str]:
    """Generate adjacent character swap variations."""
    name, tld = extract_domain_parts(domain)
    
    for i in range(len(name) - 1):
        yield name[:i] + name[i+1] + name[i] + name[i+2:] + tld


def generate_duplications(domain: str) -> Iterator[str]:
    """Generate character duplication variations."""
    name, tld = extract_domain_parts(domain)
    
    for i in range(len(name)):
        yield name[:i] + name[i] + name[i:] + tld


def generate_insertions(domain: str) -> Iterator[str]:
    """Generate character insertion variations (keyboard adjacent)."""
    name, tld = extract_domain_parts(domain)
    
    for i, char in enumerate(name):
        if char in KEYBOARD_ADJACENT:
            for adj in KEYBOARD_ADJACENT[char]:
                yield name[:i] + adj + name[i:] + tld
                yield name[:i+1] + adj + name[i+1:] + tld


def generate_replacements(domain: str) -> Iterator[str]:
    """Generate adjacent key replacement variations."""
    name, tld = extract_domain_parts(domain)
    
    for i, char in enumerate(name):
        if char in KEYBOARD_ADJACENT:
            for adj in KEYBOARD_ADJACENT[char]:
                yield name[:i] + adj + name[i+1:] + tld


def check_keyword_addition(domain: str, brand_domain: str) -> tuple[bool, str | None]:
    """Check if domain is brand + phishing keyword."""
    brand_name, _ = extract_domain_parts(brand_domain)
    domain_name, _ = extract_domain_parts(domain)
    domain_lower = domain_name.lower()
    brand_lower = brand_name.lower()
    
    # Check if domain contains brand name + keyword
    if brand_lower in domain_lower:
        remainder = domain_lower.replace(brand_lower, '')
        # Remove common separators
        remainder = remainder.replace('-', '').replace('_', '').replace('.', '')
        
        for keyword in PHISHING_KEYWORDS:
            if keyword in remainder:
                return True, f"brand+keyword ({brand_lower}+{keyword})"
    
    return False, None


def is_legitimate_domain(domain: str) -> bool:
    """Check if domain is a known legitimate protected domain."""
    domain_lower = domain.lower().strip()
    if domain_lower.startswith('www.'):
        domain_lower = domain_lower[4:]
    
    return domain_lower in LEGITIMATE_DOMAINS


def detect_typosquat(domain: str) -> TyposquatMatch:
    """
    Detect if a domain is a typosquat of a protected brand.
    
    This is the main detection function - it checks if a domain
    appears to be impersonating a legitimate brand through:
    - Homoglyphs
    - Character manipulation
    - Keyword additions
    - Edit distance similarity
    
    Returns TyposquatMatch with detection results.
    """
    result = TyposquatMatch(domain=domain)
    
    # Clean domain
    domain_lower = domain.lower().strip()
    if domain_lower.startswith('www.'):
        domain_lower = domain_lower[4:]
    
    # Skip if it's a known legitimate domain
    if domain_lower in LEGITIMATE_DOMAINS:
        return result
    
    domain_name, domain_tld = extract_domain_parts(domain_lower)
    
    best_score = 0.0
    best_match = None
    best_technique = None
    
    for brand, brand_domains in PROTECTED_BRANDS.items():
        for brand_domain in brand_domains:
            brand_name, brand_tld = extract_domain_parts(brand_domain)
            
            # Skip if domains are identical
            if domain_lower == brand_domain:
                continue
            
            # Check 1: Keyword addition (microsoft-login.com)
            is_keyword, keyword_technique = check_keyword_addition(domain_lower, brand_domain)
            if is_keyword:
                result.is_typosquat = True
                result.target_brand = brand
                result.target_domain = brand_domain
                result.technique = keyword_technique
                result.similarity_score = 85.0
                return result
            
            # Check 2: Normalize common homoglyphs to letters (one-way only)
            # This catches g00gle -> google, micr0soft -> microsoft
            NORMALIZE_MAP = {'0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't', '@': 'a', '$': 's'}
            normalized_domain = domain_name
            for fake, real in NORMALIZE_MAP.items():
                normalized_domain = normalized_domain.replace(fake, real)
            
            # If normalization changed the domain and it now matches brand, it's homoglyph attack
            if normalized_domain != domain_name:
                norm_score = similarity_score(normalized_domain, brand_name)
                if norm_score >= 90:
                    result.is_typosquat = True
                    result.target_brand = brand
                    result.target_domain = brand_domain
                    result.technique = "homoglyph_substitution"
                    result.similarity_score = norm_score
                    return result
            
            # Check 3: Direct similarity (catches omissions, swaps, etc.)
            score = similarity_score(domain_name, brand_name)
            
            # High similarity threshold - we want confident matches
            if score >= 75 and score < 100:
                if score > best_score:
                    best_score = score
                    best_match = (brand, brand_domain)
                    
                    # Determine technique
                    if len(domain_name) < len(brand_name):
                        best_technique = "character_omission"
                    elif len(domain_name) > len(brand_name):
                        best_technique = "character_addition"
                    else:
                        # Same length - likely swap or homoglyph
                        diff_count = sum(1 for a, b in zip(domain_name, brand_name) if a != b)
                        if diff_count == 1:
                            best_technique = "homoglyph_or_typo"
                        elif diff_count == 2:
                            best_technique = "character_swap"
                        else:
                            best_technique = "multiple_changes"
            
            # Check 3: TLD variation with exact name match
            if domain_name == brand_name and domain_tld != brand_tld:
                result.is_typosquat = True
                result.target_brand = brand
                result.target_domain = brand_domain
                result.technique = f"tld_variation ({domain_tld} vs {brand_tld})"
                result.similarity_score = 90.0
                return result
    
    # Apply best match if found
    if best_match and best_score >= 75:
        result.is_typosquat = True
        result.target_brand = best_match[0]
        result.target_domain = best_match[1]
        result.technique = best_technique
        result.similarity_score = best_score
    
    return result


def detect_typosquat_batch(domains: list[str]) -> list[TyposquatMatch]:
    """Detect typosquats in a batch of domains."""
    return [detect_typosquat(d) for d in domains]


def get_typosquat_fingerprint(domain: str) -> dict | None:
    """
    Get typosquat fingerprint for integration with other detection modules.
    
    Returns None if not a typosquat, otherwise returns detection details.
    """
    result = detect_typosquat(domain)
    if result.is_typosquat:
        return {
            "is_typosquat": True,
            "target_brand": result.target_brand,
            "target_domain": result.target_domain,
            "technique": result.technique,
            "similarity": result.similarity_score,
        }
    return None


if __name__ == "__main__":
    # Test the typosquat detection
    test_domains = [
        # Homoglyphs
        "micros0ft.com",
        "micrоsoft.com",  # Cyrillic 'о'
        "0ffice365.com",
        "g00gle.com",
        
        # Omissions
        "microsft.com",
        "gogle.com",
        "amazn.com",
        
        # Swaps
        "microsfot.com",
        "gooogle.com",
        
        # Keyword additions
        "microsoft-login.com",
        "office365-verify.com",
        "google-signin.com",
        "outlook-secure.com",
        
        # TLD variations
        "microsoft.net",
        "office365.io",
        
        # Legitimate (should NOT match)
        "microsoft.com",
        "google.com",
        "randomdomain.com",
        "colinandresw.com",  # Not a typosquat, just malicious
    ]
    
    print("Typosquat Detection Test")
    print("=" * 70)
    
    for domain in test_domains:
        result = detect_typosquat(domain)
        if result.is_typosquat:
            print(f"🚨 {domain:30s} -> {result.target_brand} ({result.technique}, {result.similarity_score:.0f}%)")
        else:
            print(f"✓  {domain:30s} -> Not a typosquat")
