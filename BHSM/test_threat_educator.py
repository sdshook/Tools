"""
Test suite for the BHSM ThreatEducator module.
"""

import unittest
import json
import tempfile
import os

from threat_educator import (
    ThreatEducator, ThreatCurriculum, ThreatCategory, Severity,
    FeatureProfile, SignaturePattern, MutationRule, EducationResult
)
from BHSM import PSIIndex, EMBED_DIM


class TestThreatCurriculum(unittest.TestCase):
    """Tests for ThreatCurriculum data structures."""
    
    def test_curriculum_creation(self):
        """Test creating a curriculum."""
        curriculum = ThreatCurriculum(
            name="Test Threat",
            category=ThreatCategory.INJECTION,
            severity=Severity.HIGH,
            description="Test description"
        )
        self.assertEqual(curriculum.name, "Test Threat")
        self.assertEqual(curriculum.category, ThreatCategory.INJECTION)
        self.assertEqual(curriculum.severity, Severity.HIGH)
    
    def test_curriculum_serialization(self):
        """Test curriculum to_dict and from_dict."""
        curriculum = ThreatCurriculum(
            name="SQL Injection",
            category=ThreatCategory.INJECTION,
            severity=Severity.CRITICAL,
            templates=["' OR '1'='1", "UNION SELECT"],
            base_valence=0.95
        )
        
        # Serialize
        d = curriculum.to_dict()
        self.assertEqual(d["name"], "SQL Injection")
        self.assertEqual(d["category"], "INJECTION")
        self.assertIn("' OR '1'='1", d["templates"])
        
        # Deserialize
        restored = ThreatCurriculum.from_dict(d)
        self.assertEqual(restored.name, curriculum.name)
        self.assertEqual(restored.category, curriculum.category)
        self.assertEqual(restored.base_valence, curriculum.base_valence)
    
    def test_feature_profile(self):
        """Test FeatureProfile."""
        profile = FeatureProfile(
            entropy_range=(0.5, 0.8),
            special_char_ratio=(0.1, 0.3)
        )
        
        d = profile.to_dict()
        self.assertEqual(d["entropy_range"], (0.5, 0.8))
        
        restored = FeatureProfile.from_dict(d)
        self.assertEqual(restored.entropy_range, profile.entropy_range)


class TestThreatEducator(unittest.TestCase):
    """Tests for the ThreatEducator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.educator = ThreatEducator(examples_per_curriculum=5)
        self.psi = PSIIndex()
    
    def test_builtin_curricula(self):
        """Test that built-in curricula exist."""
        curricula = ThreatEducator.builtin_curricula()
        self.assertGreater(len(curricula), 0)
        
        names = [c.name for c in curricula]
        self.assertIn("SQL Injection", names)
        self.assertIn("Cross-Site Scripting (XSS)", names)
        self.assertIn("Path Traversal", names)
        self.assertIn("Command Injection", names)
    
    def test_example_generation(self):
        """Test synthetic example generation."""
        curriculum = ThreatCurriculum(
            name="Test",
            category=ThreatCategory.INJECTION,
            severity=Severity.HIGH,
            templates=["test_{var}_template", "another_{var}"]
        )
        
        examples = self.educator.generate_examples(curriculum, 5)
        self.assertEqual(len(examples), 5)
    
    def test_profile_to_embedding(self):
        """Test embedding generation from profile."""
        profile = FeatureProfile(
            entropy_range=(0.5, 0.7),
            special_char_ratio=(0.1, 0.3)
        )
        
        embedding = self.educator.profile_to_embedding(profile, "test text")
        
        self.assertEqual(len(embedding), EMBED_DIM)
        # Should be L2 normalized
        norm = (embedding ** 2).sum() ** 0.5
        self.assertAlmostEqual(norm, 1.0, places=5)
    
    def test_teach_curriculum(self):
        """Test teaching a single curriculum."""
        curriculum = ThreatEducator.builtin_curricula()[0]  # SQL Injection
        
        result = self.educator.teach(curriculum, self.psi)
        
        self.assertIsInstance(result, EducationResult)
        self.assertEqual(result.curriculum_name, curriculum.name)
        self.assertGreater(result.entries_created, 0)
        self.assertTrue(result.prototype_injected)
        
        # Check PSI has entries
        self.assertGreater(len(self.psi.docs), 0)
    
    def test_teach_builtin(self):
        """Test teaching all built-in curricula."""
        results = self.educator.teach_builtin(self.psi)
        
        self.assertEqual(len(results), 4)  # 4 built-in curricula
        
        total_entries = sum(r.entries_created for r in results)
        self.assertEqual(len(self.psi.docs), total_entries)
    
    def test_educated_entries_tagged(self):
        """Test that educated entries are properly tagged."""
        self.educator.teach_builtin(self.psi)
        
        # All entries should have "educated" tag
        for doc_id, entry in self.psi.docs.items():
            self.assertIn("educated", entry["tags"])
    
    def test_prototypes_created(self):
        """Test that prototypes are created for each curriculum."""
        self.educator.teach_builtin(self.psi)
        
        # Should have prototype entries
        prototype_ids = [k for k in self.psi.docs.keys() if k.startswith("prototype_")]
        self.assertEqual(len(prototype_ids), 4)
    
    def test_load_custom_curriculum(self):
        """Test loading curriculum from JSON."""
        json_content = json.dumps({
            "name": "Custom Threat",
            "category": "INJECTION",
            "severity": "HIGH",
            "description": "A custom threat curriculum",
            "templates": ["template1", "template2"],
            "base_valence": 0.85
        })
        
        curricula = ThreatEducator.load_curricula_from_json(json_content)
        
        self.assertEqual(len(curricula), 1)
        self.assertEqual(curricula[0].name, "Custom Threat")
        self.assertEqual(curricula[0].base_valence, 0.85)
    
    def test_load_curriculum_from_file(self):
        """Test loading curriculum from a file."""
        curriculum_data = {
            "name": "File Test",
            "category": "XSS",
            "severity": "MEDIUM",
            "templates": ["<script>test</script>"]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(curriculum_data, f)
            filepath = f.name
        
        try:
            curricula = ThreatEducator.load_curricula_from_file(filepath)
            self.assertEqual(len(curricula), 1)
            self.assertEqual(curricula[0].name, "File Test")
        finally:
            os.unlink(filepath)
    
    def test_stats_tracking(self):
        """Test that statistics are tracked."""
        self.educator.teach_builtin(self.psi)
        
        stats = self.educator.get_stats()
        self.assertEqual(stats.curricula_taught, 4)
        self.assertGreater(stats.total_entries, 0)
    
    def test_taught_curricula_tracking(self):
        """Test tracking of which curricula were taught."""
        self.educator.teach_builtin(self.psi)
        
        taught = self.educator.get_taught_curricula()
        self.assertIn("SQL Injection", taught)
        self.assertTrue(self.educator.is_taught("SQL Injection"))
        self.assertFalse(self.educator.is_taught("Nonexistent"))


class TestEducatedPSIClassification(unittest.TestCase):
    """Tests for classification using educated PSI."""
    
    def setUp(self):
        """Set up educated PSI."""
        self.psi = PSIIndex()
        self.educator = ThreatEducator(examples_per_curriculum=10)
        self.educator.teach_builtin(self.psi)
    
    def test_threat_classification(self):
        """Test that educated PSI classifies threats correctly."""
        # Generate embedding for SQL injection-like pattern
        profile = FeatureProfile(
            entropy_range=(0.55, 0.75),
            special_char_ratio=(0.15, 0.35)
        )
        test_embedding = self.educator.profile_to_embedding(profile, "' OR '1'='1")
        
        # Search PSI
        avg_valence = self.psi.compute_valence_weighted_average(test_embedding, top_k=5)
        
        # Should be positive (threat-like)
        self.assertGreater(avg_valence, 0.5)
    
    def test_search_returns_results(self):
        """Test that PSI search returns results after education."""
        profile = FeatureProfile()
        test_embedding = self.educator.profile_to_embedding(profile, "test query")
        
        results = self.psi.search(test_embedding, top_k=3)
        
        self.assertEqual(len(results), 3)
        for similarity, doc_id, entry in results:
            self.assertGreater(similarity, 0)
            self.assertIn("educated", entry["tags"])


if __name__ == "__main__":
    unittest.main()
