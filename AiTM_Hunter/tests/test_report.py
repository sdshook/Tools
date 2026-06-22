"""Unit tests for report module."""

import json
import csv
import tempfile
from pathlib import Path

import pytest
from aitm_hunter.report import (
    merge_record,
    write_json_report,
    write_csv_report,
    summarize,
    REPORT_FIELDS,
)
from aitm_hunter.search import SerpResult
from aitm_hunter.triage import TriageResult


class TestMergeRecord:
    """Tests for record merging."""

    def test_merge_serp_and_triage(self):
        """Should merge SERP and triage results."""
        serp = SerpResult(
            query="test",
            rank=1,
            result_type="ad",
            title="Test",
            displayed_url="test.com",
            actual_url="https://test.com",
        )
        triage = TriageResult(
            original_url="https://test.com",
            final_url="https://test.com/landing",
            risk_score=75,
            risk_reasons=["suspicious"],
        )
        
        merged = merge_record(serp, triage)
        
        assert merged["query"] == "test"
        assert merged["rank"] == 1
        assert merged["final_url"] == "https://test.com/landing"
        assert merged["risk_score"] == 75

    def test_merge_dict_inputs(self):
        """Should accept dict inputs directly."""
        serp_dict = {"query": "dict test", "rank": 2}
        triage_dict = {"risk_score": 50}
        
        merged = merge_record(serp_dict, triage_dict)
        
        assert merged["query"] == "dict test"
        assert merged["risk_score"] == 50


class TestJsonReport:
    """Tests for JSON report generation."""

    def test_write_json_report_creates_file(self):
        """Should create JSON file with records."""
        records = [
            {"url": "https://a.com", "risk_score": 80},
            {"url": "https://b.com", "risk_score": 30},
        ]
        
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            write_json_report(records, f.name)
            
            data = json.loads(Path(f.name).read_text())
        
        # Should be sorted by risk score descending
        assert len(data) == 2
        assert data[0]["risk_score"] == 80
        assert data[1]["risk_score"] == 30
        Path(f.name).unlink()

    def test_write_json_report_creates_parent_dirs(self):
        """Should create parent directories if needed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "subdir" / "report.json"
            records = [{"url": "https://test.com"}]
            
            write_json_report(records, str(out_path))
            
            assert out_path.exists()


class TestCsvReport:
    """Tests for CSV report generation."""

    def test_write_csv_report_creates_file(self):
        """Should create CSV file with proper headers."""
        records = [
            {
                "query": "test",
                "rank": 1,
                "original_url": "https://test.com",
                "risk_score": 75,
                "risk_reasons": ["reason1", "reason2"],
            }
        ]
        
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            write_csv_report(records, f.name)
            
            with open(f.name, newline="") as csvfile:
                reader = csv.DictReader(csvfile)
                rows = list(reader)
        
        assert len(rows) == 1
        assert rows[0]["query"] == "test"
        assert rows[0]["risk_reasons"] == "reason1; reason2"
        Path(f.name).unlink()

    def test_csv_handles_signature_matches(self):
        """Should properly format signature_matches field."""
        records = [
            {
                "original_url": "https://test.com",
                "risk_score": 90,
                "signature_matches": [
                    {"type": "JA4", "hash": "abc123", "kit": "Evilginx"},
                    {"type": "JA4S", "hash": "def456", "kit": "Sliver"},
                ],
            }
        ]
        
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            write_csv_report(records, f.name)
            
            with open(f.name, newline="") as csvfile:
                reader = csv.DictReader(csvfile)
                rows = list(reader)
        
        assert "JA4:Evilginx" in rows[0]["signature_matches"]
        assert "JA4S:Sliver" in rows[0]["signature_matches"]
        Path(f.name).unlink()


class TestSummarize:
    """Tests for summary generation."""

    def test_summarize_counts_high_risk(self):
        """Should count high-risk records correctly."""
        records = [
            {"final_domain": "bad1.com", "risk_score": 80, "risk_reasons": ["reason1"]},
            {"final_domain": "bad2.com", "risk_score": 60, "risk_reasons": ["reason2"]},
            {"final_domain": "ok.com", "risk_score": 20, "risk_reasons": []},
        ]
        
        summary = summarize(records, threshold=50)
        
        assert "Total URLs triaged: 3" in summary
        assert "High risk (score >= 50): 2" in summary
        assert "bad1.com" in summary
        assert "bad2.com" in summary
        assert "ok.com" not in summary  # Below threshold

    def test_summarize_with_custom_threshold(self):
        """Should respect custom threshold."""
        records = [
            {"final_domain": "a.com", "risk_score": 90, "risk_reasons": []},
            {"final_domain": "b.com", "risk_score": 70, "risk_reasons": []},
        ]
        
        summary = summarize(records, threshold=80)
        
        assert "High risk (score >= 80): 1" in summary


class TestReportFields:
    """Tests for report field configuration."""

    def test_report_fields_includes_fingerprint_fields(self):
        """Report fields should include fingerprint data."""
        assert "tls_version" in REPORT_FIELDS
        assert "cert_issuer" in REPORT_FIELDS
        assert "is_likely_aitm" in REPORT_FIELDS
        assert "signature_matches" in REPORT_FIELDS
        assert "fingerprint_risk_score" in REPORT_FIELDS

    def test_report_fields_includes_core_fields(self):
        """Report fields should include all core fields."""
        assert "query" in REPORT_FIELDS
        assert "original_url" in REPORT_FIELDS
        assert "final_url" in REPORT_FIELDS
        assert "risk_score" in REPORT_FIELDS
        assert "screenshot_path" in REPORT_FIELDS
