"""Unit tests for search module."""

import json
import csv
import tempfile
from pathlib import Path

import pytest
from aitm_hunter.search import SerpResult, load_manual_results


class TestSerpResult:
    """Tests for SerpResult dataclass."""

    def test_to_dict(self):
        """SerpResult should serialize to dict."""
        result = SerpResult(
            query="o365 login",
            rank=1,
            result_type="ad",
            title="Office 365 Login",
            displayed_url="office.com",
            actual_url="https://office.com/login",
            position_block="ads",
        )
        d = result.to_dict()
        assert d["query"] == "o365 login"
        assert d["rank"] == 1
        assert d["result_type"] == "ad"
        assert d["actual_url"] == "https://office.com/login"


class TestManualResultsLoading:
    """Tests for loading manually collected results."""

    def test_load_json_results(self):
        """Should load results from JSON file."""
        data = [
            {
                "query": "test query",
                "rank": 1,
                "result_type": "organic",
                "title": "Test Result",
                "displayed_url": "example.com",
                "actual_url": "https://example.com",
                "position_block": "organic",
            }
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            results = load_manual_results(f.name)
        
        assert len(results) == 1
        assert results[0].query == "test query"
        assert results[0].actual_url == "https://example.com"
        Path(f.name).unlink()

    def test_load_csv_results(self):
        """Should load results from CSV file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "query", "rank", "result_type", "title", 
                "displayed_url", "actual_url", "position_block"
            ])
            writer.writeheader()
            writer.writerow({
                "query": "csv test",
                "rank": "2",
                "result_type": "ad",
                "title": "CSV Result",
                "displayed_url": "csv.example.com",
                "actual_url": "https://csv.example.com",
                "position_block": "ads",
            })
            f.flush()
            results = load_manual_results(f.name)
        
        assert len(results) == 1
        assert results[0].query == "csv test"
        assert results[0].rank == 2
        assert results[0].result_type == "ad"
        Path(f.name).unlink()

    def test_load_unsupported_format_raises(self):
        """Should raise error for unsupported file formats."""
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            f.write(b"<data></data>")
            f.flush()
            with pytest.raises(ValueError, match="Unsupported file type"):
                load_manual_results(f.name)
        Path(f.name).unlink()
