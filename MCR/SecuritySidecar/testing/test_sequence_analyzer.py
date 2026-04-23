"""
Tests for the SecuritySidecar sequence analyzer module.

Run with: pytest testing/test_sequence_analyzer.py -v
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from models import PolicyDecision
from config import PatternLibrary, ToxicPattern, ToolCategory


def make_mock_library(categories=None, patterns=None):
    """Create a mock PatternLibrary for testing."""
    return PatternLibrary(
        categories=categories or [],
        patterns=patterns or [],
    )


class TestCheckSequence:
    """Tests for the check_sequence function."""

    def test_no_patterns_returns_none(self):
        from sequence_analyzer import check_sequence
        
        mock_library = make_mock_library(categories=[], patterns=[])
        
        with patch("sequence_analyzer.get_patterns", return_value=mock_library):
            result = check_sequence("http_request", ["read_file", "search_code"])
        
        assert result is None  # No match means continue evaluation

    def test_simple_sequence_match(self):
        from sequence_analyzer import check_sequence
        
        mock_library = make_mock_library(
            categories=[
                ToolCategory(name="credential_read", tools=["read_secrets", "get_env"]),
                ToolCategory(name="network_egress", tools=["http_request", "fetch_url"]),
            ],
            patterns=[
                ToxicPattern(
                    name="credential_exfil",
                    description="Credential read then network call",
                    severity="critical",
                    sequence=["credential_read", "network_egress"],
                    window=5,
                ),
            ],
        )
        
        with patch("sequence_analyzer.get_patterns", return_value=mock_library):
            result = check_sequence("http_request", ["read_file", "read_secrets"])
        
        assert result is not None
        assert isinstance(result, PolicyDecision)
        assert result.permitted is False
        assert result.matched_pattern == "credential_exfil"

    def test_no_match_clean_history(self):
        from sequence_analyzer import check_sequence
        
        mock_library = make_mock_library(
            categories=[
                ToolCategory(name="credential_read", tools=["read_secrets"]),
                ToolCategory(name="network_egress", tools=["http_request"]),
            ],
            patterns=[
                ToxicPattern(
                    name="credential_exfil",
                    description="Credential read then network call",
                    severity="critical",
                    sequence=["credential_read", "network_egress"],
                    window=5,
                ),
            ],
        )
        
        with patch("sequence_analyzer.get_patterns", return_value=mock_library):
            # No credential read in history
            result = check_sequence("http_request", ["read_file", "search_code"])
        
        assert result is None  # No match

    def test_window_respected(self):
        from sequence_analyzer import check_sequence
        
        mock_library = make_mock_library(
            categories=[
                ToolCategory(name="credential_read", tools=["read_secrets"]),
                ToolCategory(name="network_egress", tools=["http_request"]),
            ],
            patterns=[
                ToxicPattern(
                    name="credential_exfil",
                    description="Credential read then network call",
                    severity="critical",
                    sequence=["credential_read", "network_egress"],
                    window=3,  # Only look back 3 calls
                ),
            ],
        )
        
        with patch("sequence_analyzer.get_patterns", return_value=mock_library):
            # read_secrets is 5 calls back, outside window of 3
            result = check_sequence(
                "http_request",
                ["read_secrets", "a", "b", "c", "d"]
            )
        
        assert result is None  # No match because outside window


class TestToolCategoryMatching:
    """Tests for tool to category matching."""

    def test_exact_match(self):
        from sequence_analyzer import _tool_matches_category
        
        category = ToolCategory(name="test", tools=["read_file"])
        assert _tool_matches_category("read_file", category) is True

    def test_no_match(self):
        from sequence_analyzer import _tool_matches_category
        
        category = ToolCategory(name="test", tools=["read_file"])
        assert _tool_matches_category("write_file", category) is False

    def test_glob_match(self):
        from sequence_analyzer import _tool_matches_category
        
        category = ToolCategory(name="test", tools=["delete_*"])
        assert _tool_matches_category("delete_user", category) is True
        assert _tool_matches_category("delete_file", category) is True
        assert _tool_matches_category("create_user", category) is False

    def test_case_insensitive(self):
        from sequence_analyzer import _tool_matches_category
        
        category = ToolCategory(name="test", tools=["Read_File"])
        assert _tool_matches_category("read_file", category) is True


class TestCategoryResolution:
    """Tests for resolving tool names to categories."""

    def test_resolve_single_category(self):
        from sequence_analyzer import _resolve_category
        
        library = make_mock_library(
            categories=[
                ToolCategory(name="file_ops", tools=["read_file", "write_file"]),
                ToolCategory(name="network", tools=["http_request"]),
            ],
        )
        
        result = _resolve_category("read_file", library)
        assert result == ["file_ops"]

    def test_resolve_multiple_categories(self):
        from sequence_analyzer import _resolve_category
        
        library = make_mock_library(
            categories=[
                ToolCategory(name="sensitive", tools=["read_secrets"]),
                ToolCategory(name="credential_read", tools=["read_secrets", "get_env"]),
            ],
        )
        
        result = _resolve_category("read_secrets", library)
        assert "sensitive" in result
        assert "credential_read" in result

    def test_resolve_no_category(self):
        from sequence_analyzer import _resolve_category
        
        library = make_mock_library(
            categories=[
                ToolCategory(name="network", tools=["http_request"]),
            ],
        )
        
        result = _resolve_category("unknown_tool", library)
        assert result == []


class TestDescribeHistory:
    """Tests for the describe_history helper."""

    def test_describe_annotates_categories(self):
        from sequence_analyzer import describe_history
        
        mock_library = make_mock_library(
            categories=[
                ToolCategory(name="file_ops", tools=["read_file"]),
                ToolCategory(name="network", tools=["http_request"]),
            ],
        )
        
        with patch("sequence_analyzer.get_patterns", return_value=mock_library):
            result = describe_history(["read_file", "http_request", "unknown"])
        
        assert len(result) == 3
        assert result[0]["tool"] == "read_file"
        assert "file_ops" in result[0]["categories"]
        assert result[1]["tool"] == "http_request"
        assert "network" in result[1]["categories"]
        assert result[2]["categories"] == []


class TestPatternLibraryHelper:
    """Tests for PatternLibrary helper methods."""

    def test_category_tools_found(self):
        library = make_mock_library(
            categories=[
                ToolCategory(name="network", tools=["http_request", "fetch_url"]),
            ],
        )
        
        tools = library.category_tools("network")
        assert tools == ["http_request", "fetch_url"]

    def test_category_tools_not_found(self):
        library = make_mock_library(
            categories=[
                ToolCategory(name="network", tools=["http_request"]),
            ],
        )
        
        tools = library.category_tools("nonexistent")
        assert tools == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
