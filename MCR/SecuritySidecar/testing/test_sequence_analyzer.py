"""
Tests for the SecuritySidecar sequence analyzer module.

Run with: pytest testing/test_sequence_analyzer.py -v
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sequence_analyzer import (
    load_patterns,
    match,
    build_call_graph,
    find_pattern_match,
)


class TestPatternLoading:
    """Tests for pattern file loading."""

    def test_load_valid_patterns(self, tmp_path):
        patterns_file = tmp_path / "patterns.yaml"
        patterns_file.write_text("""
toxic_flows:
  - name: credential_exfil
    description: Read credentials then make network call
    sequence:
      - category: credential_read
        tools: [read_secrets, get_env, read_config]
      - category: network_egress
        tools: [http_request, curl, wget]
    window: 5
    severity: critical
""")
        patterns = load_patterns(str(patterns_file))
        assert len(patterns["toxic_flows"]) == 1
        assert patterns["toxic_flows"][0]["name"] == "credential_exfil"

    def test_load_multiple_patterns(self, tmp_path):
        patterns_file = tmp_path / "patterns.yaml"
        patterns_file.write_text("""
toxic_flows:
  - name: pattern_1
    sequence:
      - category: a
        tools: [tool_a]
      - category: b
        tools: [tool_b]
    window: 3
  - name: pattern_2
    sequence:
      - category: x
        tools: [tool_x]
      - category: y
        tools: [tool_y]
    window: 5
""")
        patterns = load_patterns(str(patterns_file))
        assert len(patterns["toxic_flows"]) == 2

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_patterns("/nonexistent/patterns.yaml")


class TestCallGraphBuilding:
    """Tests for building tool call graphs from history."""

    def test_empty_history(self):
        graph = build_call_graph([])
        assert len(graph.nodes) == 0

    def test_single_call(self):
        history = [{"tool": "read_file", "step": 1}]
        graph = build_call_graph(history)
        assert len(graph.nodes) == 1
        assert "read_file:1" in graph.nodes

    def test_sequential_calls(self):
        history = [
            {"tool": "read_file", "step": 1},
            {"tool": "process_data", "step": 2},
            {"tool": "write_file", "step": 3},
        ]
        graph = build_call_graph(history)
        assert len(graph.nodes) == 3
        assert graph.has_edge("read_file:1", "process_data:2")
        assert graph.has_edge("process_data:2", "write_file:3")


class TestPatternMatching:
    """Tests for toxic flow pattern matching."""

    def test_no_match_clean_history(self):
        patterns = {
            "toxic_flows": [{
                "name": "exfil",
                "sequence": [
                    {"category": "cred", "tools": ["read_secrets"]},
                    {"category": "net", "tools": ["http_request"]},
                ],
                "window": 5
            }]
        }
        history = [
            {"tool": "read_file", "step": 1},
            {"tool": "write_file", "step": 2},
        ]
        proposed = {"tool": "search_code", "step": 3}
        result = match(history, proposed, patterns)
        assert result["matched"] is False

    def test_match_simple_sequence(self):
        patterns = {
            "toxic_flows": [{
                "name": "exfil",
                "sequence": [
                    {"category": "cred", "tools": ["read_secrets"]},
                    {"category": "net", "tools": ["http_request"]},
                ],
                "window": 5
            }]
        }
        history = [
            {"tool": "read_file", "step": 1},
            {"tool": "read_secrets", "step": 2},
        ]
        proposed = {"tool": "http_request", "step": 3}
        result = match(history, proposed, patterns)
        assert result["matched"] is True
        assert result["pattern_name"] == "exfil"

    def test_match_respects_window(self):
        patterns = {
            "toxic_flows": [{
                "name": "exfil",
                "sequence": [
                    {"category": "cred", "tools": ["read_secrets"]},
                    {"category": "net", "tools": ["http_request"]},
                ],
                "window": 3
            }]
        }
        # read_secrets is 5 steps back, outside window
        history = [
            {"tool": "read_secrets", "step": 1},
            {"tool": "a", "step": 2},
            {"tool": "b", "step": 3},
            {"tool": "c", "step": 4},
            {"tool": "d", "step": 5},
        ]
        proposed = {"tool": "http_request", "step": 6}
        result = match(history, proposed, patterns)
        assert result["matched"] is False

    def test_match_three_step_sequence(self):
        patterns = {
            "toxic_flows": [{
                "name": "escalate_delete",
                "sequence": [
                    {"category": "auth", "tools": ["assume_role"]},
                    {"category": "read", "tools": ["list_resources"]},
                    {"category": "delete", "tools": ["delete_resource"]},
                ],
                "window": 10
            }]
        }
        history = [
            {"tool": "assume_role", "step": 1},
            {"tool": "list_resources", "step": 2},
        ]
        proposed = {"tool": "delete_resource", "step": 3}
        result = match(history, proposed, patterns)
        assert result["matched"] is True
        assert result["pattern_name"] == "escalate_delete"

    def test_partial_sequence_no_match(self):
        patterns = {
            "toxic_flows": [{
                "name": "exfil",
                "sequence": [
                    {"category": "cred", "tools": ["read_secrets"]},
                    {"category": "net", "tools": ["http_request"]},
                ],
                "window": 5
            }]
        }
        # Only has the second part, missing first
        history = [
            {"tool": "read_file", "step": 1},
        ]
        proposed = {"tool": "http_request", "step": 2}
        result = match(history, proposed, patterns)
        assert result["matched"] is False


class TestFindPatternMatch:
    """Tests for the pattern matching helper."""

    def test_find_in_window(self):
        history = ["a", "b", "target", "c", "d"]
        found = find_pattern_match(history, "target", window=5)
        assert found is True

    def test_not_in_window(self):
        history = ["target", "a", "b", "c", "d", "e"]
        found = find_pattern_match(history, "target", window=3)
        assert found is False

    def test_multiple_occurrences(self):
        history = ["target", "a", "target", "b"]
        found = find_pattern_match(history, "target", window=2)
        assert found is True  # Second occurrence is within window


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
