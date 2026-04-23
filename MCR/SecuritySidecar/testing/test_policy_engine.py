"""
Tests for the SecuritySidecar policy engine module.

Run with: pytest testing/test_policy_engine.py -v
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from policy_engine import (
    evaluate,
    check_allowlist,
    check_denylist,
    validate_args,
    check_sequence,
    check_egress,
    requires_human_approval,
)
from models import PolicyDecision


class TestAllowlist:
    """Tests for tool allowlist checking."""

    def test_allowed_tool_passes(self):
        policy = {"tools": {"allowlist": ["read_file", "search_code"]}}
        result = check_allowlist("read_file", policy)
        assert result["permitted"] is True

    def test_unlisted_tool_fails(self):
        policy = {"tools": {"allowlist": ["read_file"]}}
        result = check_allowlist("write_file", policy)
        assert result["permitted"] is False
        assert "not in allowlist" in result["reason"]

    def test_empty_allowlist_permits_all(self):
        policy = {"tools": {"allowlist": []}}
        result = check_allowlist("any_tool", policy)
        assert result["permitted"] is True

    def test_wildcard_allowlist(self):
        policy = {"tools": {"allowlist": ["read_*"]}}
        result = check_allowlist("read_file", policy)
        assert result["permitted"] is True


class TestDenylist:
    """Tests for tool denylist checking."""

    def test_denied_tool_blocked(self):
        policy = {"tools": {"denylist": ["execute_shell", "rm_rf"]}}
        result = check_denylist("execute_shell", policy)
        assert result["permitted"] is False
        assert "denylist" in result["reason"]

    def test_unlisted_tool_passes(self):
        policy = {"tools": {"denylist": ["execute_shell"]}}
        result = check_denylist("read_file", policy)
        assert result["permitted"] is True

    def test_wildcard_denylist(self):
        policy = {"tools": {"denylist": ["delete_*"]}}
        result = check_denylist("delete_user", policy)
        assert result["permitted"] is False


class TestArgValidation:
    """Tests for tool argument validation."""

    def test_valid_args_pass(self):
        policy = {
            "tools": {
                "schemas": {
                    "read_file": {
                        "path": {"type": "string", "required": True}
                    }
                }
            }
        }
        args = {"path": "/etc/config.yaml"}
        result = validate_args("read_file", args, policy)
        assert result["valid"] is True

    def test_missing_required_arg_fails(self):
        policy = {
            "tools": {
                "schemas": {
                    "read_file": {
                        "path": {"type": "string", "required": True}
                    }
                }
            }
        }
        args = {}
        result = validate_args("read_file", args, policy)
        assert result["valid"] is False
        assert "path" in result["reason"]

    def test_wrong_type_fails(self):
        policy = {
            "tools": {
                "schemas": {
                    "read_file": {
                        "path": {"type": "string", "required": True}
                    }
                }
            }
        }
        args = {"path": 12345}
        result = validate_args("read_file", args, policy)
        assert result["valid"] is False

    def test_unknown_tool_passes(self):
        # Tools without schemas are allowed by default
        policy = {"tools": {"schemas": {}}}
        result = validate_args("unknown_tool", {"any": "args"}, policy)
        assert result["valid"] is True


class TestSequenceCheck:
    """Tests for toxic tool call sequence detection."""

    def test_clean_sequence_passes(self):
        policy = {
            "sequences": {
                "deny": [
                    {"pattern": ["read_secrets", "http_request"], "window": 5}
                ]
            }
        }
        prior_calls = ["read_file", "search_code", "read_file"]
        result = check_sequence("write_file", "wf-123", prior_calls, policy)
        assert result["permitted"] is True

    def test_exfil_sequence_blocked(self):
        policy = {
            "sequences": {
                "deny": [
                    {"pattern": ["read_secrets", "http_request"], "window": 5}
                ]
            }
        }
        prior_calls = ["read_file", "read_secrets", "format_data"]
        result = check_sequence("http_request", "wf-123", prior_calls, policy)
        assert result["permitted"] is False
        assert "sequence" in result["reason"].lower()

    def test_sequence_outside_window_passes(self):
        policy = {
            "sequences": {
                "deny": [
                    {"pattern": ["read_secrets", "http_request"], "window": 3}
                ]
            }
        }
        # read_secrets is 5 calls back, outside window of 3
        prior_calls = ["read_secrets", "a", "b", "c", "d"]
        result = check_sequence("http_request", "wf-123", prior_calls, policy)
        assert result["permitted"] is True


class TestEgressCheck:
    """Tests for egress domain restriction."""

    def test_approved_domain_passes(self):
        policy = {
            "egress": {
                "approved_domains": ["api.internal.com", "docs.company.com"]
            }
        }
        args = {"url": "https://api.internal.com/v1/data"}
        result = check_egress("http_request", args, policy)
        assert result["permitted"] is True

    def test_unapproved_domain_blocked(self):
        policy = {
            "egress": {
                "approved_domains": ["api.internal.com"]
            }
        }
        args = {"url": "https://evil.com/exfil"}
        result = check_egress("http_request", args, policy)
        assert result["permitted"] is False
        assert "domain" in result["reason"].lower()

    def test_non_network_tool_passes(self):
        policy = {
            "egress": {
                "approved_domains": ["api.internal.com"]
            }
        }
        args = {"path": "/etc/config"}
        result = check_egress("read_file", args, policy)
        assert result["permitted"] is True

    def test_egress_limit_enforced(self):
        policy = {
            "egress": {
                "max_calls_per_workflow": 3,
                "approved_domains": ["*"]
            }
        }
        # Simulate 3 prior egress calls
        args = {"url": "https://any.com", "_egress_count": 3}
        result = check_egress("http_request", args, policy)
        assert result["permitted"] is False
        assert "limit" in result["reason"].lower()


class TestHumanApproval:
    """Tests for human-in-the-loop approval requirements."""

    def test_destructive_requires_approval(self):
        policy = {
            "tools": {
                "require_approval": ["delete_*", "publish_*", "send_*"]
            }
        }
        result = requires_human_approval("delete_user", policy)
        assert result is True

    def test_safe_tool_no_approval(self):
        policy = {
            "tools": {
                "require_approval": ["delete_*"]
            }
        }
        result = requires_human_approval("read_file", policy)
        assert result is False

    def test_explicit_approval_list(self):
        policy = {
            "tools": {
                "require_approval": ["deploy_production", "rotate_keys"]
            }
        }
        assert requires_human_approval("deploy_production", policy) is True
        assert requires_human_approval("deploy_staging", policy) is False


class TestFullEvaluation:
    """Integration tests for the full policy evaluation pipeline."""

    def test_permitted_call(self):
        policy = {
            "tools": {
                "allowlist": ["read_file", "search_code"],
                "denylist": ["execute_shell"],
                "require_approval": ["delete_*"],
                "schemas": {}
            },
            "sequences": {"deny": []},
            "egress": {"approved_domains": ["*"]}
        }
        result = evaluate("read_file", {"path": "/test"}, "wf-1", 1, policy)
        assert isinstance(result, PolicyDecision)
        assert result.permitted is True
        assert result.requires_approval is False

    def test_denied_by_denylist(self):
        policy = {
            "tools": {
                "allowlist": [],
                "denylist": ["execute_shell"],
                "require_approval": [],
                "schemas": {}
            },
            "sequences": {"deny": []},
            "egress": {"approved_domains": ["*"]}
        }
        result = evaluate("execute_shell", {"cmd": "rm -rf"}, "wf-1", 1, policy)
        assert result.permitted is False
        assert "denylist" in result.violation_reason

    def test_requires_approval_flagged(self):
        policy = {
            "tools": {
                "allowlist": ["delete_user"],
                "denylist": [],
                "require_approval": ["delete_*"],
                "schemas": {}
            },
            "sequences": {"deny": []},
            "egress": {"approved_domains": ["*"]}
        }
        result = evaluate("delete_user", {"id": "123"}, "wf-1", 1, policy)
        assert result.permitted is True
        assert result.requires_approval is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
