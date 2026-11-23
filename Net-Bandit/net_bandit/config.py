"""Configuration: defaults merged with an optional TOML file."""
from __future__ import annotations

import copy
import tomllib

DEFAULTS = {
    "general": {"data_dir": "net-bandit-data", "poll_interval": 2.0},
    "llm": {
        "analyze_model": "claude-sonnet-5-5",   # full analysis + compilation on misses
        "verify_model": "claude-haiku-5-5",     # cheap verdict-only checks
        "max_tokens": 2000,
        "api_key_file": "",                     # file holding the API key (for SYSTEM); else ANTHROPIC_API_KEY
        "daily_token_budget": 2_000_000,
        "diff_sample_rate_pending": 0.25,       # share of pending-entry hits re-checked
        # Set these from current Claude API pricing to see cost estimates in `stats`.
        "price_input_per_mtok": 0.0,
        "price_output_per_mtok": 0.0,
    },
    "cache": {
        "approval_mode": "manual",              # manual: new entries start pending; auto: approved at once
        "confidence_threshold": 0.7,
        "no_compile_retry_minutes": 60,
        "demote_min_disagreements": 2,
        "demote_disagreement_rate": 0.2,
    },
    "spotcheck": {                             # re-checking approved entries' cache hits
        "mode": "bandit",                     # bandit (adaptive) | fixed
        "fixed_rate": 0.05,                   # used when mode = fixed
        "floor": 0.01,                        # never check less than 1% of an entry's hits
        "risk_floor": 0.05,                   # floor for risky classes
        "ceiling": 0.5,
        "prior_checks": 10,                   # strength of the starting belief
        "prior_disagree_rate": 0.05,          # starting belief: 5% (same as fixed mode)
        "half_life_days": 7,                  # evidence decays, so checks rise again over time
        "gain": 1.0,                          # check rate = gain x sampled disagreement rate
    },
    "eventlog": {                              # Windows event log output
        "target": "security",                 # security | application | none
        "fallback_to_application": False,     # if the Security log can't be written, use Application
        "source": "net-bandit",
        "register_source": True,              # install the event source (needs elevation once)
        "log_novelty_above": 0.9,             # also log benign observations this novel (0 = off)
    },
    "isolation": {                             # where model-written checks execute
        "mode": "auto",                       # auto | appcontainer | restricted | process | inprocess
        "allow_unisolated": False,            # Windows: never run checks unsandboxed unless True
        "timeout_ms": 1000,                   # worker is killed and restarted past this
        "worker_memory_mb": 256,
        "max_restarts_per_minute": 10,
    },
    "resources": {
        "background_mode": True,                # low CPU, I/O and memory priority (else below-normal)
        "low_memory_priority": True,            # our pages are trimmed before the OS's and apps'
        "eco_qos": True,                        # hybrid CPUs: prefer efficiency cores
        "cpu_affinity": [],                     # e.g. [14, 15] to confine the agent to two logical CPUs
        "cpu_rate_cap_percent": 5.0,            # job-object hard cap on total CPU (0 = off)
        "memory_limit_mb": 512,                 # job-object ceiling; allocations beyond it fail (0 = off)
        "working_set_max_mb": 0,                # hard working-set cap; excess pages are trimmed (0 = off)
        "decision_retention_days": 14,
        "self_report_minutes": 10,              # log own working set and CPU time (0 = off)
    },
    "sources": {
        "event_log": True,
        "tcp_table": True,
        "process_snapshot": "auto",             # auto | always | never
        "signatures": True,
        "skip_baseline": True,
        "channels": {},                         # empty = built-in defaults
    },
}


def load(path: str | None) -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    if path:
        with open(path, "rb") as f:
            user = tomllib.load(f)
        for section, values in user.items():
            if isinstance(values, dict) and section in cfg:
                cfg[section].update(values)
            else:
                cfg[section] = values
    return cfg
