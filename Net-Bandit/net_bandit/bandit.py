"""Adaptive spot-checking of cache hits (Thompson sampling with guard rails).

For each approved entry we keep a Beta posterior over its *disagreement rate*
(how often Claude would disagree with it). On each cache hit we draw a sample
from that posterior and re-check the hit with that probability, clamped to:

  floor        never check less than this, however reliable the entry looks
  risk_floor   a higher floor for risky classes (non-benign verdicts, unsigned or
               invalid binaries, privileged accounts running unsigned code,
               system binary names outside System32/SysWOW64)
  ceiling      never check more than this

Evidence decays with a half-life, so an entry's apparent reliability fades and
checks slowly rise again unless fresh agreement keeps them low. Sampling uses the
OS's secure RNG so an attacker cannot predict which events will be re-checked.

Cost: two floats and a timestamp per entry, one Beta draw per hit (microseconds),
no extra disk I/O beyond the existing check records.
"""
from __future__ import annotations

import random
import time

SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe",
                "smss.exe", "wininit.exe", "explorer.exe", "rundll32.exe", "dllhost.exe"}

_rng = random.SystemRandom()


def is_risky(template: dict, verdict: str | None) -> bool:
    if verdict and verdict != "benign":
        return True
    sig = template.get("sig")
    if sig in ("unsigned", "invalid"):
        return True
    if "sig" in template and template.get("acct") in ("system", "service") and sig not in ("embedded", "catalog"):
        return True
    if (template.get("kind") == "process_start" and template.get("name") in SYSTEM_NAMES
            and template.get("dir") not in ("<SYSTEM32>", "<SYSWOW64>", "<WINDIR>")):
        return True
    return False


class SpotChecker:
    def __init__(self, cfg: dict):
        self.mode = cfg.get("mode", "bandit")
        self.fixed_rate = float(cfg.get("fixed_rate", 0.05))
        self.floor = float(cfg.get("floor", 0.01))
        self.risk_floor = float(cfg.get("risk_floor", 0.05))
        self.ceiling = float(cfg.get("ceiling", 0.5))
        self.half_life = float(cfg.get("half_life_days", 7)) * 86400
        self.gain = float(cfg.get("gain", 1.0))
        n0 = float(cfg.get("prior_checks", 10))
        p0 = float(cfg.get("prior_disagree_rate", 0.1))
        self.a0, self.b0 = n0 * p0, n0 * (1 - p0)
        self._state: dict[int, list] = {}  # entry_id -> [disagreements, agreements, last_ts]

    # -- evidence ----------------------------------------------------------
    def _load(self, row) -> list:
        st = self._state.get(row["id"])
        if st is None:
            checks, dis = row["diff_checks"] or 0, row["disagreements"] or 0
            last = row["last_check_ts"] if "last_check_ts" in row.keys() and row["last_check_ts"] else time.time()
            st = [float(dis), float(checks - dis), float(last)]
            self._state[row["id"]] = st
        return st

    def _decayed(self, st, now: float) -> tuple[float, float]:
        if self.half_life <= 0:
            return st[0], st[1]
        f = 0.5 ** (max(0.0, now - st[2]) / self.half_life)
        return st[0] * f, st[1] * f

    def record(self, row, disagreed: bool) -> None:
        now = time.time()
        st = self._load(row)
        d, a = self._decayed(st, now)
        st[0], st[1], st[2] = d + (1 if disagreed else 0), a + (0 if disagreed else 1), now

    # -- decisions ---------------------------------------------------------
    def _bounds(self, template: dict, verdict: str | None) -> tuple[float, float]:
        lo = self.risk_floor if is_risky(template, verdict) else self.floor
        return lo, max(lo, self.ceiling)

    def expected_rate(self, row, template: dict, verdict: str | None) -> float:
        """Mean check probability, for display (no randomness)."""
        if self.mode != "bandit":
            return self.fixed_rate
        d, a = self._decayed(self._load(row), time.time())
        mean = (self.a0 + d) / (self.a0 + self.b0 + d + a)
        lo, hi = self._bounds(template, verdict)
        return min(hi, max(lo, self.gain * mean))

    def should_check(self, row, template: dict, verdict: str | None) -> bool:
        if self.mode != "bandit":
            return _rng.random() < self.fixed_rate
        d, a = self._decayed(self._load(row), time.time())
        p = _rng.betavariate(self.a0 + d, self.b0 + a)
        lo, hi = self._bounds(template, verdict)
        return _rng.random() < min(hi, max(lo, self.gain * p))
