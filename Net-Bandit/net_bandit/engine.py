"""The judgment loop: cache first, Claude on a miss, differential checks on hits."""
from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass

from . import sandbox
from .events import Event, class_key, class_template
from .llm import Analysis, AnalyzerError
from . import notify as N
from .bandit import SpotChecker
from .runner import EntryRunner, RunnerDown
from .similar import ClassIndex

SEVERITY = {"benign": 0, "suspicious": 1, "malicious": 1}


@dataclass
class Decision:
    class_key: str
    kind: str
    source: str        # cache | cache-pending | llm-analyze | llm-verify | budget | error
    verdict: str
    confidence: float
    reason: str
    entry_id: int | None = None
    novelty: float | None = None   # set on misses: 1.0 = unlike any known class


class Engine:
    def __init__(self, cfg: dict, store, analyzer, log=print, sinks=None, runner=None):
        self.cfg = cfg
        self.store = store
        self.analyzer = analyzer
        self.log = log
        self.alerts_path = store.dir / "alerts.jsonl"
        c = cfg["cache"]
        self.threshold = float(c["confidence_threshold"])
        self.approval_mode = c["approval_mode"]
        self.no_compile_minutes = float(c["no_compile_retry_minutes"])
        self.demote_n = int(c["demote_min_disagreements"])
        self.demote_rate = float(c["demote_disagreement_rate"])
        l = cfg["llm"]
        self.diff_rate_pending = float(l["diff_sample_rate_pending"])
        self.daily_budget = int(l["daily_token_budget"])
        self.spot = SpotChecker(cfg["spotcheck"])
        self.sinks = list(sinks or [])
        # All model-written code executes in the isolated worker, never in this process.
        if runner is None:
            runner = EntryRunner(cfg.get("isolation", {}), log)
            try:
                runner.start()
            except RunnerDown as e:
                log(f"[!] {e}")
        self.runner = runner
        self._runner_down_flagged = 0.0
        self.novelty_alert = float(cfg.get("eventlog", {}).get("log_novelty_above", 0) or 0)
        self._budget_flagged = 0.0
        self.index = ClassIndex()
        self._templates: dict[str, dict] = {}
        for r in store.all_classes():
            self._templates[r["class_key"]] = json.loads(r["template"])
            self.index.add(r["class_key"], self._templates[r["class_key"]],
                           {"verdict": r["verdict"], "reason": r["reason"]})

    # ------------------------------------------------------------------
    def handle(self, ev: Event) -> Decision:
        tpl = class_template(ev)
        key = class_key(tpl)
        e = ev.flat()

        d = self._try_cache(key, ev.kind, e, tpl)
        if d is None:
            d = self._miss(key, ev.kind, e, tpl)

        self.store.add_decision(key, ev.kind, d.source, d.entry_id, d.verdict, d.confidence, d.reason,
                                ev.to_json())
        if d.verdict in ("suspicious", "malicious"):
            self._alert(ev, d)
            eid, lvl = (N.MALICIOUS, N.ERROR) if d.verdict == "malicious" else (N.SUSPICIOUS, N.WARNING)
            self._notify(eid, lvl, self._observation(ev, d, f"{d.verdict.upper()}: {ev.kind} - {d.reason}"))
        elif self.novelty_alert and d.novelty is not None and d.novelty >= self.novelty_alert:
            self._notify(N.NOVEL, N.INFO, self._observation(
                ev, d, f"High-novelty {ev.kind} (novelty {d.novelty:.2f}), judged {d.verdict}"))
        return d

    # ------------------------------------------------------------------
    def _try_cache(self, key: str, kind: str, e: dict, tpl: dict) -> Decision | None:
        row = self.store.active_entry(key)
        if row is None:
            return None
        if not sandbox.verify(self.store.key, row["code"], row["sig"]):
            self.store.set_status(row["id"], "revoked", "signature check failed")
            self.log(f"[!] entry {row['id']} failed its integrity check and was revoked")
            self._notify(N.ENTRY_TAMPERED, N.ERROR, {"summary": f"Entry {row['id']} failed its integrity check "
                         "and was revoked (possible tampering with the agent's store)", "entry_id": row["id"],
                         "class_key": key})
            return None
        try:
            out = self.runner.run(row["code"], row["code_sha"], e)
        except RunnerDown as err:
            # Not the entry's fault: don't revoke, and don't send every event to Claude either.
            if time.time() - self._runner_down_flagged > 3600:
                self._runner_down_flagged = time.time()
                self._notify(N.RUNNER_DOWN, N.ERROR, {"summary": "Isolated entry worker unavailable: cached "
                             "checks are not running", "error": str(err)})
            return Decision(key, kind, "error", "unknown", 0.0, f"entry worker unavailable: {err}", row["id"])
        except sandbox.EntryError as err:
            self.store.set_status(row["id"], "revoked", f"runtime error: {err}")
            self.log(f"[!] entry {row['id']} errored and was revoked: {err}")
            self._notify(N.ENTRY_REVOKED, N.WARNING, {"summary": f"Entry {row['id']} revoked after a runtime error",
                         "entry_id": row["id"], "class_key": key, "error": str(err)})
            return None
        if out["verdict"] == "unknown" or out["confidence"] < self.threshold:
            return None  # outside the entry's scope: treat as a miss

        pending = row["status"] == "pending"
        self.store.bump(row["id"], hits=1)
        d = Decision(key, kind, "cache-pending" if pending else "cache", out["verdict"], out["confidence"],
                     out["reason"], row["id"])

        if pending:
            check = random.SystemRandom().random() < self.diff_rate_pending
        else:
            check = self.spot.should_check(row, tpl, out["verdict"])
        if check and self._budget_ok():
            d = self._differential(row, d, e)
        return d

    def _differential(self, row, d: Decision, e: dict) -> Decision:
        self.store.flush()  # never hold a write lock across a network call
        try:
            a = self.analyzer.verify(e)
        except AnalyzerError as err:
            self.log(f"[!] differential check failed: {err}")
            return d
        self.store.add_llm_call("verify", a.usage.model, d.class_key, a.usage)
        disagree = SEVERITY.get(a.verdict, 1) != SEVERITY.get(d.verdict, 1)
        self.store.bump(row["id"], diff_checks=1, disagreements=int(disagree), checked=True)
        self.spot.record(row, disagree)
        if not disagree:
            return d
        fresh = self.store.get_entry(row["id"])
        self.log(f"[~] entry {row['id']} disagreed with the model ({d.verdict} vs {a.verdict})")
        self._notify(N.ENTRY_DISAGREED, N.WARNING, {
            "summary": f"Entry {row['id']} said {d.verdict}; Claude said {a.verdict}. Claude's verdict was used.",
            "entry_id": row["id"], "class_key": d.class_key, "claude_reason": a.reason, "event": e})
        if (fresh["disagreements"] >= self.demote_n
                and fresh["disagreements"] / max(1, fresh["diff_checks"]) >= self.demote_rate):
            self.store.set_status(row["id"], "revoked", "differential disagreement")
            self.log(f"[!] entry {row['id']} revoked after repeated disagreement")
            self._notify(N.ENTRY_REVOKED, N.WARNING, {"summary": f"Entry {row['id']} revoked after repeated "
                         "disagreement with Claude", "entry_id": row["id"], "class_key": d.class_key,
                         "checks": fresh["diff_checks"], "disagreements": fresh["disagreements"]})
        # On disagreement, the model's verdict wins for this event.
        return Decision(d.class_key, d.kind, "llm-verify", a.verdict, a.confidence, a.reason, row["id"])

    # ------------------------------------------------------------------
    def _miss(self, key: str, kind: str, e: dict, tpl: dict) -> Decision:
        novelty = self.index.novelty(tpl, exclude=key)
        if not self._budget_ok():
            if time.time() - self._budget_flagged > 86400:
                self._budget_flagged = time.time()
                self._notify(N.BUDGET, N.WARNING, {"summary": "Daily token budget reached: new activity is "
                             "recorded as 'unknown' and not analysed until the budget resets",
                             "daily_token_budget": self.daily_budget})
            return Decision(key, kind, "budget", "unknown", 0.0,
                            "daily token budget reached; queued for review", novelty=novelty)

        last = self.store.last_analysis(key)
        self.store.flush()  # never hold a write lock across a network call
        declined_recently = (last is not None and not last["compiled"]
                             and time.time() - last["ts"] < self.no_compile_minutes * 60)
        try:
            if declined_recently:
                a = self.analyzer.verify(e)  # cheaper: no compile attempt for this class
                self.store.add_llm_call("verify", a.usage.model, key, a.usage)
                return Decision(key, kind, "llm-verify", a.verdict, a.confidence, a.reason, novelty=novelty)
            samples = self.store.recent_samples(key, 3)
            neighbors = [{"similarity": round(sim, 2), "template": self._template_of(k),
                          "verdict": summ["verdict"], "reason": summ["reason"]}
                         for sim, k, summ in self.index.nearest(tpl, k=3, exclude=key)]
            a = self.analyzer.analyze(e, tpl, samples, neighbors)
        except AnalyzerError as err:
            self.log(f"[!] analysis failed: {err}")
            self._notify(N.ANALYSIS_FAILED, N.WARNING, {"summary": "Claude analysis call failed; event recorded "
                         "as unknown", "class_key": key, "error": str(err)})
            return Decision(key, kind, "error", "unknown", 0.0, f"analysis failed: {err}", novelty=novelty)

        self.store.add_llm_call("analyze", a.usage.model, key, a.usage)
        entry_id, compile_error = self._maybe_install(key, tpl, e, a)
        self.store.add_analysis(key, a.verdict, a.confidence, a.reason, entry_id is not None, compile_error, a.raw)
        self.store.upsert_class(key, kind, tpl, a.verdict, a.confidence, a.reason)
        self.index.add(key, tpl, {"verdict": a.verdict, "reason": a.reason})
        self._templates[key] = tpl
        return Decision(key, kind, "llm-analyze", a.verdict, a.confidence, a.reason, entry_id, novelty)

    def _maybe_install(self, key: str, tpl: dict, e: dict, a: Analysis):
        if not a.compile:
            return None, "model declined to compile"
        errs = sandbox.validate(a.entry_code)
        if errs:
            self.log(f"[x] rejected entry for {key}: {'; '.join(errs)}")
            self._notify(N.ENTRY_REJECTED, N.WARNING, {"summary": "A compiled entry from the model failed "
                         "validation and was rejected", "class_key": key, "problems": errs})
            return None, "; ".join(errs)
        # Self-test (in the isolated worker): the entry must reproduce the model's verdict on
        # the event it was built from.
        try:
            out = self.runner.run(a.entry_code, sandbox.code_sha(a.entry_code), e)
        except RunnerDown as err:
            return None, f"self-test skipped, worker unavailable: {err}"
        except sandbox.EntryError as err:
            return None, f"self-test error: {err}"
        if out["verdict"] != a.verdict:
            return None, f"self-test mismatch: entry said {out['verdict']}, model said {a.verdict}"
        status = "approved" if self.approval_mode == "auto" else "pending"
        sig = sandbox.sign(self.store.key, a.entry_code)
        entry_id = self.store.add_entry(key, a.entry_code, sandbox.code_sha(a.entry_code), sig,
                                        a.entry_description, tpl, a.usage.model, status)
        self.log(f"[+] new {status} entry {entry_id} for class {key} ({tpl.get('kind')})")
        self._notify(N.ENTRY_NEW, N.INFO, {"summary": f"New {status} entry {entry_id} for a "
                     f"{tpl.get('kind')} class: {a.entry_description}", "entry_id": entry_id,
                     "class_key": key, "verdict": a.verdict, "template": tpl})
        return entry_id, None

    def _template_of(self, key: str) -> dict:
        return self._templates.get(key, {})

    # ------------------------------------------------------------------
    def _budget_ok(self) -> bool:
        day_start = time.time() - 86400
        return self.store.tokens_since(day_start) < self.daily_budget

    def _notify(self, event_id: int, level: str, record: dict) -> None:
        for sink in self.sinks:
            try:
                sink(event_id, level, record)
            except Exception as err:  # a broken sink must never stop detection
                self.log(f"[!] notification sink failed: {err}")

    @staticmethod
    def _observation(ev: Event, d: Decision, summary: str) -> dict:
        return {"summary": summary, "host": ev.host, "kind": ev.kind, "verdict": d.verdict,
                "confidence": d.confidence, "reason": d.reason, "source": d.source,
                "novelty": d.novelty, "class_key": d.class_key, "entry_id": d.entry_id,
                "event": ev.fields}

    def _alert(self, ev: Event, d: Decision) -> None:
        rec = {"ts": ev.ts, "host": ev.host, "kind": ev.kind, "verdict": d.verdict,
               "confidence": d.confidence, "reason": d.reason, "source": d.source,
               "class_key": d.class_key, "entry_id": d.entry_id, "novelty": d.novelty,
               "event": ev.fields}
        with open(self.alerts_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
