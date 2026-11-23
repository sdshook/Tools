"""Command line: run | replay | entries | show | approve | revoke | stats | doctor"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import config as config_mod
from .engine import Engine
from .llm import AnalyzerError, ClaudeAnalyzer, FakeAnalyzer
from .store import Store


def _analyzer(cfg, fake: bool):
    if fake:
        return FakeAnalyzer()
    l = cfg["llm"]
    try:
        return ClaudeAnalyzer(l["analyze_model"], l["verify_model"], int(l["max_tokens"]),
                              l.get("api_key_file", ""))
    except AnalyzerError as e:
        raise SystemExit(f"Cannot start the Claude analyzer: {e}")


def _print_decision(ev, d, verbose: bool):
    if d.verdict == "benign" and not verbose and not d.source.startswith("llm"):
        return
    name = ev.fields.get("name") or ev.fields.get("target_user") or ev.fields.get("event_id") or ""
    nov = f"  novelty={d.novelty:.2f}" if d.novelty is not None else ""
    print(f"[{d.source:13}] {d.verdict:10} {d.confidence:.2f}  {ev.kind:13} {name}  - {d.reason}{nov}")


def _loop(engine, sources, interval: float, verbose: bool, once: bool, res: dict | None = None):
    res = res or {}
    report_every = float(res.get("self_report_minutes", 0) or 0) * 60
    retention = float(res.get("decision_retention_days", 14) or 14)
    next_report = time.time() + report_every if report_every else float("inf")
    next_prune = time.time() + 3600
    try:
        while True:
            for s in sources:
                for ev in s.poll():
                    _print_decision(ev, engine.handle(ev), verbose)
            engine.store.flush()
            if once:
                return
            now = time.time()
            if now >= next_prune:
                engine.store.prune(retention)
                next_prune = now + 86400
            if now >= next_report:
                from .win.resource import self_usage
                print(f"[i] agent footprint: {self_usage()}")
                next_report = now + report_every
            time.sleep(interval)
    except KeyboardInterrupt:
        engine.store.flush()
        print("\nstopped")


def cmd_run(args, cfg):
    from .sources import build_live_sources
    from .win.resource import apply as apply_resource_limits
    apply_resource_limits(cfg["resources"])
    store = Store(cfg["general"]["data_dir"])
    from .notify import STARTED, build_sink
    sinks = []
    sink, where = build_sink(cfg["eventlog"])
    if sink is None:
        print(f"[!] {where} (alerts still go to alerts.jsonl)")
    else:
        print(f"[i] writing events to the {where}")
        try:
            sink(STARTED, "info", {"summary": "net-bandit started", "data_dir": str(store.dir.resolve())})
            sinks.append(sink)
        except OSError as e:
            print(f"[!] event log write failed, output disabled: {e}")
    from .win.proc import process_user
    if process_user(os.getpid()).upper().endswith("\\SYSTEM"):
        from .win.isolate import harden_paths
        for m in harden_paths([str(store.dir.resolve()), cfg["llm"].get("api_key_file", "")]):
            print(f"[i] {m}")
    engine = Engine(cfg, store, _analyzer(cfg, args.fake_llm), sinks=sinks)
    sources = build_live_sources(cfg)
    print(f"[i] net-bandit running; data in {store.dir.resolve()}  (Ctrl+C to stop)")
    try:
        _loop(engine, sources, float(cfg["general"]["poll_interval"]), args.verbose, once=False,
              res=cfg["resources"])
    finally:
        engine.runner.close()


def cmd_replay(args, cfg):
    from .sources import ReplaySource
    store = Store(cfg["general"]["data_dir"])
    engine = Engine(cfg, store, _analyzer(cfg, args.fake_llm))
    try:
        for _ in range(args.passes):
            _loop(engine, [ReplaySource(args.file)], 0, args.verbose, once=True)
    finally:
        engine.runner.close()
    cmd_stats(args, cfg)


def cmd_entries(args, cfg):
    store = Store(cfg["general"]["data_dir"])
    rows = store.list_entries(args.status)
    if not rows:
        print("no entries")
    from .bandit import SpotChecker
    spot = SpotChecker(cfg["spotcheck"])
    pending_rate = float(cfg["llm"]["diff_sample_rate_pending"])
    for r in rows:
        tpl = json.loads(r["template"] or "{}")
        if r["status"] == "pending":
            rate = f"{pending_rate:.1%}"
        elif r["status"] == "approved":
            rate = f"{spot.expected_rate(r, tpl, store.class_verdict(r['class_key'])):.1%}"
        else:
            rate = "-"
        print(f"#{r['id']:<4} {r['status']:9} v{r['version']}  hits={r['hits']:<6} "
              f"checks={r['diff_checks']}/{r['disagreements']} disagree  spot-check={rate:>6}  {tpl.get('kind')}  "
              f"{tpl.get('name') or tpl.get('event_id') or ''}  {r['description'] or ''}")


def cmd_show(args, cfg):
    r = Store(cfg["general"]["data_dir"]).get_entry(args.id)
    if not r:
        raise SystemExit("no such entry")
    print(f"entry #{r['id']}  class {r['class_key']}  v{r['version']}  {r['status']}  model={r['model']}")
    if r["status_note"]:
        print(f"note: {r['status_note']}")
    print(f"template: {r['template']}")
    print(f"description: {r['description']}\n")
    print(r["code"])


def cmd_set(args, cfg, status):
    store = Store(cfg["general"]["data_dir"])
    if not store.get_entry(args.id):
        raise SystemExit("no such entry")
    store.set_status(args.id, status, f"{status} by operator")
    print(f"entry #{args.id} {status}")


def cmd_stats(args, cfg):
    store = Store(cfg["general"]["data_dir"])
    s = store.stats()
    l = cfg["llm"]
    calls = s["llm_calls"]
    tok = lambda p: sum((calls.get(p, {}).get(k) or 0) for k in  # noqa: E731
                        ("input_tokens", "output_tokens", "cache_read", "cache_write"))
    n_calls = sum(c["calls"] for c in calls.values())
    used = tok("analyze") + tok("verify")
    hits = s["by_source"].get("cache", 0) + s["by_source"].get("cache-pending", 0)
    # Counterfactual: every cache hit would otherwise have been at least a verdict-only call.
    per_verify = (tok("verify") / calls["verify"]["calls"]) if calls.get("verify") else None
    per_any = used / n_calls if n_calls else 0
    est_per_hit = per_verify or per_any
    saved = int(hits * est_per_hit)
    print("\n=== net-bandit stats ===")
    print(f"decisions: {s['decisions']}  classes: {s['classes']}")
    print(f"by source: {s['by_source']}")
    print(f"by verdict: {s['by_verdict']}")
    print(f"entries: {s['entries']}")
    print(f"LLM calls: {n_calls}  tokens used: {used:,}")
    if s["decisions"]:
        print(f"cache hit rate: {hits / s['decisions']:.0%}")
    print(f"est. tokens avoided by cache hits: {saved:,}  (~{est_per_hit:,.0f} per hit)")
    pin, pout = float(l["price_input_per_mtok"]), float(l["price_output_per_mtok"])
    if pin or pout:
        inp = sum((c.get("input_tokens") or 0) + (c.get("cache_read") or 0) + (c.get("cache_write") or 0)
                  for c in calls.values())
        out = sum((c.get("output_tokens") or 0) for c in calls.values())
        print(f"est. spend: ${(inp * pin + out * pout) / 1e6:.4f} (cache reads/writes priced as input; adjust)")


def cmd_doctor(args, cfg):
    from .win import IS_WINDOWS
    if not IS_WINDOWS:
        raise SystemExit("doctor checks native Windows APIs; run it on Windows.")
    import ctypes
    import os
    print(f"python {sys.version.split()[0]}  {'64' if sys.maxsize > 2**32 else '32'}-bit")
    try:
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        admin = False
    print(f"elevated: {admin}  (Security and Sysmon channels need an elevated prompt)")

    from .sources import DEFAULT_CHANNELS
    from .win.eventlog import Subscription
    for ch, q in DEFAULT_CHANNELS.items():
        try:
            Subscription(ch, q).close()
            print(f"  ok   event channel {ch}")
        except OSError as e:
            print(f"  --   event channel {ch}: {e}")

    from .win import nettable, proc, trust
    try:
        rows = nettable.tcp_rows()
        print(f"  ok   iphlpapi GetExtendedTcpTable: {len(rows)} listen/established sockets")
    except OSError as e:
        print(f"  FAIL iphlpapi: {e}")
    try:
        snap = proc.snapshot()
        me = os.getpid()
        print(f"  ok   Toolhelp32 snapshot: {len(snap)} processes")
        print(f"  ok   own image: {proc.image_path(me)}")
        print(f"  ok   own command line: {proc.command_line(me)[:80]}")
        print(f"  ok   own user: {proc.process_user(me)}")
    except OSError as e:
        print(f"  FAIL process APIs: {e}")
    windir = os.environ.get("WINDIR", r"C:\Windows")
    for p in (sys.executable, os.path.join(windir, "System32", "cmd.exe"),
              os.path.join(windir, "System32", "notepad.exe")):
        print(f"  ok   signature {trust.signature_state(p):9} {p}")
    from .win import seclog
    src = cfg["eventlog"].get("source", "net-bandit")
    ok, msg = seclog.enable_audit_privilege()
    print(f"  {'ok  ' if ok else 'FAIL'} Security log: {msg}")
    pol = seclog.application_generated_auditing()
    print(f"  {'ok  ' if pol else 'FAIL' if pol is False else '??  '} 'Application Generated' auditing: "
          f"{'on' if pol else 'OFF - run: auditpol /set /subcategory:\"Application Generated\" /success:enable' if pol is False else 'unknown'}")
    if ok:
        ok2, msg2 = seclog.install_source(src)
        print(f"  {'ok  ' if ok2 else 'FAIL'} Security log source '{src}': {msg2}")
        try:
            w = seclog.SecurityLogWriter(src, install=False, log=lambda *_: None)
            from .notify import STARTED, _fields
            wrote = w.write(STARTED, _fields("info", {"summary": "net-bandit doctor: test event"}))
            w.close()
            print(f"  {'ok  ' if wrote else 'FAIL'} test event {STARTED} written to the Security log")
        except OSError as e:
            print(f"  FAIL Security log write: {e}")
    else:
        print("       Run doctor as SYSTEM to test the Security log, e.g. from an elevated prompt:\n"
              "       psexec -s -i cmd   (Sysinternals), then run net-bandit doctor")
    from .runner import EntryRunner, RunnerDown
    print("\nentry worker isolation (model-written checks run here, never in this process):")
    r = EntryRunner(cfg["isolation"], log=lambda m: print("      " + m))
    try:
        mode = r.start()
        print(f"  ok   isolation mode: {mode}")
        ddir = os.path.abspath(cfg["general"]["data_dir"])
        targets = [os.path.join(ddir, "entry.key"), os.path.join(ddir, "net_bandit.db")]
        if cfg["llm"].get("api_key_file"):
            targets.append(cfg["llm"]["api_key_file"])
        res = r.probe([t for t in targets if os.path.exists(t)])
        for path, v in res.get("read", {}).items():
            print(f"  {'FAIL' if v == 'ALLOWED' else 'ok  '} worker read {path}: {v}")
        for path, v in res.get("write", {}).items():
            print(f"  {'FAIL' if v == 'ALLOWED' else 'ok  '} worker write in {path}: {v}")
        net = res.get("network")
        flag = "ok  " if net and net != "ALLOWED" else ("--  " if mode == "restricted" else "FAIL")
        print(f"  {flag} worker network: {net}" + ("  (restricted mode does not block network)" if mode == "restricted" and net == "ALLOWED" else ""))
    except RunnerDown as e:
        print(f"  FAIL {e}")
    finally:
        r.close()
    print("\nIf 4688 events lack command lines, enable 'Include command line in process creation events' "
          "(Group Policy) and audit Process Creation. Installing Sysmon gives richer process and network events.")


def cmd_install_task(args, cfg):
    """Register a scheduled task that runs net-bandit as SYSTEM at startup (needed for the Security log)."""
    import os
    import subprocess
    from .win import IS_WINDOWS
    if not IS_WINDOWS:
        raise SystemExit("install-task is Windows only")
    if not args.config:
        raise SystemExit("pass -c <config.toml> with an absolute data_dir and api_key_file")
    cfg_path = os.path.abspath(args.config)
    if not os.path.isabs(cfg["general"]["data_dir"]):
        raise SystemExit("set an absolute data_dir in the config, e.g. C:\\ProgramData\\net-bandit")
    py = sys.executable.replace("python.exe", "pythonw.exe") if args.hidden else sys.executable
    tr = f'"{py}" -m net_bandit -c "{cfg_path}" run'
    cmd = ["schtasks", "/Create", "/TN", "net-bandit", "/SC", "ONSTART", "/RU", "SYSTEM", "/RL", "HIGHEST",
           "/TR", tr, "/F"]
    print("running:", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    print(r.stdout or r.stderr)
    if r.returncode == 0:
        print("Start it now with:  schtasks /Run /TN net-bandit")


def main(argv=None):
    p = argparse.ArgumentParser(prog="net-bandit", description="ARC host intrusion detection POC")
    p.add_argument("-c", "--config", help="TOML config file")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="collect live events from native Windows APIs")
    r.add_argument("--fake-llm", action="store_true", help="use the offline fake analyzer")
    r.add_argument("-v", "--verbose", action="store_true", help="print benign cache hits too")

    rp = sub.add_parser("replay", help="replay a JSONL file of events")
    rp.add_argument("file")
    rp.add_argument("--fake-llm", action="store_true")
    rp.add_argument("--passes", type=int, default=1, help="replay the file N times")
    rp.add_argument("-v", "--verbose", action="store_true")

    e = sub.add_parser("entries", help="list compiled entries")
    e.add_argument("--status", choices=["pending", "approved", "revoked"])
    for name in ("show", "approve", "revoke"):
        x = sub.add_parser(name, help=f"{name} an entry")
        x.add_argument("id", type=int)
    sub.add_parser("stats", help="usage and savings")
    sub.add_parser("doctor", help="check native Windows collectors and Security log output")
    it = sub.add_parser("install-task", help="run net-bandit as SYSTEM at startup (scheduled task)")
    it.add_argument("--hidden", action="store_true", help="use pythonw.exe (no console window)")

    args = p.parse_args(argv)
    cfg = config_mod.load(args.config)
    {"run": cmd_run, "replay": cmd_replay, "entries": cmd_entries, "show": cmd_show,
     "approve": lambda a, c: cmd_set(a, c, "approved"), "revoke": lambda a, c: cmd_set(a, c, "revoked"),
     "stats": cmd_stats, "doctor": cmd_doctor, "install-task": cmd_install_task}[args.cmd](args, cfg)


if __name__ == "__main__":
    main()
