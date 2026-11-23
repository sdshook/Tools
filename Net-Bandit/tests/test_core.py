import json
import os

import pytest

from net_bandit import sandbox
from net_bandit.config import load
from net_bandit.engine import Engine
from net_bandit.events import Event, abstract, account_class, class_key, class_template, win_path_bucket
from net_bandit.llm import Analysis, FakeAnalyzer, Usage
from net_bandit.store import Store
from net_bandit.win.eventlog import parse_event_xml
from net_bandit.win.normalize import normalize

GOOD = """
def judge(e):
    cl = e.get('cmdline', '').lower()
    if contains_any(cl, [' -enc']):
        return {'verdict': 'malicious', 'confidence': 0.9, 'reason': 'encoded'}
    if win_path_bucket(e.get('exe', '')) == '<SYSTEM32>':
        return {'verdict': 'benign', 'confidence': 0.8, 'reason': 'system binary'}
    return {'verdict': 'unknown', 'confidence': 0.0, 'reason': 'out of scope'}
"""

BAD = {
    "import": "import os\ndef judge(e):\n    return {}",
    "dunder": "def judge(e):\n    return e.__class__",
    "builtin": "def judge(e):\n    return open('x')",
    "while": "def judge(e):\n    while True:\n        pass",
    "lambda": "def judge(e):\n    f = lambda x: x\n    return f(e)",
    "two_funcs": "def judge(e):\n    return {}\ndef other(x):\n    return x",
    "attr": "def judge(e):\n    return e.pop('x')",
    "big_mul": "def judge(e):\n    return 'a' * 1000 * 1000",
    "call_local": "def judge(e):\n    g = e.get\n    return g('x')",
}


def test_good_entry_runs():
    fn = sandbox.compile_entry(GOOD)
    out = sandbox.run_entry(fn, {"cmdline": "powershell -enc AAA", "exe": ""})
    assert out["verdict"] == "malicious"
    out = sandbox.run_entry(fn, {"cmdline": "", "exe": r"C:\Windows\System32\cmd.exe"})
    assert out["verdict"] == "benign"


@pytest.mark.parametrize("name", sorted(BAD))
def test_bad_entries_rejected(name):
    assert sandbox.validate(BAD[name]), name


def test_opcode_budget_stops_long_loops():
    code = ("def judge(e):\n    n = 0\n    for a in e.get('xs'):\n        for b in e.get('xs'):\n"
            "            n = n + 1\n    return {'verdict': 'benign', 'confidence': 1, 'reason': str(n)}")
    fn = sandbox.compile_entry(code)
    with pytest.raises(sandbox.EntryTimeout):
        sandbox.run_entry(fn, {"xs": list(range(2000))})


def test_entry_cannot_mutate_event():
    code = "def judge(e):\n    e.get('d').update({'x': 1}) if False else None\n    return {'verdict': 'benign', 'confidence': 1, 'reason': ''}"
    # .update is not allowlisted, so this is rejected outright
    assert sandbox.validate(code)


def test_signature_roundtrip():
    k = b"k" * 32
    s = sandbox.sign(k, GOOD)
    assert sandbox.verify(k, GOOD, s)
    assert not sandbox.verify(k, GOOD + "#", s)


def test_buckets_and_accounts():
    assert win_path_bucket(r"C:\Users\bob\AppData\Local\Temp\x.exe") == "<USERTEMP>"
    assert win_path_bucket(r'"C:\Program Files (x86)\App\a.exe"') == "<PROGRAMFILES>"
    assert account_class("NT AUTHORITY\\SYSTEM") == "system"
    assert account_class("CORP\\WS01$") == "machine"
    assert account_class("CORP\\alice") == "user"


def test_class_key_ignores_variable_parts():
    a = Event("logon", {"event_id": 4625, "target_user": "H\\admin", "logon_type": 3, "ip": "203.0.113.4"})
    b = Event("logon", {"event_id": 4625, "target_user": "H\\sql", "logon_type": 3, "ip": "198.51.100.9"})
    assert class_key(class_template(a)) == class_key(class_template(b))
    assert "<b64>" in abstract("powershell -enc " + "A" * 60)


SYSMON_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID><TimeCreated SystemTime='2026-11-23T10:00:00Z'/>
<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS1</Computer></System><EventData>
<Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='CommandLine'>cmd /c whoami</Data>
<Data Name='User'>CORP\\alice</Data><Data Name='ProcessId'>1234</Data><Data Name='ParentProcessId'>99</Data>
<Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data></EventData></Event>"""


def test_sysmon_parse_and_normalize():
    ev = normalize(parse_event_xml(SYSMON_XML))
    assert ev.kind == "process_start"
    assert ev.fields["name"] == "cmd.exe" and ev.fields["parent_name"] == "explorer.exe"
    assert ev.fields["pid"] == 1234 and ev.host == "WS1"


def test_4688_hex_pids():
    ev = normalize({"channel": "Security", "event_id": 4688, "data": {
        "NewProcessName": r"C:\Windows\System32\whoami.exe", "NewProcessId": "0x1a2b", "ProcessId": "0x10",
        "SubjectUserName": "alice", "SubjectDomainName": "CORP", "CommandLine": "whoami"}})
    assert ev.fields["pid"] == 0x1A2B and ev.fields["ppid"] == 0x10 and ev.fields["user"] == "CORP\\alice"


class BadCompiler(FakeAnalyzer):
    def analyze(self, event, template, samples, neighbors=None):
        return Analysis("benign", 0.9, "ok", compile=True,
                        entry_code="import os\ndef judge(e):\n    return {}", usage=Usage("t", 10, 10))


def _engine(tmp_path, analyzer, mode="auto"):
    cfg = load(None)
    cfg["general"]["data_dir"] = str(tmp_path)
    cfg["cache"]["approval_mode"] = mode
    cfg["llm"]["diff_sample_rate"] = 0.0
    return Engine(cfg, Store(str(tmp_path)), analyzer, log=lambda *_: None)


def test_engine_miss_then_hit(tmp_path):
    eng = _engine(tmp_path, FakeAnalyzer())
    e1 = Event("logon", {"event_id": 4625, "target_user": "H\\a", "ip": "203.0.113.1", "ip_category": "public", "logon_type": 3})
    e2 = Event("logon", {"event_id": 4625, "target_user": "H\\b", "ip": "203.0.113.2", "ip_category": "public", "logon_type": 3})
    assert eng.handle(e1).source == "llm-analyze"
    d2 = eng.handle(e2)
    assert d2.source == "cache" and d2.verdict == "suspicious"
    assert os.path.exists(tmp_path / "alerts.jsonl")


def test_engine_rejects_unsafe_entry(tmp_path):
    eng = _engine(tmp_path, BadCompiler())
    ev = Event("process_start", {"name": "a.exe", "exe": r"C:\a.exe"})
    assert eng.handle(ev).source == "llm-analyze"
    assert eng.store.list_entries() == []


def test_tampered_entry_is_revoked(tmp_path):
    eng = _engine(tmp_path, FakeAnalyzer())
    e = Event("logon", {"event_id": 4625, "target_user": "H\\a", "ip": "203.0.113.1", "ip_category": "public", "logon_type": 3})
    eng.handle(e)
    eng.store.db.execute("UPDATE entries SET code = code || '\n'")
    eng.store.db.commit()
    eng.store._front.clear()  # simulate a restart: the tampered copy is read from disk
    assert eng.handle(e).source == "llm-analyze"
    assert eng.store.list_entries()[0]["status"] == "revoked"


def test_front_cache_sees_revocation_from_another_process(tmp_path):
    eng = _engine(tmp_path, FakeAnalyzer())
    e = Event("logon", {"event_id": 4625, "target_user": "H\\a", "ip": "203.0.113.1", "ip_category": "public", "logon_type": 3})
    eng.handle(e)
    assert eng.handle(e).source == "cache"
    eng.store.flush()                      # the run loop flushes every poll cycle
    other = Store(str(tmp_path))           # e.g. `net-bandit revoke 1` in another shell
    other.set_status(1, "revoked", "operator")
    eng.store._dv_checked = 0              # skip the 1-second check interval
    assert eng.handle(e).source == "llm-analyze"


def test_neighbors_and_novelty(tmp_path):
    seen = {}

    class Spy(FakeAnalyzer):
        def analyze(self, event, template, samples, neighbors=None):
            seen["neighbors"] = neighbors
            return super().analyze(event, template, samples, neighbors)

    eng = _engine(tmp_path, Spy())
    base = {"name": "svchost.exe", "exe": r"C:\Windows\System32\svchost.exe", "parent_name": "services.exe",
            "user": "NT AUTHORITY\\SYSTEM", "signature": "catalog"}
    d1 = eng.handle(Event("process_start", dict(base, cmdline="svchost.exe -k netsvcs -p -s Schedule")))
    assert d1.novelty == 1.0
    lookalike = dict(base, exe=r"C:\Users\bob\AppData\Local\Temp\svchost.exe", signature="unsigned",
                     cmdline="svchost.exe -k netsvcs -p -s Schedule")
    d2 = eng.handle(Event("process_start", lookalike))
    assert d2.source == "llm-analyze" and 0 < d2.novelty < 1
    assert seen["neighbors"] and seen["neighbors"][0]["verdict"] == "benign"


# ---- adaptive spot-checking ------------------------------------------------
from net_bandit.bandit import SpotChecker, is_risky

CALM = {"kind": "process_start", "name": "chrome.exe", "dir": "<PROGRAMFILES>", "sig": "embedded", "acct": "user"}


def _row(i=1, checks=0, dis=0):
    return {"id": i, "diff_checks": checks, "disagreements": dis, "last_check_ts": None}


class _R(dict):
    def keys(self):
        return super().keys()


def test_bandit_rate_falls_with_agreement_but_respects_floor():
    sc = SpotChecker(load(None)["spotcheck"])
    r = _R(_row())
    start = sc.expected_rate(r, CALM, "benign")
    for _ in range(500):
        sc.record(r, disagreed=False)
    end = sc.expected_rate(r, CALM, "benign")
    assert start == pytest.approx(0.05) and end == pytest.approx(0.01)


def test_bandit_rate_rises_with_disagreement():
    sc = SpotChecker(load(None)["spotcheck"])
    r = _R(_row())
    for _ in range(10):
        sc.record(r, disagreed=True)
    assert sc.expected_rate(r, CALM, "benign") > 0.4


def test_risky_classes_keep_higher_floor():
    sc = SpotChecker(load(None)["spotcheck"])
    r = _R(_row())
    for _ in range(500):
        sc.record(r, disagreed=False)
    fake_svchost = {"kind": "process_start", "name": "svchost.exe", "dir": "<USERTEMP>", "sig": "unsigned", "acct": "user"}
    assert is_risky(fake_svchost, "benign") and not is_risky(CALM, "benign")
    assert sc.expected_rate(r, fake_svchost, "benign") == pytest.approx(0.05)
    assert sc.expected_rate(r, CALM, "malicious") == pytest.approx(0.05)


def test_evidence_decays_so_checks_rise_again():
    sc = SpotChecker(load(None)["spotcheck"])
    r = _R(_row())
    for _ in range(200):
        sc.record(r, disagreed=False)
    low = sc.expected_rate(r, CALM, "benign")
    sc._state[1][2] -= 60 * 86400  # pretend the last check was 60 days ago
    assert sc.expected_rate(r, CALM, "benign") > low * 3


def test_logon_classes_are_not_risky_just_for_lacking_a_signature():
    assert not is_risky({"kind": "logon", "acct": "system", "event_id": 4624}, "benign")


# ---- notifications ------------------------------------------------------------
from net_bandit import notify


def test_notifications_for_detections_and_entries(tmp_path):
    sink = notify.MemorySink()
    cfg = load(None)
    cfg["general"]["data_dir"] = str(tmp_path)
    eng = Engine(cfg, Store(str(tmp_path)), FakeAnalyzer(), log=lambda *_: None, sinks=[sink])
    eng.handle(Event("process_start", {"name": "powershell.exe", "exe": r"C:\Windows\System32\powershell.exe",
                                       "cmdline": "powershell -enc AAAA", "parent_name": "winword.exe"}))
    ids = [i for i, _, _ in sink.items]
    assert notify.ENTRY_NEW in ids and notify.MALICIOUS in ids
    lvl = dict((i, l) for i, l, _ in sink.items)
    assert lvl[notify.MALICIOUS] == "error"
    rec = dict((i, r) for i, _, r in sink.items)[notify.MALICIOUS]
    assert rec["event"]["cmdline"] == "powershell -enc AAAA" and rec["summary"].startswith("MALICIOUS")


def test_broken_sink_does_not_stop_detection(tmp_path):
    def bad(*_):
        raise RuntimeError("disk full")
    cfg = load(None)
    cfg["general"]["data_dir"] = str(tmp_path)
    eng = Engine(cfg, Store(str(tmp_path)), FakeAnalyzer(), log=lambda *_: None, sinks=[bad])
    d = eng.handle(Event("net_listen", {"name": "nc.exe", "laddr_port": 4444, "laddr_ip": "0.0.0.0"}))
    assert d.verdict == "malicious"


def test_security_log_fields_are_fixed_and_ordered():
    f = notify._fields("error", {"summary": "MALICIOUS: x", "verdict": "malicious", "kind": "net_listen",
                                 "host": "H", "class_key": "k", "entry_id": None, "novelty": 0.5, "confidence": 0.9})
    assert len(f) == 9 and f[0].startswith("MALICIOUS: x") and f[1:] == [
        "error", "malicious", "net_listen", "H", "k", "-", "0.5", "0.9"]


def test_event_ids_avoid_windows_security_ranges():
    ids = [v for k, v in vars(notify).items() if k.isupper() and isinstance(v, int)]
    assert all(7100 <= i <= 7199 for i in ids)


def test_build_sink_off_windows_or_disabled():
    assert notify.build_sink({"target": "none"})[0] is None
    sink, why = notify.build_sink({"target": "security"}, log=lambda *_: None)
    assert sink is None and "unavailable" in why   # not Windows here


# ---- isolated worker ---------------------------------------------------------
from net_bandit.runner import EntryRunner, RunnerDown

REDOS = ("def judge(e):\n    if re_search('(a+)+$', e.get('s', '')):\n"
         "        return {'verdict': 'benign', 'confidence': 1, 'reason': 'x'}\n"
         "    return {'verdict': 'unknown', 'confidence': 0, 'reason': 'x'}\n")


def _runner(**kw):
    r = EntryRunner({"mode": "process", "timeout_ms": 1500, **kw}, log=lambda *_: None)
    r.start()
    return r


def test_worker_runs_entries_out_of_process():
    r = _runner()
    try:
        out = r.run(GOOD, sandbox.code_sha(GOOD), {"cmdline": "powershell -enc AAA", "exe": ""})
        assert out["verdict"] == "malicious"
        assert r.w.pid != os.getpid()
    finally:
        r.close()


def test_hung_entry_is_killed_and_worker_restarts():
    # Catastrophic regex backtracking runs inside C code: an in-process budget cannot stop it.
    r = _runner()
    try:
        first_pid = r.w.pid
        with pytest.raises(sandbox.EntryTimeout):
            r.run(REDOS, sandbox.code_sha(REDOS), {"s": "a" * 64 + "b"})
        assert r.w.pid != first_pid  # killed and replaced
        out = r.run(GOOD, sandbox.code_sha(GOOD), {"cmdline": "", "exe": r"C:\Windows\System32\a.exe"})
        assert out["verdict"] == "benign"
    finally:
        r.close()


def test_main_process_never_executes_model_code(tmp_path, monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("model-written code executed in the main process")
    monkeypatch.setattr(sandbox, "run_entry", forbidden)
    monkeypatch.setattr(sandbox, "compile_entry", forbidden)
    cfg = load(None)
    cfg["general"]["data_dir"] = str(tmp_path)
    cfg["isolation"]["mode"] = "process"
    eng = Engine(cfg, Store(str(tmp_path)), FakeAnalyzer(), log=lambda *_: None)
    try:
        e = Event("logon", {"event_id": 4625, "target_user": "H\\a", "ip": "203.0.113.1", "ip_category": "public", "logon_type": 3})
        assert eng.handle(e).source == "llm-analyze"   # self-test ran in the worker
        assert eng.handle(e).source.startswith("cache")  # cache hit ran in the worker
    finally:
        eng.runner.close()


def test_runner_down_does_not_revoke_or_call_llm(tmp_path):
    cfg = load(None)
    cfg["general"]["data_dir"] = str(tmp_path)
    cfg["isolation"]["mode"] = "process"
    sink = notify.MemorySink()
    eng = Engine(cfg, Store(str(tmp_path)), FakeAnalyzer(), log=lambda *_: None, sinks=[sink])
    e = Event("logon", {"event_id": 4625, "target_user": "H\\a", "ip": "203.0.113.1", "ip_category": "public", "logon_type": 3})
    eng.handle(e)
    eng.runner.close()
    eng.runner.mode = None                             # simulate: no isolated worker available
    calls_before = eng.store.stats()["llm_calls"]
    d = eng.handle(e)
    assert d.source == "error" and d.verdict == "unknown"
    assert eng.store.list_entries()[0]["status"] != "revoked"
    assert eng.store.stats()["llm_calls"] == calls_before
    assert notify.RUNNER_DOWN in [i for i, _, _ in sink.items]


def test_validation_rejects_oversized_or_nested_before_parsing():
    assert sandbox.validate("x" * 100_000) == ["code too long"]
    assert sandbox.validate("def judge(e):\n    return " + "(" * 300 + "1" + ")" * 300) == ["too deeply nested"]
