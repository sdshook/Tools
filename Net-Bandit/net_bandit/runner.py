"""EntryRunner: executes compiled entries in an isolated worker process.

The agent (possibly running as SYSTEM) never executes model-written code itself. It
sends the entry's code and the event to a worker over a pipe and reads back a verdict.
If the worker does not answer within the timeout, it is killed (job object) and
restarted. That also stops hangs inside C code, such as catastrophic regex
backtracking, which an in-process trace budget cannot interrupt.

Isolation modes, tried in order for mode = "auto":
  Windows: appcontainer -> restricted          (never unisolated unless allow_unisolated)
  other:   process                             (plain child process; development only)
"inprocess" runs entries in the agent itself and exists only for tests.
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time

from . import sandbox


class RunnerDown(sandbox.EntryError):
    """No isolated worker is available; entries cannot be executed safely right now."""


def _bootstrap_args() -> list[str]:
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code = (f"import sys; sys.path.insert(0, {pkg_parent!r}); "
            "from net_bandit.worker import main; main()")
    return ["-I", "-B", "-S", "-c", code]


def _interpreter() -> str:
    # A venv's python.exe is a launcher that spawns the real interpreter as a child, which
    # the sandbox forbids, so always start the base interpreter directly.
    return getattr(sys, "_base_executable", None) or sys.executable


def _grant_paths() -> list[str]:
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return sorted({os.path.dirname(_interpreter()), sys.base_prefix, pkg_parent})


class _PlainWorker:
    """Unsandboxed child process (non-Windows development, or allow_unisolated)."""

    def __init__(self):
        sysroot = os.environ.get("SystemRoot")
        env = {"SYSTEMROOT": sysroot} if sysroot else {}
        kw = {"creationflags": 0x08000000} if os.name == "nt" else {}
        self.p = subprocess.Popen([_interpreter()] + _bootstrap_args(), stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
                                  cwd=tempfile.gettempdir(), **kw)
        self.stdin, self.stdout, self.pid, self.mode = self.p.stdin, self.p.stdout, self.p.pid, "process"

    def alive(self) -> bool:
        return self.p.poll() is None

    def kill(self) -> None:
        try:
            self.p.kill()
            self.p.wait(timeout=2)
        except Exception:
            pass
        for f in (self.stdin, self.stdout):
            try:
                f.close()
            except OSError:
                pass


class EntryRunner:
    def __init__(self, cfg: dict, log=print):
        self.requested = cfg.get("mode", "auto")
        self.allow_unisolated = bool(cfg.get("allow_unisolated", False))
        self.timeout = float(cfg.get("timeout_ms", 1000)) / 1000.0
        self.mem_mb = int(cfg.get("worker_memory_mb", 256))
        self.max_restarts = int(cfg.get("max_restarts_per_minute", 10))
        self.log = log
        self.mode: str | None = None
        self.w = None
        self.q: queue.Queue = queue.Queue()
        self.loaded: set[str] = set()
        self._id = 0
        self._restarts: list[float] = []
        self._lock = threading.Lock()

    # ---- lifecycle ---------------------------------------------------------
    def _candidates(self) -> list[str]:
        if self.requested == "inprocess":
            return ["inprocess"]
        if self.requested != "auto":
            modes = [self.requested]
        elif os.name == "nt":
            modes = ["appcontainer", "restricted"]
        else:
            modes = ["process"]
        if os.name == "nt" and self.allow_unisolated and "process" not in modes:
            modes.append("process")
        return modes

    def start(self) -> str:
        errors = []
        for m in self._candidates():
            try:
                self._spawn(m)
                if m != "inprocess":
                    self._request({"op": "ping"})
                self.mode = m
                self.log(f"[i] entry worker isolation: {m}" + (f" (pid {self.w.pid})" if self.w else ""))
                return m
            except Exception as e:
                errors.append(f"{m}: {e}")
                self._kill()
        self.mode = None
        raise RunnerDown("no isolated entry worker could be started -> " + "; ".join(errors))

    def _spawn(self, mode: str) -> None:
        self.loaded.clear()
        self.q = queue.Queue()
        if mode == "inprocess":
            self.w = None
            return
        if mode in ("appcontainer", "restricted"):
            from .win.isolate import WinWorker
            self.w = WinWorker(mode, _interpreter(), _bootstrap_args(), _grant_paths(), self.mem_mb)
        elif mode == "process":
            self.w = _PlainWorker()
        else:
            raise ValueError(f"unknown isolation mode {mode}")
        t = threading.Thread(target=self._reader, args=(self.w.stdout, self.q), daemon=True)
        t.start()

    @staticmethod
    def _reader(stream, q) -> None:
        try:
            for line in iter(stream.readline, b""):
                q.put(line)
        except (OSError, ValueError):
            pass
        q.put(None)  # EOF: worker exited

    def _kill(self) -> None:
        if self.w is not None:
            self.w.kill()
        self.w = None

    def _restart(self, why: str) -> None:
        now = time.time()
        self._restarts = [t for t in self._restarts if now - t < 60] + [now]
        self._kill()
        if len(self._restarts) > self.max_restarts:
            self.mode = None
            raise RunnerDown(f"entry worker restarted too often ({why}); entries disabled")
        self.log(f"[!] restarting entry worker: {why}")
        self._spawn(self.mode)
        self._request({"op": "ping"})

    def close(self) -> None:
        self._kill()

    # ---- protocol ----------------------------------------------------------
    def _request(self, msg: dict) -> dict:
        self._id += 1
        msg["id"] = self._id
        try:
            self.w.stdin.write((json.dumps(msg, default=str) + "\n").encode())
            self.w.stdin.flush()
        except (OSError, ValueError, AttributeError) as e:
            raise sandbox.EntryError(f"worker pipe closed: {e}") from None
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            try:
                line = self.q.get(timeout=max(0.0, remaining))
            except queue.Empty:
                raise sandbox.EntryTimeout("worker did not answer in time") from None
            if line is None:
                raise sandbox.EntryError("worker exited")
            resp = json.loads(line)
            if resp.get("id") == self._id:
                return resp
            # a late reply to an earlier, timed-out request: discard and keep waiting

    def run(self, code: str, sha: str, event: dict) -> dict:
        """Execute an entry on an event. Raises EntryTimeout/EntryError (entry's fault) or RunnerDown."""
        with self._lock:
            if self.mode is None:
                raise RunnerDown("entry worker unavailable")
            if self.mode == "inprocess":
                return sandbox.run_entry(sandbox.compile_entry(code), event)
            try:
                if not self.w.alive():
                    self._restart("worker had exited")
                if sha not in self.loaded:
                    r = self._request({"op": "load", "sha": sha, "code": code})
                    if not r.get("ok"):
                        raise sandbox.EntryError(r.get("error", "load failed"))
                    self.loaded.add(sha)
                r = self._request({"op": "run", "sha": sha, "event": event})
                if not r.get("ok") and r.get("error") == "not-loaded":
                    self.loaded.discard(sha)
                    self._request({"op": "load", "sha": sha, "code": code})
                    self.loaded.add(sha)
                    r = self._request({"op": "run", "sha": sha, "event": event})
            except sandbox.EntryTimeout:
                self._restart("entry timed out")   # kill the hung worker; blame the entry
                raise
            except RunnerDown:
                raise
            except sandbox.EntryError as e:
                if self.w is None or not self.w.alive():
                    self._restart(str(e))          # the entry crashed the worker
                raise
            if r.get("ok"):
                return r["result"]
            if r.get("timeout"):
                raise sandbox.EntryTimeout(r.get("error", "entry exceeded its budget"))
            raise sandbox.EntryError(r.get("error", "entry failed"))

    def probe(self, paths: list[str]) -> dict:
        with self._lock:
            if self.mode in (None, "inprocess"):
                return {"mode": self.mode}
            old, self.timeout = self.timeout, 10.0
            try:
                r = self._request({"op": "probe", "paths": paths})
            finally:
                self.timeout = old
            return {"mode": self.mode, **(r.get("result") or {})}
