"""Isolated worker: the only process that executes model-written entries.

Launched by EntryRunner and spoken to with JSON lines on stdin/stdout. It holds no API
key, no database handle and no signing key. On Windows it runs inside an AppContainer
(no network, can read only the files explicitly granted to it) or, failing that, under a
restricted low-integrity token with no privileges. It runs in a job object that lets it
start no child processes. The parent kills and restarts it if it ever stops answering.

Requests:  {"id", "op": "ping" | "load" | "run" | "probe", ...}
Responses: {"id", "ok": bool, "result"?, "error"?, "timeout"?}
"""
from __future__ import annotations

import json
import os
import sys


def _probe(paths: list[str]) -> dict:
    """Report what this process can reach, so `doctor` can confirm the isolation works."""
    out: dict = {"pid": os.getpid(), "read": {}, "write": {}, "network": None}
    for p in paths:
        try:
            with open(p, "rb") as f:
                f.read(1)
            out["read"][p] = "ALLOWED"
        except OSError as e:
            out["read"][p] = f"denied ({e.__class__.__name__})"
        d = p if os.path.isdir(p) else os.path.dirname(p)
        t = os.path.join(d, ".net-bandit-probe")
        try:
            with open(t, "wb") as f:
                f.write(b"x")
            os.remove(t)
            out["write"][d] = "ALLOWED"
        except OSError as e:
            out["write"][d] = f"denied ({e.__class__.__name__})"
    try:
        import socket
        s = socket.create_connection(("1.1.1.1", 443), timeout=2)
        s.close()
        out["network"] = "ALLOWED"
    except OSError as e:
        out["network"] = f"denied ({e.__class__.__name__})"
    return out


def main() -> None:
    from net_bandit import sandbox

    funcs: dict = {}
    inp, out = sys.stdin.buffer, sys.stdout.buffer
    for line in inp:
        rid = None
        try:
            req = json.loads(line)
            rid = req.get("id")
            op = req.get("op")
            if op == "ping":
                resp = {"ok": True, "result": {"pid": os.getpid()}}
            elif op == "load":
                funcs[req["sha"]] = sandbox.compile_entry(req["code"])
                if len(funcs) > 512:
                    funcs.pop(next(iter(funcs)))
                resp = {"ok": True}
            elif op == "run":
                fn = funcs.get(req["sha"])
                if fn is None:
                    resp = {"ok": False, "error": "not-loaded"}
                else:
                    resp = {"ok": True, "result": sandbox.run_entry(fn, req["event"])}
            elif op == "probe":
                resp = {"ok": True, "result": _probe(req.get("paths", []))}
            else:
                resp = {"ok": False, "error": f"unknown op {op!r}"}
        except sandbox.EntryTimeout as e:
            resp = {"ok": False, "error": str(e), "timeout": True}
        except sandbox.EntryError as e:
            resp = {"ok": False, "error": str(e)}
        except Exception as e:  # report, never die on a bad request
            resp = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        resp["id"] = rid
        out.write((json.dumps(resp, default=str) + "\n").encode())
        out.flush()


if __name__ == "__main__":
    main()
