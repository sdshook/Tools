"""Event sources. Each source has poll() -> list[Event]."""
from __future__ import annotations

import json
import socket
import time

from .events import Event, basename, ip_category
from .win import IS_WINDOWS

DEFAULT_CHANNELS = {
    "Security": "*[System[(EventID=4688 or EventID=4624 or EventID=4625 or EventID=4720 "
                "or EventID=4732 or EventID=4698 or EventID=1102)]]",
    "System": "*[System[(EventID=7045)]]",
    "Microsoft-Windows-Sysmon/Operational": "*[System[(EventID=1 or EventID=3)]]",
    "Microsoft-Windows-PowerShell/Operational": "*[System[(EventID=4104)]]",
    "Microsoft-Windows-Windows Defender/Operational": "*[System[(EventID=1116 or EventID=1117)]]",
}


def _host() -> str:
    return socket.gethostname()


class ReplaySource:
    """Replays events from a JSONL file: {"kind", "host", "ts", "fields"} per line."""

    def __init__(self, path: str):
        self.path = path
        self.done = False

    def poll(self) -> list[Event]:
        if self.done:
            return []
        self.done = True
        out = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(Event.from_dict(json.loads(line)))
        return out


class EventLogSource:
    """Live subscriptions to Windows event channels (wevtapi.dll)."""

    def __init__(self, channels: dict[str, str], enrich_signatures: bool = True, log=print):
        from .win.eventlog import Subscription
        self.subs = []
        self.enrich = enrich_signatures
        self.host = _host()
        self.log = log
        for ch, q in channels.items():
            try:
                self.subs.append(Subscription(ch, q))
                log(f"[i] subscribed to {ch}")
            except OSError as e:
                log(f"[i] skipping {ch}: {e}")
        self.has_sysmon = any(s.channel == "Microsoft-Windows-Sysmon/Operational" for s in self.subs)

    def poll(self) -> list[Event]:
        from .win.eventlog import parse_event_xml
        from .win.normalize import normalize
        out = []
        for s in self.subs:
            try:
                xmls = s.read()
            except OSError as e:
                self.log(f"[!] read failed on {s.channel}: {e}")
                continue
            for x in xmls:
                try:
                    parsed = parse_event_xml(x)
                except Exception:  # malformed XML from a provider should not stop the agent
                    continue
                if self.has_sysmon and parsed["channel"] == "Security" and parsed["event_id"] == 4688:
                    continue  # Sysmon event 1 is richer; avoid duplicates
                ev = normalize(parsed, self.host)
                if ev is None:
                    continue
                if self.enrich and ev.kind == "process_start" and ev.fields.get("exe"):
                    from .win.trust import signature_state
                    ev.fields["signature"] = signature_state(ev.fields["exe"])
                out.append(ev)
        return out


class TcpTableSource:
    """New listeners and established connections from GetExtendedTcpTable (iphlpapi.dll)."""

    def __init__(self, skip_baseline: bool = True):
        from .win.proc import NameCache
        self.names = NameCache()
        self.host = _host()
        self.seen: set = set()
        if skip_baseline:
            self.seen = {self._key(r) for r in self._rows()}

    def _rows(self):
        from .win.nettable import tcp_rows
        return tcp_rows()

    @staticmethod
    def _key(r):
        if r["state"] == "listen":
            return ("L", r["pid"], r["laddr_ip"], r["laddr_port"])
        # Connections are keyed without the ephemeral local port, so repeat connections
        # from the same process to the same endpoint are reported once.
        return ("E", r["pid"], r["raddr_ip"], r["raddr_port"])

    def poll(self) -> list[Event]:
        out = []
        for r in self._rows():
            k = self._key(r)
            if k in self.seen:
                continue
            self.seen.add(k)
            exe = self.names.get(r["pid"])
            base = {"name": basename(exe) or "unknown", "exe": exe, "pid": r["pid"],
                    "laddr_ip": r["laddr_ip"], "laddr_port": r["laddr_port"], "source": "iphlpapi"}
            if r["state"] == "listen":
                base["bind_category"] = ip_category(r["laddr_ip"])
                out.append(Event("net_listen", base, self.host))
            else:
                if ip_category(r["raddr_ip"]) == "loopback":
                    continue
                base.update(raddr_ip=r["raddr_ip"], raddr_port=r["raddr_port"],
                            raddr_category=ip_category(r["raddr_ip"]))
                out.append(Event("net_connect", base, self.host))
        if len(self.seen) > 200_000:
            self.seen.clear()
        return out


class ProcessSnapshotSource:
    """Fallback when neither Sysmon nor Security 4688 is available: polls Toolhelp32 snapshots.

    Polling misses processes that start and exit between polls; prefer Sysmon or 4688.
    """

    def __init__(self, skip_baseline: bool = True, enrich_signatures: bool = True):
        from .win import proc
        self.proc = proc
        self.host = _host()
        self.enrich = enrich_signatures
        self.seen: set = set()
        if skip_baseline:
            self.seen = {(p, n) for p, _, n in proc.snapshot()}

    def poll(self) -> list[Event]:
        snap = self.proc.snapshot()
        names = {p: n for p, _, n in snap}
        out = []
        for pid, ppid, name in snap:
            if (pid, name) in self.seen:
                continue
            self.seen.add((pid, name))
            exe = self.proc.image_path(pid)
            f = {"name": name.lower(), "exe": exe, "cmdline": self.proc.command_line(pid),
                 "user": self.proc.process_user(pid), "pid": pid, "ppid": ppid,
                 "parent_name": (names.get(ppid) or "").lower(), "parent_exe": self.proc.image_path(ppid),
                 "source": "snapshot"}
            if self.enrich and exe:
                from .win.trust import signature_state
                f["signature"] = signature_state(exe)
            out.append(Event("process_start", f, self.host))
        live = {(p, n) for p, _, n in snap}
        self.seen &= live
        return out


def build_live_sources(cfg: dict, log=print) -> list:
    if not IS_WINDOWS:
        raise SystemExit("Live collection uses native Windows APIs; run on Windows, or use 'replay'.")
    s = cfg["sources"]
    out: list = []
    elog = None
    if s.get("event_log", True):
        channels = s.get("channels") or DEFAULT_CHANNELS
        elog = EventLogSource(channels, s.get("signatures", True), log)
        out.append(elog)
    if s.get("tcp_table", True):
        out.append(TcpTableSource(s.get("skip_baseline", True)))
    have_proc_events = elog is not None and any(
        sub.channel in ("Microsoft-Windows-Sysmon/Operational", "Security") for sub in elog.subs)
    if s.get("process_snapshot") == "always" or (s.get("process_snapshot", "auto") == "auto" and not have_proc_events):
        log("[i] using Toolhelp32 process polling")
        out.append(ProcessSnapshotSource(s.get("skip_baseline", True), s.get("signatures", True)))
    return out
