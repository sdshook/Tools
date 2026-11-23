"""Event model and problem-class templating.

A *problem class* is the shape of an event with its variable parts abstracted
away (numbers, GUIDs, user names, paths reduced to well-known buckets). Events
that share a class key are judged by the same compiled cache entry.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import ntpath
import re
import time
from dataclasses import dataclass, field

VERDICTS = ("benign", "suspicious", "malicious", "unknown")


@dataclass
class Event:
    kind: str
    fields: dict
    host: str = ""
    ts: float = field(default_factory=time.time)

    def flat(self) -> dict:
        d = dict(self.fields)
        d["kind"] = self.kind
        d["host"] = self.host
        return d

    def to_json(self) -> str:
        return json.dumps(
            {"kind": self.kind, "host": self.host, "ts": self.ts, "fields": self.fields},
            default=str,
        )

    @classmethod
    def from_dict(cls, d: dict) -> "Event":
        return cls(
            kind=d["kind"],
            fields=d.get("fields", {}),
            host=d.get("host", ""),
            ts=d.get("ts", time.time()),
        )


# --------------------------------------------------------------------------
# Windows-aware helpers (also exposed to compiled entries)
# --------------------------------------------------------------------------

_BUCKETS = [
    (re.compile(r"^[a-z]:\\windows\\system32\\"), "<SYSTEM32>"),
    (re.compile(r"^[a-z]:\\windows\\syswow64\\"), "<SYSWOW64>"),
    (re.compile(r"^[a-z]:\\windows\\temp\\"), "<WINTEMP>"),
    (re.compile(r"^[a-z]:\\windows\\"), "<WINDIR>"),
    (re.compile(r"^[a-z]:\\program files( \(x86\))?\\"), "<PROGRAMFILES>"),
    (re.compile(r"^[a-z]:\\programdata\\"), "<PROGRAMDATA>"),
    (re.compile(r"^[a-z]:\\users\\[^\\]+\\appdata\\local\\temp\\"), "<USERTEMP>"),
    (re.compile(r"^[a-z]:\\users\\[^\\]+\\appdata\\"), "<APPDATA>"),
    (re.compile(r"^[a-z]:\\users\\[^\\]+\\(downloads|desktop|documents)\\"), "<USERDOCS>"),
    (re.compile(r"^[a-z]:\\users\\"), "<USERS>"),
    (re.compile(r"^[a-z]:\\"), "<DRIVE>"),
]


def win_path_bucket(path: str) -> str:
    """Map a Windows path to a coarse, security-meaningful location bucket."""
    if not path:
        return ""
    q = str(path).strip().strip('"').replace("/", "\\").lower()
    if q.startswith("\\\\?\\"):
        q = q[4:]
    if q.startswith("\\\\"):
        return "<UNC>"
    for rx, name in _BUCKETS:
        if rx.match(q):
            return name
    return "<OTHER>"


def basename(path: str) -> str:
    return ntpath.basename(str(path or "").strip('"')).lower()


def _path_token(path: str) -> str:
    ext = ntpath.splitext(basename(path))[1][:6]
    return f"{win_path_bucket(path)}*{ext}"


def account_class(user: str) -> str:
    u = str(user or "").strip().lower()
    if not u or u == "-":
        return "none"
    name = u.split("\\")[-1]
    if name in ("system", "local system") or u.endswith("\\system"):
        return "system"
    if name in ("local service", "network service") or u.startswith("nt service\\"):
        return "service"
    if name.startswith(("dwm-", "umfd-")):
        return "system"
    if name == "anonymous logon":
        return "anonymous"
    if name.endswith("$"):
        return "machine"
    return "user"


def ip_category(ip: str) -> str:
    s = str(ip or "").strip().strip("[]")
    if s in ("", "-", "*"):
        return "none"
    if s.startswith("::ffff:"):
        s = s[7:]
    try:
        a = ipaddress.ip_address(s.split("%")[0])
    except ValueError:
        return "invalid"
    if a.is_unspecified:
        return "any"
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link_local"
    if a.is_multicast:
        return "multicast"
    if a.is_private:
        return "private"
    return "public"


COMMON_PORTS = {1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8000, 8080,
                8443, 8888, 9200, 27017, 4444, 1337, 31337}


def port_class(port) -> str:
    try:
        p = int(port)
    except (TypeError, ValueError):
        return "none"
    if p < 1024 or p in COMMON_PORTS:
        return str(p)
    return "eph"


# --------------------------------------------------------------------------
# Text abstraction
# --------------------------------------------------------------------------

_QUOTED_WINPATH = re.compile(r'"((?:[A-Za-z]:\\|\\\\)[^"]*)"')
_WINPATH = re.compile(r"(?:[A-Za-z]:\\|\\\\)[^\s\"'|<>&;,]*")
_GUID = re.compile(r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?")
_SID = re.compile(r"S-1-[0-9-]+")
_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HEX = re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{12,}\b")
_NUM = re.compile(r"\b\d+\b")
_USER = re.compile(r"(?i)\b(user|for)\s+(?!invalid\b)([^\s,]+)")
_WS = re.compile(r"\s+")


def abstract(text, limit: int = 240) -> str:
    """Replace the variable parts of free text with placeholders."""
    if not text:
        return ""
    s = str(text)
    s = _QUOTED_WINPATH.sub(lambda m: _path_token(m.group(1)), s)
    s = _WINPATH.sub(lambda m: _path_token(m.group(0)), s)
    s = _GUID.sub("<GUID>", s)
    s = _SID.sub("<SID>", s)
    s = _B64.sub("<B64>", s)
    s = _IPV4.sub("<IP>", s)
    s = _HEX.sub("<HEX>", s)
    s = _NUM.sub("<N>", s)
    s = _USER.sub(lambda m: f"{m.group(1)} <USER>", s)
    s = _WS.sub(" ", s).strip()
    return s[:limit].lower()


# --------------------------------------------------------------------------
# Class templates
# --------------------------------------------------------------------------

def class_template(ev: Event) -> dict:
    f = ev.fields
    k = ev.kind
    if k == "process_start":
        return {
            "kind": k,
            "name": basename(f.get("exe") or f.get("name", "")),
            "parent": basename(f.get("parent_exe") or f.get("parent_name", "")),
            "acct": account_class(f.get("user", "")),
            "dir": win_path_bucket(f.get("exe", "")),
            "sig": f.get("signature", "unknown"),
            "cmd": abstract(f.get("cmdline", "")),
        }
    if k == "net_connect":
        return {
            "kind": k,
            "name": basename(f.get("exe") or f.get("name", "")),
            "dir": win_path_bucket(f.get("exe", "")),
            "rport": port_class(f.get("raddr_port")),
            "rcat": ip_category(f.get("raddr_ip")),
        }
    if k == "net_listen":
        return {
            "kind": k,
            "name": basename(f.get("exe") or f.get("name", "")),
            "port": port_class(f.get("laddr_port")),
            "bind": ip_category(f.get("laddr_ip")),
        }
    if k == "logon":
        return {
            "kind": k,
            "event_id": f.get("event_id"),
            "logon_type": f.get("logon_type"),
            "acct": account_class(f.get("target_user", "")),
            "ipcat": ip_category(f.get("ip")),
            "process": basename(f.get("process", "")),
            "status": str(f.get("sub_status") or f.get("status") or "").lower(),
        }
    if k == "win_event":
        data = f.get("data", {}) or {}
        eid = f.get("event_id")
        tpl = {"kind": k, "channel": f.get("channel"), "event_id": eid}
        if eid == 7045:  # service installed
            tpl.update(acct=account_class(data.get("AccountName", "")),
                       image=abstract(data.get("ImagePath", ""), 120),
                       start=data.get("StartType"))
        elif eid == 4104:  # PowerShell script block
            tpl.update(script=abstract(data.get("ScriptBlockText", ""), 160))
        else:
            items = sorted((str(a), abstract(b, 80)) for a, b in data.items())
            tpl.update(data=abstract(json.dumps(items), 300))
        return tpl
    return {"kind": k, "data": abstract(json.dumps(f, sort_keys=True, default=str), 300)}


def class_key(template: dict) -> str:
    blob = json.dumps(template, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()[:16]
