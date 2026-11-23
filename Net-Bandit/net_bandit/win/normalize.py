"""Map parsed Windows events (Security, Sysmon, System, PowerShell, Defender) to Events.

Pure Python, so it can be unit-tested off Windows.
"""
from __future__ import annotations

from ..events import Event, basename, ip_category


def _int(v, base=10, default=None):
    try:
        s = str(v).strip()
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s, base)
    except (TypeError, ValueError):
        return default


def _join_user(domain, name) -> str:
    domain, name = (domain or "").strip(), (name or "").strip()
    if not name or name == "-":
        return ""
    return f"{domain}\\{name}" if domain and domain != "-" else name


def normalize(ev: dict, host: str = "") -> Event | None:
    ch, eid, d = ev.get("channel", ""), ev.get("event_id"), ev.get("data", {})
    host = host or ev.get("computer", "")

    if ch == "Microsoft-Windows-Sysmon/Operational" and eid == 1:
        return Event("process_start", {
            "name": basename(d.get("Image")), "exe": d.get("Image", ""), "cmdline": d.get("CommandLine", ""),
            "user": d.get("User", ""), "pid": _int(d.get("ProcessId")), "ppid": _int(d.get("ParentProcessId")),
            "parent_exe": d.get("ParentImage", ""), "parent_name": basename(d.get("ParentImage")),
            "parent_cmdline": d.get("ParentCommandLine", ""), "integrity": d.get("IntegrityLevel", ""),
            "hashes": d.get("Hashes", ""), "source": "sysmon"}, host)

    if ch == "Microsoft-Windows-Sysmon/Operational" and eid == 3:
        return Event("net_connect", {
            "name": basename(d.get("Image")), "exe": d.get("Image", ""), "pid": _int(d.get("ProcessId")),
            "user": d.get("User", ""), "laddr_ip": d.get("SourceIp", ""), "laddr_port": _int(d.get("SourcePort")),
            "raddr_ip": d.get("DestinationIp", ""), "raddr_port": _int(d.get("DestinationPort")),
            "raddr_category": ip_category(d.get("DestinationIp")), "initiated": d.get("Initiated") == "true",
            "protocol": d.get("Protocol", ""), "source": "sysmon"}, host)

    if ch == "Security" and eid == 4688:
        return Event("process_start", {
            "name": basename(d.get("NewProcessName")), "exe": d.get("NewProcessName", ""),
            "cmdline": d.get("CommandLine", ""),
            "user": _join_user(d.get("TargetDomainName") or d.get("SubjectDomainName"),
                               d.get("TargetUserName") or d.get("SubjectUserName")),
            "pid": _int(d.get("NewProcessId")), "ppid": _int(d.get("ProcessId")),
            "parent_exe": d.get("ParentProcessName", ""), "parent_name": basename(d.get("ParentProcessName")),
            "integrity": d.get("MandatoryLabel", ""), "elevation": d.get("TokenElevationType", ""),
            "source": "security"}, host)

    if ch == "Security" and eid in (4624, 4625):
        ip = d.get("IpAddress", "")
        return Event("logon", {
            "event_id": eid, "outcome": "success" if eid == 4624 else "failure",
            "target_user": _join_user(d.get("TargetDomainName"), d.get("TargetUserName")),
            "logon_type": _int(d.get("LogonType")), "ip": ip, "ip_category": ip_category(ip),
            "workstation": d.get("WorkstationName", ""), "process": d.get("ProcessName", ""),
            "auth_package": d.get("AuthenticationPackageName", ""), "status": d.get("Status", ""),
            "sub_status": d.get("SubStatus", "")}, host)

    return Event("win_event", {"channel": ch, "provider": ev.get("provider", ""), "event_id": eid,
                               "data": d}, host)
