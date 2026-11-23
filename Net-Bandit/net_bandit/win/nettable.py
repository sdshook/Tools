"""TCP connection tables via iphlpapi.dll GetExtendedTcpTable (IPv4 and IPv6)."""
from __future__ import annotations

import ctypes
import socket
import struct
from ctypes import wintypes

from . import IS_WINDOWS

AF_INET, AF_INET6 = 2, 23
TCP_TABLE_OWNER_PID_ALL = 5
ERROR_INSUFFICIENT_BUFFER = 122
MIB_TCP_STATE_LISTEN = 2
MIB_TCP_STATE_ESTAB = 5


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwState", wintypes.DWORD), ("dwLocalAddr", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD), ("dwRemoteAddr", wintypes.DWORD),
                ("dwRemotePort", wintypes.DWORD), ("dwOwningPid", wintypes.DWORD)]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("ucLocalAddr", ctypes.c_ubyte * 16), ("dwLocalScopeId", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD), ("ucRemoteAddr", ctypes.c_ubyte * 16),
                ("dwRemoteScopeId", wintypes.DWORD), ("dwRemotePort", wintypes.DWORD),
                ("dwState", wintypes.DWORD), ("dwOwningPid", wintypes.DWORD)]


if IS_WINDOWS:
    _ip = ctypes.WinDLL("iphlpapi")
    _ip.GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                                        wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
    _ip.GetExtendedTcpTable.restype = wintypes.DWORD


def _port(dw: int) -> int:
    return socket.ntohs(dw & 0xFFFF)


def _table(af: int):
    size = wintypes.DWORD(0)
    _ip.GetExtendedTcpTable(None, ctypes.byref(size), False, af, TCP_TABLE_OWNER_PID_ALL, 0)
    for _ in range(4):  # the table can grow between calls
        buf = ctypes.create_string_buffer(size.value + 4096)
        size = wintypes.DWORD(len(buf))
        rc = _ip.GetExtendedTcpTable(buf, ctypes.byref(size), False, af, TCP_TABLE_OWNER_PID_ALL, 0)
        if rc == 0:
            return buf
        if rc != ERROR_INSUFFICIENT_BUFFER:
            raise OSError(rc, f"GetExtendedTcpTable failed ({rc})")
    raise OSError(ERROR_INSUFFICIENT_BUFFER, "TCP table kept growing")


def tcp_rows() -> list[dict]:
    """Return LISTEN and ESTABLISHED TCP sockets with owning PIDs."""
    rows: list[dict] = []
    buf = _table(AF_INET)
    n = wintypes.DWORD.from_buffer(buf).value
    for r in (MIB_TCPROW_OWNER_PID * n).from_buffer(buf, ctypes.sizeof(wintypes.DWORD)):
        if r.dwState not in (MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_ESTAB):
            continue
        rows.append({
            "state": "listen" if r.dwState == MIB_TCP_STATE_LISTEN else "established",
            "laddr_ip": socket.inet_ntoa(struct.pack("<I", r.dwLocalAddr)),
            "laddr_port": _port(r.dwLocalPort),
            "raddr_ip": socket.inet_ntoa(struct.pack("<I", r.dwRemoteAddr)),
            "raddr_port": _port(r.dwRemotePort),
            "pid": r.dwOwningPid,
        })
    buf = _table(AF_INET6)
    n = wintypes.DWORD.from_buffer(buf).value
    for r in (MIB_TCP6ROW_OWNER_PID * n).from_buffer(buf, ctypes.sizeof(wintypes.DWORD)):
        if r.dwState not in (MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_ESTAB):
            continue
        rows.append({
            "state": "listen" if r.dwState == MIB_TCP_STATE_LISTEN else "established",
            "laddr_ip": socket.inet_ntop(socket.AF_INET6, bytes(r.ucLocalAddr)),
            "laddr_port": _port(r.dwLocalPort),
            "raddr_ip": socket.inet_ntop(socket.AF_INET6, bytes(r.ucRemoteAddr)),
            "raddr_port": _port(r.dwRemotePort),
            "pid": r.dwOwningPid,
        })
    return rows
