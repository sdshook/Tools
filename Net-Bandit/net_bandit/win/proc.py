"""Process information via kernel32, advapi32 and ntdll.

- CreateToolhelp32Snapshot / Process32FirstW / Process32NextW : process list
- OpenProcess + QueryFullProcessImageNameW                   : image path
- NtQueryInformationProcess(ProcessCommandLineInformation)     : command line
- OpenProcessToken + GetTokenInformation + LookupAccountSidW   : user
"""
from __future__ import annotations

import ctypes
import time
from ctypes import wintypes

from . import IS_WINDOWS

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TokenUser = 1
ProcessCommandLineInformation = 60
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT),
                ("Buffer", ctypes.c_void_p)]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


if IS_WINDOWS:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    nt = ctypes.WinDLL("ntdll")

    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k32.Process32FirstW.restype = wintypes.BOOL
    k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k32.Process32NextW.restype = wintypes.BOOL
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                               ctypes.POINTER(wintypes.DWORD)]
    k32.QueryFullProcessImageNameW.restype = wintypes.BOOL

    nt.NtQueryInformationProcess.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                             wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)]
    nt.NtQueryInformationProcess.restype = ctypes.c_long

    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.OpenProcessToken.restype = wintypes.BOOL
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    adv.GetTokenInformation.restype = wintypes.BOOL
    adv.LookupAccountSidW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR,
                                      ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR,
                                      ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    adv.LookupAccountSidW.restype = wintypes.BOOL


def snapshot() -> list[tuple[int, int, str]]:
    """Return (pid, ppid, exe_name) for every running process."""
    h = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not h or h == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    out = []
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k32.Process32FirstW(h, ctypes.byref(pe))
        while ok:
            out.append((pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile))
            ok = k32.Process32NextW(h, ctypes.byref(pe))
    finally:
        k32.CloseHandle(h)
    return out


def _open(pid: int):
    return k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)


def image_path(pid: int) -> str:
    h = _open(pid)
    if not h:
        return ""
    try:
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return buf.value
        return ""
    finally:
        k32.CloseHandle(h)


def command_line(pid: int) -> str:
    """Command line via NtQueryInformationProcess (Windows 8.1+)."""
    h = _open(pid)
    if not h:
        return ""
    try:
        need = wintypes.ULONG(0)
        nt.NtQueryInformationProcess(h, ProcessCommandLineInformation, None, 0, ctypes.byref(need))
        if need.value == 0:
            return ""
        buf = ctypes.create_string_buffer(need.value)
        status = nt.NtQueryInformationProcess(h, ProcessCommandLineInformation, buf, need, ctypes.byref(need))
        if status != 0:
            return ""
        us = UNICODE_STRING.from_buffer(buf)
        if not us.Buffer or not us.Length:
            return ""
        return ctypes.wstring_at(us.Buffer, us.Length // 2)
    finally:
        k32.CloseHandle(h)


def process_user(pid: int) -> str:
    h = _open(pid)
    if not h:
        return ""
    tok = wintypes.HANDLE()
    try:
        if not adv.OpenProcessToken(h, TOKEN_QUERY, ctypes.byref(tok)):
            return ""
        try:
            need = wintypes.DWORD(0)
            adv.GetTokenInformation(tok, TokenUser, None, 0, ctypes.byref(need))
            if not need.value:
                return ""
            buf = ctypes.create_string_buffer(need.value)
            if not adv.GetTokenInformation(tok, TokenUser, buf, need, ctypes.byref(need)):
                return ""
            sid = SID_AND_ATTRIBUTES.from_buffer(buf).Sid
            name = ctypes.create_unicode_buffer(256)
            dom = ctypes.create_unicode_buffer(256)
            cn, cd, use = wintypes.DWORD(256), wintypes.DWORD(256), wintypes.DWORD()
            if not adv.LookupAccountSidW(None, sid, name, ctypes.byref(cn), dom, ctypes.byref(cd),
                                         ctypes.byref(use)):
                return ""
            return f"{dom.value}\\{name.value}" if dom.value else name.value
        finally:
            k32.CloseHandle(tok)
    finally:
        k32.CloseHandle(h)


class NameCache:
    """pid -> image path, refreshed lazily (pids are reused, so entries expire)."""

    def __init__(self, ttl: float = 60.0):
        self.ttl = ttl
        self._c: dict[int, tuple[float, str]] = {}

    def get(self, pid: int) -> str:
        if pid in (0, 4):
            return "System"
        now = time.time()
        hit = self._c.get(pid)
        if hit and now - hit[0] < self.ttl:
            return hit[1]
        path = image_path(pid)
        self._c[pid] = (now, path)
        if len(self._c) > 4096:
            self._c.clear()
        return path
