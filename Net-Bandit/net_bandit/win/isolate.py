"""Launch the entry worker in a Windows sandbox (kernel32, advapi32, userenv).

Modes, strongest first:
  appcontainer  CreateAppContainerProfile + PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES with
                no capabilities: no network (including loopback), no access to files
                unless explicitly granted. We grant read+execute on the Python install
                and the net_bandit package only.
  restricted    CreateRestrictedToken(DISABLE_MAX_PRIVILEGE) with restricting SIDs
                (Everyone, Users, Authenticated Users, RESTRICTED) and Low integrity: no
                privileges, no writes to normal objects, and reads limited to what
                ordinary users can read. Network is NOT blocked in this mode, so keep
                the API key and data directory readable by SYSTEM/Administrators only
                (harden_paths does this).
Both modes also use:
  - a job object: kill-on-close, one active process, memory cap, die on unhandled exception
  - PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY: the worker cannot create child processes
  - a minimal environment (no API key, no PATH)
  - stdin/stdout anonymous pipes passed with PROC_THREAD_ATTRIBUTE_HANDLE_LIST
"""
from __future__ import annotations

import ctypes
import msvcrt
import os
import subprocess
from ctypes import wintypes

from .resource import (JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation)

EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
STARTF_USESTDHANDLES = 0x00000100
HANDLE_FLAG_INHERIT = 0x1
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY = 0x0002000E
PROCESS_CREATION_CHILD_PROCESS_RESTRICTED = 0x01
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_ADJUST_DEFAULT = 0x1, 0x2, 0x8, 0x80
DISABLE_MAX_PRIVILEGE = 0x1
TokenIntegrityLevel = 25
SE_GROUP_INTEGRITY = 0x20
GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
OPEN_EXISTING = 3
WAIT_TIMEOUT = 0x102
HRESULT_ALREADY_EXISTS = 0x800700B7
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

APPCONTAINER_NAME = "net-bandit.entry-worker"
RESTRICTING_SIDS = ("S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-12")  # Everyone, Users, AuthUsers, RESTRICTED
LOW_INTEGRITY_SID = "S-1-16-4096"


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [("AppContainerSid", ctypes.c_void_p), ("Capabilities", ctypes.c_void_p),
                ("CapabilityCount", wintypes.DWORD), ("Reserved", wintypes.DWORD)]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", SID_AND_ATTRIBUTES)]


_k = ctypes.WinDLL("kernel32", use_last_error=True)
_a = ctypes.WinDLL("advapi32", use_last_error=True)
_u = ctypes.WinDLL("userenv", use_last_error=True)

_k.CreatePipe.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE),
                          ctypes.POINTER(SECURITY_ATTRIBUTES), wintypes.DWORD]
_k.CreatePipe.restype = wintypes.BOOL
_k.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
_k.SetHandleInformation.restype = wintypes.BOOL
_k.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                                 ctypes.POINTER(ctypes.c_size_t)]
_k.InitializeProcThreadAttributeList.restype = wintypes.BOOL
_k.UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p,
                                         ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
_k.UpdateProcThreadAttribute.restype = wintypes.BOOL
_k.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
_k.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
                              wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p,
                              ctypes.POINTER(PROCESS_INFORMATION)]
_k.CreateProcessW.restype = wintypes.BOOL
_k.ResumeThread.argtypes = [wintypes.HANDLE]
_k.ResumeThread.restype = wintypes.DWORD
_k.CloseHandle.argtypes = [wintypes.HANDLE]
_k.CloseHandle.restype = wintypes.BOOL
_k.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
_k.CreateJobObjectW.restype = wintypes.HANDLE
_k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
_k.SetInformationJobObject.restype = wintypes.BOOL
_k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
_k.AssignProcessToJobObject.restype = wintypes.BOOL
_k.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
_k.TerminateJobObject.restype = wintypes.BOOL
_k.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
_k.TerminateProcess.restype = wintypes.BOOL
_k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
_k.WaitForSingleObject.restype = wintypes.DWORD
_k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                           wintypes.DWORD, wintypes.HANDLE]
_k.CreateFileW.restype = wintypes.HANDLE
_k.GetCurrentProcess.restype = wintypes.HANDLE
_k.LocalFree.argtypes = [ctypes.c_void_p]
_a.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
_a.OpenProcessToken.restype = wintypes.BOOL
_a.CreateRestrictedToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                     wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                     ctypes.POINTER(wintypes.HANDLE)]
_a.CreateRestrictedToken.restype = wintypes.BOOL
_a.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
_a.SetTokenInformation.restype = wintypes.BOOL
_a.CreateProcessAsUserW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
                                    ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p,
                                    wintypes.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(PROCESS_INFORMATION)]
_a.CreateProcessAsUserW.restype = wintypes.BOOL
_a.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
_a.ConvertStringSidToSidW.restype = wintypes.BOOL
_a.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
_a.ConvertSidToStringSidW.restype = wintypes.BOOL
_a.GetLengthSid.argtypes = [ctypes.c_void_p]
_a.GetLengthSid.restype = wintypes.DWORD
_a.FreeSid.argtypes = [ctypes.c_void_p]
_u.CreateAppContainerProfile.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
_u.CreateAppContainerProfile.restype = ctypes.c_long
_u.DeriveAppContainerSidFromAppContainerName.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
_u.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long


def _err(what: str) -> OSError:
    e = ctypes.get_last_error()
    return OSError(e, f"{what} failed (error {e})")


def _sid_string(psid) -> str:
    out = wintypes.LPWSTR()
    if not _a.ConvertSidToStringSidW(psid, ctypes.byref(out)):
        raise _err("ConvertSidToStringSid")
    try:
        return out.value
    finally:
        _k.LocalFree(out)


def _sid(s: str):
    p = ctypes.c_void_p()
    if not _a.ConvertStringSidToSidW(s, ctypes.byref(p)):
        raise _err(f"ConvertStringSidToSid({s})")
    return p  # LocalFree when done


def appcontainer_sid():
    psid = ctypes.c_void_p()
    hr = _u.CreateAppContainerProfile(APPCONTAINER_NAME, "net-bandit entry worker",
                                      "Runs model-written detection checks with no network access",
                                      None, 0, ctypes.byref(psid))
    if hr & 0xFFFFFFFF == HRESULT_ALREADY_EXISTS:
        hr = _u.DeriveAppContainerSidFromAppContainerName(APPCONTAINER_NAME, ctypes.byref(psid))
    if hr != 0:
        raise OSError(hr, f"AppContainer profile failed (HRESULT 0x{hr & 0xFFFFFFFF:08X})")
    return psid  # FreeSid when done


def grant_read(sid_string: str, paths: list[str]) -> None:
    """Give the AppContainer read+execute on the folders the worker must load code from."""
    for p in paths:
        r = subprocess.run(["icacls", p, "/grant", f"*{sid_string}:(OI)(CI)RX", "/Q"],
                           capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        if r.returncode != 0:
            raise OSError(r.returncode, f"icacls grant on {p} failed: {r.stdout.strip() or r.stderr.strip()}")


def harden_paths(paths: list[str]) -> list[str]:
    """Limit data dir / key files to SYSTEM and Administrators (call only when running as SYSTEM)."""
    msgs = []
    for p in paths:
        if not p or not os.path.exists(p):
            continue
        args = ["icacls", p, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/Q"]
        if os.path.isfile(p):
            args = ["icacls", p, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", "/Q"]
        r = subprocess.run(args, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        msgs.append(f"{p}: {'restricted to SYSTEM and Administrators' if r.returncode == 0 else 'icacls failed'}")
    return msgs


def _restricted_low_token():
    me = wintypes.HANDLE()
    if not _a.OpenProcessToken(_k.GetCurrentProcess(),
                               TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
                               ctypes.byref(me)):
        raise _err("OpenProcessToken")
    sids = [_sid(s) for s in RESTRICTING_SIDS]
    try:
        arr = (SID_AND_ATTRIBUTES * len(sids))(*[SID_AND_ATTRIBUTES(s.value, 0) for s in sids])
        new = wintypes.HANDLE()
        if not _a.CreateRestrictedToken(me, DISABLE_MAX_PRIVILEGE, 0, None, 0, None, len(sids), arr,
                                        ctypes.byref(new)):
            raise _err("CreateRestrictedToken")
        low = _sid(LOW_INTEGRITY_SID)
        try:
            tml = TOKEN_MANDATORY_LABEL(SID_AND_ATTRIBUTES(low.value, SE_GROUP_INTEGRITY))
            if not _a.SetTokenInformation(new, TokenIntegrityLevel, ctypes.byref(tml),
                                          ctypes.sizeof(tml) + _a.GetLengthSid(low)):
                raise _err("SetTokenInformation(integrity)")
        finally:
            _k.LocalFree(low)
        return new
    finally:
        for s in sids:
            _k.LocalFree(s)
        _k.CloseHandle(me)


def _job(mem_mb: int):
    job = _k.CreateJobObjectW(None, None)
    if not job:
        raise _err("CreateJobObject")
    ext = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    ext.BasicLimitInformation.LimitFlags = (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                                            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
                                            | JOB_OBJECT_LIMIT_PROCESS_MEMORY)
    ext.BasicLimitInformation.ActiveProcessLimit = 1
    ext.ProcessMemoryLimit = mem_mb * 1024 * 1024
    if not _k.SetInformationJobObject(job, JobObjectExtendedLimitInformation, ctypes.byref(ext), ctypes.sizeof(ext)):
        _k.CloseHandle(job)
        raise _err("SetInformationJobObject")
    return job


class WinWorker:
    """A sandboxed worker process with binary stdin/stdout file objects."""

    def __init__(self, mode: str, exe: str, args: list[str], grant_paths: list[str], mem_mb: int = 256):
        self.mode = mode
        sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
        in_r, in_w, out_r, out_w = (wintypes.HANDLE() for _ in range(4))
        if not _k.CreatePipe(ctypes.byref(in_r), ctypes.byref(in_w), ctypes.byref(sa), 0):
            raise _err("CreatePipe(stdin)")
        if not _k.CreatePipe(ctypes.byref(out_r), ctypes.byref(out_w), ctypes.byref(sa), 0):
            raise _err("CreatePipe(stdout)")
        _k.SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0)   # parent ends stay private
        _k.SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0)
        nul = _k.CreateFileW("NUL", GENERIC_READ | GENERIC_WRITE, 3, ctypes.byref(sa), OPEN_EXISTING, 0, None)

        handles = (wintypes.HANDLE * 3)(in_r, out_w, nul)
        child_policy = wintypes.DWORD(PROCESS_CREATION_CHILD_PROCESS_RESTRICTED)
        n_attrs = 3 if mode == "appcontainer" else 2
        size = ctypes.c_size_t(0)
        _k.InitializeProcThreadAttributeList(None, n_attrs, 0, ctypes.byref(size))
        attr_buf = ctypes.create_string_buffer(size.value)
        if not _k.InitializeProcThreadAttributeList(attr_buf, n_attrs, 0, ctypes.byref(size)):
            raise _err("InitializeProcThreadAttributeList")
        psid = token = None
        caps = None
        try:
            if not _k.UpdateProcThreadAttribute(attr_buf, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles,
                                                ctypes.sizeof(handles), None, None):
                raise _err("UpdateProcThreadAttribute(handles)")
            if not _k.UpdateProcThreadAttribute(attr_buf, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                                                ctypes.byref(child_policy), ctypes.sizeof(child_policy),
                                                None, None):
                raise _err("UpdateProcThreadAttribute(child policy)")
            if mode == "appcontainer":
                psid = appcontainer_sid()
                grant_read(_sid_string(psid), grant_paths)
                caps = SECURITY_CAPABILITIES(psid.value, None, 0, 0)
                if not _k.UpdateProcThreadAttribute(attr_buf, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                                    ctypes.byref(caps), ctypes.sizeof(caps), None, None):
                    raise _err("UpdateProcThreadAttribute(security capabilities)")
            elif mode == "restricted":
                token = _restricted_low_token()
            else:
                raise ValueError(f"unknown isolation mode {mode}")

            si = STARTUPINFOEXW()
            si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES
            si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput, si.StartupInfo.hStdError = in_r, out_w, nul
            si.lpAttributeList = ctypes.cast(attr_buf, ctypes.c_void_p)
            sysroot = os.environ.get("SystemRoot", r"C:\Windows")
            env_chars = f"SYSTEMROOT={sysroot}\0\0"  # double-NUL-terminated environment block
            env = (ctypes.c_wchar * len(env_chars))(*env_chars)
            cmd = ctypes.create_unicode_buffer(subprocess.list2cmdline([exe] + args))
            flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT
            pi = PROCESS_INFORMATION()
            cwd = os.path.dirname(exe)
            if token is not None:
                ok = _a.CreateProcessAsUserW(token, exe, cmd, None, None, True, flags, env, cwd,
                                             ctypes.byref(si), ctypes.byref(pi))
            else:
                ok = _k.CreateProcessW(exe, cmd, None, None, True, flags, env, cwd, ctypes.byref(si),
                                       ctypes.byref(pi))
            if not ok:
                raise _err(f"CreateProcess ({mode})")
        finally:
            _k.DeleteProcThreadAttributeList(attr_buf)
            if psid is not None:
                _a.FreeSid(psid)
            if token is not None:
                _k.CloseHandle(token)
            for h in (in_r, out_w, nul):  # the child holds its own copies now
                _k.CloseHandle(h)

        try:
            self.job = _job(mem_mb)
            if not _k.AssignProcessToJobObject(self.job, pi.hProcess):
                raise _err("AssignProcessToJobObject")
        except OSError:
            _k.TerminateProcess(pi.hProcess, 1)
            _k.CloseHandle(pi.hThread)
            _k.CloseHandle(pi.hProcess)
            raise
        _k.ResumeThread(pi.hThread)
        _k.CloseHandle(pi.hThread)
        self.hprocess = pi.hProcess
        self.pid = pi.dwProcessId
        self.stdin = os.fdopen(msvcrt.open_osfhandle(in_w.value, os.O_WRONLY), "wb", 0)
        self.stdout = os.fdopen(msvcrt.open_osfhandle(out_r.value, os.O_RDONLY), "rb", 0)

    def alive(self) -> bool:
        return bool(self.hprocess) and _k.WaitForSingleObject(self.hprocess, 0) == WAIT_TIMEOUT

    def kill(self) -> None:
        if getattr(self, "job", None):
            _k.TerminateJobObject(self.job, 1)
            _k.CloseHandle(self.job)
            self.job = None
        for f in (getattr(self, "stdin", None), getattr(self, "stdout", None)):
            try:
                f and f.close()
            except OSError:
                pass
        if getattr(self, "hprocess", None):
            _k.CloseHandle(self.hprocess)
            self.hprocess = None
