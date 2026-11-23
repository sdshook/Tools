"""Write to the Windows Security event log via authz.dll (third-party security audit sources).

Requirements, all checked by `net-bandit doctor`:
  1. SeAuditPrivilege ("Generate security audits"): held by LocalSystem, LocalService and
     NetworkService. Run net-bandit as SYSTEM (service or scheduled task), or grant the
     right to its account (secpol.msc > Local Policies > User Rights Assignment).
  2. The source is registered once with AuthzInstallSecurityEventSource (elevated).
  3. The "Application Generated" audit subcategory is enabled, otherwise Windows drops
     the events silently:  auditpol /set /subcategory:"Application Generated" /success:enable

APIs: AuthzInstallSecurityEventSource, AuthzRegisterSecurityEventSource,
AuthzReportSecurityEvent, AuthzUnregisterSecurityEventSource (authz.dll);
OpenProcessToken, LookupPrivilegeValueW, AdjustTokenPrivileges, AuditQuerySystemPolicy (advapi32).

AuthzReportSecurityEvent is variadic: each parameter is passed as (APT_String, PCWSTR).
That is safe through ctypes on 64-bit Windows, which net-bandit requires.
"""
from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes

from . import IS_WINDOWS

APF_AuditSuccess = 0x1
APT_String = 2
AUTHZ_ALLOW_MULTIPLE_SOURCE_INSTANCES = 0x1
ERROR_ALREADY_EXISTS = 183
ERROR_OBJECT_ALREADY_EXISTS = 5010
ERROR_NOT_ALL_ASSIGNED = 1300
ERROR_PRIVILEGE_NOT_HELD = 1314
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x2
POLICY_AUDIT_EVENT_SUCCESS = 0x1
MAX_CHARS = 31_000

_SEC_KEY = r"SYSTEM\CurrentControlSet\Services\EventLog\Security"


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


# Object Access > Application Generated
APPLICATION_GENERATED = GUID(0x0CCE9222, 0x69AE, 0x11D9,
                             (ctypes.c_ubyte * 8)(0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30))


class AUTHZ_REGISTRATION_OBJECT_TYPE_NAME_OFFSET(ctypes.Structure):
    _fields_ = [("szObjectTypeName", wintypes.LPWSTR), ("dwOffset", wintypes.DWORD)]


class AUTHZ_SOURCE_SCHEMA_REGISTRATION(ctypes.Structure):
    _fields_ = [("dwFlags", wintypes.DWORD), ("szEventSourceName", wintypes.LPWSTR),
                ("szEventMessageFile", wintypes.LPWSTR), ("szEventSourceXmlSchemaFile", wintypes.LPWSTR),
                ("szEventAccessStringsFile", wintypes.LPWSTR), ("szExecutableImagePath", wintypes.LPWSTR),
                ("pReserved", ctypes.c_void_p), ("dwObjectTypeNameCount", wintypes.DWORD),
                ("ObjectTypeNames", AUTHZ_REGISTRATION_OBJECT_TYPE_NAME_OFFSET * 1)]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


class AUDIT_POLICY_INFORMATION(ctypes.Structure):
    _fields_ = [("AuditSubCategoryGuid", GUID), ("AuditingInformation", wintypes.ULONG),
                ("AuditCategoryGuid", GUID)]


if IS_WINDOWS:
    _authz = ctypes.WinDLL("authz", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _authz.AuthzInstallSecurityEventSource.argtypes = [wintypes.DWORD, ctypes.POINTER(AUTHZ_SOURCE_SCHEMA_REGISTRATION)]
    _authz.AuthzInstallSecurityEventSource.restype = wintypes.BOOL
    _authz.AuthzRegisterSecurityEventSource.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, ctypes.POINTER(wintypes.HANDLE)]
    _authz.AuthzRegisterSecurityEventSource.restype = wintypes.BOOL
    _authz.AuthzUnregisterSecurityEventSource.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    _authz.AuthzUnregisterSecurityEventSource.restype = wintypes.BOOL
    _authz.AuthzReportSecurityEvent.restype = wintypes.BOOL  # variadic: no argtypes
    _k32.GetCurrentProcess.restype = wintypes.HANDLE
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    _adv.OpenProcessToken.restype = wintypes.BOOL
    _adv.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
    _adv.LookupPrivilegeValueW.restype = wintypes.BOOL
    _adv.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
                                           wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
    _adv.AdjustTokenPrivileges.restype = wintypes.BOOL
    _adv.AuditQuerySystemPolicy.argtypes = [ctypes.POINTER(GUID), wintypes.ULONG,
                                            ctypes.POINTER(ctypes.POINTER(AUDIT_POLICY_INFORMATION))]
    _adv.AuditQuerySystemPolicy.restype = wintypes.BOOL
    _adv.AuditFree.argtypes = [ctypes.c_void_p]


def enable_audit_privilege() -> tuple[bool, str]:
    """Enable SeAuditPrivilege in our token. Fails if the account does not hold it."""
    tok = wintypes.HANDLE()
    if not _adv.OpenProcessToken(_k32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(tok)):
        return False, f"OpenProcessToken failed ({ctypes.get_last_error()})"
    try:
        luid = LUID()
        if not _adv.LookupPrivilegeValueW(None, "SeAuditPrivilege", ctypes.byref(luid)):
            return False, f"LookupPrivilegeValue failed ({ctypes.get_last_error()})"
        tp = TOKEN_PRIVILEGES(1, (LUID_AND_ATTRIBUTES * 1)(LUID_AND_ATTRIBUTES(luid, SE_PRIVILEGE_ENABLED)))
        ok = _adv.AdjustTokenPrivileges(tok, False, ctypes.byref(tp), 0, None, None)
        err = ctypes.get_last_error()
        if not ok or err == ERROR_NOT_ALL_ASSIGNED:
            return False, ("this account does not hold 'Generate security audits' (SeAuditPrivilege); "
                           "run net-bandit as SYSTEM or grant the right")
        return True, "SeAuditPrivilege enabled"
    finally:
        _k32.CloseHandle(tok)


def application_generated_auditing() -> bool | None:
    """True if success auditing is on for Object Access > Application Generated; None if unknown."""
    if not IS_WINDOWS:
        return None
    out = ctypes.POINTER(AUDIT_POLICY_INFORMATION)()
    guid = GUID.from_buffer_copy(APPLICATION_GENERATED)
    if not _adv.AuditQuerySystemPolicy(ctypes.byref(guid), 1, ctypes.byref(out)):
        return None
    try:
        return bool(out[0].AuditingInformation & POLICY_AUDIT_EVENT_SUCCESS)
    finally:
        _adv.AuditFree(out)


def _message_file() -> str | None:
    windir = os.environ.get("SystemRoot", r"C:\Windows")
    for fw in ("Framework64", "Framework"):
        p = os.path.join(windir, "Microsoft.NET", fw, "v4.0.30319", "EventLogMessages.dll")
        if os.path.exists(p):
            return p
    return None


def install_source(source: str) -> tuple[bool, str]:
    """Register `source` as a Security log event source (once, elevated)."""
    import winreg
    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{_SEC_KEY}\\{source}"))
        return True, "already installed"
    except FileNotFoundError:
        pass
    except PermissionError:
        pass  # the Security key may be unreadable; let the install call decide
    reg = AUTHZ_SOURCE_SCHEMA_REGISTRATION()
    reg.dwFlags = AUTHZ_ALLOW_MULTIPLE_SOURCE_INSTANCES
    reg.szEventSourceName = source
    reg.szEventMessageFile = _message_file()  # .NET's "%1" pass-through messages
    reg.dwObjectTypeNameCount = 0
    if _authz.AuthzInstallSecurityEventSource(0, ctypes.byref(reg)):
        return True, "installed"
    err = ctypes.get_last_error()
    if err in (ERROR_ALREADY_EXISTS, ERROR_OBJECT_ALREADY_EXISTS):
        return True, "already installed"
    return False, f"AuthzInstallSecurityEventSource failed ({err}); run elevated once"


class SecurityLogWriter:
    def __init__(self, source: str, install: bool = True, log=print):
        if not IS_WINDOWS:
            raise RuntimeError("Security log output requires Windows")
        if sys.maxsize <= 2**32:
            raise RuntimeError("Security log output requires 64-bit Python")
        ok, msg = enable_audit_privilege()
        if not ok:
            raise PermissionError(msg)
        if install:
            ok, msg = install_source(source)
            log(f"[i] Security log source '{source}': {msg}")
        if application_generated_auditing() is False:
            log("[!] 'Application Generated' auditing is OFF, so Windows will drop these events. Enable it with:\n"
                '    auditpol /set /subcategory:"Application Generated" /success:enable')
        self.h = wintypes.HANDLE()
        if not _authz.AuthzRegisterSecurityEventSource(0, source, ctypes.byref(self.h)):
            err = ctypes.get_last_error()
            raise OSError(err, f"AuthzRegisterSecurityEventSource failed ({err})")

    def write(self, audit_id: int, params: list[str]) -> bool:
        args = []
        for p in params:
            args += [wintypes.DWORD(APT_String), ctypes.c_wchar_p(str(p)[:MAX_CHARS])]
        ok = _authz.AuthzReportSecurityEvent(wintypes.DWORD(APF_AuditSuccess), ctypes.c_void_p(self.h.value),
                                             wintypes.DWORD(audit_id), ctypes.c_void_p(None),
                                             wintypes.DWORD(len(params)), *args)
        return bool(ok)

    def close(self) -> None:
        if self.h:
            _authz.AuthzUnregisterSecurityEventSource(0, ctypes.byref(self.h))
            self.h = None
