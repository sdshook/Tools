"""Write to the Windows Application event log (advapi32 RegisterEventSourceW / ReportEventW).

Source registration creates
  HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\<source>
with EventMessageFile pointing at the .NET Framework's EventLogMessages.dll, whose
messages are a plain "%1" pass-through. Event Viewer then shows our text cleanly. This
is the same file .NET's EventLog.CreateEventSource uses. Registration needs an elevated
process; without it, events are still written but Event Viewer prefixes them with
"The description for Event ID ... cannot be found".
"""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes

from . import IS_WINDOWS

EVENTLOG_ERROR_TYPE = 0x0001
EVENTLOG_WARNING_TYPE = 0x0002
EVENTLOG_INFORMATION_TYPE = 0x0004
_LEVEL = {"error": EVENTLOG_ERROR_TYPE, "warning": EVENTLOG_WARNING_TYPE, "info": EVENTLOG_INFORMATION_TYPE}
MAX_CHARS = 31_000  # ReportEvent strings are limited to 31,839 characters

_KEY = r"SYSTEM\CurrentControlSet\Services\EventLog\Application"

if IS_WINDOWS:
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _adv.RegisterEventSourceW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    _adv.RegisterEventSourceW.restype = wintypes.HANDLE
    _adv.DeregisterEventSource.argtypes = [wintypes.HANDLE]
    _adv.DeregisterEventSource.restype = wintypes.BOOL
    _adv.ReportEventW.argtypes = [wintypes.HANDLE, wintypes.WORD, wintypes.WORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.WORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPCWSTR), ctypes.c_void_p]
    _adv.ReportEventW.restype = wintypes.BOOL


def _message_file() -> str | None:
    windir = os.environ.get("SystemRoot", r"C:\Windows")
    for fw in ("Framework64", "Framework"):
        p = os.path.join(windir, "Microsoft.NET", fw, "v4.0.30319", "EventLogMessages.dll")
        if os.path.exists(p):
            return p
    return None


def register_source(source: str) -> tuple[bool, str]:
    """Create the event source registry key if missing. Returns (ok, message)."""
    if not IS_WINDOWS:
        return False, "not Windows"
    import winreg
    path = f"{_KEY}\\{source}"
    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path))
        return True, "already registered"
    except FileNotFoundError:
        pass
    mf = _message_file()
    if mf is None:
        return False, "EventLogMessages.dll not found; events will be written without a message file"
    try:
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_WRITE) as k:
            winreg.SetValueEx(k, "EventMessageFile", 0, winreg.REG_EXPAND_SZ, mf)
            winreg.SetValueEx(k, "TypesSupported", 0, winreg.REG_DWORD, 7)
        return True, "registered"
    except PermissionError:
        return False, "not registered (run elevated once to register)"


class EventLogWriter:
    def __init__(self, source: str):
        if not IS_WINDOWS:
            raise RuntimeError("Windows event log output requires Windows")
        self.h = _adv.RegisterEventSourceW(None, source)
        if not self.h:
            raise ctypes.WinError(ctypes.get_last_error())

    def write(self, event_id: int, level: str, message: str) -> bool:
        strings = (wintypes.LPCWSTR * 1)(message[:MAX_CHARS])
        return bool(_adv.ReportEventW(self.h, _LEVEL.get(level, EVENTLOG_INFORMATION_TYPE), 0, event_id,
                                      None, 1, 0, strings, None))

    def close(self) -> None:
        if self.h:
            _adv.DeregisterEventSource(self.h)
            self.h = None
