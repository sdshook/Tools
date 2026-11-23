"""Authenticode and catalog signature state via wintrust.dll.

Returns one of: embedded, catalog, unsigned, invalid, unknown.

- WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2) checks an embedded signature.
- Most in-box Windows binaries are catalog-signed rather than embedded-signed,
  so on TRUST_E_NOSIGNATURE we look the file hash up in the system catalogs with
  CryptCATAdminCalcHashFromFileHandle2 / CryptCATAdminEnumCatalogFromHash.
  POC limitation: finding the hash in a catalog is reported as "catalog" without
  a second WinVerifyTrust call against that catalog.
"""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes

from . import IS_WINDOWS

TRUST_E_NOSIGNATURE = 0x800B0100
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(0x00AAC56B, 0xCD44, 0x11D0,
                                         (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.POINTER(GUID))]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)), ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p)]


if IS_WINDOWS:
    _wt = ctypes.WinDLL("wintrust", use_last_error=True)
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _wt.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
    _wt.WinVerifyTrust.restype = wintypes.LONG
    _wt.CryptCATAdminAcquireContext2.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(GUID),
                                                 wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD]
    _wt.CryptCATAdminAcquireContext2.restype = wintypes.BOOL
    _wt.CryptCATAdminCalcHashFromFileHandle2.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
                                                         ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
                                                         wintypes.DWORD]
    _wt.CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL
    _wt.CryptCATAdminEnumCatalogFromHash.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                                     wintypes.DWORD, ctypes.c_void_p]
    _wt.CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE
    _wt.CryptCATAdminReleaseCatalogContext.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
    _wt.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL
    _wt.CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _wt.CryptCATAdminReleaseContext.restype = wintypes.BOOL
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                 wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]


def _embedded(path: str) -> int:
    fi = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
    wd = WINTRUST_DATA()
    wd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    wd.dwUIChoice = WTD_UI_NONE
    wd.fdwRevocationChecks = WTD_REVOKE_NONE
    wd.dwUnionChoice = WTD_CHOICE_FILE
    wd.pFile = ctypes.pointer(fi)
    wd.dwStateAction = WTD_STATEACTION_VERIFY
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
    action = GUID.from_buffer_copy(WINTRUST_ACTION_GENERIC_VERIFY_V2)
    rc = _wt.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(wd)) & 0xFFFFFFFF
    wd.dwStateAction = WTD_STATEACTION_CLOSE
    _wt.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(wd))
    return rc


def _in_catalog(path: str) -> bool:
    hfile = _k32.CreateFileW(path, GENERIC_READ, 7, None, OPEN_EXISTING, 0, None)
    if not hfile or hfile == INVALID_HANDLE_VALUE:
        return False
    try:
        for alg in ("SHA256", None):  # modern catalogs, then legacy SHA1
            admin = wintypes.HANDLE()
            if not _wt.CryptCATAdminAcquireContext2(ctypes.byref(admin), None, alg, None, 0):
                continue
            try:
                n = wintypes.DWORD(0)
                _wt.CryptCATAdminCalcHashFromFileHandle2(admin, hfile, ctypes.byref(n), None, 0)
                if not n.value:
                    continue
                h = (ctypes.c_ubyte * n.value)()
                if not _wt.CryptCATAdminCalcHashFromFileHandle2(admin, hfile, ctypes.byref(n), h, 0):
                    continue
                cat = _wt.CryptCATAdminEnumCatalogFromHash(admin, h, n, 0, None)
                if cat:
                    _wt.CryptCATAdminReleaseCatalogContext(admin, cat, 0)
                    return True
            finally:
                _wt.CryptCATAdminReleaseContext(admin, 0)
        return False
    finally:
        _k32.CloseHandle(hfile)


_cache: dict[tuple, str] = {}


def signature_state(path: str) -> str:
    if not IS_WINDOWS or not path:
        return "unknown"
    try:
        st = os.stat(path)
    except OSError:
        return "unknown"
    key = (path.lower(), st.st_size, st.st_mtime_ns)
    hit = _cache.get(key)
    if hit:
        return hit
    try:
        rc = _embedded(path)
        if rc == 0:
            state = "embedded"
        elif rc == TRUST_E_NOSIGNATURE:
            state = "catalog" if _in_catalog(path) else "unsigned"
        else:
            state = "invalid"
    except OSError:
        state = "unknown"
    if len(_cache) > 8192:
        _cache.clear()
    _cache[key] = state
    return state
