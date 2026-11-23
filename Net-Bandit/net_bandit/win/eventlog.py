"""Live Windows Event Log subscriptions via wevtapi.dll (pull model).

EvtSubscribe(..., EvtSubscribeToFutureEvents) with a signal event, then EvtNext
until ERROR_NO_MORE_ITEMS, rendering each event to XML with EvtRender.
"""
from __future__ import annotations

import ctypes
import xml.etree.ElementTree as ET
from ctypes import wintypes

from . import IS_WINDOWS

EvtSubscribeToFutureEvents = 1
EvtRenderEventXml = 1
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NO_MORE_ITEMS = 259
ERROR_TIMEOUT = 1460
ERROR_INVALID_OPERATION = 4317
ERROR_EVT_CHANNEL_NOT_FOUND = 15007

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

if IS_WINDOWS:
    _w = ctypes.WinDLL("wevtapi", use_last_error=True)
    _k = ctypes.WinDLL("kernel32", use_last_error=True)
    _w.EvtSubscribe.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
    _w.EvtSubscribe.restype = wintypes.HANDLE
    _w.EvtNext.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    _w.EvtNext.restype = wintypes.BOOL
    _w.EvtRender.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                             ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    _w.EvtRender.restype = wintypes.BOOL
    _w.EvtClose.argtypes = [wintypes.HANDLE]
    _w.EvtClose.restype = wintypes.BOOL
    _k.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    _k.CreateEventW.restype = wintypes.HANDLE
    _k.ResetEvent.argtypes = [wintypes.HANDLE]
    _k.ResetEvent.restype = wintypes.BOOL
    _k.CloseHandle.argtypes = [wintypes.HANDLE]


def _render_xml(h) -> str:
    used, props = wintypes.DWORD(0), wintypes.DWORD(0)
    _w.EvtRender(None, h, EvtRenderEventXml, 0, None, ctypes.byref(used), ctypes.byref(props))
    err = ctypes.get_last_error()
    if err != ERROR_INSUFFICIENT_BUFFER:
        raise ctypes.WinError(err)
    buf = ctypes.create_unicode_buffer(used.value // 2 + 1)
    if not _w.EvtRender(None, h, EvtRenderEventXml, ctypes.sizeof(buf), buf, ctypes.byref(used),
                        ctypes.byref(props)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buf.value


class Subscription:
    def __init__(self, channel: str, query: str):
        self.channel = channel
        self.signal = _k.CreateEventW(None, True, True, None)
        self.handle = _w.EvtSubscribe(None, self.signal, channel, query, None, None, None,
                                      EvtSubscribeToFutureEvents)
        if not self.handle:
            err = ctypes.get_last_error()
            _k.CloseHandle(self.signal)
            raise OSError(err, f"EvtSubscribe({channel}) failed with error {err}")

    def read(self, batch: int = 64) -> list[str]:
        out: list[str] = []
        arr = (wintypes.HANDLE * batch)()
        got = wintypes.DWORD(0)
        while True:
            if not _w.EvtNext(self.handle, batch, arr, 0, 0, ctypes.byref(got)):
                err = ctypes.get_last_error()
                if err in (ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT, ERROR_INVALID_OPERATION):
                    break
                raise ctypes.WinError(err)
            for i in range(got.value):
                try:
                    out.append(_render_xml(arr[i]))
                except OSError:
                    pass
                finally:
                    _w.EvtClose(arr[i])
        _k.ResetEvent(self.signal)
        return out

    def close(self) -> None:
        if self.handle:
            _w.EvtClose(self.handle)
            self.handle = None
        if self.signal:
            _k.CloseHandle(self.signal)
            self.signal = None


def parse_event_xml(xml: str) -> dict:
    """Flatten an event's XML into {channel, provider, event_id, computer, time, data}."""
    root = ET.fromstring(xml)
    sys_ = root.find("e:System", NS)
    out = {
        "channel": sys_.findtext("e:Channel", default="", namespaces=NS),
        "provider": (sys_.find("e:Provider", NS).get("Name") if sys_.find("e:Provider", NS) is not None else ""),
        "event_id": int(sys_.findtext("e:EventID", default="0", namespaces=NS) or 0),
        "computer": sys_.findtext("e:Computer", default="", namespaces=NS),
        "time": (sys_.find("e:TimeCreated", NS).get("SystemTime") if sys_.find("e:TimeCreated", NS) is not None else ""),
        "data": {},
    }
    ed = root.find("e:EventData", NS)
    if ed is not None:
        for i, d in enumerate(ed.findall("e:Data", NS)):
            out["data"][d.get("Name") or f"Data{i}"] = d.text or ""
    ud = root.find("e:UserData", NS)
    if ud is not None:
        for el in ud.iter():
            if len(el) == 0 and el.text and el.text.strip():
                out["data"][el.tag.split("}")[-1]] = el.text.strip()
    return out
