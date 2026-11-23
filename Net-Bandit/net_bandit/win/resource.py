"""Keep the agent from competing with the OS and foreground apps (kernel32 / psapi).

Applied once at startup, each step optional and independent:
  background mode   SetPriorityClass(PROCESS_MODE_BACKGROUND_BEGIN): low CPU, I/O and memory priority
  memory priority   SetProcessInformation(ProcessMemoryPriority): our pages are trimmed first
  EcoQoS            SetProcessInformation(ProcessPowerThrottling): on hybrid CPUs, prefer efficiency cores
  affinity          SetProcessAffinityMask: confine the agent to chosen logical CPUs
  job object        hard CPU-rate cap and process memory ceiling
  working set cap   SetProcessWorkingSetSizeEx with a hard maximum
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes

from . import IS_WINDOWS

PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
ProcessMemoryPriority = 0
ProcessPowerThrottling = 4
MEMORY_PRIORITY_LOW = 2
PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 0x1
JobObjectExtendedLimitInformation = 9
JobObjectCpuRateControlInformation = 15
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x1
JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x4
QUOTA_LIMITS_HARDWS_MIN_DISABLE = 0x2
QUOTA_LIMITS_HARDWS_MAX_ENABLE = 0x4


class MEMORY_PRIORITY_INFORMATION(ctypes.Structure):
    _fields_ = [("MemoryPriority", wintypes.ULONG)]


class PROCESS_POWER_THROTTLING_STATE(ctypes.Structure):
    _fields_ = [("Version", wintypes.ULONG), ("ControlMask", wintypes.ULONG), ("StateMask", wintypes.ULONG)]


class JOBOBJECT_CPU_RATE_CONTROL_INFORMATION(ctypes.Structure):
    _fields_ = [("ControlFlags", wintypes.DWORD), ("CpuRate", wintypes.DWORD)]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in ("ReadOperationCount", "WriteOperationCount",
                                                   "OtherOperationCount", "ReadTransferCount",
                                                   "WriteTransferCount", "OtherTransferCount")]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD)]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION), ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]


if IS_WINDOWS:
    _k = ctypes.WinDLL("kernel32", use_last_error=True)
    _k.GetCurrentProcess.restype = wintypes.HANDLE
    _k.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k.SetPriorityClass.restype = wintypes.BOOL
    _k.SetProcessInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _k.SetProcessInformation.restype = wintypes.BOOL
    _k.SetProcessAffinityMask.argtypes = [wintypes.HANDLE, ctypes.c_size_t]
    _k.SetProcessAffinityMask.restype = wintypes.BOOL
    _k.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    _k.CreateJobObjectW.restype = wintypes.HANDLE
    _k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _k.SetInformationJobObject.restype = wintypes.BOOL
    _k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _k.AssignProcessToJobObject.restype = wintypes.BOOL
    _k.SetProcessWorkingSetSizeEx.argtypes = [wintypes.HANDLE, ctypes.c_size_t, ctypes.c_size_t, wintypes.DWORD]
    _k.SetProcessWorkingSetSizeEx.restype = wintypes.BOOL
    _k.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    _k.GetProcessTimes.restype = wintypes.BOOL
    _psapi = ctypes.WinDLL("psapi", use_last_error=True)
    _psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD]
    _psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

_job = None  # keep the job handle alive for the life of the process


def _try(label: str, ok: bool, log) -> None:
    log(f"[i] {label}: {'ok' if ok else f'failed (error {ctypes.get_last_error()})'}")


def apply(cfg: dict, log=print) -> None:
    """Apply the [resources] section of the config to the current process."""
    if not IS_WINDOWS:
        return
    global _job
    me = _k.GetCurrentProcess()

    if cfg.get("background_mode", True):
        # Background mode lowers CPU, I/O and memory priority together.
        _try("background mode", _k.SetPriorityClass(me, PROCESS_MODE_BACKGROUND_BEGIN), log)
    else:
        _try("below-normal priority", _k.SetPriorityClass(me, BELOW_NORMAL_PRIORITY_CLASS), log)

    if cfg.get("low_memory_priority", True):
        mp = MEMORY_PRIORITY_INFORMATION(MEMORY_PRIORITY_LOW)
        _try("low memory priority", _k.SetProcessInformation(me, ProcessMemoryPriority, ctypes.byref(mp),
                                                              ctypes.sizeof(mp)), log)

    if cfg.get("eco_qos", True):
        st = PROCESS_POWER_THROTTLING_STATE(1, PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
                                            PROCESS_POWER_THROTTLING_EXECUTION_SPEED)
        _try("EcoQoS (efficiency cores)", _k.SetProcessInformation(me, ProcessPowerThrottling, ctypes.byref(st),
                                                                    ctypes.sizeof(st)), log)

    cpus = cfg.get("cpu_affinity") or []
    if cpus:
        mask = 0
        for c in cpus:
            mask |= 1 << int(c)
        _try(f"affinity to CPUs {cpus}", _k.SetProcessAffinityMask(me, mask), log)

    cpu_pct = float(cfg.get("cpu_rate_cap_percent", 0) or 0)
    mem_mb = int(cfg.get("memory_limit_mb", 0) or 0)
    if cpu_pct or mem_mb:
        _job = _k.CreateJobObjectW(None, None)
        if cpu_pct:
            info = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION(
                JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                max(1, min(10000, int(cpu_pct * 100))))
            _try(f"job CPU hard cap {cpu_pct}%", _k.SetInformationJobObject(
                _job, JobObjectCpuRateControlInformation, ctypes.byref(info), ctypes.sizeof(info)), log)
        if mem_mb:
            ext = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            ext.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY
            ext.ProcessMemoryLimit = mem_mb * 1024 * 1024
            _try(f"job memory ceiling {mem_mb} MB", _k.SetInformationJobObject(
                _job, JobObjectExtendedLimitInformation, ctypes.byref(ext), ctypes.sizeof(ext)), log)
        _try("assign to job object", _k.AssignProcessToJobObject(_job, me), log)

    ws_mb = int(cfg.get("working_set_max_mb", 0) or 0)
    if ws_mb:
        _try(f"working set hard max {ws_mb} MB", _k.SetProcessWorkingSetSizeEx(
            me, 1024 * 1024, ws_mb * 1024 * 1024,
            QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_ENABLE), log)


def self_usage() -> dict:
    """Working set, peak working set and CPU seconds of this process."""
    if not IS_WINDOWS:
        return {}
    me = _k.GetCurrentProcess()
    pmc = PROCESS_MEMORY_COUNTERS()
    pmc.cb = ctypes.sizeof(pmc)
    _psapi.GetProcessMemoryInfo(me, ctypes.byref(pmc), pmc.cb)
    c, e, kt, ut = (wintypes.FILETIME() for _ in range(4))
    _k.GetProcessTimes(me, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kt), ctypes.byref(ut))
    ft = lambda f: ((f.dwHighDateTime << 32) | f.dwLowDateTime) / 1e7  # noqa: E731 (100 ns units)
    return {"working_set_mb": round(pmc.WorkingSetSize / 2**20, 1),
            "peak_working_set_mb": round(pmc.PeakWorkingSetSize / 2**20, 1),
            "cpu_seconds": round(ft(kt) + ft(ut), 2), "page_faults": pmc.PageFaultCount}
