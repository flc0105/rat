SCRIPT_METADATA = {
    "name": "win/files/locking_processes",
    "display_name": "Locking Processes",
    "description": "List Windows processes that are currently locking a file",
    "platforms": ["windows"],
    "category": "Misc",
    "params": [
        {
            "name": "file",
            "type": "string",
            "required": True,
            "default": "",
            "description": "Target file path to inspect"
        }
    ]
}

import ctypes
import json
import os
import sys
from ctypes import wintypes

CCH_RM_MAX_APP_NAME = 255
CCH_RM_MAX_SVC_NAME = 63
ERROR_MORE_DATA = 234
RM_SESSION_KEY_LEN = 32


class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [
        ("dwProcessId", wintypes.DWORD),
        ("ProcessStartTime", FILETIME),
    ]


class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [
        ("Process", RM_UNIQUE_PROCESS),
        ("strAppName", wintypes.WCHAR * (CCH_RM_MAX_APP_NAME + 1)),
        ("strServiceShortName", wintypes.WCHAR * (CCH_RM_MAX_SVC_NAME + 1)),
        ("ApplicationType", wintypes.UINT),
        ("AppStatus", wintypes.ULONG),
        ("TSSessionId", wintypes.DWORD),
        ("bRestartable", wintypes.BOOL),
    ]


rstrtmgr = ctypes.WinDLL("Rstrtmgr.dll")

RmStartSession = rstrtmgr.RmStartSession
RmStartSession.argtypes = [
    ctypes.POINTER(wintypes.DWORD),
    wintypes.DWORD,
    wintypes.WCHAR * (RM_SESSION_KEY_LEN + 1),
]
RmStartSession.restype = wintypes.DWORD

RmRegisterResources = rstrtmgr.RmRegisterResources
RmRegisterResources.argtypes = [
    wintypes.DWORD,
    wintypes.UINT,
    ctypes.POINTER(wintypes.LPCWSTR),
    wintypes.UINT,
    ctypes.c_void_p,
    wintypes.UINT,
    ctypes.c_void_p,
]
RmRegisterResources.restype = wintypes.DWORD

RmGetList = rstrtmgr.RmGetList
RmGetList.argtypes = [
    wintypes.DWORD,
    ctypes.POINTER(wintypes.UINT),
    ctypes.POINTER(wintypes.UINT),
    ctypes.POINTER(RM_PROCESS_INFO),
    ctypes.POINTER(wintypes.DWORD),
]
RmGetList.restype = wintypes.DWORD

RmEndSession = rstrtmgr.RmEndSession
RmEndSession.argtypes = [wintypes.DWORD]
RmEndSession.restype = wintypes.DWORD


def get_locking_processes(file_path):
    abs_path = os.path.abspath(file_path)

    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"File not found: {abs_path}")

    session_handle = wintypes.DWORD(0)
    session_key = (wintypes.WCHAR * (RM_SESSION_KEY_LEN + 1))()

    result = RmStartSession(ctypes.byref(session_handle), 0, session_key)
    if result != 0:
        raise OSError(f"RmStartSession failed, error={result}")

    try:
        resources = (wintypes.LPCWSTR * 1)(abs_path)
        result = RmRegisterResources(session_handle.value, 1, resources, 0, None, 0, None)
        if result != 0:
            raise OSError(f"RmRegisterResources failed, error={result}")

        needed = wintypes.UINT(0)
        count = wintypes.UINT(0)
        reboot_reasons = wintypes.DWORD(0)

        result = RmGetList(
            session_handle.value,
            ctypes.byref(needed),
            ctypes.byref(count),
            None,
            ctypes.byref(reboot_reasons),
        )

        if result == ERROR_MORE_DATA:
            process_info = (RM_PROCESS_INFO * needed.value)()
            count = wintypes.UINT(needed.value)

            result = RmGetList(
                session_handle.value,
                ctypes.byref(needed),
                ctypes.byref(count),
                process_info,
                ctypes.byref(reboot_reasons),
            )

            if result != 0:
                raise OSError(f"RmGetList failed, error={result}")

            return [
                {
                    "pid": process_info[i].Process.dwProcessId,
                    "app_name": process_info[i].strAppName or "",
                    "service_name": process_info[i].strServiceShortName or "",
                    "session_id": process_info[i].TSSessionId,
                    "restartable": bool(process_info[i].bRestartable),
                }
                for i in range(count.value)
            ]

        if result == 0:
            return []

        raise OSError(f"RmGetList failed, error={result}")

    finally:
        RmEndSession(session_handle.value)


def build_result(success, file_path="", processes=None, error=""):
    return {
        "success": success,
        "file_path": os.path.abspath(file_path) if file_path else "",
        "count": len(processes or []),
        "processes": processes or [],
        "error": error,
    }


if os.name != "nt":
    print(json.dumps(build_result(False, error="This script only supports Windows."), ensure_ascii=False))

file_path = kwargs.get('file', '')

try:
    processes = get_locking_processes(file_path)
    print(json.dumps(build_result(True, file_path=file_path, processes=processes), ensure_ascii=False))
except Exception as e:
    print(json.dumps(build_result(False, file_path=file_path, error=str(e)), ensure_ascii=False))