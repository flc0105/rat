SCRIPT_METADATA = {
    "name": "windows/privilege/token_privileges",
    "display_name": "Token Privileges",
    "description": "Enumerate the privileges assigned to the current process token on Windows",
    "platforms": ["windows"],
    "category": "Privilege",
    "params": []
}

import ctypes
import json
import os
from ctypes import wintypes


def get_windows_privileges():
    if os.name != "nt":
        raise OSError("Windows only")

    TOKEN_QUERY = 0x0008
    TokenPrivileges = 3

    SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
    SE_PRIVILEGE_ENABLED = 0x00000002
    SE_PRIVILEGE_REMOVED = 0x00000004
    SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class LUID(ctypes.Structure):
        _fields_ = [
            ("LowPart", wintypes.DWORD),
            ("HighPart", wintypes.LONG),
        ]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Luid", LUID),
            ("Attributes", wintypes.DWORD),
        ]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [
            ("PrivilegeCount", wintypes.DWORD),
            ("Privileges", LUID_AND_ATTRIBUTES * 1),
        ]

    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL

    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL

    advapi32.LookupPrivilegeNameW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(LUID),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.LookupPrivilegeNameW.restype = wintypes.BOOL

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    def raise_last_error():
        raise ctypes.WinError(ctypes.get_last_error())

    def privilege_flags(attributes):
        flags = []

        if attributes & SE_PRIVILEGE_ENABLED:
            flags.append("enabled")
        else:
            flags.append("disabled")

        if attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT:
            flags.append("enabled_by_default")

        if attributes & SE_PRIVILEGE_REMOVED:
            flags.append("removed")

        if attributes & SE_PRIVILEGE_USED_FOR_ACCESS:
            flags.append("used_for_access")

        return flags

    def lookup_privilege_name(luid):
        size = wintypes.DWORD(256)
        name = ctypes.create_unicode_buffer(size.value)

        ok = advapi32.LookupPrivilegeNameW(
            None,
            ctypes.byref(luid),
            name,
            ctypes.byref(size),
        )

        if not ok:
            raise_last_error()

        return name.value

    token = wintypes.HANDLE()

    ok = advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_QUERY,
        ctypes.byref(token),
    )

    if not ok:
        raise_last_error()

    try:
        needed = wintypes.DWORD(0)

        advapi32.GetTokenInformation(
            token,
            TokenPrivileges,
            None,
            0,
            ctypes.byref(needed),
        )

        if needed.value == 0:
            raise_last_error()

        buf = ctypes.create_string_buffer(needed.value)

        ok = advapi32.GetTokenInformation(
            token,
            TokenPrivileges,
            buf,
            needed.value,
            ctypes.byref(needed),
        )

        if not ok:
            raise_last_error()

        tp = ctypes.cast(buf, ctypes.POINTER(TOKEN_PRIVILEGES)).contents
        count = tp.PrivilegeCount

        result = []
        base_offset = TOKEN_PRIVILEGES.Privileges.offset
        item_size = ctypes.sizeof(LUID_AND_ATTRIBUTES)

        for i in range(count):
            item = LUID_AND_ATTRIBUTES.from_buffer_copy(
                buf.raw,
                base_offset + i * item_size,
            )

            result.append(
                {
                    "name": lookup_privilege_name(item.Luid),
                    "enabled": bool(item.Attributes & SE_PRIVILEGE_ENABLED),
                    "flags": privilege_flags(item.Attributes),
                }
            )

        return result

    finally:
        kernel32.CloseHandle(token)


privileges = get_windows_privileges()
    
# Sort: enabled first, then alphabetically by name
privileges.sort(key=lambda x: (not x["enabled"], x["name"].lower()))
    
print(json.dumps(privileges, ensure_ascii=False, indent=2))