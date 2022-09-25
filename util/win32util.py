from util.win32const import *

kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32


def create_remote_thread(pid, dll_path):
    size = (len(dll_path) + 1) * ctypes.sizeof(wintypes.WCHAR)
    # 获取目标进程句柄
    h_proc = kernel32.OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, False, pid)
    if not h_proc:
        return 0, 'Error obtaining process handle: {}'.format(ctypes.GetLastError())
    # 在目标进程中开辟内存空间用于存储DLL路径
    kernel32.VirtualAllocEx.restype = wintypes.LPVOID
    kernel32.VirtualAllocEx.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        ctypes.c_size_t,
        wintypes.DWORD,
        wintypes.DWORD)
    addr = kernel32.VirtualAllocEx(h_proc, 0, size, MEM_COMMIT, PAGE_READWRITE)
    if not addr:
        return 0, 'Error assigning space for DLL path: {}'.format(ctypes.GetLastError())
    # 向目标进程的内存空间中写入DLL地址
    kernel32.WriteProcessMemory.restype = wintypes.BOOL
    kernel32.WriteProcessMemory.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.LPCVOID,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t))
    if not kernel32.WriteProcessMemory(h_proc, addr, dll_path, size, None):
        return 0, 'Error writing DLL path: {}'.format(ctypes.GetLastError())
    # 创建远程线程
    kernel32.CreateRemoteThread.restype = wintypes.HANDLE
    kernel32.CreateRemoteThread.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        ctypes.c_size_t,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPDWORD)
    if kernel32.CreateRemoteThread(h_proc, None, 0, kernel32.LoadLibraryW, addr, 0, None):
        return 1, 'Thread created'
    else:
        return 0, 'Error creating thread: {}'.format(ctypes.GetLastError())


def get_integrity_level(pid):
    """
    获取进程权限
    """
    h_proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    h_token = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(h_proc, TOKEN_READ, ctypes.byref(h_token)):
        raise Exception('OpenProcessToken error: {}'.format(ctypes.GetLastError()))
    info_size = wintypes.DWORD()
    if advapi32.GetTokenInformation(h_token, TokenIntegrityLevel, None, 0, ctypes.byref(info_size)):
        raise Exception('GetTokenInformation error: {}'.format(ctypes.GetLastError()))
    if ctypes.GetLastError() != ERROR_INSUFFICIENT_BUFFER:
        raise Exception('GetTokenInformation error: {}'.format(ctypes.GetLastError()))
    token_info = TOKEN_MANDATORY_LABEL()
    ctypes.resize(token_info, info_size.value)
    if not advapi32.GetTokenInformation(h_token, TokenIntegrityLevel, ctypes.byref(token_info), info_size,
                                        ctypes.byref(info_size)):
        raise Exception('GetTokenInformation error: {}'.format(ctypes.GetLastError()))
    advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    sid_size = advapi32.GetSidSubAuthorityCount(token_info.Label.Sid).contents.value
    advapi32.GetSidSubAuthority.argtypes = (ctypes.c_void_p, wintypes.DWORD)
    advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    integrity_level = advapi32.GetSidSubAuthority(token_info.Label.Sid, sid_size - 1).contents.value
    mapping = {
        0x0000: 'Untrusted',
        0x1000: 'Low',
        0x2000: 'Medium',
        0x2100: 'Medium high',
        0x3000: 'High',
        0x4000: 'System',
        0x5000: 'Protected process',
    }
    return mapping.get(integrity_level)
