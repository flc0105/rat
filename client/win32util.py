import ctypes
from ctypes import wintypes

kernel32 = ctypes.windll.kernel32


def create_remote_thread(pid, dll_path):
    """
    远程线程注入
    """
    PROCESS_CREATE_THREAD = 0x0002
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_WRITE = 0x0020
    MEM_COMMIT = 0x1000
    PAGE_READWRITE = 0x0004
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
