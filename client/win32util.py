import ctypes
from ctypes import wintypes
from ctypes.wintypes import HANDLE, DWORD, WORD, LPBYTE, LPWSTR

import ntsecuritycon
import psutil
import win32api
import win32con
import win32process
import win32profile
import win32security
import win32service
import win32ts

kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32


def get_integrity_level():
    mapping = {
        0x0000: 'Untrusted',
        0x1000: 'Low',
        0x2000: 'Medium',
        0x2100: 'Medium high',
        0x3000: 'High',
        0x4000: 'System',
        0x5000: 'Protected process',
    }
    try:
        h_token = win32security.OpenProcessToken(win32process.GetCurrentProcess(), win32security.TOKEN_READ)
        sid = win32security.GetTokenInformation(h_token, ntsecuritycon.TokenIntegrityLevel)[0]
        return mapping.get(sid.GetSubAuthority(sid.GetSubAuthorityCount() - 1))
    except:
        pass


def create_remote_thread(pid, dll_path):
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


def enable_privilege(privilege_name):
    h_token = win32security.OpenProcessToken(win32process.GetCurrentProcess(),
                                             ntsecuritycon.TOKEN_ADJUST_PRIVILEGES | ntsecuritycon.TOKEN_QUERY)
    privilege_id = win32security.LookupPrivilegeValue(None, privilege_name)
    new_privilege = [(privilege_id, win32con.SE_PRIVILEGE_ENABLED)]
    win32security.AdjustTokenPrivileges(h_token, 0, new_privilege)
    win32api.CloseHandle(h_token)


def get_pid(process_name):
    for proc in psutil.process_iter():
        if process_name in proc.name():
            return proc.pid


def get_process_token(pid):
    h_process = kernel32.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
    h_token = win32security.OpenProcessToken(h_process, win32con.TOKEN_DUPLICATE | win32con.TOKEN_QUERY)
    return h_token


def duplicate_token(h_token):
    return win32security.DuplicateTokenEx(h_token, win32security.SecurityImpersonation, win32con.MAXIMUM_ALLOWED,
                                          win32security.TokenPrimary,
                                          win32security.SECURITY_ATTRIBUTES())


def start_service(service_name):
    h_scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
    h_service = win32service.OpenService(h_scm, service_name,
                                         win32service.SERVICE_START | win32service.SERVICE_QUERY_STATUS)
    status = win32service.QueryServiceStatus(h_service)[1]
    if status == win32service.SERVICE_STOPPED:
        win32service.StartService(h_service, None)
    win32service.CloseServiceHandle(h_service)


def create_process_with_token(h_token, exec_path):
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

    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    si.lpDesktop = 'winsta0\\default'
    pi = PROCESS_INFORMATION()
    creation_flags = win32con.CREATE_NEW_CONSOLE | win32con.NORMAL_PRIORITY_CLASS | win32con.CREATE_UNICODE_ENVIRONMENT
    advapi32.CreateProcessWithTokenW(int(h_token), 1, *exec_path, creation_flags, None, None, ctypes.byref(si),
                                     ctypes.byref(pi))
    return pi.dwProcessId


def create_process_as_user(h_token, exec_path):
    si = win32process.STARTUPINFO()
    si.lpDesktop = 'winsta0\\default'
    creation_flags = win32con.CREATE_NEW_CONSOLE | win32con.NORMAL_PRIORITY_CLASS | win32con.CREATE_UNICODE_ENVIRONMENT
    environment = win32profile.CreateEnvironmentBlock(h_token, False)
    hProcess, hThread, dwProcessId, dwThreadId = win32process.CreateProcessAsUser(h_token, *exec_path, None, None,
                                                                                  False,
                                                                                  creation_flags, environment, None,
                                                                                  si)
    return dwProcessId


def get_user_token():
    console_session_id = win32ts.WTSGetActiveConsoleSessionId()
    return win32ts.WTSQueryUserToken(console_session_id)


def get_linked_token(h_token):
    return win32security.GetTokenInformation(h_token, ntsecuritycon.TokenLinkedToken)
