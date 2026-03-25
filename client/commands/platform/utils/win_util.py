import ctypes
from ctypes.wintypes import DWORD, HANDLE, LPBYTE, LPWSTR, WORD

import ntsecuritycon
import psutil
import win32api
import win32con
import win32process
import win32security
import win32service
import winerror

kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32


def get_integrity_level() -> str:
    """
    获取当前进程的完整性级别
    """
    mapping = {
        0x0000: 'Untrusted',
        0x1000: 'Low',
        0x2000: 'Medium',
        0x2100: 'Medium High',
        0x3000: 'High',
        0x4000: 'System',
        0x5000: 'Protected',
    }

    try:
        h_token = win32security.OpenProcessToken(
            win32process.GetCurrentProcess(),
            win32security.TOKEN_READ
        )
        sid = win32security.GetTokenInformation(h_token, ntsecuritycon.TokenIntegrityLevel)[0]
        return mapping.get(sid.GetSubAuthority(sid.GetSubAuthorityCount() - 1), 'Unknown')
    except Exception:
        return 'Unknown'


def logon_user(username, password):
    """验证用户凭证"""
    try:
        token = win32security.LogonUser(username, None, password, win32security.LOGON32_LOGON_INTERACTIVE,
                                        win32security.LOGON32_PROVIDER_DEFAULT)
        token.Close()
        return True
    except win32security.error as e:
        if e.winerror == winerror.ERROR_ACCOUNT_RESTRICTION:
            return True
        if e.winerror == winerror.ERROR_LOGON_FAILURE:
            return False
        return False


def enable_privilege(privilege_name):
    """启用指定权限"""
    h_token = win32security.OpenProcessToken(win32process.GetCurrentProcess(),
                                             win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY)
    privilege_id = win32security.LookupPrivilegeValue(None, privilege_name)
    new_privilege = [(privilege_id, win32con.SE_PRIVILEGE_ENABLED)]
    win32security.AdjustTokenPrivileges(h_token, 0, new_privilege)
    win32api.CloseHandle(h_token)


def get_pid(process_name):
    """根据进程名获取 PID"""
    for proc in psutil.process_iter(['name']):
        if process_name.lower() in proc.info['name'].lower():
            return proc.pid
    return None


def get_process_token(pid):
    """获取进程 Token"""
    h_process = kernel32.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
    return win32security.OpenProcessToken(h_process, win32con.TOKEN_DUPLICATE | win32con.TOKEN_QUERY)


def duplicate_token(h_token):
    """复制 Token"""
    return win32security.DuplicateTokenEx(h_token, win32security.SecurityImpersonation, win32con.MAXIMUM_ALLOWED,
                                          win32security.TokenPrimary, win32security.SECURITY_ATTRIBUTES())


def start_service(service_name):
    """启动服务"""
    h_scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
    h_service = win32service.OpenService(h_scm, service_name,
                                         win32service.SERVICE_START | win32service.SERVICE_QUERY_STATUS)
    status = win32service.QueryServiceStatus(h_service)[1]
    if status == win32service.SERVICE_STOPPED:
        win32service.StartService(h_service, None)
    win32service.CloseServiceHandle(h_service)


def create_process_with_token(h_token, lp_application_name, lp_command_line):
    """使用 Token 创建进程"""

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
    advapi32.CreateProcessWithTokenW(int(h_token), 1, lp_application_name, lp_command_line, creation_flags, None, None,
                                     ctypes.byref(si), ctypes.byref(pi))
    return pi.dwProcessId
