import os
import platform
import sys
from pathlib import Path


def check_privilege():
    if os.name == 'posix':
        if os.geteuid() == 0:
            if 'SUDO_USER' in os.environ:
                return 'Root (via sudo)'
            return 'Root'
        return 'User'
    if os.name == 'nt':
        from client.commands.platform.utils.win_util import get_integrity_level
        return get_integrity_level()

    return 'N/A'


def wrap_path(path):
    """如果路径包含空格，用双引号包裹"""
    return f'"{path}"' if ' ' in path else path


def get_executable_path():
    """
    获取当前脚本的执行命令，用于重启或后台启动

    适配 macOS 和 Windows:
    - 开发模式 (python script.py): 返回 "python script.py"
    - 打包模式 (pyinstaller): 返回可执行文件路径
    """
    executable = wrap_path(os.path.realpath(sys.executable))

    if getattr(sys, 'frozen', False):
        return executable
    else:
        script_path = os.path.realpath(sys.argv[0])
        args = sys.argv[1:]
        argv = wrap_path(script_path)
        if args:
            args_str = ' '.join(wrap_path(arg) for arg in args)
            return f'{executable} {argv} {args_str}'
        return f'{executable} {argv}'


def get_executable_path_for_shell():
    """返回 (shell, args) 元组，用于 ShellExecuteW"""
    executable = wrap_path(os.path.realpath(sys.executable))
    script_path = os.path.realpath(sys.argv[0])
    args = sys.argv[1:]

    if not getattr(sys, 'frozen', False):
        cmd_parts = [executable, wrap_path(script_path)]
        if args:
            cmd_parts.extend(wrap_path(arg) for arg in args)
        cmd = ' '.join(cmd_parts)
        return r'c:\windows\system32\cmd.exe', f'/c {cmd}'
    else:
        return executable, None


def get_exec_and_args():
    """
    返回 (executable, params)

    - 开发模式:
        executable = python.exe
        params = "script.py" args...

    - 打包模式:
        executable = exe
        params = args...
    """
    executable = os.path.realpath(sys.executable)

    if getattr(sys, 'frozen', False):
        # 👉 打包模式
        args = sys.argv[1:]
        params = ' '.join(wrap_path(arg) for arg in args) if args else None
        return executable, params

    else:
        # 👉 开发模式
        script_path = os.path.realpath(sys.argv[0])
        args = sys.argv[1:]

        params_parts = [wrap_path(script_path)]
        if args:
            params_parts.extend(wrap_path(arg) for arg in args)

        params = ' '.join(params_parts)
        return executable, params


def get_system_paths():
    # 获取系统路径
    system_paths = {}
    if platform.system() == 'Windows':
        system_paths['root'] = 'C:\\'
    else:
        system_paths['root'] = '/'

    system_paths['home'] = str(Path.home())
    system_paths['desktop'] = str(Path.home() / 'Desktop')
    system_paths['documents'] = str(Path.home() / 'Documents')
    system_paths['downloads'] = str(Path.home() / 'Downloads')

    if getattr(sys, 'frozen', False):
        system_paths['executable'] = os.path.dirname(sys.executable)
    else:
        script_path = os.path.realpath(sys.argv[0])
        argv = wrap_path(script_path)
        system_paths['executable'] = os.path.dirname(argv)

    return system_paths
