import os
import platform
import subprocess
import sys
from pathlib import Path
import shlex


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

# add exec脚本参数异常 2026-04-07 00:00
class ScriptArgError(Exception):
    pass


# add exec脚本必填参数读取 2026-04-07 00:00
def require_kwarg(kwargs, name, default='', allow_empty=False, error_prefix='[参数异常]'):
    value = kwargs.get(name, default)

    if allow_empty:
        return value

    if value is None:
        print(f'{error_prefix} 缺少必要参数: {name}')
        raise ScriptArgError(f'缺少必要参数: {name}')

    if isinstance(value, str) and not value.strip():
        print(f'{error_prefix} 缺少必要参数: {name}')
        raise ScriptArgError(f'缺少必要参数: {name}')

    return value


def reset(socket):
    spawn_new_instance()

    try:
        socket.close()
    except Exception:
        pass

    os._exit(0)


# add 启动新实例不退出当前进程 2026-04-10 00:00
def spawn_new_instance():
    restart_command = get_executable_path()

    if getattr(sys, 'frozen', False):
        launch_cwd = os.path.dirname(os.path.realpath(sys.executable))
    else:
        launch_cwd = os.path.dirname(os.path.realpath(sys.argv[0]))

    popen_kwargs = {
        'cwd': launch_cwd,
        'env': dict(os.environ),
        'stdin': subprocess.DEVNULL,
        'stdout': subprocess.DEVNULL,
        'stderr': subprocess.DEVNULL,
        'close_fds': True,
    }

    if os.name == 'nt':
        creationflags = 0
        creationflags |= getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
        creationflags |= getattr(subprocess, 'DETACHED_PROCESS', 0)

        return subprocess.Popen(
            restart_command,
            shell=False,
            creationflags=creationflags,
            **popen_kwargs,
        )

    if os.name == 'posix':
        return subprocess.Popen(
            shlex.split(restart_command),
            shell=False,
            start_new_session=True,
            **popen_kwargs,
        )

    raise RuntimeError(f'Unsupported os.name: {os.name}')