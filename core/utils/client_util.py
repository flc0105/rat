import os
import shlex
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

from client.config.config import CLIENT_BUILD_VERSION
from core.device.machine_identity import build_machine_identity_payload, _detect_machine_identity_components
from core.platform.platform_identity import detect_platform_alias, detect_platform_name, detect_platform_info
from core.utils.formatting import get_size, seconds_to_readable_text, timestamp_to_readable_time


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
    if detect_platform_alias() == 'win':
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



class ScriptArgError(Exception):
    pass



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


def ensure_directory(path: str) -> str:
    directory = os.path.abspath(path)
    os.makedirs(directory, exist_ok=True)
    return directory


def get_client_bundle_release_dir() -> str:
    # update 命令默认下载目录
    if detect_platform_name().lower() != 'ios':
        return ensure_directory(os.path.join(str(Path.home()), 'client_bundle', 'releases'))
    else:
        return ensure_directory(os.path.join(str(Path.home()), 'Documents', 'client_bundle', 'releases'))


def build_bundle_extract_dir(release_dir: str, file_name: str) -> str:
    base_name = os.path.splitext(os.path.basename(file_name))[0] or 'client_bundle'
    return os.path.join(os.path.abspath(release_dir), base_name)


def safe_extract_zip_file(zip_path: str, destination_dir: str) -> str:
    destination_dir = ensure_directory(destination_dir)
    destination_dir_abs = os.path.abspath(destination_dir)

    with zipfile.ZipFile(zip_path, 'r') as archive:
        for member in archive.infolist():
            member_path = os.path.abspath(os.path.join(destination_dir_abs, member.filename))
            if os.path.commonpath([destination_dir_abs, member_path]) != destination_dir_abs:
                raise ValueError(f'Unsafe zip entry detected: {member.filename}')
        archive.extractall(destination_dir_abs)

    return destination_dir_abs


def _resolve_python_command_for_source_bundle() -> list[str]:
    if not getattr(sys, 'frozen', False):
        return [os.path.realpath(sys.executable)]

    candidates = []

    env_python = os.environ.get('PYTHON_EXECUTABLE', '').strip()
    if env_python:
        candidates.append([env_python])

    python3_path = shutil.which('python3')
    if python3_path:
        candidates.append([python3_path])

    python_path = shutil.which('python')
    if python_path:
        candidates.append([python_path])

    py_launcher = shutil.which('py')
    if py_launcher:
        candidates.append([py_launcher, '-3'])

    if not candidates:
        raise RuntimeError('Python interpreter not found; cannot launch source bundle')

    return candidates[0]


def spawn_detached_python_script(script_path: str, cwd: str = '', args=None):
    script_path = os.path.abspath(script_path)
    launch_cwd = os.path.abspath(cwd) if cwd else os.path.dirname(script_path)
    command = _resolve_python_command_for_source_bundle() + [script_path]

    if args:
        command.extend(str(item) for item in args)

    popen_kwargs = {
        'cwd': launch_cwd,
        'env': dict(os.environ),
        'stdin': subprocess.DEVNULL,
        'stdout': subprocess.DEVNULL,
        'stderr': subprocess.DEVNULL,
        'close_fds': True,
        'shell': False,
    }

    if os.name == 'nt':
        creationflags = 0
        creationflags |= getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
        creationflags |= getattr(subprocess, 'DETACHED_PROCESS', 0)
        return subprocess.Popen(command, creationflags=creationflags, **popen_kwargs)

    if os.name == 'posix':
        return subprocess.Popen(command, start_new_session=True, **popen_kwargs)

    raise RuntimeError(f'Unsupported os.name: {os.name}')


def is_process_alive(pid: int) -> bool:
    try:
        pid = int(pid)
    except Exception:
        return False

    if pid <= 0:
        return False

    if os.name == 'nt':
        # Windows 下不能用 os.kill(pid, 0) 探活，否则可能直接终止目标进程
        import ctypes

        process_query_limited_information = 0x1000
        still_active = 259

        process_handle = ctypes.windll.kernel32.OpenProcess(
            process_query_limited_information,
            False,
            pid,
        )
        if not process_handle:
            return False

        try:
            exit_code = ctypes.c_ulong()
            if not ctypes.windll.kernel32.GetExitCodeProcess(process_handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == still_active
        finally:
            ctypes.windll.kernel32.CloseHandle(process_handle)

    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False



def upload_file_via_http(file_obj, filename, upload_url, category='', client_id=None):
    """给脚本使用的工具方法"""
    form_data = {
        'artifact_type': 'files',
        'category': category,
        'client_id': client_id,
    }
    try:
        file_obj.seek(0)
    except Exception:
        pass

    files = {
        'file': (filename, file_obj)
    }

    import requests
    return requests.post(
        upload_url,
        files=files,
        data=form_data,
        timeout=30,
    )



