import os
import sys


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

    # 判断是否是打包后的可执行文件
    if getattr(sys, 'frozen', False):
        # PyInstaller 打包后的模式
        return executable
    else:
        # 开发模式，需要包含脚本路径
        script_path = os.path.realpath(''.join(sys.argv))
        argv = wrap_path(script_path)
        return f'{executable} {argv}'