import ctypes
import json
import logging
import os
import signal
import subprocess
import time
import urllib.error
import urllib.request

from core.utils.client_util import spawn_new_instance

def _build_remote_watchdog_file_logger(log_file_path: str):
    logger_name = f'remote_watchdog_file_logger::{os.path.abspath(log_file_path)}'
    file_logger = logging.getLogger(logger_name)
    file_logger.setLevel(logging.DEBUG)
    file_logger.propagate = False

    if not file_logger.handlers:
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
        file_handler.setFormatter(formatter)
        file_logger.addHandler(file_handler)

    return file_logger


class WatchdogActionExecutor:
    def __init__(self, parent_pid: int, launch_cwd: str, parent_launch_argv: list[str]):
        self.parent_pid = int(parent_pid)
        self.launch_cwd = str(launch_cwd or '').strip() or os.getcwd()
        self.parent_launch_argv = list(parent_launch_argv or [])

    # add watchdog action executor 2026-04-10 00:00
    # def is_parent_alive(self) -> bool:
    #     try:
    #         os.kill(self.parent_pid, 0)
    #         return True
    #     except Exception:
    #         return False

    def is_parent_alive(self) -> bool:
        if self.parent_pid <= 0:
            return False

        if os.name == 'nt':
            # Windows 下不能用 os.kill(pid, 0) 探活，否则可能直接终止目标进程
            process_query_limited_information = 0x1000
            still_active = 259

            process_handle = ctypes.windll.kernel32.OpenProcess(
                process_query_limited_information,
                False,
                self.parent_pid,
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
            os.kill(self.parent_pid, 0)
            return True
        except Exception:
            return False

    # add watchdog action executor 2026-04-10 00:00
    def kill_parent_process(self):
        if not self.is_parent_alive():
            return

        if os.name == 'nt':
            subprocess.run(
                ['taskkill', '/PID', str(self.parent_pid), '/F', '/T'],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            os.kill(self.parent_pid, signal.SIGKILL)

    # add watchdog action executor 2026-04-10 00:00
    def spawn_restarted_parent(self):
        if not self.parent_launch_argv:
            raise RuntimeError('Missing parent launch argv')

        popen_kwargs = {
            'cwd': self.launch_cwd,
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
            subprocess.Popen(
                self.parent_launch_argv,
                shell=False,
                creationflags=creationflags,
                **popen_kwargs,
            )
        elif os.name == 'posix':
            subprocess.Popen(
                self.parent_launch_argv,
                shell=False,
                start_new_session=True,
                **popen_kwargs,
            )
        else:
            raise RuntimeError(f'Unsupported os.name: {os.name}')

    # add watchdog action executor 2026-04-10 00:00
    def restart_parent_and_exit(self):
        self.spawn_restarted_parent()
        time.sleep(0.2)
        self.kill_parent_process()
        os._exit(0)

    # add watchdog action executor 2026-04-10 00:00
    def kill_parent_and_exit(self):
        self.kill_parent_process()
        os._exit(0)

    def spawn_new_instance(self):
        self.spawn_restarted_parent()


class RemoteHttpWatchdogMonitor:
    def __init__(
        self,
        client_id: str,
        base_url: str,
        poll_interval: float,
        remote_watchdog_log_file_path: str,
        action_executor: WatchdogActionExecutor,
    ):
        self.client_id = str(client_id or '').strip()
        self.base_url = str(base_url or '').rstrip('/')
        self.poll_interval = max(float(poll_interval or 0), 1.0)
        self.remote_watchdog_log_file_path = str(remote_watchdog_log_file_path or '').strip()
        self.action_executor = action_executor

        self._logger = _build_remote_watchdog_file_logger(self.remote_watchdog_log_file_path)
        self._next_poll_at = 0.0

    # add remote watchdog monitor 2026-04-10 00:00
    def _build_poll_url(self) -> str:
        return f'{self.base_url}/api/connections/{self.client_id}/control'

    # add remote watchdog monitor 2026-04-10 00:00
    def _log_http_debug(self, message: str):
        self._logger.debug(message)

    # add remote watchdog monitor 2026-04-10 00:00
    def _log_http_warning(self, message: str):
        self._logger.warning(message)

    # add remote watchdog monitor 2026-04-10 00:00
    def _log_http_error(self, message: str):
        self._logger.error(message)

    # add remote watchdog monitor 2026-04-10 00:00
    def _fetch_command(self) -> str:
        request = urllib.request.Request(
            self._build_poll_url(),
            method='GET',
            headers={
                'Accept': 'application/json',
            },
        )

        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode('utf-8', errors='replace'))

        if not isinstance(payload, dict):
            return ''

        data = payload.get('data') or {}
        if not isinstance(data, dict):
            return ''

        command = str(data.get('command') or '').strip().lower()
        if command in ('kill', 'reset', 'spawn'):
            return command

        return ''

    # add remote watchdog monitor 2026-04-10 00:00
    def _execute_command(self, command: str):
        command_text = str(command or '').strip().lower()

        if command_text == 'kill':
            self.action_executor.kill_parent_and_exit()

        if command_text == 'reset':
            self.action_executor.restart_parent_and_exit()

        if command_text == 'spawn':
            self.action_executor.spawn_new_instance()
            return

        raise ValueError(f'Unsupported remote watchdog control command: {command_text}')

    # add remote watchdog monitor 2026-04-10 00:00
    def run_iteration(self, now: float):
        if now < self._next_poll_at:
            return

        poll_url = self._build_poll_url()
        self._log_http_debug(
            f'http control poll request: client_id={self.client_id}, url={poll_url}'
        )

        try:
            command = self._fetch_command()
            if command:
                self._log_http_warning(
                    f'http control command received: client_id={self.client_id}, command={command}'
                )
                self._execute_command(command)
        except urllib.error.HTTPError as e:
            self._log_http_error(
                f'http control poll failed: client_id={self.client_id}, http_status={e.code}, url={poll_url}'
            )
        except urllib.error.URLError as e:
            self._log_http_error(
                f'http control poll failed: client_id={self.client_id}, error={e}, url={poll_url}'
            )
        except Exception as e:
            self._log_http_error(
                f'http control poll failed: client_id={self.client_id}, error={e}, url={poll_url}'
            )

        self._next_poll_at = now + self.poll_interval