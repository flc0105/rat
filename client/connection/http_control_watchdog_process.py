import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import Optional

from core.utils.logger import logger


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


class HttpRemoteControlWatchdogProcess:
    def __init__(
        self,
        base_url: str,
        client_id: str,
        poll_interval: float = 30,
        local_watchdog_heartbeat_file_path: str | None = None,
        remote_watchdog_log_file_path: str | None = None,
        local_watchdog_enabled: bool = True,
        local_watchdog_timeout_seconds: float = 15,
    ):
        self.base_url = str(base_url or '').rstrip('/')
        self.client_id = str(client_id or '').strip()
        self.poll_interval = max(float(poll_interval or 0), 1.0)
        self.local_watchdog_heartbeat_file_path = (
            local_watchdog_heartbeat_file_path or self._build_default_local_watchdog_heartbeat_file_path()
        )
        self.remote_watchdog_log_file_path = (
            remote_watchdog_log_file_path or self._build_default_remote_watchdog_log_file_path()
        )
        self.local_watchdog_enabled = bool(local_watchdog_enabled)
        self.local_watchdog_timeout_seconds = max(float(local_watchdog_timeout_seconds or 0), 1.0)
        self._process = None

    # add remote watchdog cleanup 2026-04-10 00:00
    def _build_default_local_watchdog_heartbeat_file_path(self):
        return os.path.join(tempfile.gettempdir(), f'client_local_watchdog_heartbeat_{self.client_id}.json')

    # add remote watchdog cleanup 2026-04-10 00:00
    def _build_default_remote_watchdog_log_file_path(self):
        return os.path.join(tempfile.gettempdir(), f'client_remote_watchdog_{self.client_id}.log')

    # add remote watchdog cleanup 2026-04-10 00:00
    def _build_parent_launch_argv(self):
        if getattr(sys, 'frozen', False):
            return [os.path.realpath(sys.executable), *sys.argv[1:]]

        return [os.path.realpath(sys.executable), os.path.realpath(sys.argv[0]), *sys.argv[1:]]

    # add remote watchdog cleanup 2026-04-10 00:00
    def _build_worker_argv(self):
        parent_launch_argv_json = json.dumps(self._build_parent_launch_argv())

        if getattr(sys, 'frozen', False):
            return [
                os.path.realpath(sys.executable),
                '--remote-watchdog-worker',
                '--watch-parent-pid', str(os.getpid()),
                '--watch-client-id', self.client_id,
                '--watch-base-url', self.base_url,
                '--watch-poll-interval', str(self.poll_interval),
                '--watch-launch-cwd', os.getcwd(),
                '--watch-parent-launch-argv-json', parent_launch_argv_json,
                '--watch-local-heartbeat-file-path', self.local_watchdog_heartbeat_file_path,
                '--watch-remote-log-file-path', self.remote_watchdog_log_file_path,
                '--watch-local-watchdog-enabled', '1' if self.local_watchdog_enabled else '0',
                '--watch-local-watchdog-timeout-seconds', str(self.local_watchdog_timeout_seconds),
            ]

        return [
            os.path.realpath(sys.executable),
            os.path.realpath(sys.argv[0]),
            '--remote-watchdog-worker',
            '--watch-parent-pid', str(os.getpid()),
            '--watch-client-id', self.client_id,
            '--watch-base-url', self.base_url,
            '--watch-poll-interval', str(self.poll_interval),
            '--watch-launch-cwd', os.getcwd(),
            '--watch-parent-launch-argv-json', parent_launch_argv_json,
            '--watch-local-heartbeat-file-path', self.local_watchdog_heartbeat_file_path,
            '--watch-remote-log-file-path', self.remote_watchdog_log_file_path,
            '--watch-local-watchdog-enabled', '1' if self.local_watchdog_enabled else '0',
            '--watch-local-watchdog-timeout-seconds', str(self.local_watchdog_timeout_seconds),
        ]

    # add remote watchdog cleanup 2026-04-10 00:00
    def start(self):
        if self._process is not None and self._process.poll() is None:
            return

        popen_kwargs = {
            'cwd': os.getcwd(),
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
            self._process = subprocess.Popen(
                self._build_worker_argv(),
                shell=False,
                creationflags=creationflags,
                **popen_kwargs,
            )
        elif os.name == 'posix':
            self._process = subprocess.Popen(
                self._build_worker_argv(),
                shell=False,
                start_new_session=True,
                **popen_kwargs,
            )
        else:
            raise RuntimeError(f'Unsupported os.name: {os.name}')

        logger.info(
            f'Remote watchdog process started: pid={self._process.pid}, '
            f'client_id={self.client_id}'
        )

    # add remote watchdog cleanup 2026-04-10 00:00
    def stop(self):
        process = self._process
        if process is None:
            return

        if process.poll() is not None:
            return

        try:
            if os.name == 'nt':
                subprocess.run(
                    ['taskkill', '/PID', str(process.pid), '/F', '/T'],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                os.kill(process.pid, signal.SIGKILL)
        except Exception:
            pass


class HttpRemoteControlWatchdogWorker:
    def __init__(
        self,
        parent_pid: int,
        client_id: str,
        base_url: str,
        poll_interval: float,
        launch_cwd: str,
        parent_launch_argv: list[str],
        local_watchdog_heartbeat_file_path: str,
        remote_watchdog_log_file_path: str,
        local_watchdog_enabled: bool,
        local_watchdog_timeout_seconds: float,
    ):
        self.parent_pid = int(parent_pid)
        self.client_id = str(client_id or '').strip()
        self.base_url = str(base_url or '').rstrip('/')
        self.poll_interval = max(float(poll_interval or 0), 1.0)
        self.launch_cwd = str(launch_cwd or '').strip() or os.getcwd()
        self.parent_launch_argv = list(parent_launch_argv or [])
        self.local_watchdog_heartbeat_file_path = str(local_watchdog_heartbeat_file_path or '').strip()
        self.remote_watchdog_log_file_path = str(remote_watchdog_log_file_path or '').strip()
        self.local_watchdog_enabled = bool(local_watchdog_enabled)
        self.local_watchdog_timeout_seconds = max(float(local_watchdog_timeout_seconds or 0), 1.0)
        self._remote_watchdog_logger = _build_remote_watchdog_file_logger(self.remote_watchdog_log_file_path)

    # add remote watchdog cleanup 2026-04-10 00:00
    def _log_http_debug(self, message: str):
        self._remote_watchdog_logger.debug(message)

    # add remote watchdog cleanup 2026-04-10 00:00
    def _log_http_warning(self, message: str):
        self._remote_watchdog_logger.warning(message)

    # add remote watchdog cleanup 2026-04-10 00:00
    def _log_http_error(self, message: str):
        self._remote_watchdog_logger.error(message)

    # add remote watchdog cleanup 2026-04-10 00:00
    def _build_poll_url(self) -> str:
        return f'{self.base_url}/api/connections/{self.client_id}/control'

    # add remote watchdog cleanup 2026-04-10 00:00
    def _is_parent_alive(self) -> bool:
        try:
            os.kill(self.parent_pid, 0)
            return True
        except Exception:
            return False

    # add remote watchdog cleanup 2026-04-10 00:00
    def _kill_parent_process(self):
        if not self._is_parent_alive():
            return

        try:
            if os.name == 'nt':
                subprocess.run(
                    ['taskkill', '/PID', str(self.parent_pid), '/F', '/T'],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                os.kill(self.parent_pid, signal.SIGKILL)
        except Exception as e:
            self._log_http_error(f'kill parent process failed: {e}')

    # add remote watchdog cleanup 2026-04-10 00:00
    def _spawn_restarted_parent(self):
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

    # add remote watchdog cleanup 2026-04-10 00:00
    def _read_local_watchdog_heartbeat_age_seconds(self):
        if (
            not self.local_watchdog_heartbeat_file_path
            or not os.path.isfile(self.local_watchdog_heartbeat_file_path)
        ):
            return None

        try:
            with open(self.local_watchdog_heartbeat_file_path, 'r', encoding='utf-8') as file_obj:
                data = json.load(file_obj)
            ts_value = float(data.get('ts') or 0)
            if ts_value <= 0:
                return None
            return max(time.time() - ts_value, 0.0)
        except Exception:
            return None

    # add remote watchdog cleanup 2026-04-10 00:00
    def _fetch_remote_control_command(self) -> str:
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
        if command in ('kill', 'reset'):
            return command

        return ''

    # add remote watchdog cleanup 2026-04-10 00:00
    def _execute_remote_control_command(self, command: str):
        command_text = str(command or '').strip().lower()

        if command_text == 'kill':
            self._kill_parent_process()
            os._exit(0)

        if command_text == 'reset':
            self._spawn_restarted_parent()
            time.sleep(0.2)
            self._kill_parent_process()
            os._exit(0)

        raise ValueError(f'Unsupported remote watchdog control command: {command_text}')

    # add remote watchdog cleanup 2026-04-10 00:00
    # add remote watchdog cleanup 2026-04-10 00:00
    def _handle_local_watchdog_timeout(self, heartbeat_age_seconds: float):
        self._log_http_warning(
            f'local watchdog timeout detected: client_id={self.client_id}, '
            f'heartbeat_age_seconds={heartbeat_age_seconds:.2f}, '
            f'timeout_seconds={self.local_watchdog_timeout_seconds}'
        )

        self._spawn_restarted_parent()

        self._log_http_warning(
            f'local watchdog restart spawned: client_id={self.client_id}, '
            f'launch_cwd={self.launch_cwd}'
        )

        time.sleep(0.2)

        self._log_http_warning(
            f'local watchdog killing old parent: client_id={self.client_id}, '
            f'parent_pid={self.parent_pid}'
        )

        self._kill_parent_process()
        os._exit(0)

    # add remote watchdog cleanup 2026-04-10 00:00
    def run(self):
        next_http_poll_at = 0.0

        while True:
            if not self._is_parent_alive():
                break

            if self.local_watchdog_enabled:
                heartbeat_age_seconds = self._read_local_watchdog_heartbeat_age_seconds()
                if (
                    heartbeat_age_seconds is not None
                    and heartbeat_age_seconds > self.local_watchdog_timeout_seconds
                ):
                    self._handle_local_watchdog_timeout(heartbeat_age_seconds)

            now = time.time()
            if now >= next_http_poll_at:
                poll_url = self._build_poll_url()
                self._log_http_debug(
                    f'http control poll request: client_id={self.client_id}, url={poll_url}'
                )

                try:
                    command = self._fetch_remote_control_command()
                    if command:
                        self._log_http_warning(
                            f'http control command received: client_id={self.client_id}, command={command}'
                        )
                        self._execute_remote_control_command(command)
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

                next_http_poll_at = now + self.poll_interval

            time.sleep(0.5)


# add remote watchdog cleanup 2026-04-10 00:00
def _read_flag_value(flag_name: str, default_value: Optional[str] = None) -> Optional[str]:
    argv = sys.argv[1:]
    for index, arg in enumerate(argv):
        if arg == flag_name and index + 1 < len(argv):
            return argv[index + 1]
        if arg.startswith(f'{flag_name}='):
            return arg.split('=', 1)[1]
    return default_value


# add remote watchdog cleanup 2026-04-10 00:00
def run_remote_watchdog_worker_from_argv():
    parent_pid = int(_read_flag_value('--watch-parent-pid', '0') or '0')
    client_id = _read_flag_value('--watch-client-id', '') or ''
    base_url = _read_flag_value('--watch-base-url', '') or ''
    poll_interval = float(_read_flag_value('--watch-poll-interval', '30') or '30')
    launch_cwd = _read_flag_value('--watch-launch-cwd', os.getcwd()) or os.getcwd()
    parent_launch_argv_json = _read_flag_value('--watch-parent-launch-argv-json', '[]') or '[]'
    local_watchdog_heartbeat_file_path = _read_flag_value('--watch-local-heartbeat-file-path', '') or ''
    remote_watchdog_log_file_path = _read_flag_value('--watch-remote-log-file-path', '') or ''
    local_watchdog_enabled = (_read_flag_value('--watch-local-watchdog-enabled', '1') or '1') == '1'
    local_watchdog_timeout_seconds = float(
        _read_flag_value('--watch-local-watchdog-timeout-seconds', '15') or '15'
    )

    parent_launch_argv = json.loads(parent_launch_argv_json)
    if not isinstance(parent_launch_argv, list):
        raise ValueError('Invalid parent launch argv json')

    worker = HttpRemoteControlWatchdogWorker(
        parent_pid=parent_pid,
        client_id=client_id,
        base_url=base_url,
        poll_interval=poll_interval,
        launch_cwd=launch_cwd,
        parent_launch_argv=parent_launch_argv,
        local_watchdog_heartbeat_file_path=local_watchdog_heartbeat_file_path,
        remote_watchdog_log_file_path=remote_watchdog_log_file_path,
        local_watchdog_enabled=local_watchdog_enabled,
        local_watchdog_timeout_seconds=local_watchdog_timeout_seconds,
    )
    worker.run()