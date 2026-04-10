import json
import os
import signal
import subprocess
import sys
import time
from typing import Optional

from client.connection.http_control_poller import HttpControlPoller
from core.utils.logger import logger


class HttpControlWatchdogProcess:
    def __init__(self, base_url: str, client_id: str, poll_interval: float = 3):
        self.base_url = str(base_url or '').rstrip('/')
        self.client_id = str(client_id or '').strip()
        self.poll_interval = max(float(poll_interval or 0), 1.0)
        self._process = None

    # add 子进程控制守护 2026-04-10 00:00
    def _build_parent_launch_argv(self):
        if getattr(sys, 'frozen', False):
            return [os.path.realpath(sys.executable), *sys.argv[1:]]

        return [os.path.realpath(sys.executable), os.path.realpath(sys.argv[0]), *sys.argv[1:]]

    # add 子进程控制守护 2026-04-10 00:00
    def _build_worker_argv(self):
        parent_launch_argv_json = json.dumps(self._build_parent_launch_argv())

        if getattr(sys, 'frozen', False):
            return [
                os.path.realpath(sys.executable),
                '--control-watchdog-worker',
                '--watch-parent-pid', str(os.getpid()),
                '--watch-client-id', self.client_id,
                '--watch-base-url', self.base_url,
                '--watch-poll-interval', str(self.poll_interval),
                '--watch-launch-cwd', os.getcwd(),
                '--watch-parent-launch-argv-json', parent_launch_argv_json,
            ]

        return [
            os.path.realpath(sys.executable),
            os.path.realpath(sys.argv[0]),
            '--control-watchdog-worker',
            '--watch-parent-pid', str(os.getpid()),
            '--watch-client-id', self.client_id,
            '--watch-base-url', self.base_url,
            '--watch-poll-interval', str(self.poll_interval),
            '--watch-launch-cwd', os.getcwd(),
            '--watch-parent-launch-argv-json', parent_launch_argv_json,
        ]

    # add 子进程控制守护 2026-04-10 00:00
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
            f'HTTP control watchdog process started: pid={self._process.pid}, '
            f'client_id={self.client_id}, base_url={self.base_url}'
        )

    # add 子进程控制守护 2026-04-10 00:00
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


class HttpControlWatchdogWorker:
    def __init__(
        self,
        parent_pid: int,
        client_id: str,
        base_url: str,
        poll_interval: float,
        launch_cwd: str,
        parent_launch_argv: list[str],
    ):
        self.parent_pid = int(parent_pid)
        self.client_id = str(client_id or '').strip()
        self.base_url = str(base_url or '').rstrip('/')
        self.poll_interval = max(float(poll_interval or 0), 1.0)
        self.launch_cwd = str(launch_cwd or '').strip() or os.getcwd()
        self.parent_launch_argv = list(parent_launch_argv or [])
        self._poller = HttpControlPoller(
            base_url=self.base_url,
            client_id=self.client_id,
            command_handler=self._handle_control_command,
            poll_interval=self.poll_interval,
        )

    # add 子进程控制守护 2026-04-10 00:00
    def _is_parent_alive(self) -> bool:
        try:
            os.kill(self.parent_pid, 0)
            return True
        except Exception:
            return False

    # add 子进程控制守护 2026-04-10 00:00
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
            logger.error(f'Failed to kill parent process: {e}', exc_info=True)

    # add 子进程控制守护 2026-04-10 00:00
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

    # add 子进程控制守护 2026-04-10 00:00
    def _handle_control_command(self, command: str):
        command_text = str(command or '').strip().lower()
        logger.warning(f'Watchdog received control command: {command_text}')

        if command_text == 'kill':
            self._kill_parent_process()
            os._exit(0)

        if command_text == 'reset':
            self._spawn_restarted_parent()
            time.sleep(0.2)
            self._kill_parent_process()
            os._exit(0)

        raise ValueError(f'Unsupported watchdog control command: {command_text}')

    # add 子进程控制守护 2026-04-10 00:00
    def run(self):
        logger.info(
            f'HTTP control watchdog worker running: pid={os.getpid()}, parent_pid={self.parent_pid}, '
            f'client_id={self.client_id}, base_url={self.base_url}'
        )
        self._poller.start()

        try:
            while True:
                parent_alive = self._is_parent_alive()
                logger.debug(
                    f'Watchdog polling heartbeat: pid={os.getpid()}, parent_pid={self.parent_pid}, '
                    f'client_id={self.client_id}, parent_alive={parent_alive}, '
                    f'url={self._poller._build_poll_url()}'
                )
                if not parent_alive:
                    logger.info('Watchdog parent process exited, worker stopping')
                    break
                time.sleep(min(self.poll_interval, 1.0))
        finally:
            self._poller.stop()


# add 子进程控制守护 2026-04-10 00:00
def _read_flag_value(flag_name: str, default_value: Optional[str] = None) -> Optional[str]:
    argv = sys.argv[1:]
    for index, arg in enumerate(argv):
        if arg == flag_name and index + 1 < len(argv):
            return argv[index + 1]
        if arg.startswith(f'{flag_name}='):
            return arg.split('=', 1)[1]
    return default_value


# add 子进程控制守护 2026-04-10 00:00
def run_watchdog_worker_from_argv():
    parent_pid = int(_read_flag_value('--watch-parent-pid', '0') or '0')
    client_id = _read_flag_value('--watch-client-id', '') or ''
    base_url = _read_flag_value('--watch-base-url', '') or ''
    poll_interval = float(_read_flag_value('--watch-poll-interval', '3') or '3')
    launch_cwd = _read_flag_value('--watch-launch-cwd', os.getcwd()) or os.getcwd()
    parent_launch_argv_json = _read_flag_value('--watch-parent-launch-argv-json', '[]') or '[]'

    parent_launch_argv = json.loads(parent_launch_argv_json)
    if not isinstance(parent_launch_argv, list):
        raise ValueError('Invalid parent launch argv json')

    worker = HttpControlWatchdogWorker(
        parent_pid=parent_pid,
        client_id=client_id,
        base_url=base_url,
        poll_interval=poll_interval,
        launch_cwd=launch_cwd,
        parent_launch_argv=parent_launch_argv,
    )
    worker.run()