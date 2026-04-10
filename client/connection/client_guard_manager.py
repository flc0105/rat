import json
import logging
import os
import tempfile
import threading
import time

from client.config.config import (
    CONTROL_POLLER_BACKEND,
    CONTROL_POLL_INTERVAL_SECONDS,
    LOCAL_WATCHDOG_ENABLED,
    LOCAL_WATCHDOG_HEARTBEAT_INTERVAL_SECONDS,
    LOCAL_WATCHDOG_TIMEOUT_SECONDS,
    UPLOAD_BASE_URL,
)
from client.connection.http_control_poller import HttpRemoteControlPoller
from client.connection.http_control_watchdog_process import HttpRemoteControlWatchdogProcess
from core.utils.logger import logger


def _build_guard_file_logger(log_file_path: str):
    logger_name = f'guard_file_logger::{os.path.abspath(log_file_path)}'
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


class LocalWatchdogHeartbeatFeeder:
    def __init__(self, client_id: str, heartbeat_interval_seconds: float, heartbeat_file_path: str, log_file_path: str):
        self.client_id = str(client_id or '').strip()
        self.heartbeat_interval_seconds = max(float(heartbeat_interval_seconds or 0), 0.5)
        self.heartbeat_file_path = str(heartbeat_file_path or '').strip()
        self.log_file_path = str(log_file_path or '').strip()

        self._stop_event = threading.Event()
        self._thread = None
        self._local_watchdog_logger = _build_guard_file_logger(self.log_file_path)

    # add local watchdog feeder split 2026-04-10 00:00
    def _log_debug(self, message: str):
        self._local_watchdog_logger.debug(message)

    # add local watchdog feeder split 2026-04-10 00:00
    def _log_info(self, message: str):
        self._local_watchdog_logger.info(message)

    # add local watchdog feeder split 2026-04-10 00:00
    def _write_heartbeat(self):
        temp_file_path = f'{self.heartbeat_file_path}.tmp'

        os.makedirs(os.path.dirname(self.heartbeat_file_path), exist_ok=True)
        payload = {
            'ts': time.time(),
            'pid': os.getpid(),
            'client_id': self.client_id,
        }

        with open(temp_file_path, 'w', encoding='utf-8') as file_obj:
            json.dump(payload, file_obj)

        os.replace(temp_file_path, self.heartbeat_file_path)

    # add local watchdog feeder split 2026-04-10 00:00
    def _run_loop(self):
        self._log_info(
            f'Local watchdog heartbeat feeder running: pid={os.getpid()}, '
            f'client_id={self.client_id}, heartbeat_file_path={self.heartbeat_file_path}, '
            f'local_watchdog_log_file_path={self.log_file_path}, '
            f'heartbeat_interval_seconds={self.heartbeat_interval_seconds}'
        )

        while not self._stop_event.is_set():
            try:
                self._write_heartbeat()
                self._log_debug(
                    f'Local watchdog heartbeat written: pid={os.getpid()}, '
                    f'client_id={self.client_id}, heartbeat_file_path={self.heartbeat_file_path}'
                )
            except Exception as e:
                self._local_watchdog_logger.error(f'Failed to write local watchdog heartbeat: {e}')

            self._stop_event.wait(self.heartbeat_interval_seconds)

    # add local watchdog feeder split 2026-04-10 00:00
    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._write_heartbeat()

        self._thread = threading.Thread(
            target=self._run_loop,
            name='LocalWatchdogHeartbeatFeeder',
            daemon=True,
        )
        self._thread.start()

    # add local watchdog feeder split 2026-04-10 00:00
    def stop(self):
        self._stop_event.set()


class ClientGuardManager:
    def __init__(self, client_id: str, remote_control_command_handler):
        self.client_id = str(client_id or '').strip()
        self.remote_control_command_handler = remote_control_command_handler

        self._remote_control_stop_event = threading.Event()
        self._remote_control_poller = None
        self._remote_watchdog_process = None
        self._local_watchdog_feeder = None

    # add guard manager split 2026-04-10 00:00
    def _build_local_watchdog_heartbeat_file_path(self):
        return os.path.join(tempfile.gettempdir(), f'client_local_watchdog_heartbeat_{self.client_id}.json')

    # add guard manager split 2026-04-10 00:00
    def _build_local_watchdog_log_file_path(self):
        return os.path.join(tempfile.gettempdir(), f'client_local_watchdog_{self.client_id}.log')

    # add guard manager split 2026-04-10 00:00
    def _build_remote_watchdog_log_file_path(self):
        return os.path.join(tempfile.gettempdir(), f'client_remote_watchdog_{self.client_id}.log')

    # add guard manager split 2026-04-10 00:00
    def _ensure_local_watchdog_feeder(self):
        if self._local_watchdog_feeder is None:
            self._local_watchdog_feeder = LocalWatchdogHeartbeatFeeder(
                client_id=self.client_id,
                heartbeat_interval_seconds=LOCAL_WATCHDOG_HEARTBEAT_INTERVAL_SECONDS,
                heartbeat_file_path=self._build_local_watchdog_heartbeat_file_path(),
                log_file_path=self._build_local_watchdog_log_file_path(),
            )

    # add guard manager split 2026-04-10 00:00
    def _start_local_watchdog_feeder(self):
        if not LOCAL_WATCHDOG_ENABLED:
            logger.info(f'Local watchdog disabled: client_id={self.client_id}')
            return

        self._ensure_local_watchdog_feeder()
        logger.info(
            f'Starting local watchdog heartbeat feeder: client_id={self.client_id}, '
            f'heartbeat_file_path={self._build_local_watchdog_heartbeat_file_path()}, '
            f'local_watchdog_log_file_path={self._build_local_watchdog_log_file_path()}, '
            f'heartbeat_interval_seconds={LOCAL_WATCHDOG_HEARTBEAT_INTERVAL_SECONDS}'
        )
        self._local_watchdog_feeder.start()

    # add guard manager split 2026-04-10 00:00
    def _start_remote_watchdog_process(self):
        if self._remote_watchdog_process is not None:
            return

        logger.info(
            f'Starting remote watchdog process: client_id={self.client_id}, '
            f'control_url={UPLOAD_BASE_URL}/api/connections/{self.client_id}/control, '
            f'local_watchdog_heartbeat_file_path={self._build_local_watchdog_heartbeat_file_path()}, '
            f'remote_watchdog_log_file_path={self._build_remote_watchdog_log_file_path()}, '
            f'local_watchdog_enabled={LOCAL_WATCHDOG_ENABLED}, '
            f'local_watchdog_timeout_seconds={LOCAL_WATCHDOG_TIMEOUT_SECONDS}'
        )

        self._remote_watchdog_process = HttpRemoteControlWatchdogProcess(
            base_url=UPLOAD_BASE_URL,
            client_id=self.client_id,
            poll_interval=CONTROL_POLL_INTERVAL_SECONDS,
            local_watchdog_heartbeat_file_path=self._build_local_watchdog_heartbeat_file_path(),
            remote_watchdog_log_file_path=self._build_remote_watchdog_log_file_path(),
            local_watchdog_enabled=LOCAL_WATCHDOG_ENABLED,
            local_watchdog_timeout_seconds=LOCAL_WATCHDOG_TIMEOUT_SECONDS,
        )
        self._remote_watchdog_process.start()

    # add guard manager split 2026-04-10 00:00
    def _start_remote_control_thread_poller(self):
        if self._remote_control_poller is not None:
            return

        logger.info(
            f'Starting remote control thread poller: client_id={self.client_id}, '
            f'control_url={UPLOAD_BASE_URL}/api/connections/{self.client_id}/control, '
            f'poll_interval_seconds={CONTROL_POLL_INTERVAL_SECONDS}'
        )

        self._remote_control_poller = HttpRemoteControlPoller(
            base_url=UPLOAD_BASE_URL,
            client_id=self.client_id,
            command_handler=self.remote_control_command_handler,
            poll_interval=CONTROL_POLL_INTERVAL_SECONDS,
            stop_event=self._remote_control_stop_event,
        )
        self._remote_control_poller.start()

    # add guard manager split 2026-04-10 00:00
    def start(self):
        if CONTROL_POLLER_BACKEND == 'process':
            self._start_local_watchdog_feeder()
            self._start_remote_watchdog_process()
            return

        self._start_remote_control_thread_poller()

    # add guard manager split 2026-04-10 00:00
    def stop(self):
        self._remote_control_stop_event.set()

        if self._remote_control_poller is not None:
            self._remote_control_poller.stop()

        if self._remote_watchdog_process is not None:
            self._remote_watchdog_process.stop()

        if self._local_watchdog_feeder is not None:
            self._local_watchdog_feeder.stop()