import json
import logging
import os
import tempfile
import threading
import time

from client.config.config import (
    LOCAL_WATCHDOG_ENABLED,
    LOCAL_WATCHDOG_HEARTBEAT_INTERVAL_SECONDS,
    LOCAL_WATCHDOG_TIMEOUT_SECONDS,
    REMOTE_HTTP_WATCHDOG_ENABLED,
    REMOTE_HTTP_WATCHDOG_INTERVAL_SECONDS,
    UPLOAD_BASE_URL,
)
from client.connection.http_control_watchdog_process import HttpRemoteControlWatchdogProcess
from core.utils.logger import logger


def _build_local_watchdog_file_logger(log_file_path: str):
    logger_name = f'local_watchdog_file_logger::{os.path.abspath(log_file_path)}'
    file_logger = logging.getLogger(logger_name)
    file_logger.setLevel(logging.ERROR)
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
    def __init__(
        self,
        client_id: str,
        heartbeat_interval_seconds: float,
        heartbeat_file_path: str,
        local_watchdog_log_file_path: str,
    ):
        self.client_id = str(client_id or '').strip()
        self.heartbeat_interval_seconds = max(float(heartbeat_interval_seconds or 0), 0.5)
        self.heartbeat_file_path = str(heartbeat_file_path or '').strip()
        self.local_watchdog_log_file_path = str(local_watchdog_log_file_path or '').strip()

        self._stop_event = threading.Event()
        self._thread = None
        self._local_watchdog_logger = _build_local_watchdog_file_logger(self.local_watchdog_log_file_path)

    # add local watchdog cleanup 2026-04-10 00:00
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

    # add local watchdog cleanup 2026-04-10 00:00
    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                self._write_heartbeat()
            except Exception as e:
                self._local_watchdog_logger.error(f'write local watchdog heartbeat failed: {e}')

            self._stop_event.wait(self.heartbeat_interval_seconds)

    # add local watchdog cleanup 2026-04-10 00:00
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

    # add local watchdog cleanup 2026-04-10 00:00
    def stop(self):
        self._stop_event.set()


class ClientGuardManager:
    def __init__(self, client_id: str):
        self.client_id = str(client_id or '').strip()
        self._remote_watchdog_process = None
        self._local_watchdog_feeder = None
        self._started = False

    # add guard manager cleanup 2026-04-10 00:00
    def _build_local_watchdog_heartbeat_file_path(self):
        return os.path.join(tempfile.gettempdir(), f'client_local_watchdog_heartbeat_{self.client_id}.json')

    # add guard manager cleanup 2026-04-10 00:00
    def _build_local_watchdog_log_file_path(self):
        return os.path.join(tempfile.gettempdir(), f'client_local_watchdog_{self.client_id}.log')

    # add guard manager cleanup 2026-04-10 00:00
    def _build_remote_watchdog_log_file_path(self):
        return os.path.join(tempfile.gettempdir(), f'client_remote_watchdog_{self.client_id}.log')

    # add guard manager cleanup 2026-04-10 00:00
    def _ensure_local_watchdog_feeder(self):
        if self._local_watchdog_feeder is None:
            self._local_watchdog_feeder = LocalWatchdogHeartbeatFeeder(
                client_id=self.client_id,
                heartbeat_interval_seconds=LOCAL_WATCHDOG_HEARTBEAT_INTERVAL_SECONDS,
                heartbeat_file_path=self._build_local_watchdog_heartbeat_file_path(),
                local_watchdog_log_file_path=self._build_local_watchdog_log_file_path(),
            )

    # add guard manager cleanup 2026-04-10 00:00
    def _start_local_watchdog_feeder(self):
        if not LOCAL_WATCHDOG_ENABLED:
            return

        self._ensure_local_watchdog_feeder()
        self._local_watchdog_feeder.start()

    # add guard manager cleanup 2026-04-10 00:00
    def _start_remote_watchdog_process(self):
        if not REMOTE_HTTP_WATCHDOG_ENABLED:
            return

        if self._remote_watchdog_process is not None:
            return

        self._remote_watchdog_process = HttpRemoteControlWatchdogProcess(
            base_url=UPLOAD_BASE_URL,
            client_id=self.client_id,
            poll_interval=REMOTE_HTTP_WATCHDOG_INTERVAL_SECONDS,
            local_watchdog_heartbeat_file_path=self._build_local_watchdog_heartbeat_file_path(),
            remote_watchdog_log_file_path=self._build_remote_watchdog_log_file_path(),
            local_watchdog_enabled=LOCAL_WATCHDOG_ENABLED,
            local_watchdog_timeout_seconds=LOCAL_WATCHDOG_TIMEOUT_SECONDS,
        )
        self._remote_watchdog_process.start()

    # add guard manager cleanup 2026-04-10 00:00
    def _log_guard_startup_once(self):
        logger.info(
            f'Guard startup: client_id={self.client_id}, '
            f'remote_http_watchdog_enabled={REMOTE_HTTP_WATCHDOG_ENABLED}, '
            f'remote_http_watchdog_interval_seconds={REMOTE_HTTP_WATCHDOG_INTERVAL_SECONDS}, '
            f'remote_watchdog_log_file_path={self._build_remote_watchdog_log_file_path()}, '
            f'local_watchdog_enabled={LOCAL_WATCHDOG_ENABLED}, '
            f'local_watchdog_heartbeat_interval_seconds={LOCAL_WATCHDOG_HEARTBEAT_INTERVAL_SECONDS}, '
            f'local_watchdog_timeout_seconds={LOCAL_WATCHDOG_TIMEOUT_SECONDS}, '
            f'local_watchdog_heartbeat_file_path={self._build_local_watchdog_heartbeat_file_path()}, '
            f'local_watchdog_log_file_path={self._build_local_watchdog_log_file_path()}'
        )

    # add guard manager cleanup 2026-04-10 00:00
    def start(self):
        if self._started:
            return

        self._log_guard_startup_once()
        self._start_local_watchdog_feeder()
        self._start_remote_watchdog_process()
        self._started = True

    # add guard manager cleanup 2026-04-10 00:00
    def stop(self):
        if self._remote_watchdog_process is not None:
            self._remote_watchdog_process.stop()

        if self._local_watchdog_feeder is not None:
            self._local_watchdog_feeder.stop()

        self._started = False