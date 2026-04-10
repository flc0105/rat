import json
import threading
import time
import urllib.error
import urllib.request

from core.utils.logger import logger


class HttpControlPoller:
    def __init__(
        self,
        base_url: str,
        client_id: str,
        command_handler,
        poll_interval: float = 3,
        stop_event: threading.Event | None = None,
    ):
        self.base_url = str(base_url or '').rstrip('/')
        self.client_id = str(client_id or '').strip()
        self.command_handler = command_handler
        self.poll_interval = max(float(poll_interval or 0), 1.0)
        self.stop_event = stop_event or threading.Event()

        self._thread = None

    # add 运维控制轮询线程 2026-04-10 00:00
    def _build_poll_url(self) -> str:
        return f'{self.base_url}/api/connections/{self.client_id}/control'

    # add 运维控制轮询线程 2026-04-10 00:00
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
        if command in ('kill', 'reset'):
            return command

        return ''

    # add 运维控制轮询线程 2026-04-10 00:00
    def _run_loop(self):
        while not self.stop_event.is_set():
            try:
                logger.debug(f'Polling HTTP control endpoint: {self._build_poll_url()}')

                command = self._fetch_command()
                if command:
                    logger.warning(f'Received HTTP control command: {command}')
                    self.command_handler(command)
            except urllib.error.HTTPError as e:
                logger.debug(f'HTTP control poll failed: {e.code}')
            except urllib.error.URLError as e:
                logger.debug(f'HTTP control poll failed: {e}')
            except Exception as e:
                logger.error(f'HTTP control poller error: {e}', exc_info=True)

            self.stop_event.wait(self.poll_interval)

    # add 运维控制轮询线程 2026-04-10 00:00
    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return

        self.stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name='HttpControlPoller',
            daemon=True,
        )
        self._thread.start()

    # add 运维控制轮询线程 2026-04-10 00:00
    def stop(self):
        self.stop_event.set()

        current = threading.current_thread()
        if self._thread is not None and self._thread.is_alive() and self._thread is not current:
            self._thread.join(timeout=1)