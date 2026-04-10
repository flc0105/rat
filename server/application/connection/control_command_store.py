import threading
from datetime import datetime


class ControlCommandStore:
    def __init__(self):
        self._commands_by_client = {}
        self._lock = threading.RLock()

    # add HTTP 控制命令通道 2026-04-10 00:00
    def _now_iso(self) -> str:
        return datetime.now().isoformat()

    # add HTTP 控制命令通道 2026-04-10 00:00
    def set_pending_command(self, client_id: str, command: str) -> dict:
        client_id_text = str(client_id or '').strip()
        command_text = str(command or '').strip().lower()

        if not client_id_text:
            raise ValueError('client_id is required')

        if command_text not in ('kill', 'reset'):
            raise ValueError('command must be kill or reset')

        payload = {
            'client_id': client_id_text,
            'command': command_text,
            'created_at': self._now_iso(),
        }

        with self._lock:
            self._commands_by_client[client_id_text] = payload

        return dict(payload)

    # add HTTP 控制命令通道 2026-04-10 00:00
    def pop_pending_command(self, client_id: str) -> dict | None:
        client_id_text = str(client_id or '').strip()
        if not client_id_text:
            return None

        with self._lock:
            payload = self._commands_by_client.pop(client_id_text, None)

        if payload is None:
            return None

        return dict(payload)