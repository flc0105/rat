import json
import urllib.error
import urllib.request

from server.config.config import WEB_PUBLIC_BASE_URL


class ControlBuiltinSupport:
    def __init__(self, conn):
        self.conn = conn

    # add server端控制命令转发 2026-04-10 00:00
    def _get_client_id(self) -> str:
        session_info = getattr(self.conn, 'session_info', None)
        return str(getattr(session_info, 'client_id', '') or '').strip()

    # add server端控制命令转发 2026-04-10 00:00
    def _build_control_url(self) -> str:
        client_id = self._get_client_id()
        if not client_id:
            raise ValueError('Missing client_id for current connection')

        return f'{WEB_PUBLIC_BASE_URL}/api/connections/{client_id}/control'

    # add server端控制命令转发 2026-04-10 00:00
    def _post_control_command(self, command: str) -> dict:
        normalized_command = str(command or '').strip().lower()
        if normalized_command not in ('kill', 'reset', 'spawn'):
            raise ValueError('command must be kill, reset or spawn')

        payload = json.dumps({
            'command': normalized_command
        }).encode('utf-8')

        request = urllib.request.Request(
            self._build_control_url(),
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            method='POST'
        )

        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                response_text = response.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='replace')
            raise RuntimeError(f'HTTP {e.code}: {body or e.reason}')
        except urllib.error.URLError as e:
            raise RuntimeError(f'Failed to call control api: {e}')
        except Exception as e:
            raise RuntimeError(f'Failed to call control api: {e}')

        try:
            result = json.loads(response_text or '{}')
        except Exception:
            raise RuntimeError(f'Invalid control api response: {response_text}')

        if not isinstance(result, dict):
            raise RuntimeError('Invalid control api response')

        if result.get('code') != 0:
            raise RuntimeError(result.get('message') or 'Control api failed')

        return result.get('data') or {}

    # add server端控制命令转发 2026-04-10 00:00
    def force_kill(self):
        payload = self._post_control_command('kill')
        yield 1, f'force_kill sent -> client_id={payload.get("client_id", self._get_client_id())}, command=kill'

    # add server端控制命令转发 2026-04-10 00:00
    def force_reset(self):
        payload = self._post_control_command('reset')
        yield 1, f'force_reset sent -> client_id={payload.get("client_id", self._get_client_id())}, command=reset'

    def force_spawn(self):
        payload = self._post_control_command('spawn')
        yield 1, f'force_spawn sent -> client_id={payload.get("client_id", self._get_client_id())}, command=spawn'