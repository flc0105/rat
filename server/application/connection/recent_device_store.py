import json
import os
from datetime import datetime


class RecentDeviceStore:
    """
    最近见过的设备缓存。

    规则：
    - 以 hostname 为维度
    - 同 hostname 仅保留一条
    - 在线设备写入时覆盖旧记录
    - 下线时更新 offline 状态和时间
    """

    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)

    def _normalize_hostname_key(self, hostname: str) -> str:
        value = str(hostname or '').strip()
        return value.lower()

    def _now_iso(self) -> str:
        return datetime.now().isoformat()

    def _read_all(self) -> dict:
        if not os.path.isfile(self.file_path):
            return {}

        try:
            with open(self.file_path, 'r', encoding='utf-8') as fp:
                data = json.load(fp)
            if isinstance(data, dict):
                return data
        except Exception:
            pass

        return {}

    def _write_all(self, data: dict):
        temp_path = f'{self.file_path}.tmp'
        with open(temp_path, 'w', encoding='utf-8') as fp:
            json.dump(data, fp, ensure_ascii=False, indent=2)
        os.replace(temp_path, self.file_path)

    def upsert_from_connection(self, connection_payload: dict):
        if not isinstance(connection_payload, dict):
            return

        hostname = str(connection_payload.get('hostname') or '').strip()
        if not hostname:
            return

        key = self._normalize_hostname_key(hostname)
        if not key:
            return

        current = self._read_all()
        previous = current.get(key, {}) if isinstance(current.get(key), dict) else {}

        record = {
            'hostname': hostname,
            'client_id': str(connection_payload.get('client_id') or previous.get('client_id') or ''),
            'addr': str(connection_payload.get('addr') or previous.get('addr') or ''),
            'os_type': str(connection_payload.get('os_type') or previous.get('os_type') or ''),
            'os_ver': str(connection_payload.get('os_ver') or previous.get('os_ver') or ''),
            'integrity': str(connection_payload.get('integrity') or previous.get('integrity') or ''),
            'cwd': str(connection_payload.get('cwd') or previous.get('cwd') or ''),
            'build_version': str(connection_payload.get('build_version') or previous.get('build_version') or ''),
            'python_ver': connection_payload.get('python_ver') or previous.get('python_ver') or '',
            'process_id': connection_payload.get('process_id') or previous.get('process_id') or '',
            'launch_command': connection_payload.get('launch_command') or previous.get('launch_command') or '',
            'username': connection_payload.get('username') or previous.get('username') or '',
            'process_name': connection_payload.get('process_name') or previous.get('process_name') or '',
            'http_transfer_mode': connection_payload.get('http_transfer_mode') or previous.get('http_transfer_mode') or '',
            'python_execution_mode': connection_payload.get('python_execution_mode') or previous.get('python_execution_mode') or '',
            'remote_watchdog_enabled': connection_payload.get('remote_watchdog_enabled'),
            'local_watchdog_enabled': connection_payload.get('local_watchdog_enabled'),
            'connected_at': str(connection_payload.get('connected_at') or previous.get('connected_at') or ''),
            'disconnected_at': str(connection_payload.get('disconnected_at') or ''),
            'last_seen_at': str(connection_payload.get('last_seen_at') or previous.get('last_seen_at') or ''),
            'last_heartbeat_sent_at': str(connection_payload.get('last_heartbeat_sent_at') or previous.get('last_heartbeat_sent_at') or ''),
            'last_heartbeat_ack_at': str(connection_payload.get('last_heartbeat_ack_at') or previous.get('last_heartbeat_ack_at') or ''),
            'last_rtt_ms': connection_payload.get('last_rtt_ms'),
            'stale_after_seconds': connection_payload.get('stale_after_seconds') or previous.get('stale_after_seconds') or 45,
            'connection_state': str(connection_payload.get('connection_state') or previous.get('connection_state') or 'offline'),
            'recent_cached': True,
            'recent_updated_at': self._now_iso(),
        }

        current[key] = record
        self._write_all(current)

    def mark_offline(self, hostname: str, disconnected_at: str = ''):
        key = self._normalize_hostname_key(hostname)
        if not key:
            return

        current = self._read_all()
        record = current.get(key)
        if not isinstance(record, dict):
            return

        record['connection_state'] = 'offline'
        record['disconnected_at'] = str(disconnected_at or self._now_iso())
        record['recent_cached'] = True
        record['recent_updated_at'] = self._now_iso()
        current[key] = record
        self._write_all(current)

    def list_recent_devices(self) -> list[dict]:
        current = self._read_all()
        items = [value for value in current.values() if isinstance(value, dict)]

        items.sort(
            key=lambda item: str(
                item.get('last_seen_at')
                or item.get('connected_at')
                or item.get('disconnected_at')
                or item.get('recent_updated_at')
                or ''
            ),
            reverse=True,
        )
        return items