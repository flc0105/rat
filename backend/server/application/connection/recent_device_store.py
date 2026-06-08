import json
import os
import tempfile
import threading
from datetime import datetime

from core.utils.logger import logger


class RecentDeviceStore:
    """
    最近见过的设备缓存。

    规则：
    - 以 machine_id 为维度
    - 同 machine_id 仅保留一条
    - 在线设备写入时覆盖旧记录
    - 下线时更新 offline 状态和时间
    """

    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
        self._lock = threading.RLock()
        self._forgotten_machine_keys = set()

    def _normalize_machine_id_key(self, machine_id: str) -> str:
        value = str(machine_id or '').strip()
        return value.lower()

    def _normalize_client_id_key(self, client_id: str) -> str:
        return str(client_id or '').strip()

    def _now_iso(self) -> str:
        return datetime.now().isoformat()

    def _read_all_unlocked(self) -> dict:
        if not os.path.isfile(self.file_path):
            return {}

        try:
            with open(self.file_path, 'r', encoding='utf-8') as fp:
                data = json.load(fp)
            if isinstance(data, dict):
                return data
        except Exception:
            logger.error('RecentDeviceStore read failed: %s', self.file_path, exc_info=True)

        return {}

    def _write_all_unlocked(self, data: dict):
        dir_name = os.path.dirname(self.file_path)
        fd, temp_path = tempfile.mkstemp(
            prefix='recent_devices_',
            suffix='.tmp',
            dir=dir_name,
        )
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as fp:
                json.dump(data, fp, ensure_ascii=False, indent=2)
            os.replace(temp_path, self.file_path)
        finally:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                logger.warning('RecentDeviceStore temp cleanup failed: %s', temp_path, exc_info=True)

    def _normalize_bool_map(self, value) -> dict:
        if isinstance(value, dict):
            return {
                self._normalize_client_id_key(key): True
                for key, enabled in value.items()
                if self._normalize_client_id_key(key) and bool(enabled)
            }

        if isinstance(value, list):
            return {
                self._normalize_client_id_key(item): True
                for item in value
                if self._normalize_client_id_key(item)
            }

        return {}

    def _find_key_by_client_id_unlocked(self, current: dict, client_id: str) -> str:
        target_client_key = self._normalize_client_id_key(client_id)
        if not target_client_key:
            return ''

        for key, record in current.items():
            if not isinstance(record, dict):
                continue

            if self._normalize_client_id_key(record.get('client_id')) == target_client_key:
                return key

            hidden_client_ids = self._normalize_bool_map(record.get('hidden_client_ids'))
            if target_client_key in hidden_client_ids:
                return key

        return ''

    def _get_record_key_unlocked(self, current: dict, client_id: str = '', machine_id: str = '') -> str:
        machine_key = self._normalize_machine_id_key(machine_id)
        if machine_key:
            return machine_key

        return self._find_key_by_client_id_unlocked(current, client_id)

    def _build_device_view_prefs(self, record: dict, client_id: str = '') -> dict:
        if not isinstance(record, dict):
            return {
                'machine_alias': '',
                'device_alias': '',
                'device_hidden': False,
                'device_hidden_by_client': False,
                'device_hidden_by_machine': False,
            }

        target_client_key = self._normalize_client_id_key(client_id or record.get('client_id'))
        hidden_client_ids = self._normalize_bool_map(record.get('hidden_client_ids'))
        hidden_by_client = bool(target_client_key and hidden_client_ids.get(target_client_key))
        hidden_by_machine = bool(record.get('device_hidden_by_machine'))
        machine_alias = str(record.get('machine_alias') or '').strip()

        return {
            'machine_alias': machine_alias,
            'device_alias': machine_alias,
            'device_hidden': hidden_by_client or hidden_by_machine,
            'device_hidden_by_client': hidden_by_client,
            'device_hidden_by_machine': hidden_by_machine,
        }

    def upsert_from_connection(self, connection_payload: dict):
        if not isinstance(connection_payload, dict):
            return

        machine_id = str(connection_payload.get('machine_id') or '').strip()
        if not machine_id:
            return

        key = self._normalize_machine_id_key(machine_id)
        if not key:
            return

        connection_state = str(connection_payload.get('connection_state') or '').strip().lower()
        disconnected_at = str(connection_payload.get('disconnected_at') or '').strip()
        is_offline_payload = connection_state == 'offline' or bool(disconnected_at)

        with self._lock:
            if key in self._forgotten_machine_keys:
                if is_offline_payload:
                    return
                self._forgotten_machine_keys.discard(key)

            current = self._read_all_unlocked()
            previous = current.get(key, {}) if isinstance(current.get(key), dict) else {}

            record = {
                'recent_device_key': key,
                'machine_id': machine_id,
                # 'machine_id_version': str(connection_payload.get('machine_id_version') or previous.get('machine_id_version') or ''),
                'machine_fingerprint_basis': str(connection_payload.get('machine_fingerprint_basis') or previous.get('machine_fingerprint_basis') or ''),
                'hostname': str(connection_payload.get('hostname') or previous.get('hostname') or ''),
                'client_id': str(connection_payload.get('client_id') or previous.get('client_id') or ''),
                'addr': str(connection_payload.get('addr') or previous.get('addr') or ''),
                'os_type': str(connection_payload.get('os_type') or previous.get('os_type') or ''),
                'os_alias': str(connection_payload.get('os_alias') or previous.get('os_alias') or 'unknown'),
                'os_ver': str(connection_payload.get('os_ver') or previous.get('os_ver') or ''),


                'os_name': str(connection_payload.get('os_name') or previous.get('os_name') or ''),
                'os_full': str(connection_payload.get('os_full') or previous.get('os_full') or ''),
                'arch': str(connection_payload.get('arch') or previous.get('arch') or ''),
                'manufacturer': str(connection_payload.get('manufacturer') or previous.get('manufacturer') or ''),
                'model': str(connection_payload.get('model') or previous.get('model') or ''),

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
                'machine_alias': str(previous.get('machine_alias') or '').strip(),
                'device_hidden_by_machine': bool(previous.get('device_hidden_by_machine')),
                'hidden_client_ids': self._normalize_bool_map(previous.get('hidden_client_ids')),
                'device_view_prefs_updated_at': previous.get('device_view_prefs_updated_at') or '',
                'recent_cached': True,
                'recent_updated_at': self._now_iso(),
            }

            current[key] = record
            self._write_all_unlocked(current)

    def mark_offline(self, machine_id: str, disconnected_at: str = ''):
        key = self._normalize_machine_id_key(machine_id)
        if not key:
            return

        with self._lock:
            if key in self._forgotten_machine_keys:
                return

            current = self._read_all_unlocked()
            record = current.get(key)
            if not isinstance(record, dict):
                return

            record['recent_device_key'] = key
            record['connection_state'] = 'offline'
            record['disconnected_at'] = str(disconnected_at or self._now_iso())
            record['recent_cached'] = True
            record['recent_updated_at'] = self._now_iso()
            current[key] = record
            self._write_all_unlocked(current)

    def remove_by_identity(self, client_id: str = '', machine_id: str = '') -> dict:
        target_client_id = str(client_id or '').strip()
        target_machine_key = self._normalize_machine_id_key(machine_id)
        removed_keys = []

        with self._lock:
            current = self._read_all_unlocked()

            if target_machine_key and target_machine_key in current:
                removed_keys.append(target_machine_key)

            if target_client_id:
                for key, record in list(current.items()):
                    if not isinstance(record, dict):
                        continue
                    if str(record.get('client_id') or '').strip() == target_client_id:
                        removed_keys.append(key)

            removed_keys = sorted(set(key for key in removed_keys if key))
            forgotten_keys = set(removed_keys)
            if target_machine_key:
                forgotten_keys.add(target_machine_key)

            for key in removed_keys:
                current.pop(key, None)

            self._forgotten_machine_keys.update(forgotten_keys)

            if removed_keys:
                self._write_all_unlocked(current)

        return {
            'removed_count': len(removed_keys),
            'removed_keys': removed_keys,
        }

    def get_device_view_prefs(self, client_id: str = '', machine_id: str = '') -> dict:
        target_client_id = self._normalize_client_id_key(client_id)

        with self._lock:
            current = self._read_all_unlocked()
            key = self._get_record_key_unlocked(
                current,
                client_id=target_client_id,
                machine_id=machine_id,
            )
            record = current.get(key) if key else None

        return self._build_device_view_prefs(record, client_id=target_client_id)

    def update_device_view_prefs(self, client_id: str = '', machine_id: str = '', patch: dict = None) -> dict:
        patch = patch or {}
        target_client_id = self._normalize_client_id_key(client_id)
        target_machine_id = str(machine_id or '').strip()
        target_machine_key = self._normalize_machine_id_key(target_machine_id)

        has_machine_alias = 'machine_alias' in patch
        has_client_hidden = 'client_hidden' in patch
        has_machine_hidden = 'machine_hidden' in patch

        if not (has_machine_alias or has_client_hidden or has_machine_hidden):
            return self.get_device_view_prefs(
                client_id=target_client_id,
                machine_id=target_machine_id,
            )

        if has_client_hidden and not target_client_id:
            raise ValueError('Invalid client id')

        if (has_machine_alias or has_machine_hidden) and not target_machine_key:
            raise ValueError('Invalid machine id')

        with self._lock:
            current = self._read_all_unlocked()
            record_key = self._get_record_key_unlocked(
                current,
                client_id=target_client_id,
                machine_id=target_machine_id,
            )

            if not record_key:
                raise ValueError('Invalid device identity')

            record = current.get(record_key)
            if not isinstance(record, dict):
                record = {
                    'recent_device_key': record_key,
                    'machine_id': target_machine_id,
                    'client_id': target_client_id,
                    'recent_cached': True,
                }

            if target_machine_id:
                record['machine_id'] = target_machine_id
            if target_client_id and not str(record.get('client_id') or '').strip():
                record['client_id'] = target_client_id

            if has_machine_alias:
                machine_alias = str(patch.get('machine_alias') or '').strip()
                if machine_alias:
                    record['machine_alias'] = machine_alias
                else:
                    record.pop('machine_alias', None)

            if has_machine_hidden:
                record['device_hidden_by_machine'] = bool(patch.get('machine_hidden'))

            if has_client_hidden:
                hidden_client_ids = self._normalize_bool_map(record.get('hidden_client_ids'))
                if bool(patch.get('client_hidden')):
                    hidden_client_ids[target_client_id] = True
                else:
                    hidden_client_ids.pop(target_client_id, None)

                if hidden_client_ids:
                    record['hidden_client_ids'] = hidden_client_ids
                else:
                    record.pop('hidden_client_ids', None)

            record['recent_device_key'] = record_key
            record['recent_cached'] = True
            record['device_view_prefs_updated_at'] = self._now_iso()
            current[record_key] = record
            self._write_all_unlocked(current)

            prefs = self._build_device_view_prefs(record, client_id=target_client_id)

        return prefs

    def list_recent_devices(self) -> list[dict]:
        with self._lock:
            current = self._read_all_unlocked()

        items = [value for value in current.values() if isinstance(value, dict)]

        deduped = {}
        for item in items:
            key = str(item.get('recent_device_key') or self._normalize_machine_id_key(item.get('machine_id'))).strip()
            if not key:
                continue

            existing = deduped.get(key)
            if existing is None:
                deduped[key] = item
                continue

            existing_time = str(
                existing.get('last_seen_at')
                or existing.get('connected_at')
                or existing.get('disconnected_at')
                or existing.get('recent_updated_at')
                or ''
            )
            current_time = str(
                item.get('last_seen_at')
                or item.get('connected_at')
                or item.get('disconnected_at')
                or item.get('recent_updated_at')
                or ''
            )
            if current_time >= existing_time:
                deduped[key] = item

        results = list(deduped.values())
        results.sort(
            key=lambda item: str(
                item.get('last_seen_at')
                or item.get('connected_at')
                or item.get('disconnected_at')
                or item.get('recent_updated_at')
                or ''
            ),
            reverse=True,
        )
        return results
