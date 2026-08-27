import json
import os
import threading
from datetime import datetime

from core.utils.files import secure_filename


class ConnectionHistoryStore:
    """
    服务端机器连接历史存储。

    职责：
    - 按 machine_id 持久化每个 client_id(session) 的连接生命周期
    - 保存连接时的必要设备快照
    - 记录上线、最后活动、下线和在线时长
    """

    SCHEMA_VERSION = 1

    def __init__(self, root_dir: str):
        self.root_dir = os.path.abspath(root_dir)
        self._lock = threading.RLock()
        os.makedirs(self.root_dir, exist_ok=True)

    def _now_iso(self) -> str:
        return datetime.now().isoformat()

    def _safe_parse_iso(self, value: str):
        text = str(value or '').strip()
        if not text:
            return None
        try:
            return datetime.fromisoformat(text)
        except Exception:
            return None

    def _normalize_machine_id(self, machine_id: str) -> str:
        safe_name = secure_filename(str(machine_id or '').strip())
        return safe_name or 'unknown_machine'

    def _get_file_path(self, machine_id: str) -> str:
        return os.path.join(self.root_dir, f'{self._normalize_machine_id(machine_id)}.json')

    def _empty_payload(self, machine_id: str) -> dict:
        return {
            'schema_version': self.SCHEMA_VERSION,
            'machine_id': str(machine_id or '').strip(),
            'tracking_started_at': '',
            'sessions': [],
        }

    def _read_payload_unlocked(self, machine_id: str) -> dict:
        file_path = self._get_file_path(machine_id)
        if not os.path.isfile(file_path):
            return self._empty_payload(machine_id)

        try:
            with open(file_path, 'r', encoding='utf-8') as file_obj:
                payload = json.load(file_obj)
            if isinstance(payload, dict):
                payload.setdefault('schema_version', self.SCHEMA_VERSION)
                payload.setdefault('machine_id', str(machine_id or '').strip())
                payload.setdefault('tracking_started_at', '')
                payload.setdefault('sessions', [])
                if not isinstance(payload.get('sessions'), list):
                    payload['sessions'] = []
                return payload
        except Exception:
            pass

        return self._empty_payload(machine_id)

    def _write_payload_unlocked(self, machine_id: str, payload: dict):
        file_path = self._get_file_path(machine_id)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as file_obj:
            json.dump(payload, file_obj, ensure_ascii=False, indent=2)

    def _find_session(self, sessions: list, client_id: str):
        target_client_id = str(client_id or '').strip()
        if not target_client_id:
            return None

        for item in reversed(sessions or []):
            if not isinstance(item, dict):
                continue
            if str(item.get('client_id') or '').strip() == target_client_id:
                return item
        return None

    def _update_duration(self, session: dict, now_value: str = ''):
        connected_at = self._safe_parse_iso(session.get('connected_at'))
        end_value = session.get('disconnected_at') or now_value
        ended_at = self._safe_parse_iso(end_value)

        if connected_at is None or ended_at is None:
            session['duration_ms'] = 0
            return

        session['duration_ms'] = max(int((ended_at - connected_at).total_seconds() * 1000), 0)

    def _apply_connection_snapshot(self, session: dict, connection: dict):
        snapshot_fields = (
            'machine_id',
            'client_id',
            'hostname',
            'addr',
            'os_type',
            'os_alias',
            'os_ver',
            'os_name',
            'os_full',
            'arch',
            'manufacturer',
            'model',
            'integrity',
            'cwd',
            'build_version',
            'python_ver',
            'process_id',
            'launch_command',
            'username',
            'process_name',
            'http_transfer_mode',
            'python_execution_mode',
            'remote_watchdog_enabled',
            'local_watchdog_enabled',
        )

        for field in snapshot_fields:
            value = connection.get(field)
            if value is None:
                continue
            if isinstance(value, str) and not value and field in session:
                continue
            session[field] = value

        last_seen_at = str(connection.get('last_seen_at') or '').strip()
        if last_seen_at:
            session['last_seen_at'] = last_seen_at

    def record_connected(self, connection: dict):
        machine_id = str((connection or {}).get('machine_id') or '').strip()
        client_id = str((connection or {}).get('client_id') or '').strip()
        if not machine_id or not client_id:
            return

        connected_at = str(connection.get('connected_at') or self._now_iso()).strip()

        with self._lock:
            payload = self._read_payload_unlocked(machine_id)
            sessions = payload.setdefault('sessions', [])

            # 如果服务端上次异常退出，旧 session 可能没有收到正常 close。
            # 新 session 建立时，用旧记录最后活动时间收口，避免永久显示在线。
            for item in sessions:
                if not isinstance(item, dict):
                    continue
                if str(item.get('client_id') or '').strip() == client_id:
                    continue
                if str(item.get('disconnected_at') or '').strip():
                    continue

                fallback_disconnected_at = str(item.get('last_seen_at') or item.get('connected_at') or connected_at).strip()
                item['disconnected_at'] = fallback_disconnected_at
                item['connection_state'] = 'interrupted'
                item['disconnect_reason'] = 'server_interrupted'
                self._update_duration(item)

            session = self._find_session(sessions, client_id)
            if session is None:
                session = {
                    'client_id': client_id,
                    'machine_id': machine_id,
                    'connected_at': connected_at,
                    'disconnected_at': '',
                    'last_seen_at': str(connection.get('last_seen_at') or connected_at).strip(),
                    'duration_ms': 0,
                    'connection_state': 'online',
                    'disconnect_reason': '',
                    'tracking_source': 'connection_lifecycle',
                    'commands': [],
                }
                sessions.append(session)
            else:
                session['connected_at'] = str(session.get('connected_at') or connected_at).strip()
                session['disconnected_at'] = ''
                session['connection_state'] = 'online'
                session['disconnect_reason'] = ''

            session.setdefault('commands', [])
            self._apply_connection_snapshot(session, connection)
            self._update_duration(session, now_value=self._now_iso())

            if not payload.get('tracking_started_at'):
                payload['tracking_started_at'] = connected_at

            payload['machine_id'] = machine_id
            self._write_payload_unlocked(machine_id, payload)

    def record_heartbeat(self, connection: dict):
        machine_id = str((connection or {}).get('machine_id') or '').strip()
        client_id = str((connection or {}).get('client_id') or '').strip()
        if not machine_id or not client_id:
            return

        with self._lock:
            payload = self._read_payload_unlocked(machine_id)
            sessions = payload.setdefault('sessions', [])
            session = self._find_session(sessions, client_id)

            if session is None:
                self.record_connected(connection)
                return

            self._apply_connection_snapshot(session, connection)
            if not str(session.get('disconnected_at') or '').strip():
                session['connection_state'] = 'online'
                self._update_duration(session, now_value=self._now_iso())

            self._write_payload_unlocked(machine_id, payload)

    def reconcile_active_sessions(self, machine_id: str, active_client_ids: set[str]):
        machine_id_text = str(machine_id or '').strip()
        if not machine_id_text:
            return

        active_ids = {
            str(client_id or '').strip()
            for client_id in active_client_ids or set()
            if str(client_id or '').strip()
        }

        with self._lock:
            payload = self._read_payload_unlocked(machine_id_text)
            changed = False

            for item in payload.get('sessions') or []:
                if not isinstance(item, dict):
                    continue
                client_id = str(item.get('client_id') or '').strip()
                if client_id in active_ids:
                    continue
                if str(item.get('disconnected_at') or '').strip():
                    continue

                # 内存中已经没有这个 session，说明服务端没能拿到正常 close 回调。
                item['disconnected_at'] = str(item.get('last_seen_at') or item.get('connected_at') or self._now_iso()).strip()
                item['connection_state'] = 'interrupted'
                item['disconnect_reason'] = 'server_interrupted'
                self._update_duration(item)
                changed = True

            if changed:
                self._write_payload_unlocked(machine_id_text, payload)

    def record_disconnected(self, connection: dict):
        machine_id = str((connection or {}).get('machine_id') or '').strip()
        client_id = str((connection or {}).get('client_id') or '').strip()
        if not machine_id or not client_id:
            return

        disconnected_at = str(connection.get('disconnected_at') or self._now_iso()).strip()

        with self._lock:
            payload = self._read_payload_unlocked(machine_id)
            sessions = payload.setdefault('sessions', [])
            session = self._find_session(sessions, client_id)

            if session is None:
                session = {
                    'client_id': client_id,
                    'machine_id': machine_id,
                    'connected_at': str(connection.get('connected_at') or '').strip(),
                    'last_seen_at': str(connection.get('last_seen_at') or '').strip(),
                    'tracking_source': 'connection_lifecycle',
                    'commands': [],
                }
                sessions.append(session)

            self._apply_connection_snapshot(session, connection)
            session['disconnected_at'] = disconnected_at
            session['connection_state'] = 'offline'
            session['disconnect_reason'] = 'disconnected'
            self._update_duration(session)

            if not payload.get('tracking_started_at'):
                payload['tracking_started_at'] = str(session.get('connected_at') or disconnected_at).strip()

            payload['machine_id'] = machine_id
            self._write_payload_unlocked(machine_id, payload)

    def _build_command_snapshot(self, entry: dict) -> dict:
        return {
            'entry_id': str(entry.get('entry_id') or '').strip(),
            'command': entry.get('command') or '',
            'source': entry.get('source') or '',
            'status': entry.get('status') or '',
            'final_status': entry.get('final_status') or '',
            'started_at': entry.get('started_at') or entry.get('time') or '',
            'finished_at': entry.get('finished_at') or '',
            'duration_ms': int(entry.get('duration_ms', 0) or 0),
            'cwd_start': entry.get('cwd_start') or '',
            'cwd_end': entry.get('cwd_end') or '',
            'hostname': entry.get('hostname') or '',
            'addr': entry.get('addr') or '',
            'output_summary': entry.get('output_summary') or '',
            'output_line_count': int(entry.get('output_line_count', 0) or 0),
            'output_char_count': int(entry.get('output_char_count', 0) or 0),
            'output_truncated': bool(entry.get('output_truncated', False)),
            'file_count': int(entry.get('file_count', 0) or 0),
        }

    def record_command_snapshot(self, entry: dict) -> bool:
        if not isinstance(entry, dict):
            return False

        machine_id = str(entry.get('machine_id') or '').strip()
        client_id = str(entry.get('client_id') or '').strip()
        entry_id = str(entry.get('entry_id') or '').strip()
        if not machine_id or not client_id or not entry_id:
            return False

        with self._lock:
            payload = self._read_payload_unlocked(machine_id)
            session = self._find_session(payload.get('sessions') or [], client_id)
            if session is None:
                return False

            commands = session.setdefault('commands', [])
            command_snapshot = self._build_command_snapshot(entry)
            replaced = False

            for index, item in enumerate(commands):
                if not isinstance(item, dict):
                    continue
                if str(item.get('entry_id') or '').strip() != entry_id:
                    continue
                commands[index] = command_snapshot
                replaced = True
                break

            if not replaced:
                commands.append(command_snapshot)

            self._write_payload_unlocked(machine_id, payload)
            return True

    def remove_command_snapshot(self, machine_id: str, entry_id: str) -> bool:
        machine_id_text = str(machine_id or '').strip()
        entry_id_text = str(entry_id or '').strip()
        if not machine_id_text or not entry_id_text:
            return False

        with self._lock:
            payload = self._read_payload_unlocked(machine_id_text)
            changed = False

            for session in payload.get('sessions') or []:
                if not isinstance(session, dict):
                    continue
                commands = session.get('commands') or []
                filtered = [
                    item for item in commands
                    if not isinstance(item, dict) or str(item.get('entry_id') or '').strip() != entry_id_text
                ]
                if len(filtered) != len(commands):
                    session['commands'] = filtered
                    changed = True

            if changed:
                self._write_payload_unlocked(machine_id_text, payload)
            return changed

    def clear_command_snapshots(self, machine_id: str):
        machine_id_text = str(machine_id or '').strip()
        if not machine_id_text:
            return

        with self._lock:
            payload = self._read_payload_unlocked(machine_id_text)
            changed = False

            for session in payload.get('sessions') or []:
                if not isinstance(session, dict):
                    continue
                if session.get('commands'):
                    session['commands'] = []
                    changed = True

            if changed:
                self._write_payload_unlocked(machine_id_text, payload)

    def get_history(self, machine_id: str) -> dict:
        machine_id_text = str(machine_id or '').strip()
        if not machine_id_text:
            return self._empty_payload('')

        with self._lock:
            payload = self._read_payload_unlocked(machine_id_text)
            now_iso = self._now_iso()
            sessions = []

            for item in reversed(payload.get('sessions') or []):
                if not isinstance(item, dict):
                    continue
                copied = dict(item)
                if not str(copied.get('disconnected_at') or '').strip():
                    copied['connection_state'] = 'online'
                    self._update_duration(copied, now_value=now_iso)
                else:
                    self._update_duration(copied)
                sessions.append(copied)

            return {
                'schema_version': payload.get('schema_version', self.SCHEMA_VERSION),
                'machine_id': payload.get('machine_id') or machine_id_text,
                'tracking_started_at': payload.get('tracking_started_at') or '',
                'sessions': sessions,
            }
