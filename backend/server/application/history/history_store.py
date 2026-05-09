import json
import os
import threading
import uuid
from datetime import datetime

from core.utils.files import secure_filename
from server.application.history.history_view_service import HistoryViewService
from server.application.history.history_write_service import HistoryWriteService
from server.application.history.pinned_command_store import PinnedCommandStore
from server.config.config import (
    COMMAND_HISTORY_MAX_ENTRIES_PER_HOST,
    COMMAND_HISTORY_MAX_OUTPUT_RECORD_CHARS,
    COMMAND_HISTORY_MAX_OUTPUT_RECORDS,
    COMMAND_HISTORY_MAX_OUTPUT_SUMMARY_CHARS,
    COMMAND_HISTORY_ROOT_DIR,
)


class CommandHistoryStore:
    """
    服务端命令历史存储。

    职责：
    - 按 machine_id 持久化命令历史
    - 提供底层 entry 读写能力
    - 将写入 / 展示逻辑委托给 write_service / view_service
    """

    MAX_OUTPUT_RECORD_CHARS = COMMAND_HISTORY_MAX_OUTPUT_RECORD_CHARS
    MAX_OUTPUT_SUMMARY_CHARS = COMMAND_HISTORY_MAX_OUTPUT_SUMMARY_CHARS
    MAX_OUTPUT_RECORDS = COMMAND_HISTORY_MAX_OUTPUT_RECORDS
    TIME_FORMAT = '%Y-%m-%d %H:%M:%S'
    ENTRY_PIN_FIELDS = ('is_pinned', 'pinned_at', 'pin_order')

    def __init__(self):
        self.history_root_dir = COMMAND_HISTORY_ROOT_DIR
        self.max_entries_per_host = COMMAND_HISTORY_MAX_ENTRIES_PER_HOST
        self._lock = threading.RLock()
        self.artifact_service = None

        self._prepare_dirs()
        self.pinned_store = PinnedCommandStore(self.history_root_dir, self._now_text)
        self.write_service = HistoryWriteService(self)
        self.view_service = HistoryViewService(self)

    def _prepare_dirs(self):
        os.makedirs(self.history_root_dir, exist_ok=True)

    def _normalize_machine_id(self, machine_id: str) -> str:
        safe_name = secure_filename((machine_id or '').strip())
        return safe_name or 'unknown_machine'

    def _get_history_file_path(self, machine_id: str) -> str:
        normalized = self._normalize_machine_id(machine_id)
        return os.path.join(self.history_root_dir, f'{normalized}.json')

    def _read_entries(self, machine_id: str) -> list:
        file_path = self._get_history_file_path(machine_id)
        if not os.path.isfile(file_path):
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as file_obj:
                payload = json.load(file_obj)
                if isinstance(payload, list):
                    return payload
        except Exception:
            pass

        return []

    def _strip_entry_pin_fields(self, entry: dict) -> dict:
        if not isinstance(entry, dict):
            return {}

        for field in self.ENTRY_PIN_FIELDS:
            entry.pop(field, None)
        return entry

    def _strip_entries_pin_fields(self, entries: list) -> list:
        return [self._strip_entry_pin_fields(item) for item in entries or [] if isinstance(item, dict)]

    def _has_entry_pin_fields(self, entries: list) -> bool:
        for item in entries or []:
            if not isinstance(item, dict):
                continue
            if any(field in item for field in self.ENTRY_PIN_FIELDS):
                return True
        return False

    def _write_entries(self, machine_id: str, entries: list):
        file_path = self._get_history_file_path(machine_id)
        clean_entries = self._strip_entries_pin_fields(entries)
        with open(file_path, 'w', encoding='utf-8') as file_obj:
            json.dump(clean_entries, file_obj, ensure_ascii=False, indent=2)

    def _now_text(self) -> str:
        return datetime.now().strftime(self.TIME_FORMAT)

    def _parse_time_text(self, value: str):
        text = str(value or '').strip()
        if not text:
            return None

        try:
            return datetime.strptime(text, self.TIME_FORMAT)
        except Exception:
            return None

    def _build_entry(self, conn, command: str, source: str) -> dict:
        session_info = getattr(conn, 'session_info', None)
        started_text = self._now_text()

        return {
            'entry_id': uuid.uuid4().hex,
            'time': started_text,
            'started_at': started_text,
            'finished_at': '',
            'duration_ms': 0,
            'command': command,
            'raw_command': command,
            'source': source,
            'status': 'running',
            'final_status': '',
            'hostname': getattr(session_info, 'hostname', '') or 'unknown_host',
            'machine_id': getattr(session_info, 'machine_id', '') or 'unknown_machine',
            'client_id': getattr(session_info, 'client_id', '') or '',
            'addr': getattr(session_info, 'addr', '') or '',
            'cwd_start': getattr(session_info, 'cwd', '') or '',
            'cwd_end': '',
            'has_output': False,
            'output_summary': '',
            'output_line_count': 0,
            'output_chunk_count': 0,
            'output_char_count': 0,
            'output_stored_char_count': 0,
            'output_truncated': False,
            'output_record_seq': 0,
            'output_records': [],
            'has_files': False,
            'file_count': 0,
            'files': [],
        }

    def _trim_entries(self, entries: list) -> list:
        if len(entries) > self.max_entries_per_host:
            return entries[-self.max_entries_per_host:]
        return entries

    def _get_machine_id_from_conn(self, conn) -> str:
        session_info = getattr(conn, 'session_info', None)
        return getattr(session_info, 'machine_id', '') or 'unknown_machine'

    def _find_entry(self, entries: list, entry_id: str):
        for item in reversed(entries):
            if item.get('entry_id') == entry_id:
                return item
        return None

    def _safe_text(self, text) -> str:
        if text is None:
            return ''
        return str(text)

    def _count_output_lines(self, text: str) -> int:
        if not text:
            return 0
        return max(len(text.splitlines()), 1)

    def _build_output_summary(self, entry: dict) -> str:
        if entry.get('has_files'):
            file_count = entry.get('file_count', 0)
            if file_count > 0:
                return f'Produced {file_count} file(s)'

        records = entry.get('output_records') or []
        for item in reversed(records):
            text = self._safe_text(item.get('text'))
            if not text:
                continue

            text = text.strip()
            if not text:
                continue

            if '\n' not in text and '\r' not in text:
                return text[:self.MAX_OUTPUT_SUMMARY_CHARS]

            break

        status = entry.get('status') or ''
        if status == 'success':
            return 'Command completed'
        if status == 'error':
            return 'Command failed'
        return 'No output'

    def _update_duration(self, entry: dict):
        started_at = entry.get('started_at') or ''
        finished_at = entry.get('finished_at') or ''
        start_dt = self._parse_time_text(started_at)
        end_dt = self._parse_time_text(finished_at)

        if start_dt is None or end_dt is None:
            entry['duration_ms'] = 0
            return

        entry['duration_ms'] = max(int((end_dt - start_dt).total_seconds() * 1000), 0)

    def _normalize_entry_flags(self, entry: dict) -> dict:
        """
        兼容旧调用名：execution history entry 不再承载 pin 字段。
        """
        return self._strip_entry_pin_fields(entry)

    def create_entry_for_connection(self, conn, command: str, source: str = 'cli'):
        return self.write_service.create_entry_for_connection(conn, command, source=source)

    def append_output_for_connection(self, conn, entry_id: str, status: int, text: str, eof: int = 0):
        return self.write_service.append_output_for_connection(conn, entry_id, status, text, eof=eof)

    def append_file_for_connection(self, conn, entry_id: str, artifact: dict):
        return self.write_service.append_file_for_connection(conn, entry_id, artifact)

    def update_entry_command_for_connection(self, conn, entry_id: str, command: str):
        return self.write_service.update_entry_command_for_connection(conn, entry_id, command)

    def update_entry_status_for_connection(self, conn, entry_id: str, status: str, cwd_end: str = ''):
        return self.write_service.update_entry_status_for_connection(conn, entry_id, status, cwd_end=cwd_end)

    def clear_history_for_connection(self, conn):
        return self.write_service.clear_history_for_connection(conn)

    def clear_history_by_machine_id(self, machine_id: str):
        return self.write_service.clear_history_by_machine_id(machine_id)

    def set_command_pinned_for_connection(self, conn, command: str, is_pinned: bool):
        return self.write_service.set_command_pinned_for_connection(conn, command, is_pinned)

    def set_command_pinned_by_machine_id(self, machine_id: str, command: str, is_pinned: bool):
        return self.write_service.set_command_pinned_by_machine_id(machine_id, command, is_pinned)

    def move_pinned_command_by_machine_id(self, machine_id: str, command: str, direction: str):
        return self.write_service.move_pinned_command_by_machine_id(machine_id, command, direction)

    def delete_execution_entry_by_machine_id(self, machine_id: str, entry_id: str):
        return self.write_service.delete_execution_entry_by_machine_id(machine_id, entry_id)

    def get_history_for_connection(self, conn) -> list:
        return self.view_service.get_history_for_connection(conn)

    def get_execution_history_for_connection(self, conn) -> list:
        return self.view_service.get_execution_history_for_connection(conn)

    def get_history_by_machine_id(self, machine_id: str) -> list:
        return self.view_service.get_history_by_machine_id(machine_id)
