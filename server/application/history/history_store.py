import json
import os
import threading
import uuid
from datetime import datetime

from core.utils.files import secure_filename
from server.application.history.history_view_service import HistoryViewService
from server.application.history.history_write_service import HistoryWriteService
from server.config.config import (
    COMMAND_HISTORY_MAX_ENTRIES_PER_HOST,
    COMMAND_HISTORY_ROOT_DIR,
)


class CommandHistoryStore:
    """
    服务端命令历史存储。

    职责：
    - 按 hostname 持久化命令历史
    - 提供底层 entry 读写能力
    - 将写入 / 展示逻辑委托给 write_service / view_service
    """

    MAX_OUTPUT_RECORD_CHARS = 64 * 1024
    MAX_OUTPUT_SUMMARY_CHARS = 240
    MAX_OUTPUT_RECORDS = 200
    TIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    def __init__(self):
        self.history_root_dir = COMMAND_HISTORY_ROOT_DIR
        self.max_entries_per_host = COMMAND_HISTORY_MAX_ENTRIES_PER_HOST
        self._lock = threading.RLock()
        self.artifact_service = None

        self.write_service = HistoryWriteService(self)
        self.view_service = HistoryViewService(self)

        self._prepare_dirs()

    def _prepare_dirs(self):
        os.makedirs(self.history_root_dir, exist_ok=True)

    def _normalize_hostname(self, hostname: str) -> str:
        safe_name = secure_filename((hostname or '').strip())
        return safe_name or 'unknown_host'

    def _get_history_file_path(self, hostname: str) -> str:
        normalized = self._normalize_hostname(hostname)
        return os.path.join(self.history_root_dir, f'{normalized}.json')

    def _read_entries(self, hostname: str) -> list:
        file_path = self._get_history_file_path(hostname)
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

    def _write_entries(self, hostname: str, entries: list):
        file_path = self._get_history_file_path(hostname)
        with open(file_path, 'w', encoding='utf-8') as file_obj:
            json.dump(entries, file_obj, ensure_ascii=False, indent=2)

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
        info = getattr(conn, 'info', {}) or {}
        started_text = self._now_text()

        return {
            'entry_id': uuid.uuid4().hex,
            'time': started_text,
            'started_at': started_text,
            'finished_at': '',
            'duration_ms': 0,

            'command': command,
            'source': source,
            'status': 'running',
            'final_status': '',

            'hostname': info.get('hostname') or 'unknown_host',
            'client_id': info.get('id') or '',
            'addr': info.get('addr') or '',
            'cwd_start': info.get('cwd') or '',
            'cwd_end': '',

            'is_pinned': False,
            'pinned_at': '',
            'pin_order': 0,

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

    def _get_hostname_from_conn(self, conn) -> str:
        info = getattr(conn, 'info', {}) or {}
        return info.get('hostname') or 'unknown_host'

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
            text = self._safe_text(item.get('text')).strip()
            if text:
                return text[:self.MAX_OUTPUT_SUMMARY_CHARS]

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
        if not isinstance(entry, dict):
            return {}

        entry['is_pinned'] = bool(entry.get('is_pinned', False))
        entry['pinned_at'] = str(entry.get('pinned_at') or '').strip()

        try:
            entry['pin_order'] = int(entry.get('pin_order', 0) or 0)
        except Exception:
            entry['pin_order'] = 0

        return entry

    def _find_latest_pinned_metadata(self, entries: list, command_text: str, skip_entry=None):
        """
        查找同 command 最近一次有效的 pin 元数据。

        返回：
        - is_pinned
        - pinned_at
        - pin_order
        """
        inherited_is_pinned = False
        inherited_pinned_at = ''
        inherited_pin_order = 0

        for item in reversed(entries):
            if item is skip_entry:
                continue

            self._normalize_entry_flags(item)
            if (item.get('command') or '') != command_text:
                continue
            if not item.get('is_pinned'):
                continue

            inherited_is_pinned = True
            inherited_pinned_at = str(item.get('pinned_at') or '').strip()
            inherited_pin_order = int(item.get('pin_order', 0) or 0)
            break

        return inherited_is_pinned, inherited_pinned_at, inherited_pin_order

    def _next_pin_order(self, entries: list) -> int:
        """
        为新的 pinned command 分配固定顺序号。

        这里不复用空洞，直接单调递增：
        - 实现简单稳定
        - 不会因为删除/取消 pin 导致其他 pinned 位置抖动
        """
        max_pin_order = 0

        for item in entries:
            self._normalize_entry_flags(item)
            if not item.get('is_pinned'):
                continue
            max_pin_order = max(max_pin_order, int(item.get('pin_order', 0) or 0))

        return max_pin_order + 1

    def _sort_pinned_snapshot_items(self, pinned_items: list) -> list:
        """
        对 pinned 快照项做稳定排序。

        规则：
        - 先按 pin_order 升序
        - 老数据没有 pin_order 时，再退化到 pinned_at
        - 最后再用 command 兜底，确保排序稳定
        """
        def sort_key(item):
            self._normalize_entry_flags(item)

            pin_order = int(item.get('pin_order', 0) or 0)
            pinned_at = str(item.get('pinned_at') or '').strip()
            command_text = str(item.get('command') or '')

            has_pin_order = 0 if pin_order > 0 else 1
            fallback_time = pinned_at or '9999-12-31 23:59:59'

            return (
                has_pin_order,
                pin_order if pin_order > 0 else 0,
                fallback_time,
                command_text,
            )

        return sorted(pinned_items, key=sort_key)

    # ------------------ public write api ------------------ #
    def create_entry_for_connection(self, conn, command: str, source: str = 'cli'):
        return self.write_service.create_entry_for_connection(conn, command, source=source)

    def append_output_for_connection(self, conn, entry_id: str, status: int, text: str, eof: int = 0):
        return self.write_service.append_output_for_connection(conn, entry_id, status, text, eof=eof)

    def append_file_for_connection(self, conn, entry_id: str, file_info: dict):
        return self.write_service.append_file_for_connection(conn, entry_id, file_info)

    def update_entry_command_for_connection(self, conn, entry_id: str, command: str):
        return self.write_service.update_entry_command_for_connection(conn, entry_id, command)

    def update_entry_status_for_connection(self, conn, entry_id: str, status: str, cwd_end: str = ''):
        return self.write_service.update_entry_status_for_connection(conn, entry_id, status, cwd_end=cwd_end)

    def clear_history_for_connection(self, conn):
        return self.write_service.clear_history_for_connection(conn)

    def set_command_pinned_for_connection(self, conn, command: str, is_pinned: bool):
        return self.write_service.set_command_pinned_for_connection(conn, command, is_pinned)

    def move_pinned_command_for_connection(self, conn, command: str, direction: str):
        return self.write_service.move_pinned_command_for_connection(conn, command, direction)

    def delete_execution_entry_for_connection(self, conn, entry_id: str):
        return self.write_service.delete_execution_entry_for_connection(conn, entry_id)

    # ------------------ public view api ------------------ #
    def get_history_for_connection(self, conn) -> list:
        return self.view_service.get_history_for_connection(conn)

    def get_execution_history_for_connection(self, conn) -> list:
        return self.view_service.get_execution_history_for_connection(conn)

    def get_history_by_hostname(self, hostname: str) -> list:
        return self.view_service.get_history_by_hostname(hostname)