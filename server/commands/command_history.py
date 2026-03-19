import json
import os
import threading
import uuid
from datetime import datetime

from core.utils.files import secure_filename
from server.config.config import (
    COMMAND_HISTORY_MAX_ENTRIES_PER_HOST,
    COMMAND_HISTORY_ROOT_DIR,
)


class CommandHistoryStore:
    """
    服务端命令历史存储。

    职责：
    - 按 hostname 持久化命令历史
    - 同时供 CLI / Web 读取
    - 控制最大保留条数
    - 保存所有命令，但默认展示去重后的最新记录
    """

    MAX_OUTPUT_RECORD_CHARS = 64 * 1024
    MAX_OUTPUT_SUMMARY_CHARS = 240
    MAX_OUTPUT_RECORDS = 200

    def __init__(self):
        self.history_root_dir = COMMAND_HISTORY_ROOT_DIR
        self.max_entries_per_host = COMMAND_HISTORY_MAX_ENTRIES_PER_HOST
        self._lock = threading.RLock()
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
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def _now_iso(self) -> str:
        return datetime.now().isoformat()

    def _build_entry(self, conn, command: str, source: str) -> dict:
        info = getattr(conn, 'info', {}) or {}
        started_at = self._now_iso()
        started_text = self._now_text()

        return {
            'entry_id': uuid.uuid4().hex,
            'time': started_text,
            'started_at': started_at,
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

            'has_output': False,
            'output_summary': '',
            'output_line_count': 0,
            'output_chunk_count': 0,
            'output_char_count': 0,
            'output_stored_char_count': 0,
            'output_truncated': False,
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
        if not started_at or not finished_at:
            entry['duration_ms'] = 0
            return

        try:
            start_dt = datetime.fromisoformat(started_at)
            end_dt = datetime.fromisoformat(finished_at)
            entry['duration_ms'] = max(int((end_dt - start_dt).total_seconds() * 1000), 0)
        except Exception:
            entry['duration_ms'] = 0

    def _build_file_record(self, file_info: dict) -> dict:
        return {
            'original_name': file_info.get('original_name', ''),
            'saved_name': file_info.get('saved_name', ''),
            'saved_path': file_info.get('saved_path', ''),
            'size': file_info.get('size', 0),
            'created_at': file_info.get('created_at', self._now_text()),
            'download_url': file_info.get('download_url', ''),
        }

    def create_entry_for_connection(self, conn, command: str, source: str = 'cli'):
        """
        为指定连接创建一条命令历史，并返回 entry_id
        """
        if conn is None:
            return ''

        command_text = (command or '').strip()
        if not command_text:
            return ''

        hostname = self._get_hostname_from_conn(conn)

        with self._lock:
            entries = self._read_entries(hostname)
            entry = self._build_entry(conn, command_text, source)
            entries.append(entry)
            entries = self._trim_entries(entries)
            self._write_entries(hostname, entries)
            return entry['entry_id']

    def append_output_for_connection(self, conn, entry_id: str, status: int, text: str, eof: int = 0):
        """
        为指定执行记录追加输出分片
        """
        if conn is None or not entry_id:
            return

        hostname = self._get_hostname_from_conn(conn)
        output_text = self._safe_text(text)

        with self._lock:
            entries = self._read_entries(hostname)
            entry = self._find_entry(entries, entry_id)
            if entry is None:
                return

            entry['has_output'] = entry.get('has_output', False) or bool(output_text)
            entry['output_chunk_count'] = int(entry.get('output_chunk_count', 0)) + 1
            entry['output_line_count'] = int(entry.get('output_line_count', 0)) + self._count_output_lines(output_text)
            entry['output_char_count'] = int(entry.get('output_char_count', 0)) + len(output_text)

            records = entry.setdefault('output_records', [])
            stored_char_count = int(entry.get('output_stored_char_count', 0))
            remaining_chars = max(self.MAX_OUTPUT_RECORD_CHARS - stored_char_count, 0)

            stored_text = ''
            if output_text and remaining_chars > 0 and len(records) < self.MAX_OUTPUT_RECORDS:
                stored_text = output_text[:remaining_chars]
                if len(stored_text) < len(output_text):
                    entry['output_truncated'] = True
                records.append({
                    'status': status,
                    'text': stored_text,
                    'time': self._now_text(),
                    'eof': eof,
                })
                entry['output_stored_char_count'] = stored_char_count + len(stored_text)
            elif output_text:
                entry['output_truncated'] = True

            entry['output_summary'] = self._build_output_summary(entry)
            self._write_entries(hostname, entries)

    def append_file_for_connection(self, conn, entry_id: str, file_info: dict):
        """
        为指定执行记录追加产出文件信息
        """
        if conn is None or not entry_id or not isinstance(file_info, dict):
            return

        hostname = self._get_hostname_from_conn(conn)

        with self._lock:
            entries = self._read_entries(hostname)
            entry = self._find_entry(entries, entry_id)
            if entry is None:
                return

            files = entry.setdefault('files', [])
            files.append(self._build_file_record(file_info))
            entry['has_files'] = True
            entry['file_count'] = len(files)
            entry['output_summary'] = self._build_output_summary(entry)
            self._write_entries(hostname, entries)

    def update_entry_status_for_connection(self, conn, entry_id: str, status: str, cwd_end: str = ''):
        """
        更新指定历史记录的状态，并补全结束时间 / 耗时 / cwd_end
        """
        if conn is None or not entry_id:
            return

        hostname = self._get_hostname_from_conn(conn)

        with self._lock:
            entries = self._read_entries(hostname)
            changed = False

            for item in reversed(entries):
                if item.get('entry_id') == entry_id:
                    item['status'] = status
                    item['final_status'] = status
                    item['finished_at'] = self._now_iso()
                    item['cwd_end'] = cwd_end or (getattr(conn, 'info', {}) or {}).get('cwd', '') or item.get('cwd_end', '')
                    item['time'] = item.get('time') or self._now_text()
                    self._update_duration(item)
                    item['output_summary'] = self._build_output_summary(item)
                    changed = True
                    break

            if changed:
                self._write_entries(hostname, entries)

    def clear_history_for_connection(self, conn):
        """
        清空指定连接的命令历史
        """
        if conn is None:
            return

        hostname = self._get_hostname_from_conn(conn)

        with self._lock:
            self._write_entries(hostname, [])

    def _build_deduplicated_latest_view(self, entries: list) -> list:
        """
        构造默认展示视图：
        - 保留所有原始记录
        - 展示时按时间倒序去重
        - 相同 command 只保留最新一条
        """
        seen = set()
        result = []

        for item in reversed(entries):
            command_text = item.get('command') or ''
            if command_text in seen:
                continue
            seen.add(command_text)

            copied = dict(item)
            result.append(copied)

        for index, item in enumerate(result, start=1):
            item['index'] = index

        return result

    def _build_execution_history_view(self, entries: list) -> list:
        """
        构造完整执行历史视图：
        - 不去重
        - 按最新优先
        - 保留完整执行元数据
        """
        result = []

        for item in reversed(entries):
            copied = dict(item)
            copied['output_records'] = list(item.get('output_records') or [])
            copied['files'] = list(item.get('files') or [])
            result.append(copied)

        for index, item in enumerate(result, start=1):
            item['index'] = index

        return result

    def get_history_for_connection(self, conn) -> list:
        """
        获取指定连接的默认历史视图：
        去重，只保留每条命令的最新记录
        """
        if conn is None:
            return []

        hostname = self._get_hostname_from_conn(conn)

        with self._lock:
            entries = self._read_entries(hostname)

        return self._build_deduplicated_latest_view(entries)

    def get_execution_history_for_connection(self, conn) -> list:
        """
        获取指定连接的完整执行历史视图
        """
        if conn is None:
            return []

        hostname = self._get_hostname_from_conn(conn)

        with self._lock:
            entries = self._read_entries(hostname)

        return self._build_execution_history_view(entries)

    def get_history_by_hostname(self, hostname: str) -> list:
        """
        按 hostname 读取默认历史视图
        """
        hostname_text = (hostname or '').strip() or 'unknown_host'

        with self._lock:
            entries = self._read_entries(hostname_text)

        return self._build_deduplicated_latest_view(entries)