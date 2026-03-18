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

    def _build_entry(self, conn, command: str, source: str) -> dict:
        info = getattr(conn, 'info', {}) or {}
        return {
            'entry_id': uuid.uuid4().hex,
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'command': command,
            'source': source,
            'status': 'running',
            'hostname': info.get('hostname') or 'unknown_host',
            'client_id': info.get('id') or '',
            'addr': info.get('addr') or '',
            'cwd': info.get('cwd') or '',
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

        info = getattr(conn, 'info', {}) or {}
        hostname = info.get('hostname') or 'unknown_host'

        with self._lock:
            entries = self._read_entries(hostname)
            entry = self._build_entry(conn, command_text, source)
            entries.append(entry)
            if len(entries) > self.max_entries_per_host:
                entries = entries[-self.max_entries_per_host:]
            self._write_entries(hostname, entries)
            return entry['entry_id']

    def update_entry_status_for_connection(self, conn, entry_id: str, status: str):
        """
        更新指定历史记录的状态
        """
        if conn is None or not entry_id:
            return

        info = getattr(conn, 'info', {}) or {}
        hostname = info.get('hostname') or 'unknown_host'

        with self._lock:
            entries = self._read_entries(hostname)
            changed = False

            for item in reversed(entries):
                if item.get('entry_id') == entry_id:
                    item['status'] = status
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

        info = getattr(conn, 'info', {}) or {}
        hostname = info.get('hostname') or 'unknown_host'

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

    def get_history_for_connection(self, conn) -> list:
        """
        获取指定连接的默认历史视图：
        去重，只保留每条命令的最新记录
        """
        if conn is None:
            return []

        info = getattr(conn, 'info', {}) or {}
        hostname = info.get('hostname') or 'unknown_host'

        with self._lock:
            entries = self._read_entries(hostname)

        return self._build_deduplicated_latest_view(entries)

    def get_history_by_hostname(self, hostname: str) -> list:
        """
        按 hostname 读取默认历史视图
        """
        hostname_text = (hostname or '').strip() or 'unknown_host'

        with self._lock:
            entries = self._read_entries(hostname_text)

        return self._build_deduplicated_latest_view(entries)