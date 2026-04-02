
import os


class HistoryViewService:
    """
    命令历史视图服务。

    职责：
    - 解析 artifact 文件展示状态
    - 构造 quick history / execution history 视图
    """

    def __init__(self, store):
        self.store = store

    def _resolve_artifact_file_view(self, file_item: dict) -> dict:
        copied = dict(file_item)
        artifact_id = (copied.get('artifact_id') or '').strip()

        if artifact_id and self.store.artifact_service is not None:
            try:
                artifact = self.store.artifact_service.get_artifact_by_id(artifact_id)
                copied.update({
                    'artifact_type': artifact.get('artifact_type', copied.get('artifact_type', '')),
                    'category': artifact.get('category', copied.get('category', '')),
                    'hostname': artifact.get('hostname', copied.get('hostname', '')),
                    'client_id': artifact.get('client_id', copied.get('client_id', '')),
                    'original_name': artifact.get('original_name', copied.get('original_name', '')),
                    'stored_name': artifact.get('stored_name', copied.get('stored_name', '')),
                    'saved_path': artifact.get('saved_path', copied.get('saved_path', '')),
                    'size': artifact.get('size', copied.get('size', 0)),
                    'created_at': artifact.get('created_at', copied.get('created_at', '')),
                    'download_url': artifact.get('download_url', copied.get('download_url', '')),
                    'raw_url': artifact.get('raw_url', copied.get('raw_url', '')),
                    'preview_url': artifact.get('preview_url', copied.get('preview_url', '')),
                    'source_type': artifact.get('source_type', copied.get('source_type', '')),
                    'related_path': artifact.get('related_path', copied.get('related_path', '')),
                    'is_available': artifact.get('is_available', True),
                    'status_text': artifact.get('status_text', ''),
                })
                return copied
            except Exception:
                copied['is_available'] = False
                copied['status_text'] = copied.get('status_text') or 'Artifact removed'
                return copied

        saved_path = copied.get('saved_path', '')
        is_available = bool(saved_path) and os.path.isfile(saved_path)
        copied['is_available'] = is_available
        copied['status_text'] = '' if is_available else 'File removed'
        return copied

    def _refresh_file_status_for_view(self, item: dict) -> dict:
        copied = dict(item)
        files = []

        for file_item in item.get('files') or []:
            files.append(self._resolve_artifact_file_view(file_item))

        copied['files'] = files
        copied['file_count'] = len(files)
        copied['has_files'] = len(files) > 0
        return copied

    def _build_deduplicated_latest_view(self, entries: list) -> list:
        """
        构造默认展示视图：
        - 保留所有原始记录
        - 展示时按时间倒序去重
        - 相同 command 只保留最新一条
        - 置顶命令固定排在最上方
        """
        seen = set()
        pinned_items = []
        normal_items = []

        for item in reversed(entries):
            self.store._normalize_entry_flags(item)
            command_text = item.get('command') or ''
            if command_text in seen:
                continue
            seen.add(command_text)

            copied = dict(item)
            copied = self._refresh_file_status_for_view(copied)

            if copied.get('is_pinned'):
                pinned_items.append(copied)
            else:
                normal_items.append(copied)

        result = pinned_items + normal_items

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
            self.store._normalize_entry_flags(item)
            copied = self._refresh_file_status_for_view(item)
            copied['output_records'] = list(item.get('output_records') or [])
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

        hostname = self.store._get_hostname_from_conn(conn)

        with self.store._lock:
            entries = self.store._read_entries(hostname)
            for item in entries:
                self.store._normalize_entry_flags(item)

        return self._build_deduplicated_latest_view(entries)

    def get_execution_history_for_connection(self, conn) -> list:
        """
        获取指定连接的完整执行历史视图
        """
        if conn is None:
            return []

        hostname = self.store._get_hostname_from_conn(conn)

        with self.store._lock:
            entries = self.store._read_entries(hostname)
            for item in entries:
                self.store._normalize_entry_flags(item)

        return self._build_execution_history_view(entries)

    def get_history_by_hostname(self, hostname: str) -> list:
        """
        按 hostname 读取默认历史视图
        """
        hostname_text = (hostname or '').strip() or 'unknown_host'

        with self.store._lock:
            entries = self.store._read_entries(hostname_text)
            for item in entries:
                self.store._normalize_entry_flags(item)

        return self._build_deduplicated_latest_view(entries)









