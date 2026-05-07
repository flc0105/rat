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
                    'machine_id': artifact.get('machine_id', copied.get('machine_id', '')),
                    'client_id': artifact.get('client_id', copied.get('client_id', '')),
                    'original_name': artifact.get('original_name', copied.get('original_name', '')),
                    'stored_name': artifact.get('stored_name', copied.get('stored_name', '')),
                    'saved_path': artifact.get('saved_path', copied.get('saved_path', '')),
                    'size': artifact.get('size', copied.get('size', 0)),
                    'created_at': artifact.get('created_at', copied.get('created_at', '')),
                    'download_url': artifact.get('download_url', copied.get('download_url', '')),
                    'raw_url': artifact.get('raw_url', copied.get('raw_url', '')),
                    'preview_url': artifact.get('preview_url', copied.get('preview_url', '')),
                    # 'source_type': artifact.get('source_type', copied.get('source_type', '')),
                    # 'related_path': artifact.get('related_path', copied.get('related_path', '')),
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

    def _apply_quick_history_move_flags(self, pinned_items: list, normal_items: list):
        for index, item in enumerate(pinned_items):
            item['can_move_up'] = index > 0
            item['can_move_down'] = index < len(pinned_items) - 1

        for item in normal_items:
            item['can_move_up'] = False
            item['can_move_down'] = False

    def _build_latest_entry_map(self, entries: list) -> dict:
        latest_by_command = {}

        for item in reversed(entries):
            self.store._normalize_entry_flags(item)
            command_text = str(item.get('command') or '').strip()
            if not command_text or command_text in latest_by_command:
                continue
            latest_by_command[command_text] = item

        return latest_by_command

    def _build_pinned_quick_item(self, pinned_item: dict, latest_entry: dict | None) -> dict:
        command_text = str(pinned_item.get('command') or '').strip()
        snapshot = pinned_item.get('snapshot') if isinstance(pinned_item.get('snapshot'), dict) else {}
        source_item = latest_entry if isinstance(latest_entry, dict) else snapshot

        copied = dict(source_item or {})
        copied['command'] = command_text
        copied['raw_command'] = str(copied.get('raw_command') or command_text).strip()
        copied['is_pinned'] = True
        copied['pinned_at'] = str(pinned_item.get('pinned_at') or '').strip()
        copied['pin_order'] = int(pinned_item.get('pin_order', 0) or 0)

        copied = self._refresh_file_status_for_view(copied)
        return copied

    def _build_normal_quick_item(self, item: dict) -> dict:
        copied = dict(item)
        copied['is_pinned'] = False
        copied['pinned_at'] = ''
        copied['pin_order'] = 0
        copied = self._refresh_file_status_for_view(copied)
        return copied

    def _build_deduplicated_latest_view(self, entries: list, pinned_items: list | None = None) -> list:
        latest_by_command = self._build_latest_entry_map(entries)
        pinned_source_items = pinned_items or []
        pinned_commands = {
            str(item.get('command') or '').strip()
            for item in pinned_source_items
            if str(item.get('command') or '').strip()
        }

        pinned_quick_items = []
        normal_items = []

        for pinned_item in pinned_source_items:
            command_text = str(pinned_item.get('command') or '').strip()
            if not command_text:
                continue
            pinned_quick_items.append(
                self._build_pinned_quick_item(pinned_item, latest_by_command.get(command_text))
            )

        for command_text, item in latest_by_command.items():
            if command_text in pinned_commands:
                continue
            normal_items.append(self._build_normal_quick_item(item))

        self._apply_quick_history_move_flags(pinned_quick_items, normal_items)
        result = pinned_quick_items + normal_items

        for index, item in enumerate(result, start=1):
            item['index'] = index

        return result

    def _build_execution_history_view(self, entries: list) -> list:
        result = []

        for item in reversed(entries):
            self.store._normalize_entry_flags(item)
            copied = self._refresh_file_status_for_view(item)
            copied['output_records'] = list(item.get('output_records') or [])
            result.append(copied)

        for index, item in enumerate(result, start=1):
            item['index'] = index

        return result

    def _maybe_cleanup_legacy_pin_fields(self, machine_id: str, entries: list, had_legacy_pin_fields: bool):
        if had_legacy_pin_fields:
            self.store._write_entries(machine_id, entries)

    def get_history_for_connection(self, conn) -> list:
        if conn is None:
            return []

        machine_id = self.store._get_machine_id_from_conn(conn)

        with self.store._lock:
            entries = self.store._read_entries(machine_id)
            had_legacy_pin_fields = self.store._has_entry_pin_fields(entries)
            pinned_items = self.store.pinned_store.ensure_seeded_from_legacy_entries(machine_id, entries)
            for item in entries:
                self.store._normalize_entry_flags(item)
            self._maybe_cleanup_legacy_pin_fields(machine_id, entries, had_legacy_pin_fields)

        return self._build_deduplicated_latest_view(entries, pinned_items=pinned_items)

    def get_execution_history_for_connection(self, conn) -> list:
        if conn is None:
            return []

        machine_id = self.store._get_machine_id_from_conn(conn)

        with self.store._lock:
            entries = self.store._read_entries(machine_id)
            had_legacy_pin_fields = self.store._has_entry_pin_fields(entries)
            self.store.pinned_store.ensure_seeded_from_legacy_entries(machine_id, entries)
            for item in entries:
                self.store._normalize_entry_flags(item)
            self._maybe_cleanup_legacy_pin_fields(machine_id, entries, had_legacy_pin_fields)

        return self._build_execution_history_view(entries)

    def get_history_by_machine_id(self, machine_id: str) -> list:
        machine_id_text = (machine_id or '').strip() or 'unknown_machine'

        with self.store._lock:
            entries = self.store._read_entries(machine_id_text)
            had_legacy_pin_fields = self.store._has_entry_pin_fields(entries)
            pinned_items = self.store.pinned_store.ensure_seeded_from_legacy_entries(machine_id_text, entries)
            for item in entries:
                self.store._normalize_entry_flags(item)
            self._maybe_cleanup_legacy_pin_fields(machine_id_text, entries, had_legacy_pin_fields)

        return self._build_deduplicated_latest_view(entries, pinned_items=pinned_items)

    def get_execution_history_by_machine_id(self, machine_id: str) -> list:
        machine_id_text = (machine_id or '').strip() or 'unknown_machine'

        with self.store._lock:
            entries = self.store._read_entries(machine_id_text)
            had_legacy_pin_fields = self.store._has_entry_pin_fields(entries)
            self.store.pinned_store.ensure_seeded_from_legacy_entries(machine_id_text, entries)
            for item in entries:
                self.store._normalize_entry_flags(item)
            self._maybe_cleanup_legacy_pin_fields(machine_id_text, entries, had_legacy_pin_fields)

        return self._build_execution_history_view(entries)
