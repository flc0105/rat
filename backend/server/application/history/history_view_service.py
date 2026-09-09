import base64
import json
import os

from server.config.config import COMMAND_HISTORY_MAX_PAGE_SIZE, COMMAND_HISTORY_PAGE_SIZE


class HistoryViewService:
    """Command history read models: Quick History and paged permanent executions."""

    def __init__(self, store):
        self.store = store

    def _resolve_artifact_file_view(self, file_item: dict) -> dict:
        copied = dict(file_item)
        artifact_id = str(copied.get('artifact_id') or '').strip()

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
        copied.pop('_started_at_ms', None)
        files = [self._resolve_artifact_file_view(file_item) for file_item in item.get('files') or []]
        copied['files'] = files
        copied['file_count'] = len(files)
        copied['has_files'] = bool(files)
        return copied

    @staticmethod
    def _apply_quick_history_move_flags(pinned_items: list, normal_items: list):
        for index, item in enumerate(pinned_items):
            item['can_move_up'] = index > 0
            item['can_move_down'] = index < len(pinned_items) - 1
        for item in normal_items:
            item['can_move_up'] = False
            item['can_move_down'] = False

    def _build_pinned_quick_item(self, pinned_item: dict, latest_entry: dict | None) -> dict:
        command_text = str(pinned_item.get('command') or '').strip()
        snapshot = pinned_item.get('snapshot') if isinstance(pinned_item.get('snapshot'), dict) else {}
        source_item = latest_entry if isinstance(latest_entry, dict) else snapshot
        copied = dict(source_item or {})
        copied.pop('output_records', None)
        copied['command'] = command_text
        copied['raw_command'] = str(copied.get('raw_command') or command_text).strip()
        copied['is_pinned'] = True
        copied['pinned_at'] = str(pinned_item.get('pinned_at') or '').strip()
        copied['pin_order'] = int(pinned_item.get('pin_order', 0) or 0)
        return self._refresh_file_status_for_view(copied)

    def _build_normal_quick_item(self, item: dict) -> dict:
        copied = dict(item)
        copied.pop('output_records', None)
        copied['is_pinned'] = False
        copied['pinned_at'] = ''
        copied['pin_order'] = 0
        return self._refresh_file_status_for_view(copied)

    def _build_quick_history(self, machine_id: str) -> list:
        pinned_source_items = self.store.pinned_store.get_items(machine_id)
        pinned_commands = {item['command'] for item in pinned_source_items}
        pinned_items = []
        for pinned_item in pinned_source_items:
            command = pinned_item['command']
            pinned_items.append(
                self._build_pinned_quick_item(
                    pinned_item,
                    self.store._get_latest_entry_for_command(machine_id, command),
                )
            )

        normal_items = [
            self._build_normal_quick_item(item)
            for item in self.store._list_recents(machine_id)
            if str(item.get('command') or '').strip() not in pinned_commands
        ]
        self._apply_quick_history_move_flags(pinned_items, normal_items)
        result = pinned_items + normal_items
        for index, item in enumerate(result, start=1):
            item['index'] = index
        return result

    def _build_execution_entry_view(self, entry: dict, index: int = 0) -> dict:
        copied = self._refresh_file_status_for_view(entry)
        copied['output_records'] = list(entry.get('output_records') or [])
        if index > 0:
            copied['index'] = index
        return copied

    @staticmethod
    def _encode_cursor(started_at_ms: int, entry_id: str) -> str:
        payload = json.dumps({'t': int(started_at_ms), 'id': str(entry_id)}, separators=(',', ':')).encode('utf-8')
        return base64.urlsafe_b64encode(payload).decode('ascii').rstrip('=')

    @staticmethod
    def _decode_cursor(cursor: str):
        text = str(cursor or '').strip()
        if not text:
            return None
        try:
            padding = '=' * ((4 - len(text) % 4) % 4)
            payload = json.loads(base64.urlsafe_b64decode((text + padding).encode('ascii')).decode('utf-8'))
            return int(payload['t']), str(payload['id'])
        except Exception as exc:
            raise ValueError('Invalid history cursor') from exc

    @staticmethod
    def _normalize_page_limit(limit) -> int:
        try:
            value = int(limit)
        except Exception:
            value = COMMAND_HISTORY_PAGE_SIZE
        return min(max(value, 1), COMMAND_HISTORY_MAX_PAGE_SIZE)

    def get_history_for_connection(self, conn) -> list:
        if conn is None:
            return []
        return self.get_history_by_machine_id(self.store._get_machine_id_from_conn(conn))

    def get_history_by_machine_id(self, machine_id: str) -> list:
        machine_id_text = str(machine_id or '').strip() or 'unknown_machine'
        with self.store._lock:
            return self._build_quick_history(machine_id_text)

    def get_connection_command_summaries_by_machine_id(self, machine_id: str) -> list:
        machine_id_text = str(machine_id or '').strip() or 'unknown_machine'
        rows = self.store.database.connection().execute(
            '''
            SELECT entry_id, client_id, command, source, status, final_status,
                   started_at, finished_at, duration_ms, cwd_start, cwd_end,
                   hostname, addr, output_summary, output_line_count,
                   output_char_count, output_truncated, file_count
            FROM command_executions
            WHERE machine_id = ?
            ORDER BY started_at_ms DESC, entry_id DESC
            ''',
            (machine_id_text,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_execution_history_page(self, machine_id: str, *, limit=None, cursor: str = '') -> dict:
        machine_id_text = str(machine_id or '').strip() or 'unknown_machine'
        page_limit = self._normalize_page_limit(limit)
        decoded_cursor = self._decode_cursor(cursor)
        rows = self.store._list_execution_rows(
            machine_id_text,
            limit=page_limit + 1,
            cursor=decoded_cursor,
        )
        has_more = len(rows) > page_limit
        page_rows = rows[:page_limit]
        items = [
            self._build_execution_entry_view(self.store._row_to_entry(row), index=index)
            for index, row in enumerate(page_rows, start=1)
        ]
        next_cursor = ''
        if has_more and page_rows:
            last = page_rows[-1]
            next_cursor = self._encode_cursor(int(last['started_at_ms'] or 0), last['entry_id'])
        total_row = self.store.database.connection().execute(
            'SELECT COUNT(*) FROM command_executions WHERE machine_id = ?',
            (machine_id_text,),
        ).fetchone()
        return {
            'items': items,
            'next_cursor': next_cursor,
            'has_more': has_more,
            'total_count': int(total_row[0] if total_row else 0),
        }
