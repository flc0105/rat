from server.models.history import HistoryFileRef


class HistoryWriteService:
    """
    命令历史写入服务。

    职责：
    - 创建 entry
    - 追加输出
    - 追加文件
    - 更新最终状态
    """

    def __init__(self, store):
        self.store = store

    def _normalize_lookup_machine_id(self, machine_id: str) -> str:
        return str(machine_id or '').strip() or 'unknown_machine'

    def _find_latest_entry_for_command(self, entries: list, command_text: str):
        for item in reversed(entries or []):
            if str(item.get('command') or '').strip() == command_text:
                return item
        return None

    def create_entry_for_connection(self, conn, command: str, source: str = 'cli'):
        if conn is None:
            return ''

        command_text = (command or '').strip()
        if not command_text:
            return ''

        machine_id = self.store._get_machine_id_from_conn(conn)

        with self.store._lock:
            entries = self.store._read_entries(machine_id)
            entry = self.store._build_entry(conn, command_text, source)

            entries.append(entry)
            entries = self.store._trim_entries(entries)
            self.store._write_entries(machine_id, entries)
            return entry['entry_id']

    def append_output_for_connection(self, conn, entry_id: str, status: int, text: str, eof: int = 0):
        if conn is None or not entry_id:
            return

        machine_id = self.store._get_machine_id_from_conn(conn)
        output_text = self.store._safe_text(text)

        with self.store._lock:
            entries = self.store._read_entries(machine_id)
            entry = self.store._find_entry(entries, entry_id)
            if entry is None:
                return

            entry['has_output'] = entry.get('has_output', False) or bool(output_text)
            entry['output_chunk_count'] = int(entry.get('output_chunk_count', 0)) + 1
            entry['output_line_count'] = int(entry.get('output_line_count', 0)) + self.store._count_output_lines(output_text)
            entry['output_char_count'] = int(entry.get('output_char_count', 0)) + len(output_text)

            records = entry.setdefault('output_records', [])
            stored_char_count = int(entry.get('output_stored_char_count', 0))
            remaining_chars = max(self.store.MAX_OUTPUT_RECORD_CHARS - stored_char_count, 0)

            next_seq = int(entry.get('output_record_seq', 0)) + 1
            entry['output_record_seq'] = next_seq

            if output_text and remaining_chars > 0 and len(records) < self.store.MAX_OUTPUT_RECORDS:
                stored_text = output_text[:remaining_chars]
                if len(stored_text) < len(output_text):
                    entry['output_truncated'] = True
                records.append({
                    'seq': next_seq,
                    'status': status,
                    'text': stored_text,
                    'time': self.store._now_text(),
                    'eof': eof,
                })
                entry['output_stored_char_count'] = stored_char_count + len(stored_text)
            elif output_text:
                entry['output_truncated'] = True

            entry['output_summary'] = self.store._build_output_summary(entry)
            self.store._write_entries(machine_id, entries)

    def append_file_for_connection(self, conn, entry_id: str, file_info: dict):
        if conn is None or not entry_id or not isinstance(file_info, dict):
            return

        machine_id = self.store._get_machine_id_from_conn(conn)

        with self.store._lock:
            entries = self.store._read_entries(machine_id)
            entry = self.store._find_entry(entries, entry_id)
            if entry is None:
                return

            files = entry.setdefault('files', [])
            file_record = HistoryFileRef.from_dict(file_info).to_dict()
            files.append(file_record)

            entry['has_files'] = True
            entry['file_count'] = len(files)
            entry['output_summary'] = self.store._build_output_summary(entry)
            self.store._write_entries(machine_id, entries)

    def update_entry_command_for_connection(self, conn, entry_id: str, command: str):
        if conn is None or not entry_id:
            return False

        command_text = str(command or '').strip()
        if not command_text:
            return False

        machine_id = self.store._get_machine_id_from_conn(conn)
        changed = False

        with self.store._lock:
            entries = self.store._read_entries(machine_id)
            entry = self.store._find_entry(entries, entry_id)
            if entry is None:
                return False

            current_command = str(entry.get('command') or '').strip()
            if current_command == command_text:
                return False

            entry['command'] = command_text
            if not str(entry.get('raw_command') or '').strip():
                entry['raw_command'] = current_command
            changed = True

            if changed:
                self.store._write_entries(machine_id, entries)

        return changed

    def update_entry_status_for_connection(self, conn, entry_id: str, status: str, cwd_end: str = ''):
        if conn is None or not entry_id:
            return

        machine_id = self.store._get_machine_id_from_conn(conn)

        with self.store._lock:
            entries = self.store._read_entries(machine_id)
            changed = False

            for item in reversed(entries):
                if item.get('entry_id') == entry_id:
                    item['status'] = status
                    item['final_status'] = status
                    item['finished_at'] = self.store._now_text()
                    item['cwd_end'] = cwd_end or getattr(getattr(conn, 'session_info', None), 'cwd', '') or item.get('cwd_end', '')
                    item['time'] = item.get('time') or self.store._now_text()
                    self.store._update_duration(item)
                    item['output_summary'] = self.store._build_output_summary(item)
                    changed = True
                    break

            if changed:
                self.store._write_entries(machine_id, entries)

    def clear_history_for_connection(self, conn):
        if conn is None:
            return

        machine_id = self.store._get_machine_id_from_conn(conn)
        self.clear_history_by_machine_id(machine_id)

    def clear_history_by_machine_id(self, machine_id: str):
        machine_id_text = self._normalize_lookup_machine_id(machine_id)

        with self.store._lock:
            self.store._write_entries(machine_id_text, [])

    def set_command_pinned_for_connection(self, conn, command: str, is_pinned: bool):
        if conn is None:
            return False

        machine_id = self.store._get_machine_id_from_conn(conn)
        return self.set_command_pinned_by_machine_id(machine_id, command, is_pinned)

    def set_command_pinned_by_machine_id(self, machine_id: str, command: str, is_pinned: bool):
        command_text = str(command or '').strip()
        if not command_text:
            return False

        machine_id_text = self._normalize_lookup_machine_id(machine_id)

        with self.store._lock:
            entries = self.store._read_entries(machine_id_text)
            self.store.pinned_store.ensure_seeded_from_legacy_entries(machine_id_text, entries)
            latest_entry = self._find_latest_entry_for_command(entries, command_text)
            changed = self.store.pinned_store.set_command_pinned(
                machine_id_text,
                command_text,
                bool(is_pinned),
                seed_entry=latest_entry,
            )

            # 顺手清理历史文件中旧版本残留的 pin 字段。
            self.store._write_entries(machine_id_text, entries)

        return changed

    def move_pinned_command_for_connection(self, conn, command: str, direction: str):
        if conn is None:
            return False

        machine_id = self.store._get_machine_id_from_conn(conn)
        return self.move_pinned_command_by_machine_id(machine_id, command, direction)

    def move_pinned_command_by_machine_id(self, machine_id: str, command: str, direction: str):
        command_text = str(command or '').strip()
        direction_text = str(direction or '').strip().lower()

        if not command_text:
            raise ValueError('command is required')
        if direction_text not in ('up', 'down'):
            raise ValueError('direction must be up or down')

        machine_id_text = self._normalize_lookup_machine_id(machine_id)

        with self.store._lock:
            entries = self.store._read_entries(machine_id_text)
            self.store.pinned_store.ensure_seeded_from_legacy_entries(machine_id_text, entries)
            changed = self.store.pinned_store.move_pinned_command(
                machine_id_text,
                command_text,
                direction_text,
            )

            # 顺手清理历史文件中旧版本残留的 pin 字段。
            self.store._write_entries(machine_id_text, entries)

        return changed

    def delete_execution_entry_for_connection(self, conn, entry_id: str):
        if conn is None:
            return False

        machine_id = self.store._get_machine_id_from_conn(conn)
        return self.delete_execution_entry_by_machine_id(machine_id, entry_id)

    def delete_execution_entry_by_machine_id(self, machine_id: str, entry_id: str):
        target_entry_id = str(entry_id or '').strip()
        if not target_entry_id:
            return False

        machine_id_text = self._normalize_lookup_machine_id(machine_id)

        with self.store._lock:
            entries = self.store._read_entries(machine_id_text)
            new_entries = [item for item in entries if str(item.get('entry_id') or '').strip() != target_entry_id]
            if len(new_entries) == len(entries):
                return False
            self.store._write_entries(machine_id_text, new_entries)
            return True
