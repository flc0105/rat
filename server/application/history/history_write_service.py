
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

    def create_entry_for_connection(self, conn, command: str, source: str = 'cli'):
        """
        为指定连接创建一条命令历史，并返回 entry_id
        """
        if conn is None:
            return ''

        command_text = (command or '').strip()
        if not command_text:
            return ''

        hostname = self.store._get_hostname_from_conn(conn)

        with self.store._lock:
            entries = self.store._read_entries(hostname)
            entry = self.store._build_entry(conn, command_text, source)
            entries.append(entry)
            entries = self.store._trim_entries(entries)
            self.store._write_entries(hostname, entries)
            return entry['entry_id']

    def append_output_for_connection(self, conn, entry_id: str, status: int, text: str, eof: int = 0):
        """
        为指定执行记录追加输出分片
        """
        if conn is None or not entry_id:
            return

        hostname = self.store._get_hostname_from_conn(conn)
        output_text = self.store._safe_text(text)

        with self.store._lock:
            entries = self.store._read_entries(hostname)
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
            self.store._write_entries(hostname, entries)

    def append_file_for_connection(self, conn, entry_id: str, file_info: dict):
        """
        为指定执行记录追加产出文件信息
        """
        if conn is None or not entry_id or not isinstance(file_info, dict):
            return

        hostname = self.store._get_hostname_from_conn(conn)

        with self.store._lock:
            entries = self.store._read_entries(hostname)
            entry = self.store._find_entry(entries, entry_id)
            if entry is None:
                return

            files = entry.setdefault('files', [])
            file_record = HistoryFileRef.from_dict(file_info).to_dict()
            files.append(file_record)

            entry['has_files'] = True
            entry['file_count'] = len(files)
            entry['output_summary'] = self.store._build_output_summary(entry)
            self.store._write_entries(hostname, entries)

    def update_entry_status_for_connection(self, conn, entry_id: str, status: str, cwd_end: str = ''):
        """
        更新指定历史记录的状态，并补全结束时间 / 耗时 / cwd_end
        """
        if conn is None or not entry_id:
            return

        hostname = self.store._get_hostname_from_conn(conn)

        with self.store._lock:
            entries = self.store._read_entries(hostname)
            changed = False

            for item in reversed(entries):
                if item.get('entry_id') == entry_id:
                    item['status'] = status
                    item['final_status'] = status
                    item['finished_at'] = self.store._now_text()
                    item['cwd_end'] = cwd_end or (getattr(conn, 'info', {}) or {}).get('cwd', '') or item.get('cwd_end', '')
                    item['time'] = item.get('time') or self.store._now_text()
                    self.store._update_duration(item)
                    item['output_summary'] = self.store._build_output_summary(item)
                    changed = True
                    break

            if changed:
                self.store._write_entries(hostname, entries)

    def clear_history_for_connection(self, conn):
        """
        清空指定连接的命令历史
        """
        if conn is None:
            return

        hostname = self.store._get_hostname_from_conn(conn)

        with self.store._lock:
            self.store._write_entries(hostname, [])

    def set_command_pinned_for_connection(self, conn, command: str, is_pinned: bool):
        """
        设置指定命令的置顶状态。
        quick history 是按 command 去重展示，因此这里按 command 维度批量更新。
        """
        if conn is None:
            return False

        command_text = str(command or '').strip()
        if not command_text:
            return False

        hostname = self.store._get_hostname_from_conn(conn)
        pinned = bool(is_pinned)
        changed = False

        with self.store._lock:
            entries = self.store._read_entries(hostname)

            for item in entries:
                self.store._normalize_entry_flags(item)
                if (item.get('command') or '') != command_text:
                    continue

                if item.get('is_pinned') == pinned:
                    continue

                item['is_pinned'] = pinned
                item['pinned_at'] = self.store._now_text() if pinned else ''
                changed = True

            if changed:
                self.store._write_entries(hostname, entries)

        return changed

    def delete_execution_entry_for_connection(self, conn, entry_id: str):
        """
        删除指定 execution history 单条记录。
        """
        if conn is None:
            return False

        target_entry_id = str(entry_id or '').strip()
        if not target_entry_id:
            return False

        hostname = self.store._get_hostname_from_conn(conn)

        with self.store._lock:
            entries = self.store._read_entries(hostname)
            new_entries = [
                item for item in entries
                if str(item.get('entry_id') or '').strip() != target_entry_id
            ]

            if len(new_entries) == len(entries):
                return False

            self.store._write_entries(hostname, new_entries)
            return True
