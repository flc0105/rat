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

    def _normalize_lookup_hostname(self, hostname: str) -> str:
        return str(hostname or '').strip() or 'unknown_host'

    def create_entry_for_connection(self, conn, command: str, source: str = 'cli'):
        """
        为指定连接创建一条命令历史，并返回 entry_id

        修复：
        - quick history 是按 command 去重展示最新一条
        - 如果同一 command 之前已被 pin，新建执行记录时需要继承 pin 状态
        - 否则最新一条会变成未 pin，看起来像 pin 丢失
        - pin 位置应固定，因此还要继承 pin_order
        """
        if conn is None:
            return ''

        command_text = (command or '').strip()
        if not command_text:
            return ''

        hostname = self.store._get_hostname_from_conn(conn)

        with self.store._lock:
            entries = self.store._read_entries(hostname)

            inherited_is_pinned, inherited_pinned_at, inherited_pin_order = (
                self.store._find_latest_pinned_metadata(entries, command_text)
            )

            entry = self.store._build_entry(conn, command_text, source)
            entry['is_pinned'] = inherited_is_pinned
            entry['pinned_at'] = inherited_pinned_at if inherited_is_pinned else ''
            entry['pin_order'] = inherited_pin_order if inherited_is_pinned else 0

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

    def update_entry_command_for_connection(self, conn, entry_id: str, command: str):
        """
        将指定历史记录的 command 更新为新的命令文本。

        用途：
        - CLI 先以原始输入创建 history entry
        - 后续如果 executor 将 !<index> / history run 展开成真实命令
        - 这里把 entry 同步成真实命令，避免历史里保留元命令文本

        兼容处理：
        - 重新按真实命令继承 pin 状态
        - pinned 位置应固定，因此需要一并继承 pin_order
        - 避免 quick history 因 command 维度错误而出现异常去重/排序
        """
        if conn is None or not entry_id:
            return False

        command_text = str(command or '').strip()
        if not command_text:
            return False

        hostname = self.store._get_hostname_from_conn(conn)
        changed = False

        with self.store._lock:
            entries = self.store._read_entries(hostname)
            entry = self.store._find_entry(entries, entry_id)
            if entry is None:
                return False

            current_command = str(entry.get('command') or '').strip()
            if current_command == command_text:
                return False

            inherited_is_pinned, inherited_pinned_at, inherited_pin_order = (
                self.store._find_latest_pinned_metadata(entries, command_text, skip_entry=entry)
            )

            entry['command'] = command_text
            entry['is_pinned'] = inherited_is_pinned
            if not str(entry.get('raw_command') or '').strip():
                entry['raw_command'] = current_command
            entry['pinned_at'] = inherited_pinned_at if inherited_is_pinned else ''
            entry['pin_order'] = inherited_pin_order if inherited_is_pinned else 0
            changed = True

            if changed:
                self.store._write_entries(hostname, entries)

        return changed

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
                    item['cwd_end'] = cwd_end or getattr(getattr(conn, 'session_info', None), 'cwd', '') or item.get('cwd_end', '')
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
        self.clear_history_by_hostname(hostname)

    def clear_history_by_hostname(self, hostname: str):
        """
        按 hostname 清空命令历史。
        """
        hostname_text = self._normalize_lookup_hostname(hostname)

        with self.store._lock:
            self.store._write_entries(hostname_text, [])

    def set_command_pinned_for_connection(self, conn, command: str, is_pinned: bool):
        """
        设置指定命令的置顶状态。
        quick history 是按 command 去重展示，因此这里按 command 维度批量更新。

        新规则：
        - pin 时为该 command 分配固定 pin_order
        - 后续再次执行同命令时继承 pin_order，不再因为执行时间改变位置
        - unpin 时清空 pin_order
        """
        if conn is None:
            return False

        hostname = self.store._get_hostname_from_conn(conn)
        return self.set_command_pinned_by_hostname(hostname, command, is_pinned)

    def set_command_pinned_by_hostname(self, hostname: str, command: str, is_pinned: bool):
        """
        按 hostname 设置指定命令的置顶状态。
        """
        command_text = str(command or '').strip()
        if not command_text:
            return False

        hostname_text = self._normalize_lookup_hostname(hostname)
        pinned = bool(is_pinned)
        changed = False

        with self.store._lock:
            entries = self.store._read_entries(hostname_text)

            current_pin_order = 0
            for item in entries:
                self.store._normalize_entry_flags(item)
                if (item.get('command') or '') != command_text:
                    continue
                if item.get('is_pinned') and int(item.get('pin_order', 0) or 0) > 0:
                    current_pin_order = int(item.get('pin_order', 0) or 0)
                    break

            if pinned and current_pin_order <= 0:
                current_pin_order = self.store._next_pin_order(entries)

            for item in entries:
                self.store._normalize_entry_flags(item)
                if (item.get('command') or '') != command_text:
                    continue

                target_pinned_at = self.store._now_text() if pinned and not item.get('is_pinned') else str(item.get('pinned_at') or '').strip()
                target_pin_order = current_pin_order if pinned else 0

                if (
                    item.get('is_pinned') == pinned and
                    str(item.get('pinned_at') or '').strip() == (target_pinned_at if pinned else '') and
                    int(item.get('pin_order', 0) or 0) == target_pin_order
                ):
                    continue

                item['is_pinned'] = pinned
                item['pinned_at'] = target_pinned_at if pinned else ''
                item['pin_order'] = target_pin_order
                changed = True

            if changed:
                self.store._write_entries(hostname_text, entries)

        return changed

    def _build_pinned_snapshot_items(self, entries: list) -> list:
        """
        构造当前 pinned commands 的去重快照。

        规则与 quick history 保持一致：
        - 相同 command 只取最新一条代表项
        - 只保留 pinned 项
        - 最终按固定 pin 排序返回
        """
        seen = set()
        pinned_items = []

        for item in reversed(entries):
            self.store._normalize_entry_flags(item)
            command_text = str(item.get('command') or '').strip()
            if not command_text or command_text in seen:
                continue
            seen.add(command_text)

            if item.get('is_pinned'):
                pinned_items.append(dict(item))

        return self.store._sort_pinned_snapshot_items(pinned_items)

    def _apply_pin_order_to_command_entries(self, entries: list, command_text: str, pin_order: int) -> bool:
        changed = False

        for item in entries:
            self.store._normalize_entry_flags(item)
            if (item.get('command') or '') != command_text:
                continue
            if not item.get('is_pinned'):
                continue

            if int(item.get('pin_order', 0) or 0) == int(pin_order):
                continue

            item['pin_order'] = int(pin_order)
            changed = True

        return changed

    def _normalize_pinned_command_orders(self, entries: list, pinned_items: list) -> bool:
        """
        将当前 pinned 区顺序压实为 1..N。

        好处：
        - 老数据没有 pin_order 时可自动补齐
        - 移动时只需要交换相邻 command 的顺序号
        - 避免 pin_order 留下过多历史空洞导致理解困难
        """
        changed = False

        for index, item in enumerate(pinned_items, start=1):
            command_text = str(item.get('command') or '').strip()
            if not command_text:
                continue

            if self._apply_pin_order_to_command_entries(entries, command_text, index):
                changed = True

        return changed

    def move_pinned_command_for_connection(self, conn, command: str, direction: str):
        """
        在 quick history 的 pinned 区内移动指定命令。

        规则：
        - 仅允许移动 pinned command
        - 只做相邻交换，避免一次移动跨越多项
        - up / down 以当前 quick history pinned 展示顺序为准
        - 边界项移动时直接返回 False，不抛异常
        """
        if conn is None:
            return False

        hostname = self.store._get_hostname_from_conn(conn)
        return self.move_pinned_command_by_hostname(hostname, command, direction)

    def move_pinned_command_by_hostname(self, hostname: str, command: str, direction: str):
        """
        按 hostname 调整 pinned quick history 顺序。
        """
        command_text = str(command or '').strip()
        direction_text = str(direction or '').strip().lower()

        if not command_text:
            raise ValueError('command is required')
        if direction_text not in ('up', 'down'):
            raise ValueError('direction must be up or down')

        hostname_text = self._normalize_lookup_hostname(hostname)

        with self.store._lock:
            entries = self.store._read_entries(hostname_text)
            pinned_items = self._build_pinned_snapshot_items(entries)

            if not pinned_items:
                return False

            command_list = [str(item.get('command') or '').strip() for item in pinned_items]
            if command_text not in command_list:
                raise ValueError('Only pinned commands can be moved')

            changed = self._normalize_pinned_command_orders(entries, pinned_items)

            current_index = command_list.index(command_text)
            if direction_text == 'up':
                if current_index <= 0:
                    if changed:
                        self.store._write_entries(hostname_text, entries)
                    return False
                target_index = current_index - 1
            else:
                if current_index >= len(command_list) - 1:
                    if changed:
                        self.store._write_entries(hostname_text, entries)
                    return False
                target_index = current_index + 1

            current_command = command_list[current_index]
            target_command = command_list[target_index]

            current_order = current_index + 1
            target_order = target_index + 1

            if self._apply_pin_order_to_command_entries(entries, current_command, target_order):
                changed = True
            if self._apply_pin_order_to_command_entries(entries, target_command, current_order):
                changed = True

            if changed:
                self.store._write_entries(hostname_text, entries)

            return True

    def delete_execution_entry_for_connection(self, conn, entry_id: str):
        """
        删除指定 execution history 单条记录。
        """
        if conn is None:
            return False

        hostname = self.store._get_hostname_from_conn(conn)
        return self.delete_execution_entry_by_hostname(hostname, entry_id)

    def delete_execution_entry_by_hostname(self, hostname: str, entry_id: str):
        """
        按 hostname 删除指定 execution history 单条记录。
        """
        target_entry_id = str(entry_id or '').strip()
        if not target_entry_id:
            return False

        hostname_text = self._normalize_lookup_hostname(hostname)

        with self.store._lock:
            entries = self.store._read_entries(hostname_text)
            new_entries = [
                item for item in entries
                if str(item.get('entry_id') or '').strip() != target_entry_id
            ]

            if len(new_entries) == len(entries):
                return False

            self.store._write_entries(hostname_text, new_entries)
            return True
