import json
import os

from core.utils.files import secure_filename


class PinnedCommandStore:
    """
    Quick History 的 pinned command 独立存储。

    职责：
    - pinned 状态不再写入 execution history 原始记录
    - 按 machine_id 持久化命令级别 pin 状态和排序
    - 从旧 execution history 的 pin 字段做一次性迁移
    """

    SNAPSHOT_FIELDS = (
        'entry_id',
        'time',
        'started_at',
        'finished_at',
        'duration_ms',
        'command',
        'raw_command',
        'source',
        'status',
        'final_status',
        'hostname',
        'machine_id',
        'client_id',
        'addr',
        'cwd_start',
        'cwd_end',
        'has_output',
        'output_summary',
        'output_line_count',
        'output_chunk_count',
        'output_char_count',
        'output_stored_char_count',
        'output_truncated',
        'output_record_seq',
        'has_files',
        'file_count',
        'files',
    )

    def __init__(self, history_root_dir: str, now_text_provider):
        self.root_dir = os.path.join(history_root_dir, 'pinned_commands')
        self.now_text_provider = now_text_provider
        os.makedirs(self.root_dir, exist_ok=True)

    def _normalize_machine_id(self, machine_id: str) -> str:
        safe_name = secure_filename((machine_id or '').strip())
        return safe_name or 'unknown_machine'

    def _get_file_path(self, machine_id: str) -> str:
        normalized = self._normalize_machine_id(machine_id)
        return os.path.join(self.root_dir, f'{normalized}.json')

    def _has_store_file(self, machine_id: str) -> bool:
        return os.path.isfile(self._get_file_path(machine_id))

    def _now_text(self) -> str:
        return self.now_text_provider()

    def _read_items(self, machine_id: str) -> list:
        file_path = self._get_file_path(machine_id)
        if not os.path.isfile(file_path):
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as file_obj:
                payload = json.load(file_obj)
                if isinstance(payload, list):
                    return self._normalize_items(payload)
        except Exception:
            pass

        return []

    def _write_items(self, machine_id: str, items: list):
        file_path = self._get_file_path(machine_id)
        normalized_items = self._normalize_orders(self._normalize_items(items))
        with open(file_path, 'w', encoding='utf-8') as file_obj:
            json.dump(normalized_items, file_obj, ensure_ascii=False, indent=2)

    def _normalize_int(self, value, default: int = 0) -> int:
        try:
            return int(value or default)
        except Exception:
            return default

    def _sanitize_snapshot(self, snapshot: dict | None, command: str = '') -> dict:
        if not isinstance(snapshot, dict):
            snapshot = {}

        copied = {}
        for field in self.SNAPSHOT_FIELDS:
            if field in snapshot:
                copied[field] = snapshot.get(field)

        command_text = str(copied.get('command') or command or '').strip()
        copied['command'] = command_text
        copied['raw_command'] = str(copied.get('raw_command') or command_text).strip()
        copied['status'] = str(copied.get('status') or '').strip()
        copied['time'] = str(copied.get('time') or '').strip()
        copied['files'] = list(copied.get('files') or [])
        copied['file_count'] = self._normalize_int(copied.get('file_count'), len(copied['files']))
        copied['has_files'] = bool(copied.get('has_files') or copied['file_count'] > 0)

        # output_records 不进入 pinned registry，避免 Quick History 复制完整 execution log。
        copied.pop('output_records', None)

        # 彻底切断 execution entry 上的旧 pin 字段。
        copied.pop('is_pinned', None)
        copied.pop('pinned_at', None)
        copied.pop('pin_order', None)
        return copied

    def _build_snapshot_from_entry(self, entry: dict | None, command: str) -> dict:
        return self._sanitize_snapshot(entry if isinstance(entry, dict) else {}, command=command)

    def _normalize_item(self, payload: dict | None):
        if not isinstance(payload, dict):
            return None

        command_text = str(payload.get('command') or '').strip()
        if not command_text:
            return None

        pin_order = self._normalize_int(payload.get('pin_order'), 0)
        pinned_at = str(payload.get('pinned_at') or '').strip() or self._now_text()
        snapshot = self._sanitize_snapshot(payload.get('snapshot'), command=command_text)

        return {
            'command': command_text,
            'pinned_at': pinned_at,
            'pin_order': pin_order,
            'snapshot': snapshot,
        }

    def _normalize_items(self, items: list) -> list:
        normalized = []
        seen = set()

        for payload in items or []:
            item = self._normalize_item(payload)
            if not item:
                continue
            command_text = item['command']
            if command_text in seen:
                continue
            seen.add(command_text)
            normalized.append(item)

        return normalized

    def _sort_items(self, items: list) -> list:
        return sorted(
            self._normalize_items(items),
            key=lambda item: (
                int(item.get('pin_order', 0) or 0) <= 0,
                int(item.get('pin_order', 0) or 0),
                str(item.get('pinned_at') or ''),
                str(item.get('command') or ''),
            ),
        )

    def _normalize_orders(self, items: list) -> list:
        ordered = self._sort_items(items)
        for index, item in enumerate(ordered, start=1):
            item['pin_order'] = index
        return ordered

    def _find_latest_entry_for_command(self, entries: list, command_text: str):
        for item in reversed(entries or []):
            if str(item.get('command') or '').strip() == command_text:
                return item
        return None

    def _extract_legacy_pinned_items(self, entries: list) -> list:
        seen = set()
        items = []

        for entry in reversed(entries or []):
            if not isinstance(entry, dict):
                continue
            command_text = str(entry.get('command') or '').strip()
            if not command_text or command_text in seen:
                continue
            seen.add(command_text)

            if not entry.get('is_pinned'):
                continue

            items.append({
                'command': command_text,
                'pinned_at': str(entry.get('pinned_at') or '').strip() or self._now_text(),
                'pin_order': self._normalize_int(entry.get('pin_order'), 0),
                'snapshot': self._build_snapshot_from_entry(entry, command_text),
            })

        return self._normalize_orders(items)

    def ensure_seeded_from_legacy_entries(self, machine_id: str, entries: list) -> list:
        """
        只在 pinned store 文件不存在时迁移旧 execution entry 上的 pin 字段。
        这样用户 unpin 后不会被还没落盘清理的旧字段反复恢复。
        """
        if self._has_store_file(machine_id):
            return self.get_items(machine_id)

        legacy_items = self._extract_legacy_pinned_items(entries)
        if legacy_items:
            self._write_items(machine_id, legacy_items)
        return legacy_items

    def get_items(self, machine_id: str) -> list:
        return self._read_items(machine_id)

    def get_command_set(self, machine_id: str) -> set:
        return {item.get('command') for item in self.get_items(machine_id) if item.get('command')}

    def set_command_pinned(self, machine_id: str, command: str, is_pinned: bool, seed_entry: dict | None = None) -> bool:
        command_text = str(command or '').strip()
        if not command_text:
            return False

        items = self.get_items(machine_id)
        pinned = bool(is_pinned)
        changed = False

        existing_index = next(
            (index for index, item in enumerate(items) if item.get('command') == command_text),
            -1,
        )

        if not pinned:
            if existing_index < 0:
                return False
            del items[existing_index]
            changed = True
        elif existing_index < 0:
            items.append({
                'command': command_text,
                'pinned_at': self._now_text(),
                'pin_order': len(items) + 1,
                'snapshot': self._build_snapshot_from_entry(seed_entry, command_text),
            })
            changed = True
        else:
            snapshot = self._build_snapshot_from_entry(seed_entry, command_text)
            if snapshot and snapshot != items[existing_index].get('snapshot'):
                items[existing_index]['snapshot'] = snapshot
                changed = True

        if changed:
            self._write_items(machine_id, items)

        return changed

    def move_pinned_command(self, machine_id: str, command: str, direction: str) -> bool:
        command_text = str(command or '').strip()
        direction_text = str(direction or '').strip().lower()

        if not command_text:
            raise ValueError('command is required')
        if direction_text not in ('up', 'down'):
            raise ValueError('direction must be up or down')

        items = self._normalize_orders(self.get_items(machine_id))
        if not items:
            return False

        current_index = next(
            (index for index, item in enumerate(items) if item.get('command') == command_text),
            -1,
        )
        if current_index < 0:
            raise ValueError('Only pinned commands can be moved')

        if direction_text == 'up':
            if current_index <= 0:
                return False
            target_index = current_index - 1
        else:
            if current_index >= len(items) - 1:
                return False
            target_index = current_index + 1

        items[current_index], items[target_index] = items[target_index], items[current_index]

        # _write_items 会按 pin_order 重新排序，所以移动后必须先重写 pin_order。
        for index, item in enumerate(items, start=1):
            item['pin_order'] = index

        self._write_items(machine_id, items)
        return True
