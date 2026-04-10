import json
import os
import threading
from datetime import datetime

from core.utils.files import secure_filename
from server.config.config import PINNED_PATHS_ROOT_DIR


class PinnedPathStore:
    """
    服务端 hostname 级快速跳转收藏存储。

    职责：
    - 按 hostname 持久化收藏的 quick jump
    - 提供收藏列表读取 / 保存 / 删除 / 查询
    """

    TIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    def __init__(self):
        self.root_dir = PINNED_PATHS_ROOT_DIR
        self._lock = threading.RLock()
        self._prepare_dirs()

    # add hostname quick jump 存储 2026-04-09 15:30
    def _prepare_dirs(self):
        os.makedirs(self.root_dir, exist_ok=True)

    # add hostname quick jump 存储 2026-04-09 15:30
    def _normalize_hostname(self, hostname: str) -> str:
        safe_name = secure_filename((hostname or '').strip())
        return safe_name or 'unknown_host'

    # add hostname quick jump 存储 2026-04-09 15:30
    def _get_file_path(self, hostname: str) -> str:
        normalized = self._normalize_hostname(hostname)
        return os.path.join(self.root_dir, f'{normalized}.json')

    # add hostname quick jump 存储 2026-04-09 15:30
    def _now_text(self) -> str:
        return datetime.now().strftime(self.TIME_FORMAT)

    # add hostname quick jump 存储 2026-04-09 15:30
    def _normalize_entry(self, item) -> dict | None:
        if not isinstance(item, dict):
            return None

        display_name = str(item.get('display_name') or item.get('name') or '').strip()
        path = str(item.get('path') or '').strip()
        if not display_name or not path:
            return None

        created_at = str(item.get('created_at') or '').strip()
        updated_at = str(item.get('updated_at') or '').strip()
        now_text = self._now_text()

        return {
            'display_name': display_name,
            'path': path,
            'created_at': created_at or now_text,
            'updated_at': updated_at or created_at or now_text,
        }

    # add hostname quick jump 存储 2026-04-09 15:30
    def _read_payload(self, hostname: str) -> list[dict]:
        file_path = self._get_file_path(hostname)
        if not os.path.isfile(file_path):
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as file_obj:
                payload = json.load(file_obj)
        except Exception:
            return []

        if isinstance(payload, dict):
            payload = payload.get('items') or []

        if not isinstance(payload, list):
            return []

        items = []
        for item in payload:
            normalized = self._normalize_entry(item)
            if normalized:
                items.append(normalized)
        return items

    # add hostname quick jump 存储 2026-04-09 15:30
    def _write_payload(self, hostname: str, items: list[dict]):
        file_path = self._get_file_path(hostname)
        payload = {
            'hostname': self._normalize_hostname(hostname),
            'items': items,
        }
        with open(file_path, 'w', encoding='utf-8') as file_obj:
            json.dump(payload, file_obj, ensure_ascii=False, indent=2)

    # add hostname quick jump 存储 2026-04-09 15:30
    def list_items(self, hostname: str) -> list[dict]:
        with self._lock:
            items = self._read_payload(hostname)
        return sorted(items, key=lambda item: item.get('display_name', '').lower())

    # add hostname quick jump 存储 2026-04-09 15:30
    def save_item(self, hostname: str, display_name: str, path: str) -> dict:
        display_name_text = str(display_name or '').strip()
        path_text = str(path or '').strip()
        if not display_name_text:
            raise ValueError('display_name is required')
        if not path_text:
            raise ValueError('path is required')

        with self._lock:
            items = self._read_payload(hostname)
            now_text = self._now_text()
            matched_item = None

            for item in items:
                if str(item.get('display_name') or '').strip() != display_name_text:
                    continue
                item['path'] = path_text
                item['updated_at'] = now_text
                matched_item = item
                break

            if matched_item is None:
                matched_item = {
                    'display_name': display_name_text,
                    'path': path_text,
                    'created_at': now_text,
                    'updated_at': now_text,
                }
                items.append(matched_item)

            normalized_items = [self._normalize_entry(item) for item in items]
            normalized_items = [item for item in normalized_items if item]
            self._write_payload(hostname, normalized_items)
            return dict(matched_item)

    # add quick jump 管理编辑 2026-04-09 16:20
    def update_item(self, hostname: str, original_display_name: str, display_name: str, path: str) -> dict:
        original_name_text = str(original_display_name or '').strip()
        display_name_text = str(display_name or '').strip()
        path_text = str(path or '').strip()
        if not original_name_text:
            raise ValueError('original_display_name is required')
        if not display_name_text:
            raise ValueError('display_name is required')
        if not path_text:
            raise ValueError('path is required')

        with self._lock:
            items = self._read_payload(hostname)
            matched_item = None
            duplicate_item = None
            for item in items:
                item_name = str(item.get('display_name') or '').strip()
                if item_name == original_name_text:
                    matched_item = item
                elif item_name == display_name_text:
                    duplicate_item = item

            if matched_item is None:
                raise KeyError(f'Pinned path not found: {original_name_text}')
            if duplicate_item is not None and duplicate_item is not matched_item:
                raise ValueError(f'Pinned path already exists: {display_name_text}')

            now_text = self._now_text()
            matched_item['display_name'] = display_name_text
            matched_item['path'] = path_text
            matched_item['updated_at'] = now_text

            normalized_items = [self._normalize_entry(item) for item in items]
            normalized_items = [item for item in normalized_items if item]
            self._write_payload(hostname, normalized_items)
            return dict(matched_item)

    # add hostname quick jump 存储 2026-04-09 15:30
    def delete_item(self, hostname: str, display_name: str) -> dict:
        display_name_text = str(display_name or '').strip()
        if not display_name_text:
            raise ValueError('display_name is required')

        with self._lock:
            items = self._read_payload(hostname)
            kept_items = []
            removed_item = None

            for item in items:
                if removed_item is None and str(item.get('display_name') or '').strip() == display_name_text:
                    removed_item = item
                    continue
                kept_items.append(item)

            if removed_item is None:
                raise KeyError(f'Pinned path not found: {display_name_text}')

            normalized_items = [self._normalize_entry(item) for item in kept_items]
            normalized_items = [item for item in normalized_items if item]
            self._write_payload(hostname, normalized_items)
            return dict(removed_item)

    # add hostname quick jump 存储 2026-04-09 15:30
    def get_item_by_name(self, hostname: str, display_name: str) -> dict | None:
        display_name_text = str(display_name or '').strip()
        if not display_name_text:
            return None

        with self._lock:
            items = self._read_payload(hostname)

        for item in items:
            if str(item.get('display_name') or '').strip() == display_name_text:
                return dict(item)
        return None
