import json
import os
import tempfile
import threading
import uuid
from datetime import datetime

from core.utils.files import secure_filename
from server.config.config import EXTERNAL_TOOL_PARAM_PRESETS_ROOT_DIR


class ExternalToolParamPresetStore:
    """ExternalTool module parameter preset storage."""

    TIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    def __init__(self, root_dir: str = EXTERNAL_TOOL_PARAM_PRESETS_ROOT_DIR):
        self.root_dir = os.path.abspath(root_dir)
        self._lock = threading.RLock()
        os.makedirs(self.root_dir, exist_ok=True)

    def _now_text(self) -> str:
        return datetime.now().strftime(self.TIME_FORMAT)

    def _normalize_tool_id(self, tool_id: str) -> str:
        value = str(tool_id or '').strip()
        if not value:
            raise ValueError('tool_id is required')
        return value

    def _file_path(self, tool_id: str) -> str:
        normalized = self._normalize_tool_id(tool_id)
        safe_name = secure_filename(normalized)
        if not safe_name:
            raise ValueError('invalid tool_id')
        return os.path.join(self.root_dir, f'{safe_name}.json')

    def _copy_params(self, params) -> dict:
        if not isinstance(params, dict):
            raise ValueError('params must be an object')
        try:
            return json.loads(json.dumps(params, ensure_ascii=False))
        except Exception as e:
            raise ValueError(f'params must be JSON serializable: {e}') from e

    def _normalize_entry(self, item) -> dict | None:
        if not isinstance(item, dict):
            return None

        name = str(item.get('name') or '').strip()
        if not name:
            return None

        preset_id = str(item.get('preset_id') or '').strip() or uuid.uuid4().hex
        now_text = self._now_text()
        created_at = str(item.get('created_at') or '').strip() or now_text
        updated_at = str(item.get('updated_at') or '').strip() or created_at

        return {
            'preset_id': preset_id,
            'name': name,
            'params': self._copy_params(item.get('params') or {}),
            'created_at': created_at,
            'updated_at': updated_at,
        }

    def _read_payload(self, tool_id: str) -> list[dict]:
        file_path = self._file_path(tool_id)
        if not os.path.isfile(file_path):
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as file_obj:
                payload = json.load(file_obj)
        except Exception:
            return []

        items = payload.get('items') if isinstance(payload, dict) else payload
        if not isinstance(items, list):
            return []

        result = []
        for item in items:
            normalized = self._normalize_entry(item)
            if normalized:
                result.append(normalized)
        return result

    def _write_payload(self, tool_id: str, items: list[dict]):
        normalized_tool_id = self._normalize_tool_id(tool_id)
        file_path = self._file_path(normalized_tool_id)
        payload = {
            'tool_id': normalized_tool_id,
            'items': items,
        }

        fd, temp_path = tempfile.mkstemp(
            prefix='external_tool_param_presets_',
            suffix='.tmp',
            dir=self.root_dir,
        )
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as file_obj:
                json.dump(payload, file_obj, ensure_ascii=False, indent=2)
            os.replace(temp_path, file_path)
        finally:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass

    def _ensure_unique_name(self, items: list[dict], name: str, skip_preset_id: str = ''):
        target = str(name or '').strip().lower()
        skip_id = str(skip_preset_id or '').strip()
        for item in items:
            if skip_id and str(item.get('preset_id') or '') == skip_id:
                continue
            if str(item.get('name') or '').strip().lower() == target:
                raise ValueError(f'Preset already exists: {name}')

    def list_presets(self, tool_id: str) -> list[dict]:
        with self._lock:
            items = self._read_payload(tool_id)
        return sorted(items, key=lambda item: str(item.get('name') or '').lower())

    def create_preset(self, tool_id: str, name: str, params: dict) -> dict:
        name_text = str(name or '').strip()
        if not name_text:
            raise ValueError('preset name is required')

        with self._lock:
            items = self._read_payload(tool_id)
            self._ensure_unique_name(items, name_text)
            now_text = self._now_text()
            item = {
                'preset_id': uuid.uuid4().hex,
                'name': name_text,
                'params': self._copy_params(params),
                'created_at': now_text,
                'updated_at': now_text,
            }
            items.append(item)
            self._write_payload(tool_id, items)
            return dict(item)

    def update_preset(self, tool_id: str, preset_id: str, *, name: str = '', params=None) -> dict:
        preset_id_text = str(preset_id or '').strip()
        if not preset_id_text:
            raise ValueError('preset_id is required')

        with self._lock:
            items = self._read_payload(tool_id)
            matched = next((item for item in items if item.get('preset_id') == preset_id_text), None)
            if matched is None:
                raise FileNotFoundError(f'Preset not found: {preset_id_text}')

            if name:
                name_text = str(name).strip()
                if not name_text:
                    raise ValueError('preset name is required')
                self._ensure_unique_name(items, name_text, skip_preset_id=preset_id_text)
                matched['name'] = name_text
            if params is not None:
                matched['params'] = self._copy_params(params)
            matched['updated_at'] = self._now_text()
            self._write_payload(tool_id, items)
            return dict(matched)

    def delete_preset(self, tool_id: str, preset_id: str) -> dict:
        preset_id_text = str(preset_id or '').strip()
        if not preset_id_text:
            raise ValueError('preset_id is required')

        with self._lock:
            items = self._read_payload(tool_id)
            kept = []
            removed = None
            for item in items:
                if removed is None and item.get('preset_id') == preset_id_text:
                    removed = item
                    continue
                kept.append(item)
            if removed is None:
                raise FileNotFoundError(f'Preset not found: {preset_id_text}')
            self._write_payload(tool_id, kept)
            return dict(removed)
