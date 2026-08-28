import json
import os
import tempfile
import threading

from core.utils.logger import logger


DEFAULT_TOOLBAR_PREFERENCES = {
    'toolbar': [
        'remote-files',
        'artifacts',
        'info',
        'scripts',
        'history',
        'pty',
        'screen-view',
        'clipboard',
    ],
    'more': [
        'external-tools',
        'jobs',
        'agents',
        'processes',
        'keychains',
        'one-liners',
    ],
}

_ALLOWED_ACTION_IDS = tuple(
    DEFAULT_TOOLBAR_PREFERENCES['toolbar']
    + DEFAULT_TOOLBAR_PREFERENCES['more']
)


class ToolbarPreferenceStore:
    """
    Toolbar UI 偏好持久化。

    配置保存在 Server runtime，所有浏览器共享同一套 Toolbar 布局。
    """

    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
        self._lock = threading.RLock()

    def get_preferences(self) -> dict:
        with self._lock:
            return self._normalize(self._read_unlocked())

    def save_preferences(self, payload: dict) -> dict:
        normalized = self._normalize(payload)
        with self._lock:
            self._write_unlocked(normalized)
        return normalized

    def _read_unlocked(self) -> dict:
        if not os.path.isfile(self.file_path):
            return {}

        try:
            with open(self.file_path, 'r', encoding='utf-8') as file_obj:
                payload = json.load(file_obj)
            return payload if isinstance(payload, dict) else {}
        except Exception:
            logger.error('ToolbarPreferenceStore read failed: %s', self.file_path, exc_info=True)
            return {}

    def _write_unlocked(self, payload: dict):
        directory = os.path.dirname(self.file_path)
        fd, temp_path = tempfile.mkstemp(
            prefix='toolbar_preferences_',
            suffix='.tmp',
            dir=directory,
        )
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as file_obj:
                json.dump(payload, file_obj, ensure_ascii=False, indent=2)
                file_obj.write('\n')
            os.replace(temp_path, self.file_path)
        finally:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                logger.warning('ToolbarPreferenceStore temp cleanup failed: %s', temp_path, exc_info=True)

    @staticmethod
    def _normalize_list(value) -> list[str]:
        if not isinstance(value, list):
            return []

        result = []
        seen = set()
        for item in value:
            action_id = str(item or '').strip()
            if action_id not in _ALLOWED_ACTION_IDS or action_id in seen:
                continue
            seen.add(action_id)
            result.append(action_id)
        return result

    def _normalize(self, payload: dict) -> dict:
        source = payload if isinstance(payload, dict) else {}
        toolbar = self._normalize_list(source.get('toolbar'))
        more = self._normalize_list(source.get('more'))

        used = set(toolbar + more)
        for action_id in _ALLOWED_ACTION_IDS:
            if action_id in used:
                continue
            default_section = (
                'toolbar'
                if action_id in DEFAULT_TOOLBAR_PREFERENCES['toolbar']
                else 'more'
            )
            if default_section == 'toolbar':
                toolbar.append(action_id)
            else:
                more.append(action_id)
            used.add(action_id)

        return {
            'toolbar': toolbar,
            'more': more,
        }
