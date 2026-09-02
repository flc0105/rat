import json
import os
import tempfile
import threading

from core.utils.logger import logger


DEFAULT_NOTIFICATION_PREFERENCES = {
    'version': 1,
    'enabled': True,
    'events': {
        'connection_online': True,
        'connection_offline': True,
        'artifact_created': True,
        'pty_opened': True,
        'pty_closed': True,
        'pty_error': True,
        'screen_view_starting': True,
        'screen_view_closed': True,
        'screen_view_error': True,
        'background_job_running': True,
        'background_job_stopped': True,
        'background_job_error': True,
        'external_tool_daemon_started': True,
        'external_tool_daemon_stopped': True,
        'external_tool_daemon_error': True,
        'external_tool_install_completed': True,
        'external_tool_install_failed': True,
        'external_tool_uninstall_completed': False,
        'external_tool_uninstall_failed': False,
        'agent_build_completed': True,
        'agent_build_error': True,
    },
}


class NotificationPreferenceStore:
    """
    SSE 通知偏好持久化。

    配置保存在 Server runtime，所有浏览器共享同一套通知策略。
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
            logger.error('NotificationPreferenceStore read failed: %s', self.file_path, exc_info=True)
            return {}

    def _write_unlocked(self, payload: dict):
        directory = os.path.dirname(self.file_path)
        fd, temp_path = tempfile.mkstemp(
            prefix='notification_preferences_',
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
                logger.warning('NotificationPreferenceStore temp cleanup failed: %s', temp_path, exc_info=True)

    @staticmethod
    def _normalize_bool(value, default: bool) -> bool:
        return value if isinstance(value, bool) else default

    def _normalize(self, payload: dict) -> dict:
        source = payload if isinstance(payload, dict) else {}
        source_events = source.get('events') if isinstance(source.get('events'), dict) else {}

        events = {}
        for event_key, default_value in DEFAULT_NOTIFICATION_PREFERENCES['events'].items():
            events[event_key] = self._normalize_bool(
                source_events.get(event_key),
                default_value,
            )

        return {
            'version': DEFAULT_NOTIFICATION_PREFERENCES['version'],
            'enabled': self._normalize_bool(
                source.get('enabled'),
                DEFAULT_NOTIFICATION_PREFERENCES['enabled'],
            ),
            'events': events,
        }
