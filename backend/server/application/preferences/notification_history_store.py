import json
import os
import tempfile
import threading
import uuid

from core.utils.logger import logger


class NotificationHistoryStore:
    """
    SSE 通知中心持久化。

    只保存已经通过前端通知偏好判断、实际展示过的通知。
    同一个 SSE event_id 只保留一条，避免多个浏览器页签重复写入。
    """

    VERSION = 1

    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
        self._lock = threading.RLock()

    def get_history(self) -> dict:
        with self._lock:
            notifications = self._read_notifications_unlocked()
            return {
                'version': self.VERSION,
                'notifications': notifications,
            }

    def add_notification(self, payload: dict) -> tuple[dict, bool]:
        notification = self._normalize_notification(payload)

        with self._lock:
            notifications = self._read_notifications_unlocked()
            event_id = notification.get('event_id') or ''

            if event_id:
                for existing in notifications:
                    if str(existing.get('event_id') or '') == event_id:
                        return existing, False

            notifications.insert(0, notification)
            self._write_unlocked(notifications)

        return notification, True

    def delete_notification(self, notification_id: str) -> bool:
        normalized_id = str(notification_id or '').strip()
        if not normalized_id:
            raise ValueError('Notification id is required')

        with self._lock:
            notifications = self._read_notifications_unlocked()
            filtered = [
                item for item in notifications
                if str(item.get('id') or '') != normalized_id
            ]

            if len(filtered) == len(notifications):
                return False

            self._write_unlocked(filtered)
            return True

    def clear_history(self) -> int:
        with self._lock:
            notifications = self._read_notifications_unlocked()
            removed_count = len(notifications)
            self._write_unlocked([])
            return removed_count

    def _read_notifications_unlocked(self) -> list:
        if not os.path.isfile(self.file_path):
            return []

        try:
            with open(self.file_path, 'r', encoding='utf-8') as file_obj:
                payload = json.load(file_obj)
        except Exception:
            logger.error('NotificationHistoryStore read failed: %s', self.file_path, exc_info=True)
            return []

        if not isinstance(payload, dict):
            return []

        source = payload.get('notifications')
        if not isinstance(source, list):
            return []

        notifications = []
        seen_ids = set()
        seen_event_ids = set()

        for item in source:
            if not isinstance(item, dict):
                continue

            try:
                normalized = self._normalize_notification(item, allow_missing_event_id=True)
            except ValueError:
                continue

            notification_id = normalized['id']
            event_id = normalized.get('event_id') or ''

            if notification_id in seen_ids:
                continue
            if event_id and event_id in seen_event_ids:
                continue

            seen_ids.add(notification_id)
            if event_id:
                seen_event_ids.add(event_id)
            notifications.append(normalized)

        return notifications

    def _write_unlocked(self, notifications: list):
        payload = {
            'version': self.VERSION,
            'notifications': notifications,
        }

        directory = os.path.dirname(self.file_path)
        fd, temp_path = tempfile.mkstemp(
            prefix='notification_center_',
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
                logger.warning('NotificationHistoryStore temp cleanup failed: %s', temp_path, exc_info=True)

    @staticmethod
    def _normalize_string(value, max_length: int = 0) -> str:
        text = str(value or '').strip()
        if max_length > 0:
            return text[:max_length]
        return text

    def _normalize_notification(self, payload: dict, *, allow_missing_event_id: bool = False) -> dict:
        source = payload if isinstance(payload, dict) else {}
        title = self._normalize_string(source.get('title'), 300)
        message = self._normalize_string(source.get('message'), 5000)

        if not title:
            raise ValueError('Notification title is required')

        notification_id = self._normalize_string(source.get('id'), 200) or uuid.uuid4().hex
        event_id = self._normalize_string(source.get('event_id'), 200)
        if not event_id and not allow_missing_event_id:
            event_id = ''

        notification_type = self._normalize_string(source.get('type'), 32).lower()
        if notification_type not in {'success', 'warning', 'error', 'info'}:
            notification_type = 'info'

        context = source.get('context') if isinstance(source.get('context'), dict) else {}
        actions = source.get('actions') if isinstance(source.get('actions'), list) else []

        normalized_actions = []
        for action in actions:
            if not isinstance(action, dict):
                continue

            action_type = self._normalize_string(action.get('type'), 64)
            label = self._normalize_string(action.get('label'), 120)
            if not action_type or not label:
                continue

            normalized_actions.append({
                'id': self._normalize_string(action.get('id'), 120),
                'type': action_type,
                'label': label,
                'url': self._normalize_string(action.get('url'), 2000),
            })

        return {
            'id': notification_id,
            'event_id': event_id,
            'notification_key': self._normalize_string(source.get('notification_key'), 120),
            'type': notification_type,
            'title': title,
            'message': message,
            'shown_at': self._normalize_string(source.get('shown_at'), 80),
            'context': context,
            'actions': normalized_actions,
        }
